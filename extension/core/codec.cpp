/* The codecs read their input in chunks from a Source and write what they
 * produce to a Sink as it comes, so files of any size and bytes in memory go
 * through the same code. */
#include "codec.h"
#include "platform.h"

#include <brotli/decode.h>
#include <brotli/encode.h>
#include <stdio.h>
#include <zlib.h>
#include <zstd.h>

#include <memory>
#include <new>
#include <vector>

namespace neocurl {

namespace {

constexpr size_t kChunkSize = 64 * 1024;

/* zlib's window bits for the three framings of deflate. */
constexpr int kZlibWindowBits = 15;
constexpr int kGzipWindowBits = 15 + 16;
constexpr int kDeflateWindowBits = -15;
constexpr int kZlibMemLevel = 8;

int WindowBitsOf(Format format)
{
	switch (format) {
	case Format::Gzip:    return kGzipWindowBits;
	case Format::Deflate: return kDeflateWindowBits;
	default:              return kZlibWindowBits;
	}
}

/* --- Sources and sinks --- */

class FileSource : public Source {
public:
	explicit FileSource(FILE *file) : m_file(file) {}

	bool Read(char *buffer, size_t capacity, size_t &length) override
	{
		length = fread(buffer, 1, capacity, m_file);
		return !ferror(m_file);
	}

private:
	FILE *m_file;
};

class StringSource : public Source {
public:
	explicit StringSource(const std::string &bytes) : m_bytes(bytes) {}

	bool Read(char *buffer, size_t capacity, size_t &length) override
	{
		length = m_bytes.copy(buffer, capacity, m_position);
		m_position += length;
		return true;
	}

private:
	const std::string &m_bytes;
	size_t m_position = 0;
};

/* Gives the bytes read ahead (to tell the format) before the rest of inner. */
class ReplaySource : public Source {
public:
	ReplaySource(std::string head, Source &inner) : m_head(std::move(head)), m_inner(inner) {}

	bool Read(char *buffer, size_t capacity, size_t &length) override
	{
		if (m_position < m_head.size()) {
			length = m_head.copy(buffer, capacity, m_position);
			m_position += length;
			return true;
		}
		return m_inner.Read(buffer, capacity, length);
	}

private:
	std::string m_head;
	size_t m_position = 0;
	Source &m_inner;
};

class FileSink : public Sink {
public:
	explicit FileSink(FILE *file) : m_file(file) {}

	CodecError Write(const char *data, size_t length) override
	{
		if (length == 0 || fwrite(data, 1, length, m_file) == length)
			return CodecError::None;
		return CodecError::Write;
	}

private:
	FILE *m_file;
};

class StringSink : public Sink {
public:
	explicit StringSink(std::string &bytes) : m_bytes(bytes) {}

	CodecError Write(const char *data, size_t length) override
	{
		try {
			m_bytes.append(data, length);
		} catch (const std::bad_alloc &) {
			return CodecError::Memory;
		}
		return CodecError::None;
	}

private:
	std::string &m_bytes;
};

/* Fails with TooLarge once more than maxSize bytes were written; 0 means no
 * limit. */
class LimitedSink : public Sink {
public:
	LimitedSink(Sink &inner, uint64_t maxSize) : m_inner(inner), m_maxSize(maxSize) {}

	CodecError Write(const char *data, size_t length) override
	{
		m_written += length;
		if (m_maxSize != 0 && m_written > m_maxSize)
			return CodecError::TooLarge;
		return m_inner.Write(data, length);
	}

private:
	Sink &m_inner;
	uint64_t m_maxSize;
	uint64_t m_written = 0;
};

/* --- zlib: gzip, zlib and raw deflate --- */

struct DeflateEnd {
	void operator()(z_stream *stream) const { deflateEnd(stream); }
};

struct InflateEnd {
	void operator()(z_stream *stream) const { inflateEnd(stream); }
};

CodecError CompressZlib(Format format, int level, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	z_stream stream = {};
	if (deflateInit2(&stream, level, Z_DEFLATED, WindowBitsOf(format), kZlibMemLevel, Z_DEFAULT_STRATEGY) != Z_OK)
		return CodecError::Memory;
	std::unique_ptr<z_stream, DeflateEnd> streamEnd(&stream);

	std::vector<char> in(kChunkSize), out(kChunkSize);
	for (;;) {
		if (abort)
			return CodecError::Aborted;
		size_t length;
		if (!source.Read(in.data(), in.size(), length))
			return CodecError::Read;

		bool isLastChunk = length == 0;
		stream.next_in = reinterpret_cast<Bytef *>(in.data());
		stream.avail_in = static_cast<uInt>(length);
		int result;
		do {
			stream.next_out = reinterpret_cast<Bytef *>(out.data());
			stream.avail_out = static_cast<uInt>(out.size());
			result = deflate(&stream, isLastChunk ? Z_FINISH : Z_NO_FLUSH);
			if (result == Z_STREAM_ERROR)
				return CodecError::Memory;
			CodecError error = sink.Write(out.data(), out.size() - stream.avail_out);
			if (error != CodecError::None)
				return error;
		} while (isLastChunk ? result != Z_STREAM_END : stream.avail_out == 0);

		if (isLastChunk)
			return CodecError::None;
	}
}

/* For gzip, every member of the input is decompressed, as the gzip tool
 * does; for zlib and raw deflate, bytes after the stream are an error. */
CodecError DecompressZlib(Format format, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	z_stream stream = {};
	if (inflateInit2(&stream, WindowBitsOf(format)) != Z_OK)
		return CodecError::Memory;
	std::unique_ptr<z_stream, InflateEnd> streamEnd(&stream);

	bool isStreamOpen = true;
	std::vector<char> in(kChunkSize), out(kChunkSize);
	for (;;) {
		if (stream.avail_in == 0) {
			if (abort)
				return CodecError::Aborted;
			size_t length;
			if (!source.Read(in.data(), in.size(), length))
				return CodecError::Read;
			if (length == 0)
				break;
			stream.next_in = reinterpret_cast<Bytef *>(in.data());
			stream.avail_in = static_cast<uInt>(length);
		}

		if (!isStreamOpen) {
			if (format != Format::Gzip)
				return CodecError::Data;
			inflateReset(&stream);
			isStreamOpen = true;
		}

		stream.next_out = reinterpret_cast<Bytef *>(out.data());
		stream.avail_out = static_cast<uInt>(out.size());
		int result = inflate(&stream, Z_NO_FLUSH);
		if (result == Z_MEM_ERROR)
			return CodecError::Memory;
		if (result == Z_DATA_ERROR || result == Z_NEED_DICT || result == Z_STREAM_ERROR)
			return CodecError::Data;
		CodecError error = sink.Write(out.data(), out.size() - stream.avail_out);
		if (error != CodecError::None)
			return error;
		if (result == Z_STREAM_END)
			isStreamOpen = false;
	}
	return isStreamOpen ? CodecError::UnexpectedEOF : CodecError::None;
}

/* --- brotli --- */

struct BrotliEncoderDestroy {
	void operator()(BrotliEncoderState *state) const { BrotliEncoderDestroyInstance(state); }
};

struct BrotliDecoderDestroy {
	void operator()(BrotliDecoderState *state) const { BrotliDecoderDestroyInstance(state); }
};

CodecError CompressBrotli(int level, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	std::unique_ptr<BrotliEncoderState, BrotliEncoderDestroy> state(
		BrotliEncoderCreateInstance(nullptr, nullptr, nullptr));
	if (!state || !BrotliEncoderSetParameter(state.get(), BROTLI_PARAM_QUALITY, static_cast<uint32_t>(level)))
		return CodecError::Memory;

	std::vector<char> in(kChunkSize), out(kChunkSize);
	for (;;) {
		if (abort)
			return CodecError::Aborted;
		size_t length;
		if (!source.Read(in.data(), in.size(), length))
			return CodecError::Read;

		bool isLastChunk = length == 0;
		BrotliEncoderOperation operation = isLastChunk ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS;
		const uint8_t *nextIn = reinterpret_cast<const uint8_t *>(in.data());
		size_t availableIn = length;
		do {
			uint8_t *nextOut = reinterpret_cast<uint8_t *>(out.data());
			size_t availableOut = out.size();
			if (!BrotliEncoderCompressStream(state.get(), operation, &availableIn, &nextIn, &availableOut, &nextOut,
			                                 nullptr))
				return CodecError::Memory;
			CodecError error = sink.Write(out.data(), out.size() - availableOut);
			if (error != CodecError::None)
				return error;
		} while (availableIn > 0 || BrotliEncoderHasMoreOutput(state.get()) ||
		         (isLastChunk && !BrotliEncoderIsFinished(state.get())));

		if (isLastChunk)
			return CodecError::None;
	}
}

CodecError DecompressBrotli(Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	std::unique_ptr<BrotliDecoderState, BrotliDecoderDestroy> state(
		BrotliDecoderCreateInstance(nullptr, nullptr, nullptr));
	if (!state)
		return CodecError::Memory;

	std::vector<char> in(kChunkSize), out(kChunkSize);
	const uint8_t *nextIn = nullptr;
	size_t availableIn = 0;
	BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
	for (;;) {
		if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
			if (abort)
				return CodecError::Aborted;
			size_t length;
			if (!source.Read(in.data(), in.size(), length))
				return CodecError::Read;
			if (length == 0)
				return CodecError::UnexpectedEOF;
			nextIn = reinterpret_cast<const uint8_t *>(in.data());
			availableIn = length;
		}

		uint8_t *nextOut = reinterpret_cast<uint8_t *>(out.data());
		size_t availableOut = out.size();
		result = BrotliDecoderDecompressStream(state.get(), &availableIn, &nextIn, &availableOut, &nextOut, nullptr);
		if (result == BROTLI_DECODER_RESULT_ERROR) {
			BrotliDecoderErrorCode code = BrotliDecoderGetErrorCode(state.get());
			bool isAllocation = code <= BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES &&
			                    code >= BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES;
			return isAllocation ? CodecError::Memory : CodecError::Data;
		}
		CodecError error = sink.Write(out.data(), out.size() - availableOut);
		if (error != CodecError::None)
			return error;

		if (result == BROTLI_DECODER_RESULT_SUCCESS) {
			size_t length = 0;
			if (availableIn > 0 || !source.Read(in.data(), in.size(), length) || length > 0)
				return CodecError::Data;
			return CodecError::None;
		}
	}
}

/* --- zstd --- */

struct ZstdCompressFree {
	void operator()(ZSTD_CCtx *context) const { ZSTD_freeCCtx(context); }
};

struct ZstdDecompressFree {
	void operator()(ZSTD_DCtx *context) const { ZSTD_freeDCtx(context); }
};

CodecError FromZstdError(size_t result)
{
	return ZSTD_getErrorCode(result) == ZSTD_error_memory_allocation ? CodecError::Memory : CodecError::Data;
}

/* With a content checksum, as the zstd tool writes. */
CodecError CompressZstd(int level, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	std::unique_ptr<ZSTD_CCtx, ZstdCompressFree> context(ZSTD_createCCtx());
	if (!context || ZSTD_isError(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, level)) ||
	    ZSTD_isError(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_checksumFlag, 1)))
		return CodecError::Memory;

	std::vector<char> in(kChunkSize), out(kChunkSize);
	for (;;) {
		if (abort)
			return CodecError::Aborted;
		size_t length;
		if (!source.Read(in.data(), in.size(), length))
			return CodecError::Read;

		bool isLastChunk = length == 0;
		ZSTD_inBuffer input = {in.data(), length, 0};
		bool isChunkDone;
		do {
			ZSTD_outBuffer output = {out.data(), out.size(), 0};
			size_t remaining =
				ZSTD_compressStream2(context.get(), &output, &input, isLastChunk ? ZSTD_e_end : ZSTD_e_continue);
			if (ZSTD_isError(remaining))
				return FromZstdError(remaining);
			CodecError error = sink.Write(out.data(), output.pos);
			if (error != CodecError::None)
				return error;
			isChunkDone = isLastChunk ? remaining == 0 : input.pos == input.size;
		} while (!isChunkDone);

		if (isLastChunk)
			return CodecError::None;
	}
}

CodecError DecompressZstd(Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	std::unique_ptr<ZSTD_DCtx, ZstdDecompressFree> context(ZSTD_createDCtx());
	if (!context)
		return CodecError::Memory;

	bool hasInput = false;
	size_t lastResult = 0;
	std::vector<char> in(kChunkSize), out(kChunkSize);
	for (;;) {
		if (abort)
			return CodecError::Aborted;
		size_t length;
		if (!source.Read(in.data(), in.size(), length))
			return CodecError::Read;
		if (length == 0)
			break;
		hasInput = true;

		ZSTD_inBuffer input = {in.data(), length, 0};
		ZSTD_outBuffer output;
		do {
			output = {out.data(), out.size(), 0};
			lastResult = ZSTD_decompressStream(context.get(), &output, &input);
			if (ZSTD_isError(lastResult))
				return FromZstdError(lastResult);
			CodecError error = sink.Write(out.data(), output.pos);
			if (error != CodecError::None)
				return error;
		} while (input.pos < input.size || output.pos == output.size);
	}
	/* A result of 0 means the last frame is complete. */
	if (!hasInput || lastResult != 0)
		return CodecError::UnexpectedEOF;
	return CodecError::None;
}

/* --- Format detection --- */

/* Reads until at least the longest signature (or the end) is there. */
CodecError ReadHead(Source &source, std::string &head)
{
	constexpr size_t kSignatureLength = 4;
	char chunk[kSignatureLength];
	while (head.size() < kSignatureLength) {
		size_t length;
		if (!source.Read(chunk, kSignatureLength - head.size(), length))
			return CodecError::Read;
		if (length == 0)
			break;
		head.append(chunk, length);
	}
	return CodecError::None;
}

/* --- File jobs --- */

struct FileCloser {
	void operator()(FILE *file) const { fclose(file); }
};
using File = std::unique_ptr<FILE, FileCloser>;

/* The position of the first path separator at or after from, or npos. */
size_t FindSeparator(const std::string &path, size_t from)
{
	for (size_t i = from; i < path.size(); i++)
		if (platform::IsPathSeparator(path[i]))
			return i;
	return std::string::npos;
}

/* mkdir -p of the directory the file is in. */
bool CreateParentDirectories(const std::string &filePath)
{
	size_t lastSeparator = std::string::npos;
	for (size_t i = 0; i < filePath.size(); i++)
		if (platform::IsPathSeparator(filePath[i]))
			lastSeparator = i;
	if (lastSeparator == std::string::npos || lastSeparator == 0)
		return true;

	std::string directory = filePath.substr(0, lastSeparator);
	for (size_t separator = FindSeparator(directory, 1); ; separator = FindSeparator(directory, separator + 1)) {
		if (!platform::MakeDirectory(directory.substr(0, separator)))
			return false;
		if (separator == std::string::npos)
			return true;
	}
}

/* Puts the finished temp file in the output's place. Without overwrite, an
 * output that appeared while the job ran is refused. */
CodecError Publish(const std::string &tempPath, const FileJob &job)
{
	platform::RenameResult result = job.overwrite ? platform::RenameReplacing(tempPath, job.outputPath)
	                                              : platform::RenameIfAbsent(tempPath, job.outputPath);
	switch (result) {
	case platform::RenameResult::Renamed:      return CodecError::None;
	case platform::RenameResult::TargetExists: return CodecError::OutputExists;
	case platform::RenameResult::Failed:       return CodecError::Rename;
	}
	return CodecError::Rename;
}

template <typename Transform>
CodecError RunFileJob(const FileJob &job, Transform transform)
{
	if (!job.overwrite && platform::PathExists(job.outputPath))
		return CodecError::OutputExists;
	if (job.createPath && !CreateParentDirectories(job.outputPath))
		return CodecError::CreatePath;

	File input(platform::OpenFile(job.inputPath, "rb"));
	if (!input)
		return CodecError::OpenInput;

	std::string tempPath = TempPathFor(job.outputPath);
	FILE *temp = platform::OpenFile(tempPath, "wb");
	if (!temp)
		return CodecError::OpenOutput;

	FileSource source(input.get());
	FileSink sink(temp);
	CodecError result = transform(source, sink);
	bool isTempClosed = fclose(temp) == 0;
	if (result == CodecError::None && !isTempClosed)
		result = CodecError::Write;
	if (result == CodecError::None)
		result = Publish(tempPath, job);

	if (result != CodecError::None)
		platform::RemoveFile(tempPath);
	return result;
}

} // namespace

LevelRange LevelRangeOf(Format format)
{
	switch (format) {
	case Format::Brotli: return LevelRange{0, 11, 6};
	case Format::Zstd:   return LevelRange{1, 22, 3};
	case Format::Auto:   return LevelRange{0, 0, 0};
	default:             return LevelRange{1, 9, 6};
	}
}

Format DetectFormat(const char *data, size_t length)
{
	const unsigned char *bytes = reinterpret_cast<const unsigned char *>(data);
	if (length >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
		return Format::Gzip;
	if (length >= 4 && bytes[0] == 0x28 && bytes[1] == 0xb5 && bytes[2] == 0x2f && bytes[3] == 0xfd)
		return Format::Zstd;
	/* RFC 1950: deflate with a window of at most 32 KB, and the header's
	 * check bits make it a multiple of 31. */
	if (length >= 2 && (bytes[0] & 0x0f) == 8 && (bytes[0] >> 4) <= 7 && ((bytes[0] << 8) | bytes[1]) % 31 == 0)
		return Format::Zlib;
	return Format::Auto;
}

CodecError Compress(Format format, int level, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	switch (format) {
	case Format::Gzip:
	case Format::Zlib:
	case Format::Deflate: return CompressZlib(format, level, source, sink, abort);
	case Format::Brotli:  return CompressBrotli(level, source, sink, abort);
	case Format::Zstd:    return CompressZstd(level, source, sink, abort);
	case Format::Auto:    break;
	}
	return CodecError::UnknownFormat;
}

CodecError Decompress(Format format, Source &source, Sink &sink, const std::atomic<bool> &abort)
{
	switch (format) {
	case Format::Gzip:
	case Format::Zlib:
	case Format::Deflate: return DecompressZlib(format, source, sink, abort);
	case Format::Brotli:  return DecompressBrotli(source, sink, abort);
	case Format::Zstd:    return DecompressZstd(source, sink, abort);
	case Format::Auto:    break;
	}

	std::string head;
	CodecError error = ReadHead(source, head);
	if (error != CodecError::None)
		return error;
	Format detected = DetectFormat(head.data(), head.size());
	if (detected == Format::Auto)
		return CodecError::UnknownFormat;
	ReplaySource replay(std::move(head), source);
	return Decompress(detected, replay, sink, abort);
}

CodecError CompressBytes(Format format, int level, const std::string &input, uint64_t maxSize,
                         const std::atomic<bool> &abort, std::string &output)
{
	StringSource source(input);
	StringSink sink(output);
	LimitedSink limited(sink, maxSize);
	return Compress(format, level, source, limited, abort);
}

CodecError DecompressBytes(Format format, const std::string &input, uint64_t maxSize,
                           const std::atomic<bool> &abort, std::string &output)
{
	StringSource source(input);
	StringSink sink(output);
	LimitedSink limited(sink, maxSize);
	return Decompress(format, source, limited, abort);
}

std::string TempPathFor(const std::string &outputPath)
{
	return outputPath + ".tmp";
}

CodecError CompressFile(Format format, int level, const FileJob &job, const std::atomic<bool> &abort)
{
	return RunFileJob(job, [&](Source &source, Sink &sink) { return Compress(format, level, source, sink, abort); });
}

CodecError DecompressFile(Format format, const FileJob &job, uint64_t maxSize, const std::atomic<bool> &abort)
{
	return RunFileJob(job, [&](Source &source, Sink &sink) {
		LimitedSink limited(sink, maxSize);
		return Decompress(format, source, limited, abort);
	});
}

const char *CodecErrorName(CodecError error)
{
	switch (error) {
	case CodecError::None:          return "CompressError_None";
	case CodecError::OpenInput:     return "CompressError_OpenInput";
	case CodecError::OpenOutput:    return "CompressError_OpenOutput";
	case CodecError::OutputExists:  return "CompressError_OutputExists";
	case CodecError::CreatePath:    return "CompressError_CreatePath";
	case CodecError::Read:          return "CompressError_Read";
	case CodecError::Write:         return "CompressError_Write";
	case CodecError::Data:          return "CompressError_Data";
	case CodecError::UnexpectedEOF: return "CompressError_UnexpectedEOF";
	case CodecError::Memory:        return "CompressError_Memory";
	case CodecError::TooLarge:      return "CompressError_TooLarge";
	case CodecError::Rename:        return "CompressError_Rename";
	case CodecError::UnknownFormat: return "CompressError_UnknownFormat";
	case CodecError::Aborted:       return "Aborted";
	}
	return "unknown";
}

} // namespace neocurl
