/* Compression and decompression with zlib (gzip, zlib, raw deflate), brotli
 * and zstd, of files and of bytes in memory. Nothing here knows SourceMod,
 * so the unit tests run it as it is. */
#ifndef NEOCURL_CORE_CODEC_H
#define NEOCURL_CORE_CODEC_H

#include <stdint.h>

#include <atomic>
#include <string>

namespace neocurl {

/* The values are the plugin API's CompressFormat (curl_compression.inc) and
 * must stay in that order. */
enum class Format {
	Gzip = 0,
	Zlib,
	Deflate,
	Brotli,
	Zstd,
	/* Decompression only: gzip, zlib or zstd, told by the first bytes. */
	Auto,
};

constexpr Format kLastFormat = Format::Auto;

/* The results of a codec job. The values up to UnknownFormat are the plugin
 * API's CompressError (curl_compression.inc) and must stay in that order. */
enum class CodecError {
	None = 0,
	OpenInput,
	OpenOutput,
	OutputExists,
	CreatePath,
	Read,
	Write,
	Data,
	UnexpectedEOF,
	Memory,
	TooLarge,
	Rename,
	UnknownFormat,
	/* The worker stopped the job; never reaches a plugin. */
	Aborted,
};

constexpr CodecError kLastPluginCodecError = CodecError::UnknownFormat;

/* The levels a format compresses with; a plugin's -1 means level kDefault. */
struct LevelRange {
	int min;
	int max;
	int kDefault;
};

LevelRange LevelRangeOf(Format format);

/* gzip, zlib or zstd by the first bytes of data; Auto when it is none of
 * them (brotli and raw deflate have no signature). */
Format DetectFormat(const char *data, size_t length);

/* Where a codec reads from. */
class Source {
public:
	virtual ~Source() = default;
	/* Up to capacity bytes into buffer; length 0 at the end. False on a read
	 * error. */
	virtual bool Read(char *buffer, size_t capacity, size_t &length) = 0;
};

/* Where a codec writes to. */
class Sink {
public:
	virtual ~Sink() = default;
	/* None, or the error that ends the job (Write, TooLarge, Memory). */
	virtual CodecError Write(const char *data, size_t length) = 0;
};

/* Compresses all of source into sink. format is not Auto; level is within
 * LevelRangeOf(format). */
CodecError Compress(Format format, int level, Source &source, Sink &sink, const std::atomic<bool> &abort);

/* Decompresses all of source into sink. Concatenated gzip members and zstd
 * frames are all decompressed, as the gzip and zstd tools do. */
CodecError Decompress(Format format, Source &source, Sink &sink, const std::atomic<bool> &abort);

/* Bytes in memory; output stays below maxSize bytes (0: no limit), or the
 * job fails with TooLarge. */
CodecError CompressBytes(Format format, int level, const std::string &input, uint64_t maxSize,
                         const std::atomic<bool> &abort, std::string &output);
CodecError DecompressBytes(Format format, const std::string &input, uint64_t maxSize,
                           const std::atomic<bool> &abort, std::string &output);

/* A file job's paths and how it writes its output: into "<output>.tmp",
 * which is renamed onto the output once it is complete. A failed job leaves
 * no temp file and does not touch the output. Both paths are absolute and
 * differ. */
struct FileJob {
	std::string inputPath;
	std::string outputPath;
	bool overwrite;
	bool createPath;
};

std::string TempPathFor(const std::string &outputPath);

CodecError CompressFile(Format format, int level, const FileJob &job, const std::atomic<bool> &abort);
/* maxSize as for DecompressBytes. */
CodecError DecompressFile(Format format, const FileJob &job, uint64_t maxSize, const std::atomic<bool> &abort);

/* The text of a result, e.g. "CompressError_Data". */
const char *CodecErrorName(CodecError error);

} // namespace neocurl

#endif // NEOCURL_CORE_CODEC_H
