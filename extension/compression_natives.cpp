/* The natives of curl_compression.inc. Every argument is checked here, so the
 * jobs on the compression pool only ever see valid ones. */
#include "api.h"

#include "core/codec.h"
#include "core/platform.h"

#include <memory>
#include <new>
#include <utility>

using neocurl::CodecError;
using neocurl::Format;

namespace api {

namespace {

/* Reads a format argument; Auto only where allowAuto. */
bool ReadFormat(IPluginContext *context, cell_t value, bool allowAuto, Format &format)
{
	if (value < 0 || value > static_cast<cell_t>(neocurl::kLastFormat)) {
		context->ReportError("Invalid CompressFormat %d", value);
		return false;
	}
	format = static_cast<Format>(value);
	if (format == Format::Auto && !allowAuto) {
		context->ReportError("CompressFormat_Auto can only decompress");
		return false;
	}
	return true;
}

/* Reads a level argument, -1 for the format's default. */
bool ReadLevel(IPluginContext *context, Format format, cell_t value, int &level)
{
	neocurl::LevelRange range = neocurl::LevelRangeOf(format);
	if (value == -1) {
		level = range.kDefault;
		return true;
	}
	if (value < range.min || value > range.max) {
		context->ReportError("Compression level %d is outside %d-%d (or -1 for the default)", value, range.min,
		                     range.max);
		return false;
	}
	level = value;
	return true;
}

/* The limit of a decompression's output: the plugin's maxSize (0: none),
 * never above g_BufferMaxBytes for buffers. */
bool ReadMaxSize(IPluginContext *context, cell_t value, bool isBuffer, uint64_t &maxSize)
{
	if (value < 0) {
		context->ReportError("maxSize %d is negative", value);
		return false;
	}
	maxSize = static_cast<uint64_t>(value);
	if (isBuffer && (maxSize == 0 || maxSize > g_BufferMaxBytes))
		maxSize = g_BufferMaxBytes;
	return true;
}

int ErrorCode(CodecError error)
{
	return static_cast<int>(error);
}

// compression_compress_file(format, inFile, outFile, callback, data, level, overwrite, createPath)
// compression_decompress_file(format, inFile, outFile, callback, data, maxSize, overwrite, createPath)
cell_t QueueFile(IPluginContext *context, const cell_t *params, bool isCompress)
{
	Format format;
	if (!ReadFormat(context, params[1], !isCompress, format))
		return 0;
	int level = 0;
	uint64_t maxSize = 0;
	if (isCompress ? !ReadLevel(context, format, params[6], level) : !ReadMaxSize(context, params[6], false, maxSize))
		return 0;

	GamePath input, output;
	if (!ReadGamePath(context, params[2], "inFile", input) || !ReadGamePath(context, params[3], "outFile", output))
		return 0;
	if (neocurl::platform::IsSamePath(input.resolved, output.resolved))
		return context->ThrowNativeError("inFile \"%s\" and outFile \"%s\" are the same file",
		                                 input.relative.c_str(), output.relative.c_str());
	if (!ReadCallback(context, params[4], "callback"))
		return 0;

	neocurl::FileJob job{input.resolved, output.resolved, params[7] != 0, params[8] != 0};
	neocurl::Task task = [=](const std::atomic<bool> &abort) {
		CodecError error = isCompress ? neocurl::CompressFile(format, level, job, abort)
		                              : neocurl::DecompressFile(format, job, maxSize, abort);
		return neocurl::TaskResult{0, ErrorCode(error), std::string()};
	};
	SubmitJob(PoolKind::Compression, std::move(task),
	          PendingCallback{context, static_cast<funcid_t>(params[4]), params[5], CallbackShape::FilePaths,
	                          input.relative, output.relative});
	return 0;
}

/* Queues a job on bytes already copied from the plugin. */
void QueueBytes(IPluginContext *context, Format format, bool isCompress, int level, uint64_t maxSize,
                std::string input, cell_t callback, cell_t data)
{
	auto shared = std::make_shared<std::string>(std::move(input));
	neocurl::Task task = [=](const std::atomic<bool> &abort) {
		std::string output;
		CodecError error = isCompress ? neocurl::CompressBytes(format, level, *shared, maxSize, abort, output)
		                              : neocurl::DecompressBytes(format, *shared, maxSize, abort, output);
		if (error != CodecError::None)
			output.clear();
		return neocurl::TaskResult{0, ErrorCode(error), std::move(output)};
	};
	SubmitJob(PoolKind::Compression, std::move(task),
	          PendingCallback{context, static_cast<funcid_t>(callback), data, CallbackShape::Bytes, {}, {}});
}

/* params: format, the input (a CurlBuffer, or char[] and length), callback,
 * data, then level or maxSize. */
cell_t QueueBytesFrom(IPluginContext *context, const cell_t *params, bool isCompress, bool isFromBuffer)
{
	Format format;
	if (!ReadFormat(context, params[1], !isCompress, format))
		return 0;

	int next = isFromBuffer ? 3 : 4;
	cell_t callback = params[next], data = params[next + 1], levelOrMax = params[next + 2];
	int level = 0;
	uint64_t maxSize = g_BufferMaxBytes;
	if (isCompress ? !ReadLevel(context, format, levelOrMax, level) : !ReadMaxSize(context, levelOrMax, true, maxSize))
		return 0;
	if (!ReadCallback(context, callback, "callback"))
		return 0;

	std::string input;
	try {
		if (isFromBuffer) {
			CurlBuffer *buffer = ReadBuffer(context, params[2]);
			if (!buffer)
				return 0;
			input = buffer->bytes;
		} else if (!ReadBytes(context, params[2], params[3], "input", input)) {
			return 0;
		}
	} catch (const std::bad_alloc &) {
		return context->ThrowNativeError("Out of memory copying the input");
	}
	QueueBytes(context, format, isCompress, level, maxSize, std::move(input), callback, data);
	return 0;
}

cell_t Compression_CompressFile(IPluginContext *context, const cell_t *params)
{
	return QueueFile(context, params, true);
}

cell_t Compression_DecompressFile(IPluginContext *context, const cell_t *params)
{
	return QueueFile(context, params, false);
}

// compression_compress_string(format, const char[] input, length, callback, data, level)
cell_t Compression_CompressString(IPluginContext *context, const cell_t *params)
{
	return QueueBytesFrom(context, params, true, false);
}

// compression_decompress_string(format, const char[] input, length, callback, data, maxSize)
cell_t Compression_DecompressString(IPluginContext *context, const cell_t *params)
{
	return QueueBytesFrom(context, params, false, false);
}

// compression_compress_buffer(format, buffer, callback, data, level)
cell_t Compression_CompressBuffer(IPluginContext *context, const cell_t *params)
{
	return QueueBytesFrom(context, params, true, true);
}

// compression_decompress_buffer(format, buffer, callback, data, maxSize)
cell_t Compression_DecompressBuffer(IPluginContext *context, const cell_t *params)
{
	return QueueBytesFrom(context, params, false, true);
}

// compression_error_string(error, char[] buffer, maxlength)
cell_t Compression_ErrorString(IPluginContext *context, const cell_t *params)
{
	cell_t error = params[1];
	if (error < 0 || error > static_cast<cell_t>(neocurl::kLastPluginCodecError))
		return context->ThrowNativeError("Invalid CompressError %d", error);
	// Stays 0 for a maxlength of 0: nothing is written then, not even this.
	size_t written = 0;
	context->StringToLocalUTF8(params[2], params[3], neocurl::CodecErrorName(static_cast<CodecError>(error)),
	                           &written);
	return static_cast<cell_t>(written);
}

} // namespace

const sp_nativeinfo_t g_CompressionNatives[] = {
	{"compression_compress_file",     Compression_CompressFile},
	{"compression_decompress_file",   Compression_DecompressFile},
	{"compression_compress_string",   Compression_CompressString},
	{"compression_decompress_string", Compression_DecompressString},
	{"compression_compress_buffer",   Compression_CompressBuffer},
	{"compression_decompress_buffer", Compression_DecompressBuffer},
	{"compression_error_string",      Compression_ErrorString},
	{nullptr,                         nullptr},
};

} // namespace api
