/* The natives of curl_buffer.inc: CurlBuffer, a byte buffer that carries data
 * larger than a plugin's own memory between the plugin and the extension. */
#include "api.h"

#include <string.h>

#include <algorithm>
#include <new>

namespace api {

namespace {

/* The bytes a copy from offset may take: at most count, up to the end.
 * Throws a native error and returns false when offset is outside. */
bool ReadOffset(IPluginContext *context, const CurlBuffer &buffer, cell_t offset, size_t &available)
{
	if (offset < 0 || static_cast<size_t>(offset) > buffer.bytes.size()) {
		context->ReportError("Offset %d is outside the buffer of %u bytes", offset,
		                     static_cast<unsigned>(buffer.bytes.size()));
		return false;
	}
	available = buffer.bytes.size() - static_cast<size_t>(offset);
	return true;
}

/* Appends bytes unless the buffer would exceed g_BufferMaxBytes; throws a
 * native error otherwise. */
cell_t Append(IPluginContext *context, CurlBuffer &buffer, const char *data, size_t length)
{
	if (length > g_BufferMaxBytes - buffer.bytes.size())
		return context->ThrowNativeError("Appending %u bytes would exceed CurlBufferMaxBytes (%u)",
		                                 static_cast<unsigned>(length), static_cast<unsigned>(g_BufferMaxBytes));
	try {
		buffer.bytes.append(data, length);
	} catch (const std::bad_alloc &) {
		return context->ThrowNativeError("Out of memory appending %u bytes", static_cast<unsigned>(length));
	}
	return 0;
}

// curl_buffer_create()
cell_t CurlBuffer_Create(IPluginContext *context, const cell_t *params)
{
	return static_cast<cell_t>(CreateBuffer(context, std::string()));
}

// curl_buffer_length(buffer)
cell_t CurlBuffer_Length(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	return buffer ? static_cast<cell_t>(buffer->bytes.size()) : 0;
}

// curl_buffer_clear(buffer)
cell_t CurlBuffer_Clear(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	if (buffer)
		std::string().swap(buffer->bytes);
	return 0;
}

// curl_buffer_append(buffer, const char[] data, int length)
cell_t CurlBuffer_Append(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	if (!buffer)
		return 0;
	if (params[3] < 0)
		return context->ThrowNativeError("length %d is negative", params[3]);
	cell_t *data;
	context->LocalToPhysAddr(params[2], &data);
	return Append(context, *buffer, reinterpret_cast<const char *>(data), static_cast<size_t>(params[3]));
}

// curl_buffer_append_string(buffer, const char[] text)
cell_t CurlBuffer_AppendString(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	if (!buffer)
		return 0;
	char *text;
	context->LocalToString(params[2], &text);
	return Append(context, *buffer, text, strlen(text));
}

// curl_buffer_append_buffer(buffer, other)
cell_t CurlBuffer_AppendBuffer(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	CurlBuffer *other = buffer ? ReadBuffer(context, params[2]) : nullptr;
	if (!other)
		return 0;
	/* A copy first: appending a buffer to itself reads what it writes. */
	std::string bytes = other->bytes;
	return Append(context, *buffer, bytes.data(), bytes.size());
}

// curl_buffer_get_string(buffer, offset, char[] output, maxlength)
cell_t CurlBuffer_GetString(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	size_t available;
	if (!buffer || !ReadOffset(context, *buffer, params[2], available))
		return 0;
	if (params[4] < 1)
		return context->ThrowNativeError("maxlength %d must be at least 1", params[4]);

	size_t count = std::min(available, static_cast<size_t>(params[4]) - 1);
	cell_t *output;
	context->LocalToPhysAddr(params[3], &output);
	char *text = reinterpret_cast<char *>(output);
	memcpy(text, buffer->bytes.data() + params[2], count);
	text[count] = '\0';
	return static_cast<cell_t>(count);
}

// curl_buffer_get_bytes(buffer, offset, char[] output, count)
cell_t CurlBuffer_GetBytes(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	size_t available;
	if (!buffer || !ReadOffset(context, *buffer, params[2], available))
		return 0;
	if (params[4] < 0)
		return context->ThrowNativeError("count %d is negative", params[4]);

	size_t count = std::min(available, static_cast<size_t>(params[4]));
	cell_t *output;
	context->LocalToPhysAddr(params[3], &output);
	memcpy(output, buffer->bytes.data() + params[2], count);
	return static_cast<cell_t>(count);
}

// curl_buffer_get(buffer, index)
cell_t CurlBuffer_Get(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	if (!buffer)
		return 0;
	if (params[2] < 0 || static_cast<size_t>(params[2]) >= buffer->bytes.size())
		return context->ThrowNativeError("Index %d is outside the buffer of %u bytes", params[2],
		                                 static_cast<unsigned>(buffer->bytes.size()));
	return static_cast<unsigned char>(buffer->bytes[params[2]]);
}

// curl_buffer_find(buffer, const char[] pattern, length, start)
cell_t CurlBuffer_Find(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	std::string pattern;
	size_t available;
	if (!buffer || !ReadBytes(context, params[2], params[3], "pattern", pattern) ||
	    !ReadOffset(context, *buffer, params[4], available))
		return -1;
	size_t found = buffer->bytes.find(pattern, static_cast<size_t>(params[4]));
	return found == std::string::npos ? -1 : static_cast<cell_t>(found);
}

// curl_buffer_clone(buffer)
cell_t CurlBuffer_Clone(IPluginContext *context, const cell_t *params)
{
	CurlBuffer *buffer = ReadBuffer(context, params[1]);
	if (!buffer)
		return 0;
	try {
		return static_cast<cell_t>(CreateBuffer(context, buffer->bytes));
	} catch (const std::bad_alloc &) {
		return context->ThrowNativeError("Out of memory cloning %u bytes", static_cast<unsigned>(buffer->bytes.size()));
	}
}

} // namespace

const sp_nativeinfo_t g_BufferNatives[] = {
	{"curl_buffer_create",        CurlBuffer_Create},
	{"curl_buffer_length",        CurlBuffer_Length},
	{"curl_buffer_clear",         CurlBuffer_Clear},
	{"curl_buffer_append",        CurlBuffer_Append},
	{"curl_buffer_append_string", CurlBuffer_AppendString},
	{"curl_buffer_append_buffer", CurlBuffer_AppendBuffer},
	{"curl_buffer_get_string",    CurlBuffer_GetString},
	{"curl_buffer_get_bytes",     CurlBuffer_GetBytes},
	{"curl_buffer_get",           CurlBuffer_Get},
	{"curl_buffer_find",          CurlBuffer_Find},
	{"curl_buffer_clone",         CurlBuffer_Clone},
	{nullptr,                     nullptr},
};

} // namespace api
