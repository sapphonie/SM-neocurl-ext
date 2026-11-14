/* The SourceMod side of the CurlBuffer and WebSocket APIs (curl_buffer.inc,
 * curl_websocket.inc): their handle types and the game frame hook that calls
 * the plugins back. */
#ifndef _INCLUDE_NEOCURL_API_H_
#define _INCLUDE_NEOCURL_API_H_

#include "smsdk_ext.h"

#include <string>

namespace api {

/* The bytes of a CurlBuffer handle. */
struct CurlBuffer {
	std::string bytes;
};

/* The size no CurlBuffer may exceed, from "CurlBufferMaxBytes" in
 * SourceMod's core.cfg. */
extern size_t g_BufferMaxBytes;

/* Reads a CurlBuffer handle argument; throws a native error and returns null
 * when it is not one. */
CurlBuffer *ReadBuffer(IPluginContext *context, cell_t handle);

/* A new CurlBuffer handle owned by the plugin, holding bytes; 0 (after a
 * native error) when it cannot be created. */
Handle_t CreateBuffer(IPluginContext *context, std::string bytes);

/* Frees a handle the extension created for a callback, unless the plugin
 * freed it already. */
void FreeCallbackHandle(IPluginContext *context, Handle_t handle);

/* Reads a char[] argument of length bytes, or up to its NUL when length is
 * -1; throws a native error and returns false for a negative length. */
bool ReadBytes(IPluginContext *context, cell_t address, cell_t length, const char *argumentName, std::string &bytes);

/* Reads a callback argument; throws a native error and returns false when it
 * is not a function. */
bool ReadCallback(IPluginContext *context, cell_t function, const char *argumentName);

/* Called by the extension's SDK_OnLoad and SDK_OnUnload. */
bool Load(char *error, size_t maxlength);
void Unload();

/* Natives and per-frame work of the areas, in their own files. */
extern const sp_nativeinfo_t g_BufferNatives[];
extern const sp_nativeinfo_t g_WebSocketNatives[];

extern HandleType_t g_CurlBufferType;
extern HandleType_t g_WebSocketType;

void WebSocketsOnFrame();
void WebSocketsOnHandleDestroy(void *object);
void WebSocketsShutdown();

} // namespace api

#endif // _INCLUDE_NEOCURL_API_H_
