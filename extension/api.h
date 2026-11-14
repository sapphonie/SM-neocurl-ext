/* The SourceMod side of the CurlBuffer, Compression and WebSocket APIs
 * (curl_buffer.inc, curl_compression.inc, curl_websocket.inc): their handle
 * types, the worker pool of the queued jobs and the game frame hook that
 * calls the plugins back. */
#ifndef _INCLUDE_NEOCURL_API_H_
#define _INCLUDE_NEOCURL_API_H_

#include "smsdk_ext.h"

#include "core/pool.h"

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

/* A path argument as the plugin wrote it and resolved below the game
 * directory. */
struct GamePath {
	std::string relative;
	std::string resolved;
};

/* Reads a path argument; throws a native error and returns false when it is
 * not relative to the game directory (see core/paths.h). */
bool ReadGamePath(IPluginContext *context, cell_t address, const char *argumentName, GamePath &path);

/* Reads a callback argument; throws a native error and returns false when it
 * is not a function. */
bool ReadCallback(IPluginContext *context, cell_t function, const char *argumentName);

/* How a finished job calls its plugin back. */
enum class CallbackShape {
	/* (error, const char[] inFile, const char[] outFile, any data) */
	FilePaths,
	/* (error, CurlBuffer output, any data); output is null on error */
	Bytes,
};

struct PendingCallback {
	IPluginContext *context;
	funcid_t function;
	cell_t data;
	CallbackShape shape;
	std::string inputPath;
	std::string outputPath;
};

enum class PoolKind {
	Compression,
};

/* Queues task on a pool; its result calls callback on a later frame unless
 * the plugin unloaded. */
void SubmitJob(PoolKind pool, neocurl::Task task, PendingCallback callback);

/* Called by the extension's SDK_OnLoad and SDK_OnUnload. */
bool Load(char *error, size_t maxlength);
void Unload();

/* Natives and per-frame work of the areas, in their own files. */
extern const sp_nativeinfo_t g_BufferNatives[];
extern const sp_nativeinfo_t g_CompressionNatives[];
extern const sp_nativeinfo_t g_WebSocketNatives[];

extern HandleType_t g_CurlBufferType;
extern HandleType_t g_WebSocketType;

void WebSocketsOnFrame();
void WebSocketsOnHandleDestroy(void *object);
void WebSocketsShutdown();

} // namespace api

#endif // _INCLUDE_NEOCURL_API_H_
