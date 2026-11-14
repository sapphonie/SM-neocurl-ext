#include "api.h"

#include "core/paths.h"

#include <stdlib.h>
#include <string.h>

#include <new>
#include <utility>

extern IdentityToken_t *myself_Identity;

namespace api {

size_t g_BufferMaxBytes = 0;
HandleType_t g_CurlBufferType = 0;
HandleType_t g_WebSocketType = 0;

namespace {

const char kBufferMaxBytesKey[] = "CurlBufferMaxBytes";
constexpr size_t kDefaultBufferMaxBytes = 256 * 1024 * 1024;
constexpr size_t kCompressionThreads = 2;
constexpr size_t kCryptThreads = 2;

/* Destroys the objects behind the handles of this file's types and drops
 * the callbacks of plugins that unload. */
class Dispatcher : public IHandleTypeDispatch, public IPluginsListener {
public:
	void OnHandleDestroy(HandleType_t type, void *object) override
	{
		if (type == g_CurlBufferType)
			delete static_cast<CurlBuffer *>(object);
		else if (type == g_WebSocketType)
			WebSocketsOnHandleDestroy(object);
	}

	bool GetHandleApproxSize(HandleType_t type, void *object, unsigned int *size) override
	{
		if (type != g_CurlBufferType)
			return false;
		*size = static_cast<unsigned int>(sizeof(CurlBuffer) + static_cast<CurlBuffer *>(object)->bytes.capacity());
		return true;
	}

	void OnPluginUnloaded(IPlugin *plugin) override;
};

Dispatcher g_Dispatcher;

std::unique_ptr<neocurl::Pool> g_CompressionPool;
std::unique_ptr<neocurl::Pool> g_CryptPool;
std::unordered_map<neocurl::TaskId, PendingCallback> g_Pending;
neocurl::TaskId g_NextTaskId = 1;

void Dispatcher::OnPluginUnloaded(IPlugin *plugin)
{
	IPluginContext *context = plugin->GetBaseContext();
	for (auto it = g_Pending.begin(); it != g_Pending.end();) {
		if (it->second.context == context)
			it = g_Pending.erase(it);
		else
			++it;
	}
}

/* "CurlBufferMaxBytes" from core.cfg; the default when it is missing, and
 * with an error in the log when it is not a positive number. */
size_t ReadBufferMaxBytes()
{
	const char *value = smutils->GetCoreConfigValue(kBufferMaxBytesKey);
	if (!value || value[0] == '\0')
		return kDefaultBufferMaxBytes;

	char *end;
	unsigned long long parsed = strtoull(value, &end, 10);
	bool isValid = *end == '\0' && value[0] != '-' && parsed > 0 && parsed <= static_cast<unsigned long long>(SIZE_MAX);
	if (!isValid) {
		smutils->LogError(myself, "core.cfg: \"%s\" \"%s\" is not a positive number of bytes; using %u",
		                  kBufferMaxBytesKey, value, static_cast<unsigned>(kDefaultBufferMaxBytes));
		return kDefaultBufferMaxBytes;
	}
	return static_cast<size_t>(parsed);
}

void DeliverResults(neocurl::Pool &pool)
{
	for (neocurl::TaskResult &result : pool.TakeResults()) {
		auto found = g_Pending.find(result.id);
		if (found == g_Pending.end())
			continue;
		PendingCallback callback = std::move(found->second);
		g_Pending.erase(found);

		IPluginFunction *function;
		if (!callback.context->GetFunctionByIdOrNull(callback.function, &function) || !function)
			continue;

		function->PushCell(result.error);
		Handle_t output = 0;
		if (callback.shape == CallbackShape::FilePaths) {
			function->PushString(callback.inputPath.c_str());
			function->PushString(callback.outputPath.c_str());
		} else {
			if (result.error == 0)
				output = CreateBuffer(callback.context, std::move(result.output));
			function->PushCell(static_cast<cell_t>(output));
		}
		function->PushCell(callback.data);
		function->Execute(nullptr);
		if (output)
			FreeCallbackHandle(callback.context, output);
	}
}

void OnGameFrame(bool simulating)
{
	DeliverResults(*g_CompressionPool);
	DeliverResults(*g_CryptPool);
	WebSocketsOnFrame();
}

HandleType_t CreateType(const char *name, char *error, size_t maxlength)
{
	HandleError handleError;
	HandleType_t type = handlesys->CreateType(name, &g_Dispatcher, 0, nullptr, nullptr, myself_Identity,
	                                          &handleError);
	if (!type)
		smutils->Format(error, maxlength, "Could not create handle type %s (error %d)", name, handleError);
	return type;
}

} // namespace

CurlBuffer *ReadBuffer(IPluginContext *context, cell_t handle)
{
	CurlBuffer *buffer;
	HandleSecurity security(context->GetIdentity(), myself_Identity);
	HandleError error =
		handlesys->ReadHandle(static_cast<Handle_t>(handle), g_CurlBufferType, &security, reinterpret_cast<void **>(&buffer));
	if (error != HandleError_None) {
		context->ReportError("Invalid CurlBuffer handle %x (error %d)", handle, error);
		return nullptr;
	}
	return buffer;
}

Handle_t CreateBuffer(IPluginContext *context, std::string bytes)
{
	CurlBuffer *buffer = new (std::nothrow) CurlBuffer{std::move(bytes)};
	if (!buffer) {
		context->ReportError("Out of memory for a CurlBuffer");
		return 0;
	}
	HandleError error;
	Handle_t handle = handlesys->CreateHandle(g_CurlBufferType, buffer, context->GetIdentity(), myself_Identity, &error);
	if (!handle) {
		delete buffer;
		context->ReportError("Cannot create a CurlBuffer handle (error %d)", error);
	}
	return handle;
}

void FreeCallbackHandle(IPluginContext *context, Handle_t handle)
{
	HandleSecurity security(context->GetIdentity(), myself_Identity);
	handlesys->FreeHandle(handle, &security);
}

bool ReadBytes(IPluginContext *context, cell_t address, cell_t length, const char *argumentName, std::string &bytes)
{
	if (length < -1) {
		context->ReportError("%s length %d is negative", argumentName, length);
		return false;
	}
	if (length == -1) {
		char *text;
		context->LocalToString(address, &text);
		bytes.assign(text);
		return true;
	}
	cell_t *physical;
	context->LocalToPhysAddr(address, &physical);
	bytes.assign(reinterpret_cast<const char *>(physical), static_cast<size_t>(length));
	return true;
}

bool ReadGamePath(IPluginContext *context, cell_t address, const char *argumentName, GamePath &path)
{
	char *text;
	context->LocalToString(address, &text);
	if (!neocurl::IsGameRelativePath(text)) {
		context->ReportError("%s \"%s\" must be a path relative to the game directory: it must %s", argumentName,
		                     text, neocurl::kPathRules);
		return false;
	}
	char buffer[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_Game, buffer, sizeof(buffer), "%s", text);
	path = GamePath{text, buffer};
	return true;
}

bool ReadCallback(IPluginContext *context, cell_t function, const char *argumentName)
{
	IPluginFunction *found;
	if (context->GetFunctionByIdOrNull(static_cast<funcid_t>(function), &found) && found)
		return true;
	context->ReportError("%s: invalid callback function %x", argumentName, function);
	return false;
}

void SubmitJob(PoolKind pool, neocurl::Task task, PendingCallback callback)
{
	neocurl::TaskId id = g_NextTaskId++;
	g_Pending.emplace(id, std::move(callback));
	neocurl::Pool &target = pool == PoolKind::Compression ? *g_CompressionPool : *g_CryptPool;
	target.Submit(id, std::move(task));
}

bool Load(char *error, size_t maxlength)
{
	g_BufferMaxBytes = ReadBufferMaxBytes();

	g_CurlBufferType = CreateType("CurlBuffer", error, maxlength);
	if (!g_CurlBufferType)
		return false;
	g_WebSocketType = CreateType("WebSocket", error, maxlength);
	if (!g_WebSocketType)
		return false;

	g_CompressionPool = std::make_unique<neocurl::Pool>(kCompressionThreads);
	g_CryptPool = std::make_unique<neocurl::Pool>(kCryptThreads);

	sharesys->AddNatives(myself, g_BufferNatives);
	sharesys->AddNatives(myself, g_CompressionNatives);
	sharesys->AddNatives(myself, g_CryptNatives);
	sharesys->AddNatives(myself, g_WebSocketNatives);
	plsys->AddPluginsListener(&g_Dispatcher);
	smutils->AddGameFrameHook(OnGameFrame);
	return true;
}

void Unload()
{
	smutils->RemoveGameFrameHook(OnGameFrame);
	plsys->RemovePluginsListener(&g_Dispatcher);
	WebSocketsShutdown();
	g_CompressionPool.reset();
	g_CryptPool.reset();
	g_Pending.clear();
	if (g_WebSocketType)
		handlesys->RemoveType(g_WebSocketType, myself_Identity);
	if (g_CurlBufferType)
		handlesys->RemoveType(g_CurlBufferType, myself_Identity);
	g_WebSocketType = 0;
	g_CurlBufferType = 0;
}

} // namespace api
