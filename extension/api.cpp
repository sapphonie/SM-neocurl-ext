#include "api.h"

#include <stdlib.h>
#include <string.h>

#include <new>
#include <utility>

extern IdentityToken_t *myself_Identity;

namespace api {

size_t g_BufferMaxBytes = 0;
HandleType_t g_CurlBufferType = 0;

namespace {

const char kBufferMaxBytesKey[] = "CurlBufferMaxBytes";
constexpr size_t kDefaultBufferMaxBytes = 256 * 1024 * 1024;

/* Destroys the objects behind the handles of this file's types. */
class Dispatcher : public IHandleTypeDispatch {
public:
	void OnHandleDestroy(HandleType_t type, void *object) override
	{
		if (type == g_CurlBufferType)
			delete static_cast<CurlBuffer *>(object);
	}

	bool GetHandleApproxSize(HandleType_t type, void *object, unsigned int *size) override
	{
		if (type != g_CurlBufferType)
			return false;
		*size = static_cast<unsigned int>(sizeof(CurlBuffer) + static_cast<CurlBuffer *>(object)->bytes.capacity());
		return true;
	}
};

Dispatcher g_Dispatcher;

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

bool Load(char *error, size_t maxlength)
{
	g_BufferMaxBytes = ReadBufferMaxBytes();

	g_CurlBufferType = CreateType("CurlBuffer", error, maxlength);
	if (!g_CurlBufferType)
		return false;

	sharesys->AddNatives(myself, g_BufferNatives);
	return true;
}

void Unload()
{
	if (g_CurlBufferType)
		handlesys->RemoveType(g_CurlBufferType, myself_Identity);
	g_CurlBufferType = 0;
}

} // namespace api
