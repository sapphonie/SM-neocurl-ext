/* The natives of curl_websocket.inc. A WebSocket handle holds the options
 * and callbacks until websocket_connect(), then the session whose thread runs
 * the connection; every game frame its events call the plugin back. */
#include "api.h"

#include "core/websocket_session.h"

#include <ctype.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

extern IdentityToken_t *myself_Identity;

using neocurl::WsConfig;
using neocurl::WsEvent;
using neocurl::WsMessageType;
using neocurl::WsSession;
using neocurl::WsState;

namespace api {

namespace {

/* SourceMod's Action values, for OnReconnect. */
constexpr cell_t kPluginStop = 4;

enum CallbackSlot {
	Slot_Open = 0,
	Slot_Message,
	Slot_Frame,
	Slot_Pong,
	Slot_Reconnect,
	Slot_Close,
	Slot_Count,
};

constexpr cell_t kNoCallback = -1;

struct WebSocket {
	IPluginContext *context;
	Handle_t handle = 0;
	WsConfig config;
	cell_t callbacks[Slot_Count] = {kNoCallback, kNoCallback, kNoCallback, kNoCallback, kNoCallback, kNoCallback};
	cell_t data = 0;
	std::shared_ptr<WsSession> session;
	/* Set when the handle is freed, maybe in the middle of a callback. */
	bool isDestroyed = false;
};

/* The object behind a WebSocket handle. */
struct HandleObject {
	std::shared_ptr<WebSocket> socket;
};

/* The connected WebSockets whose events are delivered every frame. */
std::vector<std::shared_ptr<WebSocket>> g_Live;
/* Sessions of freed handles, kept until their threads ended. */
std::vector<std::shared_ptr<WsSession>> g_Retiring;

WebSocket *ReadWebSocket(IPluginContext *context, cell_t handle)
{
	HandleObject *object;
	HandleSecurity security(context->GetIdentity(), myself_Identity);
	HandleError error = handlesys->ReadHandle(static_cast<Handle_t>(handle), g_WebSocketType, &security,
	                                          reinterpret_cast<void **>(&object));
	if (error != HandleError_None) {
		context->ReportError("Invalid WebSocket handle %x (error %d)", handle, error);
		return nullptr;
	}
	return object->socket.get();
}

/* A WebSocket whose options may still change; throws a native error once
 * it connected. */
WebSocket *ReadUnconnected(IPluginContext *context, cell_t handle)
{
	WebSocket *socket = ReadWebSocket(context, handle);
	if (socket && socket->session) {
		context->ReportError("The WebSocket's options and callbacks can only be set before websocket_connect()");
		return nullptr;
	}
	return socket;
}

/* A connected WebSocket; throws a native error before websocket_connect(). */
WebSocket *ReadConnected(IPluginContext *context, cell_t handle)
{
	WebSocket *socket = ReadWebSocket(context, handle);
	if (socket && !socket->session) {
		context->ReportError("The WebSocket is not connected yet; call websocket_connect() first");
		return nullptr;
	}
	return socket;
}

std::string ReadString(IPluginContext *context, cell_t address)
{
	char *text;
	context->LocalToString(address, &text);
	return text;
}

bool HasPrefixIgnoringCase(const std::string &text, const char *prefix)
{
	size_t length = strlen(prefix);
	if (text.size() < length)
		return false;
	for (size_t i = 0; i < length; i++)
		if (tolower(static_cast<unsigned char>(text[i])) != prefix[i])
			return false;
	return true;
}

bool HasLineBreak(const std::string &text)
{
	return text.find_first_of("\r\n") != std::string::npos;
}

/* Reads a non-negative float argument in seconds. */
bool ReadSeconds(IPluginContext *context, cell_t value, const char *argumentName, bool mayBeZero, double &seconds)
{
	seconds = sp_ctof(value);
	if (seconds < 0.0 || (!mayBeZero && seconds == 0.0) || seconds != seconds) {
		context->ReportError("%s %f must be %s", argumentName, seconds, mayBeZero ? "0 or more" : "more than 0");
		return false;
	}
	return true;
}

/* The options a plugin must not set through websocket_setopt_*: the session
 * relies on them. */
bool IsControlledOption(CURLoption option)
{
	switch (option) {
	case CURLOPT_URL:
	case CURLOPT_CONNECT_ONLY:
	case CURLOPT_WS_OPTIONS:
	case CURLOPT_NOSIGNAL:
	case CURLOPT_NOPROGRESS:
		return true;
	default:
		return false;
	}
}

/* Reads a raw option argument of the given curl option types. */
bool ReadRawOption(IPluginContext *context, cell_t value, bool isString, CURLoption &option)
{
	option = static_cast<CURLoption>(value);
	const curl_easyoption *info = curl_easy_option_by_id(option);
	if (!info) {
		context->ReportError("Unknown CURLoption %d", value);
		return false;
	}
	bool isRightType = isString ? info->type == CURLOT_STRING
	                            : info->type == CURLOT_LONG || info->type == CURLOT_VALUES;
	if (!isRightType) {
		context->ReportError("CURLOPT_%s does not take %s", info->name, isString ? "a string" : "an integer");
		return false;
	}
	if (IsControlledOption(option)) {
		context->ReportError("CURLOPT_%s is set by the WebSocket itself", info->name);
		return false;
	}
	return true;
}

/* --- Callbacks --- */

IPluginFunction *CallbackOf(const WebSocket &socket, CallbackSlot slot)
{
	IPluginFunction *function = nullptr;
	if (socket.callbacks[slot] == kNoCallback)
		return nullptr;
	if (!socket.context->GetFunctionByIdOrNull(static_cast<funcid_t>(socket.callbacks[slot]), &function))
		return nullptr;
	return function;
}

/* Calls function with the WebSocket, the arguments pushArguments pushes and
 * the connection's data; returns the callback's result. */
template <typename PushArguments>
cell_t Call(WebSocket &socket, IPluginFunction *function, PushArguments pushArguments)
{
	cell_t result = 0;
	function->PushCell(static_cast<cell_t>(socket.handle));
	pushArguments(function);
	function->PushCell(socket.data);
	function->Execute(&result);
	return result;
}

/* Calls the callback of a payload event with a CurlBuffer that lives as
 * long as the call. */
template <typename PushBefore, typename PushAfter>
void CallWithBuffer(WebSocket &socket, IPluginFunction *function, std::string payload, PushBefore pushBefore,
                    PushAfter pushAfter)
{
	Handle_t buffer = CreateBuffer(socket.context, std::move(payload));
	if (!buffer)
		return;
	Call(socket, function, [&](IPluginFunction *f) {
		pushBefore(f);
		f->PushCell(static_cast<cell_t>(buffer));
		pushAfter(f);
	});
	FreeCallbackHandle(socket.context, buffer);
}

void Dispatch(WebSocket &socket, WsEvent &event)
{
	auto none = [](IPluginFunction *) {};
	switch (event.kind) {
	case WsEvent::Kind::Open:
		if (IPluginFunction *function = CallbackOf(socket, Slot_Open))
			Call(socket, function, none);
		break;
	case WsEvent::Kind::Message:
		if (IPluginFunction *function = CallbackOf(socket, Slot_Message))
			CallWithBuffer(socket, function, std::move(event.payload),
			               [&](IPluginFunction *f) { f->PushCell(event.type); }, none);
		break;
	case WsEvent::Kind::Frame:
		if (IPluginFunction *function = CallbackOf(socket, Slot_Frame))
			CallWithBuffer(socket, function, std::move(event.payload),
			               [&](IPluginFunction *f) { f->PushCell(event.type); },
			               [&](IPluginFunction *f) {
				               f->PushCell(static_cast<cell_t>(event.offset));
				               f->PushCell(static_cast<cell_t>(event.bytesLeft));
			               });
		break;
	case WsEvent::Kind::Pong:
		if (IPluginFunction *function = CallbackOf(socket, Slot_Pong))
			CallWithBuffer(socket, function, std::move(event.payload), none, none);
		break;
	case WsEvent::Kind::Reconnect: {
		bool proceed = true;
		if (IPluginFunction *function = CallbackOf(socket, Slot_Reconnect)) {
			cell_t action = Call(socket, function, [&](IPluginFunction *f) {
				f->PushCell(static_cast<cell_t>(event.error));
				f->PushCell(event.attempt);
				f->PushFloat(static_cast<float>(event.delay));
			});
			proceed = action != kPluginStop;
		}
		if (!socket.isDestroyed)
			socket.session->AnswerReconnect(proceed);
		break;
	}
	case WsEvent::Kind::Close:
		if (IPluginFunction *function = CallbackOf(socket, Slot_Close))
			Call(socket, function, [&](IPluginFunction *f) {
				f->PushCell(static_cast<cell_t>(event.error));
				f->PushCell(event.closeCode);
				f->PushString(event.reason.c_str());
			});
		break;
	}
}

/* --- Natives: setup --- */

// websocket_create(const char[] url)
cell_t WebSocket_Create(IPluginContext *context, const cell_t *params)
{
	std::string url = ReadString(context, params[1]);
	if (!HasPrefixIgnoringCase(url, "ws://") && !HasPrefixIgnoringCase(url, "wss://"))
		return context->ThrowNativeError("URL \"%s\" must start with ws:// or wss://", url.c_str());

	auto socket = std::make_shared<WebSocket>();
	socket->context = context;
	socket->config.url = std::move(url);
	auto *object = new HandleObject{socket};
	HandleError error;
	Handle_t handle = handlesys->CreateHandle(g_WebSocketType, object, context->GetIdentity(), myself_Identity, &error);
	if (!handle) {
		delete object;
		return context->ThrowNativeError("Cannot create a WebSocket handle (error %d)", error);
	}
	socket->handle = handle;
	return static_cast<cell_t>(handle);
}

// websocket_set_header(ws, const char[] name, const char[] value)
cell_t WebSocket_SetHeader(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (!socket)
		return 0;
	std::string name = ReadString(context, params[2]), value = ReadString(context, params[3]);
	if (name.empty() || name.find(':') != std::string::npos || HasLineBreak(name) || HasLineBreak(value))
		return context->ThrowNativeError("Invalid header \"%s\": the name must be non-empty without ':', and "
		                                 "neither may contain a line break", name.c_str());
	socket->config.headers.push_back(name + ": " + value);
	return 0;
}

// websocket_set_tls_verify(ws, bool verify)
cell_t WebSocket_SetTlsVerify(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket)
		socket->config.verifyTls = params[2] != 0;
	return 0;
}

// websocket_set_ca_file(ws, const char[] file)
cell_t WebSocket_SetCaFile(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (!socket)
		return 0;
	char path[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_Game, path, sizeof(path), "%s", ReadString(context, params[2]).c_str());
	socket->config.caFile = path;
	return 0;
}

// websocket_set_proxy(ws, const char[] proxy)
cell_t WebSocket_SetProxy(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket)
		socket->config.proxy = ReadString(context, params[2]);
	return 0;
}

// websocket_set_connect_timeout(ws, float seconds)
cell_t WebSocket_SetConnectTimeout(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket)
		ReadSeconds(context, params[2], "seconds", false, socket->config.connectTimeout);
	return 0;
}

// websocket_set_idle_timeout(ws, float seconds)
cell_t WebSocket_SetIdleTimeout(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket)
		ReadSeconds(context, params[2], "seconds", true, socket->config.idleTimeout);
	return 0;
}

// websocket_set_keepalive(ws, float interval, float timeout)
cell_t WebSocket_SetKeepalive(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	double interval, timeout;
	if (!socket || !ReadSeconds(context, params[2], "interval", true, interval) ||
	    !ReadSeconds(context, params[3], "timeout", true, timeout))
		return 0;
	socket->config.keepaliveInterval = interval;
	socket->config.keepaliveTimeout = timeout;
	return 0;
}

// websocket_set_reconnect(ws, bool enable, float initialDelay, float maxDelay, int maxAttempts)
cell_t WebSocket_SetReconnect(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	neocurl::WsReconnectConfig reconnect;
	if (!socket || !ReadSeconds(context, params[3], "initialDelay", false, reconnect.initialDelay) ||
	    !ReadSeconds(context, params[4], "maxDelay", false, reconnect.maxDelay))
		return 0;
	if (reconnect.maxDelay < reconnect.initialDelay)
		return context->ThrowNativeError("maxDelay %f is less than initialDelay %f", reconnect.maxDelay,
		                                 reconnect.initialDelay);
	if (params[5] < 0)
		return context->ThrowNativeError("maxAttempts %d is negative", params[5]);
	reconnect.isEnabled = params[2] != 0;
	reconnect.maxAttempts = params[5];
	socket->config.reconnect = reconnect;
	return 0;
}

// websocket_set_frame_mode(ws, bool frames)
cell_t WebSocket_SetFrameMode(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket)
		socket->config.isFrameMode = params[2] != 0;
	return 0;
}

// websocket_set_max_message_size(ws, int bytes)
cell_t WebSocket_SetMaxMessageSize(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (!socket)
		return 0;
	if (params[2] < 1 || static_cast<size_t>(params[2]) > g_BufferMaxBytes)
		return context->ThrowNativeError("Maximum message size %d is outside 1-%u (CurlBufferMaxBytes)", params[2],
		                                 static_cast<unsigned>(g_BufferMaxBytes));
	socket->config.maxMessageSize = static_cast<size_t>(params[2]);
	return 0;
}

// websocket_set_max_send_queue(ws, int bytes)
cell_t WebSocket_SetMaxSendQueue(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (!socket)
		return 0;
	if (params[2] < 1)
		return context->ThrowNativeError("Maximum send queue %d must be at least 1", params[2]);
	socket->config.maxSendQueue = static_cast<size_t>(params[2]);
	return 0;
}

// websocket_setopt_int(ws, CURLoption option, int value)
cell_t WebSocket_SetOptInt(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	CURLoption option;
	if (socket && ReadRawOption(context, params[2], false, option))
		socket->config.intOptions.emplace_back(option, static_cast<long>(params[3]));
	return 0;
}

// websocket_setopt_string(ws, CURLoption option, const char[] value)
cell_t WebSocket_SetOptString(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	CURLoption option;
	if (socket && ReadRawOption(context, params[2], true, option))
		socket->config.stringOptions.emplace_back(option, ReadString(context, params[3]));
	return 0;
}

/* websocket_set_on_*(ws, callback) */
template <CallbackSlot slot>
cell_t WebSocket_SetCallback(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadUnconnected(context, params[1]);
	if (socket && ReadCallback(context, params[2], "callback"))
		socket->callbacks[slot] = params[2];
	return 0;
}

// websocket_connect(ws, any data)
cell_t WebSocket_Connect(IPluginContext *context, const cell_t *params)
{
	HandleObject *object;
	HandleSecurity security(context->GetIdentity(), myself_Identity);
	HandleError error = handlesys->ReadHandle(static_cast<Handle_t>(params[1]), g_WebSocketType, &security,
	                                          reinterpret_cast<void **>(&object));
	if (error != HandleError_None)
		return context->ThrowNativeError("Invalid WebSocket handle %x (error %d)", params[1], error);
	std::shared_ptr<WebSocket> socket = object->socket;
	if (socket->session)
		return context->ThrowNativeError("The WebSocket is connected already; create a new one to connect again");

	socket->data = params[2];
	socket->session = std::make_shared<WsSession>(socket->config);
	socket->session->Start();
	g_Live.push_back(socket);
	return 0;
}

/* --- Natives: connected --- */

/* Copies a payload argument; false (after a native error) when it is not
 * valid. */
bool ReadPayload(IPluginContext *context, cell_t address, cell_t length, std::string &payload)
{
	try {
		return ReadBytes(context, address, length, "data", payload);
	} catch (const std::bad_alloc &) {
		context->ReportError("Out of memory copying the data");
		return false;
	}
}

// websocket_send_text(ws, const char[] text)
cell_t WebSocket_SendText(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadConnected(context, params[1]);
	std::string payload;
	if (!socket || !ReadPayload(context, params[2], -1, payload))
		return 0;
	return socket->session->Send(WsMessageType::Text, std::move(payload));
}

// websocket_send_binary(ws, const char[] data, int length)
cell_t WebSocket_SendBinary(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadConnected(context, params[1]);
	std::string payload;
	if (!socket)
		return 0;
	if (params[3] < 0)
		return context->ThrowNativeError("length %d is negative", params[3]);
	if (!ReadPayload(context, params[2], params[3], payload))
		return 0;
	return socket->session->Send(WsMessageType::Binary, std::move(payload));
}

// websocket_send_buffer(ws, buffer, bool binary)
cell_t WebSocket_SendBuffer(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadConnected(context, params[1]);
	CurlBuffer *buffer = socket ? ReadBuffer(context, params[2]) : nullptr;
	if (!buffer)
		return 0;
	std::string payload;
	try {
		payload = buffer->bytes;
	} catch (const std::bad_alloc &) {
		return context->ThrowNativeError("Out of memory copying the buffer");
	}
	return socket->session->Send(params[3] ? WsMessageType::Binary : WsMessageType::Text, std::move(payload));
}

// websocket_ping(ws, const char[] payload, int length)
cell_t WebSocket_Ping(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadConnected(context, params[1]);
	std::string payload;
	if (!socket || !ReadPayload(context, params[2], params[3], payload))
		return 0;
	if (payload.size() > neocurl::kMaxControlPayload)
		return context->ThrowNativeError("A ping payload has at most %u bytes, not %u",
		                                 static_cast<unsigned>(neocurl::kMaxControlPayload),
		                                 static_cast<unsigned>(payload.size()));
	return socket->session->Ping(std::move(payload));
}

/* Close codes a plugin may send (RFC 6455 section 7.4): 1000-1003 and
 * 1007-1014 of the protocol, 3000-4999 of applications. */
bool IsSendableCloseCode(cell_t code)
{
	return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1014) || (code >= 3000 && code <= 4999);
}

// websocket_close(ws, int code, const char[] reason)
cell_t WebSocket_Close(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadConnected(context, params[1]);
	if (!socket)
		return 0;
	if (!IsSendableCloseCode(params[2]))
		return context->ThrowNativeError("Close code %d is not 1000-1003, 1007-1014 or 3000-4999", params[2]);
	std::string reason = ReadString(context, params[3]);
	constexpr size_t kMaxReason = neocurl::kMaxControlPayload - 2;
	if (reason.size() > kMaxReason)
		return context->ThrowNativeError("A close reason has at most %u bytes, not %u",
		                                 static_cast<unsigned>(kMaxReason), static_cast<unsigned>(reason.size()));
	socket->session->Close(params[2], std::move(reason));
	return 0;
}

// websocket_get_state(ws)
cell_t WebSocket_GetState(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadWebSocket(context, params[1]);
	if (!socket || !socket->session)
		return static_cast<cell_t>(WsState::Idle);
	return static_cast<cell_t>(socket->session->State());
}

// websocket_get_url(ws, char[] buffer, int maxlength)
cell_t WebSocket_GetUrl(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadWebSocket(context, params[1]);
	if (!socket)
		return 0;
	// Stays 0 for a maxlength of 0: nothing is written then, not even this.
	size_t written = 0;
	context->StringToLocalUTF8(params[2], params[3], socket->config.url.c_str(), &written);
	return static_cast<cell_t>(written);
}

// websocket_get_queued_bytes(ws)
cell_t WebSocket_GetQueuedBytes(IPluginContext *context, const cell_t *params)
{
	WebSocket *socket = ReadWebSocket(context, params[1]);
	if (!socket || !socket->session)
		return 0;
	return static_cast<cell_t>(socket->session->QueuedBytes());
}

} // namespace

void WebSocketsOnFrame()
{
	/* A copy: callbacks may connect or free WebSockets. */
	std::vector<std::shared_ptr<WebSocket>> live = g_Live;
	for (const std::shared_ptr<WebSocket> &socket : live) {
		if (socket->isDestroyed)
			continue;
		/* Checked first: a finished session queues no more events. */
		bool isFinished = socket->session->IsFinished();
		for (WsEvent &event : socket->session->TakeEvents()) {
			Dispatch(*socket, event);
			if (socket->isDestroyed)
				break;
		}
		if (isFinished && !socket->isDestroyed) {
			socket->session->Stop();
			g_Live.erase(std::remove(g_Live.begin(), g_Live.end(), socket), g_Live.end());
		}
	}

	g_Retiring.erase(std::remove_if(g_Retiring.begin(), g_Retiring.end(),
	                                [](const std::shared_ptr<WsSession> &session) {
		                                if (!session->IsFinished())
			                                return false;
		                                session->Stop();
		                                return true;
	                                }),
	                 g_Retiring.end());
}

void WebSocketsOnHandleDestroy(void *object)
{
	HandleObject *handleObject = static_cast<HandleObject *>(object);
	std::shared_ptr<WebSocket> socket = handleObject->socket;
	delete handleObject;

	socket->isDestroyed = true;
	if (!socket->session)
		return;
	socket->session->RequestStop();
	/* An unanswered reconnect would keep the thread waiting. */
	socket->session->AnswerReconnect(false);
	g_Retiring.push_back(socket->session);
	g_Live.erase(std::remove(g_Live.begin(), g_Live.end(), socket), g_Live.end());
}

void WebSocketsShutdown()
{
	for (const std::shared_ptr<WebSocket> &socket : g_Live)
		socket->session->RequestStop();
	for (const std::shared_ptr<WsSession> &session : g_Retiring)
		session->RequestStop();
	for (const std::shared_ptr<WebSocket> &socket : g_Live)
		socket->session->Stop();
	for (const std::shared_ptr<WsSession> &session : g_Retiring)
		session->Stop();
	g_Live.clear();
	g_Retiring.clear();
}

const sp_nativeinfo_t g_WebSocketNatives[] = {
	{"websocket_create",               WebSocket_Create},
	{"websocket_set_header",           WebSocket_SetHeader},
	{"websocket_set_tls_verify",       WebSocket_SetTlsVerify},
	{"websocket_set_ca_file",          WebSocket_SetCaFile},
	{"websocket_set_proxy",            WebSocket_SetProxy},
	{"websocket_set_connect_timeout",  WebSocket_SetConnectTimeout},
	{"websocket_set_idle_timeout",     WebSocket_SetIdleTimeout},
	{"websocket_set_keepalive",        WebSocket_SetKeepalive},
	{"websocket_set_reconnect",        WebSocket_SetReconnect},
	{"websocket_set_frame_mode",       WebSocket_SetFrameMode},
	{"websocket_set_max_message_size", WebSocket_SetMaxMessageSize},
	{"websocket_set_max_send_queue",   WebSocket_SetMaxSendQueue},
	{"websocket_setopt_int",           WebSocket_SetOptInt},
	{"websocket_setopt_string",        WebSocket_SetOptString},
	{"websocket_set_on_open",          WebSocket_SetCallback<Slot_Open>},
	{"websocket_set_on_message",       WebSocket_SetCallback<Slot_Message>},
	{"websocket_set_on_frame",         WebSocket_SetCallback<Slot_Frame>},
	{"websocket_set_on_pong",          WebSocket_SetCallback<Slot_Pong>},
	{"websocket_set_on_reconnect",     WebSocket_SetCallback<Slot_Reconnect>},
	{"websocket_set_on_close",         WebSocket_SetCallback<Slot_Close>},
	{"websocket_connect",              WebSocket_Connect},
	{"websocket_send_text",            WebSocket_SendText},
	{"websocket_send_binary",          WebSocket_SendBinary},
	{"websocket_send_buffer",          WebSocket_SendBuffer},
	{"websocket_ping",                 WebSocket_Ping},
	{"websocket_close",                WebSocket_Close},
	{"websocket_get_state",            WebSocket_GetState},
	{"websocket_get_url",              WebSocket_GetUrl},
	{"websocket_get_queued_bytes",     WebSocket_GetQueuedBytes},
	{nullptr,                          nullptr},
};

} // namespace api
