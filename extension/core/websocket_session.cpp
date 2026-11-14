/* The thread of a WebSocket connection. libcurl's connect-only mode makes the
 * handshake in curl_easy_perform(); after it the thread waits on the socket
 * in short slices, so that queued sends, keepalive pings, timeouts and stop
 * requests are seen within kSliceMs. */
#include "websocket_session.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>

namespace neocurl {

namespace {

using Clock = std::chrono::steady_clock;

constexpr int kSliceMs = 10;
constexpr size_t kReceiveChunk = 64 * 1024;
/* How long a local close waits for the peer's close frame. */
constexpr double kCloseHandshakeTimeout = 5.0;
/* How long a send may stay blocked on a full socket. */
constexpr double kSendTimeout = 30.0;

double SecondsSince(Clock::time_point since)
{
	return std::chrono::duration<double>(Clock::now() - since).count();
}

/* Waits until the socket is readable (or writable) or timeoutMs passed. */
void WaitSocket(curl_socket_t socket, bool forWrite, int timeoutMs)
{
#ifdef _WIN32
	fd_set set;
	FD_ZERO(&set);
	FD_SET(socket, &set);
	timeval timeout = {0, timeoutMs * 1000};
	select(0, forWrite ? nullptr : &set, forWrite ? &set : nullptr, nullptr, &timeout);
#else
	pollfd entry = {socket, static_cast<short>(forWrite ? POLLOUT : POLLIN), 0};
	poll(&entry, 1, timeoutMs);
#endif
}

curl_socket_t ActiveSocket(CURL *curl)
{
	curl_socket_t socket = CURL_SOCKET_BAD;
	curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &socket);
	return socket;
}

/* The payload of a close frame: the code big-endian, then the reason. */
std::string ClosePayload(int code, const std::string &reason)
{
	std::string payload;
	payload += static_cast<char>((code >> 8) & 0xff);
	payload += static_cast<char>(code & 0xff);
	payload += reason;
	return payload;
}

} // namespace

WsSession::WsSession(WsConfig config) : m_config(std::move(config)), m_receiveBuffer(kReceiveChunk)
{
}

WsSession::~WsSession()
{
	Stop();
}

void WsSession::Start()
{
	m_state = WsState::Connecting;
	m_thread = std::thread(&WsSession::Run, this);
}

bool WsSession::Send(WsMessageType type, std::string payload)
{
	unsigned int flags = type == WsMessageType::Binary ? CURLWS_BINARY : CURLWS_TEXT;
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_isCloseRequested || m_isStopping || m_isFinished)
		return false;
	if (m_queuedBytes + payload.size() > m_config.maxSendQueue)
		return false;
	m_queuedBytes += payload.size();
	m_outgoing.push_back(Outgoing{flags, std::move(payload)});
	return true;
}

bool WsSession::Ping(std::string payload)
{
	if (payload.size() > kMaxControlPayload)
		return false;
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_isCloseRequested || m_isStopping || m_isFinished)
		return false;
	m_outgoing.push_back(Outgoing{CURLWS_PING, std::move(payload)});
	return true;
}

void WsSession::Close(int code, std::string reason)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_isCloseRequested)
			return;
		m_isCloseRequested = true;
		m_closeCode = code;
		m_closeReason = std::move(reason);
	}
	m_wakeUp.notify_all();
}

void WsSession::AnswerReconnect(bool proceed)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_reconnectAnswer = proceed ? 1 : -1;
	}
	m_wakeUp.notify_all();
}

std::vector<WsEvent> WsSession::TakeEvents()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_undeliveredBytes = 0;
	return std::exchange(m_events, {});
}

void WsSession::RequestStop()
{
	m_isStopping = true;
	m_wakeUp.notify_all();
}

void WsSession::Stop()
{
	RequestStop();
	if (m_thread.joinable())
		m_thread.join();
}

size_t WsSession::QueuedBytes()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_queuedBytes;
}

void WsSession::Run()
{
	const WsReconnectConfig &reconnect = m_config.reconnect;
	int attempt = 0;
	for (;;) {
		CURLcode error = CURLE_OK;
		bool wasOpen = false;
		if (RunConnection(error, wasOpen) != Ending::Failed)
			break;

		DropOutgoing();
		if (wasOpen)
			attempt = 0;
		bool mayRetry = reconnect.isEnabled && !IsCloseRequested() &&
		                (reconnect.maxAttempts == 0 || attempt < reconnect.maxAttempts);
		if (!mayRetry) {
			PostClose(error, kCloseAbnormal, std::string());
			break;
		}

		attempt++;
		double delay = std::min(reconnect.initialDelay * std::pow(2.0, attempt - 1), reconnect.maxDelay);
		m_state = WsState::Reconnecting;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_reconnectAnswer = 0;
		}
		WsEvent event{WsEvent::Kind::Reconnect};
		event.error = error;
		event.attempt = attempt;
		event.delay = delay;
		Post(std::move(event));

		if (!AwaitReconnectAnswer() || !WaitBeforeReconnect(delay)) {
			if (IsCloseRequested()) {
				PostLocalClose();
			} else {
				PostClose(error, kCloseAbnormal, std::string());
			}
			break;
		}
	}
	m_state = WsState::Closed;
	m_isFinished = true;
}

WsSession::Ending WsSession::RunConnection(CURLcode &error, bool &wasOpen)
{
	m_state = WsState::Connecting;
	curl_slist *headers = nullptr;
	CURL *curl = CreateHandle(headers);
	if (!curl) {
		curl_slist_free_all(headers);
		error = CURLE_OUT_OF_MEMORY;
		return Ending::Failed;
	}

	Ending ending;
	CURLcode result = curl_easy_perform(curl);
	if (result == CURLE_OK) {
		wasOpen = true;
		m_isInMessage = false;
		m_message.clear();
		m_control.clear();
		m_state = WsState::Open;
		Post(WsEvent{WsEvent::Kind::Open});
		ending = Converse(curl, error);
	} else if (m_isStopping) {
		ending = Ending::Stopped;
	} else if (IsCloseRequested()) {
		PostLocalClose();
		ending = Ending::Closed;
	} else {
		error = result;
		ending = Ending::Failed;
	}

	curl_easy_cleanup(curl);
	curl_slist_free_all(headers);
	return ending;
}

CURL *WsSession::CreateHandle(curl_slist *&headers)
{
	CURL *curl = curl_easy_init();
	if (!curl)
		return nullptr;

	long timeoutMs = static_cast<long>(m_config.connectTimeout * 1000.0);
	curl_easy_setopt(curl, CURLOPT_URL, m_config.url.c_str());
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeoutMs);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, m_config.verifyTls ? 1L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_config.verifyTls ? 2L : 0L);
	/* The Windows certificate store on Windows; no effect elsewhere. */
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
	if (!m_config.caFile.empty())
		curl_easy_setopt(curl, CURLOPT_CAINFO, m_config.caFile.c_str());
	if (!m_config.proxy.empty())
		curl_easy_setopt(curl, CURLOPT_PROXY, m_config.proxy.c_str());
	/* The progress callback lets a stop or close end a pending handshake. */
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, &WsSession::OnProgress);
	curl_easy_setopt(curl, CURLOPT_XFERINFODATA, this);

	for (const std::string &header : m_config.headers)
		headers = curl_slist_append(headers, header.c_str());
	if (headers)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	for (const auto &option : m_config.intOptions)
		curl_easy_setopt(curl, option.first, option.second);
	for (const auto &option : m_config.stringOptions)
		curl_easy_setopt(curl, option.first, option.second.c_str());
	return curl;
}

int WsSession::OnProgress(void *session, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
	WsSession *self = static_cast<WsSession *>(session);
	return self->m_isStopping || self->IsCloseRequested() ? 1 : 0;
}

WsSession::Ending WsSession::Converse(CURL *curl, CURLcode &error)
{
	curl_socket_t socket = ActiveSocket(curl);
	Clock::time_point lastReceive = Clock::now();
	Clock::time_point lastPing = Clock::now();
	bool isAwaitingPong = false;
	double keepaliveTimeout = m_config.keepaliveTimeout > 0.0 ? m_config.keepaliveTimeout : m_config.keepaliveInterval;

	for (;;) {
		if (m_isStopping) {
			SendClose(curl, kCloseGoingAway, std::string());
			return Ending::Stopped;
		}
		if (IsCloseRequested()) {
			m_state = WsState::Closing;
			int code;
			std::string reason;
			{
				std::lock_guard<std::mutex> lock(m_mutex);
				code = m_closeCode;
				reason = m_closeReason;
			}
			SendClose(curl, code, reason);
			AwaitPeerClose(curl);
			PostLocalClose();
			return Ending::Closed;
		}

		Outgoing outgoing;
		while (TakeOutgoing(outgoing)) {
			CURLcode result = SendFrame(curl, outgoing.payload, outgoing.flags);
			if (result != CURLE_OK) {
				error = result;
				return Ending::Failed;
			}
		}

		if (m_config.keepaliveInterval > 0.0) {
			if (isAwaitingPong && SecondsSince(lastPing) > keepaliveTimeout) {
				error = CURLE_OPERATION_TIMEDOUT;
				return Ending::Failed;
			}
			if (!isAwaitingPong && SecondsSince(lastPing) >= m_config.keepaliveInterval) {
				CURLcode result = SendFrame(curl, std::string(), CURLWS_PING);
				if (result != CURLE_OK) {
					error = result;
					return Ending::Failed;
				}
				isAwaitingPong = true;
				lastPing = Clock::now();
			}
		}
		if (m_config.idleTimeout > 0.0 && SecondsSince(lastReceive) > m_config.idleTimeout) {
			error = CURLE_OPERATION_TIMEDOUT;
			return Ending::Failed;
		}

		bool isBackedUp;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			isBackedUp = m_undeliveredBytes >= m_config.maxMessageSize;
		}
		WaitSocket(socket, false, kSliceMs);
		if (isBackedUp)
			continue;

		bool hasReceived = false, hasReceivedPong = false;
		Step step = ReceiveAvailable(curl, error, hasReceived, hasReceivedPong);
		if (hasReceived)
			lastReceive = Clock::now();
		if (hasReceivedPong)
			isAwaitingPong = false;
		if (step == Step::Closed)
			return Ending::Closed;
		if (step == Step::Failed)
			return Ending::Failed;
	}
}

WsSession::Step WsSession::ReceiveAvailable(CURL *curl, CURLcode &error, bool &hasReceived, bool &hasReceivedPong)
{
	for (;;) {
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_undeliveredBytes >= m_config.maxMessageSize)
				return Step::Continue;
		}

		size_t length = 0;
		const curl_ws_frame *meta = nullptr;
		CURLcode result = curl_ws_recv(curl, m_receiveBuffer.data(), m_receiveBuffer.size(), &length, &meta);
		if (result == CURLE_AGAIN)
			return Step::Continue;
		if (result != CURLE_OK) {
			error = result;
			return Step::Failed;
		}
		hasReceived = true;
		Step step = ReceiveChunk(curl, *meta, m_receiveBuffer.data(), length, hasReceivedPong);
		if (step != Step::Continue)
			return step;
	}
}

WsSession::Step WsSession::ReceiveChunk(CURL *curl, const curl_ws_frame &meta, const char *data, size_t length,
                                        bool &hasReceivedPong)
{
	/* libcurl answers pings by itself. */
	if (meta.flags & CURLWS_PING)
		return Step::Continue;

	if (meta.flags & (CURLWS_PONG | CURLWS_CLOSE)) {
		m_control.append(data, length);
		if (meta.bytesleft > 0)
			return Step::Continue;
		std::string payload = std::exchange(m_control, std::string());
		if (meta.flags & CURLWS_PONG) {
			hasReceivedPong = true;
			WsEvent event{WsEvent::Kind::Pong};
			event.payload = std::move(payload);
			Post(std::move(event));
			return Step::Continue;
		}
		int code = kCloseNoStatus;
		std::string reason;
		if (payload.size() >= 2) {
			code = (static_cast<unsigned char>(payload[0]) << 8) | static_cast<unsigned char>(payload[1]);
			reason = payload.substr(2);
		}
		m_state = WsState::Closing;
		SendClose(curl, code == kCloseNoStatus ? 1000 : code, std::string());
		PostClose(CURLE_OK, code, std::move(reason));
		return Step::Closed;
	}

	if (m_config.isFrameMode) {
		WsEvent event{WsEvent::Kind::Frame};
		event.type = meta.flags;
		event.payload.assign(data, length);
		event.offset = meta.offset;
		event.bytesLeft = meta.bytesleft;
		Post(std::move(event));
		return Step::Continue;
	}

	if (!m_isInMessage) {
		m_isInMessage = true;
		m_messageType = static_cast<int>((meta.flags & CURLWS_BINARY) ? WsMessageType::Binary : WsMessageType::Text);
		m_message.clear();
	}
	if (m_message.size() + length > m_config.maxMessageSize) {
		static const char kTooBigReason[] = "message too big";
		m_state = WsState::Closing;
		SendClose(curl, kCloseTooBig, kTooBigReason);
		PostClose(CURLE_OK, kCloseTooBig, kTooBigReason);
		return Step::Closed;
	}
	m_message.append(data, length);

	bool isMessageComplete = meta.bytesleft == 0 && !(meta.flags & CURLWS_CONT);
	if (isMessageComplete) {
		WsEvent event{WsEvent::Kind::Message};
		event.type = m_messageType;
		event.payload = std::exchange(m_message, std::string());
		m_isInMessage = false;
		Post(std::move(event));
	}
	return Step::Continue;
}

/* curl_ws_send() may take part of a frame; the rest is passed again until
 * all of it went out. */
CURLcode WsSession::SendFrame(CURL *curl, const std::string &payload, unsigned int flags)
{
	curl_socket_t socket = ActiveSocket(curl);
	Clock::time_point start = Clock::now();
	size_t offset = 0;
	do {
		size_t sent = 0;
		CURLcode result = curl_ws_send(curl, payload.data() + offset, payload.size() - offset, &sent, 0, flags);
		offset += sent;
		if (result == CURLE_AGAIN) {
			if (m_isStopping || SecondsSince(start) > kSendTimeout)
				return CURLE_OPERATION_TIMEDOUT;
			WaitSocket(socket, true, kSliceMs);
			continue;
		}
		if (result != CURLE_OK)
			return result;
	} while (offset < payload.size());
	return CURLE_OK;
}

void WsSession::SendClose(CURL *curl, int code, const std::string &reason)
{
	SendFrame(curl, ClosePayload(code, reason), CURLWS_CLOSE);
}

/* Reads until the peer's close frame, an error or the timeout; what else
 * arrives is dropped. */
void WsSession::AwaitPeerClose(CURL *curl)
{
	curl_socket_t socket = ActiveSocket(curl);
	Clock::time_point start = Clock::now();
	while (!m_isStopping && SecondsSince(start) < kCloseHandshakeTimeout) {
		size_t length = 0;
		const curl_ws_frame *meta = nullptr;
		CURLcode result = curl_ws_recv(curl, m_receiveBuffer.data(), m_receiveBuffer.size(), &length, &meta);
		if (result == CURLE_AGAIN) {
			WaitSocket(socket, false, kSliceMs);
			continue;
		}
		if (result != CURLE_OK || ((meta->flags & CURLWS_CLOSE) && meta->bytesleft == 0))
			return;
	}
}

bool WsSession::AwaitReconnectAnswer()
{
	std::unique_lock<std::mutex> lock(m_mutex);
	m_wakeUp.wait(lock, [this] { return m_reconnectAnswer != 0 || m_isStopping || m_isCloseRequested; });
	return m_reconnectAnswer == 1 && !m_isStopping && !m_isCloseRequested;
}

bool WsSession::WaitBeforeReconnect(double delay)
{
	std::unique_lock<std::mutex> lock(m_mutex);
	auto until = Clock::now() + std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(delay));
	m_wakeUp.wait_until(lock, until, [this] { return m_isStopping || m_isCloseRequested; });
	return !m_isStopping && !m_isCloseRequested;
}

bool WsSession::TakeOutgoing(Outgoing &outgoing)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_outgoing.empty())
		return false;
	outgoing = std::move(m_outgoing.front());
	m_outgoing.pop_front();
	if (outgoing.flags & (CURLWS_TEXT | CURLWS_BINARY))
		m_queuedBytes -= outgoing.payload.size();
	return true;
}

void WsSession::DropOutgoing()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_outgoing.clear();
	m_queuedBytes = 0;
}

void WsSession::Post(WsEvent event)
{
	if (m_isStopping)
		return;
	std::lock_guard<std::mutex> lock(m_mutex);
	m_undeliveredBytes += event.payload.size();
	m_events.push_back(std::move(event));
}

void WsSession::PostClose(CURLcode error, int code, std::string reason)
{
	WsEvent event{WsEvent::Kind::Close};
	event.error = error;
	event.closeCode = code;
	event.reason = std::move(reason);
	Post(std::move(event));
}

void WsSession::PostLocalClose()
{
	int code;
	std::string reason;
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		code = m_closeCode;
		reason = m_closeReason;
	}
	PostClose(CURLE_OK, code, std::move(reason));
}

bool WsSession::IsCloseRequested()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_isCloseRequested;
}

} // namespace neocurl
