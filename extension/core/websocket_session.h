/* A WebSocket connection run by a thread of its own with libcurl: it
 * connects, reconnects after errors when asked to, sends what the main
 * thread queued and queues what arrives as events for the main thread.
 * Nothing here knows SourceMod. */
#ifndef NEOCURL_CORE_WEBSOCKET_SESSION_H
#define NEOCURL_CORE_WEBSOCKET_SESSION_H

#include <curl/curl.h>
#include <stdint.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace neocurl {

/* The values are the plugin API's WebSocketState (curl_websocket.inc) and
 * must stay in that order. */
enum class WsState {
	Idle = 0,
	Connecting,
	Open,
	Reconnecting,
	Closing,
	Closed,
};

/* The values are the plugin API's WebSocketMessageType. */
enum class WsMessageType {
	Text = 0,
	Binary,
};

/* The close code of a connection that ended without a close frame. */
constexpr int kCloseAbnormal = 1006;
/* The close code sent when a message exceeds the maximum size. */
constexpr int kCloseTooBig = 1009;
/* The close code sent when the connection's Handle is closed. */
constexpr int kCloseGoingAway = 1001;
/* The close code reported for a close frame without one. */
constexpr int kCloseNoStatus = 1005;
/* A control frame's payload (ping, pong, close) is at most this long. */
constexpr size_t kMaxControlPayload = 125;

struct WsReconnectConfig {
	bool isEnabled = false;
	double initialDelay = 1.0;
	double maxDelay = 60.0;
	/* 0: no limit. */
	int maxAttempts = 0;
};

/* Everything a connection is set up with; fixed once it started. */
struct WsConfig {
	std::string url;
	/* "Name: value" lines for the handshake. */
	std::vector<std::string> headers;
	bool verifyTls = true;
	/* Absolute path, or empty for the default CA store. */
	std::string caFile;
	std::string proxy;
	double connectTimeout = 30.0;
	/* 0: off. */
	double idleTimeout = 0.0;
	/* 0: off. */
	double keepaliveInterval = 0.0;
	double keepaliveTimeout = 0.0;
	WsReconnectConfig reconnect;
	/* Deliver frames as they arrive instead of whole messages. */
	bool isFrameMode = false;
	size_t maxMessageSize = 1024 * 1024;
	size_t maxSendQueue = 1024 * 1024;
	std::vector<std::pair<CURLoption, long>> intOptions;
	std::vector<std::pair<CURLoption, std::string>> stringOptions;
};

struct WsEvent {
	enum class Kind {
		Open,
		Message,
		Frame,
		Pong,
		Reconnect,
		Close,
	};

	Kind kind;
	/* Message: the WsMessageType; Frame: the CURLWS_* flags. */
	int type = 0;
	std::string payload;
	/* Frame: where payload starts in the frame and how much of it follows. */
	int64_t offset = 0;
	int64_t bytesLeft = 0;
	/* Reconnect and Close: the error that ended the connection, CURLE_OK for
	 * a closing handshake. */
	CURLcode error = CURLE_OK;
	/* Reconnect: the attempt number (from 1) and its delay in seconds. */
	int attempt = 0;
	double delay = 0.0;
	/* Close: the close frame's code and reason. */
	int closeCode = 0;
	std::string reason;
};

class WsSession {
public:
	explicit WsSession(WsConfig config);
	/* Stops like Stop(). */
	~WsSession();
	WsSession(const WsSession &) = delete;
	WsSession &operator=(const WsSession &) = delete;

	/* Starts the connection's thread. */
	void Start();

	/* Queues a message; false when the session no longer sends or the queue
	 * would exceed the maximum. */
	bool Send(WsMessageType type, std::string payload);

	/* Queues a ping with a payload of at most kMaxControlPayload bytes. */
	bool Ping(std::string payload);

	/* Starts the closing handshake; the session ends with a Close event. */
	void Close(int code, std::string reason);

	/* Answers the last Reconnect event: whether to go on. */
	void AnswerReconnect(bool proceed);

	/* The events since the last call, in order. */
	std::vector<WsEvent> TakeEvents();

	/* Ends the connection with a close frame (going away) and no more
	 * events, without waiting for the thread. */
	void RequestStop();

	/* RequestStop() and waits for the thread. */
	void Stop();

	/* Whether the thread has ended (and Stop() returns at once). */
	bool IsFinished() const { return m_isFinished; }

	WsState State() const { return m_state; }
	size_t QueuedBytes();

private:
	/* How one connection ended. */
	enum class Ending {
		/* A Close event was queued; the session is over. */
		Closed,
		/* RequestStop(); no event. */
		Stopped,
		/* An error; reconnect or give up. */
		Failed,
	};

	struct Outgoing {
		unsigned int flags;
		std::string payload;
	};

	void Run();
	Ending RunConnection(CURLcode &error, bool &wasOpen);
	CURL *CreateHandle(curl_slist *&headers);
	Ending Converse(CURL *curl, CURLcode &error);
	/* Ending::Failed or Closed end the connection; Continue goes on. */
	enum class Step {
		Continue,
		Closed,
		Failed,
	};
	Step ReceiveAvailable(CURL *curl, CURLcode &error, bool &hasReceived, bool &hasReceivedPong);
	Step ReceiveChunk(CURL *curl, const curl_ws_frame &meta, const char *data, size_t length,
	                  bool &hasReceivedPong);
	CURLcode SendFrame(CURL *curl, const std::string &payload, unsigned int flags);
	void SendClose(CURL *curl, int code, const std::string &reason);
	void AwaitPeerClose(CURL *curl);
	bool WaitBeforeReconnect(double delay);
	bool AwaitReconnectAnswer();
	bool TakeOutgoing(Outgoing &outgoing);
	void DropOutgoing();
	void Post(WsEvent event);
	void PostClose(CURLcode error, int code, std::string reason);
	/* The Close event of a close the plugin asked for. */
	void PostLocalClose();
	bool IsCloseRequested();

	static int OnProgress(void *session, curl_off_t, curl_off_t, curl_off_t, curl_off_t);

	const WsConfig m_config;
	std::thread m_thread;
	std::atomic<WsState> m_state{WsState::Idle};
	std::atomic<bool> m_isStopping{false};
	std::atomic<bool> m_isFinished{false};

	std::mutex m_mutex;
	std::condition_variable m_wakeUp;
	std::deque<Outgoing> m_outgoing;
	size_t m_queuedBytes = 0;
	std::vector<WsEvent> m_events;
	/* Payload bytes queued as events and not taken yet. */
	size_t m_undeliveredBytes = 0;
	bool m_isCloseRequested = false;
	int m_closeCode = 0;
	std::string m_closeReason;
	/* 0: no answer yet, 1: go on, -1: give up. */
	int m_reconnectAnswer = 0;

	/* The message or control frame being received. */
	std::string m_message;
	int m_messageType = 0;
	bool m_isInMessage = false;
	std::string m_control;
	std::vector<char> m_receiveBuffer;
};

} // namespace neocurl

#endif // NEOCURL_CORE_WEBSOCKET_SESSION_H
