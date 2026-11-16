#if defined _curl_websocket_included
  #endinput
#endif
#define _curl_websocket_included

#include <cURL>

/**
 * WebSocket: a WebSocket client connection (ws:// and wss://), run by a
 * thread of the extension per connection. The plugin sets the options and
 * callbacks, then connects; every server frame, what happened since is
 * delivered to the callbacks, in order.
 *
 * - Whole-message mode (the default) reassembles fragmented messages and
 *   calls OnMessage once per text or binary message. Frame mode calls
 *   OnFrame for every piece of a frame as it arrives instead.
 * - libcurl answers pings by itself. Pongs (to the plugin's and keepalive
 *   pings) reach OnPong.
 * - Sends are queued and sent by the connection's thread; a send that would
 *   exceed the send queue's maximum fails. Messages queued while connecting
 *   are sent once open; unsent ones are dropped when a connection is lost
 *   and when the plugin closes the WebSocket.
 * - When the received but undelivered data reaches the maximum message size,
 *   the thread stops reading until the plugin got it, which slows the peer.
 * - With reconnecting on, a connection lost through an error (not a closing
 *   handshake) is opened again after a delay that doubles with every failed
 *   attempt. OnReconnect is called for every scheduled attempt and may give
 *   up; OnClose is called only when the WebSocket is closed for good.
 * - Closing the handle (delete) ends the connection, with close code 1001
 *   when it is open, and no callback is called anymore. So does unloading
 *   the plugin.
 *
 * One handle is one WebSocket: after OnClose, create a new one to connect
 * again. All options and callbacks must be set before Connect().
 *
 * See docs/websocket.md.
 */

enum WebSocketState
{
	WebSocketState_Idle = 0,      /**< Not connected yet. */
	WebSocketState_Connecting,    /**< Connecting and in the handshake. */
	WebSocketState_Open,          /**< Open: messages flow. */
	WebSocketState_Reconnecting,  /**< Lost through an error; waiting to connect again. */
	WebSocketState_Closing,       /**< In the closing handshake. */
	WebSocketState_Closed,        /**< Closed for good; OnClose was or will be called. */
};

enum WebSocketMessageType
{
	WebSocketMessage_Text = 0,
	WebSocketMessage_Binary,
};

/**
 * The flags of OnFrame (libcurl's CURLWS_* values).
 */
enum WebSocketFrameFlags
{
	WebSocketFrame_Text = 1,       /**< Part of a text message. */
	WebSocketFrame_Binary = 2,     /**< Part of a binary message. */
	WebSocketFrame_Continued = 4,  /**< Not the last fragment: more frames of this message follow. */
};

/**
 * Called when the connection is open (also again after a reconnect).
 *
 * @param ws            The WebSocket.
 * @param data          The data passed to Connect().
 */
typedef WebSocketOpenCallback = function void (WebSocket ws, any data);

/**
 * Called for every whole message received (whole-message mode).
 *
 * @param ws            The WebSocket.
 * @param type          Text or binary.
 * @param message       The message. It lives as long as the callback; use
 *                      message.Clone() to keep it.
 * @param data          The data passed to Connect().
 */
typedef WebSocketMessageCallback = function void (WebSocket ws, WebSocketMessageType type, CurlBuffer message,
                                                  any data);

/**
 * Called for every piece of a frame received (frame mode).
 *
 * @param ws            The WebSocket.
 * @param flags         WebSocketFrameFlags.
 * @param payload       This piece of the frame's payload; lives as long as
 *                      the callback.
 * @param offset        Where the piece starts in the frame's payload.
 * @param bytesLeft     How many bytes of the frame's payload follow.
 * @param data          The data passed to Connect().
 */
typedef WebSocketFrameCallback = function void (WebSocket ws, int flags, CurlBuffer payload, int offset,
                                                int bytesLeft, any data);

/**
 * Called for every pong received.
 *
 * @param ws            The WebSocket.
 * @param payload       The pong's payload; lives as long as the callback.
 * @param data          The data passed to Connect().
 */
typedef WebSocketPongCallback = function void (WebSocket ws, CurlBuffer payload, any data);

/**
 * Called when a reconnect attempt is scheduled.
 *
 * @param ws            The WebSocket.
 * @param error         The error that ended the connection or attempt.
 * @param attempt       The number of this attempt, from 1.
 * @param delay         The seconds until the attempt.
 * @param data          The data passed to Connect().
 * @return              Plugin_Stop to give up (OnClose follows), anything
 *                      else to go on.
 */
typedef WebSocketReconnectCallback = function Action (WebSocket ws, CURLcode error, int attempt, float delay,
                                                      any data);

/**
 * Called once when the WebSocket closed for good.
 *
 * @param ws            The WebSocket.
 * @param error         CURLE_OK when the peer closed, the plugin called
 *                      websocket_close() or a message exceeded the maximum
 *                      size; otherwise the error that ended it.
 * @param code          The close code: the peer's, the plugin's, 1009 when
 *                      a message exceeded the maximum size, 1005 for a close
 *                      frame without one, 1006 without a close frame.
 * @param reason        The close reason: the peer's, the plugin's, "message
 *                      too big" for 1009, empty after an error.
 * @param data          The data passed to Connect().
 */
typedef WebSocketCloseCallback = function void (WebSocket ws, CURLcode error, int code, const char[] reason,
                                                any data);

/**
 * Creates a WebSocket, not connected yet.
 *
 * @param url           A ws:// or wss:// URL.
 * @return              The WebSocket. Close it with delete or CloseHandle().
 * @error               The URL is not ws:// or wss://.
 */
native Handle websocket_create(const char[] url);

/**
 * Adds an HTTP header to the handshake, e.g. "Authorization" or
 * "Sec-WebSocket-Protocol" for a subprotocol.
 *
 * @error               Connected already, or an invalid name or value.
 */
native void websocket_set_header(Handle ws, const char[] name, const char[] value);

/**
 * Whether the TLS certificate and host name of a wss:// peer are verified
 * (default true).
 *
 * @error               Connected already.
 */
native void websocket_set_tls_verify(Handle ws, bool verify);

/**
 * The CA bundle to verify the peer with, instead of the default store. The
 * path is relative to the game directory, or absolute with "file://".
 *
 * @error               Connected already.
 */
native void websocket_set_ca_file(Handle ws, const char[] file);

/**
 * An HTTP or SOCKS proxy, e.g. "socks5h://127.0.0.1:1080".
 *
 * @error               Connected already.
 */
native void websocket_set_proxy(Handle ws, const char[] proxy);

/**
 * The seconds a connection and its handshake may take (default 30).
 *
 * @error               Connected already, or not more than 0.
 */
native void websocket_set_connect_timeout(Handle ws, float seconds);

/**
 * Closes the connection as an error (CURLE_OPERATION_TIMEDOUT) when nothing
 * was received for this many seconds; 0 (default) turns it off.
 *
 * @error               Connected already, or negative.
 */
native void websocket_set_idle_timeout(Handle ws, float seconds);

/**
 * Sends a ping every interval seconds; when no pong arrives within timeout
 * seconds (0: interval), the connection ends as an error
 * (CURLE_OPERATION_TIMEDOUT). An interval of 0 (default) turns it off.
 *
 * @error               Connected already, or negative.
 */
native void websocket_set_keepalive(Handle ws, float interval, float timeout = 0.0);

/**
 * Whether a connection lost through an error is opened again (default
 * false). Attempt n waits initialDelay * 2^(n-1) seconds, at most maxDelay;
 * the count starts over after every successful open.
 *
 * @param enable        Whether to reconnect.
 * @param initialDelay  The delay of the first attempt.
 * @param maxDelay      The longest delay.
 * @param maxAttempts   The most attempts in a row, 0 for no limit.
 * @error               Connected already, or invalid delays or attempts.
 */
native void websocket_set_reconnect(Handle ws, bool enable, float initialDelay = 1.0, float maxDelay = 60.0,
                                    int maxAttempts = 0);

/**
 * Whether OnFrame is called for every piece of a frame instead of OnMessage
 * for whole messages (default false).
 *
 * @error               Connected already.
 */
native void websocket_set_frame_mode(Handle ws, bool frames);

/**
 * The largest whole message (default 1 MB); a larger one closes the
 * connection with code 1009. Also the amount of undelivered received data
 * at which the thread stops reading.
 *
 * @error               Connected already, or outside 1 to CurlBufferMaxBytes.
 */
native void websocket_set_max_message_size(Handle ws, int bytes);

/**
 * The most bytes of unsent messages (default 1 MB).
 *
 * @error               Connected already, or less than 1.
 */
native void websocket_set_max_send_queue(Handle ws, int bytes);

/**
 * Sets a libcurl option that takes an integer on the connection's handle.
 * CURLOPT_URL, _CONNECT_ONLY, _WS_OPTIONS, _NOSIGNAL and _NOPROGRESS are
 * the WebSocket's own.
 *
 * @error               Connected already, an unknown option, one that takes
 *                      no integer, or one of the WebSocket's own.
 */
native void websocket_setopt_int(Handle ws, CURLoption option, int value);

/**
 * Sets a libcurl option that takes a string, as websocket_setopt_int.
 *
 * @error               As for websocket_setopt_int.
 */
native void websocket_setopt_string(Handle ws, CURLoption option, const char[] value);

/** Sets OnOpen. @error Connected already, or an invalid function. */
native void websocket_set_on_open(Handle ws, WebSocketOpenCallback callback);
/** Sets OnMessage. @error Connected already, or an invalid function. */
native void websocket_set_on_message(Handle ws, WebSocketMessageCallback callback);
/** Sets OnFrame. @error Connected already, or an invalid function. */
native void websocket_set_on_frame(Handle ws, WebSocketFrameCallback callback);
/** Sets OnPong. @error Connected already, or an invalid function. */
native void websocket_set_on_pong(Handle ws, WebSocketPongCallback callback);
/** Sets OnReconnect. @error Connected already, or an invalid function. */
native void websocket_set_on_reconnect(Handle ws, WebSocketReconnectCallback callback);
/** Sets OnClose. @error Connected already, or an invalid function. */
native void websocket_set_on_close(Handle ws, WebSocketCloseCallback callback);

/**
 * Starts connecting; returns at once.
 *
 * @param data          Passed to every callback.
 * @error               Connected already.
 */
native void websocket_connect(Handle ws, any data = 0);

/**
 * Queues a text message.
 *
 * @return              True when the message was queued. False when it
 *                      does not fit into the send queue, after
 *                      websocket_close(), or when the WebSocket is closed.
 * @error               websocket_connect() was not called yet.
 */
native bool websocket_send_text(Handle ws, const char[] text);

/**
 * Queues a binary message of length bytes.
 *
 * @return              As for websocket_send_text.
 * @error               websocket_connect() was not called yet, or a negative
 *                      length.
 */
native bool websocket_send_binary(Handle ws, const char[] data, int length);

/**
 * Queues a message with a copy of a buffer's bytes.
 *
 * @param binary        Binary (default) or text.
 * @return              As for websocket_send_text.
 * @error               websocket_connect() was not called yet, or an invalid
 *                      buffer.
 */
native bool websocket_send_buffer(Handle ws, Handle buffer, bool binary = true);

/**
 * Queues a ping; its pong reaches OnPong.
 *
 * @param payload       At most 125 bytes.
 * @param length        How many bytes of payload, or -1 for up to its NUL.
 * @return              False after websocket_close() or when the WebSocket
 *                      is closed.
 * @error               websocket_connect() was not called yet, or a payload
 *                      over 125 bytes.
 */
native bool websocket_ping(Handle ws, const char[] payload = "", int length = -1);

/**
 * Starts the closing handshake (or ends a pending reconnect); OnClose
 * follows with this code and reason. Never reconnects. Messages still in
 * the send queue are not sent.
 *
 * @param code          1000-1003, 1007-1014 or 3000-4999.
 * @param reason        At most 123 bytes.
 * @error               websocket_connect() was not called yet, an invalid
 *                      code or a reason over 123 bytes.
 */
native void websocket_close(Handle ws, int code = 1000, const char[] reason = "");

/** @return The state. */
native WebSocketState websocket_get_state(Handle ws);

/** Writes the URL. @return The number of bytes written. */
native int websocket_get_url(Handle ws, char[] buffer, int maxlength);

/** @return The bytes of queued, unsent messages. */
native int websocket_get_queued_bytes(Handle ws);

methodmap WebSocket < Handle
{
	/** See websocket_create. */
	public WebSocket(const char[] url)
	{
		return view_as<WebSocket>(websocket_create(url));
	}

	/** See websocket_set_header. */
	public void SetHeader(const char[] name, const char[] value) { websocket_set_header(this, name, value); }
	/** See websocket_set_tls_verify. */
	public void SetTlsVerify(bool verify) { websocket_set_tls_verify(this, verify); }
	/** See websocket_set_ca_file. */
	public void SetCaFile(const char[] file) { websocket_set_ca_file(this, file); }
	/** See websocket_set_proxy. */
	public void SetProxy(const char[] proxy) { websocket_set_proxy(this, proxy); }
	/** See websocket_set_connect_timeout. */
	public void SetConnectTimeout(float seconds) { websocket_set_connect_timeout(this, seconds); }
	/** See websocket_set_idle_timeout. */
	public void SetIdleTimeout(float seconds) { websocket_set_idle_timeout(this, seconds); }
	/** See websocket_set_keepalive. */
	public void SetKeepalive(float interval, float timeout = 0.0) { websocket_set_keepalive(this, interval, timeout); }

	/** See websocket_set_reconnect. */
	public void SetReconnect(bool enable, float initialDelay = 1.0, float maxDelay = 60.0, int maxAttempts = 0)
	{
		websocket_set_reconnect(this, enable, initialDelay, maxDelay, maxAttempts);
	}

	/** See websocket_set_frame_mode. */
	public void SetFrameMode(bool frames) { websocket_set_frame_mode(this, frames); }
	/** See websocket_set_max_message_size. */
	public void SetMaxMessageSize(int bytes) { websocket_set_max_message_size(this, bytes); }
	/** See websocket_set_max_send_queue. */
	public void SetMaxSendQueue(int bytes) { websocket_set_max_send_queue(this, bytes); }
	/** See websocket_setopt_int. */
	public void SetOptInt(CURLoption option, int value) { websocket_setopt_int(this, option, value); }
	/** See websocket_setopt_string. */
	public void SetOptString(CURLoption option, const char[] value) { websocket_setopt_string(this, option, value); }

	/** See websocket_set_on_open. */
	public void SetOnOpen(WebSocketOpenCallback callback) { websocket_set_on_open(this, callback); }
	/** See websocket_set_on_message. */
	public void SetOnMessage(WebSocketMessageCallback callback) { websocket_set_on_message(this, callback); }
	/** See websocket_set_on_frame. */
	public void SetOnFrame(WebSocketFrameCallback callback) { websocket_set_on_frame(this, callback); }
	/** See websocket_set_on_pong. */
	public void SetOnPong(WebSocketPongCallback callback) { websocket_set_on_pong(this, callback); }
	/** See websocket_set_on_reconnect. */
	public void SetOnReconnect(WebSocketReconnectCallback callback) { websocket_set_on_reconnect(this, callback); }
	/** See websocket_set_on_close. */
	public void SetOnClose(WebSocketCloseCallback callback) { websocket_set_on_close(this, callback); }

	/** See websocket_connect. */
	public void Connect(any data = 0) { websocket_connect(this, data); }
	/** See websocket_send_text. */
	public bool SendText(const char[] text) { return websocket_send_text(this, text); }
	/** See websocket_send_binary. */
	public bool SendBinary(const char[] data, int length) { return websocket_send_binary(this, data, length); }
	/** See websocket_send_buffer. */
	public bool SendBuffer(CurlBuffer buffer, bool binary = true) { return websocket_send_buffer(this, buffer, binary); }
	/** See websocket_ping. */
	public bool Ping(const char[] payload = "", int length = -1) { return websocket_ping(this, payload, length); }
	/** See websocket_close. */
	public void Close(int code = 1000, const char[] reason = "") { websocket_close(this, code, reason); }
	/** See websocket_get_url. */
	public int GetUrl(char[] buffer, int maxlength) { return websocket_get_url(this, buffer, maxlength); }

	/** See websocket_get_state. */
	property WebSocketState State
	{
		public get() { return websocket_get_state(this); }
	}

	/** See websocket_get_queued_bytes. */
	property int QueuedBytes
	{
		public get() { return websocket_get_queued_bytes(this); }
	}
}
