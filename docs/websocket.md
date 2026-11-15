# WebSocket

`WebSocket` (`curl_websocket.inc`, included by `cURL.inc`) is a WebSocket client: `ws://` and `wss://` connections
made with libcurl, each run by a thread of the extension. The plugin sets the options and callbacks, connects, and
gets what happened as callbacks on the main thread, every server frame, in order.

## Lifetime

1. `new WebSocket(url)` creates the WebSocket, not connected yet (`WebSocketState_Idle`).
2. Options and callbacks are set; all of them only before `Connect()`, a later setter is a native error.
3. `Connect(data)` starts the connection's thread and returns at once. `data` is passed to every callback.
4. Messages flow; `Close(code, reason)` starts the closing handshake.
5. `OnClose` is called once, when the WebSocket closed for good. The handle stays valid (`State` is
   `WebSocketState_Closed`) until the plugin deletes it.

One handle is one WebSocket: to connect again after `OnClose`, create a new one.

Deleting the handle while connected ends the connection with close code 1001 (going away) and calls no more
callbacks; so does unloading the plugin. Unloading the extension ends every connection.

## Options

| Method | Default | |
|---|---|---|
| `SetHeader(name, value)` | | An HTTP header of the handshake, e.g. `Authorization`, or `Sec-WebSocket-Protocol` for subprotocols. |
| `SetTlsVerify(verify)` | true | Whether a `wss://` peer's certificate and host name are verified. |
| `SetCaFile(file)` | system | A CA bundle; relative to the game directory, or absolute with `file://`. |
| `SetProxy(proxy)` | none | An HTTP or SOCKS proxy URL. |
| `SetConnectTimeout(seconds)` | 30 | How long the connection and handshake may take. |
| `SetIdleTimeout(seconds)` | 0 (off) | Ends the connection as an error when nothing arrived for this long. |
| `SetKeepalive(interval, timeout = 0.0)` | 0 (off) | A ping every `interval` seconds; no pong within `timeout` (0: `interval`) ends the connection as an error. |
| `SetReconnect(enable, initialDelay = 1.0, maxDelay = 60.0, maxAttempts = 0)` | off | See [Reconnecting](#reconnecting). |
| `SetFrameMode(frames)` | false | `OnFrame` per frame piece instead of `OnMessage` per whole message. |
| `SetMaxMessageSize(bytes)` | 1 MB | The largest whole message; also the backpressure limit. At most `CurlBufferMaxBytes`. |
| `SetMaxSendQueue(bytes)` | 1 MB | The most bytes of unsent messages. |
| `SetOptInt(option, value)`, `SetOptString(option, value)` | | Any libcurl option of that type on the connection's handle. |

`SetOptInt` and `SetOptString` take libcurl's `CURLOPT_*` options of an integer or string type; the WebSocket's own
`CURLOPT_URL`, `_CONNECT_ONLY`, `_WS_OPTIONS`, `_NOSIGNAL` and `_NOPROGRESS` are refused. They are applied after the
typed options, so they win over them.

On Linux curl verifies against Debian's CA bundle (`/etc/ssl/certs/ca-certificates.crt`), on Windows against the
Windows certificate store.

## Callbacks

```sourcepawn
typedef WebSocketOpenCallback = function void (WebSocket ws, any data);
typedef WebSocketMessageCallback = function void (WebSocket ws, WebSocketMessageType type, CurlBuffer message,
                                                  any data);
typedef WebSocketFrameCallback = function void (WebSocket ws, int flags, CurlBuffer payload, int offset,
                                                int bytesLeft, any data);
typedef WebSocketPongCallback = function void (WebSocket ws, CurlBuffer payload, any data);
typedef WebSocketReconnectCallback = function Action (WebSocket ws, CURLcode error, int attempt, float delay,
                                                      any data);
typedef WebSocketCloseCallback = function void (WebSocket ws, CURLcode error, int code, const char[] reason,
                                                any data);
```

Set them with `SetOnOpen`, `SetOnMessage`, `SetOnFrame`, `SetOnPong`, `SetOnReconnect` and `SetOnClose`; each is
optional. Payloads are [CurlBuffers](buffer.md) that live as long as the callback.

- **OnOpen**: the handshake is done; also again after every reconnect.
- **OnMessage** (whole-message mode): a complete text or binary message; fragmented messages are reassembled.
- **OnFrame** (frame mode): a piece of a data frame as it arrives. `flags` are `WebSocketFrame_Text` or `_Binary`,
  plus `WebSocketFrame_Continued` when more frames of the message follow; `offset` is where the piece starts in the
  frame's payload and `bytesLeft` how much of the frame follows. A frame may come in several pieces.
- **OnPong**: a pong, answering the plugin's `Ping()` or a keepalive ping. Pings of the peer are answered by libcurl
  and reach no callback.
- **OnReconnect**: a reconnect attempt is scheduled; return `Plugin_Stop` to give up.
- **OnClose**: the WebSocket closed for good.

`OnClose` gets:

| Situation | `error` | `code` |
|---|---|---|
| The peer closed | `CURLE_OK` | the peer's code, 1005 if its close frame had none |
| The plugin's `Close()` | `CURLE_OK` | the plugin's code |
| A message exceeded the maximum size | `CURLE_OK` | 1009 |
| An error (connect failed, connection lost, timeout) and no reconnect | the error | 1006 |

## Sending

| Method | |
|---|---|
| `SendText(text)` | A text message. |
| `SendBinary(data, length)` | A binary message of `length` bytes. |
| `SendBuffer(buffer, binary = true)` | A message with a copy of a buffer's bytes. |
| `Ping(payload = "", length = -1)` | A ping of at most 125 bytes. |
| `Close(code = 1000, reason = "")` | Starts the closing handshake, or ends a pending reconnect. Codes 1000-1003, 1007-1014 and 3000-4999; reasons up to 123 bytes. |

Sends are queued and sent by the connection's thread. They return false when the queue would exceed its maximum or
the WebSocket is closing or closed; calling them before `Connect()` is a native error. Messages queued while
connecting are sent once the connection is open. When a connection is lost, its unsent messages are dropped.

`QueuedBytes` tells how many bytes wait, `State` the state and `GetUrl` the URL.

## Backpressure

Received data waits in the extension until the next server frame delivers it. When the undelivered data reaches the
maximum message size, the thread stops reading from the socket until the plugin got it, so a fast peer is slowed down
by TCP instead of filling the server's memory.

## Reconnecting

With `SetReconnect(true, ...)`, a connection that ends through an error (it could not connect, broke, or a keepalive
or idle timeout hit) is opened again. A closing handshake, from either side, never reconnects.

Attempt n waits `initialDelay * 2^(n-1)` seconds, at most `maxDelay`. Before each attempt `OnReconnect` gets the error,
the attempt's number and its delay; `Plugin_Stop` gives up and `OnClose` follows. After `maxAttempts` failed attempts
in a row (0: no limit) the WebSocket gives up as well. The count starts over after every successful open, which calls
`OnOpen` again.

## Example

```sourcepawn
WebSocket g_Feed;

public void OnPluginStart()
{
	g_Feed = new WebSocket("wss://example.com/feed");
	g_Feed.SetHeader("Authorization", "Bearer secret");
	g_Feed.SetKeepalive(30.0);
	g_Feed.SetReconnect(true);
	g_Feed.SetOnOpen(OnFeedOpen);
	g_Feed.SetOnMessage(OnFeedMessage);
	g_Feed.SetOnClose(OnFeedClose);
	g_Feed.Connect();
}

public void OnFeedOpen(WebSocket ws, any data)
{
	ws.SendText("{\"subscribe\":\"scores\"}");
}

public void OnFeedMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
{
	char text[512];
	message.GetString(0, text, sizeof(text));
	PrintToServer("feed: %s", text);
}

public void OnFeedClose(WebSocket ws, CURLcode error, int code, const char[] reason, any data)
{
	LogMessage("feed closed: error %d, code %d %s", error, code, reason);
}
```
