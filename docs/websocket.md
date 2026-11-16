# WebSocket

`WebSocket` is a WebSocket client. A plugin opens a connection to a `ws://` or `wss://` server, sends text and binary
messages and receives the server's messages in callbacks. A WebSocket stays open, so it suits everything that should
arrive at once in either direction: chat relays, live scores, commands from a control panel.

It is part of `curl_websocket.inc`, which `#include <cURL>` includes.

Contents:

- [A first connection](#a-first-connection)
- [The life of a WebSocket](#the-life-of-a-websocket)
- [Options](#options)
- [Callbacks](#callbacks)
- [Sending](#sending)
- [Receiving large messages: frame mode](#receiving-large-messages-frame-mode)
- [Keeping a connection alive](#keeping-a-connection-alive)
- [Reconnecting](#reconnecting)
- [Closing](#closing)
- [When the server sends faster than the plugin reads](#when-the-server-sends-faster-than-the-plugin-reads)
- [Complete example: a chat relay](#complete-example-a-chat-relay)
- [Reference](#reference)
- [Common mistakes](#common-mistakes)

## A first connection

From [`websocket_relay.sp`](../pawn/scripting/examples/websocket_relay.sp): connect to a server, with a header for
authentication, keepalive and automatic reconnecting.

```sourcepawn
// Every option and callback must be set before Connect().
g_Relay = new WebSocket(url);
g_Relay.SetHeader("Authorization", authorization);
// A ping every 30 seconds; no pong within 10 seconds counts as a lost
// connection. Without this a dead connection can go unnoticed for long.
g_Relay.SetKeepalive(30.0, 10.0);
// After an error, connect again: after 1, 2, 4, ... up to 60 seconds.
g_Relay.SetReconnect(true, 1.0, 60.0);
g_Relay.SetOnOpen(OnRelayOpen);
g_Relay.SetOnMessage(OnRelayMessage);
g_Relay.SetOnReconnect(OnRelayReconnect);
g_Relay.SetOnClose(OnRelayClose);
g_Relay.Connect();
```

The callbacks:

```sourcepawn
public void OnRelayOpen(WebSocket ws, any data)
{
	// Called after the first connect and after every successful reconnect.
	LogMessage("Relay: connected");

	char hostname[128];
	FindConVar("hostname").GetString(hostname, sizeof(hostname));
	SendJson("hello", "server", hostname);
}
```

```sourcepawn
public void OnRelayMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
{
	if (type != WebSocketMessage_Text) {
		return;
	}

	// The buffer is closed when this callback returns. A copy keeps the
	// message for sm_relay_status.
	delete g_LastMessage;
	g_LastMessage = message.Clone();

	// Chat lines are short: the first 191 bytes are enough.
	char text[192];
	message.GetString(0, text, sizeof(text));
	PrintToChatAll("[Relay] %s", text);
}
```

```sourcepawn
public void OnRelayClose(WebSocket ws, CURLcode error, int code, const char[] reason, any data)
{
	// Called once, when the WebSocket is closed for good. To connect
	// again a new WebSocket is needed, so this one is deleted.
	if (error == CURLE_OK) {
		LogMessage("Relay: closed with code %d (%s)", code, reason);
	} else {
		char text[256];
		CurlEasy.StrError(error, text, sizeof(text));
		LogError("Relay: closed after an error: %s", text);
	}

	delete g_Relay;
}
```

`SendJson` is a function of the example that builds a JSON text and sends it with `SendText`.

## The life of a WebSocket

1. **Create.** `new WebSocket(url)` creates the WebSocket. It is not connected yet. The URL must start with `ws://`
   (unencrypted) or `wss://` (encrypted with TLS); anything else throws an error.
2. **Configure.** Set the options and the callbacks. All of them must be set before `Connect()`; a setter called
   later throws an error.
3. **Connect.** `Connect(data)` starts a thread of the extension for this connection and returns at once. `data` is
   any value; every callback gets it as its last argument.
4. **Use.** A WebSocket connection starts with a *handshake*: an HTTP request by which client and server agree to
   speak WebSocket. When it is done, the connection is open and `OnOpen` is called. Messages are sent with the `Send`
   methods and arrive in `OnMessage`.
5. **End.** The WebSocket ends because the plugin calls `Close()`, the server closes the connection, or an error
   occurs. Then `OnClose` is called, exactly once. (With [reconnecting](#reconnecting) on, an error does not end the
   WebSocket: it connects again, and `OnClose` comes only when that is given up.)
6. **Delete.** After `OnClose` the handle is still valid, but the WebSocket is finished: one handle is one
   connection's lifetime. Delete it, and create a new `WebSocket` to connect again.

Every callback runs on the server's main thread, in a game frame, and the callbacks of one WebSocket arrive in the
order in which things happened.

`State` tells where a WebSocket is:

| `State` | Meaning |
|---|---|
| `WebSocketState_Idle` | Created, `Connect()` not called yet. |
| `WebSocketState_Connecting` | Connecting, or in the handshake. Also during every reconnect attempt. |
| `WebSocketState_Open` | Connected. Messages flow. |
| `WebSocketState_Reconnecting` | The connection was lost through an error; waiting for the next attempt. |
| `WebSocketState_Closing` | Closing: the plugin called `Close()`, or the server sent a close. |
| `WebSocketState_Closed` | Finished for good. `OnClose` was called or will be called in the next game frame. |

## Options

All options are set between `new WebSocket(url)` and `Connect()`.

| Method | Default | What it does |
|---|---|---|
| `SetHeader(name, value)` | none | Adds a header to the request that opens the connection. |
| `SetTlsVerify(verify)` | `true` | Whether the certificate and host name of a `wss://` server are checked. |
| `SetCaFile(file)` | system store | A file with the certificate authorities to trust instead of the system's. |
| `SetProxy(proxy)` | none | The URL of an HTTP or SOCKS proxy to connect through. |
| `SetConnectTimeout(seconds)` | 30 | How long connecting and the handshake may take together. |
| `SetIdleTimeout(seconds)` | 0 (off) | Ends the connection as an error when nothing was received for this long. |
| `SetKeepalive(interval, timeout = 0.0)` | 0 (off) | Sends a ping every `interval` seconds, see [Keeping a connection alive](#keeping-a-connection-alive). |
| `SetReconnect(enable, initialDelay = 1.0, maxDelay = 60.0, maxAttempts = 0)` | off | Connects again after an error, see [Reconnecting](#reconnecting). |
| `SetFrameMode(frames)` | `false` | Delivers messages in pieces, see [frame mode](#receiving-large-messages-frame-mode). |
| `SetMaxMessageSize(bytes)` | 1048576 (1 MB) | The largest message the plugin accepts. |
| `SetMaxSendQueue(bytes)` | 1048576 (1 MB) | The most bytes of messages that may wait to be sent. |
| `SetOptInt(option, value)`, `SetOptString(option, value)` | | Sets a libcurl option directly. |

Details:

- **Headers.** `SetHeader("Authorization", "Bearer abc")` adds the header line `Authorization: Bearer abc`. Each call
  adds a line; calling it twice with the same name sends that header twice. A *subprotocol*, the name of the message
  format a server expects on top of WebSocket, is requested with the header `Sec-WebSocket-Protocol`. The name must
  not be empty or contain a colon, and neither part may contain a line break; otherwise the method throws an error.
- **Certificates.** With `SetTlsVerify(true)` a `wss://` connection fails when the server's certificate is not valid
  for its host name or not signed by a trusted authority. Turn it off only for tests. `SetCaFile` takes a path
  relative to the game directory, or `file://` followed by an absolute path. Once set, it cannot be set back to the
  system's store on the same WebSocket.
- **Timeouts** are in seconds and may have fractions (`2.5`). When the idle timeout or the keepalive timeout hits,
  the connection ends with the error `CURLE_OPERATION_TIMEDOUT`.
- **Maximum message size.** A received message larger than this ends the WebSocket; the server is told so with
  close code 1009 (see [Closing](#closing) for close codes), and there is no reconnect. A message of exactly this
  size is accepted. The value must be at least 1 and at most
  [`CurlBufferMaxBytes`](buffer.md#the-size-limit). It does not limit what the plugin sends.
- **libcurl options.** `SetOptInt` and `SetOptString` set a `CURLOPT_` option that takes a number or a string on the
  connection, for what the methods above do not cover. Options that take a large number as text (the ones
  `CurlEasy.SetOptInt64` sets), a handle or a callback cannot be set and throw an error. They are applied after the
  other options and so override them. Five options that the WebSocket needs for itself are refused with an error:
  `CURLOPT_URL`, `CURLOPT_CONNECT_ONLY`, `CURLOPT_WS_OPTIONS`, `CURLOPT_NOSIGNAL` and `CURLOPT_NOPROGRESS`. Unlike
  with [`CurlEasy`](modern.md#options-that-name-a-file), a file path set this way is passed to libcurl as it is.

## Callbacks

Each callback is optional and is set with its own method. A callback that is not set means the plugin is not told
about that event.

| Set with | Called when |
|---|---|
| `SetOnOpen` | The connection is open. Also after every successful reconnect. |
| `SetOnMessage` | A complete message arrived (not in frame mode). |
| `SetOnFrame` | A piece of a message arrived (only in frame mode). |
| `SetOnPong` | A pong arrived. |
| `SetOnReconnect` | The connection was lost and a reconnect attempt is scheduled. |
| `SetOnClose` | The WebSocket is finished for good. |

Their signatures:

```sourcepawn
public void OnOpen(WebSocket ws, any data)
public void OnMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
public void OnFrame(WebSocket ws, int flags, CurlBuffer payload, int offset, int bytesLeft, any data)
public void OnPong(WebSocket ws, CurlBuffer payload, any data)
public Action OnReconnect(WebSocket ws, CURLcode error, int attempt, float delay, any data)
public void OnClose(WebSocket ws, CURLcode error, int code, const char[] reason, any data)
```

`data` is the value given to `Connect()`. Messages and payloads are [`CurlBuffer`](buffer.md)s that exist only while
the callback runs; use `Clone()` to keep one.

### OnMessage

`type` is `WebSocketMessage_Text` or `WebSocketMessage_Binary`, as the server declared the message. `message` holds
the whole message, however many parts the server sent it in. The extension does not check that a text message
is valid UTF-8.

A message is read like any buffer. For a text known to be short, one `GetString` is enough:

```sourcepawn
// Chat lines are short: the first 191 bytes are enough.
char text[192];
message.GetString(0, text, sizeof(text));
PrintToChatAll("[Relay] %s", text);
```

### OnClose

`OnClose` tells why the WebSocket ended:

| What happened | `error` | `code` | `reason` |
|---|---|---|---|
| The server closed the connection | `CURLE_OK` | the server's close code; 1005 when it sent none | the server's reason |
| The plugin called `Close()` | `CURLE_OK` | the code given to `Close()` | the reason given to `Close()` |
| A message exceeded the maximum message size | `CURLE_OK` | 1009 | `message too big` |
| An error, and reconnecting is off or gave up | the error | 1006 | empty |

Errors are libcurl's codes: `CURLE_COULDNT_CONNECT`, `CURLE_OPERATION_TIMEDOUT` and so on.
[`CurlEasy.StrError`](modern.md#getting-a-readable-error-message) turns one into text:

```sourcepawn
if (error == CURLE_OK) {
	LogMessage("Relay: closed with code %d (%s)", code, reason);
} else {
	char text[256];
	CurlEasy.StrError(error, text, sizeof(text));
	LogError("Relay: closed after an error: %s", text);
}
```

`OnClose` is also called when the very first connection attempt fails, so it can arrive without an `OnOpen` before it.
It is not called when the plugin deletes the handle.

`OnFrame`, `OnPong` and `OnReconnect` are described in the sections on frame mode, keepalive and reconnecting below.

## Sending

| Method | What it sends |
|---|---|
| `SendText(text)` | A text message: `text` up to its NUL. |
| `SendBinary(data, length)` | A binary message: `length` bytes of `data`, which may contain NUL. |
| `SendBuffer(buffer, binary = true)` | A message with the bytes of a `CurlBuffer`: binary, or text with `false`. |
| `Ping(payload = "", length = -1)` | A ping, see [Keeping a connection alive](#keeping-a-connection-alive). |

```sourcepawn
// A binary message from an array: the length is given, so the bytes
// may contain NUL.
char small[4];
small[0] = 1;
small[1] = 0;
small[2] = 2;
small[3] = 3;
ws.SendBinary(small, sizeof(small));

// A binary message too large for a plugin's own memory is built in a
// CurlBuffer. SendBuffer copies it, so the buffer can be closed.
CurlBuffer large = new CurlBuffer();
char block[1000];
for (int i = 0; i < sizeof(block); i++) {
	block[i] = i % 251;
}
for (int i = 0; i < LARGE_SIZE / sizeof(block); i++) {
	large.Append(block, sizeof(block));
}
if (!ws.SendBuffer(large)) {
	PrintToServer("The message does not fit into the send queue.");
}
delete large;
```

A send method does not send. It puts the message into the WebSocket's **send queue** and returns; the connection's
thread sends the queue in order. That has consequences worth knowing:

- **Sending before the connection is open works.** From `Connect()` on, messages are queued and go out as soon as
  the connection is open. The same holds while a reconnect is under way. If the connection attempt fails, the
  messages queued for it are dropped. Calling a send method before `Connect()` throws an error.
- **The return value says whether the message was queued**, not whether it arrived. The methods return `false` when
  the message does not fit into the queue, or after the plugin called `Close()`, or when the WebSocket is closed.
- **The queue has a size limit**, `SetMaxSendQueue`, 1 MB by default. A message that would take the queue above it is
  refused. A single message larger than the limit can never be sent; raise the limit for large messages. Pings do
  not count towards it.
- **Queued messages can be lost.** When the connection breaks or a connection attempt fails, the messages still in
  the queue are dropped. So are they when the plugin calls `Close()`: closing does not wait for the queue.
- A copy of the data is queued. The plugin's array or buffer can be changed or closed right after the call.

`QueuedBytes` is the number of bytes in the queue that the thread has not taken yet. It helps to slow down a plugin
that produces data faster than the network carries it. It also falls to 0 when the queue is dropped, so a falling
number alone does not prove that a message was sent.

```sourcepawn
static const char states[][] = { "idle", "connecting", "open", "reconnecting", "closing", "closed" };
char url[256];
g_Relay.GetUrl(url, sizeof(url));
ReplyToCommand(client, "%s is %s, %d bytes wait to be sent", url, states[g_Relay.State], g_Relay.QueuedBytes);
```

`SendBinary` trusts its `length`: pass the size of the array or less. A negative `length` throws an error, as does an
invalid buffer for `SendBuffer`.

A connection that cannot take any data for 30 seconds, because the server does not read, ends with the error
`CURLE_OPERATION_TIMEDOUT`. The extension does not check that text
messages are valid UTF-8; a server may close the connection when they are not.

## Receiving large messages: frame mode

Normally the extension collects a message completely and then calls `OnMessage`. A message is therefore limited by
the maximum message size, and it is held in memory as a whole.

With `SetFrameMode(true)` the extension passes on every piece as it arrives instead. `OnMessage` is never called;
`OnFrame` is called for each piece:

```sourcepawn
public void OnFrame(WebSocket ws, int flags, CurlBuffer payload, int offset, int bytesLeft, any data)
```

A server sends a WebSocket message as one or more *frames*: packets with a small header that says how long they
are and whether another frame of the same message follows. A frame may in turn arrive in several pieces of up to
64 KB.

- `payload` is the piece.
- `offset` is the position of the piece within its frame, and `bytesLeft` the number of bytes of the frame that are
  still to come. `bytesLeft == 0` marks the last piece of a frame.
- `flags` is a set of bits of the enum `WebSocketFrameFlags`:
  `WebSocketFrame_Text` or `WebSocketFrame_Binary` for the kind of message, and `WebSocketFrame_Continued` when the
  message goes on in a further frame.
- A message is complete with the last piece (`bytesLeft == 0`) of a frame that is not continued.

From [`websocket_frames.sp`](../pawn/scripting/examples/websocket_frames.sp), which adds up the bytes of each
message:

```sourcepawn
public void OnFrame(WebSocket ws, int flags, CurlBuffer payload, int offset, int bytesLeft, any data)
{
	g_Pieces++;
	g_MessageBytes += payload.Length;

	// A message is complete with the last piece (no bytes of the frame
	// left) of its last frame (no continuation frame follows).
	bool lastPiece = bytesLeft == 0;
	bool lastFrame = (flags & view_as<int>(WebSocketFrame_Continued)) == 0;
	if (!lastPiece || !lastFrame) {
		return;
	}

	g_Messages++;
	PrintToServer("Message %d: %d bytes of %s data", g_Messages, g_MessageBytes,
	              (flags & view_as<int>(WebSocketFrame_Binary)) ? "binary" : "text");
	g_MessageBytes = 0;

	if (g_Messages == 2) {
		PrintToServer("Both messages came back in %d pieces", g_Pieces);
		// 1000 is the code for a normal close.
		ws.Close(1000, "done");
	}
}
```

The example sends a 4 byte message, a 300000 byte message and a ping with the payload `are you there?`. Against a
server that sends everything back, it prints:

```
Message 1: 4 bytes of binary data
Pong: are you there?
Message 2: 300000 bytes of binary data
Both messages came back in 7 pieces
Closed with code 1000 (done)
```

In frame mode the maximum message size is not enforced, since no message is ever assembled. Pongs still arrive in
`OnPong`.

## Keeping a connection alive

A connection that carries no data can die without either side noticing, for example when a router in between
forgets it. Pings find that out: one side sends a ping, the other answers with a pong.

`SetKeepalive(interval, timeout)` makes the extension send a ping `interval` seconds after the connection opened,
and then again `interval` seconds after each ping, once that ping's pong arrived. If no pong arrives within
`timeout` seconds of a ping, the connection counts as lost and ends with the error `CURLE_OPERATION_TIMEDOUT`, which
starts a reconnect when reconnecting is on. A `timeout` of 0 means the same time as `interval`.

```sourcepawn
// A ping every 30 seconds; no pong within 10 seconds counts as a lost
// connection. Without this a dead connection can go unnoticed for long.
g_Relay.SetKeepalive(30.0, 10.0);
```

Pings of the server are answered by the extension itself; the plugin is not told about them.

A plugin can also ping by hand. `Ping(payload, length)` sends a ping with up to 125 bytes of payload (`length` -1
takes `payload` up to its NUL; more than 125 bytes throws an error), and the server's pong arrives in `OnPong` with
the same payload:

```sourcepawn
public void OnPong(WebSocket ws, CurlBuffer payload, any data)
{
	char text[64];
	payload.GetString(0, text, sizeof(text));
	PrintToServer("Pong: %s", text);
}
```

`OnPong` is called for every pong, including the answers to keepalive pings, whose payload is empty.

`SetIdleTimeout(seconds)` is a simpler guard for connections on which the server sends regularly: when nothing at
all arrives for that long, the connection ends with `CURLE_OPERATION_TIMEDOUT`. Pings and pongs count as arrivals,
so on a connection with keepalive the idle timeout never hits while the server answers the pings.

## Reconnecting

With `SetReconnect(true)` a connection that ends through an error is opened again automatically. An error means: the
connection could not be established, it broke, or a keepalive or idle timeout hit. There is no reconnect when the
plugin or the server closes the connection, or when a message exceeded the maximum message size.

```sourcepawn
void WebSocket.SetReconnect(bool enable, float initialDelay = 1.0, float maxDelay = 60.0, int maxAttempts = 0)
```

- The first attempt follows `initialDelay` seconds after the error. Each further attempt waits twice as long as the
  one before, but never longer than `maxDelay`: with the defaults 1, 2, 4, 8, 16, 32, 60, 60, ... seconds.
- `maxAttempts` is the number of reconnect attempts that may fail in a row before the WebSocket gives up; 0 means
  never. The connection that failed first is not counted: with `maxAttempts` 3 and a server that is gone, the
  WebSocket tries three more times. After a successful reconnect the count and the delay start over.
- Both delays must be above 0, `maxDelay` must not be below `initialDelay`, and `maxAttempts` must not be negative;
  otherwise the method throws an error, also when `enable` is `false`.

Before each attempt `OnReconnect` is called with the error that ended the connection (or the previous attempt), the
number of the attempt, counted from 1, and the delay in seconds until it starts:

```sourcepawn
public Action OnRelayReconnect(WebSocket ws, CURLcode error, int attempt, float delay, any data)
{
	char reason[256];
	CurlEasy.StrError(error, reason, sizeof(reason));
	LogMessage("Relay: connection lost (%s), attempt %d in %.0f seconds", reason, attempt, delay);

	// Returning Plugin_Stop here would give up; OnRelayClose would follow.
	return Plugin_Continue;
}
```

Returning `Plugin_Stop` gives up: the WebSocket ends and `OnClose` is called with the error. Every other return
value lets the attempt go ahead. Without an `OnReconnect` callback every attempt goes ahead.

Things to know:

- **`OnOpen` is called again** after every successful reconnect. Whatever a plugin sends at the start of a
  connection, a login or a subscription, belongs there.
- **`OnClose` is called only at the very end**: when reconnecting gave up, or after an orderly close.
- **Every error is retried**, also one that will not go away by itself, such as a wrong URL or a refused
  certificate. With the default `maxAttempts` of 0 such a WebSocket retries forever, once a minute. Set
  `maxAttempts`, or give up in `OnReconnect`.
- **Unsent messages are dropped** when the connection breaks, and a message that was only partly received is
  discarded. Messages sent while waiting for the reconnect are queued and go out if the next attempt succeeds; if
  it fails, they are dropped too.

The log of the relay example when its server goes away for a moment:

```
Relay: connection lost (Server returned nothing (no headers, no data)), attempt 1 in 1 seconds
Relay: connected
```

## Closing

```sourcepawn
void WebSocket.Close(int code = 1000, const char[] reason = "")
```

`Close` ends the WebSocket in an orderly way: it tells the server that the connection is closing and why, with a
number, the *close code*, and a short text. It then waits up to 5 seconds for the server's confirmation, and
`OnClose` is called with the code and reason given here. Messages of the server that arrive during that wait are
discarded. While the
WebSocket waits to reconnect, `Close` ends the waiting; `OnClose` follows as well.

- `code` says why. 1000 is the normal close and 1001 "going away". Allowed are 1000 to 1003, 1007 to 1014 and
  3000 to 4999 (3000 and above are free for an application's own meanings).
- `reason` is a short text for the server's log, at most 123 bytes.
- An invalid code or a longer reason throws an error, and so does calling `Close` before `Connect()`.
- Messages still in the send queue are not sent. To be sure a last message goes out, close when the server
  confirmed it.
- A second `Close` has no effect.

**Deleting the handle** ends the connection immediately. If it was open, the server is sent close code 1001. No
callback is called anymore, `OnClose` included, so deleting is the way to drop a WebSocket the plugin has no further
interest in. Unloading the plugin closes its handles, with the same effect.

Deleting a WebSocket inside one of its own callbacks is allowed, as the example does in `OnRelayClose`.

## When the server sends faster than the plugin reads

Received messages wait in the extension until the next game frame, when the callbacks are called. If a server sends
faster than that empties, the waiting data would grow without limit. It does not: when the waiting data reaches the
maximum message size, the connection's thread stops reading from the network until the callbacks took what is
there. The server then cannot send on (TCP makes it wait), and the game server's memory stays bounded.

While the thread is not reading it does not see pongs either. On a connection that is flooded like this for long, a
keepalive or idle timeout can therefore hit.

## Complete example: a chat relay

[`websocket_relay.sp`](../pawn/scripting/examples/websocket_relay.sp) keeps a connection to a backend of your own.
Every chat line of the game goes to the backend as a JSON text message, and every text message of the backend is
printed to the game's chat. The parts not shown above:

Chat lines are sent whenever a player says something. `SendJson` returns `false` while there is no WebSocket, which
the example's console command `sm_relay_say <text>` reports to whoever typed it:

```sourcepawn
public void OnClientSayCommand_Post(int client, const char[] command, const char[] sArgs)
{
	if (client == 0) {
		return;
	}
	char name[MAX_NAME_LENGTH];
	GetClientName(client, name, sizeof(name));
	SendJson("chat", name, sArgs);
}
```

```sourcepawn
bool SendJson(const char[] type, const char[] name, const char[] text)
{
	if (g_Relay == null) {
		return false;
	}

	char escapedName[MAX_NAME_LENGTH * 2 + 1];
	EscapeJsonString(name, escapedName, sizeof(escapedName));
	char escapedText[512];
	EscapeJsonString(text, escapedText, sizeof(escapedText));

	char json[700];
	Format(json, sizeof(json), "{\"type\":\"%s\",\"name\":\"%s\",\"text\":\"%s\"}", type, escapedName, escapedText);

	// While connecting or reconnecting the message waits in the send queue
	// and is sent once the connection is open. False means: the queue is
	// full, or the WebSocket is closing or closed.
	return g_Relay.SendText(json);
}
```

With `sm_relay_url "wss://relay.example.com/gameserver"` and a token set, `sm_relay_connect` opens the connection.
After that and `sm_relay_say hello`, the backend has received:

```
{"type":"hello","name":"server","text":"A Team Fortress 2 server"}
{"type":"chat","name":"Console","text":"hello"}
```

The second example plugin, [`websocket_frames.sp`](../pawn/scripting/examples/websocket_frames.sp), shows binary
messages, frame mode and pings; it needs a server that sends every message back.

## Reference

`WebSocket` is a `Handle`. Every method has a native that takes the WebSocket as its first argument.

### Creating and connecting

| Member | Native | Notes |
|---|---|---|
| `new WebSocket(const char[] url)` | `websocket_create` | Throws an error unless the URL starts with `ws://` or `wss://`. |
| `Connect(any data = 0)` | `websocket_connect` | Throws an error when called a second time. |
| `Close(int code = 1000, const char[] reason = "")` | `websocket_close` | |
| `State` | `websocket_get_state` | A `WebSocketState`. Read-only. |
| `QueuedBytes` | `websocket_get_queued_bytes` | Bytes waiting in the send queue. Read-only. |
| `GetUrl(char[] buffer, int maxlength)` | `websocket_get_url` | Writes the URL given to the constructor. Returns the number of bytes written. |

### Options and callbacks

| Method | Native |
|---|---|
| `SetHeader(const char[] name, const char[] value)` | `websocket_set_header` |
| `SetTlsVerify(bool verify)` | `websocket_set_tls_verify` |
| `SetCaFile(const char[] file)` | `websocket_set_ca_file` |
| `SetProxy(const char[] proxy)` | `websocket_set_proxy` |
| `SetConnectTimeout(float seconds)` | `websocket_set_connect_timeout` |
| `SetIdleTimeout(float seconds)` | `websocket_set_idle_timeout` |
| `SetKeepalive(float interval, float timeout = 0.0)` | `websocket_set_keepalive` |
| `SetReconnect(bool enable, float initialDelay = 1.0, float maxDelay = 60.0, int maxAttempts = 0)` | `websocket_set_reconnect` |
| `SetFrameMode(bool frames)` | `websocket_set_frame_mode` |
| `SetMaxMessageSize(int bytes)` | `websocket_set_max_message_size` |
| `SetMaxSendQueue(int bytes)` | `websocket_set_max_send_queue` |
| `SetOptInt(CURLoption option, int value)` | `websocket_setopt_int` |
| `SetOptString(CURLoption option, const char[] value)` | `websocket_setopt_string` |
| `SetOnOpen(WebSocketOpenCallback callback)` | `websocket_set_on_open` |
| `SetOnMessage(WebSocketMessageCallback callback)` | `websocket_set_on_message` |
| `SetOnFrame(WebSocketFrameCallback callback)` | `websocket_set_on_frame` |
| `SetOnPong(WebSocketPongCallback callback)` | `websocket_set_on_pong` |
| `SetOnReconnect(WebSocketReconnectCallback callback)` | `websocket_set_on_reconnect` |
| `SetOnClose(WebSocketCloseCallback callback)` | `websocket_set_on_close` |

All of these throw an error when called after `Connect()` or with a value that is out of range.

### Sending

| Method | Native | Returns |
|---|---|---|
| `SendText(const char[] text)` | `websocket_send_text` | `bool`: whether the message was queued |
| `SendBinary(const char[] data, int length)` | `websocket_send_binary` | `bool` |
| `SendBuffer(CurlBuffer buffer, bool binary = true)` | `websocket_send_buffer` | `bool` |
| `Ping(const char[] payload = "", int length = -1)` | `websocket_ping` | `bool` |

All of these throw an error when called before `Connect()`, and for a negative `length` (`SendBinary`), an invalid
buffer (`SendBuffer`) or a payload above 125 bytes (`Ping`).

### Enums

| Enum | Values |
|---|---|
| `WebSocketState` | `WebSocketState_Idle`, `WebSocketState_Connecting`, `WebSocketState_Open`, `WebSocketState_Reconnecting`, `WebSocketState_Closing`, `WebSocketState_Closed` |
| `WebSocketMessageType` | `WebSocketMessage_Text`, `WebSocketMessage_Binary` |
| `WebSocketFrameFlags` | `WebSocketFrame_Text` (1), `WebSocketFrame_Binary` (2), `WebSocketFrame_Continued` (4) |

### What the WebSocket does not offer

The answer of the server to the opening request cannot be read: neither its headers nor the subprotocol it chose.

## Common mistakes

- **Setting an option or callback after `Connect()`.** That throws an error. Configure first, then connect.
- **Connecting a finished WebSocket again.** `Connect()` works once per handle. After `OnClose`, delete the handle
  and create a new `WebSocket`.
- **Calling `Close()` right after a send.** `Close` does not wait for the send queue, so the message is usually
  lost.
- **Taking `true` from a send method as "delivered".** It means "queued". A message arrived only when the server
  says so.
- **Keeping a message buffer.** The `CurlBuffer` of `OnMessage`, `OnFrame` and `OnPong` is closed when the callback
  returns. Keep a `Clone()`.
- **Logging in only once.** With reconnecting on, the server sees a new connection after every reconnect. Send the
  login in `OnOpen`, not after `Connect()`.
- **Reconnecting forever to a server that will never accept.** Limit the attempts with `maxAttempts` or stop in
  `OnReconnect`.
- **No keepalive on a quiet connection.** Without pings or an idle timeout, a connection that died silently is only
  noticed when the plugin next sends something. Set `SetKeepalive`.
- **Sending messages larger than the send queue.** They are refused every time. Raise `SetMaxSendQueue` above the
  size of the largest message.
- **Typing `ws://` URLs without quotes on the server console.** `//` starts a comment there.
