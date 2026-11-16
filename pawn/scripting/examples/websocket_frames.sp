/**
 * Example: receive a large binary message piece by piece (frame mode).
 *
 * Shows frame mode, binary sends from an array and from a CurlBuffer, a
 * ping with its pong, and a clean close. It needs an echo server: a
 * WebSocket server that sends every message back.
 *
 *   sm_ws_frames "ws://127.0.0.1:8098"
 *
 * The plugin sends a small binary message, a 300000 byte binary message
 * and a ping, adds up what comes back and closes the connection.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: WebSocket frame mode",
	author = "davenonymous",
	description = "Receives large WebSocket messages in pieces",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

#define LARGE_SIZE 300000

int g_Pieces;
int g_MessageBytes;
int g_Messages;

public void OnPluginStart()
{
	RegServerCmd("sm_ws_frames", Command_Frames, "sm_ws_frames <url> - runs the frame mode example");
}

public Action Command_Frames(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	g_Pieces = 0;
	g_MessageBytes = 0;
	g_Messages = 0;

	WebSocket ws = new WebSocket(url);
	// Frame mode: OnFrame is called for every piece of a frame as it
	// arrives, and OnMessage is never called. A message of any size can
	// be handled this way, since it is never held in memory as a whole.
	ws.SetFrameMode(true);
	ws.SetConnectTimeout(10.0);
	// Give up when nothing at all arrives for 20 seconds.
	ws.SetIdleTimeout(20.0);
	ws.SetOnOpen(OnOpen);
	ws.SetOnFrame(OnFrame);
	ws.SetOnPong(OnPong);
	ws.SetOnClose(OnClose);
	ws.Connect();
	return Plugin_Handled;
}

public void OnOpen(WebSocket ws, any data)
{
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

	ws.Ping("are you there?");
}

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

public void OnPong(WebSocket ws, CurlBuffer payload, any data)
{
	char text[64];
	payload.GetString(0, text, sizeof(text));
	PrintToServer("Pong: %s", text);
}

public void OnClose(WebSocket ws, CURLcode error, int code, const char[] reason, any data)
{
	if (error != CURLE_OK) {
		char text[256];
		CurlEasy.StrError(error, text, sizeof(text));
		PrintToServer("Closed after an error: %s", text);
	} else {
		PrintToServer("Closed with code %d (%s)", code, reason);
	}
	delete ws;
}
