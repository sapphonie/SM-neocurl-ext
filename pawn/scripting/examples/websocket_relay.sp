/**
 * Example: relay chat between the game server and your own backend.
 *
 * Shows a long-lived WebSocket: a request header for authentication,
 * keepalive pings, reconnecting after errors, sending text, receiving
 * messages as CurlBuffers and keeping one with Clone().
 *
 * The backend is a WebSocket server of your own. This plugin sends it one
 * JSON text message per chat line,
 *   {"type":"chat","name":"<player>","text":"<message>"}
 * and prints every text message it receives to the game's chat.
 *
 *   sm_relay_url "wss://relay.example.com/gameserver"
 *   sm_relay_token "<secret>"
 *   sm_relay_connect           connect, or connect again after a close
 *   sm_relay_say <text>        send a line from the console
 *   sm_relay_status            the state, the queue and the last message
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: WebSocket relay",
	author = "davenonymous",
	description = "Relays chat to a backend over a WebSocket",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_Url;
ConVar g_Token;

WebSocket g_Relay;
CurlBuffer g_LastMessage;

public void OnPluginStart()
{
	g_Url = CreateConVar("sm_relay_url", "", "ws:// or wss:// URL of the relay backend");
	g_Token = CreateConVar("sm_relay_token", "", "Token sent to the backend as Authorization header", FCVAR_PROTECTED);
	RegAdminCmd("sm_relay_connect", Command_Connect, ADMFLAG_RCON, "Connects to the relay backend");
	RegAdminCmd("sm_relay_say", Command_Say, ADMFLAG_CHAT, "sm_relay_say <text> - sends a line to the backend");
	RegAdminCmd("sm_relay_status", Command_Status, ADMFLAG_GENERIC, "Prints the state of the relay connection");
}

public Action Command_Connect(int client, int args)
{
	if (g_Relay != null) {
		ReplyToCommand(client, "The relay is already connected or connecting.");
		return Plugin_Handled;
	}

	char url[256];
	g_Url.GetString(url, sizeof(url));
	if (StrContains(url, "ws://") != 0 && StrContains(url, "wss://") != 0) {
		ReplyToCommand(client, "sm_relay_url must be a ws:// or wss:// URL.");
		return Plugin_Handled;
	}

	char token[128];
	g_Token.GetString(token, sizeof(token));
	char authorization[160];
	Format(authorization, sizeof(authorization), "Bearer %s", token);

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

	ReplyToCommand(client, "Connecting to %s ...", url);
	return Plugin_Handled;
}

public void OnRelayOpen(WebSocket ws, any data)
{
	// Called after the first connect and after every successful reconnect.
	LogMessage("Relay: connected");

	char hostname[128];
	FindConVar("hostname").GetString(hostname, sizeof(hostname));
	SendJson("hello", "server", hostname);
}

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

public Action OnRelayReconnect(WebSocket ws, CURLcode error, int attempt, float delay, any data)
{
	char reason[256];
	CurlEasy.StrError(error, reason, sizeof(reason));
	LogMessage("Relay: connection lost (%s), attempt %d in %.0f seconds", reason, attempt, delay);

	// Returning Plugin_Stop here would give up; OnRelayClose would follow.
	return Plugin_Continue;
}

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

public void OnClientSayCommand_Post(int client, const char[] command, const char[] sArgs)
{
	if (client == 0) {
		return;
	}
	char name[MAX_NAME_LENGTH];
	GetClientName(client, name, sizeof(name));
	SendJson("chat", name, sArgs);
}

public Action Command_Say(int client, int args)
{
	char text[192];
	GetCmdArgString(text, sizeof(text));
	if (!SendJson("chat", "Console", text)) {
		ReplyToCommand(client, "The relay is not connected.");
	}
	return Plugin_Handled;
}

public Action Command_Status(int client, int args)
{
	if (g_Relay == null) {
		ReplyToCommand(client, "The relay is not connected.");
		return Plugin_Handled;
	}

	static const char states[][] = { "idle", "connecting", "open", "reconnecting", "closing", "closed" };
	char url[256];
	g_Relay.GetUrl(url, sizeof(url));
	ReplyToCommand(client, "%s is %s, %d bytes wait to be sent", url, states[g_Relay.State], g_Relay.QueuedBytes);

	if (g_LastMessage != null) {
		char text[192];
		g_LastMessage.GetString(0, text, sizeof(text));
		ReplyToCommand(client, "Last message (%d bytes): %s", g_LastMessage.Length, text);
	}
	return Plugin_Handled;
}

/**
 * Sends {"type":"<type>","name":"<name>","text":"<text>"}.
 *
 * @return              False when there is no connection or the message
 *                      could not be queued.
 */
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

/**
 * Escapes text for use inside a JSON string: quotes, backslashes and
 * control characters.
 */
void EscapeJsonString(const char[] text, char[] output, int maxlength)
{
	int length = 0;
	for (int i = 0; text[i] != '\0' && length < maxlength - 7; i++) {
		int c = text[i] & 0xFF;
		if (c == '"' || c == '\\') {
			output[length++] = '\\';
			output[length++] = c;
		} else if (c < 0x20) {
			length += Format(output[length], maxlength - length, "\\u%04x", c);
		} else {
			output[length++] = c;
		}
	}
	output[length] = '\0';
}
