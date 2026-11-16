/**
 * Example: talk to a TCP or UDP service with send & receive.
 *
 * Shows the raw connection mode of CurlEasy: connect only, then send and
 * receive bytes yourself, with a thread of the extension doing the waiting.
 * The plugin sends one line and prints the first answer.
 *
 *   sm_tcp_send tcpbin.com:4242 hello
 *   sm_tcp_send udp://127.0.0.1:9000 hello
 *
 * The first argument is host:port for TCP, or udp://host:port for UDP.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: TCP client",
	author = "davenonymous",
	description = "Sends a line to a TCP or UDP service and prints the answer",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

// Milliseconds a send or a receive may wait for the connection.
#define IO_TIMEOUT 5000

public void OnPluginStart()
{
	RegAdminCmd("sm_tcp_send", Command_Send, ADMFLAG_RCON, "sm_tcp_send <host:port> <text> - sends a line, prints the answer");
}

public Action Command_Send(int client, int args)
{
	if (args != 2) {
		ReplyToCommand(client, "Usage: sm_tcp_send <host:port> <text>");
		return Plugin_Handled;
	}

	char address[128];
	GetCmdArg(1, address, sizeof(address));
	char line[256];
	GetCmdArg(2, line, sizeof(line));
	StrCat(line, sizeof(line), "\n");

	// The line travels to the callbacks in a DataPack.
	DataPack pack = new DataPack();
	pack.WriteString(line);

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(address);
	// Connect, and then stop: no request is sent and no answer is read.
	easy.SetOptInt(CURLOPT_CONNECT_ONLY, 1);
	easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
	easy.PerformThread(OnConnected, pack);
	return Plugin_Handled;
}

public void OnConnected(CurlEasy easy, CURLcode code, DataPack pack)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		PrintToServer("Cannot connect: %s", error);
		delete easy;
		delete pack;
		return;
	}

	char line[256];
	pack.Reset();
	pack.ReadString(line, sizeof(line));

	// What the first send sends. Then the send & receive thread starts
	// with a send; each callback tells it what to do next.
	easy.SetSendBuffer(line);
	easy.SendRecv(OnSent, OnReceived, OnEnded, SendRecv_Act_GOTO_SEND, IO_TIMEOUT, IO_TIMEOUT, 1024, pack);
}

public SendRecv_Act OnSent(CurlEasy easy, CURLcode code, const int sentBytes, DataPack pack)
{
	if (code != CURLE_OK) {
		// The error reaches OnEnded as its code.
		return SendRecv_Act_GOTO_END;
	}
	PrintToServer("Sent %d bytes", sentBytes);
	return SendRecv_Act_GOTO_RECV;
}

public SendRecv_Act OnReceived(CurlEasy easy, CURLcode code, const char[] data, const int size, DataPack pack)
{
	if (code == CURLE_OK && size > 0) {
		// The data is not NUL-terminated text: copy it with its length.
		char[] text = new char[size + 1];
		for (int i = 0; i < size; i++) {
			text[i] = data[i];
		}
		text[size] = '\0';
		PrintToServer("Received %d bytes: %s", size, text);
	}
	// One answer is enough for this example.
	return SendRecv_Act_GOTO_END;
}

public void OnEnded(CurlEasy easy, CURLcode code, DataPack pack)
{
	if (code != CURLE_OK) {
		char error[256];
		CurlEasy.StrError(code, error, sizeof(error));
		PrintToServer("The connection ended with an error: %s", error);
	}
	// Deleting the handle closes the connection.
	delete easy;
	delete pack;
}
