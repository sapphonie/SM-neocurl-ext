/**
 * Test plugin of the integration tests (test/integration/test_lifetime.py):
 * what happens when curl handles are closed at awkward moments, and other
 * cases that once crashed the server or went wrong.
 *
 * Each console command starts one case and prints a line that starts with
 * "[lifetime]". A callback that must not be called prints "UNEXPECTED".
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL lifetime test",
	author = "davenonymous",
	description = "Closes curl handles at awkward moments",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

#define DATA_DIR "addons/sourcemod/data"

CurlEasy g_Kept;
CurlFile g_HeaderFile;
int g_BodyBytes;
int g_SendValue;

public void OnPluginStart()
{
	RegServerCmd("lt_slow_request", Command_SlowRequest, "lt_slow_request <url> - starts a transfer and keeps its handle");
	RegServerCmd("lt_delete_kept", Command_DeleteKept, "Deletes the handle lt_slow_request or lt_idle_wait kept");
	RegServerCmd("lt_idle_wait", Command_IdleWait, "lt_idle_wait <host:port> - connects and waits in send & receive");
	RegServerCmd("lt_delete_in_write", Command_DeleteInWrite, "lt_delete_in_write <url> <blocking> - deletes in the write callback");
	RegServerCmd("lt_header_and_callback", Command_HeaderAndCallback, "lt_header_and_callback <url> - a header file and a write callback");
	RegServerCmd("lt_early_delete", Command_EarlyDelete, "lt_early_delete <url> - deletes a list and a file before the transfer");
	RegServerCmd("lt_sendrecv_value", Command_SendRecvValue, "lt_sendrecv_value <host:port> - the value of SendRecv's callbacks");
	RegServerCmd("lt_progress_blocking", Command_ProgressBlocking, "lt_progress_blocking <url> <stop> - progress of a blocking transfer");
	RegServerCmd("lt_delete_in_progress", Command_DeleteInProgress, "lt_delete_in_progress <url> - deletes in the progress callback");
}

/* --- A handle that is closed, or whose plugin unloads, during its transfer --- */

public Action Command_SlowRequest(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	g_Kept = new CurlEasy();
	g_Kept.SetUrl(url);
	g_Kept.PerformThread(OnUnexpectedComplete);
	PrintToServer("[lifetime] slow_request: started");
	return Plugin_Handled;
}

public Action Command_DeleteKept(int args)
{
	delete g_Kept;
	PrintToServer("[lifetime] delete_kept: deleted");
	return Plugin_Handled;
}

public void OnUnexpectedComplete(CurlEasy easy, CURLcode code)
{
	PrintToServer("[lifetime] UNEXPECTED complete callback with code %d", code);
}

/* --- A handle whose send & receive thread sleeps --- */

public Action Command_IdleWait(int args)
{
	char address[128];
	GetCmdArg(1, address, sizeof(address));

	g_Kept = new CurlEasy();
	g_Kept.SetUrl(address);
	g_Kept.SetOptInt(CURLOPT_CONNECT_ONLY, 1);
	g_Kept.PerformThread(OnIdleConnected);
	return Plugin_Handled;
}

public void OnIdleConnected(CurlEasy easy, CURLcode code)
{
	if (code != CURLE_OK) {
		PrintToServer("[lifetime] idle_wait: cannot connect, code %d", code);
		return;
	}
	easy.SendRecv(OnUnexpectedSend, OnUnexpectedReceive, OnUnexpectedComplete, SendRecv_Act_GOTO_WAIT, 5000, 5000);
	PrintToServer("[lifetime] idle_wait: waiting");
}

public SendRecv_Act OnUnexpectedSend(CurlEasy easy, CURLcode code, const int sentBytes)
{
	PrintToServer("[lifetime] UNEXPECTED send callback");
	return SendRecv_Act_GOTO_END;
}

public SendRecv_Act OnUnexpectedReceive(CurlEasy easy, CURLcode code, const char[] data, const int size)
{
	PrintToServer("[lifetime] UNEXPECTED receive callback");
	return SendRecv_Act_GOTO_END;
}

/* --- A handle that is deleted inside its own write callback --- */

public Action Command_DeleteInWrite(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));
	bool blocking = GetCmdArgInt(2) != 0;

	g_Kept = new CurlEasy();
	g_Kept.SetUrl(url);
	g_Kept.SetOptFunction(CURLOPT_WRITEFUNCTION, OnWriteDelete);
	if (!blocking) {
		g_Kept.PerformThread(OnUnexpectedComplete);
		return Plugin_Handled;
	}

	g_Kept.LoadOpt();
	CURLcode code = g_Kept.Perform();
	PrintToServer("[lifetime] delete_in_write: blocking transfer returned %d", code);
	return Plugin_Handled;
}

public int OnWriteDelete(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb)
{
	delete g_Kept;
	PrintToServer("[lifetime] delete_in_write: deleted in the callback");
	return bytes * nmemb;
}

/* --- A header file together with a write callback --- */

public Action Command_HeaderAndCallback(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	g_BodyBytes = 0;
	g_HeaderFile = new CurlFile(DATA_DIR ... "/lifetime_headers.txt", "wb");

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetHeaderFile(g_HeaderFile);
	easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnWriteCount);
	easy.PerformThread(OnHeaderAndCallbackComplete);
	return Plugin_Handled;
}

public int OnWriteCount(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb)
{
	g_BodyBytes += bytes * nmemb;
	return bytes * nmemb;
}

public void OnHeaderAndCallbackComplete(CurlEasy easy, CURLcode code)
{
	delete easy;
	delete g_HeaderFile;
	PrintToServer("[lifetime] header_and_callback: code %d, body %d bytes, header file %d bytes", code, g_BodyBytes,
	              FileSize(DATA_DIR ... "/lifetime_headers.txt"));
}

/* --- A list and a file that are closed before their transfer starts --- */

public Action Command_EarlyDelete(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	CurlSlist headers = new CurlSlist();
	headers.Append("X-Early: deleted");
	CurlFile file = new CurlFile(DATA_DIR ... "/lifetime_early.txt", "wb");

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetHeaders(headers);
	easy.SetWriteFile(file);
	delete headers;
	delete file;
	easy.PerformThread(OnEarlyDeleteComplete);
	return Plugin_Handled;
}

public void OnEarlyDeleteComplete(CurlEasy easy, CURLcode code)
{
	int status = easy.ResponseCode;
	delete easy;
	PrintToServer("[lifetime] early_delete: code %d, status %d, file %d bytes", code, status,
	              FileSize(DATA_DIR ... "/lifetime_early.txt"));
}

/* --- The value that SendRecv passes to its callbacks --- */

public Action Command_SendRecvValue(int args)
{
	char address[128];
	GetCmdArg(1, address, sizeof(address));

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(address);
	easy.SetOptInt(CURLOPT_CONNECT_ONLY, 1);
	easy.PerformThread(OnValueConnected, 111);
	return Plugin_Handled;
}

public void OnValueConnected(CurlEasy easy, CURLcode code, any value)
{
	easy.SetSendBuffer("value\n");
	easy.SendRecv(OnValueSend, OnValueReceive, OnValueComplete, SendRecv_Act_GOTO_SEND, 5000, 5000, 1024, 222);
}

public SendRecv_Act OnValueSend(CurlEasy easy, CURLcode code, const int sentBytes, any value)
{
	g_SendValue = value;
	return SendRecv_Act_GOTO_END;
}

public SendRecv_Act OnValueReceive(CurlEasy easy, CURLcode code, const char[] data, const int size, any value)
{
	return SendRecv_Act_GOTO_END;
}

public void OnValueComplete(CurlEasy easy, CURLcode code, any value)
{
	PrintToServer("[lifetime] sendrecv_value: send %d, complete %d", g_SendValue, value);
	delete easy;
}

/* --- The progress callback of a blocking transfer --- */

int g_ProgressCalls;
int g_ProgressDownloaded;
bool g_ProgressStop;

public Action Command_ProgressBlocking(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));
	g_ProgressStop = GetCmdArgInt(2) != 0;
	g_ProgressCalls = 0;
	g_ProgressDownloaded = 0;

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetProgressCallback(OnBlockingProgress, 0.0, 333);
	easy.LoadOpt();
	CURLcode code = easy.Perform();
	delete easy;
	PrintToServer("[lifetime] progress_blocking: code %d, %d calls, %d bytes", code, g_ProgressCalls,
	              g_ProgressDownloaded);
	return Plugin_Handled;
}

public Action OnBlockingProgress(CurlEasy easy, int downloaded, int downloadTotal, int uploaded, int uploadTotal,
                                 any value)
{
	if (value != 333) {
		PrintToServer("[lifetime] UNEXPECTED progress value %d", value);
	}
	g_ProgressCalls++;
	g_ProgressDownloaded = downloaded;
	return g_ProgressStop ? Plugin_Stop : Plugin_Continue;
}

/* --- A handle that is deleted inside its progress callback --- */

public Action Command_DeleteInProgress(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	g_Kept = new CurlEasy();
	g_Kept.SetUrl(url);
	g_Kept.SetProgressCallback(OnProgressDelete, 0.2);
	g_Kept.PerformThread(OnUnexpectedComplete);
	return Plugin_Handled;
}

public Action OnProgressDelete(CurlEasy easy, int downloaded, int downloadTotal, int uploaded, int uploadTotal)
{
	delete g_Kept;
	PrintToServer("[lifetime] delete_in_progress: deleted in the callback");
	return Plugin_Continue;
}
