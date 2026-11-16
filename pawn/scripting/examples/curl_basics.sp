/**
 * Example: the smaller features of CurlEasy, one console command each.
 *
 *   sm_curl_info                      what the linked libcurl can do
 *   sm_curl_head "<url>"              a blocking HEAD request, headers to a file
 *   sm_curl_put_file "<url>" <file>   upload a file with HTTP PUT
 *   sm_curl_put_text "<url>" <text>   upload generated data with a read callback
 *
 * URLs must be in quotes on the server console, since // starts a comment
 * there and : separates arguments.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: basics",
	author = "davenonymous",
	description = "Small examples of the CurlEasy methodmap",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

#define HEADER_FILE "addons/sourcemod/data/curl_basics_headers.txt"

// Number options that every transfer of this plugin gets, as pairs of
// {option, value}, for SetOptIntArray.
int g_CommonOptions[][2] = {
	{ view_as<int>(CURLOPT_CONNECTTIMEOUT), 10 },
	{ view_as<int>(CURLOPT_TIMEOUT), 30 },
	{ view_as<int>(CURLOPT_FOLLOWLOCATION), 1 },
	{ view_as<int>(CURLOPT_MAXREDIRS), 5 },
};

public void OnPluginStart()
{
	RegServerCmd("sm_curl_info", Command_Info, "Prints what the linked libcurl can do");
	RegServerCmd("sm_curl_head", Command_Head, "sm_curl_head <url> - prints the headers a URL answers with");
	RegServerCmd("sm_curl_put_file", Command_PutFile, "sm_curl_put_file <url> <file> - uploads a file with PUT");
	RegServerCmd("sm_curl_put_text", Command_PutText, "sm_curl_put_text <url> <text> - uploads text with PUT");
}

/* --- sm_curl_info: static methods, no handle needed --- */

public Action Command_Info(int args)
{
	char text[512];
	CurlEasy.Version(text, sizeof(text));
	PrintToServer("Version: %s", text);
	CurlEasy.Protocols(text, sizeof(text));
	PrintToServer("Protocols: %s", text);

	int features = CurlEasy.Features();
	PrintToServer("TLS: %s, IPv6: %s, compressed answers: %s",
	              (features & CURL_VERSION_SSL) ? "yes" : "no",
	              (features & CURL_VERSION_IPV6) ? "yes" : "no",
	              (features & CURL_VERSION_LIBZ) ? "yes" : "no");
	return Plugin_Handled;
}

/* --- sm_curl_head: a blocking transfer --- */

public Action Command_Head(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));

	CurlFile headerFile = new CurlFile(HEADER_FILE, "wb");
	if (headerFile == null) {
		PrintToServer("Cannot write %s", HEADER_FILE);
		return Plugin_Handled;
	}

	CurlEasy easy = new CurlEasy();
	easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
	easy.SetUrl(url);
	easy.SetOptInt(CURLOPT_NOBODY, 1);  // Ask for the headers only: a HEAD request.
	easy.SetHeaderFile(headerFile);

	// Perform() returns when the transfer is complete. The whole server
	// waits that long, so this is for console commands and tools; anything
	// that runs while people play should use PerformThread().
	//
	// A blocking transfer needs LoadOpt() first: it hands the options set
	// above to libcurl, which PerformThread() does by itself. LoadOpt()
	// fails when libcurl refuses one of the values.
	CURLcode code = easy.LoadOpt();
	if (code == CURLE_OK) {
		code = easy.Perform();
	}
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		PrintToServer("The request failed: %s", error);
	} else {
		char finalUrl[256];
		easy.GetEffectiveUrl(finalUrl, sizeof(finalUrl));
		PrintToServer("Status %d from %s after %.3f seconds", easy.ResponseCode, finalUrl, easy.TotalTime);

		// Everything else libcurl knows about the transfer is read with
		// GetInfoInt, into an int or a float depending on the info, and
		// with GetInfoString.
		int redirects;
		easy.GetInfoInt(CURLINFO_REDIRECT_COUNT, redirects);
		float connectSeconds;
		easy.GetInfoInt(CURLINFO_CONNECT_TIME, connectSeconds);
		char address[64];
		easy.GetInfoString(CURLINFO_PRIMARY_IP, address, sizeof(address));
		PrintToServer("%d redirects, connected to %s in %.4f seconds", redirects, address, connectSeconds);
	}

	delete easy;
	delete headerFile;  // Closing the file writes it to the disk.

	if (code == CURLE_OK) {
		PrintFile(HEADER_FILE);
	}
	return Plugin_Handled;
}

void PrintFile(const char[] path)
{
	File file = OpenFile(path, "r");
	if (file == null) {
		return;
	}
	char line[256];
	while (file.ReadLine(line, sizeof(line))) {
		TrimString(line);
		if (line[0] != '\0') {
			PrintToServer("  %s", line);
		}
	}
	delete file;
}

/* --- sm_curl_put_file: upload a file --- */

public Action Command_PutFile(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));
	char path[PLATFORM_MAX_PATH];
	GetCmdArg(2, path, sizeof(path));

	CurlFile file = new CurlFile(path, "rb");
	if (file == null) {
		PrintToServer("Cannot read %s", path);
		return Plugin_Handled;
	}

	CurlEasy easy = new CurlEasy();
	easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
	easy.SetUrl(url);
	easy.SetOptInt(CURLOPT_UPLOAD, 1);  // Send a body instead of asking for one: HTTP PUT.
	easy.SetReadFile(file);
	// With the size the request has a Content-Length; without it libcurl
	// sends the body in chunks, which not every server accepts.
	easy.SetOptInt(CURLOPT_INFILESIZE, FileSize(path));
	easy.PerformThread(OnPutDone, file);
	return Plugin_Handled;
}

public void OnPutDone(CurlEasy easy, CURLcode code, Handle file)
{
	char error[256];
	easy.GetError(code, error, sizeof(error));
	PrintToServer("PUT: %s, status %d", error, easy.ResponseCode);
	delete easy;
	delete file;  // null for sm_curl_put_text, which delete accepts.
}

/* --- sm_curl_put_text: upload data from the plugin's memory --- */

char g_Upload[1024];
int g_UploadLength;
int g_UploadSent;

public Action Command_PutText(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));
	GetCmdArg(2, g_Upload, sizeof(g_Upload));
	g_UploadLength = strlen(g_Upload);
	g_UploadSent = 0;

	CurlEasy easy = new CurlEasy();
	easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
	easy.SetUrl(url);
	easy.SetOptInt(CURLOPT_UPLOAD, 1);
	easy.SetOptInt(CURLOPT_INFILESIZE, g_UploadLength);
	easy.SetOptFunction(CURLOPT_READFUNCTION, OnUploadData);
	easy.PerformThread(OnPutDone);
	return Plugin_Handled;
}

/**
 * libcurl asks for the next piece of the upload: at most bytes * nmemb
 * bytes. The callback hands them over with SetSendBuffer() and returns
 * their number; 0 says the upload is complete.
 */
public int OnUploadData(CurlEasy easy, const int bytes, const int nmemb)
{
	int count = g_UploadLength - g_UploadSent;
	if (count > bytes * nmemb) {
		count = bytes * nmemb;
	}
	if (count <= 0) {
		return 0;
	}

	easy.SetSendBuffer(g_Upload[g_UploadSent], count);
	g_UploadSent += count;
	return count;
}
