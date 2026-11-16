/**
 * Example: look up a player in the ETF2L API.
 *
 * Shows a GET request whose answer is collected in a CurlBuffer by a write
 * callback, so its size does not matter, and reading the HTTP status and
 * the content type of the answer.
 *
 *   sm_etf2l_lookup 76561197963283262
 *
 * The API answers with JSON such as
 *   {"player":{"bans":null,"classes":[...],"country":"Sweden","id":100,
 *    "name":"Nace", ...},"status":{"code":200,"message":"OK"}}
 * and with status 404 for an unknown player.
 *
 * This example only picks the name out of the text. A real plugin should
 * read JSON with a JSON extension.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: ETF2L player lookup",
	author = "davenonymous",
	description = "Looks up players in the ETF2L API",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_ApiUrl;

public void OnPluginStart()
{
	g_ApiUrl = CreateConVar("sm_etf2l_lookup_url", "https://api-v2.etf2l.org", "Base URL of the ETF2L API");
	RegAdminCmd("sm_etf2l_lookup", Command_Lookup, ADMFLAG_GENERIC, "sm_etf2l_lookup <SteamID64> - looks up a player");
}

public Action Command_Lookup(int client, int args)
{
	if (args != 1) {
		ReplyToCommand(client, "Usage: sm_etf2l_lookup <SteamID64>");
		return Plugin_Handled;
	}

	char steamId[32];
	GetCmdArg(1, steamId, sizeof(steamId));

	CurlEasy easy = new CurlEasy();

	// The SteamID becomes a part of the URL, so it is URL-encoded: a
	// SteamID3 like [U:1:3017534] would not be a valid URL otherwise.
	char encoded[96];
	easy.Escape(steamId, encoded, sizeof(encoded));
	char url[256];
	g_ApiUrl.GetString(url, sizeof(url));
	Format(url, sizeof(url), "%s/player/%s", url, encoded);

	// The answer is collected in this buffer. It is passed to the write
	// callback and to the complete callback as their data.
	CurlBuffer answer = new CurlBuffer();

	easy.SetUrl(url);
	easy.SetUserAgent("sm-neocurl example");
	easy.SetTimeout(15);
	easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnAnswerData, answer);
	easy.PerformThread(OnAnswer, answer);
	return Plugin_Handled;
}

public int OnAnswerData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb, CurlBuffer answer)
{
	int length = bytes * nmemb;
	answer.Append(buffer, length);
	return length;
}

public void OnAnswer(CurlEasy easy, CURLcode code, CurlBuffer answer)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("ETF2L lookup failed: %s", error);
	} else if (easy.ResponseCode == 404) {
		PrintToServer("ETF2L does not know this player.");
	} else if (easy.ResponseCode != 200) {
		LogError("ETF2L lookup: HTTP status %d", easy.ResponseCode);
	} else {
		char contentType[64];
		easy.GetContentType(contentType, sizeof(contentType));

		char name[64];
		if (FindJsonString(answer, "\"name\":\"", name, sizeof(name))) {
			PrintToServer("ETF2L name: %s (%d bytes of %s)", name, answer.Length, contentType);
		} else {
			PrintToServer("The answer has no name (%d bytes of %s)", answer.Length, contentType);
		}
	}

	delete easy;
	delete answer;
}

/**
 * Copies the text between the first `key` and the next quote. Good enough
 * for an example, not a JSON parser: it does not handle escaped quotes.
 */
bool FindJsonString(CurlBuffer json, const char[] key, char[] value, int maxlength)
{
	int start = json.Find(key);
	if (start == -1) {
		return false;
	}
	start += strlen(key);

	int end = json.Find("\"", -1, start);
	if (end == -1) {
		return false;
	}

	int length = end - start;
	if (length > maxlength - 1) {
		length = maxlength - 1;
	}
	json.GetString(start, value, length + 1);
	return true;
}
