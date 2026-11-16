/**
 * Example: download a text file into a CurlBuffer and read it line by line.
 *
 * Shows why CurlBuffer exists: the answer of a server can be larger than a
 * plugin's memory, so it is collected in the extension and read in pieces.
 * The file is an item whitelist from whitelist.tf, which looks like this:
 *
 *   // Whitelist: ETF2L 6v6 Server mp_tournament_whitelist file (ID: 20077)
 *   "item_whitelist"
 *   {
 *       "unlisted_items_default_to"    "1"
 *       "Bonk! Atomic Punch"           "0"
 *       ...
 *   }
 *
 *   sm_whitelist_check
 *
 * prints how many items the whitelist bans and the first few of them.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: whitelist check",
	author = "davenonymous",
	description = "Downloads an item whitelist into a CurlBuffer and reads it",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_Url;

public void OnPluginStart()
{
	g_Url = CreateConVar("sm_whitelist_url", "https://whitelist.tf/etf2l_whitelist_6v6.txt", "The whitelist to check");
	RegAdminCmd("sm_whitelist_check", Command_Check, ADMFLAG_GENERIC, "Counts the items the whitelist bans");
}

public Action Command_Check(int client, int args)
{
	char url[256];
	g_Url.GetString(url, sizeof(url));

	CurlBuffer whitelist = new CurlBuffer();

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetTimeout(30);
	easy.SetOptInt(CURLOPT_FAILONERROR, 1);
	easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnData, whitelist);
	easy.PerformThread(OnDownloaded, whitelist);
	return Plugin_Handled;
}

public int OnData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb, CurlBuffer whitelist)
{
	int length = bytes * nmemb;
	whitelist.Append(buffer, length);
	return length;
}

public void OnDownloaded(CurlEasy easy, CURLcode code, CurlBuffer whitelist)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("Cannot download the whitelist: %s", error);
	} else {
		PrintToServer("The whitelist has %d bytes", whitelist.Length);
		CountBannedItems(whitelist);
	}

	delete easy;
	delete whitelist;
}

void CountBannedItems(CurlBuffer whitelist)
{
	int banned = 0;
	char line[256];
	int start = 0;

	while (start < whitelist.Length) {
		// A line ends at the next line feed, the last one at the end.
		int end = whitelist.Find("\n", -1, start);
		if (end == -1) {
			end = whitelist.Length;
		}

		// Copy the line, cut off if it is longer than the array.
		int length = end - start;
		if (length > sizeof(line) - 1) {
			length = sizeof(line) - 1;
		}
		whitelist.GetString(start, line, length + 1);
		start = end + 1;

		char item[128];
		if (!IsBannedItem(line, item, sizeof(item))) {
			continue;
		}
		banned++;
		if (banned <= 5) {
			PrintToServer("  banned: %s", item);
		}
	}

	PrintToServer("%d items are banned", banned);
}

/**
 * Whether a line is `"<item>"  "0"`; the item's name is copied to `item`.
 */
bool IsBannedItem(const char[] line, char[] item, int maxlength)
{
	char parts[2][128];
	char trimmed[256];
	strcopy(trimmed, sizeof(trimmed), line);
	TrimString(trimmed);
	if (trimmed[0] != '"') {
		return false;  // A comment, a brace or an empty line.
	}

	// "name" <whitespace> "value": split at the quote that ends the name.
	int nameEnd = FindCharInString(trimmed[1], '"');
	if (nameEnd == -1) {
		return false;
	}
	strcopy(parts[0], nameEnd + 1 < sizeof(parts[]) ? nameEnd + 1 : sizeof(parts[]), trimmed[1]);
	strcopy(parts[1], sizeof(parts[]), trimmed[nameEnd + 2]);
	TrimString(parts[1]);

	if (!StrEqual(parts[1], "\"0\"")) {
		return false;
	}
	strcopy(item, maxlength, parts[0]);
	return true;
}
