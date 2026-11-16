/**
 * Example: post a message to a Discord channel through a webhook.
 *
 * Shows a JSON POST with CurlEasy: a request header from a CurlSlist, the
 * body with SetPostFields, a threaded transfer and how to tell apart "the
 * transfer failed" from "the server answered with an error status".
 *
 * Setup: create a webhook in Discord (channel settings, Integrations) and
 * put its URL into sm_discord_webhook_url, in quotes.
 *
 *   sm_discord_webhook_url "https://discord.com/api/webhooks/<id>/<token>"
 *   sm_discord Server restarts in five minutes
 *
 * The plugin also announces every map change.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: Discord webhook",
	author = "davenonymous",
	description = "Posts messages to a Discord webhook",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

// Discord accepts up to 2000 characters of content.
#define MAX_CONTENT 2000

ConVar g_WebhookUrl;

public void OnPluginStart()
{
	g_WebhookUrl = CreateConVar("sm_discord_webhook_url", "", "URL of the Discord webhook to post to", FCVAR_PROTECTED);
	RegAdminCmd("sm_discord", Command_Discord, ADMFLAG_CHAT, "sm_discord <message> - posts a message to Discord");
}

public void OnMapStart()
{
	char map[PLATFORM_MAX_PATH];
	GetCurrentMap(map, sizeof(map));

	char message[PLATFORM_MAX_PATH + 32];
	Format(message, sizeof(message), "Map changed to %s", map);
	PostToDiscord(message);
}

public Action Command_Discord(int client, int args)
{
	if (args < 1) {
		ReplyToCommand(client, "Usage: sm_discord <message>");
		return Plugin_Handled;
	}

	char message[256];
	GetCmdArgString(message, sizeof(message));
	PostToDiscord(message);
	return Plugin_Handled;
}

void PostToDiscord(const char[] message)
{
	char url[256];
	g_WebhookUrl.GetString(url, sizeof(url));
	if (url[0] == '\0') {
		return;
	}

	// The body is the JSON object {"content":"<message>"}.
	char content[MAX_CONTENT * 2 + 1];
	EscapeJsonString(message, content, sizeof(content));
	char body[sizeof(content) + 16];
	Format(body, sizeof(body), "{\"content\":\"%s\"}", content);

	// Without this header libcurl would announce the body as a web form
	// (application/x-www-form-urlencoded) and Discord would refuse it.
	CurlSlist headers = new CurlSlist();
	headers.Append("Content-Type: application/json");

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetHeaders(headers);
	easy.SetPostFields(body);  // Setting a body makes the request a POST.
	easy.SetTimeout(10);

	// The headers are closed when the transfer is complete, so they travel
	// to the callback as its data.
	easy.PerformThread(OnPosted, headers);
}

public void OnPosted(CurlEasy easy, CURLcode code, CurlSlist headers)
{
	if (code != CURLE_OK) {
		// No answer at all: no network, DNS failure, timeout, TLS error ...
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("Discord webhook: the request failed: %s", error);
	} else if (easy.ResponseCode != 204) {
		// Discord answered, but not with "204 No Content", its success
		// status: 404 for a deleted webhook, 429 when rate limited, ...
		LogError("Discord webhook: HTTP status %d", easy.ResponseCode);
	}

	delete easy;
	delete headers;
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
		} else if (c == '\n') {
			output[length++] = '\\';
			output[length++] = 'n';
		} else if (c < 0x20) {
			length += Format(output[length], maxlength - length, "\\u%04x", c);
		} else {
			output[length++] = c;
		}
	}
	output[length] = '\0';
}
