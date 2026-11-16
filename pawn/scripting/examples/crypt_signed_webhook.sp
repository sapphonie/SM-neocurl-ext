/**
 * Example: send a signed request to your own backend.
 *
 * Shows an HMAC over a request body, so the receiver can check that the
 * request comes from this server and was not changed on the way. The
 * signature uses the header format GitHub made common for webhooks:
 *
 *   X-Hub-Signature-256: sha256=<HMAC-SHA256 of the body, lowercase hex>
 *
 * The receiver computes the same HMAC with the shared secret and compares.
 *
 *   sm_signed_url "https://backend.example.com/hook"
 *   sm_signed_secret "<the shared secret>"
 *   sm_signed_event match_started
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: signed webhook",
	author = "davenonymous",
	description = "Sends HMAC-signed requests to a backend",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_Url;
ConVar g_Secret;

public void OnPluginStart()
{
	g_Url = CreateConVar("sm_signed_url", "", "URL the signed events are posted to");
	g_Secret = CreateConVar("sm_signed_secret", "", "Secret shared with the receiver", FCVAR_PROTECTED);
	RegAdminCmd("sm_signed_event", Command_Event, ADMFLAG_RCON, "sm_signed_event <name> - posts a signed event");
}

public Action Command_Event(int client, int args)
{
	char url[256];
	g_Url.GetString(url, sizeof(url));
	char secret[128];
	g_Secret.GetString(secret, sizeof(secret));
	if (url[0] == '\0' || secret[0] == '\0') {
		ReplyToCommand(client, "Set sm_signed_url and sm_signed_secret first.");
		return Plugin_Handled;
	}

	char event[64];
	GetCmdArg(1, event, sizeof(event));
	char body[256];
	Format(body, sizeof(body), "{\"event\":\"%s\",\"time\":%d}", event, GetTime());

	// HMAC-SHA256 has 32 bytes: 64 hex characters and the NUL. The -1
	// lengths mean "up to the NUL" for the key and for the input.
	char signature[65];
	Crypt.HmacString(Openssl_Hash_SHA256, secret, -1, body, -1, signature, sizeof(signature));

	char signatureHeader[128];
	Format(signatureHeader, sizeof(signatureHeader), "X-Hub-Signature-256: sha256=%s", signature);

	CurlSlist headers = new CurlSlist();
	headers.Append("Content-Type: application/json");
	headers.Append(signatureHeader);

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetHeaders(headers);
	easy.SetPostFields(body);
	easy.SetTimeout(10);
	easy.PerformThread(OnEventPosted, headers);
	return Plugin_Handled;
}

public void OnEventPosted(CurlEasy easy, CURLcode code, CurlSlist headers)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("Signed event: the request failed: %s", error);
	} else if (easy.ResponseCode != 200) {
		// 401 from the receiver usually means the secrets differ.
		LogError("Signed event: HTTP status %d", easy.ResponseCode);
	} else {
		LogMessage("Signed event: accepted");
	}

	delete easy;
	delete headers;
}
