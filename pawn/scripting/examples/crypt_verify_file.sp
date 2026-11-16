/**
 * Example: digests of texts, files and buffers.
 *
 *   sm_verify_file <file> <sha256>   checks a file against a published
 *                                    SHA-256, e.g. a downloaded map
 *   sm_hash_text <text>              one text, several algorithms and
 *                                    encodings
 *   sm_hmac_file <key> <file>        the HMAC-SHA256 of a file, as base64
 *   sm_hash_buffer <text>            digest and HMAC of a CurlBuffer
 *
 * File names are relative to the game directory.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: digests",
	author = "davenonymous",
	description = "Digests and HMACs of texts, files and buffers",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

public void OnPluginStart()
{
	RegAdminCmd("sm_verify_file", Command_VerifyFile, ADMFLAG_RCON, "sm_verify_file <file> <sha256> - checks a file");
	RegAdminCmd("sm_hash_text", Command_HashText, ADMFLAG_RCON, "sm_hash_text <text> - prints digests of a text");
	RegAdminCmd("sm_hmac_file", Command_HmacFile, ADMFLAG_RCON, "sm_hmac_file <key> <file> - prints a file's HMAC");
	RegAdminCmd("sm_hash_buffer", Command_HashBuffer, ADMFLAG_RCON, "sm_hash_buffer <text> - digests of a buffer");
}

/* --- sm_verify_file: a file's digest, in the background --- */

public Action Command_VerifyFile(int client, int args)
{
	if (args != 2) {
		ReplyToCommand(client, "Usage: sm_verify_file <file> <sha256>");
		return Plugin_Handled;
	}

	char file[PLATFORM_MAX_PATH];
	GetCmdArg(1, file, sizeof(file));
	char expected[65];
	GetCmdArg(2, expected, sizeof(expected));

	// The callback needs the expected digest and the file's name.
	DataPack pack = new DataPack();
	pack.WriteString(file);
	pack.WriteString(expected);

	// The file is read by a thread of the extension, so a large map does
	// not freeze the server. The result arrives in the callback.
	Crypt.HashFile(Openssl_Hash_SHA256, file, OnFileHashed, pack);
	return Plugin_Handled;
}

public void OnFileHashed(CryptError error, CurlBuffer digest, DataPack pack)
{
	char file[PLATFORM_MAX_PATH];
	char expected[65];
	pack.Reset();
	pack.ReadString(file, sizeof(file));
	pack.ReadString(expected, sizeof(expected));
	delete pack;

	if (error != CryptError_None) {
		char reason[32];
		Crypt.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot hash %s: %s", file, reason);
		return;
	}

	// The digest arrives as a CurlBuffer with the hex text, without a NUL.
	// GetString adds the NUL.
	char actual[65];
	digest.GetString(0, actual, sizeof(actual));

	// The digests are lowercase hex; published ones are often uppercase.
	if (StrEqual(actual, expected, false)) {
		PrintToServer("%s is intact.", file);
	} else {
		PrintToServer("%s differs: its SHA-256 is %s", file, actual);
	}
}

/* --- sm_hash_text: digests of a text, at once --- */

public Action Command_HashText(int client, int args)
{
	char text[256];
	GetCmdArgString(text, sizeof(text));

	// 129 bytes hold the hex text of every digest, also of the 64 byte
	// ones like SHA-512.
	char digest[129];

	Crypt.HashString(Openssl_Hash_MD5, text, -1, digest, sizeof(digest));
	PrintToServer("MD5:            %s", digest);
	Crypt.HashString(Openssl_Hash_SHA1, text, -1, digest, sizeof(digest));
	PrintToServer("SHA-1:          %s", digest);
	Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest));
	PrintToServer("SHA-256:        %s", digest);
	Crypt.HashString(Openssl_Hash_SHA3_256, text, -1, digest, sizeof(digest));
	PrintToServer("SHA3-256:       %s", digest);
	Crypt.HashString(Openssl_Hash_CRC32, text, -1, digest, sizeof(digest));
	PrintToServer("CRC-32:         %s", digest);

	// The same SHA-256 in the other encodings.
	Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest), HashEncoding_Base64);
	PrintToServer("SHA-256 base64: %s", digest);
	Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest), HashEncoding_Base64Url);
	PrintToServer("SHA-256 b64url: %s", digest);

	// Raw: the 32 bytes themselves, no NUL. The return value is their number.
	char raw[32];
	int length = Crypt.HashString(Openssl_Hash_SHA256, text, -1, raw, sizeof(raw), HashEncoding_Raw);
	PrintToServer("SHA-256 raw:    %d bytes, the first is 0x%02x", length, raw[0] & 0xFF);
	return Plugin_Handled;
}

/* --- sm_hmac_file: a file's HMAC --- */

public Action Command_HmacFile(int client, int args)
{
	if (args != 2) {
		ReplyToCommand(client, "Usage: sm_hmac_file <key> <file>");
		return Plugin_Handled;
	}

	char key[128];
	GetCmdArg(1, key, sizeof(key));
	char file[PLATFORM_MAX_PATH];
	GetCmdArg(2, file, sizeof(file));

	Crypt.HmacFile(Openssl_Hash_SHA256, key, -1, file, OnDigest, 0, HashEncoding_Base64);
	return Plugin_Handled;
}

/* --- sm_hash_buffer: digests of a CurlBuffer --- */

public Action Command_HashBuffer(int client, int args)
{
	char text[256];
	GetCmdArgString(text, sizeof(text));

	CurlBuffer buffer = new CurlBuffer();
	buffer.AppendString(text);

	Crypt.HashBuffer(Openssl_Hash_SHA512, buffer, OnDigest);
	Crypt.HmacBuffer(Openssl_Hash_SHA256, "secret key", -1, buffer, OnDigest);

	// Both jobs copied the buffer's bytes when they were queued.
	delete buffer;
	return Plugin_Handled;
}

public void OnDigest(CryptError error, CurlBuffer digest, any data)
{
	if (error != CryptError_None) {
		char reason[32];
		Crypt.ErrorString(error, reason, sizeof(reason));
		PrintToServer("No digest: %s", reason);
		return;
	}

	char text[129];
	digest.GetString(0, text, sizeof(text));
	PrintToServer("Digest: %s", text);
}
