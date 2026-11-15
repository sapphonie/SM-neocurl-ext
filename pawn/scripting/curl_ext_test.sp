/**
 * Tests the CurlBuffer, Compression, Crypt and WebSocket APIs of the cURL
 * extension on a running server.
 *
 * sm_curl_ext_test runs every test and prints a line per check and a summary
 * to the server console. The WebSocket tests need an echo server (one that
 * sends every message back) at the URL in curl_ext_test_ws_url; they are
 * skipped while it is empty.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL extension test",
	author = "davenonymous",
	description = "Tests CurlBuffer, Compression, Crypt and WebSocket",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

#define TEST_DIR "data/curl_ext_test"
#define TEST_TEXT "rocket sticky uber medic scout rocket sticky uber medic scout rocket sticky uber"

ConVar g_WebSocketUrl;
int g_Passed;
int g_Failed;
int g_Pending;

public void OnPluginStart()
{
	g_WebSocketUrl = CreateConVar("curl_ext_test_ws_url", "", "URL of a WebSocket echo server for the WebSocket tests; empty skips them");
	RegServerCmd("sm_curl_ext_test", Command_Test, "Runs the tests of the cURL extension's new APIs");
}

void Check(bool condition, const char[] name)
{
	if (condition) {
		g_Passed++;
		PrintToServer("[curl_ext_test] PASS %s", name);
	} else {
		g_Failed++;
		PrintToServer("[curl_ext_test] FAIL %s", name);
	}
}

void Started()
{
	g_Pending++;
}

void Finished()
{
	g_Pending--;
	if (g_Pending == 0)
		PrintToServer("[curl_ext_test] DONE %d passed, %d failed", g_Passed, g_Failed);
}

bool BufferEquals(CurlBuffer buffer, const char[] text)
{
	int length = strlen(text);
	if (buffer == null || buffer.Length != length)
		return false;
	char[] bytes = new char[length + 1];
	buffer.GetString(0, bytes, length + 1);
	return StrEqual(bytes, text);
}

public Action Command_Test(int args)
{
	g_Passed = 0;
	g_Failed = 0;
	g_Pending = 1;

	TestBuffer();
	TestCryptNow();
	TestCryptLater();
	TestCompression();
	TestWebSocket();
	Finished();
	return Plugin_Handled;
}

/* --- CurlBuffer --- */

void TestBuffer()
{
	CurlBuffer buffer = new CurlBuffer();
	Check(buffer.Length == 0, "buffer starts empty");
	buffer.AppendString("hello ");
	char bytes[4];
	bytes[0] = 'w';
	bytes[1] = 0;
	bytes[2] = 'x';
	bytes[3] = 'y';
	buffer.Append(bytes, 4);
	Check(buffer.Length == 10, "buffer length after appends");
	Check(buffer.Get(6) == 'w' && buffer.Get(7) == 0 && buffer.Get(9) == 'y', "buffer bytes with NUL");
	Check(buffer.Find("xy", 2) == 8, "buffer find with length");
	Check(buffer.Find("hello", -1, 1) == -1, "buffer find from start");

	char text[16];
	Check(buffer.GetString(0, text, 4) == 3 && StrEqual(text, "hel"), "buffer get string truncates");
	char raw[8];
	Check(buffer.GetBytes(6, raw, 8) == 4 && raw[2] == 'x', "buffer get bytes stops at end");

	CurlBuffer copy = buffer.Clone();
	copy.AppendBuffer(copy);
	Check(copy.Length == 20 && buffer.Length == 10, "buffer clone and append to itself");
	copy.Clear();
	Check(copy.Length == 0, "buffer clear");
	delete copy;
	delete buffer;
}

/* --- Crypt --- */

void TestCryptNow()
{
	char digest[256];
	Crypt.HashString(Openssl_Hash_SHA256, "abc", -1, digest, sizeof(digest));
	Check(StrEqual(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256 hex");
	Crypt.HashString(Openssl_Hash_SHA3_256, "abc", -1, digest, sizeof(digest));
	Check(StrEqual(digest, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "sha3-256 hex");
	Crypt.HashString(Openssl_Hash_SHA256, "abc", 3, digest, sizeof(digest), HashEncoding_Base64);
	Check(StrEqual(digest, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="), "sha256 base64");
	Crypt.HashString(Openssl_Hash_SHA256, "abc", 3, digest, sizeof(digest), HashEncoding_Base64Url);
	Check(StrEqual(digest, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"), "sha256 base64url");
	Check(Crypt.HashString(Openssl_Hash_SHA256, "abc", 3, digest, sizeof(digest), HashEncoding_Raw) == 32
	      && digest[0] == 0xba, "sha256 raw");
	Crypt.HashString(Openssl_Hash_CRC32, "123456789", -1, digest, sizeof(digest));
	Check(StrEqual(digest, "cbf43926"), "crc32");
	Crypt.HmacString(Openssl_Hash_SHA256, "Jefe", -1, "what do ya want for nothing?", -1, digest, sizeof(digest));
	Check(StrEqual(digest, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"), "hmac-sha256");
	curl_hash_string("abc", 0, Openssl_Hash_BLAKE2S256, digest, sizeof(digest));
	Check(StrEqual(digest, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
	      "deprecated curl_hash_string with a new algorithm");
}

void TestCryptLater()
{
	CurlBuffer buffer = new CurlBuffer();
	buffer.AppendString("abc");
	Started();
	Crypt.HashBuffer(Openssl_Hash_SHA512_256, buffer, OnHashBuffer);
	delete buffer;

	char dir[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, dir, sizeof(dir), "%s", TEST_DIR);
	if (!DirExists(dir))
		CreateDirectory(dir, 511);
	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "%s/hash.txt", TEST_DIR);
	File file = OpenFile(path, "wb");
	file.WriteString("abc", false);
	delete file;

	Started();
	Crypt.HmacFile(Openssl_Hash_SHA256, "Jefe", -1, "addons/sourcemod/" ... TEST_DIR ... "/hash.txt", OnHmacFile);
	Started();
	Crypt.HashFile(Openssl_Hash_SHA256, "addons/sourcemod/" ... TEST_DIR ... "/missing.txt", OnHashMissing);
}

public void OnHashBuffer(CryptError error, CurlBuffer digest, any data)
{
	Check(error == CryptError_None
	      && BufferEquals(digest, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
	      "sha512/256 of a buffer");
	Finished();
}

public void OnHmacFile(CryptError error, CurlBuffer digest, any data)
{
	/* HMAC-SHA256 of "abc" with key "Jefe" */
	char hex[65];
	Crypt.HmacString(Openssl_Hash_SHA256, "Jefe", -1, "abc", -1, hex, sizeof(hex));
	Check(error == CryptError_None && BufferEquals(digest, hex), "hmac-sha256 of a file");
	Finished();
}

public void OnHashMissing(CryptError error, CurlBuffer digest, any data)
{
	Check(error == CryptError_OpenInput && digest == null, "hash of a missing file");
	Finished();
}

/* --- Compression --- */

void TestCompression()
{
	for (CompressFormat format = CompressFormat_Gzip; format < CompressFormat_Auto; format++) {
		Started();
		Compression.CompressString(format, TEST_TEXT, -1, OnCompressed, format);
	}

	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "%s/plain.txt", TEST_DIR);
	File file = OpenFile(path, "wb");
	file.WriteString(TEST_TEXT, false);
	delete file;
	Started();
	Compression.CompressFile(CompressFormat_Zstd, "addons/sourcemod/" ... TEST_DIR ... "/plain.txt",
	                         "addons/sourcemod/" ... TEST_DIR ... "/plain.txt.zst", OnFileCompressed, 0, -1, true);

	char name[32];
	Compression.ErrorString(CompressError_TooLarge, name, sizeof(name));
	Check(StrEqual(name, "CompressError_TooLarge"), "compression error string");
}

public void OnCompressed(CompressError error, CurlBuffer output, CompressFormat format)
{
	Check(error == CompressError_None && output.Length > 0, "compress a string");
	if (error == CompressError_None) {
		CompressFormat decompressAs = format == CompressFormat_Brotli || format == CompressFormat_Deflate
		                                  ? format
		                                  : CompressFormat_Auto;
		Started();
		Compression.DecompressBuffer(decompressAs, output, OnDecompressed, format);
		Started();
		Compression.DecompressBuffer(format, output, OnTooLarge, format, 10);
	}
	Finished();
}

public void OnDecompressed(CompressError error, CurlBuffer output, CompressFormat format)
{
	char name[64];
	Format(name, sizeof(name), "round trip of format %d", format);
	Check(error == CompressError_None && BufferEquals(output, TEST_TEXT), name);
	Finished();
}

public void OnTooLarge(CompressError error, CurlBuffer output, CompressFormat format)
{
	char name[64];
	Format(name, sizeof(name), "maxSize of format %d", format);
	Check(error == CompressError_TooLarge && output == null, name);
	Finished();
}

public void OnFileCompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	Check(error == CompressError_None, "compress a file");
	Started();
	Compression.DecompressFile(CompressFormat_Auto, outFile, "addons/sourcemod/" ... TEST_DIR ... "/unpacked/plain.txt",
	                           OnFileDecompressed, 0, 0, true);
	Finished();
}

public void OnFileDecompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	char content[256];
	File file = OpenFile(outFile, "rb");
	if (file != null) {
		file.ReadString(content, sizeof(content));
		delete file;
	}
	Check(error == CompressError_None && StrEqual(content, TEST_TEXT), "decompress a file");
	Finished();
}

/* --- WebSocket --- */

int g_Echoes;

void TestWebSocket()
{
	char url[256];
	g_WebSocketUrl.GetString(url, sizeof(url));
	if (url[0] == '\0') {
		PrintToServer("[curl_ext_test] SKIP WebSocket: curl_ext_test_ws_url is empty");
		return;
	}

	g_Echoes = 0;
	WebSocket ws = new WebSocket(url);
	ws.SetOnOpen(OnWsOpen);
	ws.SetOnMessage(OnWsMessage);
	ws.SetOnPong(OnWsPong);
	ws.SetOnClose(OnWsClose);
	Check(ws.State == WebSocketState_Idle, "websocket idle before connect");
	Started();
	ws.Connect();
	Check(ws.SendText("queued before open"), "websocket send before open");
}

public void OnWsOpen(WebSocket ws, any data)
{
	Check(ws.State == WebSocketState_Open, "websocket open");
	char binary[4];
	binary[0] = 1;
	binary[1] = 0;
	binary[2] = 2;
	binary[3] = 3;
	Check(ws.SendBinary(binary, 4), "websocket send binary");
	CurlBuffer big = new CurlBuffer();
	for (int i = 0; i < 2000; i++)
		big.AppendString("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz01");
	Check(ws.SendBuffer(big, false), "websocket send a 200 KB buffer");
	delete big;
	Check(ws.Ping("ping!"), "websocket ping");
}

public void OnWsMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
{
	g_Echoes++;
	if (g_Echoes == 1)
		Check(type == WebSocketMessage_Text && BufferEquals(message, "queued before open"), "websocket echo text");
	else if (g_Echoes == 2)
		Check(type == WebSocketMessage_Binary && message.Length == 4 && message.Get(1) == 0 && message.Get(3) == 3,
		      "websocket echo binary");
	else if (g_Echoes == 3) {
		Check(type == WebSocketMessage_Text && message.Length == 200000, "websocket echo 200 KB");
		ws.Close(1000, "test done");
	}
}

public void OnWsPong(WebSocket ws, CurlBuffer payload, any data)
{
	Check(BufferEquals(payload, "ping!"), "websocket pong");
}

public void OnWsClose(WebSocket ws, CURLcode error, int code, const char[] reason, any data)
{
	Check(error == CURLE_OK && g_Echoes == 3, "websocket closed after the echoes");
	Check(ws.State == WebSocketState_Closed || ws.State == WebSocketState_Closing, "websocket state at close");
	delete ws;
	Finished();
}
