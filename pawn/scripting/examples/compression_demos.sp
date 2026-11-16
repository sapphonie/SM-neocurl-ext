/**
 * Example: keep SourceTV demos compressed.
 *
 * Shows compressing and decompressing files in the background, and
 * compressing data in memory.
 *
 *   sm_demos_compress            compresses every .dem file in the game
 *                                directory to .dem.zst and deletes the
 *                                original when that worked
 *   sm_demos_decompress <file>   unpacks a .zst or .gz file again, next to
 *                                it, without the extension
 *   sm_compress_text <text>      compresses a text with gzip and unpacks it
 *                                again, to show the data functions
 *
 * File names are relative to the game directory.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: demo compression",
	author = "davenonymous",
	description = "Compresses SourceTV demos with zstd",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

// A decompressed demo may be this large at most: 1 GB.
#define MAX_DEMO_SIZE 1073741824

public void OnPluginStart()
{
	RegAdminCmd("sm_demos_compress", Command_Compress, ADMFLAG_RCON, "Compresses every demo in the game directory");
	RegAdminCmd("sm_demos_decompress", Command_Decompress, ADMFLAG_RCON, "sm_demos_decompress <file> - unpacks a demo");
	RegAdminCmd("sm_compress_text", Command_CompressText, ADMFLAG_RCON, "sm_compress_text <text> - gzip round trip");
}

/* --- Files: compress --- */

public Action Command_Compress(int client, int args)
{
	DirectoryListing directory = OpenDirectory(".");
	if (directory == null) {
		ReplyToCommand(client, "Cannot list the game directory.");
		return Plugin_Handled;
	}

	int count = 0;
	char name[PLATFORM_MAX_PATH];
	FileType type;
	while (directory.GetNext(name, sizeof(name), type)) {
		int length = strlen(name);
		if (type != FileType_File || length < 5 || !StrEqual(name[length - 4], ".dem")) {
			continue;
		}

		char compressed[PLATFORM_MAX_PATH];
		Format(compressed, sizeof(compressed), "%s.zst", name);
		// Queues the job and returns at once. Level -1 is the format's
		// default. An existing .zst file fails the job instead of being
		// replaced, because overwrite is false by default.
		Compression.CompressFile(CompressFormat_Zstd, name, compressed, OnDemoCompressed);
		count++;
	}
	delete directory;

	ReplyToCommand(client, "Compressing %d demos in the background.", count);
	return Plugin_Handled;
}

public void OnDemoCompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		LogError("Cannot compress %s: %s", inFile, reason);
		return;
	}

	LogMessage("Compressed %s: %d to %d bytes", inFile, FileSize(inFile), FileSize(outFile));
	// Only now, with the compressed file complete, the original goes.
	DeleteFile(inFile);
}

/* --- Files: decompress --- */

public Action Command_Decompress(int client, int args)
{
	char compressed[PLATFORM_MAX_PATH];
	GetCmdArg(1, compressed, sizeof(compressed));

	// "match.dem.zst" becomes "match.dem".
	char target[PLATFORM_MAX_PATH];
	strcopy(target, sizeof(target), compressed);
	int dot = FindCharInString(target, '.', true);
	if (dot <= 0) {
		ReplyToCommand(client, "Usage: sm_demos_decompress <file.zst or file.gz>");
		return Plugin_Handled;
	}
	target[dot] = '\0';

	// CompressFormat_Auto tells gzip, zlib and zstd apart by the first
	// bytes of the file. The size limit protects the disk from a small
	// file that unpacks to something huge.
	int userId = client == 0 ? 0 : GetClientUserId(client);
	Compression.DecompressFile(CompressFormat_Auto, compressed, target, OnDemoDecompressed, userId, MAX_DEMO_SIZE);
	return Plugin_Handled;
}

public void OnDemoDecompressed(CompressError error, const char[] inFile, const char[] outFile, int userId)
{
	// The player who asked may have left meanwhile; 0 is the console.
	int client = userId == 0 ? 0 : GetClientOfUserId(userId);
	if (userId != 0 && client == 0) {
		return;
	}

	if (error == CompressError_OutputExists) {
		ReplyToCommand(client, "%s exists already.", outFile);
	} else if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		ReplyToCommand(client, "Cannot unpack %s: %s", inFile, reason);
	} else {
		ReplyToCommand(client, "Unpacked %s: %d bytes", outFile, FileSize(outFile));
	}
}

/* --- Data in memory --- */

public Action Command_CompressText(int client, int args)
{
	char text[256];
	GetCmdArgString(text, sizeof(text));

	// -1: the input is the text up to its NUL. Level 9 is gzip's best.
	Compression.CompressString(CompressFormat_Gzip, text, -1, OnTextCompressed, strlen(text), 9);
	return Plugin_Handled;
}

public void OnTextCompressed(CompressError error, CurlBuffer output, int originalLength)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot compress: %s", reason);
		return;
	}

	PrintToServer("gzip: %d bytes became %d", originalLength, output.Length);

	// The buffer lives only as long as this callback, but a job copies
	// its input when it is queued: passing the buffer on is safe.
	Compression.DecompressBuffer(CompressFormat_Gzip, output, OnTextDecompressed, 0, 4096);
}

public void OnTextDecompressed(CompressError error, CurlBuffer output, any data)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot decompress: %s", reason);
		return;
	}

	char text[256];
	output.GetString(0, text, sizeof(text));
	PrintToServer("and back: %s", text);
}
