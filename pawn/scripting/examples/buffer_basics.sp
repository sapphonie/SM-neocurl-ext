/**
 * Example: every method of CurlBuffer, with what it prints.
 *
 *   sm_buffer_demo
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: CurlBuffer basics",
	author = "davenonymous",
	description = "Shows the methods of CurlBuffer",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

public void OnPluginStart()
{
	RegServerCmd("sm_buffer_demo", Command_Demo, "Shows the methods of CurlBuffer");
}

public Action Command_Demo(int args)
{
	CurlBuffer buffer = new CurlBuffer();
	PrintToServer("A new buffer has %d bytes", buffer.Length);  // 0

	// AppendString adds a text without its NUL.
	buffer.AppendString("rocket ");
	buffer.AppendString("jump");
	PrintToServer("After two strings: %d bytes", buffer.Length);  // 11

	// Append adds the given number of bytes, whatever they are: here a
	// NUL, a line feed and the byte 255.
	char bytes[3];
	bytes[0] = 0;
	bytes[1] = '\n';
	bytes[2] = 255;
	buffer.Append(bytes, sizeof(bytes));
	PrintToServer("After three more bytes: %d bytes", buffer.Length);  // 14

	// GetString copies text out and adds a NUL. It copies at most
	// maxlength - 1 bytes and returns how many it copied.
	char text[8];
	int copied = buffer.GetString(0, text, sizeof(text));
	PrintToServer("GetString from 0: \"%s\" (%d bytes)", text, copied);  // "rocket " (7 bytes)
	copied = buffer.GetString(7, text, sizeof(text));
	PrintToServer("GetString from 7: \"%s\" (%d bytes)", text, copied);  // "jump" (7 bytes)

	// The second call copied 7 bytes, but printed only "jump": the byte
	// after it is the NUL that was appended, and a string ends at a NUL.
	// For binary data use GetBytes, which adds no NUL, or Get for one byte.
	char raw[3];
	copied = buffer.GetBytes(11, raw, sizeof(raw));
	// The "& 0xFF" turns each char into a number from 0 to 255.
	// This prints "3 bytes: 0 10 255".
	PrintToServer("GetBytes from 11: %d bytes: %d %d %d", copied, raw[0] & 0xFF, raw[1] & 0xFF, raw[2] & 0xFF);
	PrintToServer("Get(13): %d", buffer.Get(13));  // 255

	// Find returns the position of the first match, or -1.
	PrintToServer("Find \"jump\": %d", buffer.Find("jump"));  // 7
	// The search can start later: the only "e" is at 4, before the start.
	PrintToServer("Find \"e\" from 5: %d", buffer.Find("e", -1, 5));  // -1
	PrintToServer("Find \"double\": %d", buffer.Find("double"));  // -1
	// A pattern with a NUL in it needs its length: here the two bytes "p" and NUL.
	char pattern[2];
	pattern[0] = 'p';
	pattern[1] = 0;
	PrintToServer("Find \"p\" and NUL: %d", buffer.Find(pattern, 2));  // 10

	// Clone makes an independent copy; AppendBuffer adds one buffer's
	// bytes to another.
	CurlBuffer copy = buffer.Clone();
	copy.AppendBuffer(buffer);
	PrintToServer("The copy has %d bytes, the original %d", copy.Length, buffer.Length);  // 28 and 14

	// Clear empties a buffer and frees its memory. The handle stays usable.
	copy.Clear();
	PrintToServer("The cleared copy has %d bytes", copy.Length);  // 0

	// A buffer is a Handle: close it when it is no longer needed.
	delete copy;
	delete buffer;
	return Plugin_Handled;
}
