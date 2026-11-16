# CurlBuffer

A `CurlBuffer` is a block of bytes that lives in the extension instead of in the plugin. It is how the extension and a
plugin exchange data that may be large: received WebSocket messages, the results of compression jobs and digests
arrive as buffers, and a plugin collects the body of an HTTP answer in one.

It is part of `curl_buffer.inc`, which `#include <cURL>` includes.

Contents:

- [Why it exists](#why-it-exists)
- [The methods, by example](#the-methods-by-example)
- [Reading a buffer line by line](#reading-a-buffer-line-by-line)
- [Buffers the extension passes to a callback](#buffers-the-extension-passes-to-a-callback)
- [The size limit](#the-size-limit)
- [Complete example: check an item whitelist](#complete-example-check-an-item-whitelist)
- [Reference](#reference)
- [Common mistakes](#common-mistakes)

## Why it exists

A SourceMod plugin has very little memory of its own: by default about 16 KB for all the local variables and
temporary data of the functions that are running at one time. (`#pragma dynamic` raises that amount, but it stays a
fixed size chosen when the plugin is compiled.) A string that a callback receives as `const char[]` has to fit into
that memory. A 2 MB answer of a web server does not.

So WebSocket, Compression and Crypt never hand their results to a plugin as an array. They hand over a `CurlBuffer`: a
handle to bytes that stay in the extension's memory. The plugin asks for the size, searches in it and copies out just
the pieces it needs, into arrays as small as it likes.

A buffer holds bytes, not text. It may contain any byte, including NUL (the byte with the value 0, which marks the
end of a string in SourcePawn), and it has no NUL at its end.

## The methods, by example

[`buffer_basics.sp`](../pawn/scripting/examples/buffer_basics.sp) uses every method once. The comment at the end of
each line is what the line prints.

Creating a buffer and adding to it:

```sourcepawn
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
```

Copying data out:

```sourcepawn
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
```

Searching:

```sourcepawn
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
```

Copying, joining, emptying and closing:

```sourcepawn
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
```

Positions count from 0: the first byte of a buffer is at position 0, the last at `Length - 1`.

## Reading a buffer line by line

Text that is too long for one array is read in pieces. The usual pieces are lines: find the next line feed, copy what
is before it, go on behind it. From [`buffer_whitelist.sp`](../pawn/scripting/examples/buffer_whitelist.sp):

```sourcepawn
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
```

The third argument of `GetString` is the size of the destination including the NUL, so `length + 1` copies exactly
`length` bytes.

## Buffers the extension passes to a callback

Several callbacks receive a `CurlBuffer`: a WebSocket message, a pong's payload, the output of a compression job, a
digest. Such a buffer belongs to the plugin, but only while the callback runs:

- The plugin may read it and may change it.
- The extension closes it as soon as the callback returns. The plugin does not have to delete it (deleting it does
  no harm).
- To keep the data longer, make a copy with `Clone()`. The copy is an ordinary buffer that the plugin deletes when it
  is done with it.

From [`websocket_relay.sp`](../pawn/scripting/examples/websocket_relay.sp), which keeps the last message it received:

```sourcepawn
public void OnRelayMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
{
	if (type != WebSocketMessage_Text) {
		return;
	}

	// The buffer is closed when this callback returns. A copy keeps the
	// message for sm_relay_status.
	delete g_LastMessage;
	g_LastMessage = message.Clone();

	// Chat lines are short: the first 191 bytes are enough.
	char text[192];
	message.GetString(0, text, sizeof(text));
	PrintToChatAll("[Relay] %s", text);
}
```

A buffer the plugin created itself with `new CurlBuffer()` or `Clone()` is never closed by the extension. It lives
until the plugin deletes it or is unloaded.

## The size limit

No buffer can grow beyond `CurlBufferMaxBytes` bytes. The default is 268435456 (256 MB). A server administrator can
change it with a line in SourceMod's `addons/sourcemod/configs/core.cfg`, inside the `"Core"` section:

```
"CurlBufferMaxBytes"	"67108864"
```

- The value is a number of bytes, written with digits only: `"64M"` is not accepted.
- The extension reads it once, when it is loaded. A change takes effect after a server restart.
- A value that is not a positive number is reported in SourceMod's error log, and the default is used.

The limit applies to each buffer separately. Where it is reached depends on who fills the buffer:

| Who adds the data | What happens at the limit |
|---|---|
| The plugin, with `Append`, `AppendString` or `AppendBuffer` | The method throws an error and the buffer keeps its content. |
| A compression or decompression job | The job fails with `CompressError_TooLarge`. |
| A WebSocket | `SetMaxMessageSize` does not accept a value above the limit. |

## Complete example: check an item whitelist

[`buffer_whitelist.sp`](../pawn/scripting/examples/buffer_whitelist.sp) downloads an item whitelist from
whitelist.tf, a text file of about 9 KB, and counts the items it bans. The download appends every piece it receives
to a buffer:

```sourcepawn
CurlBuffer whitelist = new CurlBuffer();

CurlEasy easy = new CurlEasy();
easy.SetUrl(url);
easy.SetTimeout(30);
easy.SetOptInt(CURLOPT_FAILONERROR, 1);
easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnData, whitelist);
easy.PerformThread(OnDownloaded, whitelist);
```

```sourcepawn
public int OnData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb, CurlBuffer whitelist)
{
	int length = bytes * nmemb;
	whitelist.Append(buffer, length);
	return length;
}
```

When the download is complete, the plugin walks through the lines and deletes the buffer:

```sourcepawn
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
```

`sm_whitelist_check` prints:

```
The whitelist has 8801 bytes
  banned: The Reserve Shooter
  banned: Bonk! Atomic Punch
  banned: Crit-a-Cola
  banned: Festive Bonk 2014
  banned: Mad Milk
135 items are banned
```

The download itself is explained in [HTTP and other transfers](modern.md#receiving-the-answer).

## Reference

`CurlBuffer` is a `Handle`. Every method has a native of the same meaning, for plugins that prefer natives; the
native takes the buffer as its first argument.

| Member | Native | What it does |
|---|---|---|
| `new CurlBuffer()` | `curl_buffer_create` | Creates an empty buffer. |
| `Length` | `curl_buffer_length` | The number of bytes in the buffer. Read-only. |
| `Clear()` | `curl_buffer_clear` | Removes all bytes and frees their memory. The buffer stays usable. |
| `Append(const char[] data, int length)` | `curl_buffer_append` | Appends `length` bytes of `data`. The bytes may contain NUL. |
| `AppendString(const char[] text)` | `curl_buffer_append_string` | Appends `text` up to its NUL. The NUL is not appended. |
| `AppendBuffer(CurlBuffer other)` | `curl_buffer_append_buffer` | Appends all bytes of `other`. `other` may be the buffer itself, which doubles it. |
| `GetString(int offset, char[] output, int maxlength)` | `curl_buffer_get_string` | Copies bytes from position `offset` into `output` and puts a NUL after them. It copies at most `maxlength - 1` bytes and stops at the end of the buffer. Returns the number of bytes copied, the NUL not counted. |
| `GetBytes(int offset, char[] output, int count)` | `curl_buffer_get_bytes` | Copies at most `count` bytes from position `offset` into `output`, without a NUL, and stops at the end of the buffer. Returns the number of bytes copied. |
| `Get(int index)` | `curl_buffer_get` | Returns the byte at position `index` as a number from 0 to 255. |
| `Find(const char[] pattern, int length = -1, int start = 0)` | `curl_buffer_find` | Searches for `pattern` at or after position `start`. `length` is the number of bytes of `pattern`; -1 takes it up to its NUL. Returns the position of the first match, or -1 when there is none. |
| `Clone()` | `curl_buffer_clone` | Creates a new buffer with a copy of the bytes. |

A buffer is closed with `delete buffer` or `CloseHandle(buffer)`.

### What counts as an error

These mistakes throw an error, which is written to SourceMod's error log and stops the function that made the call:

- using a buffer that is not valid, for example one that was deleted already,
- an `offset` or `start` below 0 or above `Length` (exactly `Length` is allowed: `GetString` then writes an empty
  string, `GetBytes` copies nothing, `Find` finds nothing),
- an `index` below 0 or at or above `Length`,
- a `length` or `count` below 0 (except the -1 of `Find`), or a `maxlength` below 1,
- growing a buffer beyond `CurlBufferMaxBytes`,
- running out of memory.

Not found is not an error: `Find` returns -1. An empty pattern is found everywhere: `Find` returns `start`.

### What the methods do not check

`Append`, `Find`, `GetBytes` and `GetString` trust the numbers they are given. `Append(data, 100)` reads 100 bytes
even when `data` is a smaller array, and `GetBytes(0, output, 100)` or `GetString(0, output, 100)` writes up to 100
bytes even when `output` is smaller. Pass `sizeof(array)` or a number known to be at most that.

## Common mistakes

- **Printing a buffer's content as if it were a string.** A buffer has no NUL at its end. Copy text out with
  `GetString`, which adds the NUL, and print the copy.
- **Expecting `GetString` to return everything.** It copies at most `maxlength - 1` bytes. Compare its return value
  with what was expected, or read in a loop as shown above.
- **Using `GetString` for binary data.** The copy is complete, but every string function stops at the first NUL
  byte in it. Use `GetBytes` and the returned count, or `Get`.
- **Keeping a callback's buffer.** A buffer that a callback received is closed when the callback returns. Storing
  the handle in a global variable leaves an invalid handle behind. Store a `Clone()`.
- **Forgetting to delete.** Buffers the plugin created with `new CurlBuffer()` or `Clone()` stay in memory until they
  are deleted. Before storing a new buffer in a variable, delete the old one: `delete` also sets the variable to
  `null`, and deleting `null` is allowed.
