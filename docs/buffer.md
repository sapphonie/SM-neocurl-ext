# CurlBuffer

`CurlBuffer` (`curl_buffer.inc`, included by `cURL.inc`) is a byte buffer that lives in the extension. It carries
data between a plugin and the extension that may be larger than the plugin's own memory: received WebSocket messages,
the results of compression jobs and digests. A buffer holds any bytes, NUL included.

A plugin has little memory of its own: by default about 16 KB beyond what its variables need (`#pragma dynamic`
raises it). A string or array argument of a callback must fit into that memory, so the extension never passes large
data as `char[]`, only as a `CurlBuffer` that the plugin reads in pieces.

## Methods

| Method | Native | What it does |
|---|---|---|
| `new CurlBuffer()` | `curl_buffer_create` | An empty buffer. Close it with `delete`. |
| `Length` | `curl_buffer_length` | The number of bytes. |
| `Clear()` | `curl_buffer_clear` | Removes all bytes and frees their memory. |
| `Append(data, length)` | `curl_buffer_append` | Appends `length` bytes of `data`; they may contain NUL. |
| `AppendString(text)` | `curl_buffer_append_string` | Appends `text` up to its NUL, without the NUL. |
| `AppendBuffer(other)` | `curl_buffer_append_buffer` | Appends the bytes of another buffer, or of itself. |
| `GetString(offset, output, maxlength)` | `curl_buffer_get_string` | Copies at most `maxlength - 1` bytes from `offset` and a NUL; returns the bytes copied. |
| `GetBytes(offset, output, count)` | `curl_buffer_get_bytes` | Copies at most `count` bytes from `offset`, without a NUL; returns the bytes copied. |
| `Get(index)` | `curl_buffer_get` | The byte at `index`, 0-255. |
| `Find(pattern, length = -1, start = 0)` | `curl_buffer_find` | The position of the first `pattern` (`length` bytes, or up to its NUL) at or after `start`, or -1. |
| `Clone()` | `curl_buffer_clone` | A new buffer with a copy of the bytes. |

An `offset` or `start` may be anything from 0 to `Length`; outside that, and for an `index` outside the buffer, the
native throws an error.

## Size limit

No buffer grows beyond `CurlBufferMaxBytes`, a key in SourceMod's `addons/sourcemod/configs/core.cfg`, in bytes:

```
"CurlBufferMaxBytes"	"268435456"
```

The default is 268435456 (256 MB). The extension reads it once when it loads, so a change needs a server restart (or
reloading the extension). A value that is not a positive number is logged as an error and the default is used.

The limit applies to each buffer on its own: appending more throws an error, a decompression whose result would be
larger fails with `CompressError_TooLarge`, and a WebSocket's maximum message size cannot be set above it.

## Buffers in callbacks

A buffer the extension passes to a callback (a WebSocket message, a compression result, a digest) belongs to the
plugin, but only for the duration of the callback: the extension closes it when the callback returns. Use `Clone()`
to keep the bytes. The buffer may be changed during the callback.

```sourcepawn
CurlBuffer g_LastMessage;

public void OnMessage(WebSocket ws, WebSocketMessageType type, CurlBuffer message, any data)
{
	delete g_LastMessage;
	g_LastMessage = message.Clone();
}
```

## Reading a large buffer

```sourcepawn
void PrintLines(CurlBuffer buffer)
{
	char line[256];
	int start = 0;
	while (start < buffer.Length) {
		int end = buffer.Find("\n", -1, start);
		if (end == -1)
			end = buffer.Length;
		int length = end - start;
		if (length > sizeof(line) - 1)
			length = sizeof(line) - 1;
		buffer.GetString(start, line, length + 1);
		PrintToServer("%s", line);
		start = end + 1;
	}
}
```

Handles of `CurlBuffer` follow SourceMod's usual handle rules: the plugin that created a buffer owns it, and
`CloneHandle` shares it with another plugin.
