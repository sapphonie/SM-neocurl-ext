# HTTP and other transfers: CurlEasy, CurlSlist, CurlForm, CurlFile

This page explains how a plugin makes HTTP requests, downloads and uploads files and talks to TCP or UDP services
with [libcurl](https://curl.se/libcurl/). It uses the four methodmaps of `curl_modern.inc`:

| Methodmap | What it is |
|---|---|
| `CurlEasy` | One transfer: its URL and options, the transfer itself and its result. |
| `CurlSlist` | A list of strings, mostly used for request headers. |
| `CurlForm` | A web form (`multipart/form-data`) with text fields and file uploads. |
| `CurlFile` | A file on the server that a transfer writes to or reads from. |

A plugin gets all of them with one line:

```sourcepawn
#include <cURL>
```

Contents:

- [A first request](#a-first-request)
- [How a transfer works](#how-a-transfer-works)
- [Setting options](#setting-options)
- [Running the transfer](#running-the-transfer)
- [Receiving the answer](#receiving-the-answer)
- [Sending data](#sending-data)
- [Reading the result](#reading-the-result)
- [Handling errors](#handling-errors)
- [CurlSlist](#curlslist), [CurlForm](#curlform), [CurlFile](#curlfile)
- [Closing handles](#closing-handles)
- [Raw TCP and UDP connections](#raw-tcp-and-udp-connections)
- [Information about libcurl](#information-about-libcurl)
- [Complete examples](#complete-examples)
- [Reference](#reference)
- [Common mistakes](#common-mistakes)

## A first request

This posts a message to a Discord channel. It is the core of
[`curl_discord_webhook.sp`](../pawn/scripting/examples/curl_discord_webhook.sp):

```sourcepawn
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
```

```sourcepawn
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
```

What happens here:

1. `new CurlEasy()` creates the transfer. Nothing is sent yet.
2. The `Set...` calls describe the request: where it goes, which headers it has, what its body is, how long it may
   take.
3. `PerformThread` starts the transfer on a thread of the extension and returns at once. The server keeps running.
4. When the transfer is complete, the extension calls `OnPosted` in a later game frame, with the `CurlEasy`, the
   result code and the value given as second argument of `PerformThread`.
5. The callback looks at the result and closes both handles with `delete`.

## How a transfer works

Five rules explain most of this API. Each is described in detail further down.

1. **One `CurlEasy` is one transfer.** Create it, set its options, run it, read its result, delete it. The options
   are handed to libcurl when the transfer starts, once per handle; options set after that have no effect. For the
   next request create a new `CurlEasy`. (The one exception is a [raw connection](#raw-tcp-and-udp-connections),
   which connects first and then sends and receives on the same handle.)
2. **A transfer runs on its own thread** when it is started with `PerformThread`. Every callback of the plugin runs on
   the server's main thread, in a game frame, so a callback may use any SourceMod function.
3. **The answer's body is thrown away** unless the plugin gives the transfer a file to write it to or a function to
   call with it. See [Receiving the answer](#receiving-the-answer).
4. **A transfer that got an answer is successful**, whatever the answer says. A "404 Not Found" page is a successful
   transfer with `ResponseCode` 404. See [Handling errors](#handling-errors).
5. **Handles are closed by the plugin.** A `CurlEasy` is deleted in its complete callback, and so are the
   `CurlSlist`, `CurlForm` and `CurlFile` handles it used. Deleting a `CurlEasy` while its transfer still runs ends
   the transfer; its complete callback is not called then. See [Closing handles](#closing-handles).

Every methodmap is a `Handle`, and every method calls one native of `cURL.inc` (the [reference](#reference) lists
which). Plugins written with the natives keep working, and natives and methods can be mixed on the same handle.

## Setting options

libcurl is configured through options named `CURLOPT_...`. The most common ones have a method of their own; any other
option is set with one of the generic `SetOpt` methods.

### The common options

| Method | Option | What it does |
|---|---|---|
| `SetUrl(url)` | `CURLOPT_URL` | The URL of the transfer. |
| `SetHeaders(headers)` | `CURLOPT_HTTPHEADER` | Additional request headers, a [`CurlSlist`](#curlslist). |
| `SetUserAgent(userAgent)` | `CURLOPT_USERAGENT` | The `User-Agent` header. Without it the request has none, and some services refuse such requests. |
| `SetTimeout(seconds)` | `CURLOPT_TIMEOUT` | The seconds the whole transfer may take, connecting included. 0 means no limit, which is the default. |
| `SetFollowLocation(follow)` | `CURLOPT_FOLLOWLOCATION` | Whether redirects (status 301, 302, ...) are followed. They are not by default. |
| `SetPostFields(fields)` | `CURLOPT_POSTFIELDS` | The body of an HTTP POST, see [Sending data](#sending-data). |
| `SetForm(form)` | `CURLOPT_HTTPPOST` | A web form as the body of an HTTP POST, a [`CurlForm`](#curlform). |
| `SetWriteFile(file)` | `CURLOPT_WRITEDATA` | The [`CurlFile`](#curlfile) the answer's body is written to. |
| `SetHeaderFile(file)` | `CURLOPT_HEADERDATA` | The [`CurlFile`](#curlfile) the answer's headers are written to. |
| `SetReadFile(file)` | `CURLOPT_READDATA` | The [`CurlFile`](#curlfile) an upload is read from. |

All of them return `true` when the option was accepted. `SetHeaders` and `SetForm` return `false` for a list or form
that is still empty: fill it first, then set it.

### Any other option

| Method | For options that take |
|---|---|
| `SetOptString(option, value)` | a string |
| `SetOptInt(option, value)` | a number or an on/off switch (1 and 0) |
| `SetOptIntArray(array, size)` | several number options at once, see below |
| `SetOptInt64(option, value)` | a number that may exceed 2147483647, written as decimal text: `"5000000000"` |
| `SetOptHandle(option, handle)` | a `CurlFile`, `CurlForm` or `CurlSlist` |
| `SetOptFunction(option, callback, value = 0)` | a callback: `CURLOPT_WRITEFUNCTION` or `CURLOPT_READFUNCTION` |

For example, from [`curl_map_download.sp`](../pawn/scripting/examples/curl_map_download.sp):

```sourcepawn
// A 404 page must not end up in the file: with CURLOPT_FAILONERROR a
// status of 400 or above fails the transfer with CURLE_HTTP_RETURNED_ERROR.
easy.SetOptInt(CURLOPT_FAILONERROR, 1);
// A map can take minutes, so there is no limit on the whole transfer.
// Instead: 10 seconds to connect, and give up when fewer than 1000
// bytes per second arrive for 30 seconds.
easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
easy.SetOptInt(CURLOPT_LOW_SPEED_LIMIT, 1000);
easy.SetOptInt(CURLOPT_LOW_SPEED_TIME, 30);
```

`SetOptIntArray` sets a list of number options in one call. It takes pairs of `{option, value}` and the number of
pairs, which is handy for the options every transfer of a plugin shares:

```sourcepawn
// Number options that every transfer of this plugin gets, as pairs of
// {option, value}, for SetOptIntArray.
int g_CommonOptions[][2] = {
	{ view_as<int>(CURLOPT_CONNECTTIMEOUT), 10 },
	{ view_as<int>(CURLOPT_TIMEOUT), 30 },
	{ view_as<int>(CURLOPT_FOLLOWLOCATION), 1 },
	{ view_as<int>(CURLOPT_MAXREDIRS), 5 },
};
```

```sourcepawn
easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
```

What each option means is described in [libcurl's option list](https://curl.se/libcurl/c/curl_easy_setopt.html). The
extension accepts the options listed in the [reference](#supported-options); the constants of the others exist in
`cURL_header.inc`, but setting them returns `false`.

### What the return value of a SetOpt method means

A `SetOpt` method only stores the option. It returns `false` when

- the extension does not accept this option with a value of this type (a string for `CURLOPT_TIMEOUT`, for
  example),
- a transfer of the handle is running, or
- the value is a `CurlSlist` or `CurlForm` that is still empty.

It does not check the value. libcurl sees the options when the transfer starts; if it refuses one, the transfer ends
at once with libcurl's error code and nothing is sent.

After a handle's transfer has ended, a `SetOpt` method still returns `true`, but the option is not used anymore: the
handle has had its one transfer.

`SetOptIntArray` returns `false` at the first pair that is not accepted and writes a line to SourceMod's error log;
the pairs before it are set. It needs a plugin compiled with SourceMod 1.11 or newer.

`SetOptHandle`, and the shortcuts built on it, throw an error and stop the calling function when the handle is of the
wrong kind for the option, for example a `CurlFile` for `CURLOPT_HTTPHEADER`.

### Options that name a file

Options such as `CURLOPT_CAINFO`, `CURLOPT_COOKIEFILE` or `CURLOPT_SSLCERT` take the path of a file. A path is relative
to the game directory (`tf/` for Team Fortress 2), like the paths of SourceMod's file functions:
`"addons/sourcemod/configs/my-ca.pem"`. For a path outside the game directory, put `file://` in front of the absolute
path: `"file:///etc/ssl/my-ca.pem"`. The same holds for the paths of `CurlFile` and `CurlForm`.

### What the extension sets by itself

Every transfer gets two settings from the extension:

- Compressed answers are requested and unpacked automatically. The request carries the header
  `Accept-Encoding: deflate, gzip, br, zstd`, and the plugin receives the unpacked data. To receive the data as the
  server sent it, set `CURLOPT_HTTP_CONTENT_DECODING` to 0.
- TLS certificates are checked against the system's certificate store. See the
  [README](../README.md#tls-certificates) for where that is. `CURLOPT_CAINFO` and `CURLOPT_CAPATH` name other
  certificates to trust.

## Running the transfer

### In the background: PerformThread

<!-- not-an-excerpt -->
```sourcepawn
void CurlEasy.PerformThread(CURL_OnComplete callback, any value = 0)
```

`PerformThread` starts the transfer on a thread of the extension and returns immediately. When the transfer is
complete, successfully or not, `callback` is called once, in a game frame:

<!-- not-an-excerpt -->
```sourcepawn
public void OnComplete(CurlEasy easy, CURLcode code, any value)
```

- `easy` is the transfer. Its result can be read now, and it is deleted here.
- `code` is `CURLE_OK` when the transfer worked, otherwise the error. See [Handling errors](#handling-errors).
- `value` is whatever was passed to `PerformThread`. It may be left out of the callback when it is not needed, and it
  may be declared with the type that was passed, such as `CurlSlist` or `DataPack`.

One value is often not enough. A `DataPack` carries several, as in
[`curl_map_download.sp`](../pawn/scripting/examples/curl_map_download.sp):

```sourcepawn
// The callback needs the file handle and the map's name.
DataPack pack = new DataPack();
pack.WriteCell(file);
pack.WriteString(map);
easy.PerformThread(OnDownloaded, pack);
```

```sourcepawn
public void OnDownloaded(CurlEasy easy, CURLcode code, DataPack pack)
{
	pack.Reset();
	CurlFile file = pack.ReadCell();
	char map[64];
	pack.ReadString(map, sizeof(map));
	delete pack;
```

This is the way to run transfers while people play.

### Blocking: LoadOpt and Perform

<!-- not-an-excerpt -->
```sourcepawn
CURLcode CurlEasy.LoadOpt()
CURLcode CurlEasy.Perform()
```

`Perform` runs the transfer on the main thread and returns its result code when it is complete. **The whole server
stands still until then**: no player moves, no tick runs. Use it only where that does not matter, such as a console
command for administrators, and always with a short timeout.

A blocking transfer needs `LoadOpt` first. `LoadOpt` hands the options to libcurl, which `PerformThread` does by
itself and `Perform` does not; without it the transfer fails with `CURLE_URL_MALFORMAT`, because libcurl was never
told the URL. `LoadOpt` returns `CURLE_OK`, or the error with which libcurl refused an option.

From [`curl_basics.sp`](../pawn/scripting/examples/curl_basics.sp), a request for the headers of a URL:

```sourcepawn
CurlEasy easy = new CurlEasy();
easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
easy.SetUrl(url);
easy.SetOptInt(CURLOPT_NOBODY, 1);  // Ask for the headers only: a HEAD request.
easy.SetHeaderFile(headerFile);

// Perform() returns when the transfer is complete. The whole server
// waits that long, so this is for console commands and tools; anything
// that runs while people play should use PerformThread().
//
// A blocking transfer needs LoadOpt() first: it hands the options set
// above to libcurl, which PerformThread() does by itself. LoadOpt()
// fails when libcurl refuses one of the values.
CURLcode code = easy.LoadOpt();
if (code == CURLE_OK) {
	code = easy.Perform();
}
if (code != CURLE_OK) {
	char error[256];
	easy.GetError(code, error, sizeof(error));
	PrintToServer("The request failed: %s", error);
} else {
	char finalUrl[256];
	easy.GetEffectiveUrl(finalUrl, sizeof(finalUrl));
	PrintToServer("Status %d from %s after %.3f seconds", easy.ResponseCode, finalUrl, easy.TotalTime);

	// Everything else libcurl knows about the transfer is read with
	// GetInfoInt, into an int or a float depending on the info, and
	// with GetInfoString.
	int redirects;
	easy.GetInfoInt(CURLINFO_REDIRECT_COUNT, redirects);
	float connectSeconds;
	easy.GetInfoInt(CURLINFO_CONNECT_TIME, connectSeconds);
	char address[64];
	easy.GetInfoString(CURLINFO_PRIMARY_IP, address, sizeof(address));
	PrintToServer("%d redirects, connected to %s in %.4f seconds", redirects, address, connectSeconds);
}

delete easy;
delete headerFile;  // Closing the file writes it to the disk.
```

## Receiving the answer

An HTTP answer has a status, headers and a body. The status is read from
[`ResponseCode`](#reading-the-result) after the transfer. For the body there are three choices.

### 1. Ignore it

Do nothing. Without a write file and without a write callback the body is received and thrown away. This is right
when only the status matters, as in the Discord example above.

### 2. Write it to a file

Open a [`CurlFile`](#curlfile) for writing and give it to the transfer with `SetWriteFile`. This is the right choice
for downloads of any size: the data goes from the network to the disk without passing through the plugin.

```sourcepawn
// The download goes into a ".part" file first, so a broken download
// never looks like a map. Paths are relative to the game directory.
char partFile[PLATFORM_MAX_PATH];
Format(partFile, sizeof(partFile), "%s.part", target);
CurlFile file = new CurlFile(partFile, "wb");
if (file == null) {
	ReplyToCommand(client, "Cannot write %s.", partFile);
	return Plugin_Handled;
}

char url[512];
g_BaseUrl.GetString(url, sizeof(url));
Format(url, sizeof(url), "%s/%s.bsp", url, map);

CurlEasy easy = new CurlEasy();
easy.SetUrl(url);
easy.SetWriteFile(file);
```

The file is complete on the disk only after its `CurlFile` was closed. Close it in the complete callback, then use
the file:

```sourcepawn
char error[256];
easy.GetError(code, error, sizeof(error));
float seconds = easy.TotalTime;

// Closing the file writes its last bytes to the disk.
delete easy;
delete file;

char target[PLATFORM_MAX_PATH];
Format(target, sizeof(target), "maps/%s.bsp", map);
char partFile[PLATFORM_MAX_PATH];
Format(partFile, sizeof(partFile), "%s.part", target);

if (code != CURLE_OK) {
	DeleteFile(partFile);
	LogError("Download of %s failed: %s", map, error);
	return;
}

if (!RenameFile(target, partFile)) {
	DeleteFile(partFile);
	LogError("Cannot move %s to %s", partFile, target);
	return;
}

LogMessage("Downloaded %s: %d bytes in %.1f seconds", target, FileSize(target), seconds);
```

The error message and the duration are read first, because they cannot be read anymore once the `CurlEasy` is
deleted.

`SetHeaderFile` does the same for the answer's headers. With `SetFollowLocation(true)` the file gets the headers of
every answer on the way, the redirects included. This is the header file of a request that was redirected once:

```
HTTP/1.1 302 Found
Content-Type: text/plain
Content-Length: 0
Location: /index.html
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 6
```

### 3. Receive it in a callback

Set a write callback with `SetOptFunction(CURLOPT_WRITEFUNCTION, callback, value)`. libcurl calls it for every piece
of the body as it arrives:

<!-- not-an-excerpt -->
```sourcepawn
public int OnData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb, any value)
```

- `easy` is the transfer.
- `buffer` holds the piece. Treat it as bytes, not as a string: it may contain NUL bytes, at which every string
  function would stop.
- The piece has `bytes * nmemb` bytes. (`bytes` is always 1; the two numbers are how libcurl reports sizes.) A piece
  is at most 16384 bytes long.
- `value` is the third argument of `SetOptFunction`. It may be left out, or declared with its real type.
- **The callback must return `bytes * nmemb`.** Any other number tells libcurl that the data could not be handled, and
  the transfer ends with `CURLE_WRITE_ERROR`.

How often the callback is called and how the body is cut into pieces is up to the network. Never assume that the
whole answer arrives in one call.

A plugin has little memory of its own, so an answer of unknown size should be collected in a
[`CurlBuffer`](buffer.md), which lives in the extension. From
[`curl_etf2l_player.sp`](../pawn/scripting/examples/curl_etf2l_player.sp):

```sourcepawn
// The answer is collected in this buffer. It is passed to the write
// callback and to the complete callback as their data.
CurlBuffer answer = new CurlBuffer();

easy.SetUrl(url);
easy.SetUserAgent("sm-neocurl example");
easy.SetTimeout(15);
easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnAnswerData, answer);
easy.PerformThread(OnAnswer, answer);
return Plugin_Handled;
```

```sourcepawn
public int OnAnswerData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb, CurlBuffer answer)
{
	int length = bytes * nmemb;
	answer.Append(buffer, length);
	return length;
}
```

The complete callback then reads the buffer and deletes it. See [CurlBuffer](buffer.md) for how to read one.

A short answer whose size is known to be small can go straight into a `char` array, as
[`curl_demo_upload.sp`](../pawn/scripting/examples/curl_demo_upload.sp) does with the one line demos.tf answers:

```sourcepawn
public int OnAnswerData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb)
{
	int length = bytes * nmemb;
	int used = strlen(g_Answer);
	int room = sizeof(g_Answer) - 1 - used;
	int count = length < room ? length : room;
	for (int i = 0; i < count; i++) {
		g_Answer[used + i] = buffer[i];
	}
	g_Answer[used + count] = '\0';
	return length;
}
```

Two things to know about write callbacks:

- When a write callback is set, a file set with `SetWriteFile` is ignored. A header file set with `SetHeaderFile`
  still gets the headers.
- Each piece is handed over in a game frame, and the transfer waits for that. A transfer with a write callback
  therefore receives at most one piece, 16 KB, per game frame: about one megabyte per second on a server that runs
  at 66 ticks per second. That is plenty for API answers. For large downloads write to a file instead, which has no
  such limit.

## Sending data

A request without a body is a GET. There are four ways to send a body: the first two make the request a POST, the
other two a PUT. Which of the two a service expects is told by its documentation; as a rule, POST hands data to the
service and PUT stores it under the URL.

### A text body: SetPostFields

`SetPostFields(text)` makes the request a POST with `text` as its body. The text is copied, so the plugin's array may
go out of scope. It is sent up to its NUL, so this method cannot send binary data.

libcurl announces such a body with the header `Content-Type: application/x-www-form-urlencoded`, the format of a
simple web form (`name=value&other=value`). For anything else, JSON for example, set the right header yourself, as in
the [first request](#a-first-request).

To send a simple web form, build the text and URL-encode the values with `Escape`:

<!-- not-an-excerpt -->
```sourcepawn
bool CurlEasy.Escape(const char[] text, char[] buffer, int maxlen)
int CurlEasy.Unescape(const char[] text, char[] buffer, int maxlen)
```

`Escape` replaces every character that has a special meaning in a URL by `%` and two hex digits: `"a b&c"` becomes
`"a%20b%26c"`. It returns `false` when libcurl could not encode the text. `Unescape` reverses it and returns the
length of the decoded text, which is more than was written when `buffer` is too small for it, and 0 when libcurl could
not decode the text. Both are methods of a `CurlEasy` but do not change it. Values that become part of a URL need the
same treatment:

```sourcepawn
// The SteamID becomes a part of the URL, so it is URL-encoded: a
// SteamID3 like [U:1:3017534] would not be a valid URL otherwise.
char encoded[96];
easy.Escape(steamId, encoded, sizeof(encoded));
char url[256];
g_ApiUrl.GetString(url, sizeof(url));
Format(url, sizeof(url), "%s/player/%s", url, encoded);
```

A request made from `[U:1:3017534]` this way goes to `/player/%5BU%3A1%3A3017534%5D`.

### A web form with files: CurlForm

For uploads as a browser's file form sends them (`multipart/form-data`), build a [`CurlForm`](#curlform) and set it
with `SetForm`. See [CurlForm](#curlform) below.

### A file as the body: SetReadFile

`CURLOPT_UPLOAD` turns the request into an upload: an HTTP PUT whose body is read from the `CurlFile` given with
`SetReadFile`. From [`curl_basics.sp`](../pawn/scripting/examples/curl_basics.sp):

```sourcepawn
CurlFile file = new CurlFile(path, "rb");
if (file == null) {
	PrintToServer("Cannot read %s", path);
	return Plugin_Handled;
}

CurlEasy easy = new CurlEasy();
easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
easy.SetUrl(url);
easy.SetOptInt(CURLOPT_UPLOAD, 1);  // Send a body instead of asking for one: HTTP PUT.
easy.SetReadFile(file);
// With the size the request has a Content-Length; without it libcurl
// sends the body in chunks, which not every server accepts.
easy.SetOptInt(CURLOPT_INFILESIZE, FileSize(path));
easy.PerformThread(OnPutDone, file);
```

### A body from a callback

When the data to upload is neither a string nor a file, a read callback supplies it piece by piece. Set it with
`SetOptFunction(CURLOPT_READFUNCTION, callback, value)`:

<!-- not-an-excerpt -->
```sourcepawn
public int OnUploadData(CurlEasy easy, const int bytes, const int nmemb, any value)
```

libcurl calls it whenever it can send more. `bytes * nmemb` is the most it takes now. The callback hands over the next
piece with `easy.SetSendBuffer(data, size)` and returns the number of bytes in it. Returning 0 means: that was all.

<!-- not-an-excerpt -->
```sourcepawn
void CurlEasy.SetSendBuffer(const char[] data, int size = -1)
```

`size` is the number of bytes of `data`; -1 takes `data` up to its NUL. Hand over exactly as many bytes as the
callback returns, and never more than `bytes * nmemb`.

```sourcepawn
char g_Upload[1024];
int g_UploadLength;
int g_UploadSent;

public Action Command_PutText(int args)
{
	char url[256];
	GetCmdArg(1, url, sizeof(url));
	GetCmdArg(2, g_Upload, sizeof(g_Upload));
	g_UploadLength = strlen(g_Upload);
	g_UploadSent = 0;

	CurlEasy easy = new CurlEasy();
	easy.SetOptIntArray(g_CommonOptions, sizeof(g_CommonOptions));
	easy.SetUrl(url);
	easy.SetOptInt(CURLOPT_UPLOAD, 1);
	easy.SetOptInt(CURLOPT_INFILESIZE, g_UploadLength);
	easy.SetOptFunction(CURLOPT_READFUNCTION, OnUploadData);
	easy.PerformThread(OnPutDone);
	return Plugin_Handled;
}
```

```sourcepawn
public int OnUploadData(CurlEasy easy, const int bytes, const int nmemb)
{
	int count = g_UploadLength - g_UploadSent;
	if (count > bytes * nmemb) {
		count = bytes * nmemb;
	}
	if (count <= 0) {
		return 0;
	}

	easy.SetSendBuffer(g_Upload[g_UploadSent], count);
	g_UploadSent += count;
	return count;
}
```

When a read callback is set, a file set with `SetReadFile` is ignored. Like a write callback, a read callback is
called in a game frame, one piece per frame.

## Reading the result

After the transfer, in the complete callback and before the `CurlEasy` is deleted:

| Member | What it gives |
|---|---|
| `ResponseCode` | The HTTP status of the last answer: 200, 404, ... It is 0 when no answer arrived. |
| `TotalTime` | The seconds the transfer took, as a `float`. |
| `GetEffectiveUrl(buffer, maxlen)` | The URL that was used in the end. With redirects that is the last one. |
| `GetContentType(buffer, maxlen)` | The answer's `Content-Type` header, such as `application/json`. Empty when it had none. |

```sourcepawn
char finalUrl[256];
easy.GetEffectiveUrl(finalUrl, sizeof(finalUrl));
PrintToServer("Status %d from %s after %.3f seconds", easy.ResponseCode, finalUrl, easy.TotalTime);
```

libcurl knows more about a transfer than these four. Everything is read with the two generic methods and an info
named `CURLINFO_...`:

<!-- not-an-excerpt -->
```sourcepawn
CURLcode CurlEasy.GetInfoString(CURLINFO info, char[] buffer, int maxlen)
CURLcode CurlEasy.GetInfoInt(CURLINFO info, any &value)
```

`GetInfoString` reads the infos that are strings, `GetInfoInt` those that are numbers. Whether a number is a whole
number or a fraction depends on the info; pass an `int` variable for the first kind and a `float` variable for the
second. The [reference](#infos) lists the infos by kind. Both methods return `CURLE_OK`, or
`CURLE_BAD_FUNCTION_ARGUMENT` when the info is not of the kind the method reads; the variable is left unchanged then.

```sourcepawn
// Everything else libcurl knows about the transfer is read with
// GetInfoInt, into an int or a float depending on the info, and
// with GetInfoString.
int redirects;
easy.GetInfoInt(CURLINFO_REDIRECT_COUNT, redirects);
float connectSeconds;
easy.GetInfoInt(CURLINFO_CONNECT_TIME, connectSeconds);
char address[64];
easy.GetInfoString(CURLINFO_PRIMARY_IP, address, sizeof(address));
PrintToServer("%d redirects, connected to %s in %.4f seconds", redirects, address, connectSeconds);
```

This prints, for example, `1 redirects, connected to 127.0.0.1 in 0.0003 seconds`.

## Handling errors

There are two different kinds of failure, and a plugin must check both.

**The transfer failed.** No usable answer arrived: the host name does not exist, nothing listens on the port, the
certificate is not trusted, the timeout ran out. The complete callback's `code` is then not `CURLE_OK` but one of
libcurl's error codes, such as `CURLE_COULDNT_RESOLVE_HOST` or `CURLE_OPERATION_TIMEDOUT`. All of them are listed in
[libcurl's error list](https://curl.se/libcurl/c/libcurl-errors.html); the enum `CURLcode` in `cURL_header.inc` has
every code of the linked libcurl, from `CURLE_OK` (0) to `CURLE_ECH_REQUIRED` (101).

**The server answered with an error.** The transfer worked, `code` is `CURLE_OK`, but the answer's status says that
the request was refused: 404, 401, 500, ... The plugin sees that in `ResponseCode`.

```sourcepawn
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
```

### Getting a readable error message

<!-- not-an-excerpt -->
```sourcepawn
void CurlEasy.GetError(CURLcode code, char[] buffer, int maxlen)
```

`GetError` writes a message for a log. It prefers the message libcurl recorded for this very transfer, which names
what went wrong:

```
Failed to connect to 127.0.0.1:1 after 0 ms: Could not connect to server
The requested URL returned error: 404
Could not open file /curl_ext_test/missing.txt
```

When libcurl recorded nothing, `GetError` writes the general description of the code instead, such as "Timeout was
reached". A buffer of 256 bytes holds every message. Call it before the `CurlEasy` is deleted.

`GetError` combines two methods that can also be called on their own:

| Method | What it gives |
|---|---|
| `GetErrorBuffer(buffer, maxlen)` | The message libcurl recorded for this transfer. Empty when there is none. |
| `CurlEasy.StrError(code, buffer, maxlen)` | The general description of an error code. A static method: it needs no handle, so it also works where only a code is at hand. |

### Turning an error status into a failed transfer

With `CURLOPT_FAILONERROR` set to 1, an answer with status 400 or above makes the transfer fail with
`CURLE_HTTP_RETURNED_ERROR`, and its body is not delivered. That saves the separate check of `ResponseCode`, and it
keeps error pages out of downloaded files:

```sourcepawn
if (code != CURLE_OK) {
	DeleteFile(partFile);
	LogError("Download of %s failed: %s", map, error);
	return;
}
```

The log line of a map that does not exist on the server:

```
Download of cp_missing failed: The requested URL returned error: 404
```

## CurlSlist

A `CurlSlist` is a list of strings for the options that take a list. Its main use is `SetHeaders`: one string per
request header, written as `Name: value`.

| Method | What it does |
|---|---|
| `new CurlSlist()` | Creates an empty list. |
| `Append(text)` | Adds a string to the end of the list. |

```sourcepawn
CurlSlist headers = new CurlSlist();
headers.Append("Content-Type: application/json");
headers.Append(signatureHeader);

CurlEasy easy = new CurlEasy();
easy.SetUrl(url);
easy.SetHeaders(headers);
```

A header set this way replaces the one libcurl would send by itself, which is how the example changes
`Content-Type`. A header with nothing after the colon (`"Accept:"`) removes libcurl's own header of that name.

The other options that take a `CurlSlist` are set with `SetOptHandle`: `CURLOPT_QUOTE`, `CURLOPT_POSTQUOTE`,
`CURLOPT_PREQUOTE`, `CURLOPT_TELNETOPTIONS`, `CURLOPT_HTTP200ALIASES`, `CURLOPT_MAIL_RCPT` and `CURLOPT_RESOLVE`.

## CurlForm

A `CurlForm` is the body of an HTTP POST in the format browsers use for forms with file uploads,
`multipart/form-data`. A form consists of sections; each has a name and is either a text or a file.

| Method | What it adds |
|---|---|
| `new CurlForm()` | Creates an empty form. |
| `AddField(name, contents)` | A section with a text. |
| `AddFile(name, path, contentType = "", filename = "")` | A section that uploads the file at `path`. `contentType` is the file's type as sent to the server; when it is empty libcurl derives one from the file's extension, and uses `application/octet-stream` for extensions it does not know. `filename` is the file name the server is told; when it is empty that is the file's own name without its directory. |
| `AddFileContent(name, path)` | A section with a text that is read from the file at `path`. Unlike `AddFile`, the server sees an ordinary text field, not an upload. |

The three `Add` methods return a `CURLFORMcode`: `CURL_FORMADD_OK` when the section was added, another value when
not. Paths follow the [rule for files](#options-that-name-a-file): relative to the game directory.

The upload of a demo to demos.tf, from
[`curl_demo_upload.sp`](../pawn/scripting/examples/curl_demo_upload.sp):

```sourcepawn
// The form: four text fields and the demo itself as a file upload.
g_Form = new CurlForm();
g_Form.AddField("key", apiKey);
g_Form.AddField("name", file);
g_Form.AddField("red", "RED");
g_Form.AddField("blu", "BLU");
if (g_Form.AddFile("demo", file, "application/octet-stream") != CURL_FORMADD_OK) {
	delete g_Form;
	ReplyToCommand(client, "Cannot add %s to the upload.", file);
	return Plugin_Handled;
}

char url[256];
g_UploadUrl.GetString(url, sizeof(url));

g_Answer[0] = '\0';
CurlEasy easy = new CurlEasy();
easy.SetUrl(url);
easy.SetForm(g_Form);  // Setting a form makes the request a POST.
easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnAnswerData);
easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
easy.SetTimeout(300);
easy.PerformThread(OnUploaded);
```

The server receives a request with five sections: `key`, `name`, `red` and `blu` as texts, and `demo` as a file named
`match.dem` of type `application/octet-stream`.

The methods cover the usual sections. For the rare other cases, the native `curl_formadd` takes a free list of
`CURLFORM_` options and works on the same handle:

<!-- not-an-excerpt -->
```sourcepawn
curl_formadd(form, CURLFORM_COPYNAME, "note", CURLFORM_COPYCONTENTS, "hello", CURLFORM_CONTENTTYPE, "text/plain",
             CURLFORM_END);
```

It accepts `CURLFORM_COPYNAME`, `CURLFORM_NAMELENGTH`, `CURLFORM_COPYCONTENTS`, `CURLFORM_CONTENTSLENGTH`,
`CURLFORM_FILECONTENT`, `CURLFORM_FILE`, `CURLFORM_CONTENTTYPE`, `CURLFORM_FILENAME` and `CURLFORM_CONTENTHEADER` (a
`CurlSlist` with headers for the section), and the list must end with `CURLFORM_END`.

## CurlFile

A `CurlFile` is an open file for a transfer to write to or read from.

<!-- not-an-excerpt -->
```sourcepawn
new CurlFile(const char[] file, const char[] mode)
```

- `file` is the path, [relative to the game directory](#options-that-name-a-file).
- `mode` is the mode of C's `fopen`: `"wb"` creates the file or empties an existing one for writing, `"ab"` appends
  to it, `"rb"` opens it for reading. The `b` keeps Windows from changing line ends; always use it.
- The result is `null` when the file cannot be opened, for example because its directory does not exist. Check for
  that before using it.

A `CurlFile` has no methods. It is given to a `CurlEasy` with `SetWriteFile`, `SetHeaderFile` or `SetReadFile`, or
with `SetOptHandle` for `CURLOPT_STDERR`, the file libcurl writes its log to when `CURLOPT_VERBOSE` is 1.

Closing a `CurlFile` closes the file. Until then the last bytes written may not be on the disk yet, so close it before
reading, renaming or measuring the file.

## Closing handles

The plugin that created a handle closes it with `delete`. The order and the moment matter little, with two rules:

- A `CurlSlist`, `CurlForm` or `CurlFile` given to a `CurlEasy` is used by its transfer. The usual place to close it
  is the complete callback. Closing it earlier is safe: the extension keeps it alive, and really closes it together
  with the `CurlEasy`. For a `CurlFile` that means the file is complete on the disk only once both are closed.
- Do not give the same `CurlSlist`, `CurlForm` or `CurlFile` to two transfers that run at the same time. Create one
  per transfer.

Deleting a `CurlEasy` while its transfer runs ends the transfer. Its complete callback is not called, so whatever the
callback would have cleaned up must be cleaned up where the `CurlEasy` is deleted. The same happens when the plugin is
unloaded during a transfer: its transfers end and none of its callbacks is called. The transfer does not stop in the
same instant: an HTTP transfer ends within about a second, a send & receive thread when its current send or receive
has finished or timed out.

## Raw TCP and UDP connections

A `CurlEasy` can also open a plain connection and let the plugin send and receive bytes itself. This is for services
that do not speak HTTP. The complete example is
[`curl_tcp_client.sp`](../pawn/scripting/examples/curl_tcp_client.sp).

### Connecting

Set the address as URL and `CURLOPT_CONNECT_ONLY` to 1, and run the transfer. It ends as soon as the connection is
established:

```sourcepawn
CurlEasy easy = new CurlEasy();
easy.SetUrl(address);
// Connect, and then stop: no request is sent and no answer is read.
easy.SetOptInt(CURLOPT_CONNECT_ONLY, 1);
easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
easy.PerformThread(OnConnected, pack);
```

The address is `host:port` for a TCP connection. With `udp://` in front, `udp://host:port`, the connection is a UDP
"connection": datagrams to and from that one address. UDP works with IPv4 addresses only.

### Sending and receiving

On the connected handle, `SendRecv` starts a thread that sends and receives for the plugin:

<!-- not-an-excerpt -->
```sourcepawn
void CurlEasy.SendRecv(CURL_OnSend onSend, CURL_OnReceive onReceive, CURL_OnComplete onComplete, SendRecv_Act act,
                       int sendTimeout, int recvTimeout, int recvBufferSize = 1024, any value = 0)
```

The thread does one thing at a time, and after each thing a callback of the plugin tells it what to do next. The
things are the values of `SendRecv_Act`:

| Action | What the thread does |
|---|---|
| `SendRecv_Act_GOTO_SEND` | Waits until the connection can take data, at most `sendTimeout` milliseconds, sends the send buffer and calls `onSend`. |
| `SendRecv_Act_GOTO_RECV` | Waits until data arrived, at most `recvTimeout` milliseconds, reads up to `recvBufferSize` bytes and calls `onReceive`. |
| `SendRecv_Act_GOTO_WAIT` | Sleeps until the plugin calls `Signal`. |
| `SendRecv_Act_GOTO_END` | Ends. `onComplete` is called. |
| `SendRecv_Act_GOTO_SEND_NO_WAIT`, `SendRecv_Act_GOTO_RECV_NO_WAIT` | Like send and receive, but without waiting for the connection first. |

The arguments of `SendRecv`:

- `onSend`, `onReceive`, `onComplete`: the three callbacks, described below.
- `act`: the first action.
- `sendTimeout`, `recvTimeout`: how long a send and a receive may wait for the connection, in milliseconds.
- `recvBufferSize`: the most bytes one receive reads.
- `value`: any value; it is passed to all three callbacks.

`SendRecv` needs a connected handle. On a handle that never connected, `onComplete` is called at once with
`CURLE_SEND_ERROR`.

```sourcepawn
// What the first send sends. Then the send & receive thread starts
// with a send; each callback tells it what to do next.
easy.SetSendBuffer(line);
easy.SendRecv(OnSent, OnReceived, OnEnded, SendRecv_Act_GOTO_SEND, IO_TIMEOUT, IO_TIMEOUT, 1024, pack);
```

The callbacks:

<!-- not-an-excerpt -->
```sourcepawn
public SendRecv_Act OnSent(CurlEasy easy, CURLcode code, const int sentBytes, any value)
public SendRecv_Act OnReceived(CurlEasy easy, CURLcode code, const char[] data, const int size, any value)
public void OnEnded(CurlEasy easy, CURLcode code, any value)
```

- `onSend` is called after a send. Look at `code` first. With `CURLE_OK`, `sentBytes` is the number of bytes sent.
  Otherwise `code` is the error, and `sentBytes` means nothing: `CURLE_OPERATION_TIMEDOUT` when the connection did
  not take data in time, `CURLE_SEND_ERROR` when the send buffer was empty.
- `onReceive` is called after a receive. Look at `code` first. With `CURLE_OK`, `data` holds `size` bytes; it has no
  NUL at its end, so copy it with its length. A `size` of 0 means that the other side closed the connection. With
  any other `code`, such as `CURLE_OPERATION_TIMEDOUT` when nothing arrived in time, `data` and `size` mean nothing.
- Both return the next action.
- `onComplete` is called once, when the thread ended. Its `code` is the result of the last send or receive. Delete the
  `CurlEasy` here, which closes the connection.

```sourcepawn
public SendRecv_Act OnSent(CurlEasy easy, CURLcode code, const int sentBytes, DataPack pack)
{
	if (code != CURLE_OK) {
		// The error reaches OnEnded as its code.
		return SendRecv_Act_GOTO_END;
	}
	PrintToServer("Sent %d bytes", sentBytes);
	return SendRecv_Act_GOTO_RECV;
}
```

```sourcepawn
public SendRecv_Act OnReceived(CurlEasy easy, CURLcode code, const char[] data, const int size, DataPack pack)
{
	if (code == CURLE_OK && size > 0) {
		// The data is not NUL-terminated text: copy it with its length.
		char[] text = new char[size + 1];
		for (int i = 0; i < size; i++) {
			text[i] = data[i];
		}
		text[size] = '\0';
		PrintToServer("Received %d bytes: %s", size, text);
	}
	// One answer is enough for this example.
	return SendRecv_Act_GOTO_END;
}
```

For `sm_tcp_send "127.0.0.1:9000" hello` against a service that answers every line in upper case, the server console
shows:

```
Sent 6 bytes
Received 12 bytes: echo: HELLO
```

### The other send & receive methods

| Member | What it does |
|---|---|
| `SetSendBuffer(data, size = -1)` | Sets what the next send sends: `size` bytes of `data`, or `data` up to its NUL with -1. A send empties the buffer, so set it before every send. It is the same buffer a [read callback](#a-body-from-a-callback) fills. |
| `Signal(action)` | Wakes a thread that sleeps in `SendRecv_Act_GOTO_WAIT` and gives it its next action. Call it only for a thread the plugin sent to sleep, by starting with or returning `SendRecv_Act_GOTO_WAIT`, and not from inside the send or receive callback. Returns `false` when the thread is not waiting. |
| `IsWaiting` | `true` while the thread waits: for `Signal`, or for a callback of the plugin to return. |
| `SetReceiveSize(size)` | Changes the most bytes a receive reads. It has an effect only after `SendRecv` was called. At most 67108864 (64 MB); 0 means 1024. |
| `SetSendTimeout(milliseconds)`, `SetRecvTimeout(milliseconds)` | Change the two timeouts. Values of 0 or below are ignored. |

A connection that only talks when the plugin has something to say starts with `SendRecv_Act_GOTO_WAIT`. When there
is something to send, the plugin sets the send buffer and wakes the thread:

<!-- not-an-excerpt -->
```sourcepawn
easy.SetSendBuffer("status\n");
easy.Signal(SendRecv_Act_GOTO_SEND);
```

## Information about libcurl

Three static methods tell what the linked libcurl is and can do. They need no handle:

| Method | What it gives |
|---|---|
| `CurlEasy.Version(buffer, maxlen)` | The versions of libcurl and of the libraries it uses. |
| `CurlEasy.Protocols(buffer, maxlen)` | The protocols it supports, separated by spaces. |
| `CurlEasy.Features()` | Its features as bits: test them with the `CURL_VERSION_...` constants. |

```sourcepawn
public Action Command_Info(int args)
{
	char text[512];
	CurlEasy.Version(text, sizeof(text));
	PrintToServer("Version: %s", text);
	CurlEasy.Protocols(text, sizeof(text));
	PrintToServer("Protocols: %s", text);

	int features = CurlEasy.Features();
	PrintToServer("TLS: %s, IPv6: %s, compressed answers: %s",
	              (features & CURL_VERSION_SSL) ? "yes" : "no",
	              (features & CURL_VERSION_IPV6) ? "yes" : "no",
	              (features & CURL_VERSION_LIBZ) ? "yes" : "no");
	return Plugin_Handled;
}
```

On a server with version 2.1.0 of the extension this prints:

```
Version: libcurl/8.23.0 OpenSSL/3.6.5 zlib/1.4 brotli/1.2.1 zstd/1.5.7 libpsl/0.21.5 libssh2/1.11.1_DEV nghttp2/1.71.0
Protocols: dict file ftp ftps gopher gophers http https imap imaps mqtt mqtts pop3 pop3s rtsp scp sftp smtp smtps telnet tftp ws wss
TLS: yes, IPv6: yes, compressed answers: yes
```

## Complete examples

Each of these is a complete plugin in [`pawn/scripting/examples/`](../pawn/scripting/examples/). They compile as they
are and were run on a test server.

| Plugin | What it does | What it shows |
|---|---|---|
| [`curl_discord_webhook.sp`](../pawn/scripting/examples/curl_discord_webhook.sp) | Posts map changes and `sm_discord <message>` to a Discord channel. | A JSON POST, request headers, status and error handling. |
| [`curl_map_download.sp`](../pawn/scripting/examples/curl_map_download.sp) | `sm_downloadmap <map>` fetches a map from a fast download server into `maps/`. | Downloading to a file, redirects, timeouts, `CURLOPT_FAILONERROR`, a `DataPack` for the callback. |
| [`curl_demo_upload.sp`](../pawn/scripting/examples/curl_demo_upload.sp) | `sm_uploaddemo <file>` uploads a SourceTV demo to demos.tf. | A form with fields and a file, a short answer read by a write callback. |
| [`curl_etf2l_player.sp`](../pawn/scripting/examples/curl_etf2l_player.sp) | `sm_etf2l_lookup <SteamID64>` asks the ETF2L API for a player. | A GET whose answer is collected in a `CurlBuffer`, URL encoding, the content type. |
| [`curl_basics.sp`](../pawn/scripting/examples/curl_basics.sp) | Four small console commands. | A blocking transfer, a header file, PUT uploads from a file and from a callback, the libcurl information. |
| [`curl_tcp_client.sp`](../pawn/scripting/examples/curl_tcp_client.sp) | `sm_tcp_send <address> <text>` sends a line to a TCP or UDP service and prints the answer. | Raw connections with send & receive. |

A note for trying them: on the server console, put URLs and addresses in quotes. The console treats `//` as the start
of a comment and `:` as a separator between arguments, so `sm_curl_head https://example.com` would not arrive as
written.

```
sm_curl_head "https://example.com"
sm_tcp_send "127.0.0.1:9000" hello
```

### Upload a demo to demos.tf

demos.tf takes a demo as a form with the fields `key` (the uploader's API key), `name`, `red`, `blu` and the file
`demo`. It answers an upload with one line of text: `STV available at: https://demos.tf/<number>` when it took the
demo, otherwise the reason, such as `Invalid key`. The text, not the status, tells whether the upload worked, so the
plugin has to read the answer:

```sourcepawn
public void OnUploaded(CurlEasy easy, CURLcode code)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("demos.tf upload failed: %s", error);
	} else if (StrContains(g_Answer, "STV available at: ") == 0) {
		// The link starts after the 18 characters of the prefix.
		PrintToChatAll("Demo uploaded: %s", g_Answer[18]);
		LogMessage("Demo uploaded: %s", g_Answer[18]);
	} else {
		LogError("demos.tf refused the upload (HTTP status %d): %s", easy.ResponseCode, g_Answer);
	}

	delete easy;
	delete g_Form;
}
```

### Look up a player in the ETF2L API

The ETF2L API answers `GET /player/<id>` with JSON, and with status 404 for a player it does not know. The complete
callback tells the three outcomes apart and reads the answer from the `CurlBuffer`:

```sourcepawn
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
```

For `sm_etf2l_lookup 76561197963283262` the console shows a line like this, with the size of the real answer:

```
ETF2L name: Nace (181 bytes of application/json)
```

## Reference

### CurlEasy

| Member | Native | Returns |
|---|---|---|
| `new CurlEasy()` | `curl_easy_init` | The handle, or `null` when libcurl could not create one. |
| `SetOptString(CURLoption option, const char[] value)` | `curl_easy_setopt_string` | `bool`, see [above](#what-the-return-value-of-a-setopt-method-means) |
| `SetOptInt(CURLoption option, int value)` | `curl_easy_setopt_int` | `bool` |
| `SetOptIntArray(int[][] array, int size)` | `curl_easy_setopt_int_array` | `bool`: `false` when one of the options was not accepted; the ones before it are set. |
| `SetOptInt64(CURLoption option, const char[] value)` | `curl_easy_setopt_int64` | `bool` |
| `SetOptHandle(CURLoption option, Handle other)` | `curl_easy_setopt_handle` | `bool` |
| `SetOptFunction(CURLoption option, CURL_Function_CB callback, any value = 0)` | `curl_easy_setopt_function` | `bool`: `false` for any option but `CURLOPT_WRITEFUNCTION` and `CURLOPT_READFUNCTION`. |
| `SetUrl`, `SetUserAgent`, `SetPostFields` | `curl_easy_setopt_string` | `bool` |
| `SetTimeout`, `SetFollowLocation` | `curl_easy_setopt_int` | `bool` |
| `SetHeaders`, `SetForm`, `SetWriteFile`, `SetReadFile`, `SetHeaderFile` | `curl_easy_setopt_handle` | `bool` |
| `LoadOpt()` | `curl_load_opt` | `CURLcode` |
| `Perform()` | `curl_easy_perform` | `CURLcode` |
| `PerformThread(CURL_OnComplete callback, any value = 0)` | `curl_easy_perform_thread` | nothing |
| `GetInfoString(CURLINFO info, char[] buffer, int maxlen)` | `curl_easy_getinfo_string` | `CURLcode` |
| `GetInfoInt(CURLINFO info, any &value)` | `curl_easy_getinfo_int` | `CURLcode` |
| `ResponseCode`, `TotalTime` | `curl_easy_getinfo_int` | `int`, `float` |
| `GetEffectiveUrl`, `GetContentType` | `curl_easy_getinfo_string` | `CURLcode` |
| `GetErrorBuffer(char[] buffer, int maxlen)` | `curl_get_error_buffer` | nothing |
| `GetError(CURLcode code, char[] buffer, int maxlen)` | `curl_get_error_buffer`, `curl_easy_strerror` | nothing |
| `Escape(const char[] text, char[] buffer, int maxlen)` | `curl_easy_escape` | `bool` |
| `Unescape(const char[] text, char[] buffer, int maxlen)` | `curl_easy_unescape` | `int`, the length of the result |
| `SendRecv(...)` | `curl_easy_send_recv` | nothing |
| `Signal(SendRecv_Act action)` | `curl_send_recv_Signal` | `bool` |
| `IsWaiting` | `curl_send_recv_IsWaiting` | `bool` |
| `SetSendBuffer(const char[] data, int size = -1)` | `curl_set_send_buffer` | nothing |
| `SetReceiveSize(int size)` | `curl_set_receive_size` | nothing |
| `SetSendTimeout(int timeout)`, `SetRecvTimeout(int timeout)` | `curl_set_send_timeout`, `curl_set_recv_timeout` | nothing |
| `CurlEasy.StrError(CURLcode code, char[] buffer, int maxlen)` | `curl_easy_strerror` | nothing |
| `CurlEasy.Version(char[] buffer, int maxlen)` | `curl_version` | nothing |
| `CurlEasy.Protocols(char[] buffer, int maxlen)` | `curl_protocols` | nothing |
| `CurlEasy.Features()` | `curl_features` | `int` |

Every method throws an error and stops the calling function when its `CurlEasy` is not a valid handle, for example
because it was deleted already.

### CurlSlist, CurlForm, CurlFile

| Member | Native | Returns |
|---|---|---|
| `new CurlSlist()` | `curl_slist` | The handle, or `null`. |
| `CurlSlist.Append(const char[] text)` | `curl_slist_append` | nothing |
| `new CurlForm()` | `curl_httppost` | The handle, or `null`. |
| `CurlForm.AddField(const char[] name, const char[] contents)` | `curl_formadd` | `CURLFORMcode` |
| `CurlForm.AddFile(const char[] name, const char[] path, const char[] contentType = "", const char[] filename = "")` | `curl_formadd` | `CURLFORMcode` |
| `CurlForm.AddFileContent(const char[] name, const char[] path)` | `curl_formadd` | `CURLFORMcode` |
| `new CurlFile(const char[] file, const char[] mode)` | `curl_OpenFile` | The handle, or `null` when the file cannot be opened. |

### Callbacks

The callback types are declared in `cURL.inc` with a `Handle` as first parameter. A plugin may declare that parameter
as `CurlEasy` instead, as this page does, and the `any` value with the type it passes. Every callback may leave out
its last parameter, the value.

| Type | Signature | Used by |
|---|---|---|
| `CURL_OnComplete` | `void (Handle easy, CURLcode code, any value)` | `PerformThread`, `SendRecv` |
| `CURL_Function_CB` (write) | `int (Handle easy, const char[] buffer, const int bytes, const int nmemb, any value)` | `SetOptFunction(CURLOPT_WRITEFUNCTION, ...)` |
| `CURL_Function_CB` (read) | `int (Handle easy, const int bytes, const int nmemb, any value)` | `SetOptFunction(CURLOPT_READFUNCTION, ...)` |
| `CURL_OnSend` | `SendRecv_Act (Handle easy, CURLcode code, const int sentBytes, any value)` | `SendRecv` |
| `CURL_OnReceive` | `SendRecv_Act (Handle easy, CURLcode code, const char[] data, const int size, any value)` | `SendRecv` |

### Supported options

Options that take a string (`SetOptString`):

`CURLOPT_URL`, `CURLOPT_PROXY`, `CURLOPT_PROXYUSERPWD`, `CURLOPT_RANGE`, `CURLOPT_USERPWD`, `CURLOPT_KEYPASSWD`,
`CURLOPT_POSTFIELDS`, `CURLOPT_REFERER`, `CURLOPT_FTPPORT`, `CURLOPT_USERAGENT`, `CURLOPT_COOKIE`,
`CURLOPT_CUSTOMREQUEST`, `CURLOPT_INTERFACE`, `CURLOPT_KRBLEVEL`, `CURLOPT_SSL_CIPHER_LIST`, `CURLOPT_SSLCERTTYPE`,
`CURLOPT_SSLKEYTYPE`, `CURLOPT_SSLENGINE`, `CURLOPT_FTP_ACCOUNT`, `CURLOPT_COOKIELIST`,
`CURLOPT_FTP_ALTERNATIVE_TO_USER`, `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`, `CURLOPT_USERNAME`, `CURLOPT_PASSWORD`,
`CURLOPT_PROXYUSERNAME`, `CURLOPT_PROXYPASSWORD`, `CURLOPT_NOPROXY`, `CURLOPT_SOCKS5_GSSAPI_SERVICE`,
`CURLOPT_MAIL_FROM`, `CURLOPT_RTSP_SESSION_ID`, `CURLOPT_RTSP_STREAM_URI`, `CURLOPT_RTSP_TRANSPORT`

Options that take the path of a file (`SetOptString`, see [Options that name a file](#options-that-name-a-file)):

`CURLOPT_COOKIEFILE`, `CURLOPT_COOKIEJAR`, `CURLOPT_RANDOM_FILE`, `CURLOPT_EGDSOCKET`, `CURLOPT_SSLCERT`,
`CURLOPT_SSLKEY`, `CURLOPT_CAINFO`, `CURLOPT_CAPATH`, `CURLOPT_NETRC_FILE`, `CURLOPT_SSH_PUBLIC_KEYFILE`,
`CURLOPT_SSH_PRIVATE_KEYFILE`, `CURLOPT_CRLFILE`, `CURLOPT_ISSUERCERT`, `CURLOPT_SSH_KNOWNHOSTS`

Options that take a number (`SetOptInt`, `SetOptIntArray`):

`CURLOPT_PORT`, `CURLOPT_NOPROGRESS`, `CURLOPT_VERBOSE`, `CURLOPT_PROXYTYPE`, `CURLOPT_HTTPPROXYTUNNEL`,
`CURLOPT_TIMEOUT`, `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_SSL_VERIFYHOST`, `CURLOPT_UPLOAD`, `CURLOPT_INFILESIZE`,
`CURLOPT_LOW_SPEED_LIMIT`, `CURLOPT_LOW_SPEED_TIME`, `CURLOPT_RESUME_FROM`, `CURLOPT_CRLF`, `CURLOPT_SSLVERSION`,
`CURLOPT_TIMECONDITION`, `CURLOPT_TIMEVALUE`, `CURLOPT_HEADER`, `CURLOPT_NOBODY`, `CURLOPT_FAILONERROR`,
`CURLOPT_POST`, `CURLOPT_DIRLISTONLY`, `CURLOPT_APPEND`, `CURLOPT_NETRC`, `CURLOPT_FOLLOWLOCATION`,
`CURLOPT_TRANSFERTEXT`, `CURLOPT_PUT`, `CURLOPT_AUTOREFERER`, `CURLOPT_PROXYPORT`, `CURLOPT_POSTFIELDSIZE`,
`CURLOPT_MAXREDIRS`, `CURLOPT_FILETIME`, `CURLOPT_MAXCONNECTS`, `CURLOPT_FRESH_CONNECT`, `CURLOPT_FORBID_REUSE`,
`CURLOPT_CONNECTTIMEOUT`, `CURLOPT_HTTPGET`, `CURLOPT_HTTP_VERSION`, `CURLOPT_FTP_USE_EPSV`,
`CURLOPT_SSLENGINE_DEFAULT`, `CURLOPT_DNS_USE_GLOBAL_CACHE`, `CURLOPT_DNS_CACHE_TIMEOUT`, `CURLOPT_COOKIESESSION`,
`CURLOPT_BUFFERSIZE`, `CURLOPT_NOSIGNAL`, `CURLOPT_UNRESTRICTED_AUTH`, `CURLOPT_FTP_USE_EPRT`, `CURLOPT_HTTPAUTH`,
`CURLOPT_FTP_CREATE_MISSING_DIRS`, `CURLOPT_PROXYAUTH`, `CURLOPT_IPRESOLVE`, `CURLOPT_MAXFILESIZE`,
`CURLOPT_USE_SSL`, `CURLOPT_TCP_NODELAY`, `CURLOPT_FTPSSLAUTH`, `CURLOPT_IGNORE_CONTENT_LENGTH`,
`CURLOPT_FTP_SKIP_PASV_IP`, `CURLOPT_FTP_FILEMETHOD`, `CURLOPT_LOCALPORT`, `CURLOPT_LOCALPORTRANGE`,
`CURLOPT_CONNECT_ONLY`, `CURLOPT_SSL_SESSIONID_CACHE`, `CURLOPT_SSH_AUTH_TYPES`, `CURLOPT_FTP_SSL_CCC`,
`CURLOPT_TIMEOUT_MS`, `CURLOPT_CONNECTTIMEOUT_MS`, `CURLOPT_HTTP_TRANSFER_DECODING`,
`CURLOPT_HTTP_CONTENT_DECODING`, `CURLOPT_NEW_FILE_PERMS`, `CURLOPT_NEW_DIRECTORY_PERMS`, `CURLOPT_POSTREDIR`,
`CURLOPT_PROXY_TRANSFER_MODE`, `CURLOPT_ADDRESS_SCOPE`, `CURLOPT_CERTINFO`, `CURLOPT_TFTP_BLKSIZE`,
`CURLOPT_PROTOCOLS`, `CURLOPT_REDIR_PROTOCOLS`, `CURLOPT_FTP_USE_PRET`, `CURLOPT_RTSP_REQUEST`,
`CURLOPT_RTSP_CLIENT_CSEQ`, `CURLOPT_RTSP_SERVER_CSEQ`, `CURLOPT_WILDCARDMATCH`, `CURLOPT_TRANSFER_ENCODING`,
`CURLOPT_GSSAPI_DELEGATION`

Options that take a large number as text (`SetOptInt64`):

`CURLOPT_INFILESIZE_LARGE`, `CURLOPT_RESUME_FROM_LARGE`, `CURLOPT_MAXFILESIZE_LARGE`, `CURLOPT_POSTFIELDSIZE_LARGE`,
`CURLOPT_MAX_SEND_SPEED_LARGE`, `CURLOPT_MAX_RECV_SPEED_LARGE`

Options that take a handle (`SetOptHandle`):

| Handle | Options |
|---|---|
| `CurlFile` | `CURLOPT_WRITEDATA`, `CURLOPT_HEADERDATA`, `CURLOPT_READDATA`, `CURLOPT_STDERR`, `CURLOPT_INTERLEAVEDATA` |
| `CurlForm` | `CURLOPT_HTTPPOST` |
| `CurlSlist` | `CURLOPT_HTTPHEADER`, `CURLOPT_QUOTE`, `CURLOPT_POSTQUOTE`, `CURLOPT_PREQUOTE`, `CURLOPT_TELNETOPTIONS`, `CURLOPT_HTTP200ALIASES`, `CURLOPT_MAIL_RCPT`, `CURLOPT_RESOLVE` |

Options that take a callback (`SetOptFunction`): `CURLOPT_WRITEFUNCTION`, `CURLOPT_READFUNCTION`

The option names are those of the libcurl version the extension was first written for. A few of them are deprecated
in the libcurl it links today; libcurl still accepts them, and what each one does now is told on its page in
[libcurl's option list](https://curl.se/libcurl/c/curl_easy_setopt.html).

### Infos

Strings, read with `GetInfoString`:

`CURLINFO_EFFECTIVE_URL`, `CURLINFO_CONTENT_TYPE`, `CURLINFO_FTP_ENTRY_PATH`, `CURLINFO_REDIRECT_URL`,
`CURLINFO_PRIMARY_IP`, `CURLINFO_LOCAL_IP`, `CURLINFO_RTSP_SESSION_ID`

Whole numbers, read with `GetInfoInt` into an `int`:

`CURLINFO_RESPONSE_CODE`, `CURLINFO_HEADER_SIZE`, `CURLINFO_REQUEST_SIZE`, `CURLINFO_SSL_VERIFYRESULT`,
`CURLINFO_FILETIME`, `CURLINFO_REDIRECT_COUNT`, `CURLINFO_HTTP_CONNECTCODE`, `CURLINFO_HTTPAUTH_AVAIL`,
`CURLINFO_PROXYAUTH_AVAIL`, `CURLINFO_OS_ERRNO`, `CURLINFO_NUM_CONNECTS`, `CURLINFO_CONDITION_UNMET`,
`CURLINFO_PRIMARY_PORT`, `CURLINFO_LOCAL_PORT`, `CURLINFO_LASTSOCKET`, `CURLINFO_RTSP_CLIENT_CSEQ`,
`CURLINFO_RTSP_SERVER_CSEQ`, `CURLINFO_RTSP_CSEQ_RECV`

Fractions, read with `GetInfoInt` into a `float`. Times are in seconds, sizes in bytes, speeds in bytes per second:

`CURLINFO_TOTAL_TIME`, `CURLINFO_NAMELOOKUP_TIME`, `CURLINFO_CONNECT_TIME`, `CURLINFO_PRETRANSFER_TIME`,
`CURLINFO_STARTTRANSFER_TIME`, `CURLINFO_REDIRECT_TIME`, `CURLINFO_APPCONNECT_TIME`, `CURLINFO_SIZE_UPLOAD`,
`CURLINFO_SIZE_DOWNLOAD`, `CURLINFO_SPEED_DOWNLOAD`, `CURLINFO_SPEED_UPLOAD`, `CURLINFO_CONTENT_LEN_DOWNLOAD`,
`CURLINFO_CONTENT_LEN_UPLOAD`

The infos that are lists (`CURLINFO_SSL_ENGINES`, `CURLINFO_COOKIELIST`, `CURLINFO_CERTINFO`) cannot be read.
[libcurl's info list](https://curl.se/libcurl/c/curl_easy_getinfo.html) describes each info.

## Common mistakes

- **Using a `CurlEasy` for a second request.** The options of a handle reach libcurl once. A second transfer on the
  same handle never sends the new request: it repeats the first one, or does nothing at all when the first one
  failed. Create a new `CurlEasy` per request.
- **Starting a transfer on a handle whose transfer still runs.** Nothing prevents it, and two transfers then work
  on the same handle. Wait for the complete callback.
- **Calling `Perform` without `LoadOpt`.** The transfer fails with `CURLE_URL_MALFORMAT`. Call `LoadOpt` first, or
  use `PerformThread`, which needs no `LoadOpt`.
- **Calling `Perform` while people play.** The server freezes for as long as the transfer takes. Use `PerformThread`.
- **Checking only the result code.** `CURLE_OK` means an answer arrived, not that it is the wanted one. Check
  `ResponseCode` too, or set `CURLOPT_FAILONERROR`.
- **Treating received data as a string.** The pieces a write or receive callback gets are bytes with a length. They
  may contain NUL bytes, and those of a receive callback have no NUL at their end. Copy them with their length, or
  append them to a `CurlBuffer`.
- **Returning the wrong number from a write callback.** It must return `bytes * nmemb`, also when it chose to drop
  the data. Anything else ends the transfer with `CURLE_WRITE_ERROR`.
- **Expecting the whole answer in one callback.** A body arrives in pieces of up to 16 KB. Collect them and use the
  result in the complete callback.
- **Reading a downloaded file before its `CurlFile` is closed.** The last bytes may still be in memory. Delete the
  `CurlFile` first.
- **Forgetting `Content-Type` on a JSON POST.** `SetPostFields` announces the body as a web form. A JSON API needs
  the header `Content-Type: application/json`.
- **Building a URL from unescaped text.** Spaces, `&`, `#`, `?` and other characters change the meaning of a URL. Run
  every value through `Escape` first.
- **Typing URLs without quotes on the server console.** `//` starts a comment and `:` separates arguments there.
- **Leaving handles open.** Every `CurlEasy`, `CurlSlist`, `CurlForm` and `CurlFile` stays in memory until it is
  deleted or the plugin unloads. A plugin that makes many requests and never deletes runs into SourceMod's handle
  limit.
