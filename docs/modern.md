# CurlEasy, CurlSlist, CurlForm, CurlFile

`curl_modern.inc` (included by `cURL.inc`) wraps the libcurl natives of `cURL.inc` into methodmaps, one per kind of
handle:

- `CurlEasy`: a curl easy handle (`curl_easy_init`) with its options, its transfer, its result and the send & receive
  natives.
- `CurlSlist`: a string list (`curl_slist`), for `CURLOPT_HTTPHEADER` and the other list options.
- `CurlForm`: a multipart/formdata HTTP POST (`curl_httppost`).
- `CurlFile`: a file a transfer is written to or read from (`curl_OpenFile`).

A method calls the native it is named after and nothing else, so the natives' comments in `cURL.inc` describe the
methods too. The natives stay as they are, and both can be used on the same handle: every methodmap is a `Handle`.

```sourcepawn
#include <cURL>

CurlFile g_File;

void Download(const char[] url)
{
	g_File = new CurlFile("addons/sourcemod/data/download.txt", "wb");

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetFollowLocation(true);
	easy.SetTimeout(30);
	easy.SetWriteFile(g_File);
	easy.PerformThread(OnDownloaded);
}

public void OnDownloaded(CurlEasy easy, CURLcode code)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("Download failed: %s", error);
	} else {
		PrintToServer("Status %d after %.2f seconds", easy.ResponseCode, easy.TotalTime);
	}
	delete easy;
	delete g_File;
}
```

The callbacks of `cURL.inc` are declared with a `Handle`; a plugin may declare its callback with `CurlEasy` instead,
as above.

## CurlEasy

| Method | Native | What it does |
|---|---|---|
| `new CurlEasy()` | `curl_easy_init` | A curl easy handle, `null` on failure. Close it with `delete`. |
| `SetOptString(opt, value)` | `curl_easy_setopt_string` | Sets an option that takes a string. |
| `SetOptInt(opt, value)` | `curl_easy_setopt_int` | Sets an option that takes a number. |
| `SetOptIntArray(array, size)` | `curl_easy_setopt_int_array` | Sets several number options, an `{option, value}` pair each. |
| `SetOptInt64(opt, value)` | `curl_easy_setopt_int64` | Sets a 64-bit option; `value` is the number as decimal text. |
| `SetOptHandle(opt, other)` | `curl_easy_setopt_handle` | Sets an option that takes a `CurlFile`, `CurlForm` or `CurlSlist`. |
| `SetOptFunction(opt, callback, value = 0)` | `curl_easy_setopt_function` | Sets `CURLOPT_WRITEFUNCTION` or `CURLOPT_READFUNCTION`. |
| `LoadOpt()` | `curl_load_opt` | Gives the options to libcurl now and returns its code; once per handle. |
| `Perform()` | `curl_easy_perform` | Runs the transfer and returns when it is complete. It blocks the server. |
| `PerformThread(callback, value = 0)` | `curl_easy_perform_thread` | Runs the transfer on a thread; `callback` gets its code. |
| `GetInfoString(info, buffer, maxlen)` | `curl_easy_getinfo_string` | Reads a `CURLINFO_` string; empty when libcurl has none. |
| `GetInfoInt(info, value)` | `curl_easy_getinfo_int` | Reads a `CURLINFO_` number into an `int` or `float` variable. |
| `GetErrorBuffer(buffer, maxlen)` | `curl_get_error_buffer` | libcurl's text about the handle's last error. |
| `Escape(text, buffer, maxlen)` | `curl_easy_escape` | URL-encodes `text`. |
| `Unescape(text, buffer, maxlen)` | `curl_easy_unescape` | URL-decodes `text`; returns the length. |

The options are given to libcurl when the transfer starts, so a `SetOpt` method only tells whether the option exists
with that type; a value libcurl refuses ends the transfer with its code. `SetOpt` methods return `false` while a
transfer of the handle runs.

Static methods, called as `CurlEasy.Version(...)`:

| Method | Native | What it does |
|---|---|---|
| `CurlEasy.StrError(code, buffer, maxlen)` | `curl_easy_strerror` | libcurl's message for a `CURLcode`. |
| `CurlEasy.Version(buffer, maxlen)` | `curl_version` | The versions of libcurl and its libraries. |
| `CurlEasy.Protocols(buffer, maxlen)` | `curl_protocols` | The protocols libcurl was built with. |
| `CurlEasy.Features()` | `curl_features` | The `CURL_VERSION_` bits of libcurl. |

### Shortcuts

Each shortcut sets one option or reads one info:

| Method | Option or info | What it does |
|---|---|---|
| `SetUrl(url)` | `CURLOPT_URL` | The URL of the transfer. |
| `SetHeaders(headers)` | `CURLOPT_HTTPHEADER` | The request's own header lines, a `CurlSlist`. |
| `SetUserAgent(userAgent)` | `CURLOPT_USERAGENT` | The `User-Agent` header. |
| `SetTimeout(seconds)` | `CURLOPT_TIMEOUT` | The seconds the whole transfer may take, 0 for no limit. |
| `SetFollowLocation(follow)` | `CURLOPT_FOLLOWLOCATION` | Whether redirects are followed. |
| `SetPostFields(fields)` | `CURLOPT_POSTFIELDS` | The body of an HTTP POST, up to its NUL. |
| `SetForm(form)` | `CURLOPT_HTTPPOST` | A multipart/formdata HTTP POST, a `CurlForm`. |
| `SetWriteFile(file)` | `CURLOPT_WRITEDATA` | The `CurlFile` the received body is written to. |
| `SetReadFile(file)` | `CURLOPT_READDATA` | The `CurlFile` an upload is read from. |
| `SetHeaderFile(file)` | `CURLOPT_HEADERDATA` | The `CurlFile` the received headers are written to. |
| `ResponseCode` | `CURLINFO_RESPONSE_CODE` | The status of the last response (200, 404, ...), 0 without one. |
| `TotalTime` | `CURLINFO_TOTAL_TIME` | The seconds the last transfer took. |
| `GetEffectiveUrl(buffer, maxlen)` | `CURLINFO_EFFECTIVE_URL` | The URL last used, after redirects. |
| `GetContentType(buffer, maxlen)` | `CURLINFO_CONTENT_TYPE` | The `Content-Type` of the response, empty without one. |
| `GetError(code, buffer, maxlen)` | | The text of a failed transfer, see below. |

### Errors

A transfer ends with a `CURLcode`, `CURLE_OK` on success. The enum in `cURL_header.inc` has every code of the linked
libcurl, up to `CURLE_ECH_REQUIRED` (101). A response with an HTTP error status is a successful transfer: check
`ResponseCode`.

`GetError(code, buffer, maxlen)` gives the text for a log. libcurl keeps a text per handle that names what failed
("Could not resolve host: example.invalid"); `GetError` gives that, and while it is empty the general message of the
code ("Couldn't resolve host name"), which is all `CurlEasy.StrError` knows.

### Send & receive

For connections the plugin talks on itself; see `curl_easy_send_recv` in `cURL.inc`.

| Method | Native |
|---|---|
| `SendRecv(onSend, onReceive, onComplete, act, sendTimeout, recvTimeout, recvBufferSize = 1024, value = 0)` | `curl_easy_send_recv` |
| `Signal(act)` | `curl_send_recv_Signal` |
| `IsWaiting` | `curl_send_recv_IsWaiting` |
| `SetSendBuffer(data, size = -1)` | `curl_set_send_buffer` |
| `SetReceiveSize(size)` | `curl_set_receive_size` |
| `SetSendTimeout(timeout)` | `curl_set_send_timeout` |
| `SetRecvTimeout(timeout)` | `curl_set_recv_timeout` |

## CurlSlist

| Method | Native | What it does |
|---|---|---|
| `new CurlSlist()` | `curl_slist` | An empty string list. Close it with `delete`. |
| `Append(text)` | `curl_slist_append` | Appends a string, e.g. a header line. |

```sourcepawn
CurlSlist headers = new CurlSlist();
headers.Append("Accept: application/json");
headers.Append("Authorization: Bearer abc");
easy.SetHeaders(headers);
```

## CurlForm

| Method | `curl_formadd` options | What it does |
|---|---|---|
| `new CurlForm()` | (`curl_httppost`) | An empty form. Close it with `delete`. |
| `AddField(name, contents)` | `CURLFORM_COPYNAME`, `CURLFORM_COPYCONTENTS` | A section with a text. |
| `AddFile(name, path, contentType = "", filename = "")` | `CURLFORM_COPYNAME`, `CURLFORM_FILE`, `CURLFORM_CONTENTTYPE`, `CURLFORM_FILENAME` | A section that uploads a file. An empty `contentType` is guessed from the file's extension, an empty `filename` is the file's name. |
| `AddFileContent(name, path)` | `CURLFORM_COPYNAME`, `CURLFORM_FILECONTENT` | A section whose text is read from a file. |

Every method returns a `CURLFORMcode`, `CURL_FORMADD_OK` on success. Paths are relative to the game directory.
`curl_formadd` takes a variable list of options, which a method cannot pass on, so sections with other options are
added with the native: `curl_formadd(form, CURLFORM_COPYNAME, "name", ..., CURLFORM_END)`.

## CurlFile

| Method | Native | What it does |
|---|---|---|
| `new CurlFile(file, mode)` | `curl_OpenFile` | Opens a file relative to the game directory with an `fopen` mode (`"wb"`, `"rb"`); `null` when it cannot be opened. Close it with `delete`. |

## Lifetime of the handles

A `CurlSlist`, `CurlForm` or `CurlFile` given to a `CurlEasy` must stay open until the transfer is complete, and
must not be given to a second handle that transfers on a thread at the same time. Close them in the complete
callback, after the `CurlEasy`. A `CurlFile` that was written to has its whole content only once it is closed.
