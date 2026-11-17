# SM-neocurl

SM-neocurl is a [SourceMod](https://www.sourcemod.net/) extension that lets plugins talk to the network and work
with data: HTTP requests and file transfers with [libcurl](https://curl.se/libcurl/), WebSocket connections,
compression, and digests and HMACs. Transfers, connections and jobs run on threads of the extension, so the game
server keeps its tick rate.

It is built for Linux and Windows, for 32-bit and 64-bit servers. All libraries it needs are part of the extension
file; nothing else has to be installed.

- [What plugins get](#what-plugins-get)
- [Installing](#installing)
- [Configuration](#configuration)
- [TLS certificates](#tls-certificates)
- [Writing a plugin](#writing-a-plugin)
- [Example plugins](#example-plugins)
- [Building](#building)
- [Testing](#testing)
- [Source layout](#source-layout)
- [Releases](#releases)

## What plugins get

| Feature | Methodmaps | Guide |
|---|---|---|
| HTTP requests, downloads and uploads with progress reports, web forms, raw TCP and UDP connections | `CurlEasy`, `CurlSlist`, `CurlForm`, `CurlFile` | [HTTP and other transfers](docs/modern.md) |
| WebSocket connections (`ws://` and `wss://`) with keepalive and automatic reconnecting | `WebSocket` | [WebSocket](docs/websocket.md) |
| gzip, zlib, deflate, brotli and zstd, for files and for data in memory | `Compression` | [Compression](docs/compression.md) |
| MD5, SHA-1, SHA-2, SHA-3, BLAKE2, SM3, Keccak-256, CRC-32 and Adler-32 digests, and HMACs | `Crypt` | [Crypt](docs/crypt.md) |
| Byte buffers for data larger than a plugin's memory | `CurlBuffer` | [CurlBuffer](docs/buffer.md) |

Each guide explains its feature step by step, with examples taken from plugins that were run on a test server, and
ends with a complete reference and a list of common mistakes.

Every feature is available in two forms: as natives (`curl_easy_init`, `websocket_connect`,
`compression_compress_file`, ...) and as methodmaps that wrap them. The guides use the methodmaps and list the
native behind each method. Plugins written for the original cURL extension with the `curl_easy_*` natives keep
working.

### What libcurl can do in this build

The extension links libcurl 8.23.0 with OpenSSL (version 2.1.0 of the extension, Linux build). It supports these
protocols:

```
dict file ftp ftps gopher gophers http https imap imaps mqtt mqtts pop3 pop3s rtsp scp sftp smtp smtps telnet tftp ws wss
```

- HTTP/1.1 and HTTP/2. There is no HTTP/3.
- Answers compressed with gzip, deflate, brotli or zstd are unpacked automatically.
- SFTP and SCP through libssh2.
- There is no LDAP support, and no support for international domain names (host names with non-ASCII characters).

A plugin can ask the running extension the same question; see
[Information about libcurl](docs/modern.md#information-about-libcurl).

## Installing

Requirements:

- SourceMod 1.12.
- On Linux: glibc 2.34 or newer (for example Debian 12 or Ubuntu 22.04).

Steps:

1. Download the archive for the server's operating system from the
   [releases](https://github.com/sapphonie/SM-neocurl-ext/releases): `sm-neocurl-v<version>-linux.tar.gz` or
   `sm-neocurl-v<version>-windows.zip`, for example `sm-neocurl-v2.1.0-linux.tar.gz`. Each archive has the files for
   32-bit and for 64-bit servers.
2. Extract it into the game directory, the one that contains `addons/` (`tf/` for Team Fortress 2).
3. Restart the server.

The archive contains:

```
addons/sourcemod/extensions/curl.ext.so          the extension for 32-bit servers (curl.ext.dll on Windows)
addons/sourcemod/extensions/x64/curl.ext.so      the extension for 64-bit servers (curl.ext.dll on Windows)
addons/sourcemod/scripting/include/cURL.inc      the include files, needed only to compile plugins
addons/sourcemod/scripting/include/cURL_header.inc
addons/sourcemod/scripting/include/curl_buffer.inc
addons/sourcemod/scripting/include/curl_compression.inc
addons/sourcemod/scripting/include/curl_crypt.inc
addons/sourcemod/scripting/include/curl_modern.inc
addons/sourcemod/scripting/include/curl_websocket.inc
addons/sourcemod/licenses/sm-neocurl/            the licenses of the libraries inside the extension
```

The extension has no plugin, no commands and no configuration file of its own. SourceMod loads it when a plugin that
uses it is loaded. To check that it is installed, type `sm exts list` on the server console; while a plugin uses it,
the list has a line like this:

```
[10] NEO cURL Extension (2.1.0): NEO cURL Extension
```

## Configuration

There is one setting, and most servers do not need it: the largest size a [`CurlBuffer`](docs/buffer.md) may have. It
is 268435456 bytes (256 MB) by default. To change it, add a line to SourceMod's
`addons/sourcemod/configs/core.cfg`, inside the `"Core"` section, and restart the server:

```
"CurlBufferMaxBytes"	"67108864"
```

See [The size limit](docs/buffer.md#the-size-limit) for what the limit applies to.

## TLS certificates

For `https://` and `wss://` connections the extension checks the server's certificate against the certificate
authorities the operating system trusts:

- **Linux:** the file `/etc/ssl/certs/ca-certificates.crt` and the directory `/etc/ssl/certs`, where Debian and
  Ubuntu keep them (package `ca-certificates`).
- **Windows:** the extension asks libcurl to use the certificate store of Windows.

If connections fail with a certificate error on a Linux server, the `ca-certificates` package is usually missing or
outdated. A plugin can also name its own certificates: with `CURLOPT_CAINFO` or `CURLOPT_CAPATH` for a
[`CurlEasy`](docs/modern.md#options-that-name-a-file), and with `SetCaFile` for a
[`WebSocket`](docs/websocket.md#options).

## Writing a plugin

Copy the include files into the `include` directory of the SourcePawn compiler, and include the main one:

```sourcepawn
#include <cURL>
```

That one line makes everything available. A plugin that includes it needs the extension to run; SourceMod loads the
extension together with the plugin and refuses to load the plugin when the extension is not installed.

A first plugin can ask the extension what it is, which also proves that everything is in place. From
[`curl_basics.sp`](pawn/scripting/examples/curl_basics.sp):

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

And this is a complete HTTP request, a message posted to a Discord channel, from
[`curl_discord_webhook.sp`](pawn/scripting/examples/curl_discord_webhook.sp):

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

[HTTP and other transfers](docs/modern.md) explains every line of it.

## Example plugins

[`pawn/scripting/examples/`](pawn/scripting/examples/) has complete plugins that compile as they are. They are the
source of the longer code in the guides, and each was run on a test server.

| Plugin | What it does |
|---|---|
| [`curl_discord_webhook.sp`](pawn/scripting/examples/curl_discord_webhook.sp) | Posts map changes and messages to a Discord channel through a webhook. |
| [`curl_map_download.sp`](pawn/scripting/examples/curl_map_download.sp) | Downloads a map from a fast download server into `maps/`. |
| [`curl_demo_upload.sp`](pawn/scripting/examples/curl_demo_upload.sp) | Uploads a SourceTV demo to demos.tf. |
| [`curl_etf2l_player.sp`](pawn/scripting/examples/curl_etf2l_player.sp) | Looks up a player in the ETF2L API. |
| [`curl_basics.sp`](pawn/scripting/examples/curl_basics.sp) | The smaller features: a blocking request, header files, PUT uploads, information about libcurl. |
| [`curl_tcp_client.sp`](pawn/scripting/examples/curl_tcp_client.sp) | Sends a line to a TCP or UDP service and prints the answer. |
| [`websocket_relay.sp`](pawn/scripting/examples/websocket_relay.sp) | Relays chat between the game and a backend over a WebSocket that reconnects by itself. |
| [`websocket_frames.sp`](pawn/scripting/examples/websocket_frames.sp) | Receives a large binary WebSocket message piece by piece. |
| [`compression_demos.sp`](pawn/scripting/examples/compression_demos.sp) | Compresses SourceTV demos with zstd in the background and unpacks them again. |
| [`crypt_signed_webhook.sp`](pawn/scripting/examples/crypt_signed_webhook.sp) | Sends requests signed with HMAC-SHA256 to a backend. |
| [`crypt_verify_file.sp`](pawn/scripting/examples/crypt_verify_file.sp) | Checks a file against a published SHA-256; digests of texts, files and buffers. |
| [`buffer_basics.sp`](pawn/scripting/examples/buffer_basics.sp) | Every method of `CurlBuffer`. |
| [`buffer_whitelist.sp`](pawn/scripting/examples/buffer_whitelist.sp) | Downloads an item whitelist into a `CurlBuffer` and reads it line by line. |

The examples are not part of the release archive.

## Building

Most people do not need this: the releases have ready-made binaries. To build the extension yourself you need

- [AMBuild](https://github.com/alliedmodders/ambuild) 2.2 or newer,
- source checkouts of SourceMod (with its submodules) and Metamod:Source, both of the branch `1.12-dev`,
- a C++17 compiler: clang or GCC 9 or newer on Linux, Visual Studio 2022 on Windows.

The libraries (curl, OpenSSL, nghttp2, libssh2, brotli, zstd, zlib, libpsl and what they need) are built from source
by `build-deps.sh` with [vcpkg](https://vcpkg.io), at the versions fixed by the `builtin-baseline` in `vcpkg.json`.
They are built as static libraries into `deps/`.

On Ubuntu 22.04:

```
sudo apt install clang gcc-multilib g++-multilib autoconf autoconf-archive automake libtool libltdl-dev \
  cmake ninja-build pkg-config git curl zip unzip perl python3 python3-pip
pip3 install git+https://github.com/alliedmodders/ambuild

git clone --recurse-submodules --branch 1.12-dev https://github.com/alliedmodders/sourcemod
git clone --branch 1.12-dev https://github.com/alliedmodders/metamod-source
git clone https://github.com/sapphonie/SM-neocurl-ext
cd SM-neocurl-ext

./build-deps.sh
mkdir build && cd build
CC=clang CXX=clang++ python3 ../configure.py --enable-optimize --targets=x86,x86_64 \
  --sm-path=../../sourcemod --mms-path=../../metamod-source
ambuild
```

On Windows, run the same commands in Git Bash with Visual Studio 2022 installed, without `sudo apt install` and
without `CC=clang CXX=clang++`.

The result is in `build/package/`: the `addons/` tree of the release archive, ready to be copied into a game
directory.

Details:

- `build-deps.sh` builds the libraries for both architectures of the current operating system. It takes the names
  of vcpkg triplets as arguments to build only some: `x86-linux`, `x64-linux`, `x86-windows-static`,
  `x64-windows-static`. Their definitions are in `triplets/`.
- With the environment variable `VCPKG_ROOT` set, `build-deps.sh` uses that vcpkg as it is. Without it, the script
  clones vcpkg into `vcpkg/` and checks out the baseline of `vcpkg.json`.
- `configure.py` options: `--targets` (`x86`, `x86_64` or both, separated by a comma; without it only `x86` is
  built), `--sm-path` and `--mms-path` (the two checkouts), `--deps-path` (a `deps/` directory somewhere else),
  `--enable-optimize` and `--enable-debug`. Build with `--enable-optimize` for anything that runs on a game
  server: a build without it contains debug checks that stop the server where the optimized build reports an error
  to the plugin.
- The first build of the libraries takes a long time, since OpenSSL and curl are compiled twice. Later builds of the
  extension itself take seconds.

## Testing

There are four kinds of tests. CI runs all of them.

**Unit tests** cover the code that does not need a game server: the compression formats, digests, encodings, path
rules and the job queue. They are built with the extension, as
`build/extension/tests/curl-tests/<platform>-<architecture>/curl-tests`. Run the program; it prints
`All tests passed` and exits with 0, or lists the failed checks and exits with 1.

**The API test plugin**, [`pawn/scripting/curl_ext_test.sp`](pawn/scripting/curl_ext_test.sp), calls the plugin API
on a running server. Compile it, load it and type `sm_curl_ext_test` on the server console. It prints a line per
check and a summary:

```
[curl_ext_test] DONE 75 passed, 0 failed
```

Two groups of checks need a service to talk to and are skipped until its URL is set. The URLs must be in quotes,
because `//` starts a comment on the server console:

| Console variable | What it needs |
|---|---|
| `curl_ext_test_http_url` | A URL that answers a GET request with status 200. |
| `curl_ext_test_ws_url` | A WebSocket server that sends every message back (an echo server). |

**The server tests** in [`test/integration/`](test/integration/) run all of this on a real game server. They start a
TF2 server with SourceMod in a Docker container, put the built extension into it, compile and load the API test
plugin, every example plugin and a plugin that closes handles at awkward moments, and check what the server prints
and what local stand-ins for the web services receive. They need Docker and Python 3.12 or newer:

```
pip install --require-hashes -r test/integration/requirements.txt
pytest test/integration
```

The first run downloads the server image, about 5 GB. A run takes a few minutes, most of it the server's start.
Useful options:

| Option | Meaning |
|---|---|
| `--package <dir>` | The directory with the `addons/` tree to test. The default is `build/package`. |
| `--image <image>` | The server image. The default is `ghcr.io/melkortf/tf2-sourcemod/i386:latest`, a 32-bit server. |
| `--server-log <file>` | Writes the server's console output to a file at the end. |
| `--keep-server` | Leaves the server container `sm-neocurl-integration` running, to look around after a failure. |

The tests use the host's network and the game port 27015, so no other game server can run on the machine at the same
time. Only the 32-bit binary is tested this way: there is no public 64-bit server image with SourceMod.

**The guide check**, `python3 test/docs/check_excerpts.py`, makes sure that the code blocks in this README and in
`docs/` are still excerpts of the example plugins, which the server tests have run. A block that is not meant to be
one, such as the signature of a method, has the line `<!-- not-an-excerpt -->` before it.

`pawn/scripting/curl_self_test.sp` is the test plugin of the original cURL extension. It is kept for reference and
is not maintained.

## Source layout

| Path | Content |
|---|---|
| `extension/` | The extension. `natives.cpp`, `curlmanager.cpp` and `curlthread.cpp` are libcurl's easy interface; `opensslmanager.cpp` and `opensslthread.cpp` the deprecated hash natives; `api.cpp` and the `*_natives.cpp` files are `CurlBuffer`, `WebSocket`, `Compression` and `Crypt`. |
| `extension/core/` | The parts of those four that know nothing about SourceMod: the compression formats, digests, encodings, path rules, the job queue and the WebSocket connection thread. |
| `extension/tests/` | The unit tests of `extension/core/`. |
| `extension/sdk/` | SourceMod's extension SDK files. `smsdk_config.h` has the extension's name and version. |
| `pawn/scripting/include/` | The include files for plugins. |
| `pawn/scripting/examples/` | The example plugins. |
| `pawn/scripting/` | The two test plugins. |
| `test/integration/` | The server tests: the pytest files, the stand-in services and the server control. |
| `test/docs/` | The check of the guides against the example plugins. |
| `docs/` | The guides. |
| `AMBuildScript`, `AMBuilder`, `PackageScript`, `configure.py` | The build. `PackageScript` decides what goes into the release archive. |
| `build-deps.sh`, `vcpkg.json`, `triplets/` | The build of the libraries. |
| `.github/workflows/ci.yml` | The automatic build, tests and releases. |

## Releases

Every push and pull request is built for Linux and Windows by GitHub Actions (`.github/workflows/ci.yml`). The
workflow runs the unit tests for both architectures, checks that the Linux binaries need no newer glibc than 2.34,
offers the two archives as build artifacts, and then runs the server tests with the 32-bit binary of the Linux
archive and the guide check. It also runs once a week, because the server tests use the newest server image and a
game update can break them.

To publish a release:

1. Set the new version in `extension/sdk/smsdk_config.h` (`SMEXT_CONF_VERSION`) and in `vcpkg.json` (`version`).
2. Commit, and push a tag that is the letter `v` followed by exactly that version, for example `v2.1.0`.

The workflow then creates a GitHub release with both archives, provided the server tests passed. A tag that does
not match `SMEXT_CONF_VERSION` is built but not released.
