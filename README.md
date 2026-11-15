# SM-neocurl

A SourceMod extension that gives plugins libcurl (`cURL.inc`), a WebSocket client, compression and decompression
(gzip, zlib, deflate, brotli, zstd) and digests and HMACs. It is built for Linux and Windows, x86 and x86_64, with every
library linked in statically.

## Installing

Download the archive for your platform from the
[releases](https://github.com/sapphonie/SM-neocurl-ext/releases) and extract it into the game folder (e.g. `tf/`):

```
addons/sourcemod/extensions/curl.ext.so|dll        32-bit servers
addons/sourcemod/extensions/x64/curl.ext.so|dll    64-bit servers
addons/sourcemod/scripting/include/cURL.inc        for compiling plugins
addons/sourcemod/scripting/include/cURL_header.inc
addons/sourcemod/scripting/include/curl_buffer.inc
addons/sourcemod/scripting/include/curl_compression.inc
addons/sourcemod/scripting/include/curl_crypt.inc
addons/sourcemod/scripting/include/curl_modern.inc
addons/sourcemod/scripting/include/curl_websocket.inc
addons/sourcemod/licenses/sm-neocurl/              licenses of the linked libraries
```

The Linux binaries need glibc 2.34 or newer (Debian 12, Ubuntu 22.04).

## Features

curl with OpenSSL, HTTP/2 (nghttp2), WebSockets, SFTP and SCP (libssh2), brotli, zstd and gzip (zlib) content
encoding, and the public suffix list for cookies (libpsl). There is no HTTP/3, SASL or LDAP support.

On Linux curl uses Debian's CA bundle `/etc/ssl/certs/ca-certificates.crt` and `/etc/ssl/certs`, with OpenSSL's
default store as fallback. On Windows it uses the Windows certificate store. Plugins can set their own with
`CURLOPT_CAINFO` and `CURLOPT_CAPATH`.

## Plugin API

`#include <cURL>` gives plugins all of it. Besides libcurl's easy interface (`curl_easy_*` natives), it has:

- [CurlEasy, CurlSlist, CurlForm, CurlFile](docs/modern.md) (`curl_modern.inc`): methodmaps over the libcurl
  natives, with shortcuts for the common options and results and the text of a failed transfer for logs.
- [CurlBuffer](docs/buffer.md) (`curl_buffer.inc`): a byte buffer in the extension, for data larger than a plugin's
  own memory. Its size limit is `CurlBufferMaxBytes` in SourceMod's `core.cfg` (default 256 MB).
- [WebSocket](docs/websocket.md) (`curl_websocket.inc`): `ws://` and `wss://` connections, one thread each, with
  whole messages or raw frames, keepalive, reconnecting with backoff and backpressure.
- [Compression](docs/compression.md) (`curl_compression.inc`): gzip, zlib, raw deflate, brotli and zstd, of files and
  data, on two background threads.
- [Crypt](docs/crypt.md) (`curl_crypt.inc`): MD5, SHA-1, SHA-2, SHA-3, BLAKE2, SM3, Keccak-256, CRC-32 and Adler-32
  digests and HMACs, as hex, base64 or raw bytes; strings at once, buffers and files on two background threads. It
  replaces the deprecated `curl_hash_file` and `curl_hash_string`.

Every API has snake_case natives (`websocket_connect`, `compression_compress_file`, ...) and a methodmap that wraps
them (`WebSocket`, `Compression`, `Crypt`, `CurlBuffer`).

```sourcepawn
#include <cURL>

public void OnPluginStart()
{
	char digest[65];
	Crypt.HashString(Openssl_Hash_SHA3_256, "hello", -1, digest, sizeof(digest));
	PrintToServer("sha3-256: %s", digest);

	Compression.CompressFile(CompressFormat_Zstd, "demos/match.dem", "demos/match.dem.zst", OnCompressed);
}

public void OnCompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	if (error == CompressError_None)
		DeleteFile(inFile);
}
```

## Building

The build uses [AMBuild](https://github.com/alliedmodders/ambuild) and needs source checkouts of SourceMod and
Metamod:Source (1.12-dev). The dependencies (curl, OpenSSL, nghttp2, libssh2, brotli, zstd, libpsl, zlib) are built
by `build-deps.sh` with [vcpkg](https://vcpkg.io), at the versions of the `builtin-baseline` in `vcpkg.json`, into
`deps/`. Without `VCPKG_ROOT` the script clones vcpkg into `vcpkg/` and checks it out at that baseline.

On Linux (Ubuntu 22.04 packages; `cmake`, `ninja-build`, `pkg-config`, `git`, `curl`, `zip`, `unzip` and `perl` are
needed too):

```
sudo apt install clang gcc-multilib g++-multilib autoconf autoconf-archive automake libtool libltdl-dev
pip install git+https://github.com/alliedmodders/ambuild

./build-deps.sh
mkdir build && cd build
CC=clang CXX=clang++ python ../configure.py --enable-optimize --targets=x86,x86_64 \
  --sm-path=/path/to/sourcemod --mms-path=/path/to/metamod-source
ambuild
```

On Windows run the same commands in Git Bash with Visual Studio 2022 installed, without `CC` and `CXX`.

`build-deps.sh` takes vcpkg triplets to build only some of them (`x86-linux`, `x64-linux`, `x86-windows-static`,
`x64-windows-static`; their overlays are in `triplets/`). `configure.py --deps-path` points to a `deps/` elsewhere.

The extension and the files of the archive end up in `build/package/`. The unit tests of `extension/core/` (codecs,
digests, encodings, paths, the worker pool) are built as `build/extension/tests/curl-tests/<platform>-<arch>/curl-tests`;
CI runs them for both architectures.

`pawn/scripting/curl_ext_test.sp` tests the plugin API on a running server: `sm_curl_ext_test` prints a line per check;
the WebSocket checks need an echo server at the URL in `curl_ext_test_ws_url`, the HTTP transfer of the methodmaps a
URL that answers a GET with status 200 in `curl_ext_test_http_url` (both in quotes on the console, since `//` starts a
comment there).

## Source layout

- `extension/`: the extension. `natives.cpp`, `curlmanager.cpp`, `curlthread.cpp` and `opensslmanager.cpp` are the
  libcurl natives and the deprecated hash natives; `api.cpp` and the `*_natives.cpp` files are the CurlBuffer,
  WebSocket, Compression and Crypt APIs.
- `extension/core/`: the code of those APIs that does not know SourceMod: codecs, digests, encodings, path rules, the
  worker pool and the WebSocket session thread.
- `extension/tests/`: the unit tests of `extension/core/`.
- `pawn/scripting/`: the include files and the test plugins.
- `docs/`: the plugin API of the libcurl methodmaps, CurlBuffer, WebSocket, Compression and Crypt.

## Releases

CI (`.github/workflows/ci.yml`) builds both platforms on every push and pull request. A pushed tag `vX.Y.Z` that
matches `SMEXT_CONF_VERSION` in `extension/sdk/smsdk_config.h` publishes the archives as a release.
