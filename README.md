# SM-neocurl

A SourceMod extension that gives plugins libcurl (`cURL.inc`) and OpenSSL hashing (`curl_hash_file`,
`curl_hash_string`). It is built for Linux and Windows, x86 and x86_64, with every library linked in statically.

## Installing

Download the archive for your platform from the
[releases](https://github.com/sapphonie/SM-neocurl-ext/releases) and extract it into the game folder (e.g. `tf/`):

```
addons/sourcemod/extensions/curl.ext.so|dll        32-bit servers
addons/sourcemod/extensions/x64/curl.ext.so|dll    64-bit servers
addons/sourcemod/scripting/include/cURL.inc        for compiling plugins
addons/sourcemod/scripting/include/cURL_header.inc
addons/sourcemod/licenses/sm-neocurl/              licenses of the linked libraries
```

The Linux binaries need glibc 2.34 or newer (Debian 12, Ubuntu 22.04).

## Features

curl with OpenSSL, HTTP/2 (nghttp2), WebSockets, SFTP and SCP (libssh2), brotli, zstd and gzip (zlib) content
encoding, and the public suffix list for cookies (libpsl). There is no HTTP/3, SASL or LDAP support.

On Linux curl uses Debian's CA bundle `/etc/ssl/certs/ca-certificates.crt` and `/etc/ssl/certs`, with OpenSSL's
default store as fallback. On Windows it uses the Windows certificate store. Plugins can set their own with
`CURLOPT_CAINFO` and `CURLOPT_CAPATH`.

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

The extension and the files of the archive end up in `build/package/`.

## Releases

CI (`.github/workflows/ci.yml`) builds both platforms on every push and pull request. A pushed tag `vX.Y.Z` that
matches `SMEXT_CONF_VERSION` in `extension/sdk/smsdk_config.h` publishes the archives as a release.
