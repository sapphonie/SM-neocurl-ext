# Crypt

`Crypt` computes digests (hashes) and HMACs: the fingerprints by which a file is checked against a published
checksum, and the signatures by which a receiver recognises that a message comes from someone who knows a shared
secret. It covers MD5, SHA-1, the SHA-2 and SHA-3 families, BLAKE2, SM3 and Keccak-256 with OpenSSL, and the CRC-32
and Adler-32 checksums with zlib.

It is part of `curl_crypt.inc`, which `#include <cURL>` includes.

Contents:

- [A first example](#a-first-example)
- [Two ways to work](#two-ways-to-work)
- [Algorithms](#algorithms)
- [Encodings](#encodings)
- [Texts and small data: at once](#texts-and-small-data-at-once)
- [Files and buffers: in the background](#files-and-buffers-in-the-background)
- [HMAC](#hmac)
- [Complete example: a signed request](#complete-example-a-signed-request)
- [Complete example: check a file](#complete-example-check-a-file)
- [The older natives](#the-older-natives)
- [Reference](#reference)
- [Common mistakes](#common-mistakes)

## A first example

The SHA-256 of a text, as the usual 64 hex characters. From
[`crypt_verify_file.sp`](../pawn/scripting/examples/crypt_verify_file.sp), where `text` is what the command was given
and `digest` an array of 129 bytes:

```sourcepawn
Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest));
PrintToServer("SHA-256:        %s", digest);
```

For the text `abc` this prints:

```
SHA-256:        ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

`Crypt` is not an object: there is nothing to create or delete. Its methods are called on the name itself.

## Two ways to work

| | At once | In the background |
|---|---|---|
| Methods | `HashString`, `HmacString` | `HashBuffer`, `HmacBuffer`, `HashFile`, `HmacFile` |
| Input | a string or array in the plugin's memory | a [`CurlBuffer`](buffer.md) or a file |
| Result | written into an array before the method returns | passed to a callback in a later game frame |
| For | short data: texts, request bodies, keys | data of any size |

Hashing a few hundred bytes takes microseconds, so the string methods simply do it. A file of 100 MB takes long
enough to make the server stutter, so files and buffers are hashed by threads of the extension.

## Algorithms

The algorithm is a value of the enum `Openssl_Hash`:

| `Openssl_Hash` | Algorithm | Digest size | Hex characters |
|---|---|---|---|
| `Openssl_Hash_MD5` | MD5 | 16 bytes | 32 |
| `Openssl_Hash_SHA1` | SHA-1 | 20 bytes | 40 |
| `Openssl_Hash_SHA224` | SHA-224 | 28 bytes | 56 |
| `Openssl_Hash_SHA256` | SHA-256 | 32 bytes | 64 |
| `Openssl_Hash_SHA384` | SHA-384 | 48 bytes | 96 |
| `Openssl_Hash_SHA512` | SHA-512 | 64 bytes | 128 |
| `Openssl_Hash_SHA512_224` | SHA-512/224 | 28 bytes | 56 |
| `Openssl_Hash_SHA512_256` | SHA-512/256 | 32 bytes | 64 |
| `Openssl_Hash_SHA3_224` | SHA3-224 | 28 bytes | 56 |
| `Openssl_Hash_SHA3_256` | SHA3-256 | 32 bytes | 64 |
| `Openssl_Hash_SHA3_384` | SHA3-384 | 48 bytes | 96 |
| `Openssl_Hash_SHA3_512` | SHA3-512 | 64 bytes | 128 |
| `Openssl_Hash_BLAKE2B512` | BLAKE2b-512 | 64 bytes | 128 |
| `Openssl_Hash_BLAKE2S256` | BLAKE2s-256 | 32 bytes | 64 |
| `Openssl_Hash_SM3` | SM3 | 32 bytes | 64 |
| `Openssl_Hash_KECCAK256` | Keccak-256, the variant Ethereum uses. It is not the same as SHA3-256. | 32 bytes | 64 |
| `Openssl_Hash_CRC32` | CRC-32, as zlib and zip compute it | 4 bytes | 8 |
| `Openssl_Hash_ADLER32` | Adler-32, as zlib computes it | 4 bytes | 8 |

Which one to pick: **SHA-256** unless something else is asked for. MD5 and SHA-1 are broken as protection against
deliberate forgery and should only be used where an existing system demands them. CRC-32 and Adler-32 are checksums
against accidental damage, not against forgery; they cannot be used for an HMAC.

The two checksums are written with their most significant byte first, as tools print them: the CRC-32 of
`123456789` is `cbf43926`.

The enum has four more values, `Openssl_Hash_MD4`, `Openssl_Hash_MD2`, `Openssl_Hash_SHA` and
`Openssl_Hash_RIPEMD160`. They exist so that the numbers of the other values stay what they always were, and are not
supported: the methods of `Crypt` throw an error for them.

## Encodings

A digest is a row of bytes. The encoding, a value of the enum `HashEncoding`, decides how it is written:

| `HashEncoding` | Output | SHA-256 of `abc` |
|---|---|---|
| `HashEncoding_Hex` (the default) | two lowercase hex digits per byte | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `HashEncoding_Base64` | base64, which writes three bytes as four letters, digits, `+` or `/`, filled up with `=` | `ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=` |
| `HashEncoding_Base64Url` | base64 with `-` and `_` instead of `+` and `/` and without the `=`, so that it can be used in URLs; JSON Web Tokens use it | `ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0` |
| `HashEncoding_Raw` | the bytes themselves | 32 bytes, the first is `0xba` |

## Texts and small data: at once

```sourcepawn
int Crypt.HashString(Openssl_Hash algorithm, const char[] input, int length, char[] output, int maxlength,
                     HashEncoding encoding = HashEncoding_Hex)
```

- `input` and `length`: the data and its number of bytes. A `length` of -1 means "up to the NUL", which is right for
  text. For binary data pass the real length.
- `output` and `maxlength`: the array for the result and its size.
- The return value is the length of what was written.

With a text encoding (hex, base64) the result is a string with a NUL at its end, and the returned length does not
count the NUL. With `HashEncoding_Raw` the bytes are written without a NUL.

**The array must be large enough**, or the method throws an error and writes nothing:

| Encoding | Size `output` needs |
|---|---|
| `HashEncoding_Hex` | twice the digest size, plus 1. 129 bytes are enough for every algorithm. |
| `HashEncoding_Base64` | 4 bytes for every 3 bytes of the digest, rounded up, plus 1. 89 bytes are enough for every algorithm. |
| `HashEncoding_Base64Url` | not more than `HashEncoding_Base64` needs. |
| `HashEncoding_Raw` | the digest size. 64 bytes are enough for every algorithm. |

From [`crypt_verify_file.sp`](../pawn/scripting/examples/crypt_verify_file.sp), one text with several algorithms and
encodings:

```sourcepawn
// 129 bytes hold the hex text of every digest, also of the 64 byte
// ones like SHA-512.
char digest[129];

Crypt.HashString(Openssl_Hash_MD5, text, -1, digest, sizeof(digest));
PrintToServer("MD5:            %s", digest);
Crypt.HashString(Openssl_Hash_SHA1, text, -1, digest, sizeof(digest));
PrintToServer("SHA-1:          %s", digest);
Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest));
PrintToServer("SHA-256:        %s", digest);
Crypt.HashString(Openssl_Hash_SHA3_256, text, -1, digest, sizeof(digest));
PrintToServer("SHA3-256:       %s", digest);
Crypt.HashString(Openssl_Hash_CRC32, text, -1, digest, sizeof(digest));
PrintToServer("CRC-32:         %s", digest);

// The same SHA-256 in the other encodings.
Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest), HashEncoding_Base64);
PrintToServer("SHA-256 base64: %s", digest);
Crypt.HashString(Openssl_Hash_SHA256, text, -1, digest, sizeof(digest), HashEncoding_Base64Url);
PrintToServer("SHA-256 b64url: %s", digest);

// Raw: the 32 bytes themselves, no NUL. The return value is their number.
char raw[32];
int length = Crypt.HashString(Openssl_Hash_SHA256, text, -1, raw, sizeof(raw), HashEncoding_Raw);
PrintToServer("SHA-256 raw:    %d bytes, the first is 0x%02x", length, raw[0] & 0xFF);
```

`sm_hash_text abc` prints:

```
MD5:            900150983cd24fb0d6963f7d28e17f72
SHA-1:          a9993e364706816aba3e25717850c26c9cd0d89d
SHA-256:        ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
SHA3-256:       3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
CRC-32:         352441c2
SHA-256 base64: ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=
SHA-256 b64url: ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0
SHA-256 raw:    32 bytes, the first is 0xba
```

## Files and buffers: in the background

```sourcepawn
void Crypt.HashFile(Openssl_Hash algorithm, const char[] file, CryptCallback callback, any data = 0,
                    HashEncoding encoding = HashEncoding_Hex)
void Crypt.HashBuffer(Openssl_Hash algorithm, CurlBuffer buffer, CryptCallback callback, any data = 0,
                      HashEncoding encoding = HashEncoding_Hex)
```

Both start a job and return immediately. Two threads of the extension work through the jobs of all plugins, and
each job's callback is called on the main thread in a later game frame:

```sourcepawn
public void OnDigest(CryptError error, CurlBuffer digest, any data)
```

- `error` is `CryptError_None` when the job worked.
- `digest` is a [`CurlBuffer`](buffer.md) with the digest in the encoding that was asked for. For hex and base64
  that is the text **without a NUL**; `digest.GetString` copies it into an array and adds the NUL. `digest` is `null`
  when the job failed, and it exists only while the callback runs.
- `data` is the value passed when the job was started. It may be declared with its real type.

About the input:

- **Files.** The path is relative to the game directory and cannot leave it. The rules are those of
  [Compression's paths](compression.md#paths). The file is read in pieces, so its size does not matter.
- **Buffers.** The bytes are copied when the job is started. The plugin may change or delete the buffer right after
  the call.

Because two jobs run at the same time, callbacks may arrive in a different order than the jobs were started. If the
plugin is unloaded before a job is finished, its callback is not called.

```sourcepawn
public Action Command_HashBuffer(int client, int args)
{
	char text[256];
	GetCmdArgString(text, sizeof(text));

	CurlBuffer buffer = new CurlBuffer();
	buffer.AppendString(text);

	Crypt.HashBuffer(Openssl_Hash_SHA512, buffer, OnDigest);
	Crypt.HmacBuffer(Openssl_Hash_SHA256, "secret key", -1, buffer, OnDigest);

	// Both jobs copied the buffer's bytes when they were queued.
	delete buffer;
	return Plugin_Handled;
}
```

```sourcepawn
public void OnDigest(CryptError error, CurlBuffer digest, any data)
{
	if (error != CryptError_None) {
		char reason[32];
		Crypt.ErrorString(error, reason, sizeof(reason));
		PrintToServer("No digest: %s", reason);
		return;
	}

	char text[129];
	digest.GetString(0, text, sizeof(text));
	PrintToServer("Digest: %s", text);
}
```

The second job computes an [HMAC](#hmac), a digest with a key, which is explained below. `sm_hash_buffer abc` prints
the HMAC-SHA256 and the SHA-512, in the order in which the two jobs finish:

```
Digest: 549b5df5db986338ab0e122cdba905d12b50aa3a274403c795b6a6c48b7bcb35
Digest: ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
```

### Errors of a job

| `CryptError` | Meaning |
|---|---|
| `CryptError_None` | The job worked. |
| `CryptError_OpenInput` | The file cannot be opened. Usually it does not exist. |
| `CryptError_Read` | Reading the file failed. |
| `CryptError_Memory` | Out of memory, or OpenSSL could not compute the digest. |

`Crypt.ErrorString(error, buffer, maxlength)` writes the name of a value, for example `CryptError_OpenInput`, and
returns its length. A buffer of 32 bytes holds every name.

## HMAC

An HMAC is a digest that also depends on a secret key. Only someone who knows the key can compute it, so it proves
where a message comes from and that it was not changed. Every method has an HMAC variant with two more arguments,
the key and its length:

```sourcepawn
int Crypt.HmacString(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] input, int length,
                     char[] output, int maxlength, HashEncoding encoding = HashEncoding_Hex)
void Crypt.HmacFile(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] file,
                    CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex)
void Crypt.HmacBuffer(Openssl_Hash algorithm, const char[] key, int keyLength, CurlBuffer buffer,
                      CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex)
```

`keyLength` is the number of bytes of the key, or -1 for a text key up to its NUL. Everything else is as for the
digests: the same sizes, encodings, callback and errors. An HMAC has the size of its algorithm's digest. All
algorithms can be used except the two checksums, CRC-32 and Adler-32.

```sourcepawn
public Action Command_HmacFile(int client, int args)
{
	if (args != 2) {
		ReplyToCommand(client, "Usage: sm_hmac_file <key> <file>");
		return Plugin_Handled;
	}

	char key[128];
	GetCmdArg(1, key, sizeof(key));
	char file[PLATFORM_MAX_PATH];
	GetCmdArg(2, file, sizeof(file));

	Crypt.HmacFile(Openssl_Hash_SHA256, key, -1, file, OnDigest, 0, HashEncoding_Base64);
	return Plugin_Handled;
}
```

## Complete example: a signed request

[`crypt_signed_webhook.sp`](../pawn/scripting/examples/crypt_signed_webhook.sp) posts events to a backend of your
own and signs each request, so the backend can reject requests that someone else sends to its address. It uses the
header format that GitHub made common for webhooks:

```
X-Hub-Signature-256: sha256=<HMAC-SHA256 of the request body, as lowercase hex>
```

The plugin and the backend share a secret. The plugin computes the HMAC of the body with it and sends the result in
the header; the backend computes the same and compares.

```sourcepawn
char body[256];
Format(body, sizeof(body), "{\"event\":\"%s\",\"time\":%d}", event, GetTime());

// HMAC-SHA256 has 32 bytes: 64 hex characters and the NUL. The -1
// lengths mean "up to the NUL" for the key and for the input.
char signature[65];
Crypt.HmacString(Openssl_Hash_SHA256, secret, -1, body, -1, signature, sizeof(signature));

char signatureHeader[128];
Format(signatureHeader, sizeof(signatureHeader), "X-Hub-Signature-256: sha256=%s", signature);

CurlSlist headers = new CurlSlist();
headers.Append("Content-Type: application/json");
headers.Append(signatureHeader);

CurlEasy easy = new CurlEasy();
easy.SetUrl(url);
easy.SetHeaders(headers);
easy.SetPostFields(body);
easy.SetTimeout(10);
easy.PerformThread(OnEventPosted, headers);
```

A backend that knows the same secret accepts the request (`Signed event: accepted` in the log). With a different
secret on one side, the signatures differ and the backend answers 401. How the request itself is made is explained
in [HTTP and other transfers](modern.md).

## Complete example: check a file

`sm_verify_file <file> <sha256>` of [`crypt_verify_file.sp`](../pawn/scripting/examples/crypt_verify_file.sp) checks
a file, a downloaded map for instance, against the SHA-256 its author published:

```sourcepawn
// The callback needs the expected digest and the file's name.
DataPack pack = new DataPack();
pack.WriteString(file);
pack.WriteString(expected);

// The file is read by a thread of the extension, so a large map does
// not freeze the server. The result arrives in the callback.
Crypt.HashFile(Openssl_Hash_SHA256, file, OnFileHashed, pack);
```

```sourcepawn
public void OnFileHashed(CryptError error, CurlBuffer digest, DataPack pack)
{
	char file[PLATFORM_MAX_PATH];
	char expected[65];
	pack.Reset();
	pack.ReadString(file, sizeof(file));
	pack.ReadString(expected, sizeof(expected));
	delete pack;

	if (error != CryptError_None) {
		char reason[32];
		Crypt.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot hash %s: %s", file, reason);
		return;
	}

	// The digest arrives as a CurlBuffer with the hex text, without a NUL.
	// GetString adds the NUL.
	char actual[65];
	digest.GetString(0, actual, sizeof(actual));

	// The digests are lowercase hex; published ones are often uppercase.
	if (StrEqual(actual, expected, false)) {
		PrintToServer("%s is intact.", file);
	} else {
		PrintToServer("%s differs: its SHA-256 is %s", file, actual);
	}
}
```

```
demo1.dem is intact.
```

## The older natives

`cURL.inc` still has the two natives that `Crypt` replaces, `curl_hash_string` and `curl_hash_file`. They are
deprecated: they keep working, also with the newer algorithms, and the compiler prints a warning where they are
used. New code should use `Crypt`:

| Deprecated | Use instead |
|---|---|
| `curl_hash_string(input, dataSize, algorithm, buffer, maxlength)` | `Crypt.HashString(algorithm, input, length, buffer, maxlength)` |
| `curl_hash_file(file, algorithm, callback, value)` | `Crypt.HashFile(algorithm, file, callback, data)` |

Mind the differences when changing a plugin over:

- The algorithm moves to the front.
- "Up to the NUL" is -1 instead of 0.
- `Crypt.HashString` returns the length of the digest and throws an error when the array is too small.
  `curl_hash_string` returns `true` and cuts the digest off.
- The callback of `Crypt.HashFile` receives a `CryptError` and a `CurlBuffer` instead of a success flag and a string.
- `Crypt.HashFile` only reads files inside the game directory. `curl_hash_file` also takes a path that leaves it.

## Reference

| Method | Native | Returns |
|---|---|---|
| `Crypt.HashString` | `crypt_hash_string` | `int`: the length of the result |
| `Crypt.HmacString` | `crypt_hmac_string` | `int`: the length of the result |
| `Crypt.HashBuffer` | `crypt_hash_buffer` | nothing |
| `Crypt.HmacBuffer` | `crypt_hmac_buffer` | nothing |
| `Crypt.HashFile` | `crypt_hash_file` | nothing |
| `Crypt.HmacFile` | `crypt_hmac_file` | nothing |
| `Crypt.ErrorString` | `crypt_error_string` | `int`: the length of the name |

The natives take the same arguments in the same order as the methods.

| Type | Definition |
|---|---|
| `CryptCallback` | `function void (CryptError error, CurlBuffer digest, any data)` |

Mistakes in a call throw an error, which is written to SourceMod's error log and stops the calling function:

- an algorithm that is not supported, or a checksum algorithm for an HMAC,
- an encoding that does not exist,
- a `length` or `keyLength` below -1,
- an `output` array that is too small, or a digest OpenSSL cannot compute (string methods),
- a path that is not allowed, an invalid `CurlBuffer` or an invalid callback (background methods).

## Common mistakes

- **An output array that is too small.** The string methods throw an error instead of cutting the digest off. Use 65
  bytes for a SHA-256 in hex, or 129 to be safe for every algorithm.
- **Forgetting that a callback's digest has no NUL.** Copy it out with `digest.GetString(0, text, sizeof(text))`,
  which adds one.
- **Comparing hex digests case-sensitively.** `Crypt` writes lowercase; published checksums are often uppercase.
  Compare with `StrEqual(a, b, false)`.
- **Passing -1 as the length of binary data.** -1 stops at the first NUL byte. Pass the real length.
- **Hashing a large file with the string methods.** Reading a file into the plugin and hashing it there blocks the
  server. `HashFile` reads the file itself, in the background.
- **Taking Keccak-256 for SHA3-256**, or the other way round. They give different results for the same input.
- **Using MD5, SHA-1 or a CRC to protect against tampering.** Use SHA-256 for digests and HMAC-SHA256 for
  signatures.
- **Keeping the digest buffer.** It is closed when the callback returns. Copy the text out, or `Clone()` the buffer.
