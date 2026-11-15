# Crypt

`Crypt` (`curl_crypt.inc`, included by `cURL.inc`) computes digests and HMACs with OpenSSL, and the CRC-32 and
Adler-32 checksums with zlib: of strings at once, of [CurlBuffers](buffer.md) and files in the background. It replaces
`curl_hash_file` and `curl_hash_string`, which are deprecated; they accept the new algorithms too.

## Algorithms

The algorithms are the values of `Openssl_Hash` in `cURL.inc`:

| `Openssl_Hash` | Digest | HMAC |
|---|---|---|
| `Openssl_Hash_MD5` | MD5, 16 bytes | yes |
| `Openssl_Hash_SHA1` | SHA-1, 20 bytes | yes |
| `Openssl_Hash_SHA224`, `_SHA256`, `_SHA384`, `_SHA512` | SHA-2 | yes |
| `Openssl_Hash_SHA512_224`, `_SHA512_256` | SHA-512/224, SHA-512/256 | yes |
| `Openssl_Hash_SHA3_224`, `_SHA3_256`, `_SHA3_384`, `_SHA3_512` | SHA-3 | yes |
| `Openssl_Hash_BLAKE2B512`, `_BLAKE2S256` | BLAKE2b-512, BLAKE2s-256 | yes |
| `Openssl_Hash_SM3` | SM3, 32 bytes | yes |
| `Openssl_Hash_KECCAK256` | Keccak-256 as Ethereum uses it (not SHA3-256), 32 bytes | yes |
| `Openssl_Hash_CRC32` | zlib's CRC-32, 4 bytes big-endian | no |
| `Openssl_Hash_ADLER32` | zlib's Adler-32, 4 bytes big-endian | no |

`Openssl_Hash_MD4`, `_MD2`, `_SHA` and `_RIPEMD160` keep their numbers for old plugins but are not supported; a
native throws an error for them, as for a checksum in an HMAC.

Checksums are written big-endian, as the usual tools print them: the CRC-32 of `123456789` is `cbf43926`.

## Encodings

| `HashEncoding` | Output |
|---|---|
| `HashEncoding_Hex` (default) | lowercase hex |
| `HashEncoding_Base64` | base64 with padding (RFC 4648 section 4) |
| `HashEncoding_Base64Url` | URL-safe base64 without padding (RFC 4648 section 5), as JWTs use it |
| `HashEncoding_Raw` | the digest's bytes |

## Strings, at once

```sourcepawn
int Crypt.HashString(Openssl_Hash algorithm, const char[] input, int length, char[] output, int maxlength,
                     HashEncoding encoding = HashEncoding_Hex);
int Crypt.HmacString(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] input, int length,
                     char[] output, int maxlength, HashEncoding encoding = HashEncoding_Hex);
```

`length` and `keyLength` are byte counts, or -1 for up to the NUL, so binary input and keys work. The digest is written
into `output` as text with a NUL, or as raw bytes without one; the return value is its length. An `output` too small
for it is a native error. 129 bytes hold every hex digest.

## Buffers and files, in the background

```sourcepawn
Crypt.HashBuffer(Openssl_Hash algorithm, CurlBuffer buffer, CryptCallback callback, any data = 0,
                 HashEncoding encoding = HashEncoding_Hex);
Crypt.HmacBuffer(Openssl_Hash algorithm, const char[] key, int keyLength, CurlBuffer buffer,
                 CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex);
Crypt.HashFile(Openssl_Hash algorithm, const char[] file, CryptCallback callback, any data = 0,
               HashEncoding encoding = HashEncoding_Hex);
Crypt.HmacFile(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] file,
               CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex);

typedef CryptCallback = function void (CryptError error, CurlBuffer digest, any data);
```

- A buffer's bytes are copied at once; the buffer may change or be closed right after.
- File paths are relative to the game directory and must not leave it, with the rules of
  [Compression's files](compression.md#files).
- Two threads of the extension, separate from the compression threads, run the jobs; each callback runs on a later
  server frame. The callback of a plugin that unloaded is not called.
- `digest` holds the digest in the requested encoding (text without a NUL) and lives as long as the callback, or is
  null on error.

| `CryptError` | Meaning |
|---|---|
| `CryptError_None` | Success. |
| `CryptError_OpenInput` | The file cannot be opened. |
| `CryptError_Read` | Reading the file failed. |
| `CryptError_Memory` | Out of memory, or OpenSSL failed. |

`Crypt.ErrorString(error, buffer, maxlength)` writes the name, e.g. `CryptError_Read`.

## Examples

Sign a webhook body with HMAC-SHA256:

```sourcepawn
char signature[65];
Crypt.HmacString(Openssl_Hash_SHA256, g_Secret, -1, body, -1, signature, sizeof(signature));
```

Check a downloaded map against a known SHA-256:

```sourcepawn
Crypt.HashFile(Openssl_Hash_SHA256, "maps/cp_process_f12.bsp", OnMapHashed);

public void OnMapHashed(CryptError error, CurlBuffer digest, any data)
{
	char hex[65];
	if (error == CryptError_None) {
		digest.GetString(0, hex, sizeof(hex));
		PrintToServer("sha256 %s", hex);
	}
}
```
