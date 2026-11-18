#if defined _curl_crypt_included
  #endinput
#endif
#define _curl_crypt_included

#include <cURL>

/**
 * Crypt: digests and HMACs with OpenSSL, and the CRC-32 and Adler-32
 * checksums, of strings at once and of CurlBuffers and files in the
 * background. Two threads of the extension run the background jobs; each
 * job's callback runs on a later server frame.
 *
 * The algorithms are those of Openssl_Hash (cURL.inc). Openssl_Hash_MD4,
 * _MD2, _SHA and _RIPEMD160 are not supported; Openssl_Hash_CRC32 and
 * _ADLER32 cannot be used for an HMAC. Checksums are written big-endian,
 * as the usual tools print them (CRC-32 of "123456789" is "cbf43926").
 *
 * See docs/crypt.md.
 */

enum HashEncoding
{
	HashEncoding_Hex = 0,    /**< Lowercase hex. */
	HashEncoding_Base64,     /**< Base64 with padding (RFC 4648 section 4). */
	HashEncoding_Base64Url,  /**< URL-safe base64 without padding (RFC 4648 section 5). */
	HashEncoding_Raw,        /**< The digest's bytes. */
};

enum CryptError
{
	CryptError_None = 0,   /**< Success. */
	CryptError_OpenInput,  /**< The file cannot be opened. */
	CryptError_Read,       /**< Reading the file failed. */
	CryptError_Memory,     /**< Out of memory, or OpenSSL failed. */
};

/**
 * Called when a background digest ended.
 *
 * @param error         CryptError_None on success.
 * @param digest        The digest in the requested encoding (text without
 *                      a NUL), or null on error. It lives as long as the
 *                      callback; use digest.Clone() to keep it.
 * @param data          The data passed with the job.
 */
typedef CryptCallback = function void (CryptError error, CurlBuffer digest, any data);

/**
 * Computes the digest of a string at once.
 *
 * @param algorithm     The algorithm.
 * @param input         The bytes.
 * @param length        How many bytes of input, or -1 for up to its NUL.
 * @param output        Where the digest goes: text with a NUL, or the raw
 *                      bytes for HashEncoding_Raw.
 * @param maxlength     The size of output.
 * @param encoding      The encoding of the digest.
 * @return              The length of the digest written, without the NUL.
 * @error               Unsupported algorithm, invalid encoding or length,
 *                      or output too small.
 */
native int crypt_hash_string(Openssl_Hash algorithm, const char[] input, int length, char[] output, int maxlength,
                             HashEncoding encoding = HashEncoding_Hex);

/**
 * Computes the HMAC of a string at once.
 *
 * @param algorithm     The algorithm; not a checksum.
 * @param key           The key's bytes.
 * @param keyLength     How many bytes of key, or -1 for up to its NUL.
 * @param input         The bytes.
 * @param length        How many bytes of input, or -1 for up to its NUL.
 * @param output        As for crypt_hash_string.
 * @param maxlength     The size of output.
 * @param encoding      The encoding of the digest.
 * @return              The length of the digest written, without the NUL.
 * @error               As for crypt_hash_string.
 */
native int crypt_hmac_string(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] input, int length,
                             char[] output, int maxlength, HashEncoding encoding = HashEncoding_Hex);

/**
 * Computes the digest of a buffer's bytes in the background; they are
 * copied at once.
 *
 * @param algorithm     The algorithm.
 * @param buffer        The CurlBuffer.
 * @param callback      Called with the digest.
 * @param data          Passed to the callback.
 * @param encoding      The encoding of the digest.
 * @error               Unsupported algorithm, invalid buffer, encoding or
 *                      callback.
 */
native void crypt_hash_buffer(Openssl_Hash algorithm, Handle buffer, CryptCallback callback, any data = 0,
                              HashEncoding encoding = HashEncoding_Hex);

/**
 * Computes the HMAC of a buffer's bytes in the background.
 *
 * @param algorithm     The algorithm; not a checksum.
 * @param key           The key's bytes.
 * @param keyLength     How many bytes of key, or -1 for up to its NUL.
 * @param buffer        The CurlBuffer.
 * @param callback      Called with the digest.
 * @param data          Passed to the callback.
 * @param encoding      The encoding of the digest.
 * @error               As for crypt_hash_buffer.
 */
native void crypt_hmac_buffer(Openssl_Hash algorithm, const char[] key, int keyLength, Handle buffer,
                              CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex);

/**
 * Computes the digest of a file in the background. The path is relative to
 * the game directory and must not leave it: absolute paths, "file://", an
 * empty path and empty, "." or ".." parts are refused, on Windows also ":".
 *
 * @param algorithm     The algorithm.
 * @param file          The file.
 * @param callback      Called with the digest.
 * @param data          Passed to the callback.
 * @param encoding      The encoding of the digest.
 * @error               Unsupported algorithm, invalid path, encoding or
 *                      callback.
 */
native void crypt_hash_file(Openssl_Hash algorithm, const char[] file, CryptCallback callback, any data = 0,
                            HashEncoding encoding = HashEncoding_Hex);

/**
 * Computes the HMAC of a file in the background; the path as for
 * crypt_hash_file.
 *
 * @param algorithm     The algorithm; not a checksum.
 * @param key           The key's bytes.
 * @param keyLength     How many bytes of key, or -1 for up to its NUL.
 * @param file          The file.
 * @param callback      Called with the digest.
 * @param data          Passed to the callback.
 * @param encoding      The encoding of the digest.
 * @error               As for crypt_hash_file.
 */
native void crypt_hmac_file(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] file,
                            CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex);

/**
 * Writes the name of an error, e.g. "CryptError_Read".
 *
 * @param error         The error.
 * @param buffer        The string to write into.
 * @param maxlength     The size of buffer.
 * @return              The number of bytes written; 0 for a maxlength of 0.
 * @error               Invalid error.
 */
native int crypt_error_string(CryptError error, char[] buffer, int maxlength);

methodmap Crypt
{
	/** See crypt_hash_string. */
	public static int HashString(Openssl_Hash algorithm, const char[] input, int length, char[] output,
	                             int maxlength, HashEncoding encoding = HashEncoding_Hex)
	{
		return crypt_hash_string(algorithm, input, length, output, maxlength, encoding);
	}

	/** See crypt_hmac_string. */
	public static int HmacString(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] input,
	                             int length, char[] output, int maxlength, HashEncoding encoding = HashEncoding_Hex)
	{
		return crypt_hmac_string(algorithm, key, keyLength, input, length, output, maxlength, encoding);
	}

	/** See crypt_hash_buffer. */
	public static void HashBuffer(Openssl_Hash algorithm, CurlBuffer buffer, CryptCallback callback, any data = 0,
	                              HashEncoding encoding = HashEncoding_Hex)
	{
		crypt_hash_buffer(algorithm, buffer, callback, data, encoding);
	}

	/** See crypt_hmac_buffer. */
	public static void HmacBuffer(Openssl_Hash algorithm, const char[] key, int keyLength, CurlBuffer buffer,
	                              CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex)
	{
		crypt_hmac_buffer(algorithm, key, keyLength, buffer, callback, data, encoding);
	}

	/** See crypt_hash_file. */
	public static void HashFile(Openssl_Hash algorithm, const char[] file, CryptCallback callback, any data = 0,
	                            HashEncoding encoding = HashEncoding_Hex)
	{
		crypt_hash_file(algorithm, file, callback, data, encoding);
	}

	/** See crypt_hmac_file. */
	public static void HmacFile(Openssl_Hash algorithm, const char[] key, int keyLength, const char[] file,
	                            CryptCallback callback, any data = 0, HashEncoding encoding = HashEncoding_Hex)
	{
		crypt_hmac_file(algorithm, key, keyLength, file, callback, data, encoding);
	}

	/** See crypt_error_string. */
	public static int ErrorString(CryptError error, char[] buffer, int maxlength)
	{
		return crypt_error_string(error, buffer, maxlength);
	}
}
