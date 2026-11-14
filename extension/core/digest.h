/* Digests and HMACs of bytes and files, with OpenSSL and zlib. Nothing here
 * knows SourceMod, so the unit tests run it as it is. */
#ifndef NEOCURL_CORE_DIGEST_H
#define NEOCURL_CORE_DIGEST_H

#include <atomic>
#include <memory>
#include <string>

namespace neocurl {

/* The values are the plugin API's Openssl_Hash (cURL.inc) and must stay in
 * that order. MD4, MD2, SHA and RIPEMD160 are kept for their numbers only. */
enum class Algorithm {
	MD5 = 0,
	MD4,
	MD2,
	SHA,
	SHA1,
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	RIPEMD160,
	SHA512_224,
	SHA512_256,
	SHA3_224,
	SHA3_256,
	SHA3_384,
	SHA3_512,
	BLAKE2B512,
	BLAKE2S256,
	SM3,
	KECCAK256,
	CRC32,
	ADLER32,
};

constexpr Algorithm kLastAlgorithm = Algorithm::ADLER32;

/* The results of a digest. The values up to Memory are the plugin API's
 * CryptError (curl_crypt.inc) and must stay in that order. */
enum class DigestError {
	None = 0,
	OpenInput,
	Read,
	Memory,
	/* The worker stopped the job; never reaches a plugin. */
	Aborted,
};

constexpr DigestError kLastPluginDigestError = DigestError::Memory;

/* The name of an algorithm for messages, e.g. "SHA3-256". */
const char *AlgorithmName(Algorithm algorithm);

bool IsSupported(Algorithm algorithm);

/* HMAC works with every supported algorithm but the checksums. */
bool SupportsHmac(Algorithm algorithm);

/* A digest (or, with a key, an HMAC) being computed. */
class Hasher {
public:
	virtual ~Hasher() = default;
	virtual bool Update(const void *data, size_t length) = 0;
	/* The raw digest; empty when OpenSSL failed. */
	virtual std::string Finish() = 0;
};

/* A hasher for algorithm, an HMAC when key is given. Null when the algorithm
 * is not supported (or not for HMAC) or OpenSSL failed. */
std::unique_ptr<Hasher> CreateHasher(Algorithm algorithm, const std::string *key);

/* The raw digest of data; Memory when OpenSSL failed. */
DigestError DigestBytes(Algorithm algorithm, const std::string *key, const void *data, size_t length,
                        std::string &digest);

/* The raw digest of the file at path, read in chunks until abort is set. */
DigestError DigestFile(Algorithm algorithm, const std::string *key, const std::string &path,
                       const std::atomic<bool> &abort, std::string &digest);

/* The text of a result, e.g. "CryptError_Read". */
const char *DigestErrorName(DigestError error);

} // namespace neocurl

#endif // NEOCURL_CORE_DIGEST_H
