#include "digest.h"
#include "platform.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
#include <zlib.h>

#include <vector>

namespace neocurl {

namespace {

constexpr size_t kChunkSize = 64 * 1024;

/* OpenSSL's name of an EVP digest; null for the checksums and the
 * unsupported algorithms. */
const char *EvpName(Algorithm algorithm)
{
	switch (algorithm) {
	case Algorithm::MD5:        return "MD5";
	case Algorithm::SHA1:       return "SHA1";
	case Algorithm::SHA224:     return "SHA2-224";
	case Algorithm::SHA256:     return "SHA2-256";
	case Algorithm::SHA384:     return "SHA2-384";
	case Algorithm::SHA512:     return "SHA2-512";
	case Algorithm::SHA512_224: return "SHA2-512/224";
	case Algorithm::SHA512_256: return "SHA2-512/256";
	case Algorithm::SHA3_224:   return "SHA3-224";
	case Algorithm::SHA3_256:   return "SHA3-256";
	case Algorithm::SHA3_384:   return "SHA3-384";
	case Algorithm::SHA3_512:   return "SHA3-512";
	case Algorithm::BLAKE2B512: return "BLAKE2B-512";
	case Algorithm::BLAKE2S256: return "BLAKE2S-256";
	case Algorithm::SM3:        return "SM3";
	case Algorithm::KECCAK256:  return "KECCAK-256";
	default:                    return nullptr;
	}
}

bool IsChecksum(Algorithm algorithm)
{
	return algorithm == Algorithm::CRC32 || algorithm == Algorithm::ADLER32;
}

class EvpHasher : public Hasher {
public:
	~EvpHasher() override
	{
		EVP_MD_CTX_free(m_context);
		EVP_MD_free(m_md);
	}

	bool Start(const char *name)
	{
		m_md = EVP_MD_fetch(nullptr, name, nullptr);
		m_context = EVP_MD_CTX_new();
		return m_md && m_context && EVP_DigestInit_ex2(m_context, m_md, nullptr) == 1;
	}

	bool Update(const void *data, size_t length) override
	{
		return EVP_DigestUpdate(m_context, data, length) == 1;
	}

	std::string Finish() override
	{
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int length = 0;
		if (EVP_DigestFinal_ex(m_context, digest, &length) != 1)
			return std::string();
		return std::string(reinterpret_cast<char *>(digest), length);
	}

private:
	EVP_MD *m_md = nullptr;
	EVP_MD_CTX *m_context = nullptr;
};

class HmacHasher : public Hasher {
public:
	~HmacHasher() override
	{
		EVP_MAC_CTX_free(m_context);
		EVP_MAC_free(m_mac);
	}

	bool Start(const char *digestName, const std::string &key)
	{
		m_mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
		if (!m_mac)
			return false;
		m_context = EVP_MAC_CTX_new(m_mac);
		if (!m_context)
			return false;
		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(digestName), 0),
			OSSL_PARAM_construct_end(),
		};
		/* An empty key is valid for HMAC; OpenSSL wants a non-null pointer. */
		static const unsigned char kEmptyKey = 0;
		const unsigned char *keyBytes =
			key.empty() ? &kEmptyKey : reinterpret_cast<const unsigned char *>(key.data());
		return EVP_MAC_init(m_context, keyBytes, key.size(), params) == 1;
	}

	bool Update(const void *data, size_t length) override
	{
		return EVP_MAC_update(m_context, static_cast<const unsigned char *>(data), length) == 1;
	}

	std::string Finish() override
	{
		unsigned char digest[EVP_MAX_MD_SIZE];
		size_t length = 0;
		if (EVP_MAC_final(m_context, digest, &length, sizeof(digest)) != 1)
			return std::string();
		return std::string(reinterpret_cast<char *>(digest), length);
	}

private:
	EVP_MAC *m_mac = nullptr;
	EVP_MAC_CTX *m_context = nullptr;
};

/* CRC-32 and Adler-32 as zlib computes them, written big-endian, as the
 * usual tools print them. */
class ChecksumHasher : public Hasher {
public:
	explicit ChecksumHasher(Algorithm algorithm)
		: m_isCrc(algorithm == Algorithm::CRC32), m_value(m_isCrc ? crc32(0, nullptr, 0) : adler32(0, nullptr, 0))
	{
	}

	bool Update(const void *data, size_t length) override
	{
		const Bytef *bytes = static_cast<const Bytef *>(data);
		/* zlib takes the length as uInt; feed large inputs in pieces. */
		while (length > 0) {
			uInt piece = length > 0x40000000 ? 0x40000000 : static_cast<uInt>(length);
			m_value = m_isCrc ? crc32(m_value, bytes, piece) : adler32(m_value, bytes, piece);
			bytes += piece;
			length -= piece;
		}
		return true;
	}

	std::string Finish() override
	{
		char digest[4] = {
			static_cast<char>((m_value >> 24) & 0xff),
			static_cast<char>((m_value >> 16) & 0xff),
			static_cast<char>((m_value >> 8) & 0xff),
			static_cast<char>(m_value & 0xff),
		};
		return std::string(digest, sizeof(digest));
	}

private:
	bool m_isCrc;
	uLong m_value;
};

struct FileCloser {
	void operator()(FILE *file) const { fclose(file); }
};

} // namespace

const char *AlgorithmName(Algorithm algorithm)
{
	switch (algorithm) {
	case Algorithm::MD4:       return "MD4";
	case Algorithm::MD2:       return "MD2";
	case Algorithm::SHA:       return "SHA";
	case Algorithm::RIPEMD160: return "RIPEMD160";
	case Algorithm::CRC32:     return "CRC32";
	case Algorithm::ADLER32:   return "ADLER32";
	default:                   break;
	}
	const char *name = EvpName(algorithm);
	return name ? name : "unknown";
}

bool IsSupported(Algorithm algorithm)
{
	return IsChecksum(algorithm) || EvpName(algorithm) != nullptr;
}

bool SupportsHmac(Algorithm algorithm)
{
	return EvpName(algorithm) != nullptr;
}

std::unique_ptr<Hasher> CreateHasher(Algorithm algorithm, const std::string *key)
{
	if (key) {
		if (!SupportsHmac(algorithm))
			return nullptr;
		auto hasher = std::make_unique<HmacHasher>();
		return hasher->Start(EvpName(algorithm), *key) ? std::move(hasher) : nullptr;
	}
	if (IsChecksum(algorithm))
		return std::make_unique<ChecksumHasher>(algorithm);
	const char *name = EvpName(algorithm);
	if (!name)
		return nullptr;
	auto hasher = std::make_unique<EvpHasher>();
	return hasher->Start(name) ? std::move(hasher) : nullptr;
}

DigestError DigestBytes(Algorithm algorithm, const std::string *key, const void *data, size_t length,
                        std::string &digest)
{
	std::unique_ptr<Hasher> hasher = CreateHasher(algorithm, key);
	if (!hasher || !hasher->Update(data, length))
		return DigestError::Memory;
	digest = hasher->Finish();
	return digest.empty() ? DigestError::Memory : DigestError::None;
}

DigestError DigestFile(Algorithm algorithm, const std::string *key, const std::string &path,
                       const std::atomic<bool> &abort, std::string &digest)
{
	std::unique_ptr<FILE, FileCloser> file(platform::OpenFile(path, "rb"));
	if (!file)
		return DigestError::OpenInput;
	std::unique_ptr<Hasher> hasher = CreateHasher(algorithm, key);
	if (!hasher)
		return DigestError::Memory;

	std::vector<char> chunk(kChunkSize);
	for (;;) {
		if (abort)
			return DigestError::Aborted;
		size_t length = fread(chunk.data(), 1, chunk.size(), file.get());
		if (ferror(file.get()))
			return DigestError::Read;
		if (!hasher->Update(chunk.data(), length))
			return DigestError::Memory;
		if (length < chunk.size())
			break;
	}
	digest = hasher->Finish();
	return digest.empty() ? DigestError::Memory : DigestError::None;
}

const char *DigestErrorName(DigestError error)
{
	switch (error) {
	case DigestError::None:      return "CryptError_None";
	case DigestError::OpenInput: return "CryptError_OpenInput";
	case DigestError::Read:      return "CryptError_Read";
	case DigestError::Memory:    return "CryptError_Memory";
	case DigestError::Aborted:   return "Aborted";
	}
	return "unknown";
}

} // namespace neocurl
