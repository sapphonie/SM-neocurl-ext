/* The natives of curl_crypt.inc: digests and HMACs of strings at once, of
 * CurlBuffers and files on the crypt pool. */
#include "api.h"

#include "core/digest.h"
#include "core/encoding.h"

#include <string.h>

#include <memory>
#include <new>
#include <utility>

using neocurl::Algorithm;
using neocurl::DigestError;
using neocurl::Encoding;

namespace api {

namespace {

/* Reads an algorithm argument; withKey refuses the checksums. */
bool ReadAlgorithm(IPluginContext *context, cell_t value, bool withKey, Algorithm &algorithm)
{
	if (value < 0 || value > static_cast<cell_t>(neocurl::kLastAlgorithm)) {
		context->ReportError("Invalid Openssl_Hash %d", value);
		return false;
	}
	algorithm = static_cast<Algorithm>(value);
	if (!neocurl::IsSupported(algorithm)) {
		context->ReportError("Openssl_Hash %s is not supported", neocurl::AlgorithmName(algorithm));
		return false;
	}
	if (withKey && !neocurl::SupportsHmac(algorithm)) {
		context->ReportError("Openssl_Hash %s cannot be used for an HMAC", neocurl::AlgorithmName(algorithm));
		return false;
	}
	return true;
}

bool ReadEncoding(IPluginContext *context, cell_t value, Encoding &encoding)
{
	if (value < 0 || value > static_cast<cell_t>(neocurl::kLastEncoding)) {
		context->ReportError("Invalid HashEncoding %d", value);
		return false;
	}
	encoding = static_cast<Encoding>(value);
	return true;
}

/* Writes the encoded digest into the plugin's array: raw bytes as they are,
 * text with a NUL after it. Returns its length. */
cell_t WriteDigest(IPluginContext *context, cell_t address, cell_t maxlength, const std::string &encoded,
                   Encoding encoding)
{
	bool isText = encoding != Encoding::Raw;
	size_t needed = encoded.size() + (isText ? 1 : 0);
	if (maxlength < 0 || static_cast<size_t>(maxlength) < needed)
		return context->ThrowNativeError("The output needs %u bytes, maxlength is %d", static_cast<unsigned>(needed),
		                                 maxlength);
	cell_t *output;
	context->LocalToPhysAddr(address, &output);
	char *bytes = reinterpret_cast<char *>(output);
	memcpy(bytes, encoded.data(), encoded.size());
	if (isText)
		bytes[encoded.size()] = '\0';
	return static_cast<cell_t>(encoded.size());
}

/* The digest of a string at once; key is null for a plain digest.
 * params from first: input, length, output, maxlength, encoding. */
cell_t DigestNow(IPluginContext *context, const cell_t *params, int first, Algorithm algorithm,
                 const std::string *key)
{
	Encoding encoding;
	std::string input;
	if (!ReadEncoding(context, params[first + 4], encoding) ||
	    !ReadBytes(context, params[first], params[first + 1], "input", input))
		return 0;
	std::string digest;
	if (neocurl::DigestBytes(algorithm, key, input.data(), input.size(), digest) != DigestError::None)
		return context->ThrowNativeError("OpenSSL failed to compute %s", neocurl::AlgorithmName(algorithm));
	return WriteDigest(context, params[first + 2], params[first + 3], neocurl::Encode(digest, encoding), encoding);
}

/* Queues a digest of a CurlBuffer or a file; key is empty without hasKey.
 * params from first: buffer or file, callback, data, encoding. */
cell_t DigestLater(IPluginContext *context, const cell_t *params, int first, Algorithm algorithm, bool hasKey,
                   std::string key, bool isFile)
{
	Encoding encoding;
	if (!ReadEncoding(context, params[first + 3], encoding) || !ReadCallback(context, params[first + 1], "callback"))
		return 0;

	auto sharedKey = hasKey ? std::make_shared<std::string>(std::move(key)) : nullptr;
	neocurl::Task task;
	if (isFile) {
		GamePath path;
		if (!ReadGamePath(context, params[first], "file", path))
			return 0;
		std::string resolved = path.resolved;
		task = [=](const std::atomic<bool> &abort) {
			std::string digest;
			DigestError error = neocurl::DigestFile(algorithm, sharedKey.get(), resolved, abort, digest);
			std::string encoded = error == DigestError::None ? neocurl::Encode(digest, encoding) : std::string();
			return neocurl::TaskResult{0, static_cast<int>(error), std::move(encoded)};
		};
	} else {
		CurlBuffer *buffer = ReadBuffer(context, params[first]);
		if (!buffer)
			return 0;
		std::shared_ptr<std::string> input;
		try {
			input = std::make_shared<std::string>(buffer->bytes);
		} catch (const std::bad_alloc &) {
			return context->ThrowNativeError("Out of memory copying the buffer");
		}
		task = [=](const std::atomic<bool> &abort) {
			std::string digest;
			DigestError error = neocurl::DigestBytes(algorithm, sharedKey.get(), input->data(), input->size(), digest);
			std::string encoded = error == DigestError::None ? neocurl::Encode(digest, encoding) : std::string();
			return neocurl::TaskResult{0, static_cast<int>(error), std::move(encoded)};
		};
	}
	SubmitJob(PoolKind::Crypt, std::move(task),
	          PendingCallback{context, static_cast<funcid_t>(params[first + 1]), params[first + 2],
	                          CallbackShape::Bytes, {}, {}});
	return 0;
}

// crypt_hash_string(algorithm, const char[] input, length, char[] output, maxlength, encoding)
cell_t Crypt_HashString(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	if (!ReadAlgorithm(context, params[1], false, algorithm))
		return 0;
	return DigestNow(context, params, 2, algorithm, nullptr);
}

// crypt_hmac_string(algorithm, const char[] key, keyLength, const char[] input, length, char[] output, maxlength,
//                   encoding)
cell_t Crypt_HmacString(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	std::string key;
	if (!ReadAlgorithm(context, params[1], true, algorithm) || !ReadBytes(context, params[2], params[3], "key", key))
		return 0;
	return DigestNow(context, params, 4, algorithm, &key);
}

// crypt_hash_buffer(algorithm, buffer, callback, data, encoding)
cell_t Crypt_HashBuffer(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	if (!ReadAlgorithm(context, params[1], false, algorithm))
		return 0;
	return DigestLater(context, params, 2, algorithm, false, std::string(), false);
}

// crypt_hmac_buffer(algorithm, const char[] key, keyLength, buffer, callback, data, encoding)
cell_t Crypt_HmacBuffer(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	std::string key;
	if (!ReadAlgorithm(context, params[1], true, algorithm) || !ReadBytes(context, params[2], params[3], "key", key))
		return 0;
	return DigestLater(context, params, 4, algorithm, true, std::move(key), false);
}

// crypt_hash_file(algorithm, const char[] file, callback, data, encoding)
cell_t Crypt_HashFile(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	if (!ReadAlgorithm(context, params[1], false, algorithm))
		return 0;
	return DigestLater(context, params, 2, algorithm, false, std::string(), true);
}

// crypt_hmac_file(algorithm, const char[] key, keyLength, const char[] file, callback, data, encoding)
cell_t Crypt_HmacFile(IPluginContext *context, const cell_t *params)
{
	Algorithm algorithm;
	std::string key;
	if (!ReadAlgorithm(context, params[1], true, algorithm) || !ReadBytes(context, params[2], params[3], "key", key))
		return 0;
	return DigestLater(context, params, 4, algorithm, true, std::move(key), true);
}

// crypt_error_string(error, char[] buffer, maxlength)
cell_t Crypt_ErrorString(IPluginContext *context, const cell_t *params)
{
	cell_t error = params[1];
	if (error < 0 || error > static_cast<cell_t>(neocurl::kLastPluginDigestError))
		return context->ThrowNativeError("Invalid CryptError %d", error);
	// Stays 0 for a maxlength of 0: nothing is written then, not even this.
	size_t written = 0;
	context->StringToLocalUTF8(params[2], params[3], neocurl::DigestErrorName(static_cast<DigestError>(error)),
	                           &written);
	return static_cast<cell_t>(written);
}

} // namespace

const sp_nativeinfo_t g_CryptNatives[] = {
	{"crypt_hash_string",  Crypt_HashString},
	{"crypt_hmac_string",  Crypt_HmacString},
	{"crypt_hash_buffer",  Crypt_HashBuffer},
	{"crypt_hmac_buffer",  Crypt_HmacBuffer},
	{"crypt_hash_file",    Crypt_HashFile},
	{"crypt_hmac_file",    Crypt_HmacFile},
	{"crypt_error_string", Crypt_ErrorString},
	{nullptr,              nullptr},
};

} // namespace api
