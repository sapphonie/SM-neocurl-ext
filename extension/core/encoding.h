/* Text encodings of binary data, for digests. */
#ifndef NEOCURL_CORE_ENCODING_H
#define NEOCURL_CORE_ENCODING_H

#include <string>

namespace neocurl {

/* The values are the plugin API's HashEncoding (curl_crypt.inc) and must stay
 * in that order. */
enum class Encoding {
	Hex = 0,
	Base64,
	Base64Url,
	Raw,
};

constexpr Encoding kLastEncoding = Encoding::Raw;

/* Lowercase hex. */
std::string ToHex(const std::string &bytes);

/* RFC 4648 section 4, with padding. */
std::string ToBase64(const std::string &bytes);

/* RFC 4648 section 5, without padding. */
std::string ToBase64Url(const std::string &bytes);

/* bytes in the given encoding; Raw returns them as they are. */
std::string Encode(const std::string &bytes, Encoding encoding);

} // namespace neocurl

#endif // NEOCURL_CORE_ENCODING_H
