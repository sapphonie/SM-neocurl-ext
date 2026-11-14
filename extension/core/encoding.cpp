#include "encoding.h"

namespace neocurl {

namespace {

const char kStandardAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char kUrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string Base64With(const std::string &bytes, const char *alphabet, bool isPadded)
{
	std::string text;
	text.reserve((bytes.size() + 2) / 3 * 4);
	size_t i = 0;
	for (; i + 3 <= bytes.size(); i += 3) {
		unsigned value = (static_cast<unsigned char>(bytes[i]) << 16) |
		                 (static_cast<unsigned char>(bytes[i + 1]) << 8) | static_cast<unsigned char>(bytes[i + 2]);
		text += alphabet[(value >> 18) & 63];
		text += alphabet[(value >> 12) & 63];
		text += alphabet[(value >> 6) & 63];
		text += alphabet[value & 63];
	}

	size_t rest = bytes.size() - i;
	if (rest == 0)
		return text;
	unsigned value = static_cast<unsigned char>(bytes[i]) << 16;
	if (rest == 2)
		value |= static_cast<unsigned char>(bytes[i + 1]) << 8;
	text += alphabet[(value >> 18) & 63];
	text += alphabet[(value >> 12) & 63];
	if (rest == 2)
		text += alphabet[(value >> 6) & 63];
	if (isPadded)
		text.append(rest == 1 ? "==" : "=");
	return text;
}

} // namespace

std::string ToHex(const std::string &bytes)
{
	static const char digits[] = "0123456789abcdef";
	std::string text;
	text.reserve(bytes.size() * 2);
	for (unsigned char byte : bytes) {
		text += digits[byte >> 4];
		text += digits[byte & 15];
	}
	return text;
}

std::string ToBase64(const std::string &bytes)
{
	return Base64With(bytes, kStandardAlphabet, true);
}

std::string ToBase64Url(const std::string &bytes)
{
	return Base64With(bytes, kUrlAlphabet, false);
}

std::string Encode(const std::string &bytes, Encoding encoding)
{
	switch (encoding) {
	case Encoding::Hex:       return ToHex(bytes);
	case Encoding::Base64:    return ToBase64(bytes);
	case Encoding::Base64Url: return ToBase64Url(bytes);
	case Encoding::Raw:       return bytes;
	}
	return bytes;
}

} // namespace neocurl
