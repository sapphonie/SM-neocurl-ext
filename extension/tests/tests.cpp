/* Unit tests of extension/core: codecs, digests, encodings, paths and the
 * worker pool. They work in a fresh directory below the system's temp
 * directory and exit non-zero when a check failed. */
#include "core/codec.h"
#include "core/digest.h"
#include "core/encoding.h"
#include "core/paths.h"
#include "core/pool.h"

#include <stdio.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace neocurl;

namespace {

std::string g_dir;
int g_failures = 0;

#define CHECK(condition)                                                                    \
	do {                                                                                    \
		if (!(condition)) {                                                                 \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition);   \
			g_failures++;                                                                   \
		}                                                                                   \
	} while (0)

#define CHECK_CODEC(actual, expected)                                                       \
	do {                                                                                    \
		CodecError a = (actual), e = (expected);                                            \
		if (a != e) {                                                                       \
			fprintf(stderr, "%s:%d: expected %s, got %s\n", __FILE__, __LINE__,             \
			        CodecErrorName(e), CodecErrorName(a));                                  \
			g_failures++;                                                                   \
		}                                                                                   \
	} while (0)

#define CHECK_EQUAL(actual, expected)                                                       \
	do {                                                                                    \
		std::string a = (actual), e = (expected);                                           \
		if (a != e) {                                                                       \
			fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__,     \
			        e.c_str(), a.c_str());                                                  \
			g_failures++;                                                                   \
		}                                                                                   \
	} while (0)

const std::atomic<bool> kNoAbort{false};
const Format kAllFormats[] = {Format::Gzip, Format::Zlib, Format::Deflate, Format::Brotli, Format::Zstd};

std::string PathOf(const std::string &name)
{
	return g_dir + "/" + name;
}

std::string ReadFile(const std::string &path)
{
	std::ifstream in(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void WriteFile(const std::string &path, const std::string &content)
{
	std::ofstream(path, std::ios::binary) << content;
}

bool Exists(const std::string &path)
{
	return std::filesystem::exists(path);
}

/* Compressible but not trivial: words from a small vocabulary. */
std::string SampleData(size_t length, unsigned seed)
{
	static const char *words[] = {"rocket ", "sticky ", "uber ", "medic ", "scout ", "\n"};
	std::mt19937 random(seed);
	std::string data;
	while (data.size() < length) {
		data += words[random() % (sizeof(words) / sizeof(words[0]))];
		data += static_cast<char>(random() & 0xff);
	}
	data.resize(length);
	return data;
}

std::string Compressed(Format format, const std::string &input, int level = -1)
{
	std::string output;
	int used = level == -1 ? LevelRangeOf(format).kDefault : level;
	CHECK_CODEC(CompressBytes(format, used, input, 0, kNoAbort, output), CodecError::None);
	return output;
}

std::string HexDigest(Algorithm algorithm, const std::string &input, const std::string *key = nullptr)
{
	std::string digest;
	CHECK(DigestBytes(algorithm, key, input.data(), input.size(), digest) == DigestError::None);
	return ToHex(digest);
}

/* --- Codecs --- */

void TestRoundTrips()
{
	std::string input = SampleData(300 * 1024, 1);
	for (Format format : kAllFormats) {
		LevelRange range = LevelRangeOf(format);
		for (int level : {range.min, range.kDefault, range.max}) {
			if (format == Format::Zstd && level == range.max)
				continue; /* level 22 is slow and changes nothing here */
			std::string compressed = Compressed(format, input, level);
			CHECK(compressed.size() < input.size());
			std::string output;
			CHECK_CODEC(DecompressBytes(format, compressed, 0, kNoAbort, output), CodecError::None);
			CHECK(output == input);
		}
	}
}

void TestEmptyInput()
{
	for (Format format : kAllFormats) {
		std::string compressed = Compressed(format, std::string());
		std::string output = "x";
		output.clear();
		CHECK_CODEC(DecompressBytes(format, compressed, 0, kNoAbort, output), CodecError::None);
		CHECK(output.empty());
	}
}

void TestSignatures()
{
	std::string gzip = Compressed(Format::Gzip, "hello");
	std::string zstd = Compressed(Format::Zstd, "hello");
	CHECK(static_cast<unsigned char>(gzip[0]) == 0x1f && static_cast<unsigned char>(gzip[1]) == 0x8b);
	CHECK(DetectFormat(gzip.data(), gzip.size()) == Format::Gzip);
	CHECK(DetectFormat(zstd.data(), zstd.size()) == Format::Zstd);
	std::string zlib = Compressed(Format::Zlib, "hello");
	CHECK(DetectFormat(zlib.data(), zlib.size()) == Format::Zlib);
	CHECK(DetectFormat("plain text", 10) == Format::Auto);
}

void TestAuto()
{
	std::string input = SampleData(10000, 2);
	for (Format format : {Format::Gzip, Format::Zlib, Format::Zstd}) {
		std::string output;
		CHECK_CODEC(DecompressBytes(Format::Auto, Compressed(format, input), 0, kNoAbort, output), CodecError::None);
		CHECK(output == input);
	}
	std::string output;
	CHECK_CODEC(DecompressBytes(Format::Auto, Compressed(Format::Brotli, input), 0, kNoAbort, output),
	            CodecError::UnknownFormat);
	CHECK_CODEC(DecompressBytes(Format::Auto, std::string(), 0, kNoAbort, output), CodecError::UnknownFormat);
	std::string compress;
	CHECK_CODEC(CompressBytes(Format::Auto, 0, input, 0, kNoAbort, compress), CodecError::UnknownFormat);
}

void TestBrokenInput()
{
	std::string input = SampleData(100000, 3);
	for (Format format : kAllFormats) {
		std::string compressed = Compressed(format, input);
		std::string output;
		CHECK_CODEC(DecompressBytes(format, compressed.substr(0, compressed.size() / 2), 0, kNoAbort, output),
		            CodecError::UnexpectedEOF);

		std::string corrupt = compressed;
		for (size_t i = 20; i < 60 && i < corrupt.size(); i++)
			corrupt[i] = static_cast<char>(corrupt[i] ^ 0x5a);
		output.clear();
		CodecError error = DecompressBytes(format, corrupt, 0, kNoAbort, output);
		CHECK(error == CodecError::Data || (error == CodecError::None && output != input));
	}
	std::string output;
	CHECK_CODEC(DecompressBytes(Format::Gzip, "not gzip at all", 0, kNoAbort, output), CodecError::Data);
	CHECK_CODEC(DecompressBytes(Format::Zlib, Compressed(Format::Zlib, "a") + "trailing", 0, kNoAbort, output),
	            CodecError::Data);
}

void TestConcatenatedGzip()
{
	std::string both = Compressed(Format::Gzip, "first ") + Compressed(Format::Gzip, "second");
	std::string output;
	CHECK_CODEC(DecompressBytes(Format::Gzip, both, 0, kNoAbort, output), CodecError::None);
	CHECK_EQUAL(output, "first second");

	std::string frames = Compressed(Format::Zstd, "first ") + Compressed(Format::Zstd, "second");
	output.clear();
	CHECK_CODEC(DecompressBytes(Format::Zstd, frames, 0, kNoAbort, output), CodecError::None);
	CHECK_EQUAL(output, "first second");
}

void TestMaxSize()
{
	std::string input(100000, 'a');
	for (Format format : kAllFormats) {
		std::string compressed = Compressed(format, input);
		std::string output;
		CHECK_CODEC(DecompressBytes(format, compressed, 99999, kNoAbort, output), CodecError::TooLarge);
		output.clear();
		CHECK_CODEC(DecompressBytes(format, compressed, 100000, kNoAbort, output), CodecError::None);
		CHECK(output == input);
	}
	std::string output;
	CHECK_CODEC(CompressBytes(Format::Gzip, 6, SampleData(100000, 4), 100, kNoAbort, output), CodecError::TooLarge);
}

void TestAbort()
{
	const std::atomic<bool> abort{true};
	std::string output;
	CHECK_CODEC(CompressBytes(Format::Zstd, 3, "data", 0, abort, output), CodecError::Aborted);
}

void TestFiles()
{
	std::string input = SampleData(200 * 1024, 5);
	WriteFile(PathOf("input.dat"), input);
	for (Format format : kAllFormats) {
		std::string packed = PathOf("packed.bin"), unpacked = PathOf("sub/dir/unpacked.dat");
		FileJob compress{PathOf("input.dat"), packed, false, false};
		CHECK_CODEC(CompressFile(format, LevelRangeOf(format).kDefault, compress, kNoAbort), CodecError::None);
		CHECK(!Exists(TempPathFor(packed)));
		CHECK_CODEC(CompressFile(format, LevelRangeOf(format).kDefault, compress, kNoAbort),
		            CodecError::OutputExists);

		FileJob withoutPath{packed, unpacked, false, false};
		CHECK_CODEC(DecompressFile(format, withoutPath, 0, kNoAbort), CodecError::OpenOutput);
		FileJob decompress{packed, unpacked, true, true};
		CHECK_CODEC(DecompressFile(format, decompress, 0, kNoAbort), CodecError::None);
		CHECK(ReadFile(unpacked) == input);

		CHECK_CODEC(DecompressFile(format, decompress, 1000, kNoAbort), CodecError::TooLarge);
		CHECK(ReadFile(unpacked) == input);
		CHECK(!Exists(TempPathFor(unpacked)));

		std::filesystem::remove(packed);
		std::filesystem::remove_all(PathOf("sub"));
	}
	FileJob missing{PathOf("missing.dat"), PathOf("out.bin"), false, false};
	CHECK_CODEC(CompressFile(Format::Gzip, 6, missing, kNoAbort), CodecError::OpenInput);
	CHECK(!Exists(PathOf("out.bin")));
}

/* --- Digests and encodings --- */

void TestDigests()
{
	CHECK_EQUAL(HexDigest(Algorithm::MD5, "abc"), "900150983cd24fb0d6963f7d28e17f72");
	CHECK_EQUAL(HexDigest(Algorithm::SHA1, "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
	CHECK_EQUAL(HexDigest(Algorithm::SHA256, "abc"),
	            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	CHECK_EQUAL(HexDigest(Algorithm::SHA512_224, "abc"), "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
	CHECK_EQUAL(HexDigest(Algorithm::SHA512_256, "abc"),
	            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
	CHECK_EQUAL(HexDigest(Algorithm::SHA3_256, "abc"),
	            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
	CHECK_EQUAL(HexDigest(Algorithm::BLAKE2S256, "abc"),
	            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
	CHECK_EQUAL(HexDigest(Algorithm::BLAKE2B512, "abc"),
	            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
	            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
	CHECK_EQUAL(HexDigest(Algorithm::SM3, "abc"), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
	CHECK_EQUAL(HexDigest(Algorithm::KECCAK256, ""),
	            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	CHECK_EQUAL(HexDigest(Algorithm::CRC32, "123456789"), "cbf43926");
	CHECK_EQUAL(HexDigest(Algorithm::ADLER32, "Wikipedia"), "11e60398");

	CHECK(!IsSupported(Algorithm::MD4));
	CHECK(!IsSupported(Algorithm::RIPEMD160));
	CHECK(!SupportsHmac(Algorithm::CRC32));
	CHECK(CreateHasher(Algorithm::MD2, nullptr) == nullptr);
}

void TestHmac()
{
	std::string jefe = "Jefe", empty;
	CHECK_EQUAL(HexDigest(Algorithm::SHA256, "what do ya want for nothing?", &jefe),
	            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	CHECK_EQUAL(HexDigest(Algorithm::SHA256, "", &empty),
	            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
	CHECK(CreateHasher(Algorithm::ADLER32, &jefe) == nullptr);
}

void TestDigestFile()
{
	WriteFile(PathOf("hash.dat"), "abc");
	std::string digest;
	CHECK(DigestFile(Algorithm::SHA256, nullptr, PathOf("hash.dat"), kNoAbort, digest) == DigestError::None);
	CHECK_EQUAL(ToHex(digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	std::string big = SampleData(1000 * 1000, 6), fromBytes;
	WriteFile(PathOf("big.dat"), big);
	CHECK(DigestBytes(Algorithm::SHA3_512, nullptr, big.data(), big.size(), fromBytes) == DigestError::None);
	CHECK(DigestFile(Algorithm::SHA3_512, nullptr, PathOf("big.dat"), kNoAbort, digest) == DigestError::None);
	CHECK(digest == fromBytes);
	CHECK(DigestFile(Algorithm::SHA256, nullptr, PathOf("missing.dat"), kNoAbort, digest) == DigestError::OpenInput);
}

void TestEncodings()
{
	CHECK_EQUAL(ToBase64(""), "");
	CHECK_EQUAL(ToBase64("f"), "Zg==");
	CHECK_EQUAL(ToBase64("foob"), "Zm9vYg==");
	CHECK_EQUAL(ToBase64("fooba"), "Zm9vYmE=");
	CHECK_EQUAL(ToBase64("foobar"), "Zm9vYmFy");
	CHECK_EQUAL(ToBase64("\xfb\xff"), "+/8=");
	CHECK_EQUAL(ToBase64Url("\xfb\xff"), "-_8");
	CHECK_EQUAL(ToHex(std::string("\x00\xab", 2)), "00ab");
	CHECK_EQUAL(Encode("ab", Encoding::Raw), "ab");
}

/* --- Paths and pool --- */

void TestPaths()
{
	CHECK(IsGameRelativePath("demos/match.dem"));
	CHECK(IsGameRelativePath("a"));
	CHECK(!IsGameRelativePath(""));
	CHECK(!IsGameRelativePath("/etc/passwd"));
	CHECK(!IsGameRelativePath("file://etc/passwd"));
	CHECK(!IsGameRelativePath("../cfg/server.cfg"));
	CHECK(!IsGameRelativePath("maps/../../x"));
	CHECK(!IsGameRelativePath("maps//x"));
	CHECK(!IsGameRelativePath("maps/./x"));
	CHECK(!IsGameRelativePath("maps/"));
}

void TestPool()
{
	Pool pool(2);
	for (TaskId id = 1; id <= 20; id++)
		pool.Submit(id, [id](const std::atomic<bool> &) {
			return TaskResult{0, static_cast<int>(id), std::to_string(id * 2)};
		});

	std::vector<TaskResult> results;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (results.size() < 20 && std::chrono::steady_clock::now() < deadline) {
		for (TaskResult &result : pool.TakeResults())
			results.push_back(std::move(result));
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	CHECK(results.size() == 20);
	for (const TaskResult &result : results) {
		CHECK(result.error == static_cast<int>(result.id));
		CHECK(result.output == std::to_string(result.id * 2));
	}
	pool.Stop();
	pool.Submit(99, [](const std::atomic<bool> &) { return TaskResult{0, 0, std::string()}; });
	CHECK(pool.TakeResults().empty());
}

} // namespace

int main()
{
	std::filesystem::path dir = std::filesystem::temp_directory_path() /
	                            ("curl-tests-" + std::to_string(std::random_device()()));
	std::filesystem::create_directories(dir);
	g_dir = dir.string();

	TestRoundTrips();
	TestEmptyInput();
	TestSignatures();
	TestAuto();
	TestBrokenInput();
	TestConcatenatedGzip();
	TestMaxSize();
	TestAbort();
	TestFiles();
	TestDigests();
	TestHmac();
	TestDigestFile();
	TestEncodings();
	TestPaths();
	TestPool();

	std::filesystem::remove_all(dir);
	if (g_failures > 0) {
		fprintf(stderr, "%d checks failed\n", g_failures);
		return 1;
	}
	printf("All tests passed\n");
	return 0;
}
