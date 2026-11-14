/* POSIX and Windows versions of the file system calls in platform.h. */
#include "platform.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace neocurl {
namespace platform {

#ifdef _WIN32

namespace {

/* UTF-8 to UTF-16; empty for invalid UTF-8, which every call below then
 * fails on. */
std::wstring Widen(const std::string &text)
{
	if (text.empty())
		return std::wstring();
	int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
	                                 nullptr, 0);
	if (length <= 0)
		return std::wstring();
	std::wstring wide(static_cast<size_t>(length), L'\0');
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), &wide[0],
	                    length);
	return wide;
}

DWORD AttributesOf(const std::string &path)
{
	return GetFileAttributesW(Widen(path).c_str());
}

RenameResult Rename(const std::string &from, const std::string &to, DWORD flags)
{
	if (MoveFileExW(Widen(from).c_str(), Widen(to).c_str(), flags))
		return RenameResult::Renamed;
	DWORD error = GetLastError();
	if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
		return RenameResult::TargetExists;
	return RenameResult::Failed;
}

} // namespace

FILE *OpenFile(const std::string &path, const char *mode)
{
	return _wfopen(Widen(path).c_str(), Widen(mode).c_str());
}

bool PathExists(const std::string &path)
{
	return AttributesOf(path) != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectory(const std::string &path)
{
	DWORD attributes = AttributesOf(path);
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool MakeDirectory(const std::string &path)
{
	return CreateDirectoryW(Widen(path).c_str(), nullptr) || IsDirectory(path);
}

bool RemoveFile(const std::string &path)
{
	return DeleteFileW(Widen(path).c_str()) != 0;
}

RenameResult RenameReplacing(const std::string &from, const std::string &to)
{
	return Rename(from, to, MOVEFILE_REPLACE_EXISTING);
}

RenameResult RenameIfAbsent(const std::string &from, const std::string &to)
{
	return Rename(from, to, 0);
}

bool IsSamePath(const std::string &a, const std::string &b)
{
	std::wstring wideA = Widen(a), wideB = Widen(b);
	for (std::wstring *wide : {&wideA, &wideB})
		for (wchar_t &c : *wide)
			if (c == L'/')
				c = L'\\';
	return CompareStringOrdinal(wideA.c_str(), -1, wideB.c_str(), -1, TRUE) == CSTR_EQUAL;
}

#else

FILE *OpenFile(const std::string &path, const char *mode)
{
	return fopen(path.c_str(), mode);
}

bool PathExists(const std::string &path)
{
	struct stat info;
	return stat(path.c_str(), &info) == 0;
}

bool IsDirectory(const std::string &path)
{
	struct stat info;
	return stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
}

bool MakeDirectory(const std::string &path)
{
	constexpr mode_t kCreatedDirectoryMode = 0775;
	return mkdir(path.c_str(), kCreatedDirectoryMode) == 0 || (errno == EEXIST && IsDirectory(path));
}

bool RemoveFile(const std::string &path)
{
	return unlink(path.c_str()) == 0;
}

RenameResult RenameReplacing(const std::string &from, const std::string &to)
{
	return rename(from.c_str(), to.c_str()) == 0 ? RenameResult::Renamed : RenameResult::Failed;
}

/* link() refuses an existing target; the source name is dropped after. */
RenameResult RenameIfAbsent(const std::string &from, const std::string &to)
{
	if (link(from.c_str(), to.c_str()) != 0)
		return errno == EEXIST ? RenameResult::TargetExists : RenameResult::Failed;
	unlink(from.c_str());
	return RenameResult::Renamed;
}

bool IsSamePath(const std::string &a, const std::string &b)
{
	return a == b;
}

#endif

} // namespace platform
} // namespace neocurl
