/* The file system calls of the jobs and natives, for POSIX and Windows.
 * Paths are UTF-8 on both; Windows converts them to UTF-16 for its wide
 * APIs, so names outside the ANSI code page work. */
#ifndef NEOCURL_CORE_PLATFORM_H
#define NEOCURL_CORE_PLATFORM_H

#include <stdio.h>

#include <string>

namespace neocurl {
namespace platform {

/* Windows takes '/' and '\\' as separators, POSIX only '/'. */
inline bool IsPathSeparator(char c)
{
#ifdef _WIN32
	return c == '/' || c == '\\';
#else
	return c == '/';
#endif
}

/* fopen() with a binary mode such as "rb" or "wb". */
FILE *OpenFile(const std::string &path, const char *mode);

bool PathExists(const std::string &path);

bool IsDirectory(const std::string &path);

/* Creates one directory (POSIX: mode 0775, less the umask); true when it
 * was created or already is a directory. */
bool MakeDirectory(const std::string &path);

bool RemoveFile(const std::string &path);

enum class RenameResult {
	Renamed,
	TargetExists,
	Failed,
};

/* Renames from onto to, replacing a file at to. */
RenameResult RenameReplacing(const std::string &from, const std::string &to);

/* Renames from onto to only while no file is at to, checked atomically. */
RenameResult RenameIfAbsent(const std::string &from, const std::string &to);

/* Whether two paths name the same file by their text: exact on POSIX,
 * ignoring case and the kind of separator on Windows. */
bool IsSamePath(const std::string &a, const std::string &b);

} // namespace platform
} // namespace neocurl

#endif // NEOCURL_CORE_PLATFORM_H
