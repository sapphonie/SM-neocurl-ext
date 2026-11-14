#include "paths.h"
#include "platform.h"

#include <string.h>

namespace neocurl {

namespace {

/* SourceMod's BuildPath() takes a path with this prefix as absolute. */
const char kAbsolutePathPrefix[] = "file://";

/* The first path separator in path, or its terminating NUL. */
const char *EndOfPart(const char *path)
{
	while (*path != '\0' && !platform::IsPathSeparator(*path))
		path++;
	return path;
}

bool IsDotPart(const char *part, size_t length)
{
	return (length == 1 && part[0] == '.') || (length == 2 && part[0] == '.' && part[1] == '.');
}

} // namespace

#ifdef _WIN32
const char *const kPathRules = "not start with a separator or \"file://\", contain no \":\" and have no empty, \".\" "
                               "or \"..\" parts";
#else
const char *const kPathRules = "not start with \"/\" or \"file://\" and have no empty, \".\" or \"..\" parts";
#endif

bool IsGameRelativePath(const char *path)
{
	if (path[0] == '\0' || platform::IsPathSeparator(path[0]))
		return false;
	if (strncmp(path, kAbsolutePathPrefix, sizeof(kAbsolutePathPrefix) - 1) == 0)
		return false;
#ifdef _WIN32
	if (strchr(path, ':'))
		return false;
#endif
	for (const char *part = path; ; ) {
		const char *end = EndOfPart(part);
		size_t length = static_cast<size_t>(end - part);
		if (length == 0 || IsDotPart(part, length))
			return false;
		if (*end == '\0')
			return true;
		part = end + 1;
	}
}

} // namespace neocurl
