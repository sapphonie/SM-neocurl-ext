/* The rules for paths that plugins pass to file jobs: relative to the game
 * directory and unable to leave it. */
#ifndef NEOCURL_CORE_PATHS_H
#define NEOCURL_CORE_PATHS_H

namespace neocurl {

/* The rules of IsGameRelativePath(), for error messages. */
extern const char *const kPathRules;

/* Whether path stays below the game directory and names its file in one way
 * only: relative, not taken as absolute by SourceMod's BuildPath() (no
 * "file://"), and without empty, "." or ".." parts. On Windows a colon
 * (drive letters, alternate data streams) is refused too. */
bool IsGameRelativePath(const char *path);

} // namespace neocurl

#endif // NEOCURL_CORE_PATHS_H
