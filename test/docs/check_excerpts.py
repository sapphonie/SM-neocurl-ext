#!/usr/bin/env python3
# Copyright 2026 davenonymous
"""Checks that the SourcePawn code in the guides is still what the example plugins say.

Every ```sourcepawn block in README.md and docs/*.md must be a contiguous excerpt of a file in
pawn/scripting/examples/, compared line by line without regard to indentation. The example plugins are compiled
and run by the integration tests, so code that passes this check is code that was tested.

A block that is not meant to be an excerpt, such as the signature of a method, is exempt when the line
"<!-- not-an-excerpt -->" stands before it.

Exits with 1 and names every block that fails.
"""

import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
EXAMPLES = REPOSITORY / "pawn" / "scripting" / "examples"
EXEMPT_MARKER = "<!-- not-an-excerpt -->"
FENCE_OPEN = "```sourcepawn"
FENCE_CLOSE = "```"


def normalized(lines):
    """Lines without indentation and trailing spaces; blank lines at both ends removed."""
    stripped = [line.strip() for line in lines]
    while stripped and not stripped[0]:
        stripped.pop(0)
    while stripped and not stripped[-1]:
        stripped.pop()
    return stripped


def code_blocks(page):
    """Yields (line number, lines, is exempt) for every sourcepawn block of a page."""
    lines = page.read_text().split("\n")
    index = 0
    while index < len(lines):
        if lines[index].strip() != FENCE_OPEN:
            index += 1
            continue

        start = index
        end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == FENCE_CLOSE), len(lines))
        before = [line.strip() for line in lines[:start] if line.strip()]
        is_exempt = bool(before) and before[-1] == EXEMPT_MARKER
        yield start + 1, lines[start + 1:end], is_exempt
        index = end + 1


def contains(haystack, needle):
    """Whether the list needle occurs in the list haystack as a contiguous run."""
    if not needle:
        return True
    first = needle[0]
    for start in range(len(haystack) - len(needle) + 1):
        if haystack[start] == first and haystack[start:start + len(needle)] == needle:
            return True
    return False


def main():
    examples = {path.name: normalized(path.read_text().split("\n")) for path in sorted(EXAMPLES.glob("*.sp"))}
    if not examples:
        print("No example plugins in %s" % EXAMPLES, file=sys.stderr)
        return 1

    pages = [REPOSITORY / "README.md"] + sorted((REPOSITORY / "docs").glob("*.md"))
    checked = 0
    failures = []
    for page in pages:
        for line_number, lines, is_exempt in code_blocks(page):
            if is_exempt:
                continue
            checked += 1
            block = normalized(lines)
            if not any(contains(example, block) for example in examples.values()):
                failures.append((page.relative_to(REPOSITORY), line_number, block[0] if block else ""))

    for page, line_number, first_line in failures:
        print("%s:%d: not an excerpt of an example plugin: %s" % (page, line_number, first_line), file=sys.stderr)
    if failures:
        print("%d of %d code blocks are not excerpts of pawn/scripting/examples/*.sp." % (len(failures), checked),
              file=sys.stderr)
        print('Change the page or the example, or put "%s" before a block that is not meant to be one.'
              % EXEMPT_MARKER, file=sys.stderr)
        return 1

    print("%d code blocks in %d pages are excerpts of the example plugins." % (checked, len(pages)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
