#!/usr/bin/env bash
# Builds the static libraries the extension links (curl with OpenSSL, nghttp2, libssh2, brotli, zstd, libpsl and
# zlib) with vcpkg, at the versions of the baseline in vcpkg.json, into deps/<triplet>/<triplet>/.
#
# Usage: build-deps.sh [triplet...]
# Without triplets it builds both architectures of the current platform. VCPKG_ROOT selects a vcpkg checkout;
# without it vcpkg is cloned into ./vcpkg.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

case "$(uname -s)" in
	Linux) default_triplets=(x86-linux x64-linux) ;;
	MINGW* | MSYS* | CYGWIN*) default_triplets=(x86-windows-static x64-windows-static) ;;
	*) echo "build-deps.sh: unsupported platform $(uname -s)" >&2; exit 1 ;;
esac
triplets=("${@:-${default_triplets[@]}}")

baseline=$(sed -n 's/.*"builtin-baseline": *"\([0-9a-f]*\)".*/\1/p' "$root/vcpkg.json")
if [ -z "$baseline" ]; then
	echo "build-deps.sh: no builtin-baseline in vcpkg.json" >&2
	exit 1
fi

# The ports' versions come from the baseline, the helper scripts that build them from the checkout. A vcpkg cloned
# here is checked out at the baseline, so both are pinned; a VCPKG_ROOT is used as it is.
if [ -n "${VCPKG_ROOT:-}" ]; then
	vcpkg_root=$VCPKG_ROOT
else
	vcpkg_root=$root/vcpkg
	if [ ! -d "$vcpkg_root/.git" ]; then
		git clone https://github.com/microsoft/vcpkg "$vcpkg_root"
	fi
	if ! git -C "$vcpkg_root" cat-file -e "$baseline^{commit}" 2>/dev/null; then
		git -C "$vcpkg_root" fetch origin
	fi
	git -C "$vcpkg_root" -c advice.detachedHead=false checkout --quiet "$baseline"
fi

vcpkg="$vcpkg_root/vcpkg"
[ -x "$vcpkg.exe" ] && vcpkg="$vcpkg.exe"
if [ ! -x "$vcpkg" ]; then
	case "$(uname -s)" in
		Linux) "$vcpkg_root/bootstrap-vcpkg.sh" -disableMetrics ;;
		*) cmd //c "$(cygpath -w "$vcpkg_root/bootstrap-vcpkg.bat")" -disableMetrics; vcpkg="$vcpkg_root/vcpkg.exe" ;;
	esac
fi

for triplet in "${triplets[@]}"; do
	"$vcpkg" install \
		--triplet="$triplet" \
		--overlay-triplets="$root/triplets" \
		--x-manifest-root="$root" \
		--x-install-root="$root/deps/$triplet" \
		--clean-after-build
done
