#!/usr/bin/env bash
#
# build.sh — build libgeektrust.so for linux/amd64 and openharmony/arm64.
#
# Both are C shared libraries (Go -buildmode=c-shared) laid out by the C ABI in
# docs/ABI.md, and both carry the provenance marker TECHPIE-GEEKTRUST=<abi>:<version>:<digest>,
# where <digest> is a SHA-256 over the whole source tree. The app recomputes that
# digest from the submodule checkout it pinned and refuses an artifact built from
# other sources, so the recipe below is a contract between the two repositories —
# it has no filters, prefixes or suffixes beyond what is written here.
#
# The script is safe to re-run; it is also the project's only build entry point
# (there is no CI on purpose: an OHOS build needs the vendor SDK).
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

# Toolchains. The OpenHarmony target needs the OpenHarmony Go fork (upstream Go
# has no openharmony port) and the clang from the OHOS command-line tools; the
# linux target builds with whatever Go and system C compiler are on PATH.
OHOS_GOROOT="${OHOS_GOROOT:-/home/zambar/dev/ohos_golang_go}"
OHOS_CC="${OHOS_CC:-/home/zambar/dev/command-line-tools/sdk/default/openharmony/native/llvm/bin/aarch64-unknown-linux-ohos-clang}"
# The Android artifact is built with the NDK's bionic toolchain: the OHOS one is
# musl and produces a library bionic refuses to load.
ANDROID_CC="${ANDROID_CC:-/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang}"
# Android needs *upstream* Go: the OpenHarmony fork's net package only carries the
# openharmony cgo path, and cgo there cannot resolve getifaddrs.
ANDROID_GO="${ANDROID_GO:-/usr/lib/go/bin/go}"
LINUX_GO="${LINUX_GO:-go}"

# ABI is the compatibility integer of docs/ABI.md; it must match core.ABI, which
# is what geektrust_status reports.
ABI=1

fail() { echo "build.sh: $*" >&2; exit 1; }

command -v readelf >/dev/null || fail "readelf is required (binutils)"
command -v nm >/dev/null || fail "nm is required (binutils)"
command -v sha256sum >/dev/null || fail "sha256sum is required (coreutils)"
command -v git >/dev/null || fail "git is required"
[ -x "$OHOS_GOROOT/bin/go" ] || fail "no OpenHarmony Go toolchain at $OHOS_GOROOT (set OHOS_GOROOT)"
[ -x "$OHOS_CC" ] || fail "no OHOS clang at $OHOS_CC (set OHOS_CC)"
command -v "$LINUX_GO" >/dev/null || fail "no Go toolchain for the linux build (set LINUX_GO)"

cd "$ROOT"

if [ "$(sed -n 's/^const ABI = \([0-9][0-9]*\)$/\1/p' internal/core/version.go)" != "$ABI" ]; then
  fail "internal/core/version.go declares another ABI than the $ABI this script embeds"
fi

# 1. Provenance. Version comes from git; the digest covers every file in the
#    tree except .git/, as "<path>\n<sha256 hex>\n" per file, paths sorted by
#    byte order. Build output is removed first so a re-run hashes the same tree
#    (and so an artifact from a previous run cannot change its own digest).
rm -rf "$DIST"
if ! version="$(git describe --tags --always --dirty 2>/dev/null)"; then
  version="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi

digest="$(
  export LC_ALL=C
  find . -path ./.git -prune -o -type f -print |
    sed 's|^\./||' |
    LC_ALL=C sort |
    while IFS= read -r path; do
      printf '%s\n' "$path"
      sha256sum -- "$path" | cut -d' ' -f1
    done | sha256sum | cut -d' ' -f1
)"

marker="TECHPIE-GEEKTRUST=${ABI}:${version}:${digest}"
ldflags="-s -w -X geektrust/internal/core.provenance=${marker}"

mkdir -p "$DIST"
echo "build.sh: version $version"
echo "build.sh: digest  $digest"

# 2. Build both targets.
echo "build.sh: building linux/amd64 with $LINUX_GO"
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  "$LINUX_GO" build -buildmode=c-shared -trimpath -ldflags "$ldflags" \
  -o "$DIST/libgeektrust-linux-amd64.so" ./cmd/geektrustcore

echo "build.sh: building openharmony/arm64 with $OHOS_GOROOT"
CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$ANDROID_CC" \
  env -u GOROOT -u GOEXPERIMENT "$ANDROID_GO" build -buildmode=c-shared -trimpath \
  -ldflags "$ldflags" \
  -o "$DIST/libgeektrust-android-arm64.so" ./cmd/geektrustcore

CGO_ENABLED=1 GOOS=openharmony GOARCH=arm64 GOROOT="$OHOS_GOROOT" CC="$OHOS_CC" \
  PATH="$OHOS_GOROOT/bin:$PATH" \
  "$OHOS_GOROOT/bin/go" build -buildmode=c-shared -trimpath -ldflags "$ldflags" \
  -o "$DIST/libgeektrust-openharmony-arm64.so" ./cmd/geektrustcore

LINUX_SO="$DIST/libgeektrust-linux-amd64.so"
OHOS_SO="$DIST/libgeektrust-openharmony-arm64.so"
ANDROID_SO="$DIST/libgeektrust-android-arm64.so"
[ -f "$LINUX_SO" ] || fail "the linux build produced no $LINUX_SO"
[ -f "$OHOS_SO" ] || fail "the openharmony build produced no $OHOS_SO"

# 3. Assert what the app depends on.

# The OHOS artifact must resolve TLS through TLSDESC (the arm64 dynamic TLS
# model the OHOS loader implements); plain TPREL relocation would mean the
# toolchain linked a different model than the platform can run.
tls_relocs="$(readelf -Wr "$OHOS_SO" | grep TLS || true)"
if ! grep -q R_AARCH64_TLSDESC <<<"$tls_relocs"; then
  fail "no R_AARCH64_TLSDESC relocation in $OHOS_SO"
fi

# Every ABI entry point must be a dynamic symbol, or dlopen cannot find it.
symbols_expected=(geektrust_version geektrust_init geektrust_start_proxies geektrust_attach_tun_fd geektrust_status geektrust_close)
for so in "$LINUX_SO" "$OHOS_SO" "$ANDROID_SO"; do
  exported="$(nm -D "$so" | awk '{print $NF}' | grep '^geektrust_' | sort -u || true)"
  for symbol in "${symbols_expected[@]}"; do
    grep -qx "$symbol" <<<"$exported" || fail "$so does not export $symbol"
  done
  # The provenance marker has to be in the artifact's read-only data, verbatim:
  # that is what the app greps for before it trusts the library.
  grep -aqF "$marker" "$so" || fail "$so does not contain the provenance marker"
done

# 4. Report.
echo
echo "artifacts:"
ls -l "$LINUX_SO" "$OHOS_SO" | awk '{printf "  %s  %s bytes\n", $NF, $5}'
echo "marker:   $marker"
echo "digest:   $digest"
echo
echo "exported symbols:"
for so in "$LINUX_SO" "$OHOS_SO" "$ANDROID_SO"; do
  echo "  $(basename "$so"):"
  nm -D "$so" | awk '{print $NF}' | grep '^geektrust_' | sort -u | sed 's/^/    /'
done
echo
echo "TLS relocations in $(basename "$OHOS_SO"):"
sed 's/^/  /' <<<"$tls_relocs"
