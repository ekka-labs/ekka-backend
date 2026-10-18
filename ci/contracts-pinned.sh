#!/usr/bin/env bash
# contracts-pinned: vendor/contracts holds exactly the files CONTRACTS_PIN lists,
# each with the sha256 it records, under a `contracts vX.Y.Z` header, and no
# symbolic link: contract files are plain files, and a link is never listed by
# content, so it could point anywhere and still pass. The
# gitleaks allowlist and the adapter's sync tests both rely on this copy being
# the released one, so a hand edit, an extra file or a missing one fails here.
#
#   ci/contracts-pinned.sh [<repo root>]     check
#   ci/contracts-pinned.sh --list <dir>      print the pin lines for <dir>
#                                            (scripts/vendor-contracts.sh uses it)
set -euo pipefail

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }

list() {  # every file under $1 but the pin itself, sorted, as "<sha256>  <path>"
  (cd "$1" && find . -type f ! -name CONTRACTS_PIN | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
    printf '%s  %s\n' "$(sha < "$f")" "$f"
  done)
}

if [ "${1:-}" = "--list" ]; then
  list "${2:?usage: ci/contracts-pinned.sh --list <dir>}"
  exit 0
fi

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DEST="$ROOT/vendor/contracts"
PIN="$DEST/CONTRACTS_PIN"
# A link above the files too: `cd` and `find` follow it, so vendor/ or vendor/contracts as a link to another copy
# would be checked in place of this repository's own.
for top in "$ROOT/vendor" "$DEST"; do
  if [ -L "$top" ]; then
    echo "contracts-pinned: ${top#"$ROOT"/} is a symbolic link; it must be a real folder in this repository" >&2
    exit 1
  fi
done
[ -f "$PIN" ] || { echo "contracts-pinned: $PIN is missing; run scripts/vendor-contracts.sh <tag> <checkout>" >&2; exit 1; }
links=$(cd "$DEST" && find . -type l | sed 's|^\./||' | LC_ALL=C sort)
if [ -n "$links" ]; then
  echo "contracts-pinned: vendor/contracts holds a symbolic link; contract files are plain files:" >&2
  printf '%s\n' "$links" | sed 's/^/  /' >&2
  echo "contracts-pinned: re-run scripts/vendor-contracts.sh <tag> <checkout>" >&2
  exit 1
fi
head -1 "$PIN" | grep -Eq '^contracts v[0-9]+\.[0-9]+\.[0-9]+$' \
  || { echo "contracts-pinned: the first line of CONTRACTS_PIN is not 'contracts vX.Y.Z'" >&2; exit 1; }
want=$(tail -n +3 "$PIN")
have=$(list "$DEST")
if [ "$want" != "$have" ]; then
  echo "contracts-pinned: vendor/contracts does not match CONTRACTS_PIN (- pinned, + on disk):" >&2
  diff <(printf '%s\n' "$want") <(printf '%s\n' "$have") | grep -E '^[<>]' | sed 's/^</-/; s/^>/+/' >&2 || true
  echo "contracts-pinned: re-run scripts/vendor-contracts.sh <tag> <checkout>; never edit vendored files by hand" >&2
  exit 1
fi
echo "contracts-pinned: $(head -1 "$PIN"), $(printf '%s\n' "$have" | wc -l | tr -d ' ') files match"
