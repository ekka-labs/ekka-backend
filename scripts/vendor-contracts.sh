#!/usr/bin/env bash
# vendor-contracts.sh: copy the contract files the adapter reads, at one
# released tag of a contracts checkout, into vendor/contracts, and record the
# tag and each file's sha256: `backend/` (its README aside), the desk grant
# limits and the gate-token schema. The adapter's sync tests read this copy,
# so CI needs no other checkout.
#
#   scripts/vendor-contracts.sh <tag> <path-to-contracts-checkout>
set -euo pipefail
REF="${1:?usage: scripts/vendor-contracts.sh <tag> <path-to-contracts-checkout>}"
SRC="${2:?usage: scripts/vendor-contracts.sh <tag> <path-to-contracts-checkout>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/vendor/contracts"
[ -d "$SRC/.git" ] || { echo "error: no contracts checkout at $SRC" >&2; exit 1; }
git -C "$SRC" rev-parse -q --verify "$REF^{commit}" >/dev/null || { echo "error: no tag $REF in $SRC" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$DEST"
git -C "$SRC" archive "$REF" -- backend governance/grant-constraints governance/gate-token.schema.json | tar -x -C "$DEST"
rm -f "$DEST/backend/README.md"
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }
{
  echo "contracts $REF"
  echo "Copied unchanged by scripts/vendor-contracts.sh. Do not hand-edit these files."
  (cd "$DEST" && find . -type f ! -name CONTRACTS_PIN | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
    printf '%s  %s\n' "$(sha < "$f")" "$f"
  done)
} > "$DEST/CONTRACTS_PIN.tmp"
mv "$DEST/CONTRACTS_PIN.tmp" "$DEST/CONTRACTS_PIN"
echo "vendored the contract files the adapter reads, at $REF"
