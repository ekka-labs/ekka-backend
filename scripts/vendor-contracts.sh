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
# The listing is ci/contracts-pinned.sh's, so writing the pin and checking it can never disagree. It is built
# outside vendor/contracts: a temporary file inside would be listed as one of the contract's own.
PIN_TMP=$(mktemp)
trap 'rm -f "$PIN_TMP"' EXIT
{
  echo "contracts $REF"
  echo "Copied unchanged by scripts/vendor-contracts.sh. Do not hand-edit these files."
  bash "$ROOT/ci/contracts-pinned.sh" --list "$DEST"
} > "$PIN_TMP"
mv "$PIN_TMP" "$DEST/CONTRACTS_PIN"
bash "$ROOT/ci/contracts-pinned.sh" "$ROOT"
echo "vendored the contract files the adapter reads, at $REF"
