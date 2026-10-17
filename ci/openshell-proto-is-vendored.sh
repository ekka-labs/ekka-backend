#!/usr/bin/env bash
# openshell-proto-is-vendored: crates/openshell-proto/proto holds NVIDIA
# OpenShell's .proto files and LICENSE exactly as NVIDIA published them at ONE
# commit, each .proto under a 4-line header naming that commit. Nothing else.
#
# A vendored file is never edited by hand. A new OpenShell version changes
# COMMIT and every hash below in the same change, and `--verify-upstream`
# proves the new hashes are NVIDIA's bytes. Before a new COMMIT, re-check in
# OpenShell's source that GetProvider and ListProviders still answer every
# credential value as `REDACTED` (at 5a7728c, v0.1.4: crates/openshell-server/
# src/grpc/provider.rs, redact_provider_credentials :55, applied :270, :287,
# :304, :564 and :2775): the adapter reads providers to digest them, and never
# expects a credential value.
#
# Why: the adapter trusts these types to say what the gateway sends. A quiet
# edit to one field would change what it reads and still compile. A CI job
# checks out one commit, so this gate cannot diff against an older one; the
# pinned hashes are what make an edit visible.
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
[ "$ROOT" = --verify-upstream ] && ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM=no
for a in "$@"; do [ "$a" = --verify-upstream ] && UPSTREAM=yes; done
DIR="$ROOT/crates/openshell-proto/proto"

COMMIT=5a7728c304b5528e954e9ae900cf21f84e1a12b1
PINNED="
datamodel.proto e50bd875a760f54b80269c65ee47984cae424fb623b7f59551ba62550c23e70b
extension.proto 60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad
gateway_interceptor.proto 905df827e50abb54ca1d2745341f38ad769cb3453c8c7301182590525f1da86f
openshell.proto eca4c0201ae623590c9deb6b0027a86b5193eb727d0e79c6852b40704d1a4d7d
options.proto b0e03562c92777978f6f3e0f46260cdb82f1d88d1c1837eab0e53cdd0f195eb7
sandbox.proto d06089ccd15b57519adb3236e7a4c16661c7c52c9f184f2f826246c62e090839
LICENSE d07c0367e2861e7fe70fa1b679f879f4fa2f9138ade4457d44ecf8b2e135bb45
"

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }
header() {
  printf '%s\n' "// Vendored from NVIDIA/OpenShell at commit $COMMIT (v0.1.4):" \
    "// https://github.com/NVIDIA/OpenShell/blob/$COMMIT/proto/$1" \
    "// Do not edit. ci/openshell-proto-is-vendored.sh refuses any change below this" \
    "// header unless the pinned commit and hashes in that gate change with it."
}

bad=0
refuse() { echo "openshell-proto-is-vendored: $1" >&2; bad=1; }

[ -d "$DIR" ] || { echo "openshell-proto-is-vendored: $DIR is missing" >&2; exit 1; }
# Every entry, hidden ones included: a dotfile is a file too.
for f in "$DIR"/* "$DIR"/.[!.]* "$DIR"/..?*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  n="$(basename "$f")"
  grep -q "^$n " <<<"$PINNED" || refuse "$n is not a pinned OpenShell file; vendor it from commit $COMMIT and pin its hash here"
done
while read -r n want; do
  [ -n "$n" ] || continue
  f="$DIR/$n"
  if [ ! -f "$f" ] || [ -L "$f" ]; then refuse "$n is missing (or a symlink); it must be the file from commit $COMMIT"; continue; fi
  if [ "$n" = LICENSE ]; then
    got="$(sha < "$f")"
  else
    [ "$(head -n 4 "$f")" = "$(header "$n")" ] || refuse "$n: the header does not name the pinned commit $COMMIT"
    got="$(tail -n +5 "$f" | sha)"
  fi
  [ "$got" = "$want" ] || refuse "$n differs from OpenShell at $COMMIT (sha256 $got, pinned $want): a vendored file is never edited; re-pin from a new commit instead"
  if [ "$UPSTREAM" = yes ]; then
    path="proto/$n"; [ "$n" = LICENSE ] && path=LICENSE
    up="$(curl -fsSL "https://raw.githubusercontent.com/NVIDIA/OpenShell/$COMMIT/$path" | sha)" || up=unreadable
    [ "$up" = "$want" ] || refuse "$n: the pinned hash is not NVIDIA's file at $COMMIT (upstream $up)"
  fi
done <<PINS
$PINNED
PINS

[ $bad -eq 0 ] && echo "openshell-proto-is-vendored: clean (OpenShell $COMMIT$( [ "$UPSTREAM" = yes ] && echo ', verified against GitHub'))"
exit $bad
