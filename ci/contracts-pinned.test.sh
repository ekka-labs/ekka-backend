#!/usr/bin/env bash
# contracts-pinned.test: the check passes this repository's vendored copy, and
# fails on each way the copy can stop being the released one: an edited file,
# an extra file (a stray temporary pin among them), a missing file, a symbolic
# link (to a file outside, or one that copies a pinned file's bytes), a pin
# that names no version.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="$HERE/contracts-pinned.sh"
fails=0

case_() {  # case_ <name> <want rc> <command run inside the copy>
  local name=$1 want=$2 d rc
  d=$(mktemp -d)
  mkdir -p "$d/vendor"
  cp -R "$HERE/../vendor/contracts" "$d/vendor/"
  (cd "$d/vendor/contracts" && eval "$3")
  bash "$CHECK" "$d" >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  if [ "$rc" -eq "$want" ]; then echo "ok    $name"; else echo "FAIL  $name: exit $rc, wanted $want"; fails=$((fails + 1)); fi
}

case_ "the vendored copy passes"              0 "true"
case_ "an edited file fails"                  1 "printf ' ' >> backend/settle-marker.v1.schema.json"
case_ "an extra file fails"                   1 "printf '{}' > backend/extra.json"
case_ "a stray temporary pin fails"           1 "cp CONTRACTS_PIN CONTRACTS_PIN.tmp"
case_ "a missing file fails"                  1 "rm backend/settle-marker.v1.schema.json"
case_ "a link to a file outside fails"        1 "ln -s /etc/hosts backend/hosts.json"
case_ "a link in place of a pinned file fails" 1 "cp backend/settle-marker.v1.schema.json ../m.json && rm backend/settle-marker.v1.schema.json && ln -s ../../m.json backend/settle-marker.v1.schema.json"
case_ "a pin that names no version fails"     1 "sed -i.bak '1s/.*/contracts main/' CONTRACTS_PIN && rm CONTRACTS_PIN.bak"
case_ "no pin at all fails"                   1 "rm CONTRACTS_PIN"

# A link ABOVE the files: vendor/contracts, or vendor/ itself, pointing at an exact copy elsewhere. The bytes all
# match the pin, so only the link refusal can catch it.
top_link() {  # top_link <name> <which: contracts | vendor>
  local name=$1 d out rc
  d=$(mktemp -d); out=$(mktemp -d)
  mkdir -p "$out/vendor"
  cp -R "$HERE/../vendor/contracts" "$out/vendor/"
  if [ "$2" = contracts ]; then mkdir -p "$d/vendor"; ln -s "$out/vendor/contracts" "$d/vendor/contracts"
  else ln -s "$out/vendor" "$d/vendor"; fi
  bash "$CHECK" "$d" >/dev/null 2>&1
  rc=$?
  rm -rf "$d" "$out"
  if [ "$rc" -eq 1 ]; then echo "ok    $name"; else echo "FAIL  $name: exit $rc, wanted 1"; fails=$((fails + 1)); fi
}
top_link "vendor/contracts as a link fails" contracts
top_link "vendor as a link fails" vendor

# A link named with a space and a glob character is reported as one name, never split or expanded.
d=$(mktemp -d); mkdir -p "$d/vendor"; cp -R "$HERE/../vendor/contracts" "$d/vendor/"
ln -s /etc/hosts "$d/vendor/contracts/backend/a b*.json"
msg=$(bash "$CHECK" "$d" 2>&1 >/dev/null); rm -rf "$d"
if printf '%s\n' "$msg" | grep -qxF '  backend/a b*.json'; then echo "ok    a link's name is reported whole"
else echo "FAIL  a link's name is reported whole: $msg"; fails=$((fails + 1)); fi

if [ "$fails" -gt 0 ]; then echo "contracts-pinned.test: $fails case(s) failed"; exit 1; fi
echo "contracts-pinned.test: all cases passed"
