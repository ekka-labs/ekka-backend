#!/usr/bin/env bash
# contracts-pinned.test: the check passes this repository's vendored copy, and
# fails on each way the copy can stop being the released one: an edited file,
# an extra file (a stray temporary pin among them), a missing file, a pin that
# names no version.
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
case_ "a pin that names no version fails"     1 "sed -i.bak '1s/.*/contracts main/' CONTRACTS_PIN && rm CONTRACTS_PIN.bak"
case_ "no pin at all fails"                   1 "rm CONTRACTS_PIN"

if [ "$fails" -gt 0 ]; then echo "contracts-pinned.test: $fails case(s) failed"; exit 1; fi
echo "contracts-pinned.test: all cases passed"
