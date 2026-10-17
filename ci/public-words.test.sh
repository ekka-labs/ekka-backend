#!/usr/bin/env bash
# public-words.test: the guard passes a clean tree, fails on each rule's
# planted red (groups A to D, commit messages, tracked bytecode and binaries,
# and the CI rule for the private names), passes the names and
# phrases each rule allows, ignores the third-party text it skips, and checks
# private names only when they are given to it.
set -uo pipefail
GUARD="$(cd "$(dirname "$0")" && pwd)/public-words.sh"
fails=0

fresh() {
  local d; d=$(mktemp -d)
  git -C "$d" init -q
  mkdir -p "$d/src" "$d/crates/openshell-proto/proto"
  printf 'fn main() {} // MUST_EQUAL is a name, not a word\n' > "$d/src/main.rs"
  printf 'Copyright (c) 2026 Example. Licensed under Apache-2.0.\n' > "$d/LICENSE"
  git -C "$d" add -A
  printf '%s' "$d"
}

expect() {  # expect <name> <want rc> <private words or ""> <file> <text>
  local name=$1 want=$2 private=$3 file=$4 text=$5 d rc
  d=$(fresh)
  if [ -n "$file" ]; then
    mkdir -p "$d/$(dirname "$file")"
    printf '%s\n' "$text" > "$d/$file"
    git -C "$d" add -A
  fi
  env -u GITHUB_ACTIONS PUBLIC_WORDS_PRIVATE="$private" bash "$GUARD" "$d" >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  if [ "$rc" -eq "$want" ]; then echo "ok    $name"; else echo "FAIL  $name: exit $rc, wanted $want"; fails=$((fails + 1)); fi
}

expect "a clean tree passes"                0 "" "" ""
expect "a link into the private org fails"  1 "" "src/a.rs" "// see https://github.com/ekka-ai/x"
expect "a private repo name fails"          1 "" "README.md" "Ported to ekka-runner later."
expect "a plan id fails"                    1 "" "src/a.rs" "// plan ADK-D6"
expect "a reviewer name fails"              1 "" "src/a.rs" "// MasterAgent said so"
expect "a build agent name fails"           1 "" "src/a.rs" "// agent2 owns this"
expect "a ticket number fails"              1 "" "src/a.rs" "// fixed in #1042"
expect "the owner as a person fails"        1 "" "src/a.rs" "// (owner, 2026-10-16)"
expect "a porting note fails"               1 "" "src/a.rs" "// ported from somewhere"
expect "a private name fails when given"    1 $'Acmecorp' "docs/x.md" "Acmecorp runs this."
expect "a private name is not known unless given" 0 "" "docs/x.md" "Acmecorp runs this."
# A private name is reported by place only: CI logs of a public repository are public.
d=$(fresh); printf 'Acmecorp runs this.\n' > "$d/docs.md"; git -C "$d" add -A
out=$(env -u GITHUB_ACTIONS PUBLIC_WORDS_PRIVATE=Acmecorp bash "$GUARD" "$d" 2>&1); rm -rf "$d"
if printf '%s' "$out" | grep -q Acmecorp; then echo "FAIL  a private name is never printed"; fails=$((fails + 1)); else echo "ok    a private name is never printed"; fi
expect "NVIDIA's protos are not scanned"    0 "" "crates/openshell-proto/proto/x.proto" "// see #1234"
expect "a Rust attribute is not a ticket"   0 "" "src/a.rs" "#[derive(Debug)] struct X;"
expect "a review tag fails"                 1 "" "src/a.rs" "// MISSING-2 from Codex"
expect "a plan item fails"                  1 "" "README.md" "Done in D5."
expect "a numbered rule fails"              1 "" "src/a.rs" "// see rule 12"
expect "a co-author line fails in a file"   1 "" "README.md" "Co-Authored-By: someone"

# A path on a build machine, in text and inside a binary; bytecode and binaries by name.
expect "a macOS home path fails"            1 "" "README.md" "Built in /Users/someone/src."
expect "a Linux home path fails"            1 "" "src/a.rs" "// from /home/alice/work"
expect "a macOS temp path fails"            1 "" "README.md" "See /private/tmp/x/y."
expect "a flattened home path fails"        1 "" "README.md" "Saved under -Users-someone-Projects."
expect "tracked bytecode fails"             1 "" "ci/__pycache__/g.cpython-314.pyc" "x"
expect "a tracked .pyc anywhere fails"      1 "" "tools/g.pyc" "x"
expect "a binary not on the list fails"     1 "" "assets/x.bin" $'\xff\xfe\x00binary'
# A binary on the list still fails with a build path inside it: the guard copied, with one name on its list.
d=$(fresh); mkdir -p "$d/assets" "$d/g"
printf '\xff\xfe/Users/someone/build\n' > "$d/assets/x.bin"; git -C "$d" add -A
sed 's/^BINARIES = frozenset()$/BINARIES = frozenset({"assets\/x.bin"})/' "$(dirname "$GUARD")/public_words.py" > "$d/g/public_words.py"
grep -q 'assets/x.bin' "$d/g/public_words.py" || { echo "FAIL  the listed-binary case could not be set up"; fails=$((fails + 1)); }
env -u GITHUB_ACTIONS python3 -B "$d/g/public_words.py" "$d" >/dev/null 2>&1; rc=$?
printf '\xff\xfe clean\n' > "$d/assets/x.bin"; env -u GITHUB_ACTIONS python3 -B "$d/g/public_words.py" "$d" >/dev/null 2>&1; rc2=$?
rm -rf "$d"
if [ "$rc" -eq 1 ] && [ "$rc2" -eq 0 ]; then echo "ok    a listed binary passes, and fails with a build path inside"; else echo "FAIL  a listed binary: exit $rc and $rc2, wanted 1 and 0"; fails=$((fails + 1)); fi

# In CI an empty PUBLIC_WORDS_PRIVATE stops the guard: a check that cannot run never passes.
ci() {  # ci <want rc> <private words or ""> <name> [--commits]
  local want=$1 private=$2 name=$3 d rc
  d=$(fresh); git -C "$d" -c user.name=EKKA -c user.email=ops@example.com commit -q -m "Plain message"
  GITHUB_ACTIONS=true PUBLIC_WORDS_PRIVATE="$private" bash "$GUARD" ${4:-} "$d" >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  if [ "$rc" -eq "$want" ]; then echo "ok    $name"; else echo "FAIL  $name: exit $rc, wanted $want"; fails=$((fails + 1)); fi
}
ci 2 "" "in CI, no private names stops the file check"
ci 2 "" "in CI, no private names stops the commit check" --commits
ci 0 "Acmecorp" "in CI, with private names, a clean tree passes"

# B: desk words, in Markdown prose and the strings code that ships shows.
expect "a sandbox in prose fails"           1 "" "README.md" "Each change runs in a sandbox."
expect "a gateway in prose fails"           1 "" "README.md" "The gateway restarts."
expect "a bare openshell in prose fails"    1 "" "README.md" "Run it beside openshell."
expect "a sandbox in a user string fails"   1 "" "src/a.rs" 'fn f() -> &'"'"'static str { "the sandbox is gone" }'
expect "NVIDIA OpenShell is allowed"        0 "" "README.md" "NVIDIA OpenShell is the desk backend this adapter supports today."
expect "(OpenShell) is allowed"             0 "" "README.md" "The desk backend (OpenShell) answers."
expect "NVIDIA OpenShell's gateway is allowed" 0 "" "README.md" "NVIDIA OpenShell's gateway replays a success."
expect "a name in backticks is not prose"   0 "" "README.md" 'It calls `GetSandbox` and needs `sandbox:write`.'
expect "an identifier with _ is not a word" 0 "" "README.md" "The record names its sandbox_id."
expect "a --flag is a name, not a word"     0 "" "README.md" "Pass --sandbox-name to pick one."
expect "a fenced block is not prose"        0 "" "README.md" $'```\nopenshell sandbox list\n```'
expect "a code comment may name the API"    0 "" "src/a.rs" "// GetSandbox on the gateway"
expect "a test's strings are not shown"     0 "" "src/a_tests.rs" 'const S: &str = "the sandbox is gone";'

# C: voice.
expect "a forecast fails"                   1 "" "README.md" "Recovery is not built yet."
expect "coming soon fails"                  1 "" "README.md" "Windows support is coming soon."
expect "an apology fails"                   1 "" "README.md" "Sorry, that is refused."
expect "plaintext fails"                    1 "" "README.md" "The file is plaintext."
expect "a price word fails"                 1 "" "README.md" "Updates are free."
expect "a coined verb fails"                1 "" "README.md" "A new token is minted."
expect "a forecast in a user string fails"  1 "" "src/a.rs" 'fn f() -> &'"'"'static str { "refused for now" }'

# D: style.
EM=$'\xe2\x80\x94'
expect "an em dash in a comment fails"      1 "" "src/a.rs" "// one ${EM} two"
expect "an em dash in prose fails"          1 "" "README.md" "One ${EM} two."
expect "vendored text keeps its em dash"    0 "" "vendor/contracts/x.md" "One ${EM} two."
expect "UK spelling in prose fails"         1 "" "README.md" "The adapter's behaviour is fixed."
expect "UK spelling in a comment fails"     1 "" "src/a.rs" "// the organisation's grant"
expect "an API name is not respelled"       0 "" "src/a.rs" "const C: i32 = Code::CANCELLED as i32;"

# Commit messages are public text: --commits reads every message from HEAD.
commit() {  # commit <want rc> <private words or ""> <name> <message>
  local want=$1 private=$2 name=$3 msg=$4 d rc
  d=$(fresh)
  git -C "$d" -c user.name=EKKA -c user.email=ops@example.com commit -q -m "$msg"
  env -u GITHUB_ACTIONS PUBLIC_WORDS_PRIVATE="$private" bash "$GUARD" --commits "$d" >/dev/null 2>&1
  rc=$?
  rm -rf "$d"
  if [ "$rc" -eq "$want" ]; then echo "ok    $name"; else echo "FAIL  $name: exit $rc, wanted $want"; fails=$((fails + 1)); fi
}
commit 0 "" "a plain commit message passes" $'Verify the gate token before any call\n\nThe token is checked first.'
commit 1 "" "a co-author trailer fails" $'Verify the gate token\n\nCo-Authored-By: Someone <someone@example.com>'
commit 1 "" "a private repo link in a commit fails" $'Verify the gate token\n\nRefs ekka-ai/x#1'
commit 1 "Acmecorp" "a private name in a commit fails" $'Verify the gate token for Acmecorp'

if [ "$fails" -gt 0 ]; then echo "public-words.test: $fails case(s) failed"; exit 1; fi
echo "public-words.test: all cases passed"
