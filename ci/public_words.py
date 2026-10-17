#!/usr/bin/env python3
"""public-words: this repository is public, so its text must read as product
text. Exits 1 and prints every hit; exits 0 when the tree is clean.

Four groups of rules:

  A  internal history, anywhere, comments included: links into a private
     organization, internal plan and review ids, reviewer and build-agent
     names, ticket numbers, porting notes, and a path on a build machine.
     A tracked Python bytecode file fails by its name: it carries the path it
     was compiled from. A binary file (one that is not UTF-8) fails unless
     BINARIES names it, and even then a path on a build machine inside it
     fails.
  B  desk words, in Markdown prose and user-facing strings: "desk" and "desk
     backend", never a bare sandbox, gateway or openshell. "NVIDIA OpenShell",
     "(OpenShell)" and "NVIDIA OpenShell's gateway" are allowed.
  C  voice, in Markdown prose and user-facing strings: a limit is a fact, never
     a forecast or an apology.
  D  style: no em dash anywhere this repository writes; US spelling in
     Markdown prose, comments and user-facing strings (an external API's
     name, such as gRPC's CANCELLED, is not a word to respell).

Markdown prose is a .md file with its fenced code blocks and backtick spans
removed. A user-facing string is a Rust string literal that contains a space,
in code that ships (not tests). In either, a `--flag` and an identifier with
an underscore are names, not words.

Commit messages are public text too. With --commits, every commit message
reachable from HEAD is checked against group A and the private names, and a
Co-Authored-By trailer fails: the public history carries only the project's
own identity.

Names that must not appear here cannot be listed here either, since that would
publish them: they come from the environment, one regular expression per line
in PUBLIC_WORDS_PRIVATE, which CI sets from a repository secret. A hit on one
is reported by file and line only, never the word, because the CI logs of a
public repository are public. In CI (GITHUB_ACTIONS=true) an empty
PUBLIC_WORDS_PRIVATE stops the guard with exit 2: a check that cannot run
never passes.

Skipped: text this repository does not write (NVIDIA's OpenShell protocol
files, the license and notice texts, the generated third-party notices,
Cargo.lock) and this guard and its test, which must name what they look for.

    python3 ci/public_words.py [<repo root>]
    python3 ci/public_words.py --commits [<repo root>]
"""
import os
import re
import subprocess
import sys

A = [
    r"ekka-ai/",
    r"@ekka-ai\b",
    r"\bekka-(runner|workspace|contracts|agent-desks|openshell-adapter|openshell-executor)\b",
    r"\bADK-[A-Z][0-9]+[a-z]?\b",
    r"\b[CDEG][0-9]{1,2}[a-z]?\b",
    r"\bCodex\b",
    r"\b(MISSING|WRONG)-[0-9]+\b",
    r"\b[Aa]gent[0-9]+\b",
    r"\bMasterAgent\b",
    r"(?i)\bowner\b[^.\n]{0,20}(rule|ruling|20[0-9]{2}-)",
    r"(?i)\bper the owner\b",
    r"\(owner,",
    r"(?i)\brule [0-9]+\b",
    r"(^|[^&\w/])#[0-9]{2,}\b",
    r"(?i)\bported from\b",
    r"(?i)\bco-authored-by\b",
]
LOCAL_PATH = r"/Users/[^/\s]+/|/home/[a-z_][a-z0-9_-]*/|/private/tmp/|/private/var/folders/|-Users-[A-Za-z0-9]"
A.append(LOCAL_PATH)
BYTECODE = re.compile(r"(^|/)__pycache__/|\.py[co]$")
# The binary files this repository means to publish. None today: a new one is added here on purpose, in review.
BINARIES = frozenset()
TRAILER = r"(?i)^co-authored-by:"
B = [r"(?i)\bsandbox(es)?\b", r"(?i)\bgateways?\b", r"(?i)\bopenshell\b"]
B_ALLOWED = re.compile(r"NVIDIA OpenShell's gateway|NVIDIA OpenShell|\(OpenShell\)")
C = [
    r"(?i)\bnot\b[^.\n]{0,60}\byet\b|\bcoming soon\b|\bfor now\b|\buntil then\b|\bknown gaps?\b",
    r"(?i)\b(sorry|apolog\w*|unfortunately|sadly)\b",
    r"(?i)\bplain ?text\b",
    r"(?i)\b(free|unlimited)\b",
    r"(?i)\buninvite\b|\bmint(s|ed|ing)?\b",
    r"(?i)\byou should never\b|\bnever do this\b",
]
EM_DASH = "\u2014"
UK = [
    r"(?i)\b(licence|behaviour|authoris\w*|organis\w*|colour|favour|analyse[sd]?|catalogu\w+|centre|defence"
    r"|whilst|(un)?recognis(e|es|ed|ing|able)|enrolment|fulfil|customis(e|es|ed|ing|ation)"
    r"|standardis(e|es|ed|ing|ation)|normalis(e|es|ed|ing|ation)|initialis(e|es|ed|ing|ation)"
    r"|prioritis(e|es|ed|ing|ation)|summaris(e|es|ed|ing|ation)|utilis(e|es|ed|ing|ation)"
    r"|specialis(e|es|ed|ing|ation)|minimis(e|es|ed|ing|ation)|maximis(e|es|ed|ing|ation)"
    r"|optimis(e|es|ed|ing|ation)|apologis(e|es|ed|ing)|travell(ed|ing)|labell(ed|ing)"
    r"|modell(ed|ing)|cancell(ed|ing)|programme)\b",
]

SKIP = re.compile(
    r"^(crates/openshell-proto/proto/|LICENSE$|NOTICE$|THIRD-PARTY-NOTICES\.md$|Cargo\.lock$"
    r"|ci/public_words\.py$|ci/public-words(\.test)?\.sh$)"
)
VENDORED = re.compile(r"^vendor/")
TEST_CODE = re.compile(r"(_tests\.rs$|/tests/|^crates/ekka-backend-fakegw/|/testkit\.rs$)")
NAMES = re.compile(r"--[a-z][a-z-]*|\b\w*_\w*\b")
STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def prose(text):
    """Markdown with its fenced code blocks and backtick spans blanked, line by line."""
    out, fenced = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else re.sub(r"`[^`]*`", "", line))
    return out


def user_strings(text):
    """Each line's Rust string literals that contain a space, joined; comments skipped."""
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append("")
            continue
        out.append(" | ".join(s for s in STRING.findall(line) if " " in s))
    return out


def comments(text):
    """Each line's comment text (after //), backtick spans removed; code lines blank."""
    out = []
    for line in text.split("\n"):
        i = line.find("//")
        out.append(re.sub(r"`[^`]*`", "", line[i + 2:]) if i >= 0 else "")
    return out


def scan(lines, patterns, path, hits, show=True, desk_words=False):
    for n, line in enumerate(lines, 1):
        text = line
        if desk_words:
            text = NAMES.sub("", B_ALLOWED.sub("", text))
        for p in patterns:
            if re.search(p, text):
                where = f"{path}:{n}"
                hits.append(f"{where}: {line.strip()[:160]}" if show else f"{where}: a private name")
                break


def commits(root, private):
    """Every commit message reachable from HEAD, checked against group A and the private names."""
    try:
        log = subprocess.run(["git", "log", "--format=%x00%h%n%B"], cwd=root, capture_output=True, text=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        print("public-words: no commits to read", file=sys.stderr)
        return 2
    hits = []
    for entry in log.split("\x00")[1:]:
        sha, _, body = entry.partition("\n")
        lines = body.split("\n")
        scan(lines, A + [TRAILER], f"commit {sha}", hits)
        scan(lines, private, f"commit {sha}", hits, show=False)
    for h in hits:
        print(f"public-words: {h}")
    if hits:
        print(f"public-words: {len(hits)} commit message line(s) need plain product words", file=sys.stderr)
        return 1
    print("public-words: commit messages clean")
    return 0


def main(argv):
    args = argv[1:]
    check_commits = "--commits" in args
    args = [a for a in args if a != "--commits"]
    root = args[0] if args else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split("\n")
    except (OSError, subprocess.CalledProcessError):
        print("public-words: not a git checkout", file=sys.stderr)
        return 2
    private = [p for p in os.environ.get("PUBLIC_WORDS_PRIVATE", "").split("\n") if p.strip()]
    if not private:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("public-words: PUBLIC_WORDS_PRIVATE is empty in CI, so private names cannot be checked; "
                  "set the repository secret PUBLIC_WORDS_PRIVATE", file=sys.stderr)
            return 2
        print("public-words: PUBLIC_WORDS_PRIVATE is not set; private names are not checked", file=sys.stderr)
    if check_commits:
        return commits(root, private)
    hits = []
    for path in files:
        if not path:
            continue
        if BYTECODE.search(path):
            hits.append(f"{path}: Python bytecode is tracked; it carries the path it was compiled from")
            continue
        if SKIP.search(path):
            continue
        try:
            with open(os.path.join(root, path), "rb") as f:
                raw = f.read()
        except OSError:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            if path not in BINARIES:
                hits.append(f"{path}: a binary file that BINARIES in ci/public_words.py does not name")
            elif re.search(LOCAL_PATH.encode(), raw):
                hits.append(f"{path}: a binary file carries a path on a build machine")
            continue
        lines = text.split("\n")
        scan(lines, A, path, hits)
        scan(lines, private, path, hits, show=False)
        if VENDORED.search(path):
            continue
        scan(lines, [EM_DASH], path, hits)
        if path.endswith(".md"):
            p = prose(text)
            scan(p, B, path, hits, desk_words=True)
            scan(p, C, path, hits)
            scan(p, UK, path, hits)
        elif path.endswith(".rs"):
            scan(comments(text), UK, path, hits)
            if not TEST_CODE.search(path):
                s = user_strings(text)
                scan(s, B, path, hits, desk_words=True)
                scan(s, C, path, hits)
                scan(s, UK, path, hits)
    for h in hits:
        print(f"public-words: {h}")
    if hits:
        print(f"public-words: {len(hits)} line(s) need plain product words; say what it does, not where it came from",
              file=sys.stderr)
        return 1
    print("public-words: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
