#!/usr/bin/env bash
# public-words: see ci/public_words.py for the rules.
#   bash ci/public-words.sh [<repo root>]
exec python3 "$(cd "$(dirname "$0")" && pwd)/public_words.py" "$@"
