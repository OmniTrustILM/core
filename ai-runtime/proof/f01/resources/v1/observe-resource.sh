#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID == 0 && ( $# == 2 || $# == 3 ) && $1 == /* && -f $1 && $2 == /* && ! -e $2 ]] || { printf '%s\n' F01_OBSERVER_INPUT_REFUSED >&2; exit 2; }
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export BASE
WORKTREE=$(cd -- "$BASE/../.." && pwd -P)
if [[ $WORKTREE == */ai-runtime/proof/f01 ]]; then WORKTREE=$(cd -- "$WORKTREE/../../.." && pwd -P); fi
OUT=$(realpath -m -- "$2")
[[ $OUT != "$WORKTREE" && $OUT != "$WORKTREE"/* ]] || { printf '%s\n' F01_OBSERVER_OUTPUT_REFUSED >&2; exit 2; }
exec python3 -I -S -B "$BASE/python/observer.py" "$1" "$OUT" "${3-}" < /dev/null
