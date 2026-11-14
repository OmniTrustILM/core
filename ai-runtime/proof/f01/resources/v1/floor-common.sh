#!/usr/bin/env bash
# Shared output, result recording and floor checks for fixed callers.
prepare_output() {
  [[ $# == 2 ]] || return 2
  OUT=$(realpath -m -- "$1")
  # In the repository protect the whole worktree; in a standalone fixture protect its whole source copy.
  WORKTREE=$(cd -- "$2/../.." && pwd -P)
  if [[ $WORKTREE == */ai-runtime/proof/f01 ]]; then WORKTREE=$(cd -- "$WORKTREE/../../.." && pwd -P); fi
  [[ $OUT != "$WORKTREE" && $OUT != "$WORKTREE"/* ]] || exit 2
  mkdir -p -- "$OUT"
}
record() {
 local id=$1 status=$2 expected=$3 actual=$4 reason=$5 file=$6
 printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$status" "$expected" "$actual" "$reason" "$(sha256sum "$file" | cut -d' ' -f1)" >> "$OUT/results.tsv"
 [[ $status == PASS ]] || FAILED=1
}
canonical_floor() {
  jq -S 'del(.status, .metadata.creationTimestamp, .metadata.generation, .metadata.resourceVersion, .metadata.uid, .metadata.managedFields, .metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]) | if .metadata.annotations == {} then del(.metadata.annotations) else . end'
}
require_floor() {
  [[ $# == 3 ]] || return 2
  case $3 in create|refuse) :;; *) return 2;; esac
  local manifest=$1 tag=$2 missing_action=$3 count index rv attempt
  k create --dry-run=client -f "$manifest" -o json | jq -s '[.[] | if .kind == "List" then .items[] else . end]' > "$OUT/$tag.source.json"
  count=$(jq length "$OUT/$tag.source.json")
  for ((index=0; index<count; index++)); do
    jq --argjson i "$index" '.[$i] | if .kind == "Namespace" then .spec.finalizers=["kubernetes"] else . end' "$OUT/$tag.source.json" > "$OUT/$tag-$index.input.json"
    k get -f "$OUT/$tag-$index.input.json" --ignore-not-found -o json > "$OUT/$tag-$index.live.json"
    if [[ ! -s $OUT/$tag-$index.live.json ]]; then
      if [[ $missing_action == refuse ]]; then
        echo "Missing installed authority; refusing creation" >&2; return 1
      fi
      k create -f "$OUT/$tag-$index.input.json" -o json > "$OUT/$tag-$index.live.json"
    fi
    for attempt in 1 2; do
      k get -f "$OUT/$tag-$index.input.json" -o json > "$OUT/$tag-$index.live.json"
      rv=$(jq -r '.metadata.resourceVersion' "$OUT/$tag-$index.live.json")
      jq --arg rv "$rv" '.metadata.resourceVersion=$rv' "$OUT/$tag-$index.input.json" > "$OUT/$tag-$index.replace.json"
      if k replace --dry-run=server -f "$OUT/$tag-$index.replace.json" -o json > "$OUT/$tag-$index.expected.json" 2> "$OUT/$tag-$index.replace-$attempt.err"; then break; fi
      if [[ $attempt == 2 ]] || ! grep -Fq 'Error from server (Conflict):' "$OUT/$tag-$index.replace-$attempt.err"; then
        cat "$OUT/$tag-$index.replace-$attempt.err" >&2
        return 1
      fi
    done
    canonical_floor < "$OUT/$tag-$index.live.json" > "$OUT/$tag-$index.actual.canonical.json"
    canonical_floor < "$OUT/$tag-$index.expected.json" > "$OUT/$tag-$index.expected.canonical.json"
    if ! cmp "$OUT/$tag-$index.actual.canonical.json" "$OUT/$tag-$index.expected.canonical.json" > "$OUT/$tag-$index.compare.txt"; then
      echo "Refusing drifted task floor object $tag/$index; review and replace it explicitly." >&2
      return 1
    fi
  done
}
