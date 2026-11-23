#!/usr/bin/env bash
# Fixed v1.36 metadata-only dryruns; IGNORE is never an actual-create fallback.
set -euo pipefail
umask 077
[[ $# == 3 && -f $1 && -f $2 && -d $3 ]] || exit 2
PROFILE=$1
BASELINE=$2
OUT=$3/absent-api-fields
[[ ! -e $OUT && ! -L $OUT ]] || exit 2
mkdir -- "$OUT"
for tool in /usr/bin/kubectl /usr/bin/timeout jq grep; do command -v "$tool" >/dev/null; done
jq -e '(.spec|has("evictionResponders")|not) and (.spec.volumes[0].emptyDir|has("mode")|not) and (.spec.containers[0].volumeMounts[0]|has("bindMountOptions")|not)' "$PROFILE" >/dev/null
for id in evictionResponders emptyDir-mode bindMountOptions; do
 case $id in
 evictionResponders) mutation='.spec.evictionResponders=[{}]'; field='spec.evictionResponders';;
 emptyDir-mode) mutation='.spec.volumes[0].emptyDir.mode=493'; field='spec.volumes[0].emptyDir.mode';;
 bindMountOptions) mutation='.spec.containers[0].volumeMounts[0].bindMountOptions={}'; field='spec.containers[0].volumeMounts[0].bindMountOptions';;
 esac
 jq "$mutation" "$PROFILE" > "$OUT/$id.input.json"
 rc=0
 /usr/bin/timeout --signal=TERM --kill-after=2s 17s /usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --cache-dir=/opt/ilm-488-f01-api-cache-r1 --request-timeout=15s create --dry-run=server --validate=strict -f "$OUT/$id.input.json" -o json > "$OUT/$id.strict.stdout" 2> "$OUT/$id.strict.stderr" || rc=$?
 printf '%s\n' "$rc" > "$OUT/$id.strict.exit"
 [[ $rc == 1 ]]
 grep -Fq 'strict decoding error' "$OUT/$id.strict.stderr"
 grep -Fq "unknown field \"$field\"" "$OUT/$id.strict.stderr"
 if grep -Eq 'F01_|denied request|violates PodSecurity' "$OUT/$id.strict.stderr"; then exit 1; fi
 /usr/bin/timeout --signal=TERM --kill-after=2s 17s /usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --cache-dir=/opt/ilm-488-f01-api-cache-r1 --request-timeout=15s create --dry-run=server --validate=ignore -f "$OUT/$id.input.json" -o json > "$OUT/$id.ignore.json" 2> "$OUT/$id.ignore.stderr"
 # Equality covers every recognized field; no privilege/metadata mutation is ignored.
 jq -e --slurpfile baseline "$BASELINE" 'def stable: del(.status,.metadata.creationTimestamp,.metadata.uid,.metadata.resourceVersion,.metadata.generation,.metadata.managedFields); stable == ($baseline[0]|stable)' "$OUT/$id.ignore.json" >/dev/null
 done
printf '%s\n' 'THREE_FIELDS_STRICT_REJECTED_IGNORE_PRUNED_RECOGNIZED_PROFILE_UNCHANGED' > "$OUT/result.txt"
