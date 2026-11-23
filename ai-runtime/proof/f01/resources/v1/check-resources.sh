#!/usr/bin/env bash
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'Supply one new absolute evidence directory.' >&2; exit 2; }
for tool in jq sha256sum sort cmp cut find xargs bash grep dirname basename tail; do command -v "$tool" >/dev/null; done
PARENT=$(cd -- "$(dirname -- "$1")" && pwd -P)
NAME=$(basename -- "$1")
[[ $NAME != . && $NAME != .. && $NAME != / ]]
OUT="$PARENT/$NAME"
# In the repository protect the whole worktree; in a standalone fixture protect its whole source copy.
WORKTREE=$(cd -- "$BASE/../.." && pwd -P)
if [[ $WORKTREE == */ai-runtime/proof/f01 ]]; then WORKTREE=$(cd -- "$WORKTREE/../../.." && pwd -P); fi
[[ ! -e $OUT && $OUT != "$WORKTREE" && $OUT != "$WORKTREE"/* ]] || exit 2
mkdir -- "$OUT"
cd "$BASE"
find . -type f -print | LC_ALL=C sort | while IFS= read -r p; do sha256sum "$p"; done > "$OUT/sources.sha256"
jq -e '.profile == "a2-v1" and .fixtureRevision == 2 and .kubernetes == "v1.36.1" and .containerd == "2.3.1" and .gvisor == "release-20261019.0" and .architecture == "arm64" and .platform == "systrap" and .busybox == "docker.io/library/busybox@sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c" and .negativeCases == 67 and (.a1Sources | length == 72) and (.profiles | length == 9)' versions.yaml > "$OUT/pins.txt"
jq -e '
 (.a1Sources | all(.[]; type=="string" and test("^[0-9a-f]{64}$"))) and
 (.profiles | all(.[]; (.sha256|type=="string" and test("^[0-9a-f]{64}$")) and (.bodySha256|type=="string" and test("^[0-9a-f]{64}$")))) and
 (.authoritySha256 | keys==["namespace.yaml","pod-floor.yaml"] and all(.[];type=="string" and test("^[0-9a-f]{64}$")))' versions.yaml > "$OUT/hash-pins.txt"
# Independently count the closed whitelist; authority file pins alone do not prove profile agreement.
jq -e '[.items[0].spec.validations[]|select(.message=="F01_EXECUTABLE")|.expression] |
 length==1 and (.[0]|[scan("object.metadata.name == \"f01-a2-")]|length)==9' pod-floor.yaml > "$OUT/tuple-count.txt"
jq -r '.a1Sources | to_entries[] | [.key,.value] | @tsv' versions.yaml | while IFS=$'\t' read -r p hash; do
 [[ $p != /* && $p != *..* && -f ../../$p ]]
 [[ $(sha256sum "../../$p" | cut -d' ' -f1) == "$hash" ]]
 printf '%s\t%s\n' "$p" "$hash"
done > "$OUT/a1-sources.tsv"
jq -r '.profiles | keys[]' versions.yaml > "$OUT/profile-ids.txt"
for file in profiles/*.yaml; do basename "$file" .yaml; done | LC_ALL=C sort > "$OUT/profile-files.txt"
cmp "$OUT/profile-ids.txt" "$OUT/profile-files.txt"
while IFS= read -r id; do
 file="profiles/$id.yaml"
 [[ $(sha256sum "$file" | cut -d' ' -f1) == "$(jq -r --arg id "$id" '.profiles[$id].sha256' versions.yaml)" ]]
 jq -e --arg id "$id" --arg image "$(jq -r .busybox versions.yaml)" '.kind == "Pod" and .metadata == {name:("f01-a2-"+$id),namespace:"ilm-sandbox-a2",labels:{"ilm.ai/proof":"a2-v1"}} and .spec.runtimeClassName == "runsc-f01-a2-v1" and .spec.activeDeadlineSeconds == 27 and .spec.terminationGracePeriodSeconds == 1 and .spec.restartPolicy == "Never" and .spec.automountServiceAccountToken == false and .spec.securityContext.runAsUser == 65532 and .spec.securityContext.runAsGroup == 65532 and (.spec.containers | length == 1) and .spec.containers[0].image == $image and .spec.containers[0].command == ["/bin/busybox","ash","-c"] and (.spec.containers[0].args | length == 1) and (.spec.containers[0] | has("env") or has("envFrom") | not) and .spec.containers[0].securityContext == {allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}} and .spec.containers[0].resources == {requests:{cpu:"100m",memory:"64Mi","ephemeral-storage":"16Mi"},limits:{cpu:"500m",memory:"256Mi","ephemeral-storage":"32Mi"}} and .spec.volumes == [{name:"scratch",emptyDir:{medium:"Memory",sizeLimit:"16Mi"}}] and .spec.containers[0].volumeMounts == [{name:"scratch",mountPath:"/scratch"},{name:"scratch",mountPath:"/tmp"}]' "$file" >/dev/null
 jq -r '.spec.containers[0].args[0]' "$file" | bash -n
 body_hash=$(jq -j '.spec.containers[0].args[0]' "$file" | sha256sum | cut -d' ' -f1)
 [[ $body_hash == "$(jq -r --arg id "$id" '.profiles[$id].bodySha256' versions.yaml)" ]]
 jq -e --slurpfile p "$file" '
 $p[0] as $p | ("(object.metadata.name == " + ($p.metadata.name|tojson) +
 " && object.metadata.labels[\"ilm.ai/proof\"] == " + ($p.metadata.labels["ilm.ai/proof"]|tojson) +
 " && variables.c.command == [" + ($p.spec.containers[0].command|map(tojson)|join(", ")) +
 "] && variables.c.args == [" + ($p.spec.containers[0].args[0]|tojson) + "])") as $tuple |
 [.items[0].spec.validations[]|select(.message=="F01_EXECUTABLE")|.expression] |
 length==1 and (.[0]|contains($tuple))' pod-floor.yaml > "$OUT/tuple-$id.txt"
 printf '%s\t%s\n' "$id" "$body_hash"
done < "$OUT/profile-ids.txt" > "$OUT/profiles.tsv"
for f in namespace.yaml pod-floor.yaml; do
 jq -e '.kind == "List"' "$f" >/dev/null
 [[ $(sha256sum "$f" | cut -d' ' -f1) == "$(jq -r --arg f "$f" '.authoritySha256[$f]' versions.yaml)" ]]
done
jq -Rse --slurpfile policy pod-floor.yaml '
 ($policy[0].items[0].spec.validations|map(.message)) as $reasons |
 endswith("\n") and (split("\n")[:-1] |
 .[0] == "case\toperation\texpected_layer\texpected_reason\tfixed_input" and length == 68 and
 (.[1:] | map(split("\t")) |
 all(length == 5 and (.[0]|test("^[A-Za-z][A-Za-z0-9-]*$")) and
 (.[1]|IN("CREATE","UPDATE","ephemeralcontainers","resize")) and
 (. as $row | ($row[2]=="PSA" and $row[3]=="RESTRICTED") or ($row[2]=="CEL" and ($reasons|index($row[3]))!=null))) and
 (map(.[0])|unique|length)==67))' cases.tsv > "$OUT/case-validation.txt"
cut -f1 cases.tsv | tail -n +2 | LC_ALL=C sort > "$OUT/case-ids.txt"
{ for p in ../../admission/v1/mutations/*.json mutations/*.json; do basename "$p" .json; done; } | LC_ALL=C sort > "$OUT/fixture-ids.txt"
cmp "$OUT/case-ids.txt" "$OUT/fixture-ids.txt"
while IFS=$'\t' read -r id operation layer reason input; do
 [[ $id == case ]] && continue
 [[ $input == "../../admission/v1/mutations/$id.json" || $input == "mutations/$id.json" ]]
 jq -e 'type=="array" and length>0 and all(type=="object" and (.op|IN("add","replace","remove")) and (.path|type=="string" and startswith("/")))' "$input" >/dev/null
 printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$operation" "$layer" "$reason" "$input"
done < cases.tsv > "$OUT/cases.tsv"
# Source is deliberately generic: reject accidental local task/credential material.
scan_rc=0
grep -nE '/Users/|/home/lab/|/private/tmp/|BEGIN .*PRIVATE KEY|Authorization:|TODO|FIXME' README.md versions.yaml namespace.yaml pod-floor.yaml prepare-runtime.sh run-floor-control.sh run-resources.sh observe-resource.sh python/*.py cases.tsv profiles/*.yaml mutations/*.json > "$OUT/forbidden.txt" 2> "$OUT/forbidden.err" || scan_rc=$?
[[ $scan_rc == 1 ]]
printf '%s\n' 'PASS fixed assets, frozen authority/profile bytes, 67-case bijection, exact 72 current portable A1-family file pins; numeric coverage N/A.' > "$OUT/result.txt"
cat "$OUT/result.txt"
