#!/usr/bin/env bash
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'Supply one new absolute evidence directory.' >&2; exit 2; }
for tool in jq sha256sum findmnt realpath awk xargs find cmp sort cut tail grep paste uname df sleep cat pgrep readlink; do command -v "$tool" >/dev/null; done
OUT=$(realpath -m -- "$1")
[[ $OUT != "$BASE" && $OUT != "$BASE"/* ]] || { echo 'Evidence must be outside the source directory.' >&2; exit 2; }
[[ ! -e $OUT && ! -L $OUT ]] || { echo 'Supply one new absolute evidence directory.' >&2; exit 2; }
mkdir -p -- "$(dirname -- "$OUT")"
mkdir -- "$OUT"
k() { /usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --cache-dir=/opt/ilm-488-f01-api-cache-r1 --request-timeout=15s "$@"; }
POD=f01-floor-v1
NS=ilm-sandbox
LIVE=false
NEGATIVE_CLASS=false
FAILED=0
printf 'case\tstatus\texpected_layer\tactual_layer\treason\tevidence_sha256\n' > "$OUT/results.tsv"
source "$BASE/resources/v1/floor-common.sh"
cleanup() {
  if $LIVE; then k delete pod "$POD" -n "$NS" --wait=true --timeout=35s > "$OUT/emergency-cleanup.txt" 2>&1 || true; fi
}
finish() {
  local rc=$?
  trap - EXIT
  cleanup
  if $NEGATIVE_CLASS; then
    if k delete runtimeclass f01-rejected-runc --wait=true > "$OUT/negative-class-cleanup.txt" 2>&1 &&
       k get runtimeclass f01-rejected-runc --ignore-not-found -o name > "$OUT/negative-class-after.txt" &&
       [[ ! -s $OUT/negative-class-after.txt ]]; then
      record negative-runtime-cleanup PASS API API ABSENT "$OUT/negative-class-cleanup.txt"
    else
      record negative-runtime-cleanup FAILED API API CLEANUP_FAILED "$OUT/negative-class-cleanup.txt"
      rc=1
    fi
  fi
  while IFS=$'\t' read -r id operation expected expected_reason || [[ -n ${id:-} ]]; do
    [[ $id == case ]] && continue
    [[ $id =~ ^[A-Za-z][A-Za-z0-9-]*$ ]] || continue
    if ! awk -F '\t' -v id="$id" '$1 == id { found=1 } END { exit !found }' "$OUT/results.tsv"; then
      printf '%s\n' 'An earlier required check stopped this case.' > "$OUT/$id.unexecuted.txt"
      record "$id" UNEXECUTED "$expected" NONE PRIOR_FAILURE "$OUT/$id.unexecuted.txt"
      rc=1
    fi
  done < "$BASE/admission/v1/cases.tsv"
  for id in baseline quantity-equivalent scratch-mode matrix-provenance metadata-writer unchanged-update live-floor dryrun-preserved cleanup negative-runtime-cleanup; do
    if ! awk -F '\t' -v id="$id" '$1 == id { found=1 } END { exit !found }' "$OUT/results.tsv"; then
      printf '%s\n' 'An earlier required check stopped this observation.' > "$OUT/$id.unexecuted.txt"
      record "$id" UNEXECUTED REQUIRED NONE PRIOR_FAILURE "$OUT/$id.unexecuted.txt"
      rc=1
    fi
  done
  printf '%s\n' 'Enabled-mode CEL denial, full F01, resource stress, network path matrix, Job/controller, identity/CSI, private ingress, readiness and missing-enforcement transition proofs: UNEXECUTED.' > "$OUT/unexecuted.txt"
  find "$OUT" -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum > "$OUT/evidence.sha256"
  exit "$rc"
}
trap finish EXIT
cd "$BASE"
find . -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/sources.sha256"
# Fixed inventory, row count and complete-line checks precede every cluster mutation.
jq -Rse --argjson count 59 '
  endswith("\n") and (split("\n")[:-1] |
    .[0] == "case\toperation\texpected_layer\texpected_reason" and length == $count + 1 and
    (.[1:] | map(split("\t")) |
      all(length == 4 and (.[0] | test("^[A-Za-z][A-Za-z0-9-]*$")) and
        (.[1] | IN("CREATE", "UPDATE", "ephemeralcontainers", "resize")) and
        (.[2] | IN("CEL", "PSA")) and (.[3] | test("^(F01_[A-Z_]+|RESTRICTED)$"))) and
      (map(.[0]) | unique | length) == $count))' admission/v1/cases.tsv > "$OUT/case-validation.txt"
tail -n +2 admission/v1/cases.tsv | cut -f1 | LC_ALL=C sort > "$OUT/case-ids.txt"
for fixture in admission/v1/mutations/*; do
  [[ -f $fixture && $fixture == *.json ]]
  name=${fixture##*/}; printf '%s\n' "${name%.json}"
done | LC_ALL=C sort > "$OUT/fixture-ids.txt"
cmp "$OUT/case-ids.txt" "$OUT/fixture-ids.txt"
k version -o json > "$OUT/version.json"
jq -e '.serverVersion.gitVersion == "v1.36.1"' "$OUT/version.json" >/dev/null
[[ $(uname -m) == aarch64 ]]
k get nodes -o json | jq '[.items[] | {name:.metadata.name,nodeInfo:(.status.nodeInfo | {architecture,operatingSystem,kernelVersion,osImage,containerRuntimeVersion,kubeletVersion})}]' > "$OUT/node-provenance.json"
jq -e 'length == 1 and all(.nodeInfo.architecture == "arm64" and .nodeInfo.operatingSystem == "linux" and .nodeInfo.kernelVersion == "7.0.14-linuxkit" and .nodeInfo.osImage == "Debian GNU/Linux 13 (trixie)" and .nodeInfo.containerRuntimeVersion == "containerd://2.3.1" and .nodeInfo.kubeletVersion == "v1.36.1")' "$OUT/node-provenance.json" >/dev/null
/usr/local/bin/runsc --version > "$OUT/runsc-version.txt"
grep -Fxq 'runsc version release-20261019.0' "$OUT/runsc-version.txt"
# Distinct launcher/helper members of the verified release-20261019.0 archive.
sha256sum /usr/local/bin/runsc /usr/local/bin/gvisor-bin/gvisor_sentry > "$OUT/runsc-binaries.sha256"
grep -Fxq 'c771292129c7ff96e83c5074485e3d33cfc938652dc70682bb792a66842d4de2  /usr/local/bin/runsc' "$OUT/runsc-binaries.sha256"
grep -Fxq '79f406de247333489ad3e1bdc5c936ede9bbe1eb1b36a315b601bc782c56aa16  /usr/local/bin/gvisor-bin/gvisor_sentry' "$OUT/runsc-binaries.sha256"
awk -F= '/^[[:space:]]*platform[[:space:]]*=/ {gsub(/[[:space:]"]/ ,"",$2); print $2}' /etc/runsc/config.toml > "$OUT/runsc-platform.txt"
[[ $(cat "$OUT/runsc-platform.txt") == systrap ]]
k get clusterinformation default -o jsonpath='{.spec.calicoVersion}' > "$OUT/calico-version.txt"
[[ $(cat "$OUT/calico-version.txt") == v3.33.0 ]]
record matrix-provenance PASS MATRIX MATRIX MEASURED "$OUT/node-provenance.json"
k get --raw /openapi/v2 > "$OUT/openapi.json"
jq --slurpfile inventory admission/v1/field-inventory.json -e '.definitions as $d | $inventory[0] | to_entries | all(. as $entry | ($d["io.k8s.api.core.v1." + $entry.key].properties | keys) == $entry.value)' "$OUT/openapi.json" >/dev/null
[[ $(df -Pk / | awk 'NR==2 {print $4}') -ge 1048576 ]]
k get pods -n "$NS" -o json > "$OUT/initial-pods.json"
jq -e '.items | length == 0' "$OUT/initial-pods.json" >/dev/null
# Compare every authority-relevant field, including top-level SA/RuntimeClass fields and namespace labels.
require_floor profile/v1/namespace.yaml profile create
require_floor admission/v1/pod-floor.yaml policy create
if k get runtimeclass f01-rejected-runc > "$OUT/negative-class-presence.txt" 2>&1; then
  echo 'Negative-only RuntimeClass already exists; refusing to own it.' >&2; exit 1
fi
k create -f admission/v1/rejected-runtime.yaml > "$OUT/negative-class-create.txt"
NEGATIVE_CLASS=true
# Observed generation, a positive and one exact negative must all be ready.
for attempt in {1..15}; do
  k get validatingadmissionpolicy f01-floor-v1 -o json > "$OUT/policy.json"
  if jq -e '.status.observedGeneration == .metadata.generation and ((.status.typeChecking.expressionWarnings // []) | length == 0)' "$OUT/policy.json" >/dev/null &&
     k create --dry-run=server -f profile/v1/pod.yaml -o json > "$OUT/baseline.json" 2> "$OUT/baseline.err"; then
    k patch --local -f profile/v1/pod.yaml --type=json --patch-file admission/v1/mutations/image-tag.json -o json > "$OUT/readiness-negative.input.json"
    if ! k create --dry-run=server -f "$OUT/readiness-negative.input.json" > "$OUT/readiness-negative.txt" 2>&1 &&
       grep -Fq "ValidatingAdmissionPolicy 'f01-floor-v1' with binding 'f01-floor-v1' denied request: F01_EXECUTABLE" "$OUT/readiness-negative.txt" &&
       ! grep -Fq 'resulted in error' "$OUT/readiness-negative.txt"; then break; fi
  fi
  sleep 1
done
jq -e '.kind == "Pod"' "$OUT/baseline.json" >/dev/null
grep -Fq "ValidatingAdmissionPolicy 'f01-floor-v1' with binding 'f01-floor-v1' denied request: F01_EXECUTABLE" "$OUT/readiness-negative.txt"
readiness_error_rc=0
grep -Fq 'resulted in error' "$OUT/readiness-negative.txt" || readiness_error_rc=$?
[[ $readiness_error_rc == 1 ]]
jq -e '.status.observedGeneration == .metadata.generation and ((.status.typeChecking.expressionWarnings // []) | length == 0)' "$OUT/policy.json" >/dev/null
k get validatingadmissionpolicybinding f01-floor-v1 -o json > "$OUT/binding.json"
k get -f profile/v1/namespace.yaml -o json > "$OUT/effective-profile.json"
record baseline PASS API API ALLOWED "$OUT/baseline.json"
# Equivalent quantities must be accepted by semantic quantity comparison.
k patch --local -f profile/v1/pod.yaml --type=json -p '[{"op":"replace","path":"/spec/containers/0/resources/limits/cpu","value":"0.5"},{"op":"replace","path":"/spec/containers/0/resources/limits/memory","value":"268435456"}]' -o json > "$OUT/quantity-input.json"
k create --dry-run=server -f "$OUT/quantity-input.json" -o json > "$OUT/quantity-equivalent.json" 2> "$OUT/quantity-equivalent.err"
record quantity-equivalent PASS API API ALLOWED "$OUT/quantity-equivalent.json"
k create --dry-run=client -f profile/v1/pod.yaml -o json > "$OUT/schema-profile.json"
bash "$BASE/check-api-absence.sh" "$OUT/schema-profile.json" "$OUT/baseline.json" "$OUT"
# v1.36 unknown-field negative only: original API_PRUNED row retains controlled IGNORE evidence.
k patch --local -f profile/v1/pod.yaml --type=json --patch-file admission/v1/controls/scratch-mode.json -o json > "$OUT/scratch-mode.input.json"
jq -e '.spec.volumes[0].emptyDir.mode == 493' "$OUT/scratch-mode.input.json" >/dev/null
k create --dry-run=server --validate=ignore -f "$OUT/scratch-mode.input.json" -o json > "$OUT/scratch-mode.json" 2> "$OUT/scratch-mode.err"
jq -e '.spec.volumes[0].emptyDir | has("mode") | not' "$OUT/scratch-mode.json" >/dev/null
record scratch-mode PASS API API API_PRUNED "$OUT/scratch-mode.json"
negative() {
  local id=$1 operation=$2 expected=$3 expected_reason=$4 actual=API reason=UNCLASSIFIED status=FAILED rc=0
  local fixture="admission/v1/mutations/$id.json" log="$OUT/$id.txt"
  if [[ $operation == CREATE ]]; then
    k patch --local -f profile/v1/pod.yaml --type=json --patch-file "$fixture" -o json > "$OUT/$id.input.json"
    k create --dry-run=server -f "$OUT/$id.input.json" -o json > "$log" 2>&1 || rc=$?
  else
    local args=()
    [[ $operation == UPDATE ]] || args=(--subresource="$operation")
    # The resourceVersion test prevents a stale live object from masking this mutation.
    local rv patch
    rv=$(k get pod "$POD" -n "$NS" -o jsonpath='{.metadata.resourceVersion}')
    patch=$(jq --arg rv "$rv" '[{"op":"test","path":"/metadata/resourceVersion","value":$rv}] + .' "$fixture")
    k patch pod "$POD" -n "$NS" "${args[@]}" --type=json -p "$patch" --dry-run=server -o json > "$log" 2>&1 || rc=$?
  fi
  if [[ $rc == 0 ]]; then actual=ACCEPT; reason=UNEXPECTED_ACCEPT
  elif grep -Fq 'violates PodSecurity "restricted:v1.36"' "$log"; then actual=PSA; reason=RESTRICTED
  elif grep -Fq "ValidatingAdmissionPolicy 'f01-floor-v1' with binding 'f01-floor-v1' denied request:" "$log" &&
       ! grep -Fq 'resulted in error' "$log" && grep -Eq 'F01_[A-Z_]+' "$log"; then
    actual=CEL; reason=$(grep -oE 'F01_[A-Z_]+' "$log" | sort -u | paste -sd,)
  fi
  [[ $actual == "$expected" && $reason == "$expected_reason" ]] && status=PASS
  record "$id" "$status" "$expected" "$actual" "$reason" "$log"
}
while IFS=$'\t' read -r id operation expected expected_reason || [[ -n ${id:-} ]]; do
  [[ $id == case || $operation != CREATE ]] || negative "$id" "$operation" "$expected" "$expected_reason"
done < admission/v1/cases.tsv
[[ $FAILED == 0 ]] || exit 1
k create -f profile/v1/pod.yaml -o json > "$OUT/live-created.json"
LIVE=true
k wait --for=condition=Ready pod/"$POD" -n "$NS" --timeout=50s > "$OUT/live-ready.txt" 2>&1
k get pod "$POD" -n "$NS" --show-managed-fields -o json > "$OUT/live-before.json"
jq '{annotations:.metadata.annotations,writers:[.metadata.managedFields[]? | {manager,operation,subresource,annotationFields:.fieldsV1."f:metadata"."f:annotations"} | select(.annotationFields != null)]}' "$OUT/live-before.json" > "$OUT/metadata-writer.json"
jq -e '.writers | any(.manager == "calico" and .subresource == "status" and (.annotationFields | has("f:cni.projectcalico.org/containerID") and has("f:cni.projectcalico.org/podIP") and has("f:cni.projectcalico.org/podIPs")))' "$OUT/metadata-writer.json" >/dev/null
/usr/bin/kubectl --kubeconfig=/etc/cni/net.d/calico-kubeconfig --cache-dir=/opt/ilm-488-f01-api-cache-r1 auth whoami -o json | jq '{username:.status.userInfo.username,groups:.status.userInfo.groups}' > "$OUT/configured-cni-principal.json"
jq -e '.username == "system:serviceaccount:kube-system:calico-cni-plugin"' "$OUT/configured-cni-principal.json" >/dev/null
k get clusterrole calico-cni-plugin -o json | jq '{name:.metadata.name,podRules:[.rules[] | select(any(.resources[]?; . == "pods" or . == "pods/status"))]}' > "$OUT/cni-pod-rbac.json"
/usr/bin/kubectl --kubeconfig=/etc/cni/net.d/calico-kubeconfig --cache-dir=/opt/ilm-488-f01-api-cache-r1 auth can-i patch pods --subresource=status -n "$NS" > "$OUT/cni-status-authorization.txt"
grep -Fxq yes "$OUT/cni-status-authorization.txt"
record metadata-writer PASS STATUS STATUS OBSERVED_MANAGER "$OUT/metadata-writer.json"
RV=$(jq -r '.metadata.resourceVersion' "$OUT/live-before.json")
UPDATE=$(jq --arg rv "$RV" '[{"op":"test","path":"/metadata/resourceVersion","value":$rv},{"op":"replace","path":"/metadata/labels/ilm.ai~1proof","value":"floor-v1"}]' <<< '{}')
k patch pod "$POD" -n "$NS" --type=json -p "$UPDATE" --dry-run=server -o json > "$OUT/unchanged-update.json"
record unchanged-update PASS API API ALLOWED "$OUT/unchanged-update.json"
for attempt in {1..10}; do
  k logs "$POD" -n "$NS" > "$OUT/live.log"
  grep -Fq FLOOR_V1_READY "$OUT/live.log" && break
  sleep 1
done
for marker in 'uid=65532' TOKEN_ABSENT HOST_AGENT_ABSENT ROOT_MOUNT_READONLY SHARED_SCRATCH_WRITABLE FLOOR_V1_READY; do grep -Fq "$marker" "$OUT/live.log"; done
grep -Fq 'gVisor' "$OUT/live.log"
grep -Eq ' /scratch ' "$OUT/live.log"
grep -Eq ' /tmp ' "$OUT/live.log"
CID=$(jq -r '.status.containerStatuses[0].containerID | sub("^containerd://"; "")' "$OUT/live-before.json")
UID_VALUE=$(jq -r '.metadata.uid' "$OUT/live-before.json")
SCRATCH="/var/lib/kubelet/pods/$UID_VALUE/volumes/kubernetes.io~empty-dir/scratch"
findmnt -n -o FSTYPE,OPTIONS --mountpoint "$SCRATCH" > "$OUT/scratch-mount.txt"
grep -Eq '^tmpfs .*size=16384k(,|$)' "$OUT/scratch-mount.txt"
# Project only fixed-profile OCI fields; do not retain runtime environment or host credentials.
/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock inspect "$CID" | jq '{runtimeType:.info.runtimeType,readonly:.info.runtimeSpec.root.readonly,noNewPrivileges:.info.runtimeSpec.process.noNewPrivileges,user:.info.runtimeSpec.process.user,capabilities:.info.runtimeSpec.process.capabilities,seccompAction:.info.runtimeSpec.linux.seccomp.defaultAction,resources:.info.runtimeSpec.linux.resources,mounts:[.info.runtimeSpec.mounts[] | select(.destination == "/scratch" or .destination == "/tmp")]}' > "$OUT/oci.json"
jq --arg scratch "$SCRATCH" -e '.runtimeType == "io.containerd.runsc.v1" and .readonly == true and .noNewPrivileges == true and .user.uid == 65532 and .user.gid == 65532 and .capabilities == {} and .seccompAction == "SCMP_ACT_ERRNO" and .resources.memory.limit == 268435456 and .resources.cpu.quota == 50000 and .resources.cpu.period == 100000 and (.mounts | length == 2) and (.mounts | all(.source == $scratch and .type == "bind" and (.options | index("rprivate") != null)))' "$OUT/oci.json" >/dev/null
SID=$(/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock pods --name "$POD" -q)
[[ $SID =~ ^[0-9a-f]{64}$ ]]
pgrep -af "$SID" | awk '$2 == "runsc-sandbox"' > "$OUT/live-sentry-process.txt"
grep -Fq -- '--platform=systrap' "$OUT/live-sentry-process.txt"
SENTRY_PID=$(awk '{print $1}' "$OUT/live-sentry-process.txt")
[[ $SENTRY_PID =~ ^[0-9]+$ ]]
readlink "/proc/$SENTRY_PID/exe" > "$OUT/live-sentry-exe-path.txt"
[[ $(cat "$OUT/live-sentry-exe-path.txt") == /usr/local/bin/gvisor-bin/gvisor_sentry ]]
sha256sum "/proc/$SENTRY_PID/exe" > "$OUT/live-sentry-exe.sha256"
EXPECTED_SENTRY=$(awk '$2 == "/usr/local/bin/gvisor-bin/gvisor_sentry" {print $1}' "$OUT/runsc-binaries.sha256")
[[ $(cut -d' ' -f1 "$OUT/live-sentry-exe.sha256") == "$EXPECTED_SENTRY" ]]
record live-floor PASS RUNTIME RUNTIME OBSERVED "$OUT/oci.json"
while IFS=$'\t' read -r id operation expected expected_reason || [[ -n ${id:-} ]]; do
  [[ $id == case || $operation == CREATE ]] || negative "$id" "$operation" "$expected" "$expected_reason"
done < admission/v1/cases.tsv
k get pod "$POD" -n "$NS" -o json > "$OUT/live-after.json"
jq -S '{spec,uid:.metadata.uid}' "$OUT/live-before.json" > "$OUT/before-stable.json"
jq -S '{spec,uid:.metadata.uid}' "$OUT/live-after.json" > "$OUT/after-stable.json"
cmp "$OUT/before-stable.json" "$OUT/after-stable.json"
record dryrun-preserved PASS API API UNCHANGED "$OUT/after-stable.json"
k delete pod "$POD" -n "$NS" --wait=true --timeout=35s > "$OUT/cleanup.txt"
LIVE=false
SCRATCH="/var/lib/kubelet/pods/$UID_VALUE/volumes/kubernetes.io~empty-dir/scratch"
for attempt in {1..20}; do test ! -e "$SCRATCH" && break; sleep 1; done
test ! -e "$SCRATCH"
k get pods -n "$NS" -o json > "$OUT/final-pods.json"
jq -e '.items | length == 0' "$OUT/final-pods.json" >/dev/null
record cleanup PASS KUBELET KUBELET SCRATCH_ABSENT "$OUT/final-pods.json"
[[ $FAILED == 0 ]]
