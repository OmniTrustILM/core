#!/usr/bin/env bash
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export BASE
[[ $EUID == 0 && $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'Run as root with one new absolute evidence directory.' >&2; exit 2; }
for tool in jq sha256sum realpath timeout python3 kubectl crictl ctr findmnt pgrep readlink cmp; do command -v "$tool" >/dev/null; done
source "$BASE/floor-common.sh"
prepare_output "$1" "$BASE"
k() { /usr/bin/kubectl --kubeconfig=/etc/kubernetes/admin.conf --cache-dir=/opt/ilm-488-f01-api-cache-r1 --request-timeout=10s "$@"; }
NS=ilm-sandbox-a2
POD=f01-a2-floor-control
LIVE=false
WATCHDOG=
NEGATIVE_CLASS=false
FAILED=0
printf 'case\tstatus\texpected_layer\tactual_layer\treason\tevidence_sha256\n' > "$OUT/results.tsv"
no_match() {
 local rc=0
 grep "$@" || rc=$?
 [[ $rc == 1 ]]
}
cri_record_absent() {
 local kind=$1 id=$2
 [[ $id =~ ^[0-9a-f]{64}$ ]] || return 2
 case "$kind" in
  container) /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock ps -a --id "$id" -q > "$OUT/$kind-after-race.txt" || return 1;;
  sandbox) /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock pods --id "$id" -q > "$OUT/$kind-after-race.txt" || return 1;;
  *) return 2;;
 esac
 [[ ! -s $OUT/$kind-after-race.txt ]]
}
remove_stopped_record() {
 local kind=$1 id=$2 action
 [[ $id =~ ^[0-9a-f]{64}$ ]] || return 2
 case "$kind" in container) action=rm;; sandbox) action=rmp;; *) return 2;; esac
 if /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock "$action" "$id" > "$OUT/stopped-$kind-remove.txt" 2>&1; then return 0; fi
 # A failed removal is success only when a fresh successful query proves this exact ID absent.
 cri_record_absent "$kind" "$id"
}
stop_watchdog() {
 if [[ -n $WATCHDOG ]]; then
  if jobs -pr | grep -Fxq "$WATCHDOG"; then kill "$WATCHDOG" 2>/dev/null || true; fi
  wait "$WATCHDOG" 2>/dev/null || true
  WATCHDOG=
 fi
}
finish() {
 local rc=$?
 trap - EXIT
 if $LIVE; then
  printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s"},"gracePeriodSeconds":1}\n' "$POD_UID" > "$OUT/emergency-delete-options.json"
  k delete --raw "/api/v1/namespaces/$NS/pods/$POD" -f "$OUT/emergency-delete-options.json" > "$OUT/emergency-cleanup.txt" 2>&1 || true
 fi
 stop_watchdog
 if $NEGATIVE_CLASS; then
  printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s"}}\n' "$CLASS_UID" > "$OUT/class-delete-options.json"
  if k delete --raw /apis/node.k8s.io/v1/runtimeclasses/f01-rejected-runc -f "$OUT/class-delete-options.json" > "$OUT/negative-class-cleanup.txt" 2>&1 &&
     k get runtimeclass f01-rejected-runc --ignore-not-found -o name > "$OUT/negative-class-after.txt" && [[ ! -s $OUT/negative-class-after.txt ]]; then
   record negative-runtime-cleanup PASS API API ABSENT "$OUT/negative-class-cleanup.txt"
  else rc=1; fi
 fi
 while IFS=$'\t' read -r id op layer reason input; do
  [[ $id == case ]] && continue
  if ! awk -F '\t' -v id="$id" '$1==id{found=1}END{exit !found}' "$OUT/results.tsv"; then
   printf '%s\n' 'Earlier prerequisite/control stopped this required case.' > "$OUT/$id.unexecuted.txt"
   record "$id" UNEXECUTED "$layer" NONE PRIOR_FAILURE "$OUT/$id.unexecuted.txt"
   rc=1
  fi
 done < "$BASE/cases.tsv"
 for id in typecheck positive-floor-control positive-scratch-a positive-scratch-b positive-process-control positive-process-limit positive-memory-control positive-memory-limit positive-cpu-control positive-cpu-deadline scratch-mode live-floor cleanup negative-runtime-cleanup; do
  if ! awk -F '\t' -v id="$id" '$1==id{found=1}END{exit !found}' "$OUT/results.tsv"; then
   printf '%s\n' 'Earlier prerequisite/control stopped this observation.' > "$OUT/$id.unexecuted.txt"
   record "$id" UNEXECUTED REQUIRED NONE PRIOR_FAILURE "$OUT/$id.unexecuted.txt"
   rc=1
  fi
 done
 [[ $FAILED == 0 ]] || rc=1
 if [[ $rc == 0 ]]; then
  printf '%s\n' 'PASS admission and one actual non-stress floor. High probes/guest process cap/full F01 UNEXECUTED; numeric coverage N/A.' > "$OUT/result.txt"
  cat "$OUT/result.txt"
 fi
 if [[ $rc != 0 ]]; then printf '%s\n' 'FAILED prerequisite/control. Remaining required observations UNEXECUTED; no high probe was launched.' > "$OUT/stopped.txt"; fi
 find "$OUT" -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum > "$OUT/evidence.sha256"
 exit "$rc"
}
trap finish EXIT
cd "$BASE"
source "$BASE/health.sh"
bash check-resources.sh "$OUT/local-assets"
health floor-before
[[ $(df -Pk / | awk 'NR==2{print $4}') -ge 1048576 ]]
k get pods -A -o json | jq -e '[.items[]|select(.metadata.namespace=="ilm-sandbox" or .metadata.namespace=="ilm-sandbox-a2")]|length==0' > "$OUT/no-proof-pods.txt"
k get --raw /openapi/v2 > "$OUT/openapi.json"
jq --slurpfile inventory ../../admission/v1/field-inventory.json -e '.definitions as $d | $inventory[0] | to_entries | all(. as $entry | ($d["io.k8s.api.core.v1." + $entry.key].properties | keys) == $entry.value)' "$OUT/openapi.json" > "$OUT/inventory.txt"
/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock info | jq '.config.containerd.runtimes["runsc-f01-a2-v1"]' > "$OUT/effective-handler.json"
jq -e '.runtimeType=="io.containerd.runsc.v1" and .baseRuntimeSpec=="/etc/runsc/f01-a2-base.json" and .options=={TypeUrl:"io.containerd.runsc.v1.options",ConfigPath:"/etc/runsc/config.toml"}' "$OUT/effective-handler.json" >/dev/null
jq -e '[.process.rlimits[]|select(.type=="RLIMIT_NPROC")]==[{type:"RLIMIT_NPROC",soft:256,hard:256}]' /etc/runsc/f01-a2-base.json > "$OUT/base-nproc.txt"
require_floor namespace.yaml profile create
require_floor pod-floor.yaml policy create
k get runtimeclass f01-rejected-runc --ignore-not-found -o name > "$OUT/negative-class-before.txt"
[[ ! -s $OUT/negative-class-before.txt ]]
k create -f ../../admission/v1/rejected-runtime.yaml -o json > "$OUT/negative-class-created.json"
CLASS_UID=$(jq -r .metadata.uid "$OUT/negative-class-created.json")
NEGATIVE_CLASS=true
for attempt in {1..15}; do
 k get validatingadmissionpolicy f01-a2-v1 -o json > "$OUT/policy.json"
 if jq -e '.status.observedGeneration==.metadata.generation and ((.status.typeChecking.expressionWarnings // [])|length==0)' "$OUT/policy.json" >/dev/null &&
    k create --dry-run=server -f profiles/floor-control.yaml -o json > "$OUT/readiness-positive.json" 2> "$OUT/readiness-positive.err"; then
  k patch --local -f profiles/floor-control.yaml --type=json --patch-file ../../admission/v1/mutations/image-tag.json -o json > "$OUT/readiness-negative.input.json"
  if ! k create --dry-run=server -f "$OUT/readiness-negative.input.json" > "$OUT/readiness-negative.txt" 2>&1 &&
     grep -Fq "ValidatingAdmissionPolicy 'f01-a2-v1' with binding 'f01-a2-v1' denied request: F01_EXECUTABLE" "$OUT/readiness-negative.txt" &&
     no_match -Fq 'resulted in error' "$OUT/readiness-negative.txt"; then break; fi
 fi
 sleep 1
done
jq -e '.kind=="Pod"' "$OUT/readiness-positive.json" >/dev/null
grep -Fq "ValidatingAdmissionPolicy 'f01-a2-v1' with binding 'f01-a2-v1' denied request: F01_EXECUTABLE" "$OUT/readiness-negative.txt"
no_match -Fq 'resulted in error' "$OUT/readiness-negative.txt"
jq -e '.status.observedGeneration==.metadata.generation and ((.status.typeChecking.expressionWarnings // [])|length==0)' "$OUT/policy.json" >/dev/null
record typecheck PASS CEL CEL NO_WARNINGS "$OUT/policy.json"
for file in profiles/*.yaml; do
 id=${file##*/};id=${id%.yaml}
 k create --dry-run=server -f "$file" -o json > "$OUT/positive-$id.json" 2> "$OUT/positive-$id.err"
 record "positive-$id" PASS API API ALLOWED "$OUT/positive-$id.json"
done
bash "$BASE/../../check-api-absence.sh" profiles/floor-control.yaml "$OUT/readiness-positive.json" "$OUT"
# v1.36 unknown-field negative only: original API_PRUNED row retains controlled IGNORE evidence.
k patch --local -f profiles/floor-control.yaml --type=json --patch-file ../../admission/v1/controls/scratch-mode.json -o json > "$OUT/scratch-mode.input.json"
jq -e '.spec.volumes[0].emptyDir.mode==493' "$OUT/scratch-mode.input.json" >/dev/null
k create --dry-run=server --validate=ignore -f "$OUT/scratch-mode.input.json" -o json > "$OUT/scratch-mode.json" 2> "$OUT/scratch-mode.err"
jq -e '.spec.volumes[0].emptyDir|has("mode")|not' "$OUT/scratch-mode.json" >/dev/null
record scratch-mode PASS API API API_PRUNED "$OUT/scratch-mode.json"
negative() {
 local id=$1 operation=$2 expected=$3 expected_reason=$4 input=$5 actual=API reason=UNCLASSIFIED status=FAILED rc=0
 local log="$OUT/$id.txt"
 if [[ $operation == CREATE ]]; then
  k patch --local -f profiles/floor-control.yaml --type=json --patch-file "$input" -o json > "$OUT/$id.input.json"
  k create --dry-run=server -f "$OUT/$id.input.json" -o json > "$log" 2>&1 || rc=$?
 else
  local args=() rv patch
  [[ $operation == UPDATE ]] || args=(--subresource="$operation")
  rv=$(k get pod "$POD" -n "$NS" -o jsonpath='{.metadata.resourceVersion}')
  patch=$(jq --arg rv "$rv" '[{op:"test",path:"/metadata/resourceVersion",value:$rv}] + .' "$input")
  k patch pod "$POD" -n "$NS" "${args[@]}" --type=json -p "$patch" --dry-run=server -o json > "$log" 2>&1 || rc=$?
 fi
 if [[ $rc == 0 ]]; then actual=ACCEPT;reason=UNEXPECTED_ACCEPT
 elif grep -Fq 'violates PodSecurity "restricted:v1.36"' "$log"; then actual=PSA;reason=RESTRICTED
 elif grep -Fq "ValidatingAdmissionPolicy 'f01-a2-v1' with binding 'f01-a2-v1' denied request:" "$log" && no_match -Fq 'resulted in error' "$log" && grep -Eq 'F01_[A-Z_]+' "$log"; then
  actual=CEL;reason=$(grep -oE 'F01_[A-Z_]+' "$log" | sort -u | paste -sd,)
 fi
 [[ $actual == "$expected" && $reason == "$expected_reason" ]] && status=PASS
 record "$id" "$status" "$expected" "$actual" "$reason" "$log"
}
while IFS=$'\t' read -r id op layer reason input; do
 [[ $id == case || $op != CREATE ]] || negative "$id" "$op" "$layer" "$reason" "$input"
done < cases.tsv
[[ $FAILED == 0 ]]
k create -f profiles/floor-control.yaml -o json > "$OUT/live-created.json"
POD_UID=$(jq -r .metadata.uid "$OUT/live-created.json")
[[ $POD_UID =~ ^[0-9a-f-]{36}$ ]]
LIVE=true
# Independent outer stop: bounded child observes only the created UID and deletes by API UID precondition.
python3 -I -S -B "$BASE/python/verify_floor_runtime.py" "$POD_UID" "$OUT" < /dev/null &
WATCHDOG=$!
k wait --for=condition=Ready pod/"$POD" -n "$NS" --timeout=20s > "$OUT/live-ready.txt" 2>&1
k get pod "$POD" -n "$NS" -o json > "$OUT/live-before.json"
while IFS=$'\t' read -r id op layer reason input; do
 [[ $id == case || $op == CREATE ]] || negative "$id" "$op" "$layer" "$reason" "$input"
done < cases.tsv
[[ $FAILED == 0 ]]
for attempt in {1..5}; do
 k logs "$POD" -n "$NS" > "$OUT/live.log"
 grep -Fq A2_FLOOR_READY "$OUT/live.log" && break
 sleep 1
done
for marker in 'uid=65532' gVisor TOKEN_ABSENT HOST_AGENT_ABSENT ROOT_MOUNT_READONLY SHARED_SCRATCH_WRITABLE NPROC_RAISE_REFUSED A2_FLOOR_READY; do grep -Fq "$marker" "$OUT/live.log"; done
no_match -Fq NPROC_RAISE_UNEXPECTED "$OUT/live.log"
grep -Fxq 'ash: error setting limit: Operation not permitted' "$OUT/live.log"
grep -Eq '^Max processes[[:space:]]+256[[:space:]]+256[[:space:]]+processes' "$OUT/live.log"
API_CID=$(jq -r '.status.containerStatuses[0].containerID|sub("^containerd://";"")' "$OUT/live-before.json")
CID=$(/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock ps -a --label "io.kubernetes.pod.uid=$POD_UID" --name '^fixed-proof$' -q)
SID=$(/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock pods --label "io.kubernetes.pod.uid=$POD_UID" -q)
[[ $CID =~ ^[0-9a-f]{64}$ && $SID =~ ^[0-9a-f]{64}$ && $CID == "$API_CID" ]]
SCRATCH="/var/lib/kubelet/pods/$POD_UID/volumes/kubernetes.io~empty-dir/scratch"
findmnt -n -o FSTYPE,OPTIONS --mountpoint "$SCRATCH" > "$OUT/scratch-mount.txt"
grep -Eq '^tmpfs .*size=16384k(,|$)' "$OUT/scratch-mount.txt"
/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock inspect "$CID" | jq '{runtimeType:.info.runtimeType,readonly:.info.runtimeSpec.root.readonly,noNewPrivileges:.info.runtimeSpec.process.noNewPrivileges,user:.info.runtimeSpec.process.user,capabilities:.info.runtimeSpec.process.capabilities,rlimits:.info.runtimeSpec.process.rlimits,seccompAction:.info.runtimeSpec.linux.seccomp.defaultAction,resources:.info.runtimeSpec.linux.resources,cgroupsPath:.info.runtimeSpec.linux.cgroupsPath,mounts:[.info.runtimeSpec.mounts[]|select(.destination=="/scratch" or .destination=="/tmp")]}' > "$OUT/oci.json"
jq --arg scratch "$SCRATCH" -e '.runtimeType=="io.containerd.runsc.v1" and .readonly and .noNewPrivileges and .user.uid==65532 and .user.gid==65532 and .capabilities=={} and .seccompAction=="SCMP_ACT_ERRNO" and .resources.memory.limit==268435456 and .resources.cpu.quota==50000 and .resources.cpu.period==100000 and ([.rlimits[]|select(.type=="RLIMIT_NPROC")]==[{type:"RLIMIT_NPROC",soft:256,hard:256}]) and (.mounts|length==2 and all(.source==$scratch and .type=="bind"))' "$OUT/oci.json" >/dev/null
/usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock inspectp "$SID" | jq '{id:.status.id,runtimeHandler:.status.runtimeHandler}' > "$OUT/sandbox-handler.json"
jq -e '.runtimeHandler=="runsc-f01-a2-v1"' "$OUT/sandbox-handler.json" >/dev/null
pgrep -af "$SID" | awk '$2=="runsc-sandbox"' > "$OUT/live-sentry-process.txt"
[[ $(wc -l < "$OUT/live-sentry-process.txt") == 1 ]]
grep -Fq -- '--platform=systrap' "$OUT/live-sentry-process.txt"
SENTRY_PID=$(awk '{print $1}' "$OUT/live-sentry-process.txt")
readlink "/proc/$SENTRY_PID/exe" > "$OUT/live-sentry-exe.txt"
[[ $(cat "$OUT/live-sentry-exe.txt") == /usr/local/bin/gvisor-bin/gvisor_sentry ]]
[[ $(sha256sum "/proc/$SENTRY_PID/exe"|cut -d' ' -f1) == 79f406de247333489ad3e1bdc5c936ede9bbe1eb1b36a315b601bc782c56aa16 ]]
cat "/proc/$SENTRY_PID/cgroup" > "$OUT/sentry-cgroup.txt"
# Resolve the actual cgroup2 membership, never infer it from an OCI path string.
CGROUP=$(awk -F: '$1=="0"{print $3}' "$OUT/sentry-cgroup.txt")
[[ $CGROUP == /* && $CGROUP != / && -d /sys/fs/cgroup$CGROUP ]]
cat "/sys/fs/cgroup$CGROUP/cgroup.procs" > "$OUT/cgroup-procs.txt"
RUNSC_ROOT=$(awk '{for(i=1;i<=NF;i++)if($i~/^--root=/){sub(/^--root=/,"",$i);print $i}}' "$OUT/live-sentry-process.txt")
[[ $RUNSC_ROOT == /* && $RUNSC_ROOT != *..* ]]
POD_CGROUP=${CGROUP%/*}
[[ ${CGROUP##*/} == "cri-containerd-$SID.scope" && ${POD_CGROUP##*/} == "kubelet-kubepods-burstable-pod${POD_UID//-/_}.slice" ]]
[[ $(jq -r .cgroupsPath "$OUT/oci.json") == "${POD_CGROUP##*/}:cri-containerd:$CID" ]]
CONTAINER_CGROUP="$POD_CGROUP/cri-containerd-$CID.scope"
# Require the fixed12s hold to end normally before the active deadline.
for attempt in {1..20}; do
 k get pod "$POD" -n "$NS" -o json > "$OUT/live-after.json"
 [[ $(jq -r .status.phase "$OUT/live-after.json") == Succeeded ]] && break
 sleep 1
done
jq -e '.status.phase=="Succeeded" and .status.containerStatuses[0].restartCount==0 and .status.containerStatuses[0].state.terminated.exitCode==0' "$OUT/live-after.json" >/dev/null
[[ ! -e $OUT/outer-stop.txt ]]
record live-floor PASS RUNTIME RUNTIME NPROC256_FLOOR_OBSERVED "$OUT/oci.json"
stop_watchdog
# Delete with an actual API UID precondition; fail if the fixed name was replaced.
printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s"},"gracePeriodSeconds":1}\n' "$POD_UID" > "$OUT/delete-options.json"
k delete --raw "/api/v1/namespaces/$NS/pods/$POD" -f "$OUT/delete-options.json" > "$OUT/cleanup.txt"
REMOVED_C=false
REMOVED_S=false
for attempt in {1..30}; do
 k get pod "$POD" -n "$NS" --ignore-not-found -o json > "$OUT/pod-after.json"
 # An identically named replacement is foreign and must never be deleted.
 [[ ! -s $OUT/pod-after.json ]] || jq --arg uid "$POD_UID" -e '.metadata.uid==$uid' "$OUT/pod-after.json" >/dev/null
 /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock ps -a --id "$CID" -q > "$OUT/container-after.txt"
 /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock pods --id "$SID" -q > "$OUT/sandbox-after.txt"
 /usr/local/bin/ctr --address /run/containerd/containerd.sock -n k8s.io tasks list | awk -v c="$CID" -v s="$SID" '$1==c || $1==s' > "$OUT/tasks-after.txt"
 /usr/local/bin/runsc --root="$RUNSC_ROOT" list --format=json > "$OUT/runsc-after.raw.json"
 # The installed CLI emits null for an empty Go slice; reject every other unexpected shape.
 jq -e 'type=="array" or .==null' "$OUT/runsc-after.raw.json" >/dev/null
 jq --arg c "$CID" --arg s "$SID" '[.[]? | select(.id==$c or .id==$s)]' "$OUT/runsc-after.raw.json" > "$OUT/runsc-after.json"
 if [[ ! -s $OUT/pod-after.json && ! -s $OUT/tasks-after.txt && ! -e $SCRATCH && ! -e /sys/fs/cgroup$CGROUP && ! -e /sys/fs/cgroup$CONTAINER_CGROUP && ! -e /sys/fs/cgroup$POD_CGROUP ]] &&
    ! kill -0 "$SENTRY_PID" 2>/dev/null && jq -e 'length==0' "$OUT/runsc-after.json" >/dev/null; then
  if [[ ! -s $OUT/container-after.txt && ! -s $OUT/sandbox-after.txt ]]; then break; fi
  # Retained EXITED/NOTREADY CRI metadata is distinct from live workload. Remove only this immutable ID,
  # after matching the exact UID/namespace/name and the original admitted profile record.
  jq --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.metadata.uid==$uid and .metadata.namespace==$ns and .metadata.name==$pod and .metadata.labels=={"ilm.ai/proof":"a2-v1"}' "$OUT/live-created.json" >/dev/null
  if [[ -s $OUT/container-after.txt ]] && ! $REMOVED_C; then
   [[ $(cat "$OUT/container-after.txt") == "$CID" ]]
   if /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock inspect "$CID" | jq '.status|{id,state,labels,metadata}' > "$OUT/stopped-container-owner.json"; then
    jq --arg cid "$CID" --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.id==$cid and .state=="CONTAINER_EXITED" and .metadata.name=="fixed-proof" and .labels["io.kubernetes.pod.uid"]==$uid and .labels["io.kubernetes.pod.namespace"]==$ns and .labels["io.kubernetes.pod.name"]==$pod' "$OUT/stopped-container-owner.json" >/dev/null
    remove_stopped_record container "$CID"
   else
    cri_record_absent container "$CID"
   fi
   REMOVED_C=true
  fi
  if [[ -s $OUT/sandbox-after.txt ]] && ! $REMOVED_S; then
   [[ $(cat "$OUT/sandbox-after.txt") == "$SID" ]]
   if /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock inspectp "$SID" | jq '.status|{id,state,metadata,runtimeHandler}' > "$OUT/stopped-sandbox-owner.json"; then
    jq --arg sid "$SID" --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.id==$sid and .state=="SANDBOX_NOTREADY" and .metadata.uid==$uid and .metadata.namespace==$ns and .metadata.name==$pod and .runtimeHandler=="runsc-f01-a2-v1"' "$OUT/stopped-sandbox-owner.json" >/dev/null
    remove_stopped_record sandbox "$SID"
   else
    cri_record_absent sandbox "$SID"
   fi
   REMOVED_S=true
  fi
 fi
 sleep 1
done
[[ ! -s $OUT/pod-after.json && ! -s $OUT/container-after.txt && ! -s $OUT/sandbox-after.txt && ! -s $OUT/tasks-after.txt && ! -e $SCRATCH && ! -e /sys/fs/cgroup$CGROUP && ! -e /sys/fs/cgroup$CONTAINER_CGROUP && ! -e /sys/fs/cgroup$POD_CGROUP ]]
if kill -0 "$SENTRY_PID" 2>/dev/null; then
 echo "FAILED owned Sentry still exists after cleanup" >&2
 exit 1
fi
jq -e 'length==0' "$OUT/runsc-after.json" >/dev/null
LIVE=false
k get pods -n "$NS" -o json > "$OUT/final-pods.json"
jq -e '.items|length==0' "$OUT/final-pods.json" >/dev/null
health floor-final
record cleanup PASS RUNTIME RUNTIME POD_CRI_SENTRY_CGROUP_SCRATCH_ABSENT "$OUT/final-pods.json"
[[ $FAILED == 0 ]]
