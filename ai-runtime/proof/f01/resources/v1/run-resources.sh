#!/usr/bin/env bash
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export BASE
source "$BASE/health.sh"
[[ $EUID == 0 && ( $# == 1 || ( $# == 2 && ${2-} == --process-control-only ) ) && $1 == /* && ! -e $1 ]] || exit 2
CONTROLS=(floor-control process-control memory-control cpu-control)
if [[ ${2-} == --process-control-only ]]; then CONTROLS=(process-control); fi
WORKTREE=$(cd -- "$BASE/../.." && pwd -P)
if [[ $WORKTREE == */ai-runtime/proof/f01 ]]; then WORKTREE=$(cd -- "$WORKTREE/../../.." && pwd -P); fi
ROOT=$(realpath -m -- "$1")
[[ $ROOT != "$WORKTREE" && $ROOT != "$WORKTREE"/* ]] || exit 2
mkdir -- "$ROOT"
OUT=$ROOT
NS=ilm-sandbox-a2
LIVE=false
CLEANUP_ATTEMPTED=false
CLEANUP_VERIFIED=false
CLEANUP_EVIDENCE_FAILED=false
WATCHDOG=
OBSERVER=
CONTROL=preflight
k() { timeout 3 k3s kubectl --request-timeout=2s "$@"; }
verify_owner() {
 jq --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.metadata.uid==$uid and .metadata.namespace==$ns and .metadata.name==$pod and .metadata.labels=={"ilm.ai/proof":"a2-v1"} and .spec.runtimeClassName=="runsc-f01-a2-v1"' "$1" >/dev/null
}
cri_record_absent() {
 local kind=$1 id=$2 output
 [[ $id =~ ^[0-9a-f]{64}$ ]] || return 2
 case "$kind" in
  container) output=$(k3s crictl ps -a --id "$id" -q) || return 1;;
  sandbox) output=$(k3s crictl pods --id "$id" -q) || return 1;;
  *) return 2;;
 esac
 printf '%s' "$output" > "$OUT/$kind-after-race.txt" || CLEANUP_EVIDENCE_FAILED=true
 [[ -z $output ]]
}
remove_stopped_record() {
 local kind=$1 id=$2 action output status=0
 [[ $id =~ ^[0-9a-f]{64}$ ]] || return 2
 case "$kind" in container) action=rm;; sandbox) action=rmp;; *) return 2;; esac
 if output=$(k3s crictl "$action" "$id" 2>&1); then :; else
  # A failed removal is success only when a fresh successful query proves this exact ID absent.
  cri_record_absent "$kind" "$id" || status=1
 fi
 printf '%s\n' "$output" > "$OUT/stopped-$kind-remove.txt" || CLEANUP_EVIDENCE_FAILED=true
 return "$status"
}
source "$BASE/floor-common.sh"
cleanup_mapping() {
 python3 -I -S -B "$BASE/python/cleanup_mapping.py" "$OUT" "$POD_UID" "$CID" "$SID" "$POD" < /dev/null
}
wait_observer() {
 local status=0
 [[ -n $OBSERVER ]] || return 1
 if wait "$OBSERVER"; then status=0; else status=$?; fi
 OBSERVER=
 [[ $status == 0 ]] || return 1
 if [[ $CONTROL == floor-control || $CONTROL == process-control ]]; then
  jq --arg uid "$POD_UID" --arg cid "$CID" --arg sid "$SID" --arg name "$POD" -e '.status=="OBSERVATION_WINDOW_FINISHED" and .target.uid==$uid and .target.cid==$cid and .target.sid==$sid and .target.name==$name' "$OUT/observation/observer-result.json" >/dev/null
 else
  python3 -I -S -B "$BASE/python/observer_wait.py" "$OUT" < /dev/null
 fi
}
accounting_protocol() {
 python3 -I -S -B "$BASE/python/accounting_dispatch.py" "$BASE/python/observer.py" "$OUT" "$CONTROL" "$1" "${OBSERVER:-0}" < /dev/null
}
live_window_logs() {
 python3 -I -S -B "$BASE/python/live_window.py" "$1" "$OUT" "$CONTROL" < /dev/null
}
wait_watchdog() {
 local status=0
 [[ -n $WATCHDOG ]] || return 1
 if wait "$WATCHDOG"; then status=0; else status=$?; fi
 printf '{"exitCode":%d,"deliberateStop":false}\n' "$status" > "$OUT/outer-watchdog-status.json"
 WATCHDOG=
 [[ $status == 0 && ! -e $OUT/outer-stop.json ]] || return 1
 python3 -I -S -B "$BASE/python/verify_watchdog_clock.py" "$OUT" "$POD_UID" < /dev/null
}
cleanup_host_checks() {
 python3 -I -S -B "$BASE/python/cleanup_host.py" "$OUT" "$POD_UID" < /dev/null
}
cleanup_body() {
 local runtime_status=UNAVAILABLE host_status=UNAVAILABLE current mapping options='' response='' containers sandboxes owner id attempt removed=' '
 CLEANUP_EVIDENCE_FAILED=${CLEANUP_EVIDENCE_FAILED:-false}
 [[ $POD_UID =~ ^[0-9a-f-]{36}$ ]] || return 1
 current=$(k get pod "$POD" -n "$NS" --ignore-not-found -o json) || return 1
 if [[ -n $current ]]; then
  verify_owner /dev/stdin <<< "$current" || return 1
  options=$(printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s"},"gracePeriodSeconds":1}\n' "$POD_UID")
  response=$(k delete --raw "/api/v1/namespaces/$NS/pods/$POD" -f - <<< "$options") || return 1
 fi
 # Diagnostics follow dispatch; a failed save is retained without gating other owned actions.
 printf '%s\n' 'INCOMPLETE cleanup verification; no absence claim yet.' > "$OUT/cleanup-result.txt" || CLEANUP_EVIDENCE_FAILED=true
 printf '%s\n' "$current" > "$OUT/delete-current.json" || CLEANUP_EVIDENCE_FAILED=true
 printf '%s\n' "$options" > "$OUT/delete-options.json" || CLEANUP_EVIDENCE_FAILED=true
 printf '%s\n' "$response" > "$OUT/delete-response.json" || CLEANUP_EVIDENCE_FAILED=true
 mapping=$(cleanup_mapping) || CLEANUP_EVIDENCE_FAILED=true
 SENTRY_PID=;RUNSC_ROOT=
 if jq -e '.status=="VALID"' <<< "$mapping" >/dev/null; then
  SENTRY_PID=$(jq -r .pid <<< "$mapping")
  RUNSC_ROOT=$(jq -r .root <<< "$mapping")
 fi
 for attempt in {1..50}; do
  current=$(k get pod "$POD" -n "$NS" --ignore-not-found -o json) || return 1
  [[ -z $current ]] || verify_owner /dev/stdin <<< "$current" || return 1
  containers=$(k3s crictl ps -a --label "io.kubernetes.pod.uid=$POD_UID" -q) || return 1
  sandboxes=$(k3s crictl pods --label "io.kubernetes.pod.uid=$POD_UID" -q) || return 1
  if [[ -z $current ]]; then
   while IFS= read -r id; do
    [[ -n $id ]] || continue
    [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
    if owner=$(k3s crictl inspect "$id" | jq '.status|{id,state,labels,metadata}'); then
     jq --arg id "$id" --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.id==$id and .state=="CONTAINER_EXITED" and .metadata.name=="fixed-proof" and .labels["io.kubernetes.pod.uid"]==$uid and .labels["io.kubernetes.pod.namespace"]==$ns and .labels["io.kubernetes.pod.name"]==$pod' <<< "$owner" >/dev/null || return 1
     [[ $removed != *" container:$id "* ]] || return 1
     remove_stopped_record container "$id" || return 1
     removed+="container:$id "
    else cri_record_absent container "$id" || return 1; fi
    printf '%s\n' "$owner" > "$OUT/stopped-container-owner.json" || CLEANUP_EVIDENCE_FAILED=true
   done <<< "$containers"
   while IFS= read -r id; do
    [[ -n $id ]] || continue
    [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
    if owner=$(k3s crictl inspectp "$id" | jq '.status|{id,state,metadata,runtimeHandler}'); then
     jq --arg id "$id" --arg uid "$POD_UID" --arg ns "$NS" --arg pod "$POD" -e '.id==$id and .state=="SANDBOX_NOTREADY" and .metadata.uid==$uid and .metadata.namespace==$ns and .metadata.name==$pod and .runtimeHandler=="runsc-f01-a2-v1"' <<< "$owner" >/dev/null || return 1
     [[ $removed != *" sandbox:$id "* ]] || return 1
     remove_stopped_record sandbox "$id" || return 1
     removed+="sandbox:$id "
    else cri_record_absent sandbox "$id" || return 1; fi
    printf '%s\n' "$owner" > "$OUT/stopped-sandbox-owner.json" || CLEANUP_EVIDENCE_FAILED=true
   done <<< "$sandboxes"
  fi
  printf '%s' "$current" > "$OUT/pod-after.json" || CLEANUP_EVIDENCE_FAILED=true
  printf '%s' "$containers" > "$OUT/container-after.txt" || CLEANUP_EVIDENCE_FAILED=true
  printf '%s' "$sandboxes" > "$OUT/sandbox-after.txt" || CLEANUP_EVIDENCE_FAILED=true
  if [[ -z $current && -z $containers && -z $sandboxes && ! -e /var/lib/kubelet/pods/$POD_UID ]]; then break; fi
  sleep .1
 done
 [[ -z $current && -z $containers && -z $sandboxes && ! -e /var/lib/kubelet/pods/$POD_UID ]] || return 1
 if [[ -n $RUNSC_ROOT ]]; then
  if /usr/local/bin/runsc --root="$RUNSC_ROOT" list --format=json | jq --arg c "$CID" --arg s "$SID" -e '(type=="array" or .==null) and ([.[]?|select(.id==$c or .id==$s)]|length==0)' > "$OUT/runsc-absent.json"; then runtime_status=PASS; else runtime_status=FAILED; fi
 fi
 k3s ctr -n k8s.io tasks list | awk -v c="$CID" -v s="$SID" '$1==c || $1==s' > "$OUT/tasks-after.txt"
 [[ ! -s $OUT/tasks-after.txt ]]
 if cleanup_host_checks; then host_status=PASS; else
  if [[ $? == 2 ]]; then host_status=FAILED; else host_status=UNAVAILABLE; fi
 fi
 k get pods -n "$NS" -o json | jq -e '.items|length==0' > "$OUT/namespace-empty.json"
 k get resourcequota -n "$NS" -o json | jq -e 'all(.items[];(.status.used.pods // "0")=="0")' > "$OUT/quota-released.json"
 local host_checks sentry_status members_status cgroup_status
 if [[ $host_status == UNAVAILABLE ]] || ! host_checks=$(jq -er '[.sentry,.hostMembers,.podCgroup] | if all(.[]; .=="PASS" or .=="FAILED" or .=="UNAVAILABLE") then @tsv else error("invalid cleanup check statuses") end' "$OUT/cleanup-host-checks.json"); then
  printf 'INCOMPLETE cleanup verification: runsc=%s; current host check statuses unavailable; no Sentry/host-member/cgroup absence claim.\n' "$runtime_status" > "$OUT/cleanup-result.txt"
  return 1
 fi
 IFS=$'\t' read -r sentry_status members_status cgroup_status <<< "$host_checks"
 if [[ $runtime_status != PASS || $host_status != PASS ]] || $CLEANUP_EVIDENCE_FAILED; then
  printf 'FAILED cleanup verification: runsc=%s; sentry=%s; hostMembers=%s; podCgroup=%s; recorded in cleanup-mapping.json and cleanup-host-checks.json. Exact Pod/CRI/tasks/kubelet/quota checks completed.\n' "$runtime_status" "$sentry_status" "$members_status" "$cgroup_status" > "$OUT/cleanup-result.txt"
  return 1
 fi
 printf '%s\n' 'PASS exact Pod/CRI/tasks/Sentry identities/host members/cgroup/kubelet path absent; quota released.' > "$OUT/cleanup-result.txt"
}
cleanup() {
 if $CLEANUP_ATTEMPTED; then $CLEANUP_VERIFIED; return; fi
 CLEANUP_ATTEMPTED=true
 CLEANUP_EVIDENCE_FAILED=false
 if exec 9> "$OUT/cleanup-command.txt"; then :; else
  CLEANUP_EVIDENCE_FAILED=true
  exec 9>/dev/null
 fi
 export OUT NS POD POD_UID SENTRY_PID RUNSC_ROOT CID SID CLEANUP_EVIDENCE_FAILED
 local status=0
 if timeout 10 bash -c "$(declare -f k verify_owner cri_record_absent remove_stopped_record cleanup_mapping cleanup_host_checks cleanup_body)"$'\nset -euo pipefail\ncleanup_body' >&9 2>&1; then
  CLEANUP_VERIFIED=true
 else status=1; fi
 exec 9>&-
 return "$status"
}
finish() {
 local rc=$?
 trap - EXIT
 if [[ -n $OBSERVER ]]; then
  if jobs -pr | grep -Fxq "$OBSERVER"; then kill "$OBSERVER" 2>/dev/null || true; fi
  wait "$OBSERVER" 2>/dev/null || true
 fi
 if $LIVE && ! $CLEANUP_ATTEMPTED; then
  if cleanup; then LIVE=false; else rc=1; fi
 fi
 if $CLEANUP_ATTEMPTED && ! $CLEANUP_VERIFIED; then rc=1; fi
 if [[ -n $WATCHDOG ]]; then
  local watchdog_status=0 watchdog_stopped=false cleanup_verified=false
  if $CLEANUP_VERIFIED; then cleanup_verified=true; fi
  if $CLEANUP_VERIFIED && jobs -pr | grep -Fxq "$WATCHDOG"; then
   kill "$WATCHDOG" 2>/dev/null || true
  fi
  if wait "$WATCHDOG"; then watchdog_status=0; else watchdog_status=$?; fi
  if [[ $watchdog_status == 143 ]]; then watchdog_stopped=true; fi
  printf '{"exitCode":%d,"deliberateStop":%s,"ownedCleanupVerified":%s}\n' "$watchdog_status" "$watchdog_stopped" "$cleanup_verified" > "$OUT/outer-watchdog-status.json"
  WATCHDOG=
  [[ $rc != 0 ]] || rc=1
 fi
 health final > "$ROOT/final-health-command.txt" 2>&1 || rc=1
 if [[ $rc != 0 ]]; then
  if [[ $CONTROL == resource-accounting ]]; then
   printf '%s\n' 'STOP full A2 resource accounting and high probes remain unaccepted; see each small-control result.' > "$ROOT/stopped.txt"
  else printf 'FAILED %s; no following controls launched.\n' "$CONTROL" > "$ROOT/stopped.txt"; fi
 fi
 for id in floor-control process-control memory-control cpu-control; do
  if [[ ! -e $ROOT/$id/control-result.txt ]]; then
   if [[ -e $ROOT/$id/created.json ]]; then
    printf '%s\tFAILED_OR_UNKNOWN\n' "$id" >> "$ROOT/results.tsv"
   else
    mkdir -p "$ROOT/$id"
    printf '%s\n' 'UNEXECUTED; no following control launched after failure or held scope.' > "$ROOT/$id/control-result.txt"
    printf '%s\tUNEXECUTED\n' "$id" >> "$ROOT/results.tsv"
   fi
  fi
 done
 find "$ROOT" -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum > "$ROOT/evidence.sha256"
 exit "$rc"
}
trap finish EXIT
cd "$BASE"
bash check-resources.sh "$ROOT/local-assets"
health before
k get pods -A -o json | jq -e '[.items[]|select(.metadata.namespace=="ilm-sandbox" or .metadata.namespace=="ilm-sandbox-a2")]|length==0' > "$ROOT/no-proof-pods.json"
require_floor namespace.yaml a2-profile refuse
require_floor pod-floor.yaml a2-policy refuse
require_floor ../../profile/v1/namespace.yaml a1-profile refuse
require_floor ../../admission/v1/pod-floor.yaml a1-policy refuse
for name in f01-a2-v1 f01-floor-v1; do
 k get validatingadmissionpolicy "$name" -o json | jq -e '.status.observedGeneration==.metadata.generation and ((.status.typeChecking.expressionWarnings // [])|length==0)' > "$ROOT/typecheck-$name.json"
done
sha256sum /etc/runsc/config.toml /etc/runsc/f01-a2-base.json /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl > "$ROOT/runtime.before.sha256"
k3s crictl info | jq '.config.containerd.runtimes["runsc-f01-a2-v1"]' > "$ROOT/effective-handler.json"
jq -e '.runtimeType=="io.containerd.runsc.v1" and .baseRuntimeSpec=="/etc/runsc/f01-a2-base.json" and .options=={TypeUrl:"io.containerd.runsc.v1.options",ConfigPath:"/etc/runsc/config.toml"}' "$ROOT/effective-handler.json" >/dev/null
printf 'case\tstatus\n' > "$ROOT/results.tsv"
for CONTROL in "${CONTROLS[@]}"; do
 OUT="$ROOT/$CONTROL";mkdir "$OUT"
 health before
 POD="f01-a2-$CONTROL";POD_UID=;CID=;SID=;SENTRY_PID=;RUNSC_ROOT=
 CLEANUP_ATTEMPTED=false;CLEANUP_VERIFIED=false;CLEANUP_EVIDENCE_FAILED=false
 k create --dry-run=server -f "profiles/$CONTROL.yaml" -o json > "$OUT/admitted.json"
 # No create retry: a missing response leaves ownership unknown and requires manual reconciliation.
 k create -f "profiles/$CONTROL.yaml" -o json > "$OUT/created.json"
 POD_UID=$(jq -r .metadata.uid "$OUT/created.json")
 [[ $POD_UID =~ ^[0-9a-f-]{36}$ ]]
 verify_owner "$OUT/created.json"
 LIVE=true
 python3 -I -S -B "$BASE/python/outer_watchdog.py" "$OUT" "$POD" "$POD_UID" < /dev/null &
 WATCHDOG=$!
 for attempt in {1..100}; do
  k get pod "$POD" -n "$NS" -o json > "$OUT/current.json"
  verify_owner "$OUT/current.json"
  API_CID=$(jq -r '.status.containerStatuses[0].containerID // ""' "$OUT/current.json")
  if [[ $API_CID == containerd://* ]]; then
  if [[ $CONTROL == memory-control || $CONTROL == cpu-control ]]; then
   # Reuse this existing bounded startup loop; never create a second clock/budget.
   [[ ! -e $OUT/outer-stop.json && -n $WATCHDOG ]] && kill -0 "$WATCHDOG" || exit 1
   [[ -f $OUT/outer-clock.json ]] && break
  else break; fi
 fi
  sleep .1
 done
 CID=$(k3s crictl ps -a --label "io.kubernetes.pod.uid=$POD_UID" --name '^fixed-proof$' -q)
 SID=$(k3s crictl pods --label "io.kubernetes.pod.uid=$POD_UID" -q)
 [[ $CID =~ ^[0-9a-f]{64}$ && $SID =~ ^[0-9a-f]{64}$ && $API_CID == "containerd://$CID" ]]
 jq --arg uid "$POD_UID" --arg cid "$CID" --arg sid "$SID" --arg name "$POD" '{uid:$uid,cid:$cid,sid:$sid,name:$name,startTime:.status.startTime}' "$OUT/current.json" > "$OUT/targets.json"
 if [[ $CONTROL == memory-control || $CONTROL == cpu-control ]]; then
  # Same watchdog clock; no accounting readiness wait may start a fresh budget.
  [[ -f $OUT/outer-clock.json ]]
  bash "$BASE/observe-resource.sh" "$OUT/targets.json" "$OUT/observation" "$OUT/outer-clock.json" > "$OUT/observer-command.txt" 2>&1 &
 else
  live_window_logs ready
  bash "$BASE/observe-resource.sh" "$OUT/targets.json" "$OUT/observation" "$OUT/live-window-input.json" > "$OUT/observer-command.txt" 2>&1 &
 fi
 OBSERVER=$!
 SCRATCH="/var/lib/kubelet/pods/$POD_UID/volumes/kubernetes.io~empty-dir/scratch"
 findmnt -n -o FSTYPE,OPTIONS --mountpoint "$SCRATCH" > "$OUT/scratch-mount.txt"
 grep -Eq '^tmpfs .*size=16384k(,|$)' "$OUT/scratch-mount.txt"
 k3s crictl inspect "$CID" | jq '{runtimeType:.info.runtimeType,readonly:.info.runtimeSpec.root.readonly,noNewPrivileges:.info.runtimeSpec.process.noNewPrivileges,user:.info.runtimeSpec.process.user,capabilities:.info.runtimeSpec.process.capabilities,rlimits:.info.runtimeSpec.process.rlimits,seccompAction:.info.runtimeSpec.linux.seccomp.defaultAction,resources:.info.runtimeSpec.linux.resources,mounts:[.info.runtimeSpec.mounts[]|select(.destination=="/scratch" or .destination=="/tmp")]}' > "$OUT/oci.json"
 jq --arg scratch "$SCRATCH" -e '.runtimeType=="io.containerd.runsc.v1" and .readonly and .noNewPrivileges and .user.uid==65532 and .user.gid==65532 and .capabilities=={} and .seccompAction=="SCMP_ACT_ERRNO" and .resources.memory.limit==268435456 and .resources.cpu.quota==50000 and .resources.cpu.period==100000 and ([.rlimits[]|select(.type=="RLIMIT_NPROC")]==[{type:"RLIMIT_NPROC",soft:256,hard:256}]) and (.mounts|length==2 and all(.source==$scratch and .type=="bind"))' "$OUT/oci.json" >/dev/null
 if [[ $CONTROL == memory-control || $CONTROL == cpu-control ]]; then
  accounting_protocol collect
  wait_observer
  accounting_protocol finish
 else
 wait_observer
 for attempt in {1..60}; do
  k get pod "$POD" -n "$NS" -o json > "$OUT/terminated.json"
  verify_owner "$OUT/terminated.json"
  [[ $(jq -r .status.phase "$OUT/terminated.json") == Succeeded ]] && break
  [[ ! -e $OUT/outer-stop.json ]]
  sleep .2
 done
 live_window_logs final
 jq -e '.status.phase=="Succeeded" and .status.containerStatuses[0].restartCount==0 and .status.containerStatuses[0].state.terminated.exitCode==0' "$OUT/terminated.json" >/dev/null
 [[ ! -e $OUT/outer-stop.json ]]
 if python3 -I -S -B "$BASE/python/qualify_small_control.py" "$OUT" "$CONTROL" < /dev/null
 then :; else exit 1; fi
 fi
 cleanup
 LIVE=false
 wait_watchdog
 health after
 sha256sum -c "$ROOT/runtime.before.sha256" > "$OUT/runtime-unchanged.txt"
 printf 'PASS fixed control with observations and cleanup; high probes UNEXECUTED.\n' > "$OUT/control-result.txt"
 printf '%s\tPASS\n' "$CONTROL" >> "$ROOT/results.tsv"
done
if [[ ${2-} == --process-control-only ]]; then exit 0; fi
CONTROL=resource-accounting
exit 1
