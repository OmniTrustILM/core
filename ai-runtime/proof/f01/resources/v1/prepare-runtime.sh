#!/usr/bin/env bash
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
export BASE
source "$BASE/health.sh"
[[ $EUID == 0 && $# == 1 && $1 == /* && ! -e $1 ]] || { echo 'Run as root with one new absolute evidence directory.' >&2; exit 2; }
for tool in jq sha256sum shasum realpath timeout systemctl python3 k3s cmp diff install stat; do command -v "$tool" >/dev/null; done
source "$BASE/floor-common.sh"
prepare_output "$1" "$BASE"
k() { k3s kubectl --request-timeout=5s "$@"; }
TEMPLATE=/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
RENDERED=/var/lib/rancher/k3s/agent/etc/containerd/config.toml
OCI=/etc/runsc/f01-a2-base.json
CONTAINERD=/var/lib/rancher/k3s/data/current/bin/containerd
ACTIVATED=false
HEALTHY=false
finish() {
 local rc=$?
 trap - EXIT
 if $ACTIVATED && ! $HEALTHY; then
  printf '%s\n' 'FAILED activation; restoring exact template; one recovery restart only.' > "$OUT/recovery.txt"
  if activate recovery >> "$OUT/recovery.txt" 2>&1; then
   printf '%s\n' 'Recovery API/Node/Calico/CoreDNS healthy.' >> "$OUT/recovery.txt"
  else printf '%s\n' 'FAILED bounded recovery restart/fresh-health/configuration' >> "$OUT/recovery.txt"; fi
  rc=1
 fi
 sha256sum "$TEMPLATE" /etc/runsc/config.toml > "$OUT/current-config.sha256" || true
 find "$OUT" -type f ! -name evidence.sha256 -print0 | sort -z | xargs -0 sha256sum > "$OUT/evidence.sha256"
 exit "$rc"
}
trap finish EXIT
verify_recovery() {
 cmp "$OUT/template.before" "$TEMPLATE" > "$OUT/recovery-template.compare" || return 1
 stat -c '%u %g %a' "$TEMPLATE" > "$OUT/recovery-template-owner-mode.txt" || return 1
 cmp "$OUT/template-owner-mode.before" "$OUT/recovery-template-owner-mode.txt" > "$OUT/recovery-template-metadata.compare" || return 1
 k3s crictl info | jq '{ordinary:.config.containerd.runtimes.runsc,hasA2:(.config.containerd.runtimes|has("runsc-f01-a2-v1"))}' > "$OUT/recovery-handlers.json" || return 1
 jq --slurpfile old "$OUT/runsc.before.json" -e '.ordinary==$old[0] and .hasA2==false' "$OUT/recovery-handlers.json" >/dev/null || return 1
 "$CONTAINERD" --config "$RENDERED" config dump > "$OUT/recovery-rendered.validated" 2> "$OUT/parser-recovery.err" || return 1
 python3 -I -S -B "$BASE/python/verify_recovery_config.py" "$OUT" < /dev/null || return 1
}
activate() {
 local tag=$1
 export OUT TEMPLATE RENDERED CONTAINERD
 # All restart, fresh-health and recovery-configuration checks share this single120s bound.
 timeout 120 bash -c "$(declare -f k health verify_recovery)"$'\nset -euo pipefail\nif [[ $1 == recovery ]]; then cp -p "$OUT/template.before" "$TEMPLATE.recovery"; mv -f "$TEMPLATE.recovery" "$TEMPLATE"; fi\ndate -u +%FT%T.%NZ > "$OUT/$1-restart-start.txt"\nsystemctl restart k3s\nT0=$(date -u +%FT%T.%NZ)\nprintf "%s\\n" "$T0" > "$OUT/$1-restart-return.txt"\nuntil health "$1" "$T0"; do sleep 1; done\nif [[ $1 == recovery ]]; then verify_recovery; fi' -- "$tag"
}
bash "$BASE/check-resources.sh" "$OUT/local-assets"
[[ $(uname -m) == aarch64 && -x $CONTAINERD && -f $TEMPLATE && ! -e $OCI ]]
handler_scan_rc=0
grep -Fq runsc-f01-a2-v1 "$TEMPLATE" || handler_scan_rc=$?
[[ $handler_scan_rc == 1 ]]
k get pods -A -o json | jq -e '[.items[]|select(.metadata.namespace=="ilm-sandbox" or .metadata.namespace=="ilm-sandbox-a2")]|length==0' > "$OUT/no-proof-pods.txt"
health before
sha256sum /etc/runsc/config.toml "$TEMPLATE" "$RENDERED" > "$OUT/before-config.sha256"
stat -c '%u %g %a' "$TEMPLATE" > "$OUT/template-owner-mode.before"
cp -p "$TEMPLATE" "$OUT/template.before"
cp -p "$RENDERED" "$OUT/rendered.before"
k3s crictl info | jq '.config.containerd.runtimes.runsc' > "$OUT/runsc.before.json"
jq -e '.runtimeType=="io.containerd.runsc.v1" and .baseRuntimeSpec=="" and .options=={TypeUrl:"io.containerd.runsc.v1.options",ConfigPath:"/etc/runsc/config.toml"}' "$OUT/runsc.before.json" >/dev/null
k3s ctr oci spec --help > "$OUT/generator-help.txt"
grep -Fq -- '--platform' "$OUT/generator-help.txt"
k3s ctr oci spec --platform linux/arm64 > "$OUT/default-oci.json"
jq -e '.ociVersion=="1.3.0" and (.root.path|type=="string" and length>0) and (.process.user|has("uid") and has("gid")) and (.process.cwd|type=="string") and (.process.rlimits|type=="array") and (.linux.namespaces|type=="array" and length>0) and (.linux.resources|type=="object") and (.linux.resources.devices|type=="array" and length>0) and (.mounts|type=="array" and length>0)' "$OUT/default-oci.json" >/dev/null
jq '.process.rlimits = ((.process.rlimits // [] | map(select(.type != "RLIMIT_NPROC"))) + [{type:"RLIMIT_NPROC",soft:256,hard:256}])' "$OUT/default-oci.json" > "$OUT/base-oci.json"
jq -S '.process.rlimits |= map(select(.type != "RLIMIT_NPROC"))' "$OUT/default-oci.json" > "$OUT/default-without-nproc.json"
jq -S '.process.rlimits |= map(select(.type != "RLIMIT_NPROC"))' "$OUT/base-oci.json" > "$OUT/base-without-nproc.json"
cmp "$OUT/default-without-nproc.json" "$OUT/base-without-nproc.json"
jq -e '[.process.rlimits[]|select(.type=="RLIMIT_NPROC")]==[{type:"RLIMIT_NPROC",soft:256,hard:256}]' "$OUT/base-oci.json" >/dev/null
jq -S . "$OUT/default-oci.json" > "$OUT/default-canonical.json"
jq -S . "$OUT/base-oci.json" > "$OUT/base-canonical.json"
diff -u "$OUT/default-canonical.json" "$OUT/base-canonical.json" > "$OUT/base.diff" || [[ $? == 1 ]]
cat > "$OUT/handler.append" <<'TOML'
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'runsc-f01-a2-v1']
  runtime_type = "io.containerd.runsc.v1"
  base_runtime_spec = "/etc/runsc/f01-a2-base.json"
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'runsc-f01-a2-v1'.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/runsc/config.toml"
TOML
cat "$OUT/template.before" "$OUT/handler.append" > "$OUT/template.candidate"
diff -u "$OUT/template.before" "$OUT/template.candidate" > "$OUT/template.diff" || [[ $? == 1 ]]
cat "$OUT/rendered.before" "$OUT/handler.append" > "$OUT/rendered.candidate"
# Validate this exact v3 schema with the installed parser, without starting another daemon.
"$CONTAINERD" --version > "$OUT/parser-version.txt"
grep -Fxq 'containerd github.com/k3s-io/containerd/v2 v2.3.4-k3s1' "$OUT/parser-version.txt"
"$CONTAINERD" --config "$OUT/rendered.candidate" config dump > "$OUT/rendered.validated" 2> "$OUT/parser-candidate.err"
grep -Fq 'Configuration migrated from version 3' "$OUT/parser-candidate.err"
python3 -I -S -B "$BASE/python/verify_handler_candidate.py" "$OUT" < /dev/null
"$CONTAINERD" --config "$OUT/rendered.before" config dump > "$OUT/rendered.before.validated" 2> "$OUT/parser-before.err"
grep -Fq 'Configuration migrated from version 3' "$OUT/parser-before.err"
python3 -I -S -B "$BASE/python/verify_handler_addition.py" "$OUT" < /dev/null
# Original template and ordinary runtime config must still match the initial checkpoint.
sha256sum --check "$OUT/before-config.sha256" > "$OUT/preinstall-preserved.txt"
install -o root -g root -m 0600 "$OUT/base-oci.json" "$OCI.new"
mv -f "$OCI.new" "$OCI"
read -r TEMPLATE_UID TEMPLATE_GID TEMPLATE_MODE < "$OUT/template-owner-mode.before"
install -o "$TEMPLATE_UID" -g "$TEMPLATE_GID" -m "$TEMPLATE_MODE" "$OUT/template.candidate" "$TEMPLATE.new"
mv -f "$TEMPLATE.new" "$TEMPLATE"
ACTIVATED=true
sha256sum "$OCI" "$TEMPLATE" > "$OUT/installed.sha256"
stat -c '%U %G %a' "$OCI" > "$OUT/base-owner-mode.txt"
grep -Fxq 'root root 600' "$OUT/base-owner-mode.txt"
ACTIVATED=true
# The timeout bounds the single planned activation and API return together.
activate after > "$OUT/restart.txt" 2>&1
k3s crictl info | jq '{ordinary:.config.containerd.runtimes.runsc,handler:.config.containerd.runtimes["runsc-f01-a2-v1"]}' > "$OUT/effective-handlers.json"
jq --slurpfile old "$OUT/runsc.before.json" -e '.ordinary==$old[0] and .handler.runtimeType=="io.containerd.runsc.v1" and .handler.baseRuntimeSpec=="/etc/runsc/f01-a2-base.json" and .handler.options=={TypeUrl:"io.containerd.runsc.v1.options",ConfigPath:"/etc/runsc/config.toml"}' "$OUT/effective-handlers.json" >/dev/null
ordinary_hash=$(awk '$2=="/etc/runsc/config.toml"{print $1}' "$OUT/before-config.sha256")
[[ $ordinary_hash =~ ^[0-9a-f]{64}$ && $(sha256sum /etc/runsc/config.toml | cut -d' ' -f1) == "$ordinary_hash" ]]
"$CONTAINERD" --config "$RENDERED" config dump > "$OUT/actual-rendered.validated" 2> "$OUT/parser-actual.err"
python3 -I -S -B "$BASE/python/verify_active_config.py" "$OUT" < /dev/null
HEALTHY=true
printf '%s\n' 'PASS separate handler active; ordinary runsc preserved; A1 regression and actual floor remain required.' > "$OUT/result.txt"
cat "$OUT/result.txt"
