#!/usr/bin/env bash
health() {
 local tag=$1 threshold=${2:-} node
 k get --raw=/readyz > "$OUT/$tag-readyz.txt" || return 1
 grep -Fxq ok "$OUT/$tag-readyz.txt" || return 1
 k get nodes -o json | jq '[.items[] | {name:.metadata.name,ready:[.status.conditions[]|select(.type=="Ready")|.status]}]' > "$OUT/$tag-nodes.json" || return 1
 jq -e 'length==1 and all(.ready==["True"])' "$OUT/$tag-nodes.json" >/dev/null || return 1
 if [[ -n $threshold ]]; then
  node=$(jq -r '.[0].name' "$OUT/$tag-nodes.json") || return 1
  k get lease "$node" -n kube-node-lease -o json | jq '.spec|{holderIdentity,renewTime}' > "$OUT/$tag-lease.json" || return 1
  python3 -I -S -B "$BASE/python/verify_node_lease.py" "$OUT/$tag-lease.json" "$threshold" "$node" < /dev/null || return 1
 fi
 k get pods -n kube-system -o json | jq '[.items[]|select(.metadata.name|test("^(calico-node-|calico-kube-controllers-|coredns-)"))|{name:.metadata.name,uid:.metadata.uid,phase:.status.phase,containers:[.status.containerStatuses[]|{name,ready,restartCount}]}]' > "$OUT/$tag-infra.json" || return 1
 jq -e 'length==4 and all(.phase=="Running" and (.containers|length>0 and all(.ready)))' "$OUT/$tag-infra.json" >/dev/null || return 1
 /usr/local/bin/crictl --runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock ps --state running --name '^(calico-node|calico-kube-controllers|coredns)$' --label io.kubernetes.pod.namespace=kube-system -o json |
  jq '[.containers[]|{id,name:.metadata.name,uid:.labels["io.kubernetes.pod.uid"],namespace:.labels["io.kubernetes.pod.namespace"],state}]' > "$OUT/$tag-infra-cri.json" || return 1
 jq --slurpfile api "$OUT/$tag-infra.json" -e '
 length==4 and (map(.name)|sort)==["calico-kube-controllers","calico-node","coredns","coredns"] and
 (map(.id)|unique|length)==4 and (map(.uid)|unique|length)==4 and (map(.uid)|sort)==($api[0]|map(.uid)|sort) and
 all(. as $c | .namespace=="kube-system" and .state=="CONTAINER_RUNNING" and (.id|test("^[0-9a-f]{64}$")) and
 any($api[0][]; .uid==$c.uid and any(.containers[]; .name==$c.name)))' "$OUT/$tag-infra-cri.json" >/dev/null || return 1
 [[ $(df -Pk / | awk 'NR==2{print $4}') -ge 1048576 ]]
}
