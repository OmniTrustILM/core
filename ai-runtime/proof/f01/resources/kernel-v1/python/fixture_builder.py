"""Authoring only: six fixed, closed fresh-namespace programs; no cluster actions."""
import copy
import hashlib
import json
from pathlib import Path

NAMESPACE = 'ilm-resource-sec-r1'
RUNTIME_CLASS = 'runsc-f01-kernel-cg-r1'
POLICY = 'f01-kernel-cg-r1'
CONTROLS = ('memory-control', 'process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b')
SOURCE_PINS = {'namespace.yaml': 'cbfc23c29f7454f278c174340a59f0bc9503445c122198df8c95c99dceaf18ba', 'pod-floor.yaml': 'a7ca56fc29d76de8b12af5c745e73e876b35ba949ee44390add4f2dccba52ceb', 'profiles/memory-control.yaml': '9fc3fa9f67132d29c47aa42c72c68d597015d5fd3d79e0fd1cac14a3539b0105', 'profiles/process-limit.yaml': '818f454ead5d1276f5ca114bb3814460e08ee1a40932a624525e068536efc486', 'profiles/memory-limit.yaml': 'ac5340f81ff765f6b8ed0c1a96e39c184fbe1a797f9370ba832f17f3acd36db1', 'profiles/cpu-deadline.yaml': 'e52f9cd898973d3945305f599cb1f3f188c9639535b84ea9f65e1b80095b7eda', 'profiles/scratch-a.yaml': '5175dc5d267f15eed7247f52d548ae0813373177d21acab3725c937b27178334', 'profiles/scratch-b.yaml': '4adbecfa3fedd272927141bf4d60100fc26686348c4652ec4299f8e17ebd1f17'}

GATE = r"""# Fixed one-shot gate; original Pod-start deadline is never reset.
set -eu
set -f
umask 077
cg_stat() {
 IFS= read -r cg_raw < /proc/self/stat || exit 100
 cg_pid=${cg_raw%% *}; cg_tail=${cg_raw##*) }
 [ "$cg_tail" != "$cg_raw" ] && [ "$cg_pid" = "$$" ] || exit 101
 set -- $cg_tail
 [ "$#" -ge 20 ] || exit 102
 cg_start=${20}
 case "$cg_start" in ''|0|*[!0-9]*) exit 103;; esac
}
cg_stat
cg_original=$cg_start
cg_count=0
/bin/busybox mkfifo /scratch/f01-cg-start || exit 104
exec 3<> /scratch/f01-cg-start || exit 105
cg_release() {
 cg_count=$((cg_count+1))
 [ "$cg_count" -eq 1 ] || exit 106
 printf 'GO\n' >&3 || exit 107
}
trap cg_release USR1
printf 'CG_READY pid=%s start=%s\n' "$$" "$cg_original" || exit 108
cg_token=
set +e
IFS= read -r -t 16 cg_token <&3
cg_rc=$?
set -e
case "$cg_token" in ''|GO) :;; *) exit 109;; esac
printf 'CG_RAW attempt=1 rc=%s count=%s token=%s\n' "$cg_rc" "$cg_count" "$cg_token" || exit 110
if [ "$cg_rc" -ne 0 ]; then
 [ -z "$cg_token" ] && [ "$cg_count" -eq 1 ] || exit 111
 set +e
 IFS= read -r -t 2 cg_token <&3
 cg_rc=$?
 set -e
 printf 'CG_RAW attempt=2 rc=%s count=%s token=%s\n' "$cg_rc" "$cg_count" "$cg_token" || exit 112
fi
[ "$cg_rc" -eq 0 ] && [ "$cg_token" = GO ] && [ "$cg_count" -eq 1 ] || exit 113
cg_stat
[ "$cg_start" = "$cg_original" ] || exit 114
printf 'CG_ACK pid=%s start=%s count=1\n' "$$" "$cg_original" || exit 115
trap - USR1
exec 3>&-
/bin/busybox rm /scratch/f01-cg-start || exit 116
printf 'CG_LOAD_BEGIN\n' || exit 117
# BEGIN_FIXED_HIGH_BODY
"""


def expand(text, environment):
    """One Kubernetes command/args expansion pass; values are never re-expanded."""
    output = []
    index = 0
    while index < len(text):
        if text[index] != '$' or index + 1 == len(text):
            output.append(text[index]); index += 1
        elif text[index + 1] == '$':
            output.append('$'); index += 2
        elif text[index + 1] == '(':
            end = text.find(')', index + 2)
            if end == -1:
                output.append('$('); index += 2
            else:
                name = text[index + 2:end]
                output.append(environment.get(name, text[index:end + 1])); index = end + 1
        else:
            output.append(text[index:index + 2]); index += 2
    return ''.join(output)


def encode(program):
    return program.replace('$', '$$')


def reference(name, reference_root):
    if name not in SOURCE_PINS:
        raise ValueError('REFERENCE_NAME')
    path = reference_root / name
    raw = path.read_bytes()
    if path.is_symlink() or hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:
        raise ValueError('REFERENCE_SOURCE_CHANGED')
    return json.loads(raw)


def executable_expression(original, profiles):
    start = ' && ((object.metadata.name'
    finish = ' && has(variables.c.terminationMessagePath)'
    if original.count(start) != 1 or original.count(finish) != 1:
        raise ValueError('REFERENCE_EXECUTABLE_SHAPE')
    prefix = original[:original.index(start)] + ' && ('
    suffix = original[original.index(finish):]
    terms = []
    for name in CONTROLS:
        pod = profiles[name];container = pod['spec']['containers'][0]
        terms.append('(object.metadata.name == ' + json.dumps(pod['metadata']['name']) +
                     ' && object.metadata.labels["ilm.ai/proof"] == "a2-v1" && variables.c.command == ' +
                     json.dumps(container['command']) + ' && variables.c.args == ' +
                     json.dumps(container['args']) + ')')
    return prefix + ' || '.join(terms) + ')' + suffix


def fixture_namespace(reference_root):
    namespace = reference('namespace.yaml', reference_root)
    for item in namespace['items']:
        if item['kind'] == 'Namespace':
            item['metadata']['name'] = NAMESPACE
        elif item['kind'] == 'RuntimeClass':
            item['metadata']['name'] = RUNTIME_CLASS
        elif item['kind'] == 'GlobalNetworkPolicy':
            item['metadata']['name'] = NAMESPACE + '-deny'
            item['spec']['selector'] = "projectcalico.org/namespace == '" + NAMESPACE + "'"
        else:
            item['metadata']['namespace'] = NAMESPACE
    return namespace


def fixture_profiles(reference_root):
    profiles = {};golden = {}
    for name in CONTROLS:
        pod = reference('profiles/' + name + '.yaml', reference_root)
        stored = pod['spec']['containers'][0]['args'][0]
        intended = expand(stored, {})
        if name == 'memory-control':
            if hashlib.sha256(intended.encode()).hexdigest() != 'b0e79e25e7b82b1bb2111430b544505ce488f04c4b1eecc8e23b2bfa902dfa0f':
                raise ValueError('CALIBRATION_GOLDEN_CHANGED')
            intended = intended.replace('for (i=1; i<=1024; i++)', 'for (i=1; i<=2048; i++)')
        else:
            if '$$' in stored:
                raise ValueError('HIGH_REFERENCE_ENCODING_CHANGED')
            intended = GATE + intended
        pod['metadata']['namespace'] = NAMESPACE
        pod['spec']['runtimeClassName'] = RUNTIME_CLASS
        pod['spec']['containers'][0]['args'] = [encode(intended)]
        profiles[name] = pod;golden[name] = intended
    return profiles, golden


def build_fixture(reference_root):
    reference_root = Path(reference_root)
    if not reference_root.is_absolute() or reference_root != reference_root.resolve() or not reference_root.is_dir():
        raise ValueError('REFERENCE_ROOT')
    namespace = fixture_namespace(reference_root)
    profiles, golden = fixture_profiles(reference_root)
    policy = reference('pod-floor.yaml', reference_root)
    policy['items'][0]['metadata']['name'] = POLICY
    binding = policy['items'][1]
    binding['metadata']['name'] = POLICY;binding['spec']['policyName'] = POLICY
    binding['spec']['matchResources']['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'] = NAMESPACE
    for row in policy['items'][0]['spec']['validations']:
        if row['message'] == 'F01_POD_FIXED':
            old = json.dumps("runsc-f01-a2-v1")
            if row['expression'].count(old) != 1:
                raise ValueError('REFERENCE_RUNTIME_CLASS_SHAPE')
            row['expression'] = row['expression'].replace(old, json.dumps(RUNTIME_CLASS))
        elif row['message'] == 'F01_METADATA':
            old = json.dumps('ilm-sandbox-a2')
            if row['expression'].count(old) != 1:
                raise ValueError('REFERENCE_NAMESPACE_SHAPE')
            row['expression'] = row['expression'].replace(old, json.dumps(NAMESPACE))
        elif row['message'] == 'F01_EXECUTABLE':
            row['expression'] = executable_expression(row['expression'], profiles)
    return {'namespace': namespace, 'policy': policy, 'profiles': profiles, 'golden': golden}
