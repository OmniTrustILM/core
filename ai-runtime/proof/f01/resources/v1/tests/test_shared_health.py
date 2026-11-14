"""Exercise the shared health check with finite local API/CRI/disk fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import bootstrap as bootstrap


SOURCE = Path(os.environ['F01_CANDIDATE_SOURCE']) / 'resources/v1'
THRESHOLD = '2026-10-29T00:00:00Z'
COMMANDS = r'''
set -euo pipefail
[[ -r "$1" ]] || exit 93
BASE=$(dirname -- "$1");export BASE
source "$1" || exit 93
OUT=$2; FIXTURES=$3; JQ_REAL=$4; FREE_KIB=$5
k() {
 printf '%s\n' "$*" >> "$OUT/calls.txt"
 case "$*" in
  'get --raw=/readyz') cat "$FIXTURES/readyz.txt";;
  'get nodes -o json') cat "$FIXTURES/nodes.json";;
  'get lease node-one -n kube-node-lease -o json') cat "$FIXTURES/lease.json";;
  'get pods -n kube-system -o json') cat "$FIXTURES/pods.json";;
  *) return 90;;
 esac
}
function /usr/local/bin/crictl() {
 [[ "$*" == '--runtime-endpoint unix:///run/containerd/containerd.sock --image-endpoint unix:///run/containerd/containerd.sock ps --state running --name ^(calico-node|calico-kube-controllers|coredns)$ --label io.kubernetes.pod.namespace=kube-system -o json' ]] || return 91
 printf '%s\n' "$*" >> "$OUT/calls.txt"
 cat "$FIXTURES/cri.json"
}
jq() { "$JQ_REAL" "$@"; }
df() {
 [[ "$*" == '-Pk /' ]] || return 92
 printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nsynthetic 4194304 0 %s 0%% /\n' "$FREE_KIB"
}
health observed "$6"
'''


class SharedHealth(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='f01-shared-health-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fixtures = self.root / 'fixtures'
        self.out = self.root / 'out'
        self.fixtures.mkdir()
        self.out.mkdir()
        self.jq = shutil.which('jq')
        self.assertIsNotNone(self.jq, 'jq is required for the offline health fixtures')
        self.bash = shutil.which('bash')
        self.assertIsNotNone(self.bash, 'Bash 5 or later is required for the offline health fixtures')
        self.write('readyz.txt', 'ok\n')
        self.write('nodes.json', {'items': [{'metadata': {'name': 'node-one'}, 'status': {
            'conditions': [{'type': 'Ready', 'status': 'True'}]}}]})
        self.write('lease.json', {'spec': {'holderIdentity': 'node-one',
                                         'renewTime': '2026-10-29T00:00:01Z'}})
        pods = []
        containers = []
        for index, name in enumerate(('calico-node', 'calico-kube-controllers', 'coredns', 'coredns')):
            uid = f'public-uid-{index}'
            pods.append({'metadata': {'name': name + '-public-' + str(index), 'uid': uid}, 'status': {
                'phase': 'Running', 'containerStatuses': [
                    {'name': name, 'ready': True, 'restartCount': 0}]}})
            containers.append({'id': str(index + 1) * 64, 'metadata': {'name': name},
                'labels': {'io.kubernetes.pod.uid': uid,
                           'io.kubernetes.pod.namespace': 'kube-system'},
                'state': 'CONTAINER_RUNNING'})
        self.write('pods.json', {'items': pods})
        self.write('cri.json', {'containers': containers})

    def write(self, name, value):
        (self.fixtures / name).write_text(value if isinstance(value, str) else json.dumps(value))

    def run_health(self, threshold=THRESHOLD, free_kib=1048576):
        return subprocess.run([
            self.bash, '-c', COMMANDS, 'offline-health', str(SOURCE / 'health.sh'),
            str(self.out), str(self.fixtures), self.jq, str(free_kib), threshold,
        ], capture_output=True, text=True, timeout=10)

    def test_success_requires_matching_api_cri_ownership_and_fresh_lease(self):
        result = self.run_health()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / 'observed-lease.json').read_text()), {
            'holderIdentity': 'node-one', 'renewTime': '2026-10-29T00:00:01Z'})
        self.assertEqual(len(json.loads((self.out / 'observed-infra-cri.json').read_text())), 4)

    def test_no_threshold_does_not_query_or_require_a_lease(self):
        (self.fixtures / 'lease.json').unlink()
        result = self.run_health(threshold='')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('get lease', (self.out / 'calls.txt').read_text())
        self.assertFalse((self.out / 'observed-lease.json').exists())

    def test_not_ready_stops_before_nodes_and_infrastructure_queries(self):
        self.write('readyz.txt', 'not-ready\n')
        result = self.run_health()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.out / 'calls.txt').read_text(), 'get --raw=/readyz\n')

    def test_wrong_cri_ownership_fails_even_when_names_and_state_match(self):
        cri = json.loads((self.fixtures / 'cri.json').read_text())
        cri['containers'][0]['labels']['io.kubernetes.pod.uid'] = 'different-public-uid'
        self.write('cri.json', cri)
        result = self.run_health()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue((self.out / 'observed-infra-cri.json').exists())

    def test_stale_lease_stops_before_infrastructure_queries(self):
        self.write('lease.json', {'spec': {'holderIdentity': 'node-one',
                                         'renewTime': THRESHOLD}})
        result = self.run_health()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('get pods', (self.out / 'calls.txt').read_text())

    def test_low_disk_fails_after_valid_infrastructure_checks(self):
        result = self.run_health(free_kib=1048575)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(json.loads((self.out / 'observed-infra-cri.json').read_text())), 4)

    def test_both_callers_load_health_before_argument_refusal_and_can_export_its_body(self):
        code = r'''
CALLER=$1; DECLARED=$2; set --
trap 'declare -f health > "$DECLARED"; "$BASH" -c "$(declare -f health); declare -F health"' EXIT
source "$CALLER"
'''
        for name in ('prepare-runtime.sh', 'run-resources.sh'):
            with self.subTest(caller=name):
                declared = self.root / (name + '.declared')
                result = subprocess.run([
                    self.bash, '-c', code, 'offline-caller', str(SOURCE / name), str(declared),
                ], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout.strip(), 'health')
                self.assertTrue(declared.read_text().startswith('health ()'))


    def test_real_callers_set_and_export_base_before_loading_and_using_shared_health(self):
        # Invalid arguments stop each real caller before any lab operation. Its EXIT
        # trap then exercises the actual imported health function with finite fixtures.
        prefix=COMMANDS.replace('BASE=$(dirname -- "$1");export BASE\nsource "$1" || exit 93\n','')
        self.assertNotEqual(prefix,COMMANDS)
        prefix=prefix[:prefix.rindex('health observed "$6"')]
        for name in ('run-resources.sh','prepare-runtime.sh'):
            with self.subTest(caller=name):
                output=self.root/(name+'-actual-caller');output.mkdir()
                script=prefix+"trap 'trap - EXIT; health observed \"$6\"; printf \"%s\\n\" \"$BASE\" > \"$OUT/actual-base.txt\"' EXIT\nsource \"$1\"\n"
                result=subprocess.run([self.bash,'-c',script,'actual-caller',str(SOURCE/name),str(output),str(self.fixtures),self.jq,'1048576',THRESHOLD],capture_output=True,text=True,timeout=10,env=os.environ|{'BASE':'/wrong-base-must-be-overwritten'})
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertEqual((output/'actual-base.txt').read_text().strip(),str(SOURCE))
                self.assertEqual(json.loads((output/'observed-lease.json').read_text())['holderIdentity'],'node-one')
                self.assertEqual(len(json.loads((output/'observed-infra-cri.json').read_text())),4)

if __name__ == '__main__':
    unittest.main()
