"""Composed fixed trial with OS/cluster boundaries injected; no native proof credit."""
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import test_kernel_runtime as runtime_fixture

BASE = Path(__file__).parents[1] / 'python'
def load(name):
    spec = importlib.util.spec_from_file_location('composed_' + name, BASE / (name + '.py'))
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
collect = load('kernel_collect');kernel = load('kernel_observer');runtime = load('kernel_runtime');protocol = load('kernel_protocol')
OUTCOMES = BASE / 'high_outcomes.py'


class Composed(unittest.TestCase):
    def setUp(self): self.unexpected = [];self.closed = [];self.calls = []
    def tearDown(self): self.assertEqual(self.unexpected, [])

    def fixture(self, bad_binary=False, actual_measurement=False):
        temp = tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root = Path(temp.name).resolve()
        target, profile, current, pod = runtime_fixture.Runtime().fixture()
        target['name'] = 'f01-a2-scratch-a';profile['metadata']['name'] = target['name'];pod['metadata']['name'] = target['name']
        stamp = datetime.datetime.now(datetime.timezone.utc)
        target['startTime'] = stamp.isoformat().replace('+00:00', 'Z');pod['status']['startTime'] = target['startTime']
        current['status']['labels']['io.kubernetes.pod.name'] = target['name']
        mono = time.monotonic();wall = time.time();deadline = mono + 30 - (wall - stamp.timestamp())
        clock = {'podStartTime': target['startTime'], 'monotonic': mono, 'realtime': wall, 'deadlineMonotonic': deadline}
        finished = (stamp + datetime.timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        state = {'exited': False, 'signal': False};sandbox = {'status': {'id': target['sid'], 'metadata': {'name': target['name'], 'uid': target['uid'], 'namespace': collect.NS, 'attempt': 0}, 'runtimeHandler': runtime.HANDLER}, 'info': {'runtimeSpec': {'linux': {'resources': {}}}}}
        argv_pod = ('/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1', '--request-timeout=2s', 'get', 'pod', target['name'], '-n', collect.NS, '-o', 'json')
        argv_cri = ('/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'inspect', target['cid']);argv_sid = ('/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'inspectp', target['sid'])
        argv_signal = ('/usr/local/bin/runsc', '--root=' + collect.RUNTIME_ROOT, 'kill', target['cid'], 'USR1')
        def command(argv, **kwargs):
            self.calls.append(list(argv));key = tuple(argv)
            if key == argv_pod:
                value = copy.deepcopy(pod);value['status']['phase'] = 'Succeeded' if state['exited'] else 'Running'
                value['status']['containerStatuses'][0]['state'] = {'terminated': {'exitCode': 0}} if state['exited'] else {'running': {}}
            elif key == argv_cri:
                value = copy.deepcopy(current)
                if state['exited']:value['status'].update(state='CONTAINER_EXITED', exitCode=0, finishedAt=finished, reason='Completed')
            elif key == argv_sid:value = copy.deepcopy(sandbox)
            elif key == argv_signal:
                self.assertFalse(state['signal'], 'one exact signal only');state['signal'] = True;return b''
            else:
                self.unexpected.append(argv);raise AssertionError('UNEXPECTED_FIXED_TRIAL_ARGV')
            return json.dumps(value)
        r = types.SimpleNamespace(**vars(runtime));r.bounded_command = command
        binaries = {}
        def identity(path):
            info = path.stat();return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        for role in ('sentry', 'gofer', 'parking'):
            p = root / role;p.write_bytes(role.encode());binaries[role] = (str(p), hashlib.sha256(p.read_bytes()).hexdigest())
        if bad_binary:binaries['sentry'] = (binaries['sentry'][0], '0' * 64)
        leaf = 'kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice'
        parent_path = '/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/' + leaf
        group = parent_path.removeprefix('/sys/fs/cgroup') + '/cri-containerd-' + target['sid'] + '.scope'
        seeds = [{'role': role, 'fd': 100000 + i, 'identity': {'pid': pid, 'startTicks': pid + 1000, 'cgroup': group}}
                 for i, (role, pid) in enumerate([('sentry', 100), ('sandbox-gofer', 200), ('container-gofer', 300)])]
        ids={};post_terminal_reads=[]
        class Parent:
            def __init__(self, path):
                self.root=Path(path);key=str(self.root)
                if key not in ids:ids[key]=[1,10+len(ids)]
                self.identity=ids[key];self.was_closed=False
            def check(self): pass
            def check_retained(self): return True
            def read_field(self,name):
                if str(self.root)!=parent_path:
                    if state['exited']:post_terminal_reads.append((str(self.root),name))
                    if name in ('pids.max','memory.max'):return ['max']
                    if name in ('pids.events','pids.events.local'):return {'max':0}
                    raise AssertionError('UNEXPECTED_SYNTHETIC_GROUP_FIELD')
                if name=='cgroup.stat':return {'nr_descendants':0 if state['exited'] else 1,'nr_dying_descendants':0}
                return copy.deepcopy(values[name])
            def directory_limits(self):
                result={parent_path:['256']}
                if not state['exited']:result['/sys/fs/cgroup'+group]=['max']
                return result
            def close(self): self.was_closed = True
            def __enter__(self):return self
            def __exit__(self,*_):self.close()
        values = {'pids.max': ['256'], 'pids.current': ['7'], 'pids.events': {'max': 0}, 'pids.events.local': {'max': 0}, 'memory.max': ['268435456'], 'memory.current': ['1000000'], 'memory.peak': ['1000000'], 'memory.swap.max': ['0'], 'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0}, 'cpu.max': ['50000', '100000'], 'cpu.stat': {'usage_usec': 1, 'nr_throttled': 0}}
        class Measurement:
            def __init__(self, *args): pass
            def read(self, retain_floor=None):
                if retain_floor is not None:
                    retain_floor({'parent': parent_path, 'identity': [1, 10],
                                  'limits': {field: list(values[field]) for field in
                                             ('pids.max', 'memory.max', 'memory.swap.max', 'cpu.max')}})
                return {'counters': copy.deepcopy(values), 'pidView': {}}
            def read_terminal_parent(self):
                return {'schema':'f01-terminal-parent-counters-v1','parentOrigin':[parent_path,[1,10]],
                        'counters':copy.deepcopy(values)}
        high_messages = ['CONTROL_BYTES 1048576', 'SCRATCH_DD_RC 1', 'FILL_BYTES 16777216', 'ALIAS_BYTES 16777216', "dd: /scratch/fill: No space left on device", 'SCRATCH_RELEASED']
        class Stream:
            def __init__(self, *args): self.buffer = collect.LogBuffer();self.stderr = b'';self.closed = False
            def drain(self, emit, wait=0):
                if not self.buffer.raw:
                    self.buffer.feed(b'2026-11-05T00:00:00Z CG_READY pid=1 start=55\n', time.monotonic(), emit)
            def finish(self, emit):
                self_outer.assertTrue(state['signal'])
                messages = ['CG_RAW attempt=1 rc=0 count=1 token=GO', 'CG_ACK pid=1 start=55 count=1', 'CG_LOAD_BEGIN'] + high_messages
                self.buffer.feed(''.join('2026-11-05T00:00:01Z ' + line + '\n' for line in messages).encode(), time.monotonic(), emit)
                self.buffer.boundary()
            def close(self): self.closed = True
        self_outer = self
        def sample_loop(control, native, observed, read, fence, terminal, query, pump, publish, now, sleep):
            self.assertEqual(fence(), 'LIVE')
            row = {'sample': 0, 'status': 'verified', 'monotonic': now(), 'counterReadStart': now(), 'counterReadEnd': now(), 'nativePids': 7, **read(), 'rootProjection': None}
            publish(row);pump(False)
            state['exited'] = True;ended = terminal()
            return {'samples': [row], 'terminal': ended, 'quiescence': None, 'discarded': 0}
        k = types.SimpleNamespace(**vars(kernel));k.PodCgroup = Parent
        k.KernelMeasurement=kernel.KernelMeasurement if actual_measurement else Measurement
        k.bind_seeds = lambda *args: seeds;k.seed_fence = lambda *args: 'LIVE';k.sample_loop = sample_loop
        owner = types.SimpleNamespace(runtime_candidates=lambda root, target: [{'role': row['role'], 'pid': row['identity']['pid']} for row in seeds])
        ops = {'BINARIES': binaries, 'file_identity': identity}
        outcome_raw = OUTCOMES.read_bytes();self.assertEqual(hashlib.sha256(outcome_raw).hexdigest(), collect.OUTCOMES_SHA)
        outcomes = {'__name__': 'composed_outcomes'};exec(compile(outcome_raw, str(OUTCOMES), 'exec'), outcomes)
        trial = collect.Trial({'kernel_observer': k, 'kernel_owner': owner, 'kernel_runtime': r,
            'kernel_protocol': protocol,'scratch_metadata':load('scratch_metadata')}, ops, outcomes, target, root / 'observation', 'scratch-a', profile, 'echo $$', clock, lambda: None)
        trial.fixture_group=Parent;trial.fixture_post_terminal_reads=post_terminal_reads
        return trial, Stream

    def test_composed_setup_exact_ownership_gate_native_outcome_publication_and_descriptor_closure(self):
        trial, stream = self.fixture()
        with patch.object(collect, 'LogStream', stream), patch.object(collect.os, 'pidfd_open', lambda pid: pid, create=True), patch.object(collect.os, 'close', side_effect=self.closed.append):
            verdict = trial.run()
        self.assertEqual(verdict['status'], 'OBSERVED')
        result = json.loads((trial.out / 'observer-result.json').read_bytes())
        self.assertEqual(result['target'], trial.target);self.assertEqual(result['samples'], 1)
        self.assertEqual(self.closed, [100000, 100001, 100002])
        self.assertTrue(trial.parent.was_closed);self.assertTrue(trial.stream.closed)
        owner = json.loads((trial.out / 'kernel-owner.json').read_bytes())
        self.assertEqual([seed['role'] for seed in owner['seeds']], ['sentry', 'sandbox-gofer', 'container-gofer'])
        self.assertNotIn('hostMembers', owner)

    def test_binary_digest_failure_prevents_gate_state_adoption_or_runtime_signal(self):
        trial, stream = self.fixture(bad_binary=True)
        with patch.object(collect, 'LogStream', stream), self.assertRaisesRegex(AssertionError, '^BINARY_DIGEST$'):trial.run()
        self.assertFalse((trial.out / 'kernel-owner.json').exists())
        self.assertFalse(any(argv[0] == '/usr/local/bin/runsc' for argv in self.calls))

    def test_actual_measurement_and_oracle_compose_after_child_scope_exits_without_any_terminal_child_read(self):
        trial,stream=self.fixture(actual_measurement=True)
        with patch.object(collect,'LogStream',stream),patch.object(collect.os,'pidfd_open',lambda pid:pid,create=True), \
             patch.object(collect.os,'close',side_effect=self.closed.append),patch.object(kernel,'PodCgroup',trial.fixture_group):
            verdict=trial.run()
        self.assertEqual(verdict['status'],'OBSERVED')
        self.assertEqual(trial.fixture_post_terminal_reads,[])
        facts=json.loads((trial.out/'facts.json').read_bytes())
        self.assertEqual(facts['terminalCounterEndpoint']['schema'],'f01-owned-terminal-endpoint-v1')
        self.assertNotIn('pidView',facts['terminalCounterEndpoint']['value'])
        self.assertIs(facts['counterOrigin']['escapeProof'],False)


if __name__ == '__main__': unittest.main()
