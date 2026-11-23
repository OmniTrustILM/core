import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('cleanup_dispatch', (Path(__file__).parents[1] / 'python' / 'kernel_cleanup.py'));m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Dispatch(unittest.TestCase):
    def setUp(self): self.calls = [];self.unexpected = [];self.expected = []
    def tearDown(self): self.assertEqual(self.unexpected, [])
    def fixture(self):
        klass = getattr(m, 'OwnedCleanup', None);self.assertIsNotNone(klass, 'finite exact-UID cleanup dispatcher missing')
        t = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'a' * 64, 'sid': 'b' * 64, 'name': 'f01-a2-process-limit', 'startTime': '2026-11-05T00:00:00Z'}
        o = {'schema': 'f01-kernel-owner-v1', 'target': t, 'namespace': m.NS, 'runtimeRoot': m.RUNTIME_ROOT,
             'parent': {'path': '/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod' + t['uid'].replace('-', '_') + '.slice', 'identity': [1, 10]},
             'seeds': [{'role': role, 'pid': pid, 'startTicks': pid + 1000} for role, pid in [('sentry', 100), ('sandbox-gofer', 200), ('container-gofer', 300)]]}
        prefix = ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1', '--request-timeout=2s']
        get = prefix + ['get', 'pod', t['name'], '-n', m.NS, '--ignore-not-found', '-o', 'json']
        pod = {'metadata': {'uid': t['uid'], 'name': t['name'], 'namespace': m.NS, 'labels': {'ilm.ai/proof': 'a2-v1'}}, 'spec': {'runtimeClassName': 'runsc-f01-kernel-cg-r1'}}
        delete = prefix + ['delete', '--raw', '/api/v1/namespaces/' + m.NS + '/pods/' + t['name'], '-f', '-']
        ps = ['/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'ps', '-a', '--label', 'io.kubernetes.pod.namespace=' + m.NS, '-o', 'json']
        sandboxes = ['/usr/local/bin/crictl', '--runtime-endpoint', 'unix:///run/containerd/containerd.sock', '--image-endpoint', 'unix:///run/containerd/containerd.sock', 'pods', '--namespace', m.NS, '-o', 'json']
        self.expected = [(get, json.dumps(pod)), (delete, '{}'), (get, ''), (ps, '{"containers":[]}'),
            (sandboxes, '{"items":[]}'), (['/usr/local/bin/ctr', '--address', '/run/containerd/containerd.sock', '-n', 'k8s.io', 'tasks', 'list'], 'TASK PID STATUS\n'),
            (['/usr/local/bin/runsc', '--root=' + m.RUNTIME_ROOT, 'list', '--format=json'], '[]'),
            (prefix + ['get', 'pods', '-n', m.NS, '-o', 'json'], '{"items":[]}'),
            (prefix + ['get', 'resourcequota', '-n', m.NS, '-o', 'json'], '{"items":[{"status":{"used":{"pods":"0"}}}]}')]
        def command(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if not self.expected or argv != self.expected[0][0]:
                self.unexpected.append(argv);raise AssertionError('UNEXPECTED_GUEST_ARGV')
            _, value = self.expected.pop(0)
            if argv == delete:
                self.assertEqual(json.loads(kwargs['input']), {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': t['uid']}, 'gracePeriodSeconds': 1})
            return value.encode() if kwargs.get('raw') else value
        saved = [];self.seed_reads = [];self.parent_reads = []
        def read_seed(pid): self.seed_reads.append(pid);return None
        def read_parent(path): self.parent_reads.append(path);return None
        cleanup = klass(command, lambda name, value: saved.append((name, value)),
                        read_seed, read_parent, lambda path: False,
                        now=lambda: 0, sleep=lambda seconds: None)
        return cleanup, t, o, ps, sandboxes

    def test_full_exact_guest_argv_sequence_and_limited_absence_are_required(self):
        c, t, o, _, _ = self.fixture();result = c.run(t, lambda: o)
        self.assertEqual(self.expected, []);self.assertEqual(len(self.calls), 9);self.assertEqual(result['status'], 'PASS')
        self.assertEqual(self.seed_reads, [100, 200, 300]);self.assertEqual(self.parent_reads, [o['parent']['path']])
        self.assertEqual(result['runtimeSeedsAbsent'], 'PASS');self.assertEqual(result['ownedKernelSubtreeAbsent'], 'PASS')
        self.assertEqual(result['escapedDescendantAbsence'], 'UNPROVEN')
        self.assertNotIn('hostMembers', result)

    def test_namespace_only_foreign_uid_container_or_sandbox_is_not_hidden_by_uid_filter(self):
        self.fixture()
        for kind in ('container', 'sandbox'):
            with self.subTest(kind=kind):
                c, t, o, ps, sandboxes = self.fixture()
                argv = ps if kind == 'container' else sandboxes
                item = {'id': 'c' * 64, 'labels': {'io.kubernetes.pod.uid': 'foreign'}, 'metadata': {'uid': 'foreign'}}
                replacement = json.dumps({'containers' if kind == 'container' else 'items': [item]})
                self.expected = [(a, replacement if a == argv else value) for a, value in self.expected]
                with self.assertRaisesRegex(m.CleanupError, '^CLEANUP_FOREIGN_CRI$'): c.run(t, lambda: o)

    def test_exact_task_or_runtime_record_remaining_prevents_cleanup_pass(self):
        self.fixture()
        for kind in ('task', 'runsc'):
            with self.subTest(kind=kind):
                c, t, o, _, _ = self.fixture()
                for index, (argv, _) in enumerate(self.expected):
                    if kind == 'task' and argv[:4] == ['/usr/local/bin/ctr', '--address', '/run/containerd/containerd.sock', '-n']: self.expected[index] = (argv, 'TASK PID STATUS\n' + t['cid'] + ' 123 RUNNING\n')
                    elif kind == 'runsc' and argv[0] == '/usr/local/bin/runsc': self.expected[index] = (argv, json.dumps([{'id': t['sid']}]))
                with self.assertRaisesRegex(m.CleanupError, '^CLEANUP_' + ('TASK' if kind == 'task' else 'RUNSC') + '_PRESENT$'): c.run(t, lambda: o)

    def test_present_kubelet_path_exhausts_only_the_fixed_fifty_polls(self):
        c, t, o, _, _ = self.fixture()
        self.expected = self.expected[:2] + self.expected[2:5] * 50
        c.exists = lambda _: True
        pauses = [];c.sleep = pauses.append
        with self.assertRaisesRegex(m.CleanupError, '^CLEANUP_API_CRI_KUBELET_PRESENT$'):
            c.run(t, lambda: o)
        self.assertEqual(self.expected, [])
        self.assertEqual(len(self.calls), 152)
        self.assertEqual(pauses, [.1] * 50)
        self.assertEqual(self.seed_reads, [])

    def test_poll_sleep_uses_only_remaining_original_deadline(self):
        c, t, o, _, _ = self.fixture()
        self.expected = self.expected[:5]
        clock = [0.];c.now = lambda: clock[0]
        c.exists = lambda _: True
        def load_owner(): clock[0] = 9.95;return o
        pauses = []
        def sleep(value): pauses.append(value);clock[0] += value
        c.sleep = sleep
        with self.assertRaisesRegex(m.CleanupError, '^CLEANUP_DEADLINE$'):
            c.run(t, load_owner)
        self.assertEqual(self.expected, [])
        self.assertEqual(len(pauses), 1)
        self.assertAlmostEqual(pauses[0], .05)
        self.assertEqual(len(self.calls), 5)
        self.assertEqual(self.seed_reads, [])


if __name__ == '__main__': unittest.main()
