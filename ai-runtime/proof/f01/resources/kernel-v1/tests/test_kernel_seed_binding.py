import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bound_kernel', (Path(__file__).parents[1] / 'python' / 'kernel_observer.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Binding(unittest.TestCase):
    def fixture(self):
        f = getattr(m, 'bind_seeds', None);self.assertIsNotNone(f, 'three-pidfd binding missing')
        sid = 'b' * 64;scope = '/pod/cri-containerd-' + sid + '.scope'
        records = {pid: {'pid': pid, 'startTicks': pid + 1000, 'cgroup': scope,
                        'exeIdentity': [1, 10 if pid == 100 else 20],
                        'args': ['runsc-sandbox', '--platform=systrap', '--root=/run/containerd/runsc/k8s.io', sid] if pid == 100 else ['runsc-gofer'],
                        'uid': [0] * 4, 'gid': [0] * 4, 'capEff': '0'} for pid in (100, 200, 300)}
        candidates = [{'role': role, 'pid': pid} for role, pid in [('sentry', 100), ('sandbox-gofer', 200), ('container-gofer', 300)]]
        opened = [];closed = [];calls = []
        def opener(pid): opened.append(pid);return pid + 10
        def reader(pid):
            calls.append(pid);self.assertEqual(opened, [100, 200, 300]);return copy.deepcopy(records[pid])
        def poller(fds, wait): self.assertEqual(wait, 0);return []
        kwargs = dict(candidates=candidates, sid=sid, podgroup='/pod', binaries={'sentry': [1, 10], 'gofer': [1, 20]},
                      deadline=10, reader=reader, opener=opener, poller=poller, now=lambda: 1)
        return f, records, opened, closed, calls, kwargs

    def test_all_pidfds_open_before_proc_reads_then_full_second_identity_fence(self):
        f, _, opened, closed, calls, kwargs = self.fixture()
        with patch.object(m.os, 'close', side_effect=closed.append): value = f(**kwargs)
        self.assertEqual(opened, [100, 200, 300]);self.assertEqual(calls, [100, 200, 300] * 2)
        self.assertEqual([row['fd'] for row in value], [110, 210, 310]);self.assertEqual(closed, [])

    def test_wrong_measured_binary_cgroup_sid_or_platform_closes_all_without_credit(self):
        for fault in ('binary', 'cgroup', 'sid', 'platform', 'root'):
            with self.subTest(fault=fault):
                f, records, _, closed, _, kwargs = self.fixture()
                if fault == 'binary': records[200]['exeIdentity'] = [1, 999]
                elif fault == 'cgroup': records[300]['cgroup'] = '/foreign'
                elif fault == 'sid': records[100]['args'][-1] = 'c' * 64
                elif fault == 'platform': records[100]['args'][1] = '--platform=ptrace'
                else: records[100]['args'][2] = '--root=/foreign'
                with patch.object(m.os, 'close', side_effect=closed.append), self.assertRaises(m.ProofError): f(**kwargs)
                self.assertEqual(closed, [110, 210, 310])

    def test_seed_exit_before_binding_is_stop_and_all_descriptors_close(self):
        f, _, _, closed, _, kwargs = self.fixture();kwargs['poller'] = lambda fds, wait: [fds[0]]
        with patch.object(m.os, 'close', side_effect=closed.append), self.assertRaisesRegex(m.ProofError, '^PRELOAD_SEED_EXIT$'): f(**kwargs)
        self.assertEqual(closed, [110, 210, 310])

    def test_second_identity_change_is_stop_never_exit_reconciliation(self):
        f, records, _, closed, calls, kwargs = self.fixture();reader = kwargs['reader']
        def changed(pid):
            value = reader(pid)
            if len(calls) > 3: value['startTicks'] += 1
            return value
        kwargs['reader'] = changed
        with patch.object(m.os, 'close', side_effect=closed.append), self.assertRaisesRegex(m.ProofError, '^SEED_IDENTITY$'): f(**kwargs)
        self.assertEqual(closed, [110, 210, 310])


if __name__ == '__main__': unittest.main()
