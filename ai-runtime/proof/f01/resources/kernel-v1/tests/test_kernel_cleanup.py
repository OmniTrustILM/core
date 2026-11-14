import copy
import importlib.util
import json
from pathlib import Path
import unittest

P = (Path(__file__).parents[1] / 'python' / 'kernel_cleanup.py')
if P.exists():
    spec = importlib.util.spec_from_file_location('kernel_cleanup', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
else: m = None


class Cleanup(unittest.TestCase):
    def fixture(self):
        self.assertIsNotNone(m, 'distinct owned kernel cleanup missing')
        target = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'a' * 64, 'sid': 'b' * 64, 'name': 'f01-a2-process-limit', 'startTime': '2026-11-05T00:00:00Z'}
        group = '/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice'
        owner = {'schema': 'f01-kernel-owner-v1', 'target': target, 'namespace': 'ilm-resource-sec-r1', 'runtimeRoot': '/run/containerd/runsc/k8s.io', 'parent': {'path': group, 'identity': [1, 10]}, 'seeds': [{'role': role, 'pid': pid, 'startTicks': pid + 1000} for role, pid in [('sentry', 100), ('sandbox-gofer', 200), ('container-gofer', 300)]]}
        return target, owner

    def test_only_original_seed_identities_and_removed_subtree_supply_limited_absence(self):
        target, owner = self.fixture();value = m.kernel_absence(owner, target, lambda pid: None, lambda path: None)
        self.assertEqual(value, {'runtimeSeedsAbsent': 'PASS', 'ownedKernelSubtreeAbsent': 'PASS', 'escapedDescendantAbsence': 'UNPROVEN'})

    def test_pid_reuse_is_original_identity_absence_but_live_original_is_failure(self):
        target, owner = self.fixture()
        result = m.kernel_absence(owner, target, lambda pid: {'pid': pid, 'startTicks': pid + 2000}, lambda path: None)
        self.assertEqual(result['runtimeSeedsAbsent'], 'PASS')
        result = m.kernel_absence(owner, target, lambda pid: {'pid': pid, 'startTicks': pid + 1000}, lambda path: None)
        self.assertEqual(result['runtimeSeedsAbsent'], 'FAILED')

    def test_empty_populated_zero_or_replaced_directory_never_means_subtree_removed(self):
        target, owner = self.fixture()
        for current in ({'identity': [1, 10], 'populated': 0}, {'identity': [1, 99], 'populated': 0}):
            with self.subTest(current=current):
                value = m.kernel_absence(owner, target, lambda pid: None, lambda path: current)
                self.assertEqual(value['ownedKernelSubtreeAbsent'], 'FAILED')

    def test_foreign_owner_uid_path_seed_or_namespace_cannot_grant_cleanup_credit(self):
        self.fixture()
        for fault in ('uid', 'path', 'seed', 'namespace', 'root'):
            with self.subTest(fault=fault):
                target, owner = self.fixture()
                if fault == 'uid': owner['target']['uid'] = 'foreign';target = dict(target, uid='12345678-1234-1234-1234-123456789abc')
                elif fault == 'path': owner['parent']['path'] = '/sys/fs/cgroup/foreign'
                elif fault == 'seed': owner['seeds'][2]['pid'] = 200
                elif fault == 'namespace': owner['namespace'] = 'foreign'
                else: owner['runtimeRoot'] = '/foreign'
                with self.assertRaises(m.CleanupError): m.kernel_absence(owner, target, lambda pid: None, lambda path: None)

    def test_missing_owner_has_no_host_absence_credit(self):
        target, _ = self.fixture();value = m.kernel_absence(None, target, lambda pid: self.fail('must not inspect guessed PID'), lambda path: self.fail('must not guess path'))
        self.assertEqual(value['runtimeSeedsAbsent'], 'UNAVAILABLE');self.assertEqual(value['ownedKernelSubtreeAbsent'], 'UNAVAILABLE')

    def test_partial_attach_can_only_dispatch_uid_delete_without_host_absence_credit(self):
        target, _ = self.fixture();partial = {key: target[key] for key in ('uid', 'name')}
        calls = []
        try: m.dispatch_delete(partial, lambda argv, **kwargs: calls.append((argv, kwargs)) or b'{}', 1)
        except m.CleanupError as error: self.fail('Known created Pod UID must retain deletion authority: ' + str(error))
        self.assertEqual(len(calls), 1);self.assertEqual(json.loads(calls[0][1]['input'])['preconditions']['uid'], target['uid'])

    def test_delete_is_exact_uid_precondition_not_name_only_or_ctr_kill(self):
        target, _ = self.fixture();calls = []
        def command(argv, **kwargs):
            calls.append((argv, kwargs));return b'{"status":"Success"}'
        value = m.dispatch_delete(target, command, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], ['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1', '--request-timeout=2s', 'delete', '--raw', '/api/v1/namespaces/ilm-resource-sec-r1/pods/f01-a2-process-limit', '-f', '-'])
        self.assertEqual(json.loads(calls[0][1]['input']), {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': target['uid']}, 'gracePeriodSeconds': 1})
        self.assertEqual(value, b'{"status":"Success"}')


if __name__ == '__main__': unittest.main()
