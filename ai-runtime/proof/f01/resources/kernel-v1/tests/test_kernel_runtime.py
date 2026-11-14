import copy
import importlib.util
from pathlib import Path
import unittest

P = (Path(__file__).parents[1] / 'python' / 'kernel_runtime.py')
if P.exists():
    spec = importlib.util.spec_from_file_location('kernel_runtime', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
else: m = None


class Runtime(unittest.TestCase):
    def fixture(self):
        self.assertIsNotNone(m, 'fixed API/CRI/OCI runtime adapter absent')
        target = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'a' * 64, 'sid': 'b' * 64, 'name': 'f01-a2-process-limit', 'startTime': '2026-11-05T00:00:00Z'}
        profile = {'metadata': {'name': target['name'], 'namespace': 'ilm-resource-sec-r1', 'labels': {'ilm.ai/proof': 'a2-v1'}}, 'spec': {'runtimeClassName': 'runsc-f01-kernel-cg-r1', 'activeDeadlineSeconds': 30, 'containers': [{'name': 'fixed-proof', 'command': ['/bin/busybox', 'ash', '-c'], 'args': ['echo $$$$'], 'image': 'pinned'}]}}
        oci = {'root': {'readonly': True}, 'process': {'args': ['/bin/busybox', 'ash', '-c', 'echo $$'], 'user': {'uid': 65532, 'gid': 65532}, 'capabilities': {}, 'noNewPrivileges': True, 'rlimits': [{'type': 'RLIMIT_NPROC', 'soft': 256, 'hard': 256}, {'type': 'RLIMIT_NOFILE', 'soft': 1024, 'hard': 1024}]}, 'linux': {'seccomp': {'defaultAction': 'SCMP_ACT_ERRNO'}, 'resources': {'memory': {'limit': 268435456}, 'cpu': {'quota': 50000, 'period': 100000}}, 'namespaces': [{'type': 'cgroup'}], 'cgroupsPath': 'kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice:cri-containerd:' + target['cid']}, 'mounts': [{'destination': '/sys/fs/cgroup', 'type': 'cgroup', 'options': ['ro']}, {'destination': '/sys', 'options': ['ro']}]}
        scratch = '/var/lib/kubelet/pods/' + target['uid'] + '/volumes/kubernetes.io~empty-dir/scratch'
        oci['mounts'] += [{'destination': destination, 'source': scratch, 'type': 'bind'} for destination in ('/scratch', '/tmp')]
        status = {'id': target['cid'], 'metadata': {'name': 'fixed-proof', 'attempt': 0}, 'labels': {'io.kubernetes.pod.' + key: value for key, value in [('uid', target['uid']), ('name', target['name']), ('namespace', 'ilm-resource-sec-r1')]}, 'state': 'CONTAINER_RUNNING'}
        current = {'status': status, 'info': {'runtimeType': 'io.containerd.runsc.v1', 'runtimeSpec': oci}}
        pod = {'metadata': {**profile['metadata'], 'uid': target['uid']}, 'spec': copy.deepcopy(profile['spec']), 'status': {'startTime': target['startTime'], 'containerStatuses': [{'name': 'fixed-proof', 'restartCount': 0, 'containerID': 'containerd://' + target['cid']}]}}
        return target, profile, current, pod

    def test_exact_golden_program_uid_and_non_migrating_runner_floor_are_required(self):
        target, profile, current, pod = self.fixture();m.check_pod(pod, target, profile);m.check_container(current, target)
        value = m.check_oci(current['info']['runtimeSpec'], target, profile, 'echo $$')
        self.assertEqual(value['podCgroup'], '/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice')
        self.assertEqual(value['programSha256'], __import__('hashlib').sha256(b'echo $$').hexdigest())

    def test_delivered_program_drift_dollar_collapse_or_wrong_mount_is_stop(self):
        self.fixture()
        for fault in ('program', 'pidlimit', 'cgroup-rw', 'hostcg-bind', 'missing-cgns', 'scratch', 'caps', 'uid', 'nofile'):
            with self.subTest(fault=fault):
                target, profile, current, _ = self.fixture();oci = current['info']['runtimeSpec']
                if fault == 'program': oci['process']['args'][-1] = 'echo $'
                elif fault == 'pidlimit': oci['linux']['resources']['pids'] = None
                elif fault == 'cgroup-rw': oci['mounts'][0]['options'] = ['rw']
                elif fault == 'hostcg-bind': oci['mounts'][0].update(type='bind', source='/sys/fs/cgroup')
                elif fault == 'missing-cgns': oci['linux']['namespaces'] = []
                elif fault == 'scratch': oci['mounts'][-1]['source'] = '/foreign'
                elif fault == 'caps': oci['process']['capabilities'] = {'effective': ['CAP_SYS_ADMIN']}
                elif fault == 'uid': oci['process']['user']['uid'] = 0
                else: oci['process']['rlimits'][-1]['hard'] = 4096
                with self.assertRaises(m.RuntimeProofError): m.check_oci(oci, target, profile, 'echo $$')

    def test_foreign_uid_namespace_cid_or_restart_cannot_be_accepted(self):
        self.fixture()
        for fault in ('uid', 'ns', 'cid', 'restart'):
            with self.subTest(fault=fault):
                target, profile, current, pod = self.fixture()
                if fault == 'uid': pod['metadata']['uid'] = 'foreign'
                elif fault == 'ns': pod['metadata']['namespace'] = 'other'
                elif fault == 'cid': pod['status']['containerStatuses'][0]['containerID'] = 'containerd://' + 'c' * 64
                else: pod['status']['containerStatuses'][0]['restartCount'] = 1
                with self.assertRaises(m.RuntimeProofError): m.check_pod(pod, target, profile)

    def test_cri_nonzero_attempt_foreign_labels_and_nonrunsc_runtime_are_stop(self):
        self.fixture()
        for fault in ('attempt', 'labels', 'runtime'):
            with self.subTest(fault=fault):
                target, _, current, _ = self.fixture()
                if fault == 'attempt': current['status']['metadata']['attempt'] = 1
                elif fault == 'labels': current['status']['labels']['io.kubernetes.pod.namespace'] = 'other'
                else: current['info']['runtimeType'] = 'io.containerd.runc.v2'
                with self.assertRaises(m.RuntimeProofError): m.check_container(current, target)


if __name__ == '__main__': unittest.main()
