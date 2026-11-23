"""Fixed proc identities only: never enumerate task/thread/children membership."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('kernel_seed', (Path(__file__).parents[1] / 'python' / 'kernel_observer.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class SeedIdentity(unittest.TestCase):
    def feature(self):
        value = getattr(m, 'read_seed_identity', None)
        self.assertIsNotNone(value, 'fixed proc seed identity reader missing')
        return value

    def fixture(self):
        root = Path(tempfile.mkdtemp()).resolve();self.addCleanup(lambda: __import__('shutil').rmtree(root))
        base = root / '123';base.mkdir();exe = root / 'trusted';exe.write_bytes(b'measured')
        (base / 'exe').symlink_to(exe)
        # Tail field20 is starttime; comm may contain closing parens and spaces.
        (base / 'stat').write_text('123 (odd ) process) S 1 ' + '0 ' * 17 + '777 0\n')
        (base / 'status').write_text('Name:\ttest\nTgid:\t123\nPid:\t123\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0000000000000000\n')
        (base / 'cgroup').write_text('0::/pod/scope\n')
        (base / 'cmdline').write_bytes(b'runsc-sandbox\0--platform=systrap\0--root=/run/containerd/runsc/k8s.io\0' + b'b' * 64 + b'\0')
        return root, base, exe

    def test_exact_proc_record_carries_start_executable_cgroup_credentials_and_args(self):
        f = self.feature();root, _, exe = self.fixture();value = f(123, root)
        self.assertEqual(value['pid'], 123);self.assertEqual(value['startTicks'], 777)
        self.assertEqual(value['cgroup'], '/pod/scope');self.assertEqual(value['uid'], [0] * 4)
        self.assertEqual(value['exeIdentity'], [exe.stat().st_dev, exe.stat().st_ino])
        self.assertEqual(value['args'][-1], 'b' * 64)

    def test_only_proc_missing_zombie_and_exe_enoent_become_exit_symptoms(self):
        f = self.feature()
        for fault in ('missing', 'zombie', 'exe'):
            with self.subTest(fault=fault):
                root, base, _ = self.fixture()
                if fault == 'missing': (base / 'status').unlink()
                elif fault == 'zombie': (base / 'stat').write_text('123 (z) Z 1 ' + '0 ' * 17 + '777 0\n')
                else: (base / 'exe').unlink()
                with self.assertRaises(m.SeedExitSymptom): f(123, root)

    def test_malformed_or_changed_numeric_identity_is_stop_not_exit(self):
        f = self.feature()
        for fault in ('pid', 'cgroup', 'status', 'nul', 'size'):
            with self.subTest(fault=fault):
                root, base, _ = self.fixture()
                if fault == 'pid': (base / 'stat').write_text('124 (x) S 1 ' + '0 ' * 17 + '777 0\n')
                elif fault == 'cgroup': (base / 'cgroup').write_text('0::/pod/../foreign\n')
                elif fault == 'status': (base / 'status').write_text('Pid: 123\nPid: 124\n')
                elif fault == 'nul': (base / 'cmdline').write_bytes(b'not-terminated')
                else: (base / 'stat').write_bytes(b'x' * 65537)
                with self.assertRaises(m.ProofError): f(123, root)

    def test_unrelated_io_error_is_not_a_seed_exit_symptom(self):
        f = self.feature();root, base, _ = self.fixture();(base / 'status').unlink();(base / 'status').mkdir()
        with self.assertRaises(IsADirectoryError): f(123, root)


if __name__ == '__main__': unittest.main()
