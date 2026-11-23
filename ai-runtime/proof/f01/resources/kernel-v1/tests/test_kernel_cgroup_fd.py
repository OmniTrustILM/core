"""Real host filesystem operations test pinning; not a native cgroup test."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import importlib.util
from pathlib import Path
_spec = importlib.util.spec_from_file_location('kernel_observer_for_' + __name__, Path(__file__).parents[1] / 'python' / 'kernel_observer.py')
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)


class CgroupFD(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve(strict=True)
        self.root = self.base / 'pod'
        self.root.mkdir(mode=0o700)
        (self.root / 'pids.max').write_bytes(b'256\n')
        (self.root / 'cgroup.type').write_bytes(b'domain\n')
        (self.root / 'cgroup.stat').write_bytes(b'nr_descendants 0\nnr_dying_descendants 0\n')
        self.owner = patch.object(module, 'KERNEL_OWNER_UID', os.getuid(), create=True)
        self.owner.start();self.addCleanup(self.owner.stop)
        self.acls = patch.object(module.os, 'listxattr', return_value=[], create=True)
        self.acls.start();self.addCleanup(self.acls.stop)

    def feature(self):
        value = getattr(module, 'PodCgroup', None)
        self.assertTrue(callable(value), 'FD-anchored Pod cgroup reader absent')
        return value

    def test_fixed_counter_is_read_from_pinned_regular_object(self):
        cls = self.feature()
        with cls(self.root) as group:
            self.assertEqual(group.read_field('pids.max'), ['256'])
            self.assertEqual(group.identity, [self.root.stat().st_dev, self.root.stat().st_ino])

    def test_same_name_new_directory_cannot_replace_original_object(self):
        cls = self.feature()
        with cls(self.root) as group:
            self.root.rename(self.base / 'old-pod')
            self.root.mkdir()
            (self.root / 'pids.max').write_bytes(b'256\n')
            with self.assertRaisesRegex(module.ProofError, '^CGROUP_IDENTITY$'):
                group.read_field('pids.max')

    def test_symlink_counter_never_becomes_a_controller_value(self):
        cls = self.feature();(self.base / 'outside').write_bytes(b'256\n')
        (self.root / 'pids.max').unlink();(self.root / 'pids.max').symlink_to(self.base / 'outside')
        with cls(self.root) as group:
            with self.assertRaisesRegex(module.ProofError, '^COUNTER_PATH$'):
                group.read_field('pids.max')

    def test_unknown_controller_is_rejected_before_any_open(self):
        cls = self.feature();calls = []
        def unexpected(*args, **kwargs):
            calls.append(args)
            raise RuntimeError('unexpected controller open')
        with cls(self.root) as group:
            with patch.object(module.os, 'open', unexpected):
                with self.assertRaisesRegex(module.ProofError, '^COUNTER_FILE$'):
                    group.read_field('../outside')
        self.assertEqual(calls, [])

    def test_replaced_controller_inode_during_read_is_not_credited(self):
        cls = self.feature();original = os.read;done = []
        def read(fd, count):
            result = original(fd, count)
            if not done:
                done.append(True)
                (self.root / 'pids.max').rename(self.root / 'old-counter')
                (self.root / 'pids.max').write_bytes(b'256\n')
            return result
        with cls(self.root) as group:
            with patch.object(module.os, 'read', read):
                with self.assertRaisesRegex(module.ProofError, '^COUNTER_IDENTITY$'):
                    group.read_field('pids.max')

    def test_counter_byte_cap_is_real_and_not_silent_truncation(self):
        cls = self.feature();(self.root / 'pids.events').write_bytes(b'x' * 8193 + b'\n')
        with cls(self.root) as group:
            with self.assertRaisesRegex(module.ProofError, '^COUNTER_BYTES$'):
                group.read_field('pids.events')

    def test_wrong_owner_is_not_a_trusted_kernel_resource_boundary(self):
        cls = self.feature()
        with patch.object(module, 'KERNEL_OWNER_UID', os.getuid() + 1):
            with self.assertRaisesRegex(module.ProofError, '^CGROUP_OWNER$'):
                cls(self.root)

    def test_directory_only_limits_enumeration_never_reads_task_population(self):
        cls = self.feature();scope = self.root / 'scope';scope.mkdir(mode=0o700)
        (scope / 'pids.max').write_bytes(b'max\n');(scope / 'cgroup.type').write_bytes(b'domain\n')
        (self.root / 'cgroup.stat').write_bytes(b'nr_descendants 1\nnr_dying_descendants 0\n')
        opened = [];original = os.open
        def opening(name, *args, **kwargs):
            opened.append(str(name))
            if str(name).endswith(('cgroup.procs', 'cgroup.threads', 'children')):
                raise RuntimeError('task census forbidden')
            return original(name, *args, **kwargs)
        with cls(self.root) as group:
            with patch.object(module.os, 'open', opening):
                limits = group.directory_limits()
        self.assertEqual(limits, {str(self.root): ['256'], str(scope): ['max']})
        self.assertTrue(opened)
        self.assertFalse(any(name.endswith(('cgroup.procs', 'cgroup.threads', 'children')) for name in opened))

    def test_cgroup_directory_count_bound_or_symlink_is_not_skipped(self):
        cls = self.feature()
        (self.root / 'cgroup.stat').write_bytes(b'nr_descendants 17\nnr_dying_descendants 0\n')
        with cls(self.root) as group:
            with self.assertRaisesRegex(module.ProofError, '^CGROUP_TOPOLOGY$'):
                group.directory_limits()
        (self.root / 'cgroup.stat').write_bytes(b'nr_descendants 1\nnr_dying_descendants 0\n')
        (self.root / 'scope').symlink_to(self.base, target_is_directory=True)
        with cls(self.root) as group:
            with self.assertRaisesRegex(module.ProofError, '^CGROUP_TOPOLOGY$'):
                group.directory_limits()


if __name__ == '__main__': unittest.main()
