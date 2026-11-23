"""Controller semantic controls only; these fixtures grant no native kernel credit."""
import copy
import errno
import os
import tempfile
from unittest.mock import patch
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('fixed_pids_calibration', Path(__file__).parents[1] / 'python/pids_calibration.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ZERO = dict.fromkeys(('parentLocal', 'leafLocal', 'parentHierarchical', 'leafHierarchical'), 0)
CG2 = b'77 30 0:29 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot\n'

class Cases(unittest.TestCase):
    def test_three_actual_limit_patterns_are_distinct_with_one_native_fork(self):
        inputs = [('positive', ZERO, None, 0),
                  ('child-limit', {'parentLocal': 0, 'leafLocal': 1, 'parentHierarchical': 1, 'leafHierarchical': 1}, errno.EAGAIN, None),
                  ('parent-limit', {'parentLocal': 1, 'leafLocal': 0, 'parentHierarchical': 1, 'leafHierarchical': 0}, errno.EAGAIN, None)]
        for case, after, error, code in inputs:
            with self.subTest(case=case):
                self.assertEqual(m.qualify(case, ZERO, after, {'attemptedForks': 1, 'forkErrno': error, 'childExit': code}), after)

    def test_legacy_fork_origin_or_hierarchical_only_cannot_pass_parent_limit_case(self):
        for after in ({'parentLocal': 0, 'leafLocal': 1, 'parentHierarchical': 0, 'leafHierarchical': 1},
                      {'parentLocal': 0, 'leafLocal': 0, 'parentHierarchical': 1, 'leafHierarchical': 0}, ZERO):
            with self.subTest(after=after), self.assertRaisesRegex(AssertionError, '^CALIBRATION_EVENT_MODE$'):
                m.qualify('parent-limit', ZERO, after, {'attemptedForks': 1, 'forkErrno': errno.EAGAIN, 'childExit': None})

    def test_wrong_errno_no_fork_or_abnormal_child_are_not_positive_or_denial(self):
        for outcome in ({'attemptedForks': 1, 'forkErrno': errno.EPERM, 'childExit': None},
                        {'attemptedForks': 1, 'forkErrno': None, 'childExit': 1}):
            with self.subTest(outcome=outcome), self.assertRaises(AssertionError):
                m.qualify('positive', ZERO, ZERO, outcome)
        with self.assertRaisesRegex(AssertionError, '^CALIBRATION_PROTOCOL$'):
            m.qualify('positive', ZERO, ZERO, {'attemptedForks': 0, 'forkErrno': None, 'childExit': 0})
        with self.assertRaisesRegex(AssertionError, '^CALIBRATION_DENIAL$'):
            m.qualify('parent-limit', ZERO, ZERO, {'attemptedForks': 1, 'forkErrno': errno.ENOMEM, 'childExit': None})

    def test_counter_reset_bool_and_multiple_events_fail_the_fixed_single_attempt(self):
        for value in (-1, True, 2):
            with self.subTest(value=value):
                after = dict(ZERO, parentLocal=value, parentHierarchical=1)
                with self.assertRaises(AssertionError):
                    m.qualify('parent-limit', ZERO, after, {'attemptedForks': 1, 'forkErrno': errno.EAGAIN, 'childExit': None})

    def test_fixed_write_uses_owned_directory_and_rejects_any_kill_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);(root / 'pids.max').write_bytes(b'')
            checks = []
            class Group:
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                def check(self): checks.append(True)
            group = Group()
            try:
                m._write(group, 'pids.max', '4')
                self.assertEqual((root / 'pids.max').read_bytes(), b'4')
                self.assertEqual(len(checks), 2)
                with self.assertRaisesRegex(AssertionError, '^CALIBRATION_WRITE$'):
                    m._write(group, 'cgroup.kill', '1')
                with patch.object(m.os, 'write', return_value=0), self.assertRaisesRegex(AssertionError, '^CALIBRATION_WRITE$'):
                    m._write(group, 'pids.max', '1')
            finally: os.close(group.fd)

    def test_missing_extra_counter_fields_and_bool_childexit_are_not_qualification(self):
        for after in ({}, dict(ZERO, extra=0)):
            with self.subTest(after=after), self.assertRaisesRegex(AssertionError, '^CALIBRATION_COUNTER$'):
                m.qualify('positive', ZERO, after, {'attemptedForks': 1, 'forkErrno': None, 'childExit': 0})
        with self.assertRaisesRegex(AssertionError, '^CALIBRATION_POSITIVE$'):
            m.qualify('positive', ZERO, ZERO, {'attemptedForks': 1, 'forkErrno': None, 'childExit': False})

    def test_exact_owned_cgroup2_mount_is_required_not_an_unrelated_cgroup2_line(self):
        m.validate_mount(CG2)
        for raw in (CG2.replace(b'/sys/fs/cgroup', b'/unrelated'), CG2.replace(b'/ /sys/fs/cgroup', b'/delegated /sys/fs/cgroup')):
            with self.subTest(raw=raw), self.assertRaisesRegex(AssertionError, '^CALIBRATION_MOUNT$'):
                m.validate_mount(raw)

    def test_localevents_mount_and_non_cgroup2_root_are_rejected(self):
        for raw in (CG2.replace(b'rw,nsdelegate', b'rw,pids_localevents,nsdelegate'), CG2.replace(b'- cgroup2', b'- cgroup')):
            with self.subTest(raw=raw), self.assertRaisesRegex(AssertionError, '^CALIBRATION_MOUNT$'):
                m.validate_mount(raw)

if __name__ == '__main__': unittest.main()
