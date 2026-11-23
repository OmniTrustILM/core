"""Only a retained strict monotonic final reread can abort as uncredited Busy."""
import copy
import pathlib
import tempfile
import types
import unittest
from test_observer_ownership import Inputs


class FinalMembership(unittest.TestCase):
    def setup_capture(self, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        value = Inputs(pathlib.Path(temporary.name))
        original_path = value.ns['pathlib'].Path
        original_group = value.group_snapshot
        scope = value.records[40]['cgroup']
        if mode == 'group-removal':
            value.groups[scope + '/empty-scope'] = {'procs': [], 'threads': []}
        reads = []
        diagnostics = []
        failure = FileNotFoundError('synthetic final cgroup reread vanished')

        class Path:
            def __init__(self, item):
                self.item = item

            def __truediv__(self, item):
                return Path(self.item / item)

            def iterdir(self):
                return self.item.iterdir()

            def read_text(self):
                if getattr(self.item, 'path', '') == '/proc/40/task/40/children' and 50 in value.records:
                    return '50'
                return self.item.read_text()

        value.ns['pathlib'] = types.SimpleNamespace(
            Path=lambda name: Path(original_path(name)), PurePosixPath=pathlib.PurePosixPath)

        def group(name):
            reads.append(name)
            if len(reads) == 2:
                if mode == 'read-failure':
                    raise failure
                if mode in ('join', 'unmeasured-join', 'new-scope', 'duplicate-new', 'missing-new-thread', 'new-scope-with-growth'):
                    value.records[50] = dict(value.records[40], pid=50, tgid=50, ppid=40, startTicks=500)
                    value.groups[scope]['procs'].append(50)
                    value.groups[scope]['threads'].append(50)
                if mode == 'unmeasured-join':
                    value.records[50]['exeIdentity'] = [9, 9]
                if mode == 'new-scope-with-growth':
                    value.groups[scope + '/new'] = {'procs': [60], 'threads': [60]}
                if mode == 'group-removal':
                    value.groups.pop(scope + '/empty-scope')
                if mode == 'new-scope':
                    value.groups[scope]['procs'].remove(50)
                    value.groups[scope]['threads'].remove(50)
                    value.groups[scope + '/new'] = {'procs': [50], 'threads': [50]}
                if mode == 'duplicate-new':
                    value.groups[scope]['procs'].append(50)
                if mode == 'missing-new-thread':
                    value.groups[scope]['threads'].remove(50)
                if mode in ('removal', 'thread-removal', 'move'):
                    value.groups[scope]['threads'].remove(30)
                if mode in ('removal', 'move'):
                    value.groups[scope]['procs'].remove(30)
                if mode == 'move':
                    value.groups[value.group]['procs'].append(30)
                    value.groups[value.group]['threads'].append(30)
                if mode == 'duplicate-known':
                    value.groups[value.group]['procs'].append(30)
                    value.groups[value.group]['threads'].append(30)
                if mode == 'order-only':
                    value.groups[scope]['procs'].reverse()
                if mode == 'thread-join':
                    value.groups[scope]['threads'].append(99)
            return original_group(name)

        value.ns['group_snapshot'] = group
        return value, reads, diagnostics, failure

    def capture(self, value, diagnostics):
        return value.real_capture(value.attached, value.group, value.binaries,
                                  value.seeds, value.projections,
                                  lambda row: diagnostics.append(copy.deepcopy(row)))

    def test_actual_final_monotonic_join_is_uncredited_then_full_new_capture_qualifies(self):
        value, reads, diagnostics, _ = self.setup_capture('join')
        with self.assertRaises(value.ns['RuntimeStateBusy']) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), value.ns['RuntimeStateBusy'])
        self.assertEqual(len(reads), 2)
        self.assertNotIn('roles', diagnostics[0])
        self.assertEqual(set(diagnostics[0]['records']), {10, 20, 30, 40})
        self.assertTrue(any(50 in group['procs'] for group in diagnostics[0]['membershipReread'].values()))
        complete = self.capture(value, diagnostics)
        self.assertEqual(len(reads), 4)
        self.assertEqual(complete['roles'][50], 'sentry-descendant-unclassified')
        self.assertEqual(set(complete['records']), {10, 20, 30, 40, 50})

    def test_unmeasured_new_member_never_gets_credit_on_the_next_full_capture(self):
        value, reads, diagnostics, _ = self.setup_capture('unmeasured-join')
        with self.assertRaises(value.ns['RuntimeStateBusy']):
            self.capture(value, diagnostics)
        self.assertNotIn('roles', diagnostics[0])
        with self.assertRaises(AssertionError) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), AssertionError)
        self.assertEqual(failed.exception.args, ('unmeasured descendant executable',))
        self.assertEqual(len(reads), 3)
        self.assertNotIn('roles', diagnostics[1])

    def test_removal_move_new_scope_duplicate_inconsistent_and_order_only_are_fatal(self):
        for mode in ('removal', 'thread-removal', 'move', 'new-scope', 'duplicate-known',
                     'duplicate-new', 'missing-new-thread', 'order-only', 'new-scope-with-growth',
                     'group-removal'):
            with self.subTest(mode=mode):
                value, reads, diagnostics, _ = self.setup_capture(mode)
                with self.assertRaises(AssertionError) as failed:
                    self.capture(value, diagnostics)
                self.assertIs(type(failed.exception), AssertionError)
                self.assertEqual(failed.exception.args, ('racing cgroup membership',))
                self.assertEqual(len(reads), 2)
                self.assertNotIn('roles', diagnostics[0])
                self.assertIn('membershipReread', diagnostics[0])

    def test_stable_membership_returns_original_full_roles_without_reread_metadata(self):
        value, reads, diagnostics, _ = self.setup_capture('stable')
        complete = self.capture(value, diagnostics)
        self.assertEqual(len(reads), 2)
        self.assertEqual(set(complete['roles']), {10, 20, 30, 40})
        self.assertNotIn('membershipReread', complete)
        self.assertEqual(diagnostics, [])

    def test_final_reread_failure_keeps_exact_original_exception(self):
        value, reads, diagnostics, failure = self.setup_capture('read-failure')
        with self.assertRaises(FileNotFoundError) as failed:
            self.capture(value, diagnostics)
        self.assertIs(failed.exception, failure)
        self.assertEqual(len(reads), 2)
        self.assertNotIn('roles', diagnostics[0])
        self.assertNotIn('membershipReread', diagnostics[0])

    def test_new_thread_is_busy_without_roles_and_failed_save_preserves_retry_veto(self):
        value, reads, _, _ = self.setup_capture('thread-join')

        def failed_save(_):
            raise OSError('synthetic diagnostic save failure')

        with self.assertRaises(value.ns['RuntimeStateBusy']) as failed:
            value.real_capture(value.attached, value.group, value.binaries,
                               value.seeds, value.projections, failed_save)
        self.assertEqual(len(reads), 2)
        self.assertTrue(any('capture diagnostic failed' in note for note in failed.exception.__notes__))


if __name__ == '__main__':
    unittest.main()
