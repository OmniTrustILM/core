"""Only observed monotonic native membership joins may abort an uncredited capture."""
import copy
import pathlib
import tempfile
import types
import unittest
from test_observer_ownership import Inputs


class CapturePopulationJoin(unittest.TestCase):
    def setup_capture(self, mode='join'):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        value = Inputs(pathlib.Path(temporary.name))
        original_path = value.ns['pathlib'].Path
        original_group = value.group_snapshot
        reads = []
        diagnostics = []

        class Path:
            def __init__(self, item):
                self.item = item

            def __truediv__(self, item):
                return Path(self.item / item)

            def iterdir(self):
                return self.item.iterdir()

            def read_text(self):
                if getattr(self.item, 'path', '') == '/proc/40/task/40/children':
                    return '50'
                return self.item.read_text()

        value.ns['pathlib'] = types.SimpleNamespace(
            Path=lambda name: Path(original_path(name)), PurePosixPath=pathlib.PurePosixPath)
        scope = value.records[40]['cgroup']

        def group(name):
            reads.append(name)
            if len(reads) == 2:
                if mode == 'read-failure':
                    raise FileNotFoundError('synthetic second membership read vanished')
                if mode in ('join', 'join-removal', 'join-thread-removal', 'join-move', 'join-new-group', 'join-existing-scope', 'unmeasured-join', 'join-extra'):
                    value.records[50] = dict(value.records[40], pid=50, tgid=50, ppid=40, startTicks=500)
                    value.groups[scope]['procs'].append(50)
                    value.groups[scope]['threads'].append(50)
                if mode in ('removal', 'join-removal'):
                    value.groups[scope]['procs'].remove(30)
                    value.groups[scope]['threads'].remove(30)
                if mode == 'join-thread-removal':
                    value.groups[scope]['threads'].remove(30)
                if mode == 'join-move':
                    for field in ('procs', 'threads'):
                        value.groups[scope][field].remove(30)
                        value.groups[value.group][field].append(30)
                if mode == 'join-existing-scope':
                    for field in ('procs', 'threads'):
                        value.groups[scope][field].remove(50)
                        value.groups[value.group][field].append(50)
                    value.records[50]['cgroup'] = value.group
                if mode == 'join-new-group':
                    value.groups[scope]['procs'].remove(50)
                    value.groups[scope]['threads'].remove(50)
                    value.groups[scope + '/new-scope'] = {'procs': [50], 'threads': [50]}
                if mode in ('unrelated', 'join-extra'):
                    value.records[60] = dict(value.records[40], pid=60, tgid=60, ppid=40, startTicks=600)
                    value.groups[scope]['procs'].append(60)
                    value.groups[scope]['threads'].append(60)
            return original_group(name)

        value.ns['group_snapshot'] = group
        if mode in ('unmeasured', 'unmeasured-join'):
            value.records[40]['exeIdentity'] = [9, 9]
        return value, reads, diagnostics

    def capture(self, value, diagnostics):
        return value.real_capture(value.attached, value.group, value.binaries,
                                  value.seeds, value.projections, lambda row: diagnostics.append(copy.deepcopy(row)))

    def test_actual_second_membership_join_aborts_without_roles_or_sample_credit(self):
        value, reads, diagnostics = self.setup_capture()
        with self.assertRaises(value.ns['RuntimeStateBusy']) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), value.ns['RuntimeStateBusy'])
        self.assertEqual(len(reads), 2)
        self.assertEqual(len(diagnostics), 1)
        self.assertNotIn('roles', diagnostics[0])
        self.assertIn(50, next(g['procs'] for g in diagnostics[0]['membershipReread'].values() if 50 in g['procs']))
        complete = self.capture(value, diagnostics)
        self.assertEqual(len(reads), 4)
        self.assertEqual(complete['roles'][50], 'sentry-descendant-unclassified')
        self.assertEqual(set(complete['records']), {10, 20, 30, 40, 50})

    def test_stable_missing_child_remains_original_assertion(self):
        value, reads, diagnostics = self.setup_capture('stable')
        with self.assertRaises(AssertionError) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), AssertionError)
        self.assertEqual(failed.exception.args, ('unaccounted descendant',))
        self.assertEqual(len(reads), 2)
        self.assertNotIn('roles', diagnostics[0])

    def test_removed_or_unrelated_membership_never_proves_the_missing_child_joined(self):
        for mode in ('removal', 'unrelated', 'join-removal', 'join-thread-removal', 'join-move', 'join-new-group'):
            with self.subTest(mode=mode):
                value, reads, diagnostics = self.setup_capture(mode)
                with self.assertRaises(AssertionError) as failed:
                    self.capture(value, diagnostics)
                self.assertIs(type(failed.exception), AssertionError)
                self.assertEqual(failed.exception.args, ('unaccounted descendant',))
                self.assertEqual(len(reads), 2)
                self.assertNotIn('roles', diagnostics[0])

    def test_unmeasured_known_record_never_becomes_retryable(self):
        for mode in ('unmeasured', 'unmeasured-join'):
            with self.subTest(mode=mode):
                value, reads, diagnostics = self.setup_capture(mode)
                with self.assertRaises(AssertionError) as failed:
                    self.capture(value, diagnostics)
                self.assertIs(type(failed.exception), AssertionError)
                self.assertEqual(failed.exception.args, ('unaccounted descendant',))
                self.assertEqual(len(reads), 1)
                self.assertNotIn('roles', diagnostics[0])

    def test_failed_second_read_cannot_change_assertion_into_terminal_reconciliation(self):
        value, reads, diagnostics = self.setup_capture('read-failure')
        with self.assertRaises(AssertionError) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), AssertionError)
        self.assertEqual(failed.exception.args, ('unaccounted descendant',))
        self.assertEqual(len(reads), 2)
        self.assertEqual(diagnostics[0]['membershipRereadFailure'], 'FileNotFoundError')
        self.assertNotIn('roles', diagnostics[0])

    def test_missing_child_in_different_existing_scope_is_not_a_parent_group_join(self):
        value, reads, diagnostics = self.setup_capture('join-existing-scope')
        with self.assertRaises(AssertionError) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), AssertionError)
        self.assertEqual(failed.exception.args, ('unaccounted descendant',))
        self.assertEqual(len(reads), 2)
        self.assertNotIn('roles', diagnostics[0])

    def test_coherent_cross_scope_descendant_still_uses_unchanged_full_verifier(self):
        value, _, _ = self.setup_capture('join-existing-scope')
        value.ns['group_snapshot'](value.group)
        value.ns['group_snapshot'](value.group)
        records=copy.deepcopy(value.records)
        threads=copy.deepcopy(records)
        children={pid:[] for pid in records}
        children[10]=[40]
        children[40]=[50]
        roles=value.ns['verify_closure'](records, value.groups, threads, children,
                                         value.seeds, 10, value.binaries)
        self.assertNotEqual(records[40]['cgroup'], records[50]['cgroup'])
        self.assertEqual(roles[50], 'sentry-descendant-unclassified')

    def test_duplicate_missing_child_cannot_classify_as_a_population_join(self):
        value, reads, _ = self.setup_capture()
        records = copy.deepcopy(value.records)
        snapshot = {'groups': copy.deepcopy(value.groups), 'records': records,
                    'threads': copy.deepcopy(records),
                    'children': {10: [40], 20: [], 30: [], 40: [50, 50]}}
        after = copy.deepcopy(value.groups)
        scope = value.records[40]['cgroup']
        after[scope]['procs'].append(50)
        after[scope]['threads'].append(50)

        def joined(group):
            reads.append(group)
            return copy.deepcopy(after)

        value.ns['group_snapshot'] = joined
        with self.assertRaises(AssertionError) as failed:
            value.ns['_capture_roles'](snapshot, value.group, value.seeds, 10, value.binaries)
        self.assertIs(type(failed.exception), AssertionError)
        self.assertEqual(failed.exception.args, ('unaccounted descendant',))
        self.assertEqual(reads, [])
        self.assertNotIn('membershipReread', snapshot)
        self.assertNotIn('roles', snapshot)
        with self.assertRaises(AssertionError):
            value.ns['guest_pids']([50, 50])

    def test_join_with_an_unrelated_extra_pid_is_busy_without_sample_credit(self):
        value, reads, diagnostics = self.setup_capture('join-extra')
        with self.assertRaises(value.ns['RuntimeStateBusy']) as failed:
            self.capture(value, diagnostics)
        self.assertIs(type(failed.exception), value.ns['RuntimeStateBusy'])
        self.assertEqual(len(reads), 2)
        self.assertNotIn('roles', diagnostics[0])
        self.assertEqual(set(diagnostics[0]['records']), {10, 20, 30, 40})
        self.assertTrue(any({50, 60} <= set(group['procs'])
                            for group in diagnostics[0]['membershipReread'].values()))
        with self.assertRaises(AssertionError) as rejected:
            self.capture(value, diagnostics)
        self.assertIs(type(rejected.exception), AssertionError)
        self.assertEqual(rejected.exception.args, ('missing ancestry edge',))
        self.assertNotIn('roles', diagnostics[1])

    def test_failed_join_diagnostic_keeps_busy_notes_for_existing_retry_veto(self):
        value, reads, _ = self.setup_capture()
        def failed_save(_):
            raise OSError('synthetic diagnostic save failure')
        with self.assertRaises(value.ns['RuntimeStateBusy']) as failed:
            value.real_capture(value.attached, value.group, value.binaries,
                               value.seeds, value.projections, failed_save)
        self.assertEqual(len(reads), 2)
        self.assertTrue(any('capture diagnostic failed' in note for note in failed.exception.__notes__))


if __name__ == '__main__':
    unittest.main()
