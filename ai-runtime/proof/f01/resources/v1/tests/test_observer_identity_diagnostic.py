"""Failed identity rereads retain diagnostics without weakening capture acceptance."""
import collections
import copy
import pathlib
import tempfile
import unittest

from test_observer_ownership import Inputs


class ProcessIdentityDiagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = pathlib.Path(self.tmp.name) / 'out'
        self.out.mkdir()
        self.inputs = Inputs(self.out)
        self.calls = collections.Counter()
        original = self.inputs.proc

        def proc(pid, tid=None):
            self.calls[(self.inputs.capture_count, pid, tid)] += 1
            result = original(pid, tid)
            if (self.inputs.capture_count == getattr(self, 'mismatch_capture', None)
                    and pid == 40 and tid is None
                    and self.calls[(self.inputs.capture_count, pid, tid)] == 2):
                result.update(self.changed)
            return result
        self.inputs.ns['proc'] = proc

    def mismatch(self, capture=1, **changed):
        self.mismatch_capture = capture
        self.changed = changed or {'comm': 'changed-during-capture'}

    def failure(self):
        with self.assertRaisesRegex(AssertionError, '^racing process identity$') as caught:
            self.inputs.observe()
        self.assertIs(type(caught.exception), AssertionError)
        self.assertNotIsInstance(caught.exception, self.inputs.ns['RuntimeStateBusy'])
        self.assertFalse((self.out / 'observer-result.json').exists())
        self.assertEqual(self.inputs.capture_count, self.mismatch_capture)
        return caught.exception

    def test_unchanged_capture_shape_and_number_of_proc_reads(self):
        snapshot = self.inputs.ns['capture'](self.inputs.attached, self.inputs.group,
            self.inputs.binaries, self.inputs.seeds, self.inputs.projections,
            lambda value: self.fail('successful capture must not save failed diagnostics'))
        self.assertEqual(set(snapshot), {'groups', 'records', 'threads', 'children', 'roles'})
        self.assertEqual(snapshot['records'], self.inputs.records)
        self.assertEqual(len(snapshot['roles']), 4)
        self.assertEqual(self.calls, collections.Counter({
            (1, pid, tid): 2 for pid in (10, 20, 30, 40) for tid in (None, pid)}))

    def test_success_still_checks_parking_association_at_both_boundaries(self):
        record = self.inputs.records[40]
        record.update(exe='/bin/parking', exeIdentity=[1, 4], argv0='/bin/parking')
        parking_reads = []
        self.inputs.ns['parking_target'] = lambda pid: parking_reads.append(pid) or 10
        snapshot = self.inputs.ns['capture'](self.inputs.attached, self.inputs.group,
            self.inputs.binaries, self.inputs.seeds, self.inputs.projections,
            lambda value: self.fail('successful capture must not save failed diagnostics'))
        self.assertEqual(snapshot['roles'][40], 'parking')
        self.assertEqual(parking_reads, [40, 40])

    def test_process_mismatch_saves_exact_pair_and_fails_without_retry_or_promotion(self):
        self.mismatch()
        self.failure()
        snapshot = self.inputs.read('capture-failure.json')
        self.assertIn('identityMismatch', snapshot,
                      'failed second process reread must retain its returned record')
        original = copy.deepcopy(self.inputs.records[40])
        returned = dict(original, comm='changed-during-capture')
        self.assertEqual(snapshot['identityMismatch'], {
            'kind': 'process', 'pid': 40, 'original': original, 'returned': returned})
        self.assertEqual(snapshot['records']['40'], original)
        self.assertNotIn('roles', snapshot)
        self.assertFalse((self.out / 'host-members.json').exists())
        self.assertFalse((self.out / 'counters.jsonl').exists())
        self.assertEqual(self.calls[(1, 40, None)], 2)

    def test_sample_failure_keeps_prior_owned_ledger_and_invalid_empty_row(self):
        self.mismatch(capture=2)
        self.failure()
        snapshot = self.inputs.read('capture-failure.json')
        self.assertIn('identityMismatch', snapshot,
                      'sample identity failure must retain exact reread diagnostics')
        ledger = {row['pid']: row for row in self.inputs.read('host-members.json')}
        self.assertEqual(ledger[40], self.inputs.records[40])
        self.assertNotEqual(ledger[40], snapshot['identityMismatch']['returned'])
        self.assertEqual(self.inputs.read_counter_rows(), [{
            'sample': 0, 'monotonic': 100., 'realtime': self.inputs.clock.time(),
            'lateSeconds': 0., 'status': 'invalid', 'groups': {}, 'failure': 'AssertionError'}])
        self.assertEqual(self.calls[(2, 40, None)], 2)

    def test_diagnostic_write_failure_preserves_original_identity_assertion(self):
        self.mismatch()
        self.inputs.write_failure = 'capture-failure.json'
        error = self.failure()
        self.assertEqual(len(error.__notes__), 1)
        self.assertIn('capture diagnostic failed:', error.__notes__[0])
        self.assertIn('diagnostic storage failed: capture-failure.json', error.__notes__[0])
        self.assertEqual(self.calls[(1, 40, None)], 2)

    def test_oversized_returned_record_is_not_dumped_as_an_unbounded_pair(self):
        self.mismatch(argv0='x' * 32769)
        self.failure()
        snapshot = self.inputs.read('capture-failure.json')
        self.assertEqual(snapshot.get('identityMismatch'), {
            'kind': 'process', 'pid': 40, 'pairOmitted': 'exceeds 32768 byte diagnostic limit'})
        self.assertEqual(snapshot['records']['40'], self.inputs.records[40])
        self.assertEqual(self.calls[(1, 40, None)], 2)


if __name__ == '__main__':
    unittest.main()
