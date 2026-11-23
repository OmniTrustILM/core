"""Additional reviewed guards; only public synthetic parking records are used."""
import unittest

import test_observer_parking_label as parking


class ParkingProjectionGuards(unittest.TestCase):
    def setUp(self):
        self.fixture = parking.ParkingLabelComparison(
            'test_exact_measured_parking_path_to_label_at_process_reread_retains_raw_fields')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.inputs = self.fixture.inputs

    def test_missing_argv0_is_fatal_even_when_both_reads_lack_it(self):
        original = self.inputs.ns['proc']
        def proc(pid, tid=None):
            record = original(pid, tid)
            if pid == 40:
                record.pop('argv0')
            return record
        self.inputs.ns['proc'] = proc
        with self.assertRaisesRegex(KeyError, 'argv0'):
            self.inputs.observe()
        self.fixture.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_only_exact_configured_path_is_allowed_not_a_path_alias(self):
        self.inputs.records[40]['argv0'] = '/bin/../bin/parking'
        with self.assertRaises(AssertionError):
            self.inputs.observe()
        self.fixture.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_pidfd_association_failure_precedes_unknown_label_projection(self):
        self.inputs.records[40]['argv0'] = 'unknown-parking-label'
        def target(call):
            raise RuntimeError('synthetic parking association failed')
        self.fixture.pidfd_target = target
        with self.assertRaisesRegex(RuntimeError, '^synthetic parking association failed$'):
            self.inputs.observe()
        self.assertEqual(self.fixture.parking_calls, [40])
        self.fixture.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_unknown_label_process_reread_retains_raw_pair_before_fatal_assertion(self):
        def transition(capture, pid, tid, read, result):
            if pid == 40 and tid is None and read == 2:
                result['argv0'] = 'unknown-parking-label'
        self.fixture.transition = transition
        with self.assertRaisesRegex(AssertionError, '^racing process identity$') as caught:
            self.inputs.observe()
        self.assertNotIsInstance(caught.exception, self.inputs.ns['RuntimeStateBusy'])
        snapshot = self.inputs.read('capture-failure.json')
        pair = snapshot['identityMismatch']
        self.assertEqual(pair['kind'], 'process')
        self.assertEqual(pair['pid'], 40)
        self.assertEqual(pair['original'], self.inputs.records[40])
        self.assertEqual(pair['returned'], dict(self.inputs.records[40], argv0='unknown-parking-label'))
        self.assertNotIn('roles', snapshot)
        self.fixture.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)
        self.assertEqual(self.fixture.calls[(1, 40, None)], 2)


if __name__ == '__main__':
    unittest.main()
