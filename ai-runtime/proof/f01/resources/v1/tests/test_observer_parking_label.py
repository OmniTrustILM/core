"""Synthetic parking label transitions against actual capture/observe boundaries."""
import collections
import copy
import pathlib
import tempfile
import unittest

from test_observer_ownership import Inputs


PATH = '/bin/parking'  # Existing fixture's configured measured parking path.
LABEL = 'runsc-fd-parking'  # Exact pinned public fdparking.c PARKING_NAME.


class ParkingLabelComparison(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = pathlib.Path(self.tmp.name) / 'out'
        self.out.mkdir()
        self.inputs = Inputs(self.out)
        self.inputs.records[40].update(exe=PATH, exeIdentity=[1, 4], argv0=PATH)
        self.calls = collections.Counter()
        self.parking_calls = []
        self.pidfd_target = lambda call: 10
        self.transition = lambda capture, pid, tid, read, result: None
        original = self.inputs.proc

        def proc(pid, tid=None):
            key = (self.inputs.capture_count, pid, tid)
            self.calls[key] += 1
            result = original(pid, tid)
            self.transition(*key, self.calls[key], result)
            return result
        self.inputs.ns['proc'] = proc

        def parking(pid):
            self.parking_calls.append(pid)
            return self.pidfd_target(len(self.parking_calls))
        self.inputs.ns['parking_target'] = parking

    def capture(self):
        saved = []
        snapshot = self.inputs.ns['capture'](self.inputs.attached, self.inputs.group,
            self.inputs.binaries, self.inputs.seeds, self.inputs.projections,
            lambda value: saved.append(copy.deepcopy(value)))
        self.assertEqual(saved, [])
        self.assertEqual(snapshot['roles'][40], 'parking')
        self.assertEqual(self.parking_calls, [40, 40])
        self.assertEqual(self.calls[(1, 40, None)], 2)
        self.assertEqual(self.calls[(1, 40, 40)], 2)
        return snapshot

    def finish_window(self):
        self.inputs.observe()
        result = self.inputs.read('observer-result.json')
        self.assertEqual(result['status'], 'OBSERVATION_WINDOW_FINISHED')
        self.assertEqual(result['deadlineMonotonic'], 130.)
        self.assertGreaterEqual(result['lastMonotonic'] - result['firstMonotonic'], 1.)
        self.assertTrue(all(r['status'] == 'verified' for r in self.inputs.read_counter_rows()))
        self.assertTrue(all(pid == 40 for pid in self.parking_calls))
        self.assertEqual(len(self.parking_calls), self.inputs.capture_count * 2)
        return [x['snapshot'] for x in self.inputs.read('mapping.json')['observations']]

    def no_acceptance(self):
        self.assertFalse((self.out / 'observer-result.json').exists())
        if (self.out / 'counters.jsonl').exists():
            self.assertTrue(all(row['status'] == 'invalid' for row in self.inputs.read_counter_rows()))

    def test_exact_measured_parking_path_to_label_at_process_reread_retains_raw_fields(self):
        def transition(capture, pid, tid, read, result):
            if pid == 40 and tid is None and read == 2:
                result['argv0'] = LABEL
        self.transition = transition
        snapshot = self.capture()
        self.assertEqual(snapshot['records'][40]['argv0'], PATH)
        self.assertEqual(snapshot['threads'][40]['argv0'], PATH)
        self.assertNotIn('identityMismatch', snapshot)

    def test_exact_measured_parking_path_to_label_at_thread_reread_retains_raw_fields(self):
        def transition(capture, pid, tid, read, result):
            if pid == tid == 40 and read == 2:
                result['argv0'] = LABEL
        self.transition = transition
        snapshot = self.capture()
        self.assertEqual(snapshot['records'][40]['argv0'], PATH)
        self.assertEqual(snapshot['threads'][40]['argv0'], PATH)

    def test_exact_measured_parking_transition_between_counter_boundaries_retains_both_raw_labels(self):
        def change():
            if self.inputs.capture_count >= 3:
                self.inputs.records[40]['argv0'] = LABEL
        self.inputs.group_hook = change
        snapshots = self.finish_window()
        self.assertEqual([s['records']['40']['argv0'] for s in snapshots[:2]], [PATH, LABEL])
        self.assertEqual([s['threads']['40']['argv0'] for s in snapshots[:2]], [PATH, LABEL])

    def test_source_defined_empty_fallback_between_boundaries_retains_raw_empty_value(self):
        def change():
            if self.inputs.capture_count >= 3:
                self.inputs.records[40]['argv0'] = ''
        self.inputs.group_hook = change
        snapshots = self.finish_window()
        self.assertEqual([s['records']['40']['argv0'] for s in snapshots[:2]], [PATH, ''])
        self.assertEqual([s['threads']['40']['argv0'] for s in snapshots[:2]], [PATH, ''])

    def test_unknown_parking_label_is_fatal_even_when_unchanged(self):
        self.inputs.records[40]['argv0'] = 'runsc-fd-parking-unknown'
        with self.assertRaises(AssertionError):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_parking_label_does_not_normalize_a_measured_nonparking_inode(self):
        self.inputs.records[40]['exeIdentity'] = [1, 2]
        def transition(capture, pid, tid, read, result):
            if pid == 40 and tid is None and read == 2:
                result['argv0'] = LABEL
        self.transition = transition
        with self.assertRaisesRegex(AssertionError, 'racing process identity'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)
        self.assertEqual(self.parking_calls, [])

    def test_unknown_executable_inode_cannot_gain_parking_ownership_from_label(self):
        self.inputs.records[40].update(exeIdentity=[9, 9], argv0=LABEL)
        with self.assertRaisesRegex(AssertionError, 'unmeasured descendant executable'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_other_eight_fields_and_unexpected_keys_remain_exact_at_process_reread(self):
        changes = {'pid': 41, 'tgid': 41, 'ppid': 2, 'startTicks': 401,
                   'comm': 'changed', 'exe': '/bin/other', 'exeIdentity': [9, 9],
                   'cgroup': '/other', 'unexpected': 1}
        for field, value in changes.items():
            with self.subTest(field=field):
                def transition(capture, pid, tid, read, result):
                    if pid == 40 and tid is None and read == 2:
                        result.update(argv0=LABEL, **{field: value})
                self.transition = transition
                before = self.inputs.capture_count
                with self.assertRaisesRegex(AssertionError, 'racing process identity') as caught:
                    self.inputs.observe()
                self.assertIs(type(caught.exception), AssertionError)
                self.assertNotIsInstance(caught.exception, self.inputs.ns['RuntimeStateBusy'])
                self.assertEqual(self.inputs.capture_count, before + 1)
                self.no_acceptance()

    def test_pidfd_association_still_required_after_valid_label(self):
        self.inputs.records[40]['argv0'] = LABEL
        self.pidfd_target = lambda call: 10 if call == 1 else 11
        with self.assertRaisesRegex(AssertionError, 'sidecar association changed'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.parking_calls, [40, 40])
        self.assertEqual(self.inputs.capture_count, 1)

    def test_population_change_remains_fatal_across_counter_boundary(self):
        def change():
            if self.inputs.capture_count == 3:
                self.inputs.records[40]['argv0'] = LABEL
                self.inputs.groups[self.inputs.group + '/new-empty-domain'] = {'procs': [], 'threads': []}
        self.inputs.group_hook = change
        with self.assertRaisesRegex(AssertionError, 'membership changed across counter read'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertTrue(self.inputs.read_counter_rows()[-1]['groups'])

    def test_runtime_seed_change_remains_fatal_for_valid_parking_label(self):
        self.inputs.records[40]['argv0'] = LABEL
        self.inputs.seed_hook = lambda: {10: 'sentry', 20: 'gofer', 30: 'parking'}
        with self.assertRaisesRegex(AssertionError, 'runtime seed changed'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)

    def test_measured_binary_change_remains_fatal_for_valid_parking_label(self):
        self.inputs.records[40]['argv0'] = LABEL
        self.inputs.binary_failure = True
        with self.assertRaisesRegex(AssertionError, 'measured binary changed'):
            self.inputs.observe()
        self.no_acceptance()
        self.assertEqual(self.inputs.capture_count, 1)


if __name__ == '__main__':
    unittest.main()
