"""Targeted offline lock-contention behavior against actual observer functions."""
import errno
import fcntl
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from test_observer_ownership import Inputs


class ObserverLockContention(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.out = self.root / 'out'
        self.out.mkdir()
        self.inputs = Inputs(self.out)
        self.state_root = self.root / 'runtime'
        self.state_root.mkdir()
        stem = self.inputs.target['sid'] + '_sandbox:' + self.inputs.target['sid']
        lock = self.state_root / (stem + '.lock')
        lock.write_bytes(b'')
        self.holder = lock.open('rb')
        self.addCleanup(self.holder.close)
        fcntl.flock(self.holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.target = dict(self.inputs.attached, root=str(self.state_root))

    def busy(self):
        # Actual shared nonblocking flock against an existing exclusive holder.
        # Missing .state ensures an unlocked/ignored-lock read cannot pass.
        with patch.dict(self.inputs.ns, canonical=pathlib.Path):
            return self.inputs.real_runtime_seeds(self.target)

    def release(self):
        fcntl.flock(self.holder, fcntl.LOCK_UN)

    def no_result(self):
        self.assertFalse((self.out / 'observer-result.json').exists())

    def test_actual_flock_contention_is_classified_without_reading_unlocked_state(self):
        with self.assertRaises(BlockingIOError) as caught:
            self.busy()
        self.assertEqual(type(caught.exception).__name__, 'RuntimeStateBusy')
        self.assertEqual(caught.exception.errno, errno.EAGAIN)
        self.assertIsInstance(caught.exception.__cause__, BlockingIOError)
        self.assertEqual(list(self.state_root.glob('*.state')), [])

    def test_transient_contention_restarts_fresh_and_never_promotes_failed_snapshot(self):
        def seed():
            if self.inputs.capture_count == 1:
                # The first snapshot already read 400; only a fresh capture sees 401.
                self.inputs.records[40]['startTicks'] = 401
                try:
                    self.busy()
                finally:
                    self.release()
        self.inputs.seed_hook = seed
        self.inputs.observe()
        self.assertEqual(self.inputs.read('observer-result.json')['status'], 'OBSERVATION_WINDOW_FINISHED')
        self.assertTrue(all(x['status'] == 'verified' for x in self.inputs.read_counter_rows()))
        members = {x['pid']: x for x in self.inputs.read('host-members.json')}
        self.assertEqual(members[40]['startTicks'], 401)
        snapshots = self.inputs.read('mapping.json')['observations']
        self.assertTrue(all('roles' in entry['snapshot'] for entry in snapshots))
        self.assertEqual(self.inputs.read('capture-failure.json')['records']['40']['startTicks'], 400)
        self.assertLess(self.inputs.events.index('host-members.json'), self.inputs.events.index('query'))

    def test_persistent_contention_stops_after_two_attempts_without_ownership_or_rows(self):
        self.inputs.seed_hook = self.busy
        with self.assertRaises(BlockingIOError):
            self.inputs.observe()
        self.assertEqual(self.inputs.capture_count, 2)
        self.assertFalse((self.out / 'host-members.json').exists())
        self.assertFalse((self.out / 'counters.jsonl').exists())
        self.no_result()

    def test_original_deadline_between_attempts_prevents_second_capture(self):
        def seed():
            try:
                self.busy()
            finally:
                self.inputs.clock.value = 130.
        self.inputs.seed_hook = seed
        with self.assertRaisesRegex(AssertionError, 'observation deadline reached'):
            self.inputs.observe()
        self.assertEqual(self.inputs.capture_count, 1)
        self.no_result()

    def test_diagnostic_write_failure_note_prevents_retry_and_preserves_primary(self):
        self.inputs.seed_hook = self.busy
        self.inputs.write_failure = 'capture-failure.json'
        with self.assertRaises(BlockingIOError) as caught:
            self.inputs.observe()
        self.assertTrue(any('capture diagnostic failed' in x for x in caught.exception.__notes__))
        self.assertEqual(self.inputs.capture_count, 1)
        self.no_result()

    def test_noncontention_flock_errors_are_not_retried(self):
        for error in [PermissionError(errno.EACCES, 'denied'), BlockingIOError(errno.EBUSY, 'other error')]:
            with self.subTest(error=type(error).__name__):
                def seed():
                    with patch.dict(self.inputs.ns, canonical=pathlib.Path), patch.object(fcntl, 'flock', side_effect=error):
                        return self.inputs.real_runtime_seeds(self.target)
                self.inputs.seed_hook = seed
                before = self.inputs.capture_count
                with self.assertRaises(type(error)) as caught:
                    self.inputs.observe()
                self.assertIs(caught.exception, error)
                self.assertEqual(self.inputs.capture_count, before + 1)
                self.no_result()

    def test_eagain_from_another_capture_operation_is_not_retried(self):
        error = BlockingIOError(errno.EAGAIN, 'unrelated proc read')
        def proc(pid, tid):
            raise error
        self.inputs.proc_hook = proc
        with self.assertRaises(BlockingIOError) as caught:
            self.inputs.observe()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.inputs.capture_count, 1)
        self.no_result()

    def test_postcounter_retry_keeps_population_equality_and_invalid_row(self):
        def seed():
            if self.inputs.capture_count == 3:
                self.inputs.records[40]['comm'] = 'changed'
                try:
                    self.busy()
                finally:
                    self.release()
        self.inputs.seed_hook = seed
        with self.assertRaisesRegex(AssertionError, 'membership changed across counter read'):
            self.inputs.observe()
        self.assertEqual(self.inputs.read_counter_rows()[-1]['status'], 'invalid')
        self.no_result()

    def test_final_fence_retry_preserves_verified_window(self):
        original = self.inputs.ns['running_fence']
        in_fence = False
        fired = False
        def fence(*args):
            nonlocal in_fence
            in_fence = True
            return original(*args)
        def seed():
            nonlocal fired
            if in_fence and not fired:
                fired = True
                try:
                    self.busy()
                finally:
                    self.release()
        self.inputs.ns['running_fence'] = fence
        self.inputs.seed_hook = seed
        self.inputs.observe()
        result = self.inputs.read('observer-result.json')
        self.assertTrue(fired)
        self.assertEqual(result['deadlineMonotonic'], 130.)
        self.assertLess(result['finishedMonotonic'], 130.)
        self.assertGreaterEqual(result['lastMonotonic'] - result['firstMonotonic'], 1.)
        self.assertTrue(all(x['status'] == 'verified' for x in self.inputs.read_counter_rows()))


if __name__ == '__main__':
    unittest.main()
