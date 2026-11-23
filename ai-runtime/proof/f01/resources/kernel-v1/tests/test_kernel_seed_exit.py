"""Exact known-exit transition; no full capture or native pidfd claim."""
import copy
import select
from unittest.mock import Mock, patch
import unittest
import importlib.util
from pathlib import Path
_spec = importlib.util.spec_from_file_location('kernel_observer_for_' + __name__, Path(__file__).parents[1] / 'python' / 'kernel_observer.py')
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)


def seeds():
    return [{'fd': index + 3, 'identity': {'pid': 100 + index,
             'startTicks': 1000 + index, 'exeIdentity': [1, 20 + index],
             'cgroup': '/pod/scope'}} for index in range(3)]


class SeedExit(unittest.TestCase):
    def feature(self):
        function = getattr(module, 'seed_fence', None)
        self.assertTrue(callable(function), 'seed fence implementation is absent')
        return function

    def fixture(self, reader=None, exited=()):
        values = seeds();calls = [];reads = [];clock = [100.]
        def poll(fds, seconds):
            self.assertEqual(tuple(fds), (3, 4, 5))
            calls.append(seconds)
            return list(exited) if seconds else []
        def read(pid):
            reads.append(pid)
            return copy.deepcopy(next(x['identity'] for x in values if x['identity']['pid'] == pid))
        return values, reader or read, poll, lambda: clock[0], calls, reads, clock

    def test_live_seed_identities_are_checked_without_population_scan(self):
        function = self.feature();values, read, poll, now, calls, reads, _ = self.fixture()
        self.assertEqual(function(values, 130., read, poll, now), 'LIVE')
        self.assertEqual(reads, [100, 101, 102])
        self.assertEqual(calls, [0, 0, 0, 0])

    def test_known_missing_seed_waits_once_then_enters_terminal_only(self):
        function = self.feature()
        def read(pid): raise module.SeedExitSymptom('proc missing')
        values, read, poll, now, calls, _, _ = self.fixture(read, (3,))
        self.assertEqual(function(values, 130., read, poll, now), 'EXITED')
        self.assertEqual(calls, [0, 2])

    def test_zombie_or_exe_enoent_has_same_once_bounded_exit_confirmation(self):
        function = self.feature()
        for reason in ('zombie', 'exe ENOENT'):
            with self.subTest(reason=reason):
                def read(pid): raise module.SeedExitSymptom(reason)
                values, read, poll, now, calls, _, _ = self.fixture(read, (4,))
                self.assertEqual(function(values, 130., read, poll, now), 'EXITED')
                self.assertEqual(calls, [0, 2])

    def test_known_symptom_with_all_pinned_seeds_alive_is_stop(self):
        function = self.feature()
        def read(pid): raise module.SeedExitSymptom('exe ENOENT')
        values, read, poll, now, calls, _, _ = self.fixture(read)
        with self.assertRaisesRegex(module.ProofError, '^SEED_NOT_EXITED$'):
            function(values, 130., read, poll, now)
        self.assertEqual(calls, [0, 2])

    def test_alive_identity_change_is_stop_without_any_blocking_wait(self):
        function = self.feature();values, original, poll, now, calls, _, _ = self.fixture()
        for field, value in (('startTicks', 9999), ('cgroup', '/foreign'), ('exeIdentity', [9, 9])):
            with self.subTest(field=field):
                calls.clear()
                def read(pid):
                    actual = original(pid);actual[field] = value;return actual
                with self.assertRaisesRegex(module.ProofError, '^SEED_IDENTITY$'):
                    function(values, 130., read, poll, now)
                self.assertEqual(calls, [0])

    def test_unrelated_file_permission_parse_and_timeout_failures_do_not_wait(self):
        function = self.feature()
        for error in (FileNotFoundError('binary missing'), PermissionError('denied'),
                      ValueError('bad identity'), TimeoutError('read timeout')):
            with self.subTest(kind=type(error).__name__):
                def read(pid): raise error
                values, read, poll, now, calls, _, _ = self.fixture(read, (3,))
                with self.assertRaises(type(error)) as actual:
                    function(values, 130., read, poll, now)
                self.assertIs(actual.exception, error)
                self.assertEqual(calls, [0])

    def test_exit_visible_before_read_never_reads_a_reused_pid(self):
        function = self.feature();values, read, _, now, calls, reads, _ = self.fixture()
        def poll(fds, seconds): calls.append(seconds);return [3]
        self.assertEqual(function(values, 130., read, poll, now), 'EXITED')
        self.assertEqual(reads, [])

    def test_exit_after_identity_read_prevents_live_credit(self):
        function = self.feature();values, read, _, now, calls, reads, _ = self.fixture()
        def poll(fds, seconds):
            calls.append(seconds);return [3] if len(calls) == 2 else []
        self.assertEqual(function(values, 130., read, poll, now), 'EXITED')
        self.assertEqual(reads, [100])

    def test_single_wait_is_capped_by_remaining_original_deadline(self):
        function = self.feature()
        def read(pid): raise module.SeedExitSymptom('proc missing')
        values, read, poll, now, calls, _, clock = self.fixture(read, (3,));clock[0] = 129.75
        self.assertEqual(function(values, 130., read, poll, now), 'EXITED')
        self.assertEqual(calls, [0, .25])

    def test_expired_original_deadline_stops_before_kernel_reads(self):
        function = self.feature();values, read, poll, now, calls, reads, clock = self.fixture();clock[0] = 130.
        with self.assertRaisesRegex(module.ProofError, '^DEADLINE$'):
            function(values, 130., read, poll, now)
        self.assertEqual(calls, []);self.assertEqual(reads, [])

    def test_wait_crossing_original_deadline_cannot_credit_exit(self):
        function = self.feature()
        def read(pid): raise module.SeedExitSymptom('proc missing')
        values, read, _, now, calls, _, clock = self.fixture(read)
        def poll(fds, seconds):
            calls.append(seconds)
            if seconds: clock[0] = 130.;return [3]
            return []
        with self.assertRaisesRegex(module.ProofError, '^DEADLINE$'):
            function(values, 130., read, poll, now)
        self.assertEqual(calls, [0, 2])

    def poll_result(self, events):
        poll = Mock();poll.poll.return_value = events
        with patch.object(select, 'poll', return_value=poll):
            return module.pidfd_poll([3, 4, 5], 0)

    def test_observed_zombie_and_reaped_pidfd_masks_are_both_known_exits(self):
        for mask in (select.POLLIN, select.POLLIN | select.POLLHUP):
            with self.subTest(mask=mask):
                self.assertEqual(self.poll_result([(3, mask)]), [3])
        self.assertEqual(self.poll_result([(3, select.POLLIN), (4, select.POLLIN | select.POLLHUP)]),
                         [3, 4])

    def test_error_closed_hup_only_and_unknown_pidfd_bits_remain_stop(self):
        for mask in (0, select.POLLERR, select.POLLNVAL, select.POLLHUP, 64,
                     select.POLLIN | select.POLLERR, select.POLLIN | select.POLLNVAL,
                     select.POLLIN | select.POLLHUP | select.POLLERR,
                     select.POLLIN | select.POLLHUP | select.POLLNVAL, 1 << 30):
            with self.subTest(mask=mask):
                with self.assertRaisesRegex(module.ProofError, '^PIDFD_STATE$'):
                    self.poll_result([(3, mask)])

    def test_reaped_known_pidfd_enters_exit_without_reading_reused_pid(self):
        poll = Mock();poll.poll.return_value = [(3, select.POLLIN | select.POLLHUP)]
        read = Mock(side_effect=AssertionError('must not read a process after pinned pidfd exit'))
        with patch.object(select, 'poll', return_value=poll):
            self.assertEqual(module.seed_fence(seeds(), 130., read, module.pidfd_poll, lambda: 100.),
                             'EXITED')
        read.assert_not_called()

    def test_foreign_pidfd_event_is_not_a_known_seed_exit(self):
        function = self.feature();values, read, _, now, _, _, _ = self.fixture()
        with self.assertRaisesRegex(module.ProofError, '^PIDFD_STATE$'):
            function(values, 130., read, lambda fds, wait: [999], now)


if __name__ == '__main__': unittest.main()
