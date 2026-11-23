"""Terminal polling and captured-failure boundaries retain their original contracts."""
import unittest
from unittest.mock import patch
import test_terminal_capture as capture

m = capture.m


class TerminalBoundaries(unittest.TestCase):
    def test_capture_failure_identity_or_sanitized_failure_is_preserved(self):
        trial, _, _, _ = capture.Capture().fixture()
        failures = [trial.kernel.ProofError('CGROUP_OWNER'), KeyboardInterrupt(), SystemExit(2),
                    AssertionError('TERMINAL_CAPTURE_OWNER'), AssertionError('TERMINAL_CAPTURE_DEADLINE')]
        for failure in failures:
            with self.subTest(error=type(failure).__name__), self.assertRaises(type(failure)) as caught:
                trial._raise_capture_failure(failure)
            self.assertIs(caught.exception, failure)
        for failure in (ValueError('private reader data'), AssertionError('private predicate')):
            with self.subTest(error=type(failure).__name__), self.assertRaisesRegex(AssertionError, '^TERMINAL_CAPTURE_FAILED$') as caught:
                trial._raise_capture_failure(failure)
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)

    def trial(self, statuses):
        trial = m.Trial.__new__(m.Trial)
        trial.observation_deadline = 130.
        trial.pod = unittest.mock.Mock(side_effect=statuses)
        return trial

    def pod(self, phase='Succeeded', exit_code=0, reason='Completed'):
        return {'status': {'phase': phase, 'reason': reason,
                           'containerStatuses': [{'state': {'terminated': {'exitCode': exit_code}}}]}}

    def test_polling_keeps_terminal_exit_agreement_and_updates_only_after_confirmation(self):
        trial = self.trial([self.pod('Running'), self.pod()])
        terminal = {'exitCode': 0}
        with patch.object(m.time, 'monotonic', return_value=112.), patch.object(m.time, 'sleep') as sleep:
            trial._confirm_terminal_pod(terminal)
        self.assertEqual(trial.pod.call_count, 2)
        sleep.assert_called_once_with(.1)
        self.assertEqual(terminal, {'exitCode': 0, 'podPhase': 'Succeeded', 'podReason': 'Completed'})

    def test_polling_deadline_incomplete_terminal_and_exit_mismatch_never_gain_credit(self):
        for fault, reason in [('deadline', 'POD_STATUS_DEADLINE'), ('running', 'POD_TERMINAL_UNPROVEN'),
                              ('exit', 'POD_TERMINAL_MISMATCH')]:
            statuses = [self.pod('Running')] * 60 if fault == 'running' else [self.pod(exit_code=1)]
            trial = self.trial(statuses);terminal = {'exitCode': 0}
            with self.subTest(fault=fault), patch.object(m.time, 'monotonic', return_value=130. if fault == 'deadline' else 112.), patch.object(m.time, 'sleep'), self.assertRaisesRegex(AssertionError, '^' + reason + '$'):
                trial._confirm_terminal_pod(terminal)
            self.assertEqual(terminal, {'exitCode': 0})
            self.assertEqual(trial.pod.call_count, {'deadline': 0, 'running': 60, 'exit': 1}[fault])


if __name__ == '__main__':
    unittest.main()
