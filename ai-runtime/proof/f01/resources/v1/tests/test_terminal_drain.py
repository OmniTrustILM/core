"""Desired drain-only semantics; never authorize the old integrated body/policy."""
import json
import unittest
from terminal_fixture import TerminalFixture


class TerminalDrain(TerminalFixture, unittest.TestCase):
    def test_verified_terminal_can_precede_delayed_hold_log_without_new_operations(self):
        self.protocol()
        context = json.loads((self.out/'accounting-protocol.json').read_text())
        self.assertEqual(self.late_ops, [])
        self.assertEqual(len(self.signals), 3)
        self.assertEqual(context['normalExit']['receivedMonotonic'], self.actual_terminal)
        self.assertGreater(context['markers']['HOLD_END']['receivedMonotonic'], self.actual_terminal)
        self.assertEqual(self.child.killed, 0)
        self.assertLess(self.now, 130.)

    def test_drain_never_extends_original_deadline_or_sends_another_action(self):
        with self.assertRaises(AssertionError):
            self.protocol('drain-deadline')
        self.assertGreaterEqual(self.now,130.,'producer failed before exercising the original drain deadline')
        self.assertEqual(self.late_ops, [])
        self.assertEqual(len(self.signals),3)
        self.assertEqual(self.child.killed,1)
        self.assertFalse((self.out/'accounting-protocol.json').exists())
        self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')


if __name__ == '__main__': unittest.main()
