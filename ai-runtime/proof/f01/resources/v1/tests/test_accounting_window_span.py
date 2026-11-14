"""Exact one-second whole-window decision on literal finite clock inputs."""
import unittest

import test_accounting_evaluator as fixtures
from domain_fixtures import root_binding


class AccountingWindowSpan(unittest.TestCase):
    setUp = fixtures.AccountingEvaluator.setUp
    raw = fixtures.AccountingEvaluator.raw
    evaluate = fixtures.AccountingEvaluator.evaluate
    status = fixtures.AccountingEvaluator.status

    def shifted(self, fixture):
        for row in fixture['rows']:
            for key in ('monotonic', 'counterReadStart', 'counterReadEnd'):
                row[key] -= 100.75
        facts = fixture['facts']
        facts['deadlineMonotonic'] -= 100.75
        for marker in facts['markers'].values():
            marker['receivedMonotonic'] -= 100.75
        facts['signalStarts'] = [value-100.75 for value in facts['signalStarts']]
        for witness in facts['witnesses']+[facts['rootRoles']]:
            for key in ('counterReadStart', 'counterReadEnd', 'queryStartedMonotonic', 'queryReceivedMonotonic'):
                witness[key] -= 100.75
        for key in ('normalExit', 'observerExit'):
            facts[key]['receivedMonotonic'] -= 100.75
        for key in ('counterReadStart', 'counterReadEnd'):
            facts['observerExit'][key] -= 100.75
        fixture['rows'][0].update(monotonic=0., counterReadStart=0., counterReadEnd=2**-54)
        fixture['rows'][1].update(monotonic=.2, counterReadStart=.3, counterReadEnd=.4)
        fixture['rows'][2].update(monotonic=.5, counterReadStart=1., counterReadEnd=1.125)
        root_binding(fixture)
        return fixture

    def test_memory_window_just_short_of_one_second_is_not_observed(self):
        fixture = self.shifted(self.memory)
        self.status('UNPROVEN', fixture, reason='INSUFFICIENT_WINDOW')
        fixture['rows'][0]['counterReadEnd'] = 0.
        root_binding(fixture)
        self.status('OBSERVED', fixture)  # Exact one second remains eligible.

    def test_cpu_uses_same_exact_whole_window_span_guard(self):
        fixture = self.shifted(self.cpu)
        self.status('UNPROVEN', fixture, control='cpu', reason='INSUFFICIENT_WINDOW')
        fixture['rows'][0]['counterReadEnd'] = 0.
        root_binding(fixture)
        self.status('OBSERVED', fixture, control='cpu')


if __name__ == '__main__':
    unittest.main()
