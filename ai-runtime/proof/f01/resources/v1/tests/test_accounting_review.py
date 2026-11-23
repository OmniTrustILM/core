"""Focused review regressions using synthetic owned facts, never runtime authority."""
import copy
import unittest

import test_accounting_evaluator as fixtures
from test_observer_ownership import CODE, EXTRACTED
from domain_fixtures import root_binding


class AccountingReview(unittest.TestCase):
    setUp = fixtures.AccountingEvaluator.setUp
    raw = fixtures.AccountingEvaluator.raw
    evaluate = fixtures.AccountingEvaluator.evaluate
    status = fixtures.AccountingEvaluator.status

    def test_strict_cpu_equality_at_large_integer_boundary_is_not_observed(self):
        b = 2251799813685250
        boundary = 10133099161583625  # Exact 9*b/2; old float arithmetic rounds one unit down.
        usages = [0, b, 2*b, 3*b, 4*b, 5*b] + [5*b + boundary + 100*i for i in range(7)]
        for row, usage in zip(self.cpu['rows'], usages):
            row['groups']['/synthetic/pod']['cpu.stat']['usage_usec'] = usage
        self.status('UNPROVEN', control='cpu', reason='CPU_INSUFFICIENT_DIFFERENTIAL')
        for row in self.cpu['rows'][6:]:
            row['groups']['/synthetic/pod']['cpu.stat']['usage_usec'] += 1
        self.status('OBSERVED', control='cpu')

    def test_finite_clocks_with_overflowed_outer_duration_stop(self):
        fixture = self.cpu
        def clock(value):
            return (-1e308 + (value-100.)*1e294 if value<106. else 1e308 + (value-106.)*1e294)
        for row in fixture['rows']:
            for key in ('monotonic', 'counterReadStart', 'counterReadEnd'):
                row[key] = clock(row[key])
        facts = fixture['facts'];facts['deadlineMonotonic'] = clock(facts['deadlineMonotonic'])
        for marker in facts['markers'].values():marker['receivedMonotonic'] = clock(marker['receivedMonotonic'])
        facts['signalStarts'] = [clock(value) for value in facts['signalStarts']]
        for witness in facts['witnesses']+[facts['rootRoles']]:
            for key in ('counterReadStart', 'counterReadEnd', 'queryStartedMonotonic', 'queryReceivedMonotonic'):
                witness[key] = clock(witness[key])
        for key in ('normalExit', 'observerExit'):facts[key]['receivedMonotonic'] = clock(facts[key]['receivedMonotonic'])
        for key in ('counterReadStart', 'counterReadEnd'):facts['observerExit'][key] = clock(facts['observerExit'][key])
        self.status('STOP', control='cpu', reason='CPU_ENDPOINTS')

    def test_exact_cpu_envelope_product_may_exceed_float_range_without_acceptance(self):
        fixture = self.cpu
        for row in fixture['rows']:
            for key in ('monotonic', 'counterReadStart', 'counterReadEnd'):row[key] -= 100.
        facts = fixture['facts'];facts['deadlineMonotonic'] -= 100.
        for marker in facts['markers'].values():marker['receivedMonotonic'] -= 100.
        facts['signalStarts'] = [value-100. for value in facts['signalStarts']]
        for witness in facts['witnesses']+[facts['rootRoles']]:
            for key in ('counterReadStart', 'counterReadEnd', 'queryStartedMonotonic', 'queryReceivedMonotonic'):
                witness[key] -= 100.
        for key in ('normalExit', 'observerExit'):facts[key]['receivedMonotonic'] -= 100.
        for key in ('counterReadStart', 'counterReadEnd'):facts['observerExit'][key] -= 100.
        facts['markers']['READY']['receivedMonotonic'] = 0.
        fixture['rows'][0].update(monotonic=0., counterReadStart=0., counterReadEnd=0.)
        fixture['rows'][1].update(monotonic=0., counterReadStart=8e-307)
        # R is finite ~1.25e308, but its exact product with T is >float max.
        root_binding(fixture)
        self.status('UNPROVEN', control='cpu', reason='CPU_INSUFFICIENT_DIFFERENTIAL')

    def test_nested_identity_numeric_lookalikes_are_rejected(self):
        mutations = [
            (lambda f: f['markers']['READY']['ownership'].update(sentryPid=10.), 'INIT_IDENTITY'),
            (lambda f: f['markers']['READY']['init'].update(pid=2.), 'INIT_IDENTITY'),
            (lambda f: f['markers']['EFFECT_HELD']['actor'].update(startTicks=201.), 'INIT_IDENTITY'),
            (lambda f: f['witnesses'][0]['init'].update(pid=2.), 'INIT_IDENTITY'),
            (lambda f: f['normalExit']['ownership'].update(sentryStartTicks=100.), 'EXIT'),
        ]
        for change, reason in mutations:
            fixture = copy.deepcopy(self.memory)
            change(fixture['facts'])
            with self.subTest(reason=reason, change=mutations.index((change, reason))):
                self.status('STOP', fixture, reason=reason)

    def test_bool_cannot_alias_an_expected_init_pid_one(self):
        facts = self.memory['facts']
        facts['init']['pid'] = 1
        for phase, marker in facts['markers'].items():
            marker['init']['pid'] = 1
            if phase in ('RELEASED', 'HOLD_END'):
                marker['actor']['pid'] = 1
        for witness in facts['witnesses']+[facts['rootRoles']]:
            witness['init']['pid'] = 1
            # Root projection deliberately remains101, independent of local init PID1.
        facts['normalExit']['init']['pid'] = 1
        self.status('OBSERVED')
        facts['witnesses'][0]['init']['pid'] = True
        self.status('STOP', reason='INIT_IDENTITY')

    def test_same_actor_ticks_do_not_reverse_across_markers(self):
        for phase in ('NO_EFFECT', 'EFFECT_HELD', 'HOLD_END'):
            fixture = copy.deepcopy(self.memory)
            fixture['facts']['markers'][phase]['ticksBefore'] = 99
            with self.subTest(phase=phase):
                self.status('STOP', fixture, reason='PHASES')

    def test_optimized_interpreter_cannot_accept_even_valid_input(self):
        self.ns = {'__name__': 'optimized_evaluator_test'}
        exec(compile(CODE, str(EXTRACTED), 'exec', optimize=1), self.ns)
        for control in ('memory', 'cpu'):
            with self.subTest(control=control):
                self.status('STOP', control=control, reason='OPTIMIZED_INTERPRETER')
        raw=self.raw(self.memory)
        with self.assertRaisesRegex(AssertionError, '^OPTIMIZED_INTERPRETER$'):
            self.ns['complete_rows'](raw, 130.)

    def test_specific_invalid_facts_and_counter_reasons(self):
        changes = [
            (lambda d: d['facts']['worker'].update(pid=2), 'INIT_IDENTITY'),
            (lambda d: d['facts']['worker'].update(startTicks=199), 'INIT_IDENTITY'),
            (lambda d: d['facts']['ownership'].update(runtimeType='runc'), 'OWNERSHIP'),
            (lambda d: d['facts']['ownership'].update(root='/run/../other'), 'OWNERSHIP'),
            (lambda d: d['facts']['target'].update(name='f01-a2-cpu-control'), 'TARGET'),
            (lambda d: d['facts']['observerExit'].update(counterReadEnd=112.4), 'EXIT'),
            (lambda d: d['rows'][0]['groups'].pop('/synthetic/pod'), 'ROW_STATUS'),
            (lambda d: d['rows'][0]['groups'].__setitem__('/context', d['rows'][0]['groups'].pop('/synthetic/pod')), 'INVALID_INPUT'),
            (lambda d: d['rows'][0]['groups']['/synthetic/pod'].pop('pids.max'), 'COUNTER_SHAPE'),
            (lambda d: d['rows'][0]['groups']['/synthetic/pod']['memory.events'].update(oom_kill=1), 'COUNTER_INTERFERENCE'),
            (lambda d: d['rows'][0]['groups']['/synthetic/pod']['memory.events'].update(oom_group_kill=1), 'COUNTER_INTERFERENCE'),
        ]
        for change, reason in changes:
            fixture = copy.deepcopy(self.memory)
            change(fixture)
            with self.subTest(reason=reason, change=changes.index((change, reason))):
                self.status('STOP', fixture, reason=reason)

    def test_sample_binding_failure_is_not_disguised_as_a_read_bracket_failure(self):
        # Out-of-range sample is rejected before any bracket/row access.
        self.memory['facts']['witnesses'][0]['sample'] = len(self.memory['rows'])
        self.status('STOP', reason='RELEASE_WITNESS')

    def test_lagged_released_receipt_does_not_make_prior_query_impossible(self):
        fixture = self.memory
        row = copy.deepcopy(fixture['rows'][9])
        row.update(monotonic=109.125, counterReadStart=109.25, counterReadEnd=109.5)
        fixture['rows'].insert(9, row)
        for index, item in enumerate(fixture['rows']):
            item['sample'] = index
        facts = fixture['facts']
        for witness in facts['witnesses']:
            witness['sample'] += 1
        facts['observerExit']['lastSample'] += 1
        witness = copy.deepcopy(facts['witnesses'][0])
        witness.update(sample=9, counterReadStart=109.25, counterReadEnd=109.5,
                       queryStartedMonotonic=109.125, queryReceivedMonotonic=109.1875)
        facts['witnesses'].insert(0, witness)
        # Query is after gate3's dispatch but before its lagged RELEASED receipt.
        self.status('OBSERVED')
        windows = self.ns['_accounting_windows'](fixture['rows'], facts, 'memory')
        self.assertNotIn(row, windows['RELEASED'])

    def test_interphase_row_does_not_replace_fixed_cpu_endpoint(self):
        fixture = self.cpu
        row = copy.deepcopy(fixture['rows'][6])
        row.update(monotonic=106.125, counterReadStart=106.25, counterReadEnd=106.5)
        row['groups']['/synthetic/pod']['cpu.stat']['usage_usec'] = 1000
        fixture['rows'].insert(6, row)
        for index, item in enumerate(fixture['rows']):
            item['sample'] = index
        for witness in fixture['facts']['witnesses']:
            witness['sample'] += 1
        fixture['facts']['observerExit']['lastSample'] += 1
        original = copy.deepcopy(fixture)
        result = self.status('OBSERVED', control='cpu')
        self.assertEqual((result['C0'], result['C1'], result['T'], result['R']), (150, 1950, 1.75, 200.))
        self.assertEqual(fixture, original)


if __name__ == '__main__':
    unittest.main()
