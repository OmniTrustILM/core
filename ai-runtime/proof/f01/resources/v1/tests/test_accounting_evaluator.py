"""Literal synthetic owned facts test conditional pure accounting, never authority."""
import copy
import json
import os
import pathlib
import unittest

from test_observer_ownership import CODE, EXTRACTED
from domain_fixtures import root_binding


ROOT = pathlib.Path(os.environ.get('F01_ACCOUNTING_FIXTURES', pathlib.Path(__file__).parent / 'testdata/accounting'))


class AccountingEvaluator(unittest.TestCase):
    def setUp(self):
        self.ns = {'__name__': 'accounting_test'}
        exec(compile(CODE, str(EXTRACTED), 'exec'), self.ns)
        self.memory = json.loads((ROOT / 'memory.json').read_text())
        self.cpu = json.loads((ROOT / 'cpu.json').read_text())

    def raw(self, fixture):
        return b''.join((json.dumps(row, separators=(',', ':')) + '\n').encode() for row in fixture['rows'])

    def evaluate(self, fixture=None, control='memory'):
        fixture = fixture or (self.memory if control == 'memory' else self.cpu)
        name = 'evaluate_' + control
        self.assertTrue(callable(self.ns.get(name)), 'accepted planned pure evaluator is not implemented')
        return self.ns[name](self.raw(fixture), fixture['facts'])

    def status(self, want, fixture=None, control='memory', reason=None):
        result = self.evaluate(fixture, control)
        self.assertEqual(result['status'], want, result)
        if reason:
            self.assertEqual(result['reason'], reason)
        return result

    def test_memory_observation_uses_held_charge_and_eligible_release_not_peak_causality(self):
        result = self.status('OBSERVED')
        self.assertEqual(result['baselineMin'], 1048476)
        self.assertEqual(result['baselineMax'], 1048576)
        self.assertEqual(result['noise'], 100)
        self.assertEqual(result['payloadBytes'], 4194304)
        self.assertEqual(result['claim'], 'COINCIDENT_OWNED_AGGREGATE_CHARGE_AND_RETURN')

    def test_cpu_uses_fixed_conservative_endpoints_and_idle_envelope(self):
        result = self.status('OBSERVED', control='cpu')
        self.assertEqual((result['C0'], result['C1'], result['T'], result['R']), (150, 1950, 1.75, 200.))
        self.assertEqual(result['claim'], 'COINCIDENT_OWNED_AGGREGATE_CPU_DIFFERENTIAL')

    def test_complete_rows_rejects_partial_invalid_nonfinite_duplicate_and_oversized_data(self):
        self.assertTrue(callable(self.ns.get('complete_rows')), 'complete-row parser is not implemented')
        raw = self.raw(self.memory)
        bad_rows = []
        for field, value, expected, reason in [('status', 'invalid', AssertionError, 'ROW_STATUS'),
                             ('counterReadEnd', float('nan'), ValueError, 'ROW_JSON'),
                             ('counterReadStart', float('inf'), ValueError, 'ROW_JSON'),
                             ('sample', True, AssertionError, 'ROW_ORDER'),
                             ('lateSeconds', -1, AssertionError, 'ROW_CLOCK'),
                             ('counterReadEnd', 100., AssertionError, 'ROW_CLOCK'),
                             ('sample', 9, AssertionError, 'ROW_ORDER'),
                             ('monotonic', 10**400, AssertionError, 'ROW_CLOCK')]:
            fixture = copy.deepcopy(self.memory);fixture['rows'][0][field] = value
            bad_rows.append((self.raw(fixture), expected, reason))
        bad_rows += [(raw[:-1], AssertionError, 'ROW_FRAMING'), (raw+b'\n', AssertionError, 'ROW_LINE'),
                     (raw.replace(b'\n', b'\r\n', 1), AssertionError, 'ROW_FRAMING'),
                     (raw+b'\x00', AssertionError, 'ROW_FRAMING'), (b'\xff\n', UnicodeDecodeError, None),
                     (b'{"sample":0,"sample":0}\n', AssertionError, 'ROW_JSON'),
                     (b' '*(8*1024*1024+1), AssertionError, 'ROW_BYTES'),
                     (b' '*65536+b'\n', AssertionError, 'ROW_LINE'), (b'{}\n'*301, AssertionError, 'ROW_COUNT'),
                     (b'', AssertionError, 'ROW_BYTES'), ('not bytes', AssertionError, 'ROW_BYTES')]
        for value, expected, reason in bad_rows:
            with self.subTest(kind=str(type(value)), size=len(value)):
                with self.assertRaises(expected) as caught:
                    self.ns['complete_rows'](value, 130.)
                self.assertIs(type(caught.exception),expected)
                if reason:self.assertEqual(str(caught.exception),reason)
        self.assertEqual(len(self.ns['complete_rows'](raw, 130.)), 13)

    def test_nested_json_retains_recursion_error_family_without_returning_success(self):
        raw=b'['*30000+b'0'+b']'*30000+b'\n'
        for parser in ('complete_rows','accounting_lines','evaluate_memory','evaluate_cpu'):
            args=(raw,130.) if parser=='complete_rows' else (raw,)
            if parser.startswith('evaluate_'):args=(raw,self.memory['facts'])
            with self.subTest(parser=parser):
                with self.assertRaises(RecursionError) as caught:self.ns[parser](*args)
                self.assertIs(type(caught.exception),RecursionError)

    def test_stop_disposition_never_promotes_a_complete_prefix_of_invalid_stream(self):
        self.assertTrue(callable(self.ns.get('evaluate_memory')), 'memory evaluator is not implemented')
        for raw,reason in [(self.raw(self.memory)+b'{','ROW_FRAMING'),
                           (self.raw(self.memory)[:-1],'ROW_FRAMING'),(b'{}\n','ROW_SHAPE')]:
            with self.subTest(raw_size=len(raw)):
                self.assertEqual(self.ns['evaluate_memory'](raw,self.memory['facts']),{'status':'STOP','reason':reason})

    def test_straddling_rows_are_ineligible_without_interpolation(self):
        self.memory['facts']['signalStarts'][0] = 102.625
        self.status('UNPROVEN', reason='INSUFFICIENT_WINDOW')

    def test_exact_window_fence_equality_is_accepted_but_short_read_span_is_not(self):
        self.memory['facts']['markers']['READY']['receivedMonotonic'] = 101.
        self.memory['facts']['rootRoles'].update(queryStartedMonotonic=101.,queryReceivedMonotonic=101.)
        self.memory['facts']['signalStarts'][0] = 102.75
        self.status('OBSERVED')
        self.memory['rows'][2]['counterReadStart'] = 102.24
        self.memory['rows'][2]['monotonic'] = 102.115
        self.status('UNPROVEN', reason='INSUFFICIENT_WINDOW')

    def test_counter_resets_unavailable_limits_events_and_noninteger_values_stop(self):
        group = '/synthetic/pod'
        mutations = [lambda v: v.update(**{'cpu.stat': {'usage_usec': -1}}),
                     lambda v: v.update(**{'memory.peak': ['1']}),
                     lambda v: v.update(**{'memory.current': {'unavailable': True}}),
                     lambda v: v.update(**{'memory.current': ['nan']}),
                     lambda v: v.update(**{'memory.max': ['max']}),
                     lambda v: v.update(**{'cpu.max': ['max', '100000']}),
                     lambda v: v.update(**{'pids.max': ['max']}),
                     lambda v: v['memory.events'].update(oom=1),
                     lambda v: v['memory.events'].update(max=1),
                     lambda v: v['pids.events'].update(max=1),
                     lambda v: v['cpu.stat'].update(usage_usec=True)]
        reasons=('COUNTER_VALUE',)*4+('COUNTER_LIMIT',)*3+('COUNTER_INTERFERENCE',)*3+('COUNTER_VALUE',)
        for mutate,reason in zip(mutations,reasons,strict=True):
            fixture = copy.deepcopy(self.memory);mutate(fixture['rows'][7]['groups'][group])
            with self.subTest(mutation=mutations.index(mutate)):
                self.status('STOP', fixture, reason=reason)
        fixture = copy.deepcopy(self.memory)
        fixture['rows'][8]['groups'][group]['cpu.stat']['usage_usec'] = 1
        self.status('STOP', fixture, reason='COUNTER_RESET')
        fixture = copy.deepcopy(self.memory)
        fixture['rows'][8]['groups'][group]['memory.peak'] = ['5242980']
        self.status('STOP', fixture, reason='COUNTER_VALUE')

    def test_init_reuse_target_owner_and_sample_binding_cannot_be_inferred(self):
        mutations = [lambda f: f['markers']['HOLD_END']['init'].update(startTicks=999),
                     lambda f: f['markers']['EFFECT_HELD']['actor'].update(startTicks=999),
                     lambda f: f['witnesses'][0]['target'].update(cid='c' * 64),
                     lambda f: f['witnesses'][0]['ownership'].update(sentryStartTicks=999),
                     lambda f: f['witnesses'][0].update(sample=0),
                     lambda f: f['witnesses'][0].update(counterReadEnd=999.),
                     lambda f: f['witnesses'][0].update(rootProjection=[]),
                     lambda f: f['witnesses'].append(copy.deepcopy(f['witnesses'][0])),
                     lambda f: f.update(witnesses=[]),
                     lambda f: f.pop('init')]
        reasons=('INIT_IDENTITY',)*4+('RELEASE_WITNESS',)*2+('ROOT_ROLES',)+('RELEASE_WITNESS',)*2+('FACT_SHAPE',)
        for mutate,reason in zip(mutations,reasons,strict=True):
            fixture = copy.deepcopy(self.memory);mutate(fixture['facts'])
            with self.subTest(mutation=mutations.index(mutate)):
                self.status('STOP', fixture, reason=reason)

    def test_release_needs_later_query_in_a_later_verified_row_and_not_teardown(self):
        fixture = copy.deepcopy(self.memory)
        fixture['facts']['witnesses'] = [fixture['facts']['witnesses'][0]]
        self.status('UNPROVEN', fixture, reason='INSUFFICIENT_WINDOW')
        fixture = copy.deepcopy(self.memory)
        fixture['facts']['witnesses'][0]['queryStartedMonotonic'] = 109.
        self.status('STOP', fixture, reason='RELEASE_WITNESS')
        fixture = copy.deepcopy(self.memory)
        fixture['facts']['normalExit']['receivedMonotonic'] = 111.
        self.status('STOP', fixture, reason='EXIT')
        fixture = copy.deepcopy(self.memory)
        fixture['facts']['markers'].pop('HOLD_END')
        self.status('STOP', fixture, reason='PHASES')

    def test_deadline_watchdog_early_exit_nonzero_exit_and_missing_phase_stop(self):
        mutations = [lambda f: f.update(deadlineMonotonic=112.),
                     lambda f: f.update(watchdogIntervened=True),
                     lambda f: f['observerExit'].update(receivedMonotonic=112.),
                     lambda f: f['observerExit'].update(lastSample=11),
                     lambda f: f['normalExit'].update(exitCode=137),
                     lambda f: f['observerExit'].update(exitCode=1),
                     lambda f: f['markers'].pop('NO_EFFECT'),
                     lambda f: f['signalStarts'].__setitem__(1, 103.),
                     lambda f: f.update(schema='unknown')]
        reasons=('ROW_CLOCK','DEADLINE','DEADLINE','EXIT','EXIT','EXIT','PHASES','DEADLINE','FACT_SCHEMA')
        for mutate,reason in zip(mutations,reasons,strict=True):
            fixture = copy.deepcopy(self.memory);mutate(fixture['facts'])
            with self.subTest(mutation=mutations.index(mutate)):
                self.status('STOP', fixture, reason=reason)

    def test_memory_strict_noise_rise_and_return_boundaries(self):
        group = '/synthetic/pod'
        fixture = copy.deepcopy(self.memory)
        fixture['rows'][0]['groups'][group]['memory.current'] = [str(1048576 - 2097152)]
        self.status('STOP', fixture, reason='COUNTER_VALUE')  # Negative charge is malformed, not baseline evidence.
        fixture = copy.deepcopy(self.memory)
        for row in fixture['rows'][:6]:
            values = row['groups'][group]
            values['memory.current'] = ['4194304' if row['sample'] else '2097152']
            values['memory.peak'] = ['5243080']
        for row in fixture['rows'][6:]:row['groups'][group]['memory.peak'] = ['5243080']
        self.status('UNPROVEN', fixture, reason='MEMORY_BASELINE_NOISE')
        fixture = copy.deepcopy(self.memory)
        fixture['rows'][6]['groups'][group]['memory.current'] = ['5242879']
        self.status('UNPROVEN', fixture, reason='MEMORY_NO_RISE')
        fixture = copy.deepcopy(self.memory)
        fixture['rows'][9]['groups'][group]['memory.current'] = ['1048677']
        self.status('UNPROVEN', fixture, reason='MEMORY_NO_RETURN')
        self.memory['rows'][9]['groups'][group]['memory.current'] = ['1048676']
        self.status('OBSERVED')

    def test_cpu_positive_ticks_and_strict_differential_have_no_epsilon(self):
        group = '/synthetic/pod'
        self.cpu['facts']['markers']['EFFECT_HELD']['ticksAfter'] = 100
        self.status('UNPROVEN', control='cpu', reason='CPU_ZERO_GUEST_TICKS')
        self.cpu['facts']['markers']['EFFECT_HELD']['ticksAfter'] = 101
        for i, value in enumerate([1050, 1150, 1250, 1350, 1450, 1550, 1650], 6):
            self.cpu['rows'][i]['groups'][group]['cpu.stat']['usage_usec'] = value
        self.status('UNPROVEN', control='cpu', reason='CPU_INSUFFICIENT_DIFFERENTIAL')
        self.cpu['rows'][6]['groups'][group]['cpu.stat']['usage_usec'] = 1051
        self.status('OBSERVED', control='cpu')

    def test_cpu_nonpositive_idle_gap_stops_without_rate_interpolation(self):
        self.cpu['rows'][1]['counterReadStart'] = 101.25
        self.cpu['rows'][1]['monotonic'] = 101.25
        self.status('STOP', control='cpu', reason='CPU_IDLE_GAP')

    def test_nonfinite_derived_idle_rate_stops_instead_of_returning_a_result(self):
        fixture = self.cpu
        for row in fixture['rows']:
            for key in ('monotonic', 'counterReadStart', 'counterReadEnd'):
                row[key] -= 100.
        facts = fixture['facts'];facts['deadlineMonotonic'] -= 100.
        for marker in facts['markers'].values():marker['receivedMonotonic'] -= 100.
        facts['signalStarts'] = [value - 100. for value in facts['signalStarts']]
        for witness in facts['witnesses']+[facts['rootRoles']]:
            for key in ('counterReadStart', 'counterReadEnd', 'queryStartedMonotonic', 'queryReceivedMonotonic'):
                witness[key] -= 100.
        for key in ('normalExit', 'observerExit'):facts[key]['receivedMonotonic'] -= 100.
        for key in ('counterReadStart', 'counterReadEnd'):facts['observerExit'][key] -= 100.
        facts['markers']['READY']['receivedMonotonic'] = 0.
        fixture['rows'][0].update(monotonic=0., counterReadStart=0., counterReadEnd=0.)
        fixture['rows'][1].update(monotonic=0., counterReadStart=5e-324)
        root_binding(fixture)
        self.status('STOP', control='cpu', reason='CPU_RATE')

    def test_evaluators_do_not_mutate_rows_or_facts(self):
        original = copy.deepcopy(self.memory)
        self.status('OBSERVED')
        self.assertEqual(self.memory, original)


if __name__ == '__main__':
    unittest.main()
