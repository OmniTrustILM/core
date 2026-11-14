"""Genuine A1 counterexamples; no kernel/native proof credit."""
import copy
import types
import unittest
from unittest.mock import patch
import test_kernel_endpoints as e
import test_kernel_pid_boundary as p
import test_kernel_measurement as measured
import test_kernel_b_composition as composition


class Closure(unittest.TestCase):
    def missing(self):
        raise e.m.ProofError('COUNTER_PATH') from FileNotFoundError('owned path removed')

    def rows(self, kind):
        baseline = {'status': 'verified', 'counters': {'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0}}, 'pidView': p.view()}
        last = copy.deepcopy(baseline)
        if kind == 'pid':
            baseline['pidView']['groups']['/ancestor/pod']['events'] = 1
            last['pidView']['groups']['/ancestor/pod']['events'] = 1
        else:
            last['counters']['memory.events']['oom_kill'] = 1
        return [baseline, last]

    def test_stale_nonzero_pid_event_is_not_a_post_disappearance_endpoint(self):
        with self.assertRaisesRegex(e.m.ProofError, '^PID_DENIAL_EVENT_UNPROVEN$'):
            e.m.final_endpoint('process-limit', self.rows('pid'), self.missing, lambda: None, quiescence=None)

    def test_global_oomkill_without_budget_max_and_oom_delta_is_not_endpoint(self):
        with self.assertRaisesRegex(e.m.ProofError, '^FINAL_EVENT_UNPROVEN$'):
            e.m.final_endpoint('memory-limit', self.rows('oom'), self.missing, lambda: None, quiescence=None)

    def test_lower_known_child_memory_limit_is_rejected_before_measurement_credit(self):
        case = measured.Measurement();value = case.fixture()
        measured.FakeGroup.values['/cg/ancestor/pod/scope']['memory.max'] = ['134217728']
        with patch.object(measured.m, 'PodCgroup', measured.FakeGroup), patch.object(measured.Path, 'stat') as info:
            info.return_value.st_mode = 0o444
            with self.assertRaisesRegex(measured.m.ProofError, '^DESCENDANT_MEMORY_LIMIT$'):
                value.read()

    def test_memory_fallback_requires_each_budget_event_delta_and_accepts_all_three(self):
        rows = self.rows('oom')
        rows[-1]['counters']['memory.events'] = {'max': 1, 'oom': 1, 'oom_kill': 1}
        endpoint = e.m.final_endpoint('memory-limit', rows, self.missing, lambda: None, quiescence=None)
        self.assertIs(endpoint['value'], rows[-1])
        self.assertEqual(endpoint['basis'], 'LAST_VALID_POSITIVE_EVENT')
        for missing in ('max', 'oom', 'oom_kill'):
            with self.subTest(missing=missing):
                candidate = copy.deepcopy(rows)
                candidate[-1]['counters']['memory.events'][missing] = 0
                with self.assertRaisesRegex(e.m.ProofError, '^FINAL_EVENT_UNPROVEN$'):
                    e.m.final_endpoint('memory-limit', candidate, self.missing, lambda: None, quiescence=None)

    def test_exact256mib_child_limit_is_allowed_but_one_byte_lower_is_not(self):
        for limit, accepted in ((268435456, True), (268435455, False)):
            with self.subTest(limit=limit):
                value = measured.Measurement().fixture()
                measured.FakeGroup.values['/cg/ancestor/pod/scope']['memory.max'] = [str(limit)]
                with patch.object(measured.m, 'PodCgroup', measured.FakeGroup), patch.object(measured.Path, 'stat') as info:
                    info.return_value.st_mode = 0o444
                    if accepted:
                        self.assertEqual(value.read()['counters']['memory.max'], ['268435456'])
                    else:
                        with self.assertRaisesRegex(measured.m.ProofError, '^DESCENDANT_MEMORY_LIMIT$'):
                            value.read()

    def test_cpu_seed_exit_quiescence_cannot_reuse_early_complete_row(self):
        case = composition.Process();case.addCleanup = self.addCleanup
        trial, result = case.finish_trial();trial.control = 'cpu-deadline';result['quiescence'] = 'SEED_EXIT'
        trial.outcomes = {'qualify': lambda *_: {'status': 'OBSERVED'}}
        with patch.object(composition.collect.time, 'monotonic', return_value=10.):
            with self.assertRaisesRegex(composition.kernel.ProofError, '^CPU_QUIESCENCE$'):
                trial.finish(result)
        self.assertFalse((trial.out / 'control-observation.json').exists())


if __name__ == '__main__': unittest.main()
