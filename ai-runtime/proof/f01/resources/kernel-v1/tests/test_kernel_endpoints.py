import copy
import test_kernel_pid_boundary as p
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('endpoint_kernel', (Path(__file__).parents[1] / 'python' / 'kernel_observer.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Endpoints(unittest.TestCase):
    def fixture(self):
        f = getattr(m, 'final_endpoint', None);self.assertIsNotNone(f, 'closed final-endpoint selection missing')
        row = {'status': 'verified', 'counters': {'pids.events': {'max': 1}, 'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0}}, 'pidView': {'parent': '/p', 'groups': {'/p': {'events': 1}, '/p/s': {'events': 1}}, 'seedCgroups': ['/p/s'] * 3}}
        return f, row

    def test_cpu_and_calibration_use_last_complete_row_without_post_exit_reads(self):
        f, row = self.fixture()
        for control in ('cpu-deadline', 'memory-control'):
            with self.subTest(control=control):
                value = f(control, [row], lambda: self.fail('post-window resource read forbidden'), lambda: None, quiescence=None)
                self.assertIs(value['value'], row)

    def test_post_terminal_same_parent_read_is_explicit_and_preferred(self):
        f, row = self.fixture();current = dict(row, counterOrigin='current');calls = []
        value = f('memory-limit', [row], lambda: current, lambda: calls.append('identity'), quiescence=None)
        self.assertIs(value['value'], current);self.assertEqual(value['basis'], 'POST_TERMINAL_SAME_PARENT')
        self.assertEqual(calls, ['identity'])

    def test_only_owned_path_disappearance_and_already_valid_positive_event_allow_fallback(self):
        f, row = self.fixture()
        def missing():
            try: raise FileNotFoundError('owned counter path removed')
            except FileNotFoundError as error: raise m.ProofError('COUNTER_PATH') from error
        row['pidView'] = p.view();baseline = copy.deepcopy(row)
        row['pidView']['groups']['/ancestor/pod']['events'] = 1
        row['pidView']['groups']['/ancestor/pod']['localEvents'] = 1
        self.assertEqual(f('process-limit', [baseline, row], missing, lambda: None, quiescence=None)['basis'], 'LAST_VALID_POSITIVE_EVENT')
        row['pidView']['groups']['/ancestor/pod']['events'] = 0
        row['pidView']['groups']['/ancestor/pod']['localEvents'] = 0
        with self.assertRaises(m.ProofError): f('process-limit', [baseline, row], missing, lambda: None, quiescence=None)

    def test_invalid_candidate_oom_zero_or_other_io_failure_never_salvaged(self):
        f, row = self.fixture()
        for fault in ('invalid', 'oomzero', 'permission'):
            with self.subTest(fault=fault):
                candidate = dict(row)
                if fault == 'invalid': candidate['status'] = 'invalid'
                def read():
                    cause = PermissionError('denied') if fault == 'permission' else FileNotFoundError('gone')
                    raise m.ProofError('COUNTER_PATH') from cause
                with self.assertRaises(m.ProofError): f('memory-limit', [candidate], read, lambda: None, quiescence=None)


if __name__ == '__main__': unittest.main()
