import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

collector = load('calibration_collector', ROOT / 'python/kernel_collect.py')
fixtures = load('calibration_fixture_tests', ROOT / 'tests/test_kernel_protocol.py')

class Evidence(unittest.TestCase):
    def trial(self, rows, phases, ops):
        phases.raw_reads = []
        value = collector.Trial.__new__(collector.Trial)
        value.rows = rows
        value.control = 'memory-control'
        value.phases = phases
        value.root_roles = [{'PID': '1', 'CMD': 'a2mi'}]
        value.protocol = fixtures.m
        value.ops = ops
        value.target = {'uid': 'synthetic'}
        value.owner = {'parent': {'path': '/synthetic/pod', 'identity': [1, 2]}}
        value.stream = SimpleNamespace(finish=lambda emit: None, buffer=SimpleNamespace(raw=b''))
        value.emit = lambda *args: None
        value.pod = lambda: {'status': {'phase': 'Succeeded', 'containerStatuses': [
            {'state': {'terminated': {'exitCode': 0}}}]}}
        value.observation_deadline = float('inf')
        value.deadline = 100.
        value.measurement = SimpleNamespace(read=lambda: None)
        value.parent = SimpleNamespace(check=lambda: None)
        value.kernel = SimpleNamespace(final_endpoint=lambda *args, **kwargs: {
            'value': rows[-1], 'basis': 'LAST_COMPLETE_CALIBRATION_ROW'})
        return value

    def test_calibration_failure_retains_exact_protocol_before_same_oracle_error(self):
        for fault, expected in [('rise', 'MEMORY_NO_RISE'), ('terminal', 'CALIBRATION_TERMINAL')]:
            with self.subTest(fault=fault):
                rows, phases, ops = fixtures.Calibration().fixture()
                if fault == 'rise':
                    rows[7]['counters']['memory.current'] = ['5194303']
                trial = self.trial(rows, phases, ops)
                if fault == 'terminal':
                    trial.pod = lambda: {'status': {'phase': 'Failed', 'containerStatuses': [
                        {'state': {'terminated': {'exitCode': 1}}}]}}
                writes = []
                trial.save = lambda name, value: writes.append((name, value))
                terminal = {'exitCode': 1 if fault == 'terminal' else 0}
                result = {'samples': rows, 'terminal': terminal,
                          'discarded': 0, 'quiescence': None}
                with self.assertRaisesRegex(fixtures.m.ProtocolError, '^' + expected + '$'):
                    trial.finish(result)
                self.assertEqual([name for name, _ in writes], ['calibration-protocol.json'])
                recorded = writes[0][1]
                self.assertEqual(recorded['markers'], phases.markers)
                self.assertEqual(recorded['signalStarts'], phases.signal_starts)
                self.assertEqual(recorded['rawReads'], phases.raw_reads)
                self.assertEqual(recorded['rootRoles'], trial.root_roles)
                self.assertEqual(recorded.get('status'), 'UNQUALIFIED_CALIBRATION_PROTOCOL')
                self.assertEqual(recorded.get('terminal'), terminal)
                self.assertNotIn('observer-result.json', [name for name, _ in writes])

if __name__ == '__main__':
    unittest.main()
