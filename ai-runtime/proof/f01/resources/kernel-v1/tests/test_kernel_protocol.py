import copy
import os
import re
import importlib.util
from pathlib import Path
import unittest

P = (Path(__file__).parents[1] / 'python' / 'kernel_protocol.py')
if P.exists():
    spec = importlib.util.spec_from_file_location('kernel_protocol', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
else: m = None


class Start(unittest.TestCase):
    def gate(self):
        self.assertIsNotNone(m, 'fixed one-shot gate parser absent');return m.StartGate(0)

    def test_direct_and_interrupted_read_both_require_one_successful_owned_signal(self):
        for interrupted in (False, True):
            with self.subTest(interrupted=interrupted):
                g = self.gate();g.feed('CG_READY pid=1 start=55', 1);g.signal_started(2);g.signal_finished(2.1)
                if interrupted: g.feed('CG_RAW attempt=1 rc=1 count=1 token=', 2.2)
                g.feed('CG_RAW attempt=' + ('2' if interrupted else '1') + ' rc=0 count=1 token=GO', 2.3)
                g.feed('CG_ACK pid=1 start=55 count=1', 2.4);g.feed('CG_LOAD_BEGIN', 2.5)
                self.assertTrue(g.complete);self.assertEqual(g.pid, 1)

    def test_timeout_without_signal_is_stop_not_optional_continuation(self):
        g = self.gate();g.feed('CG_READY pid=1 start=55', 1)
        with self.assertRaisesRegex(m.ProtocolError, '^GATE_ORDER$'): g.feed('CG_RAW attempt=1 rc=1 count=0 token=', 16)

    def test_replayed_or_unknown_markers_and_changed_init_are_stop(self):
        self.gate()
        for message in ('CG_READY pid=1 start=55', 'CG_RAW attempt=1 rc=0 count=2 token=GO', 'CG_ACK pid=2 start=55 count=1', 'CG_OTHER'):
            with self.subTest(message=message):
                g = self.gate();g.feed('CG_READY pid=1 start=55', 1);g.signal_started(2);g.signal_finished(2.1)
                with self.assertRaises(m.ProtocolError): g.feed(message, 2.2)

    def test_original_clock_limits_signal_start_completion_and_ack(self):
        ready = ('feed', ('CG_READY pid=1 start=55', 1))
        start = ('signal_started', (2,))
        finish = ('signal_finished', (2.1,))
        raw = ('feed', ('CG_RAW attempt=1 rc=0 count=1 token=GO', 2.2))
        cases = [('ready', (), 'feed', ('CG_READY pid=1 start=55', 10.1)),
                 ('start', (ready,), 'signal_started', (10.1,)),
                 ('finish', (ready, start), 'signal_finished', (12.1,)),
                 ('ack', (ready, start, finish, raw), 'feed', ('CG_ACK pid=1 start=55 count=1', 14.1))]
        for fault, prefix, method, arguments in cases:
            with self.subTest(fault=fault):
                g = self.gate()
                for name, values in prefix:
                    getattr(g, name)(*values)
                operation = getattr(g, method)
                with self.assertRaisesRegex(m.ProtocolError, '^GATE_ORDER$'):
                    operation(*arguments)

    def test_consumed_dispatch_cannot_be_resent_after_unknown_result(self):
        g = self.gate();g.feed('CG_READY pid=1 start=55', 1);g.signal_started(2)
        with self.assertRaisesRegex(m.ProtocolError, '^GATE_ORDER$'): g.signal_started(2.1)


class Calibration(unittest.TestCase):
    def fixture(self):
        self.assertIsNotNone(m, 'kernel calibration predicates absent')
        source = (Path(__file__).parents[2] / 'v1') / 'python' / 'observer.py'
        raw = source.read_bytes()
        self.assertEqual(__import__('hashlib').sha256(raw).hexdigest(), '9df097eb5519f45c330816485feebccf1899f854e324670ca078830bd9891a83')
        ops = {'__name__': 'calibration_primitives'};exec(compile(raw, str(source), 'exec'), ops)
        phases = type('Phases', (), {})();phases.complete = lambda: None
        phases.signal_starts = [2., 4., 6.]
        phases.markers = {key: {'receivedMonotonic': when} for key, when in [('READY', 0.), ('NO_EFFECT', 2.1), ('EFFECT_HELD', 4.1), ('RELEASED', 6.1), ('HOLD_END', 8.)]}
        rows = []
        for phase, begin, memory in [('READY', .1, 1000000), ('NO_EFFECT', 2.2, 1000000), ('EFFECT_HELD', 4.2, 5194304), ('RELEASED', 6.2, 1000000)]:
            for offset in (0., .6, 1.2):
                at = begin + offset;index = len(rows)
                counters = {'pids.max': ['256'], 'pids.current': ['7'], 'pids.events': {'max': 0}, 'memory.max': ['268435456'], 'memory.current': [str(memory)], 'memory.peak': ['6000000'], 'memory.events': {'low': 0, 'high': 0, 'max': 0, 'oom': 0, 'oom_kill': 0}, 'cpu.max': ['50000', '100000'], 'cpu.stat': {'usage_usec': index}}
                rows.append({'sample': index, 'status': 'verified', 'counterReadStart': at, 'counterReadEnd': at + .01, 'counters': counters})
        return rows, phases, ops

    def test_real_pure_numeric_predicates_qualify_four_complete_quiescent_windows(self):
        rows, phases, ops = self.fixture();result = m.calibration_result(rows, phases, {'exitCode': 0}, ops)
        self.assertEqual(result['status'], 'OBSERVED');self.assertEqual(result.get('logicalPayloadBytes'), 8388608)
        self.assertEqual(result['minimumRiseBytes'], 4194304)

    def test_reported_logical_payload_matches_fixed_program_elements(self):
        rows, phases, ops = self.fixture()
        result = m.calibration_result(rows, phases, {'exitCode': 0}, ops)
        body = (Path(__file__).parents[1] / 'fixtures/golden/memory-control.sh').read_text()
        count = re.search(r'for \(i=1; i<=([0-9]+); i\+\+\)', body)
        size = re.search(r'if\(length\(a\[i\]\)!=([0-9]+)\)', body)
        self.assertIsNotNone(count);self.assertIsNotNone(size)
        self.assertEqual(result.get('logicalPayloadBytes'), int(count[1]) * int(size[1]))

    def test_noise_no_rise_no_return_and_short_window_are_not_observed(self):
        self.fixture()
        for fault, reason in [('noise', 'MEMORY_BASELINE_NOISE'), ('rise', 'MEMORY_NO_RISE'), ('return', 'MEMORY_NO_RETURN'), ('short', 'INSUFFICIENT_WINDOW')]:
            with self.subTest(fault=fault):
                rows, phases, ops = self.fixture()
                if fault == 'noise': rows[1]['counters']['memory.current'] = ['3097152']
                elif fault == 'rise': rows[7]['counters']['memory.current'] = ['5194303']
                elif fault == 'return': rows[-1]['counters']['memory.current'] = ['1000001']
                else: rows.pop()
                with self.assertRaisesRegex(m.ProtocolError, '^' + reason + '$'): m.calibration_result(rows, phases, {'exitCode': 0}, ops)

    def test_counter_interference_and_abnormal_terminal_are_failclosed(self):
        self.fixture()
        for fault in ('oom', 'pid', 'exit'):
            with self.subTest(fault=fault):
                rows, phases, ops = self.fixture()
                if fault == 'oom': rows[-1]['counters']['memory.events']['oom_kill'] = 1
                elif fault == 'pid': rows[-1]['counters']['pids.events']['max'] = 1
                with self.assertRaises(AssertionError): m.calibration_result(rows, phases, {'exitCode': 1 if fault == 'exit' else 0}, ops)


if __name__ == '__main__': unittest.main()
