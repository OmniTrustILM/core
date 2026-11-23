import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import patch

P = (Path(__file__).parents[1] / 'python' / 'kernel_collect.py')
spec = importlib.util.spec_from_file_location('trial_kernel', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
Q = (Path(__file__).parents[1] / 'python' / 'kernel_protocol.py');s = importlib.util.spec_from_file_location('protocol_trial', Q);protocol = importlib.util.module_from_spec(s);s.loader.exec_module(protocol)


class Trial(unittest.TestCase):
    def trial(self):
        klass = getattr(m, 'Trial', None);self.assertIsNotNone(klass, 'complete fixed trial adapter absent')
        t = klass.__new__(klass);t.target = {'cid': 'a' * 64};t.control = 'process-limit'
        t.deadline = 30;t.gate = protocol.StartGate(0);t.gate.feed('CG_READY pid=1 start=9', 1)
        t.rows = [{'sample': 0}];t.saved = [];t.calls = [];t.fence = lambda: 'LIVE'
        t.container = lambda: {'status': {'state': 'CONTAINER_RUNNING'}}
        t.save = lambda name, value: t.saved.append((name, value.copy()))
        t.command = lambda argv, **kwargs: t.calls.append((argv, kwargs)) or b''
        return t

    def test_start_dispatch_intent_is_consumed_before_exact_cid_usr1_and_never_resent(self):
        t = self.trial()
        with patch.object(m.time, 'monotonic', side_effect=[2., 2.1]): t.signal(1)
        self.assertEqual(t.calls, [(['/usr/local/bin/runsc', '--root=/run/containerd/runsc/k8s.io', 'kill', 'a' * 64, 'USR1'], {'raw': True})])
        self.assertEqual(t.saved[0][0], 'signal-1.intent.json');self.assertEqual(t.gate.signal, 2.)
        with patch.object(m.time, 'monotonic', return_value=2.2), self.assertRaises(protocol.ProtocolError): t.signal(1)
        self.assertEqual(len(t.calls), 1)

    def test_unknown_dispatch_result_preserves_consumption_and_no_success_receipt(self):
        t = self.trial()
        def command(*args, **kwargs): raise RuntimeError('nonzero')
        t.command = command
        with patch.object(m.time, 'monotonic', return_value=2.), self.assertRaises(RuntimeError): t.signal(1)
        self.assertEqual(t.gate.signal, 2.);self.assertEqual([name for name, _ in t.saved], ['signal-1.intent.json'])

    def test_terminal_or_changed_seed_refuses_signal_before_intent(self):
        self.trial()
        for fault in ('exit', 'identity'):
            with self.subTest(fault=fault):
                t = self.trial()
                if fault == 'exit': t.container = lambda: {'status': {'state': 'CONTAINER_EXITED'}}
                else: t.fence = lambda: 'EXITED'
                with self.assertRaises(AssertionError): t.signal(1)
                self.assertEqual(t.calls, []);self.assertEqual(t.saved, [])

    def test_high_workload_messages_before_ack_are_stop_and_protocol_quiescence_never_signals(self):
        t = self.trial()
        with self.assertRaises(AssertionError): t.emit('CHILD_READY 1', 2.)
        t.stream = types.SimpleNamespace(drain=lambda callback, wait=0: None)
        t.signal = lambda _: self.fail('quiescent producer must never dispatch')
        t.pump(True)


if __name__ == '__main__': unittest.main()
