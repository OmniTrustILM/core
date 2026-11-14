"""Terminal presence is only a fail-closed quiescence hint, never success evidence."""
import json,unittest
import bootstrap as bootstrap
from terminal_fixture import TerminalFixture
import test_accounting_producer as producer
import test_postgate_fences as finish_fixture

class Quiescence(TerminalFixture,unittest.TestCase):
    def test_terminal_file_precedes_exit_receipt_and_hold_log_without_live_operations(self):
        self.protocol('exit-receipt-lag')
        self.assertEqual(self.late_ops,[]);self.assertEqual(len(self.signals),3)
        context=json.loads((self.out/'accounting-protocol.json').read_text())
        self.assertEqual(context['normalExit']['receivedMonotonic'],self.actual_terminal)
        self.assertGreater(context['markers']['HOLD_END']['receivedMonotonic'],self.actual_terminal)
        self.assertTrue(json.loads((self.out/'accounting-log.result.json').read_text())['drainOnly'])
        self.assertEqual(self.child.killed,0)

    def test_missing_or_removed_terminal_completion_never_gains_success_and_uses_original_deadline(self):
        for fault in ('missing-exit','terminal-removed'):
            with self.subTest(fault=fault):
                self.doCleanups();self.setUp()
                with self.assertRaises(AssertionError):self.protocol(fault)
                self.assertEqual(self.late_ops,[])
                self.assertGreaterEqual(self.now,130.)
                self.assertEqual(len(self.signals),3)
                self.assertFalse((self.out/'accounting-protocol.json').exists())
                result=json.loads((self.out/'accounting-log.result.json').read_text())
                self.assertEqual(result['status'],'STOP');self.assertFalse(result['drainOnly'])

    def test_malformed_or_wrong_owned_final_receipt_cannot_promote_quiescence(self):
        for fault in ('malformed-final','wrong-owner-final'):
            with self.subTest(fault=fault):
                self.doCleanups();self.setUp()
                expected=json.JSONDecodeError if fault=='malformed-final' else AssertionError
                with self.assertRaises(expected):self.protocol(fault)
                self.assertEqual(self.late_ops,[]);self.assertEqual(len(self.signals),3)
                self.assertFalse((self.out/'accounting-protocol.json').exists())
                self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')

class ReceiptTypes(producer.ProducerInputs,unittest.TestCase):
    inputs=finish_fixture.FinishBinding.inputs
    prepare=finish_fixture.FinishBinding.prepare
    def test_complete_receipt_requires_actual_drain_only_and_numeric_natural_finish(self):
        for fault in ('drain-false','natural-true','natural-false'):
            with self.subTest(fault=fault):
                self.doCleanups();self.setUp();natural,receipt=self.prepare()
                if fault=='drain-false':receipt['drainOnly']=False
                if fault=='natural-true':natural['finishedMonotonic']=True
                if fault=='natural-false':natural['finishedMonotonic']=False
                (self.out/'observation/observer-result.json').write_text(json.dumps(natural))
                (self.out/'accounting-log.result.json').write_text(json.dumps(receipt))
                with self.assertRaises(AssertionError):self.ns['accounting_finish'](self.out,'memory')
                self.assertFalse((self.out/'control-observation.json').exists())

if __name__=='__main__':unittest.main()
