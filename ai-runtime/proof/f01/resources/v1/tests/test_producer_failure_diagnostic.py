"""Safe failure-only evidence, using inherited real local pipes/files protocol."""
import json
import pathlib
import subprocess
import types
import unittest
from unittest.mock import patch
import bootstrap as bootstrap
import test_accounting_producer as producer
from test_observer_ownership import SOURCE,CODE

class FailureDiagnostics(producer.ProducerInputs,unittest.TestCase):
    protocol=producer.Protocol.protocol
    def trusted_out(self):
        original=pathlib.Path.lstat;out=self.out
        def lstat(path,*a,**kw):
            value=original(path,*a,**kw)
            return types.SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0) if path==out else value
        return patch.object(pathlib.Path,'lstat',lstat)

    def test_real_failed_signal_retains_safe_receipt_and_primary_cleanup(self):
        with self.trusted_out(),self.assertRaises(TimeoutError) as caught:self.protocol('unknown-signal')
        receipt=self.out/'accounting-failure.json'
        self.assertTrue(receipt.exists(),'escaping producer failure lost its safe diagnostic')
        value=json.loads(receipt.read_text())
        self.assertEqual(set(value),{'schema','exceptionClass','observerPythonLine','signalCount'})
        self.assertEqual(value['schema'],'f01-accounting-failure-v1')
        self.assertEqual(value['exceptionClass'],'TimeoutError');self.assertEqual(value['signalCount'],1)
        self.assertGreater(value['observerPythonLine'],0)
        self.assertEqual(self.child.killed,1);self.assertTrue(self.child.stdout.closed and self.child.stderr.closed)
        self.assertEqual(str(caught.exception),'unknown signal')
        self.assertLessEqual(receipt.stat().st_size,512)
        self.assertNotIn('unknown signal',receipt.read_text())

    def test_closed_exception_class_and_setup_failure_no_sensitive_data(self):
        error=type('PRIVATE_TYPE_DO_NOT_EMIT',(Exception,),{})('PRIVATE_MESSAGE_DO_NOT_EMIT')
        self.out.joinpath('targets.json').write_text(json.dumps(self.f['target']))
        self.ns['load_outer_clock']=lambda *args:(_ for _ in ()).throw(error)
        with self.trusted_out(),self.assertRaises(type(error)) as caught:self.ns['accounting_producer'](self.out,'memory',900)
        self.assertIs(caught.exception,error)
        receipt=self.out/'accounting-failure.json';self.assertTrue(receipt.exists(),'setup failure lost safe diagnostic')
        raw=receipt.read_text();value=json.loads(raw)
        self.assertEqual(value['exceptionClass'],'OTHER');self.assertEqual(value['signalCount'],0)
        self.assertNotIn('PRIVATE',raw);self.assertNotIn(str(self.out),raw)
        self.assertTrue(CODE.splitlines()[value['observerPythonLine']-1].strip().startswith('self.clock,self.unchanged=load_outer_clock('),'foreign traceback frame must not replace trusted observer callsite')

    def test_failure_journal_refusal_keeps_primary_identity_and_pipe_cleanup(self):
        final=self.out/'accounting-failure.json';final.write_bytes(b'previous-owned-diagnostic')
        original=self.ns['accounting_failure'];seen=[]
        def diagnostic(out,error,phases):
            seen.append(error);return original(out,error,phases)
        self.ns['accounting_failure']=diagnostic
        with self.trusted_out(),self.assertRaises(TimeoutError) as caught:self.protocol('unknown-signal')
        self.assertIs(caught.exception,seen[0]);self.assertEqual(final.read_bytes(),b'previous-owned-diagnostic')
        self.assertEqual(caught.exception.__notes__,['accounting failure diagnostic unavailable'])
        self.assertEqual(self.child.killed,1);self.assertTrue(self.child.stdout.closed and self.child.stderr.closed)
        self.assertFalse((self.out/'accounting-protocol.json').exists())

    def test_cleanup_failure_is_failure_only_and_keeps_actual_cleanup(self):
        original=self.ns['accounting_reap'];primary=OSError('PRIVATE_CLEANUP_MESSAGE')
        def cleanup(child,error=None):
            original(child,error);raise primary
        self.ns['accounting_reap']=cleanup
        with self.trusted_out(),self.assertRaises(OSError) as caught:self.protocol()
        self.assertIs(caught.exception,primary)
        raw=(self.out/'accounting-failure.json').read_text();value=json.loads(raw)
        self.assertEqual(value['exceptionClass'],'OSError');self.assertEqual(value['signalCount'],3)
        self.assertNotIn('PRIVATE',raw);self.assertEqual(self.child.killed,0)
        self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')
        self.assertTrue((self.out/'accounting-protocol.json').exists(),'published protocol alone is not final acceptance')
        self.assertFalse((self.out/'control-observation.json').exists())
        self.assertFalse((self.out/'accounting-facts.json').exists())
        self.assertTrue(self.child.stdout.closed and self.child.stderr.closed)

    def test_success_has_no_failure_receipt_or_success_schema_change(self):
        with self.trusted_out():self.protocol()
        self.assertFalse((self.out/'accounting-failure.json').exists())
        self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'COMPLETE')
        self.assertEqual(len(self.signals),3);self.assertEqual(self.child.killed,0)

    def test_untrusted_output_does_not_receive_failure_json(self):
        error=ValueError('PRIVATE_UNTRUSTED_OUTPUT')
        self.out.joinpath('targets.json').write_text(json.dumps(self.f['target']))
        self.ns['load_outer_clock']=lambda *args:(_ for _ in ()).throw(error)
        original=pathlib.Path.lstat
        def lstat(path,*a,**kw):
            value=original(path,*a,**kw)
            return types.SimpleNamespace(st_mode=value.st_mode,st_uid=65532,st_gid=65532) if path==self.out else value
        with patch.object(pathlib.Path,'lstat',lstat),self.assertRaises(ValueError) as caught:self.ns['accounting_producer'](self.out,'memory',900)
        self.assertIs(caught.exception,error);self.assertFalse((self.out/'accounting-failure.json').exists())
        self.assertEqual(caught.exception.__notes__,['accounting failure diagnostic unavailable'])


class ShellRefusal(unittest.TestCase):
    def test_invalid_input_refusal_is_literal_stderr_before_any_output_write(self):
        result=subprocess.run(['/bin/bash',str(SOURCE.parent.parent/'observe-resource.sh'),'PRIVATE_RELATIVE_INPUT','/PRIVATE_OUTPUT_MUST_NOT_BE_USED'],capture_output=True,timeout=2)
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr,b'F01_OBSERVER_INPUT_REFUSED\n')

    def test_protected_output_refusal_is_literal_and_keeps_same_predicate(self):
        guard=next(line for line in (SOURCE.parent.parent/'observe-resource.sh').read_text().splitlines() if line.startswith('[[ $OUT != "$WORKTREE"'))
        for out,code,stderr in [('/fixed','2',b'F01_OBSERVER_OUTPUT_REFUSED\n'),('/fixed/PRIVATE_SUBDIR','2',b'F01_OBSERVER_OUTPUT_REFUSED\n'),('/outside','0',b'')]:
            result=subprocess.run(['/bin/bash','-c','OUT=$1; WORKTREE=$2; '+guard,'--',out,'/fixed'],capture_output=True,timeout=2)
            self.assertEqual(result.returncode,int(code));self.assertEqual(result.stderr,stderr);self.assertEqual(result.stdout,b'')

if __name__=='__main__':unittest.main()
