"""Real pipe closure/error precedence, plus exact duration and status boundaries."""
import copy
import os
import types
import unittest
import test_accounting_producer as fixture


class Cleanup(fixture.ProducerInputs,unittest.TestCase):
    def test_reap_always_closes_both_pipes_and_preserves_primary(self):
        for operation in ('wait','kill'):
            with self.subTest(operation=operation):
                a,b=os.pipe();os.close(b);stdout=os.fdopen(a,'rb')
                a,b=os.pipe();os.close(b);stderr=os.fdopen(a,'rb')
                failure=TimeoutError('synthetic client '+operation)
                def fail(*args,**kwargs):raise failure
                child=types.SimpleNamespace(stdout=stdout,stderr=stderr,poll=lambda:None,
                    kill=fail if operation=='kill' else lambda:None,wait=fail)
                primary=AssertionError('primary protocol error')
                self.ns['accounting_reap'](child,primary)
                self.assertTrue(stdout.closed and stderr.closed)
                self.assertEqual(primary.args,('primary protocol error',))
                self.assertTrue(any('cleanup failed' in note for note in primary.__notes__))
                with self.assertRaises(TimeoutError) as caught:self.ns['accounting_reap'](child)
                self.assertIs(caught.exception,failure)

    def test_wait_failure_still_closes_actual_pipe_handles(self):
        a,b=os.pipe();os.close(b);stdout=os.fdopen(a,'rb')
        a,b=os.pipe();os.close(b);stderr=os.fdopen(a,'rb')
        def fail(**kwargs):raise TimeoutError('synthetic wait timeout')
        child=types.SimpleNamespace(stdout=stdout,stderr=stderr,poll=lambda:0,wait=fail)
        try:
            with self.assertRaises(TimeoutError):self.ns['accounting_reap'](child)
            self.assertTrue(stdout.closed and stderr.closed,'client wait failure leaked pipe handles')
        finally:stdout.close();stderr.close()

    def test_duration_is_positive_integer_nanoseconds_and_never_rounds_budget_up(self):
        self.now=0.
        self.assertEqual(self.ns['accounting_log_timeout'](.000000001),'1ns')
        self.assertEqual(self.ns['accounting_log_timeout'](1.5),'1500000000ns')
        for remaining in (0.,.0000000001,31.):
            with self.subTest(remaining=remaining),self.assertRaises(AssertionError):self.ns['accounting_log_timeout'](remaining)


class Status(fixture.ProducerInputs,unittest.TestCase):
    inputs=fixture.SignalOwnership.inputs
    # Reuse fixed owned-API fixtures, select only this new method when invoking this module.
    def test_status_count_name_state_and_typed_restart_are_fail_closed(self):
        for fault in ('count','name','state','bool'):
            with self.subTest(fault=fault):
                self.setUp();target,owner,mapping,responses=self.inputs()
                statuses=responses[0]['status']['containerStatuses']
                if fault=='count':statuses.append(copy.deepcopy(statuses[0]))
                if fault=='name':statuses[0]['name']='other'
                if fault=='state':statuses[0]['state']={'terminated':{}}
                if fault=='bool':statuses[0]['restartCount']=False
                with self.assertRaises(AssertionError):self.ns['accounting_verify'](self.out,target,owner,900,9000,1,130.)
                self.assertFalse(any(kind=='capture' for kind,_ in self.calls))




class NaturalReceipts(fixture.ProducerInputs,unittest.TestCase):
    def receipts(self):
        terminal={'status':'CONFIRMED_TERMINAL','cid':self.f['target']['cid'],'uid':self.f['target']['uid'],'exitCode':0,'monotonic':113.0}
        natural={'status':'CONTINUOUS_COLLECTION_FINISHED','deadlineMonotonic':130.,'lastSample':12,
                 'counterReadStart':112.25,'counterReadEnd':112.5,'terminal':terminal,'finishedMonotonic':113.25}
        return terminal,natural,{'exitCode':0,'finishedMonotonic':113.25}

    def test_only_complete_consistent_exact_owned_natural_receipts_can_enable_drain(self):
        import json
        obs=self.out/'observation'
        self.assertIsNone(self.ns['accounting_terminal'](self.out,self.f['target'],130.))
        for fault in ('valid','exit-bool','cid','deadline','sample-bool','last-read','future-exit'):
            with self.subTest(fault=fault):
                terminal,natural,exited=self.receipts()
                if fault=='exit-bool':exited['exitCode']=False
                if fault=='cid':terminal['cid']='c'*64
                if fault=='deadline':natural['deadlineMonotonic']=131.
                if fault=='sample-bool':natural['lastSample']=True
                if fault=='last-read':natural['counterReadEnd']=113.1
                if fault=='future-exit':exited['finishedMonotonic']=114.
                for name,value in zip(('terminal.json','observer-result.json','observer-exit.json'),(terminal,natural,exited)):
                    (obs/name).write_text(json.dumps(value))
                if fault=='valid':self.assertEqual(self.ns['accounting_terminal'](self.out,self.f['target'],130.),terminal)
                else:
                    with self.assertRaises(AssertionError):self.ns['accounting_terminal'](self.out,self.f['target'],130.)

if __name__=='__main__':unittest.main()
