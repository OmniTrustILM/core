"""Actual producer/finalizer continuation boundaries with public synthetic inputs."""
import copy,json,unittest
import bootstrap as bootstrap
import test_accounting_producer as producer

class DispatchReached(Exception):
    pass

class ContinuationFences(producer.ProducerInputs,unittest.TestCase):
    def attempt(self,fault):
        subject=self;proc_calls=[];self.continuation_proc_calls=proc_calls;pending=[];self.pending_reads=pending;self.gated=False;self.mutated=False;self.postmutation_proc=[];self.postmutation_reads=[];samples=self.ns['accounting_samples'];bytes_read=self.ns['accounting_bytes'];held={}
        def actual_samples(*args,**kwargs):
            if subject.mutated:subject.postmutation_reads.append(subject.now)
            value=samples(*args,**kwargs)
            if value is None and subject.gated:
                pending.append(subject.now)
                if fault.startswith('pending-'):
                    subject.mutated=True
                    if fault=='pending-terminal':(subject.out/'observation/terminal.json').write_text('{}')
                    if fault=='pending-binary':(subject.out/'continuation-gofer').write_bytes(b'changed')
            return value
        self.ns['accounting_samples']=actual_samples
        class Calls(list):
            def append(c,item):
                super().append(item)
                if item==('verify',1):
                    subject.gated=True
                    proc=subject.ns['proc']
                    def checked_proc(pid):
                        proc_calls.append(pid)
                        if subject.mutated:subject.postmutation_proc.append(pid)
                        if fault=='terminal' or (fault=='pending-terminal' and subject.mutated):raise AssertionError('forbidden postterminal proc')
                        record=copy.deepcopy(proc(pid))
                        if (fault=='observer' or (fault=='pending-observer' and subject.mutated)) and pid==900:record['startTicks']+=1
                        if fault=='raw-sentry' and pid==10:record['comm']='other'
                        return record
                    subject.ns['proc']=checked_proc
                    if fault=='terminal':(subject.out/'observation/terminal.json').write_text('{}')
                    if fault=='exit':(subject.out/'observation/observer-exit.json').write_text('{}')
                    if fault=='watchdog':(subject.out/'outer-stop.json').write_text('{}')
                    if fault=='deadline':subject.now=130.
                    if fault=='mapping-owner':
                        owner=copy.deepcopy(subject.f['ownership']);owner['sentryStartTicks']+=1
                        subject.ns['accounting_owner']=lambda *args:(None,owner,subject.fence_sentry)
                    if fault=='mapping-sentry':subject.fence_sentry['comm']='other'
                    if fault=='root':subject.ns['sentry_root']=lambda *args:'/different/root'
                    if fault=='init-only':
                        obs=subject.out/'observation';queries=subject.query_rows()[:3]
                        queries[-1]['rootProjection']=queries[-1]['rootProjection'][:1]
                        queries[-1]['pids']=queries[-1]['pids'][:1]
                        from domain_fixtures import table
                        queries[-1]['rawResponse']=table(queries[-1]['rootProjection'])
                        (obs/'guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in queries))
                    if fault=='window':
                        obs=subject.out/'observation'
                        (obs/'counters.jsonl').write_bytes(b''.join((json.dumps(row)+'\n').encode() for row in subject.rows[:2]))
                        (obs/'guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in subject.query_rows()[:2]))
                    if fault=='binary':(subject.out/'continuation-gofer').write_bytes(b'changed')
                    if fault.startswith('pending-'):
                        subject.now=104.25
                        (subject.out/'observation/guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in subject.query_rows()[:4]))
                    if fault=='persistent':
                        subject.now=104.25;obs=subject.out/'observation'
                        held['counters.jsonl']=(obs/'counters.jsonl').read_bytes()
                        held['guest-pids.jsonl']=''.join(json.dumps(q)+'\n' for q in subject.query_rows()[:4]).encode()
                        subject.ns['accounting_bytes']=lambda path,limit:held[path.name] if path.name in held else bytes_read(path,limit)
                if item[0]=='signal':raise DispatchReached('deliberate first dispatch cutoff')
        self.calls=Calls()
        producer.Protocol.protocol(self)
        return proc_calls,pending

    def test_after_gate_fresh_cheap_fences_reject_each_identity_or_lifecycle_drift(self):
        for fault in ('terminal','exit','watchdog','observer','mapping-owner','mapping-sentry','raw-sentry','root','binary','window','init-only'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(AssertionError):
                    calls,_=self.attempt(fault)
                self.assertEqual(self.calls.count(('verify',1)),1)
                self.assertFalse(any(item[0]=='signal' for item in self.calls))
                if fault in ('terminal','exit'):self.assertEqual(self.continuation_proc_calls,[])

    def test_fresh_postgate_init_only_pair_rejects_at_population_guard_before_signal(self):
        with self.assertRaisesRegex(AssertionError,'init-only query before release signal'):
            self.attempt('init-only')
        self.assertEqual(self.calls.count(('verify',1)),1)
        self.assertFalse(any(item[0]=='signal' for item in self.calls))

    def test_persistent_pending_expires_at_original_deadline_without_regating_or_dispatch(self):
        with self.assertRaises(AssertionError):self.attempt('persistent')
        self.assertGreaterEqual(self.now,130.,'failed before exercising original pending deadline')
        self.assertEqual(self.calls.count(('verify',1)),1)
        self.assertFalse(any(item[0]=='signal' for item in self.calls))
        self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')

    def test_mutation_after_actual_pending_is_fenced_before_another_pair_read(self):
        for fault in ('pending-terminal','pending-observer','pending-binary'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(AssertionError):self.attempt(fault)
                self.assertEqual(len(self.pending_reads),1)
                self.assertEqual(self.postmutation_reads,[])
                if fault=='pending-terminal':self.assertEqual(self.postmutation_proc,[])
                self.assertEqual(self.calls.count(('verify',1)),1)
                self.assertFalse(any(item[0]=='signal' for item in self.calls))

    def test_expired_postgate_clock_cannot_dispatch(self):
        with self.assertRaises(AssertionError):self.attempt('deadline')
        self.assertEqual(self.calls.count(('verify',1)),1)
        self.assertFalse(any(item[0]=='signal' for item in self.calls))

class FinishBinding(producer.ProducerInputs,unittest.TestCase):
    inputs=producer.SignalOwnership.inputs
    def prepare(self):
        target,_,_,_=self.inputs();self.now=113.75
        self.ns['load_outer_clock']=lambda *args:({'deadlineMonotonic':130.},lambda:None)
        context=self.context()
        terminal={'status':'CONFIRMED_TERMINAL','cid':target['cid'],'uid':target['uid'],'exitCode':0,'monotonic':context['normalExit']['receivedMonotonic']}
        natural={'status':'CONTINUOUS_COLLECTION_FINISHED','deadlineMonotonic':130.,'lastSample':12,'counterReadStart':112.25,'counterReadEnd':112.5,'finishedMonotonic':113.3,'terminal':terminal}
        receipt={'status':'COMPLETE','drainOnly':True,'rawReadObservations':[],'signalStarts':context['signalStarts'],'finishedMonotonic':113.375}
        for name,value in [('targets.json',target),('accounting-protocol.json',context),('observer-wait.json',{'exitCode':0,'receivedMonotonic':113.5}),('observation/observer-result.json',natural),('accounting-log.result.json',receipt)]:
            (self.out/name).write_text(json.dumps(value))
        (self.out/'observation/counters.jsonl').write_bytes(self.raw())
        (self.out/'observation/guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in self.query_rows()))
        return natural,receipt

    def test_finish_evaluates_exact_same_counter_buffer_that_bound_facts(self):
        self.prepare();original=self.raw();different=copy.deepcopy(self.rows)
        different[0]['groups'][self.f['aggregate']]['memory.current']=['17']
        second=b''.join((json.dumps(row)+'\n').encode() for row in different)
        reads=[];evaluated=[];reader=self.ns['accounting_bytes'];evaluate=self.ns['evaluate_memory']
        def read(path,limit):
            if path.name=='counters.jsonl':reads.append(path);return original if len(reads)==1 else second
            return reader(path,limit)
        def record(raw,facts):evaluated.append(raw);return evaluate(original,facts)
        self.ns['accounting_bytes']=read;self.ns['evaluate_memory']=record
        self.ns['accounting_finish'](self.out,'memory')
        self.assertEqual(evaluated,[original]);self.assertEqual(len(reads),1)

    def test_saved_terminal_and_complete_receipt_must_correlate_with_context_and_actual_wait(self):
        for fault in ('terminal-clock','terminal-cid','terminal-uid','terminal-exit','log-missing','log-stop','log-signals','log-early','log-late','log-bool-finish'):
            with self.subTest(fault=fault):
                self.setUp();natural,receipt=self.prepare()
                if fault=='terminal-clock':natural['terminal']['monotonic']-=.1
                if fault=='terminal-cid':natural['terminal']['cid']='c'*64
                if fault=='terminal-uid':natural['terminal']['uid']='different'
                if fault=='terminal-exit':natural['terminal']['exitCode']=1
                if fault=='log-stop':receipt['status']='STOP'
                if fault=='log-signals':receipt['signalStarts']=receipt['signalStarts'][:2]
                if fault=='log-early':receipt['finishedMonotonic']=112.
                if fault=='log-late':receipt['finishedMonotonic']=113.625
                if fault=='log-bool-finish':receipt['finishedMonotonic']=True
                (self.out/'observation/observer-result.json').write_text(json.dumps(natural))
                (self.out/'accounting-log.result.json').write_text(json.dumps(receipt))
                if fault=='log-missing':(self.out/'accounting-log.result.json').unlink()
                with self.assertRaises((AssertionError,FileNotFoundError)):
                    self.ns['accounting_finish'](self.out,'memory')
                self.assertFalse((self.out/'control-observation.json').exists())

    def test_finish_nonobserved_result_still_fails_after_saving_conditional_result(self):
        for status in ('UNPROVEN','STOP'):
            with self.subTest(status=status):
                self.setUp();self.prepare()
                self.ns['evaluate_memory']=lambda *args:{'status':status,'reason':'synthetic nonobserved'}
                with self.assertRaisesRegex(AssertionError,'accounting '+status):self.ns['accounting_finish'](self.out,'memory')
                self.assertEqual(json.loads((self.out/'control-observation.json').read_text())['status'],status)

    def test_stop_receipt_vetoes_already_published_protocol_before_evaluation(self):
        _,receipt=self.prepare();receipt['status']='STOP'
        (self.out/'accounting-log.result.json').write_text(json.dumps(receipt))
        self.assertTrue((self.out/'accounting-protocol.json').exists())
        evaluated=[]
        self.ns['evaluate_memory']=lambda *args:evaluated.append(args)
        with self.assertRaisesRegex(AssertionError,'^accounting log completion receipt$'):
            self.ns['accounting_finish'](self.out,'memory')
        self.assertEqual(evaluated,[])
        self.assertFalse((self.out/'control-observation.json').exists())
        self.assertFalse((self.out/'accounting-facts.json').exists())

if __name__=='__main__':unittest.main()
