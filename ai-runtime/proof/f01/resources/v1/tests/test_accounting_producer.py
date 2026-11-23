"""Public synthetic protocol evidence; no runtime client is executed."""
import copy
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch
from test_observer_ownership import CODE, EXTRACTED
from domain_fixtures import roles, table


class ProducerInputs:
    def setUp(self):
        self.ns={'__name__':'test'};exec(compile(CODE,str(EXTRACTED),'exec'),self.ns)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.out=pathlib.Path(self.tmp.name);(self.out/'observation').mkdir()
        self.fixture=json.loads((pathlib.Path(__file__).parent/'testdata/accounting/memory.json').read_text())
        self.f=self.fixture['facts'];self.rows=self.fixture['rows'];self.calls=[]
        self.now=113.5;self.ns['time']=types.SimpleNamespace(monotonic=lambda:self.now)

    def continuation_inputs(self):
        self.fence_sentry={'pid':10,'tgid':10,'ppid':1,'startTicks':100,'comm':'runsc-sandbox','exe':'/synthetic/sentry','exeIdentity':[1,2],'argv0':'runsc-sandbox','cgroup':'/synthetic/pod'}
        measurements={};definitions={}
        for role in ('sentry','gofer','parking'):
            path=self.out/('continuation-'+role);path.write_bytes(role.encode())
            measurements[role]=self.ns['file_identity'](path)
            definitions[role]=(str(path),self.ns['hashlib'].sha256(path.read_bytes()).hexdigest())
        self.ns['BINARIES']=definitions;self.ns['canonical']=pathlib.Path
        self.ns['sentry_root']=lambda pid,sid:self.f['ownership']['root']
        return {'sentry':copy.deepcopy(self.fence_sentry),'binaries':measurements}

    def raw(self):return b''.join((json.dumps(r)+'\n').encode() for r in self.rows)

    def query_rows(self):
        result=[]
        for row in self.rows:
            control=self.f['target']['name'].split('-')[2]
            projection=roles(control) if row['sample']<9 else roles(control)[:1]
            result.append({'sample':row['sample'],'monotonic':row['monotonic'],'pids':[r['rootPID'] for r in projection],
              'counterReadStart':row['counterReadStart'],'counterReadEnd':row['counterReadEnd'],
              'queryStartedMonotonic':row['monotonic'],'queryReceivedMonotonic':row['counterReadStart'],
              'rawResponse':table(projection),'pidDomain':'sandbox-root','rootProjection':projection})
        return result


    def context(self):
        return {'target':self.f['target'],'ownership':self.f['ownership'],'aggregate':self.f['aggregate'],
          'init':self.f['init'],'worker':self.f['worker'],'markers':self.f['markers'],
          'signalStarts':self.f['signalStarts'],'normalExit':self.f['normalExit'],'rootRoles':self.f['rootRoles']}





class Producer(ProducerInputs,unittest.TestCase):
    def test_verified_rows_and_query_wire_must_have_complete_equal_closure(self):
        self.assertIn('accounting_samples',self.ns,'missing bounded producer bridge')
        obs=self.out/'observation';(obs/'counters.jsonl').write_bytes(self.raw())
        queries=self.query_rows();path=obs/'guest-pids.jsonl';path.write_text(''.join(json.dumps(q)+'\n' for q in queries))
        rows,bound,raw=self.ns['accounting_samples'](self.out,self.f['deadlineMonotonic'],'memory')
        self.assertEqual(rows,self.rows);self.assertEqual(bound,queries);self.assertEqual(raw,self.raw())
        path.write_text(''.join(json.dumps(q)+'\n' for q in queries[:-1]))
        self.assertIsNone(self.ns['accounting_samples'](self.out,130.,'memory'))
        with self.assertRaises(AssertionError):self.ns['accounting_samples'](self.out,130.,'memory',final=True)
        for mutate in ('partial','wrong-role','wrong-bracket','wrong-domain','extra'):
            q=copy.deepcopy(queries)
            if mutate=='wrong-role':q[-1]['rootProjection'][0]['rootPID']=777
            if mutate=='wrong-bracket':q[-1]['counterReadEnd']-=.1
            if mutate=='wrong-domain':q[-1]['pidDomain']='container-proc'
            if mutate=='extra':q.append(q[-1])
            raw=''.join(json.dumps(x)+'\n' for x in q)
            if mutate=='partial':raw=raw[:-1]
            path.write_text(raw)
            if mutate=='partial':
                self.assertIsNone(self.ns['accounting_samples'](self.out,130.,'memory'))
                with self.assertRaises(AssertionError):self.ns['accounting_samples'](self.out,130.,'memory',final=True)
            else:
                with self.subTest(mutate=mutate),self.assertRaises(AssertionError):self.ns['accounting_samples'](self.out,130.,'memory')

    def test_actual_wait_bound_facts_bridge_preserves_distinct_domains_and_numeric_result(self):
        self.assertIn('accounting_facts',self.ns,'missing actual-wait facts bridge')
        context=self.context();queries=self.query_rows()
        natural={'status':'CONTINUOUS_COLLECTION_FINISHED','lastSample':12,'counterReadStart':112.25,'counterReadEnd':112.5,'deadlineMonotonic':130.,'finishedMonotonic':113.3,'terminal':{'status':'CONFIRMED_TERMINAL','cid':context['target']['cid'],'uid':context['target']['uid'],'exitCode':0,'monotonic':context['normalExit']['receivedMonotonic']}}
        wait={'exitCode':0,'receivedMonotonic':113.5}
        facts=self.ns['accounting_facts'](self.rows,queries,context,natural,wait,130.)
        self.assertEqual(facts['init']['pid'],2);self.assertEqual(facts['rootRoles']['rootProjection'][0]['rootPID'],101)
        self.assertEqual(self.ns['evaluate_memory'](self.raw(),facts)['status'],'OBSERVED')
        for which in ('wait-error','wait-before-normal','last-mismatch','late','missing-root','wrong-projection','mixed-query-domain'):
            n=copy.deepcopy(natural);w=copy.deepcopy(wait);c=copy.deepcopy(context);qs=copy.deepcopy(queries)
            if which=='wait-error':w['exitCode']=1
            if which=='wait-before-normal':w['receivedMonotonic']=113.
            if which=='last-mismatch':n['lastSample']=11
            if which=='late':w['receivedMonotonic']=130.
            if which=='missing-root':c['rootRoles']=None
            if which=='wrong-projection':qs[-1]['rootProjection'][0]['rootPID']=999
            if which=='mixed-query-domain':qs[-1]['pidDomain']='container-proc'
            with self.subTest(which=which),self.assertRaises(AssertionError):self.ns['accounting_facts'](self.rows,qs,c,n,w,130.)

    def test_bounded_command_retains_bytes_and_times_out_without_retry(self):
        self.assertIn('accounting_call',self.ns,'missing bounded fixed command transport')
        attempts=[];children=[]
        class Child:
            def __init__(s,args,**kwargs):
                attempts.append(args);s.returncode=None;s.killed=0
                a,b=os.pipe();os.write(b,b'{"ok":true}\n');os.close(b);s.stdout=os.fdopen(a,'rb',buffering=0)
                a,b=os.pipe();os.close(b);s.stderr=os.fdopen(a,'rb',buffering=0);children.append(s)
            def poll(s):s.returncode=0;return 0
            def wait(s,timeout=None):s.returncode=0;return 0
            def kill(s):s.killed+=1
        with patch.object(self.ns['subprocess'],'Popen',Child):
            raw=self.ns['accounting_call'](self.out,'pre-pod',['k3s','kubectl'],130.)
        self.assertEqual(raw,b'{"ok":true}\n');self.assertEqual(len(attempts),1)
        self.assertEqual((self.out/'pre-pod.stdout').read_bytes(),raw)
        self.assertEqual(json.loads((self.out/'pre-pod.result.json').read_text())['exitCode'],0)
        self.assertEqual(children[0].killed,0)
        self.now=130.
        with patch.object(self.ns['subprocess'],'Popen',Child),self.assertRaises(AssertionError):self.ns['accounting_call'](self.out,'late',['k3s'],130.)
        self.assertEqual(len(attempts),1,'expired command was dispatched')


class Protocol(ProducerInputs,unittest.TestCase):
    """The shipped producer reads real pipes/files; only fixed external boundaries are fake."""
    def protocol(self,fault=''):
        self.now=100.5;signals=[];violations=[];scheduled=[(100.75,[
            'NAME init busybox '+('a2ci' if 'cpu' in self.f['target']['name'] else 'a2mi')+' 2 200','INTENT 1 3',
            'NAME worker busybox '+('a2cw' if 'cpu' in self.f['target']['name'] else 'a2mw')+' 3 201','FD_OK readonly0 closed3 closed4','STAT READY 3 201 100 0',
            'READY init=2 start=200 worker=3 workerStart=201'])]
        children=[];deadline=104. if fault=='deadline' else 130.
        self.ns['load_outer_clock']=lambda path,target:({'deadlineMonotonic':deadline},lambda:None)
        fence=self.continuation_inputs()
        self.ns['proc']=lambda pid:self.fence_sentry if pid==10 else {'startTicks':9000}
        self.ns['accounting_owner']=lambda out,target:(None,self.f['ownership'],self.fence_sentry)
        def verify(out,target,owner,observer,start,n,end):
            self.calls.append(('verify',n))
            if fault=='owner' and n==2:raise AssertionError('ownership changed')
            return fence
        self.ns['accounting_verify']=verify
        class Child:
            def __init__(s,args,**kwargs):
                self.calls.append(('Popen',args));s.returncode=None;s.killed=0
                if args[:2]!=['k3s','kubectl']:violations.append(args);raise AssertionError('unexpected client')
                a,s.writer=os.pipe();s.stdout=os.fdopen(a,'rb',buffering=0)
                a,s.error_writer=os.pipe();s.stderr=os.fdopen(a,'rb',buffering=0);children.append(s)
            def poll(s):return s.returncode
            def wait(s,timeout=None):
                if s.returncode is None:raise AssertionError('wait before client EOF')
                return s.returncode
            def kill(s):
                s.killed+=1;s.returncode=-9
                for attr in ('writer','error_writer'):
                    fd=getattr(s,attr)
                    if fd is not None:os.close(fd);setattr(s,attr,None)
        def publish_terminal(obs,actual):
            terminal={'status':'CONFIRMED_TERMINAL','cid':self.f['target']['cid'],'uid':self.f['target']['uid'],'exitCode':0,'monotonic':actual}
            (obs/'terminal.json').write_text(json.dumps(terminal))
            (obs/'observer-result.json').write_text(json.dumps({'status':'CONTINUOUS_COLLECTION_FINISHED','lastSample':12,
                'counterReadStart':112.25,'counterReadEnd':112.5,'terminal':terminal,'finishedMonotonic':self.now,'deadlineMonotonic':deadline}))
            (obs/'observer-exit.json').write_text(json.dumps({'exitCode':0,'finishedMonotonic':self.now}))
        def tick():
            self.now+=.25;obs=self.out/'observation'
            rows=[r for r in self.rows if r['counterReadEnd']<=self.now]
            (obs/'counters.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            queries=self.query_rows()[:len(rows)]
            (obs/'guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in queries))
            for at,messages in list(scheduled):
                if at<=self.now:
                    scheduled.remove((at,messages))
                    payload=''.join('2026-10-29T00:00:00Z '+m+'\n' for m in messages).encode()
                    if fault=='partial' and any(m.startswith('STAT NO_EFFECT') for m in messages):payload=payload[:-1]
                    os.write(children[0].writer,payload)
            if len(signals)==3 and self.now>=signals[2]+4.25 and children[0].writer is not None:
                if fault!='terminal-lag':publish_terminal(obs,self.now-10 if fault=='terminal-before-hold' else self.now)
                for attr in ('writer','error_writer'):
                    os.close(getattr(children[0],attr));setattr(children[0],attr,None)
                children[0].returncode=0
            if fault=='terminal-lag' and len(signals)==3 and self.now>=signals[2]+4.75:
                publish_terminal(obs,self.now)
        real_selector=self.ns['selectors'].DefaultSelector
        class Selector:
            def __init__(s):s.actual=real_selector()
            def register(s,*args):return s.actual.register(*args)
            def unregister(s,*args):return s.actual.unregister(*args)
            def get_map(s):return s.actual.get_map()
            def close(s):s.actual.close()
            def select(s,wait=None):
                if wait:tick()
                return s.actual.select(0)
        def signal(out,label,args,end):
            self.calls.append(('signal',args));n=len(signals)+1;signals.append(self.now)
            expected=['/usr/local/bin/runsc','--root=/run/synthetic','kill',self.f['target']['cid'],'USR1']
            if args!=expected or n>3:violations.append(args);raise AssertionError('forbidden signal')
            if fault=='unknown-signal':raise TimeoutError('unknown signal')
            if n<3:
                prefix='NO_EFFECT' if n==1 else 'EFFECT'
                before=100;after=100 if n==1 else 101
                scheduled.append((self.now+.75,[f'RAW_READ {n} 1 {n} EMPTY',f'RAW_READ {n} 0 {n} ACK_{n}',f'ACK {n} 3',f'INTENT {n+1} 3',f'STAT {prefix}_BEFORE 3 201 {before} 0',f'STAT {prefix}_AFTER 3 201 {after} 0','NO_EFFECT' if n==1 else 'EFFECT_HELD']))
            else:
                scheduled.append((self.now+.75,['RAW_READ 3 1 3 EMPTY','RAW_READ 3 0 3 ACK_3','ACK 3 3','WORKER_EXIT 0 3 201','WAIT_FINAL 0 3','INIT_FINAL 2 200 '+('a2ci' if 'cpu' in self.f['target']['name'] else 'a2mi'),'RELEASED init=2 start=200 user=100 sys=0']))
                scheduled.append((self.now+4.,['HOLD_TIMEOUT rc=1 token=','HOLD_END init=2 start=200 user=100 sys=0']))
            return b''
        self.ns['accounting_call']=signal
        if fault=='journal':
            original_save=self.ns['atomic_json']
            def save(path,value):
                if path.name=='accounting-protocol.json':raise OSError('protocol journal failed')
                return original_save(path,value)
            self.ns['atomic_json']=save
        self.out.joinpath('targets.json').write_text(json.dumps(self.f['target']))
        (self.out/'observation/counter-origins.json').write_text(json.dumps({'aggregate':self.f['aggregate']}))
        with patch.object(self.ns['subprocess'],'Popen',Child),patch.dict(self.ns,selectors=types.SimpleNamespace(DefaultSelector=Selector,EVENT_READ=1)):
            try:self.ns['accounting_producer'](self.out,self.f['target']['name'].split('-')[2],900)
            finally:
                self.assertEqual(violations,[])
                self.assertEqual(len(children),1)
                self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
                self.signals=signals;self.child=children[0]

    def test_real_protocol_producer_collects_once_three_signals_and_binds_complete_facts(self):
        self.assertIn('accounting_producer',self.ns)
        self.protocol();context=json.loads((self.out/'accounting-protocol.json').read_text())
        self.assertEqual(context['signalStarts'],[102.75,105.75,108.75]);self.assertEqual(self.child.killed,0)
        self.assertEqual(len([x for x in self.calls if x[0]=='Popen']),1)
        rows,queries,_=self.ns['accounting_samples'](self.out,130.,'memory',final=True)
        self.now=113.75
        natural=json.loads((self.out/'observation/observer-result.json').read_text())
        facts=self.ns['accounting_facts'](rows,queries,context,natural,{'exitCode':0,'receivedMonotonic':113.75},130.)
        self.assertEqual(self.ns['evaluate_memory'](self.raw(),facts)['status'],'OBSERVED')

    def test_unknown_signal_owner_partial_and_deadline_stop_without_second_attempt(self):
        for fault,count in [('unknown-signal',1),('owner',1),('partial',1),('deadline',1)]:
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises((AssertionError,TimeoutError)):self.protocol(fault)
                self.assertEqual(len(self.signals),count)
                self.assertEqual(self.child.killed,1)
                self.assertFalse((self.out/'accounting-protocol.json').exists())
                self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')

    def test_actual_terminal_timestamp_cannot_be_replaced_by_later_file_receipt(self):
        with self.assertRaisesRegex(AssertionError,'terminal receipt'):
            self.protocol('terminal-before-hold')
        self.assertEqual(len(self.signals),3)
        self.assertFalse((self.out/'accounting-protocol.json').exists())

    def test_log_eof_waits_only_for_existing_observer_terminal_receipt_under_original_deadline(self):
        self.protocol('terminal-lag')
        self.assertEqual(len(self.signals),3);self.assertEqual(self.child.killed,0)
        self.assertLess(self.now,130.)
        self.assertTrue((self.out/'accounting-protocol.json').exists())

    def test_final_protocol_journal_failure_cannot_claim_complete(self):
        with self.assertRaises(OSError):self.protocol('journal')
        self.assertFalse((self.out/'accounting-protocol.json').exists())
        self.assertEqual(json.loads((self.out/'accounting-log.result.json').read_text())['status'],'STOP')

    def test_cpu_protocol_binds_actual_cpu_roles_and_uses_unchanged_cpu_evaluator(self):
        self.fixture=json.loads((pathlib.Path(__file__).parent/'testdata/accounting/cpu.json').read_text())
        self.f=self.fixture['facts'];self.rows=self.fixture['rows']
        self.protocol();context=json.loads((self.out/'accounting-protocol.json').read_text())
        rows,queries,_=self.ns['accounting_samples'](self.out,130.,'cpu',final=True)
        self.now=113.75
        natural=json.loads((self.out/'observation/observer-result.json').read_text())
        facts=self.ns['accounting_facts'](rows,queries,context,natural,{'exitCode':0,'receivedMonotonic':113.75},130.)
        self.assertEqual(facts['rootRoles']['rootProjection'][0]['CMD'],'a2ci')
        self.assertEqual(self.ns['evaluate_cpu'](self.raw(),facts)['status'],'OBSERVED')

class SignalOwnership(ProducerInputs,unittest.TestCase):
    def inputs(self):
        target=self.f['target'];owner=self.f['ownership'];attached=target|{'sentry':10,'root':'/run/synthetic'}
        sentry={'pid':10,'startTicks':100,'exeIdentity':[1,2]}
        binaries={};definitions={}
        for role in ('sentry','gofer','parking'):
            p=self.out/(role+'.binary');p.write_bytes(role.encode());identity=self.ns['file_identity'](p)
            binaries[role]=list(identity[:2]);definitions[role]=(str(p),self.ns['hashlib'].sha256(p.read_bytes()).hexdigest())
        sentry['exeIdentity']=binaries['sentry']
        mapping={'target':attached,'runtimeType':owner['runtimeType'],'podCgroup':'/synthetic/pod','binaries':binaries,
            'runtimeSeeds':[{'container':target['cid']},{'container':target['sid']}],
            'candidates':[], 'observations':[{'snapshot':{'records':{'10':sentry},'roles':{'10':'sentry'}}}]}
        (self.out/'observation/mapping.json').write_text(json.dumps(mapping))
        self.ns['canonical']=pathlib.Path;self.ns['BINARIES']=definitions
        self.ns['proc']=lambda pid:sentry if pid==10 else {'startTicks':9000}
        self.ns['sentry_root']=lambda pid,sid:owner['root']
        self.ns['runtime_seeds']=lambda t:({10:'sentry'},mapping['runtimeSeeds'])
        def capture(*args):
            self.calls.append(('capture',args[:2]))
            return {'groups':{},'records':{10:sentry},'threads':{},'children':{},'roles':{10:'sentry'}}
        self.ns['capture']=capture
        pod={'metadata':{'uid':target['uid'],'name':target['name'],'namespace':'ilm-sandbox-a2','labels':{'ilm.ai/proof':'a2-v1'}},
             'spec':{'runtimeClassName':'runsc-f01-a2-v1'},'status':{'startTime':target['startTime'],'phase':'Running','containerStatuses':[{'containerID':'containerd://'+target['cid'],'restartCount':0,'name':'fixed-proof','state':{'running':{}}}]}}
        container={'status':{'id':target['cid'],'metadata':{'name':'fixed-proof'},'state':'CONTAINER_RUNNING',
            'labels':{'io.kubernetes.pod.'+key:value for key,value in [('uid',target['uid']),('name',target['name']),('namespace','ilm-sandbox-a2')]}},'info':{'runtimeType':owner['runtimeType']}}
        sandbox={'status':{'id':target['sid'],'metadata':{'name':target['name'],'uid':target['uid'],'namespace':'ilm-sandbox-a2','attempt':0},'runtimeHandler':'runsc-f01-a2-v1'}}
        responses=[pod,container,sandbox]
        def call(out,label,args,deadline):
            self.calls.append(('request',args));return json.dumps(responses.pop(0)).encode()
        self.ns['accounting_call']=call
        return target,owner,mapping,responses

    def test_real_owned_tuple_binary_and_closed_capture_fence_before_signal(self):
        target,owner,mapping,responses=self.inputs()
        self.ns['accounting_verify'](self.out,target,owner,900,9000,1,130.)
        self.assertEqual(responses,[]);self.assertEqual(len(self.calls),4)
        self.assertEqual(self.calls[-1][0],'capture')
        self.assertFalse(any('kill' in args for kind,args in self.calls if kind=='request'))
        self.assertEqual(self.ns['accounting_owner'](self.out,target)[1],owner)

    def test_actual_owner_gate_rejects_wrong_pod_cri_sandbox_binary_host_observer_and_watchdog(self):
        for fault in ('pod','container','sandbox','binary','observer','watchdog','unverified','target'):
            with self.subTest(fault=fault):
                self.setUp();target,owner,mapping,responses=self.inputs()
                if fault=='pod':responses[0]['metadata']['uid']='different'
                if fault=='container':responses[1]['info']['runtimeType']='runc'
                if fault=='sandbox':responses[2]['status']['metadata']['uid']='different'
                if fault=='binary':(self.out/'gofer.binary').write_bytes(b'changed')
                if fault=='observer':self.ns['proc']=lambda pid:{'startTicks':9001}
                if fault=='watchdog':(self.out/'outer-stop.json').write_text('{}')
                if fault=='unverified':mapping['observations']=[]
                if fault=='target':mapping['target']['cid']='c'*64
                (self.out/'observation/mapping.json').write_text(json.dumps(mapping))
                with self.assertRaises((AssertionError,KeyError)):self.ns['accounting_verify'](self.out,target,owner,900,9000,1,130.)
                self.assertFalse(any(kind=='capture' for kind,_ in self.calls))

    def test_finalizer_actual_source_bridge_writes_only_conditional_observed(self):
        target,owner,mapping,_=self.inputs()
        self.ns['load_outer_clock']=lambda path,target:({'deadlineMonotonic':130.},lambda:None)
        for path,value in [('targets.json',target),('accounting-protocol.json',self.context()),
            ('observer-wait.json',{'exitCode':0,'receivedMonotonic':113.5}),
            ('observation/observer-result.json',{'status':'CONTINUOUS_COLLECTION_FINISHED','deadlineMonotonic':130.,'lastSample':12,'counterReadStart':112.25,'counterReadEnd':112.5,'finishedMonotonic':113.3,'terminal':{'status':'CONFIRMED_TERMINAL','cid':target['cid'],'uid':target['uid'],'exitCode':0,'monotonic':self.f['normalExit']['receivedMonotonic']}}),
            ('accounting-log.result.json',{'status':'COMPLETE','drainOnly':True,'rawReadObservations':[],'signalStarts':self.f['signalStarts'],'finishedMonotonic':113.4})]:
            (self.out/path).write_text(json.dumps(value))
        (self.out/'observation/counters.jsonl').write_bytes(self.raw())
        (self.out/'observation/guest-pids.jsonl').write_text(''.join(json.dumps(q)+'\n' for q in self.query_rows()))
        self.ns['accounting_finish'](self.out,'memory')
        self.assertEqual(json.loads((self.out/'control-observation.json').read_text())['status'],'OBSERVED')
        self.assertEqual(json.loads((self.out/'accounting-facts.json').read_text())['init']['pid'],2)
        (self.out/'outer-stop.json').write_text('{}')
        with self.assertRaises(AssertionError):self.ns['accounting_finish'](self.out,'memory')



class TransportFaults(ProducerInputs,unittest.TestCase):
    def attempt(self,fault):
        attempts=[];children=[];self.now=100.
        class Child:
            def __init__(s,args,**kwargs):
                attempts.append(args);s.returncode=None;s.killed=0;s.sent=0
                a,s.writer=os.pipe();s.stdout=os.fdopen(a,'rb',buffering=0)
                a,s.error_writer=os.pipe();s.stderr=os.fdopen(a,'rb',buffering=0);children.append(s)
                if fault in ('nonzero','stderr'):
                    if fault=='stderr':os.write(s.error_writer,b'warning\n')
                    s.close_writers();s.returncode=1 if fault=='nonzero' else 0
            def close_writers(s):
                for attr in ('writer','error_writer'):
                    fd=getattr(s,attr)
                    if fd is not None:os.close(fd);setattr(s,attr,None)
            def poll(s):return s.returncode
            def wait(s,timeout=None):return s.returncode
            def kill(s):s.killed+=1;s.returncode=-9;s.close_writers()
        real_selector=self.ns['selectors'].DefaultSelector
        class Selector:
            def __init__(s):s.actual=real_selector()
            def register(s,*args):return s.actual.register(*args)
            def unregister(s,*args):return s.actual.unregister(*args)
            def get_map(s):return s.actual.get_map()
            def close(s):s.actual.close()
            def select(s,wait=None):
                self.now+=.01 if fault=='overflow' else .5
                if fault=='overflow' and children[0].writer is not None:os.write(children[0].writer,b'x'*4096)
                return s.actual.select(0)
        with patch.object(self.ns['subprocess'],'Popen',Child),patch.dict(self.ns,selectors=types.SimpleNamespace(DefaultSelector=Selector,EVENT_READ=1)):
            with self.assertRaises(AssertionError):self.ns['accounting_call'](self.out,'fault',['fixed-client'],130.)
        self.assertEqual(len(attempts),1)
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        self.assertLessEqual(sum((self.out/('fault.'+x)).stat().st_size for x in ('stdout','stderr')),65536)
        self.assertEqual(children[0].killed,0 if fault in ('nonzero','stderr') else 1)
        return json.loads((self.out/'fault.result.json').read_text())

    def test_timeout_overflow_nonzero_and_stderr_are_never_success_or_retry(self):
        for fault in ('timeout','overflow','nonzero','stderr'):
            with self.subTest(fault=fault):
                self.setUp();result=self.attempt(fault)
                self.assertEqual(result['status'],'RETURNED' if fault in ('nonzero','stderr') else 'UNKNOWN')

    def test_intent_failure_never_dispatches_client(self):
        self.ns['atomic_json']=lambda *args:(_ for _ in ()).throw(OSError('intent unavailable'))
        with patch.object(self.ns['subprocess'],'Popen',side_effect=AssertionError('must not dispatch')) as create:
            with self.assertRaises(OSError):self.ns['accounting_call'](self.out,'intent',['fixed-client'],130.)
        create.assert_not_called()

if __name__=='__main__':unittest.main()
