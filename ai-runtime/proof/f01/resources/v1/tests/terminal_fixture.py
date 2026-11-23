"""Test-only copied pipe fixture with independently ordered terminal/log publication.

No production source mutation and no process execution: Popen is replaced by real
local pipe endpoints. The old marker vocabulary is synthetic test input only.
"""
import json
import os
import types
from unittest.mock import patch
import bootstrap as bootstrap
import test_accounting_producer as prior_producer


class TerminalFixture(prior_producer.ProducerInputs):
    def protocol(self,fault='terminal-first'):
        self.now=100.5;signals=[];violations=[];terminal_state={'done':False};self.late_ops=[];scheduled=[(100.75,[
            'NAME init busybox '+('a2ci' if 'cpu' in self.f['target']['name'] else 'a2mi')+' 2 200','INTENT 1 3',
            'NAME worker busybox '+('a2cw' if 'cpu' in self.f['target']['name'] else 'a2mw')+' 3 201','FD_OK readonly0 closed3 closed4','STAT READY 3 201 100 0',
            'READY init=2 start=200 worker=3 workerStart=201'])]
        children=[];deadline=104. if fault=='deadline' else 130.
        self.ns['load_outer_clock']=lambda path,target:({'deadlineMonotonic':deadline},lambda:None)
        fence=self.continuation_inputs()
        def proc(pid):
            if terminal_state['done']:
                self.late_ops.append('proc');raise AssertionError('post-terminal host proc read')
            return self.fence_sentry if pid==10 else {'startTicks':9000}
        self.ns['proc']=proc
        self.ns['accounting_owner']=lambda out,target:(None,self.f['ownership'],self.fence_sentry)
        def verify(out,target,owner,observer,start,n,end):
            if terminal_state['done']:
                self.late_ops.append('verify');raise AssertionError('post-terminal ownership/runtime query')
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
        def tick():
            self.now+=.25;obs=self.out/'observation'
            if not terminal_state['done']:
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
            if len(signals)==3 and self.now>=signals[2]+3.75 and not terminal_state['done']:
                actual=signals[2]+3.75
                terminal={'status':'CONFIRMED_TERMINAL','cid':self.f['target']['cid'],'uid':self.f['target']['uid'],'exitCode':0,'monotonic':actual}
                (obs/'terminal.json').write_text(json.dumps(terminal))
                (obs/'observer-result.json').write_text(json.dumps({'status':'CONTINUOUS_COLLECTION_FINISHED','lastSample':12,
                    'counterReadStart':112.25,'counterReadEnd':112.5,'terminal':terminal,'finishedMonotonic':actual,'deadlineMonotonic':deadline}))
                if fault not in ('exit-receipt-lag','missing-exit','malformed-final','wrong-owner-final','terminal-removed'):
                    (obs/'observer-exit.json').write_text(json.dumps({'exitCode':0,'finishedMonotonic':actual}))
                terminal_state['done']=True;self.actual_terminal=actual
            if terminal_state['done'] and len(signals)==3 and self.now>=signals[2]+4.:
                if fault in ('exit-receipt-lag','malformed-final','wrong-owner-final'):
                    (obs/'observer-exit.json').write_text(json.dumps({'exitCode':0,'finishedMonotonic':self.now}))
                    if fault=='malformed-final':(obs/'terminal.json').write_text('{')
                    if fault=='wrong-owner-final':
                        bad=json.loads((obs/'terminal.json').read_text());bad['cid']='c'*64
                        (obs/'terminal.json').write_text(json.dumps(bad))
                if fault=='terminal-removed' and (obs/'terminal.json').exists():(obs/'terminal.json').unlink()
            if len(signals)==3 and self.now>=signals[2]+4.25 and children[0].writer is not None and fault!='drain-deadline':
                for attr in ('writer','error_writer'):
                    os.close(getattr(children[0],attr));setattr(children[0],attr,None)
                children[0].returncode=0
            if fault=='terminal-lag' and len(signals)==3 and self.now>=signals[2]+4.75:
                (obs/'terminal.json').write_text(json.dumps({'status':'CONFIRMED_TERMINAL','cid':self.f['target']['cid'],'uid':self.f['target']['uid'],'exitCode':0,'monotonic':self.now}))
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
            if terminal_state['done']:
                self.late_ops.append('signal');raise AssertionError('post-terminal signal')
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
                scheduled.append((131. if fault=='drain-deadline' else self.now+4.,['HOLD_TIMEOUT rc=1 token=','HOLD_END init=2 start=200 user=100 sys=0']))
            return b''
        self.ns['accounting_call']=signal
        samples=self.ns['accounting_samples']
        def active_samples(*args,**kwargs):
            if terminal_state['done']:
                self.late_ops.append('samples');raise AssertionError('post-terminal counter/query bridge operation')
            return samples(*args,**kwargs)
        self.ns['accounting_samples']=active_samples
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

