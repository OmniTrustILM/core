"""Material B composition oracles; synthetic facts never grant native/security credit."""
import copy
import os
import datetime
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

BASE=Path(__file__).parents[1]/'python'
def load(name):
 spec=importlib.util.spec_from_file_location('b_composition_'+name,BASE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
collect=load('kernel_collect');kernel=load('kernel_observer');protocol=load('kernel_protocol')
P=BASE
def retained(name,digest):
 path=(Path(__file__).parents[2]/'v1/python/observer.py') if name=='primitives.py' else P/name;raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=digest:raise AssertionError('PINNED_TEST_SOURCE_MISMATCH')
 ns={'__name__':'b_pinned_'+name};exec(compile(raw,str(path),'exec'),ns);return ns
OPS=retained('primitives.py',collect.PRIMITIVES_SHA);OUTCOMES=retained('high_outcomes.py',collect.OUTCOMES_SHA)


def table(rows):
 rows=[['UID','PID','PPID','PGID','C','TTY','STIME','TIME','CMD']]+[['65532',str(pid),str(parent),'1','0','?','12:00','0s',name] for pid,parent,name in rows]
 widths=[max(10,max(len(row[index]) for row in rows)+3) for index in range(8)]
 return ('\n'.join(''.join(value+' '*(widths[index]-len(value)) for index,value in enumerate(row[:8]))+row[8] for row in rows)+'\n').encode()


class Memory(unittest.TestCase):
 def query_trial(self,responses):
  t=collect.Trial.__new__(collect.Trial);t.control='memory-control';t.target={'cid':'a'*64};t.ops=OPS
  t.startup=OPS['AccountingStartup']('memory');t.phases=OPS['AccountingPhases']('memory');t.root_roles=None
  responses=iter(responses);calls=[]
  def command(argv,**kwargs):
   self.assertEqual(argv,['/usr/local/bin/runsc','--root=/run/containerd/runsc/k8s.io','ps','--format=table','a'*64]);calls.append(argv);return next(responses)
  t.command=command;return t,calls

 def test_actual_startup_handoff_binds_strict_root_roles_and_never_confuses_local_pid(self):
  pending=table([(10,1,'ash'),(11,10,'awk')]);strict=table([(10,1,'a2mi'),(11,10,'a2mw')])
  t,calls=self.query_trial([pending,strict,strict]);self.assertIsNone(t.query()['rootProjection']);self.assertFalse(t.startup.bound)
  bound=t.query()['rootProjection'];self.assertTrue(t.startup.bound);self.assertEqual([row['rootPID'] for row in bound],[10,11])
  self.assertEqual(t.query()['rootProjection'],bound);self.assertEqual(len(calls),3)

 def test_root_change_or_worker_disappearance_before_release_is_stop(self):
  for fault in ('change','disappear'):
   with self.subTest(fault=fault):
    strict=table([(10,1,'a2mi'),(11,10,'a2mw')]);bad=table([(10,1,'a2mi'),(12,10,'a2mw')]) if fault=='change' else table([(10,1,'a2mi')])
    t,_=self.query_trial([strict,bad]);t.query()
    with self.assertRaisesRegex(AssertionError,'^CALIBRATION_ROOT_'+('IDENTITY' if fault=='change' else 'DISAPPEARED')+'$'):t.query()

 def test_init_only_is_allowed_only_after_exact_third_signal_consumption(self):
  strict=table([(10,1,'a2mi'),(11,10,'a2mw')]);t,_=self.query_trial([strict,table([(10,1,'a2mi')])]);t.query();t.phases.signal_starts=[1,2,3]
  self.assertEqual(len(t.query()['rootProjection']),1)

 def test_wrong_or_empty_released_init_projection_is_never_a_live_row(self):
  strict=table([(10,1,'a2mi'),(11,10,'a2mw')])
  for projection in ([(77,1,'a2mi')], []):
   with self.subTest(projection=projection):
    t,_=self.query_trial([strict,table(projection)]);t.query();t.phases.signal_starts=[1,2,3]
    with self.assertRaisesRegex(AssertionError,'^CALIBRATION_RELEASED_ROOT_IDENTITY$'):t.query()

 def pump_trial(self):
  t,_=self.query_trial([]);t.protocol=protocol;t.deadline=10;t.saved=[];t.dispatch=[]
  for message,at in [('NAME init ash a2mi 1 100',.1),('INTENT 1 2',.2),('NAME worker awk a2mw 2 101',.3),('FD_OK readonly0 closed3 closed4',.4),('STAT READY 2 101 0 0',.5),('READY init=1 start=100 worker=2 workerStart=101',1.)]:t.phases.feed(message,at)
  roles=[{'rootPID':10,'UID':65532,'rootPPID':1,'CMD':'a2mi'},{'rootPID':11,'UID':65532,'rootPPID':10,'CMD':'a2mw'}];t.root_roles=roles
  t.rows=[{'sample':index,'counterReadStart':at,'counterReadEnd':at+.01,'rootProjection':{'rootProjection':copy.deepcopy(roles)}} for index,at in enumerate((1.1,1.7,2.3))]
  t.stream=types.SimpleNamespace(drain=lambda *args:None,buffer=collect.LogBuffer())
  t.query=lambda:{'rootProjection':copy.deepcopy(roles)};t.fence=lambda:'LIVE';t.container=lambda:{'status':{'state':'CONTAINER_RUNNING'}}
  t.command=lambda argv,**kwargs:t.dispatch.append((argv,kwargs)) or b'';t.save=lambda name,value:t.saved.append((name,value.copy()))
  return t

 def test_real_memory_pump_requires_complete_root_bound_window_then_consumes_one_signal(self):
  t=self.pump_trial()
  with patch.object(collect.time,'monotonic',side_effect=[3.,3.01]):t.pump()
  self.assertEqual(t.phases.signal_starts,[3.]);self.assertEqual(len(t.dispatch),1)
  self.assertEqual(t.dispatch[0][0],['/usr/local/bin/runsc','--root=/run/containerd/runsc/k8s.io','kill','a'*64,'USR1'])
  self.assertEqual([name for name,_ in t.saved],['signal-1.intent.json','signal-1.result.json'])
  t.pump();self.assertEqual(len(t.dispatch),1,'waiting for ACK/next phase must never resend')

 def test_short_or_wrong_root_windows_and_changed_final_query_never_signal(self):
  for fault in ('short','window','query'):
   with self.subTest(fault=fault):
    t=self.pump_trial()
    if fault=='short':t.rows.pop();t.pump()
    else:
     if fault=='window':t.rows[1]['rootProjection']['rootProjection'][1]['rootPID']=99
     else:t.query=lambda:{'rootProjection':[]}
     with self.assertRaisesRegex(AssertionError,'^CALIBRATION_'+('ROOT_WINDOW' if fault=='window' else 'SIGNAL_ROOT')+'$'):t.pump()
    self.assertEqual(t.dispatch,[])


class Process(unittest.TestCase):
 def test_current_query_supports_original65536_high_table_contract_for49_valid_rows(self):
  t=collect.Trial.__new__(collect.Trial);t.control='process-limit';t.target={'cid':'a'*64};t.ops=OPS
  raw=table([(i,0 if i==1 else 1,'fixed-child-'+str(i)) for i in range(1,50)]);self.assertGreater(len(raw),4096);self.assertLessEqual(len(raw),65536)
  t.command=lambda *args,**kwargs:raw
  try:result=t.query()
  except AssertionError as error:self.fail('High query still uses small-control4096 bound: '+str(error))
  self.assertEqual(result['count'],49)

 def finish_trial(self,positive=True):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);out=Path(temp.name).resolve()
  t=collect.Trial.__new__(collect.Trial);t.control='process-limit';t.kernel=kernel;t.outcomes=OUTCOMES;t.out=out
  t.target={'uid':'12345678-1234-1234-1234-123456789abc','cid':'a'*64,'sid':'b'*64,'name':'f01-a2-process-limit','startTime':'2026-11-05T00:00:00Z'}
  t.deadline=t.observation_deadline=30;t.owner={'parent':{'path':'/ancestor/pod','identity':[1,20]}};t.gate=types.SimpleNamespace(complete=True,last=1.)
  counters={'pids.max':['256'],'pids.current':['7'],'pids.events':{'max':0},'pids.events.local':{'max':0},'memory.swap.max':['0'],'memory.max':['268435456'],'memory.current':['1000000'],'memory.peak':['1000000'],'memory.events':{'max':0,'oom':0,'oom_kill':0},'cpu.max':['50000','100000'],'cpu.stat':{'usage_usec':1,'nr_throttled':0}}
  view={'eventMode':'v2-failing-limit-local','parent':'/ancestor/pod','nrDescendants':1,'nrDyingDescendants':0,'groups':{'/ancestor/pod':{'identity':[1,20],'max':256,'events':0,'localEvents':0},'/ancestor/pod/scope':{'identity':[1,21],'max':None,'events':0,'localEvents':0}},'seedCgroups':['/ancestor/pod/scope']*3,'ociPids':[None,None],'ancestors':{'/ancestor':{'identity':[1,10],'max':1000,'current':50,'peak':100,'peakWritable':False}}}
  t.rows=[{'sample':i,'status':'verified','monotonic':at,'counterReadStart':at,'counterReadEnd':at+.01,'nativePids':7,'counters':copy.deepcopy(counters),'pidView':copy.deepcopy(view),'rootProjection':{'count':49}} for i,at in enumerate((2.,2.6,3.2))]
  final={'counters':copy.deepcopy(counters),'pidView':copy.deepcopy(view)}
  if positive:
   final['counters']['pids.events']['max']=1;final['counters']['pids.events.local']['max']=1
  value={'schema':'f01-terminal-parent-counters-v1','parentOrigin':['/ancestor/pod',[1,20]],'counters':final['counters']}
  t.measurement=types.SimpleNamespace(read=lambda:final,read_terminal_parent=lambda:copy.deepcopy(value))
  t.parent=types.SimpleNamespace(root=Path('/ancestor/pod'),identity=[1,20],check=lambda:None,check_retained=lambda:True)
  t.unchanged=lambda:None
  t.terminal_endpoint_attempted=False;t.terminal_endpoint_record=t.terminal_endpoint_error=None;t.terminal_endpoint_parent_missing=False
  raw=b'2026-11-05T00:00:03Z CHILD_READY 1\n2026-11-05T00:00:03Z xargs: can\'t fork: Resource temporarily unavailable\n'
  t.stream=types.SimpleNamespace(finish=lambda emit:None,buffer=types.SimpleNamespace(raw=raw))
  t.pod=lambda:{'status':{'phase':'Failed','containerStatuses':[{'state':{'terminated':{'exitCode':1}}}]}}
  terminal={'uid':t.target['uid'],'cid':t.target['cid'],'state':'CONTAINER_EXITED','exitCode':1,'finishedAt':'2026-11-05T00:00:03.3Z','reason':'Error'}
  terminal.update(status='CONFIRMED_TERMINAL',monotonic=9.)
  with patch.object(collect.time,'monotonic',side_effect=[9.1,9.2]):t.capture_terminal_endpoint(terminal)
  result={'samples':t.rows,'terminal':terminal,'discarded':0,'quiescence':None}
  return t,result

 def test_finish_applies_real_positive_delta_guard_before_retained_numeric_outcome(self):
  t,result=self.finish_trial()
  with patch.object(collect.time,'monotonic',return_value=10.):verdict=t.finish(result)
  self.assertEqual(verdict['status'],'OBSERVED')
  facts=collect.strict_json((t.out/'facts.json').read_bytes());self.assertEqual(facts['pidDenialEvents'],{'parentLocal':1,'parentHierarchical':1,'forkLocal':None})

 def test_zero_delta_never_reaches_outcome_qualification_even_with_fork_refusal_log(self):
  t,result=self.finish_trial(False);t.outcomes={'qualify':lambda *args:self.fail('zero delta must stop before numeric receiver')}
  with patch.object(collect.time,'monotonic',return_value=10.),self.assertRaisesRegex(kernel.ProofError,'^PID_DENIAL_EVENT_UNPROVEN$'):t.finish(result)
  self.assertFalse((t.out/'control-observation.json').exists())


if __name__=='__main__':unittest.main()
