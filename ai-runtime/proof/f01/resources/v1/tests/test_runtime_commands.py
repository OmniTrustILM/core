"""Purpose-level CLI checks on real production files; all host/runtime inputs synthetic."""
import contextlib,io,json,pathlib,runpy,sys,tempfile,types,unittest
from unittest.mock import patch
import bootstrap
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'python'
UID='12345678-1234-1234-1234-123456789abc';CID='a'*64;SID='b'*64

def invoke(name,*args):
 with patch.object(sys,'argv',[str(SOURCE/name),*map(str,args)]):return runpy.run_path(str(SOURCE/name),run_name='runtime_command_test')

class RuntimeCommands(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
 def write(self,name,value):
  path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value if isinstance(value,str) else json.dumps(value));return path
 def test_lease_requires_fresh_time_and_exact_node_identity(self):
  path=self.write('lease.json',{'holderIdentity':'node','renewTime':'2026-10-29T00:00:01Z'})
  invoke('verify_node_lease.py',path,'2026-10-29T00:00:00Z','node')
  for node,threshold in [('foreign','2026-10-29T00:00:00Z'),('node','2026-10-29T00:00:01Z')]:
   with self.subTest(node=node,threshold=threshold),self.assertRaises(AssertionError):invoke('verify_node_lease.py',path,threshold,node)
 def test_recovery_and_active_checks_compare_parsed_configuration(self):
  for script,left,right in [('verify_recovery_config.py','recovery-rendered.validated','rendered.before.validated'),('verify_active_config.py','actual-rendered.validated','rendered.validated')]:
   with self.subTest(script=script):
    self.write(left,'version=4\nvalue="same"\n');self.write(right,'value="same"\nversion=4\n');invoke(script,self.root)
    self.write(left,'version=4\nvalue="drift"\n')
    with self.assertRaises(AssertionError):invoke(script,self.root)
 def test_candidate_and_addition_keep_nonhandler_configuration_exact(self):
  self.write('rendered.before','version=3\n');self.write('rendered.candidate','version=3\n')
  text='''version=4
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'runsc-f01-a2-v1']
runtime_type='io.containerd.runsc.v1'
base_runtime_spec='/etc/runsc/f01-a2-base.json'
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'runsc-f01-a2-v1'.options]
TypeUrl='io.containerd.runsc.v1.options'
ConfigPath='/etc/runsc/config.toml'
'''
  self.write('rendered.validated',text);invoke('verify_handler_candidate.py',self.root)
  remainder=json.loads((self.root/'new-without-handler.json').read_text());self.assertEqual(remainder,{'version':4,'plugins':{'io.containerd.cri.v1.runtime':{'containerd':{'runtimes':{}}}}})
  self.write('rendered.before.validated',"version=4\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes]\n");invoke('verify_handler_addition.py',self.root)
  self.write('rendered.before.validated',"version=4\nextra=true\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes]\n")
  with self.assertRaises(AssertionError):invoke('verify_handler_addition.py',self.root)
  self.write('rendered.validated',text.replace('runsc-f01-a2-v1','foreign'))
  with self.assertRaises(KeyError):invoke('verify_handler_candidate.py',self.root)
 def test_watchdog_clock_cannot_change_uid_or_restart_original_budget(self):
  self.write('targets.json',{'uid':UID,'startTime':'2026-10-29T00:00:00Z'})
  clock={'podStartTime':'2026-10-29T00:00:00Z','monotonic':100.,'realtime':1793232000.,'deadlineMonotonic':130.}
  # Use the same independent epoch conversion as the fixed public timestamp.
  import datetime
  clock['realtime']=datetime.datetime(2026,10,29,tzinfo=datetime.timezone.utc).timestamp()
  self.write('outer-clock.json',clock);invoke('verify_watchdog_clock.py',self.root,UID)
  with self.assertRaises(AssertionError):invoke('verify_watchdog_clock.py',self.root,'foreign')
  clock['deadlineMonotonic']=160.;self.write('outer-clock.json',clock)
  with self.assertRaises(AssertionError):invoke('verify_watchdog_clock.py',self.root,UID)
 def test_successful_wait_receipt_records_only_zero_and_monotonic_time(self):
  invoke('observer_wait.py',self.root);receipt=json.loads((self.root/'observer-wait.json').read_text());self.assertEqual(receipt['exitCode'],0);self.assertGreater(receipt['receivedMonotonic'],0)
 def mapping(self):
  return {'target':{'uid':UID,'cid':CID,'sid':SID,'name':'f01-a2-floor-control','sentry':10,'root':'/run/synthetic'},'runtimeSeeds':[{'container':c,'sandbox':SID,'sentry':10,'gofer':p} for c,p in [(CID,20),(SID,30)]],'candidates':[{'pid':10,'startTicks':100}]}
 def test_mapping_missing_malformed_or_foreign_never_grants_cleanup_authority(self):
  for value,status in [(None,'UNAVAILABLE'),({},'UNAVAILABLE'),(self.mapping(),'VALID')]:
   with self.subTest(status=status):
    path=self.root/'observation/mapping.json'
    if value is not None:self.write('observation/mapping.json',value)
    elif path.exists():path.unlink()
    output=io.StringIO()
    with contextlib.redirect_stdout(output):invoke('cleanup_mapping.py',self.root,UID,CID,SID,'f01-a2-floor-control')
    result=json.loads(output.getvalue());self.assertEqual(result['status'],status)
  value=self.mapping();value['target']['uid']='foreign';self.write('observation/mapping.json',value)
  with contextlib.redirect_stdout(io.StringIO()):invoke('cleanup_mapping.py',self.root,UID,CID,SID,'f01-a2-floor-control')
  self.assertEqual(json.loads((self.root/'cleanup-mapping.json').read_text())['status'],'INVALID')
 def test_host_absence_requires_original_start_identity_and_cgroup_absence(self):
  self.write('cleanup-mapping.json',{'status':'VALID','pid':10,'startTicks':100});self.write('observation/host-members.json',[{'pid':10,'startTicks':100}])
  owner=self;real=pathlib.Path
  class Proc:
   def __truediv__(self,_):return self
   def read_text(self):
    if owner.ticks is None:raise FileNotFoundError('synthetic absent original process')
    return '10 (synthetic) '+' '.join(['R']+['0']*18+[str(owner.ticks)])
  class Groups:
   def walk(self,on_error):return [('/synthetic',['kubepods-burstable-pod'+UID.replace('-','_')+'.slice'] if owner.cgroup else [],[])]
  def path(*parts):
   if parts==('/proc',):return Proc()
   if parts==('/sys/fs/cgroup',):return Groups()
   return real(*parts)
  module=types.ModuleType('pathlib');module.Path=path
  for ticks,cgroup,code in [(None,False,0),(101,False,0),(100,False,2),(None,True,2)]:
   with self.subTest(ticks=ticks,cgroup=cgroup),patch.dict(sys.modules,{'pathlib':module}):
    self.ticks=ticks;self.cgroup=cgroup
    with self.assertRaises(SystemExit) as stopped:invoke('cleanup_host.py',self.root,UID)
    self.assertEqual(stopped.exception.code,code)
 def test_floor_supervisor_deletes_only_exact_returned_uid_and_marks_intervention(self):
  import subprocess,time
  calls=[]
  def run(args,**kwargs):
   calls.append(args)
   if 'get' in args:return types.SimpleNamespace(returncode=0,stdout=json.dumps({'metadata':{'uid':self.returned_uid}}),stderr='')
   options=json.loads((self.root/'outer-delete.json').read_text());self.assertEqual(options['preconditions'],{'uid':UID});return types.SimpleNamespace(returncode=0,stdout='deleted',stderr='')
  for returned in ('foreign',UID):
   self.returned_uid=returned;calls.clear()
   with patch.object(subprocess,'run',run),patch.object(time,'sleep'):
    try:invoke('verify_floor_runtime.py',UID,self.root)
    except SystemExit:pass
   self.assertEqual(len(calls),2 if returned==UID else 1)
  self.assertTrue((self.root/'outer-stop.txt').read_text().startswith('FAILED'))
 def test_accounting_dispatch_uses_plain_source_and_propagates_exact_child_failure(self):
  source=self.root/'observer.py';out=self.root/'out';out.mkdir()
  code="import json\ndef accounting_producer(out,control,observer):\n (out/'called.json').write_text(json.dumps([control,observer]))\n raise SystemExit(3)\ndef accounting_finish(out,control):\n (out/'called.json').write_text(json.dumps([control]))\n"
  source.write_text(code)
  with self.assertRaises(SystemExit) as error:invoke('accounting_dispatch.py',source,out,'memory-control','collect','900')
  self.assertEqual(error.exception.code,3);self.assertEqual(json.loads((out/'called.json').read_text()),['memory',900])
  invoke('accounting_dispatch.py',source,out,'cpu-control','finish','900');self.assertEqual(json.loads((out/'called.json').read_text()),['cpu'])
  with self.assertRaises(AssertionError):invoke('accounting_dispatch.py',source,out,'cpu-control','bogus','900')
 def test_process_qualification_requires_real_brackets_window_and_exact_worker_log(self):
  from test_observer_ownership import Inputs
  out=self.root;obs=out/'observation';obs.mkdir();inputs=Inputs(obs);inputs.observe()
  self.write('targets.json',inputs.target);self.write('live-window-input.json',inputs.window)
  self.write('live.log',''.join(inputs.window['records'].values()));invoke('qualify_small_control.py',out,'process-control')
  result=json.loads((out/'control-observation.json').read_text());self.assertEqual(result['status'],'OBSERVED');self.assertGreaterEqual(result['samples'],3)
  self.write('live.log','A2_WORKER_READY tag=a2w01 pid=999 uid=65532,65532,65532,65532 threads=1\n')
  with self.assertRaises(AssertionError):invoke('qualify_small_control.py',out,'process-control')
 def test_floor_qualification_requires_closed_live_rows_and_forbids_unexpected_limit_raise(self):
  from test_observer_ownership import Inputs
  from test_live_window_module import log
  out=self.root;obs=out/'observation';obs.mkdir();inputs=Inputs(obs)
  inputs.target['name']=inputs.attached['name']='f01-a2-floor-control';inputs.mapping['target']=inputs.attached.copy()
  raw=log('floor-control');import hashlib
  inputs.window={'schema':'f01-a2-live-window-v1','target':inputs.target.copy(),'clock':'CLOCK_MONOTONIC','clockMonotonic':100.,'clockRealtime':inputs.clock.time(),'receiptMonotonic':100.,'deadlineMonotonic':130.,'workers':[],'readinessSha256':hashlib.sha256(raw).hexdigest()}
  inputs.observe();self.write('targets.json',inputs.target);self.write('live-window-input.json',inputs.window)
  text='\n'.join(line.split(' ',1)[1] for line in raw.decode().splitlines())+'\n';self.write('live.log',text)
  invoke('qualify_small_control.py',out,'floor-control');self.assertEqual(json.loads((out/'control-observation.json').read_text())['status'],'OBSERVED')
  for changed in (text.replace('TOKEN_ABSENT','TOKEN_UNKNOWN'),text+'NPROC_RAISE_UNEXPECTED\n'):
   self.write('live.log',changed)
   with self.assertRaises(AssertionError):invoke('qualify_small_control.py',out,'floor-control')
if __name__=='__main__':unittest.main()
