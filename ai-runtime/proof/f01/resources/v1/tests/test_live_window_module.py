"""Real ordinary log/window CLI with only API/CRI/clock/root identity inputs synthetic."""
import contextlib,datetime,hashlib,json,os,pathlib,runpy,subprocess,sys,tempfile,time,types,unittest
from contextlib import ExitStack
from unittest.mock import patch
import bootstrap
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'python'
UID='12345678-1234-1234-1234-123456789abc';CID='a'*64;SID='b'*64

def namespace():return runpy.run_path(str(SOURCE/'live_window.py'),run_name='window_module_test')
def log(control):
 if control=='process-control':messages=[f'A2_WORKER_READY tag=a2w{i:02} pid={i+1} uid=65532,65532,65532,65532 threads=1' for i in range(1,17)]
 else:messages=['uid=65532 gid=65532 groups=65532','[   0.1] Starting gVisor...','TOKEN_ABSENT','HOST_AGENT_ABSENT','ROOT_MOUNT_READONLY','SHARED_SCRATCH_WRITABLE','FLOOR_V1_READY','NPROC_RAISE_REFUSED','A2_FLOOR_READY','Max processes 256 256 processes','ash: error setting limit: Operation not permitted']
 return ''.join('2026-10-29T00:00:01Z '+message+'\n' for message in messages).encode()

class LiveWindow(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
 def test_reserved_markers_and_worker_records_are_complete_unique_and_closed(self):
  n=namespace()
  for control in ('floor-control','process-control'):
   with self.subTest(control=control):self.assertTrue(n['parse_logs'](log(control),control)[1])
  for raw,control in [(log('floor-control')+b'2026-10-29T00:00:01Z TOKEN_ABSENT\n','floor-control'),(log('process-control')+log('process-control'),'process-control'),(log('floor-control')[:-1],'floor-control'),(b'x'*65536,'floor-control'),(b'2026-10-29T00:00:01Z TOKEN_ABSENT\x00\n','floor-control')]:
   with self.subTest(raw=raw[:30]),self.assertRaises((AssertionError,ValueError)):n['parse_logs'](raw,control)
 def exercise(self,control,fault=''):
  target={'uid':UID,'cid':CID,'sid':SID,'name':'f01-a2-'+control,'startTime':'2026-10-29T00:00:00Z'}
  clock={'podStartTime':target['startTime'],'monotonic':100.,'realtime':datetime.datetime(2026,10,29,tzinfo=datetime.timezone.utc).timestamp(),'deadlineMonotonic':130.}
  for name,value in [('targets.json',target),('outer-clock.json',clock)]:p=self.root/name;p.write_text(json.dumps(value));p.chmod(0o600)
  raw=log(control);phase='ready';calls=[];now=[100.];original=os.fstat
  def fstat(fd):
   record=original(fd);return types.SimpleNamespace(st_mode=record.st_mode,st_uid=0,st_nlink=record.st_nlink)
  def run(args,**kwargs):
   calls.append(args);self.assertGreater(kwargs['timeout'],0);self.assertLessEqual(kwargs['timeout'],2)
   if 'logs' in args:return types.SimpleNamespace(returncode=1 if fault=='command' else 0,stdout=raw,stderr=b'')
   if 'inspect' in args:
    return types.SimpleNamespace(returncode=0,stdout=json.dumps({'status':{'id':CID,'metadata':{'name':'fixed-proof'},'state':'CONTAINER_EXITED','exitCode':0,'finishedAt':'2026-10-29T00:00:12Z','labels':{'io.kubernetes.pod.uid':UID,'io.kubernetes.pod.name':target['name'],'io.kubernetes.pod.namespace':'ilm-sandbox-a2'}},'info':{'runtimeType':'io.containerd.runsc.v1'}}).encode(),stderr=b'')
   status={'name':'fixed-proof','containerID':'containerd://'+CID,'restartCount':0,'state':{'running':{}} if phase=='ready' else {'terminated':{'exitCode':0}}}
   pod={'metadata':{'uid':'foreign' if fault=='owner' else UID,'name':target['name'],'namespace':'ilm-sandbox-a2','labels':{'ilm.ai/proof':'a2-v1'}},'spec':{'runtimeClassName':'runsc-f01-a2-v1'},'status':{'startTime':target['startTime'],'phase':'Running' if phase=='ready' else 'Succeeded','containerStatuses':[status]}}
   return types.SimpleNamespace(returncode=0,stdout=json.dumps(pod).encode(),stderr=b'')
  with ExitStack() as stack:
   for item in (patch.object(os,'geteuid',return_value=0),patch.object(os,'fstat',fstat),patch.object(subprocess,'run',run),patch.object(time,'monotonic',lambda:now[0]),patch.object(time,'sleep',lambda t:now.__setitem__(0,now[0]+t))):stack.enter_context(item)
   for phase in ('ready','final'):
    if fault=='clock':clock['deadlineMonotonic']=160.;(self.root/'outer-clock.json').write_text(json.dumps(clock))
    with patch.object(sys,'argv',['window',phase,str(self.root),control]):runpy.run_path(str(SOURCE/'live_window.py'),run_name='__main__')
  return target,calls,raw
 def test_floor_and_process_cli_bind_owned_ready_and_normal_final_observations(self):
  for control in ('floor-control','process-control'):
   with self.subTest(control=control),tempfile.TemporaryDirectory() as temp:
    self.root=pathlib.Path(temp);target,calls,raw=self.exercise(control)
    value=json.loads((self.root/'live-window-input.json').read_text());self.assertEqual(value['target'],target);self.assertEqual(value['readinessSha256'],hashlib.sha256(raw).hexdigest())
    self.assertEqual((self.root/'live-timestamped.log').read_bytes(),raw);self.assertEqual(json.loads((self.root/'normal-exit.json').read_text())['status']['exitCode'],0)
    self.assertEqual(len(calls),7)
 def test_owner_command_and_original_clock_failure_never_publish_window(self):
  for fault in ('owner','command','clock'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
    self.root=pathlib.Path(temp)
    with self.assertRaises(AssertionError):self.exercise('floor-control',fault)
    self.assertFalse((self.root/'live-window-input.json').exists())
 def test_duplicate_keys_and_symlink_input_are_not_secure_observation_inputs(self):
  n=namespace();p=self.root/'duplicate.json';p.write_text('{"uid":1,"uid":2}');p.chmod(0o600);original=os.fstat
  def fstat(fd):
   st=original(fd);return types.SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_nlink=st.st_nlink)
  with patch.object(os,'fstat',fstat),self.assertRaisesRegex(AssertionError,'duplicate'):n['secure_json'](p)
  link=self.root/'symlink';link.symlink_to(p)
  with self.assertRaises(OSError):n['secure_json'](link)
 def test_decode_and_split_failures_keep_their_original_exact_families(self):
  parse=namespace()['parse_logs']
  for raw,kind in [(b'2026-10-29T00:00:01Z\xff\n',UnicodeDecodeError),(b'NO_SEPARATOR\n',ValueError)]:
   with self.subTest(kind=kind.__name__),self.assertRaises(kind) as error:parse(raw,'floor-control')
   self.assertIs(type(error.exception),kind)
if __name__=='__main__':unittest.main()
