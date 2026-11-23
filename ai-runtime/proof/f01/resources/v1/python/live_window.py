import datetime,hashlib,json,math,os,pathlib,re,stat,subprocess,sys,time
UTC_OFFSET='+00:00'
NS='ilm-sandbox-a2'
MARKERS=('TOKEN_ABSENT','HOST_AGENT_ABSENT','ROOT_MOUNT_READONLY','SHARED_SCRATCH_WRITABLE','FLOOR_V1_READY','NPROC_RAISE_REFUSED','A2_FLOOR_READY')
def parse_logs(raw,control):
 assert len(raw)<65536 and (not raw or raw.endswith(b'\n')),'truncated or excessive log snapshot'
 messages=[]
 for line in raw.decode('utf-8').split('\n')[:-1]:
  stamp,message=line.split(' ',1)
  assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',stamp)
  assert datetime.datetime.fromisoformat(stamp.replace('Z',UTC_OFFSET)).tzinfo is not None
  assert all(ord(c)>=32 or c=='\t' for c in message) and '\x7f' not in message,'control character in log'
  messages.append(message)
 markers=[];records={};local_pids={}
 for message in messages:
  marker=None
  if control=='process-control':
   if not message:continue
   _worker_record(message,records,local_pids)
   continue
  marker=_floor_marker(message)
  if marker:
   assert control=='floor-control' and marker not in markers,'duplicate or foreign reserved marker'
   markers.append(marker)
 required=set(MARKERS)|{'UID','NPROC_LIMIT','NPROC_ERROR','GVISOR'}
 if control=='process-control':return {'records':records,'localPids':local_pids},len(records)==16
 return {'markers':sorted(markers),'workerPids':[],'workerOrdinals':[],'uidRecords':0,'threadRecords':0},set(markers)==required


def _worker_record(message,records,local_pids):
 record=message+'\n'
 assert record.isascii() and len(record.encode('ascii'))<=128,'excessive or nonASCII worker record'
 match=re.fullmatch('A2_WORKER_READY tag=(a2w(?:0[1-9]|1[0-6])) pid=([1-9](?a:\\d)*) uid=65532,65532,65532,65532 threads=1',message)
 assert match,'malformed process logical record'
 tag,pid=match[1],int(match[2])
 assert tag not in records and pid not in local_pids.values(),'duplicate worker tag or local PID'
 records[tag]=record;local_pids[tag]=pid


def _floor_marker(message):
 marker=None
 assert not message.startswith(('WORKER_STATUS','CHILD_READY','A2_WORKER_READY')),'foreign worker record'
 if message.startswith(('TOKEN_','HOST_AGENT_','ROOT_MOUNT_','SHARED_SCRATCH_','FLOOR_V1_','NPROC_','A2_FLOOR_')):
  assert message in MARKERS;marker=message
 elif message.startswith('uid='):
  assert message=='uid=65532 gid=65532 groups=65532';marker='UID'
 elif message.startswith('Max processes'):
  assert re.fullmatch(r'Max processes[ \t]+256[ \t]+256[ \t]+processes[ \t]*',message);marker='NPROC_LIMIT'
 elif message.startswith('ash: error setting limit:'):
  assert message=='ash: error setting limit: Operation not permitted';marker='NPROC_ERROR'
 elif re.match(r'^\[\s*[0-9.]+\]\s*Starting gVisor',message):
  assert re.fullmatch('\\[[ \\t]*(?a:\\d)+\\.(?a:\\d)+\\] Starting gVisor\\.\\.\\.',message);marker='GVISOR'
 return marker


def secure_json(path):
 with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1
  raw=f.read(4097);assert len(raw)<=4096
 def unique(pairs):
  assert len(pairs)==len(dict(pairs)),'duplicate input key'
  return dict(pairs)
 return json.loads(raw,object_pairs_hook=unique)

def owned_pod(p,t,phase):
 assert p['metadata']['uid']==t['uid'] and p['metadata']['name']==t['name'] and p['metadata']['namespace']==NS and p['metadata']['labels']=={'ilm.ai/proof':'a2-v1'}
 assert p['spec']['runtimeClassName']=='runsc-f01-a2-v1' and p['status']['startTime']==t['startTime']
 statuses=p['status']['containerStatuses'];assert len(statuses)==1
 c=statuses[0];assert c['name']=='fixed-proof' and c['containerID']=='containerd://'+t['cid'] and type(c['restartCount']) is int and c['restartCount']==0
 if phase=='ready':assert set(c['state'])=={'running'} and p['status']['phase']=='Running'
 else:assert p['status']['phase']=='Succeeded' and set(c['state'])=={'terminated'} and type(c['state']['terminated']['exitCode']) is int and c['state']['terminated']['exitCode']==0

def snapshot(out,t,phase,deadline,attempt):
 limit=min(deadline,time.monotonic()+2);base=['k3s','kubectl','--request-timeout=2s']
 def call(args,log=False):
  remaining=limit-time.monotonic();assert remaining>0,'snapshot budget exhausted'
  q=subprocess.run(args,capture_output=True,timeout=min(2,remaining));received=time.monotonic()
  if log:(out/(phase+'-snapshot-'+str(attempt)+'.log')).write_bytes(q.stdout)
  assert q.returncode==0 and received<limit,'failed or late snapshot command'
  return q.stdout,received
 get=base+['get','pod',t['name'],'-n',NS,'-o','json']
 owned_pod(json.loads(call(get)[0]),t,phase)
 raw,received=call(base+['logs','--timestamps','--limit-bytes=65536','--container=fixed-proof',t['name'],'-n',NS],True)
 owned_pod(json.loads(call(get)[0]),t,phase)
 if phase=='final':
  c=json.loads(call(['k3s','crictl','inspect',t['cid']])[0]);s=c['status']
  assert s['id']==t['cid'] and s['metadata']['name']=='fixed-proof' and s['state']=='CONTAINER_EXITED' and type(s['exitCode']) is int and s['exitCode']==0
  assert c['info']['runtimeType']=='io.containerd.runsc.v1' and all(s['labels']['io.kubernetes.pod.'+k]==v for k,v in [('uid',t['uid']),('name',t['name']),('namespace',NS)])
  end=datetime.datetime.fromisoformat(s['finishedAt'].replace('Z',UTC_OFFSET));start=datetime.datetime.fromisoformat(t['startTime'].replace('Z',UTC_OFFSET))
  assert end.tzinfo is not None and 0<=(end-start).total_seconds()<=30
  (out/'normal-exit.json').write_text(json.dumps({'status':s,'runtimeType':c['info']['runtimeType'],'observedMonotonic':time.monotonic()})+'\n')
 assert time.monotonic()<limit
 return raw,received

def collect(out,t,control,phase):
 assert phase in ('ready','final') and control in ('floor-control','process-control') and t['name']=='f01-a2-'+control
 assert os.geteuid()==0
 now=time.monotonic();start=datetime.datetime.fromisoformat(t['startTime'].replace('Z',UTC_OFFSET));assert start.tzinfo is not None
 clock=secure_json(out/'outer-clock.json')
 assert set(clock)=={'podStartTime','monotonic','realtime','deadlineMonotonic'} and clock['podStartTime']==t['startTime']
 assert all(type(clock[k]) in (int,float) and math.isfinite(clock[k]) for k in ('monotonic','realtime','deadlineMonotonic'))
 deadline=clock['deadlineMonotonic']
 assert abs(deadline-clock['monotonic']-30+clock['realtime']-start.timestamp())<.0001
 assert 0<=deadline-30<=clock['monotonic']<=now<deadline
 if phase=='final':return _final_window(out,t,control,deadline,clock,now)
 return _ready_window(out,t,control,deadline,clock)


def _final_window(out,t,control,deadline,clock,now):
 window=secure_json(out/'live-window-input.json');assert window['target']==t and window['schema']==('f01-a2-process-window-v2' if control=='process-control' else 'f01-a2-live-window-v1') and window['clock']=='CLOCK_MONOTONIC'
 assert window['deadlineMonotonic']==deadline and window['clockMonotonic']==clock['monotonic'] and window['clockRealtime']==clock['realtime']
 assert window['receiptMonotonic']<=now<deadline
 previous=(out/'readiness.log').read_bytes();assert hashlib.sha256(previous).hexdigest()==window['readinessSha256']
 semantics,complete=parse_logs(previous,control);assert complete
 if control=='process-control':assert semantics=={'records':window['records'],'localPids':window['localPids']}
 else:assert semantics['workerPids']==window['workers']
 raw,_=snapshot(out,t,'final',deadline,0);final,complete=parse_logs(raw,control)
 assert complete and final==semantics,'final semantic records disagree with readiness'
 assert time.monotonic()<deadline
 (out/'live-timestamped.log').write_bytes(raw)
 (out/'live.log').write_text('\n'.join(line.split(' ',1)[1] for line in raw.decode().split('\n')[:-1])+'\n')


def _ready_window(out,t,control,deadline,clock):
 previous=b''
 for attempt in range(20):
  raw,received=snapshot(out,t,'ready',deadline,attempt);semantics,complete=parse_logs(raw,control)
  assert raw.startswith(previous),'readiness snapshot is not an append-only prefix';previous=raw
  assert time.monotonic()<deadline
  if complete:
   value={'schema':'f01-a2-live-window-v1','target':t,'clock':'CLOCK_MONOTONIC','clockMonotonic':clock['monotonic'],'clockRealtime':clock['realtime'],'receiptMonotonic':received,'deadlineMonotonic':deadline,'workers':semantics.get('workerPids',[]),'readinessSha256':hashlib.sha256(raw).hexdigest()}
   if control=='process-control':
    value.pop('workers');value.update(schema='f01-a2-process-window-v2',records=semantics['records'],localPids=semantics['localPids'])
   (out/'readiness.log').write_bytes(raw)
   fd=os.open(out/'live-window-input.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'w') as f:
    st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1
    f.write(json.dumps(value)+'\n')
   return
  assert attempt<19 and time.monotonic()+.1<deadline,'readiness unavailable within fixed budget'
  time.sleep(.1)


def main():
 out=pathlib.Path(sys.argv[2]);t=secure_json(out/'targets.json');collect(out,t,sys.argv[3],sys.argv[1])
if __name__=='__main__':main()
