import datetime,json,pathlib,subprocess,sys,time
out=pathlib.Path(sys.argv[1]);name,uid=sys.argv[2:];begin=time.monotonic();deadline=None;evidence_failed=False
def save(name,value):
 global evidence_failed
 try:
  f=out/name;temporary=f.with_name(f.name+'.tmp');temporary.write_text(json.dumps(value)+'\n');temporary.replace(f)
 except OSError:evidence_failed=True
base=['k3s','kubectl','--request-timeout=2s']
def get():
 q=subprocess.run(base+['get','pod',name,'-n','ilm-sandbox-a2','--ignore-not-found','-o','json'],capture_output=True,text=True,timeout=3);assert q.returncode==0
 if not q.stdout.strip():return None
 p=json.loads(q.stdout);assert p['metadata']['uid']==uid and p['metadata']['name']==name and p['metadata']['namespace']=='ilm-sandbox-a2' and p['metadata']['labels']=={'ilm.ai/proof':'a2-v1'} and p['spec']['runtimeClassName']=='runsc-f01-a2-v1';return p
for _ in range(100):
 p=get()
 if p is None:sys.exit(1 if evidence_failed else 0)
 if p.get('status',{}).get('startTime'):
  start=datetime.datetime.fromisoformat(p['status']['startTime'].replace('Z','+00:00')).timestamp();now=time.monotonic();wall=time.time();deadline=now+30-(wall-start)
  save('outer-clock.json',{'podStartTime':p['status']['startTime'],'monotonic':now,'realtime':wall,'deadlineMonotonic':deadline});break
 if time.monotonic()-begin>=10:raise RuntimeError('Pod startTime unavailable')
 time.sleep(.1)
assert deadline is not None
time.sleep(max(0,deadline-time.monotonic()))
p=get()
if p is None:sys.exit(1 if evidence_failed else 0)
q=subprocess.run(['k3s','crictl','ps','--state','running','--label','io.kubernetes.pod.uid='+uid,'-q'],capture_output=True,text=True,timeout=2);assert q.returncode==0
if q.stdout.strip():
 stop={'status':'FAILED_NATIVE_OBSERVATION','monotonic':time.monotonic(),'lateSeconds':time.monotonic()-deadline}
 options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'gracePeriodSeconds':1}
 q=subprocess.run(base+['delete','--raw','/api/v1/namespaces/ilm-sandbox-a2/pods/'+name,'-f','-'],input=json.dumps(options),capture_output=True,text=True,timeout=10)
 save('outer-stop.json',stop);save('outer-delete.json',options)
 try:(out/'outer-delete.txt').write_text(q.stdout+q.stderr)
 except OSError:evidence_failed=True
 assert q.returncode==0
assert not evidence_failed,'watchdog evidence unavailable'
