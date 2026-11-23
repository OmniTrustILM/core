import subprocess,time,json,sys,pathlib
uid,out=sys.argv[1:]; time.sleep(32)
p=subprocess.run(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1','--request-timeout=5s','get','pod','f01-a2-floor-control','-n','ilm-sandbox-a2','--ignore-not-found','-o','json'],capture_output=True,text=True)
def unobserved():
 pathlib.Path(out,'outer-stop.txt').write_text('FAILED outer32s observation unavailable\n');sys.exit(1)
if p.returncode:unobserved()
if not p.stdout.strip():sys.exit()
try:x=json.loads(p.stdout)
except ValueError:unobserved()
if x['metadata']['uid']!=uid:sys.exit()
pathlib.Path(out,'outer-stop.txt').write_text('FAILED floor survived outer32s; UID-scoped delete requested\n')
# delete --raw sends DeleteOptions with an actual UID precondition.
f=pathlib.Path(out,'outer-delete.json');f.write_text(json.dumps({'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'gracePeriodSeconds':1}))
q=subprocess.run(['/usr/bin/kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', '--cache-dir=/opt/ilm-488-f01-api-cache-r1','--request-timeout=10s','delete','--raw','/api/v1/namespaces/ilm-sandbox-a2/pods/f01-a2-floor-control','-f',str(f)],capture_output=True,text=True)
pathlib.Path(out,'outer-delete.txt').write_text(q.stdout+q.stderr)
