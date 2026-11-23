"""Current kind systemd /kubelet ownership predicate; no kernel mutation."""
from pathlib import Path
import json,shlex,shutil,subprocess,tempfile,unittest
BASE=Path(__file__).resolve().parents[1]
POD_UID='11111111-2222-3333-4444-555555555555'
SID='a'*64
CID='b'*64
class KindCgroupParentTests(unittest.TestCase):
 def run_predicate(self,group=None,uid=POD_UID,sid=SID,cid=CID,oci=None):
  lines=(BASE/'run-floor-control.sh').read_text().splitlines();first=[x for x in lines if x.startswith('[[ ${CGROUP##*/}')];second=[x for x in lines if x.startswith('[[ $(jq -r .cgroupsPath')];self.assertEqual(len(first),1);self.assertEqual(len(second),1);self.assertIsNotNone(shutil.which('jq'))
  parent='kubelet-kubepods-burstable-pod'+POD_UID.replace('-','_')+'.slice';group=group or '/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/'+parent+'/cri-containerd-'+SID+'.scope'
  with tempfile.TemporaryDirectory() as d:
   out=Path(d);(out/'oci.json').write_text(json.dumps({'cgroupsPath':oci or parent+':cri-containerd:'+CID}));values={'CGROUP':group,'POD_UID':uid,'SID':sid,'CID':cid,'OUT':str(out)};script='set -euo pipefail\n'+'\n'.join(k+'='+shlex.quote(v) for k,v in values.items())+'\nPOD_CGROUP=${CGROUP%/*}\n'+first[0]+' || exit 1\n'+second[0]+' || exit 1\n';return subprocess.run(['/bin/bash','-c',script],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
 def test_current_kind_kubelet_parent_and_exact_sid_oci_relation_pass(self):
  p=self.run_predicate();self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(p.stdout,b'')
 def test_wrong_pod_uid_rejected(self):self.assertNotEqual(self.run_predicate(uid='99999999-2222-3333-4444-555555555555').returncode,0)
 def test_wrong_sandbox_id_rejected(self):self.assertNotEqual(self.run_predicate(sid='c'*64).returncode,0)
 def test_wrong_oci_container_id_rejected(self):self.assertNotEqual(self.run_predicate(cid='c'*64).returncode,0)
 def test_legacy_unprefixed_parent_rejected_on_current_kind(self):
  group='/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod'+POD_UID.replace('-','_')+'.slice/cri-containerd-'+SID+'.scope';self.assertNotEqual(self.run_predicate(group=group,oci=group.rsplit('/',1)[0].rsplit('/',1)[-1]+':cri-containerd:'+CID).returncode,0)
 def test_other_qos_parent_rejected(self):
  group='/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod'+POD_UID.replace('-','_')+'.slice/cri-containerd-'+SID+'.scope';self.assertNotEqual(self.run_predicate(group=group,oci=group.rsplit('/',1)[0].rsplit('/',1)[-1]+':cri-containerd:'+CID).returncode,0)
if __name__=='__main__':unittest.main()
