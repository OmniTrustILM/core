"""Actual fixed Python invocation lines must preserve the former heredoc EOF."""
import json,os,pathlib,shlex,subprocess,sys,tempfile,unittest
import bootstrap
BASE=pathlib.Path(__file__).resolve().parents[1]
class ClosedStdin(unittest.TestCase):
 def test_every_fixed_python_cli_closes_ambient_stdin_without_changing_arguments(self):
  count=0
  for source in (BASE/'health.sh',BASE/'observe-resource.sh',BASE/'prepare-runtime.sh',BASE/'run-floor-control.sh',BASE/'run-resources.sh'):
   for line in source.read_text().splitlines():
    tokens=shlex.split(line.strip()) if 'python3 ' in line else []
    if not(tokens[:1]==['python3'] or tokens[:2] in (['exec','python3'],['if','python3'])):continue
    count+=1
    with self.subTest(source=source.name,module=tokens[4 if tokens[0]=='python3' else 5]),tempfile.TemporaryDirectory() as temp:
     root=pathlib.Path(temp);binary=root/'bin';binary.mkdir();receipt=root/'receipt.json'
     reader=binary/'python3';reader.write_text('#!'+sys.executable+'\nimport json,os,pathlib,sys\npathlib.Path(os.environ["STDIN_RECEIPT"]).write_text(json.dumps({"stdin":sys.stdin.buffer.read(1).hex(),"args":sys.argv[1:]}))\n');reader.chmod(0o700)
     command=line.strip()
     if command.startswith('if '):command=command[3:]
     script='set -euo pipefail\nBASE=$1;OUT=$1;tag=public;threshold=public;node=public;POD=public;POD_UID=public;CID=public;SID=public;CONTROL=floor-control;OBSERVER=900\n'+command+'\nwait\n'
     result=subprocess.run(['bash','-c',script,'--',str(root)],input=b'AMBIENT_INPUT_MUST_NOT_REACH_PYTHON',capture_output=True,timeout=3,env=os.environ|{'PATH':str(binary)+':'+os.environ['PATH'],'STDIN_RECEIPT':str(receipt)})
     self.assertEqual(result.returncode,0,result.stderr);value=json.loads(receipt.read_text());self.assertEqual(value['stdin'],'','fixed file CLI inherited ambient input')
     self.assertEqual(value['args'][:3],['-I','-S','-B']);self.assertTrue(value['args'][3].startswith(str(root)+'/python/'))
  self.assertEqual(count,15)
if __name__=='__main__':unittest.main()
