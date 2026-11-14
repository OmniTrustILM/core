"""Real interpreter controls at the exact fixed recovery CLI boundary, no runtime I/O."""
import ast,json,os,pathlib,subprocess,sys,tempfile,unittest
import bootstrap
BASE=pathlib.Path(__file__).resolve().parents[1]
class InterpreterIsolation(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
  binary=self.root/'bin';binary.mkdir();(binary/'python3').symlink_to(sys.executable)
  self.output=self.root/'out';self.output.mkdir();self.inject=self.root/'inject';self.inject.mkdir()
  self.env={k:v for k,v in os.environ.items() if not k.startswith('PYTHON')}
  self.env['PATH']=str(binary)+':'+self.env['PATH']
  self.line=next(line.strip() for line in (BASE/'prepare-runtime.sh').read_text().splitlines() if 'python/verify_recovery_config.py' in line)
 def caller(self,extra=None,drift=False):
  (self.output/'recovery-rendered.validated').write_text('version=4\nvalue="'+('drift' if drift else 'same')+'"\n')
  (self.output/'rendered.before.validated').write_text('value="same"\nversion=4\n')
  script='set -euo pipefail\nBASE=$1;OUT=$2\ncheck() {\n'+self.line+'\n}\ncheck\n'
  return subprocess.run(['/bin/bash','-c',script,'--',str(BASE),str(self.output)],env=self.env|(extra or {}),input=b'closed ambient input',capture_output=True,timeout=3)
 def test_hostile_optimize_cannot_remove_actual_recovery_assertion(self):
  result=self.caller({'PYTHONOPTIMIZE':'2'},drift=True)
  self.assertEqual(result.returncode,1)
  self.assertIn(b'AssertionError: recovery rendered config differs from baseline',result.stderr)
  self.assertEqual(result.stdout,b'')
 def test_hostile_pythonpath_cannot_replace_standard_library(self):
  (self.inject/'tomllib.py').write_text('raise SystemExit(77)\n')
  result=self.caller({'PYTHONPATH':str(self.inject)})
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
 def test_hostile_site_initialization_cannot_execute(self):
  marker=self.root/'site-ran'
  (self.inject/'sitecustomize.py').write_text('open('+repr(str(marker))+',"w").write("INJECTED_SITE")\n')
  result=self.caller({'PYTHONPATH':str(self.inject)})
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertFalse(marker.exists(),'ambient sitecustomize executed before the proof CLI')
 def test_all_production_imports_compile_under_actual_isolated_interpreter(self):
  program='''import ast,importlib,json,pathlib,sys
files=sorted(pathlib.Path(sys.argv[1]).glob('*.py'));names=set()
for path in files:
 tree=ast.parse(path.read_text(),filename=str(path));compile(tree,str(path),'exec')
 for node in ast.walk(tree):
  if isinstance(node,ast.Import):names.update(alias.name.split('.')[0] for alias in node.names)
  if isinstance(node,ast.ImportFrom):
   assert node.level==0 and node.module is not None
   names.add(node.module.split('.')[0])
assert names<=sys.stdlib_module_names
for name in sorted(names):importlib.import_module(name)
print(json.dumps({'files':[path.name for path in files],'imports':sorted(names),'flags':[sys.flags.isolated,sys.flags.no_site,sys.flags.dont_write_bytecode,sys.flags.optimize]}))
'''
  result=subprocess.run([sys.executable,'-I','-S','-B','-c',program,str(BASE/'python')],env=self.env|{'PYTHONOPTIMIZE':'2','PYTHONPATH':str(self.inject)},capture_output=True,text=True,timeout=3)
  self.assertEqual(result.returncode,0,result.stderr)
  value=json.loads(result.stdout);self.assertEqual(len(value['files']),15)
  self.assertEqual(value['flags'],[1,1,1,0]);self.assertEqual(result.stderr,'')
if __name__=='__main__':unittest.main()
