"""Protect fixed runtime CLI bindings and complete source/packaging classification."""
import ast,json,pathlib,shlex,subprocess,unittest
ROOT=pathlib.Path(__file__).resolve().parents[3]
BASE=ROOT/'resources/v1'
BINDINGS={'health.sh': ['python3 -I -S -B "$BASE/python/verify_node_lease.py" "$OUT/$tag-lease.json" "$threshold" "$node" < '
               '/dev/null || return 1'],
 'observe-resource.sh': ['exec python3 -I -S -B "$BASE/python/observer.py" "$1" "$OUT" "${3-}" < /dev/null'],
 'prepare-runtime.sh': ['python3 -I -S -B "$BASE/python/verify_recovery_config.py" "$OUT" < /dev/null || return 1',
                        'python3 -I -S -B "$BASE/python/verify_handler_candidate.py" "$OUT" < /dev/null',
                        'python3 -I -S -B "$BASE/python/verify_handler_addition.py" "$OUT" < /dev/null',
                        'python3 -I -S -B "$BASE/python/verify_active_config.py" "$OUT" < /dev/null'],
 'run-floor-control.sh': ['python3 -I -S -B "$BASE/python/verify_floor_runtime.py" "$POD_UID" "$OUT" < /dev/null &'],
 'run-resources.sh': ['python3 -I -S -B "$BASE/python/cleanup_mapping.py" "$OUT" "$POD_UID" "$CID" "$SID" "$POD" < '
                      '/dev/null',
                      'python3 -I -S -B "$BASE/python/observer_wait.py" "$OUT" < /dev/null',
                      'python3 -I -S -B "$BASE/python/accounting_dispatch.py" "$BASE/python/observer.py" "$OUT" '
                      '"$CONTROL" "$1" "${OBSERVER:-0}" < /dev/null',
                      'python3 -I -S -B "$BASE/python/live_window.py" "$1" "$OUT" "$CONTROL" < /dev/null',
                      'python3 -I -S -B "$BASE/python/verify_watchdog_clock.py" "$OUT" "$POD_UID" < /dev/null',
                      'python3 -I -S -B "$BASE/python/cleanup_host.py" "$OUT" "$POD_UID" < /dev/null',
                      'python3 -I -S -B "$BASE/python/outer_watchdog.py" "$OUT" "$POD" "$POD_UID" < /dev/null &',
                      'if python3 -I -S -B "$BASE/python/qualify_small_control.py" "$OUT" "$CONTROL" < /dev/null']}
class SourceLayout(unittest.TestCase):
 def test_all_production_modules_are_whitelisted_and_all_other_python_is_test_source(self):
  packages=[(BASE,ROOT/'runtime-assets.json',15),(ROOT/'resources/kernel-v1',ROOT/'resources/kernel-v1/source-assets.json',12)]
  allowed=[]
  for package,manifest_path,count in packages:
   listed={manifest_path.parent/row['path']:row for row in json.loads(manifest_path.read_text())['files']}
   runtime=set((package/'python').glob('*.py'));self.assertEqual(len(runtime),count)
   self.assertEqual({p for p in listed if p.suffix=='.py'},runtime)
   self.assertFalse(any('tests' in p.relative_to(manifest_path.parent).parts for p in listed))
   if package.name=='kernel-v1':
    self.assertTrue(__import__('sys').dont_write_bytecode,'maintained runner requires -B')
    actual=set()
    for path in package.rglob('*'):
     if path.relative_to(package).parts[0]=='tests':continue
     self.assertFalse(path.is_symlink(),'symlink kernel asset: '+str(path))
     if path.is_dir():continue
     self.assertTrue(path.is_file(),'nonregular kernel asset: '+str(path))
     if path not in {package/'README.md',manifest_path}:actual.add(path)
    self.assertEqual(set(listed),actual,'exact kernel non-test asset membership')
   for path,row in listed.items():
    self.assertFalse(path.is_symlink());raw=path.read_bytes();self.assertEqual(len(raw),row['bytes']);self.assertEqual(__import__('hashlib').sha256(raw).hexdigest(),row['sha256'])
   allowed.extend([package/'python',package/'tests'])
  for path in ROOT.rglob('*.py'):
   self.assertFalse(path.is_symlink());self.assertTrue(any(path.is_relative_to(directory) for directory in allowed),str(path))
 def test_shell_entrypoints_keep_every_fixed_positional_interface_and_execution_flag(self):
  for name,expected in BINDINGS.items():
   with self.subTest(name=name):
    source=(BASE/name).read_text();tokens=[shlex.split(line.strip()) for line in source.splitlines() if 'python3 ' in line]
    actual=[row for row in tokens if row[:1]==['python3'] or row[:2] in (['exec','python3'],['if','python3'])]
    self.assertEqual(actual,[shlex.split(line) for line in expected]);self.assertNotIn("<<'PY",source)
    if name!='health.sh':self.assertIn('export BASE\n',source)
 def test_standalone_shell_and_python_entrypoints_parse_without_execution(self):
  for path in sorted(BASE.glob('*.sh'))+[ROOT/'run-admission.sh']:
   with self.subTest(path=path.name):
    result=subprocess.run(['bash','-n',str(path)],capture_output=True,text=True,timeout=2);self.assertEqual(result.returncode,0,result.stderr)
  for path in (BASE/'python').glob('*.py'):ast.parse(path.read_text(),filename=str(path))
if __name__=='__main__':unittest.main()
