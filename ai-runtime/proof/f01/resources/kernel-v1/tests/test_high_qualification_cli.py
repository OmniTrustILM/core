"""Actual isolated pure-outcome CLI over synthetic fixed collector records only."""
from pathlib import Path
import json,subprocess,sys,tempfile,unittest
from test_high_outcomes import fixture
SOURCE=Path(__file__).parents[1] / 'python/high_outcomes.py'
class QualificationCli(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.out=Path(self.temp.name)
 def prepare(self,control='scratch-a'):
  data=fixture(control);(self.out/'high-facts.json').write_text(json.dumps({k:v for k,v in data.items() if k!='logs'}));(self.out/'live.log').write_bytes(data['logs']);return data
 def invoke(self,control='scratch-a'):
  return subprocess.run([sys.executable,'-I','-S','-B',str(SOURCE),str(self.out),control],stdin=subprocess.DEVNULL,capture_output=True,timeout=3)
 def test_valid_record_publishes_only_conditional_outcome_with_false_full_acceptance(self):
  self.prepare();result=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
  target=self.out/'control-observation.json';self.assertTrue(target.exists(),'fixed qualification CLI absent')
  value=json.loads(target.read_text());self.assertEqual(value['status'],'OBSERVED');self.assertIs(value['fullF01Accepted'],False)
  self.assertEqual(value['claim'],'TMPFS_BOUNDARY_AND_SHARED_ALIAS');self.assertEqual(result.stdout,b'')
 def test_stop_record_is_retained_but_native_nonzero_never_qualifies(self):
  data=self.prepare();data['terminal']['uid']='wrong';(self.out/'high-facts.json').write_text(json.dumps({k:v for k,v in data.items() if k!='logs'}))
  result=self.invoke();self.assertEqual(result.returncode,1)
  self.assertIn(b'HIGH_OUTCOME_STOP',result.stderr);self.assertEqual(json.loads((self.out/'control-observation.json').read_text()),{'status':'STOP','reason':'INVALID_OWNER'})
 def test_unknown_control_refuses_before_private_input_access(self):
  result=self.invoke('unlisted');self.assertEqual(result.returncode,1)
  self.assertIn(b'HIGH_CONTROL',result.stderr);self.assertFalse((self.out/'control-observation.json').exists())
 def test_existing_result_cannot_be_replaced(self):
  self.prepare();target=self.out/'control-observation.json';target.write_bytes(b'previous-owned-result')
  result=self.invoke();self.assertEqual(result.returncode,1);self.assertEqual(target.read_bytes(),b'previous-owned-result')
 def test_oversized_facts_stop_before_json_parse(self):
  self.prepare();(self.out/'high-facts.json').write_bytes(b' '*8388609)
  result=self.invoke();self.assertEqual(result.returncode,1);self.assertIn(b'HIGH_FACT_BYTES',result.stderr)
  self.assertFalse((self.out/'control-observation.json').exists())
 def test_unsupported_interpreter_modes_cannot_publish_intervened_outcomes(self):
  modes = [('-I', '-S', '-B', '-O'), ('-I', '-S', '-B', '-OO'),
           ('-S', '-B'), ('-I', '-B'), ('-I', '-S')]
  for index, flags in enumerate(modes):
   with self.subTest(flags=flags):
    directory = self.out / str(index);directory.mkdir()
    data = fixture('scratch-a');data['supervisorIntervened'] = True
    (directory/'high-facts.json').write_text(json.dumps({key:value for key,value in data.items() if key!='logs'}))
    (directory/'live.log').write_bytes(data['logs'])
    result = subprocess.run([sys.executable, *flags, str(SOURCE), str(directory), 'scratch-a'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=3,
        env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C'})
    self.assertNotEqual(result.returncode, 0)
    self.assertIn(b'HIGH_INTERPRETER_MODE', result.stderr)
    self.assertFalse((directory/'control-observation.json').exists())
if __name__=='__main__':unittest.main()
