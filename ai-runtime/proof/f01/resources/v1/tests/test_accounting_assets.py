import json
import os
from pathlib import Path
import unittest
import bootstrap as bootstrap

SOURCE=Path(os.environ['F01_CANDIDATE_SOURCE'])
OLD=Path(__file__).parent/'testdata/previous-profiles'

def tuple_text(p):
    c=p['spec']['containers'][0]
    return '(object.metadata.name == '+json.dumps(p['metadata']['name'])+' && object.metadata.labels["ilm.ai/proof"] == "a2-v1" && variables.c.command == ['+', '.join(map(json.dumps,c['command']))+'] && variables.c.args == ['+json.dumps(c['args'][0])+'])'

class AccountingAssets(unittest.TestCase):
    def test_old_memory_and_cpu_tuples_are_no_longer_allowlisted(self):
        policy=json.loads((SOURCE/'resources/v1/pod-floor.yaml').read_text())
        expression=next(v['expression'] for v in policy['items'][0]['spec']['validations'] if v['message']=='F01_EXECUTABLE')
        for control in ('memory-control','cpu-control'):
            old=json.loads((OLD/f'{control}.json').read_text())
            with self.subTest(control=control):self.assertNotIn(tuple_text(old),expression)

class SubstitutionCounts(unittest.TestCase):
    def test_common_fixed_substitution_rejects_missing_or_duplicate_target(self):
        import ast
        path=Path(__file__).with_name('asset_substitution.py')
        node=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='replace_once')
        ns={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),ns)
        self.assertEqual(ns['replace_once']('before X after','X','Y'),'before Y after')
        for text in ('before after','X then X'):
            with self.subTest(text=text),self.assertRaises(AssertionError):ns['replace_once'](text,'X','Y')

if __name__=='__main__':unittest.main()
