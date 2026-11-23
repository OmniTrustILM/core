"""Synthetic cross-profile contract checks; no native runtime/security credit."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).parents[3]
K=ROOT/'resources/kernel-v1'
sys.path.insert(0,str(K/'tests'))
import test_high_outcomes as outcomes

class ApprovedCutoffTest(unittest.TestCase):
    def test_all_qualifying_runner_profiles_have_the_same_27_second_native_cutoff(self):
        paths=[ROOT/'profile/v1/pod.yaml']+sorted((ROOT/'resources/v1/profiles').glob('*.yaml'))+sorted((K/'fixtures/profiles').glob('*.json'))
        for path in paths:
            raw=path.read_text()
            if path.suffix=='.yaml' and raw.lstrip().startswith('apiVersion:'):
                self.assertIn('activeDeadlineSeconds: 27',raw,str(path))
                self.assertNotIn('activeDeadlineSeconds: 180',raw,str(path))
            else:
                value=json.loads(raw)
                self.assertIs(type(value['spec']['activeDeadlineSeconds']),int,str(path))
                self.assertEqual(value['spec']['activeDeadlineSeconds'],27,str(path))
                self.assertEqual(value['spec']['terminationGracePeriodSeconds'],1,str(path))
    def test_all_qualifying_runner_cel_policies_require_exact_27(self):
        for path in [ROOT/'admission/v1/pod-floor.yaml',ROOT/'resources/v1/pod-floor.yaml',K/'fixtures/policy.json']:
            value=json.loads(path.read_text())
            expressions=[row['expression'] for item in value['items'] if item['kind']=='ValidatingAdmissionPolicy' for row in item['spec']['validations']]
            deadline=[x for x in expressions if 'variables.s.activeDeadlineSeconds ==' in x]
            self.assertEqual(len(deadline),1)
            self.assertIn('variables.s.activeDeadlineSeconds == 27',deadline[0])
    def test_cpu_qualifier_preserves_original_reference_and_inclusive_27_31_bounds(self):
        for stamp,status,reason in [('26.999999999','STOP','PREMATURE_NATIVE_DEADLINE'),('27','OBSERVED',None),('31','OBSERVED',None),('31.000000001','STOP','NATIVE_DEADLINE_LATE')]:
            data=outcomes.fixture('cpu-deadline');data['terminal']['finishedAt']='2026-11-04T19:00:'+stamp+'Z'
            result=outcomes.qualify('cpu-deadline',data)
            self.assertEqual(status,result['status'],stamp)
            if reason:self.assertEqual(reason,result['reason'])
        data=outcomes.fixture('cpu-deadline');data['supervisorIntervened']=True
        self.assertEqual(outcomes.qualify('cpu-deadline',data)['status'],'STOP')

if __name__=='__main__':unittest.main()
