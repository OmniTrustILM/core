"""Evaluate the fixed CEL namespace equality against every rendered profile."""
import copy,importlib.util,json,os
from pathlib import Path
import unittest
P=Path(__file__).parents[1]/'python/fixture_builder.py'
spec=importlib.util.spec_from_file_location('metadata_fixture',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
BASE=(Path(__file__).parents[2] / 'v1')
class NamespaceClosure(unittest.TestCase):
    def assert_closed_authorities(self, value):
        def walk(value, parent=None, key=None):
            if isinstance(value, dict):
                for name, child in value.items():
                    walk(name);walk(child, value, name)
            elif isinstance(value, list):
                for child in value:walk(child)
            elif isinstance(value, str):
                if key=='handler' and isinstance(parent,dict) and parent.get('kind')=='RuntimeClass' and value=='runsc-f01-a2-v1':return
                if 'ilm-sandbox-a2' in value:self.fail('STALE_NAMESPACE')
                if 'runsc-f01-a2-v1' in value:self.fail('STALE_RUNTIME_CLASS')
                if 'f01-a2-v1' in value:self.fail('STALE_POLICY')
        walk(value)
    def emitted_objects_and_pods(self):
        v=m.build_fixture(BASE)
        return {'objects':v['namespace']['items']+v['policy']['items'],'pods':list(v['profiles'].values())}
    def test_entire_eight_objects_and_six_pods_have_no_stale_authority_tokens(self):
        v=self.emitted_objects_and_pods();self.assertEqual((len(v['objects']),len(v['pods'])),(8,6));self.assert_closed_authorities(v)
    def test_stale_match_constraints_variable_validation_binding_class_or_pod_is_detected(self):
        baseline=self.emitted_objects_and_pods();self.assert_closed_authorities(baseline)
        for fault,reason in [('matchConstraints','STALE_NAMESPACE'),('variable','STALE_NAMESPACE'),('validation','STALE_RUNTIME_CLASS'),('binding','STALE_POLICY'),('class','STALE_RUNTIME_CLASS'),('pod','STALE_NAMESPACE'),('key','STALE_POLICY')]:
            with self.subTest(fault=fault):
                v=copy.deepcopy(baseline);policy=next(x for x in v['objects'] if x['kind']=='ValidatingAdmissionPolicy')
                if fault=='matchConstraints':policy['spec']['matchConstraints']['namespaceSelector']={'matchLabels':{'kubernetes.io/metadata.name':'ilm-sandbox-a2'}}
                elif fault=='variable':policy['spec']['variables'][0]['expression']='object.metadata.namespace == "ilm-sandbox-a2"'
                elif fault=='validation':policy['spec']['validations'][0]['expression']='object.spec.runtimeClassName == "runsc-f01-a2-v1"'
                elif fault=='binding':next(x for x in v['objects'] if x['kind']=='ValidatingAdmissionPolicyBinding')['spec']['policyName']='f01-a2-v1'
                elif fault=='class':next(x for x in v['objects'] if x['kind']=='RuntimeClass')['metadata']['name']='runsc-f01-a2-v1'
                elif fault=='pod':v['pods'][0]['metadata']['namespace']='ilm-sandbox-a2'
                else:policy['spec']['variables'][0]['f01-a2-v1']='untrusted-key'
                with self.assertRaisesRegex(AssertionError,'^'+reason+'$'):self.assert_closed_authorities(v)
    def test_actual_first_metadata_clause_matches_all_six_new_pod_namespaces(self):
        v=m.build_fixture(BASE);row=next(x for x in v['policy']['items'][0]['spec']['validations'] if x['message']=='F01_METADATA')
        clause=row['expression'].split(' && ',1)[0];lhs,separator,literal=clause.partition(' == ');self.assertEqual((lhs,separator),('object.metadata.namespace',' == '))
        accepted_namespace=json.loads(literal)
        for name,pod in v['profiles'].items():
            with self.subTest(profile=name):self.assertEqual(accepted_namespace,pod['metadata']['namespace'])
    def test_only_namespace_literal_changes_in_full_metadata_validation(self):
        original=json.loads((BASE/'pod-floor.yaml').read_bytes())['items'][0]['spec']['validations'];old=next(x for x in original if x['message']=='F01_METADATA');expected=copy.deepcopy(old)
        self.assertEqual(old['expression'].count(json.dumps('ilm-sandbox-a2')),1)
        expected['expression']=old['expression'].replace(json.dumps('ilm-sandbox-a2'),json.dumps('ilm-resource-sec-r1'))
        v=m.build_fixture(BASE);actual=next(x for x in v['policy']['items'][0]['spec']['validations'] if x['message']=='F01_METADATA')
        self.assertEqual(actual,expected)
if __name__=='__main__':unittest.main()
