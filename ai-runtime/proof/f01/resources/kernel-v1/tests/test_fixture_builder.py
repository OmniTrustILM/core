"""Fixed tuple renderer/golden program bindings, not Kubernetes admission proof."""
import copy
import os
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import shutil
import tempfile

PATH = (Path(__file__).parents[1] / 'python' / 'fixture_builder.py')
BASE = (Path(__file__).parents[2] / 'v1')
if PATH.exists():
    spec = importlib.util.spec_from_file_location('fixture_builder', PATH)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
else: module = None


class Builder(unittest.TestCase):
    def feature(self):
        self.assertIsNotNone(module, 'fixed fixture builder absent')
        return module

    def test_reference_root_is_required_and_has_no_machine_default(self):
        with self.assertRaises(TypeError):
            self.feature().build_fixture()

    def relocated_references(self):
        temp = tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve() / 'selected';root.mkdir()
        for name in self.feature().SOURCE_PINS:
            target = root / name;target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BASE / name, target)
        return root

    def test_relocated_reference_renders_reviewed_eight_mib_calibration_body(self):
        root = self.relocated_references()
        value = self.feature().build_fixture(root)
        self.assertEqual(hashlib.sha256(value['golden']['memory-control'].encode()).hexdigest(),
                         'bcb795badb1a580fd7279c1d7bf869d3267852775b9797c70a0c9b6b0a671d48')
        self.assertEqual(set(value['profiles']), {'memory-control', 'process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b'})

    def test_relative_missing_and_symlink_reference_roots_are_rejected(self):
        root = self.relocated_references();alias = root.parent / 'alias';alias.symlink_to(root, target_is_directory=True)
        for selected in (Path('relative'), root / 'absent', alias):
            with self.subTest(selected=selected):
                with self.assertRaisesRegex(ValueError, '^REFERENCE_ROOT$'):
                    self.feature().build_fixture(selected)

    def test_corrupt_selected_reference_cannot_fall_back_to_original_root(self):
        root = self.relocated_references();path = root / 'namespace.yaml'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, '^REFERENCE_SOURCE_CHANGED$'):
            self.feature().build_fixture(root)


    def test_one_pass_kubelet_expansion_and_unknown_variables(self):
        m = self.feature()
        self.assertEqual(m.expand('$$ $(KNOWN) $(MISSING) $plain $(', {'KNOWN': 'value'}), '$ value $(MISSING) $plain $(')
        self.assertEqual(m.expand('$$(KNOWN) $$$$', {'KNOWN': 'untrusted'}), '$(KNOWN) $$')

    def test_literal_encoder_preserves_program_even_with_service_environment(self):
        m = self.feature();program = 'x=$$; echo $x $(KUBERNETES_SERVICE_HOST) $((x+1))'
        stored = m.encode(program)
        self.assertEqual(m.expand(stored, {'KUBERNETES_SERVICE_HOST': 'hostile', '(x+1': 'wrong'}), program)

    def test_eight_mib_calibration_delivered_program_has_exact_reviewed_bytes(self):
        m = self.feature();rendered = m.build_fixture(BASE)
        body = rendered['golden']['memory-control']
        self.assertEqual(len(body.encode()), 5450)
        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), 'bcb795badb1a580fd7279c1d7bf869d3267852775b9797c70a0c9b6b0a671d48')

    def test_calibration_changes_only_the_closed_payload_loop_bound(self):
        rendered = self.feature().build_fixture(BASE)
        original = json.loads((BASE / 'profiles/memory-control.yaml').read_bytes())['spec']['containers'][0]['args'][0]
        original = self.feature().expand(original, {})
        expected = original.replace('for (i=1; i<=1024; i++)', 'for (i=1; i<=2048; i++)')
        self.assertNotEqual(expected, original)
        self.assertEqual(rendered['golden']['memory-control'], expected)
        self.assertEqual(self.feature().expand(rendered['profiles']['memory-control']['spec']['containers'][0]['args'][0], {}),
                         expected)

    def test_every_high_workload_suffix_is_unchanged_after_fixed_start_gate(self):
        m = self.feature();rendered = m.build_fixture(BASE)
        for name in ('process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b'):
            with self.subTest(name=name):
                original = json.loads((BASE / 'profiles' / (name + '.yaml')).read_bytes())['spec']['containers'][0]['args'][0]
                self.assertTrue(rendered['golden'][name].endswith(original))
                self.assertGreater(len(rendered['golden'][name]), len(original))
                self.assertEqual(m.expand(rendered['profiles'][name]['spec']['containers'][0]['args'][0], {'ANY': 'hostile'}), rendered['golden'][name])

    def test_only_six_fixed_profiles_in_fresh_namespace_keep_original_security_floor(self):
        m = self.feature();rendered = m.build_fixture(BASE)
        self.assertEqual(set(rendered['profiles']), {'memory-control', 'process-limit', 'memory-limit', 'cpu-deadline', 'scratch-a', 'scratch-b'})
        for name, pod in rendered['profiles'].items():
            with self.subTest(name=name):
                original = json.loads((BASE / 'profiles' / (name + '.yaml')).read_bytes())
                expected = copy.deepcopy(original)
                expected['metadata']['namespace'] = 'ilm-resource-sec-r1'
                expected['spec']['runtimeClassName'] = 'runsc-f01-kernel-cg-r1'
                expected['spec']['containers'][0]['args'] = pod['spec']['containers'][0]['args']
                self.assertEqual(pod, expected)

    def test_eight_authorities_are_new_scoped_bindings_same_runtime_handler(self):
        m = self.feature();rendered = m.build_fixture(BASE);items = rendered['namespace']['items'] + rendered['policy']['items']
        self.assertEqual(len(items), 8)
        binding = next(item for item in items if item['kind'] == 'ValidatingAdmissionPolicyBinding')
        self.assertEqual(binding['spec']['matchResources']['namespaceSelector'], {'matchLabels': {'kubernetes.io/metadata.name': 'ilm-resource-sec-r1'}})
        runtime = next(item for item in items if item['kind'] == 'RuntimeClass')
        self.assertEqual(runtime['metadata']['name'], 'runsc-f01-kernel-cg-r1')
        self.assertEqual(runtime['handler'], 'runsc-f01-a2-v1')
        deny = next(item for item in items if item['kind'] == 'GlobalNetworkPolicy')
        self.assertEqual(deny['spec']['selector'], "projectcalico.org/namespace == 'ilm-resource-sec-r1'")

    def test_all_other_admission_validation_and_variable_logic_is_retained(self):
        m = self.feature();rendered = m.build_fixture(BASE);old = json.loads((BASE / 'pod-floor.yaml').read_bytes())['items'][0]['spec'];new = rendered['policy']['items'][0]['spec']
        self.assertEqual(new['variables'], old['variables'])
        self.assertEqual(new['failurePolicy'], 'Fail')
        old_rows = {row['message']: row for row in old['validations']}
        for row in new['validations']:
            if row['message'] == 'F01_METADATA':
                expected = copy.deepcopy(old_rows[row['message']])
                expected['expression'] = expected['expression'].replace(json.dumps('ilm-sandbox-a2'), json.dumps('ilm-resource-sec-r1'))
                self.assertEqual(row, expected)
            elif row['message'] not in ('F01_POD_FIXED', 'F01_EXECUTABLE'):
                self.assertEqual(row, old_rows[row['message']])

    def test_committed_fixture_assets_match_the_closed_renderer(self):
        rendered = self.feature().build_fixture(BASE)
        root = Path(__file__).parents[1] / 'fixtures'
        for name in ('namespace', 'policy'):
            with self.subTest(asset=name):
                self.assertEqual(json.loads((root / (name + '.json')).read_bytes()), rendered[name])
        for control in self.feature().CONTROLS:
            with self.subTest(control=control):
                self.assertEqual(json.loads((root / 'profiles' / (control + '.json')).read_bytes()),
                                 rendered['profiles'][control])
                self.assertEqual((root / 'golden' / (control + '.sh')).read_text(),
                                 rendered['golden'][control])

    def test_renderer_has_no_source_mutation(self):
        m = self.feature();paths = [BASE / 'namespace.yaml', BASE / 'pod-floor.yaml'] + list((BASE / 'profiles').glob('*.yaml'))
        before = {str(path): path.read_bytes() for path in paths}
        first = m.build_fixture(BASE);second = m.build_fixture(BASE)
        self.assertEqual(first, second)
        self.assertEqual({str(path): path.read_bytes() for path in paths}, before)


if __name__ == '__main__': unittest.main()
