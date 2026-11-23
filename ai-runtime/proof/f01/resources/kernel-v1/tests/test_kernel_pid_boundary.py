"""Typed kernel-view counterexamples; no native/runtime/resource proof."""
import copy
import importlib.util
from pathlib import Path
import unittest

PATH = (Path(__file__).parents[1] / 'python' / 'kernel_observer.py')
if PATH.exists():
    spec = importlib.util.spec_from_file_location('kernel_observer', PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
else:
    module = None


def view():
    return {'eventMode': 'v2-failing-limit-local', 'parent': '/ancestor/pod', 'groups': {
        '/ancestor/pod': {'identity': [1, 10], 'max': 256, 'events': 0, 'localEvents': 0},
        '/ancestor/pod/scope': {'identity': [1, 11], 'max': None, 'events': 0, 'localEvents': 0}},
        'nrDescendants': 1, 'nrDyingDescendants': 0,
        'seedCgroups': ['/ancestor/pod/scope'] * 3, 'ociPids': [None, None],
        'ancestors': {'/ancestor': {'identity': [1, 2], 'max': 127089,
                                  'current': 77, 'peak': 339, 'peakWritable': False}}}


class PidBoundary(unittest.TestCase):
    def check(self, value):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        return module.validate_pid_view(value)

    def reject(self, value, reason):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        with self.assertRaisesRegex(module.ProofError, '^' + reason + '$'):
            module.validate_pid_view(value)

    def delta(self, before, after):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        return module.pid_denial_delta(before, after)

    def test_finite_ancestor_never_reached_cannot_be_denial_origin(self):
        self.assertEqual(self.check(view()), '/ancestor/pod/scope')

    def test_missing_or_noninteger_local_counter_is_invalid(self):
        for value in (None, -1, True):
            with self.subTest(value=value):
                item = view();item['groups'][item['parent']]['localEvents'] = value
                self.reject(item, 'CGROUP_TOPOLOGY')

    def test_legacy_mode_is_not_an_accepted_modern_view(self):
        item = view();item['eventMode'] = 'legacy'
        self.reject(item, 'PID_EVENT_MODE')

    def test_other_descendant_limit_cannot_masquerade_as_parent_refusal(self):
        value = view();value['groups']['/ancestor/pod/other'] = {'identity': [1, 12], 'max': 128, 'events': 1, 'localEvents': 0}
        value['nrDescendants'] = 2
        self.reject(value, 'DESCENDANT_PID_LIMIT')

    def test_fork_scope_itself_must_not_hide_lower_limit(self):
        value = view();value['groups']['/ancestor/pod/scope']['max'] = 128
        self.reject(value, 'DESCENDANT_PID_LIMIT')

    def test_higher_descendant_limits_preserve_the_exact_parent_boundary(self):
        for limit in (257, 28834):
            with self.subTest(limit=limit):
                value = view();value['groups']['/ancestor/pod/scope']['max'] = limit
                self.assertEqual(self.check(value), '/ancestor/pod/scope')
                value['groups']['/ancestor/pod/other'] = {
                    'identity': [1, 12], 'max': limit, 'events': 0, 'localEvents': 0}
                value['nrDescendants'] = 2
                self.assertEqual(self.check(value), '/ancestor/pod/scope')

    def test_equal_lower_or_invalid_descendant_limit_is_not_the_parent_boundary(self):
        for limit in (True, False, -1, 0, 128, 255, 256, '28834', 28834.0, 2 ** 63):
            with self.subTest(limit=limit):
                value = view();value['groups']['/ancestor/pod/scope']['max'] = limit
                self.reject(value, 'DESCENDANT_PID_LIMIT')

    def test_higher_child_events_without_parent_local_denial_grant_no_credit(self):
        before = view();before['groups']['/ancestor/pod/scope']['max'] = 28834
        after = copy.deepcopy(before)
        after['groups']['/ancestor/pod']['events'] = 1
        after['groups']['/ancestor/pod/scope']['events'] = 1
        after['groups']['/ancestor/pod/scope']['localEvents'] = 1
        with self.assertRaisesRegex(module.ProofError, '^PID_DENIAL_EVENT_UNPROVEN$'):
            self.delta(before, after)

    def test_higher_child_limit_still_requires_actual_parent_local_denial(self):
        before = view();before['groups']['/ancestor/pod/scope']['max'] = 28834
        after = copy.deepcopy(before)
        after['groups']['/ancestor/pod']['events'] = 1
        after['groups']['/ancestor/pod']['localEvents'] = 1
        self.assertEqual(self.delta(before, after),
                         {'parentLocal': 1, 'parentHierarchical': 1, 'forkLocal': 0})

    def test_directory_count_or_bound_mismatch_is_not_valid_topology(self):
        for count in (0, 17):
            with self.subTest(count=count):
                value = view();value['nrDescendants'] = count
                self.reject(value, 'CGROUP_TOPOLOGY')

    def test_oci_pid_limit_must_not_introduce_another_boundary(self):
        for index in (0, 1):
            with self.subTest(spec=index):
                value = view();value['ociPids'][index] = {'limit': 128}
                self.reject(value, 'OCI_PID_LIMIT')

    def test_all_measured_runtime_seeds_must_share_declared_fork_scope(self):
        value = view();value['seedCgroups'][2] = '/other-pod'
        self.reject(value, 'SEED_SCOPE')

    def test_parent_limit_must_remain_exact256(self):
        value = view();value['groups']['/ancestor/pod']['max'] = 257
        self.reject(value, 'POD_PID_LIMIT')

    def test_local_legacy_event_is_not_silently_replaced_by_parent_zero(self):
        before = view();after = copy.deepcopy(before);after['groups']['/ancestor/pod/scope']['events'] = 1
        with self.assertRaisesRegex(module.ProofError, '^PID_DENIAL_EVENT_UNPROVEN$'):
            self.delta(before, after)

    def test_hierarchical_parent_event_can_bind_sole_reached_boundary(self):
        before = view();after = copy.deepcopy(before);after['groups']['/ancestor/pod']['events'] = 1
        after['groups']['/ancestor/pod']['localEvents'] = 1
        self.assertEqual(self.delta(before, after), {'parentLocal': 1, 'parentHierarchical': 1, 'forkLocal': 0})

    def test_no_positive_owned_event_is_not_enforcement_credit(self):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        with self.assertRaisesRegex(module.ProofError, '^PID_DENIAL_EVENT_UNPROVEN$'):
            self.delta(view(), view())

    def test_event_reset_and_object_substitution_stop(self):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        before = view();before['groups']['/ancestor/pod/scope']['events'] = 2
        after = copy.deepcopy(before);after['groups']['/ancestor/pod/scope']['events'] = 1
        with self.assertRaisesRegex(module.ProofError, '^PID_EVENT_RESET$'):
            self.delta(before, after)
        after = copy.deepcopy(before);after['groups']['/ancestor/pod/scope']['identity'] = [1, 99]
        after['groups']['/ancestor/pod/scope']['events'] = 3
        with self.assertRaisesRegex(module.ProofError, '^CGROUP_IDENTITY$'):
            self.delta(before, after)

    def test_changed_ancestor_limit_is_not_immutable_boundary_proof(self):
        self.assertIsNotNone(module, 'kernel boundary implementation is absent')
        before = view();after = copy.deepcopy(before)
        after['ancestors']['/ancestor']['max'] += 1
        after['groups']['/ancestor/pod/scope']['events'] = 1
        with self.assertRaisesRegex(module.ProofError, '^ANCESTOR_IDENTITY$'):
            self.delta(before, after)


if __name__ == '__main__':
    unittest.main()
