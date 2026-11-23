"""New-target local limiting-cgroup criterion; native calibration is a prerequisite."""
import copy
import unittest
import test_kernel_pid_boundary as previous
m = previous.module

def view():
    value = previous.view()
    value['eventMode'] = 'v2-failing-limit-local'
    for group in value['groups'].values(): group['localEvents'] = 0
    return value

class Modern(unittest.TestCase):
    def positive(self):
        before = view();after = copy.deepcopy(before)
        after['groups'][after['parent']]['localEvents'] = 1
        return before, after
    def test_actual_parent_local_delta_is_authoritative_without_crossfile_atomicity(self):
        before, after = self.positive()
        self.assertEqual(m.pid_denial_delta(before, after), {'parentLocal': 1, 'parentHierarchical': 0, 'forkLocal': 0})
    def test_hierarchical_or_origin_only_event_cannot_prove_actual_parent_limit(self):
        for origin in ('parent', 'fork'):
            with self.subTest(origin=origin):
                before = view();after = copy.deepcopy(before)
                key = after['parent'] if origin == 'parent' else after['seedCgroups'][0]
                after['groups'][key]['events'] = 1
                if origin == 'fork': after['groups'][key]['localEvents'] = 1
                with self.assertRaisesRegex(m.ProofError, '^PID_DENIAL_EVENT_UNPROVEN$'):
                    m.pid_denial_delta(before, after)
    def test_legacy_or_localevents_mode_is_not_accepted_by_new_target_contract(self):
        for mode in ('legacy', 'pids_localevents', None):
            with self.subTest(mode=mode):
                before, after = self.positive()
                before['eventMode'] = after['eventMode'] = mode
                after['groups'][after['parent']]['events'] = 1
                with self.assertRaisesRegex(m.ProofError, '^PID_EVENT_MODE$'):
                    m.pid_denial_delta(before, after)
    def test_peak_is_not_a_causal_certificate_or_required_headroom(self):
        before, after = self.positive()
        for value in (before, after):
            ancestor = value['ancestors']['/ancestor']
            ancestor['peak'] = ancestor['max'];ancestor['peakWritable'] = True
        self.assertEqual(m.pid_denial_delta(before, after)['parentLocal'], 1)
    def test_local_counter_reset_is_not_denial_credit(self):
        before, after = self.positive()
        before['groups'][before['parent']]['localEvents'] = 2
        with self.assertRaisesRegex(m.ProofError, '^PID_EVENT_RESET$'):
            m.pid_denial_delta(before, after)

if __name__ == '__main__': unittest.main()
