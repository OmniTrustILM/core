"""New owned endpoint capture; old live ownership predicates remain strict."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import test_kernel_measurement as measured
import test_high_outcomes as outcomes

m=measured.m


class TerminalParent(unittest.TestCase):
    def start(self):
        value=measured.Measurement().fixture()
        feature=getattr(value,'read_terminal_parent',None)
        self.assertIsNotNone(feature,'distinct held-parent terminal reader missing')
        with patch.object(m,'PodCgroup',measured.FakeGroup):before=value.read()
        return value,copy.deepcopy(before)

    def test_exited_scope_is_not_reopened_or_disguised_as_a_live_pid_view(self):
        value,before=self.start()
        with patch.object(measured.FakeGroup,'directory_limits',side_effect=AssertionError('live tree read forbidden')):
            terminal=value.read_terminal_parent()
        self.assertEqual(terminal['schema'],'f01-terminal-parent-counters-v1')
        self.assertEqual(terminal['parentOrigin'],[before['pidView']['parent'],[1,20]])
        self.assertNotIn('pidView',terminal)
        self.assertEqual(terminal['counters'],before['counters'])

    def test_missing_successful_origin_parent_identity_or_floor_never_qualifies(self):
        fresh=measured.Measurement().fixture()
        reader=getattr(fresh,'read_terminal_parent',None)
        self.assertIsNotNone(reader,'distinct held-parent terminal reader missing')
        with self.assertRaisesRegex(m.ProofError,'LIVE_ORIGIN_UNPROVEN'):reader()
        for fault,reason in [('identity','CGROUP_IDENTITY'),('floor','RESOURCE_FLOOR')]:
            value,_=self.start()
            if fault=='identity':measured.FakeGroup.identities['/cg/ancestor/pod']=[1,999]
            else:measured.FakeGroup.values['/cg/ancestor/pod']['memory.swap.max']=['1']
            with self.subTest(fault=fault),self.assertRaisesRegex(m.ProofError,reason):value.read_terminal_parent()

    def test_identity_change_during_counter_read_is_detected_after_read(self):
        value,_=self.start();original=measured.FakeGroup.read_field
        def read(group,name):
            result=original(group,name)
            if name=='cpu.stat':measured.FakeGroup.identities['/cg/ancestor/pod']=[1,999]
            return result
        with patch.object(measured.FakeGroup,'read_field',read),self.assertRaisesRegex(m.ProofError,'CGROUP_IDENTITY'):
            value.read_terminal_parent()


class TerminalPidDelta(unittest.TestCase):
    def setup_rows(self):
        value,before=TerminalParent().start();last=copy.deepcopy(before)
        counters=measured.FakeGroup.values['/cg/ancestor/pod']
        counters['pids.events']['max']=3;counters['pids.events.local']['max']=2
        return before,last,value.read_terminal_parent()

    def feature(self):
        feature=getattr(m,'terminal_pid_denial_delta',None)
        self.assertIsNotNone(feature,'actual terminal parent-local delta producer missing')
        return feature

    def test_actual_positive_terminal_local_delta_never_invents_exited_child_counter(self):
        feature=self.feature();before,last,terminal=self.setup_rows()
        self.assertEqual(feature(before,terminal,last),{'parentLocal':2,'parentHierarchical':3,'forkLocal':None})

    def test_only_actual_live_scope_with_exact_parent_endpoint_agreement_provides_fork_local(self):
        feature=self.feature();before,last,terminal=self.setup_rows();parent=before['pidView']['parent']
        last['counters']=copy.deepcopy(terminal['counters'])
        last['pidView']['groups'][parent].update(events=3,localEvents=2)
        self.assertEqual(feature(before,terminal,last),{'parentLocal':2,'parentHierarchical':3,'forkLocal':0})
        terminal['counters']['pids.events']['max']+=1
        self.assertIsNone(feature(before,terminal,last)['forkLocal'])

    def test_hierarchical_only_stale_nonzero_reset_wrong_parent_or_fake_live_scope_refuse(self):
        feature=self.feature()
        for fault in ('hierarchical','old-nonzero','reset','parent','live-scope','schema'):
            before,last,terminal=self.setup_rows();parent=before['pidView']['parent']
            if fault=='hierarchical':terminal['counters']['pids.events.local']['max']=0
            if fault=='old-nonzero':
                before['counters']['pids.events.local']['max']=2
                before['pidView']['groups'][parent]['localEvents']=2
                last=copy.deepcopy(before)
            if fault=='reset':terminal['counters']['pids.events.local']['max']=-1
            if fault=='parent':terminal['parentOrigin'][1]=[1,999]
            if fault=='live-scope':last['pidView']['seedCgroups'][-1]='/foreign'
            if fault=='schema':terminal['schema']='UNQUALIFIED_TERMINAL_PARENT_COUNTERS'
            with self.subTest(fault=fault),self.assertRaises(m.ProofError):feature(before,terminal,last)

    def test_existing_exec_refusal_oracle_rejects_unavailable_fork_and_unmatched_window(self):
        self.feature()
        data=outcomes.exec_refusal_fixture();data['pidDenialEvents']['forkLocal']=None
        self.assertEqual(outcomes.qualify('process-limit',data),{'status':'STOP','reason':'PID_DENIAL_EVENTS'})
        data=outcomes.exec_refusal_fixture();data['samples'][-1]['counters']['pids.events']['max']+=1
        self.assertEqual(outcomes.qualify('process-limit',data),{'status':'STOP','reason':'PID_DENIAL_WINDOW'})


if __name__=='__main__':unittest.main()
