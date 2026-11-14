"""New immediate owned capture, never reuse of the retained unqualified diagnostic."""
import copy
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import test_kernel_trial as trial_module
import test_terminal_parent_endpoint as parent
import test_high_outcomes as outcomes

m=trial_module.m


class Capture(unittest.TestCase):
    def fixture(self):
        measurement,before=parent.TerminalParent().start()
        value=measurement.read_terminal_parent()
        data=outcomes.fixture('scratch-a')
        t=m.Trial.__new__(m.Trial);t.control='scratch-a';t.target=data['target']
        t.observation_deadline=t.deadline=130.;t.terminal_endpoint_attempted=False
        t.terminal_endpoint_record=None;t.terminal_endpoint_error=None
        t.parent=types.SimpleNamespace(root=Path('/cg/ancestor/pod'),identity=[1,20],check_retained=lambda:True)
        t.owner={'parent':{'path':'/cg/ancestor/pod','identity':[1,20]}}
        t.measurement=types.SimpleNamespace(read_terminal_parent=lambda:copy.deepcopy(value))
        t.kernel=parent.m;t.saved=[]
        t.save=lambda name,record:t.saved.append((name,copy.deepcopy(record)))
        terminal=dict(data['terminal'],status='CONFIRMED_TERMINAL',monotonic=112.)
        terminal.pop('podPhase');terminal.pop('podReason')
        return t,terminal,value,before

    def feature(self,t):
        capture=getattr(t,'capture_terminal_endpoint',None)
        self.assertIsNotNone(capture,'fresh first-terminal capture missing')
        return capture

    def capture(self,t,terminal):
        with patch.object(m.time,'monotonic',side_effect=[112.1,112.2]):self.feature(t)(terminal)

    def test_first_capture_binds_target_terminal_read_times_and_owned_parent_without_live_view(self):
        t,terminal,value,_=self.fixture();self.capture(t,terminal)
        with patch.object(m.time,'monotonic',return_value=112.3):
            result=t.read_terminal_endpoint()
        self.assertEqual(result,value)
        record=t.terminal_endpoint_record
        self.assertEqual(record['schema'],'f01-owned-terminal-endpoint-v1')
        self.assertEqual(record['target'],t.target)
        self.assertEqual(record['readStartedMonotonic'],112.1)
        self.assertEqual(record['readFinishedMonotonic'],112.2)
        self.assertIs(record['fullF01Accepted'],False)
        self.assertNotIn('pidView',result)
        with self.assertRaisesRegex(AssertionError,'TERMINAL_CAPTURE_REUSED'):self.feature(t)(terminal)

    def test_foreign_old_diagnostic_floor_identity_and_deadline_changes_are_not_salvaged(self):
        for fault in ('target','schema','floor','parent','late'):
            t,terminal,_,_=self.fixture();self.capture(t,terminal)
            if fault=='target':t.target=dict(t.target,cid='f'*64)
            if fault=='schema':t.terminal_endpoint_record['schema']='UNQUALIFIED_TERMINAL_PARENT_COUNTERS'
            if fault=='floor':t.terminal_endpoint_record['value']['counters']['memory.swap.max']=['1']
            if fault=='parent':t.parent.identity=[1,999]
            if fault=='late':t.terminal_endpoint_record['readFinishedMonotonic']=130.
            with self.subTest(fault=fault),patch.object(m.time,'monotonic',return_value=112.3),self.assertRaises(AssertionError):
                t.read_terminal_endpoint()

    def test_missing_parent_preserves_exact_error_cause_for_existing_positive_event_fallback_only(self):
        t,terminal,_,_=self.fixture()
        try:raise FileNotFoundError('original bound parent disappeared')
        except FileNotFoundError as missing:error=parent.m.ProofError('CGROUP_IDENTITY');error.__cause__=missing
        def read():raise error
        t.measurement.read_terminal_parent=read
        t.parent.check_retained=lambda:False
        self.capture(t,terminal)
        with patch.object(m.time,'monotonic',return_value=112.3),self.assertRaises(parent.m.ProofError) as caught:
            t.read_terminal_endpoint()
        self.assertIs(caught.exception,error)
        self.assertIsInstance(caught.exception.__cause__,FileNotFoundError)

    def test_missing_counter_file_under_present_parent_cannot_enter_positive_event_fallback(self):
        t,terminal,_,_=self.fixture()
        try:raise FileNotFoundError('counter file missing while parent remains')
        except FileNotFoundError as missing:error=parent.m.ProofError('COUNTER_PATH');error.__cause__=missing
        def read():raise error
        t.measurement.read_terminal_parent=read
        with patch.object(m.time,'monotonic',side_effect=[112.1,112.2]),self.assertRaisesRegex(parent.m.ProofError,'COUNTER_PATH'):
            self.feature(t)(terminal)

    def test_disappeared_parent_fallback_still_needs_actual_positive_live_oom_and_rejects_reappeared_path(self):
        for positive in (False,True):
            t,terminal,_,before=self.fixture();t.control='memory-limit'
            try:raise FileNotFoundError('parent gone')
            except FileNotFoundError as missing:error=parent.m.ProofError('CGROUP_IDENTITY');error.__cause__=missing
            def read():raise error
            t.measurement.read_terminal_parent=read;t.parent.check_retained=lambda:False
            self.capture(t,terminal)
            first=dict(copy.deepcopy(before),status='verified');last=copy.deepcopy(first)
            if positive:last['counters']['memory.events'].update(max=1,oom=1,oom_kill=1)
            with patch.object(m.time,'monotonic',return_value=112.3):
                if positive:
                    endpoint=parent.m.final_endpoint('memory-limit',[first,last],t.read_terminal_endpoint,t.check_terminal_endpoint,quiescence=None)
                    self.assertEqual(endpoint['basis'],'LAST_VALID_POSITIVE_EVENT')
                else:
                    with self.assertRaisesRegex(parent.m.ProofError,'FINAL_EVENT_UNPROVEN'):
                        parent.m.final_endpoint('memory-limit',[first,last],t.read_terminal_endpoint,t.check_terminal_endpoint,quiescence=None)
                t.parent.check_retained=lambda:True
                with self.assertRaisesRegex(AssertionError,'TERMINAL_PARENT_NOT_ABSENT'):t.read_terminal_endpoint()

    def test_confirmed_terminal_captures_before_retained_unqualified_diagnostics(self):
        t,terminal,value,_=self.fixture();events=[]
        self.feature(t)
        t.container=lambda:{'status':{'state':'CONTAINER_EXITED','exitCode':0,
            'finishedAt':terminal['finishedAt'],'reason':'Completed'}}
        t.measurement.read_terminal_parent=lambda:events.append('NEW_CAPTURE') or value
        t.retain_terminal_parent=lambda:events.append('OLD_UNQUALIFIED_DIAGNOSTIC')
        with patch.object(m.time,'monotonic',return_value=112.):t.terminal()
        self.assertEqual(events,['NEW_CAPTURE','OLD_UNQUALIFIED_DIAGNOSTIC'])

    def test_retained_fd_enoent_is_not_parent_disappearance_even_with_old_positive_oom(self):
        t,terminal,_,before=self.fixture();t.control='memory-limit';self.capture(t,terminal)
        def missing_fd():
            try:raise FileNotFoundError('retained descriptor unavailable')
            except FileNotFoundError as cause:raise parent.m.ProofError('CGROUP_IDENTITY') from cause
        t.parent.check_retained=missing_fd
        first=dict(copy.deepcopy(before),status='verified');last=copy.deepcopy(first)
        last['counters']['memory.events'].update(max=1,oom=1,oom_kill=1)
        with patch.object(m.time,'monotonic',return_value=112.3),self.assertRaisesRegex(AssertionError,'TERMINAL_RETAINED_CUSTODY'):
            parent.m.final_endpoint('memory-limit',[first,last],t.read_terminal_endpoint,t.check_terminal_endpoint,quiescence=None)

    def test_cpu_and_calibration_do_not_gain_a_terminal_counter_endpoint(self):
        for control in ('cpu-deadline','memory-control'):
            t,terminal,_,_=self.fixture();t.control=control;self.feature(t)
            t.container=lambda:{'status':{'state':'CONTAINER_EXITED','exitCode':0,
                'finishedAt':terminal['finishedAt'],'reason':'Completed'}}
            t.measurement.read_terminal_parent=lambda:self.fail('postwindow credit forbidden')
            t.retain_terminal_parent=lambda:None
            with patch.object(m.time,'monotonic',return_value=112.):t.terminal()
            self.assertIsNone(t.terminal_endpoint_record)


if __name__=='__main__':unittest.main()
