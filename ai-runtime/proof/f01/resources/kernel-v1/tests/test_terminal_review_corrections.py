"""Causal regressions for reviewed terminal and supplemental-owner failures."""
import copy
import types
import unittest
from unittest.mock import patch
import test_terminal_capture as captured
import test_terminal_parent_endpoint as parent
import test_collector_scratch_metadata as scratch

m=captured.m


class TerminalCorrections(unittest.TestCase):
    fixture=captured.Capture.fixture
    capture=captured.Capture.capture
    feature=captured.Capture.feature
    def test_failed_attempt_always_persists_rejected_fixed_metadata(self):
        for fault in ('foreign-owner','start-deadline','unexpected-reader','retained-fd'):
            t,terminal,_,_=self.fixture()
            if fault=='foreign-owner':terminal['cid']='f'*64
            if fault=='start-deadline':t.observation_deadline=112.
            if fault=='unexpected-reader':
                t.measurement.read_terminal_parent=lambda:(_ for _ in ()).throw(ValueError('private-body'))
            if fault=='retained-fd':
                error=parent.m.ProofError('CGROUP_IDENTITY');error.__cause__=FileNotFoundError('private-path')
                t.measurement.read_terminal_parent=lambda:(_ for _ in ()).throw(error)
                t.parent.check_retained=lambda:(_ for _ in ()).throw(parent.m.ProofError('CGROUP_OWNER'))
            with self.subTest(fault=fault),patch.object(m.time,'monotonic',side_effect=[112.1,112.2]),self.assertRaises(AssertionError):
                self.feature(t)(terminal)
            records=[record for name,record in t.saved if name=='owned-terminal-endpoint.json']
            self.assertEqual(len(records),1,fault)
            self.assertEqual(records[0]['status'],'REJECTED')
            self.assertIsNone(records[0]['value'])
            self.assertNotIn('private',str(records[0]))

    def test_process_missing_parent_never_credits_earlier_positive_live_events(self):
        t,terminal,_,_=self.fixture();t.control='process-limit'
        error=parent.m.ProofError('CGROUP_IDENTITY');error.__cause__=FileNotFoundError('parent gone')
        t.measurement.read_terminal_parent=lambda:(_ for _ in ()).throw(error);t.parent.check_retained=lambda:False
        self.capture(t,terminal)
        before,last,_=parent.TerminalPidDelta().setup_rows();last=copy.deepcopy(before)
        root=before['pidView']['parent']
        last['counters']['pids.events']['max']=3;last['counters']['pids.events.local']['max']=2
        last['pidView']['groups'][root].update(events=3,localEvents=2)
        for i,row in enumerate((before,last)):
            row.update(status='verified',sample=i,monotonic=111.+i/10,counterReadStart=111.+i/10,
                       rootProjection={'count':10})
        t.rows=[before,last];t.stream=types.SimpleNamespace(finish=lambda _emit:None,buffer=types.SimpleNamespace(raw=b''))
        t.gate=types.SimpleNamespace(complete=True,last=110.)
        t.pod=lambda:{'status':{'phase':'Succeeded','containerStatuses':[{'state':{'terminated':{'exitCode':0}}}]}}
        t.outcomes={'qualify':lambda *_args:self.fail('live-only process fallback reached oracle')}
        result={'samples':t.rows,'terminal':terminal,'quiescence':None}
        with patch.object(m.time,'monotonic',return_value=112.3),self.assertRaisesRegex(AssertionError,'PROCESS_TERMINAL_ENDPOINT_UNPROVEN'):
            t.finish(result)

    def test_terminal_events_cannot_reset_below_last_complete_live_endpoint(self):
        for field,key in (('pids.events','events'),('pids.events.local','localEvents')):
            before,last,terminal=parent.TerminalPidDelta().setup_rows();root=before['pidView']['parent']
            last['counters'][field]['max']=terminal['counters'][field]['max']+1
            last['pidView']['groups'][root][key]=last['counters'][field]['max']
            with self.subTest(field=field),self.assertRaisesRegex(parent.m.ProofError,'PID_EVENT_RESET'):
                parent.m.terminal_pid_denial_delta(before,terminal,last)


class ScratchFenceCorrections(unittest.TestCase):
    setUp=scratch.CollectorScratchMetadataTest.setUp
    def test_transient_fence_failure_cannot_be_hidden_by_metadata_or_later_recovery(self):
        for phase in ('prepare','before','fill'):
            for error_type in (AssertionError,ValueError):
                with self.subTest(phase=phase,error=error_type.__name__):
                    self.trial.scratch_before_attempted=self.trial.scratch_fill_attempted=False
                    self.trial.scratch_fence_error=None
                    calls=[];failure=error_type('ORIGINAL_OWNER_FAILURE')
                    def fence():
                        calls.append(1)
                        if len(calls)==1:raise failure
                        return 'LIVE'
                    self.trial.fence=fence
                    if phase=='prepare':
                        old=self.trial.scratch_metadata.bind_scratch
                        def factory(*args):
                            try:args[-1]()
                            except Exception:pass
                            return None
                        self.trial.scratch_metadata.bind_scratch=factory
                        operation=lambda:self.trial.prepare_scratch_metadata({})
                    else:
                        self.trial.prepare_scratch_metadata({})
                        self.holders[-1].sequence=0 if phase=='before' else 1
                        self.holders[-1].baseline_available=phase=='fill'
                        operation=self.trial.scratch_before_go if phase=='before' else lambda:self.trial.scratch_fill_held('FILL_BYTES 4096')
                    with self.assertRaises(error_type) as caught:operation()
                    self.assertIs(caught.exception,failure)
                    self.assertEqual(self.trial.fence(),'LIVE')
                    if phase=='prepare':self.trial.scratch_metadata.bind_scratch=old

    def test_nonlive_supplemental_fence_is_latched_even_if_next_check_recovers(self):
        self.trial.fence=lambda:'EXITED'
        self.trial.prepare_scratch_metadata({})
        with self.assertRaisesRegex(AssertionError,'SCRATCH_OWNER_NOT_LIVE'):self.trial.scratch_before_go()
        self.trial.fence=lambda:'LIVE'
        with self.assertRaisesRegex(AssertionError,'SCRATCH_OWNER_NOT_LIVE'):self.trial.scratch_fill_held('FILL_BYTES 4096')


if __name__=='__main__':unittest.main()
