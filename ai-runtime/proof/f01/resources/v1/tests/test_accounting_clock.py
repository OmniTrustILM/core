"""Actual CLI handoff and private-file clock loading; no runtime transport."""
import contextlib
import copy
import datetime
import json
import os
import pathlib
import types
import unittest
from unittest.mock import patch
import test_accounting_collection as collection


class AccountingClock(unittest.TestCase):
    def setUp(self):
        self.fixture=collection.AccountingCollection('test_continues_beyond_one_second_and_binds_queries_only_to_verified_rows')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.inputs=self.fixture.inputs;self.out=self.fixture.out
        start=datetime.datetime.fromisoformat(self.inputs.target['startTime'].replace('Z','+00:00')).timestamp()
        self.clock={'podStartTime':self.inputs.target['startTime'],'monotonic':99.,'realtime':start+1,'deadlineMonotonic':128.}
        self.path=self.out.parent/'outer-clock.json'

    @contextlib.contextmanager
    def root_owner(self,uid=0):
        fstat=os.fstat;lstat=pathlib.Path.lstat
        def owned(st):
            fields={k:getattr(st,k) for k in dir(st) if k.startswith('st_')}
            fields['st_uid']=uid
            return types.SimpleNamespace(**fields)
        with patch.object(os,'fstat',lambda fd:owned(fstat(fd))),patch.object(pathlib.Path,'lstat',lambda p:owned(lstat(p))):
            yield

    def write_clock(self,value=None):
        self.path.write_text(json.dumps(self.clock if value is None else value));self.path.chmod(0o600)

    def collect(self,unchanged=lambda:None):
        i=self.inputs
        i.ns['observe'](i.attached,self.out,i.mapping,copy.deepcopy(i.records[10]),i.measurements,i.binaries,i.seeds,i.projections,
                        unchanged=unchanged,continuous=True,outer_clock=self.clock)

    def test_cli_passes_exact_existing_clock_into_continuous_collector(self):
        calls=[];loaded=[]
        self.inputs.ns['load_outer_clock']=lambda path,t:(loaded.append((str(path),t.copy())) or self.clock,lambda:None)
        self.inputs.ns['observe']=lambda *args,**kwargs:calls.append((args,kwargs))
        self.out.rmdir()
        self.inputs.main()
        self.assertEqual(loaded,[('/synthetic-window',self.inputs.target)])
        self.assertEqual(len(calls),1)
        self.assertTrue(calls[0][1]['continuous'])
        self.assertIs(calls[0][1]['outer_clock'],self.clock)
        self.assertIsNone(calls[0][0][8])

    def test_cli_missing_accounting_clock_stops_before_attachment_or_queries(self):
        self.out.rmdir()
        self.inputs.ns['sys']=types.SimpleNamespace(argv=['observer','/synthetic-target',str(self.out)])
        with self.assertRaisesRegex(AssertionError,'accounting requires explicit outer clock'):self.inputs.ns['main']()
        self.assertEqual(self.inputs.events,[])
        self.assertEqual(self.inputs.capture_count,0)

    def test_explicit_clock_deadline_is_not_reconstructed_from_later_wall_time(self):
        self.collect()
        self.assertEqual(self.inputs.read('clock.json')['deadlineMonotonic'],128.)
        result=self.inputs.read('observer-result.json')
        self.assertEqual(result['deadlineMonotonic'],128.)
        self.assertLess(result['finishedMonotonic'],128.)
        self.assertEqual(self.inputs.read('clock.json')['outerClock'],self.clock)

    def test_clock_is_immutable_before_any_owned_capture(self):
        def changed():raise AssertionError('observation input changed')
        with self.assertRaisesRegex(AssertionError,'observation input changed'):self.collect(changed)
        self.assertEqual(self.inputs.capture_count,0)

    def test_clock_change_during_query_cannot_promote_row_or_witness(self):
        changed=False
        command=self.inputs.ns['command']
        def query(*args,**kwargs):
            nonlocal changed
            raw=command(*args,**kwargs);changed=True;return raw
        def unchanged():
            if changed:raise AssertionError('observation input changed')
        self.inputs.ns['command']=query
        with self.assertRaisesRegex(AssertionError,'observation input changed'):self.collect(unchanged)
        self.assertEqual(self.inputs.read_counter_rows()[0]['status'],'invalid')
        self.assertEqual((self.out/'guest-pids.jsonl').read_text(),'')
        self.fixture.no_result()

    def test_actual_private_clock_bytes_load_and_closure_detects_replacement(self):
        self.write_clock()
        with self.root_owner():
            value,unchanged=self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)
            self.assertEqual(value,self.clock);unchanged()
            self.path.write_text(json.dumps(dict(self.clock,deadlineMonotonic=129.)))
            with self.assertRaisesRegex(AssertionError,'observation input changed'):unchanged()

    def test_clock_change_during_validation_is_detected_before_loader_returns(self):
        self.write_clock()
        def change():
            self.path.write_text(json.dumps(dict(self.clock,deadlineMonotonic=129.)))
            return 100.
        self.inputs.clock.monotonic=change
        with self.root_owner(),self.assertRaisesRegex(AssertionError,'observation input changed'):
            self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)

    def test_clock_semantic_mismatches_never_load(self):
        variants=[dict(self.clock,podStartTime='2026-10-27T00:00:01Z'),dict(self.clock,extra=1),
                  dict(self.clock,monotonic=True),dict(self.clock,realtime=float('nan')),
                  dict(self.clock,deadlineMonotonic=float('inf')),dict(self.clock,deadlineMonotonic=129.),
                  dict(self.clock,monotonic=101.,deadlineMonotonic=130.),dict(self.clock,deadlineMonotonic=100.)]
        for value in variants:
            with self.subTest(value=value):
                self.write_clock(value)
                with self.root_owner(),self.assertRaises(AssertionError):self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)

    def test_clock_file_shape_and_duplicate_key_are_rejected(self):
        self.write_clock()
        with self.root_owner():
            self.path.chmod(0o640)
            with self.assertRaises(AssertionError):self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)
            self.path.chmod(0o600)
            self.path.write_text(json.dumps(self.clock)[:-1]+',"monotonic":99}')
            with self.assertRaisesRegex(AssertionError,'duplicate input key'):self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)
            self.path.write_text(' '*4097)
            with self.assertRaises(AssertionError):self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)
        self.write_clock()
        with self.root_owner(uid=501),self.assertRaises(AssertionError):self.inputs.ns['load_outer_clock'](self.path,self.inputs.target)
        link=self.path.with_name('link');link.symlink_to(self.path)
        with self.root_owner(),self.assertRaises(OSError):self.inputs.ns['load_outer_clock'](link,self.inputs.target)

    def test_expired_consistent_clock_stops_before_collection(self):
        self.clock.update(monotonic=70.,realtime=self.clock['realtime']-1,deadlineMonotonic=100.)
        with self.assertRaisesRegex(AssertionError,'outer clock expired or incomparable'):self.collect()
        self.assertEqual(self.inputs.capture_count,0)

    def test_outer_clock_cannot_enable_noncontinuous_collection(self):
        i=self.inputs
        original_sentry=copy.deepcopy(i.records[10])
        with self.assertRaisesRegex(AssertionError,'outer clock requires continuous collection'):
            i.ns['observe'](i.attached,self.out,i.mapping,original_sentry,i.measurements,i.binaries,i.seeds,i.projections,outer_clock=self.clock)
        self.assertEqual(i.capture_count,0)

    def test_programmatic_outer_clock_cannot_select_floor_or_noncontinuous_mode(self):
        self.inputs.attached['name']='f01-a2-floor-control'
        with self.assertRaises(AssertionError):self.collect()
        self.fixture.no_result()


if __name__=='__main__':unittest.main()
