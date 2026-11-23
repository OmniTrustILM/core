"""Desired independent correction behavior against frozen rejected production bytes."""
import copy
import errno
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as bootstrap
import test_accounting_producer as prior_producer
import test_accounting_collection as prior_collection
from test_observer_ownership import Inputs


class Publication(prior_producer.ProducerInputs, unittest.TestCase):
    def put(self, counters, queries):
        (self.out/'observation/counters.jsonl').write_bytes(counters)
        (self.out/'observation/guest-pids.jsonl').write_bytes(queries)

    def wires(self):
        return [json.dumps(row).encode()+b'\n' for row in self.rows], [json.dumps(q).encode()+b'\n' for q in self.query_rows()]

    def pending(self):
        result = self.ns['accounting_samples'](self.out, 130.0, 'memory')
        self.assertIsNone(result, 'active incomplete pair promoted a complete prefix')
        with self.assertRaises(AssertionError):
            self.ns['accounting_samples'](self.out, 130., 'memory', final=True)

    def test_query_first_complete_record_waits_for_counter_pair(self):
        counters, queries = self.wires()
        self.put(b''.join(counters[:1]), b''.join(queries[:2]))
        self.pending()

    def test_bounded_partial_tail_on_either_file_is_pending_without_prefix_promotion(self):
        counters, queries = self.wires()
        for which in ('counter', 'query'):
            with self.subTest(which=which):
                self.put(counters[0]+(counters[1][:17] if which == 'counter' else b''),
                         queries[0]+(queries[1][:17] if which == 'query' else b''))
                self.pending()

    def test_complete_malformed_or_invalid_row_is_fatal_even_while_active(self):
        counters, queries = self.wires()
        for raw in (b'not-json\n', counters[0].replace(b'"verified"', b'"invalid"'),
                    b'x'*65537+b'\n'):
            with self.subTest(rawBytes=len(raw)):
                self.put(raw, queries[0])
                with self.assertRaises((AssertionError, ValueError)):
                    self.ns['accounting_samples'](self.out,130.,'memory')

    def test_final_incomplete_or_active_oversized_records_are_never_pending_success(self):
        counters, queries = self.wires()
        for a, b in ((counters[0], b''.join(queries[:2])), (counters[0][:-1], queries[0])):
            self.put(a,b)
            with self.assertRaises(AssertionError):
                self.ns['accounting_samples'](self.out,130.,'memory',final=True)
        self.put(counters[0]+b'x'*65537, queries[0])
        with self.assertRaises(AssertionError):
            self.ns['accounting_samples'](self.out,130.,'memory')
        self.put(b'not-json\n'+b'{', queries[0])
        with self.assertRaises((AssertionError,ValueError)):
            self.ns['accounting_samples'](self.out,130.,'memory')

    def test_actual_verified_pair_flushes_query_before_counter(self):
        subject = prior_collection.AccountingCollection()
        subject.setUp(); self.addCleanup(subject.doCleanups)
        subject.responses = [prior_collection.table(prior_collection.roles()), prior_collection.table([])]
        writes = []; real_open = Path.open
        class Output:
            def __init__(s, stream, label): s.stream, s.label = stream, label
            def __enter__(s): return s
            def __exit__(s,*args): return s.stream.__exit__(*args)
            def write(s, raw): return s.stream.write(raw)
            def flush(s):
                s.stream.flush(); writes.append(s.label)
        def opened(path, mode='r', *args, **kwargs):
            stream = real_open(path, mode, *args, **kwargs)
            if mode == 'w' and path.name in ('counters.jsonl','guest-pids.jsonl'):
                return Output(stream,path.name)
            return stream
        with patch.object(Path, 'open', opened): subject.collect()
        self.assertEqual(writes[:2], ['guest-pids.jsonl','counters.jsonl'])


class CaptureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name); self.i = Inputs(self.out)

    def test_busy_partial_snapshot_never_enters_successful_mapping_history(self):
        failed = []
        def seed():
            if self.i.capture_count == 1:
                failed.append(copy.deepcopy(self.i.records[40]))
                self.i.records[40]['startTicks'] = 401
                raise self.i.ns['RuntimeStateBusy'](errno.EAGAIN, 'synthetic owned lock contention')
        self.i.seed_hook = seed
        self.i.observe()
        history = self.i.read('mapping.json')['observations']
        self.assertTrue(failed)
        self.assertTrue(all('roles' in row['snapshot'] for row in history),
                        'failed/partial diagnostic snapshot was published as ownership history')
        self.assertTrue(all(row['snapshot']['records']['40']['startTicks'] == 401 for row in history))
        self.assertEqual(self.i.read('host-members.json')[-1]['startTicks'], 401)


class GateCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name); self.i = Inputs(self.out); self.ns = self.i.ns
        self.i.target['name'] = self.i.attached['name'] = 'f01-a2-memory-control'
        snapshot = self.i.real_capture(self.i.attached,self.i.group,self.i.binaries,self.i.seeds,self.i.projections,lambda _:None)
        mapping = self.i.mapping | {'target': self.i.attached, 'runtimeType':'io.containerd.runsc.v1',
            'binaries':self.i.binaries, 'runtimeSeeds':self.i.projections, 'observations':[{'snapshot':snapshot}]}
        (self.out/'observation').mkdir(); (self.out/'observation/mapping.json').write_text(json.dumps(mapping))
        self.owner = self.ns['accounting_owner'](self.out,self.i.target)[1]
        self.original_proc = self.ns['proc']
        self.ns['proc'] = lambda pid,tid=None: {'startTicks':9000} if pid == 900 else self.original_proc(pid,tid)
        self.in_capture=False
        original_capture=self.ns['capture']
        def capture(*args):
            self.in_capture=True
            try:return original_capture(*args)
            finally:self.in_capture=False
        self.ns['capture']=capture
        self.requests = []
        def request(out,label,args,deadline):
            self.requests.append((args,deadline))
            value = json.loads(self.i.command(args))
            if args[:2] == ['k3s','kubectl']:
                value['metadata'].update(name=self.i.target['name'],namespace='ilm-sandbox-a2')
                value['status'].update(phase='Running')
                value['status']['containerStatuses'][0].update(restartCount=0,name='fixed-proof',state={'running':{}})
            return json.dumps(value).encode()
        self.ns['accounting_call'] = request

    def verify(self):
        return self.ns['accounting_verify'](self.out,self.i.target,self.owner,900,9000,1,130.)

    def test_transient_busy_restarts_complete_fresh_capture_under_original_deadline(self):
        def seed():
            if self.in_capture and self.i.capture_count == 1:
                self.i.records[40]['startTicks'] = 401
                raise self.ns['RuntimeStateBusy'](errno.EWOULDBLOCK,'synthetic owned lock contention')
        self.i.seed_hook = seed
        self.verify()
        self.assertEqual(self.i.capture_count,2)
        final = json.loads((self.out/'gate1-ownership.json').read_text())
        self.assertIn('roles',final); self.assertEqual(final['records']['40']['startTicks'],401)
        self.assertTrue(all(deadline == 130. for _,deadline in self.requests))
        self.assertLess(self.i.clock.monotonic(),130.)

    def test_persistent_busy_stops_at_two_attempts_without_verified_snapshot(self):
        def seed():
            if self.in_capture:
                raise self.ns['RuntimeStateBusy'](errno.EAGAIN,'synthetic owned lock contention')
        self.i.seed_hook = seed
        with self.assertRaises(BlockingIOError): self.verify()
        self.assertEqual(self.i.capture_count,2,'persistent gate conflict must have exactly two attempts')
        path = self.out/'gate1-ownership.json'
        self.assertFalse(path.exists() and 'roles' in json.loads(path.read_text()))

    def test_failed_gate_capture_is_not_the_verified_ownership_receipt(self):
        def seed():
            if self.in_capture:
                raise self.ns['RuntimeStateBusy'](errno.EAGAIN,'synthetic owned lock contention')
        self.i.seed_hook = seed
        with self.assertRaises(BlockingIOError): self.verify()
        path = self.out/'gate1-ownership.json'
        self.assertFalse(path.exists(), 'partial capture diagnostic occupied the successful ownership receipt')

    def test_deadline_after_first_conflict_prevents_second_capture(self):
        def seed():
            if not self.in_capture: return
            self.i.clock.value = 130.
            raise self.ns['RuntimeStateBusy'](errno.EAGAIN,'synthetic owned lock contention')
        self.i.seed_hook = seed
        # Either conservative stop is valid; exception class is not the deadline proof.
        with self.assertRaises((AssertionError, BlockingIOError)):
            self.verify()
        self.assertEqual(self.i.capture_count,1)
        self.assertEqual(self.i.clock.monotonic(),130.)
        self.assertTrue(all(deadline == 130. for _,deadline in self.requests))

    def test_postcapture_deadline_or_owner_drift_never_publishes_verified_receipt(self):
        for fault in ('deadline','owner'):
            with self.subTest(fault=fault):
                self.setUp();original=self.ns['capture']
                def capture(*args):
                    if fault=='owner':self.i.records[10]['startTicks']=101
                    value=original(*args)
                    if fault=='deadline':self.i.clock.value=130.
                    return value
                self.ns['capture']=capture
                with self.assertRaises(AssertionError):self.verify()
                self.assertFalse((self.out/'gate1-ownership.json').exists())

    def test_diagnostic_note_and_noncontention_errors_never_retry(self):
        for kind in ('note','other-eagain','permission'):
            with self.subTest(kind=kind):
                self.setUp()
                error = self.ns['RuntimeStateBusy'](errno.EAGAIN,'busy') if kind == 'note' else (
                    BlockingIOError(errno.EAGAIN,'unrelated proc I/O') if kind == 'other-eagain' else PermissionError(errno.EACCES,'denied'))
                if kind == 'note': error.add_note('capture diagnostic failed: synthetic storage failure')
                def seed():
                    if self.in_capture: raise error
                self.i.seed_hook = seed
                with self.assertRaises(type(error)) as caught: self.verify()
                self.assertIs(caught.exception,error)
                self.assertEqual(self.i.capture_count,1)


if __name__ == '__main__': unittest.main()
