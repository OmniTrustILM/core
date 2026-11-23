"""Opt-in collection: synthetic host inputs, real ownership, counter and terminal flow."""
import copy
import json
import pathlib
import subprocess
import tempfile
import unittest
from test_observer_ownership import Inputs
from domain_fixtures import table,roles


class AccountingCollection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = pathlib.Path(self.tmp.name)/'out';self.out.mkdir()
        self.inputs = Inputs(self.out)
        self.inputs.target['name'] = self.inputs.attached['name'] = 'f01-a2-memory-control'
        self.queries = []
        self.responses = [table(roles())]*15 + [table(roles()[:1])]*15 + [table([])]
        self.terminal_exit = 0
        self.terminal_state = "CONTAINER_EXITED"
        self.terminal_calls = []
        original = self.inputs.command
        def command(args, **kwargs):
            if 'ps' in args:
                started = self.inputs.clock.monotonic()
                raw = self.responses.pop(0) if self.responses else table(roles()[:1])
                self.inputs.clock.value += .002
                self.queries.append((started,self.inputs.clock.monotonic(),raw))
                if isinstance(raw,Exception):raise raw
                return raw.encode() if kwargs.get('raw') else raw
            self.terminal_calls.append((args.copy(), kwargs.get('timeout')))
            value = json.loads(original(args, **kwargs))
            value['status'].update(state=self.terminal_state,exitCode=self.terminal_exit,finishedAt='2026-10-27T00:00:05Z')
            return json.dumps(value)
        self.inputs.ns['command'] = command

    def collect(self):
        i=self.inputs
        return i.ns['observe'](i.attached,self.out,i.mapping,copy.deepcopy(i.records[10]),i.measurements,
                               i.binaries,i.seeds,i.projections,continuous=True)

    def no_result(self):
        self.assertFalse((self.out/'observer-result.json').exists())

    def test_continues_beyond_one_second_and_binds_queries_only_to_verified_rows(self):
        self.collect()
        rows=self.inputs.read_counter_rows()
        queries=[json.loads(line) for line in (self.out/'guest-pids.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows),30);self.assertEqual(len(queries),len(rows))
        self.assertGreater(rows[-1]['counterReadStart']-rows[0]['counterReadEnd'],2)
        self.assertEqual([q['pids'] for q in queries],[[101,102]]*15+[[101]]*15)
        for row,q,(start,end,raw) in zip(rows,queries,self.queries):
            self.assertEqual(row['status'],'verified');self.assertEqual(q['sample'],row['sample'])
            self.assertIn('queryStartedMonotonic',q,'verified evidence lacks actual query/read binding')
            self.assertEqual((q['queryStartedMonotonic'],q['queryReceivedMonotonic']),(start,end))
            self.assertEqual(q['rawResponse'],raw)
            self.assertEqual((q['counterReadStart'],q['counterReadEnd']),(row['counterReadStart'],row['counterReadEnd']))
            self.assertLessEqual(row['monotonic'],start);self.assertLessEqual(end,row['counterReadStart'])
        result=self.inputs.read('observer-result.json')
        self.assertEqual(result['status'],'CONTINUOUS_COLLECTION_FINISHED')
        self.assertEqual(result['lastSample'],rows[-1]['sample'])
        for key in ('counterReadStart','counterReadEnd'):self.assertEqual(result[key],rows[-1][key])
        self.assertEqual(result['terminal']['exitCode'],0);self.assertEqual(self.inputs.capture_count,61)
        self.assertIn('guestQuery',result['terminal'],'terminal empty query must remain diagnostic, not a verified sample')
        start,end,raw=self.queries[-1]
        self.assertEqual(result['terminal']['guestQuery'],{'queryStartedMonotonic':start,'queryReceivedMonotonic':end,'rawResponse':raw,'pids':[]})
        self.assertLess(result['finishedMonotonic'],result['deadlineMonotonic'])

    def test_query_failure_while_target_running_never_finishes_or_promotes_prior_verified_rows(self):
        self.terminal_state = "CONTAINER_RUNNING"
        self.responses=[table(roles()),RuntimeError('unknown query')]
        with self.assertRaisesRegex(RuntimeError,'unknown query'):self.collect()
        self.assertEqual(len(self.inputs.read_counter_rows()),1);self.no_result()
        self.assertFalse((self.out/'terminal.json').exists())

    def test_invalid_counter_row_never_publishes_its_query_as_verified_witness(self):
        original=self.inputs.canonical
        def broken(path):
            base=original(path)
            if not str(path).startswith('/sys/fs/cgroup'):return base
            class Counter:
                def __truediv__(self,name):raise OSError('counter unavailable')
            return Counter()
        self.inputs.ns['canonical']=broken
        with self.assertRaisesRegex(OSError,'counter unavailable'):self.collect()
        self.assertEqual(self.inputs.read_counter_rows()[0]['status'],'invalid')
        self.assertEqual((self.out/'guest-pids.jsonl').read_text(),'');self.no_result()

    def test_empty_initial_population_cannot_finish_with_zero_rows(self):
        self.responses=[table([])]
        with self.assertRaisesRegex(AssertionError,'no verified counter samples'):self.collect()
        self.no_result()

    def test_nonzero_exact_terminal_cannot_finish_collection(self):
        self.responses=[table(roles()),table([])];self.terminal_exit=7
        with self.assertRaisesRegex(AssertionError,'continuous container did not exit normally'):self.collect()
        self.no_result()

    def test_running_terminal_read_is_not_absence_or_normal_completion(self):
        original=self.inputs.ns['command']
        def running(args,**kwargs):
            raw=original(args,**kwargs)
            if 'inspect' in args:
                value=json.loads(raw);value['status']['state']='CONTAINER_RUNNING';return json.dumps(value)
            return raw
        self.inputs.ns['command']=running;self.responses=[table(roles()),table([])]
        with self.assertRaisesRegex(AssertionError,'exact container is not confirmed terminal'):self.collect()
        self.no_result()

    def test_deadline_without_normal_terminal_never_returns_success(self):
        self.responses=[table(roles())]*301
        with self.assertRaisesRegex(AssertionError,'continuous collection did not finish'):self.collect()
        self.no_result();self.assertLessEqual(len(self.inputs.read_counter_rows()),300)

    def test_row_cap_without_terminal_cannot_finish_with_remaining_deadline(self):
        self.responses=[table(roles())]*301
        self.inputs.ns['time'].sleep=lambda delay:None
        with self.assertRaisesRegex(AssertionError,'continuous collection did not finish'):self.collect()
        self.assertEqual(len(self.inputs.read_counter_rows()),300)
        self.assertLess(self.inputs.clock.monotonic(),130.)
        self.no_result()

    def test_terminal_read_crossing_original_deadline_cannot_finish(self):
        self.responses=[table(roles()),table([])]
        original=self.inputs.ns['command']
        def late(args,**kwargs):
            raw=original(args,**kwargs)
            if 'inspect' in args:self.inputs.clock.value=130.
            return raw
        self.inputs.ns['command']=late
        with self.assertRaisesRegex(AssertionError,'terminal read exceeded original deadline'):self.collect()
        self.no_result()

    def test_query_crossing_original_deadline_has_no_row_or_witness(self):
        original=self.inputs.ns['command']
        def late(args,**kwargs):
            raw=original(args,**kwargs)
            if 'ps' in args:self.inputs.clock.value=130.
            return raw
        self.inputs.ns['command']=late
        with self.assertRaisesRegex(AssertionError,'query exceeded original deadline'):self.collect()
        self.assertEqual(self.inputs.read_counter_rows(),[])
        self.assertEqual((self.out/'guest-pids.jsonl').read_text(),'');self.no_result()

    def test_oversized_raw_response_cannot_supply_a_witness(self):
        self.responses=[' '*4097+table(roles())]
        with self.assertRaisesRegex(AssertionError,'accounting query exceeds diagnostic bound'):self.collect()
        self.no_result()

    def test_continuous_mode_cannot_replace_process_or_floor_contract(self):
        self.inputs.attached['name']='f01-a2-process-control'
        with self.assertRaisesRegex(AssertionError,'continuous requires accounting target without live window'):self.collect()
        self.assertEqual(self.inputs.capture_count,0);self.no_result()


    def query_terminal_fixture(self):
        self.responses = [table(roles())] * 15 + [table(roles()[:1])] * 15
        error = RuntimeError('synthetic nonzero exact runsc ps')
        self.responses.append(error)
        return error

    def test_nonzero_exact_query_can_only_finish_from_owned_terminal0_without_query_credit(self):
        self.query_terminal_fixture()
        self.collect()
        rows = self.inputs.read_counter_rows()
        queries = [json.loads(x) for x in (self.out/'guest-pids.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 30)
        self.assertEqual(len(queries), 30)
        self.assertTrue(all(x['status'] == 'verified' for x in rows))
        self.assertEqual([x['sample'] for x in rows], list(range(30)))
        self.assertEqual([x['sample'] for x in queries], list(range(30)))
        diagnostic = self.inputs.read('terminal-query-failure.json')
        self.assertEqual(diagnostic['status'], 'UNVERIFIED_TERMINAL_QUERY')
        self.assertEqual(diagnostic['failure'], 'RuntimeError')
        self.assertLessEqual(diagnostic['queryStartedMonotonic'], diagnostic['failedMonotonic'])
        result = self.inputs.read('observer-result.json')
        self.assertEqual(result['lastSample'], rows[-1]['sample'])
        for key in ('counterReadStart', 'counterReadEnd'):
            self.assertEqual(result[key], rows[-1][key])
        terminal = self.inputs.read('terminal.json')
        self.assertEqual((terminal['cid'], terminal['uid'], terminal['exitCode']),
                         (self.inputs.target['cid'], self.inputs.target['uid'], 0))
        self.assertEqual(result['terminal'], terminal)
        self.assertEqual(self.inputs.capture_count, 61)
        self.assertEqual(len(self.terminal_calls), 1)
        self.assertEqual(self.terminal_calls[0][0], ['k3s','crictl','inspect',self.inputs.target['cid']])
        self.assertGreater(self.terminal_calls[0][1], 0)
        self.assertLessEqual(self.terminal_calls[0][1], 2)
        self.assertEqual(len(self.queries), 31)
        self.assertFalse((self.out/'control-observation.json').exists())
        self.assertLess(result['finishedMonotonic'], result['deadlineMonotonic'])

    def test_failed_query_terminal_mismatch_keeps_original_error_and_no_terminal_credit(self):
        for fault in ('running','cid','uid','name','namespace','container-name','nonzero','old-finish','deadline','inspect-error'):
            with self.subTest(fault=fault):
                subject = AccountingCollection()
                subject.setUp()
                self.addCleanup(subject.doCleanups)
                error = subject.query_terminal_fixture()
                original = subject.inputs.ns['command']
                def command(args, **kwargs):
                    if 'inspect' in args and fault == 'inspect-error':
                        raise RuntimeError('synthetic failed terminal inspect')
                    raw = original(args, **kwargs)
                    if 'inspect' not in args:return raw
                    value = json.loads(raw);status = value['status']
                    if fault == 'running':status['state'] = 'CONTAINER_RUNNING'
                    if fault == 'cid':status['id'] = 'c'*64
                    if fault in ('uid','name','namespace'):status['labels']['io.kubernetes.pod.'+fault] = 'wrong'
                    if fault == 'container-name':status['metadata']['name'] = 'wrong'
                    if fault == 'nonzero':status['exitCode'] = 7
                    if fault == 'old-finish':status['finishedAt'] = '2026-10-26T00:00:00Z'
                    if fault == 'deadline':subject.inputs.clock.value = 130.
                    return json.dumps(value)
                subject.inputs.ns['command'] = command
                with self.assertRaises(RuntimeError) as caught:subject.collect()
                self.assertIs(caught.exception, error)
                self.assertEqual(len(subject.inputs.read_counter_rows()),30)
                self.assertTrue(all(x['status']=='verified' for x in subject.inputs.read_counter_rows()))
                self.assertFalse((subject.out/'terminal.json').exists())
                subject.no_result()
                self.assertEqual(subject.inputs.capture_count,61)

    def test_query_timeout_cannot_reconcile_even_when_terminal_inspection_would_return0(self):
        self.query_terminal_fixture()
        self.responses[-1] = subprocess.TimeoutExpired(['runsc','ps'],2)
        with self.assertRaises(subprocess.TimeoutExpired):self.collect()
        self.assertEqual(self.terminal_calls,[])
        self.assertFalse((self.out/'terminal.json').exists())
        self.no_result()

    def test_runtime_error_outside_exact_query_call_cannot_reconcile(self):
        original = self.inputs.atomic
        error = RuntimeError('synthetic startup diagnostic precheck')
        def atomic(path,value):
            if path.name == 'accounting-startup.json':raise error
            return original(path,value)
        self.inputs.ns['atomic_json'] = atomic
        with self.assertRaises(RuntimeError) as caught:self.collect()
        self.assertIs(caught.exception,error)
        self.assertEqual(self.terminal_calls,[])
        self.assertFalse((self.out/'terminal.json').exists())
        self.no_result()

    def test_postquery_error_after_verified_pairs_cannot_reconcile(self):
        self.query_terminal_fixture()
        original = self.inputs.ns['accounting_response']
        error = RuntimeError('synthetic postquery parser failure')
        def response(*args):
            if len(self.queries) == 31:raise error
            return original(*args)
        self.inputs.ns['accounting_response'] = response
        self.responses[-1] = table(roles()[:1])
        with self.assertRaises(RuntimeError) as caught:self.collect()
        self.assertIs(caught.exception,error)
        self.assertEqual(len(self.inputs.read_counter_rows()),30)
        self.assertEqual(len((self.out/'guest-pids.jsonl').read_text().splitlines()),30)
        self.assertEqual(len(self.queries),31)
        self.assertEqual(self.terminal_calls,[])
        self.assertFalse((self.out/'terminal.json').exists())
        self.no_result()

    def test_recursion_error_query_is_never_plain_runtime_error_credit(self):
        self.query_terminal_fixture()
        error = RecursionError('synthetic query runtime subclass')
        self.responses[-1] = error
        with self.assertRaises(RecursionError) as caught:self.collect()
        self.assertIs(caught.exception,error)
        self.assertEqual(len(self.inputs.read_counter_rows()),30)
        self.assertEqual(self.terminal_calls,[])
        self.assertFalse((self.out/'terminal.json').exists())
        self.no_result()

    def test_zero_verified_pairs_cannot_finish_from_query_failure(self):
        error = RuntimeError('synthetic initial query failure')
        self.responses = [error]
        with self.assertRaises(RuntimeError) as caught:self.collect()
        self.assertIs(caught.exception,error)
        self.assertEqual(self.terminal_calls,[])
        self.assertEqual(self.inputs.read_counter_rows(),[])
        self.no_result()

    def test_runtime_error_subclass_is_not_the_ordinary_command_failure(self):
        class OtherError(RuntimeError):pass
        self.query_terminal_fixture()
        error = OtherError('synthetic other query error');self.responses[-1] = error
        with self.assertRaises(OtherError) as caught:self.collect()
        self.assertIs(caught.exception,error)
        self.assertEqual(self.terminal_calls,[])
        self.assertFalse((self.out/'terminal.json').exists())
        self.no_result()

    def test_query_terminal_publication_failure_never_produces_collection_success(self):
        self.query_terminal_fixture()
        self.inputs.write_failure = 'terminal.json'
        with self.assertRaisesRegex(OSError, '^diagnostic storage failed: terminal\\.json$'):self.collect()
        self.assertEqual(len(self.inputs.read_counter_rows()),30)
        self.assertEqual(len((self.out/'guest-pids.jsonl').read_text().splitlines()),30)
        self.no_result()


if __name__=='__main__':unittest.main()
