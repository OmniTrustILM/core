"""Independent public/synthetic startup, completion and cleanup regressions."""
import copy
import json
import unittest
import test_accounting_collection as collection
from domain_fixtures import roles,table


class Prebind(unittest.TestCase):
    def setUp(self):
        self.c=collection.AccountingCollection();self.c.setUp();self.addCleanup(self.c.doCleanups)

    def test_unknown_labels_are_only_pending_until_exact_roles_bind(self):
        unknown=roles();unknown[0]['CMD']='unqualified';unknown[1]['CMD']='unknown'
        self.c.responses=[table(unknown[:1]),table(unknown)]+[table(roles())]*15+[table(roles()[:1])]*15+[table([])]
        self.c.collect()
        rows=self.c.inputs.read_counter_rows();queries=[json.loads(x) for x in (self.c.out/'guest-pids.jsonl').read_text().splitlines()]
        self.assertEqual([row['sample'] for row in rows],list(range(30)))
        self.assertTrue(all(q['rawResponse'] not in (table(unknown[:1]),table(unknown)) for q in queries))
        state=self.c.inputs.read('accounting-startup.json')
        self.assertEqual(state['disposition'],'STRICT_BOUND');self.assertEqual(state['unknownPrebindCount'],2)
        self.assertGreaterEqual(rows[0]['monotonic'],self.c.queries[2][0])

    def test_unknown_exhaustion_never_publishes_a_row_or_result(self):
        unknown=roles()[:1];unknown[0]['CMD']='not-qualified'
        self.c.responses=[table(unknown)]*300
        with self.assertRaises(AssertionError):self.c.collect()
        self.assertEqual(self.c.inputs.read_counter_rows(),[])
        self.assertEqual(len(self.c.queries),300)
        self.assertFalse((self.c.out/'observer-result.json').exists())

    def test_skipped_startup_child_then_strict_worker_is_supported_but_third_birth_is_not(self):
        initial=roles();initial[0]['CMD']='unknown';initial[1].update(rootPID=103,CMD='unknown')
        self.c.responses=[table(initial),table(initial[:1])]+[table(roles())]*15+[table(roles()[:1])]*15+[table([])]
        self.c.collect()
        self.assertEqual(self.c.inputs.read('accounting-startup.json')['observedChildPids'],[102,103])
        for fault in ('reappear','third-birth','child-parent','root-change','uid'):
            with self.subTest(fault=fault):
                self.setUp();other=copy.deepcopy(initial);other[1]['rootPID']=104
                final=copy.deepcopy(initial);final[1]['rootPID']=105
                if fault=='reappear':self.c.responses=[table(initial),table(initial[:1]),table(initial)]
                elif fault=='third-birth':self.c.responses=[table(initial),table(other),table(final)]
                else:
                    changed=copy.deepcopy(initial)
                    if fault=='child-parent':changed[1]['rootPPID']=77
                    if fault=='root-change':changed[0]['rootPID']=111;changed[1]['rootPPID']=111
                    if fault=='uid':changed[0]['UID']=0
                    self.c.responses=[table(initial),table(changed)]
                with self.assertRaises(AssertionError):self.c.collect()
                self.assertFalse((self.c.out/'observer-result.json').exists())

    def test_postbind_unknown_or_root_reparent_is_fatal(self):
        for fault in ('postbind','root-parent','third-child'):
            with self.subTest(fault=fault):
                self.setUp();unknown=roles();unknown[0]['CMD']='unqualified';unknown[1]['CMD']='unknown'
                if fault=='postbind':self.c.responses=[table(roles()),table(unknown)]
                elif fault=='root-parent':
                    changed=copy.deepcopy(unknown);changed[0]['rootPPID']=77
                    self.c.responses=[table(unknown),table(changed)]
                else:
                    third=copy.deepcopy(unknown[1]);third['rootPID']=103
                    self.c.responses=[table(unknown+[third])]
                with self.assertRaises(AssertionError):self.c.collect()
                self.assertFalse((self.c.out/'observer-result.json').exists())




class FencedFacts(unittest.TestCase):
    def setUp(self):
        import test_accounting_evaluator as fixture
        self.fixture=fixture.AccountingEvaluator();self.fixture.setUp()

    def test_late_or_coalesced_log_receipts_yield_unproven_without_moving_terminal(self):
        for released in (109.75,112.75):
            with self.subTest(released=released):
                f=copy.deepcopy(self.fixture.memory);facts=f['facts']
                facts['normalExit']['receivedMonotonic']=112.5
                facts['markers']['HOLD_END']['receivedMonotonic']=112.75
                facts['markers']['RELEASED']['receivedMonotonic']=released
                result=self.fixture.evaluate(f)
                self.assertEqual(result['status'],'OBSERVED' if released==109.75 else 'UNPROVEN',result)
                self.assertEqual(facts['normalExit']['receivedMonotonic'],112.5)

    def test_pre_signal_or_reversed_witnesses_are_rejected(self):
        for mutation in ('before-signal3','reverse'):
            f=copy.deepcopy(self.fixture.memory);facts=f['facts']
            if mutation=='reverse':facts['witnesses'].reverse()
            else:
                early=copy.deepcopy(facts['witnesses'][0]);row=f['rows'][6]
                early.update(sample=6,counterReadStart=row['counterReadStart'],counterReadEnd=row['counterReadEnd'],
                    queryStartedMonotonic=row['monotonic'],queryReceivedMonotonic=row['counterReadStart'])
                facts['witnesses'].insert(0,early)
            self.assertEqual(self.fixture.evaluate(f)['status'],'STOP')

    def test_accidentally_equal_numeric_ids_still_require_explicit_domains(self):
        f=copy.deepcopy(self.fixture.memory);facts=f['facts']
        facts['init']['pid']=101;facts['worker']['pid']=102
        for phase,marker in facts['markers'].items():
            marker['init']=copy.deepcopy(facts['init'])
            marker['actor']=copy.deepcopy(facts['init'] if phase in ('RELEASED','HOLD_END') else facts['worker'])
        for bound in [facts['rootRoles'],facts['normalExit']]+facts['witnesses']:
            bound['init']=copy.deepcopy(facts['init'])
        self.assertEqual(self.fixture.evaluate(f)['status'],'OBSERVED')
        facts['pidDomains']['queries']='container-proc'
        self.assertEqual(self.fixture.evaluate(f)['status'],'STOP')


class PublicWire(unittest.TestCase):
    def test_independent_literal_formatter_wire_has_exact_owned_role_shape(self):
        from test_observer_ownership import CODE,EXTRACTED
        ns={'__name__':'test'};exec(compile(CODE,str(EXTRACTED),'exec'),ns)
        # Authored literal from pinned tabwriter parameters, never domain_fixtures.table output.
        raw=(b'UID       PID       PPID      PGID      C         TTY       STIME     TIME      CMD\n'
             b'65532     101       0         1         0         ?         00:00     0s        a2mi\n'
             b'65532     102       101       1         0         ?         00:00     0s        a2mw\n')
        self.assertEqual(ns['accounting_response'](raw,'memory'),[
            {'rootPID':101,'UID':65532,'rootPPID':0,'CMD':'a2mi'},
            {'rootPID':102,'UID':65532,'rootPPID':101,'CMD':'a2mw'}])
        with self.assertRaises(AssertionError):ns['accounting_response'](raw+b'\n','memory')

if __name__=='__main__':unittest.main()
