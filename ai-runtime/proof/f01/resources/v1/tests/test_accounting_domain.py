import copy
import json
import pathlib
import unittest
from test_observer_ownership import CODE,EXTRACTED
from domain_fixtures import version2,table


class AccountingDomains(unittest.TestCase):
    def setUp(self):
        self.ns={'__name__':'test'};exec(compile(CODE,str(EXTRACTED),'exec'),self.ns)
        self.old=json.loads((pathlib.Path(__file__).parent/'testdata/accounting-v1/memory.json').read_text())
        self.fixture=version2(copy.deepcopy(self.old))

    def evaluate(self,fixture=None):
        fixture=self.fixture if fixture is None else fixture
        raw=b''.join((json.dumps(row)+'\n').encode() for row in fixture['rows'])
        return self.ns['evaluate_memory'](raw,fixture['facts'])

    def test_distinct_container_local_and_sandbox_root_ids_can_be_observed(self):
        self.assertNotEqual(self.fixture['facts']['init']['pid'],101)
        self.assertEqual(self.evaluate()['status'],'OBSERVED')

    def test_old_bare_pid_schema_is_rejected_even_if_numbers_coincide(self):
        self.assertEqual(self.evaluate(self.old)['status'],'STOP')

    def test_absent_mixed_or_unbound_domain_relation_stops(self):
        changes=[lambda f:f.pop('pidDomains'),lambda f:f['pidDomains'].update(queries='container-proc'),
                 lambda f:f.pop('rootRoles'),lambda f:f['rootRoles'].update(sample=99),
                 lambda f:f['rootRoles'].update(counterReadEnd=999.),lambda f:f['rootRoles']['init'].update(startTicks=999)]
        for change in changes:
            fixture=copy.deepcopy(self.fixture);change(fixture['facts'])
            with self.subTest(change=changes.index(change)):self.assertEqual(self.evaluate(fixture)['status'],'STOP')

    def test_wrong_uid_parent_tag_extra_or_changed_root_role_stops(self):
        mutations=[lambda p:p[0].update(UID=0),lambda p:p[1].update(rootPPID=777),
                   lambda p:p[1].update(CMD='unknown'),lambda p:p.append(copy.deepcopy(p[1])),
                   lambda p:p[0].update(rootPID=True)]
        for mutate in mutations:
            fixture=copy.deepcopy(self.fixture);binding=fixture['facts']['rootRoles'];mutate(binding['rootProjection'])
            binding['rawResponse']=table(binding['rootProjection'])
            with self.subTest(change=mutations.index(mutate)):self.assertEqual(self.evaluate(fixture)['status'],'STOP')
        fixture=copy.deepcopy(self.fixture);fixture['facts']['witnesses'][0]['rootProjection'][0]['rootPID']=999
        self.assertEqual(self.evaluate(fixture)['status'],'STOP')

    def test_released_worker_extra_row_and_mismatched_raw_projection_stop(self):
        fixture=copy.deepcopy(self.fixture);w=fixture['facts']['witnesses'][0]
        w['rootProjection']=copy.deepcopy(fixture['facts']['rootRoles']['rootProjection']);w['rawResponse']=table(w['rootProjection'])
        self.assertEqual(self.evaluate(fixture)['status'],'STOP')
        fixture=copy.deepcopy(self.fixture);fixture['facts']['witnesses'][0]['rawResponse']='[2]\n'
        self.assertEqual(self.evaluate(fixture)['status'],'STOP')


if __name__=='__main__':unittest.main()
