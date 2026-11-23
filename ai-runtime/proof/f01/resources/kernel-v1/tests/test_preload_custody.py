"""Retain failed preload facts and validated owners, without observation credit."""
import copy,json,os,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
import test_kernel_measurement as measured
import test_kernel_trial_composed as composed

class FloorEvidence(unittest.TestCase):
    def fixture(self):
        case=measured.Measurement();return case.fixture()
    def test_each_bad_parsed_floor_is_saved_before_unchanged_stop(self):
        for field,bad in [('pids.max',['max']),('memory.max',['max']),('memory.swap.max',['max']),('cpu.max',['max','100000'])]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                value=self.fixture();measured.FakeGroup.values['/cg/ancestor/pod'][field]=bad
                path=Path(directory)/'preload-resource-floor.json';calls=[];expected={k:list(measured.FakeGroup.values['/cg/ancestor/pod'][k]) for k in ['pids.max','memory.max','memory.swap.max','cpu.max']}
                def retain(record):
                    calls.append(copy.deepcopy(record))
                    with path.open('x') as output:json.dump(record,output)
                with self.assertRaisesRegex(measured.m.ProofError,'^RESOURCE_FLOOR$'):value.read(retain)
                record=json.loads(path.read_bytes());self.assertEqual(record['parent'],'/cg/ancestor/pod');self.assertEqual(record['identity'],[1,20]);self.assertEqual(record['limits'][field],bad);self.assertEqual(record['limits'],expected);self.assertEqual(len(calls),1)
                self.assertEqual(set(record['limits']),{'pids.max','memory.max','memory.swap.max','cpu.max'})
    def test_evidence_write_failure_stops_instead_of_returning_measurement(self):
        value=self.fixture()
        def fail(record):raise OSError('EVIDENCE_WRITE_FAILED')
        with self.assertRaisesRegex(OSError,'^EVIDENCE_WRITE_FAILED$'):value.read(fail)
    def test_evidence_callback_cannot_repair_bad_floor_by_mutating_its_copy(self):
        value=self.fixture();measured.FakeGroup.values['/cg/ancestor/pod']['memory.swap.max']=['max']
        def mutate(record):record['limits']['memory.swap.max'][0]='0';record['identity'][0]=999
        with self.assertRaisesRegex(measured.m.ProofError,'^RESOURCE_FLOOR$'):value.read(mutate)
        self.assertEqual(measured.FakeGroup.identities['/cg/ancestor/pod'],[1,20])

class PreloadOwner(unittest.TestCase):
    def fixture(self):
        case=composed.Composed();case.setUp();self.addCleanup(case.doCleanups);self.addCleanup(case.tearDown);trial,stream=case.fixture();return case,trial,stream
    def test_validated_owner_and_projection_survive_first_floor_failure_without_credit(self):
        case,trial,stream=self.fixture()
        class FailedMeasurement:
            def __init__(self,parent,*args):self.parent=parent
            def read(self,retain=None):
                if retain:retain({'parent':str(self.parent.root),'identity':list(self.parent.identity),'limits':{'pids.max':['256'],'memory.max':['268435456'],'memory.swap.max':['max'],'cpu.max':['50000','100000']}})
                raise composed.kernel.ProofError('RESOURCE_FLOOR')
        trial.kernel.KernelMeasurement=FailedMeasurement
        with patch.object(composed.collect,'LogStream',stream),patch.object(composed.collect.os,'pidfd_open',lambda pid:pid,create=True),patch.object(composed.collect.os,'close',side_effect=case.closed.append):
            with self.assertRaisesRegex(composed.kernel.ProofError,'^RESOURCE_FLOOR$'):trial.run()
        self.assertTrue((trial.out/'kernel-owner.json').is_file())
        owner=json.loads((trial.out/'kernel-owner.json').read_bytes());self.assertEqual(owner['target'],trial.target);self.assertEqual(owner['parent']['identity'],[1,10]);self.assertEqual([r['role'] for r in owner['seeds']],['sentry','sandbox-gofer','container-gofer'])
        self.assertTrue((trial.out/'runtime-projection.json').is_file());floor=json.loads((trial.out/'preload-resource-floor.json').read_bytes());self.assertEqual(floor['status'],'UNQUALIFIED_PRELOAD_COUNTER_READ');self.assertEqual(floor['target'],trial.target);self.assertEqual(floor['limits']['memory.swap.max'],['max']);self.assertEqual(floor['parent'],owner['parent']['path'])
        cleanup=composed.load('kernel_cleanup');cleanup.validate_owner(owner,trial.target)
        absence=cleanup.kernel_absence(owner,trial.target,lambda pid:None,lambda path:None);self.assertEqual(absence,{'runtimeSeedsAbsent':'PASS','ownedKernelSubtreeAbsent':'PASS','escapedDescendantAbsence':'UNPROVEN'})
        survivor=cleanup.kernel_absence(owner,trial.target,lambda pid:{'pid':pid,'startTicks':pid+1000},lambda path:{'identity':owner['parent']['identity']});self.assertEqual(survivor['runtimeSeedsAbsent'],'FAILED');self.assertEqual(survivor['ownedKernelSubtreeAbsent'],'FAILED')
        self.assertFalse((trial.out/'observer-result.json').exists());self.assertFalse((trial.out/'control-observation.json').exists());self.assertFalse(any(argv[0]=='/usr/local/bin/runsc' for argv in case.calls));self.assertEqual(case.closed,[100000,100001,100002]);self.assertTrue(trial.parent.was_closed)
    def test_seed_binding_failure_publishes_no_owner_or_resource_floor(self):
        case,trial,stream=self.fixture()
        def fail(*args):raise composed.kernel.ProofError('SEED_IDENTITY')
        trial.kernel.bind_seeds=fail
        with patch.object(composed.collect.os,'pidfd_open',lambda pid:pid,create=True),self.assertRaisesRegex(composed.kernel.ProofError,'^SEED_IDENTITY$'):trial.run()
        for name in ['kernel-owner.json','runtime-projection.json','preload-resource-floor.json','observer-result.json','control-observation.json']:self.assertFalse((trial.out/name).exists())
        self.assertFalse(any(argv[0]=='/usr/local/bin/runsc' for argv in case.calls))


if __name__=='__main__':unittest.main()
