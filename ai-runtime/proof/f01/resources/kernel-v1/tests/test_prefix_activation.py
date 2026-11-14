"""Strict lifecycle/caller counterexamples; never execute systemctl or a workload."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import hashlib
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'python'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('prefix_activation');pfx=load('prefix_file')
def known_units():
    rows=[]
    for index in range(1,8):
        name='kubelet-kubepods-burstable-pod00000000_0000_0000_0000_'+str(index).zfill(12)+'.slice'
        transient='/run/systemd/transient/'+name
        rows.append({'Id':name,'LoadState':'loaded','ActiveState':'active','Transient':'yes',
                     'FragmentPath':transient,'DropInPaths':transient+'.d/50-TasksMax.conf',
                     'ControlGroup':'/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/'+name,
                     'MemorySwapMax':'infinity','NeedDaemonReload':'no','InvocationID':format(index,'032x'),
                     'directoryIdentity':[1,100+index],'kernelSwapCurrent':{'status':'READ','value':'0'},
                     'kernelSwapMax':{'status':'READ','value':'max'}})
    return rows

KNOWN=known_units()

def states():
    before=copy.deepcopy(KNOWN)
    for row in before:row['resourceLimits']={'memory.max':['268435456'],'pids.max':['256'],'cpu.max':['50000','100000']}
    after=copy.deepcopy(before)
    for row in after:
        row['DropInPaths']+=' '+str(pfx.DIRECTORY/pfx.FILENAME);row['MemorySwapMax']='0';row['kernelSwapMax']={'status':'READ','value':'0'}
    return before,after

class Transitions(unittest.TestCase):
    def test_loaded_config_does_not_accept_effective_swap_for_legacy_infra(self):
        before,after=states();after[0]['kernelSwapMax']['value']='max'
        m.loaded_transition(before,after,str(pfx.DIRECTORY/pfx.FILENAME))
        # This function validates only the named legacy transition; actual F01 parent0 is later mandatory.
        for row in after:row['kernelSwapCurrent']['value']='1'
        with self.assertRaisesRegex(AssertionError,'^LEGACY_INFRA_SWAP_STATE$'):m.loaded_transition(before,after,str(pfx.DIRECTORY/pfx.FILENAME))
    def test_wrong_dropin_or_requested_value_is_not_loaded(self):
        for key,value in [('MemorySwapMax','infinity'),('DropInPaths','/foreign.conf')]:
            before,after=states();after[0][key]=value
            with self.assertRaisesRegex(AssertionError,'^PREFIX_NOT_LOADED$'):m.loaded_transition(before,after,str(pfx.DIRECTORY/pfx.FILENAME))
    def test_identity_limit_and_missing_extra_units_fail_closed(self):
        for key,value in [('InvocationID','foreign'),('directoryIdentity',[1,2]),('resourceLimits',{})]:
            before,after=states();after[0][key]=value
            with self.assertRaisesRegex(AssertionError,'^INFRA_IDENTITY_OR_LIMIT_DRIFT$'):m.loaded_transition(before,after,str(pfx.DIRECTORY/pfx.FILENAME))
        before,after=states()
        with self.assertRaisesRegex(AssertionError,'^CURRENT_UNIT_SET$'):m.loaded_transition(before,after[:-1],str(pfx.DIRECTORY/pfx.FILENAME))
    def test_initial_state_requires_known_literal_max_zero_usage_and_source_paths(self):
        for key,value in [('MemorySwapMax','0'),('kernelSwapMax',{'status':'READ','value':'0'}),('kernelSwapCurrent',{'status':'READ','value':'1'}),('DropInPaths','/extra')]:
            before,_=states();before[0][key]=value
            with self.assertRaisesRegex(AssertionError,'^INITIAL_INFRA_STATE$'):m.initial_state(before,KNOWN)

class Capture(unittest.TestCase):
    def fixture(self,bad=None):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);rows,_=states();by={r['ControlGroup']:r for r in rows};self.unexpected=[];self.calls=[];self.saved=[]
        listing=[{'unit':r['Id']} for r in rows]
        if bad=='extra':listing.append({'unit':'kubelet-kubepods-burstable-x.slice'})
        values=copy.deepcopy(rows)
        if bad=='identity':values[0]['InvocationID']='foreign'
        if bad=='pending':values[0]['NeedDaemonReload']='yes'
        text='\n\n'.join('\n'.join(k+'='+str(v) for k,v in row.items() if k in m.PROPERTIES.split(',')) for row in sorted(values,key=lambda r:r['Id']))+'\n'
        expected=[(['/usr/bin/systemctl','list-units','--type=slice','--all','--no-pager','--output=json'],json.dumps(listing)),(['/usr/bin/systemctl','show','--no-pager','--property='+m.PROPERTIES,'--',*sorted(r['Id'] for r in rows)],text)]
        def call(argv):
            self.calls.append(argv)
            if not expected or argv!=expected[0][0]:self.unexpected.append(argv);raise AssertionError('UNEXPECTED_ARGV')
            return expected.pop(0)[1]
        class Group:
            def __init__(self,path):self.row=by[str(path).removeprefix('/sys/fs/cgroup')];self.identity=self.row['directoryIdentity']
            def __enter__(self):return self
            def __exit__(self,*a):return False
            def read_field(self,name):return self.row['resourceLimits'][name]
        def swap(group,name):return group.row['kernelSwapMax' if name=='memory.swap.max' else 'kernelSwapCurrent']
        cohort=types.SimpleNamespace(root=Path(tmp.name),collector={'strict_json':json.loads},call=call,save=lambda root,name,value:self.saved.append(value))
        self.addCleanup(lambda:self.assertEqual(self.unexpected,[]))
        return cohort,types.SimpleNamespace(PodCgroup=Group),swap
    def test_exact_two_public_cli_calls_and_seven_pinned_directory_reads(self):
        c,k,swap=self.fixture();rows=m.capture(c,KNOWN,k,swap);self.assertEqual(len(rows),7);self.assertEqual(len(self.calls),2);self.assertEqual(len(self.saved),9)
    def test_extra_unit_or_reused_identity_and_pending_reload_stop(self):
        for bad,reason in [('extra','CURRENT_UNIT_SET'),('identity','CURRENT_UNIT_IDENTITY'),('pending','CURRENT_UNIT_IDENTITY')]:
            with self.subTest(bad=bad):
                c,k,swap=self.fixture(bad)
                with self.assertRaisesRegex(AssertionError,'^'+reason+'$'):m.capture(c,KNOWN,k,swap)

def rollback_inputs(receipt,before):
    raw_receipt=(json.dumps(receipt)+'\n').encode();raw_before=(json.dumps(before)+'\n').encode()
    pins={'receiptSha256':hashlib.sha256(raw_receipt).hexdigest(),'beforeSha256':hashlib.sha256(raw_before).hexdigest()}
    return raw_receipt,raw_before,pins

class Lifecycle(unittest.TestCase):
    def fixture(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name).resolve();parent=root/'system';parent.mkdir(mode=0o755);out=root/'evidence';out.mkdir(mode=0o700)
        for key,value in [('DIRECTORY',parent/'kubelet-kubepods-burstable-.slice.d'),('OWNER_UID',os.getuid()),('OWNER_GID',os.getgid())]:
            context=patch.object(pfx,key,value);context.start();self.addCleanup(context.stop)
        self.events=[];self.saved={};self.code=0
        def save(out,name,value):self.saved[name]=copy.deepcopy(value);(out/name).write_text(json.dumps(value))
        def supervised(argv,seconds,path,tag):
            self.assertEqual(argv,['/usr/bin/systemctl','daemon-reload']);self.assertEqual(seconds,10);self.assertEqual(path,out);self.assertIn('prefix-file-complete.json',self.saved);self.events.append('reload')
            (out/(tag+'.stdout')).write_bytes(b'');(out/(tag+'.stderr')).write_bytes(b'');return self.code
        c=types.SimpleNamespace(deadline=time.monotonic()+60,collector={'strict_json':json.loads},root=out,guard=lambda:self.events.append('guard'),health=lambda root,tag:self.events.append('health-'+tag),save=save,supervised=supervised)
        return c
    def test_install_persists_owned_file_before_one_reload_then_records_pending_not_proof(self):
        c=self.fixture();before,after=states()
        with patch.object(m,'capture',side_effect=[before,after]):value=m.install(pfx,c,KNOWN,None,None)
        self.assertEqual(self.events,['guard','health-before','reload','health-after','guard']);self.assertFalse(value['wholeRuntimeNoSwapAccepted']);self.assertFalse(value['followingPodReleased']);self.assertTrue((pfx.DIRECTORY/pfx.FILENAME).is_file())
    def test_native_nonzero_never_auto_rolls_back_or_publishes_success(self):
        c=self.fixture();before,_=states();self.code=1
        with patch.object(m,'capture',return_value=before),self.assertRaisesRegex(AssertionError,'^RELOAD_NATIVE_NONZERO$'):m.install(pfx,c,KNOWN,None,None)
        self.assertTrue((pfx.DIRECTORY/pfx.FILENAME).is_file());self.assertNotIn('prefix-result.json',self.saved);self.assertEqual(self.events,['guard','health-before','reload'])
    def test_post_reload_drift_stops_without_automatic_remove(self):
        c=self.fixture();before,after=states();after[0]['InvocationID']='new'
        with patch.object(m,'capture',side_effect=[before,after]),self.assertRaisesRegex(AssertionError,'^INFRA_IDENTITY_OR_LIMIT_DRIFT$'):m.install(pfx,c,KNOWN,None,None)
        self.assertTrue((pfx.DIRECTORY/pfx.FILENAME).is_file());self.assertNotIn('prefix-result.json',self.saved)
    def test_separately_invoked_rollback_requires_actual_original_values(self):
        c=self.fixture();receipt=pfx.install_prefix(lambda tag,value:c.save(c.root,tag+'.json',value));before,after=states()
        with patch.object(m,'capture',side_effect=[after,before]):value=m.rollback(pfx,c,KNOWN,None,None,*rollback_inputs(receipt,before))
        self.assertFalse(pfx.DIRECTORY.exists());self.assertEqual(value['status'],'OWNED_PREFIX_ABSENT_PROVIDED_SEVEN_SELECTED_LIMITS_RESTORED_ROLLBACK_HEALTH_STABLE');self.assertEqual(self.events,['guard','health-before','reload','health-after','guard'])
    def test_failed_preflight_never_creates_prefix_directory(self):
        c=self.fixture();primary=AssertionError('BAD_PREFLIGHT')
        with patch.object(m,'capture',side_effect=primary),self.assertRaisesRegex(AssertionError,'^BAD_PREFLIGHT$'):m.install(pfx,c,KNOWN,None,None)
        self.assertFalse(pfx.DIRECTORY.exists());self.assertNotIn('reload',self.events)
    def test_late_budget_refuses_before_any_prefix_write(self):
        c=self.fixture();before,after=states();c.deadline=100.
        with patch.object(m,'capture',side_effect=[before,after]),patch.object(m.time,'monotonic',return_value=65.0001),self.assertRaisesRegex(AssertionError,'^PREFIX_REMAINING_BUDGET$'):m.install(pfx,c,KNOWN,None,None)
        self.assertFalse(pfx.DIRECTORY.exists());self.assertNotIn('reload',self.events)
    def test_rollback_rejects_missing_or_wrong_install_sha_before_any_action(self):
        c=self.fixture();receipt=pfx.install_prefix(lambda tag,value:c.save(c.root,tag+'.json',value));before,_=states();a,b,pins=rollback_inputs(receipt,before)
        for bad in [{},dict(pins,receiptSha256='0'*64),dict(pins,beforeSha256='0'*64)]:
            with self.subTest(bad=bad),self.assertRaisesRegex(AssertionError,'^ROLLBACK_INPUT_SHA$'):m.rollback(pfx,c,KNOWN,None,None,a,b,bad)
        self.assertEqual(self.events,[]);self.assertTrue(pfx.DIRECTORY.exists())

    def test_file_absence_does_not_credit_nonrestored_kernel_state(self):
        c=self.fixture();receipt=pfx.install_prefix(lambda tag,value:c.save(c.root,tag+'.json',value));before,after=states();not_restored=copy.deepcopy(before);not_restored[0]['kernelSwapMax']['value']='0'
        with patch.object(m,'capture',side_effect=[after,not_restored]),self.assertRaisesRegex(AssertionError,'^INITIAL_INFRA_STATE$'):m.rollback(pfx,c,KNOWN,None,None,*rollback_inputs(receipt,before))
        self.assertFalse(pfx.DIRECTORY.exists());self.assertNotIn('rollback-result.json',self.saved)

if __name__=='__main__':unittest.main()
