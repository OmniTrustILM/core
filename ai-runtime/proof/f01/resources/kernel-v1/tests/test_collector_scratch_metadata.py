"""Actual collector hooks with real temporary-FD metadata and injected Linux/seed boundaries."""
import datetime,importlib.util,json,os,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock

PYTHON=Path(__file__).parents[1]/'python'
def load(name):
    spec=importlib.util.spec_from_file_location('scratch_composed_'+name,PYTHON/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
collector=load('kernel_collect');metadata=load('scratch_metadata');protocol=load('kernel_protocol')


class CollectorScratchMetadataTest(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.source=self.root/'scratch';self.source.mkdir()
        self.events=[];self.holders=[]
        def factory(_target,_projection,deadline,fence):
            value=metadata._ScratchMetadata(self.source,deadline,fence,time.monotonic)
            self.holders.append(value);return value
        module=types.SimpleNamespace(bind_scratch=factory,unavailable=metadata.unavailable,
            MetadataUnavailable=metadata.MetadataUnavailable,CODES=metadata.CODES)
        started=datetime.datetime.now(datetime.timezone.utc).isoformat()
        real=time.time();mono=time.monotonic();deadline=mono+30-real+collector.instant(started)
        target={'uid':str(uuid.uuid4()),'name':'f01-a2-scratch-a','cid':'a'*64,'sid':'b'*64,'startTime':started}
        clock={'podStartTime':started,'monotonic':mono,'realtime':real,'deadlineMonotonic':deadline}
        self.trial=collector.Trial({'kernel_observer':types.SimpleNamespace(),
            'kernel_owner':types.SimpleNamespace(),'kernel_runtime':types.SimpleNamespace(),
            'kernel_protocol':protocol,'scratch_metadata':module},{},{},target,self.root/'observation',
            'scratch-a',{},'unchanged golden',clock,lambda:None)
        self.trial.fence=lambda:self.events.append('fence') or 'LIVE'
        self.trial.container=lambda:{'status':{'state':'CONTAINER_RUNNING'}}
        self.trial.command=lambda _arguments,**_options:self.events.append('signal') or b''
        self.trial.owner={'target':target,'seeds':[{'role':'sentry','pid':1,'startTicks':2}]}
        prepare=getattr(self.trial,'prepare_scratch_metadata',None)
        self.assertIsNotNone(prepare,'collector metadata factory hook is absent')
        prepare({'scratch':'validated-source-boundary-injected-for-Mac-test'})
        self.addCleanup(lambda:[holder.close() for holder in self.holders])

    def ready(self):
        self.trial.emit('CG_READY pid=1 start=2',time.monotonic())
        self.trial.signal(1)
        self.trial.emit('CG_RAW attempt=1 rc=0 count=1 token=GO',time.monotonic())
        self.trial.emit('CG_ACK pid=1 start=2 count=1',time.monotonic())
        self.trial.emit('CG_LOAD_BEGIN',time.monotonic())

    def test_actual_signal_and_fill_hooks_capture_real_metadata_without_contents(self):
        self.ready()
        before=json.loads((self.trial.out/'scratch-before-go-metadata.json').read_bytes())
        self.assertEqual(before['diagnostic']['phase'],'BEFORE_GO')
        self.assertEqual(before['diagnostic']['status'],'UNQUALIFIED_METADATA')
        self.assertLessEqual(before['diagnostic']['finishedMonotonic'],
            json.loads((self.trial.out/'signal-1.intent.json').read_bytes())['startedMonotonic'])
        body=b'private-file-content'*128;(self.source/'f01-scratch-fill').write_bytes(body)
        self.trial.emit('FILL_BYTES '+str(len(body)),time.monotonic())
        filled=json.loads((self.trial.out/'scratch-fill-held-metadata.json').read_bytes())
        self.assertEqual(filled['diagnostic']['fillFile']['bytes'],len(body))
        self.assertFalse(filled['fullF01Accepted']);self.assertEqual(filled['target'],self.trial.target)
        self.assertNotIn(b'private-file-content',json.dumps(filled).encode())
        self.assertLessEqual(len(json.dumps(filled).encode()),65536)
        original=(self.trial.out/'scratch-fill-held-metadata.json').read_bytes()
        self.trial.emit('FILL_BYTES '+str(len(body)),time.monotonic())
        self.assertEqual((self.trial.out/'scratch-fill-held-metadata.json').read_bytes(),original)
        original_before=(self.trial.out/'scratch-before-go-metadata.json').read_bytes()
        self.trial.scratch_before_go()
        self.assertEqual((self.trial.out/'scratch-before-go-metadata.json').read_bytes(),original_before)

    def test_actual_setup_binds_only_after_original_preload_live_fence(self):
        self.holders[0].close();self.trial.scratch_holder=None
        projection={'podCgroup':'/owned-test-parent','scratch':'validated-source-boundary-injected-for-Mac-test'}
        self.trial.pod=lambda:None
        self.trial.container=lambda:{'status':{'state':'CONTAINER_RUNNING'},
            'info':{'runtimeSpec':{},'runtimeType':'synthetic'}}
        self.trial.command=lambda *_args,**_options:b'{}'
        self.trial.runtime.check_oci=lambda *_args:projection
        self.trial.runtime.check_sandbox=lambda *_args:None
        self.trial.ops['BINARIES']={}
        self.trial.owner_adapter.runtime_candidates=lambda *_args:[]
        self.trial.kernel.bind_seeds=lambda *_args:[{'role':'sentry','identity':
            {'pid':1,'startTicks':2,'cgroup':'/owned-test-parent'},'fd':-1}]
        self.trial.kernel.read_seed_identity=self.trial.kernel.pidfd_poll=lambda:None
        self.trial.kernel.PodCgroup=lambda *_args:types.SimpleNamespace(root='/owned-test-parent',identity={})
        self.trial.kernel.KernelMeasurement=lambda *_args:types.SimpleNamespace(
            read=lambda _emit:self.events.append('preload'))
        self.trial.fence=lambda:self.events.append('preload-fence') or 'LIVE'
        with mock.patch.object(collector,'LogStream',lambda *_args:None), \
             mock.patch.object(collector.os,'pidfd_open',lambda *_args:-1,create=True):
            self.trial.setup()
        self.assertEqual(self.events,['preload','preload-fence'])
        self.assertIsNotNone(self.trial.scratch_holder)
        self.assertEqual(len(self.holders),2)

    def test_unavailable_snapshot_cannot_hide_original_owner_or_deadline_failure(self):
        self.trial.fence=lambda:'DEAD'
        self.holders[0].fence=self.trial.fence
        self.trial.emit('CG_READY pid=1 start=2',time.monotonic())
        with self.assertRaisesRegex(AssertionError,'SIGNAL_OWNER_NOT_LIVE'):self.trial.signal(1)
        self.assertNotIn('signal',self.events)
        value=json.loads((self.trial.out/'scratch-before-go-metadata.json').read_bytes())
        self.assertEqual(value['diagnostic']['status'],'UNAVAILABLE')

    def test_missing_or_invalid_fill_consumes_one_attempt_without_reopening(self):
        self.ready();self.trial.emit('FILL_BYTES invalid',time.monotonic())
        value=(self.trial.out/'scratch-fill-held-metadata.json').read_bytes()
        (self.source/'f01-scratch-fill').write_bytes(b'x'*4096)
        self.trial.emit('FILL_BYTES 4096',time.monotonic())
        self.assertEqual((self.trial.out/'scratch-fill-held-metadata.json').read_bytes(),value)
        self.assertEqual(json.loads(value)['diagnostic']['reason'],'INVALID_MARKER')

    def test_fill_before_existing_gate_ack_is_still_original_failure(self):
        with self.assertRaisesRegex(AssertionError,'LOAD_BEFORE_ACK'):
            self.trial.emit('FILL_BYTES 4096',time.monotonic())
        self.assertFalse((self.trial.out/'scratch-fill-held-metadata.json').exists())

    def test_run_failure_closes_real_holder_before_releasing_seed_descriptors(self):
        descriptor=os.open('/dev/null',os.O_RDONLY);self.trial.seeds=[{'fd':descriptor}]
        self.trial.parent=types.SimpleNamespace(close=lambda:self.events.append('parent-close'))
        self.trial.setup=lambda:None
        self.trial.measurement=types.SimpleNamespace(read=lambda:None)
        self.trial.kernel.sample_loop=lambda *_args:(_ for _ in ()).throw(AssertionError('ORIGINAL_FAILURE'))
        with self.assertRaisesRegex(AssertionError,'ORIGINAL_FAILURE'):self.trial.run()
        self.assertIsNone(self.holders[0].fd)
        with self.assertRaises(OSError):os.fstat(descriptor)
        self.assertEqual(self.events[-1],'parent-close')

    def test_diagnostic_io_failure_preserves_original_live_owner_failure(self):
        self.trial.fence=lambda:(_ for _ in ()).throw(AssertionError('NATIVE_WINDOW'))
        self.holders[0].fence=self.trial.fence
        self.trial.save=lambda *_args:(_ for _ in ()).throw(OSError('private-io-body'))
        self.trial.emit('CG_READY pid=1 start=2',time.monotonic())
        with self.assertRaisesRegex(AssertionError,'NATIVE_WINDOW'):self.trial.signal(1)
        self.assertNotIn('signal',self.events)

    def test_factory_rejection_is_fixed_and_never_exports_exception_message(self):
        self.holders[0].close();self.trial.scratch_holder=None
        self.trial.scratch_metadata.bind_scratch=lambda *_args:(_ for _ in ()).throw(
            metadata.MetadataUnavailable('private-factory-body'))
        self.trial.prepare_scratch_metadata({});self.ready()
        raw=(self.trial.out/'scratch-before-go-metadata.json').read_bytes()
        self.assertNotIn(b'private-factory-body',raw)
        self.assertEqual(json.loads(raw)['diagnostic']['reason'],'METADATA_UNAVAILABLE')
        self.trial.emit('FILL_BYTES 4096',time.monotonic())
        self.assertEqual(json.loads((self.trial.out/'scratch-fill-held-metadata.json').read_bytes())
            ['diagnostic']['status'],'UNAVAILABLE')

    def test_fixed_factory_reason_and_os_error_are_bounded_unavailable(self):
        for error,reason in ((metadata.MetadataUnavailable('SOURCE_BINDING'),'SOURCE_BINDING'),
                             (OSError('private-body'),'METADATA_UNAVAILABLE')):
            self.holders[0].close();self.trial.scratch_holder=None
            self.trial.scratch_metadata.bind_scratch=lambda *_args:(_ for _ in ()).throw(error)
            self.trial.prepare_scratch_metadata({});self.assertEqual(self.trial.scratch_reason,reason)

    def test_capture_error_and_record_bound_are_fixed_unavailable(self):
        self.holders[0].before_go=lambda:(_ for _ in ()).throw(OSError('private-body'))
        self.ready()
        before=json.loads((self.trial.out/'scratch-before-go-metadata.json').read_bytes())
        self.assertEqual(before['diagnostic']['reason'],'METADATA_UNAVAILABLE')
        self.holders[0].fill_held=lambda _marker:(_ for _ in ()).throw(OSError('private-body'))
        self.trial.emit('FILL_BYTES 4096',time.monotonic())
        raw=(self.trial.out/'scratch-fill-held-metadata.json').read_bytes()
        self.assertNotIn(b'private-body',raw)
        self.assertEqual(json.loads(raw)['diagnostic']['reason'],'METADATA_UNAVAILABLE')
        self.trial.save_scratch_metadata('bounded.json',{'phase':'FILL_HELD','excess':'x'*65536})
        self.assertEqual(json.loads((self.trial.out/'bounded.json').read_bytes())
            ['diagnostic']['reason'],'RECORD_BOUND')

    def test_non_scratch_control_does_not_open_or_emit_metadata(self):
        self.holders[0].close();self.trial.scratch_holder=None;self.trial.control='scratch-b'
        self.trial.prepare_scratch_metadata({});self.trial.scratch_before_go()
        self.trial.scratch_fill_held('FILL_BYTES 4096')
        self.assertIsNone(self.trial.scratch_holder);self.assertEqual(len(list(self.trial.out.iterdir())),0)

    def test_collector_bundle_requires_exact_new_module(self):
        self.assertIn('scratch_metadata.py',collector.MODULE_FILES)
        self.assertEqual(len(collector.BUNDLE_FILES),25)

    def test_diagnostic_close_error_cannot_block_original_cleanup(self):
        original_close=self.holders[0].close
        def close():
            original_close();raise OSError('private-close-body')
        self.holders[0].close=close
        descriptor=os.open('/dev/null',os.O_RDONLY);self.trial.seeds=[{'fd':descriptor}]
        self.trial.setup=lambda:None;self.trial.measurement=types.SimpleNamespace(read=lambda:None)
        self.trial.kernel.sample_loop=lambda *_args:(_ for _ in ()).throw(AssertionError('ORIGINAL_FAILURE'))
        with self.assertRaisesRegex(AssertionError,'ORIGINAL_FAILURE'):self.trial.run()
        self.holders[0].close=original_close
        with self.assertRaises(OSError):os.fstat(descriptor)

    def test_custom_owner_error_in_metadata_preserves_original_signal_failure(self):
        class ProofError(Exception):pass
        self.trial.fence=lambda:(_ for _ in ()).throw(ProofError('original-owner-check'))
        self.holders[0].fence=self.trial.fence
        self.trial.emit('CG_READY pid=1 start=2',time.monotonic())
        with self.assertRaisesRegex(ProofError,'original-owner-check'):self.trial.signal(1)
        value=json.loads((self.trial.out/'scratch-before-go-metadata.json').read_bytes())
        self.assertEqual(value['diagnostic']['status'],'UNAVAILABLE')
        self.assertNotIn('original-owner-check',json.dumps(value))

    def test_actual_terminal_hook_forbids_late_fill_source_capture(self):
        self.ready();events=[]
        self.trial.container=lambda:{'status':{'state':'CONTAINER_EXITED','exitCode':0,
            'finishedAt':self.trial.target['startTime']}}
        self.trial.retain_terminal_parent=lambda:None
        self.trial.capture_terminal_endpoint=lambda _terminal:self.assertTrue(self.trial.scratch_terminal_seen)
        ended=self.trial.terminal();self.assertEqual(ended['state'],'CONTAINER_EXITED')
        self.holders[0].fill_held=lambda _marker:events.append('forbidden-capture')
        self.trial.emit('FILL_BYTES 4096',time.monotonic())
        value=json.loads((self.trial.out/'scratch-fill-held-metadata.json').read_bytes())
        self.assertEqual(value['diagnostic']['reason'],'CAPTURE_ORDER')
        self.assertFalse(value['fullF01Accepted']);self.assertEqual(events,[])


if __name__=='__main__':unittest.main()
