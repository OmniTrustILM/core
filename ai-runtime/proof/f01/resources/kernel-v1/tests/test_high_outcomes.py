"""Synthetic facts only: fixed outcome predicates must reject false enforcement claims."""
import copy
import importlib.util
import pathlib
import unittest
import tracemalloc
from unittest.mock import patch

PATH = pathlib.Path(__file__).parents[1] / 'python/high_outcomes.py'
if PATH.exists():
    spec = importlib.util.spec_from_file_location('high_outcomes', PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    qualify = module.qualify
else:
    # RED is feature absence, never a fixture import error or a claimed runtime result.
    def qualify(control, data):
        return {'status': 'UNIMPLEMENTED'}


def log(*messages):
    return ''.join('2026-11-04T19:00:01Z '+x+'\n' for x in messages).encode()


def fixture(control):
    zero = {'max':0,'oom':0,'oom_kill':0,'oom_group_kill':0}
    before = {'pids.max':['256'],'memory.max':['268435456'],'cpu.max':['50000','100000'],
              'pids.events':{'max':0},'memory.events':zero.copy(),
              'cpu.stat':{'usage_usec':1000,'nr_throttled':0}}
    after = copy.deepcopy(before)
    after['cpu.stat'] = {'usage_usec':2000,'nr_throttled':0}
    data = {'target':{'uid':'12345678-1234-1234-1234-123456789abc','cid':'a'*64,'sid':'b'*64,
                      'name':'f01-a2-'+control,'startTime':'2026-11-04T19:00:00Z'},
            'terminal':{'uid':'12345678-1234-1234-1234-123456789abc','cid':'a'*64,
                        'state':'CONTAINER_EXITED','exitCode':0,'reason':'Completed','podPhase':'Succeeded',
                        'podReason':'','finishedAt':'2026-11-04T19:00:12Z'},
            'clock':{'deadlineMonotonic':130.,'observedMonotonic':112.5,'supervisorDeadlineMonotonic':130.},
            'supervisorIntervened':False,'before':before,'final':after,
            'samples':[{'sample':0,'status':'verified','monotonic':101.,'counterReadStart':101.01,'counterReadEnd':101.02,'nativePids':80}],
            'processWindow':None,'logs':b''}
    if control == 'process-limit':
        data['terminal'].update(exitCode=1,reason='Error',podPhase='Failed')
        data['final']['pids.events']['max']=1
        data['processWindow']={'pidDomain':'sandbox-root','samples':[{'sample':0,'monotonic':101.,'count':255},{'sample':1,'monotonic':101.5,'count':256},{'sample':2,'monotonic':102.,'count':256}]}
        data['samples']=[{'sample':i,'status':'verified','monotonic':t,'counterReadStart':t+.01,'counterReadEnd':t+.02,'nativePids':80} for i,t in enumerate([101.,101.5,102.])]
        data['logs']=log("xargs: can't fork: Resource temporarily unavailable",'CHILD_READY 1','WORKER_STATUS Pid:\t2','WORKER_STATUS Uid:\t65532\t65532\t65532\t65532','WORKER_STATUS Threads:\t1')
    elif control == 'memory-limit':
        data['terminal'].update(exitCode=137,reason='OOMKilled',podPhase='Failed')
        data['final']['memory.events'].update(max=10,oom=1,oom_kill=1)
        data['logs']=log('ALLOCATED_PAYLOAD_BYTES 16777216','ALLOCATED_PAYLOAD_BYTES 33554432')
    elif control == 'cpu-deadline':
        data['terminal'].update(exitCode=137,reason='Error',podPhase='Failed',podReason='DeadlineExceeded',finishedAt='2026-11-04T19:00:30.5Z')
        data['clock'].update(observedMonotonic=131.,supervisorDeadlineMonotonic=135.)
        data['final']['cpu.stat'].update(usage_usec=4900000,nr_throttled=80)
        data['samples'][0]['counters']=copy.deepcopy(before)
        data['samples'].append({'sample':1,'status':'verified','monotonic':129.,'counterReadStart':129.01,'counterReadEnd':129.02,'nativePids':80,'counters':copy.deepcopy(after)})
        data['logs']=log('CPU_BEGIN','CPU_END 137')
    else:
        data['logs']=log(*(['PREVIOUS_MARKER_ABSENT'] if control == 'scratch-b' else []),
                         'CONTROL_BYTES 1048576',"dd: error writing '"+('/tmp' if control=='scratch-b' else '/scratch')+"/f01-scratch-fill': No space left on device",
                         'SCRATCH_DD_RC 1','FILL_BYTES 16777216','ALIAS_BYTES 16777216','SCRATCH_RELEASED')
    return data


def exec_refusal_fixture():
    data = fixture('process-limit')
    data['terminal']['exitCode'] = 126
    data['before']['pids.events.local'] = {'max': 0}
    data['final']['pids.events.local'] = {'max': 1}
    data['pidDenialEvents'] = {'parentLocal': 1, 'parentHierarchical': 1, 'forkLocal': 0}
    baseline = dict(data['samples'][0], monotonic=100.5, counterReadStart=100.51, counterReadEnd=100.52)
    data['samples'] = [baseline] + [dict(row, sample=index + 1) for index, row in enumerate(data['samples'])]
    data['samples'][2]['nativePids'] = 256
    for index, row in enumerate(data['samples']):
        row['counters'] = copy.deepcopy(data['before'] if index < 2 else data['final'])
    data['processWindow']['samples'] = [dict(row, sample=row['sample'] + 1) for row in data['processWindow']['samples']]
    data['logs'] = log('xargs: /bin/busybox: Cannot allocate memory', 'CHILD_READY 1',
                       'WORKER_STATUS Uid:\t65532\t65532\t65532\t65532', 'WORKER_STATUS Threads:\t1')
    return data


class Outcomes(unittest.TestCase):
    def test_native_timestamps_preserve_integer_precision_and_ascii_offsets(self):
        cases = [('1970-01-01T00:00:00Z', 0),
                 ('1970-01-01T00:00:00.1Z', 100000000),
                 ('1970-01-01T00:00:00.123456789Z', 123456789),
                 ('1969-12-31T23:59:59.999999999Z', -1),
                 ('1970-01-01T01:00:00.000000001+01:00', 1),
                 ('1969-12-31T23:00:00.000000001-01:00', 1)]
        for stamp, expected in cases:
            with self.subTest(stamp=stamp):
                self.assertEqual(module.native_nanoseconds(stamp), expected)

    def test_native_timestamps_reject_unicode_digits_and_non_rfc3339_shapes(self):
        cases = ['１９７０-01-01T00:00:00Z', '1970-٠١-01T00:00:00Z',
                 '1970-01-01T00:00:00.１Z', '1970-01-01T00:00:00+٠١:00',
                 '1970-01-01T00:00:00.Z', '1970-01-01T00:00:00.1234567890Z',
                 '1970-01-01t00:00:00Z', '1970-01-01T00:00:00z',
                 '1970-01-01T00:00:00+0100', '1970-01-01T00:00:00',
                 '1970-01-01T00:00:00Z\n', ' 1970-01-01T00:00:00Z']
        for stamp in cases:
            with self.subTest(stamp=stamp):
                with self.assertRaisesRegex(AssertionError, '^INVALID_TIME$'):
                    module.native_nanoseconds(stamp)

    def test_counter_extensions_remain_bound_to_original_keys_and_integer_values(self):
        for fault, reason in [('decrease', 'COUNTER_RESET'), ('missing', 'COUNTER_RESET'),
                              ('bool', 'INVALID_COUNTER'), ('negative', 'INVALID_COUNTER')]:
            data = fixture('memory-limit')
            data['before']['cpu.stat']['extension'] = 2
            data['final']['cpu.stat']['extension'] = 2
            if fault == 'decrease': data['final']['cpu.stat']['extension'] = 1
            if fault == 'missing': del data['final']['cpu.stat']['extension']
            if fault == 'bool': data['final']['cpu.stat']['extension'] = True
            if fault == 'negative': data['final']['cpu.stat']['extension'] = -1
            with self.subTest(fault=fault):
                self.assertEqual(qualify('memory-limit', data), {'status': 'STOP', 'reason': reason})
        data = fixture('memory-limit')
        data['before']['cpu.stat']['extension'] = 2
        data['final']['cpu.stat']['extension'] = 3
        self.assertEqual(qualify('memory-limit', data)['status'], 'OBSERVED')

    def test_native_budget_nanoseconds_are_not_truncated_or_rounded(self):
        for control in ('process-limit','memory-limit','cpu-deadline','scratch-a','scratch-b'):
            data=fixture(control);bound=31 if control=='cpu-deadline' else 30
            data['terminal']['finishedAt']='2026-11-04T19:00:'+str(bound)+'.000000001Z'
            with self.subTest(control=control):self.assertEqual(qualify(control,data),{'status':'STOP','reason':'NATIVE_DEADLINE_LATE'})

    def test_cpu_exact31_with_fractional_offset_start_remains_valid(self):
        data=fixture('cpu-deadline')
        data['target']['startTime']='2026-11-04T20:00:00.000000001+01:00'
        data['terminal']['finishedAt']='2026-11-04T19:00:31.000000001Z'
        result=qualify('cpu-deadline',data)
        self.assertEqual(result['status'],'OBSERVED')
        self.assertEqual(result['nativeElapsedNanoseconds'],31000000000)
        self.assertEqual(result['nativeElapsedSeconds'],31.)

    def test_cpu_resource_window_and_endpoints_cannot_gain_supervisor_credit(self):
        for fault,reason in [('late','INVALID_SAMPLE'),('unbound-before','CPU_RESOURCE_ENDPOINTS'),('unbound-final','CPU_RESOURCE_ENDPOINTS')]:
            data=fixture('cpu-deadline')
            if fault=='late':data['samples'][-1].update(monotonic=130.,counterReadStart=130.01,counterReadEnd=130.02)
            if fault=='unbound-before':data['before']['cpu.stat']['usage_usec']+=1
            if fault=='unbound-final':data['final']['cpu.stat']['usage_usec']+=1
            with self.subTest(fault=fault):self.assertEqual(qualify('cpu-deadline',data),{'status':'STOP','reason':reason})
    def test_five_fixed_valid_controls_make_only_their_declared_claim(self):
        wants = {'process-limit':'OWNED_BOUNDED_FORK_REFUSAL','memory-limit':'OWNED_AGGREGATE_MEMORY_OOM',
                 'cpu-deadline':'NATIVE_POD_DEADLINE_AND_CPU_THROTTLING','scratch-a':'TMPFS_BOUNDARY_AND_SHARED_ALIAS','scratch-b':'FRESH_TMPFS_BOUNDARY_AND_SHARED_ALIAS'}
        for control,want in wants.items():
            with self.subTest(control=control):
                result=qualify(control,fixture(control))
                self.assertEqual(result.get('status'),'OBSERVED')
                self.assertEqual(result.get('claim'),want)
                self.assertFalse(result.get('fullF01Accepted',True))

    def test_owner_or_limit_or_supervisor_drift_never_counts_as_enforcement(self):
        for fault in ['uid','cid','name','limit','quota','pid-limit','intervention','invalid-row','bool-pids','late-read','counter-reset']:
            with self.subTest(fault=fault):
                d=fixture('memory-limit')
                if fault in ('uid','cid'):d['terminal'][fault]='wrong'
                if fault=='name':d['target']['name']='f01-a2-floor-control'
                if fault=='limit':d['final']['memory.max']=['536870912']
                if fault=='quota':d['before']['cpu.max']=['100000','100000']
                if fault=='pid-limit':d['before']['pids.max']=['max']
                if fault=='intervention':d['supervisorIntervened']=True
                if fault=='invalid-row':d['samples'][0]['status']='invalid'
                if fault=='bool-pids':d['samples'][0]['nativePids']=True
                if fault=='late-read':d['clock']['observedMonotonic']=130.
                if fault=='counter-reset':d['before']['memory.events']['oom_kill']=2
                self.assertEqual(qualify('memory-limit',d).get('status'),'STOP')

    def test_nonzero_without_owned_oom_event_cannot_be_memory_limit_proof(self):
        for fault in ['event','reason','exit','completed']:
            with self.subTest(fault=fault):
                d=fixture('memory-limit')
                if fault=='event':d['final']['memory.events']['oom_kill']=0
                if fault=='reason':d['terminal']['reason']='Error'
                if fault=='exit':d['terminal']['exitCode']=1
                if fault=='completed':d['logs']+=log('ALLOCATION_COMPLETED 335544320')
                self.assertEqual(qualify('memory-limit',d).get('status'),'STOP')

    def test_process_refusal_is_distinct_from_oom_deadline_or_oversized_root_population(self):
        for fault in ['no-refusal','oom','deadline','population','domain','short-window']:
            with self.subTest(fault=fault):
                d=fixture('process-limit')
                if fault=='no-refusal':d['logs']=log('CHILD_READY 1')
                if fault=='oom':d['final']['memory.events']['oom_kill']=1
                if fault=='deadline':d['terminal']['podReason']='DeadlineExceeded'
                if fault=='population':d['processWindow']['samples'][1]['count']=257
                if fault=='domain':d['processWindow']['pidDomain']='container-proc'
                if fault=='short-window':d['processWindow']['samples'][-1]['monotonic']=101.9
                self.assertEqual(qualify('process-limit',d).get('status'),'STOP')

    def test_root_window_binds_counter_indices_without_equating_native_pids(self):
        d=fixture('process-limit')
        self.assertEqual(qualify('process-limit',d).get('status'),'OBSERVED')
        d['processWindow']['samples'][1]['sample']=999
        self.assertEqual(qualify('process-limit',d).get('status'),'STOP')

    def test_fork_refusal_does_not_invent_guest_nproc_causality(self):
        d=fixture('process-limit');d['final']['pids.events']['max']=0
        result=qualify('process-limit',d)
        self.assertEqual(result.get('status'),'OBSERVED')
        self.assertEqual(result.get('guestNprocAttribution'),'UNPROVEN')
        self.assertFalse(result.get('podPidsMaxEventObserved',True))

    def test_exec_refusal_requires_owned_kernel_boundary_without_guest_cause_claim(self):
        result = qualify('process-limit', exec_refusal_fixture())
        self.assertEqual(result.get('status'), 'OBSERVED')
        self.assertEqual(result.get('claim'), 'OWNED_PARENT_PID_BOUNDARY_WITH_EXEC_REFUSAL')
        self.assertEqual(result.get('parentPidDenialIncrease'), 1)
        self.assertEqual(result.get('nativePidsMaxObserved'), 256)
        self.assertEqual(result.get('guestAllocatorCause'), 'UNPROVEN')
        self.assertEqual(result.get('guestNprocAttribution'), 'UNPROVEN')
        self.assertFalse(result.get('fullF01Accepted', True))

    def test_exec_refusal_rejects_missing_unbound_or_child_only_pid_evidence(self):
        for fault in ('missing', 'extra', 'bool', 'negative', 'huge', 'zero', 'hier-zero',
                      'child-event', 'local-mismatch', 'hier-mismatch', 'local-reset',
                      'bad-local', 'peak-low', 'peak-outside-window', 'peak-over-limit'):
            data = exec_refusal_fixture()
            if fault == 'missing': del data['pidDenialEvents']
            if fault == 'extra': data['pidDenialEvents']['other'] = 1
            if fault == 'bool': data['pidDenialEvents']['parentLocal'] = True
            if fault == 'negative': data['pidDenialEvents']['parentLocal'] = -1
            if fault == 'huge': data['pidDenialEvents']['parentLocal'] = 2 ** 63
            if fault == 'zero': data['pidDenialEvents']['parentLocal'] = 0
            if fault == 'hier-zero': data['pidDenialEvents']['parentHierarchical'] = 0
            if fault == 'child-event': data['pidDenialEvents']['forkLocal'] = 1
            if fault == 'local-mismatch': data['final']['pids.events.local']['max'] = 2
            if fault == 'hier-mismatch': data['final']['pids.events']['max'] = 2
            if fault == 'local-reset': data['before']['pids.events.local']['max'] = 2
            if fault == 'bad-local': data['final']['pids.events.local']['max'] = True
            if fault == 'peak-low': data['samples'][2]['nativePids'] = 255
            if fault == 'peak-over-limit': data['samples'][2]['nativePids'] = 257
            if fault == 'peak-outside-window':
                data['samples'][2]['nativePids'] = 255
                data['samples'].append(dict(data['samples'][-1], sample=4, monotonic=103.,
                    counterReadStart=103.01, counterReadEnd=103.02, nativePids=256))
            with self.subTest(fault=fault):
                self.assertEqual(qualify('process-limit', data).get('status'), 'STOP')

    def test_exec_refusal_rejects_ambiguous_errors_memory_and_nonowned_outcomes(self):
        for fault in ('memory-max', 'oom', 'kill', 'group-kill', 'exit1', 'exit0', 'signal',
                      'deadline', 'intervened', 'unknown-error', 'duplicate-error', 'mixed-error',
                      'no-child', 'duplicate-child', 'out-of-range-child', 'wrong-domain',
                      'short-window', 'population', 'owner', 'late'):
            data = exec_refusal_fixture()
            if fault == 'memory-max': data['final']['memory.events']['max'] = 1
            if fault == 'oom': data['final']['memory.events']['oom'] = 1
            if fault == 'kill': data['final']['memory.events']['oom_kill'] = 1
            if fault == 'group-kill': data['final']['memory.events']['oom_group_kill'] = 1
            if fault == 'exit1': data['terminal']['exitCode'] = 1
            if fault == 'exit0': data['terminal']['exitCode'] = 0
            if fault == 'signal': data['terminal']['exitCode'] = 137
            if fault == 'deadline': data['terminal']['podReason'] = 'DeadlineExceeded'
            if fault == 'intervened': data['supervisorIntervened'] = True
            if fault == 'unknown-error': data['logs'] = data['logs'].replace(b'Cannot allocate memory', b'Other error')
            if fault == 'duplicate-error': data['logs'] += log('xargs: /bin/busybox: Cannot allocate memory')
            if fault == 'mixed-error': data['logs'] += log("xargs: can't fork: Resource temporarily unavailable")
            if fault == 'no-child': data['logs'] = data['logs'].replace(log('CHILD_READY 1'), b'')
            if fault == 'duplicate-child': data['logs'] += log('CHILD_READY 1')
            if fault == 'out-of-range-child': data['logs'] = data['logs'].replace(b'CHILD_READY 1', b'CHILD_READY 299')
            if fault == 'wrong-domain': data['processWindow']['pidDomain'] = 'container-proc'
            if fault == 'short-window': data['processWindow']['samples'][-1]['monotonic'] = 101.9
            if fault == 'population': data['processWindow']['samples'][1]['count'] = 257
            if fault == 'owner': data['terminal']['uid'] = 'wrong'
            if fault == 'late': data['clock']['observedMonotonic'] = 130.
            with self.subTest(fault=fault):
                self.assertEqual(qualify('process-limit', data).get('status'), 'STOP')

    def test_exec_refusal_requires_denial_inside_the_post_signal_window(self):
        for fault in ('pre-signal-only', 'after-window-only', 'local-start', 'hier-start',
                      'local-end', 'hier-end', 'window-bool', 'baseline-included'):
            data = exec_refusal_fixture()
            if fault == 'pre-signal-only':
                for row in data['samples'][1:]: row['counters'] = copy.deepcopy(data['final'])
            if fault == 'after-window-only':
                for row in data['samples']: row['counters'] = copy.deepcopy(data['before'])
            if fault == 'local-start': data['samples'][1]['counters']['pids.events.local']['max'] = 1
            if fault == 'hier-start': data['samples'][1]['counters']['pids.events']['max'] = 1
            if fault == 'local-end': data['samples'][-1]['counters']['pids.events.local']['max'] = 0
            if fault == 'hier-end': data['samples'][-1]['counters']['pids.events']['max'] = 0
            if fault == 'window-bool': data['samples'][-1]['counters']['pids.events.local']['max'] = True
            if fault == 'baseline-included':
                data['processWindow']['samples'] = [dict(sample=row['sample'], monotonic=row['monotonic'], count=100) for row in data['samples'][:3]]
            with self.subTest(fault=fault):
                self.assertEqual(qualify('process-limit', data), {'status': 'STOP', 'reason': 'PID_DENIAL_WINDOW'})

    def test_exec_refusal_composes_actual_measurement_and_pid_denial_producers(self):
        source = pathlib.Path(__file__).with_name('test_kernel_measurement.py')
        spec = importlib.util.spec_from_file_location('process_measured_fixture', source)
        measured = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(measured)
        for fault in ('none', 'reset', 'different-parent-view'):
            with self.subTest(fault=fault), patch.object(measured.m, 'PodCgroup', measured.FakeGroup):
                reader = measured.Measurement().fixture()
                parent = measured.FakeGroup.values['/cg/ancestor/pod']
                if fault == 'reset': parent['pids.events.local'] = {'max': 2}
                initial = reader.read()
                parent['pids.current'] = ['55']
                first = reader.read()
                parent['pids.events'] = {'max': 1}
                parent['pids.events.local'] = {'max': 1}
                parent['pids.current'] = ['256']
                middle = reader.read()
                parent['pids.current'] = ['200']
                last = reader.read()
                parent['pids.current'] = ['3']
                final = reader.read()
                data = exec_refusal_fixture()
                data['before'], data['final'] = initial['counters'], final['counters']
                for row, snapshot in zip(data['samples'], (initial, first, middle, last)):
                    row['counters'] = snapshot['counters']
                    row['nativePids'] = int(snapshot['counters']['pids.current'][0])
                self.assertEqual(data['before']['pids.events.local']['max'], 2 if fault == 'reset' else 0)
                self.assertEqual(data['final']['pids.events.local']['max'], 1)
                if fault == 'different-parent-view': final['pidView']['parent'] = '/cg/ancestor/other'
                if fault != 'none':
                    reason = 'PID_EVENT_RESET' if fault == 'reset' else 'PID_VIEW'
                    with self.assertRaisesRegex(measured.m.ProofError, '^' + reason + '$'):
                        measured.m.pid_denial_delta(initial['pidView'], final['pidView'])
                else:
                    data['pidDenialEvents'] = measured.m.pid_denial_delta(initial['pidView'], final['pidView'])
                    self.assertEqual(data['pidDenialEvents'], {'parentLocal': 1, 'parentHierarchical': 1, 'forkLocal': 0})
                    self.assertEqual(qualify('process-limit', data)['claim'], 'OWNED_PARENT_PID_BOUNDARY_WITH_EXEC_REFUSAL')

    def test_cpu_native_deadline_never_accepts_later_finish_or_supervisor_stop(self):
        for fault in ['late','reason','timeout-outcome','no-throttle','oom','supervisor-bound','intervention']:
            with self.subTest(fault=fault):
                d=fixture('cpu-deadline')
                if fault=='late':d['terminal']['finishedAt']='2026-11-04T19:00:31.000001Z'
                if fault=='reason':d['terminal']['podReason']=''
                if fault=='timeout-outcome':d['logs']=log('CPU_BEGIN','CPU_END 0')
                if fault=='no-throttle':d['final']['cpu.stat']['nr_throttled']=0
                if fault=='oom':d['final']['memory.events']['oom_kill']=1
                if fault=='supervisor-bound':d['clock']['supervisorDeadlineMonotonic']=136.
                if fault=='intervention':d['supervisorIntervened']=True
                self.assertEqual(qualify('cpu-deadline',d).get('status'),'STOP')

    def test_scratch_failed_write_requires_exact_alias_boundary_and_normal_release(self):
        for fault in ['dd-success','short-file','alias','missing-release','duplicate','nonzero','missing-previous']:
            with self.subTest(fault=fault):
                d=fixture('scratch-b')
                if fault=='dd-success':d['logs']=d['logs'].replace(b'SCRATCH_DD_RC 1',b'SCRATCH_DD_RC 0')
                if fault=='short-file':d['logs']=d['logs'].replace(b'FILL_BYTES 16777216',b'FILL_BYTES 1048576')
                if fault=='alias':d['logs']=d['logs'].replace(b'ALIAS_BYTES 16777216',b'ALIAS_BYTES 16777215')
                if fault=='missing-release':d['logs']=d['logs'].replace(log('SCRATCH_RELEASED'),b'')
                if fault=='duplicate':d['logs']+=log('FILL_BYTES 16777216')
                if fault=='nonzero':d['terminal']['exitCode']=1
                if fault=='missing-previous':d['logs']=d['logs'].replace(log('PREVIOUS_MARKER_ABSENT'),b'')
                self.assertEqual(qualify('scratch-b',d).get('status'),'STOP')

    def test_fragment_control_byte_oversize_or_unknown_profile_never_passes(self):
        for fault in ['fragment','nul','oversize','timestamp','unknown']:
            with self.subTest(fault=fault):
                d=fixture('scratch-a');control='scratch-a'
                if fault=='fragment':d['logs']=d['logs'][:-1]
                if fault=='nul':d['logs']+=b'\0'
                if fault=='oversize':d['logs']=b'x'*262145
                if fault=='timestamp':d['logs']=b'bad '+d['logs']
                if fault=='unknown':control='memory-control'
                self.assertEqual(qualify(control,d).get('status'),'STOP')


    def test_large_allocation_marker_is_rejected_without_materializing_its_range(self):
        d=fixture('memory-limit')
        d['logs']=log('ALLOCATED_PAYLOAD_BYTES 1677721600000')
        tracemalloc.start()
        try:
            result=qualify('memory-limit',d)
            _,peak=tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result.get('status'),'STOP')
        self.assertLess(peak,1048576,'bounded marker validation allocated more than1MiB')

    def test_collector_sample_cap_cannot_be_bypassed_by_well_formed_extra_rows(self):
        d=fixture('memory-limit')
        d['samples']=[{'sample':i,'status':'verified','monotonic':101+i*.001,'counterReadStart':101+i*.001,'counterReadEnd':101+i*.001,'nativePids':80} for i in range(401)]
        self.assertEqual(qualify('memory-limit',d).get('status'),'STOP')


if __name__=='__main__':unittest.main()
