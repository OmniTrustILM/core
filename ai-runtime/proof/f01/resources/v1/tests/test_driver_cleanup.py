"""Finite offline API/CRI/proc fixtures for the actual cleanup shell functions."""
import json
import os
import pathlib
import re
import subprocess
import tempfile
import types
import unittest
import bootstrap as bootstrap
from unittest.mock import patch


SOURCE = pathlib.Path(os.environ.get('F01_DRIVER_SOURCE', pathlib.Path(__file__).with_name('run-resources.sh')))
SHELL = SOURCE.read_text()
UID = '12345678-1234-1234-1234-123456789abc'
CID, SID = 'a' * 64, 'b' * 64
POD = 'f01-a2-floor-control'


def function(name):
    start = SHELL.index(name + '() {')
    end = SHELL.index('\n', start) if name == 'k' else SHELL.index('\n}\n', start) + 2
    return SHELL[start:end]


FAKE_K3S = r'''#!/usr/bin/env python3
import json,os,pathlib,sys
p=pathlib.Path(os.environ['FIXTURE_STATE']);state=json.loads(p.read_text());a=sys.argv[1:]
state['calls'].append(a)
def done(value='',status=0):
 p.write_text(json.dumps(state));print(value,end='');sys.exit(status)
if a[0]=='kubectl':
 a=a[2:]
 if a[:2]==['get','pod']:
  if state.get('apiFailure'):done(status=1)
  done('' if state['deleted'] else json.dumps(state['pod']))
 if a[:2]==['delete','--raw']:
  assert a[2]=='/api/v1/namespaces/ilm-sandbox-a2/pods/f01-a2-floor-control'
  assert a[3]=='-f'
  options=json.loads(sys.stdin.read() if a[4]=='-' else pathlib.Path(a[4]).read_text())
  assert options=={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':'12345678-1234-1234-1234-123456789abc'},'gracePeriodSeconds':1}
  state['deletes']+=1;state['deleted']=True;done('{}')
 if a[:2]==['get','pods']:done('{"items":[]}')
 if a[:2]==['get','resourcequota']:done('{"items":[{"status":{"used":{"pods":"0"}}}]}')
elif a[0]=='crictl':
 action=a[1]
 kind='container' if action in ('ps','inspect','rm') else 'sandbox'
 table='containers' if kind=='container' else 'sandboxes'
 if action in ('ps','pods'):
  if state.get('queryFailure'):done(status=1)
  ids=list(state[table])
  if '--id' in a:ids=[i for i in ids if i==a[a.index('--id')+1]]
  done(''.join(i+'\n' for i in ids))
 if action in ('inspect','inspectp'):
  identity=a[2]
  if state.get('inspectionFailure'):
   if state.get('inspectionDisappears'):state[table].pop(identity,None)
   done(status=1)
  done(json.dumps({'status':state[table][identity]}))
 if action in ('rm','rmp'):
  identity=a[2];state['removes'].append([kind,identity])
  if (not state.get('removeFailure') or state.get('removeDisappears')) and not state.get('removeSurvives'):state[table].pop(identity,None)
  done('removed',1 if state.get('removeFailure') else 0)
elif a[:4]==['ctr','-n','k8s.io','tasks']:done('')
raise AssertionError(a)
'''


class CleanupInputs:
    def __init__(self, root):
        self.root = root
        self.out = root / 'out'
        self.out.mkdir()
        self.bin = root / 'bin'
        self.bin.mkdir()
        (self.bin / 'k3s').write_text(FAKE_K3S)
        (self.bin / 'k3s').chmod(0o700)
        (self.bin / 'timeout').write_text('''#!/usr/bin/env python3
import subprocess,sys
try:sys.exit(subprocess.run(sys.argv[2:],timeout=float(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:sys.exit(124)
''')
        (self.bin / 'timeout').chmod(0o700)
        self.runsc = self.bin / 'runsc'
        self.runsc.write_text('#!/bin/sh\nprintf "[]"\n')
        self.runsc.chmod(0o700)
        (root / 'proc').mkdir()
        (root / 'cgroups').mkdir()
        (root / 'kubelet').mkdir()
        self.pod = {'metadata': {'uid': UID, 'namespace': 'ilm-sandbox-a2', 'name': POD, 'labels': {'ilm.ai/proof': 'a2-v1'}},
                    'spec': {'runtimeClassName': 'runsc-f01-a2-v1'}}
        self.state = {'pod': self.pod, 'deleted': False, 'deletes': 0, 'removes': [], 'calls': [], 'containers': {}, 'sandboxes': {}}
        self.state_path = root / 'state.json'
        observation = self.out / 'observation'
        observation.mkdir()
        self.mapping = {'target': {'uid': UID, 'cid': CID, 'sid': SID, 'name': POD, 'sentry': 1999999999, 'root': '/run/synthetic'},
                        'runtimeSeeds': [{'container': identity, 'sandbox': SID, 'sentry': 1999999999, 'gofer': 1999999990 + i} for i, identity in enumerate((SID, CID))],
                        'candidates': [{'pid': 1999999999, 'startTicks': 100}]}
        (observation / 'mapping.json').write_text(json.dumps(self.mapping))
        (observation / 'host-members.json').write_text(json.dumps([{'pid': 1999999999, 'startTicks': 100}]))

    def stopped(self, kind, change=None):
        identity = CID if kind == 'container' else SID
        value = {'id': identity, 'state': 'CONTAINER_EXITED' if kind == 'container' else 'SANDBOX_NOTREADY',
                 'labels': {'io.kubernetes.pod.uid': UID, 'io.kubernetes.pod.namespace': 'ilm-sandbox-a2', 'io.kubernetes.pod.name': POD},
                 'metadata': {'name': 'fixed-proof'} if kind == 'container' else {'uid': UID, 'name': POD, 'namespace': 'ilm-sandbox-a2'},
                 'runtimeHandler': 'runsc-f01-a2-v1'}
        if change:
            change(value)
        self.state['containers' if kind == 'container' else 'sandboxes'][identity] = value

    def block(self, name):
        (self.out / name).mkdir()

    def script(self):
        names = ('k', 'verify_owner', 'cri_record_absent', 'remove_stopped_record', 'cleanup_mapping', 'cleanup_host_checks', 'cleanup_body', 'cleanup', 'wait_watchdog', 'finish')
        text = '\n'.join(function(name) for name in names)
        # Redirect only the synthetic host filesystem boundaries in private copies.
        modules = self.root / 'python';modules.mkdir(exist_ok=True)
        for name in ('cleanup_mapping.py','cleanup_host.py','verify_watchdog_clock.py'):
            code = (SOURCE.parent/'python'/name).read_text()
            code = code.replace("'/proc'", repr(str(self.root/'proc'))).replace("'/sys/fs/cgroup'", repr(str(self.root/'cgroups')))
            (modules/name).write_text(code)

        text = text.replace("'/proc'", repr(str(self.root / 'proc'))).replace("'/sys/fs/cgroup'", repr(str(self.root / 'cgroups')))
        text = text.replace('/var/lib/kubelet/pods/', str(self.root / 'kubelet') + '/').replace('/usr/local/bin/runsc', str(self.runsc))
        initial = SHELL[SHELL.index('LIVE=false'):SHELL.index('k() {')]
        return 'set -euo pipefail\nexport BASE='+str(self.root)+'\nOUT=$1;ROOT=$1;NS=ilm-sandbox-a2;POD='+POD+';POD_UID='+UID+';CID='+CID+';SID='+SID+';SENTRY_PID=;RUNSC_ROOT=\n'+initial+text+'''
health() { return 0; }
timeout() {
 if [[ $1 == 10 && $2 == bash && $3 == -c ]]; then printf 'attempt\n' >> "$FIXTURE_ATTEMPTS"; fi
 command timeout "$@"
}
export -f timeout
'''

    def run(self, action='cleanup', extra=''):
        self.state_path.write_text(json.dumps(self.state))
        script = self.script() + '\n' + extra + '\n' + action + '\n'
        result = subprocess.run(['bash', '-c', script, '--', str(self.out)], capture_output=True, text=True, timeout=15,
                                env=dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'], FIXTURE_STATE=str(self.state_path), FIXTURE_ATTEMPTS=str(self.root / 'attempts')))
        self.state = json.loads(self.state_path.read_text())
        return result

    def normal_exit(self):
        start = SHELL.index('\n cleanup', SHELL.index('python/qualify_small_control.py'))
        normal = SHELL[start:SHELL.index('\n health after', start)]
        extra = '''LIVE=true
CONTROL=floor-control
trap finish EXIT
( trap 'printf killed > "$FIXTURE_ATTEMPTS.killed"; exit 143' TERM; sleep .2; printf completed > "$FIXTURE_ATTEMPTS.completed" ) &
WATCHDOG=$!
'''
        return self.run(normal, extra)


class DriverCleanup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inputs = CleanupInputs(pathlib.Path(self.tmp.name))

    def test_log_open_failure_dispatches_cleanup_once_and_preserves_watchdog(self):
        self.inputs.block('cleanup-command.txt')
        result = self.inputs.normal_exit()
        self.assertEqual(self.inputs.state['deletes'], 1, result.stderr)
        self.assertEqual((self.inputs.root / 'attempts').read_text().splitlines(), ['attempt'])
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.inputs.root / 'attempts.completed').exists(), result.stderr)
        self.assertFalse((self.inputs.root / 'attempts.killed').exists())

    def test_exit_initiated_cleanup_failure_preserves_original_exit_and_watchdog(self):
        self.inputs.block('cleanup-command.txt')
        extra = """LIVE=true
CONTROL=floor-control
trap finish EXIT
( trap 'printf killed > "$FIXTURE_ATTEMPTS.killed"; exit 143' TERM; sleep .2; printf completed > "$FIXTURE_ATTEMPTS.completed" ) &
WATCHDOG=$!
"""
        result = self.inputs.run('exit 37', extra)
        self.assertEqual(result.returncode, 1, result.stderr)  # Unverified cleanup normalizes the original nonzero exit.
        self.assertEqual(self.inputs.state['deletes'], 1, result.stderr)
        self.assertEqual((self.inputs.root / 'attempts').read_text().splitlines(), ['attempt'])
        self.assertTrue((self.inputs.root / 'attempts.completed').exists(), result.stderr)
        self.assertFalse((self.inputs.root / 'attempts.killed').exists())

    def test_successful_exact_cleanup_verifies_required_evidence(self):
        result = self.inputs.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.inputs.state['deletes'], 1)
        self.assertTrue((self.inputs.out / 'cleanup-result.txt').read_text().startswith('PASS '))

    def test_foreign_owner_or_api_failure_never_deletes(self):
        for mode in ('uid', 'name', 'namespace', 'labels', 'runtime', 'api'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                if mode == 'api':
                    fixture.state['apiFailure'] = True
                elif mode == 'runtime':
                    fixture.pod['spec']['runtimeClassName'] = 'foreign'
                else:
                    fixture.pod['metadata'][mode] = {} if mode == 'labels' else 'foreign'
                result = fixture.run()
                self.assertEqual(fixture.state['deletes'], 0, result.stderr)
                self.assertNotEqual(result.returncode, 0)

    def test_running_foreign_or_unverifiable_cri_never_removed(self):
        for kind in ('container', 'sandbox'):
            for mode in ('running', 'foreign', 'unverifiable'):
                with self.subTest(kind=kind, mode=mode), tempfile.TemporaryDirectory() as temp:
                    fixture = CleanupInputs(pathlib.Path(temp))
                    fixture.stopped(kind)
                    table = fixture.state['containers' if kind == 'container' else 'sandboxes']
                    value = next(iter(table.values()))
                    if mode == 'running':
                        value['state'] = 'CONTAINER_RUNNING' if kind == 'container' else 'SANDBOX_READY'
                    elif mode == 'foreign':
                        if kind == 'container':
                            value['labels']['io.kubernetes.pod.uid'] = 'foreign'
                        else:
                            value['metadata']['uid'] = 'foreign'
                    else:
                        fixture.state['inspectionFailure'] = True
                    result = fixture.run()
                    self.assertEqual(fixture.state['removes'], [], result.stderr)
                    self.assertNotEqual(result.returncode, 0)

    def test_failed_remove_requires_successful_exact_absence_without_retry(self):
        for absent, query_failed, want in ((True, False, 0), (False, False, 1), (True, True, 1)):
            with self.subTest(absent=absent, query_failed=query_failed), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                fixture.stopped('container')
                fixture.state.update(removeFailure=True, removeDisappears=absent, queryFailure=query_failed)
                result = fixture.run('remove_stopped_record container '+CID)
                self.assertEqual(result.returncode == 0, want == 0, result.stderr)
                self.assertEqual(fixture.state['removes'], [['container', CID]])
                self.assertEqual(fixture.state['calls'][-1], ['crictl', 'ps', '-a', '--id', CID, '-q'])

    def test_missing_partial_or_surviving_ledger_stays_failed_but_pid_reuse_is_absent(self):
        for mode in ('missing', 'partial', 'survives', 'reused'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                ledger = fixture.out / 'observation/host-members.json'
                if mode == 'missing':
                    ledger.unlink()
                elif mode == 'partial':
                    ledger.write_text('[{"pid":1999999999}]')
                else:
                    process = fixture.root / 'proc/1999999999'
                    process.mkdir()
                    (process / 'stat').write_text('1999999999 (synthetic) ' + ' '.join(['S'] + ['0']*18 + ['101' if mode == 'reused' else '100']))
                result = fixture.run()
                self.assertEqual(fixture.state['deletes'], 1, result.stderr)
                self.assertEqual(result.returncode == 0, mode == 'reused', result.stderr)

    def test_failed_verification_does_not_retry_cleanup_or_kill_watchdog(self):
        (self.inputs.out / 'observation/host-members.json').unlink()
        result = self.inputs.normal_exit()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.inputs.root / 'attempts').read_text().splitlines(), ['attempt'])
        self.assertTrue((self.inputs.root / 'attempts.completed').exists(), result.stderr)
        self.assertFalse((self.inputs.root / 'attempts.killed').exists())

    def test_removal_output_failure_does_not_suppress_another_owned_removal(self):
        self.inputs.stopped('container')
        self.inputs.stopped('sandbox')
        self.inputs.block('stopped-container-remove.txt')
        result = self.inputs.run()
        self.assertEqual(self.inputs.state['removes'], [['container', CID], ['sandbox', SID]], result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_success_response_with_surviving_record_is_not_a_remove_retry(self):
        self.inputs.stopped('container')
        self.inputs.state['removeSurvives'] = True
        result = self.inputs.run()
        self.assertEqual(self.inputs.state['removes'], [['container', CID]], result.stderr)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_mapping_and_atomic_host_check_failure_remain_nonzero(self):
        for mode in ('missing', 'partial', 'atomic'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                mapping = fixture.out / 'observation/mapping.json'
                if mode == 'missing':
                    mapping.unlink()
                elif mode == 'partial':
                    mapping.write_text('{"candidates":[]}')
                else:
                    fixture.block('cleanup-host-checks.json.tmp')
                result = fixture.run()
                self.assertEqual(fixture.state['deletes'], 1, result.stderr)
                self.assertNotEqual(result.returncode, 0)

    def test_invalid_uid_never_deletes_and_second_cleanup_call_never_dispatches(self):
        result = self.inputs.run('POD_UID=invalid; cleanup')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.inputs.state['deletes'], 0)
        with tempfile.TemporaryDirectory() as temp:
            fixture = CleanupInputs(pathlib.Path(temp))
            result = fixture.run('cleanup\ncleanup')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((fixture.root / 'attempts').read_text().splitlines(), ['attempt'])

    def test_diagnostic_write_failures_do_not_gate_exact_uid_delete(self):
        for name in ('cleanup-result.txt', 'cleanup-mapping.json.tmp', 'cleanup-mapping.json', 'delete-current.json', 'delete-options.json', 'delete-response.json', 'pod-after.json', 'container-after.txt', 'sandbox-after.txt'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                fixture.block(name)
                result = fixture.run()
                self.assertEqual(fixture.state['deletes'], 1, result.stderr)
                self.assertNotEqual(result.returncode, 0)

    def test_mapping_stdout_survives_atomic_save_failure(self):
        self.inputs.block('cleanup-mapping.json.tmp')
        result = self.inputs.run('cleanup_mapping')
        self.assertTrue(result.stdout.strip(), 'validated mapping must be returned independently of saving')
        self.assertEqual(json.loads(result.stdout)['status'], 'VALID')
        self.assertNotEqual(result.returncode, 0)

    def test_stopped_owned_records_removed_despite_inspection_output_failure(self):
        for kind in ('container', 'sandbox'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                fixture = CleanupInputs(pathlib.Path(temp))
                fixture.stopped(kind)
                fixture.block('stopped-' + kind + '-owner.json')
                result = fixture.run()
                self.assertEqual(fixture.state['removes'], [[kind, CID if kind == 'container' else SID]], result.stderr)
                self.assertNotEqual(result.returncode, 0)


WATCHDOG_CODE = (SOURCE.parent / 'python/outer_watchdog.py').read_text()


class WatchdogCleanup(unittest.TestCase):
    def run_watchdog(self, blocked=None, foreign=None, api_failure=False, disappears=False):
        import datetime
        import time
        clock = types.SimpleNamespace(value=100.)
        sleeps, deletes, gets = [], [], []
        start = datetime.datetime(2026, 10, 27, tzinfo=datetime.timezone.utc)
        pod = {'metadata': {'uid': UID, 'name': POD, 'namespace': 'ilm-sandbox-a2', 'labels': {'ilm.ai/proof': 'a2-v1'}},
               'spec': {'runtimeClassName': 'runsc-f01-a2-v1'}, 'status': {'startTime': start.isoformat()}}
        if foreign == 'runtime':
            pod['spec']['runtimeClassName'] = 'foreign'
        elif foreign:
            pod['metadata'][foreign] = {} if foreign == 'labels' else 'foreign'
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            if blocked:
                (out / blocked).mkdir()
            def sleep(delay):
                sleeps.append(delay)
                clock.value += delay
            def run(args, **kwargs):
                if 'get' in args:
                    self.assertEqual(args, ['k3s','kubectl','--request-timeout=2s','get','pod',POD,'-n','ilm-sandbox-a2','--ignore-not-found','-o','json'])
                    self.assertEqual(kwargs['timeout'],3)
                    gets.append(clock.value)
                    return types.SimpleNamespace(returncode=1 if api_failure else 0, stdout='' if disappears and len(gets)>1 else json.dumps(pod), stderr='')
                if 'ps' in args:
                    self.assertEqual(args,['k3s','crictl','ps','--state','running','--label','io.kubernetes.pod.uid='+UID,'-q'])
                    self.assertEqual(kwargs['timeout'],2)
                    return types.SimpleNamespace(returncode=0, stdout=CID+'\n', stderr='')
                self.assertEqual(args,['k3s','kubectl','--request-timeout=2s','delete','--raw','/api/v1/namespaces/ilm-sandbox-a2/pods/'+POD,'-f','-'])
                self.assertEqual(args[-2], '-f')
                options = json.loads(kwargs.get('input') if args[-1] == '-' else pathlib.Path(args[-1]).read_text())
                self.assertEqual(options['preconditions'], {'uid': UID})
                self.assertEqual(options['gracePeriodSeconds'], 1)
                self.assertEqual(kwargs['timeout'], 10)
                deletes.append(clock.value)
                return types.SimpleNamespace(returncode=0, stdout='deleted', stderr='')
            error = None
            with patch.object(subprocess, 'run', run), patch.object(time, 'monotonic', lambda: clock.value), patch.object(time, 'time', lambda: start.timestamp()+10), patch.object(time, 'sleep', sleep), patch('sys.argv', ['watchdog', str(out), POD, UID]):
                try:
                    exec(compile(WATCHDOG_CODE, str(SOURCE.parent/'python/outer_watchdog.py'), 'exec'), {'__name__': 'watchdog_test'})
                except (Exception, SystemExit) as raised:
                    error = raised
            return deletes, sleeps, error

    def test_original_deadline_and_uid_delete_survive_evidence_failures(self):
        for blocked in ('outer-clock.json.tmp', 'outer-stop.json.tmp', 'outer-delete.json', 'outer-delete.json.tmp', 'outer-delete.txt'):
            with self.subTest(blocked=blocked):
                deletes, sleeps, error = self.run_watchdog(blocked)
                self.assertEqual(deletes, [120.])
                self.assertEqual(sleeps, [20.])
                self.assertIs(type(error),AssertionError)
                self.assertEqual(error.args,('watchdog evidence unavailable',))

    def test_foreign_watchdog_owner_never_deleted(self):
        for foreign in ('uid', 'name', 'namespace', 'labels', 'runtime'):
            with self.subTest(foreign=foreign):
                deletes, sleeps, error = self.run_watchdog(foreign=foreign)
                self.assertEqual(deletes, [])
                self.assertIs(type(error),AssertionError)
                self.assertEqual(error.args,())

    def test_watchdog_query_failure_denies_delete_and_success_keeps_deadline(self):
        deletes, sleeps, error = self.run_watchdog(api_failure=True)
        self.assertEqual(deletes, [])
        self.assertIs(type(error),AssertionError)
        self.assertEqual(error.args,())
        deletes, sleeps, error = self.run_watchdog()
        self.assertEqual(deletes, [120.])
        self.assertEqual(sleeps, [20.])
        self.assertIsNone(error)

    def test_watchdog_retains_evidence_failure_when_pod_disappears_at_deadline(self):
        for blocked, exit_code in ((None, 0), ('outer-clock.json.tmp', 1)):
            with self.subTest(blocked=blocked):
                deletes, sleeps, error = self.run_watchdog(blocked=blocked, disappears=True)
                self.assertEqual(deletes, [])
                self.assertEqual(sleeps, [20.])
                self.assertIsInstance(error, SystemExit)
                self.assertEqual(error.code, exit_code)

class FloorWatchdogOwnership(unittest.TestCase):
    def run_stop(self, owned, normal_stop=True, watchdog='431'):
        shell = (SOURCE.parent / 'run-floor-control.sh').read_text()
        functions = '\n'.join(re.findall(r'^\w+\(\) \{[^}\n]*\n.*?^}', shell, re.M | re.S))
        start = shell.index('\n', shell.index('record live-floor')) + 1
        normal = shell[start:shell.index('# Delete with an actual API UID precondition', start)]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'cases.tsv').write_text('case\toperation\tlayer\treason\tinput\n')
            script = functions + r'''
set -euo pipefail
OUT=$1; BASE=$1; TRACE=$1/trace
LIVE=false; NEGATIVE_CLASS=false; FAILED=0
WATCHDOG=$2; OWNED=$3
jobs() { if [[ $OWNED == true ]]; then printf '431\n'; fi; }
kill() { printf 'kill:%s\n' "$1" >> "$TRACE"; }
wait() { printf 'wait:%s\n' "$1" >> "$TRACE"; OWNED=false; }
record() { :; }
awk() { return 0; }
find() { :; }
sort() { cat; }
xargs() { cat >/dev/null; }
''' + (normal if normal_stop else '') + r'''
printf 'remaining:%s\n' "$WATCHDOG" >> "$TRACE"
finish
'''
            result = subprocess.run(['bash', '-c', script, '--', str(root), watchdog, str(owned).lower()],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return (root / 'trace').read_text().splitlines()

    def test_reaped_watchdog_is_not_signaled_again_during_exit(self):
        self.assertEqual(self.run_stop(True), ['kill:431', 'wait:431', 'remaining:'])

    def test_exited_watchdog_is_reaped_without_signaling_reused_pid(self):
        self.assertEqual(self.run_stop(False), ['wait:431', 'remaining:'])

    def test_exit_signals_only_a_running_owned_child(self):
        self.assertEqual(self.run_stop(True, normal_stop=False), ['remaining:431', 'kill:431', 'wait:431'])
        self.assertEqual(self.run_stop(False, normal_stop=False), ['remaining:431', 'wait:431'])
        self.assertEqual(self.run_stop(False, normal_stop=False, watchdog=''), ['remaining:'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
