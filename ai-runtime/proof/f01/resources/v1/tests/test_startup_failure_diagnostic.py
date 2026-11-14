"""Closed startup diagnostics; synthetic sources and bounded local shell only."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
OBSERVER = Path(os.environ.get('F01_OBSERVER_SOURCE', str(HERE.parent / 'python/observer.py')))
PROFILE = Path(os.environ.get('F01_DIAGNOSTIC_PROFILE', str(HERE.parent / 'profiles/memory-control.yaml')))


class ProfileDiagnostics(unittest.TestCase):
    def run_case(self, raw, close_stderr=False):
        body = json.loads(PROFILE.read_text())['spec']['containers'][0]['args'][0]
        # Kubelet expands argument templates before ash sees the program.
        # These fixtures have no environment reference; unresolved arithmetic stays literal.
        body = body.replace('$$', '$')
        function = body[body.index('init_stat() {'):body.index('\ninit_stat\n')]
        self.assertEqual(function.count('IFS= read -r raw < /proc/self/stat || exit 40'), 1)
        function = function.replace('IFS= read -r raw < /proc/self/stat || exit 40',
                                    'raw=' + shlex.quote(raw)).replace('"$$"', '"17"')
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c',
            'set -eu\nset -f\n' + ('exec 2>&-\n' if close_stderr else '') + function + '\ninit_stat'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=2)

    def test_kubelet_expansion_preserves_the_intended_pid_programs(self):
        # Independent pre-correction intended shell hashes, not Pod-template hashes.
        # Fix only the Kubernetes encoding boundary; preserve every delivered program byte.
        intended = {
            'memory-control': 'b0e79e25e7b82b1bb2111430b544505ce488f04c4b1eecc8e23b2bfa902dfa0f',
            'cpu-control': '784d04b906118a4fece549071fb2c4da01de281f89e26235219f329b8b4f863f',
        }
        for name, expected in intended.items():
            with self.subTest(profile=name):
                pod = json.loads(PROFILE.with_name(name + '.yaml').read_text())
                template = pod['spec']['containers'][0]['args'][0]
                delivered = template.replace('$$', '$')
                self.assertEqual(hashlib.sha256(delivered.encode()).hexdigest(), expected)
                self.assertEqual(delivered.count('[ "$spid" = "$$" ]'), 1)

    def test_unparsed_stat_reports_closed_reason_and_preserves_exit41(self):
        q = self.run_case('malformed')
        self.assertEqual(q.returncode, 41)
        self.assertEqual(q.stdout, b'')
        self.assertEqual(q.stderr, b'INIT_STAT_FAILURE PARSE\n')

    def test_pid_mismatch_reports_closed_reason_without_values_and_preserves_exit41(self):
        q = self.run_case('18 (ash) R ' + ' '.join(['0'] * 18 + ['1']))
        self.assertEqual(q.returncode, 41)
        self.assertEqual(q.stdout, b'')
        self.assertEqual(q.stderr, b'INIT_STAT_FAILURE PID\n')

    def test_closed_stderr_preserves_both_identity_failure_exit_codes(self):
        for raw in ('malformed', '18 (ash) R ' + ' '.join(['0'] * 18 + ['1'])):
            with self.subTest(rawClass='unparsed' if raw == 'malformed' else 'pid-mismatch'):
                q = self.run_case(raw, close_stderr=True)
                self.assertEqual((q.returncode, q.stdout, q.stderr), (41, b'', b''))

    def test_valid_stat_stays_silent_and_keeps_field_parsing(self):
        q = self.run_case('17 (ash) R ' + ' '.join(['0'] * 18 + ['1']))
        self.assertEqual((q.returncode, q.stdout, q.stderr), (0, b'', b''))


class ObserverStartupDiagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='f01-startup-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        text = OBSERVER.read_text()
        self.ns = {'__name__': 'synthetic_observer'}
        exec(compile(text, str(OBSERVER), 'exec'), self.ns)
        self.target = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'c' * 64,
                       'sid': 'd' * 64, 'name': 'f01-a2-memory-control', 'startTime': '2026-10-29T00:00:00Z'}
        self.input = self.root / 'target.json'
        self.binary = self.root / 'binary'
        self.binary.write_bytes(b'synthetic binary bytes; never executed')
        self.saved = {}
        self.error = FileNotFoundError('synthetic absent state')

    def main(self, continuous=True, mapping_save_error=False, exit_save_error=False, observe_error=None):
        target = dict(self.target)
        if not continuous:
            target['name'] = 'f01-a2-floor-control'
        self.input.write_text(json.dumps(target))
        pod = {'metadata': {'uid': target['uid'], 'labels': {'ilm.ai/proof': 'a2-v1'}},
               'spec': {'runtimeClassName': 'runsc-f01-a2-v1'},
               'status': {'startTime': target['startTime'], 'containerStatuses': [{'containerID': 'containerd://' + target['cid']}]}}
        leaf = 'kubepods-burstable-pod' + target['uid'].replace('-', '_') + '.slice'
        group = '/kubepods.slice/kubepods-burstable.slice/' + leaf
        container = {'status': {'id': target['cid'], 'labels': {'io.kubernetes.pod.uid': target['uid']}, 'metadata': {'name': 'fixed-proof'}},
                     'info': {'runtimeType': 'io.containerd.runsc.v1', 'runtimeSpec': {'linux': {'cgroupsPath': leaf + ':cri-containerd:' + target['cid']}}}}
        sandbox = {'status': {'id': target['sid'], 'metadata': {'name': target['name'], 'uid': target['uid'], 'namespace': 'ilm-sandbox-a2', 'attempt': 0},
                              'runtimeHandler': 'runsc-f01-a2-v1'}}
        def command(argv):
            return json.dumps(pod if argv[1] == 'kubectl' else container if argv[2] == 'inspect' else sandbox)
        def save(path, value):
            if mapping_save_error and path.name == 'mapping.json' or exit_save_error and path.name == 'observer-exit.json':
                raise OSError('synthetic diagnostic write failure')
            self.saved[path.name] = value
        def seeds(_):
            if observe_error is None:
                raise self.error
            return ({123: 'sentry'}, [])
        def observe(*args, **kwargs):
            if isinstance(observe_error, BaseException):
                raise observe_error
        self.ns.update(validate_target=lambda _: None,
            load_outer_clock=lambda *_: ({'deadlineMonotonic': time.monotonic() + 30}, lambda: None),
            load_window=lambda *_: ({}, lambda: None), command=command, canonical=lambda _: self.binary,
            file_identity=lambda _: (1, 2), BINARIES={'sentry': ('ignored', hashlib.sha256(self.binary.read_bytes()).hexdigest())},
            group_snapshot=lambda _: {group: {'procs': [123]}},
            proc=lambda _: {'exeIdentity': [1, 2], 'argv0': 'runsc-sandbox', 'cgroup': group + '/cri-containerd-' + target['sid'] + '.scope', 'pid': 123},
            sentry_root=lambda *_: '/synthetic-runsc-root', runtime_seeds=seeds, atomic_json=save, observe=observe)
        original_stat = Path.stat
        def target_stat(path, *args, **kwargs):
            if path == self.input:
                return types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
            return original_stat(path, *args, **kwargs)
        with patch.object(Path, 'stat', target_stat), patch.object(sys, 'argv', ['observer', str(self.input), str(self.root / 'out'), 'synthetic-clock']):
            self.ns['main']()

    def test_mapping_startup_failure_publishes_exit_and_preserves_original_exception(self):
        with self.assertRaises(FileNotFoundError) as caught:
            self.main()
        self.assertIs(caught.exception, self.error)
        self.assertEqual(self.saved['mapping.json']['observations'], [])
        self.assertIn('observer-exit.json', self.saved)
        receipt = self.saved['observer-exit.json']
        self.assertEqual(set(receipt), {'exitCode', 'finishedMonotonic', 'failure'})
        self.assertEqual((receipt['exitCode'], receipt['failure']), (1, 'FileNotFoundError'))
        self.assertNotIn('synthetic absent state', json.dumps(receipt))

    def test_mapping_attachment_write_failure_does_not_hide_exit_or_original_exception(self):
        with self.assertRaises(FileNotFoundError) as caught:
            self.main(mapping_save_error=True)
        self.assertIs(caught.exception, self.error)
        self.assertIn('observer-exit.json', self.saved)
        self.assertEqual(self.saved['observer-exit.json']['exitCode'], 1)

    def test_exit_write_failure_does_not_replace_original_exception(self):
        with self.assertRaises(FileNotFoundError) as caught:
            self.main(exit_save_error=True)
        self.assertIs(caught.exception, self.error)
        self.assertNotIn('observer-exit.json', self.saved)

    def test_noncontinuous_attachment_failure_does_not_publish_continuous_receipt(self):
        with self.assertRaises(FileNotFoundError):
            self.main(continuous=False)
        self.assertNotIn('observer-exit.json', self.saved)

    def test_existing_success_exit_receipt_is_unchanged(self):
        self.main(observe_error=False)
        self.assertEqual(set(self.saved['observer-exit.json']), {'exitCode', 'finishedMonotonic'})
        self.assertEqual(self.saved['observer-exit.json']['exitCode'], 0)

    def test_existing_observation_failure_receipt_remains_failed(self):
        error = AssertionError('synthetic observation failure')
        with self.assertRaises(AssertionError) as caught:
            self.main(observe_error=error)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.saved['observer-exit.json']['failure'], 'AssertionError')


if __name__ == '__main__':
    unittest.main()
