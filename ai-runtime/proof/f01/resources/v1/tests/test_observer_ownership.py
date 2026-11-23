"""Offline behavior checks for the observer's actual ordinary Python.

Only command/proc/cgroup/clock inputs are synthetic; capture, closure, identity
publication, JSON replacement, query parsing, observe and attachment run as shipped.
"""
import copy
import datetime
import hashlib
import os
import pathlib
import tempfile
import types
import unittest
import bootstrap as bootstrap
from unittest.mock import patch


SOURCE = pathlib.Path(os.environ['F01_OBSERVER_SOURCE'])
CODE = SOURCE.read_text()
EXTRACTED = SOURCE


class Clock:
    def __init__(self):
        self.value = 100.

    def monotonic(self):
        return self.value

    def time(self):
        return datetime.datetime(2026, 10, 27, tzinfo=datetime.timezone.utc).timestamp() + self.value - 100

    def sleep(self, delay):
        self.value = round(self.value + delay, 9)


class Inputs:
    """Finite host inputs for one Sentry, two gofers and one measured descendant."""
    def __init__(self, out):
        self.out = out
        self.clock = Clock()
        self.events = []
        self.target = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'a' * 64,
                       'sid': 'b' * 64, 'name': 'f01-a2-process-control', 'startTime': '2026-10-27T00:00:00Z'}
        self.group = '/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod' + self.target['uid'].replace('-', '_') + '.slice'
        scope = self.group + '/cri-containerd-' + self.target['sid'] + '.scope'
        self.binaries = {'sentry': [1, 2], 'gofer': [1, 3], 'parking': [1, 4]}
        self.measurements = {role: tuple(identity) + (100, 200, 300) for role, identity in self.binaries.items()}
        self.records = {pid: {'pid': pid, 'tgid': pid, 'ppid': 10 if pid == 40 else 1,
                             'startTicks': pid * 10, 'comm': 'synthetic', 'exe': '/bin/' + role,
                             'exeIdentity': self.binaries[role], 'argv0': 'runsc-sandbox' if pid == 10 else role,
                             'cgroup': scope} for pid, role in ((10, 'sentry'), (20, 'gofer'), (30, 'gofer'), (40, 'sentry'))}
        self.groups = {self.group: {'procs': [], 'threads': []}, scope: {'procs': [10, 20, 30, 40], 'threads': [10, 20, 30, 40]}}
        self.seeds = {10: 'sentry', 20: 'gofer', 30: 'gofer'}
        self.projections = [{'container': self.target['cid'], 'sentry': 10, 'gofer': 20},
                            {'container': self.target['sid'], 'sentry': 10, 'gofer': 30}]
        self.mapping = {'target': self.target.copy(), 'candidates': [{'pid': 999}], 'podCgroup': self.group, 'observations': []}
        self.attached = dict(self.target, sentry=10, root='/run/synthetic')
        records = {f'a2w{i:02}': f'A2_WORKER_READY tag=a2w{i:02} pid={i + 1} uid=65532,65532,65532,65532 threads=1\n' for i in range(1, 17)}
        self.window = {'schema': 'f01-a2-process-window-v2', 'target': self.target.copy(), 'clock': 'CLOCK_MONOTONIC',
                       'clockMonotonic': 100., 'clockRealtime': self.clock.time(), 'receiptMonotonic': 100.,
                       'deadlineMonotonic': 130., 'records': records,
                       'localPids': {f'a2w{i:02}': i + 1 for i in range(1, 17)}, 'readinessSha256': 'c' * 64}
        self.ns = {'__name__': 'observer_test'}
        exec(compile(CODE, str(EXTRACTED), 'exec'), self.ns)
        self.real_atomic = self.ns['atomic_json']
        self.real_capture = self.ns['capture']
        self.real_runtime_seeds = self.ns['runtime_seeds']
        self.capture_count = 0
        self.query_failure = None
        self.write_failure = None
        self.binary_failure = False
        self.proc_hook = lambda pid, tid: None
        self.seed_hook = lambda: None
        self.group_hook = lambda: None

        owner = self

        class ProcPath:
            def __init__(self, path):
                self.path = str(path)

            def __truediv__(self, value):
                return ProcPath(self.path + '/' + str(value))

            def iterdir(self):
                return [types.SimpleNamespace(name=self.path.split('/')[2])]

            def read_text(self):
                return '40' if self.path == '/proc/10/task/10/children' else ''

        class TargetPath:
            def is_symlink(self):
                return False

            def stat(self):
                return types.SimpleNamespace(st_uid=0, st_mode=0o600)

            def read_text(self):
                return __import__('json').dumps(owner.target)

        def path(value):
            if str(value).startswith('/proc'):
                return ProcPath(value)
            if str(value) == '/synthetic-target':
                return TargetPath()
            return pathlib.Path(value)

        self.ns.update(time=self.clock, pathlib=types.SimpleNamespace(Path=path, PurePosixPath=pathlib.PurePosixPath),
                       proc=self.proc, group_snapshot=self.group_snapshot, runtime_seeds=self.runtime_seeds,
                       sentry_root=lambda *args: '/run/synthetic', command=self.command,
                       canonical=self.canonical, file_identity=self.file_identity, atomic_json=self.atomic,
                       load_window=lambda *args: (self.window, lambda: self.events.append('unchanged')),
                       BINARIES={role: ('/bin/' + role, hashlib.sha256(role.encode()).hexdigest()) for role in self.binaries})

        def capture(*args):
            self.capture_count += 1
            self.events.append('capture')
            return self.real_capture(*args)

        self.ns['capture'] = capture

    def proc(self, pid, tid=None):
        self.proc_hook(pid, tid)
        return copy.deepcopy(self.records[pid])

    def group_snapshot(self, group):
        self.group_hook()
        return copy.deepcopy(self.groups)

    def runtime_seeds(self, target):
        changed = self.seed_hook()
        if changed is not None:
            return changed, copy.deepcopy(self.projections)
        return copy.deepcopy(self.seeds), copy.deepcopy(self.projections)

    def canonical(self, name):
        name = str(name)
        if name.startswith('/bin/'):
            return types.SimpleNamespace(name=name, read_bytes=lambda: name[5:].encode())
        values = {'pids.max': 'max', 'pids.current': '4', 'pids.events': 'max 0', 'memory.max': '268435456',
                  'memory.current': '1024', 'memory.peak': '1024', 'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0',
                  'cpu.max': '50000 100000', 'cpu.stat': 'usage_usec 2'}

        class CounterPath:
            def __truediv__(self, key):
                return types.SimpleNamespace(read_text=lambda: values[key])

        return CounterPath()

    def file_identity(self, path):
        self.events.append('binary')
        role = path.name.split('/')[-1]
        return (9,) * 5 if self.binary_failure else self.measurements[role]

    def atomic(self, path, value):
        self.events.append(path.name)
        if path.name == self.write_failure:
            raise OSError('diagnostic storage failed: ' + path.name)
        return self.real_atomic(path, value)

    def command(self, args, timeout=2, raw=False):
        import json
        if 'ps' in args:
            self.events.append('query')
            assert 0 < timeout <= 2
            if self.query_failure:
                raise self.query_failure
            if '--format=json' in args:
                return '[1]'
            rows = [['UID', 'PID', 'PPID', 'PGID', 'C', 'TTY', 'STIME', 'TIME', 'CMD']]
            rows += [['65532', str(pid), '0' if pid == 1 else '1', '1', '0', '?', '00:00', '0s', 'init' if pid == 1 else f'a2w{pid - 1:02}'] for pid in range(1, 18)]
            return ('\n'.join(''.join(f'{v:<10}' for v in row[:8]) + row[8] for row in rows) + '\n').encode()
        labels = {'io.kubernetes.pod.uid': self.target['uid'], 'io.kubernetes.pod.name': self.target['name'], 'io.kubernetes.pod.namespace': 'ilm-sandbox-a2'}
        if 'inspectp' in args:
            return json.dumps({'status': {'id': self.target['sid'], 'metadata': {'name': self.target['name'], 'uid': self.target['uid'], 'namespace': 'ilm-sandbox-a2', 'attempt': 0}, 'runtimeHandler': 'runsc-f01-a2-v1'}})
        if 'inspect' in args:
            return json.dumps({'status': {'id': self.target['cid'], 'labels': labels, 'metadata': {'name': 'fixed-proof'}, 'state': 'CONTAINER_RUNNING'},
                               'info': {'runtimeType': 'io.containerd.runsc.v1', 'runtimeSpec': {'linux': {'cgroupsPath': self.group.split('/')[-1] + ':cri-containerd:' + self.target['cid']}}}})
        return json.dumps({'metadata': {'uid': self.target['uid'], 'labels': {'ilm.ai/proof': 'a2-v1'}}, 'spec': {'runtimeClassName': 'runsc-f01-a2-v1'},
                           'status': {'startTime': self.target['startTime'], 'containerStatuses': [{'containerID': 'containerd://' + self.target['cid']}]}})

    def observe(self):
        self.ns['observe'](self.attached, self.out, self.mapping, copy.deepcopy(self.records[10]), self.measurements,
                           self.binaries, self.seeds, self.projections, self.window)

    def observe_nonwindow(self):
        self.target['name'] = self.attached['name'] = 'f01-a2-cpu-control'
        self.ns['observe'](self.attached, self.out, self.mapping, copy.deepcopy(self.records[10]), self.measurements,
                           self.binaries, self.seeds, self.projections)

    def main(self):
        self.ns['sys'] = types.SimpleNamespace(argv=['observer', '/synthetic-target', str(self.out), '/synthetic-window'])
        self.ns['main']()

    def read(self, name):
        import json
        return json.loads((self.out / name).read_text())

    def read_counter_rows(self):
        import json
        return [json.loads(row) for row in (self.out / 'counters.jsonl').read_text().splitlines()]


class OwnershipOrdering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = pathlib.Path(self.tmp.name) / 'out'
        self.out.mkdir()
        self.inputs = Inputs(self.out)

    def no_rows(self):
        for name in ('counters.jsonl', 'process-projection.jsonl', 'guest-pids.jsonl'):
            if (self.out / name).exists():
                self.assertEqual((self.out / name).read_text(), '')
        self.assertFalse((self.out / 'observer-result.json').exists())

    def ledger(self):
        self.assertTrue((self.out / 'host-members.json').exists(), 'verified ownership must be published before diagnostics/projection')
        self.assertEqual([r['pid'] for r in self.inputs.read('host-members.json')], [10, 20, 30, 40])

    def test_first_query_failure_keeps_verified_ownership_and_zero_rows(self):
        self.inputs.query_failure = RuntimeError('query failed')
        with self.assertRaisesRegex(RuntimeError, 'query failed'):
            self.inputs.observe()
        self.ledger()
        self.no_rows()
        self.assertLess(self.inputs.events.index('host-members.json'), self.inputs.events.index('query'))

    def test_nonwindow_empty_first_guest_list_requires_verified_counter_sample(self):
        original = self.inputs.command
        self.inputs.ns['command'] = lambda args, **kwargs: '[]' if 'ps' in args else original(args, **kwargs)
        with self.assertRaisesRegex(AssertionError, 'no verified counter samples'):
            self.inputs.observe_nonwindow()
        self.ledger()
        self.no_rows()

    def test_nonwindow_first_terminal_reconciliation_requires_verified_counter_sample(self):
        import json
        original = self.inputs.command
        def terminal(args, **kwargs):
            if 'ps' in args:
                raise RuntimeError('first query reached terminal container')
            value = json.loads(original(args, **kwargs))
            value['status'].update(state='CONTAINER_EXITED', exitCode=0, finishedAt='2026-10-27T00:00:01Z')
            return json.dumps(value)
        self.inputs.ns['command'] = terminal
        with self.assertRaisesRegex(AssertionError, 'no verified counter samples'):
            self.inputs.observe_nonwindow()
        self.assertEqual(self.inputs.read('terminal.json')['status'], 'CONFIRMED_TERMINAL')
        self.ledger()
        self.no_rows()

    def test_nonwindow_deadline_before_first_loop_requires_verified_counter_sample(self):
        original = self.inputs.atomic
        def delay_after_ownership(path, value):
            original(path, value)
            if path.name == 'clock.json':
                self.inputs.clock.value = 130.
        self.inputs.ns['atomic_json'] = delay_after_ownership
        with self.assertRaisesRegex(AssertionError, 'no verified counter samples'):
            self.inputs.observe_nonwindow()
        self.ledger()
        self.no_rows()
        self.assertNotIn('query', self.inputs.events)
        self.assertEqual(self.inputs.read('clock.json')['deadlineMonotonic'], 130.)

    def test_nonwindow_one_verified_counter_sample_allows_observed_result(self):
        queries = 0
        original = self.inputs.command
        def one_sample(args, **kwargs):
            nonlocal queries
            if 'ps' not in args:
                return original(args, **kwargs)
            queries += 1
            return '[1]' if queries == 1 else '[]'
        self.inputs.ns['command'] = one_sample
        self.inputs.observe_nonwindow()
        self.assertEqual(self.inputs.read('observer-result.json')['status'], 'OBSERVED')
        self.assertEqual([row['status'] for row in self.inputs.read_counter_rows()], ['verified'])
        self.assertEqual(self.inputs.capture_count, 3)
        self.ledger()

    def test_first_parser_failure_keeps_verified_ownership_and_zero_rows(self):
        original = self.inputs.command
        self.inputs.ns['command'] = lambda args, **kwargs: b'broken\n' if 'ps' in args else original(args, **kwargs)
        with self.assertRaisesRegex(AssertionError, 'process population'):
            self.inputs.observe()
        self.ledger()
        self.no_rows()
        self.assertEqual(self.inputs.read('process-response-failure.json')['status'], 'STOP')

    def test_mapping_failure_follows_ownership_publication(self):
        self.inputs.write_failure = 'mapping.json'
        with self.assertRaisesRegex(OSError, 'mapping.json'):
            self.inputs.observe()
        self.ledger()
        self.no_rows()
        self.assertNotIn('query', self.inputs.events)

    def test_clock_failure_follows_ownership_publication(self):
        self.inputs.write_failure = 'clock.json'
        with self.assertRaisesRegex(OSError, 'clock.json'):
            self.inputs.observe()
        self.ledger()
        self.no_rows()

    def test_stream_open_failure_follows_ownership_publication(self):
        (self.out / 'counters.jsonl').mkdir()
        with self.assertRaises(IsADirectoryError):
            self.inputs.observe()
        self.ledger()
        self.assertNotIn('query', self.inputs.events)

    def test_first_response_save_failure_keeps_ledger_and_zero_rows(self):
        self.inputs.write_failure = 'first-guest-response.json'
        with self.assertRaisesRegex(OSError, 'first-guest-response.json'):
            self.inputs.observe()
        self.ledger()
        self.no_rows()

    def test_projection_stream_write_failure_keeps_ledger_and_zero_rows(self):
        original_open = pathlib.Path.open
        class FailedStream:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def write(self, value):
                raise OSError('projection stream failed')
        def open_stream(path, *args, **kwargs):
            if path.name == 'process-projection.jsonl':
                return FailedStream()
            return original_open(path, *args, **kwargs)
        with patch.object(pathlib.Path, 'open', open_stream):
            with self.assertRaisesRegex(OSError, 'projection stream failed'):
                self.inputs.observe()
        self.ledger()
        self.no_rows()

    def test_verified_capture_does_not_call_diagnostic_before_return(self):
        def fail(snapshot):
            raise OSError('callback failed')
        snapshot = self.inputs.real_capture(self.inputs.attached, self.inputs.group, self.inputs.binaries,
                                            self.inputs.seeds, self.inputs.projections, fail)
        self.assertEqual(sorted(snapshot['records']), [10, 20, 30, 40])
        self.assertEqual(snapshot['roles'][40], 'sentry-descendant-unclassified')

    def test_failed_capture_preserves_primary_when_diagnostic_also_fails(self):
        self.inputs.groups[self.inputs.group]['procs'] = [999]
        def fail(snapshot):
            raise OSError('callback failed')
        with self.assertRaises(KeyError) as raised:
            self.inputs.real_capture(self.inputs.attached, self.inputs.group, self.inputs.binaries,
                                     self.inputs.seeds, self.inputs.projections, fail)
        self.assertIn('callback failed', raised.exception.__notes__[0])

    def test_partial_capture_never_promotes_candidates(self):
        self.inputs.groups[self.inputs.group]['procs'] = [999]
        with self.assertRaises(KeyError):
            self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()
        diagnostic = self.inputs.read('capture-failure.json')
        self.assertEqual(self.inputs.mapping['candidates'], [{'pid': 999}])
        self.assertNotIn('roles', diagnostic)
        self.assertFalse((self.out/'mapping.json').exists())

    def test_binary_change_never_publishes_verified_members(self):
        self.inputs.binary_failure = True
        with self.assertRaisesRegex(AssertionError, 'measured binary changed'):
            self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_seed_change_fails_capture_without_publication(self):
        count = 0
        def change():
            nonlocal count
            count += 1
            if count == 2:
                return {10: 'sentry', 20: 'sentry', 30: 'gofer'}
        self.inputs.seed_hook = change
        with self.assertRaisesRegex(AssertionError, 'runtime seed changed'):
            self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_pid_start_race_fails_capture_without_publication(self):
        count = 0
        def change(pid, tid):
            nonlocal count
            if pid == 10 and tid is None:
                count += 1
                if count == 2:
                    self.inputs.records[10]['startTicks'] += 1
        self.inputs.proc_hook = change
        with self.assertRaisesRegex(AssertionError, 'racing process identity'):
            self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_attachment_sentry_identity_change_does_not_publish(self):
        attached = copy.deepcopy(self.inputs.records[10])
        attached['startTicks'] -= 1
        self.inputs.ns['proc'] = self.inputs.proc
        with self.assertRaisesRegex(AssertionError, 'Sentry identity changed since attachment'):
            self.inputs.ns['observe'](self.inputs.attached, self.out, self.inputs.mapping, attached, self.inputs.measurements,
                                      self.inputs.binaries, self.inputs.seeds, self.inputs.projections, self.inputs.window)
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_failed_atomic_replace_leaves_only_non_authoritative_temporary(self):
        with patch.object(self.inputs.ns['os'], 'replace', side_effect=OSError('replace failed')):
            with self.assertRaisesRegex(OSError, 'replace failed'):
                self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.assertTrue((self.out / 'host-members.json.tmp').exists())
        self.no_rows()

    def test_expired_process_window_is_rejected_before_ownership_capture(self):
        self.inputs.window['deadlineMonotonic'] = 100.
        with self.assertRaises(AssertionError):
            self.inputs.observe()
        self.assertEqual(self.inputs.capture_count, 0)
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_capture_cannot_extend_original_deadline(self):
        def exhaust():
            self.inputs.clock.value = 131.
        self.inputs.group_hook = exhaust
        with self.assertRaisesRegex(AssertionError, 'observation deadline reached'):
            self.inputs.observe()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_nonwindow_original_deadline_is_checked_before_initial_capture(self):
        self.inputs.attached['name'] = 'f01-a2-cpu-control'
        self.inputs.clock.time = lambda: datetime.datetime(2026, 10, 27, tzinfo=datetime.timezone.utc).timestamp() + 31
        with self.assertRaisesRegex(AssertionError, 'observation deadline reached'):
            self.inputs.ns['observe'](self.inputs.attached, self.out, self.inputs.mapping, self.inputs.records[10],
                                      self.inputs.measurements, self.inputs.binaries, self.inputs.seeds, self.inputs.projections)
        self.assertEqual(self.inputs.capture_count, 0)
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()

    def test_success_preserves_before_after_captures_and_final_fence(self):
        self.inputs.observe()
        self.ledger()
        result = self.inputs.read('observer-result.json')
        self.assertEqual(result['status'], 'OBSERVATION_WINDOW_FINISHED')
        self.assertEqual(result['deadlineMonotonic'], 130.)
        rows = (self.out / 'counters.jsonl').read_text().splitlines()
        self.assertGreaterEqual(len(rows), 3)
        self.assertEqual(self.inputs.capture_count, 2 * len(rows) + 2)
        self.assertTrue(all(__import__('json').loads(row)['status'] == 'verified' for row in rows))
        self.assertEqual(self.inputs.read('live-fence.json')['status'], 'VERIFIED')
        events = self.inputs.events
        self.assertLess(events.index('capture'), events.index('host-members.json'))
        self.assertLess(events.index('binary'), events.index('host-members.json'))
        self.assertLess(events.index('host-members.json'), events.index('mapping.json'))
        self.assertLess(events.index('host-members.json'), events.index('clock.json'))
        self.assertLess(events.index('host-members.json'), events.index('query'))

    def test_changed_population_between_counter_boundaries_invalidates_sample(self):
        def change():
            if self.inputs.capture_count == 3:
                self.inputs.records[40]['comm'] = 'changed'
        self.inputs.group_hook = change
        with self.assertRaisesRegex(AssertionError, 'membership changed across counter read'):
            self.inputs.observe()
        self.ledger()
        self.assertEqual(self.inputs.read_counter_rows()[0]['status'], 'invalid')
        self.assertFalse((self.out / 'observer-result.json').exists())

    def test_later_pid_reuse_keeps_previous_verified_ledger(self):
        def change():
            if self.inputs.capture_count == 2:
                self.inputs.records[40]['startTicks'] = 401
        self.inputs.group_hook = change
        with self.assertRaisesRegex(AssertionError, 'PID reused during observation'):
            self.inputs.observe()
        self.assertEqual(self.inputs.read('host-members.json')[-1]['startTicks'], 400)
        self.assertFalse((self.out / 'observer-result.json').exists())

    def test_later_seed_identity_change_keeps_previous_verified_ledger(self):
        def change():
            if self.inputs.capture_count == 2:
                self.inputs.records[20]['comm'] = 'changed'
        self.inputs.group_hook = change
        with self.assertRaisesRegex(AssertionError, 'seed identity changed'):
            self.inputs.observe()
        self.assertEqual(self.inputs.read('host-members.json')[1]['comm'], 'synthetic')

    def test_successful_attachment_defers_mapping_until_verified_publication(self):
        self.out.rmdir()
        self.inputs.main()
        self.ledger()
        self.assertLess(self.inputs.events.index('host-members.json'), self.inputs.events.index('mapping.json'))
        self.assertEqual(self.inputs.read('observer-result.json')['status'], 'OBSERVATION_WINDOW_FINISHED')

    def test_failed_attachment_preserves_partial_mapping_without_ledger(self):
        self.out.rmdir()
        self.inputs.ns['sentry_root'] = lambda *args: (_ for _ in ()).throw(ValueError('attachment failed'))
        with self.assertRaisesRegex(ValueError, 'attachment failed'):
            self.inputs.main()
        self.assertEqual(self.inputs.read('mapping.json')['candidates'][0]['pid'], 10)
        self.assertFalse((self.out / 'host-members.json').exists())

    def test_attachment_mapping_failure_still_publishes_first_verified_ledger(self):
        self.out.rmdir()
        self.inputs.write_failure = 'mapping.json'
        with self.assertRaisesRegex(OSError, 'mapping.json'):
            self.inputs.main()
        self.ledger()
        self.no_rows()

    def test_attachment_failure_and_write_failure_preserve_primary(self):
        self.out.rmdir()
        self.inputs.ns['sentry_root'] = lambda *args: (_ for _ in ()).throw(ValueError('attachment failed'))
        self.inputs.write_failure = 'mapping.json'
        with self.assertRaisesRegex(ValueError, 'attachment failed') as raised:
            self.inputs.main()
        self.assertFalse((self.out / 'host-members.json').exists())
        self.no_rows()
        self.assertIn('mapping.json', raised.exception.__notes__[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
