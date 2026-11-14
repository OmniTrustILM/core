"""Actual collector flow at exact-owned terminal/capture interleavings; no runtime."""
import json
import unittest
import test_accounting_collection as collection
from domain_fixtures import table, roles


class TerminalCapture(unittest.TestCase):
    def subject(self):
        s = collection.AccountingCollection()
        s.setUp()
        self.addCleanup(s.doCleanups)
        s.responses = [table(roles())] * 15 + [table(roles()[:1])] * 17
        s.terminal_inspections = []
        original = s.inputs.ns['command']
        def command(args, **kwargs):
            if 'inspect' in args:
                s.terminal_inspections.append((args.copy(), kwargs['timeout']))
            return original(args, **kwargs)
        s.inputs.ns['command'] = command
        return s

    def missing(self, s, count=63):
        error = FileNotFoundError('synthetic disappearing /proc task executable')
        def hook(pid, tid):
            if s.inputs.capture_count == count and tid is not None:
                raise error
        s.inputs.proc_hook = hook
        return error

    def success(self, count, phase):
        s = self.subject()
        self.missing(s, count)
        s.collect()
        rows = s.inputs.read_counter_rows()
        queries = [json.loads(x) for x in (s.out/'guest-pids.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 30)
        self.assertEqual(len(queries), 30)
        self.assertTrue(all(x['status'] == 'verified' for x in rows))
        self.assertEqual([x['sample'] for x in rows], list(range(30)))
        self.assertEqual([x['sample'] for x in queries], list(range(30)))
        diagnostic = s.inputs.read('terminal-capture-failure.json')
        self.assertEqual(diagnostic['capturePhase'], phase)
        self.assertEqual(diagnostic['row']['status'], 'invalid')
        self.assertEqual(diagnostic['row']['failure'], 'FileNotFoundError')
        self.assertEqual(diagnostic['row']['sample'], 30)
        self.assertEqual('counterReadEnd' in diagnostic['row'], phase == 'after')
        result = s.inputs.read('observer-result.json')
        self.assertEqual(result['status'], 'CONTINUOUS_COLLECTION_FINISHED')
        self.assertEqual(result['lastSample'], rows[-1]['sample'])
        for key in ('counterReadStart', 'counterReadEnd'):
            self.assertEqual(result[key], rows[-1][key])
        terminal = s.inputs.read('terminal.json')
        self.assertEqual(result['terminal'], terminal)
        self.assertEqual((terminal['cid'], terminal['uid'], terminal['exitCode']),
                         (s.inputs.target['cid'], s.inputs.target['uid'], 0))
        self.assertLess(result['finishedMonotonic'], result['deadlineMonotonic'])
        self.assertEqual(s.inputs.capture_count, count)
        self.assertEqual(len(s.queries), 31)
        self.assertEqual(len(s.terminal_inspections), 1)
        self.assertEqual(s.terminal_inspections[0][0],
                         ['k3s', 'crictl', 'inspect', s.inputs.target['cid']])
        self.assertGreater(s.terminal_inspections[0][1], 0)
        self.assertLessEqual(s.terminal_inspections[0][1], 2)
        self.assertFalse((s.out/'control-observation.json').exists(),
                         'normal terminal never supplies numeric OBSERVED by itself')

    def test_exact_terminal0_after_before_capture_disappearance_keeps_only_complete_rows(self):
        self.success(62, 'before')

    def test_exact_terminal0_after_after_capture_disappearance_never_credits_candidate_counters(self):
        self.success(63, 'after')

    def test_unproven_terminal_keeps_original_error_invalid_row_and_no_result(self):
        for fault in ('running', 'cid', 'uid', 'name', 'namespace', 'container-name',
                      'nonzero', 'old-finish', 'deadline', 'inspect-error'):
            with self.subTest(fault=fault):
                s = self.subject()
                error = self.missing(s)
                original = s.inputs.ns['command']
                def command(args, **kwargs):
                    if 'inspect' in args and fault == 'inspect-error':
                        raise RuntimeError('synthetic terminal inspection failed')
                    raw = original(args, **kwargs)
                    if 'inspect' not in args:
                        return raw
                    value = json.loads(raw)
                    status = value['status']
                    if fault == 'running': status['state'] = 'CONTAINER_RUNNING'
                    if fault == 'cid': status['id'] = 'c' * 64
                    if fault in ('uid', 'name', 'namespace'):
                        status['labels']['io.kubernetes.pod.' + fault] = 'wrong'
                    if fault == 'container-name': status['metadata']['name'] = 'wrong'
                    if fault == 'nonzero': status['exitCode'] = 9
                    if fault == 'old-finish': status['finishedAt'] = '2026-10-26T00:00:00Z'
                    if fault == 'deadline': s.inputs.clock.value = 130.
                    return json.dumps(value)
                s.inputs.ns['command'] = command
                with self.assertRaises(FileNotFoundError) as caught:
                    s.collect()
                self.assertIs(caught.exception, error)
                self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
                self.assertEqual(len((s.out/'guest-pids.jsonl').read_text().splitlines()), 30)
                s.no_result()
                self.assertFalse((s.out/'terminal.json').exists())
                self.assertEqual(s.inputs.capture_count, 63)

    def test_missing_counter_path_is_not_reconciled_as_capture_disappearance(self):
        s = self.subject()
        original = s.inputs.ns['canonical']
        def canonical(path):
            if s.inputs.capture_count == 62 and str(path).startswith('/sys/fs/cgroup'):
                raise FileNotFoundError('synthetic missing counter path')
            return original(path)
        s.inputs.ns['canonical'] = canonical
        with self.assertRaisesRegex(FileNotFoundError, 'missing counter path'):
            s.collect()
        self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
        self.assertFalse((s.out/'terminal.json').exists())
        s.no_result()

    def test_missing_measured_binary_is_not_reconciled_as_capture_disappearance(self):
        s = self.subject()
        original = s.inputs.ns['file_identity']
        def file_identity(path):
            if s.inputs.capture_count == 63:
                raise FileNotFoundError('synthetic missing measured binary')
            return original(path)
        s.inputs.ns['file_identity'] = file_identity
        with self.assertRaisesRegex(FileNotFoundError, 'missing measured binary'):
            s.collect()
        self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
        self.assertFalse((s.out/'terminal.json').exists())
        s.no_result()

    def test_zero_verified_rows_cannot_finish_from_capture_disappearance(self):
        s = self.subject()
        error = self.missing(s, 2)
        with self.assertRaises(FileNotFoundError) as caught:
            s.collect()
        self.assertIs(caught.exception, error)
        self.assertEqual(s.inputs.read_counter_rows()[0]['status'], 'invalid')
        s.no_result()

    def test_non_file_not_found_capture_error_never_reconciles(self):
        s = self.subject()
        def hook(pid, tid):
            if s.inputs.capture_count == 63 and tid is not None:
                raise OSError('synthetic other capture failure')
        s.inputs.proc_hook = hook
        with self.assertRaisesRegex(OSError, 'other capture failure'):
            s.collect()
        self.assertFalse((s.out/'terminal.json').exists())
        self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
        s.no_result()

    def test_process_window_capture_disappearance_keeps_original_fail_closed_contract(self):
        s = self.subject()
        s.inputs.target['name'] = s.inputs.attached['name'] = 'f01-a2-process-control'
        s.inputs.ns['command'] = s.inputs.command
        error = self.missing(s, 3)
        with self.assertRaises(FileNotFoundError) as caught:
            s.inputs.observe()
        self.assertIs(caught.exception, error)
        self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
        self.assertFalse((s.out/'terminal.json').exists())
        s.no_result()

    def test_terminal_publication_failure_never_completes_or_credits_candidate(self):
        s = self.subject()
        self.missing(s)
        s.inputs.write_failure = 'terminal.json'
        with self.assertRaisesRegex(OSError, '^diagnostic storage failed: terminal\\.json$'):
            s.collect()
        self.assertEqual(s.inputs.read_counter_rows()[-1]['status'], 'invalid')
        self.assertEqual(len((s.out/'guest-pids.jsonl').read_text().splitlines()), 30)
        s.no_result()


if __name__ == '__main__':
    unittest.main()
