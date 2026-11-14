import importlib.util
from pathlib import Path
import unittest

P = (Path(__file__).parents[1] / 'python' / 'kernel_collect.py')
if P.exists():
    spec = importlib.util.spec_from_file_location('kernel_collect', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
else: m = None


class CollectorBoundary(unittest.TestCase):
    def feature(self): self.assertIsNotNone(m, 'fixed collector CLI adapter missing');return m

    def test_partial_timestamped_stream_is_one_ordered_bounded_message_sequence(self):
        f = self.feature().LogBuffer();events = []
        f.feed(b'2026-11-05T00:00:01Z CG_RE', 1, lambda text, at: events.append((text, at)))
        f.feed(b'ADY pid=1 start=55\n2026-11-05T00:00:02Z second\n', 2, lambda text, at: events.append((text, at)))
        f.boundary();self.assertEqual(events, [('CG_READY pid=1 start=55', 2), ('second', 2)])

    def test_missing_stamp_control_bytes_unframed_and_oversize_logs_are_stop(self):
        self.feature()
        for raw in (b'not timestamp\n', b'2026-11-05T00:00:01Z x\x00\n', b'x' * 4097, b'x' * 262145):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(AssertionError): m.LogBuffer().feed(raw, 1, lambda *_: None)
        f = m.LogBuffer();f.feed(b'2026-11-05T00:00:01Z incomplete', 1, lambda *_: None)
        with self.assertRaises(AssertionError): f.boundary()

    def test_fixed_process_status_tabs_survive_fragmented_timestamped_logs(self):
        log = self.feature().LogBuffer();events = []
        messages = ['WORKER_STATUS Pid:\t3', 'WORKER_STATUS Uid:\t65532\t65532\t65532\t65532',
                    'WORKER_STATUS Threads:\t1']
        raw = b''.join(b'2026-11-05T00:00:01Z ' + text.encode('ascii') + b'\n' for text in messages)
        boundary = raw.index(b'\t')
        for chunk in (raw[:boundary], raw[boundary:boundary + 1], raw[boundary + 1:]):
            log.feed(chunk, 2, lambda text, at: events.append((text, at)))
        log.boundary()
        self.assertEqual(events, [(text, 2) for text in messages])
        self.assertEqual(log.raw, raw)

    def test_other_control_bytes_and_tabbed_timestamps_remain_invalid(self):
        for byte in list(range(9)) + list(range(11, 32)) + [127, 128, 255]:
            with self.subTest(byte=byte):
                raw = b'2026-11-05T00:00:01Z WORKER_STATUS ' + bytes([byte]) + b'\n'
                with self.assertRaisesRegex(AssertionError, '^LOG_BOUND$'):
                    self.feature().LogBuffer().feed(raw, 1, lambda *_: None)
        with self.assertRaises(AssertionError):
            self.feature().LogBuffer().feed(b'2026-11-05\t00:00:01Z WORKER_STATUS Pid:\t3\n',
                                           1, lambda *_: None)

    def test_clock_is_original_pod_start_and_cpu_only_adds_terminal_observation(self):
        f = self.feature();target = {'startTime': '2026-11-05T00:00:00Z'}
        clock = {'podStartTime': target['startTime'], 'monotonic': 100., 'realtime': 1793836802., 'deadlineMonotonic': 128.}
        self.assertEqual(f.validate_clock(clock, target, 'process-limit', 101), (128., 128.))
        self.assertEqual(f.validate_clock(clock, target, 'cpu-deadline', 101), (128., 133.))
        clock['deadlineMonotonic'] = 130.
        with self.assertRaises(AssertionError): f.validate_clock(clock, target, 'cpu-deadline', 101)

    def test_terminal_record_requires_owned_explicit_exit_not_absence_or_running(self):
        f = self.feature();target = {'uid': 'owned', 'cid': 'cid', 'startTime': '2026-11-05T00:00:00Z'}
        running = {'state': 'CONTAINER_RUNNING'}
        self.assertIsNone(f.terminal_record(running, target, 10))
        exited = {'state': 'CONTAINER_EXITED', 'exitCode': 0, 'finishedAt': '2026-11-05T00:00:02.123456789Z', 'reason': 'Completed'}
        self.assertEqual(f.terminal_record(exited, target, 10)['cid'], 'cid')
        for field, value in [('exitCode', True), ('finishedAt', ''), ('state', 'CONTAINER_UNKNOWN')]:
            current = dict(exited);current[field] = value
            with self.assertRaises(AssertionError): f.terminal_record(current, target, 10)


if __name__ == '__main__': unittest.main()
