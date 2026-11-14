import importlib.util
from pathlib import Path
import subprocess
import unittest

spec = importlib.util.spec_from_file_location('sampled_kernel', (Path(__file__).parents[1] / 'python' / 'kernel_observer.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Sampling(unittest.TestCase):
    def fixture(self, terminal_at=1):
        f = getattr(m, 'sample_loop', None);self.assertIsNotNone(f, 'bounded kernel sampling loop missing')
        clock = [0.0];calls = [];published = []
        def terminal(): calls.append(('terminal', clock[0]));return {'state': 'CONTAINER_EXITED'} if clock[0] >= terminal_at else None
        def read(): calls.append(('read', clock[0]));return {'counters': {'pids.current': ['7']}, 'pidView': {}}
        def fence(): calls.append(('fence', clock[0]));return 'LIVE'
        def query(): calls.append(('query', clock[0]));return {'count': 7}
        def pump(terminal_only=False): calls.append(('pump-only' if terminal_only else 'pump', clock[0]))
        def sleep(value): clock[0] += value
        kwargs = dict(control='process-limit', deadline=2, observation_deadline=2, read=read,
                      fence=fence, terminal=terminal, query=query, pump=pump,
                      publish=lambda row: published.append(row), now=lambda: clock[0], sleep=sleep)
        return f, clock, calls, published, kwargs

    def test_rows_have_two_live_seed_fences_and_only_complete_intervals_publish(self):
        f, _, calls, rows, kwargs = self.fixture();result = f(**kwargs)
        self.assertEqual(result['terminal']['state'], 'CONTAINER_EXITED');self.assertGreaterEqual(len(rows), 10)
        self.assertEqual(sum(name == 'fence' for name, _ in calls), len(rows) * 2)
        self.assertEqual(sum(name == 'read' for name, _ in calls), len(rows))
        self.assertTrue(all(row['status'] == 'verified' and row['nativePids'] == 7 for row in rows))
        self.assertTrue(all(row['counterReadEnd'] < 2 for row in rows))

    def test_seed_exit_after_read_discards_candidate_and_permanently_quiesces(self):
        f, _, calls, rows, kwargs = self.fixture(.3);states = iter(['LIVE', 'EXITED']);kwargs['fence'] = lambda: next(states)
        result = f(**kwargs)
        self.assertEqual(rows, []);self.assertEqual(sum(name == 'read' for name, _ in calls), 1)
        self.assertEqual(result['quiescence'], 'SEED_EXIT');self.assertEqual(result['discarded'], 1)
        self.assertEqual(sum(name == 'pump' for name, _ in calls), 1)
        self.assertTrue(any(name == 'pump-only' for name, _ in calls))

    def test_only_plain_query_runtimeerror_can_enter_terminal_only_phase(self):
        f, _, calls, rows, kwargs = self.fixture(.3)
        def query(): raise RuntimeError('exact in-flight query nonzero')
        kwargs['query'] = query;result = f(**kwargs)
        self.assertEqual(rows, []);self.assertEqual(result['quiescence'], 'QUERY_NONZERO');self.assertEqual(result['discarded'], 1)
        self.assertEqual(sum(name == 'read' for name, _ in calls), 0)

    def test_timeout_subclass_and_validation_are_stop_not_terminal_fallback(self):
        self.fixture()
        class SpecialRuntimeError(RuntimeError): pass
        for error in (subprocess.TimeoutExpired(['exact'], 2), SpecialRuntimeError('x'), m.ProofError('x')):
            with self.subTest(error=type(error).__name__):
                f, _, _, _, kwargs = self.fixture()
                def query(): raise error
                kwargs['query'] = query
                with self.assertRaises(type(error)): f(**kwargs)

    def test_cpu_after30_is_terminal_only_without_new_query_fence_or_counters(self):
        f, clock, calls, rows, kwargs = self.fixture(30.3);clock[0] = 29.8
        kwargs.update(control='cpu-deadline', deadline=30, observation_deadline=35)
        result = f(**kwargs)
        self.assertEqual(result['terminal']['state'], 'CONTAINER_EXITED')
        self.assertTrue(all(when < 30 for name, when in calls if name in ('read', 'fence', 'query')))
        self.assertTrue(all(row['counterReadEnd'] < 30 for row in rows))

    def test_a_read_crossing_original_clock_is_uncredited_not_new_window(self):
        f, clock, _, rows, kwargs = self.fixture(.4)
        def read(): clock[0] = .21;return {'counters': {'pids.current': ['7']}, 'pidView': {}}
        kwargs.update(control='cpu-deadline', deadline=.2, observation_deadline=.5, read=read)
        result = f(**kwargs);self.assertEqual(rows, []);self.assertEqual(result['discarded'], 1)

    def test_terminal_absence_at_deadline_never_counts_as_native_exit(self):
        f, _, _, _, kwargs = self.fixture(3)
        with self.assertRaisesRegex(m.ProofError, '^TERMINAL_UNPROVEN$'): f(**kwargs)

    def test_one_complete_sample_preserves_clock_and_callback_order(self):
        f, clock, calls, rows, kwargs = self.fixture(.1)
        def now(): calls.append(('now', clock[0]));return clock[0]
        def publish(row): calls.append(('publish', clock[0]));rows.append(row)
        def sleep(value): calls.append(('sleep', value));clock[0] += value
        kwargs.update(now=now, publish=publish, sleep=sleep)
        result = f(**kwargs)
        names = [name for name, _ in calls]
        self.assertEqual(names, ['now', 'now', 'terminal', 'now', 'pump', 'now', 'now',
                                 'fence', 'query', 'now', 'now', 'read', 'now', 'now',
                                 'fence', 'now', 'publish', 'now', 'now', 'sleep', 'now', 'terminal'])
        self.assertEqual(calls[-3], ('sleep', .1))
        self.assertEqual(result['discarded'], 0)
        self.assertIsNone(result['quiescence'])
        self.assertEqual(rows, result['samples'])
        self.assertEqual(len(rows), 1)

    def test_publication_failure_propagates_without_retry_or_next_tick(self):
        f, _, calls, rows, kwargs = self.fixture()
        failure = RuntimeError('synthetic publication failure')
        attempts = []
        def publish(row): attempts.append(row);raise failure
        kwargs.update(publish=publish, sleep=lambda _: self.fail('failed publication reached next tick'))
        with self.assertRaises(RuntimeError) as caught:
            f(**kwargs)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]['status'], 'verified')
        self.assertEqual(rows, [])
        self.assertEqual(sum(name == 'terminal' for name, _ in calls), 1)


if __name__ == '__main__': unittest.main()
