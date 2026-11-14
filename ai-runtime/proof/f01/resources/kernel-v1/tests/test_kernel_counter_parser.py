"""Fixed kernel-file byte/parser boundary, including actual new controller fields."""
import unittest
import importlib.util
from pathlib import Path
_spec = importlib.util.spec_from_file_location('kernel_observer_for_' + __name__, Path(__file__).parents[1] / 'python' / 'kernel_observer.py')
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)


class CounterParser(unittest.TestCase):
    def parse(self, name, raw):
        function = getattr(module, 'parse_field', None)
        self.assertTrue(callable(function), 'bounded fixed-field parser absent')
        return function(name, raw)

    def reject(self, name, raw, reason):
        self.assertTrue(callable(getattr(module, 'parse_field', None)), 'bounded fixed-field parser absent')
        with self.assertRaisesRegex(module.ProofError, '^' + reason + '$'):
            self.parse(name, raw)

    def test_fixed_scalars_and_quota_retain_raw_tokens_for_existing_predicates(self):
        self.assertEqual(self.parse('pids.max', b'256\n'), ['256'])
        self.assertEqual(self.parse('pids.current', b'7\n'), ['7'])
        self.assertEqual(self.parse('memory.swap.max', b'0\n'), ['0'])
        self.assertEqual(self.parse('pids.peak', b'339\n'), ['339'])
        self.assertEqual(self.parse('cpu.max', b'50000 100000\n'), ['50000', '100000'])

    def test_infinite_limit_is_not_allowed_for_instantaneous_or_event_counter(self):
        self.assertEqual(self.parse('pids.max', b'max\n'), ['max'])
        self.reject('pids.current', b'max\n', 'COUNTER_FORMAT')
        self.reject('pids.events', b'max max\n', 'COUNTER_FORMAT')

    def test_new_cgroup_maps_are_not_misparsed_as_scalar_lists(self):
        self.assertEqual(self.parse('cgroup.events', b'populated 1\nfrozen 0\n'), {'populated': 1, 'frozen': 0})
        self.assertEqual(self.parse('cgroup.stat', b'nr_descendants 2\nnr_dying_descendants 0\n'), {'nr_descendants': 2, 'nr_dying_descendants': 0})

    def test_duplicate_or_missing_required_map_field_stops(self):
        self.reject('pids.events', b'max 0\nmax 1\n', 'COUNTER_FORMAT')
        self.reject('cgroup.stat', b'nr_descendants 1\n', 'COUNTER_FORMAT')
        self.reject('cpu.stat', b'usage_usec 1\n', 'COUNTER_FORMAT')

    def test_all_map_values_are_nonnegative_bounded_ascii_integers(self):
        for raw in (b'max -1\n', b'max +1\n', b'max 1.0\n', b'max 9223372036854775808\n'):
            with self.subTest(raw=raw):
                self.reject('pids.events', raw, 'COUNTER_RANGE' if b'9223' in raw else 'COUNTER_FORMAT')
        self.reject('pids.current', '１\n'.encode(), 'COUNTER_BYTES')

    def test_unknown_file_and_unframed_or_excessive_bytes_stop(self):
        self.reject('unknown.controller', b'1\n', 'COUNTER_FILE')
        for raw in (b'1', b'1\r\n', b'1\0\n', b'x' * 8193 + b'\n'):
            with self.subTest(size=len(raw)):
                self.reject('pids.current', raw, 'COUNTER_BYTES')

    def test_counter_map_can_retain_numeric_kernel_extension_without_dropping_it(self):
        raw = b'usage_usec 100\nnr_throttled 2\ncore_sched.force_idle_usec 3\n'
        self.assertEqual(self.parse('cpu.stat', raw), {'usage_usec': 100, 'nr_throttled': 2, 'core_sched.force_idle_usec': 3})

    def test_quota_max_is_only_a_first_token_and_period_is_positive(self):
        self.assertEqual(self.parse('cpu.max', b'max 100000\n'), ['max', '100000'])
        for raw in (b'50000 max\n', b'max 0\n', b'50000 0\n', b'50000 100000\n1\n'):
            with self.subTest(raw=raw):
                self.reject('cpu.max', raw, 'COUNTER_FORMAT')


if __name__ == '__main__': unittest.main()
