"""Actual counter-read bracketing; no evaluator or runtime input is wired."""
import pathlib
import tempfile
import unittest

from test_observer_ownership import Inputs


class CounterReadBrackets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = pathlib.Path(self.tmp.name) / 'out'
        self.out.mkdir()
        self.inputs = Inputs(self.out)
        self.reads = []
        self.fail_read = None
        self.missing_pair = None
        self.values = {}
        original = self.inputs.canonical
        owner = self
        def canonical(path):
            base = original(path)
            if str(path).startswith('/bin/'):
                return base
            class Counter:
                def __truediv__(self, name):
                    actual = base / name
                    class Read:
                        def read_text(self):
                            start = owner.inputs.clock.monotonic()
                            owner.inputs.clock.value += .001
                            owner.reads.append((start, owner.inputs.clock.monotonic()))
                            if len(owner.reads) == owner.fail_read:
                                raise OSError('synthetic counter read failed')
                            if (str(path), name) == owner.missing_pair:
                                raise FileNotFoundError('synthetic missing counter')
                            if name in owner.values:
                                return owner.values[name]
                            return actual.read_text()
                    return Read()
            return Counter()
        self.inputs.ns['canonical'] = canonical
        command = self.inputs.command
        queries = 0
        def first_then_empty(args, **kwargs):
            nonlocal queries
            if 'ps' in args:
                queries += 1
                if queries == 2:
                    return '[]'
            return command(args, **kwargs)
        self.inputs.ns['command'] = first_then_empty

    def test_verified_row_brackets_all_sequential_counter_reads(self):
        self.inputs.observe_nonwindow()
        rows = self.inputs.read_counter_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn('counterReadStart', row, 'sample-start is not the actual counter-read boundary')
        self.assertIn('counterReadEnd', row)
        self.assertEqual(row['counterReadStart'], self.reads[0][0])
        self.assertEqual(row['counterReadEnd'], self.reads[-1][1])
        self.assertGreater(row['counterReadEnd'], row['counterReadStart'])
        self.assertLessEqual(row['monotonic'], row['counterReadStart'])
        self.assertEqual(row['status'], 'verified')
        self.assertEqual(self.inputs.capture_count, 3)
        self.assertEqual(self.inputs.read('observer-result.json')['status'], 'OBSERVED')

    def test_actual_written_row_passes_complete_parser_and_aggregate_counter_checks(self):
        self.values['pids.max'] = '256'
        self.inputs.observe_nonwindow()
        raw = (self.out / 'counters.jsonl').read_bytes()
        rows = self.inputs.ns['complete_rows'](raw, 130.)
        self.assertEqual(rows, self.inputs.read_counter_rows())
        values = self.inputs.ns['_accounting_values'](rows, self.inputs.group)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]['memory.current'], 1024)
        self.assertEqual(values[0]['cpu.stat']['usage_usec'], 2)

    def test_missing_context_counter_is_recorded_but_not_used_as_aggregate(self):
        self.values['pids.max'] = '256'
        self.missing_pair = ('/sys/fs/cgroup/', 'memory.current')
        self.inputs.observe_nonwindow()
        rows = self.inputs.ns['complete_rows']((self.out / 'counters.jsonl').read_bytes(), 130.)
        self.assertEqual(rows[0]['groups']['/']['memory.current'], {'unavailable': True})
        self.assertEqual(self.inputs.ns['_accounting_values'](rows, self.inputs.group)[0]['memory.current'], 1024)

    def test_missing_owned_counter_keeps_invalid_row_and_actual_end(self):
        self.missing_pair = ('/sys/fs/cgroup' + self.inputs.group, 'memory.current')
        with self.assertRaisesRegex(AssertionError, '^required counter unavailable$'):
            self.inputs.observe_nonwindow()
        row = self.inputs.read_counter_rows()[0]
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['groups'][self.inputs.group]['memory.current'], {'unavailable': True})
        self.assertEqual(row['counterReadEnd'], self.reads[-1][1])
        raw=(self.out / 'counters.jsonl').read_bytes()
        with self.assertRaisesRegex(AssertionError, '^ROW_SHAPE$'):
            self.inputs.ns['complete_rows'](raw, 130.)
        self.assertFalse((self.out / 'observer-result.json').exists())

    def test_failed_read_keeps_actual_end_and_invalid_row_without_promotion(self):
        self.fail_read = 3
        with self.assertRaisesRegex(OSError, '^synthetic counter read failed$'):
            self.inputs.observe_nonwindow()
        row = self.inputs.read_counter_rows()[0]
        self.assertIn('counterReadStart', row, 'failed read must retain its actual bounded interval')
        self.assertIn('counterReadEnd', row)
        self.assertEqual(row['counterReadStart'], self.reads[0][0])
        self.assertEqual(row['counterReadEnd'], self.reads[-1][1])
        self.assertEqual(row['status'], 'invalid')
        self.assertEqual(row['failure'], 'OSError')
        self.assertEqual(self.inputs.capture_count, 2)
        self.assertFalse((self.out / 'observer-result.json').exists())


if __name__ == '__main__':
    unittest.main()
