import importlib.util
import inspect
from pathlib import Path
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('native_client', (Path(__file__).parents[1] / 'python' / 'kernel_runtime.py'));m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
PY = sys.executable


class Client(unittest.TestCase):
    def feature(self):
        self.assertIn('input', inspect.signature(m.bounded_command).parameters, 'bounded exact stdin adapter missing')
        return m.bounded_command
    def argv(self, body): return [PY, '-I', '-S', '-B', '-c', body]

    def test_exact_delete_input_bytes_and_default_eof_reach_only_owned_child(self):
        f = self.feature()
        self.assertEqual(f(self.argv('import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'), input=b'exact\n', raw=True), b'exact\n')
        self.assertEqual(f(self.argv('import sys;assert sys.stdin.buffer.read()==b"";print("EOF")')), 'EOF\n')

    def test_nonzero_keeps_only_plain_runtimeerror_query_family_and_native_code(self):
        f = self.feature()
        with self.assertRaises(RuntimeError) as caught: f(self.argv('raise SystemExit(7)'))
        self.assertIs(type(caught.exception), RuntimeError)
        self.assertEqual(caught.exception.native_exit_code, 7)

    def test_stderr_output_bound_and_native_timeout_are_distinct_stop_families(self):
        f = self.feature()
        with self.assertRaisesRegex(m.RuntimeProofError, '^COMMAND_STDERR$'): f(self.argv('import sys;sys.stderr.write("coded")'))
        with self.assertRaisesRegex(m.RuntimeProofError, '^COMMAND_OUTPUT_BOUND$'): f(self.argv('import os;os.write(1,b"x"*100)'), cap=10)
        with self.assertRaises(subprocess.TimeoutExpired): f(self.argv('import time;time.sleep(1)'), timeout=.05)

    def test_bad_input_or_timeout_is_refused_before_launch(self):
        f = self.feature()
        for kwargs in ({'input': 'notbytes'}, {'input': b'x' * 4097}, {'timeout': 3}, {'timeout': 0}):
            with self.subTest(kwargs={key: len(value) if type(value) is bytes else value for key, value in kwargs.items()}):
                with self.assertRaises(m.RuntimeProofError): f(['/not/a/program'], **kwargs)


if __name__ == '__main__': unittest.main()
