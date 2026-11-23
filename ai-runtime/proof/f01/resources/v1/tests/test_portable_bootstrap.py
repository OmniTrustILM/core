"""Detect incorrect source defaults and generated files inside the checkout."""
import contextlib
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
KEYS = ('F01_OBSERVER_SOURCE', 'F01_DRIVER_SOURCE', 'F01_CANDIDATE_SOURCE')


class PortableBootstrap(unittest.TestCase):
    def load(self, overrides=None):
        env = {key: value for key, value in os.environ.items() if key not in KEYS}
        env.update(overrides or {})
        with tempfile.TemporaryDirectory(prefix='f01-bootstrap-cwd-') as cwd, \
                contextlib.chdir(cwd), patch.dict(os.environ, env, clear=True):
            namespace = runpy.run_path(str(HERE / 'bootstrap.py'))
            return {'environment': {key: os.environ.get(key) for key in KEYS},
                    'generated': '_EXTRACTED_DIRECTORY' in namespace or 'F01_OBSERVER_EXTRACTED' in os.environ}

    def test_defaults_load_adjacent_sources_independent_of_working_directory(self):
        result = self.load()['environment']
        self.assertEqual(result['F01_OBSERVER_SOURCE'], str(HERE.parent / 'python/observer.py'))
        self.assertEqual(result['F01_DRIVER_SOURCE'], str(HERE.parent / 'run-resources.sh'))
        self.assertEqual(result['F01_CANDIDATE_SOURCE'], str(HERE.parent.parent.parent))

    def test_bootstrap_uses_ordinary_source_without_generated_observer(self):
        self.assertFalse(self.load()['generated'])

    def test_explicit_source_and_extraction_overrides_are_preserved(self):
        with tempfile.TemporaryDirectory(prefix='f01-explicit-') as tmp:
            overrides = dict(zip(KEYS, (
                str(Path(tmp) / 'chosen-observer.sh'),
                str(Path(tmp) / 'chosen-driver.sh'),
                str(Path(tmp) / 'chosen-root'),
            )))
            self.assertEqual(self.load(overrides)['environment'], overrides)


if __name__ == '__main__':
    unittest.main()
