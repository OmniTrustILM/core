"""Actual private-file locking/metadata parser, synthetic runtime records only."""
import copy
import fcntl
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = (Path(__file__).parents[1] / 'python' / 'kernel_owner.py')
if PATH.exists():
    spec = importlib.util.spec_from_file_location('kernel_owner', PATH)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
else: module = None


class Owner(unittest.TestCase):
    def feature(self):
        self.assertIsNotNone(module, 'fixed runtime seed owner adapter absent')
        return module

    def fixture(self):
        m = self.feature();temp = tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve(strict=True)
        target = {'uid': '12345678-1234-1234-1234-123456789abc', 'cid': 'a' * 64, 'sid': 'b' * 64,
                  'name': 'f01-a2-process-limit', 'startTime': '2026-11-05T00:00:00Z'}
        metadata = {'id': target['sid'], 'pid': 100, 'podName': target['name'], 'namespace': 'ilm-resource-sec-r1'}
        paths = []
        for identity, pid in ((target['sid'], 200), (target['cid'], 300)):
            stem = identity + '_sandbox:' + target['sid'];path = root / (stem + '.state')
            path.write_text(json.dumps({'id': identity, 'sandbox': copy.deepcopy(metadata), 'goferPid': pid}))
            path.chmod(0o600);lock = root / (stem + '.lock');lock.write_bytes(b'');lock.chmod(0o600)
            paths.append(path)
        owner = patch.object(m, 'KERNEL_OWNER_UID', os.getuid());owner.start();self.addCleanup(owner.stop)
        return m, root, target, paths

    def test_current_pair_derives_exact_sentry_and_two_gofers_without_proc_scan(self):
        m, root, target, _ = self.fixture();result = m.runtime_candidates(root, target)
        self.assertEqual(result, [{'role': 'sentry', 'pid': 100}, {'role': 'sandbox-gofer', 'pid': 200}, {'role': 'container-gofer', 'pid': 300}])

    def test_foreign_id_namespace_or_sentry_disagreement_cannot_supply_candidates(self):
        self.feature()
        for field in ('id', 'namespace', 'pid'):
            with self.subTest(field=field):
                m, root, target, paths = self.fixture();value = json.loads(paths[1].read_bytes())
                if field == 'id': value['id'] = 'c' * 64
                else: value['sandbox'][field] = 'foreign' if field == 'namespace' else 999
                paths[1].write_text(json.dumps(value))
                with self.assertRaisesRegex(m.OwnerError, '^RUNTIME_OWNERSHIP$'):
                    m.runtime_candidates(root, target)

    def test_reused_or_boolean_gofer_pid_is_not_a_distinct_runtime_seed(self):
        self.feature()
        for pid in (100, 200, True, '300'):
            with self.subTest(pid=pid):
                m, root, target, paths = self.fixture();value = json.loads(paths[1].read_bytes());value['goferPid'] = pid;paths[1].write_text(json.dumps(value))
                with self.assertRaisesRegex(m.OwnerError, '^RUNTIME_SEED_TYPE$'):
                    m.runtime_candidates(root, target)

    def test_missing_duplicate_key_and_worldwritable_state_do_not_get_adopted(self):
        self.feature()
        for fault in ('missing', 'duplicate', 'writable'):
            with self.subTest(fault=fault):
                m, root, target, paths = self.fixture()
                if fault == 'missing': paths[0].unlink()
                elif fault == 'duplicate': paths[0].write_bytes(b'{"id":"x","id":"y"}')
                else: paths[0].chmod(0o666)
                with self.assertRaises(m.OwnerError): m.runtime_candidates(root, target)

    def test_actual_busy_runtime_lock_fails_once_before_reading_state(self):
        m, root, target, paths = self.fixture();lock = paths[0].with_suffix('.lock')
        with lock.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.OwnerError, '^RUNTIME_STATE_BUSY$'):
                m.runtime_candidates(root, target)

    def test_symlink_state_is_rejected_as_a_runtime_path(self):
        m, root, target, paths = self.fixture();old = paths[0].read_bytes();paths[0].unlink();outside = root / 'other';outside.write_bytes(old);outside.chmod(0o600);paths[0].symlink_to(outside)
        with self.assertRaisesRegex(m.OwnerError, '^RUNTIME_STATE_FILE$'):
            m.runtime_candidates(root, target)

    def test_fifo_state_rejected_without_waiting_for_a_writer(self):
        m, root, target, paths = self.fixture();paths[0].unlink();os.mkfifo(paths[0], 0o600)
        script = "import importlib.util,os,sys;spec=importlib.util.spec_from_file_location('fixed_owner',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.KERNEL_OWNER_UID=os.getuid()\ntry:m.runtime_candidates(sys.argv[2],__import__('json').loads(sys.argv[3]))\nexcept m.OwnerError as error:print(str(error));raise SystemExit(0)\nraise SystemExit(2)"
        try:
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, str(PATH), str(root), json.dumps(target)], capture_output=True, timeout=.5)
        except subprocess.TimeoutExpired:
            self.fail('FIFO opened before type check blocks the fixed ownership read')
        self.assertEqual(result.returncode, 0);self.assertEqual(result.stdout, b'RUNTIME_STATE_FILE\n');self.assertEqual(result.stderr, b'')

    def test_container_id_cannot_escape_the_fixed_runtime_state_root(self):
        m, root, target, _ = self.fixture();target['cid'] = '../outside'
        with self.assertRaisesRegex(m.OwnerError, '^TARGET$'):
            m.runtime_candidates(root, target)


if __name__ == '__main__': unittest.main()
