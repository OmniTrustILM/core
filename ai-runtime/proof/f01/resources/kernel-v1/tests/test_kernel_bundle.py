import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

P = (Path(__file__).parents[1] / 'python' / 'kernel_collect.py');spec = importlib.util.spec_from_file_location('bundle_kernel', P);m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Bundle(unittest.TestCase):
    def fixture(self):
        f = getattr(m, 'verify_bundle', None);self.assertIsNotNone(f, 'fixed bundle byte/mode custody absent')
        temp = tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root = Path(temp.name).resolve()
        rows = []
        for name in sorted(m.BUNDLE_FILES):
            p = root / name;p.parent.mkdir(exist_ok=True)
            raw = b'# inert fixture\n';p.write_bytes(raw);p.chmod(0o600)
            rows.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        raw = (json.dumps({'schema': 'f01-kernel-bundle-v1', 'files': rows}) + '\n').encode()
        p = root / 'bundle-manifest.json';p.write_bytes(raw);p.chmod(0o600)
        owner = patch.object(m, 'KERNEL_OWNER_UID', os.getuid());owner.start();self.addCleanup(owner.stop)
        return f, root, raw

    def test_every_expected_regular_byte_is_verified_and_unchanged_closure_is_live(self):
        f, root, _ = self.fixture();values, unchanged = f(root)
        self.assertEqual(set(values), set(m.BUNDLE_FILES));unchanged()
        target = root / 'kernel_owner.py';target.write_bytes(b'changed')
        with self.assertRaises(AssertionError): unchanged()

    def test_extra_missing_duplicate_or_path_traversal_entry_fails_closed(self):
        self.fixture()
        for fault in ('extra', 'missing', 'duplicate', 'traversal'):
            with self.subTest(fault=fault):
                f, root, raw = self.fixture();value = json.loads(raw)
                if fault == 'extra': value['files'].append({'path': 'extra.py', 'bytes': 1, 'sha256': '0' * 64})
                elif fault == 'missing': value['files'].pop()
                elif fault == 'duplicate': value['files'].append(value['files'][0])
                else: value['files'][0]['path'] = '../outside'
                (root / 'bundle-manifest.json').write_text(json.dumps(value))
                with self.assertRaises(AssertionError): f(root)

    def test_symlink_writable_owner_file_and_manifest_replacement_are_not_adopted(self):
        self.fixture()
        for fault in ('symlink', 'writable', 'manifest'):
            with self.subTest(fault=fault):
                f, root, _ = self.fixture();p = root / 'kernel_owner.py'
                if fault == 'symlink': p.unlink();p.symlink_to(root / 'kernel_observer.py')
                elif fault == 'writable': p.chmod(0o666)
                if fault != 'manifest':
                    with self.assertRaises((AssertionError, OSError)): f(root)
                else:
                    _, unchanged = f(root);p = root / 'bundle-manifest.json';raw = p.read_bytes();p.unlink();p.write_bytes(raw);p.chmod(0o600)
                    with self.assertRaises(AssertionError): unchanged()


if __name__ == '__main__': unittest.main()
