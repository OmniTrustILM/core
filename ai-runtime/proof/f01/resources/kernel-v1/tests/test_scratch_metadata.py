"""Real temporary-filesystem metadata; no Linux sandbox or tmpfs proof credit."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).parents[1] / 'python/scratch_metadata.py'
spec = importlib.util.spec_from_file_location('candidate_scratch_metadata', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ScratchMetadataTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def holder(self, fence=lambda: 'LIVE', now=lambda: 1.0, source=None, deadline=30.0):
        feature = getattr(module, '_ScratchMetadata', None)
        self.assertIsNotNone(feature, 'two-snapshot metadata holder is missing')
        value = feature(source or self.root, deadline, fence, now)
        self.addCleanup(value.close)
        return value

    def test_two_real_metadata_snapshots_have_no_acceptance_or_contents(self):
        value = self.holder()
        baseline = value.before_go()
        self.assertEqual(baseline['status'], 'UNQUALIFIED_METADATA')
        self.assertEqual(baseline['phase'], 'BEFORE_GO')
        self.assertEqual(baseline['filesystem']['fragmentSize'], os.statvfs(self.root).f_frsize)
        payload = b'private-content-must-not-be-recorded' * 100
        (self.root / 'f01-scratch-fill').write_bytes(payload)
        filled = value.fill_held(len(payload))
        self.assertEqual(filled['status'], 'UNQUALIFIED_METADATA')
        self.assertEqual(filled['fillFile']['bytes'], 3600)
        self.assertEqual(filled['source'], baseline['source'])
        for record in (baseline, filled):
            self.assertIs(record['fullF01Accepted'], False)
            encoded = json.dumps(record).encode()
            self.assertLessEqual(len(encoded), 65536)
            self.assertNotIn(b'private-content', encoded)
        self.assertEqual(value.fill_held(len(payload))['reason'], 'CAPTURE_ORDER')

    def test_replaced_source_never_reads_the_replacement_directory(self):
        source = self.root / 'scratch'
        source.mkdir()
        value = self.holder(source=source)
        source.rename(self.root / 'old-owned-source')
        source.mkdir()
        record = value.before_go()
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertEqual(record['reason'], 'SOURCE_CHANGED')
        self.assertNotIn('filesystem', record)

    def test_symlinked_ancestor_is_not_followed_when_binding(self):
        actual = self.root / 'actual'
        actual.mkdir()
        source = actual / 'scratch'
        source.mkdir()
        alias = self.root / 'alias'
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises((OSError, module.MetadataUnavailable)):
            self.holder(source=alias / 'scratch')

    def test_removed_fill_after_capture_is_unavailable_even_with_live_seeds(self):
        calls = 0
        path = self.root / 'f01-scratch-fill'
        def fence():
            nonlocal calls
            calls += 1
            if calls == 4:
                path.unlink()
            return 'LIVE'
        value = self.holder(fence=fence)
        value.before_go()
        path.write_bytes(b'x' * 4096)
        record = value.fill_held(4096)
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertNotIn('filesystem', record)

    def test_replaced_fill_after_capture_is_not_confused_with_same_size_file(self):
        calls = 0
        path = self.root / 'f01-scratch-fill'
        def fence():
            nonlocal calls
            calls += 1
            if calls == 4:
                path.unlink()
                path.write_bytes(b'y' * 4096)
            return 'LIVE'
        value = self.holder(fence=fence)
        value.before_go()
        path.write_bytes(b'x' * 4096)
        record = value.fill_held(4096)
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertEqual(record['reason'], 'FILL_CHANGED')

    def test_fill_with_multiple_links_is_not_a_valid_fixed_file_observation(self):
        path = self.root / 'f01-scratch-fill'
        path.write_bytes(b'x' * 4096)
        os.link(path, self.root / 'second-link')
        value = self.holder()
        value.before_go()
        self.assertEqual(value.fill_held(4096)['status'], 'UNAVAILABLE')

    def test_missing_symlinked_and_wrong_size_fill_are_unavailable(self):
        for fault in ('missing', 'symlink', 'wrong-size'):
            with self.subTest(fault=fault):
                source = self.root / fault
                source.mkdir()
                if fault != 'missing':
                    other = source / 'other'
                    other.write_bytes(b'private' * 10)
                    if fault == 'symlink':
                        (source / 'f01-scratch-fill').symlink_to(other)
                    else:
                        other.rename(source / 'f01-scratch-fill')
                value = self.holder(source=source)
                value.before_go()
                record = value.fill_held(4096)
                self.assertEqual(record['status'], 'UNAVAILABLE')
                self.assertNotIn('private', json.dumps(record))

    def test_untyped_marker_cannot_skip_fill_identity_checks(self):
        for marker in (None, True):
            with self.subTest(marker=marker):
                (self.root / 'f01-scratch-fill').write_bytes(b'x')
                value = self.holder()
                value.before_go()
                self.assertEqual(value.fill_held(marker)['status'], 'UNAVAILABLE')

    def test_deadline_prevents_ownership_work_and_late_reads_keep_no_partial_metadata(self):
        calls = 0
        def fence():
            nonlocal calls
            calls += 1
            return 'LIVE'
        with self.assertRaises(module.MetadataUnavailable):
            self.holder(fence=fence, now=lambda: 30.0)
        self.assertEqual(calls, 0)
        clock = [1.0]
        ownership_calls = 0
        def late_fence():
            nonlocal ownership_calls
            ownership_calls += 1
            if ownership_calls == 2:
                clock[0] = 30.0
            return 'LIVE'
        late = self.holder(now=lambda: clock[0], fence=late_fence)
        record = late.before_go()
        self.assertEqual(record['reason'], 'DEADLINE')
        self.assertNotIn('filesystem', record)

    def test_backward_clock_cannot_label_an_observation_available(self):
        clock = [0.0]
        def fence():
            clock[0] = 1.0
            return 'LIVE'
        value = self.holder(now=lambda: clock[0], fence=fence)
        clock[0] = 2.0
        self.assertEqual(value.before_go()['status'], 'UNAVAILABLE')

    def test_invalid_deadline_is_rejected_before_directory_binding(self):
        for deadline in (True, float('inf'), float('nan'), -1):
            with self.subTest(deadline=deadline), self.assertRaises(module.MetadataUnavailable):
                self.holder(deadline=deadline)

    def test_failed_baseline_has_no_fill_fallback_or_second_ownership_attempt(self):
        calls = 0
        def fence():
            nonlocal calls
            calls += 1
            return 'EXITED'
        value = self.holder(fence=fence)
        self.assertEqual(value.before_go()['status'], 'UNAVAILABLE')
        self.assertEqual(value.fill_held(1)['reason'], 'BASELINE_UNAVAILABLE')
        self.assertEqual(calls, 1)

    def test_owner_failure_never_records_exception_text(self):
        def fence():
            raise AssertionError('private-provider-and-token-text')
        record = self.holder(fence=fence).before_go()
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertNotIn('private-provider', json.dumps(record))

    def test_external_diagnostic_exception_cannot_smuggle_its_message_into_record(self):
        def fence():
            raise module.MetadataUnavailable('private-token-should-not-be-returned')
        record = self.holder(fence=fence).before_go()
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertNotIn('private-token', json.dumps(record))

    def test_expired_ownership_check_prevents_following_metadata_path_work(self):
        source = self.root / 'scratch'
        source.mkdir()
        clock = [1.0]
        def fence():
            clock[0] = 30.0
            source.rename(self.root / 'old-source')
            return 'LIVE'
        value = self.holder(source=source, now=lambda: clock[0], fence=fence)
        self.assertEqual(value.before_go()['reason'], 'DEADLINE')

    def test_closed_holder_is_unavailable_and_is_never_reopened(self):
        value = self.holder()
        value.close()
        try:
            record = value.before_go()
        except Exception as error:
            self.fail('closed holder leaked ' + type(error).__name__)
        self.assertEqual(record['status'], 'UNAVAILABLE')
        self.assertEqual(record['reason'], 'CLOSED')

    def test_fixed_source_accepts_only_the_derived_owned_oci_path(self):
        feature = getattr(module, 'fixed_source', None)
        self.assertIsNotNone(feature, 'fixed OCI source binding is missing')
        uid = '8115e77c-cce8-49c3-97b4-08b776ebb0e5'
        expected = '/var/lib/kubelet/pods/' + uid + '/volumes/kubernetes.io~empty-dir/scratch'
        self.assertEqual(str(feature({'uid': uid}, {'scratch': expected})), expected)
        for target, projection in [({'uid': '../escape'}, {'scratch': expected}),
                                   ({'uid': uid}, {'scratch': '/tmp/foreign'}),
                                   ({'uid': uid}, {'scratch': expected + '/..'})]:
            with self.subTest(target=target), self.assertRaises(module.MetadataUnavailable):
                feature(target, projection)

    @unittest.skipUnless(os.uname().sysname == 'Darwin', 'macOS-specific unsupported platform boundary')
    def test_live_factory_refuses_macos_without_emulating_linux_ownership(self):
        feature = getattr(module, 'bind_scratch', None)
        self.assertIsNotNone(feature, 'Linux-only live factory is missing')
        with self.assertRaises(module.MetadataUnavailable):
            feature({}, {}, 30.0, lambda: 'LIVE')


if __name__ == '__main__':
    unittest.main()
