import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('measured_kernel', (Path(__file__).parents[1] / 'python' / 'kernel_observer.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class FakeGroup:
    values = {}
    identities = {}
    closed = []
    def __init__(self, root): self.root = Path(root)
    @property
    def identity(self): return self.identities[str(self.root)]
    def check(self): pass
    def read_field(self, key): return self.values[str(self.root)][key]
    def directory_limits(self): return {'/cg/ancestor/pod': ['256'], '/cg/ancestor/pod/scope': ['max']}
    def __enter__(self): return self
    def __exit__(self, *_): self.closed.append(str(self.root))


class Measurement(unittest.TestCase):
    def feature(self):
        f = getattr(m, 'KernelMeasurement', None);self.assertIsNotNone(f, 'kernel directory measurement missing');return f

    def fixture(self):
        f = self.feature();FakeGroup.values = {
            '/cg/ancestor/pod': {'pids.max': ['256'], 'pids.current': ['7'], 'pids.events': {'max': 0}, 'pids.events.local': {'max': 0}, 'memory.max': ['268435456'], 'memory.current': ['1048576'], 'memory.peak': ['2097152'], 'memory.swap.max': ['0'], 'memory.events': {'max': 0, 'oom': 0, 'oom_kill': 0}, 'cpu.max': ['50000', '100000'], 'cpu.stat': {'usage_usec': 1, 'nr_throttled': 0}, 'cgroup.stat': {'nr_descendants': 1, 'nr_dying_descendants': 0}},
            '/cg/ancestor/pod/scope': {'pids.events': {'max': 0}, 'pids.events.local': {'max': 0}, 'memory.max': ['max']},
            '/cg/ancestor': {'pids.max': ['1000'], 'pids.current': ['50'], 'pids.peak': ['100']}}
        FakeGroup.identities = {'/cg/ancestor/pod': [1, 20], '/cg/ancestor/pod/scope': [1, 21], '/cg/ancestor': [1, 10]}
        FakeGroup.closed = []
        return f(FakeGroup('/cg/ancestor/pod'), ['/ancestor/pod/scope'] * 3, [None, None], '/cg')

    def test_reads_hierarchical_parent_not_sentry_only_and_keeps_each_event_origin(self):
        with patch.object(m, 'PodCgroup', FakeGroup), patch.object(Path, 'stat') as info:
            info.return_value.st_mode = 0o444;value = self.fixture();row = value.read()
        self.assertEqual(row['counters']['pids.current'], ['7'])
        self.assertEqual(row['pidView']['seedCgroups'], ['/cg/ancestor/pod/scope'] * 3)
        self.assertEqual(row['pidView']['groups']['/cg/ancestor/pod/scope']['events'], 0)
        self.assertEqual(set(FakeGroup.closed), {'/cg/ancestor/pod/scope', '/cg/ancestor'})

    def test_measurement_preserves_nonlimiting_finite_descendant_cap(self):
        limits = {'/cg/ancestor/pod': ['256'], '/cg/ancestor/pod/scope': ['28834']}
        with patch.object(m, 'PodCgroup', FakeGroup), patch.object(
                FakeGroup, 'directory_limits', return_value=limits):
            row = self.fixture().read()
        self.assertEqual(row['pidView']['groups']['/cg/ancestor/pod']['max'], 256)
        self.assertEqual(row['pidView']['groups']['/cg/ancestor/pod/scope']['max'], 28834)
        self.assertEqual(row['pidView']['seedCgroups'], ['/cg/ancestor/pod/scope'] * 3)

    def test_local_counter_same_scope_and_resource_floor_are_required_each_read(self):
        self.feature()
        for fault, reason in (('local', 'CGROUP_TOPOLOGY'), ('scope', 'SEED_SCOPE'), ('limit', 'RESOURCE_FLOOR')):
            with self.subTest(fault=fault), patch.object(m, 'PodCgroup', FakeGroup), patch.object(Path, 'stat') as info:
                info.return_value.st_mode = 0o444;value = self.fixture()
                if fault == 'local': FakeGroup.values['/cg/ancestor/pod']['pids.events.local'] = {'max': -1}
                elif fault == 'scope': value.seed_cgroups[-1] = '/cg/ancestor/pod/foreign'
                else: FakeGroup.values['/cg/ancestor/pod']['memory.swap.max'] = ['1']
                with self.assertRaisesRegex(m.ProofError, '^' + reason + '$'): value.read()

    def test_scope_object_replacement_is_stop_even_when_parent_is_unchanged(self):
        with patch.object(m, 'PodCgroup', FakeGroup), patch.object(Path, 'stat') as info:
            info.return_value.st_mode = 0o444;value = self.fixture();value.read()
            FakeGroup.identities['/cg/ancestor/pod/scope'] = [1, 999]
            with self.assertRaisesRegex(m.ProofError, '^CGROUP_IDENTITY$'): value.read()

    def test_parent_path_must_be_beneath_fixed_mount_and_seeds_beneath_parent(self):
        f = self.feature()
        with self.assertRaisesRegex(m.ProofError, '^CGROUP_IDENTITY$'):
            f(FakeGroup('/elsewhere/pod'), ['/pod/scope'] * 3, [None, None], '/cg')


if __name__ == '__main__': unittest.main()
