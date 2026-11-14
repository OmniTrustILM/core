"""Fixed kernel-cgroup proof predicates; no task-census or runtime action on import."""
from pathlib import Path, PurePosixPath
from copy import deepcopy
import os
import stat


class ProofError(AssertionError):
    pass


def require(condition, reason):
    if not condition:
        raise ProofError(reason)


def integer(value):
    return type(value) is int and 0 <= value < 2 ** 63


def identity(value):
    return (type(value) is list and len(value) == 2 and
            all(integer(item) for item in value) and value[1] > 0)


def path(value):
    return (type(value) is str and value.startswith('/') and value != '/' and
            str(PurePosixPath(value)) == value and '..' not in value.split('/'))


def validate_pid_view(view):
    """Exact256 parent; requires separately calibrated normal-v2 local-event semantics."""
    require(type(view) is dict, 'PID_VIEW')
    require(view.get('eventMode') == 'v2-failing-limit-local', 'PID_EVENT_MODE')
    root = view.get('parent');groups = view.get('groups')
    require(path(root) and type(groups) is dict and root in groups, 'PID_VIEW')
    count = view.get('nrDescendants');dying = view.get('nrDyingDescendants')
    require(integer(count) and count <= 16 and count == len(groups) - 1 and
            integer(dying) and dying <= 16, 'CGROUP_TOPOLOGY')
    for name, record in groups.items():
        require(path(name) and (name == root or name.startswith(root + '/')) and
                type(record) is dict and identity(record.get('identity')) and
                integer(record.get('events')) and integer(record.get('localEvents')),
                'CGROUP_TOPOLOGY')
        if name == root:
            require(type(record.get('max')) is int and record['max'] == 256, 'POD_PID_LIMIT')
        else:
            limit = record.get('max')
            require(limit is None or integer(limit) and limit > 256, 'DESCENDANT_PID_LIMIT')
    seeds = view.get('seedCgroups')
    require(type(seeds) is list and len(seeds) == 3 and
            len(set(seeds)) == 1 and seeds[0] in groups and seeds[0] != root, 'SEED_SCOPE')
    require(view.get('ociPids') == [None, None], 'OCI_PID_LIMIT')
    ancestors = view.get('ancestors')
    require(type(ancestors) is dict and bool(ancestors), 'ANCESTOR_COUNTER')
    for name, record in ancestors.items():
        require(path(name) and root.startswith(name + '/') and type(record) is dict and
                identity(record.get('identity')), 'ANCESTOR_COUNTER')
        limit = record.get('max')
        require(limit is None or integer(limit) and limit > 0, 'ANCESTOR_COUNTER')
    return seeds[0]


def pid_denial_delta(before, after):
    """Only actual limiting-Pod local MAX delta grants credit; never peak/origin inference."""
    scope = validate_pid_view(before)
    require(validate_pid_view(after) == scope and before['parent'] == after['parent'],
            'CGROUP_IDENTITY')
    require(before['ancestors'].keys() == after['ancestors'].keys(), 'ANCESTOR_IDENTITY')
    for name, record in before['ancestors'].items():
        current = after['ancestors'][name]
        require(record['identity'] == current['identity'] and record['max'] == current['max'],
                'ANCESTOR_IDENTITY')
    for name in (before['parent'], scope):
        original = before['groups'][name];current = after['groups'][name]
        require(original['identity'] == current['identity'], 'CGROUP_IDENTITY')
        for field in ('events', 'localEvents'):
            require(current[field] >= original[field], 'PID_EVENT_RESET')
    deltas = {key: after['groups'][name][field] - before['groups'][name][field]
              for key, name, field in (('parentLocal', before['parent'], 'localEvents'),
                                       ('parentHierarchical', before['parent'], 'events'),
                                       ('forkLocal', scope, 'localEvents'))}
    require(deltas['parentLocal'] > 0, 'PID_DENIAL_EVENT_UNPROVEN')
    return deltas


class SeedExitSymptom(Exception):
    """Only a known proc-missing/zombie/exe-ENOENT observation, never generic IO."""


def _poll_seed_exit(fds, wait, deadline, poller, now):
    require(now() < deadline, 'DEADLINE')
    values = poller(fds, wait)
    require(now() < deadline, 'DEADLINE')
    require(type(values) is list and len(values) <= 3 and
            all(type(fd) is int and fd in fds for fd in values) and
            len(set(values)) == len(values), 'PIDFD_STATE')
    return bool(values)


def seed_fence(seeds, deadline, reader, poller, now):
    """One bounded confirmation of exit symptoms; never retry a capture or query."""
    require(type(seeds) is list and len(seeds) == 3, 'PIDFD_STATE')
    fds = [seed['fd'] for seed in seeds]
    require(all(type(fd) is int and fd >= 0 for fd in fds) and len(set(fds)) == 3,
            'PIDFD_STATE')

    if _poll_seed_exit(fds, 0, deadline, poller, now):
        return 'EXITED'
    for seed in seeds:
        try:
            current = reader(seed['identity']['pid'])
        except SeedExitSymptom:
            remaining = deadline - now()
            require(remaining > 0, 'DEADLINE')
            if _poll_seed_exit(fds, min(2, remaining), deadline, poller, now):
                return 'EXITED'
            raise ProofError('SEED_NOT_EXITED')
        original = seed['identity']
        require(type(current) is dict and current.keys() == original.keys() and
                all(type(current[key]) is type(value) and current[key] == value
                    for key, value in original.items()), 'SEED_IDENTITY')
        if _poll_seed_exit(fds, 0, deadline, poller, now):
            return 'EXITED'
    return 'LIVE'


SCALARS = frozenset(('pids.max', 'pids.current', 'pids.peak', 'memory.max',
                     'memory.current', 'memory.peak', 'memory.swap.max'))
LIMITS = frozenset(('pids.max', 'memory.max', 'memory.swap.max'))
MAP_FIELDS = {'pids.events': frozenset(('max',)),
              'pids.events.local': frozenset(('max',)),
              'memory.events': frozenset(('max', 'oom', 'oom_kill')),
              'cpu.stat': frozenset(('usage_usec', 'nr_throttled')),
              'cgroup.events': frozenset(('populated', 'frozen')),
              'cgroup.stat': frozenset(('nr_descendants', 'nr_dying_descendants'))}


def counter_integer(text):
    require(bool(text) and len(text) <= 20 and text.isascii() and text.isdecimal(),
            'COUNTER_FORMAT')
    value = int(text)
    require(integer(value), 'COUNTER_RANGE')
    return value


def _scalar_fields(name, text):
    require('\n' not in text, 'COUNTER_FORMAT')
    fields = text.split()
    require(len(fields) == (2 if name == 'cpu.max' else 1), 'COUNTER_FORMAT')
    for index, field in enumerate(fields):
        if field == 'max' and index == 0 and (name in LIMITS or name == 'cpu.max'):
            continue
        value = counter_integer(field)
        if name == 'cpu.max' and index == 1:
            require(value > 0, 'COUNTER_FORMAT')
    return fields


def _map_fields(name, text):
    values = {}
    lines = text.splitlines()
    require(1 <= len(lines) <= 128, 'COUNTER_FORMAT')
    for line in lines:
        fields = line.split()
        require(len(fields) == 2, 'COUNTER_FORMAT')
        key, number = fields
        require(0 < len(key) <= 64 and (key[0].islower() or key[0] == '_') and
                all(char.islower() or char.isdigit() or char in '_.' for char in key) and
                key not in values, 'COUNTER_FORMAT')
        values[key] = counter_integer(number)
    require(MAP_FIELDS[name] <= values.keys(), 'COUNTER_FORMAT')
    return values


def parse_field(name, raw):
    """Fixed cgroup files only; preserve every numeric map field, reject duplicates."""
    require(name in SCALARS or name in MAP_FIELDS or name == 'cpu.max', 'COUNTER_FILE')
    require(type(raw) is bytes and 0 < len(raw) <= 8192 and raw.endswith(b'\n') and
            all(byte in (9, 10) or 32 <= byte <= 126 for byte in raw), 'COUNTER_BYTES')
    text = raw[:-1].decode('ascii')
    if name in SCALARS or name == 'cpu.max':
        return _scalar_fields(name, text)
    return _map_fields(name, text)


KERNEL_OWNER_UID = 0


class PodCgroup:
    """Read fixed controller files through one pinned directory, never task lists."""
    def __init__(self, root):
        self.root = Path(root)
        self.fd = None
        require(self.root.is_absolute() and self.root.resolve(strict=True) == self.root,
                'CGROUP_IDENTITY')
        try:
            self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            current = os.fstat(self.fd)
            require(current.st_uid == KERNEL_OWNER_UID and not current.st_mode & 0o022,
                    'CGROUP_OWNER')
            require(stat.S_ISDIR(current.st_mode), 'CGROUP_IDENTITY')
            self._identity = (current.st_dev, current.st_ino)
            attributes = os.listxattr(self.root)
            require(not {'system.posix_acl_access', 'system.posix_acl_default'}.intersection(attributes),
                    'CGROUP_DELEGATION')
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def identity(self):
        return list(self._identity)

    def check(self):
        try:
            current = self.root.lstat()
        except OSError as error:
            raise ProofError('CGROUP_IDENTITY') from error
        require(stat.S_ISDIR(current.st_mode) and
                (current.st_dev, current.st_ino) == self._identity, 'CGROUP_IDENTITY')
        require(current.st_uid == KERNEL_OWNER_UID and not current.st_mode & 0o022,
                'CGROUP_OWNER')

    def check_retained(self):
        """A captured endpoint keeps its original FD; a replacement path is never accepted."""
        require(type(self.fd) is int and self.fd >= 0, 'CGROUP_IDENTITY')
        try:
            held = os.fstat(self.fd)
            require(stat.S_ISDIR(held.st_mode) and (held.st_dev, held.st_ino) == self._identity,
                    'CGROUP_IDENTITY')
            require(held.st_uid == KERNEL_OWNER_UID and not held.st_mode & 0o022, 'CGROUP_OWNER')
            try:
                current = self.root.lstat()
            except FileNotFoundError:
                return False
            require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == self._identity,
                    'CGROUP_IDENTITY')
            require(current.st_uid == KERNEL_OWNER_UID and not current.st_mode & 0o022, 'CGROUP_OWNER')
            return True
        except OSError as error:
            raise ProofError('CGROUP_IDENTITY') from error

    def _read(self, name):
        require(name in SCALARS or name in MAP_FIELDS or name in ('cpu.max', 'cgroup.type'),
                'COUNTER_FILE')
        self.check()
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.fd)
            original = os.fstat(fd)
            require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1 and
                    original.st_dev == self._identity[0], 'COUNTER_PATH')
            require(original.st_uid == KERNEL_OWNER_UID and not original.st_mode & 0o022,
                    'CGROUP_OWNER')
            data = bytearray()
            while len(data) <= 8192:
                chunk = os.read(fd, 8193 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            require(len(data) <= 8192, 'COUNTER_BYTES')
            current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_ISREG(current.st_mode) and
                    (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                    'COUNTER_IDENTITY')
            self.check()
            return bytes(data)
        except OSError as error:
            raise ProofError('COUNTER_PATH') from error
        finally:
            if fd is not None:
                os.close(fd)

    def read_field(self, name):
        require(name in SCALARS or name in MAP_FIELDS or name == 'cpu.max', 'COUNTER_FILE')
        return parse_field(name, self._read(name))

    def directory_limits(self):
        initial = self.read_field('cgroup.stat')
        require(initial['nr_descendants'] <= 16 and initial['nr_dying_descendants'] <= 16,
                'CGROUP_TOPOLOGY')
        limits = {}

        def visit(group):
            require(len(limits) <= 16 and group._read('cgroup.type') == b'domain\n',
                    'CGROUP_TOPOLOGY')
            limits[str(group.root)] = group.read_field('pids.max')
            with os.scandir(group.fd) as entries:
                for entry in entries:
                    require(not entry.is_symlink(), 'CGROUP_TOPOLOGY')
                    if entry.is_dir(follow_symlinks=False):
                        with PodCgroup(group.root / entry.name) as child:
                            visit(child)
            group.check()

        visit(self)
        final = self.read_field('cgroup.stat')
        require(initial['nr_descendants'] == final['nr_descendants'] == len(limits) - 1 and
                final['nr_dying_descendants'] <= 16, 'CGROUP_TOPOLOGY')
        return limits

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _proc_bytes(base, name):
    try:
        with (base / name).open('rb') as stream:
            raw = stream.read(65537)
    except FileNotFoundError as error:
        raise SeedExitSymptom('PROC_MISSING') from error
    require(0 < len(raw) <= 65536, 'PROC_BYTES')
    return raw


def read_seed_identity(pid, proc_root='/proc'):
    """Read one known leader only; ENOENT/zombie is exit-pending, never credit."""
    require(type(pid) is int and 1 < pid < 2 ** 31, 'SEED_IDENTITY')
    base = Path(proc_root) / str(pid)
    raw = _proc_bytes(base, 'stat')
    require(raw.endswith(b'\n') and b' (' in raw and b') ' in raw, 'PROC_STAT')
    head, tail = raw.rsplit(b') ', 1)
    fields = tail.split()
    require(len(fields) >= 20 and head.split(b' ', 1)[0] == str(pid).encode(), 'PROC_STAT')
    if fields[0] in (b'Z', b'X', b'x'):
        raise SeedExitSymptom('PROC_ZOMBIE')
    require(fields[0] in tuple(bytes([char]) for char in b'RSDTtWPI') and
            fields[19].isascii() and fields[19].isdigit(), 'PROC_STAT')
    start = counter_integer(fields[19].decode('ascii'))
    require(start > 0, 'PROC_STAT')
    status = {}
    for line in _proc_bytes(base, 'status').decode('ascii').splitlines():
        require(':' in line, 'PROC_STATUS')
        key, value = line.split(':', 1)
        require(key not in status, 'PROC_STATUS')
        status[key] = value.strip()
    require(status.get('Tgid') == status.get('Pid') == str(pid), 'PROC_STATUS')
    credentials = {}
    for key in ('Uid', 'Gid'):
        values = status.get(key, '').split()
        require(len(values) == 4, 'PROC_STATUS')
        credentials[key.lower()] = [counter_integer(value) for value in values]
    caps = status.get('CapEff', '')
    require(0 < len(caps) <= 16 and all(char in '0123456789abcdef' for char in caps),
            'PROC_STATUS')
    cgroup = _proc_bytes(base, 'cgroup').decode('ascii')
    require(cgroup.endswith('\n') and cgroup.count('\n') == 1 and
            cgroup.startswith('0::') and path(cgroup[3:-1]), 'PROC_CGROUP')
    args = _proc_bytes(base, 'cmdline')
    require(args.endswith(b'\0') and args != b'\0', 'PROC_ARGS')
    try:
        executable = (base / 'exe').stat()
        executable_path = os.readlink(base / 'exe')
    except FileNotFoundError as error:
        raise SeedExitSymptom('PROC_EXE_MISSING') from error
    require(stat.S_ISREG(executable.st_mode), 'PROC_EXE')
    return {'pid': pid, 'startTicks': start, 'cgroup': cgroup[3:-1],
            'exe': executable_path, 'exeIdentity': [executable.st_dev, executable.st_ino],
            'args': [value.decode('utf-8', 'strict') for value in args[:-1].split(b'\0')],
            'uid': credentials['uid'], 'gid': credentials['gid'], 'capEff': caps}


RESOURCE_FIELDS = ('pids.max', 'pids.current', 'pids.events', 'pids.events.local', 'memory.max',
                   'memory.current', 'memory.peak', 'memory.swap.max',
                   'memory.events', 'cpu.max', 'cpu.stat')


def _require_resource_floor(counters):
    require(counters['pids.max'] == ['256'] and counters['memory.max'] == ['268435456'] and
            counters['memory.swap.max'] == ['0'] and counters['cpu.max'] == ['50000', '100000'],
            'RESOURCE_FLOOR')


def validate_terminal_parent(value, origin):
    require(type(value) is dict and set(value) == {'schema', 'parentOrigin', 'counters'} and
            value['schema'] == 'f01-terminal-parent-counters-v1', 'TERMINAL_COUNTER_SCHEMA')
    require(type(origin) is list and len(origin) == 2 and path(origin[0]) and identity(origin[1]) and
            value['parentOrigin'] == origin, 'CGROUP_IDENTITY')
    require(type(value['counters']) is dict and set(value['counters']) == set(RESOURCE_FIELDS), 'TERMINAL_COUNTER_SCHEMA')
    _require_resource_floor(value['counters'])


class KernelMeasurement:
    """Per-read parent aggregates with directory/seed fences, never an atomic census."""
    def __init__(self, parent, seed_cgroups, oci_pids, mount='/sys/fs/cgroup'):
        self.parent = parent
        self.mount = str(Path(mount))
        require(str(parent.root).startswith(self.mount + '/') and
                path(str(parent.root)), 'CGROUP_IDENTITY')
        require(type(seed_cgroups) is list and len(seed_cgroups) == 3 and
                all(path(value) for value in seed_cgroups), 'SEED_SCOPE')
        self.seed_cgroups = [self.mount + value for value in seed_cgroups]
        self.oci_pids = oci_pids
        self.origin = None
        self.terminal_origin = None

    def read(self, retain_floor=None):
        self.parent.check()
        counters = {field: self.parent.read_field(field) for field in RESOURCE_FIELDS}
        if retain_floor is not None:
            retain_floor({'parent': str(self.parent.root), 'identity': list(self.parent.identity),
                          'limits': {field: list(counters[field]) for field in
                                     ('pids.max', 'memory.max', 'memory.swap.max', 'cpu.max')}})
        _require_resource_floor(counters)
        limits = self.parent.directory_limits()
        parent_name = str(self.parent.root)
        groups = {}
        for name, limit in limits.items():
            if name == parent_name:
                groups[name] = {'identity': self.parent.identity, 'max': 256,
                                'events': counters['pids.events']['max'],
                                'localEvents': counters['pids.events.local']['max']}
            else:
                with PodCgroup(name) as group:
                    memory_limit = group.read_field('memory.max')
                    require(memory_limit == ['max'] or int(memory_limit[0]) >= 268435456,
                            'DESCENDANT_MEMORY_LIMIT')
                    groups[name] = {'identity': group.identity,
                                    'max': None if limit == ['max'] else int(limit[0]),
                                    'events': group.read_field('pids.events')['max'],
                                    'localEvents': group.read_field('pids.events.local')['max']}
        ancestors = {}
        name = self.parent.root.parent
        while str(name) != self.mount:
            require(str(name).startswith(self.mount + '/'), 'CGROUP_IDENTITY')
            with PodCgroup(name) as group:
                limit = group.read_field('pids.max')
                record = {'identity': group.identity,
                          'max': None if limit == ['max'] else int(limit[0])}
                ancestors[str(name)] = record
            name = name.parent
        topology = self.parent.read_field('cgroup.stat')
        view = {'eventMode': 'v2-failing-limit-local',
                'parent': parent_name, 'groups': groups,
                'nrDescendants': topology['nr_descendants'],
                'nrDyingDescendants': topology['nr_dying_descendants'],
                'seedCgroups': list(self.seed_cgroups), 'ociPids': self.oci_pids,
                'ancestors': ancestors}
        scope = validate_pid_view(view)
        origin = {'parent': [parent_name, groups[parent_name]['identity']],
                  'forkScope': [scope, groups[scope]['identity']],
                  'ancestors': {key: [value['identity'], value['max']]
                                for key, value in ancestors.items()}}
        if self.origin is None:
            self.origin = origin
        require(self.origin == origin, 'CGROUP_IDENTITY')
        self.parent.check()
        if self.terminal_origin is None:
            self.terminal_origin = [str(self.parent.root), list(self.parent.identity)]
        return {'counters': counters, 'pidView': view}

    def read_terminal_parent(self):
        """Read the already-bound parent after exit; no departed child topology claim."""
        require(self.terminal_origin is not None, 'LIVE_ORIGIN_UNPROVEN')
        self.parent.check()
        require([str(self.parent.root), self.parent.identity] == self.terminal_origin, 'CGROUP_IDENTITY')
        counters = {field: self.parent.read_field(field) for field in RESOURCE_FIELDS}
        _require_resource_floor(counters)
        self.parent.check()
        require([str(self.parent.root), self.parent.identity] == self.terminal_origin, 'CGROUP_IDENTITY')
        return {'schema': 'f01-terminal-parent-counters-v1',
                'parentOrigin': deepcopy(self.terminal_origin), 'counters': deepcopy(counters)}


def terminal_pid_denial_delta(before, terminal, last):
    """Actual limiting-parent local MAX evidence; fork attribution may stay unavailable."""
    validate_pid_view(before['pidView'])
    root = before['pidView']['parent']
    validate_terminal_parent(terminal, [root, before['pidView']['groups'][root]['identity']])
    for row in (before, last):
        view = row['pidView'];validate_pid_view(view)
        require(view['parent'] == root, 'CGROUP_IDENTITY')
        for field, key in (('pids.events', 'events'), ('pids.events.local', 'localEvents')):
            number = row['counters'][field]['max']
            require(integer(number) and number == view['groups'][root][key], 'PID_EVENT_ORIGIN')
    deltas = {}
    for key, field in (('parentLocal', 'pids.events.local'), ('parentHierarchical', 'pids.events')):
        old = before['counters'][field]['max'];current = terminal['counters'][field]['max']
        require(integer(current) and current >= old and current >= last['counters'][field]['max'], 'PID_EVENT_RESET')
        deltas[key] = current - old
    require(deltas['parentHierarchical'] >= deltas['parentLocal'] > 0, 'PID_DENIAL_EVENT_UNPROVEN')
    deltas['forkLocal'] = None
    try:
        live = pid_denial_delta(before['pidView'], last['pidView'])
    except ProofError as error:
        if error.args != ('PID_DENIAL_EVENT_UNPROVEN',):
            raise
    else:
        if all(last['counters'][field]['max'] == terminal['counters'][field]['max']
               for field in ('pids.events', 'pids.events.local')):
            deltas['forkLocal'] = live['forkLocal']
    return deltas


def pidfd_poll(fds, timeout):
    import select
    import math
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 <= timeout <= 2,
            'PIDFD_STATE')
    poll = select.poll()
    for fd in fds:
        poll.register(fd, select.POLLIN)
    values = poll.poll(math.ceil(timeout * 1000))
    require(all(flags in (select.POLLIN, select.POLLIN | select.POLLHUP)
                for _, flags in values), 'PIDFD_STATE')
    return [fd for fd, _ in values]


def bind_seeds(candidates, sid, podgroup, binaries, deadline, reader, opener, poller, now):
    require(type(candidates) is list and len(candidates) == 3 and
            [value.get('role') for value in candidates] ==
            ['sentry', 'sandbox-gofer', 'container-gofer'] and
            all(type(value.get('pid')) is int and 1 < value['pid'] < 2 ** 31
                for value in candidates) and
            len({value['pid'] for value in candidates}) == 3, 'SEED_IDENTITY')
    require(path(podgroup) and type(sid) is str and len(sid) == 64 and
            all(char in '0123456789abcdef' for char in sid), 'SEED_IDENTITY')
    seeds = []
    try:
        for value in candidates:
            require(now() < deadline, 'DEADLINE')
            seeds.append({'role': value['role'], 'fd': opener(value['pid'])})
        require(not poller([value['fd'] for value in seeds], 0), 'PRELOAD_SEED_EXIT')
        scope = podgroup + '/cri-containerd-' + sid + '.scope'
        for seed, candidate in zip(seeds, candidates):
            require(now() < deadline, 'DEADLINE')
            record = reader(candidate['pid'])
            role = 'sentry' if seed['role'] == 'sentry' else 'gofer'
            require(record['pid'] == candidate['pid'] and record['cgroup'] == scope and
                    record['exeIdentity'] == binaries[role], 'SEED_IDENTITY')
            if role == 'sentry':
                args = record['args']
                require(args[0] == 'runsc-sandbox' and args[-1] == sid and
                        args.count('--platform=systrap') == 1 and
                        [value for value in args if value.startswith('--root=')] ==
                        ['--root=/run/containerd/runsc/k8s.io'], 'SENTRY_IDENTITY')
            seed['identity'] = record
        require(seed_fence(seeds, deadline, reader, poller, now) == 'LIVE',
                'PRELOAD_SEED_EXIT')
        return seeds
    except BaseException:
        for seed in seeds:
            os.close(seed['fd'])
        raise


def _sample_candidate(control, deadline, read, fence, query, now, sample_index):
    row = {'sample': sample_index, 'status': 'invalid', 'monotonic': now()}
    if fence() == 'EXITED':
        return None, 'SEED_EXIT'
    try:
        projection = query() if control in ('process-limit', 'memory-control') else None
    except RuntimeError as error:
        if type(error) is not RuntimeError:
            raise
        return None, 'QUERY_NONZERO'
    if not now() < deadline:
        return None, None
    row['counterReadStart'] = now()
    values = read()
    row['counterReadEnd'] = now()
    if now() >= deadline:
        return None, None
    if fence() == 'EXITED':
        return None, 'SEED_EXIT'
    if not now() < deadline:
        return None, None
    pids = int(values['counters']['pids.current'][0])
    require(1 <= pids <= 256, 'NATIVE_PID_COUNT')
    row.update(values, status='verified', nativePids=pids,
               rootProjection=projection)
    return row, None


def _pause_until_tick(epoch, index, observation_deadline, now, sleep):
    remaining = observation_deadline - now()
    delay = epoch + (index + 1) * .1 - now()
    if remaining > 0 and delay > 0:
        sleep(min(delay, remaining))


def sample_loop(control, deadline, observation_deadline, read, fence, terminal,
                query, pump, publish, now, sleep):
    """At most400 candidates; exit/query ambiguity latches terminal-only observation."""
    require(control in ('memory-control', 'process-limit', 'memory-limit',
                        'cpu-deadline', 'scratch-a', 'scratch-b') and
            observation_deadline >= deadline, 'SAMPLE_INPUT')
    rows = [];quiescence = None;discarded = 0
    epoch = now()
    for index in range(400):
        if now() >= observation_deadline:
            break
        ended = terminal()
        if ended is not None:
            return {'samples': rows, 'terminal': ended, 'quiescence': quiescence,
                    'discarded': discarded}
        pump(quiescence is not None or now() >= deadline)
        if quiescence is None and now() < deadline:
            row, quiescence = _sample_candidate(control, deadline, read, fence, query,
                                                 now, len(rows))
            if row is None:
                discarded += 1
            else:
                publish(row)
                rows.append(row)
        _pause_until_tick(epoch, index, observation_deadline, now, sleep)
    raise ProofError('TERMINAL_UNPROVEN')


def final_endpoint(control, rows, read, check_parent, *, quiescence):
    require(type(rows) is list and bool(rows) and rows[-1].get('status') == 'verified',
            'FINAL_ROW_UNPROVEN')
    last = rows[-1]
    if control in ('cpu-deadline', 'memory-control'):
        if control == 'cpu-deadline':
            require(quiescence is None, 'CPU_QUIESCENCE')
        return {'value': last, 'basis': 'LAST_COMPLETE_PRE30' if control == 'cpu-deadline'
                else 'LAST_COMPLETE_CALIBRATION_ROW'}
    try:
        check_parent()
        current = read()
        return {'value': current, 'basis': 'POST_TERMINAL_SAME_PARENT'}
    except ProofError as error:
        if not isinstance(error.__cause__, FileNotFoundError):
            raise
        if control == 'memory-limit':
            first_events = rows[0]['counters']['memory.events']
            last_events = last['counters']['memory.events']
            positive = all(last_events[key] > first_events[key]
                           for key in ('max', 'oom', 'oom_kill'))
        elif control == 'process-limit':
            pid_denial_delta(rows[0]['pidView'], last['pidView'])
            positive = True
        else:
            positive = False
        require(positive, 'FINAL_EVENT_UNPROVEN')
        return {'value': last, 'basis': 'LAST_VALID_POSITIVE_EVENT'}
