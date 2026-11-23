"""Fixed counter calibration predicates and owned-directory writes; no native CLI."""
import errno
import os

CASES = {'positive': ('4', '4'), 'child-limit': ('4', '1'), 'parent-limit': ('1', 'max')}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def qualify(case, before, after, outcome):
    """Distinguish limiting-cgroup local MAX from origin/rolled-up counters."""
    require(case in CASES and type(outcome) is dict and
            set(outcome) == {'attemptedForks', 'forkErrno', 'childExit'} and
            type(outcome['attemptedForks']) is int and outcome['attemptedForks'] == 1,
            'CALIBRATION_PROTOCOL')
    names = {'parentLocal', 'leafLocal', 'parentHierarchical', 'leafHierarchical'}
    require(type(before) is dict and type(after) is dict and
            set(before) == set(after) == names, 'CALIBRATION_COUNTER')
    deltas = {}
    for name in ('parentLocal', 'leafLocal', 'parentHierarchical', 'leafHierarchical'):
        require(type(before[name]) is int and type(after[name]) is int and
                0 <= before[name] <= after[name] < 2 ** 63, 'CALIBRATION_COUNTER')
        deltas[name] = after[name] - before[name]
    if case == 'positive':
        require(outcome['forkErrno'] is None and type(outcome['childExit']) is int and
                outcome['childExit'] == 0 and not any(deltas.values()), 'CALIBRATION_POSITIVE')
    else:
        require(type(outcome['forkErrno']) is int and outcome['forkErrno'] == errno.EAGAIN and
                outcome['childExit'] is None, 'CALIBRATION_DENIAL')
        expected = {'parentLocal': 0, 'leafLocal': 1,
                    'parentHierarchical': 1, 'leafHierarchical': 1}
        if case == 'parent-limit':
            expected = {'parentLocal': 1, 'leafLocal': 0,
                        'parentHierarchical': 1, 'leafHierarchical': 0}
        require(deltas == expected, 'CALIBRATION_EVENT_MODE')
    return deltas


def validate_mount(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b'\n'),
            'CALIBRATION_MOUNT')
    selected = [line.split() for line in raw.splitlines()
                if len(line.split()) >= 6 and line.split()[4] == b'/sys/fs/cgroup']
    require(len(selected) == 1, 'CALIBRATION_MOUNT')
    fields = selected[0]
    require(fields.count(b'-') == 1, 'CALIBRATION_MOUNT')
    index = fields.index(b'-')
    require(index >= 6 and len(fields) > index + 3 and fields[3] == b'/' and
            fields[index + 1] == b'cgroup2', 'CALIBRATION_MOUNT')
    options = set(fields[5].split(b',')) | set(fields[index + 3].split(b','))
    require(b'rw' in options and b'ro' not in options and b'pids_localevents' not in options,
            'CALIBRATION_MOUNT')


def _write(group, name, value):
    require(name in ('pids.max', 'cgroup.subtree_control', 'cgroup.procs'), 'CALIBRATION_WRITE')
    group.check()
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=group.fd)
    try:
        data = value.encode('ascii')
        require(os.write(fd, data) == len(data), 'CALIBRATION_WRITE')
    finally:
        os.close(fd)
    group.check()
