"""Derive three trusted-runtime seeds from two exact locked state files once."""
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat

KERNEL_OWNER_UID = 0
NAMESPACE = 'ilm-resource-sec-r1'
CONTROLS = ('memory-control', 'process-limit', 'memory-limit', 'cpu-deadline',
            'scratch-a', 'scratch-b')


class OwnerError(AssertionError):
    pass


def require(value, reason):
    if not value:
        raise OwnerError(reason)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'RUNTIME_STATE_JSON')
        result[key] = value
    return result


def _constant(value):
    raise OwnerError('RUNTIME_STATE_JSON')


def _file(directory, name):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        current = os.fstat(fd)
        require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1 and
                current.st_uid == KERNEL_OWNER_UID and not current.st_mode & 0o022,
                'RUNTIME_STATE_FILE')
        return fd, (current.st_dev, current.st_ino)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def _state(directory, stem):
    lock = state = None
    try:
        lock, lock_identity = _file(directory, stem + '.lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            raise OwnerError('RUNTIME_STATE_BUSY') from error
        state, state_identity = _file(directory, stem + '.state')
        raw = bytearray()
        while len(raw) <= 262144:
            chunk = os.read(state, 262145 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        require(0 < len(raw) <= 262144, 'RUNTIME_STATE_BYTES')
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        for name, expected in ((stem + '.lock', lock_identity),
                               (stem + '.state', state_identity)):
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISREG(current.st_mode) and
                    (current.st_dev, current.st_ino) == expected and
                    current.st_uid == KERNEL_OWNER_UID and not current.st_mode & 0o022,
                    'RUNTIME_STATE_FILE')
        return value
    except (OSError, ValueError, UnicodeError) as error:
        raise OwnerError('RUNTIME_STATE_FILE') from error
    finally:
        if state is not None:
            os.close(state)
        if lock is not None:
            os.close(lock)


def runtime_candidates(root, target):
    require(type(target) is dict and
            all(type(target.get(key)) is str and
                re.fullmatch('[0-9a-f]{64}', target[key]) for key in ('sid', 'cid')) and
            target['sid'] != target['cid'] and
            target.get('name') in tuple('f01-a2-' + control for control in CONTROLS) and
            type(target.get('uid')) is str and
            re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', target['uid']) and
            type(target.get('startTime')) is str and bool(target['startTime']), 'TARGET')
    root = Path(root)
    directory = None
    try:
        require(root.is_absolute() and root.resolve(strict=True) == root, 'RUNTIME_STATE_ROOT')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        original = os.fstat(directory)
        require(original.st_uid == KERNEL_OWNER_UID and not original.st_mode & 0o022,
                'RUNTIME_STATE_ROOT')
        records = [_state(directory, cid + '_sandbox:' + target['sid'])
                   for cid in (target['sid'], target['cid'])]
        current = root.lstat()
        require(stat.S_ISDIR(current.st_mode) and
                (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                'RUNTIME_STATE_ROOT')
        sentry = None
        gofers = []
        for cid, record in zip((target['sid'], target['cid']), records):
            require(type(record) is dict and type(record.get('sandbox')) is dict,
                    'RUNTIME_OWNERSHIP')
            sandbox = record['sandbox']
            require(record.get('id') == cid and sandbox.get('id') == target['sid'] and
                    sandbox.get('podName') == target['name'] and
                    sandbox.get('namespace') == NAMESPACE, 'RUNTIME_OWNERSHIP')
            pid = sandbox.get('pid')
            require(type(pid) is int and 1 < pid < 2 ** 31, 'RUNTIME_SEED_TYPE')
            require(sentry is None or pid == sentry, 'RUNTIME_OWNERSHIP')
            sentry = pid
            gofer = record.get('goferPid')
            require(type(gofer) is int and 1 < gofer < 2 ** 31 and
                    gofer != sentry and gofer not in gofers, 'RUNTIME_SEED_TYPE')
            gofers.append(gofer)
        return [{'role': 'sentry', 'pid': sentry},
                {'role': 'sandbox-gofer', 'pid': gofers[0]},
                {'role': 'container-gofer', 'pid': gofers[1]}]
    except OSError as error:
        raise OwnerError('RUNTIME_STATE_ROOT') from error
    finally:
        if directory is not None:
            os.close(directory)
