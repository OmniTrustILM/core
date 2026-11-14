"""Metadata-only scratch diagnostic candidate; no qualification or runtime actions."""
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


class MetadataUnavailable(ValueError):
    """A fixed diagnostic reason, never arbitrary exception text."""


CODES = frozenset(('CAPTURE_ORDER', 'BASELINE_UNAVAILABLE', 'SOURCE_BINDING',
    'UNSUPPORTED_PLATFORM', 'SOURCE_OWNER', 'SOURCE_CHANGED', 'CLOSED',
    'FILL_CHANGED', 'INVALID_MARKER', 'DEADLINE', 'OWNER_UNAVAILABLE',
    'RECORD_BOUND', 'METADATA_UNAVAILABLE'))


def unavailable(phase, reason):
    if type(reason) is not str or reason not in CODES:
        reason = 'METADATA_UNAVAILABLE'
    return {'status': 'UNAVAILABLE', 'phase': phase, 'reason': reason,
            'fullF01Accepted': False}


def fixed_source(target, projection):
    uid = target.get('uid') if type(target) is dict else None
    if type(uid) is not str or re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', uid) is None:
        raise MetadataUnavailable('SOURCE_BINDING')
    source = '/var/lib/kubelet/pods/' + uid + '/volumes/kubernetes.io~empty-dir/scratch'
    if type(projection) is not dict or projection.get('scratch') != source:
        raise MetadataUnavailable('SOURCE_BINDING')
    return Path(source)


def bind_scratch(target, projection, deadline, fence, now=time.monotonic):
    """Linux/root boundary; target and projection must already pass collector ownership."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise MetadataUnavailable('UNSUPPORTED_PLATFORM')
    result = _ScratchMetadata(fixed_source(target, projection), deadline, fence, now)
    if result.owner != 0:
        result.close()
        raise MetadataUnavailable('SOURCE_OWNER')
    return result


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _directory(source):
    if not source.is_absolute() or '..' in source.parts:
        raise MetadataUnavailable('SOURCE_BINDING')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open('/', flags)
    try:
        for component in source.parts[1:]:
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        result, current = current, None
        return result
    finally:
        if current is not None:
            os.close(current)


class _ScratchMetadata:
    """A held source; the collector must obtain it through the fixed-source factory."""
    def __init__(self, source, deadline, fence, now):
        if not _number(deadline) or deadline <= 0:
            raise MetadataUnavailable('DEADLINE')
        bound_at = now()
        if not _number(bound_at) or not 0 <= bound_at < deadline:
            raise MetadataUnavailable('DEADLINE')
        self.source = Path(source)
        self.deadline = deadline
        self.fence = fence
        self.now = now
        self.sequence = 0
        self.baseline_available = False
        self.fd = _directory(self.source)
        try:
            initial = os.fstat(self.fd)
        except BaseException:
            self.close()
            raise
        self.identity = [initial.st_dev, initial.st_ino]
        self.owner = initial.st_uid
        self.bound_at = bound_at

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def before_go(self):
        if self.sequence != 0:
            return unavailable('BEFORE_GO', 'CAPTURE_ORDER')
        self.sequence = 1
        result = self._capture('BEFORE_GO', None)
        self.baseline_available = result['status'] == 'UNQUALIFIED_METADATA'
        return result

    def fill_held(self, marker_bytes):
        if self.sequence != 1:
            return unavailable('FILL_HELD', 'CAPTURE_ORDER')
        self.sequence = 2
        if not self.baseline_available:
            return unavailable('FILL_HELD', 'BASELINE_UNAVAILABLE')
        if type(marker_bytes) is not int or not 0 <= marker_bytes <= 20971520:
            return unavailable('FILL_HELD', 'INVALID_MARKER')
        return self._capture('FILL_HELD', marker_bytes)

    def _check_source(self):
        if self.fd is None:
            raise MetadataUnavailable('CLOSED')
        held = os.fstat(self.fd)
        current = _directory(self.source)
        try:
            named = os.fstat(current)
            if any([info.st_dev, info.st_ino] != self.identity or
                   info.st_uid != self.owner for info in (held, named)):
                raise MetadataUnavailable('SOURCE_CHANGED')
        finally:
            os.close(current)

    def _fill(self, fd, marker_bytes):
        info = os.fstat(fd)
        named = os.stat('f01-scratch-fill', dir_fd=self.fd, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_blocks', 'st_mtime_ns', 'st_ctime_ns')
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_dev != self.identity[0] or info.st_size != marker_bytes or
                any(getattr(info, key) != getattr(named, key) for key in fields)):
            raise MetadataUnavailable('FILL_CHANGED')
        return info

    def _clock(self, minimum):
        value = self.now()
        if not _number(value) or not minimum <= value < self.deadline:
            raise MetadataUnavailable('DEADLINE')
        return value

    def _capture(self, phase, marker_bytes):
        file_fd = None
        try:
            started = self._clock(self.bound_at)
            if self.fence() != 'LIVE':
                raise MetadataUnavailable('OWNER_UNAVAILABLE')
            self._clock(started)
            self._check_source()
            initial_file = None
            if marker_bytes is not None:
                file_fd = os.open('f01-scratch-fill', os.O_RDONLY | os.O_NONBLOCK |
                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
                initial_file = self._fill(file_fd, marker_bytes)
            values = os.fstatvfs(self.fd)
            record = {'status': 'UNQUALIFIED_METADATA', 'phase': phase,
                'source': list(self.identity), 'startedMonotonic': started,
                'filesystem': {name: getattr(values, key) for name, key in (
                    ('blockSize', 'f_bsize'), ('fragmentSize', 'f_frsize'),
                    ('totalBlocks', 'f_blocks'), ('freeBlocks', 'f_bfree'),
                    ('availableBlocks', 'f_bavail'), ('totalFiles', 'f_files'),
                    ('freeFiles', 'f_ffree'), ('availableFiles', 'f_favail'))},
                'fullF01Accepted': False, 'unlinkedAllocationAttribution': 'UNPROVEN'}
            if self.fence() != 'LIVE':
                raise MetadataUnavailable('OWNER_UNAVAILABLE')
            self._clock(started)
            self._check_source()
            if initial_file is not None:
                info = self._fill(file_fd, marker_bytes)
                if info != initial_file:
                    raise MetadataUnavailable('FILL_CHANGED')
                record['fillFile'] = {'device': info.st_dev, 'inode': info.st_ino,
                    'links': info.st_nlink, 'bytes': info.st_size, 'blocks': info.st_blocks}
            record['finishedMonotonic'] = self._clock(started)
            if len(json.dumps(record, allow_nan=False).encode()) > 65536:
                raise MetadataUnavailable('RECORD_BOUND')
            return record
        except MetadataUnavailable as error:
            return unavailable(phase, error.args[0])
        except (OSError, AssertionError, ValueError):
            return unavailable(phase, 'METADATA_UNAVAILABLE')
        finally:
            if file_fd is not None:
                os.close(file_fd)
