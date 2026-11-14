"""Exact-owned24byte systemd prefix file; no systemctl or workload action here."""
import hashlib
import os
from pathlib import Path
import stat

DIRECTORY = Path('/etc/systemd/system/kubelet-kubepods-burstable-.slice.d')
FILENAME = '50-ilm-488-noswap.conf'
CONTENT = b'[Slice]\nMemorySwapMax=0\n'
OWNER_UID = OWNER_GID = 0


def need(value, reason):
    if not value:
        raise AssertionError(reason)


def parent_guard():
    parent = DIRECTORY.parent
    need(parent.resolve(strict=True) == parent, 'PREFIX_PARENT')
    value = parent.stat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == OWNER_UID and
         value.st_gid == OWNER_GID and stat.S_IMODE(value.st_mode) == 0o755,
         'PREFIX_PARENT')
    need(os.geteuid() == OWNER_UID and os.getegid() == OWNER_GID, 'PREFIX_AUTHORITY')


def directory_identity(fd):
    value = os.fstat(fd)
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == OWNER_UID and
         value.st_gid == OWNER_GID and stat.S_IMODE(value.st_mode) == 0o755,
         'PREFIX_DIRECTORY')
    current = DIRECTORY.lstat()
    need(stat.S_ISDIR(current.st_mode) and (value.st_dev, value.st_ino) ==
         (current.st_dev, current.st_ino), 'PREFIX_DIRECTORY')
    return [value.st_dev, value.st_ino]


def inspect_prefix(expected):
    parent_guard()
    need(type(expected) is dict and set(expected) ==
         {'path', 'directoryIdentity', 'fileIdentity', 'bytes', 'sha256'} and
         expected['path'] == str(DIRECTORY / FILENAME), 'PREFIX_RECEIPT')
    directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        identity = directory_identity(directory)
        need(identity == expected['directoryIdentity'], 'PREFIX_DIRECTORY')
        need(os.listdir(directory) == [FILENAME], 'PREFIX_MEMBERSHIP')
        fd = os.open(FILENAME, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER_UID and
                 before.st_gid == OWNER_GID and stat.S_IMODE(before.st_mode) == 0o644 and
                 before.st_nlink == 1, 'PREFIX_FILE')
            raw = os.read(fd, len(CONTENT) + 1)
            after = os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)
            need(stat.S_ISREG(after.st_mode) and (before.st_dev, before.st_ino) ==
                 (after.st_dev, after.st_ino), 'PREFIX_FILE')
            value = {'path': str(DIRECTORY / FILENAME), 'directoryIdentity': identity,
                     'fileIdentity': [before.st_dev, before.st_ino], 'bytes': len(raw),
                     'sha256': hashlib.sha256(raw).hexdigest()}
            need(raw == CONTENT and value == expected, 'PREFIX_FILE')
        finally:
            os.close(fd)
        directory_identity(directory)
        return value
    finally:
        os.close(directory)


def install_prefix(record):
    parent_guard()
    os.mkdir(DIRECTORY, 0o755)  # Exclusive creation; no adoption of any existing path.
    directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(directory, 0o755);identity = directory_identity(directory)
        os.fsync(directory)
        record('directory-created', {'path': str(DIRECTORY), 'identity': identity})
        fd = os.open(FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o644, dir_fd=directory)
        try:
            os.fchmod(fd, 0o644)
            remaining = CONTENT
            while remaining:
                count = os.write(fd, remaining);need(count > 0, 'PREFIX_WRITE')
                remaining = remaining[count:]
            os.fsync(fd);value = os.fstat(fd)
            receipt = {'path': str(DIRECTORY / FILENAME), 'directoryIdentity': identity,
                       'fileIdentity': [value.st_dev, value.st_ino], 'bytes': len(CONTENT),
                       'sha256': hashlib.sha256(CONTENT).hexdigest()}
        finally:
            os.close(fd)
        os.fsync(directory);directory_identity(directory)
    finally:
        os.close(directory)
    inspect_prefix(receipt)
    record('prefix-file-complete', receipt)
    return receipt


def remove_prefix(receipt):
    inspect_prefix(receipt)
    directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(directory_identity(directory) == receipt['directoryIdentity'], 'PREFIX_DIRECTORY')
        need(os.listdir(directory) == [FILENAME], 'PREFIX_MEMBERSHIP')
        current = os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)
        need([current.st_dev, current.st_ino] == receipt['fileIdentity'] and
             stat.S_ISREG(current.st_mode), 'PREFIX_FILE')
        os.unlink(FILENAME, dir_fd=directory);os.fsync(directory)
        directory_identity(directory)
    finally:
        os.close(directory)
    os.rmdir(DIRECTORY)  # Nonrecursive; any unexpected member stops removal.
