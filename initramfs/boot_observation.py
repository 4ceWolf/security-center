"""Root-local initrd inventory history, never unlock authority or attestation."""
import json
import math
import os
import pathlib
import re
import stat
import time

DIRECTORY = '/run/security-center-observation'
MAX_BYTES = 65536
ERRORS = {'usb_scan_incomplete', 'platform_scan_incomplete'}
LIMITATIONS = ['snapshot_only', 'topology_unapproved', 'hotplug_uncontrolled', 'dma_unverified']
FIELDS = {'schema_version', 'producer', 'boot_id', 'source_manifest_sha256',
          'policy_sha256', 'started_boottime', 'finished_boottime', 'observation_only',
          'attested', 'coverage_complete', 'unlock_method', 'enforcement', 'counts',
          'errors', 'limitations'}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate observation field')
        result[key] = value
    return result


def validate(data, boot_id, now):
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError('Invalid observation schema')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise ValueError('Unsupported observation schema')
    if (not isinstance(boot_id, str) or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id)
            or data['boot_id'] != boot_id):
        raise ValueError('Wrong boot identity')
    for name in ('source_manifest_sha256', 'policy_sha256'):
        if not isinstance(data[name], str) or not re.fullmatch('[0-9a-f]{64}', data[name]):
            raise ValueError('Invalid digest')
    if (data['producer'] != 'security-center-initrd-observer-v1'
            or data['observation_only'] is not True or data['attested'] is not False
            or data['coverage_complete'] is not False or data['unlock_method'] != 'unknown'
            or data['enforcement'] != 'not_enabled'):
        raise ValueError('Unsupported security claim')
    start, end = data['started_boottime'], data['finished_boottime']
    if (any(type(v) not in (int, float) or not math.isfinite(v) for v in (start, end, now))
            or not 0 <= start <= end <= now or end-start > 5):
        raise ValueError('Invalid observation interval')
    counts = data['counts']
    if (not isinstance(counts, dict) or set(counts) != {'usb', 'pci', 'thunderbolt'}
            or any(type(v) is not int or not 0 <= v <= 256 for v in counts.values())):
        raise ValueError('Invalid inventory counts')
    errors = data['errors']
    if (not isinstance(errors, list) or len(errors) > len(ERRORS)
            or any(type(v) is not str or v not in ERRORS for v in errors)
            or len(errors) != len(set(errors)) or data['limitations'] != LIMITATIONS):
        raise ValueError('Invalid diagnostics')
    return data


def decode(raw, boot_id, now):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Observation exceeds bound')
    try:
        return validate(json.loads(raw, object_pairs_hook=unique), boot_id, now)
    except (RecursionError, OverflowError) as error:
        raise ValueError('Observation exceeds structural or numeric bounds') from error


def private_directory(directory):
    if not isinstance(directory, str) or not directory.startswith('/') or str(pathlib.PurePosixPath(directory)) != directory or '..' in pathlib.PurePosixPath(directory).parts:
        raise ValueError('Canonical absolute directory required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in pathlib.PurePosixPath(directory).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('Untrusted observation ancestry')
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise ValueError('Observation directory must be private')
        return fd
    except BaseException:
        os.close(fd)
        raise


def publish(data, directory=DIRECTORY):
    if os.geteuid() != 0:
        raise PermissionError('Root producer required')
    validate(data, data['boot_id'], time.clock_gettime(time.CLOCK_BOOTTIME))
    raw = json.dumps(data, sort_keys=True, allow_nan=False).encode()
    if len(raw) > MAX_BYTES:
        raise ValueError('Observation exceeds bound')
    parent = private_directory(directory)
    temp = '.pending-'+os.urandom(12).hex()
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp, 'boot.json', src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        finally:
            os.unlink(temp, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def consume(boot_id, directory=DIRECTORY):
    parent = private_directory(directory)
    try:
        fd = os.open('boot.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or before.st_size > MAX_BYTES):
                raise ValueError('Invalid observation metadata')
            raw = stream.read(MAX_BYTES+1)
            after = os.fstat(stream.fileno())
            current = os.stat('boot.json', dir_fd=parent, follow_symlinks=False)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                        info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)
            if identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('Observation changed during read')
        return decode(raw, boot_id, time.clock_gettime(time.CLOCK_BOOTTIME))
    finally:
        os.close(parent)
