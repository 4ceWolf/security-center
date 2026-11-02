"""Undeployed gate evidence parser. Root-local observations, never attestation.

The caller must establish inventory coverage and hold hotplug enforcement. Passing
this parser alone is insufficient to authorize production TPM automatic unlock.
"""
import json
import math
import os
import pathlib
import re
import stat

MAX_BYTES = 8192
MAX_AGE = 5.0
FIELDS = {'schema_version', 'boot_id', 'policy_sha256', 'mode',
          'sampled_boottime', 'checker_complete', 'coverage_complete', 'decision'}
DECISION = {'allow_tpm_attempt', 'manual_recovery_required', 'reason'}
BOOT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
DIGEST = re.compile(r'[0-9a-f]{64}')


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('Duplicate gate field')
        out[key] = value
    return out


def validate(raw, boot_id, policy_sha256, mode, now, checker_ok):
    """Raise on unavailable evidence; dispatcher must then select manual recovery."""
    if checker_ok is not True:
        raise ValueError('Checker did not complete successfully')
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Gate record exceeds bound or is not bytes')
    if (not isinstance(boot_id, str) or not BOOT.fullmatch(boot_id)
            or not isinstance(policy_sha256, str) or not DIGEST.fullmatch(policy_sha256)
            or mode not in ('normal', 'distress')):
        raise ValueError('Invalid expected context')
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ValueError('Invalid gate record schema')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise ValueError('Unsupported gate schema')
    if (data['boot_id'] != boot_id or data['policy_sha256'] != policy_sha256
            or data['mode'] != mode):
        raise ValueError('Gate context mismatch')
    stamp = data['sampled_boottime']
    if any(type(value) not in (float, int) or not math.isfinite(value)
           for value in (now, stamp)) or not 0 <= stamp <= now or now-stamp > MAX_AGE:
        raise ValueError('Gate observation stale or invalid')
    if any(type(data[key]) is not bool for key in ('checker_complete', 'coverage_complete')):
        raise ValueError('Invalid gate completion flags')
    if data['checker_complete'] is not True:
        raise ValueError('Incomplete checker record')
    decision = data['decision']
    if not isinstance(decision, dict) or set(decision) != DECISION:
        raise ValueError('Invalid decision schema')
    if any(type(decision[key]) is not bool for key in ('allow_tpm_attempt', 'manual_recovery_required')):
        raise ValueError('Invalid decision flags')
    if decision['allow_tpm_attempt'] == decision['manual_recovery_required']:
        raise ValueError('Contradictory decision')
    if not isinstance(decision['reason'], str) or not 1 <= len(decision['reason']) <= 256:
        raise ValueError('Invalid decision reason')
    if decision['allow_tpm_attempt'] and (mode != 'normal' or not data['coverage_complete']):
        raise ValueError('TPM permission without coverage or during distress')
    return dict(decision)


def read_record(directory, **context):
    """Read fixed decision.json via trusted root-owned ancestry and private directory.

    This is not a caller-selected file API. A future installed adapter must pass
    its fixed reviewed /run location; current uses are disposable guest fixtures.
    """
    parts = pathlib.PurePosixPath(directory).parts
    if not directory.startswith('/') or '..' in parts or len(parts) < 2:
        raise ValueError('Canonical absolute directory required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('Untrusted gate ancestry')
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise ValueError('Gate directory must be private')
        fd = os.open('decision.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or before.st_size > MAX_BYTES):
                raise ValueError('Invalid gate file metadata')
            raw = stream.read(MAX_BYTES+1)
            after = os.fstat(stream.fileno())
            current = os.stat('decision.json', dir_fd=parent, follow_symlinks=False)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                        info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)
            if identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('Gate record changed while reading')
        return validate(raw, **context)
    finally:
        os.close(parent)
