"""Staged observation-only producer; no TPM, credentials or device authorization."""
import hashlib
import json
import os
import pathlib
import stat
import time
from gate_record import unique, validate


def build(policy_raw, boot_id, started, now, usb, platform):
    if not isinstance(policy_raw, bytes) or len(policy_raw) > 65536:
        raise ValueError('Policy exceeds bound')
    policy = json.loads(policy_raw, object_pairs_hook=unique)
    if (not isinstance(policy, dict) or set(policy) != {'schema_version', 'internal', 'trusted_external'}
            or type(policy['schema_version']) is not int or policy['schema_version'] != 1):
        raise ValueError('Invalid policy snapshot')
    from device_gate import identity, MAX_DEVICES
    for key in ('internal', 'trusted_external'):
        items = policy[key]
        if not isinstance(items, list) or len(items) > MAX_DEVICES:
            raise ValueError('Invalid policy identities')
        identities = [identity(item) for item in items]
        if len(identities) != len(set(identities)):
            raise ValueError('Duplicate policy identities')
    if set(map(identity, policy['internal'])) & set(map(identity, policy['trusted_external'])):
        raise ValueError('Conflicting policy identities')
    digest = hashlib.sha256(policy_raw).hexdigest()
    data = dict(schema_version=1, boot_id=boot_id, policy_sha256=digest, mode='normal',
                sampled_boottime=started, checker_complete=True, coverage_complete=False,
                decision=dict(allow_tpm_attempt=False, manual_recovery_required=True,
                              reason='Observation only; platform coverage and hotplug enforcement unverified'))
    raw = json.dumps(data, sort_keys=True).encode()
    validate(raw, boot_id=boot_id, policy_sha256=digest, mode='normal', now=now, checker_ok=True)
    # Summary is diagnostic only and does not establish completeness or classify
    # any device as internal. Scanner errors remain visible even with manual denial.
    summary = dict(schema_version=1, boot_id=boot_id, policy_sha256=digest,
                   observation_only=True, usb_count=len(usb['devices']),
                   pci_count=len(platform['pci']), thunderbolt_count=len(platform['thunderbolt']),
                   usb_errors=usb['errors'], platform_errors=platform['errors'])
    summary_raw = json.dumps(summary, sort_keys=True).encode()
    if len(summary_raw) > 65536:
        raise ValueError('Observation summary exceeds bound')
    return raw, summary_raw


def publish(directory, decision, summary):
    """Directory must be created by the supervisor under trusted /run ancestry."""
    if os.geteuid() != 0:
        raise PermissionError('Root producer required')
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Private root directory required')
        for name, raw in (('observations.json', summary), ('decision.json', decision)):
            temp = '.'+name+'-'+os.urandom(8).hex()
            try:
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temp, dir_fd=parent)
                except FileNotFoundError:
                    pass
    finally:
        os.close(parent)


def main():
    # This entrypoint is deliberately guest-only until a production initramfs
    # adapter and its path/manifest/ancestry contract have been reviewed.
    if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
        raise SystemExit('Refusing outside disposable guest')
    from device_inventory import collect as usb_collect
    from platform_inventory import collect as platform_collect
    started = time.clock_gettime(time.CLOCK_BOOTTIME)
    with open('/policy/normal-devices.json', 'rb') as stream:
        policy_raw = stream.read(65537)
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    usb, platform = usb_collect(), platform_collect()
    decision, summary = build(policy_raw, boot, started, time.clock_gettime(time.CLOCK_BOOTTIME), usb, platform)
    publish('/run/security-center-gate', decision, summary)


if __name__ == '__main__':
    main()
