"""Initrd-only inventory snapshot; no unlock, authorization or credentials."""
import hashlib
import pathlib
import time
from boot_observation import LIMITATIONS, publish, validate

CONFIG = pathlib.Path('/etc/security-center-observation')


def build(policy_raw, source_digest, boot_id, start, end, usb, platform):
    if not isinstance(policy_raw, bytes) or len(policy_raw) > 65536:
        raise ValueError('Policy snapshot exceeds bound')
    # Reuse the reviewed exact candidate-policy validator without publishing a gate
    # decision or importing the unlock dispatcher. Its decision is discarded.
    from gate_observer import build as validate_policy
    validate_policy(policy_raw, boot_id, start, end, usb, platform)
    data = dict(schema_version=1, producer='security-center-initrd-observer-v1',
                boot_id=boot_id, source_manifest_sha256=source_digest,
                policy_sha256=hashlib.sha256(policy_raw).hexdigest(),
                started_boottime=start, finished_boottime=end, observation_only=True,
                attested=False, coverage_complete=False, unlock_method='unknown',
                enforcement='not_enabled', counts={'usb': len(usb['devices']),
                'pci': len(platform['pci']), 'thunderbolt': len(platform['thunderbolt'])},
                errors=(['usb_scan_incomplete'] if usb['errors'] else [])+
                       (['platform_scan_incomplete'] if platform['errors'] else []),
                limitations=list(LIMITATIONS))
    return validate(data, boot_id, end)


def main():
    # /etc/initrd-release is removed at switch-root in systemd initrd boots. A
    # postboot restart must fail before collecting or publishing anything.
    if not pathlib.Path('/etc/initrd-release').is_file():
        raise SystemExit('Observer requires initrd environment')
    from device_inventory import collect as usb_collect
    from platform_inventory import collect as platform_collect
    start = time.clock_gettime(time.CLOCK_BOOTTIME)
    with (CONFIG/'normal-devices.json').open('rb') as stream:
        policy = stream.read(65537)
    with (CONFIG/'source.sha256').open() as stream:
        source = stream.read(66).strip()
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    usb, platform = usb_collect(), platform_collect()
    publish(build(policy, source, boot, start, time.clock_gettime(time.CLOCK_BOOTTIME), usb, platform))


if __name__ == '__main__':
    main()
