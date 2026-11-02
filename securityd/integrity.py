"""Fixed-path FIM: no secret files, recursion, writes or automatic baselines."""
import hashlib
import json
import os
import pathlib
import stat

PATHS = (
 '/usr/local/lib/security-center/network_policy.py',
 '/usr/local/lib/security-center/boot_observation.py',
 '/usr/local/lib/security-center/boot_observation_status.py',
 '/etc/security-center/normal-devices.candidate.json',
 '/usr/local/lib/security-center/device_gate.py', '/usr/local/lib/security-center/device_inventory.py',
 '/usr/local/lib/security-center/trust_policy.py', '/usr/local/lib/security-center/trust_store.py',
 '/usr/local/lib/security-center/usb_policy.py',
 '/usr/local/lib/security-center/device-trust-helper.py',
 '/usr/local/lib/security-center/tpm-unlock-helper.py',
 '/etc/miku-boot/zen.cmdline', '/etc/miku-boot/zen.conf',
 '/etc/miku-boot/zen-uki.conf', '/etc/mkinitcpio.d/linux-zen.preset',
 '/etc/systemd/system/security-center.service',
 '/etc/systemd/system/security-center-apparmor.service',
 '/etc/systemd/system/security-center-telemetry.service',
 '/usr/local/lib/security-center/telemetry.py',
 '/usr/local/lib/security-center/telemetry_worker.py',
 '/usr/local/lib/security-center/telemetry_health.py',
 '/usr/local/lib/security-center/telemetry_query.py',
 '/usr/local/lib/security-center/telemetry_actions.py',
 '/usr/local/lib/security-center/telemetry_export.py',
 '/usr/local/lib/security-center/telemetry-helper.py',
 '/etc/systemd/system/cockpit.socket.d/security-center-local.conf',
 '/usr/local/lib/security-center/collector.py', '/usr/local/lib/security-center/daemon.py',
 '/usr/local/lib/security-center/client.py', '/usr/local/lib/security-center/adapters.py',
 '/usr/local/lib/security-center/audit.py', '/usr/local/lib/security-center/history.py',
 '/usr/local/lib/security-center/handover.py',
 '/usr/local/lib/security-center/integrity.py', '/usr/local/lib/security-center/confinement.py',
 '/usr/local/share/cockpit/security_center/app.js',
 '/usr/local/share/cockpit/security_center/telemetry-controls.js',
 '/usr/local/share/cockpit/security_center/unlock-controls.js',
 '/usr/local/share/cockpit/security_center/usb-controls.js',
 '/usr/local/share/cockpit/security_center/index.html',
 '/usr/local/share/cockpit/security_center/style.css',
 '/usr/local/share/cockpit/security_center/manifest.json',
)
MAX_BYTES = 1024 * 1024
BASELINE = '/var/lib/security-center-monitor/integrity-baseline.json'


def open_fixed(path):
    """Do not follow symlinks in any component or block on special files."""
    parts = pathlib.PurePosixPath(path).parts
    if not path.startswith('/') or '..' in parts:
        raise ValueError('Absolute canonical path required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)


def inspect(path):
    try:
        fd = open_fixed(path)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                return {'state': 'unavailable', 'reason': 'Not a regular file'}
            if before.st_size > MAX_BYTES:
                return {'state': 'unavailable', 'reason': 'File exceeds scan limit'}
            digest = hashlib.sha256()
            count = 0
            while True:
                block = stream.read(min(65536, MAX_BYTES + 1 - count))
                if not block:
                    break
                count += len(block)
                if count > MAX_BYTES:
                    return {'state': 'unavailable', 'reason': 'File exceeds scan limit'}
                digest.update(block)
            after = os.fstat(stream.fileno())
            # Reopen the same path to detect replacement during the read.
            check = open_fixed(path)
            try:
                current = os.fstat(check)
            finally:
                os.close(check)
            if identity(before) != identity(after) or identity(after) != identity(current):
                return {'state': 'unavailable', 'reason': 'File changed during scan'}
            return {'state': 'present', 'sha256': digest.hexdigest(),
                    'uid': after.st_uid, 'gid': after.st_gid,
                    'mode': stat.S_IMODE(after.st_mode), 'size': after.st_size,
                    'mtime_ns': after.st_mtime_ns}
    except FileNotFoundError:
        return {'state': 'missing'}
    except (OSError, ValueError):
        return {'state': 'unavailable', 'reason': 'Path inaccessible or symlink detected'}


def scan():
    return {path: inspect(path) for path in PATHS}


def load_baseline():
    fd = open_fixed(BASELINE)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Baseline must be root-owned and private')
        raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('Baseline exceeds bound')
    data = json.loads(raw)
    if data.get('schema_version') != 1 or data.get('approved') is not True:
        raise ValueError('Unapproved baseline')
    files = data['files']
    if set(files) != set(PATHS):
        raise ValueError('Baseline scope differs; review required')
    for item in files.values():
        if item.get('state') != 'present' or not isinstance(item.get('sha256'), str) or len(item['sha256']) != 64:
            raise ValueError('Incomplete baseline')
        if any(not isinstance(item.get(k), int) for k in ('uid','gid','mode','size','mtime_ns')):
            raise ValueError('Invalid baseline metadata')
    return files


def compare(current, baseline):
    changes, unavailable = [], []
    for path in PATHS:
        item = current[path]
        if item['state'] == 'unavailable':
            unavailable.append(path)
        elif item != baseline[path]:
            changes.append({'path': path, 'kind': 'deleted' if item['state'] == 'missing' else 'changed',
                            'previous': baseline[path], 'current': item,
                            'package_attribution': 'Not established; an update is not proof of authorization'})
    return changes, unavailable


def configuration():
    current = scan()
    try:
        baseline = load_baseline()
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'unknown', 'summary': 'File baseline needs explicit review and approval',
                'details': {'baseline_approved': False, 'inventory': current,
                            'scope': 'Fixed security configuration and installed dashboard code only'}}
    changes, unavailable = compare(current, baseline)
    return {'status': 'attention' if changes else 'unknown' if unavailable else 'secure',
            'summary': f'{len(changes)} file changes; {len(unavailable)} files unreadable',
            'details': {'baseline_approved': True, 'changes': changes, 'unavailable': unavailable,
                        'scope': 'Fixed files only; no ACL, directory inventory or full disk verification',
                        'note': 'Polling may miss temporary changes between scans. Root can tamper with this local baseline.'}}
