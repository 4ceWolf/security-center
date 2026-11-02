#!/usr/bin/python3
"""Fixed owner-requested TPM-token removal. Never enrolls, clears TPM or erases slots."""
import copy
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time

DEVICE = '/dev/nvme0n1p2'
UUID = '2dd04c28-ca38-4d93-8f51-5f47e0984431'
STATE = '/var/lib/security-center-unlock'
CRYPT = '/usr/bin/cryptsetup'
ENV = {'PATH': '/usr/bin', 'LC_ALL': 'C', 'HOME': '/root'}


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def token_id(metadata):
    slots, tokens = metadata.get('keyslots'), metadata.get('tokens')
    if not isinstance(slots, dict) or not isinstance(tokens, dict) or '0' not in slots:
        raise ValueError('Manual slot 0 required')
    found = [key for key, value in tokens.items() if value.get('type') == 'systemd-tpm2']
    if len(found) != 1: raise ValueError('Exactly one TPM token required')
    key = found[0]
    if not re.fullmatch(r'(?:0|[1-9][0-9]?)', key) or int(key) > 31: raise ValueError('Invalid token ID')
    assigned = tokens[key].get('keyslots')
    if (not isinstance(assigned, list) or not assigned or len(set(assigned)) != len(assigned)
            or any(not isinstance(slot, str) or slot == '0' or slot not in slots for slot in assigned)):
        raise ValueError('Unsafe TPM slot assignment')
    if any('0' in value.get('keyslots', []) for value in tokens.values()):
        raise ValueError('Manual slot is assigned to a token')
    return key


def proposal(metadata, identity, issued=None):
    key = token_id(metadata)
    return {'schema_version': 1, 'action': 'disable_tpm_unlock', 'device_uuid': UUID,
            'token_id': key, 'state_sha256': digest({'metadata': metadata, 'identity': identity}),
            'issued_at': int(time.time()) if issued is None else issued}


def validate_proposal(value, metadata, identity, now=None):
    if not isinstance(value, dict) or type(value.get('issued_at')) is not int: raise ValueError('Review required')
    now = int(time.time()) if now is None else now
    if not 0 <= now - value['issued_at'] <= 120: raise ValueError('Review expired')
    if value != proposal(metadata, identity, value['issued_at']): raise ValueError('State changed')


def after_removal(metadata, key):
    expected = copy.deepcopy(metadata)
    del expected['tokens'][key]
    return expected


def run(args, *, data=None, timeout=30):
    result = subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, timeout=timeout)
    if result.returncode: raise RuntimeError('Native operation failed')
    return result.stdout


def read_metadata(device):
    raw = run([CRYPT, 'luksDump', '--dump-json-metadata', device])
    if len(raw) > 1024 * 1024: raise ValueError('Oversized metadata')
    return decode(raw)


def disk_identity():
    info = os.stat(DEVICE, follow_symlinks=False)
    if not stat.S_ISBLK(info.st_mode): raise ValueError('Fixed partition is not a block device')
    if run([CRYPT, 'luksUUID', DEVICE]).decode().strip() != UUID: raise ValueError('Wrong disk UUID')
    # Verify this exact partition backs the active root mapping; no browser device input.
    root = run(['/usr/bin/findmnt', '-n', '-o', 'SOURCE', '/']).decode().strip().split('[')[0]
    if root != '/dev/mapper/root': raise ValueError('Unexpected root mapping')
    chain = decode(run(['/usr/bin/lsblk', '-s', '-J', '-o', 'PATH,TYPE,UUID', root]))
    def contains(entries):
        return any((e.get('path') == DEVICE and e.get('type') == 'part' and e.get('uuid') == UUID)
                   or contains(e.get('children', [])) for e in entries)
    if not contains(chain.get('blockdevices', [])): raise ValueError('Partition does not back root')
    return {'rdev': info.st_rdev, 'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def private_parent():
    """Fixed protected directory; reject every symlink/writable parent."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in ('var', 'lib', 'security-center-unlock'):
            try: child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if part != 'security-center-unlock': raise
                os.mkdir(part, 0o700, dir_fd=fd); os.fsync(fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022: raise PermissionError('Unsafe state directory')
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700: raise PermissionError('Unsafe state mode')
    finally: os.close(fd)


def native_passphrase():
    # Run a fixed native dialog as the desktop owner, never as root. No inherited
    # plugin/library/loader environment and no secret returned to the web page.
    socket = pathlib.Path('/run/user/1000/wayland-1')
    if not stat.S_ISSOCK(socket.lstat().st_mode) or socket.lstat().st_uid != 1000:
        raise RuntimeError('Owner Wayland session unavailable')
    args = ['/usr/bin/runuser', '-u', 'kyo', '--', '/usr/bin/env', '-i',
            'PATH=/usr/bin', 'HOME=/home/user', 'USER=kyo', 'XDG_RUNTIME_DIR=/run/user/1000',
            'WAYLAND_DISPLAY=wayland-1', 'QT_QPA_PLATFORM=wayland',
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
            '/usr/bin/kdialog', '--title', 'Security Center — disable automatic disk unlock',
            '--password', 'Enter your DISK unlock passphrase to disable TPM automatic unlock.\nFuture boots will need this passphrase. Cancel to keep automatic unlock.']
    secret = bytearray(run(args, timeout=90))
    if secret.endswith(b'\n'): del secret[-1:]
    if not secret or len(secret) > 4096 or b'\n' in secret or b'\0' in secret:
        for index in range(len(secret)): secret[index] = 0
        raise ValueError('Credential cancelled or unsupported')
    return secret


def verify_passphrase(device, secret):
    run([CRYPT, 'open', '--type', 'luks2', '--test-passphrase', '--key-slot', '0',
         '--key-file', '-', device], data=secret, timeout=60)


def receipt(folder, value):
    path = folder / 'receipt.json'
    temporary = folder / 'receipt.new'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def disable(review, *, capture, credential, verify, backup, remove, record):
    """Injectable transaction sequence, shared by production and disposable tests."""
    before, identity = capture()
    validate_proposal(review, before, identity)
    key = token_id(before)
    secret = credential()
    try:
        verify(DEVICE, secret)
        saved, saved_device, saved_hash = backup(before)
        if saved != before: raise ValueError('Backup metadata mismatch')
        verify(saved_device, secret)
    finally:
        for index in range(len(secret)): secret[index] = 0
    current, current_identity = capture()
    validate_proposal(review, current, current_identity)
    record({'phase': 'removal_pending', 'token_id': key, 'header_backup_sha256': saved_hash})
    # One exact metadata token only. Never luksKillSlot, wipe-slot, TPM clear or header restore.
    remove(key)
    after, after_identity = capture()
    if after != after_removal(before, key) or after_identity != identity:
        record({'phase': 'verification_failed', 'token_id': key, 'header_backup_sha256': saved_hash})
        raise RuntimeError('Post-removal verification failed; inspect protected receipt')
    record({'phase': 'disabled', 'token_id': key, 'header_backup_sha256': saved_hash})
    return {'disabled': True, 'manual_slot_0_preserved': True, 'boot_verified': False,
            'message': 'TPM token removed. Next boot requires the disk passphrase. Startup has not been tested.'}


def apply(review):
    folder = None
    def capture(): return read_metadata(DEVICE), disk_identity()
    def backup(before):
        nonlocal folder
        folder = pathlib.Path(tempfile.mkdtemp(prefix='disable-', dir=STATE))
        parent = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
        path = folder / 'header.img'
        run([CRYPT, 'luksHeaderBackup', DEVICE, '--header-backup-file', str(path)])
        os.chmod(path, 0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1: raise ValueError('Unsafe header backup')
            os.fsync(stream.fileno())
            sha = hashlib.file_digest(stream, 'sha256').hexdigest()
        if run([CRYPT, 'luksUUID', str(path)]).decode().strip() != UUID: raise ValueError('Backup UUID mismatch')
        receipt(folder, {'phase': 'backup_created', 'header_backup_sha256': sha})
        return read_metadata(str(path)), str(path), sha
    return disable(review, capture=capture, credential=native_passphrase, verify=verify_passphrase,
                   backup=backup, remove=lambda key: run([CRYPT, 'token', 'remove', '--token-id', key, DEVICE]),
                   record=lambda value: receipt(folder, value))


def main():
    if os.geteuid() != 0: raise PermissionError('Administrator required')
    if len(sys.argv) != 1: raise ValueError('Arguments not supported')
    os.umask(0o077)
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192: raise ValueError('Oversized request')
    request = decode(raw)
    if not isinstance(request, dict): raise ValueError('Invalid request')
    operation = request.get('operation')
    if operation not in ('review', 'disable') or set(request) != ({'operation'} if operation == 'review' else {'operation', 'proposal'}):
        raise ValueError('Unsupported operation')
    # Acquire the same protected update lock used by the installer.
    # This helper imports only the standard library under isolated Python.
    with tempfile.TemporaryDirectory(prefix='security-center-unlock-cache-', dir='/run') as cache:
        sys.pycache_prefix = cache; sys.dont_write_bytecode = True
        # Inline the lock acquisition to avoid any mutable or hyphenated imports.
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        lock = None
        try:
            for part in ('var', 'lib', 'security-center-updates'):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
                info = os.fstat(fd)
                if info.st_uid != 0 or info.st_mode & 0o022: raise PermissionError('Unsafe lock parent')
            lock = os.open('update.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise PermissionError('Unsafe lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if operation == 'review': result = proposal(read_metadata(DEVICE), disk_identity())
            else:
                private_parent()
                result = apply(request['proposal'])
            print(json.dumps({'ok': True, 'result': result}))
        finally:
            if lock is not None: os.close(lock)
            os.close(fd)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        code = ('authorization_required' if isinstance(error, PermissionError) else
                'busy' if isinstance(error, BlockingIOError) else
                'review_required' if isinstance(error, ValueError) else 'unavailable')
        print(json.dumps({'ok': False, 'error': code})); sys.exit(1)
