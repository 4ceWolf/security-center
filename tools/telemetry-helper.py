#!/usr/bin/python3
"""Fixed on-demand administrator telemetry export/removal; no arbitrary commands."""
import contextlib
import fcntl
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import sys
import syslog
import tempfile


@contextlib.contextmanager
def update_guard():
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    lock = None
    try:
        for part in ('var', 'lib', 'security-center-updates'):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Unsafe update-lock parent')
        lock = os.open('update.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise PermissionError('Unsafe update lock')
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield
    finally:
        if lock is not None: os.close(lock)
        os.close(parent)


def main():
    if os.geteuid() != 0:
        raise PermissionError('Administrator access required')
    if len(sys.argv) != 1:
        raise ValueError('Arguments are not supported')
    with update_guard(), tempfile.TemporaryDirectory(prefix='security-center-telemetry-helper-', dir='/run') as cache:
        sys.pycache_prefix = cache
        sys.dont_write_bytecode = True
        sys.path.insert(0, '/usr/local/lib/security-center')
        from telemetry_actions import MAX_REQUEST, request, erase
        data = request(sys.stdin.buffer.read(MAX_REQUEST + 1))
        if data['operation'] == 'export':
            from telemetry_export import export
            with export(hours=data['hours'], resolution=data['resolution'],
                        include_processes=data['include_processes']) as spool:
                shutil.copyfileobj(spool, sys.stdout.buffer, 65536)
        else:
            result = erase()
            # No sample values, process identities, tokens or paths in the audit.
            # Record root execution, not an inferred authenticated human identity.
            try:
                syslog.openlog('security-center-telemetry-helper')
                syslog.syslog(syslog.LOG_NOTICE, 'Diagnostic history cleared by administrator helper; actor_uid=0')
            except OSError:
                pass  # An audit transport failure cannot undo a committed removal.
            print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = ('authorization_required' if isinstance(error, PermissionError) else
                'busy' if isinstance(error, BlockingIOError) or isinstance(error, sqlite3.OperationalError)
                and ('locked' in str(error) or 'busy' in str(error)) else
                'invalid_request' if isinstance(error, ValueError) else
                'not_recorded' if isinstance(error, FileNotFoundError) else 'unavailable')
        print(json.dumps({'ok': False, 'error': code}))
        sys.exit(1)
