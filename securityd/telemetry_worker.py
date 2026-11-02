"""Fixed-path background recorder. No remote API or privileged actions."""
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import threading
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from telemetry import Sampler, Store, private_lock

DIRECTORY = Path('/var/lib/security-center-telemetry')
PRIVATE_DIRECTORY = Path('/var/lib/private/security-center-telemetry')


def state_directory(public=DIRECTORY, private=PRIVATE_DIRECTORY, *, alias_owner=0):
    # DynamicUser provides a root-owned link to its private/id-mapped directory.
    # Resolve only that exact managed alias; Store/private_lock still reject
    # symlinks, unsafe ownership and public permissions at the actual directory.
    if not public.is_symlink(): return public
    info = public.lstat()
    target = public.readlink()
    if info.st_uid != alias_owner or target not in (private, Path('private') / private.name):
        raise ValueError('Unexpected telemetry state alias')
    resolved = public.resolve(strict=True)
    if resolved != private:
        raise ValueError('Telemetry state alias escaped its private directory')
    return resolved


def publish_health(directory, status):
    """Atomic private status; readers must check boot and freshness after a crash."""
    fd, name = tempfile.mkstemp(prefix='.health-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(status, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / 'health.json')
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def run(directory=DIRECTORY, interval=30, stop=None, sampler=None, store_factory=Store):
    if not math.isfinite(interval) or not 1 <= interval <= 300:
        raise ValueError('Sampling interval out of range')
    directory = Path(directory)
    lock = private_lock(directory / 'worker.lock')
    stop = stop if stop is not None else threading.Event()
    sampler = sampler if sampler is not None else Sampler(interval=interval)
    store = None
    status = dict(schema=1, pid=os.getpid(), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  interval_seconds=interval, samples_written=0, consecutive_failures=0,
                  last_success_unix=None, last_success_boottime=None, error=None)
    def publish(state):
        status.update(state=state, updated_unix=time.time(), updated_boottime=time.clock_gettime(time.CLOCK_BOOTTIME))
        publish_health(directory, status)
    try:
        publish('starting')
        while not stop.is_set():
            started = time.monotonic()
            try:
                if store is None:
                    store = store_factory(directory / 'diagnostics.sqlite')
                sample = sampler.sample()
                store.append(sample)
            except (OSError, ValueError, sqlite3.Error) as error:
                if store is not None:
                    store.close()
                    store = None
                status['consecutive_failures'] += 1
                # Do not persist exception strings, SQL or file contents.
                status['error'] = type(error).__name__
                publish('degraded')
            else:
                status.update(samples_written=status['samples_written'] + 1,
                              consecutive_failures=0, error=None,
                              last_success_unix=time.time(),
                              last_success_boottime=time.clock_gettime(time.CLOCK_BOOTTIME))
                publish('recording')
            # No catch-up burst if a collection or resume is delayed.
            stop.wait(max(1, interval - (time.monotonic() - started)))
        publish('stopped')
    finally:
        if store is not None:
            store.close()
        os.close(lock)


def main():
    os.umask(0o077)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    run(directory=state_directory(), stop=stop)


if __name__ == '__main__':
    main()
