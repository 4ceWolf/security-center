#!/usr/bin/python3
"""Real worker crash/restart, shutdown and degraded-storage rehearsal."""
import json
from pathlib import Path
import resource
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
RUNNER = '''import runpy,signal,threading,sys
worker=runpy.run_path(sys.argv[1])
stop=threading.Event()
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
worker['run'](directory=sys.argv[2],interval=1,stop=stop)
'''


def stop(child, force=False):
    if child.poll() is None:
        child.kill() if force else child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        raise


def ready(child, directory, state, samples=0):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError('Worker exited before expected state')
        try:
            value = json.loads((directory / 'health.json').read_text())
            if value['pid'] == child.pid and value['state'] == state and value['samples_written'] >= samples:
                return value
        except FileNotFoundError:
            pass
        time.sleep(.05)
    raise TimeoutError('Worker state deadline')


def count(path):
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    try:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        return db.execute('SELECT count(*) FROM samples').fetchone()[0]
    finally:
        db.close()


def main():
    with tempfile.TemporaryDirectory(prefix='telemetry-worker-', dir=ROOT / 'work') as folder:
        directory = Path(folder)
        log = directory / 'worker.log'
        def launch():
            with log.open('ab') as stream:
                return subprocess.Popen([sys.executable, '-I', '-c', RUNNER,
                                         str(ROOT / 'securityd/telemetry_worker.py'), str(directory)], stdout=stream, stderr=stream)
        child = launch()
        try:
            ready(child, directory, 'recording', 2)
            before = count(directory / 'diagnostics.sqlite')
        finally:
            stop(child, force=True)
        child = launch()
        try:
            ready(child, directory, 'recording', 2)
            after = count(directory / 'diagnostics.sqlite')
            assert after >= before + 2
        finally:
            stop(child)
        assert child.returncode == 0
        assert json.loads((directory / 'health.json').read_text())['state'] == 'stopped'
        # Preserve actual successful DB while testing an unavailable DB pathname.
        (directory / 'diagnostics.sqlite').rename(directory / 'saved.sqlite')
        (directory / 'diagnostics.sqlite').mkdir()
        child = launch()
        try:
            degraded = ready(child, directory, 'degraded')
            assert degraded['samples_written'] == 0 and degraded['last_success_unix'] is None
            (directory / 'diagnostics.sqlite').rmdir()
            (directory / 'saved.sqlite').rename(directory / 'diagnostics.sqlite')
            recovered = ready(child, directory, 'recording', 1)
            assert recovered['consecutive_failures'] == 0
        finally:
            stop(child)
        report = dict(passed=True, records_before_crash=before, records_after_restart=after,
                      graceful_shutdown=True, storage_error_reported=True, storage_recovery=True,
                      child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                      limitations='Unprivileged temporary worker; not installed DynamicUser service or full-stack benchmark.')
    target = ROOT / 'work/telemetry/worker-report.json'
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
