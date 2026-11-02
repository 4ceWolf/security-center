import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'securityd'))
import telemetry as t
import telemetry_worker as w


class Stop:
    def __init__(self, count):
        self.count = count
        self.waits = []
    def is_set(self):
        return self.count <= 0
    def wait(self, seconds):
        self.waits.append(seconds)
        self.count -= 1


class Sampler:
    def sample(self):
        return dict(timestamp=100000, metrics={'cpu.busy_percent':12}, interval_seconds=30,
                    issues=[], boot_id='fixture', top_cpu=[], top_ram=[])


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_writer_lock_excludes_second_store_and_releases(self):
        path = self.root / 'db'
        first = t.Store(path)
        try:
            with self.assertRaises(BlockingIOError):
                t.Store(path)
        finally:
            first.close()
        t.Store(path).close()

    def test_failed_open_releases_lock(self):
        path = self.root / 'db'
        path.write_text('not a database')
        path.chmod(0o600)
        for _ in range(2):
            with self.assertRaises(sqlite3.DatabaseError):
                t.Store(path)

    def test_normal_stop_has_saved_samples_and_health(self):
        stop = Stop(2)
        w.run(self.root, interval=30, stop=stop, sampler=Sampler())
        health = json.loads((self.root / 'health.json').read_text())
        self.assertEqual(health['state'], 'stopped')
        self.assertEqual(health['samples_written'], 2)
        self.assertIsNotNone(health['last_success_boottime'])
        self.assertTrue(all(1 <= delay <= 30 for delay in stop.waits))
        self.assertEqual((self.root / 'health.json').stat().st_mode & 0o777, 0o600)
        store = t.Store(self.root / 'diagnostics.sqlite')
        try:
            self.assertEqual(store.db.execute('SELECT count(*) FROM samples').fetchone()[0], 2)
        finally:
            store.close()

    def test_failure_then_recovery_visible_without_exception_details(self):
        states = []
        publish = w.publish_health
        def capture(directory, status):
            states.append(dict(status))
            publish(directory, status)
        attempts = []
        def factory(path):
            attempts.append(1)
            if len(attempts) == 1:
                raise sqlite3.OperationalError('SECRET database details')
            return t.Store(path)
        with patch.object(w, 'publish_health', side_effect=capture):
            w.run(self.root, interval=1, stop=Stop(2), sampler=Sampler(), store_factory=factory)
        self.assertEqual([s['state'] for s in states], ['starting','degraded','recording','stopped'])
        self.assertNotIn('SECRET', json.dumps(states))
        self.assertEqual(states[1]['consecutive_failures'], 1)
        self.assertEqual(states[-1]['consecutive_failures'], 0)

    def test_duplicate_worker_does_not_touch_health(self):
        lock = t.private_lock(self.root / 'worker.lock')
        self.addCleanup(os.close, lock)
        with self.assertRaises(BlockingIOError):
            w.run(self.root, stop=Stop(1), sampler=Sampler())
        self.assertFalse((self.root / 'health.json').exists())

    def test_health_write_failure_releases_all_locks(self):
        with patch.object(w, 'publish_health', side_effect=OSError('full disk')):
            with self.assertRaises(OSError):
                w.run(self.root, stop=Stop(1), sampler=Sampler())
        os.close(t.private_lock(self.root / 'worker.lock'))

    def test_invalid_interval_rejected_before_creating_state(self):
        for interval in (0, 301, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                w.run(self.root / 'unused', interval=interval)
        self.assertFalse((self.root / 'unused').exists())


if __name__ == '__main__':
    unittest.main()

class ManagedDirectoryTests(unittest.TestCase):
    def test_exact_managed_alias_resolves_to_private_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / 'private/security-center-telemetry'
            private.mkdir(parents=True, mode=0o700)
            public = root / 'security-center-telemetry'
            public.symlink_to(Path('private/security-center-telemetry'))
            self.assertEqual(w.state_directory(public, private, alias_owner=os.getuid()), private)
            # The normal no-symlink lock path is used after alias validation.
            lock = t.private_lock(w.state_directory(public, private, alias_owner=os.getuid()) / 'worker.lock')
            os.close(lock)
    def test_wrong_target_or_owner_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);private = root / 'private/security-center-telemetry'
            private.mkdir(parents=True)
            public = root / 'security-center-telemetry';public.symlink_to(root)
            with self.assertRaises(ValueError):w.state_directory(public, private, alias_owner=os.getuid())
            public.unlink();public.symlink_to(private)
            with self.assertRaises(ValueError):w.state_directory(public, private, alias_owner=os.getuid()+1)
