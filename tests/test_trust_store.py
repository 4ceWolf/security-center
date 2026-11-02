import copy
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'policies'))
from trust_store import Store
from trust_policy import propose, device_id, revision

class TrustStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-center-trust-test-')
        self.addCleanup(self.temp.cleanup)
        self.path = pathlib.Path(self.temp.name)
        self.store = Store(fixture=self.path)
        self.seed = json.loads((ROOT / 'policies/normal-devices.candidate.json').read_text())
        self.device = copy.deepcopy(self.seed['trusted_external'][1]); self.device['port'] += '.1'
        self.inv = {'usb_observation_complete': True, 'errors': [], 'devices': [self.device]}
        self.proposal = propose(self.seed, self.inv, 'add', device_id(self.device))

    def test_saved_policy_and_recoverable_previous_are_durable(self):
        after = self.store.save(self.seed, self.proposal, self.inv, actor=os.getuid())
        self.assertEqual(Store(fixture=self.path).read(self.seed), after)
        with self.store.connect() as db:
            row = db.execute('SELECT before_policy, after_revision FROM audit').fetchone()
            self.assertEqual(json.loads(row[0]), self.seed)
            self.assertEqual(row[1], revision(after))
        self.assertEqual((self.path / 'state.sqlite').stat().st_mode & 0o777, 0o600)

    def test_stale_concurrent_writer_cannot_overwrite_state(self):
        self.store.save(self.seed, self.proposal, self.inv, actor=0)
        with self.assertRaises(ValueError): self.store.save(self.seed, self.proposal, self.inv, actor=0)
        with self.store.connect() as db: self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], 1)

    def test_failure_after_audit_rolls_back_both_state_and_audit(self):
        self.store.read(self.seed)
        with self.store.connect() as db:
            db.execute("CREATE TRIGGER reject_state BEFORE INSERT ON state BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        with self.assertRaises(sqlite3.DatabaseError): self.store.save(self.seed, self.proposal, self.inv, actor=0)
        self.assertEqual(self.store.read(self.seed), self.seed)
        with self.store.connect() as db: self.assertEqual(db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], 0)

    def test_symlink_permissions_and_hardlinks_refused(self):
        outside = self.path / 'outside'; outside.write_text('untouched')
        (self.path / 'state.sqlite').symlink_to(outside)
        with self.assertRaises(PermissionError): self.store.read(self.seed)
        (self.path / 'state.sqlite').unlink()
        os.link(outside, self.path / 'state.sqlite')
        with self.assertRaises(PermissionError): self.store.read(self.seed)
        (self.path / 'state.sqlite').unlink()
        os.chmod(self.path, 0o755)
        with self.assertRaises(PermissionError): self.store.read(self.seed)
        self.assertEqual(outside.read_text(), 'untouched')

    def test_exclusive_lock_and_recovery_after_process_death(self):
        self.store.read(self.seed)
        with self.store.connect():
            with self.assertRaises(BlockingIOError): self.store.read(self.seed)
        pid = os.fork()
        if pid == 0:
            with self.store.connect() as db:
                db.execute('UPDATE state SET policy=? WHERE id=1', (b'bad uncommitted state',))
                os._exit(9)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 9)
        self.assertEqual(self.store.read(self.seed), self.seed)

    def test_lost_database_never_recreates_seed(self):
        selected = device_id(self.seed['trusted_external'][1])
        removal = propose(self.seed, {}, 'remove', selected)
        self.store.save(self.seed, removal, {}, actor=0)
        (self.path / 'state.sqlite').unlink()
        with self.assertRaises(FileNotFoundError): self.store.read(self.seed)
        self.assertFalse((self.path / 'state.sqlite').exists())

    def test_missing_policy_and_changed_seed_never_restore_removed_trust(self):
        selected = device_id(self.seed['trusted_external'][1])
        removal = propose(self.seed, {}, 'remove', selected)
        after = self.store.save(self.seed, removal, {}, actor=0)
        self.assertEqual(self.store.read(self.seed), after)
        with self.store.connect() as db: db.execute('DELETE FROM state')
        with self.assertRaises(ValueError): self.store.read(self.seed)

    def test_initial_seed_is_persisted_and_missing_row_fails_closed(self):
        self.store.read(self.seed)
        changed = copy.deepcopy(self.seed); changed['trusted_external'] = []
        self.assertEqual(self.store.read(changed), self.seed)
        with self.store.connect() as db: db.execute('DELETE FROM state')
        with self.assertRaises(ValueError): self.store.read(changed)

    def test_empty_database_or_interrupted_initialization_requires_recovery(self):
        self.store.read(self.seed)
        (self.path / 'state.sqlite').write_bytes(b'')
        with self.assertRaises(ValueError): self.store.read(self.seed)
        (self.path / 'state.sqlite').unlink()
        with self.assertRaises(FileNotFoundError): self.store.read(self.seed)

    def test_normal_management_does_not_bootstrap_missing_state(self):
        # Exercise the production no-bootstrap branch without host root paths.
        self.store.allow_initialize = False
        with self.assertRaises(FileNotFoundError): self.store.read(self.seed)
        self.assertEqual(list(self.path.iterdir()), [])
        self.path.rmdir()
        with self.assertRaises(FileNotFoundError): self.store.read(self.seed)
        self.assertFalse(self.path.exists())

if __name__ == '__main__': unittest.main()
