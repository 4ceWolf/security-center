import contextlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'securityd'))
from telemetry import Store
import telemetry_actions as actions


def paused_append(path, sample, channel):
    store=Store(path)
    def pause(sql):
        if sql.startswith('SELECT payload FROM hourly'):
            channel.send('write_lock_acquired')
            if not channel.poll(5):raise RuntimeError('Test peer did not respond')
            channel.recv()
    store.db.set_trace_callback(pause)
    store.append(sample)
    store.close()


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'work',prefix='telemetry-actions-test-')
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'diagnostics.sqlite'
        self.sample=dict(schema=1,timestamp=100*3600,boot_id='boot-one',interval_seconds=None,
            metrics={'cpu.cpu.busy_percent':20},batteries={},top_cpu=[],top_ram=[],processes_observed=0,issues=[])
        store=Store(self.path);store.append(self.sample);store.close()
    def counts(self):
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            return tuple(db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('samples','hourly'))
    def test_fixed_requests_and_privacy_selection(self):
        export=dict(operation='export',hours=24,resolution='hourly',include_processes=False)
        self.assertEqual(actions.request(json.dumps(export).encode()),export)
        for change in ({'path':'/etc/shadow'},{'sql':'DELETE FROM x'},{'include_processes':1},{'hours':True},{'hours':2161},{'resolution':[]}):
            with self.assertRaises(ValueError):actions.validate({**export,**change})
        for raw in (b'{}',b'['*2000+b'0'+b']'*2000,b'x'*4097,b'{"operation":"erase","operation":"export"}'):
            with self.assertRaises(ValueError):actions.request(raw)
        for confirmation in (None,True,'yes','erase'):
            with self.assertRaises(ValueError):actions.validate(dict(operation='erase',confirmation=confirmation))
        self.assertEqual(actions.validate(dict(operation='erase',confirmation='erase_saved_telemetry'))['operation'],'erase')
    def test_clear_in_place_and_next_sample(self):
        before=self.path.stat();result=actions.erase(self.path)
        self.assertEqual((result['removed_samples'],result['removed_hours']),(1,1))
        self.assertFalse(result['forensic_erasure']);self.assertEqual(self.counts(),(0,0))
        after=self.path.stat();self.assertEqual((before.st_ino,before.st_uid,before.st_mode),(after.st_ino,after.st_uid,after.st_mode))
        store=Store(self.path);store.append(self.sample);store.close()
        with contextlib.closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(json.loads(db.execute('SELECT payload FROM hourly').fetchone()[0])['samples'],1)
    def test_missing_linked_fifo_or_public_database_refused(self):
        missing=self.path.with_name('missing')
        with self.assertRaises(FileNotFoundError):actions.erase(missing)
        self.assertFalse(missing.exists())
        alias=self.path.with_name('alias');alias.symlink_to(self.path)
        with self.assertRaises(ValueError):actions.erase(alias)
        fifo=self.path.with_name('fifo');os.mkfifo(fifo)
        with self.assertRaises(ValueError):actions.erase(fifo)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):actions.erase(self.path)
        self.path.chmod(0o600);os.link(self.path,self.path.with_name('hardlink'))
        with self.assertRaises(ValueError):actions.erase(self.path)
    def test_schema_surprises_refuse_without_deleting(self):
        for sql in ('CREATE TABLE other(x)', 'CREATE TRIGGER extra AFTER DELETE ON samples BEGIN DELETE FROM hourly; END', 'CREATE TRIGGER sqliteevil AFTER DELETE ON samples BEGIN DELETE FROM hourly; END'):
            with contextlib.closing(sqlite3.connect(self.path)) as db, db:db.execute(sql)
            with self.assertRaises(ValueError):actions.erase(self.path)
            self.assertEqual(self.counts(),(1,1))
            with contextlib.closing(sqlite3.connect(self.path)) as db, db:db.execute('DROP '+('TABLE other' if 'TABLE' in sql else 'TRIGGER sqliteevil' if 'sqliteevil' in sql else 'TRIGGER extra'))
    def test_failure_between_deletes_rolls_back(self):
        real_connect=actions.sqlite3.connect
        def connect(*args,**kwargs):
            db=real_connect(*args,**kwargs)
            def authorize(action,table,*unused):
                return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_DELETE and table=='hourly' else sqlite3.SQLITE_OK
            db.set_authorizer(authorize);return db
        from unittest.mock import patch
        with patch.object(actions.sqlite3,'connect',side_effect=connect):
            with self.assertRaises(sqlite3.DatabaseError):actions.erase(self.path)
        self.assertEqual(self.counts(),(1,1))
    def test_actual_concurrent_append_lock_prevents_old_summary_resurrection(self):
        ctx=multiprocessing.get_context('spawn');parent,child=ctx.Pipe()
        process=ctx.Process(target=paused_append,args=(str(self.path),self.sample,child));process.start();child.close()
        try:
            self.assertTrue(parent.poll(5),'writer did not reach locked read')
            self.assertEqual(parent.recv(),'write_lock_acquired')
            with self.assertRaises(sqlite3.OperationalError):actions.erase(self.path)
            parent.send('continue');process.join(5);self.assertEqual(process.exitcode,0)
            self.assertEqual(actions.erase(self.path)['removed_samples'],2)
            store=Store(self.path);store.append(self.sample);store.close()
            with contextlib.closing(sqlite3.connect(self.path)) as db, db:
                self.assertEqual(json.loads(db.execute('SELECT payload FROM hourly').fetchone()[0])['samples'],1)
        finally:
            if process.is_alive():process.terminate();process.join(5)
            parent.close()

if __name__=='__main__':unittest.main()
