import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'securityd'))
import telemetry_query as q


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'db'
        db = sqlite3.connect(self.path)
        db.execute('CREATE TABLE hourly(hour INTEGER PRIMARY KEY,payload TEXT)')
        db.commit(); db.close(); self.path.chmod(0o600)
        self.value = dict(samples=2, metrics={'cpu':dict(count=2,sum=30,min=10,max=20)}, mixed_boots=False)
        self.insert(100,self.value)

    def insert(self, hour, value):
        db = sqlite3.connect(self.path)
        db.execute('INSERT OR REPLACE INTO hourly VALUES(?,?)',(hour,json.dumps(value)))
        db.commit(); db.close()

    def test_mean_missing_metrics_and_gaps(self):
        value = q.query(self.path, metrics=['cpu','absent'], now=100*3600)
        self.assertEqual(value['rows'][0]['metrics']['cpu']['mean'],15)
        self.assertIsNone(value['rows'][0]['metrics']['absent'])
        self.assertEqual(value['missing_hours'],23)

    def test_query_does_not_mutate_database(self):
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        q.query(self.path,metrics=['cpu'],now=100*3600)
        self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_future_and_old_rows_excluded(self):
        self.insert(101,self.value); self.insert(76,self.value)
        result = q.query(self.path, metrics=['cpu'], now=100*3600)
        self.assertEqual(len(result['rows']),1)

    def test_metric_string_cannot_change_sql(self):
        result = q.query(self.path,metrics=["'; DROP TABLE hourly; --"],now=100*3600)
        self.assertEqual(len(result['rows']),1)
        self.assertEqual(len(q.query(self.path,metrics=['cpu'],now=100*3600)['rows']),1)

    def test_invalid_parameters(self):
        for kwargs in [dict(hours=23),dict(hours=True),dict(metrics=[]),dict(metrics=['x']*9),dict(metrics=['x','x']),dict(now=float('nan'))]:
            with self.assertRaises(ValueError):q.query(self.path,**kwargs)

    def test_invalid_metric_and_oversize_output_fail_closed(self):
        self.value['metrics']['cpu']['count']=0; self.insert(100,self.value)
        with self.assertRaises(ValueError):q.query(self.path,metrics=['cpu'],now=100*3600)
        self.value['metrics']['cpu']['count']=2; self.insert(100,self.value)
        with patch.object(q,'MAX_OUTPUT',100):
            with self.assertRaises(ValueError):q.query(self.path,metrics=['cpu'],now=100*3600)

    def test_deadline(self):
        with patch.object(q.time,'monotonic',side_effect=[1,4]):
            with self.assertRaises(TimeoutError):q.query(self.path,metrics=['cpu'],now=100*3600)

    def test_symlink_and_public_file_rejected(self):
        alias = self.path.parent / 'alias'; alias.symlink_to(self.path)
        with self.assertRaises(ValueError):q.query(alias)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):q.query(self.path)

    def test_missing_db_not_created(self):
        missing=self.path.parent/'missing'
        with self.assertRaises(FileNotFoundError):q.query(missing)
        self.assertFalse(missing.exists())


if __name__=='__main__':unittest.main()

class DaemonHistoryTests(unittest.TestCase):
    def test_recording_history_failure_does_not_hide_security_modules(self):
        import datetime
        import threading
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'initramfs'))
        import daemon
        for failure in (FileNotFoundError(), ValueError('malformed')):
            stop = threading.Event()
            snapshot = dict(generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),boot_id='fixture',modules=[])
            with tempfile.TemporaryDirectory() as temp, patch.object(daemon,'stop',stop), patch.object(stop,'wait',side_effect=lambda _:stop.set()), patch.object(daemon,'snapshot',return_value=snapshot), patch.object(daemon,'journal_batch',side_effect=OSError()), patch.object(daemon,'telemetry_query',side_effect=failure):
                daemon.refresh(database=str(Path(temp)/'events.sqlite'))
                result=json.loads(daemon.cache)
            self.assertIn('modules',result)
            self.assertEqual(result['telemetry_history_status'],'not_recorded' if isinstance(failure,FileNotFoundError) else 'unavailable')
            self.assertEqual(result['history_status'],'available')
            self.assertNotIn('telemetry_history',result)
