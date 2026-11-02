import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'securityd'))
from telemetry import Store
spec=importlib.util.spec_from_file_location('telemetry_export',ROOT/'tools/export-telemetry.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)

class ExportTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.path=Path(self.temp.name)/'diagnostics.sqlite'
  self.sample=dict(schema=1,timestamp=100*3600,boot_id='boot-one',interval_seconds=None,
    metrics={'cpu.cpu.busy_percent':20,'battery.BAT0.percent':60},batteries={'BAT0':{'status':'Discharging'}},
    top_cpu=[],top_ram=[dict(name='PRIVATE_APP',pid=42,start_ticks=10,ticks=20,rss_bytes=2048)],processes_observed=1,issues=['source unavailable'])
  self.append(self.sample)
 def append(self,sample):
  store=Store(self.path)
  try:store.append(sample)
  finally:store.close()
 def get(self,**kwargs):
  with e.export(self.path,now=100*3600+60,**kwargs) as spool:return json.load(spool)
 def test_raw_preserves_values_boot_gap_and_omits_processes_by_default(self):
  result=self.get(resolution='raw')
  self.assertEqual(result['row_count'],1)
  row=result['rows'][0];self.assertEqual(row['metrics']['cpu.cpu.busy_percent'],20)
  self.assertIsNone(row['interval_seconds']);self.assertEqual(row['source_issue_count'],1)
  self.assertNotIn('PRIVATE_APP',json.dumps(result));self.assertNotIn('top_ram',row)
 def test_explicit_process_optin_keeps_only_allowed_fields(self):
  process=self.sample['top_ram'][0];process.update(argv='SECRET_ARG',environment='SECRET_ENV',path='/secret/path')
  db=sqlite3.connect(self.path);db.execute('UPDATE samples SET payload=?',(json.dumps(self.sample),));db.commit();db.close()
  row=self.get(resolution='raw',include_processes=True)['rows'][0]
  self.assertEqual(row['top_ram'][0]['name'],'PRIVATE_APP')
  for secret in ('SECRET_ARG','SECRET_ENV','/secret/path'):self.assertNotIn(secret,json.dumps(row))
 def test_hourly_mean_coverage_and_private_peaks(self):
  result=self.get();row=result['rows'][0]
  self.assertEqual(row['metrics']['cpu.cpu.busy_percent']['mean'],20)
  self.assertEqual(result['missing_hours'],23);self.assertEqual(row['samples_with_issues'],1);self.assertEqual(row['boot_ids'],['boot-one'])
  self.assertNotIn('PRIVATE_APP',json.dumps(row))
  self.assertEqual(self.get(include_processes=True)['rows'][0]['peak_ram']['name'],'PRIVATE_APP')
 def test_future_and_old_rows_excluded_without_filling_gaps(self):
  db=sqlite3.connect(self.path)
  for stamp in (100*3600+120,75*3600):
   value=copy.deepcopy(self.sample);value['timestamp']=stamp
   db.execute('INSERT INTO samples(timestamp,payload) VALUES(?,?)',(stamp,json.dumps(value)))
  db.commit();db.close()
  self.assertEqual(self.get(resolution='raw')['row_count'],1)
 def test_readonly_hash_unchanged_and_missing_db_not_created(self):
  before=hashlib.sha256(self.path.read_bytes()).hexdigest();self.get()
  self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(),before)
  path=self.path.with_name('missing')
  with self.assertRaises(FileNotFoundError):e.export(path)
  self.assertFalse(path.exists())
 def test_byte_bound_failure_returns_no_partial_export(self):
  with patch.object(e,'MAX_OUTPUT',100):
   with self.assertRaises(ValueError):self.get()
 def test_deadline(self):
  with patch.object(e.time,'monotonic',side_effect=[1,10]):
   with self.assertRaises(TimeoutError):self.get()
 def test_malformed_nonfinite_duplicate_and_timestamp_mismatch_rejected(self):
  malformed=['{"schema":1,"schema":1}',json.dumps({**self.sample,'timestamp':0}),json.dumps({**self.sample,'metrics':{'cpu.cpu.busy_percent':float('nan')}})]
  for raw in malformed:
   db=sqlite3.connect(self.path);db.execute('UPDATE samples SET payload=?',(raw,));db.commit();db.close()
   with self.assertRaises(ValueError):self.get(resolution='raw')
 def test_invalid_window_options_and_public_or_linked_database_rejected(self):
  for kwargs in (dict(hours=25,resolution='raw'),dict(hours=True),dict(hours=2161),dict(include_processes=1)):
   with self.assertRaises(ValueError):self.get(**kwargs)
  self.path.chmod(0o644)
  with self.assertRaises(ValueError):self.get()
  self.path.chmod(0o600)
  alias=self.path.with_name('alias');alias.symlink_to(self.path)
  with self.assertRaises(ValueError):e.export(alias)
  os.link(self.path,self.path.with_name('hardlink'))
  with self.assertRaises(ValueError):self.get()

if __name__=='__main__':unittest.main()
