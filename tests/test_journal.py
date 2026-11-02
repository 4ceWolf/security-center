import copy,json,pathlib,sqlite3,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
import collector,history

class JournalTests(unittest.TestCase):
 def row(self,cursor='a',**changes):
  return dict({'__CURSOR':cursor,'MESSAGE':'Started secret=DO_NOT_EXPORT','UNIT':'security-center.service',
   '_PID':'1','_UID':'0','_COMM':'systemd','_BOOT_ID':'boot','__REALTIME_TIMESTAMP':str(int(time.time()*1000000))},**changes)
 def test_restart_resumes_after_exact_anchor(self):
  with patch.object(collector,'run',side_effect=[json.dumps(self.row()),json.dumps(self.row('b'))]) as run:
   batch=collector.journal_batch('a')
  self.assertFalse(batch['gap']);self.assertEqual(batch['cursor'],'b')
  self.assertIn('--after-cursor=a',run.call_args_list[1].args[0])
  self.assertNotIn('DO_NOT_EXPORT',json.dumps(batch))
 def test_rotation_reports_gap_and_replays_retained(self):
  with patch.object(collector,'run',side_effect=[json.dumps(self.row('other')),json.dumps(self.row('b'))]) as run:
   batch=collector.journal_batch('a')
  self.assertTrue(batch['gap']);self.assertIn('--since=-30days',run.call_args_list[1].args[0])
 def test_empty_batch_preserves_position(self):
  with patch.object(collector,'run',side_effect=[json.dumps(self.row()),'']):
   self.assertEqual(collector.journal_batch('a')['cursor'],'a')
 def test_spoofed_client_fields_do_not_produce_event(self):
  with patch.object(collector,'run',return_value=json.dumps(self.row(_PID='500',_UID='1000'))):
   batch=collector.journal_batch()
  self.assertEqual(batch['events'],[]);self.assertEqual(batch['cursor'],'a')
 def test_batch_boundary_reports_possible_backlog(self):
  with patch.object(collector,'JOURNAL_LIMIT',2),patch.object(collector,'run',return_value='\n'.join(json.dumps(self.row(str(i))) for i in range(2))):
   self.assertTrue(collector.journal_batch()['backlog'])
 def test_malformed_cursor_never_advances(self):
  with patch.object(collector,'run',return_value=json.dumps(self.row(''))):
   with self.assertRaises(ValueError):collector.journal_batch()
 def test_events_and_cursor_roll_back_together(self):
  with tempfile.TemporaryDirectory() as folder:
   store=history.History(pathlib.Path(folder)/'events.sqlite')
   data={'generated_at':history.datetime.datetime.now(history.datetime.timezone.utc).isoformat(),
    'boot_id':'boot','modules':[],'events':[], '_journal_batch':{'cursor':'a','gap':False}}
   store.record(data);self.assertEqual(store.journal_cursor(),'a')
   data['_journal_batch']={'cursor':'b','gap':True}
   with patch.object(store,'_insert',side_effect=sqlite3.DatabaseError):
    with self.assertRaises(sqlite3.DatabaseError):store.record(data)
   self.assertEqual(history.History(store.path).journal_cursor(),'a')
   rows=store.record(data);self.assertEqual(store.journal_cursor(),'b')
   self.assertEqual(rows[0]['kind'],'coverage_gap')

if __name__=='__main__':unittest.main()
