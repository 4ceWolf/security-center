import copy,json,pathlib,sqlite3,sys,tempfile,time,unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
import history,daemon

class HistoryTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.path=pathlib.Path(self.temp.name)/'events.sqlite'
  self.data={'generated_at':history.datetime.datetime.now(history.datetime.timezone.utc).isoformat(),
   'boot_id':'boot-a','modules':[{'id':'lockdown','status':'secure','summary':'Integrity enabled','details':{}}],
   'events':[],'event_status':'available'}
 def test_durable_deduplicated_and_labeled(self):
  store=history.History(self.path);first=store.record(self.data)
  self.assertEqual(first[0]['kind'],'observation')
  self.assertEqual(len(history.History(self.path).record(self.data)),1)
  changed=copy.deepcopy(self.data);changed['modules'][0]['status']='attention'
  changed['modules'][0]['summary']='Lockdown off'
  self.assertEqual(len(store.record(changed)),2)
  changed['boot_id']='boot-b'
  self.assertEqual(len(store.record(changed)),3)
  self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
 def test_retention_and_old_journal_events(self):
  self.data['events']=[{'timestamp':time.time()+i,'boot_id':'a','source':'test','severity':'info','summary':str(i)} for i in range(20)]
  self.data['events'].append({'timestamp':1,'boot_id':'old','source':'test','severity':'info','summary':'expired'})
  with patch.object(history,'MAX_EVENTS',5):rows=history.History(self.path).record(self.data)
  self.assertEqual(len(rows),5);self.assertNotIn('expired',json.dumps(rows))
 def test_untrusted_strings_are_data_and_bounded(self):
  self.data['events']=[{'timestamp':time.time(),'boot_id':'a','source':"'; DROP TABLE events;--",'severity':'info','summary':'<script>'+('x'*1000)}]
  rows=history.History(self.path).record(self.data)
  self.assertEqual(len(rows),2)
  self.assertLessEqual(max(len(e['summary']) for e in rows),256)
 def test_history_failure_preserves_status(self):
  stopper=Mock();stopper.is_set.side_effect=[False,True]
  with patch.object(daemon,'stop',stopper),patch.object(daemon,'snapshot',return_value=copy.deepcopy(self.data)),patch.object(daemon,'journal_batch',side_effect=RuntimeError),patch.object(daemon,'History') as cls:
   cls.return_value.record.side_effect=sqlite3.DatabaseError('bad db')
   daemon.refresh()
  out=json.loads(daemon.cache)
  self.assertEqual(out['modules'][0]['status'],'secure')
  self.assertEqual(out['history_status'],'unavailable')

 def test_native_policy_change_same_count_is_recorded(self):
  item={'id':'opensnitch','status':'unknown','summary':'One rule','details':{'inventory':{'rules':[{'fingerprint':'a'*64}]}}}
  changed=copy.deepcopy(item);changed['details']['inventory']['rules'][0]['fingerprint']='b'*64
  self.assertNotEqual(history.fingerprint(item),history.fingerprint(changed))
  self.data['modules']=[item];store=history.History(self.path);store.record(self.data)
  self.data['modules']=[changed];rows=store.record(self.data)
  self.assertEqual(len(rows),2);self.assertIn('state_change',[row['kind'] for row in rows])

 def test_native_integrity_change_without_device_count_change_is_recorded(self):
  for identifier,field in [('opensnitch','native_configuration'),('usbguard','native_policy_integrity')]:
   item={'id':identifier,'status':'unknown','summary':'Unchanged counts','details':{field:{'rules_sha256':'a'*64}}}
   changed=copy.deepcopy(item);changed['details'][field]['rules_sha256']='b'*64
   self.assertNotEqual(history.fingerprint(item),history.fingerprint(changed))

if __name__=='__main__':unittest.main()

