import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upgrade_review',ROOT/'tools/prepare-monitor-upgrade.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ReviewTests(unittest.TestCase):
 def setUp(self):
  self.manifest={'fim_paths':['/a','/b'],'files':[{'source':'source','destination':'/a','sha256':'new'}]}
  self.present={'state':'present','sha256':'old','uid':0,'gid':0,'mode':0o644}
  self.observations={'/a':dict(self.present),'/b':dict(self.present)}
 def test_missing_baseline_never_implies_approval(self):
  plan=m.compare(self.manifest,self.observations)
  self.assertFalse(plan['deployable']);self.assertFalse(plan['approval_granted'])
  self.assertEqual(plan['baseline_state'],'unavailable');self.assertIsNone(plan['scope_additions'])
  self.assertEqual(plan['files'][0]['action'],'replace')
 def test_matching_hash_wrong_permissions_still_replacement(self):
  self.observations['/a'].update(sha256='new',mode=0o666)
  self.assertEqual(m.compare(self.manifest,self.observations)['files'][0]['action'],'replace')
 def test_addition_unreadable_and_unchanged_distinct(self):
  for state,expected in [({'state':'missing'},'add'),({'state':'unavailable'},'unreadable'),(dict(self.present,sha256='new'),'unchanged')]:
   self.observations['/a']=state
   self.assertEqual(m.compare(self.manifest,self.observations)['files'][0]['action'],expected)
 def test_drift_and_scope_additions_are_explicit(self):
  baseline={'schema_version':1,'approved':True,'files':{'/a':dict(self.present,sha256='unexpected')}}
  plan=m.compare(self.manifest,self.observations,baseline)
  self.assertEqual(plan['baseline_drift'],['/a']);self.assertEqual(plan['scope_additions'],['/b'])
 def test_scope_removal_and_incomplete_observation_rejected(self):
  with self.assertRaises(ValueError):m.compare(self.manifest,{'/a':self.present})
  with self.assertRaises(ValueError):m.compare(self.manifest,self.observations,{'schema_version':1,'approved':True,'files':{'/removed':self.present}})

if __name__=='__main__':unittest.main()
