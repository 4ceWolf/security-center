import copy
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'modules'))
from unlock_recovery_plan import prepare

class RecoveryPlanTests(unittest.TestCase):
 def evidence(self):
  return dict(schema_version=1,device_uuid='11111111-2222-3333-4444-555555555555',expected_device_uuid='11111111-2222-3333-4444-555555555555',secure_boot=True,lockdown='integrity',manual_slot_0_present=True,manual_passphrase_verified=True,public_key_sha256='a'*64,expected_public_key_sha256='a'*64,intentional_change_confirmed=True,header_backup_verified=True,tokens=[dict(direct_pcrs=[7],signed_pcrs=[11],policy_reference='initrd',pcr_bank='sha256',srk_present=True,keyslots=['2'])])
 def test_clean_plan_is_not_permission_or_success(self):
  e=self.evidence();before=copy.deepcopy(e);r=prepare(e)
  self.assertTrue(r['eligible_for_transaction_review']);self.assertFalse(r['repair_authorized']);self.assertFalse(r['enrollment_performed']);self.assertEqual(e,before)
 def test_every_required_fact_blocks_independently(self):
  for key in ('secure_boot','manual_slot_0_present','manual_passphrase_verified','intentional_change_confirmed','header_backup_verified'):
   e=self.evidence();e[key]=False
   with self.subTest(key=key):self.assertTrue(prepare(e)['blockers'])
 def test_identity_policy_and_manual_slot_changes_block(self):
  changes=[('device_uuid','21111111-2222-3333-4444-555555555555'),('public_key_sha256','b'*64),('lockdown','none'),('tokens',[])]
  for key,value in changes:
   e=self.evidence();e[key]=value
   with self.subTest(key=key):self.assertTrue(prepare(e)['blockers'])
  for key,value in (('direct_pcrs',[]),('signed_pcrs',[7]),('policy_reference',''),('pcr_bank','sha1'),('srk_present',False),('keyslots',['0'])):
   e=self.evidence();e['tokens'][0][key]=value
   with self.subTest(token_key=key):self.assertTrue(prepare(e)['blockers'])
 def test_secrets_unknown_fields_and_malformed_evidence_refused(self):
  for key,value in (('passphrase','secret'),('schema_version',True),('secure_boot',1),('device_uuid','/dev/other'),('tokens',[{'tpm2-blob':'secret'}])):
   e=self.evidence();e[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):prepare(e)
 def test_digest_binds_all_inputs(self):
  e=self.evidence();original=prepare(e)['proposal_sha256'];e['header_backup_verified']=False
  self.assertNotEqual(original,prepare(e)['proposal_sha256'])
