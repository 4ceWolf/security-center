import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('unlock_helper', ROOT/'tools/tpm-unlock-helper.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)

class DisableTests(unittest.TestCase):
    def setUp(self):
        self.metadata={'keyslots':{'0':{'type':'luks2','key_size':64},'2':{'type':'luks2','key_size':64}},
                       'tokens':{'1':{'type':'systemd-tpm2','keyslots':['2'],'tpm2-blob':'private'}},
                       'digests':{'0':{'keyslots':['0','2']}},'config':{'json_size':'12288'}}
        self.identity={'rdev':1,'boot_id':'test'}
        self.review=h.proposal(self.metadata,self.identity)
        self.events=[];self.secret=bytearray(b'test-only')
        self.state=copy.deepcopy(self.metadata)
    def execute(self, **overrides):
        def capture(): return copy.deepcopy(self.state),self.identity.copy()
        def remove(key): self.events.append('remove');del self.state['tokens'][key]
        def backup(before): self.events.append('backup');return copy.deepcopy(before),'fixture.img','a'*64
        def verify(device,secret): self.assertEqual(secret,b'test-only');self.events.append('verify')
        args=dict(capture=capture,credential=lambda:self.secret,verify=verify,backup=backup,
                  remove=remove,record=lambda value:self.events.append(value['phase']))
        args.update(overrides)
        return h.disable(self.review,**args)
    def test_success_preserves_all_slots_and_unrelated_metadata(self):
        result=self.execute();self.assertTrue(result['disabled']);self.assertFalse(result['boot_verified'])
        self.assertEqual(self.state,h.after_removal(self.metadata,'1'))
        self.assertEqual(self.events,['verify','backup','verify','removal_pending','remove','disabled'])
        self.assertEqual(self.secret,bytearray(len(self.secret)))
    def test_no_sealed_data_in_proposal(self):
        self.assertNotIn('private',str(self.review));self.assertNotIn('keyslots',self.review)
    def test_stale_or_future_or_modified_proposal(self):
        for delta in (-121,1):
            review=h.proposal(self.metadata,self.identity,issued=1000+delta)
            with self.assertRaises(ValueError):h.validate_proposal(review,self.metadata,self.identity,now=1000)
        self.review['token_id']='2'
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.events,[])
    def test_wrong_passphrase_stops_before_backup(self):
        def wrong(*args): raise RuntimeError('wrong')
        with self.assertRaises(RuntimeError):self.execute(verify=wrong)
        self.assertEqual(self.events,[]);self.assertEqual(self.state,self.metadata)
        self.assertEqual(self.secret,bytearray(len(self.secret)))
    def test_backup_failure_stops_before_removal(self):
        def fail(*args):raise OSError('full')
        with self.assertRaises(OSError):self.execute(backup=fail)
        self.assertNotIn('remove',self.events)
    def test_backup_mismatch_stops_before_removal(self):
        with self.assertRaises(ValueError):self.execute(backup=lambda _:({},'fixture.img','a'*64))
        self.assertNotIn('remove',self.events)
    def test_changed_state_after_password_stops(self):
        calls=0
        def capture():
            nonlocal calls
            calls+=1
            return copy.deepcopy(self.state),dict(self.identity,rdev=1 if calls==1 else 2)
        with self.assertRaises(ValueError):self.execute(capture=capture)
        self.assertNotIn('remove',self.events)
    def test_unexpected_post_mutation_state_never_claims_success(self):
        def bad_remove(key):
            del self.state['tokens'][key];self.state['keyslots'].pop('0')
        with self.assertRaises(RuntimeError):self.execute(remove=bad_remove)
        self.assertEqual(self.events[-1],'verification_failed');self.assertNotIn('disabled',self.events)
    def test_command_failure_keeps_pending_receipt(self):
        def failed(key):raise RuntimeError('native failure')
        with self.assertRaises(RuntimeError):self.execute(remove=failed)
        self.assertEqual(self.events[-1],'removal_pending')
    def test_manual_slot_or_ambiguous_tokens_refused(self):
        variants=[]
        a=copy.deepcopy(self.metadata);a['keyslots'].pop('0');variants.append(a)
        a=copy.deepcopy(self.metadata);a['tokens']['3']=copy.deepcopy(a['tokens']['1']);variants.append(a)
        a=copy.deepcopy(self.metadata);a['tokens']['1']['keyslots']=['0'];variants.append(a)
        a=copy.deepcopy(self.metadata);a['tokens']={};variants.append(a)
        a=copy.deepcopy(self.metadata);a['tokens']['1']['keyslots']=['7'];variants.append(a)
        for value in variants:
            with self.assertRaises(ValueError):h.token_id(value)
    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):h.decode('{"operation":"review","operation":"disable"}')

if __name__=='__main__': unittest.main()
