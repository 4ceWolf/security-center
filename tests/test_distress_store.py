import os,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
from distress import State,transition,permits_tpm
from distress_store import Store,encode,digest,decode

class TestWitness:
    """Test-only memory witness. This provides NO real TPM/rollback security."""
    def __init__(self):self.value=None;self.fail=False
    def read(self):return self.value
    def compare_exchange(self,old,new):
        if self.fail:raise OSError('Simulated witness failure')
        if self.value!=old:raise ValueError('Witness changed')
        self.value=new

class DistressStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.witness=TestWitness();self.store=Store(self.tmp.name,self.witness)
        self.normal=State('NORMAL','boot-a','a'*64)
        self.initial=self.store.commit(self.normal,None)
        self.strict=transition(self.normal,'trigger',boot_id='boot-a',policy_digest='a'*64)
    def test_commit_survives_store_reopen(self):
        value=self.store.commit(self.strict,self.initial)
        reopened=Store(self.tmp.name,self.witness)
        self.assertEqual(reopened.verified(),self.strict)
        self.assertEqual(value,digest(encode(self.strict)))
        self.assertFalse(permits_tpm(reopened.verified()))
        self.assertEqual(self.store.path.stat().st_mode&0o777,0o600)
    def test_crash_at_each_commit_boundary(self):
        for point in ('temporary_synced','state_synced','witness_committed'):
            with self.subTest(point=point),tempfile.TemporaryDirectory() as folder:
                witness=TestWitness();store=Store(folder,witness);prior=store.commit(self.normal,None)
                def crash(at):
                    if at==point:raise RuntimeError('Simulated power loss')
                with self.assertRaises(RuntimeError):store.commit(self.strict,prior,crash)
                if point=='temporary_synced':self.assertEqual(store.verified(),self.normal)
                elif point=='state_synced':
                    with self.assertRaises(ValueError):store.verified()
                else:self.assertEqual(store.verified(),self.strict)
    def test_process_exit_during_commit(self):
        # File witness is a durable fixture, NOT an antirollback implementation.
        class FileWitness(TestWitness):
            def __init__(self,path):self.path=path
            def read(self):return self.path.read_text() if self.path.exists() else None
            def compare_exchange(self,old,new):
                if self.read()!=old:raise ValueError('Witness changed')
                with self.path.open('w') as out:
                    out.write(new);out.flush();os.fsync(out.fileno())
        for point in ('temporary_synced','state_synced','witness_committed'):
            with self.subTest(point=point),tempfile.TemporaryDirectory() as folder:
                root=pathlib.Path(folder);data=root/'state';data.mkdir()
                store=Store(data,FileWitness(root/'fake-witness'))
                prior=store.commit(self.normal,None)
                pid=os.fork()
                if pid==0:
                    def die(at):
                        if at==point:os._exit(77)
                    try:store.commit(self.strict,prior,die)
                    except BaseException:os._exit(78)
                    os._exit(79)
                _,status=os.waitpid(pid,0)
                self.assertEqual(os.waitstatus_to_exitcode(status),77)
                reopened=Store(data,FileWitness(root/'fake-witness'))
                if point=='temporary_synced':self.assertEqual(reopened.verified(),self.normal)
                elif point=='state_synced':
                    with self.assertRaises(ValueError):reopened.verified()
                else:self.assertEqual(reopened.verified(),self.strict)
    def test_witness_failure_cannot_acknowledge_or_restore_normal(self):
        self.witness.fail=True
        with self.assertRaises(OSError):self.store.commit(self.strict,self.initial)
        with self.assertRaises(ValueError):self.store.verified()
        with self.assertRaises(ValueError):self.store.commit(self.normal,None)
    def test_replayed_normal_file_rejected(self):
        old=self.store.path.read_bytes();self.store.commit(self.strict,self.initial)
        self.store.path.write_bytes(old)
        with self.assertRaises(ValueError):self.store.verified()
    def test_old_witness_against_new_file_rejected(self):
        self.store.commit(self.strict,self.initial);self.witness.value=self.initial
        with self.assertRaises(ValueError):self.store.verified()
    def test_stale_writer_and_policy_changes_rejected(self):
        self.store.commit(self.strict,self.initial)
        with self.assertRaises(ValueError):self.store.commit(self.strict,self.initial)
        changed=State('NORMAL','boot-b','b'*64,2)
        with self.assertRaises(ValueError):self.store.commit(changed,self.witness.value)
    def test_corrupt_missing_symlink_and_unsafe_files_rejected(self):
        self.store.path.write_bytes(b'{}')
        with self.assertRaises((ValueError,TypeError)):self.store.verified()
        self.store.path.unlink()
        with self.assertRaises(OSError):self.store.verified()
        self.store.path.symlink_to('/dev/null')
        with self.assertRaises(OSError):self.store.verified()
    def test_full_cycle_uses_reducer_and_never_resets_original_policy(self):
        state=self.normal;expected=self.initial
        steps=[('trigger','boot-a',{}),('shutdown_prepared','boot-a',{}),
         ('boot_observed','boot-b',{}),('owner_recovered','boot-b',{'manual_unlock':True,'owner_authenticated':True,'power_only':True}),
         ('normal_reboot_requested','boot-b',{'owner_authenticated':True}),
         ('boot_observed','boot-c',{'restoration_verified':True})]
        for index,(event,boot,evidence) in enumerate(steps):
            state=transition(state,event,boot_id=boot,policy_digest='a'*64,**evidence)
            expected=self.store.commit(state,expected)
            self.assertEqual(self.store.verified(),state)
            self.assertEqual(permits_tpm(state),index==len(steps)-1)
    def test_duplicate_fields_and_noncanonical_records_rejected(self):
        for raw in (b'{"schema_version":1,"schema_version":1,"state":{}}',encode(self.normal)+b' ',b'x'*4097):
            with self.assertRaises(ValueError):decode(raw)

if __name__=='__main__':unittest.main()
