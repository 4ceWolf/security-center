"""Root-only filesystem evidence checks inside the disposable guest."""
import json
import os
import pathlib
import sys
import time

if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')
sys.path.insert(0, '/policy')
from gate_record import read_record
from unlock_dispatch import unlock

folder = pathlib.Path('/run/gate-evidence')
folder.mkdir(mode=0o700)
path = folder/'decision.json'
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
record = dict(schema_version=1, boot_id=boot, policy_sha256='a'*64, mode='normal',
              sampled_boottime=time.clock_gettime(time.CLOCK_BOOTTIME),
              checker_complete=True, coverage_complete=True,
              decision=dict(allow_tpm_attempt=True, manual_recovery_required=False,
                            reason='Disposable fixture only'))

def write():
    record['sampled_boottime'] = time.clock_gettime(time.CLOCK_BOOTTIME)
    path.write_text(json.dumps(record))
    path.chmod(0o600)

def load():
    return read_record(str(folder), boot_id=boot, policy_sha256='a'*64, mode='normal',
                       now=time.clock_gettime(time.CLOCK_BOOTTIME), checker_ok=True)

def denied():
    calls = []
    result = unlock(load, lambda: calls.append('tpm'), lambda: True)
    assert calls == [] and result['method'] == 'manual'

write()
assert load()['allow_tpm_attempt'] is True  # No actual TPM invocation here.
for mode in (0o644, 0o660):
    path.chmod(mode)
    denied()
path.chmod(0o600)
folder.chmod(0o777)
denied()
folder.chmod(0o700)
path.unlink()
denied()
path.symlink_to('/key')
denied()
path.unlink()
write()
os.link(path, folder/'extra-link')
denied()
(folder/'extra-link').unlink()
path.write_bytes(b' '*8193)
denied()
path.unlink()
os.mkfifo(path, 0o600)
denied()  # Must not block opening a FIFO.
path.unlink()
write()
record['coverage_complete'] = False
record['decision'].update(allow_tpm_attempt=False, manual_recovery_required=True)
write()
assert load()['allow_tpm_attempt'] is False
print('VM_GATE_RECORD_FILESYSTEM_PASS', flush=True)
