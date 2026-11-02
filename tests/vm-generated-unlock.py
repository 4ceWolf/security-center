"""Narrow disposable-guest adapter, never a host entrypoint."""
import pathlib,sys,subprocess
if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')
sys.path.insert(0,'/policy')
from unlock_dispatch import unlock
calls=[]
def decision():
    assert pathlib.Path('/run/device-check-finished').read_text()=='done'
    # A successful scanner is still not approval of this guest's external USB.
    return {'allow_tpm_attempt':False,'manual_recovery_required':True}
def tpm():
    calls.append('tpm');return False
def manual():
    calls.append('manual')
    key='/key' if pathlib.Path('/run/generated-correct').exists() else '/wrong'
    return subprocess.run(['cryptsetup','open','--disable-external-tokens','--key-slot','0',
        '--key-file',key,'/dev/vda','generated_test'],timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
result=unlock(decision,tpm,manual)
pathlib.Path('/run/generated-attempts').write_text(','.join(calls))
raise SystemExit(0 if result['unlocked'] else 1)
