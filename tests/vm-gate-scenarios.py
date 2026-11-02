"""Guest-only fixtures: never run on host. Uses only disposable /dev/vda."""
import sys
if 'security_center_test_vm=1' not in open('/proc/cmdline').read().split():
    raise SystemExit('Refusing outside explicitly marked disposable test guest')
sys.path.insert(0,'/policy')
import subprocess
import os
from handover import make_record,publish,consume
BOOT_ID=open("/proc/sys/kernel/random/boot_id").read().strip()
from device_gate import evaluate
from unlock_dispatch import unlock

base={'schema_version':1,'complete':True,'transports_checked':['usb','thunderbolt','pci-external'],'devices':[]}
policy={'schema_version':1,'internal':[],'trusted_external':[]}
unknown=dict(base,devices=[{'transport':'usb','vendor':'ffff','product':'ffff','serial':'test','port':'1-1','interfaces':['08:06:50']}])

def command(args):
    return subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15).returncode == 0

def scenario(label, loader, expected, wrong=False, missing_tpm=False):
    calls=[]
    def tpm():
        calls.append('tpm')
        device='/dev/absent-tpm' if missing_tpm else '/dev/tpmrm0'
        return command(['/usr/lib/systemd/systemd-cryptsetup','attach','gate_test','/dev/vda','-',f'tpm2-device={device},tpm2-signature=/test-signature.json,headless=yes,password-cache=no'])
    def manual():
        calls.append('manual')
        return command(['cryptsetup','open','--disable-external-tokens','--key-slot','0','--key-file','/wrong' if wrong else '/key','/dev/vda','gate_test'])
    result=unlock(loader,tpm,manual)
    assert calls == expected == result['attempts'], (label,result,calls)
    assert result['unlocked'] is (not wrong), (label,result)
    active=command(['cryptsetup','status','gate_test'])
    assert active is (not wrong), (label,active)
    directory='/run/handover-'+label
    os.mkdir(directory,0o700)
    publish(directory,make_record(BOOT_ID,result,'allow' if calls[0]=='tpm' else 'manual'))
    observation=consume(directory,BOOT_ID)
    assert observation['unlock']==result and observation['attested'] is False
    try:publish(directory,observation)
    except FileExistsError:pass
    else:raise AssertionError('Existing record was overwritten')
    try:consume(directory,'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    except ValueError:pass
    else:raise AssertionError('Old boot record was accepted')
    if active:assert command(['cryptsetup','close','gate_test'])
    print('VM_GATE_'+label+'_PASS',flush=True)

scenario('ALLOW',lambda:evaluate(base,policy),['tpm'])
scenario('UNKNOWN_DEVICE',lambda:evaluate(unknown,policy),['manual'])
scenario('INCOMPLETE_SCAN',lambda:evaluate(dict(base,complete=False),policy),['manual'])
def broken():raise RuntimeError('simulated scan failure')
scenario('SCAN_FAILURE',broken,['manual'])
scenario('DISTRESS',lambda:evaluate(base,policy,'distress'),['manual'])
scenario('WRONG_MANUAL',lambda:evaluate(unknown,policy),['manual'],wrong=True)
scenario('MISSING_TPM',lambda:evaluate(base,policy),['tpm','manual'],missing_tpm=True)

# Actual kernel sysfs enumeration of QEMU's attached USB mouse, not a fixture.
import time
from device_inventory import collect
for _ in range(30):
    observed=collect()
    if observed['usb_observation_complete'] and observed['devices']:break
    time.sleep(.1)
assert observed['usb_observation_complete'],observed
assert len(observed['devices'])==1,observed
mouse=observed['devices'][0]
assert mouse['transport']=='usb' and mouse['interfaces'],mouse
print('VM_USB_DISCOVERY_PASS',flush=True)
# Isolate USB rejection with synthetic coverage for the OTHER transports.
# This is not a claim that the real scanner covers all platform buses.
scenario('REAL_USB_UNKNOWN',lambda:evaluate(dict(base,devices=observed['devices']),policy),['manual'])
# Even approving that mouse cannot turn the actual partial observation green.
trusted={'schema_version':1,'internal':[],'trusted_external':[mouse]}
scenario('REAL_USB_PARTIAL',lambda:evaluate(observed,trusted),['manual'])

os.chmod('/run/handover-ALLOW/boot.json',0o644)
try:consume('/run/handover-ALLOW',BOOT_ID)
except ValueError:pass
else:raise AssertionError('Readable-by-others record accepted')
os.symlink('/run/handover-ALLOW','/run/handover-symlink')
try:consume('/run/handover-symlink',BOOT_ID)
except OSError:pass
else:raise AssertionError('Symlink directory accepted')
print('VM_HANDOVER_IO_PASS',flush=True)

if os.path.isdir('/run/systemd/system'):
    def systemd_decision():
        if not command(['systemctl','is-active','--quiet','device-check.service']):
            raise RuntimeError('Device-check service did not succeed')
        # A successful service is not sufficient: actual scan coverage must also pass.
        return evaluate(collect(),policy)
    scenario('SYSTEMD_SERVICE_EVIDENCE',systemd_decision,['manual'])
