"""Reproduce a second generated-service bypass in a disposable guest only."""
import os
import pathlib
import subprocess
import sys
sys.path.insert(0, '/policy')
from unlock_candidate_audit import audit
if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')


def run(args, check=True, env=None):
    return subprocess.run(args, check=check, env=env, capture_output=True, timeout=20)


# Set up real udev before generating two names for one actual guest LUKS UUID.
# This runs before PCR7 is deliberately invalidated by later test scenarios.
pathlib.Path('/etc/udev/rules.d').mkdir(parents=True, exist_ok=True)
pathlib.Path('/etc/udev/rules.d/99-test-systemd.rules').write_text('SUBSYSTEM=="block", TAG+="systemd"\n')
run(['/usr/lib/systemd/systemd-udevd', '--daemon'])
run(['udevadm', 'trigger', '--subsystem-match=block'])
run(['udevadm', 'settle', '--timeout=10'])
uuid = run(['cryptsetup', 'luksUUID', '/dev/vda']).stdout.decode().strip()
source = '/dev/disk/by-uuid/'+uuid
assert pathlib.Path(source).resolve(strict=True) == pathlib.Path('/dev/vda')
base = pathlib.Path('/etc/systemd/system')
crypttab = pathlib.Path('/run/duplicate-crypttab')
opts = 'noauto,tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no'
crypttab.write_text(''.join(name+' UUID='+uuid+' - '+opts+'\n'
                           for name in ('gated_fixture', 'bypass_fixture')))
for folder in ('/run/duplicate-early', '/run/duplicate-late'):
    pathlib.Path(folder).mkdir()
env = dict(os.environ, SYSTEMD_IN_INITRD='1', SYSTEMD_CRYPTTAB=str(crypttab), SYSTEMD_PROC_CMDLINE='')
run(['/test-cryptsetup-generator', str(base), '/run/duplicate-early', '/run/duplicate-late'], env=env)
units = sorted(p for p in base.glob('systemd-cryptsetup@*.service') if source in p.read_text())
assert {p.name for p in units} == {'systemd-cryptsetup@gated_fixture.service',
                                    'systemd-cryptsetup@bypass_fixture.service'}
# Exact generated-root-unit allowlist: this two-path candidate MUST be refused.
expected = {'systemd-cryptsetup@gated_fixture.service'}
rejected = audit({p.name:dict(fragment=p.read_text(),dropins=[]) for p in units},
 'systemd-cryptsetup@gated_fixture.service','gated_fixture',{source},opts,
 ['/usr/bin/python3','/deny-fixture.py'])
assert rejected['accepted'] is False, 'Candidate auditor missed duplicate root path'
pathlib.Path('/deny-fixture.py').write_text('''import pathlib,sys
sys.path.insert(0,'/policy')
from unlock_dispatch import unlock
calls=[]
def tpm():
 calls.append('tpm');return True
def manual():
 calls.append('manual');return False
result=unlock(lambda:{'allow_tpm_attempt':False,'manual_recovery_required':True},tpm,manual)
assert calls==['manual'] and result['unlocked'] is False
pathlib.Path('/run/denied-fixture').write_text('manual-only; no TPM attempt')
raise SystemExit(1)
''')
drop = base/'systemd-cryptsetup@gated_fixture.service.d'
drop.mkdir()
(drop/'50-test-gate.conf').write_text('''[Unit]
Wants=device-check.service
After=device-check.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /deny-fixture.py
''')
accepted=audit({'systemd-cryptsetup@gated_fixture.service':dict(
 fragment=(base/'systemd-cryptsetup@gated_fixture.service').read_text(),
 dropins=[dict(name='50-test-gate.conf',text=(drop/'50-test-gate.conf').read_text())])},
 'systemd-cryptsetup@gated_fixture.service','gated_fixture',{source},opts,
 ['/usr/bin/python3','/deny-fixture.py'])
assert accepted['accepted'] is True, accepted
run(['systemctl', 'daemon-reload'])
gated = run(['systemctl', 'show', 'systemd-cryptsetup@gated_fixture.service', '--property=ExecStart', '--value']).stdout
bypass = run(['systemctl', 'show', 'systemd-cryptsetup@bypass_fixture.service', '--property=ExecStart', '--value']).stdout
assert b'/deny-fixture.py' in gated and b' attach ' not in gated
assert b' attach bypass_fixture ' in bypass and source.encode() in bypass
assert run(['systemctl', 'start', 'systemd-cryptsetup@gated_fixture.service'], check=False).returncode != 0
assert pathlib.Path('/run/denied-fixture').read_text() == 'manual-only; no TPM attempt'
assert run(['cryptsetup', 'status', 'gated_fixture'], check=False).returncode != 0
# Prove the ungated generated service can actually unseal the disposable disk.
# Its '-' key argument, headless mode, explicit TPM and no cache exclude the
# manual fixture keyfile; the test supplies no terminal input here.
try:
    run(['systemctl', 'start', 'systemd-cryptsetup@bypass_fixture.service'])
    status = run(['cryptsetup', 'status', 'bypass_fixture']).stdout
    assert b'/dev/vda' in status
    print('VM_ALTERNATE_UNLOCK_BYPASS_REPRODUCED', flush=True)
finally:
    run(['systemctl', 'stop', 'systemd-cryptsetup@bypass_fixture.service'])
assert run(['cryptsetup', 'status', 'bypass_fixture'], check=False).returncode != 0
# Remove only these isolated generated fixtures; no production paths are involved.
for unit in units:
    unit.unlink()
(drop/'50-test-gate.conf').unlink()
drop.rmdir()
run(['systemctl', 'daemon-reload'])
print('VM_ALTERNATE_UNLOCK_CANDIDATE_REJECTED', flush=True)
