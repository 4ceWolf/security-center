"""Guest-only test of a real cryptsetup-generator unit with a gate drop-in."""
import os,pathlib,subprocess
if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')

def run(args,check=True,env=None):
    return subprocess.run(args,check=check,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)

# Minimal guest udev publishes real block device units to PID1.
pathlib.Path('/etc/udev/rules.d').mkdir(parents=True,exist_ok=True)
pathlib.Path('/etc/udev/rules.d/99-test-systemd.rules').write_text('SUBSYSTEM=="block", TAG+="systemd"\n')
if not pathlib.Path('/run/udev/control').exists():
    run(['/usr/lib/systemd/systemd-udevd','--daemon'])
run(['/usr/bin/udevadm','trigger','--subsystem-match=block'])
run(['/usr/bin/udevadm','settle','--timeout=10'])
base=pathlib.Path('/etc/systemd/system')
for name in ('/run/generator-early','/run/generator-late'):pathlib.Path(name).mkdir(exist_ok=True)
pathlib.Path('/run/test-crypttab').write_text('generated_test /dev/vda - noauto,tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no\n')
env=dict(os.environ,SYSTEMD_IN_INITRD='1',SYSTEMD_CRYPTTAB='/run/test-crypttab',SYSTEMD_PROC_CMDLINE='')
run(['/test-cryptsetup-generator',str(base),'/run/generator-early','/run/generator-late'],env=env)
unit=base/'systemd-cryptsetup@generated_test.service'
assert unit.is_file() and 'tpm2-device=' in unit.read_text()
drop=base/(unit.name+'.d');drop.mkdir()
(drop/'50-security-center-test.conf').write_text('''[Unit]
Wants=device-check.service
After=device-check.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /generated-unit-unlock.py
TimeoutStartSec=20
''')
run(['systemctl','daemon-reload'])
loaded=run(['systemctl','show',unit.name,'--property=ExecStart','--value']).stdout
assert b'/generated-unit-unlock.py' in loaded and b' attach ' not in loaded
for expected in (False,True):
    pathlib.Path('/run/generated-correct').unlink(missing_ok=True)
    if expected:pathlib.Path('/run/generated-correct').touch()
    result=run(['systemctl','start',unit.name],check=False)
    assert (result.returncode==0) is expected
    active=run(['cryptsetup','status','generated_test'],check=False).returncode==0
    assert active is expected
    assert pathlib.Path('/run/generated-attempts').read_text()=='manual'
    if expected:
        run(['systemctl','stop',unit.name])
        assert run(['cryptsetup','status','generated_test'],check=False).returncode!=0
    else:run(['systemctl','reset-failed',unit.name])
    print('VM_GENERATED_UNIT_'+('CORRECT' if expected else 'WRONG')+'_PASS',flush=True)
