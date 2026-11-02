"""Guest-only generated systemd unit plus real interactive LUKS recovery."""
import os
import pathlib
import select
import subprocess
import termios
import time
import sys
sys.path.insert(0, '/policy')

if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')


def run(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=20)


# Reuse the real generator/udev setup and its wrong/correct keyfile assertions.
subprocess.run(['/usr/bin/python3', '/generated-unit.py'], check=True, timeout=50)
unit = 'systemd-cryptsetup@generated_test.service'
# Replace the guest-only keyfile adapter with a terminal-owning adapter. The
# generated service and its checker ordering remain loaded by actual PID1.
pathlib.Path('/generated-unit-unlock.py').write_text('''import os,sys,fcntl,subprocess,pathlib,termios,time,hashlib
sys.path.insert(0,'/policy')
from unlock_dispatch import unlock
from gate_record import read_record
calls=[]
def decision():
 assert pathlib.Path('/run/device-check-finished').read_text()=='done'
 if subprocess.run(['systemctl','is-active','--quiet','device-check.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3).returncode!=0:
  raise ValueError('Device checker failed')
 return read_record('/run/security-center-gate',
  boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
  policy_sha256=hashlib.sha256(pathlib.Path('/policy/normal-devices.json').read_bytes()).hexdigest(),mode='normal',now=time.clock_gettime(time.CLOCK_BOOTTIME),
  checker_ok=subprocess.run(['systemctl','is-active','--quiet','gate-observer.service'],
   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3).returncode==0)
def tpm():
 calls.append('tpm');return False
def manual():
 calls.append('manual')
 def console():
  os.setsid()
  fd=os.open(pathlib.Path('/run/recovery-console').read_text(),os.O_RDWR)
  fcntl.ioctl(fd,termios.TIOCSCTTY,0)
  for target in (0,1,2):os.dup2(fd,target)
  if fd>2:os.close(fd)
 return subprocess.run(['/usr/bin/cryptsetup','open','--disable-external-tokens',
  '--key-slot','0','--tries','1','--timeout','2',
  pathlib.Path('/run/generated-source').read_text() if pathlib.Path('/run/generated-source').exists() else '/dev/vda','generated_test'],
  preexec_fn=console,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=10).returncode==0
result=unlock(decision,tpm,manual)
pathlib.Path('/run/generated-attempts').write_text(','.join(calls))
raise SystemExit(0 if result['unlocked'] else 1)
''')
secret = b'DISPOSABLE-VM-ONLY-NOT-A-LAPTOP-PASSWORD'
if not any(row.split()[1] == '/dev/pts' for row in pathlib.Path('/proc/mounts').read_text().splitlines()):
    pathlib.Path('/dev/pts').mkdir(exist_ok=True)
    run(['mount', '-t', 'devpts', 'devpts', '/dev/pts'])



def automatic_source(label):
    uuid = run(['cryptsetup', 'luksUUID', '/dev/vda']).stdout.decode().strip()
    source = '/dev/disk/by-uuid/'+uuid
    run(['udevadm', 'trigger', '--subsystem-match=block'])
    run(['udevadm', 'settle', '--timeout=10'])
    assert pathlib.Path(source).resolve(strict=True) == pathlib.Path('/dev/vda')
    pathlib.Path('/run/generated-source').write_text(source)
    base = pathlib.Path('/etc/systemd/system')
    (base/'cryptsetup.target').write_text('[Unit]\nDefaultDependencies=no\n')
    crypttab = pathlib.Path('/run/test-crypttab')
    opts = 'tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no'
    cmdline = ''
    if label == 'AUTO_CRYPTTAB':
        crypttab.write_text('generated_test UUID='+uuid+' - '+opts+'\n')
    else:
        crypttab.write_text('')
        cmdline = 'rd.luks.name='+uuid+'=generated_test rd.luks.options='+uuid+'='+opts
    env = dict(os.environ, SYSTEMD_IN_INITRD='1', SYSTEMD_CRYPTTAB=str(crypttab),
               SYSTEMD_PROC_CMDLINE=cmdline)
    (base/unit).unlink()  # Each fixture generation starts without its previous unit.
    subprocess.run(['/test-cryptsetup-generator', str(base), '/run/generator-early',
                    '/run/generator-late'], env=env, check=True, timeout=15)
    text = (base/unit).read_text()
    from unlock_candidate_audit import audit
    checked=audit({p.name:dict(fragment=p.read_text(),dropins=[dict(name=d.name,text=d.read_text())
      for d in sorted((base/(p.name+'.d')).glob('*.conf'))])
      for p in base.glob('systemd-cryptsetup@*.service')},unit,'generated_test',
      {source},opts,['/usr/bin/python3','/generated-unit-unlock.py'])
    assert checked['accepted'] is True, checked
    assert source in text and 'noauto' not in text
    # Require a real generated dependency from cryptsetup.target, not an explicit
    # start of the mapping unit or a hand-written target relationship.
    deps = list((base/'cryptsetup.target.requires').glob('*'))
    assert any(p.name == unit or 'generated_test' in p.name for p in deps), deps
    run(['systemctl', 'daemon-reload'])
    effective = run(['systemctl', 'show', unit, '--property=ExecStart', '--value']).stdout
    assert b'/generated-unit-unlock.py' in effective and b' attach ' not in effective


for label, answer, expected in (
    ('WRONG', b'WRONG-DISPOSABLE-INPUT\n', False),
    ('CANCEL', b'\x03', False),
    ('TIMEOUT', None, False),
    ('CORRECT', secret+b'\n', True),
    ('AUTO_CRYPTTAB', secret+b'\n', True),
    ('AUTO_CMDLINE', secret+b'\n', True),
):
    if label.startswith('AUTO_'):
        automatic_source(label)
    state = run(['systemctl', 'show', unit, '--property=ActiveState', '--value']).stdout.strip()
    if state == b'failed':
        run(['systemctl', 'reset-failed', unit])
    master, slave = os.openpty()
    pathlib.Path('/run/recovery-console').write_text(os.ttyname(slave))
    start_target = 'cryptsetup.target' if label.startswith('AUTO_') else unit
    proc = subprocess.Popen(['systemctl', 'start', start_target], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    output = bytearray()
    prompted = False
    try:
        deadline = time.monotonic()+18
        while proc.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], .05)
            if ready:
                output.extend(os.read(master, 4096))
                assert len(output) <= 16384, 'Terminal output exceeded bound'
                if not prompted and b'Enter passphrase' in output:
                    assert not termios.tcgetattr(slave)[3] & termios.ECHO
                    prompted = True
                    if answer is not None:
                        os.write(master, answer)
        assert proc.poll() is not None, 'Generated service exceeded recovery deadline'
        # Drain bytes left after the service exited before checking for leaks.
        while select.select([master], [], [], 0)[0]:
            chunk = os.read(master, 4096)
            if not chunk:
                break
            output.extend(chunk)
            assert len(output) <= 16384
        assert prompted, 'Generated unit never requested manual input'
        assert secret not in output, 'Secret echoed'
        assert (proc.returncode == 0) is expected
        active = subprocess.run(['cryptsetup', 'status', 'generated_test'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10).returncode == 0
        assert active is expected
        assert pathlib.Path('/run/generated-attempts').read_text() == 'manual'
        logs = run(['journalctl', '-u', unit, '--no-pager']).stdout
        assert secret not in logs, 'Secret leaked to journal'
        keep_root = label == 'AUTO_CMDLINE' and pathlib.Path('/keep-generated-root').exists()
        if active and not keep_root:
            if label.startswith('AUTO_'):
                run(['systemctl', 'stop', 'cryptsetup.target'])
            run(['systemctl', 'stop', unit])
            assert subprocess.run(['cryptsetup', 'status', 'generated_test'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=10).returncode != 0
        print('VM_INTEGRATED_RECOVERY_'+label+'_PASS', flush=True)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
            subprocess.run(['systemctl', 'stop', unit], timeout=20, check=False)
        os.close(master)
        os.close(slave)
