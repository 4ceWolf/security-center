"""Configure the guarded native guest for stock TPM unlock plus passive observer."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path('/home/user/Projects/security-center')
MODES = ('success', 'absent', 'failed', 'timeout', 'memory', 'manual', 'masked')


def configure(root, init, copy, binary, mode):
    if (root.resolve() != root or root.name != 'root' or root.parent.parent != ROOT/'work'
            or not root.parent.name.startswith('luks-vm-') or mode not in MODES):
        raise ValueError('Disposable project guest required')
    target = '/usr/lib/security-center-observation/'
    sources = {'initramfs/boot_observation.py': 'boot_observation.py',
               'initramfs/boot_observer.py': 'boot_observer.py',
               'initramfs/observation_entry.py': 'entry.py',
               'initramfs/gate_observer.py': 'gate_observer.py',
               'initramfs/gate_record.py': 'gate_record.py',
               'policies/device_gate.py': 'device_gate.py',
               'policies/device_inventory.py': 'device_inventory.py',
               'policies/platform_inventory.py': 'platform_inventory.py'}
    hashes = {}
    for src, dst in sources.items():
        copy(ROOT/src, target+dst)
        hashes[src] = hashlib.sha256((ROOT/src).read_bytes()).hexdigest()
    config = root/'etc/security-center-observation'; config.mkdir()
    copy(ROOT/'policies/normal-devices.candidate.json', '/etc/security-center-observation/normal-devices.json')
    hashes['policy'] = hashlib.sha256((config/'normal-devices.json').read_bytes()).hexdigest()
    unit = (ROOT/'initramfs/units/security-center-observation.service').read_text()
    hashes['unit'] = hashlib.sha256(unit.encode()).hexdigest()
    manifest = json.dumps(hashes, sort_keys=True).encode()
    (root.parent/'observer-source-manifest.json').write_bytes(manifest)
    (config/'source.sha256').write_text(hashlib.sha256(manifest).hexdigest()+'\n')
    units = root/'etc/systemd/system'
    # Full Arch initrds activate udev independently of our optional observer.
    udev = units/'initrd.target.d'; udev.mkdir(exist_ok=True)
    (udev/'50-stock-udev.conf').write_text('[Unit]\nWants=systemd-udev-trigger.service\nAfter=systemd-udev-trigger.service\n')
    if mode == 'failed':
        binary('/usr/bin/false')
        unit = unit.replace('/usr/bin/python3 -I /usr/lib/security-center-observation/entry.py', '/usr/bin/false')
    elif mode == 'timeout':
        unit = unit.replace('/usr/bin/python3 -I /usr/lib/security-center-observation/entry.py', '/usr/bin/sleep 30')
    elif mode == 'memory':
        memory = root/'memory-observer.py'
        memory.write_text('x=bytearray(256*1024*1024)\n')
        unit = unit.replace('/usr/bin/python3 -I /usr/lib/security-center-observation/entry.py', '/usr/bin/python3 -I /memory-observer.py')
        # Avoid guest-wide OOM: the fixture keeps the same per-service 64MiB cap.
    if mode == 'masked':
        (units/'security-center-observation.service').symlink_to('/dev/null')
    elif mode != 'absent':
        (units/'security-center-observation.service').write_text(unit)
    old = units/'systemd-cryptsetup@cold_root.service.d/50-test-gate.conf'
    old.unlink()
    old.with_name('50-observation.conf').write_text('[Unit]\nWants=security-center-observation.service\nAfter=security-center-observation.service\n')
    # The obsolete gate fixture is unreferenced and removed to keep the snapshot clear.
    (units/'gate-observer.service').unlink()
    copy(ROOT/'tests/vm-boot-observation-files.py', '/usr/lib/security-center-observation/file-tests.py')
    (root/'cold-post.py').write_text('''import os,pathlib,subprocess,sys,traceback,time
sys.path.insert(0,'/usr/lib/security-center-observation')
from boot_observation import consume
try:
 assert os.path.realpath('/proc/1/exe')=='/usr/lib/systemd/systemd'
 rows=[r.split() for r in pathlib.Path('/proc/mounts').read_text().splitlines() if r.split()[1]=='/']
 assert any(r[2]=='ext4' and os.stat(r[0]).st_rdev==os.stat('/dev/mapper/cold_root').st_rdev for r in rows)
 path=os.path.realpath('/dev/mapper/cold_root')
 assert pathlib.Path('/sys/class/block/'+os.path.basename(path)+'/slaves/vda').exists()
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 mode=pathlib.Path('/stock-mode').read_text()
 if mode in ('success','manual'):
  record=consume(boot)
  assert record['unlock_method']=='unknown' and record['enforcement']=='not_enabled'
  assert record['attested'] is False and record['coverage_complete'] is False
  subprocess.run(['/usr/bin/python3','/usr/lib/security-center-observation/file-tests.py'],check=True,timeout=3)
  print('\\nVM_STOCK_RECORD_RETAINED',flush=True)
 else:
  assert not pathlib.Path('/run/security-center-observation/boot.json').exists()
  print('\\nVM_STOCK_RECORD_ABSENT',flush=True)
 # Observer cannot run after switch-root or manufacture new preboot history.
 retry=subprocess.run(['/usr/bin/python3','-I','/usr/lib/security-center-observation/entry.py'],capture_output=True,timeout=3)
 assert retry.returncode!=0
 print('\\nVM_STOCK_POSTBOOT_REFUSED\\nVM_STOCK_POSTROOT\\nVM_TEST_PASS',flush=True)
except BaseException:
 traceback.print_exc();print('\\nVM_TEST_FAIL',flush=True)
finally:
 os.sync();pathlib.Path('/proc/sysrq-trigger').write_text('o')
''')
    (root/'stock-mode').write_text(mode)
    init = init.replace('cp /cold-post.py /prepared/', 'cp /cold-post.py /stock-mode /prepared/')
    # Assert the generated and effective command, observer outcome and cgroup peak
    # before initrd cleanup discards the manager state; a bounded verifier service
    # runs after root mapping activation and before the native switch-root service.
    copy(ROOT/'tests/vm-stock-observation-check.py', '/stock-check.py')
    (units/'stock-check.service').write_text('''[Unit]
DefaultDependencies=no
Requires=systemd-cryptsetup@cold_root.service
After=systemd-cryptsetup@cold_root.service
Before=initrd-cleanup.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /stock-check.py
RemainAfterExit=yes
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TimeoutStartSec=5
''')
    drop = units/'initrd-cleanup.service.d'; drop.mkdir(exist_ok=True)
    (drop/'50-stock-check.conf').write_text('[Unit]\nRequires=stock-check.service\nAfter=stock-check.service\n')
    if mode == 'manual':
        for name in ('systemd-ask-password-console.path', 'systemd-ask-password-console.service'):
            copy('/usr/lib/systemd/system/'+name)
        binary('/usr/bin/systemd-tty-ask-password-agent')
        binary('/usr/lib/libseccomp.so.2')
        trigger = units/'initrd.target.d/50-stock-udev.conf'
        trigger.write_text(trigger.read_text()+'Wants=systemd-ask-password-console.path\n')
        # Confirm actual TPM rejection before allowing stock manual recovery; do
        # not infer a manual unlock merely from the existence of a passphrase slot.
        broken = '''
tpm2_pcrextend 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if /usr/lib/systemd/systemd-cryptsetup attach must_fail /dev/vda - 'tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no'; then fail; fi
if cryptsetup status must_fail; then fail; fi
echo VM_STOCK_TPM_FAILURE_CONFIRMED
'''
        init = init.replace('echo VM_COLD_PREPARED', broken+'echo VM_COLD_PREPARED')
    return init
