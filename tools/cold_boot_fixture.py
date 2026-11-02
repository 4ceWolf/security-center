"""Build the disposable guest's fresh-manager initrd scenario, never host boot."""
import pathlib

UUID = '11111111-2222-3333-4444-555555555555'


def build(root, loads, binary, copy, signed_setup, mode, input_case="correct"):
    expected=pathlib.Path('/home/user/Projects/security-center/work')
    if (root.name!='root' or root.parent.parent!=expected
            or not root.parent.name.startswith('luks-vm-') or root.resolve()!=root):
        raise ValueError('Disposable project guest directory required')
    if input_case not in ('correct','wrong','cancel','timeout','exhaust'):
        raise ValueError('Unsupported guest input case')
    if mode not in ('observe','failed','timeout'):
        raise ValueError('Unsupported guest checker mode')
    unit_source = pathlib.Path('/usr/lib/systemd/system')
    # Native targets plus the services/sockets needed for this initrd root path.
    for path in unit_source.glob('*.target'):
        if path.is_file():
            copy(path)
    for name in ('initrd-parse-etc.service', 'initrd-cleanup.service',
                 'initrd-switch-root.service', 'initrd-udevadm-cleanup-db.service',
                 'systemd-udevd.service', 'systemd-udevd-kernel.socket',
                 'systemd-udevd-varlink.socket', 'systemd-udev-trigger.service',
                 'systemd-udev-settle.service'):
        copy(unit_source/name)
    for name in ('systemd-cryptsetup-generator','systemd-fstab-generator'):
        binary('/usr/lib/systemd/system-generators/'+name)
    binary('/usr/lib/systemd/systemd-sysroot-fstab-check')
    binary('/usr/bin/umount')
    units = root/'etc/systemd/system'
    (units/'default.target').unlink(missing_ok=True)
    (units/'default.target').symlink_to('/usr/lib/systemd/system/initrd.target')
    (root/'etc/initrd-release').write_text('ID=security-center-test\n')
    (root/'etc/udev/rules.d').mkdir(parents=True,exist_ok=True)
    (root/'etc/udev/rules.d/99-test-systemd.rules').write_text('SUBSYSTEM=="block", TAG+="systemd"\n')
    observer_exec = '/usr/bin/python3 /policy/gate_observer.py' if mode=='observe' else '/usr/bin/sleep 30' if mode=='timeout' else '/usr/bin/false'
    if mode=='failed':
        binary('/usr/bin/false')
    (units/'gate-observer.service').write_text('''[Unit]
DefaultDependencies=no
Wants=systemd-udev-trigger.service
After=systemd-udev-trigger.service
[Service]
Type=oneshot
RuntimeDirectory=security-center-gate
RuntimeDirectoryMode=0700
RemainAfterExit=yes
TimeoutStartSec=5
TimeoutStopSec=1
KillMode=control-group
ExecStart='''+observer_exec+'\n')
    drop=units/'systemd-cryptsetup@cold_root.service.d'
    drop.mkdir()
    (drop/'50-test-gate.conf').write_text('''[Unit]
Wants=gate-observer.service
After=gate-observer.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /cold-unlock.py
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TTYReset=yes
TimeoutStartSec=45
''')
    (root/'cold-mode').write_text(mode)
    (root/'cold-input').write_text(input_case)
    copy(expected.parent/'tests/vm-cold-unlock.py','/cold-unlock.py')
    (root/'cold-post.py').write_text('''import os,pathlib,sys,traceback
sys.path.insert(0,'/policy')
try:
 from handover import consume
 assert os.path.realpath('/proc/1/exe')=='/usr/lib/systemd/systemd'
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 record=consume('/run/cold-handover',boot)
 assert record['unlock']['method']=='manual' and record['attested'] is False
 rows=[r.split() for r in pathlib.Path('/proc/mounts').read_text().splitlines() if r.split()[1]=='/']
 assert any(r[2]=='ext4' and os.stat(r[0]).st_rdev==os.stat('/dev/mapper/cold_root').st_rdev for r in rows)
 print('\\nVM_COLD_POSTROOT\\nVM_TEST_PASS',flush=True)
except BaseException:
 traceback.print_exc()
 print('\\nVM_TEST_FAIL',flush=True)
finally:
 os.sync()
 pathlib.Path('/proc/sysrq-trigger').write_text('o')
''')
    # Fixture provisioning is explicit and happens before the first real manager.
    # The prepared mapping is closed before any gate/unlock test begins.
    init='''#!/bin/sh
export PATH=/usr/bin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
fail() { echo VM_TEST_FAIL; sync; echo o > /proc/sysrq-trigger; }
trap fail ERR
set -E -e
'''+loads+'''
for i in {1..30}; do test -b /dev/vda && break; sleep 1; done
cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --uuid '''+UUID+''' --key-file /key /dev/vda
cryptsetup open --disable-external-tokens --key-slot 0 --key-file /key /dev/vda prepare_root
mkfs.ext4 -q /dev/mapper/prepare_root
mkdir /prepared
mount /dev/mapper/prepare_root /prepared
for tree in /usr /bin /lib /lib64 /etc /policy; do
 if test -e "$tree"; then cp -a "$tree" /prepared/; fi
done
cp /cold-post.py /prepared/
python3 /prepare-final-root.py
sync
umount /prepared
cryptsetup close prepare_root
'''+signed_setup+'''
systemd-cryptenroll --unlock-key-file=/key --tpm2-device=/dev/tpmrm0 --tpm2-pcrs=7 --tpm2-public-key=/test-pcr-public.pem --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=initrd --tpm2-signature=/test-signature.json /dev/vda
echo VM_COLD_PREPARED
exec /usr/lib/systemd/systemd --system --show-status=yes --log-target=console --log-level=debug
'''
    (root/'prepare-final-root.py').write_text('''import pathlib
base=pathlib.Path('/prepared')
(base/'etc/initrd-release').unlink()
(base/'etc/fstab').write_text('')
units=base/'etc/systemd/system'
(units/'default.target').unlink()
(units/'default.target').write_text('[Unit]\\nDefaultDependencies=no\\nWants=cold-post.service\\nAfter=cold-post.service\\n')
(units/'cold-post.service').write_text('[Unit]\\nDefaultDependencies=no\\n[Service]\\nType=oneshot\\nExecStart=/usr/bin/python3 /cold-post.py\\nStandardOutput=tty\\nStandardError=tty\\nTTYPath=/dev/console\\n')
for name in ('proc','sys','dev','run','tmp'):(base/name).mkdir(exist_ok=True)
''')
    return init
