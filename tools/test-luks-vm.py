#!/usr/bin/python3
"""Disposable offline guest only. Never gives QEMU a host block device or TPM."""
import argparse, gzip, json, os, pathlib, re, shutil, stat, subprocess, tempfile, time, hashlib, fcntl
from initrd_manifest import inspect_newc
parser=argparse.ArgumentParser();parser.add_argument("--tpm",action="store_true");parser.add_argument("--signed-pcr",action="store_true");parser.add_argument("--gate",action="store_true");parser.add_argument("--switch-root",action="store_true");parser.add_argument("--systemd-gate",choices=("success","failure"));parser.add_argument("--integrated-recovery",action="store_true");parser.add_argument("--cold-boot",choices=("observe","failed","timeout"));parser.add_argument("--cold-input",choices=("correct","wrong","cancel","timeout","exhaust"),default="correct");parser.add_argument("--stock-observation",choices=("success","absent","failed","timeout","memory","manual","masked"));parser.add_argument("--arch-base");options=parser.parse_args()
if options.arch_base and options.stock_observation=="absent":parser.error("Arch base already contains the unit; use masked for unavailable-unit testing")
if options.arch_base and not options.stock_observation:parser.error("--arch-base requires --stock-observation")
if options.stock_observation:options.cold_boot="observe"
if options.stock_observation and options.cold_input!='correct':parser.error('Stock observer input cases use their own credential driver')
if options.cold_input!="correct" and not options.cold_boot:parser.error("--cold-input requires --cold-boot")
if options.cold_boot:
    options.systemd_gate="success";options.switch_root=True
if options.integrated_recovery and not options.systemd_gate:parser.error("--integrated-recovery requires --systemd-gate")
if options.systemd_gate:
    options.gate=True
if options.switch_root:options.gate=True
if options.gate:options.signed_pcr=True
if options.signed_pcr:options.tpm=True
ROOT=pathlib.Path('/home/user/Projects/security-center/work')
ROOT.mkdir(exist_ok=True)
work=pathlib.Path(tempfile.mkdtemp(prefix='luks-vm-',dir=ROOT))
root=work/'root';root.mkdir()
kernel=os.uname().release

def copy(src,dst=None):
    target=root/str(dst or src).lstrip('/')
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(src,target)
    target.chmod(pathlib.Path(src).stat().st_mode & 0o777)

def binary(src,dst=None):
    copy(src,dst)
    text=subprocess.check_output(['ldd',src],text=True)
    for path in set(re.findall(r'(/[\w/+.\-]+)',text)):
        if pathlib.Path(path).is_file():copy(path)

for name in ('bash','mount','mkdir','sleep','insmod','cryptsetup','sync','cp','switch_root','mkfs.ext4'):
    binary('/usr/bin/'+name)
if options.tpm:
    binary('/usr/bin/systemd-cryptenroll')
    if options.signed_pcr:
        binary('/usr/bin/openssl')
        binary('/usr/lib/systemd/systemd-measure')
    binary('/usr/lib/systemd/systemd-cryptsetup')
    binary('/usr/bin/tpm2_pcrextend')
    binary('/usr/bin/tpm2_pcrread')
    for name in ('libtss2-esys.so.0','libtss2-rc.so.0','libtss2-mu.so.0','libtss2-tcti-device.so.0'):
        binary('/usr/lib/'+name)
    binary('/usr/lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so')
if options.gate:
    import sysconfig
    binary('/usr/bin/python3')
    library=pathlib.Path(sysconfig.get_path('stdlib'))
    for path in library.glob('*.py'):copy(path)
    for name in ('encodings','json','re','collections','importlib','pathlib','logging'):
        for path in (library/name).rglob('*.py'):copy(path)
    for name in ('_posixsubprocess','select','math','_opcode','_struct','_typing','_json','fcntl','termios','_hashlib','_sha2','_blake2','_md5','_sha1','_sha3'):
        for path in (library/'lib-dynload').glob(name+'.*.so'):binary(str(path))
    project=ROOT.parent
    copy(project/'policies/device_gate.py','/policy/device_gate.py')
    copy(project/'policies/device_inventory.py','/policy/device_inventory.py')
    copy(project/'initramfs/unlock_dispatch.py','/policy/unlock_dispatch.py')
    copy(project/'initramfs/manual_recovery.py','/policy/manual_recovery.py')
    copy(project/'initramfs/gate_record.py','/policy/gate_record.py')
    copy(project/'initramfs/gate_observer.py','/policy/gate_observer.py')
    copy(project/'initramfs/unlock_candidate_audit.py','/policy/unlock_candidate_audit.py')
    copy(project/'policies/platform_inventory.py','/policy/platform_inventory.py')
    copy(project/'policies/normal-devices.candidate.json','/policy/normal-devices.json')
    copy(project/'initramfs/handover.py','/policy/handover.py')
    copy(project/'tests/vm-gate-scenarios.py','/gate-scenarios.py')
    copy(project/'tests/vm-interactive-recovery.py','/interactive-recovery.py')
(root/'bin').mkdir();(root/'bin/sh').symlink_to('/usr/bin/bash')
modules=[]
for name in ('virtio_pci','virtio_blk','dm_crypt','aesni_intel','xts','tpm_tis','xhci_pci','ext4'):
    output=subprocess.check_output(['modprobe','--show-depends',name],text=True)
    for line in output.splitlines():
        if line.startswith('insmod '):
            path=line.split()[1]
            if path not in modules:copy(path);modules.append(path)
for folder in ('proc','sys','dev','run','tmp','etc'):(root/folder).mkdir(exist_ok=True)
(root/'etc/passwd').write_text('root:x:0:0:root:/:/bin/sh\n')
(root/'key').write_text('DISPOSABLE-VM-ONLY-NOT-A-LAPTOP-PASSWORD')
(root/'wrong').write_text('INTENTIONALLY-WRONG-TEST-INPUT\n')
(root/'key').chmod(0o600);(root/'wrong').chmod(0o600)
loads='\n'.join('/usr/bin/insmod '+p for p in modules)
init='''#!/bin/sh
export PATH=/usr/bin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
finish() { sync; echo o > /proc/sysrq-trigger; while true; do sleep 1; done; }
fail() { echo VM_TEST_FAIL; finish; }
trap fail ERR
set -E -e
'''+loads+'''
for i in {1..30}; do test -b /dev/vda && break; sleep 1; done
test -b /dev/vda
cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file /key /dev/vda
echo VM_FORMAT_PASS
if cryptsetup open --test-passphrase --key-file /wrong /dev/vda; then fail; fi
echo VM_WRONG_PASSWORD_REJECTED
cryptsetup open --test-passphrase --key-file /key /dev/vda
echo VM_CORRECT_PASSWORD_ACCEPTED
cryptsetup open --key-file /key /dev/vda disposable_test
cryptsetup status disposable_test
echo VM_MAPPING_OPENED
cryptsetup close disposable_test
echo VM_MAPPING_CLOSED
echo VM_TEST_PASS
finish
'''
if options.tpm:
    tpm_steps = """
test -c /dev/tpmrm0
systemd-cryptenroll --unlock-key-file=/key --tpm2-device=/dev/tpmrm0 --tpm2-pcrs=7 /dev/vda
echo VM_TPM_ENROLLED
/usr/lib/systemd/systemd-cryptsetup attach tpm_test /dev/vda - tpm2-device=/dev/tpmrm0,headless=yes,password-cache=no
cryptsetup status tpm_test
echo VM_TPM_UNLOCKED
/usr/lib/systemd/systemd-cryptsetup detach tpm_test
if cryptsetup open --disable-external-tokens --key-slot 0 --key-file /wrong /dev/vda manual_test; then fail; fi
echo VM_MANUAL_WRONG_REJECTED_WITH_TPM_PRESENT
cryptsetup open --disable-external-tokens --key-slot 0 --key-file /key /dev/vda manual_test
cryptsetup status manual_test
echo VM_MANUAL_CORRECT_WITH_TPM_PRESENT
cryptsetup close manual_test
before_pcr=$(tpm2_pcrread -T device:/dev/tpmrm0 sha256:7)
tpm2_pcrextend -T device:/dev/tpmrm0 7:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
after_pcr=$(tpm2_pcrread -T device:/dev/tpmrm0 sha256:7)
test "$before_pcr" != "$after_pcr"
echo VM_TEST_PCR_CHANGED
if /usr/lib/systemd/systemd-cryptsetup attach mismatch_test /dev/vda - tpm2-device=/dev/tpmrm0,headless=yes,password-cache=no; then fail; fi
if cryptsetup status mismatch_test; then fail; fi
echo VM_TPM_POLICY_MISMATCH_REJECTED
cryptsetup open --disable-external-tokens --key-slot 0 --key-file /key /dev/vda recovery_test
cryptsetup status recovery_test
echo VM_MANUAL_RECOVERY_AFTER_MISMATCH
cryptsetup close recovery_test
"""
    if options.signed_pcr:
        setup = """
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /test-pcr-private.pem
openssl pkey -in /test-pcr-private.pem -pubout -out /test-pcr-public.pem
/usr/lib/systemd/systemd-measure sign --current --phase= --bank=sha256 --policyref=initrd --private-key=/test-pcr-private.pem --public-key=/test-pcr-public.pem --tpm2-device=/dev/tpmrm0 > /test-signature.json
"""
        tpm_steps=tpm_steps.replace('test -c /dev/tpmrm0','test -c /dev/tpmrm0\n'+setup)
        tpm_steps=tpm_steps.replace('--tpm2-pcrs=7 /dev/vda', '--tpm2-pcrs=7 --tpm2-public-key=/test-pcr-public.pem --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=initrd --tpm2-signature=/test-signature.json /dev/vda')
        tpm_steps=tpm_steps.replace('tpm2-device=/dev/tpmrm0,headless=yes,password-cache=no', 'tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no')
        signed_check = """
tpm2_pcrextend -T device:/dev/tpmrm0 11:sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
if /usr/lib/systemd/systemd-cryptsetup attach stale_test /dev/vda - tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no; then fail; fi
if cryptsetup status stale_test; then fail; fi
echo VM_STALE_PCR11_SIGNATURE_REJECTED
/usr/lib/systemd/systemd-measure sign --current --phase= --bank=sha256 --policyref=initrd --private-key=/test-pcr-private.pem --public-key=/test-pcr-public.pem --tpm2-device=/dev/tpmrm0 > /test-signature.json
/usr/lib/systemd/systemd-cryptsetup attach resigned_test /dev/vda - tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no
cryptsetup status resigned_test
/usr/lib/systemd/systemd-cryptsetup detach resigned_test
echo VM_NEW_AUTHORIZED_PCR11_SIGNATURE_ACCEPTED
/usr/lib/systemd/systemd-measure sign --current --phase= --bank=sha256 --policyref=wrong-reference --private-key=/test-pcr-private.pem --public-key=/test-pcr-public.pem --tpm2-device=/dev/tpmrm0 > /wrong-reference.json
if /usr/lib/systemd/systemd-cryptsetup attach wrongref_test /dev/vda - tpm2-device=/dev/tpmrm0,tpm2-signature=/wrong-reference.json,headless=yes,password-cache=no; then fail; fi
if cryptsetup status wrongref_test; then fail; fi
echo VM_WRONG_POLICY_REFERENCE_REJECTED
"""
        tpm_steps=tpm_steps.replace('before_pcr=$(tpm2_pcrread',signed_check+'\nbefore_pcr=$(tpm2_pcrread')
    if options.gate:tpm_steps=tpm_steps.replace('before_pcr=$(tpm2_pcrread','python3 /gate-scenarios.py\npython3 /interactive-recovery.py\nbefore_pcr=$(tpm2_pcrread')
    if options.integrated_recovery:
        tpm_steps=tpm_steps.replace('before_pcr=$(tpm2_pcrread','python3 /alternate-unlock.py\nbefore_pcr=$(tpm2_pcrread')
    if options.integrated_recovery:tpm_steps += '\npython3 /gate-record-test.py\npython3 /observer-supervision.py\npython3 /preboot-integration.py\n'
    init=init.replace('echo VM_TEST_PASS',tpm_steps+'\necho VM_TEST_PASS')
if options.switch_root:
    if options.integrated_recovery:(root/'keep-generated-root').write_text('guest-only')
    (root/'record-root.py').write_text("""import os,sys
sys.path.insert(0,'/policy')
from handover import make_record,publish
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
os.mkdir('/run/root-handover',0o700)
publish('/run/root-handover',make_record(boot,{'unlocked':True,'method':'manual','attempts':['manual']},'manual'))
""")
    postcheck = """import os,sys
sys.path.insert(0,'/policy')
from handover import consume
assert os.getpid()!=1  # Python is invoked by the new root's PID1 shell.
boot=open('/proc/sys/kernel/random/boot_id').read().strip()
record=consume('/run/root-handover',boot)
assert record['unlock']['unlocked'] is True and record['unlock']['method']=='manual'
assert record['attested'] is False
roots=[line.split() for line in open('/proc/mounts') if line.split()[1]=='/']
assert any(row[2]=='ext4' and row[0].startswith('/dev/') for row in roots), roots
assert os.path.exists('/dev/mapper/handover_root')
print(chr(10)+'VM_HANDOVER_SWITCH_ROOT_PASS',flush=True)
"""
    if options.integrated_recovery:
        postcheck=postcheck.replace('handover_root','generated_test')
        postcheck += "assert any(os.stat(row[0]).st_rdev==os.stat('/dev/mapper/generated_test').st_rdev for row in roots)\n"
        postcheck += "assert os.path.exists('/sys/class/block/'+os.path.basename(os.path.realpath('/dev/mapper/generated_test'))+'/slaves/vda')\nprint('VM_INTEGRATED_SAME_MAPPING_PASS',flush=True)\n"
    (root/'post-root.py').write_text(postcheck)
    (root/'post-init').write_text("""#!/bin/sh
export PATH=/usr/bin:/bin
if python3 /post-root.py; then echo VM_TEST_PASS; else echo VM_TEST_FAIL; fi
sync
echo o > /proc/sysrq-trigger
while true; do sleep 1; done
""")
    (root/'post-init').chmod(0o755)
    switch = """
cryptsetup open --disable-external-tokens --key-slot 0 --key-file /key /dev/vda handover_root
cryptsetup status handover_root
python3 /record-root.py
mkfs.ext4 -q /dev/mapper/handover_root
mkdir /newroot
mount /dev/mapper/handover_root /newroot
for tree in /usr /bin /lib /lib64 /etc /policy; do
    if test -e "$tree"; then cp -a "$tree" /newroot/; fi
done
cp /post-root.py /post-init /newroot/
mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/run /newroot/tmp
sync
mount --move /run /newroot/run
exec switch_root /newroot /post-init
"""
    if options.integrated_recovery:
        switch=switch.replace('cryptsetup open --disable-external-tokens --key-slot 0 --key-file /key /dev/vda handover_root\n','')
        switch=switch.replace('handover_root','generated_test')
        record=root/'record-root.py'
        record.write_text(record.read_text().replace("os.mkdir('/run/root-handover',0o700)", "assert open('/run/generated-attempts').read()=='manual'\nos.mkdir('/run/root-handover',0o700)"))
    init=init.replace('echo VM_TEST_PASS',switch)
if options.systemd_gate:
    binary('/usr/lib/systemd/system-generators/systemd-cryptsetup-generator','/test-cryptsetup-generator')
    binary('/usr/bin/udevadm')
    binary('/usr/bin/dmsetup')
    for rule in ('10-dm.rules','60-persistent-storage.rules','95-dm-notify.rules'):
        copy('/usr/lib/udev/rules.d/'+rule)
    binary('/usr/lib/systemd/systemd-udevd')
    binary('/usr/bin/systemd-cryptsetup')
    copy(project/'tests/vm-generated-unit.py','/generated-unit.py')
    if options.integrated_recovery:
        binary('/usr/bin/journalctl')
        copy(project/'tests/vm-preboot-integration.py','/preboot-integration.py')
        copy(project/'tests/vm-gate-record.py','/gate-record-test.py')
        copy(project/'tests/vm-observer-supervision.py','/observer-supervision.py')
        copy(project/'tests/vm-alternate-unlock.py','/alternate-unlock.py')
    copy(project/'tests/vm-generated-unlock.py','/generated-unit-unlock.py')
    binary('/usr/lib/systemd/systemd')
    binary('/usr/lib/systemd/systemd-executor')
    binary('/usr/bin/systemctl')
    unitdir=root/'etc/systemd/system';unitdir.mkdir(parents=True,exist_ok=True)
    (root/'etc/os-release').write_text('ID=security-center-test\nNAME=Disposable-test-guest\n')
    (root/'etc/machine-id').write_text('')
    if options.switch_root:(root/'etc/initrd-release').write_text('ID=security-center-test\n')
    gate_script = '#!/bin/sh\nsleep 1\nprintf done > /run/device-check-finished\nexit '+('1' if options.systemd_gate=='failure' else '0')+'\n'
    (root/'device-check').write_text(gate_script);(root/'device-check').chmod(0o755)
    (unitdir/'device-check.service').write_text("""[Unit]
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/device-check
RemainAfterExit=yes
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TimeoutStartSec=10
""")
    (unitdir/'vm-unlock-test.service').write_text("""[Unit]
DefaultDependencies=no
Wants=device-check.service
After=device-check.service
[Service]
Type=oneshot
ExecStart=/vm-unlock-test
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
TimeoutStartSec=100
""")
    (unitdir/'default.target').write_text("""[Unit]
DefaultDependencies=no
Wants=vm-unlock-test.service
After=vm-unlock-test.service
""")
    # PID1 systemd provides these API mounts. Do not hide /run/systemd with a new tmpfs.
    runner=init.replace('python3 /interactive-recovery.py', 'python3 /interactive-recovery.py\npython3 /generated-unit.py')
    if options.integrated_recovery:
        runner=runner.replace('python3 /generated-unit.py','')
    if options.switch_root:
        runner=runner.replace('mount --move /run /newroot/run\nexec switch_root /newroot /post-init', 'systemctl --no-block switch-root /newroot /post-init\nwhile true; do sleep 1; done')
    for line in ('mount -t proc proc /proc','mount -t sysfs sysfs /sys','mount -t devtmpfs devtmpfs /dev','mount -t tmpfs tmpfs /run'):
        runner=runner.replace(line+'\n','')
    assertion='test -f /run/device-check-finished\n'
    assertion += ('systemctl is-failed --quiet device-check.service\n' if options.systemd_gate=='failure' else 'systemctl is-active --quiet device-check.service\n')
    assertion += 'echo VM_SYSTEMD_GATE_'+options.systemd_gate.upper()+'_ORDERING_PASS\n'
    runner=runner.replace('set -E -e\n','set -E -e\n'+assertion)
    (root/'vm-unlock-test').write_text(runner);(root/'vm-unlock-test').chmod(0o755)
    init='#!/bin/sh\nexec /usr/lib/systemd/systemd --system --unit=default.target --show-status=yes --log-target=console --log-level=debug\n'
if options.cold_boot:
    from cold_boot_fixture import build as build_cold
    init=build_cold(root,loads,binary,copy,setup,options.cold_boot,options.cold_input)
    if options.stock_observation:
        from stock_observation_fixture import configure
        init=configure(root,init,copy,binary,options.stock_observation)
(root/'init').write_text(init);(root/'init').chmod(0o755)
# newc archive: no privileged mounts or device-node creation on the host.
archive=bytearray()
def add(name,mode,data,ino):
    fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0]
    archive.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode())
    archive.extend(name.encode()+b'\0');archive.extend(b'\0'*(-len(archive)%4))
    archive.extend(data);archive.extend(b'\0'*(-len(archive)%4))
arch_base_raw=b'';arch_binding=None
if options.arch_base:
    from arch_boot_fixture import select
    arch_base_raw,selected,arch_binding=select(options.arch_base,root)
    for ino,(name,mode,data) in enumerate(selected,1):add(name,mode,data,ino)
else:
    for ino,path in enumerate(sorted(root.rglob('*')),1):
        mode=path.lstat().st_mode
        data=os.readlink(path).encode() if path.is_symlink() else path.read_bytes() if path.is_file() else b''
        add(str(path.relative_to(root)),mode,data,ino)
add('TRAILER!!!',0,b'',0)
image=work/'initramfs.gz'
supplement_raw=bytes(archive)
if options.arch_base:
    image.write_bytes(arch_base_raw+gzip.compress(supplement_raw))
else:
    with gzip.open(image,'wb') as f:f.write(archive)
del archive
# Boot a sealed copy of the captured compressed initrd, not a mutable path.
sealed_image=os.memfd_create('security-center-test-initrd',os.MFD_ALLOW_SEALING)
with image.open('rb') as src, os.fdopen(os.dup(sealed_image),'wb') as dst:
    shutil.copyfileobj(src,dst,65536)
fcntl.fcntl(sealed_image,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
try:
    os.pwrite(sealed_image,b'x',0)
except PermissionError:
    pass
else:
    raise RuntimeError('Initrd sealing did not prevent writes')
os.lseek(sealed_image,0,os.SEEK_SET)
compressed_hash=hashlib.sha256()
while True:
    block=os.read(sealed_image,65536)
    if not block:break
    compressed_hash.update(block)
os.lseek(sealed_image,0,os.SEEK_SET)
if options.arch_base:
    # Parse/hash the actual sealed fd, including the untouched base prefix.
    sealed_base=os.pread(sealed_image,len(arch_base_raw),0)
    if hashlib.sha256(sealed_base).hexdigest()!=arch_binding['base_image_sha256']:
        raise ValueError('Sealed Arch base differs from reviewed test artifact')
    from arch_initrd_manifest import inspect as inspect_arch
    base_manifest=inspect_arch(sealed_base)
    with os.fdopen(os.dup(sealed_image),'rb') as src:
        src.seek(len(arch_base_raw))
        with gzip.GzipFile(fileobj=src,mode='rb') as decoded:
            supplement_manifest=inspect_newc(decoded)
    artifact_manifest=dict(schema_version=1,approved=False,format='arch-base-plus-fixture',
                           scope='Ordered early-newc and zstd-newc Arch base plus gzip-newc fixture supplement',
                           base=arch_binding,base_manifest=base_manifest,supplement=supplement_manifest)
    artifact_manifest['files']=artifact_manifest['supplement']['files']
else:
    with os.fdopen(os.dup(sealed_image),'rb') as src, gzip.GzipFile(fileobj=src,mode='rb') as decoded:
        artifact_manifest=inspect_newc(decoded)
artifact_manifest.update(compressed_sha256=compressed_hash.hexdigest(),
                         compressed_bytes=os.fstat(sealed_image).st_size,
                         boot_input_sealed=True)
manifest_raw=json.dumps(artifact_manifest,sort_keys=True,indent=2).encode()
(work/'initrd-manifest.json').write_bytes(manifest_raw)
manifest_digest=hashlib.sha256(manifest_raw).hexdigest()
os.lseek(sealed_image,0,os.SEEK_SET)
with (work/'disk.raw').open('xb') as f:f.truncate((256 if options.switch_root else 64)*1024*1024)
args=['qemu-system-x86_64','-accel','kvm','-cpu','host','-m','384','-smp','2',
      '-nodefaults','-no-reboot','-display','none','-serial','stdio','-monitor','none','-nic','none',
      '-kernel',f'/usr/lib/modules/{kernel}/vmlinuz','-initrd',f'/proc/self/fd/{sealed_image}',
      '-append','console=ttyS0 rdinit=/init panic=1 quiet security_center_test_vm=1',
      '-drive',f'file={work}/disk.raw,format=raw,if=virtio']
if options.gate:args += ['-device','qemu-xhci,id=testusb','-device','usb-mouse,bus=testusb.0']
if options.cold_boot:
    idx=args.index('-append')+1
    args[idx] += ' root=/dev/mapper/cold_root rootfstype=ext4 rw rd.luks.name=11111111-2222-3333-4444-555555555555=cold_root rd.luks.options=11111111-2222-3333-4444-555555555555=tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no'
if options.stock_observation=='manual':
    idx=args.index('-append')+1
    args[idx]=args[idx].replace('headless=yes,','')
if options.arch_base:
    idx=args.index('-append')+1
    args[idx]=args[idx].replace('rdinit=/init','rdinit=/arch-provision')
emulator=None
if options.tpm:
    state=work/'tpm-state';state.mkdir(mode=0o700)
    sock=work/'tpm.sock'
    log=(work/'tpm.log').open('w')
    emulator=subprocess.Popen(['swtpm','socket','--tpm2','--tpmstate',f'dir={state}',
        '--ctrl',f'type=unixio,path={sock}','--flags','not-need-init','--terminate'],stdout=log,stderr=log)
    for _ in range(100):
        if sock.exists() or emulator.poll() is not None:break
        time.sleep(.05)
    if not sock.exists():
        emulator.terminate();emulator.wait(timeout=5);log.close()
        raise RuntimeError('Test TPM socket did not start')
    args += ['-chardev',f'socket,id=chrtpm,path={sock}','-tpmdev','emulator,id=tpm0,chardev=chrtpm','-device','tpm-tis,tpmdev=tpm0']
started=time.monotonic()
cold_abort_reason=None
try:
    with (work/'console.log').open('w') as console:
        if options.cold_boot:
            child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=console,stderr=subprocess.STDOUT,pass_fds=(sealed_image,))
            sent=False
            secret=b'DISPOSABLE-VM-ONLY-NOT-A-LAPTOP-PASSWORD\n'
            answers={'correct':[secret],'wrong':[b'WRONG-DISPOSABLE-INPUT\n',secret],
                     'cancel':[b'\x03',secret],'timeout':[None,secret],
                     'exhaust':[b'WRONG-DISPOSABLE-INPUT\n']*3}[options.cold_input]
            prompts=0;retries=0
            try:
                deadline=time.monotonic()+120
                while child.poll() is None and time.monotonic()<deadline:
                    text=(work/'console.log').read_text(errors='replace')
                    if 'Traceback (most recent call last):' in text:
                        cold_abort_reason='Unhandled guest traceback';child.terminate();break
                    prompt_count=text.count('Please enter passphrase') if options.stock_observation=='manual' else text.count('Enter passphrase')
                    if prompt_count>prompts:
                        if prompts>=len(answers):
                            cold_abort_reason='Unexpected extra password prompt';child.terminate();break
                        answer=answers[prompts];prompts+=1
                        if answer is not None:
                            child.stdin.write(answer);child.stdin.flush()
                            if answer==secret:sent=True
                    if text.count('VM_COLD_RETRY_PROMPT_')>retries:
                        child.stdin.write(b'\n');child.stdin.flush();retries+=1
                    time.sleep(.05)
                if cold_abort_reason:child.wait(timeout=5)
                if child.poll() is None:raise subprocess.TimeoutExpired(args,120)
                result=child
            finally:
                if child.poll() is None:child.kill()
                child.wait(timeout=5)
                child.stdin.close()
        else:
            result=subprocess.run(args,stdout=console,stderr=subprocess.STDOUT,text=True,timeout=120,pass_fds=(sealed_image,))
    output=(work/'console.log').read_text(errors='replace');code=result.returncode
except subprocess.TimeoutExpired as exc:
    output=(work/'console.log').read_text(errors='replace')
    code='timeout'
finally:
    os.close(sealed_image)
    if emulator is not None:
        if emulator.poll() is None:emulator.terminate()
        try:emulator.wait(timeout=5)
        except subprocess.TimeoutExpired:emulator.kill();emulator.wait()
        log.close()
(work/'console.log').write_text(output)
markers=[line.strip() for line in output.splitlines() if line.startswith('VM_')]
required={'VM_FORMAT_PASS','VM_WRONG_PASSWORD_REJECTED','VM_CORRECT_PASSWORD_ACCEPTED',
          'VM_MAPPING_OPENED','VM_MAPPING_CLOSED','VM_TEST_PASS'}
if options.tpm:
    required.update({'VM_TPM_ENROLLED','VM_TPM_UNLOCKED','VM_MANUAL_WRONG_REJECTED_WITH_TPM_PRESENT',
                     'VM_MANUAL_CORRECT_WITH_TPM_PRESENT','VM_TEST_PCR_CHANGED',
                     'VM_TPM_POLICY_MISMATCH_REJECTED','VM_MANUAL_RECOVERY_AFTER_MISMATCH'})
if options.signed_pcr:required.update({'VM_STALE_PCR11_SIGNATURE_REJECTED','VM_NEW_AUTHORIZED_PCR11_SIGNATURE_ACCEPTED','VM_WRONG_POLICY_REFERENCE_REJECTED'})
if options.gate:required.update('VM_GATE_'+name+'_PASS' for name in ('ALLOW','UNKNOWN_DEVICE','INCOMPLETE_SCAN','SCAN_FAILURE','DISTRESS','WRONG_MANUAL','MISSING_TPM','REAL_USB_UNKNOWN','REAL_USB_PARTIAL'))
if options.gate:required.update({'VM_USB_DISCOVERY_PASS','VM_HANDOVER_IO_PASS'})
if options.gate:required.update('VM_INTERACTIVE_'+name+'_PASS' for name in ('WRONG','CANCEL','TIMEOUT','CORRECT'))
if options.switch_root:required.add('VM_HANDOVER_SWITCH_ROOT_PASS')
if options.integrated_recovery:required.update({'VM_GATE_RECORD_FILESYSTEM_PASS','VM_OBSERVER_SUPERVISION_PASS','VM_ALTERNATE_UNLOCK_BYPASS_REPRODUCED','VM_ALTERNATE_UNLOCK_CANDIDATE_REJECTED'})
if options.switch_root and options.integrated_recovery:required.add('VM_INTEGRATED_SAME_MAPPING_PASS')
if options.systemd_gate:required.update({'VM_GENERATED_UNIT_WRONG_PASS','VM_GENERATED_UNIT_CORRECT_PASS'})
if options.systemd_gate:required.update({'VM_SYSTEMD_GATE_'+options.systemd_gate.upper()+'_ORDERING_PASS','VM_GATE_SYSTEMD_SERVICE_EVIDENCE_PASS'})
if options.integrated_recovery:required.update('VM_INTEGRATED_RECOVERY_'+name+'_PASS' for name in ('WRONG','CANCEL','TIMEOUT','CORRECT','AUTO_CRYPTTAB','AUTO_CMDLINE'))
if options.cold_boot:required={'VM_COLD_PREPARED','VM_COLD_MANUAL_UNLOCK','VM_COLD_POSTROOT','VM_TEST_PASS','VM_COLD_GENERATOR_AUDIT','VM_COLD_RUNTIME_GRAPH','VM_COLD_CHECKER_'+('ACTIVE' if options.cold_boot=='observe' else 'FAILED')}
secret_absent = b'DISPOSABLE-VM-ONLY-NOT-A-LAPTOP-PASSWORD'.decode() not in output
if options.cold_boot:
    required.add('VM_COLD_MANUAL_ATTEMPTS_'+str(1 if options.cold_input=='correct' else 3 if options.cold_input=='exhaust' else 2))
    if options.cold_input!='correct':required.add('VM_COLD_ATTEMPT_FAILED_1')
    if options.cold_input=='exhaust':
        required.discard('VM_COLD_MANUAL_UNLOCK');required.discard('VM_COLD_POSTROOT');required.add('VM_COLD_RECOVERY_EXHAUSTED')
if options.stock_observation:
    required={'VM_COLD_PREPARED','VM_STOCK_COMMAND_UNCHANGED','VM_STOCK_TPM_UNLOCKED','VM_STOCK_POSTROOT','VM_STOCK_POSTBOOT_REFUSED','VM_TEST_PASS', 'VM_STOCK_RECORD_RETAINED' if options.stock_observation in ('success','manual') else 'VM_STOCK_RECORD_ABSENT'}
    if options.stock_observation in ('success','manual'):required.add('VM_OBSERVATION_FILES_PASS')
    if options.stock_observation=='manual':
        required.discard('VM_STOCK_TPM_UNLOCKED')
        required.update({'VM_STOCK_TPM_FAILURE_CONFIRMED','VM_STOCK_MANUAL_RECOVERED'})
        if not sent or prompts!=1:required.add('VM_MANUAL_INPUT_NOT_VERIFIED')
    elif sent or prompts:required.add('VM_UNEXPECTED_MANUAL_INPUT')
passed=(bool(options.stock_observation) or not options.cold_boot or sent is (options.cold_input!='exhaust')) and code==0 and required.issubset(markers) and 'VM_TEST_FAIL' not in markers and (not (options.integrated_recovery or options.cold_boot) or secret_absent)
report={'initrd_manifest_sha256':manifest_digest,'initrd_compressed_sha256':artifact_manifest['compressed_sha256'],
        'initrd_manifest_scope':artifact_manifest.get('scope','Complete single-newc test archive'), 'initrd_member_count':len(artifact_manifest['files'])+(sum(len(segment['files']) for segment in artifact_manifest['base_manifest']['segments']) if options.arch_base else 0),'initrd_boot_input_sealed':True,'passed':passed,'returncode':code,'seconds':round(time.monotonic()-started,2),
        'markers':markers,'work':str(work),'guest_memory_mib':384,
        'host_disks_exposed':False,'host_tpm_exposed':False,'network':False,
        'test_secret_absent_from_console':secret_absent,'integrated_recovery':options.integrated_recovery,'cold_boot':options.cold_boot,'cold_input':options.cold_input,'arch_base':arch_binding,'stock_observation':options.stock_observation,'cold_abort_reason':cold_abort_reason,'systemd_gate':options.systemd_gate,'switch_root':options.switch_root,'gate_fixtures':options.gate,'software_tpm':options.tpm,'signed_pcr11':options.signed_pcr,'scope':'Guest LUKS/software TPM with optional signed-PCR11 policyref initrd; no firmware Secure Boot claim'}
(work/'report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
if not passed:print(output[-5000:]);raise SystemExit(1)
