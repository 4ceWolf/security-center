"""Disposable VM provisioning ONLY. This file must never enter target image."""
import os,pathlib,subprocess,traceback,time

def run(args):
 r=subprocess.run(args,capture_output=True,timeout=40)
 if r.returncode:raise RuntimeError('Provisioning command failed: '+args[0]+': '+r.stderr.decode(errors='replace')[-800:])
 return r.stdout
try:
 assert 'security_center_test_vm=1' in pathlib.Path('/proc/cmdline').read_text().split()
 for _ in range(100):
  if pathlib.Path('/dev/vdb').exists() and pathlib.Path('/dev/tpmrm0').exists():break
  time.sleep(.1)
 assert pathlib.Path('/dev/vdb').is_block_device()
 sig='/run/systemd/tpm2-pcr-signature.json'
 assert pathlib.Path(sig).is_file(), 'Missing stub PCR signature'
 run(['/usr/bin/cryptsetup','luksFormat','--type','luks2','--batch-mode','--uuid','11111111-2222-3333-4444-555555555555','--pbkdf','pbkdf2','--pbkdf-force-iterations','1000','--key-file','/disposable-key','/dev/vdb'])
 run(['/usr/bin/cryptsetup','open','--key-file','/disposable-key','/dev/vdb','prepare_root'])
 run(['/usr/bin/mkfs.ext4','-q','/dev/mapper/prepare_root'])
 pathlib.Path('/prepared').mkdir()
 run(['/usr/bin/mount','/dev/mapper/prepare_root','/prepared'])
 run(['/usr/bin/cp','-a','/fixture-root/.','/prepared/'])
 base=pathlib.Path('/prepared');(base/'etc/initrd-release').unlink(missing_ok=True)
 (base/'etc/fstab').write_text('')
 (base/'etc/os-release').write_text('ID=security-center-two-boot\nNAME=Disposable-measured-root\n')
 init=base/'usr/bin/init';init.unlink(missing_ok=True);init.symlink_to('../lib/systemd/systemd')
 units=base/'etc/systemd/system';units.mkdir(parents=True,exist_ok=True)
 (units/'default.target').unlink(missing_ok=True)
 (units/'default.target').write_text('[Unit]\nDefaultDependencies=no\nWants=fixture-post.service\nAfter=fixture-post.service\n')
 (units/'fixture-post.service').write_text('[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /post-root.py\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTimeoutStartSec=30\n')
 for name in ('proc','sys','dev','run','tmp'):(base/name).mkdir(exist_ok=True)
 os.sync();run(['/usr/bin/umount','/prepared']);run(['/usr/bin/cryptsetup','close','prepare_root'])
 run(['/usr/bin/systemd-cryptenroll','--unlock-key-file=/disposable-key','--tpm2-device=/dev/tpmrm0','--tpm2-pcrs=7','--tpm2-public-key=/fixture-public.pem','--tpm2-public-key-pcrs=11','--tpm2-public-key-policyref=initrd','--tpm2-signature='+sig,'/dev/vdb'])
 print('TWO_BOOT_PROVISIONED',flush=True)
except BaseException:
 traceback.print_exc();print('TWO_BOOT_PROVISION_FAILED',flush=True)
finally:
 os.sync();pathlib.Path('/proc/sysrq-trigger').write_text('o')
