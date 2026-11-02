#!/usr/bin/python3
"""Unsigned disposable mkinitcpio build; no host boot/keys/devices/network."""
import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import tempfile
from observation_package import verify
BASE=pathlib.Path('/home/user/Projects/security-center')
parser=argparse.ArgumentParser();parser.add_argument('--package',required=True);parser.add_argument('--provisioning-tools',action='store_true');options=parser.parse_args()
package=pathlib.Path(options.package)
if (package.resolve()!=package or package.parent!=BASE/'work' or not package.name.startswith('observation-package-')):
    raise SystemExit('Captured project-local observer package required')
verified=verify(package)
work=pathlib.Path(tempfile.mkdtemp(prefix='arch-observer-build-',dir=BASE/'work'))
(work/'generated').mkdir()
(work/'mkinitcpio.conf').write_text('MODULES=(virtio_pci virtio_blk dm_crypt tpm_tis ext4 btrfs)\nBINARIES=()\nFILES=()\nHOOKS=(base systemd modconf keyboard sd-vconsole sd-encrypt filesystems security-center-observation)\nCOMPRESSION="zstd"\nCOMPRESSION_OPTIONS=(-T1 -3)\n')
if options.provisioning_tools:
    config=work/'mkinitcpio.conf'
    config.write_text(config.read_text().replace('BINARIES=()', 'BINARIES=(/usr/bin/cryptsetup /usr/bin/systemd-cryptenroll /usr/bin/mkfs.ext4 /usr/bin/cp /usr/bin/mkdir /usr/bin/mount /usr/bin/umount /usr/bin/sync)'))
args=['/usr/bin/bwrap','--unshare-all','--uid','0','--gid','0','--die-with-parent','--clearenv','--setenv','PATH','/usr/bin','--setenv','LC_ALL','C','--setenv','TMPDIR','/tmp',
 '--overlay-src',str(package/'root/usr'),'--overlay-src','/usr','--ro-overlay','/usr',
 '--overlay-src',str(package/'root/etc'),'--tmp-overlay','/etc',
 '--ro-bind',str(work/'mkinitcpio.conf'),'/etc/mkinitcpio.conf',
 '--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
 '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/run','--bind',str(work),'/work','--chdir','/work',
 '--','/usr/bin/fakeroot','--','/usr/bin/mkinitcpio','--nopost','-n','-k',os.uname().release,'-c','/etc/mkinitcpio.conf','-d','/work/generated','-g','/work/guest-initramfs.img']
(work/'command.json').write_text(json.dumps(args,indent=2))
with (work/'build.log').open('w') as log:
    try:result=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,timeout=120);code=result.returncode
    except subprocess.TimeoutExpired:code='timeout'
report=dict(returncode=code,host_boot_access=False,host_tpm_access=False,network=False,
            signed=False,provisioning_tools=options.provisioning_tools,work=str(work),package=str(package),source_manifest_sha256=verified['inputs_sha256'])
if code==0:
    tree=work/'generated'
    inventory={}
    for path in tree.rglob('*'):
        info=path.lstat();mode=stat.S_IMODE(info.st_mode)
        if path.is_symlink():item=dict(type='symlink',target=os.readlink(path),mode=mode)
        elif path.is_dir():item=dict(type='directory',mode=mode)
        elif path.is_file():item=dict(type='file',mode=mode,size=info.st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        else:raise ValueError('Unsupported generated special member')
        inventory[str(path.relative_to(tree))]=item
    for member in ('usr/lib/security-center-observation/entry.py','usr/lib/security-center-observation/boot_observation.py',
                   'usr/lib/systemd/system/security-center-observation.service',
                   'etc/security-center-observation/source.sha256'):
        assert inventory[member]['sha256']==verified['files'][member]['sha256'],member
    mapping=(package/'root/etc/security-center-observation/root-mapping').read_text().strip()
    drop='etc/systemd/system/systemd-cryptsetup@'+mapping+'.service.d/50-security-center-observation.conf'
    assert (tree/drop).read_bytes()==(package/'root'/drop).read_bytes()
    assert b'ExecStart' not in (tree/drop).read_bytes()
    raw=json.dumps(inventory,sort_keys=True,indent=2).encode();(work/'generated-manifest.json').write_bytes(raw)
    report.update(generated_manifest_sha256=hashlib.sha256(raw).hexdigest(),members=len(inventory),
                  image_sha256=hashlib.sha256((work/'guest-initramfs.img').read_bytes()).hexdigest(),
                  image_bytes=(work/'guest-initramfs.img').stat().st_size)
report['passed']=code==0
(work/'report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
if code!=0:print((work/'build.log').read_text()[-2500:]);raise SystemExit(1)
