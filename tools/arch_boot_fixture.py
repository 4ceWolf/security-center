"""Select a bounded fixture overlay for the exact unsigned Arch test initrd."""
import hashlib
import json
import pathlib
import stat

BASE = pathlib.Path('/home/user/Projects/security-center/work')
ALLOWED_ETC = ('etc/systemd/system/systemd-cryptsetup@cold_root.service.d/',
               'etc/systemd/system/initrd-cleanup.service.d/',
               'etc/systemd/system/initrd.target.d/')
NATIVE_HELPERS = {'usr/bin/false','usr/bin/cp','usr/bin/mkdir','usr/bin/mount','usr/bin/sleep',
                  'usr/bin/sync','usr/bin/insmod','usr/bin/switch_root'}
ROOT_FILES = {'key','wrong','cold-post.py','prepare-final-root.py','stock-mode',
              'stock-check.py','memory-observer.py'}
EXACT_ETC = {'etc/systemd/system/stock-check.service', 'etc/systemd/system/default.target',
             'etc/systemd/system/security-center-observation.service',
             'etc/os-release', 'etc/machine-id'}


def select(folder, root):
    folder = pathlib.Path(folder)
    if folder.resolve()!=folder or folder.parent!=BASE or not folder.name.startswith('arch-observer-build-'):
        raise ValueError('Captured project Arch build required')
    if (root.resolve()!=root or root.name!='root' or root.parent.parent!=BASE
            or not root.parent.name.startswith('luks-vm-')):
        raise ValueError('Disposable guest root required')
    report=json.loads((folder/'report.json').read_bytes())
    if report.get('passed') is not True or report.get('signed') is not False:
        raise ValueError('Successful unsigned test build required')
    image=(folder/'guest-initramfs.img').read_bytes()
    if len(image)>128*1024*1024 or hashlib.sha256(image).hexdigest()!=report['image_sha256']:
        raise ValueError('Arch base image changed')
    raw=(folder/'generated-manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=report['generated_manifest_sha256']:
        raise ValueError('Arch generated manifest changed')
    inventory=json.loads(raw)
    entries={}
    def add(name,mode,data):
        if name in entries:raise ValueError('Duplicate fixture path')
        entries[name]=(mode,data)
    # The wrapper is moved, so the original Arch /init symlink remains untouched.
    init=(root/'init').read_bytes()
    init=init.replace(b'exec /usr/lib/systemd/systemd --system', b'exec /init --system')
    # Use the Arch module metadata and loader, not the hand-built fixture's paths.
    lines=init.decode().splitlines()
    lines=[line for line in lines if not line.startswith('/usr/bin/insmod ')]
    idx=lines.index('set -E -e')+1
    lines[idx:idx]=['/usr/bin/modprobe '+name for name in ('virtio_pci','virtio_blk','dm_crypt','tpm_tis','ext4')]
    add('arch-provision',stat.S_IFREG|0o755, ('\n'.join(lines)+'\n').encode())
    for path in sorted(root.rglob('*')):
        name=str(path.relative_to(root))
        if path.is_dir() and not path.is_symlink():continue
        if '/' not in name and name not in ROOT_FILES:continue
        if name.startswith('policy/'):continue
        if name=='init' or name.startswith(('lib/modules/','usr/lib/modules/','usr/lib/systemd/system/','etc/udev/')):
            continue
        if name.startswith('etc/') and not (name in EXACT_ETC or name.startswith(ALLOWED_ETC)
                                             or name.startswith('etc/security-center-observation/')):
            continue
        if name.startswith('usr/') and name in inventory:
            expected=inventory[name]
            if name in NATIVE_HELPERS:
                continue  # Keep Arch's own helper (often its BusyBox applet).
            if expected.get('type')=='symlink' and not path.is_symlink():
                target=pathlib.PurePosixPath(expected['target'])
                resolved=target if target.is_absolute() else pathlib.PurePosixPath(name).parent/target
                expected=inventory.get(str(resolved).lstrip('/'),{})
            if path.is_symlink():
                if expected.get('type')!='symlink' or str(path.readlink())!=expected.get('target'):
                    raise ValueError('Overlapping native symlink differs: '+name)
            elif expected.get('type')!='file' or hashlib.sha256(path.read_bytes()).hexdigest()!=expected.get('sha256'):
                raise ValueError('Overlapping native payload differs: '+name)
            continue
        if name in inventory and not name.startswith('etc/'):
            # /bin and /lib64 alias members already provided by Arch are not replaced.
            continue
        if name.startswith(('usr/lib64/','lib64/','bin/')):continue
        mode=path.lstat().st_mode
        data=str(path.readlink()).encode() if path.is_symlink() else path.read_bytes()
        add(name,mode,data)
    for name in list(entries):
        for parent in pathlib.PurePosixPath(name).parents:
            parent=str(parent)
            if parent!='.' and parent not in entries:
                if inventory.get(parent,{}).get('type')=='symlink':
                    raise ValueError('Supplement below native symlink: '+name+' via '+parent)
                entries[parent]=(stat.S_IFDIR|0o755,b'')
    return image,sorted((name,mode,data) for name,(mode,data) in entries.items()),dict(
        base_image_sha256=report['image_sha256'],base_generated_manifest_sha256=report['generated_manifest_sha256'],
        base=str(folder),scope='Exact unsigned Arch image plus explicit disposable fixture supplement')
