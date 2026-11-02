"""Project-local capture of fixed observer input bytes, never a host installer."""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sysconfig
import tempfile

ROOT = pathlib.Path('/home/user/Projects/security-center')
LIBRARY = '/usr/lib/security-center-observation/'
PAYLOAD = {'initramfs/boot_observation.py':'boot_observation.py',
           'initramfs/boot_observer.py':'boot_observer.py',
           'initramfs/observation_entry.py':'entry.py',
           'initramfs/gate_observer.py':'gate_observer.py',
           'initramfs/gate_record.py':'gate_record.py',
           'policies/device_gate.py':'device_gate.py',
           'policies/device_inventory.py':'device_inventory.py',
           'policies/platform_inventory.py':'platform_inventory.py'}
PACKAGES = ('encodings','json','re','collections','importlib','pathlib','logging')
EXTENSIONS = ('_posixsubprocess','select','math','_opcode','_struct','_typing',
              '_json','fcntl','_hashlib','_sha2','_blake2','_md5','_sha1','_sha3')
MAX_FILE = 64*1024*1024
MAX_TOTAL = 256*1024*1024


def sha(raw): return hashlib.sha256(raw).hexdigest()


def destination(name):
    if (not isinstance(name,str) or not name.startswith('/')
            or str(pathlib.PurePosixPath(name))!=name or '..' in pathlib.PurePosixPath(name).parts):
        raise ValueError('Invalid captured destination')
    return name.lstrip('/')


def build(mapping):
    if not isinstance(mapping,str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',mapping):
        raise ValueError('Invalid reviewed root mapping')
    parent = ROOT/'work'; parent.mkdir(exist_ok=True)
    folder = pathlib.Path(tempfile.mkdtemp(prefix='observation-package-',dir=parent))
    tree = folder/'root'; tree.mkdir()
    files = {}; total = 0
    def put(name, raw, mode=0o644, **metadata):
        nonlocal total
        relative = destination(name)
        if relative in files: raise ValueError('Duplicate package member')
        if len(raw)>MAX_FILE or total+len(raw)>MAX_TOTAL or len(files)>=4096:
            raise ValueError('Package capture exceeds bound')
        target=tree/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(mode)
        files[relative]=dict(sha256=sha(raw),size=len(raw),mode=mode,**metadata)
        total += len(raw)
    def capture(source, name=None):
        source=pathlib.Path(source); name=str(name or source)
        if destination(name) in files:return
        resolved=source.resolve(strict=True)
        with source.open('rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_FILE:
                raise ValueError('Invalid capture source')
            raw=stream.read(MAX_FILE+1);after=os.fstat(stream.fileno())
        current=source.stat()
        def identity(info):
            return (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if identity(before)!=identity(after) or identity(after)!=identity(current) or source.resolve()!=resolved:
            raise ValueError('Source changed during capture')
        put(name,raw,stat.S_IMODE(before.st_mode),source=str(source),resolved_source=str(resolved))
    def binary(source):
        capture(source)
        output=subprocess.check_output(['/usr/bin/ldd',str(source)],text=True,timeout=5,
                    env={'PATH':'/usr/bin','LC_ALL':'C'})
        if 'not found' in output:raise ValueError('Unresolved ELF dependency')
        for name in set(re.findall(r'(/[\w/+.\-]+)',output)):
            capture(name)
    for source, name in PAYLOAD.items():capture(ROOT/source,LIBRARY+name)
    capture(ROOT/'initramfs/units/security-center-observation.service', '/usr/lib/systemd/system/security-center-observation.service')
    capture(ROOT/'initramfs/install/security-center-observation', '/usr/lib/initcpio/install/security-center-observation')
    capture(ROOT/'policies/normal-devices.candidate.json','/etc/security-center-observation/normal-devices.json')
    put('/etc/security-center-observation/root-mapping',(mapping+'\n').encode())
    put('/etc/systemd/system/systemd-cryptsetup@'+mapping+'.service.d/50-security-center-observation.conf',
        b'[Unit]\nWants=security-center-observation.service\nAfter=security-center-observation.service\n')
    binary('/usr/bin/python3')
    stdlib=pathlib.Path(sysconfig.get_path('stdlib'))
    if not re.fullmatch(r'/usr/lib/python[0-9]+\.[0-9]+',str(stdlib)):
        raise ValueError('Unexpected host Python layout')
    for source in sorted(stdlib.glob('*.py')):capture(source)
    for package in PACKAGES:
        for source in sorted((stdlib/package).rglob('*.py')):capture(source)
    for extension in EXTENSIONS:
        for source in sorted((stdlib/'lib-dynload').glob(extension+'.*.so')):binary(source)
    inputs=dict(schema_version=1,approved=False,scope='observer_inputs_only',mapping=mapping,files=dict(files))
    raw=json.dumps(inputs,sort_keys=True,indent=2).encode()
    (folder/'inputs.json').write_bytes(raw)
    put('/etc/security-center-observation/source.sha256',(sha(raw)+'\n').encode())
    manifest=dict(schema_version=1,approved=False,installed=False,inputs_sha256=sha(raw),files=files)
    (folder/'package.json').write_text(json.dumps(manifest,sort_keys=True,indent=2))
    return folder


def read_regular(path, limit):
    """Bound staging reads; reject FIFOs/devices and detect entry replacement.

    This is an unprivileged staging check, not a privileged publication primitive.
    A later publisher must capture and verify its own immutable input bytes.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError('Invalid or oversized package file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    if len(raw) > limit or identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError('Package file changed during read')
    return raw, before


def verify(folder):
    folder=pathlib.Path(folder)
    if folder.is_symlink():raise ValueError('Symlink package refused')
    for name in ('package.json','inputs.json','root'):
        if (folder/name).is_symlink():raise ValueError('Symlink package metadata/root refused')
    data=json.loads(read_regular(folder/'package.json', 4*1024*1024)[0])
    raw=read_regular(folder/'inputs.json', 4*1024*1024)[0]
    if (data.get('approved') is not False or data.get('installed') is not False
            or data.get('schema_version')!=1 or sha(raw)!=data.get('inputs_sha256')):
        raise ValueError('Invalid package manifest')
    files=data['files'];tree=folder/'root'
    if not isinstance(files,dict) or len(files)>4096:
        raise ValueError('Invalid package member count')
    actual=set(); total=0
    for path in tree.rglob('*'):
        if path.is_symlink():raise ValueError('Package symlink refused')
        if path.is_dir():continue
        relative=str(path.relative_to(tree));actual.add(relative)
        item=files.get(relative)
        if not isinstance(item,dict):raise ValueError('Unexpected member')
        payload,info=read_regular(path,MAX_FILE)
        total+=len(payload)
        if total>MAX_TOTAL:raise ValueError('Package exceeds total bound')
        if (sha(payload)!=item['sha256'] or info.st_size!=item['size']
                or stat.S_IMODE(info.st_mode)!=item['mode']):raise ValueError('Captured bytes/metadata changed')
    if actual!=set(files):raise ValueError('Package member set changed')
    if read_regular(tree/'etc/security-center-observation/source.sha256',65)[0].decode()!=sha(raw)+'\n':
        raise ValueError('Embedded source digest differs')
    inputs=json.loads(raw)
    expected=dict(files);expected.pop('etc/security-center-observation/source.sha256')
    if (inputs.get('schema_version')!=1 or inputs.get('approved') is not False
            or inputs.get('scope')!='observer_inputs_only'
            or not isinstance(inputs.get('mapping'),str)
            or not re.fullmatch('[A-Za-z0-9_-]{1,64}',inputs['mapping'])
            or inputs.get('files')!=expected):raise ValueError('Input manifest differs from captured files')
    return data
