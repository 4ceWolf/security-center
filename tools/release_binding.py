"""Bind captured release bytes and prior baseline to reviewed digests.

This is continuity validation, not a source of human approval. No host mutation.
"""
import copy
import importlib.util
from pathlib import Path
import sys
from baseline_migration import document,digest,present
from protected_files import TARGETS
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binding_release',ROOT/'tools/build-monitor-release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
READ_ONLY_SCOPE=frozenset(('/etc/miku-boot/zen.cmdline','/etc/miku-boot/zen.conf','/etc/miku-boot/zen-uki.conf',
                          '/etc/mkinitcpio.d/linux-zen.preset','/etc/systemd/system/cockpit.socket.d/security-center-local.conf'))
SCOPE=TARGETS|READ_ONLY_SCOPE


def bind(previous_raw,previous_digest,release_raw,release_digest,contents,before):
    previous=document(previous_raw,previous_digest);manifest=document(release_raw,release_digest)
    if previous.get('schema_version')!=1 or previous.get('approved') is not True:raise ValueError('Approved prior baseline required')
    old=previous.get('files')
    if not isinstance(old,dict) or not READ_ONLY_SCOPE.issubset(old) or not set(old).issubset(SCOPE):raise ValueError('Prior baseline scope incompatible')
    if manifest.get('schema_version')!=1:raise ValueError('Invalid release schema')
    records=manifest.get('files')
    if not isinstance(records,list) or len(records)!=len(release.FILES) or any(not isinstance(item,dict) for item in records):raise ValueError('Invalid release entries')
    names=[item.get('source') for item in records]
    if len(set(names))!=len(names) or set(names)!=set(release.FILES):raise ValueError('Changed release file set')
    if set(contents)!=set(release.FILES) or any(not isinstance(raw,bytes) for raw in contents.values()):raise ValueError('Exact captured payload bytes required')
    for item in records:
        name=item['source']
        if item.get('destination')!=release.FILES[name] or digest(contents[name])!=item.get('sha256'):raise ValueError('Release path or payload changed')
    declared=release.validate(contents)
    if declared!=manifest.get('fim_paths') or set(declared)!=SCOPE:raise ValueError('Unexpected integrity scope')
    if set(before)!=SCOPE:raise ValueError('Complete current scope scan required')
    for path,entry in old.items():
        present(entry)
        if before[path]!=entry:raise ValueError('Unexplained installed drift: '+path)
        if path in TARGETS and (entry['uid'],entry['gid'],entry['mode'])!=(0,0,0o644):raise ValueError('Unreviewed installed ownership or mode')
    additions=SCOPE-set(old)
    if not additions.issubset(TARGETS) or any(before[path]!={'state':'missing'} for path in additions):raise ValueError('Unapproved preexisting scope addition')
    writes={release.FILES[name]:raw for name,raw in contents.items()
            if before[release.FILES[name]].get('sha256')!=digest(raw)}
    return dict(previous_baseline_sha256=previous_digest,release_sha256=release_digest,
                target_contents={release.FILES[name]:raw for name,raw in contents.items()},
                writes=writes,
                target_before={path:copy.deepcopy(before[path]) for path in TARGETS},
                scope_before=copy.deepcopy(before),scope_additions=sorted(additions),
                baseline_approval_granted=False)


def capture_bundle(folder,reviewed_digest):
    """Read fixed source names without symlinks; verify the SAME bytes returned."""
    sys.path.insert(0,str(ROOT/'securityd'))
    from integrity import open_fixed
    import os,stat
    folder=Path(folder).absolute()
    def read(name,limit):
        fd=open_fixed(str(folder/name))
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ValueError('Invalid bundle member')
            raw=stream.read(limit+1)
            if len(raw)>limit:raise ValueError('Oversized bundle member')
            return raw
    raw=read('release.json',65536)
    manifest=document(raw,reviewed_digest)
    records=manifest.get('files')
    if not isinstance(records,list) or len(records)!=len(release.FILES):raise ValueError('Invalid bundle members')
    if {item.get('source') for item in records}!=set(release.FILES):raise ValueError('Unexpected bundle member')
    contents={name:read(name,release.LIMIT) for name in release.FILES}
    for item in records:
        if item.get('destination')!=release.FILES[item['source']] or digest(contents[item['source']])!=item.get('sha256'):raise ValueError('Captured content differs from reviewed bundle')
    if release.validate(contents)!=manifest.get('fim_paths'):raise ValueError('Captured scope differs')
    return raw,contents
