"""Allowlisted, directory-fd-relative monitor file operations.

No CLI, service controls, baseline approval or boot-path access. Caller must hold
an exclusive protected transaction lock and durably save backups before writes.
Root peers are trusted; this does not serialize other privileged administrators.
"""
import hashlib
import os
from pathlib import PurePosixPath
import secrets
import stat

LIMIT=1024*1024
TARGETS=frozenset(
    ['/usr/local/lib/security-center/'+name for name in
     ('network_policy.py','boot_observation.py','boot_observation_status.py','collector.py','daemon.py','client.py','adapters.py','history.py','audit.py','integrity.py',
      'confinement.py','handover.py','device_gate.py','device_inventory.py','trust_policy.py','trust_store.py','usb_policy.py','device-trust-helper.py','tpm-unlock-helper.py','telemetry.py','telemetry_worker.py','telemetry_health.py','telemetry_query.py','telemetry_actions.py','telemetry_export.py','telemetry-helper.py')]
    +['/usr/local/share/cockpit/security_center/'+name for name in ('manifest.json','index.html','app.js','style.css','telemetry-controls.js','unlock-controls.js','usb-controls.js')]
    +['/etc/security-center/normal-devices.candidate.json','/etc/systemd/system/security-center.service','/etc/systemd/system/security-center-telemetry.service','/etc/systemd/system/security-center-apparmor.service'])


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)


class ProtectedFiles:
    def __init__(self):
        if os.geteuid()!=0:raise PermissionError('Production file operations require root')
        self._initialize('/',0,0)

    @classmethod
    def fixture(cls,root):
        """Explicit disposable test tree only, never a host-path override."""
        from pathlib import Path
        root=Path(root)
        if root.is_symlink() or not root.name.startswith('security-center-protected-') or (root/'.fixture').read_text()!='DISPOSABLE SECURITY CENTER TEST\n':
            raise ValueError('Marked disposable fixture required')
        instance=cls.__new__(cls)
        instance._initialize(str(root),os.geteuid(),os.getegid())
        return instance

    def _initialize(self,root,uid,gid):
        self.uid,self.gid=uid,gid
        self.root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:self._directory(self.root_fd)
        except BaseException:self.close();raise

    def close(self):
        if self.root_fd is not None:os.close(self.root_fd);self.root_fd=None

    def _directory(self,fd):
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.uid or info.st_mode&0o022:
            raise ValueError('Untrusted writable directory')

    def _parent(self,path,*,create=False):
        if path not in TARGETS:raise ValueError('Path outside monitor allowlist')
        parts=PurePosixPath(path).parts
        fd=os.dup(self.root_fd)
        try:
            walked=[]
            for part in parts[1:-1]:
                walked.append(part)
                try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                except FileNotFoundError:
                    if not create or '/'+('/'.join(walked))!='/etc/security-center':raise
                    os.mkdir(part,0o755,dir_fd=fd);os.fsync(fd)
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    os.fchmod(child,0o755);os.fsync(child);os.fsync(fd)
                os.close(fd);fd=child;self._directory(fd)
            return fd,parts[-1]
        except BaseException:os.close(fd);raise

    def _read(self,parent,name):
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:return {'state':'missing'},None
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=self.uid or before.st_mode&0o022 or before.st_size>LIMIT:
                raise ValueError('Unsafe installed file')
            raw=stream.read(LIMIT+1)
            if len(raw)>LIMIT:raise ValueError('File exceeds limit')
            after=os.fstat(stream.fileno())
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if identity(before)!=identity(after) or identity(after)!=identity(current):raise ValueError('File changed during read')
            record=dict(state='present',sha256=hashlib.sha256(raw).hexdigest(),uid=after.st_uid,gid=after.st_gid,
                        mode=stat.S_IMODE(after.st_mode),size=after.st_size,mtime_ns=after.st_mtime_ns)
            return record,raw

    def read(self,path):
        try:parent,name=self._parent(path)
        except FileNotFoundError:return {'state':'missing'},None
        try:return self._read(parent,name)
        finally:os.close(parent)

    def replace(self,path,raw,expected,*,mode=0o644,mtime_ns=None,checkpoint=lambda _:None):
        if not isinstance(raw,bytes) or len(raw)>LIMIT or mode not in (0o600,0o644):raise ValueError('Invalid replacement payload or permissions')
        if mtime_ns is not None and (type(mtime_ns) is not int or mtime_ns<0):raise ValueError('Invalid modification time')
        parent,name=self._parent(path,create=True);temporary=None
        try:
            if self._read(parent,name)[0]!=expected:raise ValueError('Installed file differs from expected state')
            temporary='.security-center-'+secrets.token_hex(16)
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);stream.flush()
                os.fchown(stream.fileno(),self.uid,self.gid);os.fchmod(stream.fileno(),mode)
                if mtime_ns is not None:os.utime(stream.fileno(),ns=(mtime_ns,mtime_ns))
                os.fsync(stream.fileno())
            checkpoint('payload_synced')
            if self._read(parent,name)[0]!=expected:raise ValueError('Installed file changed before replacement')
            os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent);temporary=None
            checkpoint('published')
            os.fsync(parent)
            return self._read(parent,name)[0]
        finally:
            if temporary is not None:
                try:os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)

    def remove_added(self,path,expected):
        if expected.get('state')!='present':raise ValueError('Expected installed file required')
        parent,name=self._parent(path)
        try:
            if self._read(parent,name)[0]!=expected:raise ValueError('Added file changed after installation')
            os.unlink(name,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
