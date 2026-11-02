"""Protected monitor backups and restartable file transaction; no deployment CLI.

Caller separately verifies reviewed release and approved-baseline continuity,
coordinates services, and obtains replacement-baseline approval. No boot writes.
"""
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from protected_files import TARGETS,LIMIT


def sha(raw):return hashlib.sha256(raw).hexdigest()


class TransactionStore:
    def __init__(self,files):
        self.files=files;self.directory=None;self.lock=None
        parent=os.dup(files.root_fd)
        try:
            for component in ('var','lib'):
                child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                os.close(parent);parent=child;files._directory(parent)
            try:os.mkdir('security-center-updates',0o700,dir_fd=parent);os.fsync(parent)
            except FileExistsError:pass
            self.directory=os.open('security-center-updates',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            self._private_directory(self.directory)
            self.lock=os.open('update.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=self.directory)
            self._private_file(self.lock,LIMIT)
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:self.close();raise
        finally:os.close(parent)

    def close(self):
        for name in ('lock','directory'):
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)

    def _private_directory(self,fd):
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.files.uid or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Unsafe transaction directory')

    def _private_file(self,fd,limit):
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=self.files.uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit:raise ValueError('Unsafe transaction file')

    def _folder(self,token):
        if not re.fullmatch(r'txn-[0-9a-f]{32}',token):raise ValueError('Invalid transaction identifier')
        fd=os.open(token,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.directory)
        try:self._private_directory(fd);return fd
        except BaseException:os.close(fd);raise

    def _read(self,folder,name,limit=LIMIT):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
        with os.fdopen(fd,'rb') as stream:
            self._private_file(stream.fileno(),limit)
            raw=stream.read(limit+1)
            if len(raw)>limit:raise ValueError('Transaction data too large')
            return raw

    def _write(self,folder,name,raw):
        temporary='.journal-'+secrets.token_hex(16)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=folder)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,name,src_dir_fd=folder,dst_dir_fd=folder);os.fsync(folder)
        finally:
            try:os.unlink(temporary,dir_fd=folder)
            except FileNotFoundError:pass

    def _save(self,folder,record):
        raw=json.dumps(record,sort_keys=True,allow_nan=False).encode()
        if len(raw)>65536:raise ValueError('Journal too large')
        self._write(folder,'record.json',raw)

    def prepare(self,contents,expected_before,reviewed_release_sha):
        if not isinstance(contents,dict) or not contents or not set(contents).issubset(TARGETS) or set(contents)!=set(expected_before):raise ValueError('Invalid transaction targets')
        if not isinstance(reviewed_release_sha,str) or not re.fullmatch('[0-9a-f]{64}',reviewed_release_sha):raise ValueError('Reviewed release digest required')
        backups={}
        # Validate every target before any transaction state or installed writes.
        for path,raw in contents.items():
            if not isinstance(raw,bytes) or len(raw)>LIMIT:raise ValueError('Invalid payload')
            before,old=self.files.read(path)
            if before!=expected_before[path]:raise ValueError('Observed state changed before preparation')
            if old is not None and (before['gid']!=self.files.gid or before['mode'] not in (0o600,0o644)):
                raise ValueError('Existing metadata cannot be restored by this transaction')
            backups[path]=(before,old)
        token='txn-'+secrets.token_hex(16);os.mkdir(token,0o700,dir_fd=self.directory);os.fsync(self.directory)
        folder=self._folder(token)
        try:
            entries=[]
            for index,(path,raw) in enumerate(sorted(contents.items())):
                before,old=backups[path]
                if old is not None:self._write(folder,f'{index}.old',old)
                self._write(folder,f'{index}.new',raw)
                after=dict(state='present',sha256=sha(raw),uid=self.files.uid,gid=self.files.gid,mode=0o644,size=len(raw),mtime_ns=time.time_ns())
                entries.append(dict(path=path,before=before,after=after))
            record=dict(schema=1,phase='prepared',reviewed_release_sha=reviewed_release_sha,entries=entries)
            self._save(folder,record)
            return token
        finally:os.close(folder)

    def _load(self,folder):
        record=json.loads(self._read(folder,'record.json',65536))
        if record.get('schema')!=1 or record.get('phase') not in ('prepared','applying','applied','rolling_back','rolled_back'):raise ValueError('Invalid transaction state')
        entries=record.get('entries')
        if not isinstance(entries,list) or not 1<=len(entries)<=len(TARGETS):raise ValueError('Invalid entries')
        paths=[entry['path'] for entry in entries]
        if len(set(paths))!=len(paths) or not set(paths).issubset(TARGETS):raise ValueError('Invalid journal paths')
        for index,item in enumerate(entries):
            for suffix,key in (('new','after'),('old','before')):
                metadata=item[key]
                if key=='before' and metadata=={'state':'missing'}:continue
                if metadata.get('state')!='present' or any(type(metadata.get(k)) is not int or metadata[k]<0 for k in ('uid','gid','mode','size','mtime_ns')):raise ValueError('Invalid journal metadata')
                if metadata['uid']!=self.files.uid or metadata['gid']!=self.files.gid or metadata['mode'] not in (0o600,0o644):raise ValueError('Untrusted journal ownership or mode')
                raw=self._read(folder,f'{index}.{suffix}')
                if len(raw)!=metadata['size'] or sha(raw)!=metadata['sha256']:raise ValueError('Backup or payload mismatch')
        return record

    def run(self,token,*,rollback=False,checkpoint=lambda _:None):
        folder=self._folder(token)
        try:
            record=self._load(folder)
            if not rollback and record['phase'] in ('rolling_back','rolled_back'):raise ValueError('Cannot reapply a rolled-back transaction')
            # Refuse all mutation if any destination has an unrelated change.
            for item in record['entries']:
                if self.files.read(item['path'])[0] not in (item['before'],item['after']):raise ValueError('Installed files conflict with journal')
            record['phase']='rolling_back' if rollback else 'applying';self._save(folder,record)
            checkpoint('intent_saved')
            for index,item in enumerate(record['entries']):
                desired=item['before'] if rollback else item['after']
                current=self.files.read(item['path'])[0]
                if current!=desired:
                    if desired=={'state':'missing'}:self.files.remove_added(item['path'],current)
                    else:
                        raw=self._read(folder,f'{index}.'+('old' if rollback else 'new'))
                        result=self.files.replace(item['path'],raw,current,mode=desired['mode'],mtime_ns=desired['mtime_ns'],checkpoint=lambda stage,index=index:checkpoint(f'{index}:{stage}'))
                        if result!=desired:raise ValueError('Installed metadata differs from journal')
                checkpoint(f'{index}:verified')
            record['phase']='rolled_back' if rollback else 'applied';self._save(folder,record)
            return record
        finally:os.close(folder)
