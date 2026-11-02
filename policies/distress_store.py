"""Undeployed durable-state protocol. Witness is an external trusted-adapter contract.

No TPM/PAM/shutdown code. A file-backed witness is NOT antirollback protection.
Callers serialize operations; production needs an authenticated exclusive writer.
"""
import hashlib,json,os,pathlib,tempfile
from dataclasses import asdict
from distress import State

LIMIT=4096

def encode(state):
    if not isinstance(state,State) or not state.valid():
        raise ValueError('Invalid state')
    return (json.dumps({'schema_version':1,'state':asdict(state)},sort_keys=True,separators=(',',':'))+'\n').encode()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw):
    if len(raw)>LIMIT:raise ValueError('Oversized state')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate state field')
            result[key]=value
        return result
    data=json.loads(raw,object_pairs_hook=unique)
    if set(data)!={'schema_version','state'} or type(data['schema_version']) is not int or data['schema_version']!=1:
        raise ValueError('Invalid state envelope')
    state=State(**data['state'])
    if encode(state)!=raw:raise ValueError('Noncanonical or invalid state')
    return state

class Store:
    def __init__(self,directory,witness):
        self.directory=pathlib.Path(directory)
        self.path=self.directory/'state.json'
        self.witness=witness

    def read_raw(self):
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            import stat
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:
                raise ValueError('Unsafe state permissions/type')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(LIMIT+1)
            decode(raw)
            return raw
        finally:os.close(fd)

    def verified(self):
        # Two witness reads also reject a concurrent commit crossing the file read.
        first=self.witness.read()
        raw=self.read_raw()
        second=self.witness.read()
        if not isinstance(first,str) or first!=second or digest(raw)!=first:
            raise ValueError('State/witness disagreement: require manual recovery')
        return decode(raw)

    def commit(self,state,expected,checkpoint=lambda _:None):
        """Durably publish file, then advance witness. Any disagreement denies trust.

        expected=None is explicit first provisioning, never automatic boot repair.
        checkpoint is a test fault-injection hook. No recovery silently resets witness.
        """
        if expected is None:
            if self.path.exists() or self.witness.read() is not None:
                raise ValueError('Already provisioned or incomplete prior transaction')
        else:
            previous=self.verified()
            if digest(encode(previous))!=expected:raise ValueError('Stale transaction')
            if state.sequence!=previous.sequence+1 or state.policy_digest!=previous.policy_digest:
                raise ValueError('Sequence or original policy changed')
        raw=encode(state)
        fd,temp=tempfile.mkstemp(prefix='.distress-',dir=self.directory)
        try:
            with os.fdopen(fd,'wb') as out:
                out.write(raw);out.flush();os.fsync(out.fileno())
            checkpoint('temporary_synced')
            os.replace(temp,self.path)
            folder=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(folder)
            finally:os.close(folder)
            checkpoint('state_synced')
            self.witness.compare_exchange(expected,digest(raw))
            checkpoint('witness_committed')
            if self.verified()!=state:raise ValueError('Commit verification failed')
            return digest(raw)
        finally:
            if os.path.exists(temp):os.unlink(temp)
