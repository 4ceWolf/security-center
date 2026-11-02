"""Fixed-path deployment adapter. Caller holds the protected update lock."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

STATE = '/var/lib/security-center-trust'
LIB = '/usr/local/lib/security-center'


def directory(path, private=False):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Untrusted deployment directory')
        if private and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise ValueError('Private deployment state required')
    finally: os.close(fd)


class TrustInitialization:
    def __init__(self):
        if os.geteuid() != 0: raise PermissionError('Administrator access required')

    def prepare(self):
        directory('/var/lib')
        try: os.lstat(STATE)
        except FileNotFoundError: return 'create'
        # Verify through the frozen installer model: an earlier file rollback
        # can legitimately preserve state while removing the installed helper.
        directory(STATE, private=True)
        from trust_store import Store
        Store().read({'schema_version':1,'internal':[],'trusted_external':[]})
        return 'preserve'

    def _run(self, initialize, seed=None):
        # Imports come only from the already validated installed release.
        directory(LIB)
        script = """import sys,json,pathlib
sys.path.insert(0,'/usr/local/lib/security-center')
from trust_store import Store
from trust_policy import decode,validate
seed=validate(decode(sys.stdin.buffer.read(262145))) if sys.argv[1]=='initialize' else {'schema_version':1,'internal':[],'trusted_external':[]}
store=Store(initialize=sys.argv[1]=='initialize')
policy=store.read(seed)
print(json.dumps({'valid':True}))
"""
        with tempfile.TemporaryDirectory(prefix='security-center-import-',dir='/run') as cache:
            result = subprocess.run(['/usr/bin/python3','-I','-B','-X','pycache_prefix='+cache,'-c',script,'initialize' if initialize else 'verify'],
                                    input=seed or b'',capture_output=True,timeout=15,check=False,
                                    env={'PATH':'/usr/bin','LC_ALL':'C'})
        if result.returncode or result.stdout != b'{"valid": true}\n':
            raise RuntimeError('Trust initialization/verification failed; preserve state for recovery')
        directory(STATE, private=True)

    def initialize(self, seed):
        directory('/var/lib')
        if os.path.lexists(STATE): raise ValueError('Refuse to initialize existing trust state')
        self._run(True, seed)
        fd = os.open('/var/lib',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def verify(self):
        directory(STATE, private=True)
        self._run(False)
