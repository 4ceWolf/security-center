#!/usr/bin/python3
"""Auditable bootstrap text to run with isolated Python after root authentication.

The launcher must embed these exact reviewed bytes in the authentication command;
executing this editable project file as root would defeat runtime capture.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

NAMES=frozenset(['tools/'+name for name in
 ('deploy-monitor.py','monitor_deployment.py','protected_files.py','protected_transaction.py',
  'service_transaction.py','monitor_services.py','trust_initialization.py',
  'baseline_migration.py','release_binding.py','build-monitor-release.py')]+['securityd/integrity.py','policies/device_gate.py','policies/trust_policy.py','policies/trust_store.py'])


def capture(path, expected):
    if len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):raise ValueError('Invalid runtime digest')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>1048576:raise ValueError('Invalid runtime file')
        raw=stream.read(1048577)
    if len(raw)>1048576 or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Runtime differs from reviewed digest')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('Duplicate runtime field')
            result[k]=v
        return result
    data=json.loads(raw,object_pairs_hook=unique)
    if set(data)!= {'schema','files'} or data['schema']!=1 or set(data['files'])!=NAMES:raise ValueError('Unexpected runtime members')
    for name,source in data['files'].items():
        if not isinstance(source,str) or len(source.encode())>262144:raise ValueError('Invalid source member')
        compile(source,name,'exec')
    return data['files']


def main():
    if os.geteuid()!=0:raise PermissionError('Administrator authentication required')
    if len(sys.argv)<4:raise ValueError('Runtime path, digest and operation required')
    files=capture(sys.argv[1],sys.argv[2])
    # The private runtime is ephemeral. Transaction state/backups remain persistent.
    parent=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(parent)
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Untrusted runtime parent')
    finally:os.close(parent)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='security-center-installer-',dir='/run') as temp:
        folder=Path(temp)
        for name,source in files.items():
            path=folder/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_text(source);path.chmod(0o600)
        command=['/usr/bin/python3','-I',str(folder/'tools/deploy-monitor.py'),*sys.argv[3:]]
        result=subprocess.run(command,env={'PATH':'/usr/bin','LC_ALL':'C'},check=False)
        return result.returncode

if __name__=='__main__':sys.exit(main())
