#!/usr/bin/python3
"""Freeze installer source bytes for a hash-pinned privileged bootstrap."""
import hashlib
import json
from pathlib import Path
import tempfile

ROOT=Path(__file__).resolve().parents[1]
NAMES=('deploy-monitor.py','monitor_deployment.py','protected_files.py','protected_transaction.py',
       'service_transaction.py','monitor_services.py','trust_initialization.py',
       'baseline_migration.py','release_binding.py','build-monitor-release.py')


def build():
    files={}
    for name in ['tools/'+name for name in NAMES]+['securityd/integrity.py','policies/device_gate.py','policies/trust_policy.py','policies/trust_store.py']:
        path=ROOT/name
        if path.is_symlink():raise ValueError('Installer source symlink')
        raw=path.read_bytes()
        if len(raw)>262144:raise ValueError('Oversized installer source')
        compile(raw,name,'exec')
        files[name]=raw.decode('utf-8')
    raw=(json.dumps({'schema':1,'files':files},sort_keys=True)+'\n').encode()
    parent=ROOT/'work/installer';parent.mkdir(exist_ok=True)
    folder=Path(tempfile.mkdtemp(prefix='runtime-',dir=parent))
    (folder/'runtime.json').write_bytes(raw)
    (folder/'review.json').write_text(json.dumps({'sha256':hashlib.sha256(raw).hexdigest(),
      'files':{n:hashlib.sha256(s.encode()).hexdigest() for n,s in files.items()},
      'installed':False,'baseline_approved':False},indent=2)+'\n')
    return folder,hashlib.sha256(raw).hexdigest()

if __name__=='__main__':
    folder,sha=build();print(json.dumps({'runtime':str(folder/'runtime.json'),'sha256':sha,'files':len(NAMES)+4,'installed':False}))
