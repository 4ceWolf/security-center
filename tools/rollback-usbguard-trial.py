#!/usr/bin/python3
"""Owner-invoked rollback of this exact USBGuard trial; never runs automatically."""
import os,pathlib,subprocess
BASE=pathlib.Path('/home/user/Projects/security-center')
READER=r'''import hashlib,json,os,pathlib,stat,subprocess,tempfile
os.umask(0o077)
backup=pathlib.Path('/var/lib/security-center-usbguard-trial-x8y8a10y')
s=backup.lstat()
if not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_mode&0o077:raise ValueError('Unsafe backup directory')
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_mode&0o077 or s.st_size>65536:raise ValueError('Unsafe backup file')
  raw=f.read(65537)
  if len(raw)>65536:raise ValueError('Oversized backup')
  return raw
parent=pathlib.Path('/etc/usbguard')
for name,digest in [('rules.conf','544cb3ef7774b444206121e649cf956cdbf3d8094db984d5040ccca7c9fe4cff'),('usbguard-daemon.conf','76ae7da93d8ac00521c7fd1387ce20f81c8942f7e6b335d53cef568ec59bbdae')]:
 if hashlib.sha256(read(parent/name)).hexdigest()!=digest:raise ValueError('Current policy changed; review instead of blind rollback')
state=json.loads(read(backup/'state.json'))
restored={name:read(backup/name) for name in ('rules.conf','usbguard-daemon.conf')}
for path,value in state['defaults'].items():
 p=pathlib.Path(path)
 if not path.startswith('/sys/devices/') or p.name!='authorized_default' or value not in ('0','1','2') or str(p.resolve())!=path:raise ValueError('Invalid saved controller state')
subprocess.run(['/usr/bin/systemctl','disable','--now','usbguard.service'],check=True,timeout=30)
for name,raw in restored.items():
 fd,tmp=tempfile.mkstemp(prefix='.security-center-',dir=parent)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(tmp,parent/name)
for path,value in state['defaults'].items():pathlib.Path(path).write_text(value)
print(json.dumps({'rolled_back':True,'usbguard_enabled':False,'controller_defaults_restored':True,'other_protections_changed':False}))
'''
if __name__=='__main__':
 result=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center: roll back the exact postboot USBGuard trial: ','/usr/bin/python3','-I','-c',READER],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=90)
 (BASE/'work/usbguard-owner-rollback.log').write_bytes(result.stdout+result.stderr)
 print((result.stdout+result.stderr).decode(errors='replace')[-1500:]);raise SystemExit(result.returncode)
