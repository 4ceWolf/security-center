#!/usr/bin/python3
"""Owner-authorized runtime USBGuard trial; fixed captured data, no boot enablement."""
import hashlib,json,os,pathlib,subprocess
BASE=pathlib.Path('/home/user/Projects/security-center')
READER=r'''import fcntl,hashlib,json,os,pathlib,stat,subprocess,tempfile
os.umask(0o077)
base=pathlib.Path('/home/user/Projects/security-center')
def command(args,accepted=(0,)):
 r=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if r.returncode not in accepted:raise RuntimeError('Fixed operation failed: '+args[0])
 if len(r.stdout)>262144:raise ValueError('Output exceeds bound')
 return r.stdout.strip()
def regular(path,bound):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_size>bound:raise ValueError('Invalid file')
  raw=stream.read(bound+1)
  if len(raw)>bound:raise ValueError('Oversized file')
  return raw
payloads={}
for name,expected in [('usbguard-postboot-candidate.rules','544cb3ef7774b444206121e649cf956cdbf3d8094db984d5040ccca7c9fe4cff'),('usbguard-postboot-candidate.conf','76ae7da93d8ac00521c7fd1387ce20f81c8942f7e6b335d53cef568ec59bbdae')]:
 raw=regular(base/'work'/name,65536)
 if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Candidate changed')
 payloads[name]=raw
observed=regular(base/'work/usbguard-observed-policy.txt',65536)
if command(['/usr/bin/usbguard','generate-policy','--with-ports']).encode()!=observed.rstrip(b'\n'):raise ValueError('Devices changed; recapture/review')
if command(['/usr/bin/systemctl','is-active','usbguard.service'],(0,3,4))!='inactive':raise ValueError('Trial requires inactive service')
if command(['/usr/bin/systemctl','is-enabled','usbguard.service'],(0,1,4))!='disabled':raise ValueError('Trial requires disabled service')
parent=pathlib.Path('/etc/usbguard');meta=parent.lstat()
if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:raise ValueError('Unsafe config directory')
# Reject inherited additional policies. New config references only the captured file.
existing={name:regular(parent/name,65536) for name in ('rules.conf','usbguard-daemon.conf')}
for name in existing:
 s=(parent/name).lstat()
 if s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Unsafe existing config')
authorized={str(p.resolve()):p.read_text().strip() for p in pathlib.Path('/sys/bus/usb/devices').glob('*/authorized') if ':' not in p.parent.name}
defaults={str(p.resolve()):p.read_text().strip() for p in pathlib.Path('/sys/bus/usb/devices').glob('usb*/authorized_default')}
if len(authorized)!=7 or not defaults or any(v not in ('0','1','2') for v in defaults.values()):raise ValueError('Unexpected USB state')
backup=pathlib.Path(tempfile.mkdtemp(prefix='security-center-usbguard-trial-',dir='/var/lib'))
for name,raw in existing.items():(backup/name).write_bytes(raw)
state={'authorized':authorized,'defaults':defaults,'service_enabled_before':False}
(backup/'state.json').write_text(json.dumps(state,indent=2))
def write(name,raw):
 fd,tmp=tempfile.mkstemp(prefix='.security-center-',dir=parent)
 try:
  with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
  os.replace(tmp,parent/name)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
try:
 write('rules.conf',payloads['usbguard-postboot-candidate.rules'])
 write('usbguard-daemon.conf',payloads['usbguard-postboot-candidate.conf'])
 command(['/usr/bin/systemctl','start','usbguard.service'])
 if command(['/usr/bin/systemctl','is-active','usbguard.service'])!='active':raise ValueError('Daemon not active')
 after={str(p.resolve()):p.read_text().strip() for p in pathlib.Path('/sys/bus/usb/devices').glob('*/authorized') if ':' not in p.parent.name}
 if after!=authorized:raise ValueError('Existing device state changed')
 rules=command(['/usr/bin/usbguard','list-rules'])
 parameters={k:command(['/usr/bin/usbguard','get-parameter',k]) for k in ('ImplicitPolicyTarget','InsertedDevicePolicy')}
 if parameters!={'ImplicitPolicyTarget':'block','InsertedDevicePolicy':'apply-policy'}:raise ValueError('Unexpected runtime policy')
 report={'active':True,'enabled_at_boot':False,'existing_device_states_preserved':True,'backup':str(backup),'parameters':parameters,'present_device_policy_from_captured_config':'keep','runtime_rules':rules,'rules_sha256':hashlib.sha256(payloads['usbguard-postboot-candidate.rules']).hexdigest(),'physical_reconnect_tested':False,'scope':'Runtime postboot trial; pre-existing devices kept, future insertions evaluated; not preboot protection'}
 (backup/'receipt.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
except BaseException:
 command(['/usr/bin/systemctl','stop','usbguard.service'],(0,1,3))
 for name,raw in existing.items():write(name,raw)
 for path,value in defaults.items():pathlib.Path(path).write_text(value)
 # Restore only devices whose authorization changed during this failed trial.
 for path,value in authorized.items():
  p=pathlib.Path(path)
  if p.exists() and p.read_text().strip()!=value:p.write_text(value)
 (backup/'rollback.json').write_text(json.dumps({'automatic_rollback':True,'boot_enablement_changed':False}))
 raise
'''
def main():
 os.umask(0o077)
 r=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center: trial postboot USB protection while preserving connected devices: ','/usr/bin/python3','-I','-c',READER],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
 (BASE/'work/usbguard-trial-output.json').write_bytes(r.stdout);(BASE/'work/usbguard-trial-error.log').write_bytes(r.stderr)
 if r.returncode:print(r.stderr.decode(errors='replace')[-2000:]);raise SystemExit(r.returncode)
 report=json.loads(r.stdout);print(json.dumps({k:v for k,v in report.items() if k!='runtime_rules'},indent=2))
if __name__=='__main__':main()
