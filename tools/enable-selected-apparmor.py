#!/usr/bin/python3
"""Staged owner-authorized post-trial step; refuses a non-AppArmor boot."""
import os,pathlib,subprocess
SOURCE=r'''import fcntl,hashlib,json,os,pathlib,stat,subprocess
if os.geteuid()!=0:raise PermissionError('Administrator required')
if pathlib.Path('/sys/module/apparmor/parameters/enabled').read_text().strip()!='Y':raise ValueError('Verify the AppArmor trial boot first')
line=pathlib.Path('/proc/cmdline').read_text().split()
if 'apparmor=1' not in line or 'lockdown=integrity' not in line:raise ValueError('Unexpected trial security state')
expected={'/etc/apparmor.d/usr.sbin.avahi-daemon':'5b3e1b4aed4f4b3d3ef0143a7caa46e348585c2ff559bdd29be7f4db9621a821','/etc/apparmor.d/lsb_release':'c9d3d976dfb914adbc0cd5f59b51595a8af85f6d67f2c21da1f1f0dd050f1399'}
for name,digest in expected.items():
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe profile')
  if hashlib.sha256(stream.read()).hexdigest()!=digest:raise ValueError('Profile changed since offline review')
unit='/etc/systemd/system/security-center-apparmor.service'
fd=os.open(unit,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as stream:
 info=os.fstat(stream.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe selected-profile unit')
 if hashlib.sha256(stream.read()).hexdigest()!='04ef70cf150496a5ee415cbc632d3bb33989ab26ac4576612da0f8ac38f17b48':raise ValueError('Selected-profile unit differs from reviewed release')
parent=pathlib.Path('/var/lib/security-center-updates').lstat()
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or parent.st_mode&0o077:raise ValueError('Unsafe update lock directory')
lock=os.open('/var/lib/security-center-updates/update.lock',os.O_RDONLY|os.O_NOFOLLOW)
info=os.fstat(lock)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('Unsafe update lock')
fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
try:
 subprocess.run(['/usr/bin/systemctl','start','security-center-apparmor.service'],check=True,capture_output=True,timeout=45)
 profiles=pathlib.Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()
 if 'avahi-daemon (enforce)' not in profiles or 'lsb_release (enforce)' not in profiles:raise ValueError('Selected kernel profiles not enforcing')
 subprocess.run(['/usr/bin/systemctl','enable','security-center-apparmor.service'],check=True,capture_output=True,timeout=30)
 print(json.dumps({'selected_profiles_enforcing':['avahi-daemon','lsb_release'],'enabled_at_future_boots':True,'package_wide_service_enabled_by_this_tool':False,'authentication_profile_requested':False,'desktop_coverage_verified':False,'existing_process_attachment':'Not inferred; inspect live labels separately'}))
finally:os.close(lock)
'''
if __name__=='__main__':
 root=pathlib.Path('/home/user/Projects/security-center')
 result=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center selected AppArmor profiles after successful trial boot: ','/usr/bin/python3','-I','-c',SOURCE],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
 (root/'work/apparmor-selected-enablement.json').write_bytes(result.stdout);(root/'work/apparmor-selected-enablement-error.log').write_bytes(result.stderr)
 print(result.stdout.decode());print(result.stderr.decode()[-1500:]);raise SystemExit(result.returncode)
