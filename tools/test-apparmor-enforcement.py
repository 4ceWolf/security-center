#!/usr/bin/python3
"""Owner-run after the trial boot. Disposable named profile, no application policy edits."""
import os,pathlib,subprocess
SOURCE=r'''import json,os,pathlib,subprocess,tempfile
os.umask(0o077)
if pathlib.Path('/sys/module/apparmor/parameters/enabled').read_text().strip()!='Y':raise ValueError('Boot the AppArmor trial image first')
name='security-center-disposable-check'
if any(line.startswith(name+' ') for line in pathlib.Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()):raise ValueError('Existing test profile requires review')
folder=pathlib.Path(tempfile.mkdtemp(prefix='security-center-apparmor-test-',dir='/run'))
(folder/'allowed').write_text('fixture allowed\n');(folder/'denied').write_text('fixture denied\n')
profile=folder/'profile'
profile.write_text('abi <abi/4.0>,\ninclude <tunables/global>\nprofile '+name+' flags=(attach_disconnected) {\n include <abstractions/base>\n /usr/bin/cat rix,\n '+str(folder)+'/allowed r,\n deny '+str(folder)+'/denied r,\n}\n')
def command(args):return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
loaded=False
try:
 result=command(['/usr/bin/apparmor_parser','--replace','--skip-cache',str(profile)])
 if result.returncode:raise ValueError('Kernel rejected disposable profile')
 loaded=True
 allow=command(['/usr/bin/aa-exec','-p',name,'--','/usr/bin/cat',str(folder/'allowed')])
 deny=command(['/usr/bin/aa-exec','-p',name,'--','/usr/bin/cat',str(folder/'denied')])
 if allow.returncode!=0 or allow.stdout!=b'fixture allowed\n' or deny.returncode==0:raise ValueError('Allowed/denied kernel enforcement not established')
 print(json.dumps({'apparmor_enabled':True,'allowed_read_passed':True,'denied_read_passed':True,'scope':'Disposable named profile; not desktop application coverage'}))
finally:
 if loaded:
  if command(['/usr/bin/apparmor_parser','--remove','--skip-cache',str(profile)]).returncode:raise RuntimeError('Disposable profile removal needs administrator inspection')
 import shutil
 shutil.rmtree(folder)
'''
if __name__=='__main__':
 root=pathlib.Path('/home/user/Projects/security-center')
 result=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center AppArmor disposable kernel-enforcement check: ','/usr/bin/python3','-I','-c',SOURCE],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
 (root/'work/apparmor-enforcement-check.json').write_bytes(result.stdout);(root/'work/apparmor-enforcement-check-error.log').write_bytes(result.stderr)
 print(result.stdout.decode());print(result.stderr.decode()[-1500:]);raise SystemExit(result.returncode)
