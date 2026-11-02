#!/usr/bin/python3
"""Owner-requested rollback of normal boot image and build command line."""
import hashlib,json,os,shutil
from pathlib import Path
base=Path('/var/lib/security-center/integrity-candidate-20261014-235319')
r=json.loads((base/'promotion/result.json').read_text())
assert os.geteuid()==0
normal=Path(r['normal']);recovery=Path(r['recovery']);cmd=Path(r['cmdline'])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(normal)==r['normal_sha256'], 'Normal image changed since promotion; review needed'
assert sha(recovery)==r['recovery_sha256'], 'Recovery image changed; review needed'
assert sha(cmd)==r['cmdline_sha256'], 'Build command line changed; review needed'
old=(base/'promotion/zen.cmdline.before').read_bytes()
tmp=normal.with_name(normal.name+'.rollback-tmp')
with recovery.open('rb') as a,tmp.open('xb') as b:
 shutil.copyfileobj(a,b);b.flush();os.fsync(b.fileno())
assert sha(tmp)==r['recovery_sha256']
os.replace(tmp,normal)
tmpcmd=cmd.with_name(cmd.name+'.rollback-tmp')
with tmpcmd.open('xb') as f:f.write(old);f.flush();os.fsync(f.fileno())
os.chmod(tmpcmd,0o644);os.replace(tmpcmd,cmd);os.sync()
print('Pre-integrity image and command line restored. Reboot to leave running lockdown. Recovery entry retained.')
