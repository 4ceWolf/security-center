#!/usr/bin/python3
"""Explicit rollback; refuses to overwrite subsequently modified files."""
import hashlib,json,os
from pathlib import Path
base=Path('/var/lib/security-center/integrity-candidate-20261014-235319')
r=json.loads((base/'staging.json').read_text())
assert os.geteuid()==0
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
menu=Path(r['menu']);image=Path(r['test_image']);backup=Path(r['menu_backup'])
assert sha(menu)==r['menu_after_sha256'], 'Menu changed since staging; merge manually'
assert sha(image)==r['candidate_sha256'], 'Test image changed since staging'
assert sha(backup)==r['menu_before_sha256']
tmp=menu.with_suffix('.rollback.tmp')
with tmp.open('xb') as f:f.write(backup.read_bytes());f.flush();os.fsync(f.fileno())
os.replace(tmp,menu)
os.sync()
image.unlink();os.sync()
print('Original menu restored; separate test image removed; known-good image and LUKS unchanged')
