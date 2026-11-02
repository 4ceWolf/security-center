#!/usr/bin/python3
import hashlib,json,os,shutil,subprocess
from pathlib import Path
BASE=Path('/var/lib/security-center/integrity-candidate-20261014-235319')
SOURCE=BASE/'candidate.efi'
DEST=Path('/boot/EFI/Linux/arch-linux-zen-integrity-test.efi')
MENU=Path('/boot/EFI/visor/boot.conf')
ORIGINAL=Path('/boot/EFI/Linux/arch-linux-zen.efi')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(a): return subprocess.check_output(a,timeout=30)
assert os.geteuid()==0
os.umask(0o077)
report=json.loads((BASE/'report.json').read_text())
assert sha(SOURCE)==report['candidate_sha256']
assert sha(ORIGINAL)==report['original_sha256']
assert not DEST.exists()
old=MENU.read_bytes();text=old.decode()
assert '\ndefault=0\n' in text and '\nremember_last=0\n' in text
assert 'integrity-test' not in text
assert text.split('entry {',1)[1].split('}',1)[0].find('kernel=\\EFI\\Linux\\arch-linux-zen.efi')>=0
assert shutil.disk_usage('/boot').free>SOURCE.stat().st_size+64*1024*1024
metadata=run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])
run(['/usr/bin/sbverify','--cert','/var/lib/sbctl/keys/db/db.pem',str(SOURCE)])
backup=BASE/'boot.conf.before-test'
assert not backup.exists();backup.write_bytes(old)
addition='\n# Security Center: separate integrity trial; original default remains entry 0.\nentry {\n name="Arch Linux Zen - integrity test"\n kernel=\\EFI\\Linux\\arch-linux-zen-integrity-test.efi\n icon=\\EFI\\visor\\icons\\arch.png\n}\n'
new=old+addition.encode()
tmp=DEST.with_suffix('.tmp')
try:
 with SOURCE.open('rb') as src,tmp.open('xb') as dst:
  shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
 assert sha(tmp)==report['candidate_sha256']
 os.replace(tmp,DEST)
 mt=MENU.with_suffix('.security-center.tmp')
 with mt.open('xb') as f:f.write(new);f.flush();os.fsync(f.fileno())
 os.replace(mt,MENU)
 os.sync()
 assert sha(ORIGINAL)==report['original_sha256']
 assert run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])==metadata
 run(['/usr/bin/sbverify','--cert','/var/lib/sbctl/keys/db/db.pem',str(DEST)])
 record={'test_image':str(DEST),'candidate_sha256':sha(DEST),'menu':str(MENU),
         'menu_before_sha256':hashlib.sha256(old).hexdigest(),'menu_after_sha256':sha(MENU),
         'menu_backup':str(backup),'original_image_unchanged':True,'luks_metadata_unchanged':True,
         'default_unchanged':True,'boot_test':'pending','reboot_initiated':False}
 (BASE/'staging.json').write_text(json.dumps(record,indent=2))
 print(json.dumps(record,indent=2))
except Exception:
 # Restore this transaction's menu only; leave a validated extra image harmlessly unselected.
 if MENU.read_bytes()==new:MENU.write_bytes(old);os.sync()
 raise
