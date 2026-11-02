#!/usr/bin/python3
"""Promote the boot-tested candidate; retain a signed recovery entry."""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
BASE=Path('/var/lib/security-center/integrity-candidate-20261014-235319')
NORMAL=Path('/boot/EFI/Linux/arch-linux-zen.efi')
TEST=Path('/boot/EFI/Linux/arch-linux-zen-integrity-test.efi')
RECOVERY=Path('/boot/EFI/Linux/arch-linux-zen-pre-integrity.efi')
MENU=Path('/boot/EFI/visor/boot.conf')
CMDLINE=Path('/etc/miku-boot/zen.cmdline')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(a):return subprocess.check_output(a,timeout=30)
def atomic_bytes(path,data):
 tmp=path.with_name(path.name+'.security-center-tmp')
 with tmp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.chmod(tmp,0o644)
 os.replace(tmp,path)
def atomic_copy(src,dst):
 tmp=dst.with_name(dst.name+'.security-center-tmp')
 with src.open('rb') as a,tmp.open('xb') as b:
  shutil.copyfileobj(a,b);b.flush();os.fsync(b.fileno())
 assert sha(src)==sha(tmp)
 os.replace(tmp,dst)
assert os.geteuid()==0
os.umask(0o077)
assert '[integrity]' in Path('/sys/kernel/security/lockdown').read_text()
assert 'lockdown=integrity' in Path('/proc/cmdline').read_text().split()
r=json.loads((BASE/'report.json').read_text());s=json.loads((BASE/'staging.json').read_text())
assert sha(NORMAL)==r['original_sha256'] and sha(TEST)==r['candidate_sha256']
assert sha(MENU)==s['menu_after_sha256']
assert not RECOVERY.exists()
assert shutil.disk_usage('/boot').free>TEST.stat().st_size*2+64*1024*1024
cert='/var/lib/sbctl/keys/db/db.pem'
for p in (NORMAL,TEST):run(['/usr/bin/sbverify','--cert',cert,str(p)])
oldcmd=CMDLINE.read_bytes();oldmenu=MENU.read_bytes()
assert not any(x.startswith('lockdown=') for x in oldcmd.decode().split())
newcmd=(oldcmd.decode().strip()+' lockdown=integrity\n').encode()
assert newcmd.decode().strip()==(BASE/'cmdline').read_text().strip()
newmenu=oldmenu.decode().replace('name="Arch Linux Zen - integrity test"','name="Arch Linux Zen - pre-integrity recovery"').replace('kernel=\\EFI\\Linux\\arch-linux-zen-integrity-test.efi','kernel=\\EFI\\Linux\\arch-linux-zen-pre-integrity.efi').replace('# Security Center: separate integrity trial; original default remains entry 0.','# Security Center: signed pre-integrity recovery; normal default remains entry 0.').encode()
assert b'integrity-test.efi' not in newmenu and b'\ndefault=0\n' in newmenu
metadata=run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])
backup=BASE/'promotion';backup.mkdir(mode=0o700)
(backup/'zen.cmdline.before').write_bytes(oldcmd);(backup/'boot.conf.before').write_bytes(oldmenu)
atomic_copy(NORMAL,RECOVERY)
run(['/usr/bin/sbverify','--cert',cert,str(RECOVERY)])
# Recovery menu is committed before replacing the normal image.
atomic_bytes(MENU,newmenu);os.sync()
atomic_bytes(CMDLINE,newcmd)
atomic_copy(TEST,NORMAL);os.sync()
assert sha(NORMAL)==r['candidate_sha256'] and sha(RECOVERY)==r['original_sha256']
run(['/usr/bin/sbverify','--cert',cert,str(NORMAL)])
assert run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])==metadata
result={'normal':str(NORMAL),'normal_sha256':sha(NORMAL),'recovery':str(RECOVERY),
 'recovery_sha256':sha(RECOVERY),'cmdline':str(CMDLINE),'cmdline_sha256':sha(CMDLINE),
 'menu_sha256':sha(MENU),'default_index':0,'luks_metadata_unchanged':True,
 'future_build_source_updated':True,'owner_sound_sleep_wake_wifi':'reported passed',
 'normal_path_reboot_test':'pending; identical candidate already boot-tested'}
(backup/'result.json').write_text(json.dumps(result,indent=2))
# Remove only the now redundant test copy after validating both retained images.
assert sha(TEST)==r['candidate_sha256'];TEST.unlink();os.sync()
print(json.dumps(result,indent=2))
