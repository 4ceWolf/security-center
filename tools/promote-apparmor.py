#!/usr/bin/python3
"""Review first; apply only after owner hardware-trial acceptance and exact approval.
Retain the signed pre-AppArmor recovery entry; never change TPM/LUKS policy.
"""
import argparse,fcntl,hashlib,json,os,shutil,stat,subprocess
from pathlib import Path
BASE=Path('/var/lib/security-center/apparmor-candidate-20261020-153225')
NORMAL=Path('/boot/EFI/Linux/arch-linux-zen.efi')
TEST=Path('/boot/EFI/Linux/arch-linux-zen-apparmor-test.efi')
RECOVERY=Path('/boot/EFI/Linux/arch-linux-zen-pre-apparmor.efi')
MENU=Path('/boot/EFI/visor/boot.conf')
CMDLINE=Path('/etc/miku-boot/zen.cmdline')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(a):return subprocess.check_output(a,timeout=30)
def atomic_bytes(path,data):
 tmp=path.with_name(path.name+'.security-center-tmp')
 with tmp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.chmod(tmp,0o644)
 os.replace(tmp,path)
 directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(directory)
 finally:os.close(directory)
def atomic_copy(src,dst):
 tmp=dst.with_name(dst.name+'.security-center-tmp')
 with src.open('rb') as a,tmp.open('xb') as b:
  shutil.copyfileobj(a,b);b.flush();os.fsync(b.fileno())
 assert sha(src)==sha(tmp)
 os.replace(tmp,dst)
 directory=os.open(dst.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(directory)
 finally:os.close(directory)
parser=argparse.ArgumentParser()
mode=parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--review',action='store_true')
mode.add_argument('--apply',action='store_true')
parser.add_argument('--approved-review-sha256')
parser.add_argument('--owner-trial-passed',action='store_true')
args=parser.parse_args()
assert os.geteuid()==0
os.umask(0o077)
parent=Path('/var/lib/security-center-updates').lstat()
assert stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o077
lock=os.open('/var/lib/security-center-updates/update.lock',os.O_RDONLY|os.O_NOFOLLOW)
info=os.fstat(lock)
assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
assert '[integrity]' in Path('/sys/kernel/security/lockdown').read_text()
assert 'lockdown=integrity' in Path('/proc/cmdline').read_text().split()
assert 'apparmor=1' in Path('/proc/cmdline').read_text().split()
assert Path('/sys/module/apparmor/parameters/enabled').read_text().strip()=='Y'
assert run(['/usr/bin/systemctl','is-active','security-center-apparmor.service']).strip()==b'active'
r=json.loads((BASE/'report.json').read_text());s=json.loads((BASE/'staging.json').read_text())
assert r['original_sha256']=='df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987'
assert r['candidate_sha256']=='9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2'
assert s['menu_after_sha256']=='935952813f2fe2452ca7506aefd7a300e561de37b071b75a1353a3515eb70316'
assert sha(NORMAL)==r['original_sha256'] and sha(TEST)==r['candidate_sha256']
assert sha(MENU)==s['menu_after_sha256']
assert not RECOVERY.exists()
# Only the recovery copy needs extra image space: the already staged test image
# will atomically replace the normal path after recovery is durable and selectable.
required_free=NORMAL.stat().st_size+65*1024*1024
assert shutil.disk_usage('/boot').free>required_free
assert NORMAL.parent.stat().st_dev==TEST.parent.stat().st_dev
cert='/var/lib/sbctl/keys/db/db.pem'
for p in (NORMAL,TEST):run(['/usr/bin/sbverify','--cert',cert,str(p)])
oldcmd=CMDLINE.read_bytes();oldmenu=MENU.read_bytes()
assert hashlib.sha256(oldcmd).hexdigest()=='e5fb9b71aeca275dd894ba339c870d0af7dad77aa68995248107611e00227d75'
assert 'lockdown=integrity' in oldcmd.decode().split()
assert not any(x.startswith(('apparmor=','lsm=')) for x in oldcmd.decode().split())
newcmd=(oldcmd.decode().strip()+' apparmor=1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf\n').encode()
assert newcmd.decode().strip()==(BASE/'cmdline').read_text().strip()
newmenu=oldmenu.decode().replace('name="Arch Linux Zen - AppArmor test"','name="Arch Linux Zen - pre-AppArmor recovery"').replace('kernel=\\EFI\\Linux\\arch-linux-zen-apparmor-test.efi','kernel=\\EFI\\Linux\\arch-linux-zen-pre-apparmor.efi').replace('# Security Center: separate AppArmor trial; original default remains entry 0.','# Security Center: signed pre-AppArmor recovery; normal default remains entry 0.').encode()
assert b'apparmor-test.efi' not in newmenu and b'\ndefault=0\n' in newmenu
assert b'\nremember_last=0\n' in newmenu
metadata=run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])
assert '0' in json.loads(metadata)['keyslots']
proposal={'schema':1,'normal':str(NORMAL),'normal_before_sha256':sha(NORMAL),
 'normal_after_sha256':sha(TEST),'recovery':str(RECOVERY),'recovery_sha256':sha(NORMAL),
 'menu_before_sha256':sha(MENU),'menu_after_sha256':hashlib.sha256(newmenu).hexdigest(),
 'cmdline_before_sha256':sha(CMDLINE),'cmdline_after_sha256':hashlib.sha256(newcmd).hexdigest(),
 'default_index':0,'remember_last':0,'luks_metadata_sha256':hashlib.sha256(metadata).hexdigest(),
 'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
 'promotion_method':'copy signed recovery, then atomically rename staged test over normal',
 'required_free_bytes':required_free,
 'tpm_reenrollment':False,'reboot_initiated':False}
review_sha=hashlib.sha256(json.dumps(proposal,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if args.review:
 print(json.dumps({'proposal':proposal,'review_sha256':review_sha,'applied':False}))
 raise SystemExit(0)
if args.approved_review_sha256!=review_sha or not args.owner_trial_passed:
 raise ValueError('Exact review approval and actual owner compatibility result required')
backup=BASE/'promotion';backup.mkdir(mode=0o700)
(backup/'approved-proposal.json').write_text(json.dumps({'proposal':proposal,'review_sha256':review_sha},indent=2))
(backup/'zen.cmdline.before').write_bytes(oldcmd);(backup/'boot.conf.before').write_bytes(oldmenu)
atomic_copy(NORMAL,RECOVERY)
run(['/usr/bin/sbverify','--cert',cert,str(RECOVERY)])
# Recovery menu is committed before replacing the normal image.
atomic_bytes(MENU,newmenu);os.sync()
atomic_bytes(CMDLINE,newcmd)
assert sha(TEST)==r['candidate_sha256']
os.replace(TEST,NORMAL)
directory=os.open(NORMAL.parent,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(directory)
finally:os.close(directory)
os.sync()
assert sha(NORMAL)==r['candidate_sha256'] and sha(RECOVERY)==r['original_sha256']
run(['/usr/bin/sbverify','--cert',cert,str(NORMAL)])
assert run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata','/dev/nvme0n1p2'])==metadata
result={'normal':str(NORMAL),'normal_sha256':sha(NORMAL),'recovery':str(RECOVERY),
 'recovery_sha256':sha(RECOVERY),'cmdline':str(CMDLINE),'cmdline_sha256':sha(CMDLINE),
 'menu_sha256':sha(MENU),'default_index':0,'luks_metadata_unchanged':True,
 'future_build_source_updated':True,'owner_sound_sleep_wake_wifi':'reported passed',
 'approved_review_sha256':review_sha,
 'normal_path_reboot_test':'pending; identical candidate already boot-tested'}
(backup/'result.json').write_text(json.dumps(result,indent=2))
# The exact test image moved to normal; no separate test copy is deleted.
assert not TEST.exists()
print(json.dumps(result,indent=2))
