import hashlib,pathlib,subprocess,sys,time,os,signal,select,termios
if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
 raise SystemExit('Refusing outside disposable guest')
sys.path.insert(0,'/policy')
from gate_record import read_record
from unlock_dispatch import unlock
from manual_recovery import recover
from handover import make_record,publish
from unlock_candidate_audit import audit
base=pathlib.Path('/run/systemd/generator')
unit='systemd-cryptsetup@cold_root.service'
options='tpm2-device=/dev/tpmrm0,tpm2-signature=/test-signature.json,headless=yes,password-cache=no'
checked=audit({p.name:dict(fragment=p.read_text(),dropins=[dict(name=d.name,text=d.read_text())
 for d in sorted((pathlib.Path('/etc/systemd/system')/(p.name+'.d')).glob('*.conf'))])
 for p in base.glob('systemd-cryptsetup@*.service')},unit,'cold_root',
 {'/dev/disk/by-uuid/11111111-2222-3333-4444-555555555555'},options,
 ['/usr/bin/python3','/cold-unlock.py'],checker='gate-observer.service')
assert checked['accepted'],checked
loaded=subprocess.check_output(['systemctl','show',unit,'--property=ExecStart','--value'],timeout=3)
assert b'/cold-unlock.py' in loaded and b' attach ' not in loaded
for field in ('Wants','After'):
 names=subprocess.check_output(['systemctl','show',unit,'--property='+field,'--value'],text=True,timeout=3).split()
 assert 'gate-observer.service' in names,field
requires=subprocess.check_output(['systemctl','show',unit,'--property=Requires','--value'],text=True,timeout=3).split()
assert 'gate-observer.service' not in requires
print('\nVM_COLD_RUNTIME_GRAPH',flush=True)
actual=subprocess.check_output(['systemctl','show','gate-observer.service','--property=ActiveState','--value'],text=True,timeout=3).strip()
expected='active' if pathlib.Path('/cold-mode').read_text()=='observe' else 'failed'
assert actual==expected,(actual,expected)
result=subprocess.check_output(['systemctl','show','gate-observer.service','--property=Result','--value'],text=True,timeout=3).strip()
expected_result={'observe':'success','failed':'exit-code','timeout':'timeout'}[pathlib.Path('/cold-mode').read_text()]
assert result==expected_result,(result,expected_result)
print('\nVM_COLD_GENERATOR_AUDIT\nVM_COLD_CHECKER_'+actual.upper(),flush=True)
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def decision():
 ok=subprocess.run(['systemctl','is-active','--quiet','gate-observer.service'],timeout=3).returncode==0
 return read_record('/run/security-center-gate',boot_id=boot,
  policy_sha256=hashlib.sha256(pathlib.Path('/policy/normal-devices.json').read_bytes()).hexdigest(),
  mode='normal',now=time.clock_gettime(time.CLOCK_BOOTTIME),checker_ok=ok)
def tpm():
 raise RuntimeError('Observation-only guest must not select TPM')
manual_stats=[]
attempt_count=0
def attempt():
 global attempt_count
 attempt_count+=1
 try:
  result=subprocess.run(['cryptsetup','open','--disable-external-tokens','--key-slot','0',
   '--tries','1','--timeout','5','/dev/disk/by-uuid/11111111-2222-3333-4444-555555555555','cold_root'],
   env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=8)
  success=result.returncode==0
 except subprocess.TimeoutExpired:
  success=False
 active=subprocess.run(['cryptsetup','status','cold_root'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3).returncode==0
 if not success:
  assert not active and not pathlib.Path('/run/cold-handover/boot.json').exists()
  print('\nVM_COLD_ATTEMPT_FAILED_'+str(attempt_count),flush=True)
  return False
 assert active
 path=os.path.realpath('/dev/mapper/cold_root')
 assert pathlib.Path('/sys/class/block/'+os.path.basename(path)+'/slaves/vda').exists()
 return True

def confirm_retry(count):
 before=termios.tcgetattr(0)
 hidden=list(before);hidden[3] &= ~termios.ECHO
 termios.tcsetattr(0,termios.TCSANOW,hidden)
 try:
  print('\nVM_COLD_RETRY_PROMPT_'+str(count)+'\nRecovery paused; press Enter to try manual unlock again.',flush=True)
  ready,_,_=select.select([0],[],[],5)
  return bool(ready) and os.read(0,128) in (b'\n',b'\r\n')
 finally:
  termios.tcsetattr(0,termios.TCSANOW,before)

def manual():
 # Keep the supervisor alive on Ctrl-C; exec resets this caught handler in the
 # cryptsetup child so it can cancel and restore its terminal itself.
 previous=signal.signal(signal.SIGINT,lambda *_:None)
 try:
  stats=recover(attempt,confirm_retry,limit=3)
  manual_stats.append(stats)
  return stats['unlocked']
 finally:
  signal.signal(signal.SIGINT,previous)
if expected=='active':
 observed=decision()
 assert observed['allow_tpm_attempt'] is False and observed['manual_recovery_required'] is True
else:
 try:decision()
 except (OSError,ValueError):pass
 else:raise AssertionError('Failed checker accepted')
result=unlock(decision,tpm,manual)
assert result['attempts']==['manual'] and len(manual_stats)==1
case=pathlib.Path('/cold-input').read_text()
expected_count=1 if case=='correct' else 3 if case=='exhaust' else 2
assert manual_stats[0]['attempts']==expected_count and attempt_count==expected_count
print('\nVM_COLD_MANUAL_ATTEMPTS_'+str(attempt_count),flush=True)
if case=='exhaust':
 assert not result['unlocked'] and result['method']=='none'
 assert not pathlib.Path('/dev/mapper/cold_root').exists()
 assert not pathlib.Path('/run/cold-handover/boot.json').exists()
 print('\nVM_COLD_RECOVERY_EXHAUSTED\nVM_TEST_PASS',flush=True)
 os.sync();pathlib.Path('/proc/sysrq-trigger').write_text('o')
 raise SystemExit(1)  # Must not fall through if poweroff fails.
assert result['unlocked'] and result['method']=='manual'
os.mkdir('/run/cold-handover',0o700)
publish('/run/cold-handover',make_record(boot,result,'manual'))
print('\nVM_COLD_MANUAL_UNLOCK',flush=True)
