"""No password, formatter, enrollment or signer; post-root evidence only."""
import json,os,pathlib,stat,subprocess,sys,traceback
sys.path.insert(0,'/usr/lib/security-center-observation')
sys.path.insert(0,'/')
from boot_observation import consume
from pre_unlock import read_pcr
try:
 assert os.path.realpath('/proc/1/exe')=='/usr/lib/systemd/systemd'
 rows=[r.split() for r in pathlib.Path('/proc/mounts').read_text().splitlines() if r.split()[1]=='/']
 assert any(r[2]=='ext4' and os.stat(r[0]).st_rdev==os.stat('/dev/mapper/root').st_rdev for r in rows)
 mapper=os.path.basename(os.path.realpath('/dev/mapper/root'))
 assert pathlib.Path('/sys/class/block/'+mapper+'/slaves/vdb').exists()
 record_retained=False
 try:
  record=consume(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
 except FileNotFoundError:
  pass  # Record the independent observer failure; overall normal test must fail.
 else:
  assert record['unlock_method']=='unknown' and record['enforcement']=='not_enabled' and record['attested'] is False
  record_retained=True
 expected=pathlib.Path('/fixture-observer-mode').read_text()
 assert (record_retained if expected=='normal' else not record_retained), expected
 signature=pathlib.Path('/run/two-boot-public-signature.json')
 assert signature.is_file() and stat.S_ISBLK(os.stat('/dev/vdb').st_mode)
 signed=json.loads(signature.read_text())['sha256']
 assert len(signed)==1 and signed[0]['pcrs']==[11] and signed[0]['ref']=='initrd'
 result=subprocess.run(['/usr/bin/systemd-cryptsetup','attach','phase_must_fail','/dev/vdb','-',
  'tpm2-device=/dev/tpmrm0,tpm2-signature=/run/two-boot-public-signature.json,headless=yes,password-cache=no'],capture_output=True,timeout=10)
 diagnostic=result.stderr.decode(errors='replace').lower()
 policy_diagnostic=any(word in diagnostic for word in ('pcr','policy','unseal','signature'))
 assert result.returncode!=0 and policy_diagnostic and not pathlib.Path('/dev/mapper/phase_must_fail').exists()
 print('TWO_BOOT_POST_ROOT='+json.dumps({'pcr11':read_pcr(),'encrypted_root':True,'backing':'vdb','record_retained':record_retained,'post_phase_unseal_rejected':True,'negative_returncode':result.returncode,'policy_diagnostic_present':policy_diagnostic,'saved_signature_present':True}),flush=True)
except BaseException:
 traceback.print_exc();print('TWO_BOOT_TARGET_FAILED',flush=True)
finally:
 os.sync();pathlib.Path('/proc/sysrq-trigger').write_text('o')
