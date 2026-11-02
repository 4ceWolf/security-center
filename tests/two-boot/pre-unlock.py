"""Read-only phase evidence immediately before the stock mapping."""
print('TWO_BOOT_PRE_ENTRY',flush=True)
import json,pathlib,struct,subprocess,shutil

def read_pcr():
 payload=struct.pack('>IHB',1,0x000b,3)+bytes((0,8,0));command=struct.pack('>HII',0x8001,10+len(payload),0x17e)+payload
 with open('/dev/tpmrm0','r+b',buffering=0) as tpm:tpm.write(command);response=tpm.read(4096)
 if len(response)!=62 or response[:10]!=struct.pack('>HII',0x8001,62,0):raise ValueError('Unexpected PCR response')
 if response[14:30]!=payload+struct.pack('>IH',1,32):raise ValueError('Unexpected PCR selection/digest')
 return response[30:].hex()

def phase():
 text=subprocess.check_output(['/usr/bin/systemctl','show','systemd-pcrphase-initrd.service','-p','ConditionResult','-p','Result','-p','ActiveState'],text=True,timeout=5)
 return dict(line.split('=',1) for line in text.splitlines())

if __name__=='__main__':
 print('TWO_BOOT_PRE_IMPORTS_READY',flush=True)
 assert 'security_center_test_vm=1' in pathlib.Path('/proc/cmdline').read_text().split()
 state=phase();print('TWO_BOOT_PRE_PHASE_READY='+json.dumps(state),flush=True);assert state=={'ActiveState':'active','ConditionResult':'yes','Result':'success'},state
 sig=pathlib.Path('/run/systemd/tpm2-pcr-signature.json');assert sig.is_file()
 shutil.copyfile(sig,'/run/two-boot-public-signature.json')
 print('TWO_BOOT_PRE_SIGNATURE_READY',flush=True)
 print('TWO_BOOT_PRE_UNLOCK='+json.dumps({'phase':state,'pcr11':read_pcr()}),flush=True)
