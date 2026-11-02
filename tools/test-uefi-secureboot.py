#!/usr/bin/python3
"""Disposable UEFI signature acceptance/rejection; never host firmware or keys."""
import hashlib,json,pathlib,shutil,subprocess,tempfile,time,os
import pefile
from observation_package import read_regular
BASE=pathlib.Path('/home/user/Projects/security-center')
SOURCE=BASE/'work/uefi-phase-warfldt4'
VARS_TOOL=BASE/'work/firmware-tools-a169cjz6/venv/bin/virt-fw-vars'

def firmware_rejected(text):
 return any('BdsDxe: failed to load' in line and
            ('Security Violation' in line or 'Access Denied -- rejected probably by Secure Boot' in line)
            for line in text.splitlines())

def main():
 os.umask(0o077)
 work=pathlib.Path(tempfile.mkdtemp(prefix='secureboot-guest-',dir=BASE/'work'))
 source=json.loads(read_regular(SOURCE/'report.json',65536)[0])
 if source.get('passed') is not True or source.get('secure_firmware') is not True:raise ValueError('Successful measured firmware fixture required')
 for name in ('probe.efi','CODE.fd'):
  raw=read_regular(SOURCE/name,256*1024*1024)[0]
  if hashlib.sha256(raw).hexdigest()!=source['inputs'][name]:raise ValueError('Source changed')
  (work/name).write_bytes(raw)
 (work/'empty-vars.fd').write_bytes(read_regular(pathlib.Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd'),8*1024*1024)[0])
 commands=[]
 def run(args):
  commands.append(args)
  r=subprocess.run(args,capture_output=True,timeout=30)
  if r.returncode:
   (work/'command-error.log').write_bytes(r.stdout+r.stderr);raise RuntimeError('Offline setup failed: '+str(work))
  return r.stdout
 run(['/usr/bin/openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Disposable Security Center Guest Only/',
      '-keyout',str(work/'disposable.key'),'-out',str(work/'disposable.pem')])
 run([str(VARS_TOOL),'-i',str(work/'empty-vars.fd'),'-o',str(work/'enrolled-vars.fd'),'--enroll-cert',str(work/'disposable.pem'),
      '--microsoft-db','none','--microsoft-kek','none','--add-db','7b475a86-41e8-4a82-9ae2-32a7f8b7680c',str(work/'disposable.pem'),'--secure-boot','--output-json',str(work/'vars-public.json')])
 variables=json.loads((work/'vars-public.json').read_text())['variables']
 if not {'PK','KEK','db'}.issubset({v['name'] for v in variables}):raise ValueError('Guest trust database incomplete')
 run(['/usr/bin/sbsign','--key',str(work/'disposable.key'),'--cert',str(work/'disposable.pem'),'--output',str(work/'signed.efi'),str(work/'probe.efi')])
 run(['/usr/bin/sbverify','--cert',str(work/'disposable.pem'),str(work/'signed.efi')])
 signed=read_regular(work/'signed.efi',256*1024*1024)[0];pe=pefile.PE(data=signed,fast_load=True)
 section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.linux')
 altered=bytearray(signed);altered[section.PointerToRawData+4096]^=1;(work/'tampered.efi').write_bytes(altered)
 del altered,pe
 (work/'setup-commands.json').write_text(json.dumps(commands,indent=2))
 results={}
 for case,image in [('signed','signed.efi'),('unsigned','probe.efi'),('tampered','tampered.efi')]:
  folder=work/case;folder.mkdir();esp=folder/'esp/EFI/BOOT';esp.mkdir(parents=True)
  shutil.copyfile(work/image,esp/'BOOTX64.EFI');shutil.copyfile(work/'enrolled-vars.fd',folder/'VARS.fd')
  (folder/'tpm').mkdir();sock=folder/'tpm.sock'
  args=['/usr/bin/qemu-system-x86_64','-machine','q35,smm=on','-accel','tcg','-cpu','max','-m','768','-smp','1',
   '-nodefaults','-no-reboot','-display','none','-serial','stdio','-monitor','none','-nic','none',
   '-drive','if=pflash,format=raw,readonly=on,file='+str(work/'CODE.fd'),
   '-drive','if=pflash,format=raw,file='+str(folder/'VARS.fd'),
   '-drive','format=raw,if=virtio,readonly=on,file=fat:ro:'+str(folder/'esp'),
   '-global','driver=cfi.pflash01,property=secure,value=on',
   '-chardev','socket,id=tpmchar,path='+str(sock),'-tpmdev','emulator,id=tpm0,chardev=tpmchar','-device','tpm-tis,tpmdev=tpm0']
  (folder/'qemu-command.json').write_text(json.dumps(args,indent=2))
  started=time.monotonic();child=None;reason=None
  with (folder/'tpm.log').open('wb') as log:
   tpm=subprocess.Popen(['/usr/bin/swtpm','socket','--tpm2','--tpmstate','dir='+str(folder/'tpm'),'--ctrl','type=unixio,path='+str(sock),'--flags','not-need-init','--terminate'],stdout=log,stderr=log)
   try:
    for _ in range(100):
     if sock.exists() or tpm.poll() is not None:break
     time.sleep(.05)
    if not sock.exists():raise RuntimeError('Software TPM startup')
    with (folder/'console.log').open('wb') as console:
     child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=console,stderr=subprocess.STDOUT)
     deadline=time.monotonic()+(150 if case=='signed' else 45)
     while child.poll() is None:
      text=(folder/'console.log').read_text(errors='replace')
      if case!='signed' and firmware_rejected(text):
       reason='explicit_firmware_security_violation';child.terminate();break
      if time.monotonic()>deadline:reason='timeout';child.terminate();break
      time.sleep(.2)
     try:child.wait(timeout=5)
     except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
   finally:
    if child is not None and child.poll() is None:child.kill();child.wait(timeout=5)
    if tpm.poll() is None:tpm.terminate()
    try:tpm.wait(timeout=5)
    except subprocess.TimeoutExpired:tpm.kill();tpm.wait(timeout=5)
  text=(folder/'console.log').read_text(errors='replace')
  row={'seconds':round(time.monotonic()-started,2),'returncode':child.returncode,'stop_reason':reason,'passed':False}
  if case=='signed':
   lines=[l.split('UEFI_PHASE_RESULT=',1)[1] for l in text.splitlines() if 'UEFI_PHASE_RESULT=' in l]
   if len(lines)==1:
    actual=json.loads(lines[0]);row['actual']=actual
    row['passed']=(child.returncode==0 and actual['variables']=={'SecureBoot':'01','SetupMode':'00','StubPcrKernelImage':'310031000000'}
       and actual['before']=={'ActiveState':'active','ConditionResult':'yes','Result':'success'}
       and actual['after']['Result']=='success' and actual['after']['ActiveState']=='inactive'
       and actual['enter']==source['expected']['enter-initrd']['sha256'][0]['hash']
       and actual['leave']==source['expected']['enter-initrd:leave-initrd']['sha256'][0]['hash'])
  else:row['passed']=(reason=='explicit_firmware_security_violation' and 'UEFI_PHASE_RESULT=' not in text and 'Linux version' not in text)
  results[case]=row
 report={'scope':'Disposable guest Secure Boot signature enforcement only; no disk unlock or laptop deployment',
   'passed':all(r['passed'] for r in results.values()),'work':str(work),'cases':results,'host_firmware_changed':False,'host_keys_accessed':False,
   'inputs':{name:hashlib.sha256((work/name).read_bytes()).hexdigest() for name in ('CODE.fd','enrolled-vars.fd','probe.efi','signed.efi','tampered.efi','disposable.pem')},
   'virt_firmware_version':'26.9','source_phase_report':str(SOURCE/'report.json')}
 (work/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
 if not report['passed']:raise SystemExit(1)
if __name__=='__main__':main()
