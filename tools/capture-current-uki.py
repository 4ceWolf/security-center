#!/usr/bin/python3
"""User-side authenticated read-only capture; no keys or boot mutations."""
import hashlib,json,os,pathlib,subprocess,tarfile,tempfile
BASE=pathlib.Path('/home/user/Projects/security-center')
# This literal program, not an editable privileged module path, crosses sudo.
READER=r'''import os,stat,sys,tarfile,hashlib
if os.geteuid()!=0:raise PermissionError('Administrator required')
paths=[('/boot/EFI/Linux/arch-linux-zen.efi','zen.efi',268435456),('/var/lib/sbctl/keys/db/db.pem','db-cert.pem',65536),('/etc/miku-boot/zen-pcr-public.pem','pcr-public.pem',65536)]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
 for path,name,bound in paths:
  directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
  try:
   for part in path.split('/')[1:-1]:
    new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);os.close(directory);directory=new
    meta=os.fstat(directory)
    if meta.st_uid!=0 or meta.st_mode&0o022:raise ValueError('Untrusted capture ancestry')
   fd=os.open(path.split('/')[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
  finally:os.close(directory)
  with os.fdopen(fd,'rb') as stream:
   before=os.fstat(fd)
   if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022 or not 0<before.st_size<=bound:raise ValueError('Untrusted capture file')
   if name.endswith('.pem'):
    marker=b'-----BEGIN CERTIFICATE-----' if name=='db-cert.pem' else b'-----BEGIN PUBLIC KEY-----'
    if not stream.read(128).startswith(marker):raise ValueError('Public PEM expected')
    stream.seek(0)
   info=tarfile.TarInfo(name);info.size=before.st_size;info.mode=0o600
   archive.addfile(info,stream)
   after=os.fstat(fd)
   identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   if identity(before)!=identity(after):raise ValueError('Capture changed')
'''

def main():
 os.umask(0o077);folder=pathlib.Path(tempfile.mkdtemp(prefix='current-uki-',dir=BASE/'work'))
 (folder/'reader.py').write_text(READER)
 with (folder/'capture.partial').open('xb') as output:
  result=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center: capture working boot image and public certificates for review: ','/usr/bin/python3','-I','-c',READER],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.PIPE,timeout=300)
 if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')[-1000:])
 limits={'zen.efi':268435456,'db-cert.pem':65536,'pcr-public.pem':65536};seen={}
 with tarfile.open(folder/'capture.partial','r|') as archive:
  for member in archive:
   if member.name not in limits or member.name in seen or not member.isfile() or not 0<member.size<=limits[member.name]:raise ValueError('Unexpected capture member')
   h=hashlib.sha256()
   with archive.extractfile(member) as source,(folder/member.name).open('xb') as dest:
    while b:=source.read(65536):dest.write(b);h.update(b)
   seen[member.name]={'size':member.size,'sha256':h.hexdigest()}
 if set(seen)!=set(limits):raise ValueError('Capture incomplete')
 expected=json.loads((BASE/'work/installer/current-boot-audit.json').read_text())['images']['/boot/EFI/Linux/arch-linux-zen.efi']['sha256']
 if seen['zen.efi']['sha256']!=expected:raise ValueError('Boot image changed since audit; retain capture, review new bytes')
 (folder/'capture.partial').unlink()
 result=subprocess.run(['/usr/bin/sbverify','--cert',str(folder/'db-cert.pem'),str(folder/'zen.efi')],capture_output=True,text=True,timeout=20)
 receipt={'read_only':True,'host_boot_changed':False,'private_keys_read':False,'source_matches_audit':True,'efi_signature_verified':result.returncode==0,'files':seen,'reader_sha256':hashlib.sha256(READER.encode()).hexdigest(),'work':str(folder)}
 (folder/'signature-check.log').write_text(result.stdout+result.stderr);(folder/'receipt.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt,indent=2))
 if result.returncode:raise SystemExit(1)
if __name__=='__main__':main()
