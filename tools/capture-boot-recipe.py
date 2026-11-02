#!/usr/bin/python3
"""Bounded authenticated read-only recipe capture. Never execute captured configs."""
import hashlib,json,os,pathlib,subprocess,tempfile
BASE=pathlib.Path('/home/user/Projects/security-center')
READER=r'''import base64,hashlib,json,os,stat
if os.geteuid()!=0:raise PermissionError('Administrator required')
def directory(path):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.strip('/').split('/'):
   new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   os.close(fd);fd=new
   s=os.fstat(fd)
   if s.st_uid or s.st_mode&0o022:raise ValueError('Untrusted directory')
  return fd
 except BaseException:
  os.close(fd);raise
identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid)
files={};absent=[];total=0
paths=['/etc/mkinitcpio.conf','/etc/miku-boot/zen.conf','/etc/miku-boot/zen.cmdline','/etc/miku-boot/zen-uki.conf','/usr/bin/mkinitcpio','/usr/lib/initcpio/functions']
fd=directory('/etc/mkinitcpio.conf.d')
try:
 names=sorted(os.listdir(fd))
 if len(names)>128:raise ValueError('Too many drop-ins')
 paths += ['/etc/mkinitcpio.conf.d/'+n for n in names if n.endswith('.conf')]
finally:os.close(fd)
for name in ('base','systemd','autodetect','microcode','modconf','kms','keyboard','sd-vconsole','plymouth','block','sd-encrypt','filesystems','fsck'):
 for kind in ('install','hooks'):paths.append('/usr/lib/initcpio/'+kind+'/'+name)
for path in paths:
 parent,name=path.rsplit('/',1);fd=directory(parent)
 try:
  try:source=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
  except FileNotFoundError:
   if '/hooks/' not in path:raise
   absent.append(path);continue
  with os.fdopen(source,'rb') as stream:
   before=os.fstat(source)
   if not stat.S_ISREG(before.st_mode) or before.st_uid or before.st_mode&0o022 or before.st_size>1048576:raise ValueError('Untrusted recipe file')
   raw=stream.read(1048577);total+=len(raw)
   if len(raw)!=before.st_size or total>8388608:raise ValueError('Capture size changed or exceeded bound')
   if identity(before)!=identity(os.fstat(source)) or identity(before)!=identity(os.stat(name,dir_fd=fd,follow_symlinks=False)):raise ValueError('Recipe changed during capture')
   if b'-----BEGIN PRIVATE KEY-----' in raw or b'-----BEGIN RSA PRIVATE KEY-----' in raw:raise ValueError('Unexpected private key material')
   files[path]={'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(before.st_mode),'uid':before.st_uid,'gid':before.st_gid,'size':len(raw),'base64':base64.b64encode(raw).decode()}
 finally:os.close(fd)
print(json.dumps({'files':files,'absent_runtime_hooks':absent,'dropin_names':names,'kernel_release':os.uname().release,'read_only':True,'configs_executed':False,'private_key_files_opened':False,'complete_runtime_closure':False}))
'''
def main():
 os.umask(0o077)
 folder=pathlib.Path(tempfile.mkdtemp(prefix='boot-recipe-',dir=BASE/'work'))
 (folder/'reader.py').write_text(READER)
 result=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center: read current boot recipe and hook source for review: ','/usr/bin/python3','-I','-c',READER],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=300)
 if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace')[-1200:])
 if len(result.stdout)>12*1024*1024:raise ValueError('Capture output exceeds bound')
 data=json.loads(result.stdout);(folder/'recipe.json').write_bytes(result.stdout)
 receipt={'work':str(folder),'files':len(data['files']),'recipe_sha256':hashlib.sha256(result.stdout).hexdigest(),'reader_sha256':hashlib.sha256(READER.encode()).hexdigest(),'read_only':True,'build_authorized':False,'complete_runtime_closure':False}
 (folder/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
if __name__=='__main__':main()
