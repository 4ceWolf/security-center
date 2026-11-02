#!/usr/bin/python3
"""Two distinct measured UKIs with one disposable LUKS disk/software TPM."""
import argparse,gzip,hashlib,json,os,pathlib,shutil,stat,subprocess,tempfile,time
import pefile
from observation_package import read_regular
from arch_initrd_manifest import inspect
BASE=pathlib.Path('/home/user/Projects/security-center')
TARGET=BASE/'work/arch-observer-build-3ga34q76'
PROVISION=BASE/'work/arch-observer-build-xwx5shof'
UUID='11111111-2222-3333-4444-555555555555'


def digest(raw):return hashlib.sha256(raw).hexdigest()

def archive(items):
 out=bytearray()
 for ino,(name,mode,data) in enumerate(items+[('TRAILER!!!',0,b'')]):
  values=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0]
  out.extend(b'070701'+''.join(f'{v:08x}' for v in values).encode());out.extend(name.encode()+b'\0');out.extend(b'\0'*(-len(out)%4))
  out.extend(data);out.extend(b'\0'*(-len(out)%4))
 return bytes(out)


def main():
 parser=argparse.ArgumentParser();parser.add_argument('--accel',choices=('tcg','kvm'),default='tcg');parser.add_argument('--observer',choices=('normal','masked'),default='normal');parser.add_argument('--firmware',choices=('secure','plain'),default='secure');parser.add_argument('--cpu',choices=('host','Haswell-noTSX'),default='host')
 parser.add_argument('--diagnostic-observer-timeout',type=int,choices=(30,60),help='TEST ONLY: relaxed observer timeout; never a production timing pass')
 options=parser.parse_args()
 if options.diagnostic_observer_timeout and options.observer!='normal':parser.error('Diagnostic timeout requires normal observer')
 os.umask(0o077)
 work=pathlib.Path(tempfile.mkdtemp(prefix='two-boot-luks-',dir=BASE/'work'))
 def captured(folder,provision):
  report=json.loads(read_regular(folder/'report.json',65536)[0]);image=read_regular(folder/'guest-initramfs.img',128*1024*1024)[0]
  if report.get('passed') is not True or report.get('provisioning_tools',False)!=provision or digest(image)!=report['image_sha256']:raise ValueError('Fixture mismatch')
  inventory=read_regular(folder/'generated-manifest.json',1024*1024)[0]
  if digest(inventory)!=report['generated_manifest_sha256']:raise ValueError('Inventory mismatch')
  return image,json.loads(inventory)
 target,tree=captured(TARGET,False);provision,_=captured(PROVISION,True)
 # Source guest image inventories are retained; production alias conflict is not waived.
 (work/'target-base-inventory.json').write_text(json.dumps(inspect(target)))
 (work/'empty.conf').write_text('[UKI]\n')
 wrapper=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--clearenv','--setenv','PATH','/usr/bin','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64','--dir','/etc','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(work),'/work','--chdir','/work','--']
 def isolated(args):
  r=subprocess.run(wrapper+args,capture_output=True,timeout=60)
  if r.returncode:
   (work/'build-error.log').write_bytes(r.stdout+r.stderr);raise RuntimeError('Build failed: '+str(work))
  return r.stdout
 isolated(['/usr/bin/openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','/work/disposable-private.pem'])
 isolated(['/usr/bin/openssl','pkey','-in','/work/disposable-private.pem','-pubout','-out','/work/disposable-public.pem'])
 public=(work/'disposable-public.pem').read_bytes();secret=os.urandom(24).hex().encode('ascii');(work/'disposable-manual.key').write_bytes(secret)
 F=stat.S_IFREG|0o600;D=stat.S_IFDIR|0o755
 post=(BASE/'tests/two-boot/post-root.py').read_bytes();pre=(BASE/'tests/two-boot/pre-unlock.py').read_bytes()
 root_entries=[('fixture-root',D,b'')]
 for name,expected in sorted(tree.items(),key=lambda pair:(len(pathlib.PurePosixPath(pair[0]).parts),pair[0])):
  if name.split('/')[0] not in ('usr','etc','bin','sbin','lib','lib64'):continue
  path=TARGET/'generated'/name;s=path.lstat()
  if stat.S_IMODE(s.st_mode)!=expected['mode']:raise ValueError('Root metadata changed')
  if path.is_symlink():
   payload=os.readlink(path).encode()
   if expected['type']!='symlink' or payload.decode()!=expected['target']:raise ValueError('Symlink changed')
   mode=stat.S_IFLNK|expected['mode']
  elif path.is_dir():payload=b'';mode=stat.S_IFDIR|expected['mode']
  else:
   payload=read_regular(path,64*1024*1024)[0]
   if expected['type']!='file' or digest(payload)!=expected['sha256']:raise ValueError('Root bytes changed')
   mode=stat.S_IFREG|expected['mode']
  root_entries.append(('fixture-root/'+name,mode,payload))
 root_entries += [('fixture-root/post-root.py',F,post),('fixture-root/pre_unlock.py',F,pre),('fixture-root/fixture-observer-mode',F,options.observer.encode())]
 provision_unit='''[Unit]
DefaultDependencies=no
Wants=systemd-pcrphase-initrd.service systemd-udev-trigger.service
After=systemd-pcrphase-initrd.service systemd-udev-trigger.service
Before=initrd.target initrd-root-fs.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /fixture-provision.py
TimeoutStartSec=120
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
'''
 prov_entries=root_entries+[
  ('disposable-key',F,secret),('fixture-public.pem',F,public),('fixture-provision.py',F,(BASE/'tests/two-boot/provision.py').read_bytes()),
  ('usr/lib/systemd/system/fixture-provision.service',stat.S_IFREG|0o644,provision_unit.encode()),
  ('usr/lib/systemd/system/initrd.target.wants/fixture-provision.service',stat.S_IFLNK|0o777,b'../fixture-provision.service')]
 pre_unit='''[Unit]
DefaultDependencies=no
Wants=systemd-pcrphase-initrd.service
After=systemd-pcrphase-initrd.service
Before=cryptsetup-pre.target
OnFailure=fixture-diagnostic.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /pre-unlock.py
RemainAfterExit=yes
TimeoutStartSec=60
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
'''
 target_entries=[('pre-unlock.py',F,pre),
  ('usr/lib/systemd/system/fixture-diagnostic.service',stat.S_IFREG|0o644,b'[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=-/usr/bin/systemctl --no-pager --full status fixture-pre.service\nExecStartPost=/usr/bin/systemctl poweroff --force --force\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'),
  ('usr/lib/systemd/system/fixture-pre.service',stat.S_IFREG|0o644,pre_unit.encode()),
  ('etc/systemd/system/systemd-cryptsetup@root.service.d/40-fixture-pre.conf',stat.S_IFREG|0o644,
   b'[Unit]\nRequires=fixture-pre.service\nAfter=fixture-pre.service\n')]
 if options.observer=='masked':
  target_entries.append(('etc/systemd/system/security-center-observation.service',stat.S_IFLNK|0o777,b'/dev/null'))
 if options.diagnostic_observer_timeout:
  target_entries.extend([
   ('etc/systemd/system/security-center-observation.service.d',D,b''),
   ('etc/systemd/system/security-center-observation.service.d/90-fixture-timeout.conf',stat.S_IFREG|0o644,
    ('[Service]\nTimeoutStartSec='+str(options.diagnostic_observer_timeout)+'\nStandardError=tty\nTTYPath=/dev/ttyS0\n').encode())])
 for _,_,data in target_entries:
  if secret in data or b'BEGIN PRIVATE KEY' in data or b'luksFormat' in data or b'cryptenroll' in data:raise ValueError('Target contains provisioning material')
 # The target base is independently captured and contains no test enrollment code.
 private=(work/'disposable-private.pem').read_bytes()
 if secret in target or private in target:raise ValueError('Target base contains fixture credential')
 for name,path in [('linux',pathlib.Path('/usr/lib/modules')/os.uname().release/'vmlinuz'),('stub',pathlib.Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub')),
                   ('CODE.fd',pathlib.Path('/usr/share/edk2/x64')/('OVMF_CODE.secboot.4m.fd' if options.firmware=='secure' else 'OVMF_CODE.4m.fd')),('VARS.fd',pathlib.Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd'))]:
  (work/name).write_bytes(read_regular(path.resolve(),128*1024*1024)[0])
 (work/'os-release').write_text('ID=disposable-two-boot\nNAME="Disposable measured LUKS fixture"\n')
 expected={};images={}
 for mode,base,entries in [('provision',provision,prov_entries),('target',target,target_entries)]:
  image=base+gzip.compress(archive(entries),mtime=0);(work/(mode+'.img')).write_bytes(image)
  cmdline='console=ttyS0 panic=1 quiet security_center_test_vm=1 systemd.tty.term.ttyS0=dumb'
  if mode=='target':cmdline+=' init=/usr/lib/systemd/systemd root=/dev/mapper/root rootfstype=ext4 rw rd.luks.name='+UUID+'=root rd.luks.options='+UUID+'=tpm2-device=/dev/tpmrm0,tpm2-signature=/run/systemd/tpm2-pcr-signature.json,headless=yes,password-cache=no'
  (work/'cmdline').write_text(cmdline)
  args=['/usr/bin/ukify','build','--config=/work/empty.conf','--linux=/work/linux','--stub=/work/stub','--initrd=/work/'+mode+'.img','--cmdline=@/work/cmdline','--os-release=@/work/os-release','--pcr-private-key=/work/disposable-private.pem','--pcr-public-key=/work/disposable-public.pem','--pcr-banks=sha256','--phases=enter-initrd','--policyref=initrd','--no-sign-initrd-pcrs','--no-sign-kernel','--output=/work/'+mode+'.efi']
  (work/(mode+'-build-command.json')).write_text(json.dumps(args,indent=2));isolated(args)
  raw=read_regular(work/(mode+'.efi'),256*1024*1024)[0];pe=pefile.PE(data=raw)
  sections={s.Name.rstrip(b'\0').decode():s.get_data()[:s.Misc_VirtualSize] for s in pe.sections}
  if sections['.initrd']!=image:raise ValueError('Measured initrd differs')
  params=[]
  for section in ('linux','osrel','cmdline','initrd','ucode','splash','dtb','dtbauto','uname','sbat','pcrpkey','profile','hwids','efifw'):
   if '.'+section in sections:
    (work/('section-'+section)).write_bytes(sections['.'+section]);params.append('--'+section+'=/work/section-'+section)
  expected[mode]={}
  for phase in ('enter-initrd','enter-initrd:leave-initrd'):
   expected[mode][phase]=json.loads(isolated(['/usr/lib/systemd/systemd-measure','calculate','--bank=sha256','--phase='+phase,'--json=short']+params))['sha256'][0]['hash']
  sig=json.loads(sections['.pcrsig'].rstrip(b'\0'))['sha256']
  if len(sig)!=1 or sig[0]['pcrs']!=[11] or sig[0]['ref']!='initrd':raise ValueError('Signed policy scope differs')
  images[mode]={'uki_sha256':digest(raw),'initrd_sha256':digest(image),'supplement':[{ 'name':n,'mode':m,'size':len(d),'sha256':digest(d)} for n,m,d in entries]}
 (work/'inputs.json').write_text(json.dumps({'images':images,'expected':expected,'target_secret_excluded':True,'target_private_key_excluded':True},indent=2))
 # Root is the second virtio device: ESP=vda, disposable encrypted volume=vdb.
 with (work/'disk.raw').open('xb') as f:f.truncate(384*1024*1024)
 (work/'tpm-state').mkdir();sock=work/'tpm.sock';stages={}
 for mode in ('provision','target'):
  folder=work/mode;folder.mkdir();esp=folder/'esp/EFI/BOOT';esp.mkdir(parents=True);shutil.copyfile(work/(mode+'.efi'),esp/'BOOTX64.EFI')
  args=['/usr/bin/qemu-system-x86_64','-machine',('q35,smm=on' if options.firmware=='secure' else 'pc'),'-accel',options.accel,'-cpu',(options.cpu if options.accel=='kvm' else 'max'),'-m','768','-smp','1','-nodefaults','-no-reboot','-display','none','-serial','stdio','-monitor','none','-nic','none',
   '-drive','if=pflash,format=raw,readonly=on,file='+str(work/'CODE.fd'),'-drive','if=pflash,format=raw,file='+str(work/'VARS.fd'),
   '-drive','format=raw,if=virtio,readonly=on,file=fat:ro:'+str(folder/'esp'),'-drive','file='+str(work/'disk.raw')+',format=raw,if=virtio',
   '-chardev','socket,id=tpmchar,path='+str(sock),'-tpmdev','emulator,id=tpm0,chardev=tpmchar','-device','tpm-tis,tpmdev=tpm0']
  if options.firmware=='secure':args+=['-global','driver=cfi.pflash01,property=secure,value=on']
  (folder/'command.json').write_text(json.dumps(args,indent=2));started=time.monotonic()
  with (folder/'tpm.log').open('wb') as log:
   tpm=subprocess.Popen(['/usr/bin/swtpm','socket','--tpm2','--tpmstate','dir='+str(work/'tpm-state'),'--ctrl','type=unixio,path='+str(sock),'--flags','not-need-init','--terminate'],stdout=log,stderr=log)
   try:
    for _ in range(100):
     if sock.exists() or tpm.poll() is not None:break
     time.sleep(.05)
    if not sock.exists():raise RuntimeError('TPM startup failed')
    with (folder/'console.log').open('wb') as console:
     try:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=console,stderr=subprocess.STDOUT,timeout=210)
     except subprocess.TimeoutExpired:r=subprocess.CompletedProcess(args,124)
   finally:
    if tpm.poll() is None:tpm.terminate()
    try:tpm.wait(timeout=5)
    except subprocess.TimeoutExpired:tpm.kill();tpm.wait(timeout=5)
  text=(folder/'console.log').read_text(errors='replace');state={'returncode':r.returncode,'seconds':round(time.monotonic()-started,2),'passed':False}
  if mode=='provision':state['passed']=r.returncode==0 and 'TWO_BOOT_PROVISIONED' in text and 'TWO_BOOT_PROVISION_FAILED' not in text
  else:
   def result(prefix):
    lines=[line.split(prefix,1)[1] for line in text.splitlines() if prefix in line]
    return json.loads(lines[0]) if len(lines)==1 else None
   before=result('TWO_BOOT_PRE_UNLOCK=');after=result('TWO_BOOT_POST_ROOT=');state.update(before=before,after=after)
   state['passed']=bool(r.returncode==0 and before and after and before['pcr11']==expected['target']['enter-initrd'] and after['pcr11']==expected['target']['enter-initrd:leave-initrd'] and after['post_phase_unseal_rejected'] and (after['record_retained'] if options.observer=='normal' else not after['record_retained']) and after['encrypted_root'] and 'Please enter passphrase' not in text and 'TWO_BOOT_TARGET_FAILED' not in text)
  stages[mode]=state
  (work/'report.json').write_text(json.dumps({'work':str(work),'passed':False,'stages':stages,'scope':'Disposable two-boot measured LUKS; no laptop deployment','accel':options.accel,'observer':options.observer,'firmware':options.firmware,'cpu':options.cpu if options.accel=='kvm' else 'max','expected':expected,'target_contains_secret':False,'target_contains_private_key':False},indent=2))
  if not state['passed']:break
 report=json.loads((work/'report.json').read_text());report['passed']=len(stages)==2 and all(s['passed'] for s in stages.values())
 report['diagnostic_observer_timeout_seconds']=options.diagnostic_observer_timeout
 report['production_observer_timing_passed']=False
 report['production_observer_timing_scope']='Not established by this guest run; relaxed TCG diagnostics never satisfy the original cap'
 (work/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
 if not report['passed']:raise SystemExit(1)
if __name__=='__main__':main()
