#!/usr/bin/python3
"""Disposable unsigned UEFI execution and native PCR phase probe. Never deploy."""
import argparse
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import pefile
from observation_package import read_regular

BASE = pathlib.Path('/home/user/Projects/security-center')
ARCH = BASE/'work/arch-observer-build-3ga34q76'

def archive(items):
    out = bytearray()
    for ino, (name, mode, data) in enumerate(items + [('TRAILER!!!', 0, b'')]):
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name.encode())+1, 0]
        out.extend(b'070701'+''.join(f'{v:08x}' for v in fields).encode())
        out.extend(name.encode()+b'\0'); out.extend(b'\0'*(-len(out)%4))
        out.extend(data); out.extend(b'\0'*(-len(out)%4))
    return bytes(out)

PROBE = r'''import json, pathlib, struct, subprocess

def read_pcr():
    payload=struct.pack('>IHB',1,0x000b,3)+b'\x00\x08\x00'
    command=struct.pack('>HII',0x8001,10+len(payload),0x17e)+payload
    with open('/dev/tpmrm0','r+b',buffering=0) as tpm:
        tpm.write(command); response=tpm.read(4096)
    if len(response)!=62 or struct.unpack('>HII',response[:10])!=(0x8001,62,0):
        raise ValueError('Unexpected TPM response')
    if response[14:24]!=struct.pack('>IHB',1,0x000b,3)+b'\x00\x08\x00':
        raise ValueError('Unexpected PCR selection')
    if response[24:30]!=struct.pack('>IH',1,32):raise ValueError('Unexpected digest count')
    return response[30:].hex()

def state():
    out=subprocess.check_output(['/usr/bin/systemctl','show','systemd-pcrphase-initrd.service',
        '-p','ConditionResult','-p','Result','-p','ActiveState'],text=True,timeout=10)
    return dict(line.split('=',1) for line in out.splitlines())
try:
    before=state()
    srk_log=subprocess.run(['/usr/bin/journalctl','--no-pager','-u','systemd-tpm2-setup-early.service','-n','15','-o','cat'],capture_output=True,text=True,timeout=10)
    print('UEFI_SRK_DIAGNOSTIC='+json.dumps(srk_log.stdout[-4096:]),flush=True)
    enter=read_pcr()
    efivars=pathlib.Path('/sys/firmware/efi/efivars')
    values={}
    for name in ('SecureBoot','SetupMode','StubPcrKernelImage'):
        matches=list(efivars.glob(name+'-*'))
        values[name]=matches[0].read_bytes()[4:].hex() if len(matches)==1 else None
    subprocess.run(['/usr/bin/systemctl','stop','systemd-pcrphase-initrd.service'],check=True,timeout=15)
    leave=read_pcr()
    print('UEFI_PHASE_RESULT='+json.dumps(dict(before=before,after=state(),enter=enter,leave=leave,variables=values)),flush=True)
except Exception as exc:
    print('UEFI_PHASE_ERROR='+type(exc).__name__+':'+str(exc),flush=True)
finally:
    subprocess.run(['/usr/bin/systemctl','poweroff','--force','--force'],timeout=10)
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--accel', choices=('kvm','tcg'), default='kvm')
    parser.add_argument('--secure-firmware', action='store_true')
    options=parser.parse_args()
    work=pathlib.Path(tempfile.mkdtemp(prefix='uefi-phase-',dir=BASE/'work')); work.chmod(0o700)
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    base=read_regular(ARCH/'guest-initramfs.img',128*1024*1024)[0]
    source=json.loads(read_regular(ARCH/'report.json',65536)[0])
    if source.get('passed') is not True or digest(base)!=source['image_sha256']:
        raise ValueError('Captured Arch fixture mismatch')
    unit='''[Unit]
Description=Disposable firmware phase probe
DefaultDependencies=no
Wants=systemd-pcrphase-initrd.service
After=systemd-pcrphase-initrd.service systemd-udev-trigger.service
Before=initrd.target initrd-root-fs.target initrd-switch-root.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /uefi-probe.py
TimeoutStartSec=40
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
'''
    supplement=archive([('uefi-probe.py',stat.S_IFREG|0o600,PROBE.encode()),
        ('usr/lib/systemd/system/uefi-probe.service',stat.S_IFREG|0o644,unit.encode()),
        ('usr/lib/systemd/system/initrd.target.wants/uefi-probe.service',stat.S_IFLNK|0o777,
         b'../uefi-probe.service')])
    supplement = gzip.compress(supplement, mtime=0)
    (work/'initrd').write_bytes(base+supplement)
    for name,path in [('linux',pathlib.Path('/usr/lib/modules')/os.uname().release/'vmlinuz'),
                     ('stub',pathlib.Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub')),
                     ('CODE.fd',pathlib.Path('/usr/share/edk2/x64')/('OVMF_CODE.secboot.4m.fd' if options.secure_firmware else 'OVMF_CODE.4m.fd')),
                     ('VARS.fd',pathlib.Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd'))]:
        (work/name).write_bytes(read_regular(path.resolve(),128*1024*1024)[0])
    (work/'empty.conf').write_text('[UKI]\n')
    (work/'cmdline').write_text('console=ttyS0 panic=1 systemd.log_target=console systemd.tty.term.ttyS0=dumb security_center_test_vm=1')
    (work/'os-release').write_text('ID=disposable-phase-probe\nNAME="Disposable UEFI phase probe"\n')
    wrapper=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--clearenv','--setenv','PATH','/usr/bin',
             '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
             '--symlink','usr/lib','/lib64','--dir','/etc','--proc','/proc','--dev','/dev',
             '--tmpfs','/tmp','--bind',str(work),'/work','--chdir','/work','--']
    def run(args):
        result=subprocess.run(wrapper+args,capture_output=True,timeout=60)
        if result.returncode:
            (work/'build-error.log').write_bytes(result.stdout+result.stderr)
            raise RuntimeError('Isolated build failed: '+str(work))
        return result.stdout
    run(['/usr/bin/ukify','build','--config=/work/empty.conf','--linux=/work/linux',
         '--stub=/work/stub','--initrd=/work/initrd','--cmdline=@/work/cmdline',
         '--os-release=@/work/os-release','--no-sign-kernel','--output=/work/probe.efi'])
    uki=read_regular(work/'probe.efi',256*1024*1024)[0]
    pe=pefile.PE(data=uki)
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:raise ValueError('Unexpected EFI signature')
    sections={}
    for section in pe.sections:
        name=section.Name.rstrip(b'\0').decode('ascii')
        if name in sections:raise ValueError('Duplicate section')
        sections[name]=section.get_data()[:section.Misc_VirtualSize]
    if sections['.initrd']!=base+supplement:raise ValueError('Embedded image mismatch')
    measure=[]
    for name in ('linux','osrel','cmdline','initrd','ucode','splash','dtb','dtbauto','uname','sbat',
                 'pcrpkey','profile','hwids','efifw'):
        if '.'+name in sections:
            (work/('section-'+name)).write_bytes(sections['.'+name]); measure.append('--'+name+'=/work/section-'+name)
    expected={}
    for phase in ('enter-initrd','enter-initrd:leave-initrd'):
        expected[phase]=json.loads(run(['/usr/lib/systemd/systemd-measure','calculate','--bank=sha256',
                                       '--phase='+phase,'--json=short']+measure))
    (work/'expected.json').write_text(json.dumps(expected,indent=2))
    esp=work/'esp/EFI/BOOT'; esp.mkdir(parents=True); (esp/'BOOTX64.EFI').write_bytes(uki)
    (work/'tpm-state').mkdir(mode=0o700)
    sock=work/'tpm.sock'
    args=['/usr/bin/qemu-system-x86_64','-machine',('q35,smm=on' if options.secure_firmware else 'q35'),'-accel',options.accel,'-cpu',('host' if options.accel=='kvm' else 'max'),'-m',('768' if options.secure_firmware else '384'),'-smp','1',
          '-nodefaults','-no-reboot','-display','none','-serial','stdio','-monitor','none','-nic','none',
          '-drive','if=pflash,format=raw,readonly=on,file='+str(work/'CODE.fd'),
          '-drive','if=pflash,format=raw,file='+str(work/'VARS.fd'),
          '-drive','format=raw,if=virtio,readonly=on,file=fat:ro:'+str(work/'esp'),
          '-chardev','socket,id=chrtpm,path='+str(sock),'-tpmdev','emulator,id=tpm0,chardev=chrtpm',
          '-device','tpm-tis,tpmdev=tpm0']
    if options.secure_firmware:
        args += ['-global','driver=cfi.pflash01,property=secure,value=on']
    (work/'qemu-command.json').write_text(json.dumps(args,indent=2))
    initial_hashes={name:digest((work/name).read_bytes()) for name in ('CODE.fd','VARS.fd','linux','stub','initrd','probe.efi')}
    started=time.monotonic()
    with (work/'tpm.log').open('wb') as log:
        emulator=subprocess.Popen(['/usr/bin/swtpm','socket','--tpm2','--tpmstate','dir='+str(work/'tpm-state'),
            '--ctrl','type=unixio,path='+str(sock),'--flags','not-need-init','--terminate'],stdout=log,stderr=log)
        try:
            for _ in range(100):
                if sock.exists() or emulator.poll() is not None:break
                time.sleep(.05)
            if not sock.exists():raise RuntimeError('Software TPM unavailable')
            with (work/'console.log').open('wb') as console:
                try:
                    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=console,stderr=subprocess.STDOUT,timeout=60)
                except subprocess.TimeoutExpired:
                    result=subprocess.CompletedProcess(args,124)
        finally:
            if emulator.poll() is None:emulator.terminate()
            try:emulator.wait(timeout=5)
            except subprocess.TimeoutExpired:emulator.kill(); emulator.wait(timeout=5)
    text=(work/'console.log').read_text(errors='replace')
    lines=[line.split('UEFI_PHASE_RESULT=',1)[1] for line in text.splitlines() if 'UEFI_PHASE_RESULT=' in line]
    report=dict(work=str(work),passed=False,scope='Unsigned disposable UEFI phase probe only',accel=options.accel,secure_firmware=options.secure_firmware,
        laptop_candidate=False,host_tpm_exposed=False,host_boot_exposed=False,
        tools={name:digest(read_regular(pathlib.Path(name).resolve(),128*1024*1024)[0])
               for name in ('/usr/bin/qemu-system-x86_64','/usr/bin/swtpm','/usr/bin/ukify',
                            '/usr/lib/systemd/systemd-measure')},
        expected=expected,inputs=initial_hashes,seconds=round(time.monotonic()-started,2),returncode=result.returncode)
    if len(lines)==1:
        actual=json.loads(lines[0]); report['actual']=actual
        values={phase:value['sha256'][0]['hash'] for phase,value in expected.items()}
        report['secure_boot_state'] = {'00':'disabled','01':'enabled'}.get(actual['variables']['SecureBoot'],'unavailable')
        report['secure_boot_enforcement_tested'] = False
        report['measurement_passed']=(result.returncode==0 and actual['before']==dict(ConditionResult='yes',Result='success',ActiveState='active')
            and actual['after']['Result']=='success' and actual['after']['ActiveState']=='inactive'
            and actual['enter']==values['enter-initrd'] and actual['leave']==values['enter-initrd:leave-initrd']
            and actual['variables']['StubPcrKernelImage']=='310031000000')
        report['passed'] = report['measurement_passed']
    (work/'report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
