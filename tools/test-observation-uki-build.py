#!/usr/bin/python3
"""Offline disposable PCR-signed UKI construction; never a laptop candidate.

Only a fresh project directory is writable in the isolated builder. No EFI signing
or host TPM, disk, firmware, boot configuration or signing key is exposed.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from observation_package import read_regular

BASE=pathlib.Path('/home/user/Projects/security-center')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--arch-base',required=True)
    options=parser.parse_args()
    source=pathlib.Path(options.arch_base)
    if source.resolve()!=source or source.parent!=BASE/'work' or not source.name.startswith('arch-observer-build-'):
        parser.error('Project-local disposable Arch build required')
    report=json.loads(read_regular(source/'report.json',65536)[0])
    image=read_regular(source/'guest-initramfs.img',128*1024*1024)[0]
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    if report.get('passed') is not True or report.get('signed') is not False or digest(image)!=report['image_sha256']:
        raise ValueError('Exact successful unsigned guest image required')
    work=pathlib.Path(tempfile.mkdtemp(prefix='observation-uki-test-',dir=BASE/'work'))
    work.chmod(0o700)
    (work/'initrd.img').write_bytes(image)
    for name,host in [('linux',pathlib.Path('/usr/lib/modules')/os.uname().release/'vmlinuz'),
                      ('stub',pathlib.Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub'))]:
        (work/name).write_bytes(read_regular(host.resolve(),128*1024*1024)[0])
    (work/'empty.conf').write_text('[UKI]\n')
    (work/'os-release').write_text('ID=security-center-disposable\nNAME="Disposable offline UKI build test"\n')
    (work/'cmdline').write_text('console=ttyS0 panic=1 security_center_test_vm=1')
    wrapper=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--clearenv',
             '--setenv','PATH','/usr/bin','--setenv','LC_ALL','C',
             '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
             '--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
             '--dir','/etc','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
             '--bind',str(work),'/work','--chdir','/work','--']
    def run(args):
        result=subprocess.run(wrapper+args,capture_output=True,timeout=60)
        if result.returncode:
            (work/'failure.log').write_bytes(result.stdout+result.stderr)
            raise RuntimeError('Isolated command failed; see '+str(work/'failure.log'))
        return result.stdout
    run(['/usr/bin/openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out','/work/disposable-pcr-private.pem'])
    (work/'disposable-pcr-private.pem').chmod(0o600)
    run(['/usr/bin/openssl','pkey','-in','/work/disposable-pcr-private.pem','-pubout','-out','/work/disposable-pcr-public.pem'])
    args=['/usr/bin/ukify','build','--config=/work/empty.conf','--linux=/work/linux',
          '--stub=/work/stub','--initrd=/work/initrd.img','--cmdline=@/work/cmdline',
          '--os-release=@/work/os-release','--pcr-private-key=/work/disposable-pcr-private.pem',
          '--pcr-public-key=/work/disposable-pcr-public.pem','--pcr-banks=sha256',
          '--phases=enter-initrd','--policyref=initrd','--no-sign-initrd-pcrs',
          '--no-sign-kernel','--output=/work/disposable.efi']
    (work/'build-command.json').write_text(json.dumps(args,indent=2))
    (work/'build.log').write_bytes(run(args))
    import pefile
    raw=read_regular(work/'disposable.efi',256*1024*1024)[0]
    pe=pefile.PE(data=raw)
    sections={}
    for section in pe.sections:
        name=section.Name.rstrip(b'\0').decode('ascii')
        if name in sections:raise ValueError('Duplicate PE section')
        payload=section.get_data()[:section.Misc_VirtualSize]
        sections[name]=payload
    if sections['.initrd']!=image or sections['.linux']!=(work/'linux').read_bytes():
        raise ValueError('Embedded input differs')
    if sections['.pcrpkey'].rstrip(b'\0')!=(work/'disposable-pcr-public.pem').read_bytes().rstrip(b'\0'):
        raise ValueError('Embedded key differs')
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size:raise ValueError('Unexpected EFI signing')
    names=('linux','osrel','cmdline','initrd','ucode','splash','dtb','dtbauto','uname','sbat','pcrpkey','profile','hwids','efifw')
    measure=[]
    for name in names:
        if '.'+name in sections:
            (work/('section-'+name)).write_bytes(sections['.'+name])
            measure.append('--'+name+'=/work/section-'+name)
    expected=json.loads(run(['/usr/lib/systemd/systemd-measure','policy-digest','--bank=sha256','--phase=enter-initrd','--policyref=initrd','--json=short']+measure))
    signatures=json.loads(sections['.pcrsig'].rstrip(b'\0'))
    if set(expected)!={'sha256'} or set(signatures)!={'sha256'} or len(expected['sha256'])!=1 or len(signatures['sha256'])!=1:
        raise ValueError('Unexpected policy bank or signature count')
    policy=expected['sha256'][0];signature=signatures['sha256'][0]
    if (policy['pcrs']!=[11] or policy['ref']!='initrd'
            or any(signature.get(key)!=policy[key] for key in ('pcrs','ref','pol'))):
        raise ValueError('Embedded policy differs from extracted-section calculation')
    # systemd fingerprints RSA public keys in PKCS#1 DER, not SPKI DER.
    public_der=run(['/usr/bin/openssl','rsa','-pubin','-in','/work/disposable-pcr-public.pem','-RSAPublicKey_out','-outform','DER'])
    if signature['pkfp']!=digest(public_der):raise ValueError('Unexpected public-key fingerprint')
    (work/'policy.tbs').write_bytes(bytes.fromhex(policy['tbs']))
    signature_bytes=base64.b64decode(signature['sig'],validate=True)
    (work/'policy.sig').write_bytes(signature_bytes)
    verify_args=['/usr/bin/openssl','dgst','-sha256','-verify','/work/disposable-pcr-public.pem',
                 '-signature','/work/policy.sig','/work/policy.tbs']
    run(verify_args)
    (work/'policy.sig').write_bytes(bytes([signature_bytes[0]^1])+signature_bytes[1:])
    negative=subprocess.run(wrapper+verify_args,capture_output=True,timeout=10)
    (work/'policy.sig').write_bytes(signature_bytes)
    if negative.returncode!=1 or b'Verification failure' not in negative.stdout:
        raise ValueError('Altered signature did not produce the expected rejection')
    (work/'expected-policy.json').write_text(json.dumps(expected,indent=2))
    (work/'public-signatures.json').write_text(json.dumps(signatures,indent=2))
    result={'schema_version':1,'scope':'Offline disposable UKI construction only',
            'work':str(work),'uki_sha256':digest(raw),'initrd_sha256':digest(image),
            'sections':{name:{'size':len(data),'sha256':digest(data)} for name,data in sections.items()},
            'efi_signed':False,'boot_tested':False,'laptop_candidate':False,
            'host_tpm_exposed':False,'host_boot_exposed':False,
            'policy_matches_extracted_sections':True,'pcr_signature_verified':True,
            'altered_signature_rejected':True,'passed':True}
    (work/'report.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
