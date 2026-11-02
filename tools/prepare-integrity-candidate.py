#!/usr/bin/python3
"""Offline candidate only. Does not deploy, select a boot entry, or alter TPM/LUKS."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import pefile

SOURCE = Path('/boot/EFI/Linux/arch-linux-zen.efi')
CONFIG = Path('/etc/miku-boot/zen-uki.conf')
PUBLIC = Path('/etc/miku-boot/zen-pcr-public.pem')
CERT = Path('/var/lib/sbctl/keys/db/db.pem')
STUB = Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub')
DEVICE = '/dev/nvme0n1p2'


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=180,
                          env={'PATH':'/usr/bin','LC_ALL':'C'}, **kwargs).stdout


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def sections(path):
    with pefile.PE(str(path)) as pe:
        out = {}
        for s in pe.sections:
            name = s.Name.rstrip(b'\0').decode()
            if name in out: raise RuntimeError('Multiple profiles/duplicate sections need review')
            out[name] = s.get_data()[:min(s.Misc_VirtualSize,s.SizeOfRawData)]
        return out


def public_der(data):
    if b'-----BEGIN' not in data:
        try: data = base64.b64decode(data, validate=True)
        except ValueError: pass
    for fmt in ('PEM','DER'):
        try: return run(['/usr/bin/openssl','pkey','-pubin','-inform',fmt,'-outform','DER'],input=data)
        except subprocess.CalledProcessError: pass
    raise RuntimeError('Could not normalize enrolled public key')


def main():
    if os.geteuid()!=0: raise SystemExit('Run through system administrator authentication')
    os.umask(0o077)
    meta = run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata',DEVICE])
    d = json.loads(meta)
    assert set(d['keyslots']) == {'0','2'}, 'Unexpected LUKS slots: review required'
    tokens=[v for v in d['tokens'].values() if v.get('type')=='systemd-tpm2']
    assert len(tokens)==1
    t=tokens[0]
    assert t['keyslots']==['2'] and t['tpm2-pcrs']==[7]
    assert t['tpm2_pubkey_pcrs']==[11] and t['tpm2_pubkey_ref']=='initrd'
    assert t['tpm2-pcr-bank']=='sha256'
    assert public_der(t['tpm2_pubkey'].encode())==public_der(PUBLIC.read_bytes())
    original=sections(SOURCE); stub=sections(STUB)
    assert original['.text']==stub['.text'], 'Installed stub differs from working image; review required'
    assert public_der(original['.pcrpkey'])==public_der(PUBLIC.read_bytes())
    supported={'.sbat','.osrel','.cmdline','.uname','.pcrpkey','.linux','.initrd','.pcrsig'}
    assert not (set(original)-set(stub)-supported), 'Unexpected sections need preservation review'
    assert '.profile' not in original
    oldline=original['.cmdline'].rstrip(b'\0').decode().strip()
    assert not any(x.startswith('lockdown=') for x in oldline.split())
    expected=oldline+' lockdown=integrity'
    source_hash=sha(SOURCE); config_hash=sha(CONFIG)
    root=Path('/var/lib/security-center')
    root.mkdir(mode=0o700,exist_ok=True)
    out=root/('integrity-candidate-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(mode=0o700)
    # Save the exact known-good image independently of the ESP.
    import shutil
    shutil.copyfile(SOURCE,out/'known-good.efi')
    for name in ('.linux','.initrd','.osrel','.uname','.pcrpkey'):
        (out/name[1:]).write_bytes(original[name])
    (out/'cmdline').write_text(expected+'\n')
    candidate=out/'candidate.efi'
    command=['/usr/lib/systemd/ukify','build','--config='+str(CONFIG),
             '--linux='+str(out/'linux'),'--initrd='+str(out/'initrd'),
             '--cmdline=@'+str(out/'cmdline'),'--os-release=@'+str(out/'osrel'),
             '--uname='+original['.uname'].rstrip(b'\0').decode().strip(),
             '--no-sign-kernel','--output='+str(candidate)]
    try:
        proc=subprocess.run(command,capture_output=True,timeout=240)
        (out/'build.log').write_bytes(proc.stdout+proc.stderr)
        proc.check_returncode()
        run(['/usr/bin/sbverify','--cert',str(CERT),str(candidate)])
        built=sections(candidate)
        for name in ('.linux','.initrd','.uname','.pcrpkey'):
            assert built[name]==original[name], name+' changed unexpectedly'
        assert built['.osrel'].rstrip(b'\0\n')==original['.osrel'].rstrip(b'\0\n')
        assert built['.cmdline'].rstrip(b'\0').decode().strip()==expected
        policies=json.loads(built['.pcrsig'].rstrip(b'\0'))
        assert any(p.get('ref')=='initrd' and p.get('pcrs')==[11] for p in policies.get('sha256',[])), 'Initrd-bound signed PCR11 policy missing'
        assert sha(SOURCE)==source_hash and sha(CONFIG)==config_hash
        assert run(['/usr/bin/cryptsetup','luksDump','--dump-json-metadata',DEVICE])==meta
        report={'status':'candidate built; NOT boot tested or deployed','directory':str(out),
                'original_sha256':source_hash,'candidate_sha256':sha(candidate),
                'secure_boot_signature':'verified with existing db certificate',
                'kernel_and_initrd':'byte-identical to working image',
                'public_key':'matches existing enrolled TPM policy key',
                'pcr_policy':'sha256 PCR11 with initrd reference present; live unseal requires boot test',
                'cmdline_addition':'lockdown=integrity','luks_metadata_unchanged':True,
                'boot_files_unchanged':True,'command':command}
        (out/'report.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))
    except Exception:
        (out/'NOT_VALIDATED').write_text('Candidate failed validation. Do not deploy. Inspect build.log locally.\n')
        raise

if __name__=='__main__':main()
