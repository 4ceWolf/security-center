#!/usr/bin/python3
"""Offline captured UKI section/signature review; never signing or boot changes."""
import base64,hashlib,json,pathlib,subprocess,os
import pefile
BASE=pathlib.Path('/home/user/Projects/security-center')
FOLDER=BASE/'work/current-uki-qo1bvv4d'
MEASURED=('linux','osrel','cmdline','initrd','ucode','splash','dtb','dtbauto','uname','sbat','pcrpkey','profile','hwids','efifw')

def main():
 os.umask(0o077)
 receipt=json.loads((FOLDER/'receipt.json').read_text())
 if receipt.get('source_matches_audit') is not True or receipt.get('efi_signature_verified') is not True:raise ValueError('Verified capture required')
 path=FOLDER/'zen.efi';h=hashlib.sha256()
 with path.open('rb') as f:
  while b:=f.read(65536):h.update(b)
 if h.hexdigest()!=receipt['files']['zen.efi']['sha256']:raise ValueError('Capture changed')
 pe=pefile.PE(str(path),fast_load=True);sections={};small={};root=FOLDER/'sections';root.mkdir(mode=0o700,exist_ok=True)
 with path.open('rb') as image:
  for s in pe.sections:
   name=s.Name.rstrip(b'\0').decode('ascii')
   if name in sections or len(name)>16:raise ValueError('Ambiguous section')
   size=s.Misc_VirtualSize
   if size>256*1024*1024 or s.PointerToRawData+s.SizeOfRawData>path.stat().st_size:raise ValueError('Section bounds')
   # Uninitialized PE sections are inventoried but never passed as UKI payloads.
   if size>s.SizeOfRawData:
    if name[1:] in MEASURED or name=='.pcrsig':raise ValueError('Truncated measured section')
    sections[name]={'virtual_size':size,'raw_size':s.SizeOfRawData,'uninitialized':True};continue
   image.seek(s.PointerToRawData);left=size;hasher=hashlib.sha256();parts=[]
   output=(root/name[1:]).open('wb') if name[1:] in MEASURED else None
   try:
    while left:
     b=image.read(min(left,65536))
     if not b:raise ValueError('Truncated section')
     hasher.update(b);left-=len(b)
     if output:output.write(b)
     if name in ('.pcrsig','.pcrpkey','.cmdline','.uname'):
      if size>65536:raise ValueError('Public metadata bound')
      parts.append(b)
   finally:
    if output:output.close()
   sections[name]={'virtual_size':size,'raw_size':s.SizeOfRawData,'sha256':hasher.hexdigest()}
   if parts:small[name]=b''.join(parts).rstrip(b'\0')
 pe.close()
 if small['.pcrpkey'].rstrip()!=(FOLDER/'pcr-public.pem').read_bytes().rstrip():raise ValueError('Embedded public key differs')
 args=['/usr/lib/systemd/systemd-measure','policy-digest','--bank=sha256','--phase=enter-initrd','--policyref=initrd','--json=short']
 args += ['--'+name+'='+str(root/name) for name in MEASURED if '.'+name in sections]
 expected=json.loads(subprocess.check_output(args,timeout=30))['sha256']
 signatures=json.loads(small['.pcrsig'])['sha256'];candidates=[x for x in signatures if x.get('ref')=='initrd']
 if len(expected)!=1 or len(candidates)!=1:raise ValueError('Unexpected initrd policy count')
 policy=expected[0];signed=candidates[0]
 if policy['pcrs']!=[11] or any(signed.get(k)!=policy[k] for k in ('pol','pcrs','ref')):raise ValueError('Signed initrd phase mismatch')
 der=subprocess.check_output(['/usr/bin/openssl','rsa','-pubin','-in',str(FOLDER/'pcr-public.pem'),'-RSAPublicKey_out','-outform','DER'],stderr=subprocess.DEVNULL,timeout=10)
 if signed['pkfp']!=hashlib.sha256(der).hexdigest():raise ValueError('Signing fingerprint mismatch')
 (FOLDER/'initrd-policy.tbs').write_bytes(bytes.fromhex(policy['tbs']));(FOLDER/'initrd-policy.sig').write_bytes(base64.b64decode(signed['sig'],validate=True))
 checked=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-verify',str(FOLDER/'pcr-public.pem'),'-signature',str(FOLDER/'initrd-policy.sig'),str(FOLDER/'initrd-policy.tbs')],capture_output=True,text=True,timeout=10)
 if checked.returncode:raise ValueError('PCR signature verification failed')
 result={'passed':True,'source_sha256':receipt['files']['zen.efi']['sha256'],'efi_signature_verified':True,'initrd_signature_matches_extracted_sections':True,'pcr_public_key_matches':True,'initrd_policy':{'pcrs':signed['pcrs'],'ref':signed['ref'],'pkfp':signed['pkfp'],'pol':signed['pol']},'sections':sections,'command_line':small['.cmdline'].decode().strip(),'kernel_release':small.get('.uname',b'').decode().strip(),'other_signature_refs':[x.get('ref') for x in signatures if x is not signed],'private_keys_accessed':False,'host_changes':False}
 (FOLDER/'section-review.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
