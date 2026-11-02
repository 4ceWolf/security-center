#!/usr/bin/python3
"""Disposable regular-file LUKS2 integration. No host disks or physical TPM."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('helper',ROOT/'tools/tpm-unlock-helper.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='unlock-disable-fixture-',dir=ROOT/'work') as temporary:
    folder=Path(temporary);device=folder/'test.img';key=folder/'fixture.key';backup=folder/'header.img'
    key.write_bytes(os.urandom(32))
    with device.open('wb') as stream:stream.truncate(64*1024*1024)
    def native(*args,data=None):return h.run([h.CRYPT,*args],data=data,timeout=90)
    native('luksFormat','--batch-mode','--type','luks2','--pbkdf','pbkdf2','--pbkdf-force-iterations','1000','--key-file',str(key),str(device))
    native('luksAddKey','--pbkdf','pbkdf2','--pbkdf-force-iterations','1000','--key-slot','2','--key-file',str(key),str(device),str(key))
    token={'type':'systemd-tpm2','keyslots':['2'],'tpm2-pcrs':[7],'tpm2-blob':'AA==','tpm2-policy-hash':'00','tpm2-pin':False}
    native('token','import','--disable-external-tokens','--token-id','1',str(device),data=json.dumps(token).encode())
    before=h.read_metadata(str(device));identity={'fixture':True};review=h.proposal(before,identity)
    records=[]
    def verify(_device,secret):h.verify_passphrase(str(device) if _device==h.DEVICE else _device,secret)
    def save(_before):
        native('luksHeaderBackup',str(device),'--header-backup-file',str(backup))
        return h.read_metadata(str(backup)),str(backup),'fixture-only'
    result=h.disable(review,capture=lambda:(h.read_metadata(str(device)),identity),credential=lambda:bytearray(key.read_bytes()),
        verify=verify,backup=save,remove=lambda tid:native('token','remove','--token-id',tid,str(device)),record=records.append)
    assert result['disabled'] and result['manual_slot_0_preserved'] and not result['boot_verified']
    assert h.read_metadata(str(device))==h.after_removal(before,'1')
    h.verify_passphrase(str(device),bytearray(key.read_bytes()))
    assert records[-1]['phase']=='disabled'
    print('PASS: native LUKS2 backup readable, exact token removed, every keyslot/unrelated field unchanged, manual slot0 verifies before and after; synthetic TPM token only, no hardware TPM/boot claim')
