"""Undeployed, root-private boot observations. Never an attestation or unlock gate."""
import json
import math
import os
import re
import stat
import time

FIELDS={'schema_version','boot_id','producer','observed_boottime','unlock','device_decision','attested'}
BOOT_ID=re.compile(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
MAX_BYTES=4096


def validate(data,boot_id,uptime):
    if not isinstance(data,dict) or set(data)!=FIELDS:raise ValueError('Invalid record schema')
    if type(data['schema_version']) is not int or data['schema_version']!=1:raise ValueError('Unsupported schema')
    if not isinstance(data['boot_id'],str) or not BOOT_ID.fullmatch(data['boot_id']) or data['boot_id']!=boot_id:
        raise ValueError('Wrong boot identity')
    if data['producer']!='security-center-observer-v1' or data['attested'] is not False:
        raise ValueError('Unsupported provenance claim')
    stamp=data['observed_boottime']
    if type(stamp) not in (float,int) or not math.isfinite(stamp) or not 0<=stamp<=uptime:
        raise ValueError('Invalid observation time')
    if data['device_decision'] not in ('allow','manual','unknown'):raise ValueError('Invalid device decision')
    result=data['unlock']
    if not isinstance(result,dict) or set(result)!={'unlocked','method','attempts'} or type(result['unlocked']) is not bool:
        raise ValueError('Invalid unlock observation')
    attempts=result['attempts'];method=result['method']
    if attempts not in (['tpm'],['manual'],['tpm','manual']):raise ValueError('Invalid attempt order')
    if method not in ('tpm','manual','none'):raise ValueError('Invalid unlock method')
    if result['unlocked'] != (method!='none') or (result['unlocked'] and method!=attempts[-1]):
        raise ValueError('Contradictory unlock result')
    if data['device_decision']!='allow' and 'tpm' in attempts:raise ValueError('TPM attempted despite policy')
    return data


def make_record(boot_id,unlock_result,decision):
    data={'schema_version':1,'boot_id':boot_id,'producer':'security-center-observer-v1',
          'observed_boottime':time.clock_gettime(time.CLOCK_BOOTTIME),'unlock':unlock_result,
          'device_decision':decision,'attested':False}
    return validate(data,boot_id,time.clock_gettime(time.CLOCK_BOOTTIME))


def private_directory(path):
    # Parent ancestry is the adapter's responsibility: production location is under /run.
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    info=os.fstat(fd)
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
        os.close(fd);raise ValueError('Record directory must be root-owned mode0700')
    return fd


def publish(directory,data):
    if os.geteuid()!=0:raise PermissionError('Root required')
    validate(data,data['boot_id'],time.clock_gettime(time.CLOCK_BOOTTIME))
    raw=json.dumps(data,sort_keys=True).encode()
    if len(raw)>MAX_BYTES:raise ValueError('Oversized record')
    parent=private_directory(directory);name='.pending-'+os.urandom(12).hex()
    try:
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            # Publish once. Existing evidence is never silently overwritten.
            os.link(name,'boot.json',src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.fsync(parent)
        finally:os.unlink(name,dir_fd=parent)
    finally:os.close(parent)


def consume(directory,current_boot_id):
    parent=private_directory(directory)
    try:fd=os.open('boot.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
            raise ValueError('Invalid record ownership/type/permissions')
        raw=f.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:raise ValueError('Oversized record')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate JSON field')
            result[key]=value
        return result
    data=json.loads(raw,object_pairs_hook=unique)
    return validate(data,current_boot_id,time.clock_gettime(time.CLOCK_BOOTTIME))
