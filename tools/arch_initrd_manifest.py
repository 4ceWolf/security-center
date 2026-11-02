"""Bounded, nonextracting inventory of Arch early-newc + zstd-newc test images.

No image authorization. Unsupported compression, hardlinked payloads or special
nodes refuse rather than disappear from the reported inventory.
"""
import hashlib
import os
import pathlib
import select
import stat
import subprocess
import tempfile
import time

MAX_IMAGE = 256*1024*1024
MAX_DECODED = 256*1024*1024
MAX_MEMBER = 64*1024*1024
MAX_ENTRIES = 16384


def newc(raw, start=0):
    pos=start;files={}
    while True:
        if pos+110>len(raw) or raw[pos:pos+6]!=b'070701':raise ValueError('Invalid newc header')
        header=raw[pos+6:pos+110];pos+=110
        if any(value not in b'0123456789abcdefABCDEF' for value in header):raise ValueError('Invalid header digits')
        values=[int(header[i:i+8],16) for i in range(0,104,8)]
        ino,mode,uid,gid,nlink,mtime,size,devmajor,devminor,rmajor,rminor,namesize,checksum=values
        if not 1<=namesize<=4096 or size>MAX_MEMBER or pos+namesize>len(raw):raise ValueError('Member exceeds bound')
        name_raw=raw[pos:pos+namesize];pos+=namesize
        if not name_raw.endswith(b'\0') or b'\0' in name_raw[:-1]:raise ValueError('Invalid member name')
        name=name_raw[:-1].decode('utf-8','strict')
        pad=(-pos)%4
        if pos+pad>len(raw) or any(raw[pos:pos+pad]):raise ValueError('Invalid name padding')
        pos+=pad
        if name=='TRAILER!!!':
            if size or mode:raise ValueError('Invalid trailer')
            return dict(format='newc',files=files,archive_bytes=pos-start),pos
        raw_name=name
        if name.startswith('./'):name=name[2:]
        if stat.S_IFMT(mode)==stat.S_IFDIR and name.endswith('/'):
            name=name[:-1]
        if raw_name in ('.','./'):name='.'
        if name!='.' and (not name or name.startswith('/') or str(pathlib.PurePosixPath(name))!=name or '..' in pathlib.PurePosixPath(name).parts):
            raise ValueError('Unsafe archive member: '+repr(name))
        if name in files or len(files)>=MAX_ENTRIES or pos+size>len(raw):raise ValueError('Duplicate, excessive or truncated member')
        kind=stat.S_IFMT(mode)
        if kind not in (stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK):raise ValueError('Unsupported special node')
        if checksum or rmajor or rminor or (kind!=stat.S_IFDIR and nlink>1):raise ValueError('Unsupported link/device/checksum metadata: '+name+' '+str((nlink,rmajor,rminor,checksum)))
        if kind==stat.S_IFDIR and size:raise ValueError('Directory payload')
        if kind==stat.S_IFLNK and not 1<=size<=4096:raise ValueError('Invalid symlink size')
        payload=raw[pos:pos+size];pos+=size
        pad=(-pos)%4
        if pos+pad>len(raw) or any(raw[pos:pos+pad]):raise ValueError('Invalid payload padding')
        pos+=pad
        item=dict(raw_name=raw_name,mode=mode,uid=uid,gid=gid,nlink=nlink,size=size,mtime=mtime,
                  devmajor=devmajor,devminor=devminor,ino=ino,sha256=hashlib.sha256(payload).hexdigest())
        if kind==stat.S_IFLNK:
            if b'\0' in payload:raise ValueError('Invalid symlink target')
            item['symlink_target']=payload.decode('utf-8','strict')
        files[name]=item


def zstd(raw):
    output=bytearray();child=None
    with tempfile.TemporaryFile(dir=pathlib.Path(__file__).resolve().parents[1]/'work') as stream:
        stream.write(raw);stream.seek(0)
        child=subprocess.Popen(['/usr/bin/zstd','-d','-q','--stdout'],stdin=stream,
                               stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+15
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ValueError('Decompression timeout')
                if not select.select([child.stdout],[],[],remaining)[0]:raise ValueError('Decompression timeout')
                block=os.read(child.stdout.fileno(),65536)
                if not block:break
                output.extend(block)
                if len(output)>MAX_DECODED:raise ValueError('Decoded archive exceeds bound')
            if child.wait(timeout=3)!=0:raise ValueError('Invalid zstd stream')
        finally:
            if child.poll() is None:child.kill()
            child.wait(timeout=3);child.stdout.close()
    return bytes(output)


def inspect(raw):
    if not isinstance(raw,bytes) or len(raw)>MAX_IMAGE:raise ValueError('Image exceeds bound')
    early,end=newc(raw)
    boundary=end
    while boundary<len(raw) and raw[boundary]==0:boundary+=1
    if boundary-end>10240 or raw[boundary:boundary+4]!=b'\x28\xb5\x2f\xfd':raise ValueError('Expected bounded padding then zstd main image')
    decoded=zstd(raw[boundary:])
    main,finish=newc(decoded)
    if len(decoded)-finish>10240 or any(decoded[finish:]):raise ValueError('Unsupported main archive trailer')
    early.update(offset=0,compression='none',sha256=hashlib.sha256(raw[:boundary]).hexdigest(),stored_bytes=boundary)
    main.update(offset=boundary,compression='zstd',sha256=hashlib.sha256(raw[boundary:]).hexdigest(),
                stored_bytes=len(raw)-boundary,decoded_bytes=len(decoded))
    return dict(schema_version=1,approved=False,format='early-newc+zstd-newc',
                image_sha256=hashlib.sha256(raw).hexdigest(),segments=[early,main])
