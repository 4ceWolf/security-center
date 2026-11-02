"""Bounded manifest of our single-newc test initrd. Reads; never extracts.

Unsupported archive variants require review. A manifest captures bytes; it does
not approve their behavior, signatures or fitness for production boot.
"""
import hashlib
import pathlib
import stat

MAX_ENTRIES = 8192
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024


def inspect_newc(stream):
    consumed = 0
    files = {}

    def read(size):
        nonlocal consumed
        if size < 0 or consumed+size > MAX_TOTAL:
            raise ValueError('Archive exceeds bound')
        out = stream.read(size)
        if len(out) != size:
            raise ValueError('Truncated archive')
        consumed += size
        return out

    def align():
        if any(read((-consumed) % 4)):
            raise ValueError('Nonzero archive padding')

    while True:
        header = read(110)
        if header[:6] != b'070701':
            raise ValueError('Expected single newc archive')
        if any(value not in b'0123456789abcdefABCDEF' for value in header[6:]):
            raise ValueError('Invalid archive header digits')
        try:
            fields = [int(header[i:i+8], 16) for i in range(6,110,8)]
        except ValueError:
            raise ValueError('Invalid archive header') from None
        ino, mode, uid, gid, links, mtime, size, major, minor, rmajor, rminor, namesize, checksum = fields
        if not 1 <= namesize <= 4096 or size > MAX_FILE:
            raise ValueError('Member exceeds bound')
        name_raw = read(namesize)
        if not name_raw.endswith(b'\0') or b'\0' in name_raw[:-1]:
            raise ValueError('Invalid member name')
        name = name_raw[:-1].decode('utf-8', errors='strict')
        align()
        if name == 'TRAILER!!!':
            if size != 0 or mode != 0:
                raise ValueError('Invalid trailer')
            if stream.read(1):
                raise ValueError('Unsupported trailing archive data')
            break
        parts = pathlib.PurePosixPath(name).parts
        if (not name or name.startswith('/') or any(part in ('.','..') for part in name.split('/'))
                or str(pathlib.PurePosixPath(name)) != name or name in files or len(files) >= MAX_ENTRIES):
            raise ValueError('Unsafe, duplicate or excessive member names')
        if links != 1 or checksum != 0 or any((major,minor,rmajor,rminor)):
            raise ValueError('Unsupported link/device/checksum metadata')
        kind = stat.S_IFMT(mode)
        if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            raise ValueError('Unsupported special member')
        if kind == stat.S_IFDIR and size != 0:
            raise ValueError('Directory payload unsupported')
        if kind == stat.S_IFLNK and not 1 <= size <= 4096:
            raise ValueError('Invalid symlink size')
        digest = hashlib.sha256()
        left = size
        target = b''
        while left:
            block = read(min(left,65536))
            digest.update(block)
            if kind == stat.S_IFLNK:
                target += block
            left -= len(block)
        align()
        item = dict(mode=mode,uid=uid,gid=gid,size=size,sha256=digest.hexdigest(),
                    mtime=mtime,nlink=links)
        if kind == stat.S_IFLNK:
            if b'\0' in target:
                raise ValueError('Invalid symlink target')
            item['symlink_target'] = target.decode('utf-8',errors='strict')
        files[name] = item
    for name in files:
        for parent in pathlib.PurePosixPath(name).parents:
            if str(parent) == '.':
                continue
            if str(parent) not in files or not stat.S_ISDIR(files[str(parent)]['mode']):
                raise ValueError('Missing parent or member beneath symlink')
    return dict(schema_version=1, format='single-newc', approved=False,
                archive_bytes=consumed,files=files)


def verify(actual, reviewed):
    """Match captured structure; caller must separately authenticate review digest."""
    if (not isinstance(reviewed,dict) or actual != reviewed):
        raise ValueError('Initrd differs from the pinned manifest')
    return True
