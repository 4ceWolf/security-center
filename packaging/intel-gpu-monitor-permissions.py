#!/usr/bin/python3 -I
"""Root-only, fixed native tool permissions; no arguments or project imports."""
import os
import pathlib
import pwd
import stat
import subprocess
import sys


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1:
        raise PermissionError('Fixed administrator operation only')
    target=pathlib.Path('/usr/bin/intel_gpu_top')
    parent=target.parent.stat()
    info=target.lstat()
    if (parent.st_uid!=0 or parent.st_mode&0o022 or not stat.S_ISREG(info.st_mode)
            or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022 or info.st_nlink!=1):
        raise ValueError('Unsafe native monitor file')
    uid=pwd.getpwnam('kyo').pw_uid
    if uid!=1000:
        raise ValueError('Desktop account identity changed; review required')
    def run(args):
        return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,
                              timeout=10,check=True,env={'PATH':'/usr/bin','LC_ALL':'C'})
    owner=run(['/usr/bin/pacman','-Qqo',str(target)]).stdout.strip()
    if owner!='intel-gpu-tools':
        raise ValueError('Unexpected package owner')
    caps=run(['/usr/bin/getcap',str(target)]).stdout.strip()
    if caps not in ('',str(target)+' cap_perfmon=ep'):
        raise ValueError('Unexpected capability configuration')
    # Neither CAP_SYS_ADMIN nor broad system-wide perf access is needed.
    run(['/usr/bin/setfacl','-m','u:1000:r-x,g::---,o::---',str(target)])
    run(['/usr/bin/setcap','cap_perfmon=ep',str(target)])
    if run(['/usr/bin/getcap',str(target)]).stdout.strip()!=str(target)+' cap_perfmon=ep':
        raise ValueError('Capability verification failed')


if __name__=='__main__':
    main()
