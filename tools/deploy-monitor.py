#!/usr/bin/python3
"""Root-only protected update CLI. Never approves a file baseline or changes boot."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys


def main():
    if os.geteuid() != 0: raise PermissionError('Administrator authentication required')
    os.umask(0o077)
    # This entrypoint must run from a captured, root-owned installer runtime.
    runtime = Path(__file__).resolve().parents[1]
    directory_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(__file__).absolute().parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd); directory_fd = child
            info = os.fstat(directory_fd)
            if info.st_uid != 0 or info.st_mode & 0o022: raise PermissionError('Root-owned installer runtime required')
    finally: os.close(directory_fd)
    for path in [*runtime.joinpath('tools').glob('*.py'),*runtime.joinpath('policies').glob('*.py'),runtime/'securityd/integrity.py']:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=0 or info.st_mode&0o022:
            raise PermissionError('Unsafe installer module')
    sys.path.insert(0, str(runtime/'policies'))
    sys.path.insert(0, str(runtime/'tools'))
    sys.path.insert(0, str(runtime/'securityd'))
    from integrity import open_fixed, inspect, BASELINE
    from protected_files import ProtectedFiles, TARGETS
    from protected_transaction import TransactionStore
    from monitor_services import MonitorServices
    from monitor_deployment import Deployment
    from trust_initialization import TrustInitialization, directory
    from release_binding import capture_bundle, READ_ONLY_SCOPE
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='operation',required=True)
    sub.add_parser('inspect')
    prepare = sub.add_parser('prepare');prepare.add_argument('bundle');prepare.add_argument('--release-sha256',required=True);prepare.add_argument('--baseline-sha256',required=True)
    for action in ('apply','rollback'):
        command=sub.add_parser(action);command.add_argument('token')
    args=parser.parse_args()
    def baseline():
        fd=open_fixed(BASELINE)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('Unsafe prior baseline')
            raw=stream.read(65537)
        if len(raw)>65536:raise ValueError('Oversized baseline')
        return raw
    files=ProtectedFiles();tx=None;baseline_lock=None
    try:
        tx=TransactionStore(files)
        directory('/var/lib/security-center-monitor')
        baseline_lock=os.open('/var/lib/security-center-monitor/.baseline-approval.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        tx._private_file(baseline_lock,1048576);fcntl.flock(baseline_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def scan():
            return {**{p:files.read(p)[0] for p in TARGETS},**{p:inspect(p) for p in READ_ONLY_SCOPE}}
        flow=Deployment(tx,MonitorServices(),scan,TrustInitialization(),baseline)
        if args.operation=='inspect':
            from baseline_migration import digest
            prior=baseline()
            print(json.dumps(dict(baseline_sha256=digest(prior),scope=scan(),service_state=MonitorServices().states(),trust_state=TrustInitialization().prepare(),installed=False)))
            return
        if args.operation=='prepare':
            raw,contents=capture_bundle(args.bundle,args.release_sha256)
            token=flow.prepare(baseline(),args.baseline_sha256,raw,args.release_sha256,contents)
            print(json.dumps(dict(token=token,phase='prepared',installed=False,baseline_approved=False)))
            return
        result=flow.run(args.token,rollback=args.operation=='rollback')
        if result['phase']=='awaiting_baseline_approval':
            # Publish only the unapproved exact candidate for the separate owner gate.
            parent_fd=os.open('/var/lib/security-center-monitor',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                try:os.mkdir('baseline-review',0o700,dir_fd=parent_fd);os.fsync(parent_fd)
                except FileExistsError:pass
                review=os.open('baseline-review',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
                try:
                    tx._private_directory(review)
                    folder=tx._folder(args.token)
                    try:raw=tx._read(folder,'candidate-baseline.json',65536)
                    finally:os.close(folder)
                    name=result['candidate_sha256']+'.json'
                    try:existing=tx._read(review,name,65536)
                    except FileNotFoundError:tx._write(review,name,raw)
                    else:
                        if existing!=raw:raise ValueError('Existing review candidate differs')
                finally:os.close(review)
            finally:os.close(parent_fd)
        print(json.dumps(result))
    finally:
        if baseline_lock is not None:os.close(baseline_lock)
        if tx is not None:tx.close()
        files.close()

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'error_type':type(error).__name__,'error':str(error),'complete':False}),file=sys.stderr)
        sys.exit(1)
