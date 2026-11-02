#!/usr/bin/python3
"""On-demand administrator helper; staged, fixed operations and fixed paths only."""
import contextlib
import fcntl
import json
import os
import pathlib
import stat
import sys
import tempfile

LIB = pathlib.Path('/usr/local/lib/security-center')
SEED = pathlib.Path('/etc/security-center/normal-devices.candidate.json')


@contextlib.contextmanager
def update_guard():
    """Serialize helper execution/imports with the protected installer."""
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    lock=None
    try:
        for part in ('var','lib','security-center-updates'):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
            info=os.fstat(parent)
            if info.st_uid!=0 or info.st_mode&0o022:raise PermissionError('Unsafe update-lock parent')
        lock=os.open('update.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
            raise PermissionError('Unsafe update lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        if lock is not None:os.close(lock)
        os.close(parent)


def main():
    if os.geteuid()!=0:raise PermissionError('Administrator access required')
    with update_guard(), tempfile.TemporaryDirectory(prefix='security-center-helper-',dir='/run') as cache:
        # Never execute a preexisting project-module bytecode cache as root.
        sys.pycache_prefix=cache
        sys.dont_write_bytecode=True
        authorized_main()


def authorized_main():
    # The Cockpit superuser bridge must establish administrator authorization first.
    if os.geteuid() != 0:
        raise PermissionError('Administrator access required')
    if len(sys.argv) != 1:
        raise ValueError('Arguments are not supported')
    sys.path.insert(0, str(LIB))
    from trust_policy import MAX_BYTES, decode, validate
    from trust_store import Store
    from device_inventory import collect
    request = decode(sys.stdin.buffer.read(MAX_BYTES + 1))
    if not isinstance(request, dict): raise ValueError('Invalid request')
    operation = request.get('operation')
    native_fields = {'native_list': {'operation'}, 'native_review': {'operation','action','selected_id'},
                     'native_apply': {'operation','proposal'}}
    if isinstance(operation, str) and operation in native_fields:
        if set(request) != native_fields[operation]: raise ValueError('Unsupported native request')
        import usb_policy
        if operation == 'native_list': result = usb_policy.view()
        elif operation == 'native_review': result = usb_policy.propose(usb_policy.capture(), request['action'], request['selected_id'])
        else: result = usb_policy.apply(request['proposal'])
        print(json.dumps({'ok': True, 'result': result}))
        return
    fields = {'list': {'operation'}, 'propose': {'operation', 'action', 'device_id'}, 'apply': {'operation', 'proposal'}}
    if not isinstance(operation, str) or operation not in fields or set(request) != fields[operation]:
        raise ValueError('Unsupported request')
    fd = os.open(SEED, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise PermissionError('Unsafe installed seed policy')
        with os.fdopen(fd, 'rb', closefd=False) as stream: seed = validate(decode(stream.read(MAX_BYTES + 1)))
    finally: os.close(fd)
    result = dispatch(request, Store(), seed, collect, actor=0)
    print(json.dumps({'ok': True, 'result': result}))


def dispatch(request, store, seed, collect, *, actor):
    """Testable fixed-operation boundary; main establishes root and fixed paths."""
    from trust_policy import view, propose
    fields = {'list': {'operation'}, 'propose': {'operation', 'action', 'device_id'}, 'apply': {'operation', 'proposal'}}
    if not isinstance(request, dict) or not isinstance(request.get('operation'), str):
        raise ValueError('Invalid request')
    operation = request['operation']
    if operation not in fields or set(request) != fields[operation]:
        raise ValueError('Unsupported request')
    policy = store.read(seed)
    inventory = collect()
    if operation == 'list': return view(policy, inventory)
    if operation == 'propose': return propose(policy, inventory, request['action'], request['device_id'])
    policy = store.save(seed, request['proposal'], inventory, actor=actor)
    try:
        refreshed = collect()
    except Exception:
        refreshed = {}
    # A failed post-commit observation must not erase the successful receipt.
    return view(policy, refreshed)



if __name__ == '__main__':
    try: main()
    except Exception as error:
        # No raw exceptions, paths or tracebacks in browser responses.
        code = 'authorization_required' if isinstance(error, PermissionError) else 'busy' if isinstance(error, BlockingIOError) else 'review_required' if isinstance(error, ValueError) else 'unavailable'
        print(json.dumps({'ok': False, 'error': code}))
        sys.exit(1)
