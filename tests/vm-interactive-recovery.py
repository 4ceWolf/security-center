"""Guest-only real terminal recovery tests; all entered secrets are disposable."""
import os
if 'security_center_test_vm=1' not in open('/proc/cmdline').read().split():
    raise SystemExit('Refusing outside explicitly marked disposable guest')
import fcntl,select,signal,subprocess,sys,termios,time
sys.path.insert(0,"/policy")
from unlock_dispatch import unlock

def command(args):
    return subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15).returncode==0

if not any(line.split()[1]=='/dev/pts' for line in open('/proc/mounts')):
    os.makedirs('/dev/pts',exist_ok=True)
    assert command(['mount','-t','devpts','devpts','/dev/pts'])

SECRET=b'DISPOSABLE-VM-ONLY-NOT-A-LAPTOP-PASSWORD'

def attempt(label,answer,expected):
    master,slave=os.openpty()
    pid=os.fork()
    if pid==0:
        os.close(master);os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
        for target in (0,1,2):os.dup2(slave,target)
        if slave>2:os.close(slave)
        os.execve('/usr/bin/cryptsetup',['cryptsetup','open','--disable-external-tokens',
            '--key-slot','0','--tries','1','--timeout','2','/dev/vda','interactive_test'],
            {'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    output=bytearray();prompt=False;status=None;deadline=time.monotonic()+15
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],.05)
            if ready:
                try:chunk=os.read(master,4096)
                except OSError:chunk=b''
                output.extend(chunk)
                if len(output)>16384:raise AssertionError('Unexpected terminal output volume')
                if not prompt and b'Enter passphrase' in output:
                    assert not (termios.tcgetattr(slave)[3]&termios.ECHO), 'Secret echo must be disabled'
                    prompt=True
                    if answer is not None:os.write(master,answer)
            done,child_status=os.waitpid(pid,os.WNOHANG)
            if done:
                status=child_status;break
        assert status is not None,'Interactive recovery exceeded outer timeout'
        assert prompt,'Recovery must actually request terminal input'
        assert SECRET not in output,'Passphrase leaked to terminal output'
        success=os.waitstatus_to_exitcode(status)==0
        assert success is expected,(label,'unexpected return status')
        active=command(['cryptsetup','status','interactive_test'])
        assert active is expected,(label,'unexpected mapping state')
        if active:assert command(['cryptsetup','close','interactive_test'])
        return success
    finally:
        if status is None:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(pid,0)
        os.close(master);os.close(slave)

# A valid TPM token/signature exists here. Denied input must never auto-unlock.
def decision():
    if os.path.exists('/run/device-check-finished'):
        if not command(['systemctl','is-active','--quiet','device-check.service']):
            raise RuntimeError('Device check service failed')
    return {'allow_tpm_attempt':False,'manual_recovery_required':True}

for label,answer,expected in [('WRONG',b'WRONG-DISPOSABLE-INPUT\n',False),
                              ('CANCEL',b'\x03',False),('TIMEOUT',None,False),
                              ('CORRECT',SECRET+b'\n',True)]:
    calls=[];completed=[]
    def tpm():
        calls.append('tpm')
        raise AssertionError('TPM must never be attempted')
    def manual():
        calls.append('manual')
        success=attempt(label,answer,expected)
        completed.append(success)
        return success
    result=unlock(decision,tpm,manual)
    assert completed==[expected], 'Interactive assertions did not complete'
    assert calls==['manual'] and result['attempts']==['manual']
    assert result['unlocked'] is expected
    assert result['method']==('manual' if expected else 'none')
    print('VM_INTERACTIVE_'+label+'_PASS',flush=True)
