"""Disposable guest assertions outside any unlock callback exception boundary."""
import pathlib
import subprocess
assert 'security_center_test_vm=1' in pathlib.Path('/proc/cmdline').read_text().split()
unit = 'systemd-cryptsetup@cold_root.service'
def show(name, field):
    return subprocess.check_output(['systemctl', 'show', name, '--property='+field, '--value'], text=True, timeout=2).strip()
text = pathlib.Path('/run/systemd/generator/'+unit).read_text()
assert '/usr/bin/systemd-cryptsetup attach' in text
mode = pathlib.Path('/stock-mode').read_text()
assert 'password-cache=no' in text
assert ('headless=yes' in text) is (mode != 'manual')
loaded = show(unit, 'ExecStart')
assert '/usr/bin/systemd-cryptsetup attach cold_root' in loaded
assert '/cold-unlock.py' not in loaded
assert len(list(pathlib.Path('/run/systemd/generator').glob('systemd-cryptsetup@*.service'))) == 1
assert 'security-center-observation.service' in show(unit, 'Wants').split()
assert 'security-center-observation.service' in show(unit, 'After').split()
assert 'security-center-observation.service' not in show(unit, 'Requires').split()
mode = pathlib.Path('/stock-mode').read_text()
observer = 'security-center-observation.service'
expected = {'success':'success', 'failed':'exit-code', 'timeout':'timeout', 'memory':'oom-kill', 'manual':'success'}
if mode in ('absent','masked'):
    assert show(observer, 'LoadState') == ('not-found' if mode=='absent' else 'masked')
else:
    result = show(observer, 'Result')
    assert result == expected[mode], (result, mode)
    print('\nVM_STOCK_OBSERVER_RESULT_'+result.upper().replace('-', '_'), flush=True)
    print('\nVM_STOCK_OBSERVER_MEMORY_'+show(observer, 'MemoryPeak'), flush=True)
if pathlib.Path('/arch-provision').exists():
    print('\nVM_STOCK_PCRPHASE_CONDITION_'+show('systemd-pcrphase-initrd.service','ConditionResult').upper(),flush=True)
assert show(unit, 'Result') == 'success'
assert not pathlib.Path('/run/security-center-boot/boot.json').exists()
print('\nVM_STOCK_COMMAND_UNCHANGED', flush=True)
print('\nVM_STOCK_MANUAL_RECOVERED' if mode=='manual' else '\nVM_STOCK_TPM_UNLOCKED', flush=True)
