"""Actual PID1 supervision of the guest-only observer and a hung fixture."""
import hashlib
import json
import pathlib
import subprocess
import sys
import time
if 'security_center_test_vm=1' not in pathlib.Path('/proc/cmdline').read_text().split():
    raise SystemExit('Refusing outside disposable guest')
sys.path.insert(0, '/policy')
from gate_record import read_record
base = pathlib.Path('/etc/systemd/system')
(base/'gate-observer.service').write_text('''[Unit]
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /policy/gate_observer.py
RuntimeDirectory=security-center-gate
RuntimeDirectoryMode=0700
RemainAfterExit=yes
TimeoutStartSec=5
TimeoutStopSec=1
KillMode=control-group
''')
(base/'gate-observer-hang.service').write_text('''[Unit]
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/usr/bin/sleep 30
TimeoutStartSec=1
TimeoutStopSec=1
KillMode=control-group
''')
def run(args):
    return subprocess.run(args, check=True, capture_output=True, timeout=10)
run(['systemctl', 'daemon-reload'])
run(['systemctl', 'start', 'gate-observer.service'])
assert run(['systemctl', 'is-active', 'gate-observer.service']).stdout.strip() == b'active'
policy = hashlib.sha256(pathlib.Path('/policy/normal-devices.json').read_bytes()).hexdigest()
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
context = dict(boot_id=boot, policy_sha256=policy, mode='normal',
               now=time.clock_gettime(time.CLOCK_BOOTTIME), checker_ok=True)
assert read_record('/run/security-center-gate', **context)['allow_tpm_attempt'] is False
summary = json.loads(pathlib.Path('/run/security-center-gate/observations.json').read_bytes())
assert summary['observation_only'] is True and summary['usb_count'] >= 1
prior = pathlib.Path('/run/security-center-gate/decision.json').read_bytes()
started = time.monotonic()
result = subprocess.run(['systemctl', 'start', 'gate-observer-hang.service'],
                        capture_output=True, timeout=10)
assert result.returncode != 0 and time.monotonic()-started < 6
assert run(['systemctl', 'show', 'gate-observer-hang.service', '--property=Result', '--value']).stdout.strip() == b'timeout'
assert run(['systemctl', 'show', 'gate-observer-hang.service', '--property=MainPID', '--value']).stdout.strip() == b'0'
assert pathlib.Path('/run/security-center-gate/decision.json').read_bytes() == prior
try:
    read_record('/run/security-center-gate', **dict(context, checker_ok=False))
except ValueError:
    pass
else:
    raise AssertionError('Failed supervisor reused prior evidence')
print('VM_OBSERVER_SUPERVISION_PASS', flush=True)
