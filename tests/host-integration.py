"""Explicit local integration checks; run as root. Always restart collector."""
import subprocess, json, pathlib, socket

def run(args):
 return subprocess.check_output(args,text=True,timeout=15)
assert '127.0.0.1:9090' in run(['/usr/bin/ss','-lnt'])
assert '[integrity]' in pathlib.Path('/sys/kernel/security/lockdown').read_text()
probe=subprocess.run(['/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups',
 '/usr/bin/python3','-I','/usr/local/lib/security-center/client.py'],capture_output=True,text=True)
assert probe.returncode != 0 and 'PermissionError' in probe.stderr
print('PASS: unprivileged non-wheel user cannot read socket')
try:
 subprocess.run(['/usr/bin/systemctl','stop','security-center.service'],check=True)
 assert not pathlib.Path('/run/security-center/status.sock').exists()
 rules=json.loads(run(['/usr/bin/nft','-j','list','table','inet','machine_care_guard']))
 assert any(x.get('chain',{}).get('hook')=='input' and x['chain'].get('policy')=='drop' for x in rules['nftables'])
 assert '[integrity]' in pathlib.Path('/sys/kernel/security/lockdown').read_text()
 print('PASS: collector stopped; firewall and lockdown remain enforced')
finally:
 subprocess.run(['/usr/bin/systemctl','start','security-center.service'],check=True)
print('PASS: collector restarted')
