#!/usr/bin/python3
"""Reviewed installation update; not exposed through any dashboard action."""
import pathlib,subprocess,os,json,hashlib
p=pathlib.Path('/home/user/Projects/security-center')
assert os.geteuid()==0
record=p/'backups/mvp-install.json';data=json.loads(record.read_text())
files={x['path']:x for x in data['files']}
changes=[('securityd/daemon.py','/usr/local/lib/security-center/daemon.py'),
 ('securityd/history.py','/usr/local/lib/security-center/history.py'),
 ('securityd/client.py','/usr/local/lib/security-center/client.py'),
 ('packaging/security-center.service','/etc/systemd/system/security-center.service'),
 ('cockpit/app.js','/usr/local/share/cockpit/security_center/app.js'),
 ('cockpit/index.html','/usr/local/share/cockpit/security_center/index.html'),
 ('cockpit/style.css','/usr/local/share/cockpit/security_center/style.css')]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for src,dst in changes:
 d=pathlib.Path(dst)
 if dst in files:assert sha(d)==files[dst]['sha256'], 'Installed file changed; review needed'
 else:assert not d.exists()
backup=p/'backups/history-before';backup.mkdir(mode=0o700)
(backup/'install-record.json').write_bytes(record.read_bytes())
for src,dst in changes:
 d=pathlib.Path(dst)
 if d.exists():(backup/(d.parent.name+'-'+d.name)).write_bytes(d.read_bytes())
subprocess.run(['/usr/bin/systemctl','stop','security-center.service'],check=True)
try:
 for src,dst in changes:
  d=pathlib.Path(dst);temp=d.with_suffix(d.suffix+'.new')
  with temp.open('xb') as f:f.write((p/src).read_bytes());f.flush();os.fsync(f.fileno())
  os.chmod(temp,0o644);os.replace(temp,d)
  files[dst]={'path':dst,'sha256':sha(d)}
 data['files']=list(files.values());record.write_text(json.dumps(data,indent=2))
finally:
 subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
 subprocess.run(['/usr/bin/systemctl','start','security-center.service'],check=True)
print('Persistent history installed; service restarted')
