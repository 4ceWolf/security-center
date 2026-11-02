#!/usr/bin/python3
"""Reviewed one-time installation; never callable by the web API."""
import pathlib
import subprocess
import shutil
import os
import hashlib
import json

raise SystemExit('Retired fresh-install script: use the reviewed protected update workflow; device trust requires journalled initialization.')

source = pathlib.Path('/home/user/Projects/security-center')
assert os.geteuid() == 0
lib = pathlib.Path('/usr/local/lib/security-center')
ui = pathlib.Path('/usr/local/share/cockpit/security_center')
unit = pathlib.Path('/etc/systemd/system/security-center.service')
listen = pathlib.Path('/etc/systemd/system/cockpit.socket.d/security-center-local.conf')
for p in (lib, ui, unit, listen):
    if p.exists(): raise RuntimeError('Existing destination requires review: '+str(p))
before_packages = subprocess.check_output(['/usr/bin/pacman','-Qq'], text=True).splitlines()
subprocess.run(['/usr/bin/pacman','-S','--needed','--noconfirm','cockpit'], check=True)
files = []
def copy(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    os.chown(dst, 0, 0)
    os.chmod(dst, 0o644)
    files.append({'path':str(dst),'sha256':hashlib.sha256(dst.read_bytes()).hexdigest()})
for name in ['collector.py','daemon.py','client.py','adapters.py','history.py','audit.py','integrity.py','confinement.py','telemetry.py','telemetry_worker.py','telemetry_health.py','telemetry_query.py']: copy(source/'securityd'/name,lib/name)
copy(source/'initramfs/handover.py',lib/'handover.py')
for name in ['manifest.json','index.html','app.js','style.css']: copy(source/'cockpit'/name,ui/name)
copy(source/'packaging/security-center.service',unit)
copy(source/'packaging/security-center-telemetry.service',pathlib.Path('/etc/systemd/system/security-center-telemetry.service'))
listen.parent.mkdir(parents=True,exist_ok=True)
listen.write_text('[Socket]\nListenStream=\nListenStream=127.0.0.1:9090\n')
os.chmod(listen,0o644)
files.append({'path':str(listen),'sha256':hashlib.sha256(listen.read_bytes()).hexdigest()})
after_packages = subprocess.check_output(['/usr/bin/pacman','-Qq'], text=True).splitlines()
record={'files':files,'packages_added':sorted(set(after_packages)-set(before_packages)),
        'units_enabled':['security-center.service','cockpit.socket'],'listen':'127.0.0.1:9090'}
backup=source/'backups/mvp-install.json'
backup.write_text(json.dumps(record,indent=2));os.chmod(backup,0o600)
subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
subprocess.run(['/usr/bin/systemctl','enable','--now','security-center.service','cockpit.socket'],check=True)
print(json.dumps(record,indent=2))
