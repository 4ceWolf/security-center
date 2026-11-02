#!/usr/bin/python3
"""Install the fixed journal reader, preserving the approved FIM baseline."""
import datetime,hashlib,json,os,pathlib,subprocess,sys,tempfile

def main():
 if os.geteuid()!=0:raise SystemExit('Administrator authentication required')
 os.umask(0o077)
 project=pathlib.Path('/home/user/Projects/security-center')
 sys.path.insert(0,'/usr/local/lib/security-center')
 import integrity
 before=integrity.scan()
 changes,unavailable=integrity.compare(before,integrity.load_baseline())
 if changes or unavailable:raise SystemExit('Existing integrity differences require review before installation')
 manifest=project/'backups/mvp-install.json';old_manifest=manifest.read_bytes()
 record=json.loads(old_manifest);entries={item['path']:item for item in record['files']}
 pairs=[('securityd/'+name,'/usr/local/lib/security-center/'+name) for name in ('collector.py','history.py','daemon.py')]
 pairs.append(('cockpit/app.js','/usr/local/share/cockpit/security_center/app.js'))
 prepared={};old={}
 for source,target in pairs:
  path=pathlib.Path(target);raw=path.read_bytes()
  if hashlib.sha256(raw).hexdigest()!=entries[target]['sha256']:raise SystemExit('Installed file differs from installation record')
  old[target]=raw;prepared[target]=(project/source).read_bytes()
  if len(prepared[target])>1024*1024:raise SystemExit('Source exceeds limit')
  if target.endswith('.py'):compile(prepared[target],target,'exec')
 backup=pathlib.Path(tempfile.mkdtemp(prefix='journal-before-',dir=project/'backups'))
 (backup/'install-record.json').write_bytes(old_manifest)
 for target,raw in old.items():(backup/pathlib.Path(target).name).write_bytes(raw)
 def put(path,raw):
  path=pathlib.Path(path);fd,tmp=tempfile.mkstemp(prefix='.security-center-',dir=path.parent)
  try:
   with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
   os.chmod(tmp,0o644 if str(path) in prepared else 0o600);os.replace(tmp,path)
  finally:
   if os.path.exists(tmp):os.unlink(tmp)
 subprocess.run(['/usr/bin/systemctl','stop','security-center.service'],check=True)
 try:
  for target,raw in prepared.items():
   put(target,raw);entries[target]={'path':target,'sha256':hashlib.sha256(raw).hexdigest()}
  record['files']=list(entries.values());put(manifest,(json.dumps(record,indent=2)+'\n').encode())
  subprocess.run(['/usr/bin/systemctl','start','security-center.service'],check=True)
 except BaseException:
  for target,raw in old.items():put(target,raw)
  put(manifest,old_manifest)
  subprocess.run(['/usr/bin/systemctl','start','security-center.service'],check=False)
  raise
 report={'installed':True,'backup':str(backup),'changed_files':list(prepared),
         'approved_baseline_preserved':True,'baseline_review_required':True,
         'installed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 (backup/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))

if __name__=='__main__':main()
