#!/usr/bin/python3
"""Build/check a project-local release snapshot. Does not install or approve files."""
import ast,hashlib,json,pathlib,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
FILES={**{'policies/'+name:'/usr/local/lib/security-center/'+name for name in ('device_gate.py','device_inventory.py','trust_policy.py','trust_store.py','usb_policy.py')},
 'tools/tpm-unlock-helper.py':'/usr/local/lib/security-center/tpm-unlock-helper.py',
 'tools/device-trust-helper.py':'/usr/local/lib/security-center/device-trust-helper.py',
 'tools/telemetry-helper.py':'/usr/local/lib/security-center/telemetry-helper.py',
 'tools/export-telemetry.py':'/usr/local/lib/security-center/telemetry_export.py',
 'policies/normal-devices.candidate.json':'/etc/security-center/normal-devices.candidate.json',
 'initramfs/boot_observation.py':'/usr/local/lib/security-center/boot_observation.py',
 'initramfs/handover.py':'/usr/local/lib/security-center/handover.py',**{'securityd/'+name:'/usr/local/lib/security-center/'+name for name in
 ('network_policy.py','boot_observation_status.py','collector.py','daemon.py','client.py','adapters.py','history.py','audit.py','integrity.py','confinement.py','telemetry.py','telemetry_worker.py','telemetry_health.py','telemetry_query.py','telemetry_actions.py')},
 **{'cockpit/'+name:'/usr/local/share/cockpit/security_center/'+name for name in
 ('manifest.json','index.html','app.js','style.css','telemetry-controls.js','unlock-controls.js','usb-controls.js')},
 'packaging/security-center-apparmor.service':'/etc/systemd/system/security-center-apparmor.service',
 'packaging/security-center.service':'/etc/systemd/system/security-center.service',
 'packaging/security-center-telemetry.service':'/etc/systemd/system/security-center-telemetry.service'}
LIMIT=1024*1024

def sha(raw):return hashlib.sha256(raw).hexdigest()

def validate(contents):
 if set(contents)!=set(FILES):raise ValueError('Release file set differs from required files')
 local={pathlib.PurePosixPath(FILES[name]).stem for name in contents if name.endswith('.py')}
 for name,raw in contents.items():
  if len(raw)>LIMIT:raise ValueError('Oversized release file')
  if not name.endswith('.py'):continue
  tree=ast.parse(raw,filename=name)
  for node in ast.walk(tree):
   imports=[]
   if isinstance(node,ast.Import):imports=[item.name.split('.')[0] for item in node.names]
   elif isinstance(node,ast.ImportFrom):
    if node.level:raise ValueError('Relative imports require a reviewed package layout')
    imports=[(node.module or '').split('.')[0]]
   for dependency in imports:
    if dependency not in local and dependency not in sys.stdlib_module_names:
     raise ValueError('Unbundled dependency: '+dependency)
 tree=ast.parse(contents['securityd/integrity.py'])
 assignments=[node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PATHS' for t in node.targets)]
 if len(assignments)!=1:raise ValueError('FIM path declaration is ambiguous')
 paths=ast.literal_eval(assignments[0].value)
 if not isinstance(paths,tuple) or any(not isinstance(path,str) for path in paths) or len(set(paths))!=len(paths):
  raise ValueError('Invalid FIM paths')
 if not set(FILES.values()).issubset(paths):raise ValueError('Installed release files missing from FIM scope')
 return list(paths)

def build(root=ROOT):
 contents={}
 for name in FILES:
  path=root/name
  if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):raise ValueError('Source escaped project')
  with path.open('rb') as stream:contents[name]=stream.read(LIMIT+1)
 coverage=validate(contents)
 parent=root/'work/releases';parent.mkdir(parents=True,exist_ok=True)
 folder=pathlib.Path(tempfile.mkdtemp(prefix='monitor-',dir=parent))
 records=[]
 for name,raw in contents.items():
  target=folder/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  installed=pathlib.Path(FILES[name])
  # Observation only: never accept this as an approved baseline or installer authority.
  previous=None
  if installed.is_file() and not installed.is_symlink():
   with installed.open('rb') as stream:observed=stream.read(LIMIT+1)
   if len(observed)<=LIMIT:previous=sha(observed)
  records.append({'source':name,'destination':FILES[name],'sha256':sha(raw),'observed_installed_sha256':previous})
 manifest={'schema_version':1,'files':records,'fim_paths':coverage,'deployment_approved':False,
           'baseline_approved':False,'limitations':'Static imports and fixed scope checked; dynamic behavior and host authorization are not verified.'}
 (folder/'release.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 verify(folder)
 return folder

def verify(folder):
 folder=pathlib.Path(folder)
 with (folder/'release.json').open('rb') as stream:raw=stream.read(65537)
 if len(raw)>65536:raise ValueError('Oversized manifest')
 manifest=json.loads(raw)
 if manifest.get('schema_version')!=1:raise ValueError('Invalid manifest version')
 records=manifest['files']
 if len(records)!=len(FILES) or {item['source'] for item in records}!=set(FILES):raise ValueError('Invalid manifest file set')
 contents={}
 for item in records:
  name=item['source']
  if item['destination']!=FILES[name]:raise ValueError('Destination changed')
  path=folder/name
  if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()):raise ValueError('Bundle path escaped')
  with path.open('rb') as stream:contents[name]=stream.read(LIMIT+1)
  if sha(contents[name])!=item['sha256']:raise ValueError('Bundle content changed')
 if validate(contents)!=manifest['fim_paths']:raise ValueError('FIM declaration differs')
 return manifest

if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--verify':
  verify(sys.argv[2]);print('Release contents and dependencies verified; deployment not authorized.')
 elif len(sys.argv)==1:
  folder=build();print(json.dumps({'release':str(folder),'files':len(FILES),'installed':False,'baseline_approved':False}))
 else:raise SystemExit('Usage: build-monitor-release.py [--verify DIRECTORY]')
