"""Pure, undeployed release/baseline transition checks. No file writes or approval.

Inputs must come from trusted bounded scans and an independently reviewed release.
Matching a caller-supplied digest is continuity checking, not authentication.
"""
import copy,hashlib,json,pathlib

def digest(raw):return hashlib.sha256(raw).hexdigest()

def document(raw,expected):
 if not isinstance(raw,bytes) or len(raw)>65536 or digest(raw)!=expected:
  raise ValueError('Reviewed document differs')
 def unique(pairs):
  value={}
  for key,item in pairs:
   if key in value:raise ValueError('Duplicate document field')
   value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique)

def present(item):
 if not isinstance(item,dict) or item.get('state')!='present':raise ValueError('File not readable')
 value=item.get('sha256')
 if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError('Invalid file hash')
 for key in ('uid','gid','mode','size','mtime_ns'):
  if type(item.get(key)) is not int or item[key]<0:raise ValueError('Invalid metadata')
 if item['size']>1024*1024 or item['mode']>0o7777:raise ValueError('Metadata exceeds bounds')

def prepare(previous_raw,previous_digest,release_raw,release_digest,before,after):
 previous=document(previous_raw,previous_digest);release=document(release_raw,release_digest)
 if previous.get('schema_version')!=1 or previous.get('approved') is not True:raise ValueError('Prior baseline unapproved')
 if release.get('schema_version')!=1:raise ValueError('Invalid release')
 old=previous['files'];new=release['fim_paths']
 if not isinstance(old,dict) or not isinstance(new,list) or len(new)>128 or len(set(new))!=len(new):raise ValueError('Invalid scope')
 if not set(old).issubset(new):raise ValueError('Scope removal requires separate review')
 if any(not isinstance(p,str) or not p.startswith('/') or '..' in pathlib.PurePosixPath(p).parts for p in new):raise ValueError('Invalid path')
 if set(before)!=set(new) or set(after)!=set(new):raise ValueError('Scans do not cover exact new scope')
 records=release['files'];targets={r['destination']:r['sha256'] for r in records}
 if len(targets)!=len(records) or not set(targets).issubset(new):raise ValueError('Invalid release destinations')
 for path,prior in old.items():
  present(prior)
  if before[path]!=prior:raise ValueError('Unexplained pre-update drift: '+path)
 added=set(new)-set(old)
 for path in added:
  if path not in targets or before[path]!={'state':'missing'}:raise ValueError('New path already exists or is not a release file')
 changed=[]
 for path in new:
  current=after[path];present(current)
  if path in targets:
   if current['sha256']!=targets[path] or (current['uid'],current['gid'],current['mode'])!=(0,0,0o644):raise ValueError('Release content/permissions mismatch')
  elif current!=old[path]:raise ValueError('Unrelated file changed: '+path)
  if path not in old or current!=old[path]:changed.append(path)
 candidate={'schema_version':1,'approved':False,'files':copy.deepcopy(after),
  'replaces_baseline_sha256':previous_digest,'release_sha256':release_digest,
  'scope_change':{'added':sorted(added),'removed':[]}}
 raw=(json.dumps(candidate,sort_keys=True,indent=2)+'\n').encode()
 if len(raw)>65536:raise ValueError('Candidate exceeds baseline limit')
 return {'candidate':candidate,'candidate_raw':raw,'candidate_sha256':digest(raw),
         'changed_paths':sorted(changed),'previous_count':len(old),'new_count':len(new)}

def rollback_plan(before,installed,current,targets):
 """Refuse to overwrite anything changed after installation, even during rollback."""
 if len(set(targets))!=len(targets):raise ValueError('Duplicate rollback targets')
 operations=[]
 for path in targets:
  if path not in before or path not in installed or current.get(path)!=installed[path]:raise ValueError('Rollback conflicts with later changes')
  present(installed[path])
  if before[path]=={'state':'missing'}:operation='remove_added_file'
  else:present(before[path]);operation='restore_backup'
  operations.append({'path':path,'operation':operation})
 return operations
