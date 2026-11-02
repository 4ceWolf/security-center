"""Disposable-filesystem transaction executor; intentionally NOT a host installer.
Trusted test directory, serialized caller. No service, privilege or baseline actions.
"""
import hashlib,json,os,pathlib,stat,tempfile,time
LIMIT=1024*1024

def sha(raw):return hashlib.sha256(raw).hexdigest()

def sync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def atomic(path,raw,mode=0o600,mtime=None):
 fd,name=tempfile.mkstemp(prefix='.transaction-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as stream:
   stream.write(raw);stream.flush();os.fchmod(stream.fileno(),mode)
   if mtime is not None:os.utime(stream.fileno(),ns=(mtime,mtime))
   os.fsync(stream.fileno())
  os.replace(name,path);sync_directory(path.parent)
 finally:
  if os.path.exists(name):os.unlink(name)

class Transaction:
 def __init__(self,root):
  root=pathlib.Path(root)
  if root.is_symlink() or not root.name.startswith('security-center-fixture-'):
   raise ValueError('Disposable fixture root required')
  self.root=root.resolve()
  if (self.root/'.fixture').read_text()!='DISPOSABLE SECURITY CENTER TEST\n':raise ValueError('Fixture marker missing')
  self.folder=self.root/'.transaction'
 def target(self,name):
  path=pathlib.PurePosixPath(name)
  if not name or path.is_absolute() or any(p in ('.','..','.transaction','.fixture') for p in path.parts) or str(path)!=name:
   raise ValueError('Unsafe transaction path')
  target=self.root/name
  for part in (target,*target.parents):
   if part==self.root:break
   if part.is_symlink():raise ValueError('Symlink in fixture')
  if not target.parent.is_dir():raise ValueError('Create fixture directories before transaction')
  return target
 def inspect(self,path):
  try:info=path.lstat()
  except FileNotFoundError:return None
  if not stat.S_ISREG(info.st_mode) or info.st_size>LIMIT:raise ValueError('Invalid transaction file')
  raw=path.read_bytes()
  return {'sha256':sha(raw),'mode':stat.S_IMODE(info.st_mode),'mtime':info.st_mtime_ns,
          'uid':info.st_uid,'gid':info.st_gid}
 def prepare(self,contents):
  if not contents or len(contents)>32:raise ValueError('Invalid transaction size')
  # Validate every target before creating the transaction record.
  for name,raw in contents.items():
   self.target(name)
   if not isinstance(raw,bytes) or len(raw)>LIMIT:raise ValueError('Invalid payload')
  self.folder.mkdir(mode=0o700)
  entries=[]
  for index,(name,raw) in enumerate(sorted(contents.items())):
   path=self.target(name);before=self.inspect(path)
   if before and (before['uid'],before['gid'])!=(os.geteuid(),os.getegid()):raise ValueError('Fixture ownership must match test process')
   if before:atomic(self.folder/(str(index)+'.old'),path.read_bytes())
   atomic(self.folder/(str(index)+'.new'),raw)
   after={'sha256':sha(raw),'mode':0o644,'mtime':time.time_ns(),'uid':os.geteuid(),'gid':os.getegid()}
   entries.append({'path':name,'before':before,'after':after})
  record={'schema':1,'phase':'prepared','entries':entries}
  atomic(self.folder/'record.json',json.dumps(record,sort_keys=True).encode())
  sync_directory(self.root)
 def load(self):
  if self.folder.is_symlink():raise ValueError('Transaction directory symlink')
  with (self.folder/'record.json').open('rb') as stream:raw=stream.read(65537)
  if len(raw)>65536:raise ValueError('Oversized transaction')
  record=json.loads(raw)
  if record.get('schema')!=1 or not 0<len(record['entries'])<=32:raise ValueError('Invalid transaction record')
  names=[item['path'] for item in record['entries']]
  if len(set(names))!=len(names):raise ValueError('Duplicate targets')
  for index,item in enumerate(record['entries']):
   self.target(item['path'])
   for suffix,key in (('new','after'),('old','before')):
    expected=item[key]
    if expected is None:continue
    info=self.inspect(self.folder/(str(index)+'.'+suffix))
    if info is None or info['sha256']!=expected['sha256']:raise ValueError('Transaction payload/backup changed')
  return record
 def run(self,rollback=False,checkpoint=lambda _:None):
  record=self.load()
  if not rollback and record['phase'] in ('rolling_back','rolled_back'):raise ValueError('Rolled-back transaction cannot be reapplied')
  # Check ALL paths before any mutation; later conflicts cause refusal.
  for item in record['entries']:
   if self.inspect(self.target(item['path'])) not in (item['before'],item['after']):raise ValueError('Concurrent file change')
  record['phase']='rolling_back' if rollback else 'applying'
  atomic(self.folder/'record.json',json.dumps(record,sort_keys=True).encode())
  for index,item in enumerate(record['entries']):
   path=self.target(item['path']);desired=item['before'] if rollback else item['after']
   if self.inspect(path)==desired:continue
   if desired is None:path.unlink();sync_directory(path.parent)
   else:
    raw=(self.folder/(str(index)+('.old' if rollback else '.new'))).read_bytes()
    atomic(path,raw,desired['mode'],desired['mtime'])
   checkpoint(index)
  record['phase']='rolled_back' if rollback else 'applied'
  atomic(self.folder/'record.json',json.dumps(record,sort_keys=True).encode())
