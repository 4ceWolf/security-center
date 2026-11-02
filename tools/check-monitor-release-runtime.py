#!/usr/bin/python3
"""Run packaged daemon as current user with private test socket/database only."""
import importlib.util,json,os,pathlib,resource,socket,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release',ROOT/'tools/build-monitor-release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
RUNNER='''import os,sys
sys.path.insert(0,sys.argv[1])
import daemon
daemon.main(socket_path=sys.argv[2],database=sys.argv[3],owner_uid=os.getuid(),owner_gid=os.getgid())
'''

def query(path,payload=b'GET\n'):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
  client.settimeout(3);client.connect(str(path));client.sendall(payload);raw=bytearray()
  while True:
   part=client.recv(65536)
   if not part:break
   raw.extend(part)
   if len(raw)>2097152:raise ValueError('Oversized response')
 return json.loads(raw)

def wait_ready(child,path):
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  if child.poll() is not None:raise RuntimeError('Packaged daemon exited early')
  try:
   data=query(path)
   if 'modules' in data:return data
  except (FileNotFoundError,ConnectionRefusedError):pass
  time.sleep(.1)
 raise TimeoutError('Packaged daemon did not become ready')

def stop(child,kill=False):
 if child.poll() is None:
  child.kill() if kill else child.terminate()
 try:child.wait(timeout=10)
 except subprocess.TimeoutExpired:child.kill();child.wait();raise

def main():
 folder=release.build();manifest=release.verify(folder)
 # Keep the Unix socket path short; all output artifacts remain under the project.
 with tempfile.TemporaryDirectory(prefix='runtime-',dir=ROOT/'work') as temp:
  temp=pathlib.Path(temp);path=temp/'status.sock';database=temp/'events.sqlite';log=temp/'daemon.log'
  library=temp/'lib';library.mkdir()
  for item in manifest['files']:
   if item['destination'].startswith('/usr/local/lib/security-center/'):
    (library/pathlib.Path(item['destination']).name).write_bytes((folder/item['source']).read_bytes())
  def start(db):
   with log.open('ab') as stream:
    return subprocess.Popen([sys.executable,'-I','-c',RUNNER,str(library),str(path),str(db)],stdout=stream,stderr=stream)
  first=start(database)
  try:
   before=wait_ready(first,path)
   assert before['history_status']=='available'
   assert {'apparmor','integrity','preboot','processes','telemetry'}.issubset({m['id'] for m in before['modules']})
   assert '_journal_batch' not in before
   assert query(path,b'EXEC\n')=={'error':'Read-only API: unsupported request'}
   assert path.stat().st_mode&0o777==0o660
  finally:stop(first,kill=True)
  second=start(database)
  try:
   after=wait_ready(second,path)
   assert after['history_status']=='available'
   old={json.dumps(event,sort_keys=True) for event in before['events']}
   new={json.dumps(event,sort_keys=True) for event in after['events']}
   assert old.issubset(new),'Saved history lost after process crash'
  finally:stop(second)
  assert not path.exists(),'Socket not removed on orderly shutdown'
  bad=temp/'database-is-directory';bad.mkdir()
  third=start(bad)
  try:
   degraded=wait_ready(third,path)
   assert degraded['history_status']=='unavailable'
   assert len(degraded['modules'])==len(before['modules'])
  finally:stop(third)
  report={'passed':True,'release':str(folder),'modules':len(before['modules']),
   'history_events_before':len(before['events']),'history_events_after_restart':len(after['events']),
   'invalid_request_rejected':True,'crash_restart_history_preserved':True,
   'database_failure_isolated':True,'orderly_socket_cleanup':True,
   'child_peak_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
   'limitations':'Unprivileged isolated socket/database; not root service permissions or whole Cockpit stack validation.'}
  (folder/'runtime-report.json').write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report,indent=2))

if __name__=='__main__':main()
