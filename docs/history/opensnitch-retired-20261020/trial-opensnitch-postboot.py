#!/usr/bin/python3
"""Fixed protected application-firewall trial, rollback on failed connectivity tests."""
import os,pathlib,subprocess
BASE=pathlib.Path('/home/user/Projects/security-center')
READER=r'''import copy,hashlib,json,os,pathlib,pwd,shutil,stat,subprocess,tempfile,time
os.umask(0o077)
def run(args,timeout=20,check=True):
 r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:raise RuntimeError('Fixed operation failed: '+args[0]+': '+r.stderr[-400:])
 return r
def table():return json.loads(run(['/usr/bin/nft','-j','list','table','inet','machine_care_guard']).stdout)
def normalize(item):
 if isinstance(item,dict):
  return {k:({'packets':0,'bytes':0} if k=='counter' and isinstance(v,dict) and set(v)=={'packets','bytes'} else normalize(v)) for k,v in item.items()}
 if isinstance(item,list):return [normalize(v) for v in item]
 return item
if run(['/usr/bin/systemctl','is-active','opensnitchd.service'],check=False).stdout.strip()!='inactive':raise ValueError('Expected inactive daemon')
if run(['/usr/bin/systemctl','is-enabled','opensnitchd.service'],check=False).stdout.strip()!='disabled':raise ValueError('Expected disabled daemon')
if any(pathlib.Path('/etc/opensnitchd/rules').glob('*.json')):raise ValueError('Existing app rules require review')
before=table();baseline=normalize(before)
chains=[r['chain'] for r in before['nftables'] if 'chain' in r and r['chain'].get('hook') in ('input','forward')]
if len(chains)!=2 or any(c.get('policy')!='drop' for c in chains):raise ValueError('Original inbound/forward protection not established')
configs={p:pathlib.Path(p).read_bytes() for p in ('/etc/opensnitchd/default-config.json','/etc/opensnitchd/system-fw.json')}
backup=pathlib.Path(tempfile.mkdtemp(prefix='security-center-opensnitch-',dir='/var/lib'))
for p,raw in configs.items():(backup/pathlib.Path(p).name).write_bytes(raw)
(backup/'firewall-before.json').write_text(json.dumps(before,indent=2))
config=json.loads(configs['/etc/opensnitchd/default-config.json'])
config['LogLevel']=1
config['DefaultAction']='allow';config['InterceptUnknown']=False;config['ProcMonitorMethod']='proc'
config['Internal']['FlushConnsOnStart']=False;config['Server']['LogFile']='/dev/stdout'
uid=pwd.getpwnam('kyo').pw_uid
if uid==0:raise ValueError('Desktop account must be unprivileged')
config['Server']['Address']='unix:///run/user/'+str(uid)+'/security-center-opensnitch.sock'
config['Stats']['Workers']=1
config['FwOptions']['QueueBypass']=True
new={ '/etc/opensnitchd/default-config.json':(json.dumps(config,indent=2)+'\n').encode(),
      '/etc/opensnitchd/system-fw.json':b'{"Enabled":false,"Version":1,"SystemRules":[]}\n'}
def write(path,raw):
 parent=pathlib.Path(path).parent;s=parent.stat()
 if s.st_uid!=0 or s.st_mode&0o022:raise ValueError('Unsafe configuration parent')
 fd,tmp=tempfile.mkstemp(prefix='.security-center-',dir=parent)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
probe=pathlib.Path(tempfile.mkdtemp(prefix='security-center-network-probe-',dir='/run'));probe.chmod(0o755)
exe=probe/'curl';shutil.copyfile('/usr/bin/curl',exe);exe.chmod(0o755)
rule=pathlib.Path('/etc/opensnitchd/rules/security-center-temporary-probe-deny.json')
if rule.exists():raise ValueError('Probe rule already exists')
override=pathlib.Path('/run/systemd/system/opensnitchd.service.d/security-center-single-rule-loader.conf')
if override.exists():raise ValueError('Existing runtime override requires review')
override.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
# Native package passes -rules-path after config already loaded it. v1.7.2's
# asynchronous stop/restart can lose its watcher on that second Reload().
# Rely on the pinned config path instead; no upstream code or rules are patched.
responses=[]
start=time.time()
phase='before_start'
def request():
 r=run(['/usr/bin/runuser','-u','kyo','--',str(exe),'--noproxy','*','--silent','--show-error','--output','/dev/null','--head','--connect-timeout','5','--max-time','10','https://archlinux.org/'],timeout=12,check=False)
 responses.append({'phase':phase,'returncode':r.returncode,'error':r.stderr[-250:]})
 return r.returncode
passed=False
try:
 if request()!=0:raise ValueError('Before-start probe failed: '+json.dumps(responses[-1]))
 for p,raw in new.items():write(p,raw)
 write(str(override),b'[Service]\nExecStart=\nExecStart=/usr/bin/opensnitchd\n')
 run(['/usr/bin/systemctl','daemon-reload'])
 run(['/usr/bin/systemctl','start','opensnitchd.service'])
 time.sleep(2)
 # Bound startup readiness separately from the service's Type=simple active state.
 readiness=[]
 for _ in range(30):
  readiness=pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()
  if len(readiness)>=2:break
  time.sleep(.5)
 if len(readiness)<2:raise ValueError('Native packet queues not ready after 17 seconds')
 if run(['/usr/bin/systemctl','is-active','opensnitchd.service']).stdout.strip()!='active':raise ValueError('Daemon failed')
 if normalize(table())!=baseline:raise ValueError('Existing firewall semantics changed')
 phase='allow_after_start'
 if request()!=0:raise ValueError('Observation-mode connectivity failed')
 denial={'name':'security-center-temporary-probe-deny','description':'Temporary private executable test only','enabled':True,'precedence':True,'action':'deny','duration':'always','operator':{'type':'simple','sensitive':True,'operand':'process.path','data':str(exe)}}
 write(str(rule),(json.dumps(denial)+'\n').encode());time.sleep(1)
 # v1.7.2 watches Write/Remove, not Create/MovedTo. Explicit whitespace write
 # after the atomic publication triggers its native watcher without partial JSON.
 with rule.open('ab') as notify:notify.write(b'\n');notify.flush();os.fsync(notify.fileno())
 time.sleep(2)
 phase='deny_probe'
 denied=request()!=0
 rule.unlink();time.sleep(2)
 phase='recover_probe'
 recovered=request()==0
 if not denied or not recovered:raise ValueError('Scoped application deny/recovery not established')
 if normalize(table())!=baseline:raise ValueError('Original firewall changed')
 report={'active':True,'enabled_at_boot':False,'default_action':'allow','unreviewed_applications_blocked':False,'scoped_native_app_deny_verified':True,'connectivity_recovered_after_rule_removal':True,'original_firewall_preserved':True,'flush_connections_on_start':False,'ui_socket':config['Server']['Address'],'backup':str(backup),'temporary_rule_removed':True,'probe_results':responses,'configuration_sha256':{p:hashlib.sha256(raw).hexdigest() for p,raw in new.items()},'baseline_sha256':hashlib.sha256(pathlib.Path('/var/lib/security-center-monitor/integrity-baseline.json').read_bytes()).hexdigest()}
 (backup/'receipt.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));passed=True
finally:
 if rule.exists():rule.unlink()
 try:
  # Persist bounded diagnostic outcomes even when the acceptance test fails.
  diagnostic={'probe_results':responses,'phase':phase,'passed':passed}
  logs=run(['/usr/bin/journalctl','-u','opensnitchd.service','--since','@'+str(int(start)),'--no-pager','-o','cat'],check=False).stdout.splitlines()
  diagnostic['rule_reload_observed']=any('security-center-temporary-probe-deny.json' in line and 'Ruleset changed' in line for line in logs)
  diagnostic['probe_process_rule_event_observed']=any(str(exe) in line and 'security-center-temporary-probe-deny' in line for line in logs)
  diagnostic['queue_rules_present']=any('queue' in json.dumps(item) for item in json.loads(run(['/usr/bin/nft','-j','list','ruleset']).stdout).get('nftables',[]))
  (backup/'diagnostics.json').write_text(json.dumps(diagnostic,indent=2))
  print(json.dumps({'diagnostics':diagnostic,'backup':str(backup)}))
 except Exception as diagnostic_error:
  print(json.dumps({'diagnostic_error':type(diagnostic_error).__name__,'probe_results':responses,'backup':str(backup)}))
 if not passed:
  run(['/usr/bin/systemctl','stop','opensnitchd.service'],check=False)
  for p,raw in configs.items():write(p,raw)
  if override.exists():override.unlink()
  run(['/usr/bin/systemctl','daemon-reload'])
  (backup/'rollback.json').write_text(json.dumps({'rolled_back':True,'original_firewall_preserved':normalize(table())==baseline}))
 shutil.rmtree(probe)
'''
if __name__=='__main__':
 os.umask(0o077)
 r=subprocess.run(['/usr/bin/sudo','-A','-p','Security Center: test application firewall with a temporary probe only: ','/usr/bin/python3','-I','-c',READER],env=dict(os.environ,SUDO_ASKPASS='/usr/bin/ksshaskpass'),stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
 (BASE/'work/opensnitch-host-trial-single-loader-20261020.json').write_bytes(r.stdout);(BASE/'work/opensnitch-host-trial-single-loader-20261020-error.log').write_bytes(r.stderr)
 print((r.stdout+r.stderr).decode(errors='replace')[-2500:]);raise SystemExit(r.returncode)
