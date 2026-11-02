#!/usr/bin/python3
"""Native firewall coexistence in private user/net/PID namespaces; no host rules."""
import json,os,pathlib,subprocess,tempfile
BASE=pathlib.Path('/home/user/Projects/security-center')
CHILD=r'''import json,pathlib,subprocess,time
work=pathlib.Path('/work')
def nft(*args):
 r=subprocess.run(['/usr/bin/nft',*args],capture_output=True,timeout=5)
 if r.returncode:raise RuntimeError('Fixture nft command failed')
 return json.loads(r.stdout) if '-j' in args else r.stdout
nft('-f','/work/baseline.nft')
before=nft('-j','list','table','inet','security_center_fixture')
with (work/'daemon.log').open('wb') as log:
 child=subprocess.Popen(['/usr/bin/opensnitchd','-config-file','/work/config.json','-rules-path','/work/rules','-workers','2'],stdout=log,stderr=log)
 seen=False;tables=[]
 try:
  for _ in range(40):
   time.sleep(.25)
   if child.poll() is not None:break
   ruleset=nft('-j','list','ruleset')
   (work/'during-ruleset.json').write_text(json.dumps(ruleset,indent=2))
   tables=[r['table']['name'] for r in ruleset['nftables'] if 'table' in r]
   if any('queue' in expression for row in ruleset['nftables'] if 'rule' in row for expression in row['rule'].get('expr',[])):
    seen=True;break
  during=nft('-j','list','table','inet','security_center_fixture')
  alive=child.poll() is None
 finally:
  child.terminate()
  try:child.wait(timeout=15)
  except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
 after=nft('-j','list','table','inet','security_center_fixture')
 report={'private_network_namespace':True,'physical_network_available':False,'host_rules_changed':False,'daemon_started':alive,'native_queue_rule_seen':seen,'table_names':tables,'baseline_preserved_during':before==during,'baseline_preserved_after':before==after,'passed':alive and seen and before==during==after,'scope':'Synthetic native queue-rule coexistence only; no real traffic/host enforcement claim','limitations':['User namespace cannot load host BPF or process-event monitor; those are not tested']}
(work/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if not report['passed']:raise SystemExit(1)
'''
def main():
 os.umask(0o077)
 work=pathlib.Path(tempfile.mkdtemp(prefix='opensnitch-namespace-',dir=BASE/'work'))
 config=json.loads(pathlib.Path('/etc/opensnitchd/default-config.json').read_text())
 config['DefaultAction']='allow';config['InterceptUnknown']=False;config['ProcMonitorMethod']='proc'
 config['Internal']['FlushConnsOnStart']=False
 config['Server']['Address']='unix:///work/ui.sock';config['Server']['LogFile']='/work/events.log'
 config['FwOptions']['ConfigPath']='/work/system-fw.json'
 config['Rules']['Path']='/work/rules';config['Stats']['Workers']=1
 (work/'config.json').write_text(json.dumps(config));(work/'system-fw.json').write_text(json.dumps({'Enabled':False,'Version':1,'SystemRules':[]}))
 (work/'rules').mkdir();(work/'fixture.py').write_text(CHILD)
 (work/'baseline.nft').write_text('table inet security_center_fixture {\n chain inbound { type filter hook input priority 0; policy drop; iifname "lo" accept; ct state established,related accept; }\n}\n')
 args=['/usr/bin/bwrap','--unshare-all','--uid','0','--gid','0','--cap-add','CAP_NET_ADMIN','--die-with-parent','--clearenv','--setenv','PATH','/usr/bin','--ro-bind','/usr','/usr','--ro-bind','/etc','/etc','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/run','--bind',str(work),'/work','--','/usr/bin/python3','-I','/work/fixture.py']
 (work/'command.json').write_text(json.dumps(args,indent=2));r=subprocess.run(args,capture_output=True,timeout=45)
 (work/'console.log').write_bytes(r.stdout+r.stderr);print('Fixture: '+str(work));print((r.stdout+r.stderr).decode(errors='replace')[-4000:]);raise SystemExit(r.returncode)
if __name__=='__main__':main()
