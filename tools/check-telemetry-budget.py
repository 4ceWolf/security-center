#!/usr/bin/python3
"""Temporary user-service rehearsal of worker memory/CPU/task limits."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
RUNNER='''import runpy,signal,threading,sys
worker=runpy.run_path(sys.argv[1]);stop=threading.Event()
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
worker['run'](directory=sys.argv[2],interval=2,stop=stop)
'''


def command(*args):
    return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,timeout=15)


def properties(unit):
    names=('ActiveState','SubState','MemoryCurrent','MemoryPeak','MemorySwapCurrent','CPUUsageNSec','ControlGroup','NRestarts','MemoryMax','MemoryHigh','TasksMax','CPUQuotaPerSecUSec')
    raw=command('systemctl','--user','show',unit,*['--property='+name for name in names])
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)


def main():
    with tempfile.TemporaryDirectory(prefix='telemetry-budget-',dir=ROOT/'work') as folder:
        directory=Path(folder);unit=directory.name+'.service';launched=False
        try:
            command('systemd-run','--user','--unit='+unit,'--property=MemoryHigh=24M','--property=MemoryMax=40M',
                    '--property=CPUQuota=5%','--property=TasksMax=8','--property=NoNewPrivileges=yes',
                    '--property=RuntimeMaxSec=75','--property=TimeoutStopSec=10','--property=UMask=0077',
                    sys.executable,'-I','-c',RUNNER,str(ROOT/'securityd/telemetry_worker.py'),str(directory))
            launched=True;started=time.monotonic();health=None
            while time.monotonic()-started<35:
                state=properties(unit)
                if state.get('ActiveState')!='active':raise RuntimeError('Trial worker stopped unexpectedly: '+str(state))
                try:health=json.loads((directory/'health.json').read_text())
                except FileNotFoundError:pass
                if health and health['state']=='degraded':raise RuntimeError('Trial recorder degraded')
                time.sleep(1)
            state=properties(unit)
            events_path=Path('/sys/fs/cgroup')/state['ControlGroup'].lstrip('/')/'memory.events'
            events=dict(line.split() for line in events_path.read_text().splitlines())
            assert int(state['MemoryMax'])==40*1024*1024
            assert int(state['MemoryHigh'])==24*1024*1024
            assert int(state['TasksMax'])==8 and state['NRestarts']=='0'
            assert state['CPUQuotaPerSecUSec']=='50ms'
            assert events.get('oom')=='0' and events.get('oom_kill')=='0'
            assert health and health['samples_written']>=10
            command('systemctl','--user','stop',unit);launched=False
            final=json.loads((directory/'health.json').read_text())
            assert final['state']=='stopped'
            db=sqlite3.connect((directory/'diagnostics.sqlite').as_uri()+'?mode=ro',uri=True)
            try:
                rows=db.execute('SELECT count(*) FROM samples').fetchone()[0]
                assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                last=json.loads(db.execute('SELECT payload FROM samples ORDER BY id DESC LIMIT 1').fetchone()[0])
            finally:db.close()
            report=dict(passed=True,duration_seconds=round(time.monotonic()-started,2),samples=rows,
                        metric_count=len(last['metrics']),last_issues=last['issues'],properties=state,
                        memory_events=events,graceful_shutdown=True,
                        limitations='Accelerated 2-second sampling for 35 seconds; user identity, not DynamicUser or full production sandbox; not battery-life or whole-stack benchmark.')
        finally:
            if launched:subprocess.run(['systemctl','--user','stop',unit],timeout=15,check=False)
    target=ROOT/'work/telemetry/budget-report.json'
    target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
