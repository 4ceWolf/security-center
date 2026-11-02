#!/usr/bin/python3
"""Captured root validation/telemetry activation; no boot or baseline approval."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time

LIB='/usr/local/lib/security-center'
UNIT='security-center-telemetry.service'
CANDIDATE='3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee'


def command(args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=45,env={'PATH':'/usr/bin','LC_ALL':'C'})
    if result.returncode:raise RuntimeError('Fixed verification command failed: '+args[0])
    if len(result.stdout)>1048576:raise ValueError('Oversized verification response')
    return result.stdout


def properties(unit):
    keys=('ActiveState','MainPID','DynamicUser','MemoryCurrent','MemoryPeak','MemoryMax','CPUUsageNSec','NRestarts','TasksCurrent','UnitFileState')
    raw=command(['/usr/bin/systemctl','show',unit,*['--property='+key for key in keys]])
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)


def helper(request):
    result=subprocess.run(['/usr/bin/python3','-I',LIB+'/device-trust-helper.py'],input=json.dumps(request),capture_output=True,text=True,timeout=15,env={'PATH':'/usr/bin','LC_ALL':'C'})
    if len(result.stdout)>524288:raise ValueError('Oversized helper response')
    return result.returncode,json.loads(result.stdout)


def snapshot():
    info=properties('security-center.service')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(3);sock.connect('/run/security-center/status.sock')
        pid,uid,gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0 or pid!=int(info['MainPID']):raise ValueError('Collector peer mismatch')
        sock.sendall(b'GET\n');raw=bytearray()
        while True:
            part=sock.recv(65536)
            if not part:break
            raw.extend(part)
            if len(raw)>2097152:raise ValueError('Collector response exceeds bound')
    data=json.loads(raw)
    if data.get('schema_version')!=1 or data.get('read_only') is not True or data.get('history_status')!='available' or len(data.get('modules',[]))!=18:raise ValueError('Collector health failed')
    return data


def main():
    if os.geteuid()!=0:raise PermissionError('Administrator access required')
    lock=os.open('/var/lib/security-center-updates/update.lock',os.O_RDONLY|os.O_NOFOLLOW)
    fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    before=properties(UNIT);started=False;enabled=False
    try:
        code,devices=helper({'operation':'list'})
        if code or devices.get('ok') is not True:raise ValueError('Installed trust helper failed')
        if not any(entry['device']['vendor']=='046d' and entry['device']['product']=='c542' and entry['connected'] is True for entry in devices['result']['saved']):raise ValueError('Approved Logitech receiver is not connected')
        code,denied=helper({'operation':'shell'})
        if code==0 or denied.get('ok') is not False:raise ValueError('Helper accepted an unsupported operation')
        if before.get('ActiveState')!='active':command(['/usr/bin/systemctl','start',UNIT]);started=True
        deadline=time.monotonic()+70
        health_path=Path('/var/lib/private/security-center-telemetry/health.json')
        while True:
            state=properties(UNIT)
            if state.get('ActiveState')!='active':raise ValueError('Telemetry service failed')
            try:health=json.loads(health_path.read_text())
            except FileNotFoundError:health={}
            if health.get('state')=='degraded':raise ValueError('Telemetry reports a storage or collection failure')
            if health.get('state')=='recording' and health.get('samples_written',0)>=2:break
            if time.monotonic()>=deadline:raise TimeoutError('Telemetry did not record two samples')
            time.sleep(1)
        pid=int(state['MainPID']);status=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
        if state.get('DynamicUser')!='yes' or int(status['Uid'].split()[1])==0 or int(status['CapBnd'].strip(),16)!=0:raise ValueError('Unexpected telemetry privilege')
        if int(state['MemoryMax'])!=40*1024*1024 or int(state['NRestarts'])!=0:raise ValueError('Unexpected memory limit or recorder restart')
        db=health_path.parent/'diagnostics.sqlite'
        for path in (health_path,db):
            info=path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_nlink!=1:raise ValueError('Unsafe telemetry file')
        connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
        try:
            if connection.execute('PRAGMA quick_check').fetchone()!=('ok',):raise ValueError('Diagnostic database failed integrity check')
        finally:connection.close()
        with tempfile.TemporaryDirectory(prefix='security-center-validation-',dir='/run') as cache:
            script="import sys,json;sys.path.insert(0,'/usr/local/lib/security-center');from telemetry_query import query;print(json.dumps(query()))"
            history=json.loads(command(['/usr/bin/python3','-I','-B','-X','pycache_prefix='+cache,'-c',script]))
        if not history.get('rows'):raise ValueError('Recorded history query is empty')
        command(['/usr/bin/systemctl','enable',UNIT]);enabled=True
        data=snapshot()
        candidate=Path('/var/lib/security-center-monitor/baseline-review')/(CANDIDATE+'.json')
        raw=candidate.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=CANDIDATE:raise ValueError('Review candidate changed')
        reference=json.loads(raw)
        print(json.dumps(dict(schema=1,collector_modules=[m['id'] for m in data['modules']],
          helper_list='passed',unsupported_operation='refused',trusted_devices=devices['result'],
          telemetry_health=health,telemetry_properties=properties(UNIT),
          telemetry_uid=status['Uid'].split()[1],capability_bound=status['CapBnd'].strip(),
          history_rows=len(history['rows']),monitor_properties=properties('security-center.service'),
          cockpit_properties={u:properties(u) for u in ('cockpit.service','cockpit.socket')},
          baseline_candidate=reference,baseline_candidate_sha256=CANDIDATE,enabled=True)))
    except BaseException:
        if enabled and before.get('UnitFileState')!='enabled':subprocess.run(['/usr/bin/systemctl','disable',UNIT],capture_output=True)
        if started:subprocess.run(['/usr/bin/systemctl','stop',UNIT],capture_output=True)
        raise
    finally:os.close(lock)

if __name__=='__main__':main()
