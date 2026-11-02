"""Fixed monitor service adapter and bounded collector health check; no CLI."""
import datetime
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

UNITS=('security-center.service','security-center-telemetry.service')
SOCKET='/run/security-center/status.sock'


def validate_snapshot(data,required,boot,now,not_before=0):
    if not isinstance(data,dict) or data.get('schema_version')!=1 or data.get('read_only') is not True or data.get('boot_id')!=boot:
        raise ValueError('Unexpected collector identity/schema')
    stamp=datetime.datetime.fromisoformat(data['generated_at'])
    if stamp.tzinfo is None:raise ValueError('Missing timestamp timezone')
    timestamp=stamp.timestamp()
    if not 0<=now-timestamp<=150 or timestamp<not_before:raise ValueError('Collector snapshot is stale')
    modules=data.get('modules')
    if not isinstance(modules,list) or len(modules)>32 or any(not isinstance(m,dict) or not isinstance(m.get('id'),str) for m in modules):raise ValueError('Invalid module list')
    ids=[m['id'] for m in modules]
    if len(set(ids))!=len(ids) or not set(required).issubset(ids):raise ValueError('Missing or duplicate collector modules')
    if data.get('history_status')!='available':raise ValueError('Collector persistent history unavailable')
    return dict(modules=ids,generated_at=data['generated_at'],history_status='available')


class MonitorServices:
    def __init__(self,runner=subprocess.run):self.runner=runner
    def _command(self,*args):
        result=self.runner(['/usr/bin/systemctl',*args],capture_output=True,text=True,timeout=45,check=False,
                           env={'PATH':'/usr/bin','LC_ALL':'C'})
        if result.returncode:raise RuntimeError('Fixed service operation failed')
        if len(result.stdout)>16384:raise ValueError('Oversized service response')
        return result.stdout
    def states(self):
        result={}
        for unit in UNITS:
            text=self._command('show',unit,'--property=LoadState','--property=ActiveState','--property=MainPID')
            fields=dict(line.split('=',1) for line in text.splitlines() if '=' in line)
            if fields.get('LoadState')=='not-found':result[unit]=False
            elif fields.get('LoadState')=='loaded' and fields.get('ActiveState') in ('active','inactive','failed'):
                result[unit]=fields['ActiveState']=='active'
            else:raise ValueError('Service is not in a stable supported state')
        return result
    def _root(self):
        if os.geteuid()!=0:raise PermissionError('Service changes require root')
    def stop(self):
        self._root()
        for unit,active in self.states().items():
            if active:self._command('stop',unit)
        if any(self.states().values()):raise RuntimeError('Monitor services did not stop')
    def reload(self):self._root();self._command('daemon-reload')
    def restore(self,desired):
        self._root()
        if set(desired)!=set(UNITS) or any(type(v) is not bool for v in desired.values()):raise ValueError('Invalid saved service state')
        current=self.states()
        for unit in UNITS:
            if current[unit] and not desired[unit]:self._command('stop',unit)
            if desired[unit] and not current[unit]:self._command('start',unit)
        if self.states()!=desired:raise RuntimeError('Service state restoration failed')
    def health(self,required,not_before=0):
        fields=dict(line.split('=',1) for line in self._command('show',UNITS[0],'--property=ActiveState','--property=MainPID').splitlines() if '=' in line)
        if fields.get('ActiveState')!='active' or not fields.get('MainPID','').isdigit() or int(fields['MainPID'])<=0:raise ValueError('Collector not active')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(3);client.connect(SOCKET)
            pid,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            if uid!=0 or pid!=int(fields['MainPID']):raise ValueError('Socket peer does not match root collector service')
            client.sendall(b'GET\n');raw=bytearray()
            while True:
                block=client.recv(65536)
                if not block:break
                raw.extend(block)
                if len(raw)>2097152:raise ValueError('Collector reply exceeds limit')
        return validate_snapshot(json.loads(raw),required,Path('/proc/sys/kernel/random/boot_id').read_text().strip(),time.time(),not_before)
