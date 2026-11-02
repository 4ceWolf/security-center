#!/usr/bin/python3
"""Bounded JSON export to stdout. Reads only; never uploads or approves changes."""
import argparse
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import time

DATABASE=Path('/var/lib/private/security-center-telemetry/diagnostics.sqlite')
TRIAL=Path('/home/user/Projects/security-center/work/telemetry/diagnostics.sqlite')
MAX_OUTPUT=32*1024*1024
MAX_RECORD=262144
PREFIXES=('cpu.','memory.','load.','filesystem.','frequency.','pressure.',
          'network.','disk.','battery.','power.','sensor.')


def number(value):
    if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('Invalid diagnostic number')
    return value


def integer(value,limit=None):
    if type(value) is not int or value<0 or (limit is not None and value>limit):raise ValueError('Invalid diagnostic count')
    return value


def text(value,limit):
    if not isinstance(value,str) or len(value)>limit:raise ValueError('Invalid diagnostic label')
    return value


def decode(raw):
    if type(raw) is not str or len(raw.encode())>MAX_RECORD:raise ValueError('Oversized diagnostic record')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('Duplicate diagnostic field')
            result[k]=v
        return result
    def constant(_):raise ValueError('Nonfinite JSON number')
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=constant)
    if not isinstance(value,dict):raise ValueError('Invalid diagnostic record')
    return value


def metrics(values,samples=None):
    if not isinstance(values,dict) or len(values)>1024:raise ValueError('Invalid metric collection')
    result={}
    for key,value in values.items():
        text(key,256)
        if not key.startswith(PREFIXES):raise ValueError('Unsupported metric namespace')
        if samples is None:result[key]=number(value);continue
        if not isinstance(value,dict):raise ValueError('Invalid metric summary')
        count=integer(value.get('count'))
        if not 1<=count<=samples:raise ValueError('Invalid metric coverage')
        total,low,high=(number(value.get(k)) for k in ('sum','min','max'))
        if low>high:raise ValueError('Invalid metric range')
        result[key]=dict(count=count,sum=total,mean=number(total/count),min=low,max=high)
    return result


def process(value):
    if not isinstance(value,dict):raise ValueError('Invalid process peak')
    result=dict(name=text(value.get('name'),64),pid=integer(value.get('pid')),
                start_ticks=integer(value.get('start_ticks')),rss_bytes=integer(value.get('rss_bytes')))
    if result['pid']==0:raise ValueError('Invalid process identity')
    for key in ('ticks','cpu_percent_one_core','timestamp'):
        if key in value:
            result[key]=integer(value[key]) if key=='ticks' else number(value[key])
            if result[key]<0:raise ValueError('Negative process counter')
    return result


def raw_row(timestamp,data,include_processes):
    if data.get('schema')!=1 or number(data.get('timestamp'))!=timestamp:raise ValueError('Sample timestamp/schema mismatch')
    issues=data.get('issues')
    if not isinstance(issues,list) or len(issues)>128:raise ValueError('Invalid source coverage')
    interval=data.get('interval_seconds')
    if interval is not None and number(interval)<=0:raise ValueError('Invalid sample interval')
    result=dict(timestamp=timestamp,boot_id=text(data.get('boot_id'),64),interval_seconds=interval,
                metrics=metrics(data.get('metrics')),processes_observed=integer(data.get('processes_observed'),1024),
                source_issue_count=len(issues))
    batteries=data.get('batteries')
    if not isinstance(batteries,dict) or len(batteries)>16:raise ValueError('Invalid battery collection')
    result['batteries']={text(name,64):{'status':text(item.get('status'),64)} for name,item in batteries.items()}
    if include_processes:
        for kind in ('top_cpu','top_ram'):
            items=data.get(kind)
            if not isinstance(items,list) or len(items)>5:raise ValueError('Invalid process list')
            result[kind]=[process(item) for item in items]
    return result


def hourly_row(hour,data,include_processes):
    samples=integer(data.get('samples'))
    if samples<1:raise ValueError('Empty hourly summary')
    result=dict(hour_unix=hour*3600,samples=samples,metrics=metrics(data.get('metrics'),samples))
    for key in ('mixed_boots','metrics_truncated','boot_ids_truncated'):
        value=data.get(key)
        if value is not None and type(value) is not bool:raise ValueError('Invalid coverage flag')
        result[key]=value
    for key in ('samples_with_issues','rate_samples'):
        value=data.get(key)
        result[key]=integer(value,samples) if value is not None else None
    boots=data.get('boot_ids')
    if boots is not None and (not isinstance(boots,list) or len(boots)>16):raise ValueError('Invalid boot coverage')
    result['boot_ids']=[text(boot,64) for boot in boots] if boots is not None else None
    if include_processes:
        for kind in ('peak_cpu','peak_ram'):
            result[kind]=process(data[kind]) if data.get(kind) is not None else None
    return result


def export(path=DATABASE,*,hours=24,resolution='hourly',include_processes=False,now=None):
    """Return a complete, validated private spool. Caller closes it after reading.

    Only trusted fixed paths are supported by the CLI. The path parameter exists
    for project trials/tests; this is not a hostile-filesystem transaction API.
    """
    if resolution not in ('raw','hourly') or type(hours) is not int or not 1<=hours<=(24 if resolution=='raw' else 2160):raise ValueError('Choose raw 1..24 hours or hourly 1..2160 hours')
    if type(include_processes) is not bool:raise ValueError('Invalid privacy selection')
    now=time.time() if now is None else number(now)
    if now<0:raise ValueError('Invalid export time')
    path=Path(path).absolute()
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('Symlink database not allowed')
    info,parent=path.stat(),path.parent.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o077 or parent.st_mode&0o077 or info.st_uid!=parent.st_uid or info.st_size>64*1024*1024:raise ValueError('Unsafe diagnostic database')
    spool=tempfile.SpooledTemporaryFile(max_size=512*1024,mode='w+b')
    db=None;size=0;count=0;deadline=time.monotonic()+5
    def write(value):
        nonlocal size
        raw=value if isinstance(value,bytes) else json.dumps(value,separators=(',',':'),allow_nan=False).encode()
        size+=len(raw)
        if size>MAX_OUTPUT:raise ValueError('Export exceeds 32 MiB; select a shorter window')
        spool.write(raw)
    try:
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)
        db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA cache_size=-512')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,MAX_RECORD)
        db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
        db.execute('BEGIN')
        start=now-hours*3600 if resolution=='raw' else (int(now//3600)-hours+1)*3600
        header=dict(schema=1,kind='local_diagnostic_export',resolution=resolution,window_hours=hours,
                    window_start_unix=start,window_end_unix=now,generated_at_unix=now,
                    process_details_included=include_processes,
                    note='Observed samples only; gaps are not zero. Hourly means are sample means, not time-weighted. Current hour can be partial; clock adjustments can affect bucket coverage. Sensor indices can change across boots. Process names/PIDs are private; RSS includes shared pages.')
        write(json.dumps(header,separators=(',',':')).encode()[:-1]+b',"rows":[')
        if resolution=='raw':
            cursor=db.execute('SELECT timestamp,payload FROM samples WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp,id LIMIT 2881',(start,now));limit=2880
        else:
            cursor=db.execute('SELECT hour,payload FROM hourly WHERE hour BETWEEN ? AND ? ORDER BY hour LIMIT 2161',(int(start//3600),int(now//3600)));limit=2160
        for stamp,payload in cursor:
            if time.monotonic()>deadline:raise TimeoutError('Export deadline exceeded')
            if count>=limit:raise ValueError('Export row bound exceeded')
            number(stamp)
            if resolution=='hourly' and type(stamp) is not int:raise ValueError('Invalid hourly timestamp')
            data=decode(payload)
            row=raw_row(stamp,data,include_processes) if resolution=='raw' else hourly_row(stamp,data,include_processes)
            if count:write(b',')
            write(row);count+=1
        write(b'],"row_count":'+str(count).encode()+b',"missing_hours":'+(str(hours-count).encode() if resolution=='hourly' else b'null')+b'}\n')
        db.execute('ROLLBACK')
        spool.seek(0)
        return spool
    except BaseException:
        spool.close();raise
    finally:
        if db is not None:db.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hours',type=int,default=24)
    parser.add_argument('--resolution',choices=('raw','hourly'),default='hourly')
    parser.add_argument('--include-processes',action='store_true',help='Include private short process names and PID/CPU/RSS peaks')
    parser.add_argument('--trial',action='store_true',help='Export only the existing project trial recording as the current user')
    args=parser.parse_args()
    if not args.trial and os.geteuid()!=0:raise PermissionError('Production diagnostics require administrator access')
    with export(TRIAL if args.trial else DATABASE,hours=args.hours,resolution=args.resolution,include_processes=args.include_processes) as spool:
        shutil.copyfileobj(spool,sys.stdout.buffer,65536)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Export failed ('+type(error).__name__+'): '+str(error),file=sys.stderr)
        sys.exit(1)
