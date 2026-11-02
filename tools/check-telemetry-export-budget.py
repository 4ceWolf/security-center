#!/usr/bin/python3
"""Disposable synthetic export/storage budget check; never reads owner recordings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import sqlite3
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    work=Path(tempfile.mkdtemp(prefix='telemetry-export-budget-',dir=ROOT/'work'));work.chmod(0o700)
    path=work/'diagnostics.sqlite';now=int(time.time())
    db=sqlite3.connect(path);path.chmod(0o600)
    db.execute('CREATE TABLE samples(id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, payload TEXT NOT NULL)')
    db.execute('CREATE TABLE hourly(hour INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
    values={'cpu.fixture_metric_'+str(index):float(index) for index in range(128)}
    sample=dict(schema=1,boot_id='SYNTHETIC-BUDGET-FIXTURE',interval_seconds=30,metrics=values,
                processes_observed=0,issues=[],batteries={},top_cpu=[],top_ram=[])
    def samples():
        for index in range(2880):
            stamp=now-86400+1+index*30
            yield stamp,json.dumps(dict(sample,timestamp=stamp),separators=(',',':'))
    db.executemany('INSERT INTO samples(timestamp,payload) VALUES(?,?)',samples())
    summary=dict(samples=120,rate_samples=120,samples_with_issues=0,mixed_boots=False,boot_ids=['SYNTHETIC-BUDGET-FIXTURE'],
                 metrics={key:dict(count=120,sum=value*120,min=value,max=value) for key,value in values.items()},peak_cpu=None,peak_ram=None)
    payload=json.dumps(summary,separators=(',',':'))
    db.executemany('INSERT INTO hourly(hour,payload) VALUES(?,?)',((int(now//3600)-2159+index,payload) for index in range(2160)))
    db.commit();db.close()
    spec=importlib.util.spec_from_file_location('telemetry_export',ROOT/'tools/export-telemetry.py')
    exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)
    def file_digest():
        value=hashlib.sha256()
        with path.open('rb') as stream:
            while chunk:=stream.read(65536):value.update(chunk)
        return value.hexdigest()
    before=file_digest()
    results=[]
    for resolution,hours in (('raw',24),('hourly',24),('hourly',2160)):
        started=time.monotonic()
        try:
            with exporter.export(path,hours=hours,resolution=resolution,now=now) as stream:
                output_bytes=0;checksum=hashlib.sha256()
                while chunk:=stream.read(65536):output_bytes+=len(chunk);checksum.update(chunk)
            result=dict(status='complete',output_bytes=output_bytes,sha256=checksum.hexdigest())
        except (ValueError,TimeoutError,sqlite3.OperationalError) as error:
            # Refusal is a bounded result, not a successful full-window export.
            result=dict(status='refused',error_type=type(error).__name__,reason=str(error))
        result.update(resolution=resolution,hours=hours,seconds=round(time.monotonic()-started,3));results.append(result)
    unchanged=file_digest()==before
    report=dict(scope='Synthetic128metrics/2880raw/2160hourly; no production records',work=str(work),
                database_bytes=path.stat().st_size,results=results,database_unchanged=unchanged,
                process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                includes_fixture_construction=True,includes_browser_or_cockpit=False,passed=unchanged and all(row['status']=='complete' for row in results[:2]))
    (work/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
    if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
