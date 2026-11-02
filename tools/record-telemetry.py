#!/usr/bin/python3
"""Finite, unprivileged diagnostic capture under this project."""
import argparse
import json
import os
from pathlib import Path
import resource
import sqlite3
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'securityd'))
from telemetry import Sampler, Store
from telemetry_query import query


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--interval', type=float, default=30)
    parser.add_argument('--summary', action='store_true', help='Read saved summary without collecting')
    parser.add_argument('--history', type=int, choices=(24,168,2160), help='Read hourly history for this many hours without collecting')
    args = parser.parse_args()
    path = ROOT / 'work/telemetry/diagnostics.sqlite'
    if args.history:
        print(json.dumps(query(path, hours=args.history), indent=2))
        return
    if args.summary:
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        try:
            row = db.execute('SELECT payload FROM samples ORDER BY id DESC LIMIT 1').fetchone()
            latest = json.loads(row[0]) if row else None
            row = db.execute('SELECT hour,payload FROM hourly ORDER BY hour DESC LIMIT 1').fetchone()
            hourly = json.loads(row[1]) if row else None
            if hourly:
                hourly['hour_start_unix'] = row[0] * 3600
                for metric in hourly['metrics'].values():
                    metric['sample_mean'] = metric['sum'] / metric['count']
            print(json.dumps({'detailed_samples': db.execute('SELECT count(*) FROM samples').fetchone()[0],
                              'hourly_summaries': db.execute('SELECT count(*) FROM hourly').fetchone()[0],
                              'latest': latest, 'latest_hour': hourly}, indent=2))
        finally:
            db.close()
        return
    if not 1 <= args.samples <= 2880 or not 1 <= args.interval <= 300:
        parser.error('samples must be 1..2880 and interval 1..300 seconds')
    os.umask(0o077)
    store, sampler = Store(path), Sampler(interval=args.interval)
    cpu_start, start = time.process_time(), time.monotonic()
    try:
        for index in range(args.samples):
            sample = sampler.sample()
            store.append(sample)
            if index + 1 < args.samples:
                time.sleep(max(0, start + (index + 1) * args.interval - time.monotonic()))
    finally:
        store.close()
    report = {'samples_written': args.samples, 'database': str(path),
              'elapsed_seconds': round(time.monotonic() - start, 3),
              'collector_cpu_seconds': round(time.process_time() - cpu_start, 3),
              'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              'database_bytes': path.stat().st_size, 'last_metric_count': len(sample['metrics']),
              'last_issues': sample['issues'], 'continuous_recording': False}
    (path.parent / 'capture-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
