#!/usr/bin/python3
"""Exercise retention using a synthetic copy of a locally captured sample."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'securityd'))
from telemetry import Store


def main():
    source = ROOT / 'work/telemetry/diagnostics.sqlite'
    db = sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)
    try:
        sample = json.loads(db.execute('SELECT payload FROM samples ORDER BY id DESC LIMIT 1').fetchone()[0])
    finally:
        db.close()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='telemetry-retention-', dir=ROOT / 'work') as folder:
        path = Path(folder) / 'data.sqlite'
        store = Store(path)
        try:
            # 92 days of hourly data, then more than one full day of 30s samples.
            base = 2000000000 // 3600 * 3600
            for hour in range(92 * 24):
                sample['timestamp'] = base + hour * 3600
                store.append(sample)
            end = sample['timestamp']
            for index in range(3000):
                sample['timestamp'] = end + 30 * (index + 1)
                store.append(sample)
            raw = store.db.execute('SELECT count(*) FROM samples').fetchone()[0]
            hourly = store.db.execute('SELECT count(*) FROM hourly').fetchone()[0]
            assert raw <= 2880 and hourly <= 2160
            assert store.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            report = dict(passed=True, synthetic_writes=92 * 24 + 3000,
                          retained_samples=raw, retained_hours=hourly,
                          database_bytes=path.stat().st_size,
                          metric_count=len(sample['metrics']),
                          elapsed_seconds=round(time.monotonic() - started, 3),
                          note='Synthetic timestamps with current host metric set; no claim of 92-day field testing.')
        finally:
            store.close()
    (ROOT / 'work/telemetry/retention-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
