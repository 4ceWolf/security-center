"""Bounded read-only hourly diagnostics query; no commands or arbitrary SQL."""
import json
import math
from pathlib import Path
import sqlite3
import stat
import time

DATABASE = Path('/var/lib/private/security-center-telemetry/diagnostics.sqlite')
DEFAULT_METRICS = ('cpu.cpu.busy_percent', 'memory.used_percent', 'battery.BAT0.percent', 'battery.BAT0.discharge_w')
MAX_OUTPUT = 512 * 1024


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value)


def query(path=DATABASE, *, hours=24, metrics=DEFAULT_METRICS, now=None):
    if type(hours) is not int or hours not in (24, 168, 2160):
        raise ValueError('History window must be 24, 168 or 2160 hours')
    if not isinstance(metrics, (tuple, list)) or not 1 <= len(metrics) <= 8 or any(type(k) is not str or not 1 <= len(k) <= 160 for k in metrics) or len(set(metrics)) != len(metrics):
        raise ValueError('Select one to eight distinct metric names')
    now = time.time() if now is None else now
    if not numeric(now) or now < 0:
        raise ValueError('Invalid time')
    path = Path(path).absolute()
    # Caller supplies a fixed trusted private location; no browser-provided paths.
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Symlink database not allowed')
    info, parent = path.stat(), path.parent.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or parent.st_mode & 0o077 or info.st_uid != parent.st_uid or info.st_size > 64 * 1024 * 1024:
        raise ValueError('Unsafe diagnostic database')
    end = int(now // 3600)
    result = dict(schema=1, window_hours=hours, first_hour_unix=(end-hours+1)*3600,
                  last_hour_unix=end*3600, metrics=list(metrics), rows=[], missing_hours=hours,
                  note='Observed-sample means; missing readings are not zero. Current hour may be partial. Not a time-weighted average.')
    deadline = time.monotonic() + 2
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=.2)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA cache_size=-512')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 262144)
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        output_bytes = 1024
        for hour, payload in db.execute('SELECT hour,payload FROM hourly WHERE hour BETWEEN ? AND ? ORDER BY hour LIMIT ?', (end-hours+1, end, hours)):
            if time.monotonic() > deadline:
                raise TimeoutError('History query deadline exceeded')
            if type(hour) is not int or type(payload) is not str or len(payload.encode()) > 262144:
                raise ValueError('Invalid hourly record')
            data = json.loads(payload)
            if not isinstance(data, dict) or type(data.get('samples')) is not int or data['samples'] < 1 or not isinstance(data.get('metrics'), dict):
                raise ValueError('Invalid hourly summary')
            selected = {}
            for name in metrics:
                metric = data['metrics'].get(name)
                if metric is None:
                    selected[name] = None
                    continue
                if not isinstance(metric, dict) or type(metric.get('count')) is not int or not 1 <= metric['count'] <= data['samples'] or any(not numeric(metric.get(k)) for k in ('sum','min','max')) or metric['min'] > metric['max']:
                    raise ValueError('Invalid metric summary')
                mean = metric['sum'] / metric['count']
                if not math.isfinite(mean):
                    raise ValueError('Invalid average')
                selected[name] = dict(mean=mean, min=metric['min'], max=metric['max'], count=metric['count'])
            row = dict(hour_unix=hour*3600, samples=data['samples'], metrics=selected,
                       mixed_boots=data.get('mixed_boots') if type(data.get('mixed_boots')) is bool else None,
                       samples_with_issues=data.get('samples_with_issues') if type(data.get('samples_with_issues')) is int else None)
            output_bytes += len(json.dumps(row, allow_nan=False).encode()) + 2
            if output_bytes > MAX_OUTPUT:
                raise ValueError('History output exceeds limit; request fewer metrics or a shorter window')
            result['rows'].append(row)
    finally:
        db.close()
    result['missing_hours'] -= len(result['rows'])
    return result
