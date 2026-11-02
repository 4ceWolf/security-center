"""Bounded local diagnostic samples. No privileged actions or network access."""
import json
import fcntl
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

MAX_PROCESSES = 1024
MAX_METRICS = 1024
RAW_ROWS = 2880
HOUR_ROWS = 2160


def private_lock(path):
    """Exclusive nonblocking writer lock in caller-owned trusted private ancestry."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if path.parent.is_symlink() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError('Lock requires an owned private directory')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Unsafe lock file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, limit=131072):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        value = f.read(limit + 1)
    if len(value) > limit:
        raise ValueError('Source exceeds read limit')
    return value.strip()


def number(path):
    value = float(read(path, 128))
    if not math.isfinite(value):
        raise ValueError('Nonfinite sensor')
    return value


def entries(path, limit, issues):
    result = []
    try:
        with os.scandir(path) as stream:
            for entry in stream:
                if len(result) >= limit:
                    issues.append(str(path) + ': enumeration truncated')
                    break
                result.append(Path(entry.path))
    except OSError:
        issues.append(str(path) + ': unavailable')
    return sorted(result)


def process_stat(text):
    # comm can contain spaces and closing parentheses; fields after last ')' are fixed.
    end = text.rfind(')')
    fields = text[end + 2:].split()
    if end < 0 or len(fields) < 22:
        raise ValueError('Malformed stat')
    return {'name': text[text.index('(') + 1:end][:64],
            'ticks': int(fields[11]) + int(fields[12]),
            'start_ticks': int(fields[19]), 'rss_bytes': max(0, int(fields[21])) * os.sysconf('SC_PAGE_SIZE')}


class Sampler:
    def __init__(self, proc='/proc', sys='/sys', interval=30):
        self.proc, self.sys = Path(proc), Path(sys)
        self.interval, self.previous = interval, None
        self.hz = os.sysconf('SC_CLK_TCK')

    def sample(self):
        issues, metrics, counters, processes, batteries = [], {}, {}, {}, {}
        boot = read(self.proc / 'sys/kernel/random/boot_id', 64)
        mono = time.monotonic()
        elapsed_boot = time.clock_gettime(time.CLOCK_BOOTTIME)
        timestamp = time.time()
        def put(key, value):
            if math.isfinite(value) and len(metrics) < MAX_METRICS:
                metrics[key] = round(value, 6)
        def section(name, callback):
            try:
                callback()
            except (OSError, ValueError, IndexError, KeyError):
                issues.append(name + ': unavailable or malformed')
        def cpu():
            for line in read(self.proc / 'stat').splitlines():
                fields = line.split()
                if re.fullmatch(r'cpu\d*', fields[0]):
                    ticks = [int(v) for v in fields[1:9]]
                    if len(ticks) != 8:
                        raise ValueError('Incomplete CPU counters')
                    counters['cpu.' + fields[0]] = ticks
        section('cpu', cpu)
        def memory():
            mem = {line.split(':')[0]: int(line.split()[1]) * 1024
                   for line in read(self.proc / 'meminfo').splitlines() if ':' in line}
            for key in ('MemTotal', 'MemAvailable', 'Cached', 'Buffers', 'SwapTotal', 'SwapFree', 'Dirty', 'Slab'):
                if key in mem:
                    put('memory.' + key + '_bytes', mem[key])
            put('memory.used_bytes', mem['MemTotal'] - mem['MemAvailable'])
            put('memory.used_percent', 100 * (1 - mem['MemAvailable'] / mem['MemTotal']))
            put('memory.swap_used_bytes', mem['SwapTotal'] - mem['SwapFree'])
        section('memory', memory)
        def load():
            for suffix, value in zip(('1m', '5m', '15m'), read(self.proc / 'loadavg').split()[:3]):
                put('load.' + suffix, float(value))
        section('load', load)
        for label, path in (('root', '/'), ('home', '/home')):
            def filesystem(label=label, path=path):
                usage = os.statvfs(path)
                put('filesystem.' + label + '.total_bytes', usage.f_blocks * usage.f_frsize)
                put('filesystem.' + label + '.available_bytes', usage.f_bavail * usage.f_frsize)
            section('filesystem.' + label, filesystem)
        for policy in entries(self.sys / 'devices/system/cpu/cpufreq', 256, issues):
            if re.fullmatch(r'policy\d+', policy.name):
                section('frequency.' + policy.name, lambda policy=policy:
                        put('frequency.' + policy.name + '.mhz', number(policy / 'scaling_cur_freq') / 1000))
        for kind in ('cpu', 'memory', 'io'):
            def pressure(kind=kind):
                for line in read(self.proc / 'pressure' / kind).splitlines():
                    fields = line.split()
                    for item in fields[1:]:
                        key, value = item.split('=')
                        if key in ('avg10', 'avg60', 'avg300'):
                            put('pressure.' + kind + '.' + fields[0] + '.' + key + '_percent', float(value))
            section('pressure.' + kind, pressure)
        def network():
            for line in read(self.proc / 'net/dev').splitlines()[2:66]:
                name, data = line.split(':', 1)
                values = [int(v) for v in data.split()]
                name = name.strip()
                identity = read(self.sys / 'class/net' / name / 'ifindex', 32)
                counters['network.' + name] = [identity, values[0], values[8], values[2], values[10], values[3], values[11]]
        section('network', network)
        def disks():
            lines = read(self.proc / 'diskstats').splitlines()
            if len(lines) > 128:
                issues.append('disk: enumeration truncated')
            for line in lines[:128]:
                f = line.split()
                if len(f) < 14:
                    continue
                try:
                    sequence = read(self.sys / 'class/block' / f[2] / 'diskseq', 64)
                except OSError:
                    # Partitions and drivers without diskseq cannot reliably distinguish replacement.
                    issues.append('disk.' + f[2] + ': no diskseq; rates omitted')
                    continue
                counters['disk.' + f[2]] = [f[0] + ':' + f[1] + ':' + sequence, int(f[5]) * 512, int(f[9]) * 512, int(f[12])]
        section('disk', disks)
        for device in entries(self.sys / 'class/power_supply', 16, issues):
            def battery(device=device):
                if read(device / 'type', 64) != 'Battery':
                    try:
                        put('power.' + device.name + '.online', number(device / 'online'))
                    except OSError:
                        pass
                    return
                prefix = 'battery.' + device.name + '.'
                state = read(device / 'status', 64)
                batteries[device.name] = {'status': state}
                fields = {'capacity': ('percent', 1), 'energy_now': ('energy_wh', 1e-6),
                          'energy_full': ('full_wh', 1e-6), 'energy_full_design': ('design_wh', 1e-6),
                          'voltage_now': ('voltage_v', 1e-6), 'cycle_count': ('cycles', 1),
                          'charge_now': ('charge_ah', 1e-6), 'charge_full': ('full_ah', 1e-6),
                          'charge_full_design': ('design_ah', 1e-6)}
                for field, (suffix, scale) in fields.items():
                    try:
                        put(prefix + suffix, number(device / field) * scale)
                    except (OSError, ValueError):
                        pass
                try:
                    watts = abs(number(device / 'power_now')) * 1e-6
                except (OSError, ValueError):
                    try:
                        watts = abs(number(device / 'current_now') * number(device / 'voltage_now')) * 1e-12
                    except (OSError, ValueError):
                        watts = None
                if watts is not None:
                    put(prefix + 'power_w', watts)
                    if state == 'Discharging':
                        put(prefix + 'discharge_w', watts)
                    elif state == 'Charging':
                        put(prefix + 'charge_w', watts)
                for unit in ('wh', 'ah'):
                    full, design = metrics.get(prefix + 'full_' + unit), metrics.get(prefix + 'design_' + unit)
                    if full is not None and design and design > 0:
                        put(prefix + 'health_percent', full / design * 100)
                        break
            section('battery.' + device.name, battery)
        sensor_count = 0
        for device in entries(self.sys / 'class/hwmon', 32, issues):
            def sensors(device=device):
                nonlocal sensor_count
                chip = read(device / 'name', 128)
                for item in entries(device, 256, issues):
                    if re.fullmatch(r'(temp|fan)\d+_input', item.name):
                        try:
                            suffix, scale = ('_c', .001) if item.name.startswith('temp') else ('_rpm', 1)
                            put('sensor.' + device.name + '.' + chip + '.' + item.name + suffix, number(item) * scale)
                            sensor_count += 1
                        except (OSError, ValueError):
                            issues.append('sensor.' + device.name + '.' + item.name + ': unavailable')
            section('sensor.' + device.name, sensors)
        if not sensor_count:
            issues.append('sensors: no readings')
        missing = 0
        # Enumerate bounded /proc entries, then cap PIDs separately.
        pids = [p for p in entries(self.proc, MAX_PROCESSES + 512, issues) if p.name.isdecimal()]
        if len(pids) > MAX_PROCESSES:
            issues.append('processes: enumeration truncated')
        for directory in pids[:MAX_PROCESSES]:
            try:
                one = process_stat(read(directory / 'stat', 8192))
                two = process_stat(read(directory / 'stat', 8192))
                if one['start_ticks'] != two['start_ticks']:
                    raise ValueError('PID changed')
                processes[directory.name] = two
            except (OSError, ValueError, IndexError):
                missing += 1
        if missing:
            issues.append('processes: %d unreadable or changed' % missing)
        prev = self.previous
        dt = mono - prev['mono'] if prev else None
        gap = not prev or prev['boot'] != boot or dt <= 0 or dt > self.interval * 3
        if prev and abs((elapsed_boot - prev['elapsed_boot']) - dt) > 1:
            gap = True
        if gap:
            issues.append('rates: first sample, changed boot, sleep or long gap')
        else:
            for key, current in counters.items():
                old = prev['counters'].get(key)
                if old is None or len(old) != len(current):
                    continue
                if key.startswith('cpu.'):
                    delta = [a - b for a, b in zip(current, old)]
                    total = sum(delta)
                    if min(delta) >= 0 and total > 0:
                        put(key + '.busy_percent', 100 * (total - delta[3] - delta[4]) / total)
                        put(key + '.iowait_percent', 100 * delta[4] / total)
                elif current[0] == old[0]:
                    suffixes = ('rx_bytes_s', 'tx_bytes_s', 'rx_errors_s', 'tx_errors_s', 'rx_drops_s', 'tx_drops_s') if key.startswith('network.') else ('read_bytes_s', 'write_bytes_s', 'busy_percent')
                    for suffix, a, b in zip(suffixes, current[1:], old[1:]):
                        if a >= b:
                            put(key + '.' + suffix, (a - b) / dt / (10 if suffix == 'busy_percent' else 1))
            for pid, process in processes.items():
                old = prev['processes'].get(pid)
                if old and old['start_ticks'] == process['start_ticks'] and process['ticks'] >= old['ticks']:
                    process['cpu_percent_one_core'] = round(100 * (process['ticks'] - old['ticks']) / self.hz / dt, 4)
        top_cpu = sorted((dict(p, pid=int(pid)) for pid, p in processes.items() if 'cpu_percent_one_core' in p), key=lambda p: p['cpu_percent_one_core'], reverse=True)[:5]
        top_ram = sorted((dict(p, pid=int(pid)) for pid, p in processes.items()), key=lambda p: p['rss_bytes'], reverse=True)[:5]
        self.previous = dict(boot=boot, mono=mono, elapsed_boot=elapsed_boot, counters=counters, processes=processes)
        if len(metrics) >= MAX_METRICS:
            issues.append('metrics: limit reached')
        return dict(schema=1, timestamp=timestamp, boot_id=boot, interval_seconds=None if gap else dt,
                    metrics=metrics, batteries=batteries, top_cpu=top_cpu, top_ram=top_ram,
                    processes_observed=len(processes), issues=issues[:128])


class Store:
    """Private, single-writer diagnostic DB; not authenticated security evidence."""
    def __init__(self, path):
        self.lock_fd = private_lock(str(path) + '.lock')
        self.db = None
        try:
            self._open(path)
        except BaseException:
            self.close()
            raise

    def _open(self, path):
        path = Path(path)
        parent = path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
            raise ValueError('Database requires an owned private directory')
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('Database requires owner-only permissions')
        finally:
            os.close(fd)
        # Ancestors/caller must be trusted; not a hostile-filesystem transaction API.
        self.db = sqlite3.connect(path, timeout=2)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA cache_size=-512')
        page = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute('PRAGMA max_page_count=%d' % (64 * 1024 * 1024 // page))
        self.db.execute('CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, payload TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS hourly(hour INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
        self.db.commit()

    def append(self, sample):
        payload = json.dumps(sample, separators=(',', ':'), allow_nan=False)
        if len(payload.encode()) > 131072 or len(sample['metrics']) > MAX_METRICS:
            raise ValueError('Oversized sample')
        now = sample['timestamp']
        hour = int(now // 3600)
        with self.db:
            # Serialize summary reads with owner-requested history removal too.
            # A deferred read before acquiring the write lock can restore an old
            # summary after a concurrent deletion committed.
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT payload FROM hourly WHERE hour=?', (hour,)).fetchone()
            summary = json.loads(row[0]) if row else dict(samples=0, rate_samples=0, metrics={}, peak_cpu=None, peak_ram=None)
            summary['samples'] += 1
            summary['rate_samples'] += sample['interval_seconds'] is not None
            summary['samples_with_issues'] = summary.get('samples_with_issues', 0) + bool(sample['issues'])
            boots = summary.setdefault('boot_ids', [])
            if sample['boot_id'] not in boots:
                if len(boots) < 16:
                    boots.append(sample['boot_id'])
                else:
                    summary['boot_ids_truncated'] = True
            summary['mixed_boots'] = len(boots) > 1 or summary.get('boot_ids_truncated', False)
            for key, value in sample['metrics'].items():
                if not math.isfinite(value):
                    raise ValueError('Nonfinite metric')
                if key not in summary['metrics'] and len(summary['metrics']) >= MAX_METRICS:
                    summary['metrics_truncated'] = True
                    continue
                item = summary['metrics'].setdefault(key, dict(count=0, sum=0, min=value, max=value))
                item['count'] += 1
                item['sum'] += value
                item['min'], item['max'] = min(item['min'], value), max(item['max'], value)
            for kind, field in (('cpu', 'cpu_percent_one_core'), ('ram', 'rss_bytes')):
                top = sample['top_' + kind]
                old = summary['peak_' + kind]
                if top and (old is None or top[0][field] > old[field]):
                    summary['peak_' + kind] = dict(top[0], timestamp=now)
            # Prune before inserting, so freed pages can be reused at the size cap.
            self.db.execute('DELETE FROM samples WHERE timestamp < ?', (now - 86400,))
            self.db.execute('DELETE FROM samples WHERE id NOT IN (SELECT id FROM samples ORDER BY id DESC LIMIT ?)', (RAW_ROWS - 1,))
            self.db.execute('DELETE FROM hourly WHERE hour < ?', (hour - HOUR_ROWS + 1,))
            self.db.execute('INSERT INTO samples(timestamp,payload) VALUES(?,?)', (now, payload))
            self.db.execute('INSERT OR REPLACE INTO hourly VALUES(?,?)', (hour, json.dumps(summary, separators=(',', ':'), allow_nan=False)))
            self.db.execute('DELETE FROM hourly WHERE hour NOT IN (SELECT hour FROM hourly ORDER BY hour DESC LIMIT ?)', (HOUR_ROWS,))

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
