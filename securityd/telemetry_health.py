"""Read-only recorder health, never a security or process-liveness attestation."""
import json
import math
import os
from pathlib import Path
import stat
import time
from integrity import open_fixed

# DynamicUser StateDirectory lives here; avoid its public symlink for nofollow reads.
HEALTH = '/var/lib/private/security-center-telemetry/health.json'


def interpret(value, boot_id, boottime):
    if not isinstance(value, dict) or value.get('schema') != 1:
        raise ValueError('Invalid health schema')
    state = value.get('state')
    if state not in ('starting', 'recording', 'degraded', 'stopped'):
        raise ValueError('Invalid state')
    for key in ('updated_boottime', 'interval_seconds'):
        n = value.get(key)
        if type(n) not in (int, float) or not math.isfinite(n) or n < 0:
            raise ValueError('Invalid timing')
    if not 1 <= value['interval_seconds'] <= 300:
        raise ValueError('Invalid interval')
    for key in ('samples_written', 'consecutive_failures'):
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError('Invalid counter')
    success = value.get('last_success_boottime')
    if success is not None and (type(success) not in (int, float) or not math.isfinite(success) or success < 0 or success > value['updated_boottime']):
        raise ValueError('Invalid success time')
    if state == 'recording' and (success is None or value['samples_written'] < 1 or value['consecutive_failures']):
        raise ValueError('Inconsistent recording state')
    current = value.get('boot_id') == boot_id
    age = boottime - value['updated_boottime']
    fresh = current and 0 <= age <= max(90, 3 * value['interval_seconds'])
    details = dict(reported_state=state, current_boot=current, fresh=fresh,
                   samples_this_run=value['samples_written'], consecutive_failures=value['consecutive_failures'],
                   interval_seconds=value['interval_seconds'],
                   last_success_age_seconds=round(boottime - success, 1) if current and success is not None and success <= boottime else None,
                   note='Recorder self-report. Freshness is checked; process liveness and complete metric coverage are not attested.')
    if not fresh:
        return dict(status='attention', summary='Telemetry recording status is stale', details=details)
    if state == 'degraded':
        return dict(status='attention', summary='Telemetry recorder reports a collection or storage failure', details=details)
    if state == 'stopped':
        return dict(status='attention', summary='Telemetry recording is stopped', details=details)
    return dict(status='unknown', summary='Telemetry recording reported' if state == 'recording' else 'Telemetry recorder is starting', details=details)


def configuration():
    try:
        fd = open_fixed(HEALTH)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('Unsafe health file')
            parent = Path(HEALTH).parent.stat()
            if parent.st_mode & 0o077 or parent.st_uid != info.st_uid:
                raise ValueError('Unsafe health directory')
            data = stream.read(8193)
            if len(data) > 8192:
                raise ValueError('Oversized health')
        value = json.loads(data)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return interpret(value, boot, time.clock_gettime(time.CLOCK_BOOTTIME))
    except FileNotFoundError:
        return dict(status='unknown', summary='Telemetry recorder has not published status', details={'installed': 'Not established'})
    except (OSError, ValueError, TypeError):
        return dict(status='unavailable', summary='Telemetry recorder status is unreadable or invalid', details={})
