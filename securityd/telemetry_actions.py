"""On-demand fixed telemetry operations. Authorization belongs to the helper."""
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

MAX_REQUEST = 4096
DATABASE = Path('/var/lib/private/security-center-telemetry/diagnostics.sqlite')


def request(raw):
    if type(raw) is not bytes or len(raw) > MAX_REQUEST:
        raise ValueError('Invalid request size')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate field')
            value[key] = item
        return value
    try:
        data = json.loads(raw, object_pairs_hook=unique)
    except (RecursionError, OverflowError) as error:
        raise ValueError('Invalid request structure') from error
    return validate(data)


def validate(data):
    if type(data) is not dict or type(data.get('operation')) is not str:
        raise ValueError('Invalid operation')
    if data['operation'] == 'export':
        if (set(data) != {'operation', 'hours', 'resolution', 'include_processes'}
                or type(data['resolution']) is not str or data['resolution'] not in ('raw', 'hourly')
                or type(data['hours']) is not int
                or not 1 <= data['hours'] <= (24 if data['resolution'] == 'raw' else 2160)
                or type(data['include_processes']) is not bool):
            raise ValueError('Invalid export selection')
    elif data['operation'] == 'erase':
        if set(data) != {'operation', 'confirmation'} or data['confirmation'] != 'erase_saved_telemetry':
            raise ValueError('Explicit history removal confirmation required')
    else:
        raise ValueError('Unsupported operation')
    return data


def erase(path=DATABASE):
    """Logical deletion in-place, serialized with Store.append; no unlink/VACUUM.

    The path parameter is for disposable tests only. Production callers use the
    fixed private location. Trusted private ancestry/root peers are assumed.
    """
    path = Path(path).absolute()
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Linked database refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info, parent = os.fstat(fd), path.parent.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & 0o077 or parent.st_mode & 0o077
                or info.st_uid != parent.st_uid or not stat.S_ISDIR(parent.st_mode)
                or info.st_size > 64 * 1024 * 1024):
            raise ValueError('Unsafe diagnostic database')
        current = path.stat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('Database entry changed')
        db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=.2)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA cache_size=-512')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 262144)
            deadline = time.monotonic() + 5
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            with db:
                db.execute('BEGIN IMMEDIATE')
                schema = db.execute("SELECT type,name,tbl_name FROM sqlite_schema ORDER BY name").fetchall()
                if schema != [('table', 'hourly', 'hourly'), ('table', 'samples', 'samples')]:
                    raise ValueError('Unexpected diagnostic schema')
                expected = {'samples': [('id', 'INTEGER', 0, 1), ('timestamp', 'REAL', 1, 0), ('payload', 'TEXT', 1, 0)],
                            'hourly': [('hour', 'INTEGER', 0, 1), ('payload', 'TEXT', 1, 0)]}
                for table in ('samples', 'hourly'):
                    actual = [(row[1], row[2], row[3], row[5]) for row in db.execute('PRAGMA table_info(' + table + ')')]
                    if actual != expected[table]:
                        raise ValueError('Unexpected diagnostic columns')
                samples = db.execute('SELECT count(*) FROM samples').fetchone()[0]
                hours = db.execute('SELECT count(*) FROM hourly').fetchone()[0]
                if samples > 2880 or hours > 2160:
                    raise ValueError('Diagnostic row bounds exceeded')
                db.execute('DELETE FROM samples')
                db.execute('DELETE FROM hourly')
            return dict(schema=1, kind='local_diagnostic_erasure', removed_samples=samples,
                        removed_hours=hours, erased_at_unix=time.time(),
                        recording_continues=True, forensic_erasure=False)
        finally:
            db.close()
    finally:
        os.close(fd)
