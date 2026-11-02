"""Private candidate state with policy, previous versions and audit in one commit."""
import contextlib
import fcntl
import os
import pathlib
import sqlite3
import stat
import time
from trust_policy import apply, canonical, decode, revision, validate

STATE = pathlib.Path('/var/lib/security-center-trust')


class Store:
    def __init__(self, *, fixture=None, initialize=False):
        self.path = STATE if fixture is None else pathlib.Path(fixture)
        if fixture is None and os.geteuid() != 0:
            raise PermissionError('Administrator access required')
        if fixture is not None and not self.path.name.startswith('security-center-trust-test-'):
            raise ValueError('Use a marked disposable fixture directory')
        # Production bootstrap belongs to the reviewed installer, never to a
        # browser list/save request. Losing the whole directory cannot reset trust.
        if fixture is None and initialize and self.path.exists():
            raise FileExistsError('Initialization requires a new state directory')
        self.allow_initialize = initialize or fixture is not None
        self.owner = os.geteuid()

    @contextlib.contextmanager
    def connect(self):
        if self.allow_initialize:
            self.path.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock = None
        db = None
        try:
            info = os.fstat(fd)
            if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o700:
                raise PermissionError('Unsafe trust directory')
            try:
                if not self.allow_initialize: raise FileExistsError
                lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
                first_open = True
                os.fsync(lock)
                os.fsync(fd)
            except FileExistsError:
                lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                first_open = False

            self._private(os.fstat(lock))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # The private directory prevents unprivileged replacement after these checks.
            for name in ('state.sqlite', 'state.sqlite-journal', 'state.sqlite-wal', 'state.sqlite-shm'):
                try: self._private(os.stat(name, dir_fd=fd, follow_symlinks=False))
                except FileNotFoundError: pass
            if not first_open:
                # The retained lock is initialization intent, not a permission
                # to recreate lost state. Incomplete initialization needs repair.
                existing = os.stat('state.sqlite', dir_fd=fd, follow_symlinks=False)
                if existing.st_size == 0:
                    raise ValueError('Trust database is empty; explicit recovery required')
            initial = os.open('state.sqlite', os.O_RDWR | (os.O_CREAT if first_open else 0) | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
            try: self._private(os.fstat(initial))
            finally: os.close(initial)
            db = sqlite3.connect(f'/proc/self/fd/{fd}/state.sqlite', timeout=0, isolation_level=None)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA cache_size=-512')
            db.execute('PRAGMA max_page_count=16384')
            if not first_open:
                # Missing tables in existing state are corruption, not bootstrap.
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'state', 'audit', 'metadata'}.issubset(tables):
                    raise ValueError('Trust schema missing; explicit recovery required')
            db.execute('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), policy BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor INTEGER NOT NULL, action TEXT NOT NULL, device_id TEXT NOT NULL, before_policy BLOB NOT NULL, after_revision TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.execute('COMMIT')
            os.fsync(fd)
        except BaseException:
            if db is not None and db.in_transaction: db.execute('ROLLBACK')
            raise
        finally:
            if db is not None: db.close()
            if lock is not None: os.close(lock)
            os.close(fd)

    def _private(self, info):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o600:
            raise PermissionError('Unsafe trust state file')

    @staticmethod
    def current(db, seed):
        row = db.execute('SELECT policy FROM state WHERE id=1').fetchone()
        marker = db.execute('SELECT initialized FROM metadata WHERE id=1').fetchone()
        if row:
            if marker != (1,): raise ValueError('Trust initialization record missing')
            return validate(decode(row[0]))
        if marker is not None or db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]:
            raise ValueError('Saved policy missing; explicit recovery required')
        policy = validate(seed)
        db.execute('INSERT INTO state(id,policy) VALUES (1,?)', (canonical(policy),))
        db.execute('INSERT INTO metadata(id,initialized) VALUES (1,1)')
        return policy

    def read(self, seed):
        with self.connect() as db:
            policy = self.current(db, seed)
            return policy

    def save(self, seed, proposal, inventory, *, actor):
        if type(actor) is not int or actor < 0:
            raise ValueError('Invalid actor')
        with self.connect() as db:
            before = self.current(db, seed)
            after = apply(before, inventory, proposal)
            db.execute('INSERT INTO audit(at,actor,action,device_id,before_policy,after_revision) VALUES (?,?,?,?,?,?)',
                       (int(time.time()), actor, proposal['action'], proposal['device_id'], canonical(before), revision(after)))
            db.execute('INSERT INTO state(id,policy) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy', (canonical(after),))
            # Bounded local history; previous policy and audit always commit together.
            db.execute('DELETE FROM audit WHERE sequence <= (SELECT COALESCE(MAX(sequence),0)-200 FROM audit)')
        return after
