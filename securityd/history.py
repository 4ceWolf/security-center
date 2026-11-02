"""Bounded local observations and normalized events. No credentials/raw journals."""
import contextlib
import datetime
import hashlib
import json
import os
import sqlite3
import time

MAX_EVENTS = 2000
RETENTION_SECONDS = 30 * 86400


def fingerprint(module):
    # Ignore poll timestamps and changing database age; include meaningful inventory changes.
    details = module.get('details', {})
    if module['id']=='processes':
        evidence=[module['status'],details.get('findings'),details.get('findings_truncated'),details.get('truncated')]
        return hashlib.sha256(json.dumps(evidence,sort_keys=True).encode()).hexdigest()
    fields = {'usbguard': ['devices', 'counts', 'native_policy_integrity'], 'integrity': ['changes', 'unavailable', 'baseline_approved'], 'audit': ['checks'], 'devices': ['devices'], 'listeners': ['tcp_listeners'],
              'services': ['units'], 'updates': ['packages'], 'snapshots': ['recent']}
    evidence = {key: details.get(key) for key in fields.get(module['id'], [])}
    return hashlib.sha256(json.dumps([module['status'], module['summary'], evidence],
                                    sort_keys=True).encode()).hexdigest()


class History:
    def __init__(self, path):
        self.path = path

    def journal_cursor(self):
        if not os.path.exists(self.path):
            return None
        with contextlib.closing(sqlite3.connect(self.path, timeout=2)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='journal_state'").fetchone():
                return None
            row = db.execute('SELECT cursor FROM journal_state WHERE id=1').fetchone()
            return row[0] if row else None

    def record(self, snapshot):
        with contextlib.closing(sqlite3.connect(self.path, timeout=2)) as db:
            os.chmod(self.path, 0o600)
            db.execute('PRAGMA max_page_count=4096')
            db.execute('PRAGMA cache_size=-1024')
            db.execute('PRAGMA secure_delete=ON')
            db.execute('CREATE TABLE IF NOT EXISTS events (key TEXT PRIMARY KEY, timestamp REAL NOT NULL, boot_id TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS events_time ON events(timestamp)')
            db.execute('CREATE TABLE IF NOT EXISTS states (module TEXT PRIMARY KEY, boot_id TEXT NOT NULL, fingerprint TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS journal_state (id INTEGER PRIMARY KEY CHECK(id=1), cursor TEXT, gaps INTEGER NOT NULL)')
            stamp = datetime.datetime.fromisoformat(snapshot['generated_at']).timestamp()
            boot_id = str(snapshot['boot_id'])[:64]
            with db:
                for module in snapshot['modules']:
                    identifier = str(module['id'])[:64]
                    current = fingerprint(module)
                    previous = db.execute('SELECT boot_id,fingerprint FROM states WHERE module=?', (identifier,)).fetchone()
                    if previous != (boot_id, current):
                        kind = 'observation' if previous is None or previous[0] != boot_id else 'state_change'
                        prefix = 'Observed: ' if kind == 'observation' else 'Changed: '
                        event = {'timestamp': stamp, 'boot_id': boot_id, 'source': identifier,
                                 'severity': module['status'], 'kind': kind,
                                 'summary': (prefix + module['summary'])[:256]}
                        self._insert(db, event)
                        db.execute('INSERT OR REPLACE INTO states VALUES (?,?,?)', (identifier, boot_id, current))
                for event in snapshot.get('events', []):
                    event = dict(event, kind='journal')
                    if event['timestamp'] >= time.time()-RETENTION_SECONDS:
                        self._insert(db, event)
                batch = snapshot.get('_journal_batch')
                if batch is not None:
                    previous = db.execute('SELECT gaps FROM journal_state WHERE id=1').fetchone()
                    gaps = (previous[0] if previous else 0) + int(batch['gap'])
                    if batch['gap']:
                        self._insert(db, {'timestamp': stamp, 'boot_id': boot_id, 'source': 'journal',
                            'severity': 'attention', 'kind': 'coverage_gap',
                            'summary': 'Saved journal position is missing; resumed from retained entries. Events may be missing.'})
                    db.execute('INSERT OR REPLACE INTO journal_state VALUES (1,?,?)', (batch['cursor'], gaps))
                db.execute('DELETE FROM events WHERE timestamp < ?', (time.time()-RETENTION_SECONDS,))
                db.execute('DELETE FROM events WHERE key IN (SELECT key FROM events ORDER BY timestamp DESC,key DESC LIMIT -1 OFFSET ?)', (MAX_EVENTS,))
            rows = db.execute('SELECT timestamp,boot_id,source,severity,kind,summary FROM events ORDER BY timestamp,key').fetchall()
            return [dict(zip(('timestamp','boot_id','source','severity','kind','summary'), row)) for row in rows]

    @staticmethod
    def _insert(db, event):
        normalized = {'timestamp': float(event['timestamp']), 'boot_id': str(event.get('boot_id') or '')[:64],
                      'source': str(event['source'])[:64], 'severity': str(event['severity'])[:24],
                      'kind': str(event['kind'])[:24], 'summary': str(event['summary'])[:256]}
        key = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)',
                   (key, *(normalized[k] for k in ('timestamp','boot_id','source','severity','kind','summary'))))
