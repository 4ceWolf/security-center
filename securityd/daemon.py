"""Unix-socket read-only snapshot service. No client-controlled commands."""
import grp
import json
import os
import pathlib
import signal
import socket
import threading
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from collector import snapshot, journal_batch
from history import History
from telemetry_query import query as telemetry_query

SOCKET = '/run/security-center/status.sock'
DATABASE = '/var/lib/security-center-monitor/events.sqlite'
cache = b'{"error":"Initial checks still running"}'
stop = threading.Event()


def refresh(database=DATABASE):
    global cache
    while not stop.is_set():
        try:
            data = snapshot(include_timeline=False)
            store = History(database)
            try:
                batch = journal_batch(store.journal_cursor())
                data['events'] = batch['events']
                data['_journal_batch'] = batch
                data['journal_coverage'] = {key: batch[key] for key in ('gap', 'backlog', 'coverage')}
                data['event_status'] = 'available'
            except Exception:
                data['event_status'] = 'unavailable'
            try:
                journal_status = data.get('event_status')
                data['events'] = store.record(data)
                data['history_status'] = 'available'
                data['journal_status'] = journal_status
                data['event_status'] = 'available'
                data['history_retention'] = {'maximum_events': 2000, 'maximum_days': 30}
            except Exception:
                data['history_status'] = 'unavailable'
            data.pop('_journal_batch', None)
            try:
                data['telemetry_history'] = telemetry_query()
                data['telemetry_history_status'] = 'available'
            except FileNotFoundError:
                data['telemetry_history_status'] = 'not_recorded'
            except Exception:
                data['telemetry_history_status'] = 'unavailable'
            cache = json.dumps(data).encode()
        except Exception:
            cache = b'{"error":"Collector unavailable"}'
        stop.wait(60)


def main(*, socket_path=SOCKET, database=DATABASE, owner_uid=0, owner_gid=None):
    os.umask(0o077)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=refresh, kwargs={'database': database}, daemon=True)
    thread.start()
    path = pathlib.Path(socket_path)
    path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(socket_path)
        os.chown(socket_path, owner_uid, grp.getgrnam('wheel').gr_gid if owner_gid is None else owner_gid)
        os.chmod(socket_path, 0o660)
        server.listen(8)
        server.settimeout(1)
        while not stop.is_set():
            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            with client:
                client.settimeout(1)
                try:
                    request = b''
                    while len(request) < 5 and not request.endswith(b'\n'):
                        chunk = client.recv(5-len(request))
                        if not chunk:
                            break
                        request += chunk
                    client.sendall(cache if request == b'GET\n' else b'{"error":"Read-only API: unsupported request"}')
                except (TimeoutError, OSError):
                    pass
    path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
