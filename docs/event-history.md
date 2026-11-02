# Event history
A bounded SQLite database at /var/lib/security-center-monitor/events.sqlite stores normalized journal events and observed module changes. No raw journal messages, passwords, key material or device serials are stored in event summaries. Inventory fingerprints detect changes without persisting inventory contents in this database.

Root-owned service state directory 0750; SQLite file 0600. The existing root/wheel socket serves cached sanitized history only. No new network endpoint or mutation API. At most 2,000 events / 30 days, 16 MiB database page ceiling (default 4 KiB pages), ~1 MiB SQLite cache. SQLite rollback journal may temporarily add disk overhead; no WAL/index daemon.

First sightings are labeled “Observed”, not reported as historical activation or proof. Subsequent changed fingerprints are labeled “Changed”. Boot IDs distinguish boots. Journal ingestion now resumes from a SQLite cursor, reading at most 256 selected system-manager entries per cycle across boots. The cursor and normalized events commit together. Exact anchor checks detect a missing saved position; a coverage-gap event records fallback to the retained last 30 days. A full batch displays catch-up status. Only trusted journald PID=1, UID=0, COMM=systemd records with allowlisted UNIT values are normalized. Deleted intermediate entries and unavailable/expired logs can still leave undetectable gaps; this is not a complete audit trail.

All retained cached events are searchable locally in the UI; render 100 at a time to bound DOM overhead. The API response cap is 2 MiB. History errors produce history_status unavailable while retaining current status checks. Corrupt databases are not deleted/rebaselined automatically.

Purpose: useful persistent evidence across daemon restarts and boots. Files modified: daemon.py, new history.py, client.py response bound, service StateDirectory, Cockpit search/history controls. Prior installed copies and manifest saved under backups/history-before.
Rollback: stop collector; restore the named backed-up code/UI/unit files and install manifest after checking for later changes; remove only newly installed history.py; daemon-reload; restart. Retain the database for owner-controlled review/deletion. Rolling back the service never removes encryption/firewall/lockdown.

Tests: durable reopen, deduplication, state transitions and new boot observations, retention, old-event rejection, SQL-like strings, bounded text and database failure isolation. Live deployment/restart and memory checks follow installation.

Journal update installed with rollback at backups/journal-before-u8bjwowr. Live catch-up completed with journal/history available. 63 Python tests and UI regression passed. A read-only live test recovered 208 normalized events across two batches with durable cursor reopen. A transient test under the same memory limits peaked at48.5MiB with7.1MiB swap. Authenticated full Cockpit-stack memory remains unverified.
