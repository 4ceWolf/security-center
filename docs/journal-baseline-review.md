# Journal update: replacement baseline review

The incremental journal reader is installed. The existing approved reference is still active and correctly reports four changed files; the remaining thirteen monitored files are unchanged. No boot configuration or security policy was changed by this update.

Changed files:
- collector.py: bounded sequential journal batches, saved-position validation, trusted system-manager source checks, normalized messages only.
- history.py: commit the position and events together; preserve a coverage-gap event if the previous position disappeared.
- daemon.py: resume on restart, isolate journal/database failures, keep the private cursor out of the dashboard response.
- app.js: show catch-up, unavailable and missing-position states.

All four files match the installer manifest. The full candidate contains seventeen files, including unchanged boot files. Local hashes prove continuity with these records, not absence of malware or protection against root compromise.

Candidate SHA256: `168eeb6da0a25d26aed6c6f874ef9d08837d319502ab55f68f5a00061d60e151`

Previous approved baseline file SHA256: `d1b47615c7eb18eba84b39c1ce156c8c2fd81c7c34c7c3cbe528f661f098fd62`

Private candidate: `/var/lib/security-center-monitor/baseline-review/168eeb6da0a25d26aed6c6f874ef9d08837d319502ab55f68f5a00061d60e151.json`.

Approval would replace the file-change reference after rescanning all seventeen files and checking both digests. The prior reference is archived. Approval changes no firewall, boot, disk-unlock, device or authentication settings. The implementation plan requires explicit baseline approval; the user explicitly approved this replacement in the security chat.

Validation: 63 Python tests and the UI state regression check passed. A read-only live-journal test recovered 208 normalized events in two batches and verified cursor persistence on database reopen. A transient memory-limited service passed with 48.5 MiB cgroup memory peak and 7.1 MiB swap under MemoryHigh=48M and MemoryMax=80M. This is not a measurement of the whole authenticated Cockpit stack.

Rollback copies and installation manifest: `/home/user/Projects/security-center/backups/journal-before-u8bjwowr`. The installed service started successfully and returned history/journal available, no private cursor, and the expected four FIM differences.
