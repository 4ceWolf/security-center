# File integrity monitoring

Initial scope: 17 fixed boot configuration and installed Security Center files. No recursion, credentials, signing keys, whole-/etc hashing or additional daemon. SHA256 plus uid/gid/mode/size/mtime are recorded; contents are never returned. Each file is capped at 1 MiB, read in 64 KiB chunks on the existing 60-second cycle. Future wider policy inventories remain outstanding.

All path components reject symlinks. Special files are refused without blocking; before/after descriptor metadata and a reopened path detect changes during scanning. This does not eliminate every possible concurrent race or detect temporary changes between polls. Errors remain unknown, never clean or deleted.

Baseline: /var/lib/security-center-monitor/integrity-baseline.json must be root-owned, private, schema 1, explicitly approved, and cover exactly the current scope. No baseline is generated or approved automatically. Before approval, the dashboard shows an inventory with unknown trust. Missing/unreadable files cannot establish a complete baseline. Later modifications require separate review; no automatic acceptance of package updates. Package attribution, created-file discovery, ACL monitoring and broader directory policies remain outstanding.

This local baseline is not resistant to root compromise. It is independent of the Secure Boot/TPM trust chain and is not an attestation mechanism.

Files modified: securityd/integrity.py, collector.py, history.py; cockpit/app.js/index.html; installer scripts. Deployment helper: tools/update-integrity-monitor.py. No kernel, boot, authentication or enforcement changes.

Rollback: stop security-center.service; inspect subsequent changes; restore backed-up collector.py, history.py, app.js, index.html and install-record.json from backups/integrity-monitor-before; remove added installed integrity.py; restart. Retain any baseline for explicit owner review. No baseline exists yet.

Tests: content changes, deletion, unreadable states, missing baseline, ancestor/leaf symlinks, FIFO rejection, size cap and replacement while scanning. 22 Python tests passed before deployment.

Update: first baseline explicitly approved and active. See baseline-review.md for exact digest and verification. Earlier no-baseline statements describe the preapproval state.
