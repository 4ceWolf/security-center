# Read-only configuration auditing

Scope: four runtime sysctls, plus ownership and group/other write permissions for eight fixed boot/security-center files and their ancestor directories. The audit never reads configuration contents or credentials. It performs no mutation and uses the existing collector schedule; no new service or package.

Findings carry status, explanation, evidence, and a review suggestion. Unreadable values and missing files are unavailable. Symlinks require review and are never declared checked. Unrecognized sysctl values are flagged. This is a bounded initial assessment, not full Lynis coverage, an ACL audit, persistent-setting verification or file integrity monitoring. The Audit navigation exposes the results; changes in evidence are recorded even when the total finding count stays constant.

Sysctl references:
- https://cdn.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html
- https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html

Files: securityd/audit.py, collector.py, history.py; cockpit/app.js and index.html; install-mvp.py and update-audit.py. Existing enforcement and boot settings remain unchanged.

Before deployment: 16 Python tests passed, covering missing/invalid values, insecure parent directories, symlinks, non-root ownership, unavailable aggregate status and history fingerprints. Direct read-only host run found kernel.kptr_restrict=0, three other checked sysctls enabled, and checked file/ancestor permissions acceptable. This is a finding for compatibility review, not an automatic hardening instruction.

Deployment: tools/update-audit.py checks installed hashes against the installation record before copying root-owned code and restarting the collector. Prior copies and manifest retained under backups/audit-before. Rollback: stop the collector, verify no subsequent changes, restore backed-up collector.py/history.py/app.js/index.html and install-record.json, remove the added audit.py only, then restart. Keep event history. No boot, LUKS, TPM, firewall, or authentication changes are involved.

Live deployment verified: 15 modules, 12 audit checks, history available and no unavailable modules. Peak collector 50,835,456 bytes, no automatic restarts. UI logic regression suite passed; authenticated UI rendering still pending.
