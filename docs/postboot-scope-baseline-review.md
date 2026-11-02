# Installed scope/recovery review — exact baseline approval pending

Protected transaction txn-bd7cbae1d23fdf074e3fd81482cafc7f installed the reviewed
scope/recovery release and restored both previously active services. The protected
health check accepted all17retained module identifiers. No custom preboot modules
are required. No boot, TPM enrollment, keyslot or existing firewall policy changed.

Changed files: collector.py removes two out-of-scope scheduled readers; adapters.py
labels preboot gating outside scope; Cockpit app.js/index.html update scope/device
copy and add the read-only automatic-unlock recovery review. The review explicitly
states actual repair is not installed. It cannot enroll/reset the TPM or accept a
passphrase. Twenty-seven release files were identical in prior host observation.

Release: work/releases/monitor-o8ib655z/release.json
SHA256:3a2fbd9154ced8a0845b1cab95fd0386898fe946eba0557241ebb0ae18c54764
Current approved reference:
c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437
EXACT new36-path candidate:
2039b424681401638c682d272df92dc44af2e5284bb76bb30c24191d72a2ca50

Approval records the installed files as the change-detection reference and archives
the previous reference. It changes no disk/TPM/USB/network security setting. Actual
USBGuard/OpenSnitch activation and TPM repair are separate work. All three native
protection packages are installed, currently disabled/inactive. AppArmor remains
disabled in the running kernel. Package integrity verification was retained; an
exact missing AppArmor signature came from Arch's official package archive.

Project plan requires explicit owner approval of this exact baseline. No earlier
approval covers it. The approval publisher must recheck current files and candidate;
installation success alone is not approval. Protected backups/old baseline remain.
