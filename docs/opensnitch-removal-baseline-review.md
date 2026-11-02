# OpenSnitch removal — exact installed reference review

The requested removal is installed. OpenSnitch package, daemon, GUI, startup override
and active configuration are removed; private historical records are archived.
Existing firewall rules are unchanged. Networking is owner-managed; remaining firewall
and listener checks are read-only. USB trust and disk unlock settings are unchanged.

The dashboard no longer offers application-firewall Open/Stop controls. Collector
no longer schedules OpenSnitch observations. All37 release-file hashes match installed
bytes. Fresh collector reports16modules, telemetry recording, persistent history available, USB native
policy verified and integrity mode active. Its current6file-change findings are the
six intended edits below, pending this explicit replacement-reference approval.

Approving only updates the change-detection reference and archives the previous one.
The implementation plan requires “Approve baselines explicitly” (line13).
No TPM, LUKS, boot selection or network enforcement changes are part of publication.

Exact candidate SHA256:
350c5194000d7b1bb4c2f18bc1d60eb3a8f63909ab3053700cb7e13f578aedca
Previous approved reference:
b731cd86767d993ca744e91d18a14a20fc76074e96637bb29eff253d10b0e4d9
Transaction: txn-ca929f2f433d936114321f9000af4e24
Release: monitor-wsm8y_z1,37files,42monitored paths.
Manifest SHA256: ee649315e177527e71911f191454f68bef35ce7c7d5e00b0c11f8281ebe981bf

Changed paths:

- /usr/local/lib/security-center/network_policy.py
- /usr/local/lib/security-center/adapters.py
- /usr/local/lib/security-center/history.py
- /usr/local/share/cockpit/security_center/index.html
- /usr/local/share/cockpit/security_center/app.js
- /usr/local/share/cockpit/security_center/usb-controls.js

The generic network_policy.py contains only a retirement docstring. Retaining that
monitored path preserves the approved FIM scope; it has no imports or operations.

Evidence: work/installer/network-removal-combined.json,
work/network-removal-installed-check.json, work/opensnitch-removal-20261020.json,
work/usb-controls-browser-en1is44m/report.json. Retained adapter/history/release/
protected deployment checks passed before installation. No real USB trust change,
reboot or TPM disable was invoked. AppArmor trial remains a separate pending step.

## Owner approved and published

Owner explicitly approved the exact350c5194… candidate above. Publication succeeded
with the captured baseline publisher (returncode0); previous reference archived.
Receipt: work/network-removal-baseline-publication.json. No approval remains pending
for this removal. Final collector refresh verification is recorded in HANDOFF.
