# Approval review: installed monitor, telemetry and device management

The corrected combined release is installed and passed its live checks. This review asks only to replace the file-change reference. It does not authorize boot, TPM, LUKS, USBGuard or Distress changes.

## Exact candidate

- Candidate SHA256: `3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee`
- Previous approved baseline SHA256: `19f88b6f672ea2390c30a72b05d53e551aac5b21774025590dd3200e39cfc5f9`
- Protected root candidate: `/var/lib/security-center-monitor/baseline-review/3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee.json`
- Readable exact candidate copy: `work/installer/replacement-baseline.review.json` (hash verified identical to protected candidate).
- Protected transaction: `txn-6678cfb8b8fae4b4b0a5a78763e0adcf`
- Release: `work/releases/monitor-18cuezjm`
- Release manifest SHA256: `93266f0ab6039ccbd0af047652f617486cab8831f9e8ad2ca29fc6331cf6aeb6`

## What approval covers

The reference expands from 17 to 30 files: 13 new code/configuration files, 8 replaced files, 4 identical retained release files, and 5 unchanged read-only settings already in the previous scope. The boot settings are observations only and were not edited. The mutable device-policy database and diagnostic recordings are not treated as immutable files.

| Action | Installed file | SHA256 |
| --- | --- | --- |
| Added | `/etc/security-center/normal-devices.candidate.json` | `1914828742f1c1294a3eaf0c09de3811394e5797ad6091e6bea62e1cfbbc96e6` |
| Added | `/etc/systemd/system/security-center-telemetry.service` | `e1f34a90564994cffd152f16f06af2fe9d0ce70e5a6011c57f2ccc29baa74b1c` |
| Unchanged | `/etc/systemd/system/security-center.service` | `8a33b3aa0a2bf84b01dad076f58ce8b811f536e9c3a3775b8690167ad2aca7cc` |
| Replaced | `/usr/local/lib/security-center/adapters.py` | `fd3bc1677c96e3723361cb88625ee2b9b33954dac1db6a82726c5c516190b124` |
| Unchanged | `/usr/local/lib/security-center/audit.py` | `2fc862b278734f89c0923362fe4a2bd34b516b3b2579620a3e0c1a8599c698f1` |
| Unchanged | `/usr/local/lib/security-center/client.py` | `2dcf4c1030452abdfa28d4395a82aa9174c0d7d240c98a90bc462f8e89a94eaf` |
| Replaced | `/usr/local/lib/security-center/collector.py` | `5a452eba20aa3ca04287b4ea38132c3165be8f2947937e9166c022982675de5d` |
| Added | `/usr/local/lib/security-center/confinement.py` | `125832915abe216a13dc103e5a3b2583a5cdd5129e58a9d56058b1ee07f4f1aa` |
| Replaced | `/usr/local/lib/security-center/daemon.py` | `0a8fbbb0a5d7cf6a7942f35da838d7cdf234153f6ab3922300f18a5ca7ba8f45` |
| Added | `/usr/local/lib/security-center/device-trust-helper.py` | `cf66e8b04b5616822cfbc60534b78654a5b388d316978b4222c974031e94db59` |
| Added | `/usr/local/lib/security-center/device_gate.py` | `2a06e14f872cc9bd456f1b84a188ee07d4a3b6b084b04d114320cab40579a9d1` |
| Added | `/usr/local/lib/security-center/device_inventory.py` | `9137d4acb593d3f0b2c8a2ead30ce58ffaaaf9948252f098b566c04f35375275` |
| Added | `/usr/local/lib/security-center/handover.py` | `65f719561ab9349b10852b8120dc03eed970c77e0ddaed42fb7f4d6943387732` |
| Replaced | `/usr/local/lib/security-center/history.py` | `5f2441e587b6cccc6f7c45d50750877a5551bb20809c85351abc710f40ef9dac` |
| Replaced | `/usr/local/lib/security-center/integrity.py` | `b59993748aa938a704105b7fdd52bcec4485fa2ad76f40d890bcf6817a8ebeb5` |
| Added | `/usr/local/lib/security-center/telemetry.py` | `d22589c48fc271fb7da2dc9375b1fca3a923baa1dcb96add290a3d82c99d3d79` |
| Added | `/usr/local/lib/security-center/telemetry_health.py` | `f6872690c69759a9cffd94a08f348b30b4cca2de03982669354f0912a421dae1` |
| Added | `/usr/local/lib/security-center/telemetry_query.py` | `6ad42475884d5500c5f9d26df677b57a2f3912f23108122c89a49a366fbf02e8` |
| Added | `/usr/local/lib/security-center/telemetry_worker.py` | `94dfa9e183c7a7c4c1291ee0d344a332a8539748a6ef8afaf317636b8b1d3f9b` |
| Added | `/usr/local/lib/security-center/trust_policy.py` | `6cdb63e8a6fd6450c6526cbbad928a1f075d1278e6be42a34d87f1de801019ee` |
| Added | `/usr/local/lib/security-center/trust_store.py` | `1ffc31f5302fb0677f6bca13d6170c0d39a29f31a6126c1e93c9a039009b8727` |
| Replaced | `/usr/local/share/cockpit/security_center/app.js` | `6a9223f06970c77b435df20d276aeac0ab522320093a2dc631b86f04da28c4b0` |
| Replaced | `/usr/local/share/cockpit/security_center/index.html` | `10eebba0f723d8c2238158f136f8c23ff13c965d056360a065f2e45d5b229e44` |
| Unchanged | `/usr/local/share/cockpit/security_center/manifest.json` | `e446615e23aa74954245fddc71c0e86ebaad2ae33c9e02e5b09ce4c315ea6481` |
| Replaced | `/usr/local/share/cockpit/security_center/style.css` | `274dbc6a2c50b5618ea314b69de8544505f80a8f9aa60657288f264817268411` |

## Retained observations

| Existing setting | SHA256 |
| --- | --- |
| `/etc/miku-boot/zen-uki.conf` | `3c59d221ee451bb887de8fa175276f15c588594e3e62c7593586f508af3caf71` |
| `/etc/miku-boot/zen.cmdline` | `e5fb9b71aeca275dd894ba339c870d0af7dad77aa68995248107611e00227d75` |
| `/etc/miku-boot/zen.conf` | `ce7d9cf596f6f14cbccf2d9f9653e60dde86bace9339da3608517d8f94bb850e` |
| `/etc/mkinitcpio.d/linux-zen.preset` | `f1f9fe41e950f93e91dacd851fa548b96f8bdf62f11a1c256c5665a928a53b30` |
| `/etc/systemd/system/cockpit.socket.d/security-center-local.conf` | `53e50de76a07ad7626942d972d807da21b76bca968643ae02cdad78551c68a70` |

## Validation and recovery

- 260 Python tests passed; both UI suites passed. Native unit syntax checks passed.
- Actual protected update, rollback to the original monitor, and corrected reapply succeeded. Protected backups remain available.
- Root collector peer and 18-module health passed. Installed helper listed the approved connected Logitech receiver and refused an unsupported operation.
- Telemetry recorded two initial samples with no failures/restarts, a non-root dynamic UID and zero capability bound; its private database integrity check and history query passed. Recording is enabled every 30 seconds, with a 40 MiB service memory limit.
- Measured background memory was approximately 59 MB including monitor, recorder and idle Cockpit socket. Cockpit was not logged in during this measurement; full authenticated UI memory and interactions remain pending.
- The first recorder start found a managed-directory symlink incompatibility. It was stopped; the narrow fix went through a complete file rollback and protected corrected reapply.
- The original approved baseline remains installed. Approval archives it and adopts only this exact candidate after rechecking all 30 files. Later changes require a new review.
- File rollback after approving a new reference requires explicit recovery planning so the reference continues to describe the installed files. Device candidates and recorded diagnostics are preserved by file rollback.

Approve only the candidate SHA256 shown above; the earlier `6e57...` candidate is superseded.

## Approval completed — 2026-10-18

Owner explicitly authorized this exact pending candidate. Captured approval script
rechecked all 30 files, archived the previous reference and published approval.
New reference SHA256: `b160da7edd4bfc853ed1d9d721ef4db2bd1b62bd8742a40d44b08988c024907c`.
Independent privileged scan: zero changes and zero unreadable files; previous
archive digest verified. Evidence: `work/installer/baseline-approved-verification.json`.
The candidate digest remains 3464d566…; the new reference digest differs because
approval metadata was added. This is file-change monitoring, not whole-host attestation.

Refreshed live collector also confirmed the approved reference and zero changes;
its socket peer PID matched the active service. Evidence:
`work/installer/baseline-approved-live-monitor.json`. Telemetry remained fresh
with zero consecutive reported failures. The earlier verification report includes
a cached pre-refresh collector response; use the later report for adoption.
