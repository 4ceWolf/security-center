# Installed controls baseline review — 2026-10-19

The tested dashboard/telemetry update is installed and its protected transaction
passed live verification. Exact new candidate SHA256:
523f21c367cd83a30fa099249768f085b51997a51ea8472b20772921c4bdb1c5

Previous approved reference:
b160da7edd4bfc853ed1d9d721ef4db2bd1b62bd8742a40d44b08988c024907c

Release manifest: f635d6df7cf81cd5b0fd03588a8594d861da2bcbd0f7625f89e77c93f4b07a00
Protected rollback transaction: txn-39dca112763236821d3352cbde3a490f.

Scope grows30→36monitored paths: telemetry helper/export/action logic/UI and passive
boot-observation reader/parser. Existing collector, adapters, FIM, recorder and UI
updates were already described in monitor-controls-release-review.md. No initrd,
TPM, LUKS, signing keys, authentication policy or boot default changed.

All36installed paths exactly match the generated candidate. Both services are
active, zero automatic restarts;19modules available. Both saved receiver identities
are preserved. Live24-hour export passed and excluded process data by default;
unsupported helper operations were rejected. No history was erased. Measured
collector+recorder+idleCockpit socket57,413,632B (~54.8MiB); signed-in browser and
Cockpit session memory still need separate observation.

Approval records these installed files as the new change-detection reference and
archives the old reference. It does not change boot policy or authorize telemetry
erasure. Until approval, the expanded FIM reports that its baseline needs review.
Source checks/receipts: work/installer/finish-inspect.json,finish-prepare.json,
finish-apply.json,finish-verification.json. Rollback uses the protected transaction.

## Completed approval

Owner approved the exact523f21c3… candidate in chat. Publication succeeded; new
reference is c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437.
Later same-boot and post-restart snapshots report0changed/0unreadable files.
No approval is pending. After this baseline change the ordinary transaction
rollback CLI intentionally refuses because its prior-baseline guard differs. Any
rollback now needs a separately reviewed baseline/file recovery sequence using
protected backups; do not blindly rerun rollback or substitute project copies.
No rollback is currently required.
