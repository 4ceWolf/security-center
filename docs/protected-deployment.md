# Protected monitor, telemetry and candidate-device deployment

Implemented 2026-10-18 following Astra's administrator-boundary review.
No boot image, TPM, LUKS, USBGuard or Distress activation is part of this update.

## Captured authority

The combined release now has 25 immutable files and 30 FIM paths (25 deployable
files plus five existing read-only boot/Cockpit settings). Six candidate-management
files are included coherently with the matching UI. The live SQLite candidate
state is mutable and is deliberately not an immutable-baseline file.

The installer runtime contains 14 fixed, compiled Python source files as exact
captured JSON bytes. tools/installer-bootstrap.py is embedded directly into an
isolated Python authentication command, not launched as an editable project file.
It validates the independently pinned runtime digest and exact member set before
extracting into a fresh root-private directory under /run. No archive-supplied
paths or project modules are imported with administrator privileges.

The root-only deploy-monitor.py CLI verifies runtime ancestor ownership/modes
before imports, uses fixed target/scope/service adapters, and takes the existing
protected update lock plus the baseline-approval lock. Its prepare operation
captures all reviewed payloads, previous baseline and original metadata into the
protected transaction. apply/resume uses those captured bytes, not the source
folder; changed release inputs, unrelated changes, and changed baselines refuse.

The command names are inspect, prepare, apply and rollback. There is no baseline
approval operation and no arbitrary shell command or web deployment endpoint.
The retired install-mvp.py refuses to bypass this workflow.

## Failure and recovery behavior

The service coordinator stops prior running monitor/recorder services, applies
journalled files, prepares/verifies candidate state, reloads systemd, restores
prior running states and verifies the root collector peer and fresh health.
Inactive telemetry remains inactive during this update. Standalone activation
follows production account/sandbox validation.

Fresh candidate state initialization is journalled before execution. A restart
at the initializing phase requires explicit recovery; it never deletes or
reseeds a partial database. Existing valid state is verified and preserved. File
rollback preserves the database/evidence. Initialization failure rolls installed
files and prior service state back without claiming successful deployment.
The helper holds a shared update lock across its imports and operations, so it
cannot execute through an in-progress update. Root-only helper imports use a fresh
private bytecode-cache prefix. No persistent management daemon is introduced.

Only /etc/security-center may be created as a missing target parent, with mode
0755 under validated root ancestors. Rollback removes the added seed file and
retains the empty root-owned directory. Other missing parent directories refuse.
Backups and incomplete transactions are preserved. Automatic archive/orphan-temp
cleanup is not implemented; do not remove incomplete state merely to retry.

A successful update generates an unapproved exact replacement baseline in the
protected transaction and publishes identical bytes to the root-private baseline
review directory. Existing approved reference remains in force until explicit
owner approval. Scope expansion approval now checks the exact prior baseline
and preserves its scope without requiring it to already contain the new paths.
Rollback after a baseline reference changes is refused pending explicit recovery.

## Verification boundary

Unit orchestration tests simulate root metadata, service calls and initialization;
separate tests use real protected fixture files and actual interrupted processes.
Those tests are not evidence of live privileged operation. Root live evidence is
recorded separately under work/installer and in docs/HANDOFF.md.

Known remaining work: authenticated Cockpit interaction, full-stack memory checks,
long-run telemetry validation, transaction archive/temp cleanup, recovery UI,
telemetry export/deletion, and the larger native/preboot/Distress integrations.
