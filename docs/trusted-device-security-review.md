# Trusted-device administrator boundary review — 2026-10-18

Scope: staged policy editor, SQLite state, fixed helper, Cockpit request boundary,
and deployment prerequisites. This is a source/fixture review, not authorization
to install, trust a boot image, or enable enforcement.

## Corrected findings

1. Lost database or missing current-policy row could fall back to the packaged
   seed and silently restore a receiver whose trust had been removed. Production
   Store() now requires existing state, lock and nonempty database. Only the
   reviewed installer may call Store(initialize=True) against a new directory.
   First seed is persisted with an initialization record. Missing schema, current
   policy or initialization record fails closed; the retained lock is initialization
   intent, so an interrupted first creation requires explicit repair. Fixtures
   have an explicit separate bootstrap allowance. Neither list nor apply can
   recreate a deleted production directory. This is loss detection, not TPM-backed
   rollback protection against a root administrator restoring the whole state.

2. A device scan exception after a committed save could return a generic failure
   even though policy changed. The helper now returns the committed policy/revision
   with observation unavailable. A transport interruption or storage failure around
   commit can still require a reload to determine the result; never blindly retry.

3. Seed and lock/database opens now use nonblocking flags before regular-file
   validation, avoiding a wait on a substituted FIFO. Protected root directories
   and fixed deployment paths remain prerequisites.

## Boundary assessment

Browser input is a fixed operation plus device selection/review; additions are
matched to a fresh helper observation, exact full identity, and current candidate
revision. Internal entries remain outside these editing operations. Duplicate,
partial, changed and stale input is refused. Candidate changes do not themselves
allow TPM attempts; Distress still rejects external exceptions.

Cockpit superuser require establishes a full administrator session, not a new
per-operation least-privilege polkit policy. The helper has a narrow protocol but
this does not limit what an already-authorized Cockpit administrator can do via
other Cockpit features. Execution actor is recorded as root, not a verified human.
Do not claim human attribution, cryptographic USB identity, all-transport coverage,
preboot activation or anti-rollback from this implementation.

## Concrete handoff to Sol

1. Finish the existing protected deployment entrypoint. Extend the fixed release,
   target and FIM declarations coherently to include the six trust bundle files.
   No direct copying around the rollback mechanism. Verify root-owned, non-writable
   ancestors for Python helper/library and seed paths before privileged invocation.
   Python runs isolated; no project-directory imports in a privileged deployment.
2. Initialize private state only as an explicit fresh-install transaction step,
   using the captured/reviewed seed and Store(initialize=True). Record initialization
   in the deployment journal. On interrupted initialization, preserve evidence and
   require explicit recovery; do not remove the lock/database and seed again.
   Existing state is preserved on upgrade or rollback; never overwrite trust edits
   with the packaged seed. Missing/corrupt state fails unavailable. Never hash the
   mutable SQLite database as an immutable file-baseline entry.
3. Keep the helper and matching UI together in release/dependency verification;
   authenticate and exercise list/review/add/remove with a disposable candidate,
   including denied access, concurrent changes, scan failure and restart. Confirm
   no boot-image/USBGuard mutations. Obtain the project's exact replacement FIM
   baseline approval only after a concrete complete review is prepared.
4. Complete telemetry deployment and ordinary UI/runtime verification within the
   existing project authorization. Measure the actual authenticated stack's memory.
   Do not add another persistent management daemon.
5. Return to Astra before connecting these candidates to signed boot policy,
   TPM/LUKS changes, real preboot gating, or Distress authentication/recovery.
   Existing explicit boot/recovery checkpoints still apply.

## Evidence and limits

242 full Python tests passed after fixes (six new regression cases). Tests cover
lost database, empty/interrupted initialization, missing policy after removal,
missing policy before any edit, persisted first seed, no bootstrap through normal
management, and successful save despite a failed follow-up scan. Existing child
process crash, lock, symlink/hardlink, metadata and policy tests also pass.
No live privileged installation, real Cockpit authorization or hardware power-loss
test was performed. UI source was unchanged in this review.

Reviewed-source bundle: work/releases/device-trust-q_sjj4d9 (6 files).
This supersedes the earlier trust bundles; it remains uninstalled/unapproved.
