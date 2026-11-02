# Monitor release build

The staged AppArmor collector adds confinement.py. Deploying only collector.py would break imports; deploying the new module without expanding FIM would leave executable collector code outside monitored scope.

`tools/build-monitor-release.py` creates a project-local13-file snapshot under work/releases. It checks the complete fixed file set, Python syntax and static imports against bundled local modules/standard library, and verifies that all installed destinations occur in the staged integrity.PATHS tuple. The tuple now contains18paths, adding confinement.py; live installed scope remains17paths. It copies sources into the snapshot and records their SHA256, fixed destination and an optional read-only installed-file hash observation. The observation is not an approved baseline and cannot authorize an upgrade.

`--verify DIRECTORY` rechecks the fixed mapping, every content hash, source containment/no final symlinks, imports and FIM scope. It rejects missing/unbundled dependencies and changes to installation destinations. This is a build consistency verifier, not a signature or tamper-proof release authority: the owner/root can modify both the code and manifest. It does not cover dynamic imports or arbitrary runtime behavior.

Built snapshot: work/releases/monitor-ubz3zvzm.13files. No system files installed; no baseline modified.89 Python tests pass, including seven release tests for dependency/FIM omissions, changed contents, destination changes and symlinks. Tests are in tests/test_monitor_release.py.

## Deployment prerequisites

A new updater must consume the exact reviewed snapshot, verify the current installed files against the previous approved reference and installer record, save a root-private rollback set, install all dependent modules together, and verify service health. Historical update scripts that copy only collector.py must not be used with this source snapshot.

FIM scope migration is a separate operation: preserve/validate the exact old17-file reference; explicitly enumerate the new path and all updated files; generate an18-file candidate and show the change set; approve that exact candidate only through the established approval checkpoint. Current baseline tooling intentionally expects an exact scope and is not yet a cross-scope migration tool. Do not install the changed integrity.py and then silently discard or regenerate the old reference.

This release does not enable AppArmor, modify LSM boot parameters, install OpenSnitch/USBGuard or expose new privileged actions. Those retain separate compatibility and recovery gates.

## Cross-scope validation built, not deployed
`tools/baseline_migration.py` is a pure validation/planning module. Given exact prior baseline bytes/digest, exact reviewed release manifest bytes/digest, and trusted before/after scans over the new scope, it checks:

- the prior reference was approved and every old file matched it before installation;
- no scope removal, duplicate path, unrepresented addition or preexisting new file is accepted;
- every post-install file is readable; release files have reviewed hashes/root ownership/0644 permissions; non-release files are byte/metadata-identical to the prior reference;
- the resulting candidate stays unapproved and records the previous-reference digest, release digest, added paths and exact post-install metadata.

The rollback planner first validates all selected paths against the observed installed state. Any later edit refuses the complete plan. It distinguishes restore-from-backup for existing files from removal of files newly introduced by this update. It performs no writes and cannot authenticate a caller or prove backup integrity.

Nine new tests cover candidate copying/unapproved state, existing drift, unrelated changes, preexisting additions, incorrect hash/permissions, incomplete scans, document tampering and rollback conflict.98 project tests pass. Inputs in these tests are temporary in-memory fixtures, not the owner's live approved reference.

Still required: a privileged transaction executor with protected backup bytes, per-step durable transaction record, service stop/start/health handling and crash-recovery tests; the actual exact17->18 candidate; independent approval before replacing the reference. The validator's caller must use the release verifier, trusted no-follow scans, serialized installation and independently authorized digests. A matching self-supplied digest is not authorization. No production migration/rollback command is exposed yet.

## Disposable-filesystem executor
`tools/fixture_transaction.py` now exercises the transaction mechanics against explicitly marked `security-center-fixture-*` directories. It refuses `/` and unmarked directories, absolute/traversal target paths, symlinks, oversized payloads and mismatched fixture ownership. It saves and hashes old/new bytes before the prepared record; files and record are individually published atomically with fsync. Planned metadata is recorded before mutation, allowing a restarted executor to recognize exact before/after state even if the process exited between replacement and journal advancement.

The executor preflights every target and backup before applying or rolling back. Later-change conflicts refuse the plan. Rollback restores bytes/mode/mtime and removes only transaction-added files. An interrupted rollback can continue but cannot be reinterpreted as a new apply. An incomplete prepare has no usable transaction record and must not initiate mutation.

Eight fixture tests cover apply/restore, actual child-process exit after each updated file, exit during rollback, later-edit conflicts, corrupt backup, symlink targets, refusal to reapply rollback and host-root refusal.106 project tests pass. No live files/services or baseline were changed.

This is NOT the privileged production installer. The fixture assumes trusted ancestors and a serialized non-hostile test directory; path checks are not race-proof openat-based security against concurrent malicious writers. The manifest/backups lack an external trust anchor. Service stop/start/health handling, root-protected lock/transaction store, robust pending-transaction boot handling, authenticated release selection, actual baseline migration/approval and physical power-loss tests remain outstanding. Production must not bypass those gaps by renaming a real system directory to match the fixture marker.

## Packaged daemon runtime rehearsal
The staged daemon now accepts Python-call parameters for socket/database/ownership so the actual packaged service can be exercised unprivileged. Its normal CLI still has fixed production defaults, root:wheel ownership and no user-controlled command or environment configuration API. Installed daemon unchanged.

`tools/check-monitor-release-runtime.py` builds/verifies a fresh release and launches its actual daemon in isolated Python mode, using a private temporary socket/database. It queries the real API, requires16modules, checks unsupported-request rejection and absence of private journal cursor, force-kills the process, restarts it against the same database and verifies all prior events remain. It also checks orderly socket cleanup and runs with a database path that is a directory, requiring history unavailable while all16module results remain available. Test processes are reaped; no live service stopped/restarted.

Evidence: work/releases/monitor-rhsxy4iv/runtime-report.json passed,122events before crash and226after restart. A second complete rehearsal under a transient user service with MemoryHigh48M/MemoryMax80M also passed: work/releases/monitor-a42nuir2/runtime-report.json. Reported cgroup peak48.4MiB, swap23.1MiB, runtime3.752s. These figures include the rehearsal parent and children; they are not a whole-stack or authenticated Cockpit measurement.106Python regression tests pass.

This establishes coherent packaged startup and real socket/history failure behavior under the test user's permissions. Root-only module evidence, root:wheel access enforcement, systemd production hardening, actual live baseline migration and authenticated browser UI remain separate validation gates. No live baseline approval is implied.

## Shared handover parser packaging update
Latest staged release monitor-4ep_gn1n contains14files; declared FIM scope is now19paths (confinement.py and handover.py added to the live17). Handover source remains canonical at initramfs/handover.py and maps to the installed library's handover.py. Runtime rehearsal now assembles all declared library destinations into a private temporary library; it does not assume source-folder layout equals installation layout.139tests and the17-module runtime rehearsal pass. Earlier13-file/18-path references describe older snapshots; migration must use the exact latest reviewed manifest, never silently add either path to the approved baseline.

## Telemetry expansion (latest staged scope)

Release now includes telemetry.py, telemetry_worker.py, telemetry_health.py and
security-center-telemetry.service:18release files,23FIM paths. Installed baseline
still17paths, untouched. Exact reviewed migration must cover current scope;
previous19path plans are historical. Fresh installer copies telemetry files/unit
but only enables the existing MVP services. Current upgrade execution and
telemetry activation remain separate pending work. Do not use partial updaters.

Latest history-query expansion supersedes the previous scope:19release files,
24FIM paths, installed baseline still17. telemetry_query.py is now bundled and
fresh-install mapped. Runtime report monitor-3ke_4sjk passed18modules and
history crash/restart124->233, invalidrequest, DBfailure and socketcleanup.

## Installed-state upgrade review

`tools/prepare-monitor-upgrade.py` builds/verifies the current release and scans
its exact integrity scope without changing the host. It creates a user-owned
JSON plan and Markdown review with installed metadata, proposed hashes, action
classification, baseline access/drift status, rollback and deployment checkpoints.
These are review artifacts only: deployable/approval flags remain false even
when observations match. The protected installer must repeat checks under lock.

Current observed review: work/upgrades/upgrade-15imz02u/review.md.
Release monitor-qxrs91pf:7additions,8replacements,4unchanged,0unreadable release
files;24total FIM paths. The root-private approved baseline was not readable,
so its digest/continuity and exact scope additions are intentionally unverified.
Prior historical17path scope is not substituted for a current baseline read.
No service, baseline or installed file was modified.186Python tests pass.

## Protected installed-file operations

`tools/protected_files.py` adds a production-root constructor and an explicitly
marked disposable-fixture constructor. Its fixed19path allowlist exactly matches
the monitor release; it cannot write boot settings or the approved baseline.
It traverses directories using held directory descriptors, nofollow flags and
owner/non-writable-directory checks. Installed files must be private from other
writers, regular, singly linked and bounded; scans check identity before/after.

Replacement writes an exclusive random temporary file in the target directory,
sets owner/mode, optionally restores mtime, fsyncs content, rechecks expected old
state, publishes by directory-relative rename and fsyncs the directory. Removal
also requires exact expected installed state. This is a file-operation layer,
not a complete privileged installer: the caller must hold a protected transaction
lock, durably save backups/intent, and prove removal targets were newly added.
Concurrent root administrators are outside this layer's unprivileged-race model.

196Python tests pass, including10new protection tests. Actual child exits before
and after publication leave complete old/new files in disposable fixtures.
Those are process-exit tests, not power-failure storage tests. Death before
publication can leave a private temporary file; the transaction journal/recovery
layer must track/clean such files rather than delete arbitrary matching paths.
Root host-path mutation has not been exercised. No installed files changed.

## Protected durable backup journal

`tools/protected_transaction.py` now coordinates ProtectedFiles with a private
`/var/lib/security-center-updates` state directory beneath the selected trusted
root. Directory traversal is nofollow/descriptor-based; root ownership and0700
state directories /0600 singly linked regular files are required. One exclusive
nonblocking lock covers preparation, apply and rollback. Test construction uses
the same code below a marked disposable root, never the host state directory.

Preparation validates every requested target and expected before-state before
creating an immutable transaction directory. Old/new payloads are fsynced before
publishing prepared intent. The journal stores before/after content hashes and
metadata, the reviewed release digest, and state. All payloads/backups and current
installed states are preflighted before a resumed mutation. Applied files use a
planned mtime, allowing recognition after death between rename and journal update.
Rollback restores original bytes/mode/mtime or removes newly added files only;
later edits cause refusal before any other target changes. A rolled-back
transaction cannot be applied again. Files with nonrestorable ownership/mode
are refused before preparation rather than failing halfway through restoration.

204project Python tests passed.18protected-layer tests passed again after the
final ownership/mode restriction. Child processes were terminated after durable
intent, payload fsync, publication and final-file verification; resume and exact
rollback passed, including death during rollback. Backup tampering, duplicate
writers, unsafe state paths and unrelated later edits are also covered.

This is still a library, not an authorized deployment command. Caller must
validate the actual reviewed release/baseline and coordinate service stop,
restart, health and separately approved baseline migration. Prepared journals
are not authorization. Interrupted preparation may leave an unused journal
folder, and prepublication crashes may leave private temporary files; deliberate
journal-linked cleanup/archive remains pending. No automatic broad cleanup is
performed. No installed files or host state directories were modified in tests.

## Service coordination and collector health

Added monitor_services.py with fixed commands for security-center.service and
security-center-telemetry.service. Mutation methods require root; there is no
web/command API and no enable/disable operation. State captures running versus
not-running (including failed/not-installed); transitional states are refused.
A successful restart must return a fresh same-boot, read-only schema1 snapshot,
required unique module identities and available persistent history. Unix peer
credentials must match root and the service's current MainPID. Security warnings
are not treated as collector failure or falsely promoted to secure.

service_transaction.py saves prior running states and observed module identities
before stopping services. Durable phases cover stopping, file apply, restart,
health, rollback file restore and service restore. Recovery from rollback phases
continues rollback. Failures attempt file rollback and prior running-state
restoration; rollback health checks require the original module set. If rollback
itself cannot proceed, its journal remains pending and the error propagates.
A healthy/rolled_back terminal receipt is idempotent, not a new liveness check.
Previously inactive telemetry remains inactive; activation is a separate action.

211Python tests pass. Service actions use a simulated controller in disposable
file-transaction fixtures, including start failure and interrupted apply/rollback.
No claim of a real systemd upgrade or restart. A live READ-ONLY adapter check
passed: existing root collector peer/MainPID, fresh16module response and available
history; telemetry was not running. No services were stopped or restarted.

Deployment still needs exact reviewed release/baseline binding, protected
transaction cleanup/archive and a controlled privileged run. Telemetry-specific
post-start health must also be checked if a future transaction includes an
already-running recorder; current coordinator validates collector health only.

## Exact release and baseline binding

`tools/release_binding.py` validates captured bytes against externally reviewed
manifest and prior-baseline digests, rejects duplicate document keys, and checks
the exact source/destination list, static dependency closure and24path scope.
The five non-release boot/Cockpit settings must already belong to the approved
baseline and match exactly; they remain read-only and retain their approved
permissions. Every new release path must be missing before installation.
Unexplained metadata/content drift blocks preparation. Identical existing files
are excluded from the write set, preserving their metadata as the review states.

capture_bundle reads fixed members without symlink traversal and validates the
same in-memory bytes it returns. A later change to the project bundle cannot
substitute bytes between verification and transaction preparation. These checks
establish continuity only: reviewed digests still must originate from the
required human/root approval process, and current scans must be obtained under
the protected transaction lock. No baseline approval is generated by binding.

221Python tests pass, including10binding tests. Real19file bundle capture was
verified without installation. Current approved baseline remains unreadable to
the unprivileged process, so no live full binding was claimed. Unit tests cover
payload/destination substitution, duplicate entries, missing/drifted scope,
pre-existing additions, changed digests, unchanged private boot permissions and
preservation of identical targets. A captured source remains stable after its
on-disk source is modified; recapturing that modified source is refused.
