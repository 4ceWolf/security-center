# Latest owner update — 2026-10-20

TPM automatic-unlock **repair is deferred to future ideas**, not an active unfinished
requirement. See ideas.md and the preserved recovery design. A separate disable
button is installed and tested; protected transaction status is recorded in HANDOFF.
Building/installing it never invokes the actual token removal. No TPM, LUKS keyslot,
boot image, PCR, signing key or current unlock setting was changed by development.
The new helper verifies manual slot0 via a native disk-passphrase prompt only when
the owner explicitly confirms disabling. See tpm-unlock-disable.md.

The trust-editor copy fix is installed: saved candidates are distinguished from
live USBGuard enforcement. Owner approved exact candidatefbffa043…; published
reference58eab555… covers38files, final0changes/0unreadable. Previous1570242a…
reference archived. No approval remains pending for this disable-control release.

# Current project status — 2026-10-19

Start here. Historical HANDOFF/changes/testing entries describe their date; later
entries may supersede pending approvals, older package counts or deployment state.
The revised project remains incomplete. Distress Mode was removed by the owner on
2026-10-19; all older Distress tasks are superseded. See sol-preboot-handoff-2026-10-19.md. No new overall percentage is claimed:
built, installed and verified-on-hardware are different completion gates.

## Latest owner approvals applied

See postboot-promotion-2026-10-19.md. Candidate2039b424… approved and published as
1570242a…; FIM0changes/0unreadable. Logitech reconnect/input passed; USBGuard now
active+enabled with exact tested policy. No pending approval for that baseline/test.
OpenSnitch host app-deny trial failed and rolled back, remains off. AppArmor offline
profile checks pass, LSM still disabled. ActualTPM repair remains unfinished.
The older progress entries below are historical where they disagree.

## Latest installed progress — owner available

See postboot-installed-progress-2026-10-19.md. Scope/recovery dashboard update is
installed,17modules healthy. Exact new baseline2039b424… approval question pending.
Native USBGuard/AppArmor/OpenSnitch packages installed. USBGuard runtime protection
active, not enabled for future boots; receiver reconnect question pending. Existing
7device authorization states preserved, new unknown insertions blocked. OpenSnitch
native isolated firewall coexistence passed; host service inactive. AppArmor LSM
disabled. Actual automatic-unlock repair remains unfinished; noTPM/boot changes.

## Current scope — preboot removed by owner

Custom preboot gating and initrd observation/handover rollout are removed, not
pending. Keep their earlier reports/source as historical reference. No more custom
preboot builds or firmware tests are required. Existing integrity/Secure Boot/TPM
unlock/manual recovery remain. Distress remains removed.

Remaining: postboot device/application/network protection; authenticated Cockpit
and memory verification; recovery and final installed checks. Newly requested:
automatic-unlock recovery with diagnosis and an explicitly reviewed administrator
repair, preserving manual slot0 and PCR7 + signedPCR11/initrd. See
automatic-unlock-recovery-design.md. Historical preboot checkpoints below are
superseded; none authorizes changing the existing boot/security policy.

## Latest unattended staging — owner away

Scope update and automatic-unlock review staged in monitor-o8ib655z;31files,
4changed from installed host observation. New installer runtime r5p6009t expects
17retained modules. Tests pass; protected install/baseline not run or requested.
Recovery preflight and design complete; actual repair backend remains unfinished.
See automatic-unlock-recovery-design.md and postboot-remaining-work.md. No new
administrator prompt, production setting change or boot change while owner away.

## Latest Sol follow-through — 2026-10-19

See sol-recipe-and-observer-2026-10-19.md. Authenticated read-only20-file recipe
capture complete (not full dependency closure). Firmware normal observer functionality
passes with a TEST-only30second TCG timeout; original5second timing remains open.
Record retention, actual automatic encrypted root, PCR enter/leave and post-phase
policy rejection passed. All production settings unchanged. Saved older passes reused.

## Latest Astra review — 2026-10-19

See astra-preboot-decisions-2026-10-19.md. Exact-image directory transition review
now succeeds:2424records/2405paths,9explicit transitions, approved=false. Twelve
affected tests pass; full suite/VM passes reused. This supersedes the archive refusal
below only for the exact captured image with its reviewed ledger. Production
control/candidate build, hardware coverage and unlock integration remain unfinished.
No installed settings changed. Next Sol work and retained owner checkpoints are in
that contract; Distress remains out of scope.

## Latest Sol checkpoint — 2026-10-19

See firmware-enforcement-results-2026-10-19.md for current evidence and limits.
- Enrolled-key guest Secure Boot: signed accept, unsigned/tampered reject, PASS.
- Two firmware boots with persistent guest TPM/LUKS: observer-masked profile PASS,
  actual stock automatic root unlock/switch-root and post-phase policy rejection.
- Normal observer still fails the5s cap underTCG; KVM firmware startups hang.
  Full firmware failure/manual matrix is unfinished. Existing observer cap unchanged.
- Working laptop UKI captured read-only, EFI and initrd PCR signature verified.
  Stored-image parser ceiling now256MiB; decoded/member/count caps unchanged.
 355early+2069mainmembers inventoried; conservative effective-path review refuses
 existing directory-mode transitions. Raw-path transitions are inventoried separately.
- Live preboot enforcement remains undeployed. Production capture/control/delta,
  alias-transition review, internal/hotplug/DMA profile and old-image/header bypass
  remain the specialist checkpoints. Do not infer production approval from guest passes.
-354Python tests passed after offline parser/tool changes; later fixture scripts
  compiled and the final masked two-boot run passed. No new installed code drift.

## Installed update — 2026-10-19 (supersedes staged status below)

Release monitor-iwww5mjl is now installed:31files/36monitored paths. Both services
passed live checks,19modules, two saved receiver identities preserved, hourly
export/default privacy and unsupported-operation rejection verified. No records
erased. Owner approved candidate523f21c367cd83a30fa099249768f085b51997a51ea8472b20772921c4bdb1c5;
published reference c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437.
FIM now reports0changes/0unreadable. Rollback transaction:
txn-39dca112763236821d3352cbde3a490f. Background memory ~54.8MiB; signed-in Cockpit
still needs separate verification. Previous approval requests for this candidate
are satisfied; do not ask again. See installed-controls-baseline-review.md.

Telemetry warning diagnosed from36recentrawsamples: partition diskseq missing,
so partition rates omitted; one first-sample/gap flag after recorder restart.
This does not invalidate independently recorded temperatures/CPU/RAM/battery.

Firmware phase probe now passes withTCG; Secure Boot-capable OVMF needs768MiB guest
memory for this fixture. It boots in SetupMode with SecureBoot=0 and native PCR11
matches. Actual enrolled-key Secure Boot and two-boot LUKS acceptance remain pending.
No laptop boot configuration or key was changed. Current protected configuration
captured read-only in work/installer/current-boot-audit.json.

## Installed and previously verified

- Kernel lockdown integrity is the normal boot configuration after the owner
  reported automatic unlock, desktop, sound and sleep/wake/Wi-Fi working.
- Original Secure Boot/TPM PCR7 + signedPCR11/initrd enrollment and manual LUKS slot0
  are preserved. This is not a claim that the future device gate is deployed.
- Read-only Cockpit Security Center/collector, event history, bounded configuration/
  process/service checks and fixed-path FIM are installed.
- Local telemetry recorder is installed, enabled and saving raw/hourly data every
  30seconds with DynamicUser/no capabilities and40MiB hard memory limit.
- Trusted-device candidate manager and both approved receiver identities were saved
  earlier. Candidates do not activate preboot or USBGuard enforcement.
- Owner-approved candidate3464d566... was published as reference b160da7e... on
  2026-10-18. Earlier HANDOFF requests for approval of that candidate are historical;
  do not ask again. See changes.md specialist follow-up and the protected verification
  artifacts. It covers the installed25file/30path release, not later staged changes.
- Last current read-only service check: collector+recorder+idle Cockpit socket
  51,146,752bytes/about48.8MiB, both services active with0restarts. Cockpit web service
  inactive. Total authenticated memory and the roughly200MB target remain unverified.

## Built/tested, staged only

| Deliverable | Evidence | Remaining gate |
| --- | --- | --- |
| Passive initrd observation and postboot row | Arch mkinitcpio build; disposable auto/manual/failure/timeout/OOM tests | Real firmware/phase tests, exact laptop image review and owner boot trial |
| Source/runtime capture and archive inventories | Bounded package checks; both Arch initrd segments; sealed guest inputs | Complete production recipe/delta/alias checks and signed image approval |
| Disposable offline PCR-signed UKI construction | Extracted-section policy/signature match; corrupted signature rejected | Firmware execution and guest Secure Boot are not tested |
| Telemetry JSON download and clear-history UI/helper |345Python tests and3JS suites; actual Firefox synthetic download/focus/320px/200%zoom | Reviewed installation, explicit new baseline, authenticated owner interaction |
| Recorder/delete serialization | Separate-process append/delete lock and rollback tests | Deployment with the telemetry controls bundle |
| Read-only adapter memory bounds | See adapter-resource-bounds.md | Deployment with a reviewed new release |
| Normal device-policy model | Unit/failure/guest fixtures | Enforced TPM gating, old-image/header bypass and hardware recovery |

Use telemetry-controls-implementation.md for browser/control evidence. Latest combined
review bundle is monitor-iwww5mjl (31files/36FIMpaths); its hash and captured installer
runtime are recorded in adapter-resource-bounds.md. This latest bundle is not installed.
All staged bundles are unapproved; none authorizes root execution or installation.

## Sol can continue

- Routine implementation under the existing contracts, isolated fixtures, monitoring
  resource limits and UI correctness. Use current source and rebuild captures when
  bytes change. Do not rerun completed checks without a changed input or open issue.
- Prepare exact installer/change/rollback artifacts for owner review. Authentication
  and baseline gates remain pending while unattended; no automatic rebaseline.
- Complete authenticated UI/combined RAM checks only when the owner is available;
  no automatic administrator prompt from page load or refresh.

## Astra / owner-dependent work

- Firmware/stub signed-PCR phase correctness and production image delta/signing:
  measured-observation-next-contract.md. Offline UKI construction is only one step.
- Device-policy internal classification, hotplug/DMA coverage, actual TPM gating,
  old signed UKI/header bypass and an acceptable recovery/migration boundary.
- Reviewed native enforcement integrations (USBGuard/AppArmor/OpenSnitch), input/
  network compatibility and recovery trials; missing packages are not enforcement.
- Optional on-demand malware scanner still needs resource and scope selection;
  no always-on scanner or automatic quarantine is deployed.
- Owner hardware interactions: separate boot trial/manual recovery, input/peripheral
  classification, authenticated UI and promotion only after verified normal use.

Current safeties: no TPM reset, slot edits, signing-key changes, PAM replacement,
reboots, enforcement enablement or production telemetry deletion in the latest Sol
work. No live files require rollback. Documentation/tests and captured review bundles
stay under this project. See project-brief.txt for full unchanged scope.

## Specialist continuation update — 2026-10-19

See astra-progress-2026-10-19.md: 354Python tests pass; conservative effective-archive
review added and a real synthetic metadata conflict refused. UEFI native phase
measurements match in one guest; complete firmware/Secure Boot/signed unseal tests
remain unfinished, including intermittent startup hangs. This is not production
boot approval. Swap review found no monitored baseline changes. Requested telemetry
summary and access/coverage limits: telemetry-review-2026-10-19.md.
