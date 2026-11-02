# Focused Astra handoff: preboot/device-gate architecture

Prepared 2026-10-18 after the Sol deployment and export work. The owner explicitly
asked Sol to stop at preboot/TPM/Distress integration and reserve Astra for the
specialist decisions. Do not redo ordinary monitor/export implementation.

## Current authoritative evidence

work/preboot-readiness-20261018.json captures fresh current-boot observations
from a root-peer collector and unprivileged sysfs reads:

- Kernel lockdown reports integrity, and the boot command line requests it.
- UEFI SecureBoot variable reports enabled; this is not measured-chain attestation.
- Three USB devices observed, with complete USB observation but explicitly
  incomplete all-transport inventory.
- Connected receiver is the approved Logitech 046d:c542 at
  pci:0000:00:14.0/usb:1, no serial, mouse interface 03:01:02.
- Other USB observations are 8087:0aaa at usb:10 and 13d3:540a at usb:8. They
  are not approved as internal merely because their IDs resemble built-in hardware.
- Twenty PCI entries, zero Thunderbolt entries and no sampling errors. These
  observations do not establish no external DMA/USB4/PCIe path, physical power-only
  state, hotplug exclusion, internal classification or firmware DMA protection.
- policies/normal-devices.candidate.json has two authorized external receiver
  candidates and an EMPTY internal list. The deployed private candidate database
  was last checked by the installed helper with the same two receiver candidates;
  the new readiness report does not itself reread that private database.

Normal integrity boot, existing PCR7 + signed PCR11(initrd) TPM enrollment and
manual LUKS slot 0 must be preserved. No new live preboot gate exists. Protected
file backups are available for the monitor; these are unrelated to boot recovery.

## Already implemented; reuse it

- policies/device_gate.py: bounded pure fail-to-manual evaluator, all three
  transport coverage claims required, exact combined identity, Distress forbids
  trusted external exceptions. Identity is spoofable operational matching.
- policies/device_inventory.py and platform_inventory.py: bounded read-only
  observations, no inferred internal approvals and no complete physical gate.
- initramfs/unlock_dispatch.py: tested adapter dispatch/manual flow.
- initramfs/handover.py: bounded current-boot parser. Root-private userspace
  records are observations and are not attested authority to restore/unlock.
- policies/distress.py and distress_store.py: state/reducer and durable prototype;
  independent witness is abstract, not a provisioned TPM NV anti-rollback design.
- tools/test-luks-vm.py and tests/vm-gate-scenarios.py: disposable real LUKS/swtpm
  and systemd boot-ordering rehearsals. docs/testing.md distinguishes actual VM
  evidence from fixtures, host observations and owner hardware tests. Do not infer
  actual laptop ordering/recovery safety from the VM alone.

## Astra's decisions now

1. Design the narrow next initramfs/device-gate integration and its staged rollout.
   Determine the source/approval of internal topology, complete transport coverage,
   keyboard accessibility, late hotplug handling and a usable manual fallback.
   Empty Thunderbolt enumeration is insufficient. Start with observation rather
   than changing the existing TPM authorization policy silently.
2. Trace every TPM unlock path and signed image that remains authorized. Explain
   the enforcement boundary of merely suppressing one cryptsetup invocation.
   Older signed UKIs/recovery images may still present an accepted signed-PCR11
   policy and bypass a new software gate. Resolve or state this limitation before
   claiming enforced protection; do not erase the manual recovery escape path.
3. Decide how any future Distress witness/anti-rollback design could be bound to
   actual TPM authorization and manual owner recovery without allowing old-image
   bypass or unprivileged restoration. Root authentication alone does not prove
   the LUKS passphrase was used. Do not provision NV, replace tokens, rotate keys
   or change authentication while deciding this.
4. Return a concrete implementation/validation contract to Sol: exact interfaces,
   files, VM failure cases and owner checkpoints. Perform only the specialist
   architecture or hard security fixes; leave routine scaffolding to Sol.

Any boot/PCR/token/keyslot/authentication operation still needs its existing
explicit review/checkpoint. Do not rebuild both kernels, clear TPM or weaken
PCR7/signed-PCR11. Do not collect passwords, TPM blobs, keys or covert media.

## Separate ordinary-work state

Installed corrected release monitor-18cuezjm has 25 immutable files / 30 FIM scope.
Monitor and private device-management helper passed live checks. Telemetry is
recording at 30s and enabled at startup; service is nonroot, no capabilities and
40 MiB memory cap. Background monitor+recorder+idle Cockpit measured about 59 MB;
authenticated Cockpit memory/interaction remain unverified. Staged JSON export
passed saved-trial verification; 269 full Python tests pass.

A baseline approval request is pending, NOT answered by automatic goal messages:
- review: docs/monitor-telemetry-baseline-review.md
- exact candidate: 3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee
- old reference: 19f88b6f672ea2390c30a72b05d53e551aac5b21774025590dd3200e39cfc5f9

Sol can handle that exact approval when the owner answers, authenticated UI checks,
export/download/delete controls and installer archive/temp cleanup. Do not alter
installed immutable files while this candidate is awaiting approval. The full
project is still unfinished; this handoff is not a completion claim.

## Follow-up — 2026-10-18

Owner subsequently approved the exact 3464d566… candidate; publication and direct
30-file verification succeeded. See monitor-telemetry-baseline-review.md.
Specialist next-stage contract is now in preboot-implementation-contract.md.
It includes legacy-header/object replay, concrete guest integration interfaces,
coverage/hotplug limits and owner checkpoints. No host boot or TPM changes made.

## Sol integration progress — 2026-10-18

Generated-service interactive recovery now passes both successful/failed checker
guests: four real terminal cases, hidden input, mapping verification and detach.
See testing.md and tests/vm-preboot-integration.py. Scope is still generated noauto
/dev/vda, with a separate final switch-root mapping. Continue automatic UUID and
cmdline paths plus same-mapping switch-root before declaring the contract's full
combined guest integration complete. Host configuration and approved baseline
remain unchanged. User reported 9% usage remaining; this pass stayed targeted.

### Further guest coverage — 2026-10-18

Automatic UUID crypttab/cmdline source generation and target-driven activation now
pass. Final cmdline-generated mapping is carried into encrypted-root switch-root;
post-root verifies actual root device number and vda backing. Final reports:
luks-vm-djphr8e6 and luks-vm-e0u94rst. Earlier separate-mapping limitation is closed
for the combined scenario. Remaining integration gaps include complete cold-boot
initrd target graph, alternate/duplicate unlock paths, production credential agent,
bounded trusted inventory, hotplug and hardware/legacy-object enforcement. Do not
treat controlled generator environment inputs as tested laptop boot parameters.

### Decision record consumption — 2026-10-18

Staged gate_record.py now checks exact bounded context/freshness and private
root-owned filesystem provenance. Generated guest adapter consumes it plus actual
service result; both checker outcomes pass terminal/UUID/same-mapping integration.
See gate-record-build.md. Full Python suite275passed. Next routine work: bounded
checker supervisor and observation producer, plus alternate unlock-path coverage.
Do not interpret record acceptance as complete inventory, hotplug closure, trusted
owner recovery or TPM attestation. Hardware/legacy-object migration stays pending.

### Supervised observer — 2026-10-18

Guest-only observation producer now samples real USB/platform inventories and
publishes bounded denial-only records under actual systemd oneshot supervision.
Timeout/stale-evidence refusal and full guest recovery pass for both checker
outcomes; Python suite278passed. See gate-observer-build.md. No production
permission or completeness upgrade. Next routine gaps: alternate/duplicate unlock
paths and cold-boot target graph; topology approval/hotplug/legacy-object migration
still need their existing specialist and owner checkpoints.

### Concrete alternate-service bypass evidence — 2026-10-18

Guest regression now demonstrates a second generated service actually TPM-unlocks
the same disk despite denial by the intended gated service. Both checker outcomes
pass along with all prior tests: bpf8c6he/z2wazwcb. See alternate-unlock-test.md.
The exact service-set negative check is fixture-local; production candidate image
all-path auditing is still unimplemented. Do not describe one replaced ExecStart
as comprehensive enforcement. No host bypass was attempted; cryptographic legacy
image/header migration remains outside these routine guest changes.

### Generated snapshot auditor — 2026-10-18

Reusable unlock_candidate_audit.py now validates the collected generated-service
snapshot and ordered drop-ins; duplicate bypass and both normal UUID guest cases
call it. Final Python suite286passed; lpj22qqw/_52di9fk guest runs passed.
See unlock-candidate-audit.md. It is not a full candidate builder, image hash
manifest, effective-runtime inventory or legacy-image defense. Next routine gaps:
complete candidate-image capture and cold-boot/runtime graph checks. Hardware and
cryptographic enforcement checkpoints remain unchanged.

### Captured exact test initrd — 2026-10-18

Test harness now inventories all508newc members from a sealed compressed object,
boots that same descriptor and pins hashes in its report. Four new parser tests;
Python suite290passed; ft74_a4d/wpldnf_g guest runs passed. See
initrd-artifact-manifest.md. Still no production source approval, signed UKI,
kernel/firmware attestation or complete cold-boot/runtime unit-graph proof. Dynamic
guest output units/adapters retain separate snapshot checks. Next routine stage:
complete cold-boot/runtime graph and production candidate source packaging; do not
convert captured manifests into automatic signing or enforcement approval.

### Native core startup graph — 2026-10-18

Fresh-manager --cold-boot modes now exercise actual kernel-cmdline generator startup,
native sysroot/root-fs/parse-etc/cleanup/switch-root and final-root systemd, rather
than only explicit service starts. Observe/failed/timeout profiles all pass final
runtime/snapshot/state/manual/root assertions. Stronger checks exposed and fixed
fixture /run1777; secure reader was not weakened. Python suite292passed. See
native-initrd-boot-test.md for reports and important limits. Next routine steps:
native wrong/cancel/retry handling, production source packaging and reviewed
observation image. Firmware/UKI, actual hardware, full Arch initramfs and older
image/header/Distress cryptographic migration remain separate checkpoints.

### Current specialist checkpoint — 2026-10-18

Read docs/astra-native-review.md for the current consolidated handoff. Native retry
and negative exhaustion now pass; Python suite298passed. Sol is stopping at the
owner-requested specialist boundary before production laptop boot integration.
Do not deploy guest manual-only overrides as a host observation image or break
current TPM auto-unlock. Full project, hardware and cryptographic migration remain
incomplete; original owner checkpoints apply.

## 2026-10-18 focused Astra review completed

Read observation-image-contract.md for findings, the staged observer interface,
exact allowed integration, tests and owner deployment checkpoints. The staged unit
auditor dependency-reset defect was fixed; installed laptop configuration unchanged.
Sol owns the next implementation. This is not production boot approval.
