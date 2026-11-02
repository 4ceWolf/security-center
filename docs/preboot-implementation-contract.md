# Preboot implementation contract — specialist review, 2026-10-18

Status: next-stage design, not deployment approval or a completed hardware security review.
Read alongside astra-preboot-handoff.md and testing.md. Existing policy/VM work is
retained. This document resolves the next implementation scope, not the remaining
cryptographic migration. No host boot, token, keyslot, NV or PAM changes occurred.

## Decision and enforcement boundary

Build a complete disposable-guest integration next. A production candidate must
first run as observation only, on a separately reviewed boot image. Do not put the
existing incomplete platform inventory in charge of the laptop's automatic unlock.
The eventual software gate is useful, but must be labelled separately from
rollback-resistant enforcement. Do not present observation mode as satisfying the
project's final device-gate or Distress requirements.

The current enrollment accepts PCR7 plus signed PCR11 with initrd policy reference.
Signed PCR policies authorize multiple signed measurements; replacing the default
boot entry does not revoke older authorized measurements [1]. Consequently, an old
UKI with a still-accepted signature and compatible PCR7 can potentially invoke the
old unlock path. This is a design inference, not a tested attack on this laptop.
Deleting an ESP copy or adding a drop-in to the new image cannot close that path.

A second migration hazard is retained LUKS headers: changing/removing a current
slot does not revoke a saved old header's access to the unchanged volume key [3].
Therefore a future NV-gated enrollment must also address old sealed objects and
headers. An NV flag checked only by new software does not constrain old objects
that never included that condition. Do not claim key rotation, reenrollment or
removal of a boot entry alone fixes this. Preserve the owner's recovery backup.

Before claiming enforcement, demonstrate rejection of the historical auto-unlock
path in a disposable clone design. Candidate strategies requiring a separate
specialist review include revoking old boot authorization with a compatible new
PCR7 enrollment, or another explicit cryptographic migration invalidating legacy
unseal paths. Neither is authorized here. A firmware revocation design must include
all alternate boot chains and recovery compatibility; changing PCR7 incidentally
is not a permanent revocation proof. No proposal to clear the TPM or reencrypt the
laptop is made by this contract.

## Concrete next deliverable for Sol

Add `tests/vm-preboot-integration.py` and extend `tools/test-luks-vm.py` with an
explicit integration scenario. Keep host-device/TPM access forbidden. Use fresh
software TPM, guest keys and disk, no network, bounded execution, and the existing
384 MiB guest budget. No new resident daemon. Do not discard existing failure
reports or replace real assertions with success markers.

Join the existing generated-unit and terminal-recovery tests into ONE actual
systemd initrd boot. Cover crypttab and kernel-command-line generation separately.
Use the generated UUID mapping, normal automatic target activation, actual udev
resolution and encrypted-root switch-root. Existing noauto `/dev/vda` fixtures do
not establish this coverage. Retain a disposable interactive PTY for credentials;
production console ownership remains a later adapter review.

Proposed integration-only files:

- `initramfs/gate_runner.py`: bounded inventory/evaluation adapter; no credential
  handling, commands supplied by input, token enrollment or policy initialization.
- `initramfs/unlock_adapter.py`: fixed root mapping and volume identity taken from
  the reviewed image manifest; invokes the existing pure dispatcher. Reject an
  already-open unexpected mapping. Verify mapping identity after command success.
- `initramfs/units/security-center-device-check.service`: bounded oneshot.
- A generated mapping-specific drop-in: clear stock ExecStart and invoke the
  adapter; Wants+After the checker so checker failure still reaches manual recovery.
  Do not install a wildcard replacement for unrelated encrypted volumes.

These files are to be built/tested in the guest first; they are not installed paths
or authorization to change mkinitcpio. A build report must list the effective
root-unit ExecStart, all other services/generators capable of opening the same
volume, keyfile/credential/token sources and console agents. Any duplicate path
fails the integration acceptance check. Merely ordering Before=cryptsetup.target
is insufficient. Account for fallback initrds, EFI entries, bootloader overrides,
removable media, recovery images and emergency/manual commands in the later host
inventory; do not assume the root service seen after switch-root is complete.

## Evidence and policy interfaces

Keep `device_gate.evaluate` pure. Never reinterpret `observation_complete` from
platform_inventory as full device coverage. The adapter may supply complete=True
only after a reviewed platform profile explicitly covers USB, Thunderbolt/USB4 and
external PCI paths. Missing controllers, read errors, changed topology, unknown
ports or transport support all require manual recovery in enforcement mode.

The platform profile must identify physical external ports, controller ancestry,
internal-device routes and built-in keyboard input independently of VID/PID names.
An empty Thunderbolt directory is not proof of absent hardware. Firmware capability
information and physical port tests are required. Two matching scans do not close
a hotplug race. Internal camera/Bluetooth observations stay unapproved until that
review; do not auto-fill the currently empty internal list.

Use a measured, embedded policy snapshot for a reviewed image. Record its digest
and revision with the image manifest. Cockpit edits remain pending candidates until
an explicit publication workflow builds and verifies an image; changing the saved
list alone must not change preboot policy. Normal mode includes the approved
receivers; Distress ignores every trusted external exception. Devices without a
serial remain exact descriptor/interface/port matches, not authenticated devices.

Gate output should be a bounded schema with boot ID, policy digest, monotonic
sample time, coverage result, reason and the existing decision booleans. Require
root-owned private /run ancestry, exact schema, current boot and policy, and checker
completion. Missing, malformed, old, future, truncated or conflicting output goes
manual. Use a fixed five-second initial scan budget in the guest; expiry goes
manual, never an unbounded boot wait. This is a software provenance contract, not
TPM attestation.

A TPM adapter must attempt only the designated TPM method with no password/keyfile
fallback, otherwise a successful command cannot establish TPM provenance. The
manual adapter must use slot0 with external token plugins disabled, no keyfile or
credential/cache source, cryptsetup-owned hidden terminal input, and bounded
attempts. Cancellation returns to a usable recovery prompt; it must not retry TPM.
Never pass the passphrase through securityd, JSON, logs, argv or environment.

Reuse handover.py for the successful final mapping only. Preserve attested=False.
Failed attempts must not publish success. If observation-only scanning is added
without owning unlock, use a separate observation record; do not invent unlock
method to fit the existing schema. No userspace boot record is authority to clear
Distress, and ordinary root authentication does not prove manual LUKS recovery.

## Hotplug and recovery contract

Before future enforcement, establish controller/device authorization before driver
binding, retain it throughout unlock, and hand it to postboot enforcement without
an allow-all interval. Linux USB authorization is a useful mechanism [2], but does
not authenticate descriptors, prevent all enumeration attacks, or cover PCI/DMA.
`authorized_default=2` is not independent proof that firmware classified ports
correctly. Late devices, changed interface sets, new hubs and reset/re-enumeration
must not inherit an earlier decision. USBGuard alone cannot cover Thunderbolt/PCI.

Until these properties are proven, describe any scan as a snapshot observation and
leave complete enforcement unavailable. Built-in keyboard/manual entry must work
when external HID is rejected. If built-in input is unavailable, the recovery
interface must explain the limitation and offer an explicitly reviewed recovery
boot, not silently authorize arbitrary keyboards. Keeping manual recovery usable
is mandatory even when the scanner crashes or no platform profile is approved.

## Distress witness decision

Do not implement a production TPM NV backend from the current Witness interface
without another concrete protocol review. Treat durable store tests as software
crash tests only. TPM NV compare-exchange is not assumed, and an administrator who
can overwrite/delete/recreate an index must not thereby restore NORMAL.

Required protocol deliverable: exact NV public attributes and authorization
policies; initialization and index-name verification; reset/undefine protections;
writer serialization; durable monotonic epoch and boot/policy binding; strict
transition before acknowledgment; interruption behavior; actual unseal dependency;
legacy-object rejection; and owner-only restoration based on manual unlock plus
separate normal authentication. Identify which actor possesses each authorization
and whether compromised postboot root can use it. Failures must retain manual
recovery. Evaluate pcrlock as an existing policy mechanism [4], not as a ready-made
Distress switch or permission to replace this enrollment.

## Required acceptance cases

| Case | Required result |
| --- | --- |
| Valid complete guest policy | Exactly one TPM attempt; actual mapper evidence |
| Unknown device / no profile / checker crash or timeout | No TPM attempt, usable manual route |
| Wrong/correct input, cancellation, repeat | No mapping on failure; slot0 succeeds; no secret in output |
| TPM failure after allowed decision | Manual succeeds; method reflects actual successful adapter |
| Duplicate generator path, credentials, keyfile, alternative token | Detected/refused; cannot bypass adapter |
| Policy/boot mismatch, replay, malformed record | Manual route, no fabricated success |
| Hotplug after sample or during unlock | No inherited permission; limits explicit until enforced |
| Systemd switch-root | Current-boot record retained; no attestation claim |
| Older signed image + old TPM object/header | Explicit bypass reproduction, then rejection proof before enforcement claim |
| Distress transition interruption / stale state / witness reset | Never report NORMAL or successful activation without durable proof |
| Recovery/retrigger/concurrent policy update | Strict state retained until verified restoration; no overwrite of newer policy |

Implement the first eight guest cases before proposing a host observation image.
The legacy-object and hardware-witness cases remain specialist work in a disposable
environment, not approval to improvise TPM policy on this laptop. Owner checkpoints:
physical topology/keyboard confirmation; exact separate observation image/recovery
review; observation reboot results; then a separate enforcement/migration decision.
The original full-project requirements remain outstanding until enforced behavior
and recovery are proven. Sol may proceed with these guest integration tasks and
ordinary UI/export work; return to specialist review before the hardware protocol
or any production boot/authentication migration.

## Sources consulted

[1] systemd 262 signed-PCR policy semantics:
https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html

[2] Linux USB device/interface authorization:
https://cdn.kernel.org/doc/html/latest/usb/authorization.html

[3] Cryptsetup project FAQ, old headers/keyslots and volume keys:
https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md?plain=1&ref_type=heads

[4] systemd PCR policy manager (not a Distress implementation):
https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html
