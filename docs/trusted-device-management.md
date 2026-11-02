# Cockpit trusted-device management

Requested 2026-10-18. Design for implementation; controls are not built or deployed.

## Current receiver

A fresh host sysfs observation on 2026-10-18 matched the existing approved
Logitech receiver exactly: 046d:c542, no serial, pci:0000:00:14.0/usb:1,
mouse interface 03:01:02. USB observation reported no errors. The existing
candidate entry is retained without widening it or duplicating it.
The inventory remains incomplete for all-transport preboot enforcement.

## Owner workflow

Cockpit's Devices area must show connected devices and saved trusted devices,
including disconnected ones. Display readable name, USB ID, serial or “Not
provided”, port, full interface list, last observation and authorization scope.
Receiver interfaces that include a keyboard must be made explicit.

Provide “Review trust” for a connected device and “Remove trust” for a saved
entry. Review shows the exact identity and port restriction, including that
USB descriptors can be imitated. Never default to a vendor-wide or HID-wide
exception. Do not silently widen trust after moving a receiver to another port.

Show separate states for a saved candidate, active postboot USBGuard policy,
and the policy included in the boot image. Saving an entry must not imply
preboot protection is deployed. A reboot alone must not imply activation was
verified. Distress Mode continues to reject external trusted exceptions.

## Mutation boundary

Keep the existing monitoring endpoint read-only. Add a narrowly scoped,
authenticated administrator operation through a reviewed local helper, with
fixed operations for trust proposal, reviewed save and removal. Do not expose
arbitrary shell commands, paths, policy text or browser-supplied device claims.
The helper must re-observe a selected connected device, verify the exact
reviewed identity and policy revision, reject stale proposals or changed
interfaces, validate bounded policy data, and atomically save root-owned state
under an exclusive lock with an audit record and recoverable previous version.

The UI needs authorization-denied, disconnected-during-review, stale-policy,
validation-error, save-failure and recovery states. Preserve focus and provide
plain-language status. Successful save must return the actual saved revision.

Boot-image generation/signing and activation remain separate reviewed steps
with existing recovery checkpoints. Keep manual LUKS recovery available.
No TPM enrollment, key rotation or boot changes are authorized by adding a
receiver. Postboot removal must not silently disconnect the owner's input device.

## Build order and acceptance

1. Validated policy model and revision-aware, bounded editing operations,
   tested against malformed input, duplication, concurrent edits and widening.
2. Authorized fixed-operation helper with durable save/audit/recovery tests.
3. Cockpit connected/saved lists, review/add/remove and truthful activation
   states; test keyboard access, errors and stale data against the helper.
4. Connect reviewed policy to USBGuard and the preboot image pipeline, with
   separate activation evidence and real-device/recovery checks.

Reuse existing inventory and device-gate validation. Do not add an always-on
management daemon solely for this feature; use on-demand operations and verify
the full stack against the owner's approximately 200 MB memory target.

## Implemented stage — 2026-10-18

The earlier design-only status is superseded for the candidate-management slice.
Implemented policies/trust_policy.py, trust_store.py, the fixed on-demand
administrator helper tools/device-trust-helper.py, and Cockpit controls in the
existing index.html/app.js/style.css. These are staged; no privileged deployment
or enforcement activation has occurred.

The model uses exact USB identity including port and interface multiplicity.
Adds use helper observations, reject incomplete/ambiguous USB reads, and recheck
reviewed policy/device identity on save. Removals can operate on disconnected
saved devices. Internal entries cannot be edited by these operations. USB
coverage is not treated as complete all-transport preboot evidence.

Private candidate state is separate from both the approved FIM baseline and
any boot policy: /var/lib/security-center-trust/state.sqlite. It is created only
when the installed administrator helper is explicitly invoked. The helper seed
is fixed at /etc/security-center/normal-devices.candidate.json. Policy and the
previous policy/audit record commit in one SQLite transaction; at most 200 audit
records and a 64 MiB database limit. Root-owned 0700 directory, 0600 files,
no-follow checks, single-link checks and an exclusive lock protect access.
SQLite uses full synchronization and rollback journaling. Tests establish
process-crash recovery; hardware power-loss recovery has not been tested.
The audit actor is root execution (0), not verified human identity.

Cockpit invokes the fixed Python helper with isolated imports and
superuser:'require', sending only bounded fixed-operation JSON through stdin.
It does not request elevation on page load. It shows exact identity, serial
absence, port, interfaces, keyboard warning, last observation, and connected vs
saved candidates; add/remove requires review. Save does not activate USBGuard
or change a signed boot image. Cancellation, busy, denied, changed evidence and
unavailable-helper paths are handled; failure requires reloading/reviewing.
No always-running management service was added.

Tests: 236 Python cases, both Node UI suites. Headless Firefox rendered simulated
review pages at 1280 and 320 CSS px (work/trust-ui). Mock tests exercise focus
placement and cancellation restoration, but actual keyboard traversal, screen
reader, 200% zoom and authenticated administrator/Cockpit interaction remain
untested. A live read-only host view found 3 USB devices, 2 saved receivers and
the Logitech connected/saved; evidence is work/trust-ui/host-observation.json.
Running the actual staged helper without root returned authorization_required.

Latest review bundles: work/releases/device-trust-18exhhl2 (6 fixed files) and
work/releases/monitor-12mp6a1j (19 existing monitor files including updated UI).
These are distinct review artifacts; neither installs or authorizes anything.
The trust helper/state/seed are not yet integrated into the protected installer
allowlist or FIM scope. The monitor bundle alone cannot enable management.

The user requested a stop when Astra is needed. Next checkpoint: Astra review of
the administrator boundary, storage/recovery and deployment design before
privileged activation; then preboot/USBGuard integration with existing approval
and recovery requirements. Existing goal remains unfinished.
