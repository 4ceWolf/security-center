# Disable TPM automatic unlock — 2026-10-20

Owner asked to defer repair to ideas and add a disable button. Building the control
does not disable working automatic unlock. No re-enable or repair action is exposed.

## Exact action

The fixed helper targets only /dev/nvme0n1p2 with LUKS UUID
2dd04c28-ca38-4d93-8f51-5f47e0984431, and verifies that it backs /dev/mapper/root.
It requires exactly one systemd-tpm2 token and an independent manual slot0. Review
contains only UUID, token ID, timestamp and a hash binding full metadata/device/boot.
No sealed blob or credential reaches the browser. Review expires after two minutes.

After explicit browser confirmation and Cockpit administrator authorization, a native
KDialog password prompt runs as kyo, using a fixed, minimal Wayland environment.
The entered disk passphrase goes by pipe to cryptsetup test-passphrase for slot0.
It is separate from administrator authentication. Cancellation/wrong input stops.
No password in browser inputs, command arguments, reports or saved files. Python
and subprocess buffers cannot provide a guarantee of complete memory erasure;
the owned mutable buffer is overwritten after use. No persistent passphrase copy.

A fresh root-only header backup is created below /var/lib/security-center-unlock,
its metadata must exactly match the live header, and slot0 passphrase verification
must work on that backup too. The helper recaptures disk identity and metadata,
rejects changes/expired review, durably records removal_pending, then runs only:
cryptsetup token remove --token-id <reviewed exact ID> <fixed partition>.
It never deletes a keyslot, changes PCR policy, clears TPM or rebuilds boot images.
Every post-action metadata field must equal the prior value except the removed token.
A disabled receipt explicitly records boot_verified=false. All disk keyslots remain,
including the now unreferenced TPM slot; there is deliberately no broad cleanup.

A protected exclusive update lock serializes this helper and the installer. Other
privileged administrators are trusted and must not independently modify disk metadata
during a transaction. Failed/interrupted removal leaves a pending receipt; do not
blindly retry or automatically restore an old header. Inspect the live token state.

## User-visible consequences and limits

Future boot will need the manual disk passphrase; the open desktop is unaffected.
The existing kernel command line uses tpm2-device=auto without an external TPM blob.
Boot fallback after the real action still needs owner verification; no reboot is
performed as part of building or pressing this control. It may briefly attempt TPM
before falling back. No claim of physical boot testing is made by an enrollment read.
Restoring automatic unlock needs a separate reviewed operation. Protected header
backups contain sensitive recovery material and retain the old token; they are not
for publication. Do not automatically restore them or claim TPM trust was revoked.
This button disables the current on-disk auto-unlock path, not all copies/backups.

The native prompt currently requires kyo UID1000 and wayland-1; other sessions fail
closed rather than accepting caller-selected display commands or secret web fields.
No new daemon or background polling is added.

## Validation

11 transaction tests cover exact-token preservation, ambiguous/manual-slot rejection,
stale/future/changed proposals, wrong credentials, backup failures, changed disk,
failed native removal and failed post-action verification. UI tests cover review,
acknowledgment, cancellation, fixed administrator endpoint and truthful outcomes.
A native disposable regular-file LUKS2 test verifies real backup readability,
exact token deletion, all keyslots/unrelated metadata unchanged and manual slot0
before/after. Its TPM token is synthetic: this is not physical TPM or reboot proof.
No laptop token or keyslot is changed by these tests.

Primary command reference: https://man7.org/linux/man-pages/man8/cryptsetup-token.8.html
Systemd token discovery: https://www.freedesktop.org/software/systemd/man/262/crypttab.html

## Deployment

Installed in txn-b81a137903c71e6b512b0266fcac3e2c. Owner approved exact candidate
fbffa043adc034bac274eac983fbdf929b007f81b6b67f9a0e81c31d9fb0cb8f; published
reference58eab555dda3f5b84f0192fa0f44a918c1a9f662a26f271819b83effa6a932db.
Final38-file scan:0changes/0unreadable. Installed root helper review passed and
confirmed token1 still present. All33installed file hashes matched the release.
Installing did not invoke disable or display a disk-passphrase prompt. Actual
owner credential/physical boot tests remain intentionally unperformed.
