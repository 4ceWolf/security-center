# Owner scope update — 2026-10-20

Automatic-unlock repair is deferred to the ideas list at the owner's request.
The design below is retained for future reference, not an active completion task.
The read-only installed review remains useful. The new requested action is disabling
TPM automatic unlock; see tpm-unlock-disable.md. No repair or reenrollment is built.

# Automatic-unlock recovery — staged design, 2026-10-19

Owner requested an option to restore automatic disk unlock after a TPM policy failure.
This is retained boot maintenance, not a return of custom preboot device enforcement.
No laptop repair/enrollment is needed or authorized to run unattended now.

## Current implementation

Staged Cockpit button: Review automatic unlock recovery. Displays only existing
sanitized Secure Boot/lockdown/TPM/LUKS check summaries. It rejects stale/unavailable
snapshots and never infers successful automatic unlock from TPM/token presence.
No additional polling/service, administrator prompt, passphrase field, enrollment
or disk write. UI clearly says automatic repair is not installed yet. Current installed
Cockpit is unchanged until reviewed deployment; this is not a completed reset button.
The collector no longer schedules custom preboot/handover checks outside scope.
Historical reader code remains inert. Trust copy now describes postboot candidates.

## Intended owner flow

1. Owner manually unlocks the disk at startup and reaches the desktop.
2. In Security Center, review the failure. Establish whether a deliberate BIOS/Secure
   Boot/firmware update explains it. Unexplained changes require investigation;
   never silently trust them. Correcting a setting or repairing a missing signed
   image may be sufficient; a TPM policy mismatch does not mean the TPM was cleared.
3. Administrator-authorized diagnosis captures current root UUID/backing device,
   boot mode/signatures/lockdown, public PCR key fingerprint, exact LUKS token policy,
   manual-slot metadata and normalized failure class. Never export sealed blobs,
   raw tokens, volume keys or arbitrary journal messages.
4. Prepare a root-private transaction with fresh header backup and before/after
   metadata/hash binding. Show an exact proposal with cause, device, PCR policy and
   public-key identity. If any differs or is ambiguous, stop for specialist review.
5. For a repair that changes enrollment, owner explicitly approves that transaction
   and proves the working manual slot0 passphrase via a trusted local credential
   interface. Admin login is separate from the disk passphrase. No passphrase in
   web content, chat, arguments, logs, persistent files or telemetry. Native helper
   should own credential input and bounded lifetime; handling must be guest-tested.
6. Add the replacement TPM enrollment without removing the old one first. Preserve
   directPCR7/SHA256 plus signedPCR11/refinitrd, existing public key, RSA/SRK,
   noPIN/noPCRLock settings. Pin all options; do not inherit unreviewed discovery
   files or silently accept new tool defaults. Verify metadata and slot0 unchanged.
7. Leave old enrollment cleanup pending until a supervised reboot confirms automatic
   unlock and manual recovery. Any cleanup identifies only the exact obsolete TPM
   token/keyslot; never wipe all/password/recovery/manual slots. No automatic reboot.

No TPM clear, seed reset, Secure Boot disable, PCR broadening, signing key rotation,
header restore or policy-reference change is a recovery shortcut. Header backups
are protected recovery material; record paths/digests, never publish their contents.
Do not offer a green Repaired state merely because enrollment returned success:
label enrollment prepared until an actual later boot establishes the result.

## Signed-policy challenge needing implementation review

The existing policy is initrd-only. The current desktop PCR11 differs after
leave-initrd. systemd-cryptenroll verifies a found/supplied PCR signature against
current PCR state before writing a slot; a desktop failure here must not cause the
workflow to broaden phases or sign current PCRs. Upstream also permits enrollment
without signature verification when none is found. Do not silently bypass the
safety check to make the repair work. Review and disposable-test an enrollment and
later-initrd verification sequence preserving the exact policy before enabling Apply.
This maintenance review remains necessary even though custom preboot is removed.

Primary reference: systemd262 systemd-cryptenroll documentation, signed-PCR options,
policyref, signature validation and slot-wipe ordering:
https://www.freedesktop.org/software/systemd/man/262/systemd-cryptenroll.html

## Required independent tests before Apply exists

Use fresh disposable software TPM/LUKS disk only. Cover deliberate PCR7 change,
manual recovery, reviewed replacement enrollment, existing public-key preservation,
initrd-only signed policy, failed enrollment retaining old slots, unchanged manual
slot0, credential cancellation/wrong input, stale proposal, changed disk/boot/key,
failed backup, interruption and concurrency. Root helper accepts fixed operations
and fixed device identity, not browser command arguments or caller-supplied paths.
No physical TPM/root disk or owner credential in these tests. Earlier TPM VM passes
are reusable evidence for their original cases, not proof of this new transaction.

## Owner-away pending items

No authentication/re-enrollment/reboot/physical interaction while the owner is away.
Finish safe source/tests and release review. Installation requires reviewed protected
transaction and later exact baseline approval. Enable Apply only after the recovery
transaction passes its own review and tests. Never ask the owner to reset a currently
working enrollment just to test the feature.
