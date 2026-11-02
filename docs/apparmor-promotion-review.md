# Make the tested AppArmor configuration normal — exact review

Trial enforcement passed and owner confirmed automatic disk unlock, Wi-Fi, sound,
keyboard/mouse and sleep/wake. See apparmor-trial-results.md. The read-only promotion
preflight passed, including both image signatures and the manual LUKS slot0 check.
No boot files were changed by that preflight.

Proposed changes, requiring owner approval:

- Retain the existing signed normal image as
  /boot/EFI/Linux/arch-linux-zen-pre-apparmor.efi and expose it as
  “Arch Linux Zen - pre-AppArmor recovery”.
- Put the exact already boot-tested AppArmor image at the normal default path
  /boot/EFI/Linux/arch-linux-zen.efi. Default index0 and remember_last0 stay unchanged.
- Append the already-tested AppArmor/LSM options to /etc/miku-boot/zen.cmdline so
  future normal Zen image builds preserve them. Keep integrity lockdown and all
  other existing options. No new signing, TPM reenrollment, LUKS changes or reboot.

Exact proposal digest:
ef926c04fd7f2b1f80664f086ed2036324d3b9057de45dc848aeb1bfc749b34f
Captured promotion-source SHA256:
6646d848c9a42e75868768ed362ded52094995c034d2aa8e8448a9adc164afa1
Normal image after promotion:
9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2
Retained recovery image:
df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987
Menu after:
6e178f7e3e45e9f147ded249178eb145251c21ec5db32442a890c3710b03b437
Future build command-line file after:
c5591f7221b885e4fd67e67ed02629651859c75eea6582c113bfb5440af50313

The first read-only preflight refused the older two-extra-copy space requirement.
It made no changes. The revised procedure needs one additional image copy: preserve
and verify signed recovery, make it selectable, then atomically rename the exact
staged test image over normal. It requires276183216free bytes (recovery image plus
65MiB reserve); current boot free space is approximately306MiB. It deletes no other
boot or recovery images. Disk space, exact hashes, signatures, same filesystem,
actual trial state, metadata fingerprint and proposal digest are rechecked at apply.

Protected backups: /var/lib/security-center/apparmor-candidate-20261020-153225/promotion.
An interrupted operation must be inspected using that folder and exact retained image
hashes. Before the final rename, normal is still the old signed image; after it,
normal is the tested image and the verified previous image is in the recovery entry.
No automatic retry or TPM recovery-policy change is allowed.

Captured apply launcher: work/apply-approved-apparmor-promotion.py. Not executed.
Read-only review receipt: work/apparmor-promotion-review.json.
After successful promotion, verify installed boot files and prepare the separately
reviewed file-integrity reference for the changed build command-line source. This
approval authorizes only the exact boot promotion above, not automatic FIM approval.
The same candidate has already booted successfully; the normal-path reboot itself
will remain distinguished from that successful trial.

## Exact proposal approved and applied

Owner explicitly approved ef926c04…; captured apply returned0. Normal/recovery/menu/
command-line hashes match this review; LUKS metadata unchanged. No automatic reboot.
Root independent verification passed; only zen.cmdline changed within the42-file
static reference. Its separate candidate is in apparmor-final-baseline-review.md.
The earlier unexecuted wording above describes the preapproval state.
