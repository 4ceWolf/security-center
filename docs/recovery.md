# Recovery and rollback
## Runtime lockdown trial
Writing integrity to /sys/kernel/security/lockdown is monotonic: it cannot be lowered while this kernel runs. Reboot returns to the original configuration because no boot file is changed in this trial. Save work and use the normal reboot UI; no forced reboot is part of this project. A reboot is an interruption and needs owner coordination.

## Boot deployment (not yet performed)
Preserve the exact current signed Zen UKI and its hash. Keep a separate selectable signed known-good image before testing a candidate. Verify the actual Visor/systemd-boot recovery selection path on this machine. LTS is unsigned and is NOT a Secure-Boot-on fallback. Do not change firmware Secure Boot settings merely to test lockdown: this can change PCR7 and require manual unlock.

Never overwrite the only working image. Back up build source, UKI and relevant configuration root-only, record hashes, check ESP capacity. Restore previous cmdline/build source and known-good UKI to roll back a permanent deployment. Do not touch LUKS tokens or TPM keys to roll back lockdown.

## Disk recovery
Manual slot 0 exists, but only the owner can establish that their passphrase works. Never put it in chat or command arguments. Existing header backup /home/user/Projects/security-center/docs/recovery-backups/luks-header-before-tpm-reenroll.img is root:root 0600 and 16 MiB. Its restoration has not been tested and is dangerous: do not restore automatically. Existing older backups under /var/lib/boot-care are not interchangeable with current metadata.

Snapper root/home snapshots are not a backup of the FAT ESP or proof of recoverability. Keep independent boot artifacts and backup access. Recovery tools and a verified owner-held passphrase are required before live device/authentication gates.

## Dashboard removal
Stop/disable only new securityd and Cockpit units; remove only their owned installation files. Existing enforcement remains intact. Never flush nftables globally. Additive enforcement changes require their own reverse operation and saved pre-state.

## Current recovery after promotion
Normal Arch Linux Zen now enforces integrity; “Arch Linux Zen - pre-integrity recovery” selects the original signed image. Both are signed with the existing trusted certificate. No firmware setting change is needed. Runtime lockdown cannot be lowered; boot the recovery entry to return to the previous behavior.
Rollback helper: tools/rollback-integrity-promotion.py restores normal image/build cmdline only after matching expected hashes. The earlier test-staging rollback helper is superseded. Do not restore its old menu snapshot because the separate test file was removed.
The saved recovery image is tied to kernel 7.2.9-zen1-1-zen. After future kernel updates, its external module tree may no longer be installed; do not assume indefinite full desktop recovery from a frozen image. Maintain/test the fallback and Snapper recovery plan during the update phase.

## Encryption-header backup relocated — 2026-10-19

At the owner's request, moved the original home-directory header backup into
docs/recovery-backups/luks-header-before-tpm-reenroll.img. Verified unchanged contents
and preservedroot:root0600; containing directoryroot:root0700. Old home-directory
file removed only after verification. The directory is excluded by .gitignore.
This relocation did not change the live LUKS header, TPM enrollment or recovery
passphrase. It remains a historical pre-reenrollment backup; do not auto-restore it.
Receipt:work/header-backup-move.json.
