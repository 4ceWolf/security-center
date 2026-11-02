# Current postboot recovery notes — 2026-10-20

These notes preserve earlier recovery.md instructions. Never restore a LUKS header,
clear TPM, remove manual slot0, rotate boot keys or broaden PCR policy as a shortcut.
The normal signed image and manual disk passphrase remain the boot recovery choices.

## AppArmor normal entry and retained recovery

Owner-approved promotion completed after actual AppArmor boot/enforcement and hardware
checks. Normal /boot/EFI/Linux/arch-linux-zen.efi now has SHA256
9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2.
The previous signed working image is retained at
/boot/EFI/Linux/arch-linux-zen-pre-apparmor.efi, SHA256
df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987.
Select “Arch Linux Zen - pre-AppArmor recovery” if the normal configuration fails.
Default index0 and remember_last0 remain unchanged. No automatic reboot occurred.
TPM/LUKS metadata was verified unchanged. Use the known manual disk passphrase if
automatic unlock fails. The unsigned LTS image is not a Secure-Boot-on fallback.

The original AppArmor test image was atomically moved to the normal path, not deleted
and rebuilt. Previous test-image instructions are superseded. Protected promotion
proposal/config backups/result are under
/var/lib/security-center/apparmor-candidate-20261020-153225/promotion.
Do not restore a whole old menu blindly: compare exact hashes and preserve subsequent
owner changes. Future normal Zen image builds now include the tested AppArmor options.
The selected loader condition skips AppArmor-disabled recovery boots; it does not
silently enable package-wide profiles or alter TPM policy.

## Native USB trust changes

Prepared helper changes never issue allow-device/block-device/reject-device or
restart the daemon. They affect future connections. Root-private
/var/lib/security-center-usb-policy contains the before-policy backups, exact current
reference and the last200 change receipts once the editor has made a real change.
A pending reference blocks further editing rather than silently adopting live drift.
Inspect live rules and the matching backup before recovery. Do not replace all rules
from an old unrelated backup. Initial exact policy/config fingerprints are pinned in
the installed usb_policy.py and checked independently of the ordinary code baseline.
Earlier complete USBGuard rollout recovery remains in the trial/promotion docs.

Native IPC testing used a redundant block before the final block rule; it changed no
current device authorizations and restored both the exact policy bytes and native
rule set. No receiver trust was removed for testing.

## Networking is owner-managed

OpenSnitch was removed at the owner's request. Its former configuration, proof and
trial backups are archived under the root-only directory
/home/user/Projects/security-center/docs/history/opensnitch-removal-private-20261020.
Do not restore/reinstall it as part of routine recovery. Its active startup override,
GUI configuration and private endpoint were removed. The existing machine_care_guard
firewall table was verified unchanged. Never flush the complete nftables ruleset.

## Installed dashboard release

Use the protected transaction and prior-baseline archive recorded in HANDOFF. An
ordinary pre-approval rollback is deliberately refused once a new baseline has been
published; any later recovery must compare current files and restore only exact
matching protected backups. Do not run an obsolete installer snapshot against a new
source release or accept drift automatically.
