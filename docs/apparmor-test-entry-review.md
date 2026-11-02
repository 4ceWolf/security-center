# AppArmor trial entry — staging review, 2026-10-20

Approved offline build completed and verified. Exact candidate SHA256:
9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2
Working normal image SHA256:
df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987

Proposed operation: copy that exact signed candidate to
/boot/EFI/Linux/arch-linux-zen-apparmor-test.efi and append a clearly named
“Arch Linux Zen - AppArmor test” entry to /boot/EFI/visor/boot.conf.
Keep default=0 and remember_last=0. Preserve the normal image and all existing
recovery entries. No reboot or default selection change is performed now.

Capture original menu privately in the candidate directory, verify signatures and
hashes before/after, preserve full LUKS metadata, use exclusive temporary writes,
and restore only this operation's menu bytes if staging fails without later edits.
If either normal image/menu assumptions changed, stop for renewed review.

Later the owner can reboot, manually choose the AppArmor test entry and confirm
auto-unlock and ordinary sound/sleep/Wi-Fi/input. A failure means choose the normal
entry at the next startup and use the known manual LUKS passphrase if needed. Do not
promote this candidate to the normal image until that actual trial succeeds.
No profiles are enabled by staging this image; a small selected profile rollout is
separate. LTS remains unsigned and is not the Secure-Boot-on recovery choice.
