# Baseline — 2026-10-14, Asia/Karachi
Observed on the host, not the Flatpak runtime:
- Arch Linux; running kernel 7.2.9-zen1-1-zen. Intel laptop; Niri/iNiR desktop. Btrfs root and home inside /dev/nvme0n1p2 LUKS2.
- UEFI Secure Boot enabled (user mode); systemd-stub reports measured UKI and OS. TPM2 present. The exact firmware-to-kernel execution path needs further review: EFI entries include Visor and Linux Boot Manager.
- Running image /boot/EFI/Linux/arch-linux-zen.efi. sbctl verifies its signature. Current loader default names that image.
- /etc/mkinitcpio.d/linux-zen.preset uses /etc/miku-boot/zen.conf, zen.cmdline and zen-uki.conf. The ordinary /etc/kernel/cmdline is NOT this boot path's source.
- Zen hooks: base systemd autodetect microcode modconf kms keyboard sd-vconsole plymouth block sd-encrypt filesystems fsck.
- UKI config uses existing sbctl db signing key, existing Zen PCR signing key, SHA256, SignInitrdPCRs=yes, signed phases enter-initrd through ready.
- LTS has a separate legacy encrypt configuration and is deliberately unsigned. It cannot be assumed bootable with current Secure Boot. Never change that arrangement casually.
- LUKS slot 0: Argon2id manual passphrase slot. Slot 2: TPM token-associated slot. Presence is verified; the passphrase itself has not been tested in this project.
- cryptsetup unit completed this boot. Its normal logs do not identify automatic versus manual unlock. User reports successful TPM automatic unlock following repair.
- Kernel lockdown initially [none]. LSM list capability, landlock, lockdown, yama, bpf. CONFIG_MODULE_SIG_ALL=y; all 212 loaded modules have the build-time signer. No DKMS package found.
- Saved history inspected privately: Bash 500 lines, Fish 348 commands. No matched unsigned-module, undervolting or kernel-debug workflows. History is incomplete and is not proof of compatibility.
- Desktop GPU telemetry invokes intel_gpu_top. Check this explicitly after lockdown. Active tuned profile powersave; automatic-power-profile service changes profiles.
- machine-care-firewall.service enabled and active (oneshot). Custom nftables input/forward chains default drop; Cloudflare WARP also installs rules. nftables.service/UFW being disabled DOES NOT mean firewall absent.
- No non-loopback TCP listeners during initial audit. mDNS and DHCPv6 UDP sockets observed.
- Cockpit, AppArmor, OpenSnitch, USBGuard, AIDE, Lynis, ClamAV absent. audit package installed; audit services disabled. Snapper root and home configured; cleanup/timeline timers present.
- USB snapshot: internal camera 13d3:540a and Intel Bluetooth 8087:0aaa plus root hubs. This snapshot is not a trustworthy device allowlist or proof no external hardware exists.
- Screen lock configured after 150 seconds and before sleep, not interactively tested.
- User input-group access and ChatGPT Flatpak host execution remain separate risks; lockdown does not solve either.

Privileged reads were authorized through system polkit prompts. No passwords or private keys were read into project reports. Earlier Waydroid cleanup is separate: package absent; stale UFW rules, lease, cached trace, and two user icons removed.
