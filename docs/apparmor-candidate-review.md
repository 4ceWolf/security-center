# AppArmor candidate — offline signing review, 2026-10-20

The running kernel supports AppArmor but excludes it from the default active LSM list.
Proposed next operation: build a **separate offline signed test image** using
prepare-apparmor-candidate.py and the existing Secure Boot/PCR keys. Extract the current
working Zen UKI's exact kernel/initrd and preserve their bytes. Keep lockdown=integrity.
Append only:

apparmor=1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf

This retains every LSM in the kernel's compiled default and adds AppArmor. Keep the
existing TPM PCR7 + signed PCR11/SHA256/initrd policy, keys and manual slot0 unchanged.
No reenrollment, TPM clear, initramfs rebuild, key rotation or security disable.

Output is root-private /var/lib/security-center/apparmor-candidate-<timestamp>/,
including a separate known-good signed image and verification report. Verify existing
certificate, exact payloads/public key, initrd PCR signature reference and unchanged
source/config/full LUKS metadata. A failure leaves NOT_VALIDATED and stops.

This permission covers offline candidate signing only. It does not write the ESP,
select a boot entry/default, change firmware, enable shipped profiles or reboot.
A later staging/trial decision will show exact candidate hash and a known-good entry.
After a successful trial, use only a separately reviewed small profile set; do not
enable every profile supplied by the package or risk authentication profiles blindly.

The project brief explicitly requires confirmation before regenerating boot-security
material, even though the initrd bytes are preserved. Current signed-image recovery
checkpoints still apply. No private key bytes are copied to project files/reports.
