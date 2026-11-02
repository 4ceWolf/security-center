# Disposable UEFI phase probe — 2026-10-19

A bounded first step toward the two-boot encrypted-root contract. Boot the complete
probe initrd inside a UKI through OVMF, using copied private firmware variables and
fresh software TPM state, no physical disk/TPM/ESP/network. Read-only virtual FAT
contains only the disposable EFI image. No host signing keys or credentials.

Reuse the captured synthetic Arch initrd plus an explicitly test-only service.
Run native systemd-pcrphase-initrd, read SHA256 PCR11, stop that service to exercise
its native leave-initrd action, and read PCR11 again. Independently calculate both
expected values from extracted UKI sections outside the guest. Require successful
unit conditions/results and exact PCR matches. Record firmware/tool/input hashes.
Secure Boot is separately reported from guest variables; this unsigned probe must
not claim Secure Boot, encrypted-root unlock, switch-root or policy rejection.
The known synthetic archive metadata conflict is retained and explicitly outside
production acceptance; this fixture is never a laptop candidate.

No production rollback needed: all artifacts are private project files; VM and
software TPM must be terminated on success/failure/timeout. Later two-boot LUKS,
signed-policy rejection and Secure Boot tests remain mandatory before deployment.

The measurement result is separate from Secure Boot state. OVMF_CODE.4m.fd
executed an unsigned UKI but did not expose SecureBoot/SetupMode variables; report
those as unavailable, never infer enabled or a successful Secure Boot test. The
Secure Boot-capable CODE trial timed out before Linux; no successful Secure Boot
result is claimed. Overall `passed` in this probe means phase measurement only.

## Enrolled-key disposable branch

Use project-local virt-firmware26.9 (no system installation) to enroll only a fresh
throwaway certificate into copied VARS (no Microsoft keys). Sign the captured probe
with that disposable key; independently verify its EFI signature. Run signed,
unsigned and payload-tampered images underTCG/secure-capableOVMF with768MiB guest
memory. Require SecureBoot=1,SetupMode=0 and exact native phase measurements for
signed acceptance. Negative cases require explicit firmware Security Violation,
not simply a timeout or absent Linux marker. No host firmware/key access. See
https://gitlab.com/kraxel/virt-firmware and
https://man.archlinux.org/man/extra/virt-firmware/virt-fw-vars.1.en.
