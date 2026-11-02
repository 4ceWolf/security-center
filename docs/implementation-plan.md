# Current scope update — 2026-10-19
Custom preboot gating and initrd observation/handover rollout (older stages4/5) and
Distress (stage6) are removed by owner instruction. Preserve the historical plan
below for reference. Continue postboot protection, final installed checks and the
new automatic-unlock recovery workflow. Existing boot protections stay intact.

# Staged implementation
0. Audit and documentation (this stage). Record current TPM repair, actual boot configuration, signed recovery constraints, architecture, threat model and rollback before changing protection.
0a. Enable lockdown integrity for the running session only after recording baseline. No PCR, token, keyslot or boot-file changes. Check module signatures first; check GPU telemetry, services and logs afterward. Undo requires reboot; no automatic reboot.
0b. After runtime and interactive sleep/wake checks, build a separate candidate signed Zen UKI using the same signing/PCR keys, preserving the original image. Validate embedded command line, signatures, signed PCR policy and public-key identity. Boot-test candidate with manual recovery available; only after success update the normal build source/default. This stage changes initramfs security material and requires its explicit review checkpoint. Never blindly regenerate both kernels.
1. Read-only Cockpit/securityd MVP. Secure Boot, TPM, LUKS, lockdown, firewall, AppArmor, bounded journal timeline, independent failure states. Install only audited fixed collectors. No arbitrary root API or network exposure. Test timeout/malformed metadata/module crash/UI unavailable.
2. Optional installed-tool adapters: OpenSnitch, USBGuard, updates, Snapper and process/services. Observe before enforcing; USBGuard must preserve current keyboard and recovery access. Firewall coexistence tests are mandatory.
3. Audits, bounded FIM, optional on-demand ClamAV. Approve baselines explicitly; record package transactions without assuming they explain every modification.
4. Handover with honest trust levels. Observe-only initramfs instrumentation and boot-ID binding first; confirm record survives switch-root. Stronger TPM-backed claims require design review.
5. Device gate. Simulate policy against inventories, then test in a disposable environment before live initramfs. Explicit cryptsetup ordering, no race to auto-unlock, manual fallback and old-image bypass evaluation.
6. Distress core only. Test state machine and interrupted transitions off-device first. No PAM changes, TPM NV provisioning, persistent preboot gate or shutdown trigger before reviewed recovery tests. No camera/microphone initially.

Completion gates: boot changes need actual successful boot plus owner-confirmed recovery usability. Sleep/wake, hardware attach and manual-passphrase tests cannot be claimed from static inspection. Risky/authentication changes are incremental; this project does not authorize unreviewed credential capture or destructive operations.
