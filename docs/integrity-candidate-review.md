# Integrity candidate — review checkpoint
User confirms this reboot unlocked automatically and they know the manual LUKS passphrase. This is owner confirmation, not a passphrase test performed by the project.

Proposed operation: run tools/prepare-integrity-candidate.py with administrator authentication. Extract the existing signed Zen image's kernel and initramfs, preserve both byte-for-byte, append only lockdown=integrity to the embedded command line, and build a separate signed candidate using the same existing Secure Boot and PCR signing keys. Preserve SHA256 PCR11 initrd-policy signing. The new PCR11 measurements must be authorized by the existing signing key; no direct PCR binding or LUKS enrollment changes.

Destination: root-only /var/lib/security-center/integrity-candidate-<timestamp>/. Save the current image there as known-good.efi. Produce a signature/evidence report. This step does not write the ESP, change a default/one-shot boot selection, change firmware variables, re-enroll TPM, or reboot.

Checks: enrolled public-key identity, current slots 0/2, direct PCR7, signed PCR11 with initrd reference, existing stub compatibility, current image hashes. After build: existing certificate verifies image signature; exact kernel/initramfs preservation; correct embedded command line and policy-reference presence; unchanged source image, build config and complete LUKS metadata. These do not substitute for a real boot and TPM-unseal test.

Rollback at this stage: do not deploy the candidate; running boot configuration is untouched. Keep failed candidates marked NOT_VALIDATED. A later deployment needs a separate reviewed boot-selection/recovery plan, with the original signed Zen image preserved and selectable. LTS is unsigned and is not a Secure-Boot-on recovery fallback.

The project brief explicitly lists regenerating initramfs security material among actions requiring confirmation. Although this preserves the actual initramfs payload, it creates new signed PCR authorization material, so request confirmation before executing the build. Private keys remain in their existing protected paths and are not copied into project source or reports.
