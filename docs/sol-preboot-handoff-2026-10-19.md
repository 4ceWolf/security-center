# Sol handoff: normal preboot device enforcement

Owner instruction2026-10-19: remove Distress Mode; switch to Sol for normal preboot
work. This supersedes older instructions to implement Distress or treat its unfinished
prototype as a remaining milestone. No Distress feature was deployed, so no live
shutdown/authentication/TPM mechanism needs disabling. Keep historical prototypes
and evidence rather than deleting shared code blindly. Do not add new Distress work.

## Starting state

Read STATUS.md, astra-progress-2026-10-19.md and measured-observation-next-contract.md.
Normal integrity boot, existing PCR7 plus signedPCR11/initrd enrollment and manual
slot0 are unchanged. Trusted receiver identities are candidates, not enforcement.
Latest monitor release remains staged, not installed. No swap baseline change was
needed: current monitored files match, swap resides on encrypted root.

## Next implementation sequence

1. Diagnose and stabilize tools/test-uefi-phase.py in a disposable VM. One run
   (uefi-phase-jxib1zot) reached native measured-os phase and exact expected
   enter/leave PCR11; other attempts hung. Guest early TPM SRK setup failed and
   needs diagnosis. SecureBoot/SetupMode variables were missing under normal OVMF;
   the Secure Boot-capable trial timed out. Do not label these overall acceptance.
2. Complete the separate provisioning/target two-boot contract. No formatting,
   enrollment, manual secret or private signing key in the target image. Match
   native enter-initrd PCR11 before stock unlock, verify encrypted switch-root,
   then prove the initrd-only signature no longer authorizes after leave-initrd.
   Add missing/stale/wrong-ref/modified-image negatives and manual recovery.
3. Keep the normal device gate fail-to-manual on unknown/incomplete inventory or
   scanner errors. Close duplicate/alternate unlock paths; existing guest test
   demonstrates a second cryptsetup service bypass. Preserve native input/recovery.
4. Use effective_initrd.py for conservative ordered alias/collision review. It
   refuses the current synthetic Arch image because duplicate usr/lib/firmware
   permissions differ0700→0755. Do not ignore or normalize that finding. This
   fixture is not the actual laptop recipe; production capture/delta/dependency
   closure remain separate mandatory checks.
5. Before any production gate claim, resolve internal topology, late hotplug/DMA
   limits and older authorized image/header bypass. Removing Distress does not
   remove these normal-device-gate bypasses. Do not solve them by quietly changing
   the existing TPM policy or signing keys.

## Checkpoints and permissions

Owner now explicitly authorized sudo for reading telemetry history, temperatures and
watts. That authorization is not permission to change boot policy, deploy enforcement
or rotate keys. Existing exact image/signing/staging/one-time boot-trial/promotion
checkpoints still apply. Do not clear TPM, edit LUKS slots, weaken PCR policy or
remove manual recovery. Keep work under this project. Safe implementation and
isolated tests may continue without repeated confirmation. Ask focused technical
questions only when needed; do not revive the removed Distress feature.

Use current test evidence rather than rerunning all unchanged suites. Last complete
Python run354PASS. Document source changes and exact guest outcomes. Return a
specific unresolved cryptographic decision to specialist review if needed; ordinary
preboot implementation and isolated failure testing belong to Sol.
