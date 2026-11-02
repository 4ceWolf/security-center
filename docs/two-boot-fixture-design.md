# Two-boot measured LUKS fixture implementation — 2026-10-19

Implements the disposable portion of measured-observation-next-contract.md only.
Provisioning base is a fresh isolated mkinitcpio image with explicit formatting/
enrollment tools; target base is the earlier captured native observer image. Both
are fixtures, never production candidates (including the known duplicate-directory
metadata review conflict). Archive/capture hashes must match before use.

Build each complete UKI with one disposable public PCR key, private key retained on
host. ukify signs enter-initrd with policyref initrd, SHA256 only. Extract final
sections and calculate expected PCR11 independently. Provisioning contains a random
test key and selected target root filesystem; it formats only the virtual disk,
creates manual slot0, writes an ext4 root, enrolls PCR7 plus signedPCR11/initrd under
its valid current phase, then powers off. No TPM clear, slot wipes or policy bypass.
Target contains no provisioning script/key/private signer; generated stock root
mapping must unlock the same disk on a second firmware boot with persistent guest
TPM/VARS and no input. A dependency-only pre-unlock checker records phase/currentPCR
and preserves public signature for post-root negative check. Native observer remains
passive. Root checker verifies native PID1, actual encrypted-root backing, retained
observation, changedPCR11 and failed fresh second-mapping TPM attach after leave-initrd.
No target prompt or alternate unlock service is allowed as a success substitute.

Each image is entirely inside its UKI. Firmware uses fresh copied private VARS and
software TPM, project-only virtual ESP/data disks, no host block/TPM/ESP/key access,
no network. A signed-policy acceptance failure remains a failure; do not enroll
against target's current PCR, resign inside guest, broaden phases or weaken tests.
Manual-secret and private-signer bytes are explicitly excluded from target members.
Report stages separately, retain failed consoles and terminate bounded child processes.
Additional stale/wrong-ref/modified-policy/manual cases follow only after normal
stock target unlock/switch-root succeeds. Production checkpoints remain unchanged.
