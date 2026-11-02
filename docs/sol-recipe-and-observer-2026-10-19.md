# Current recipe capture and observer diagnosis — 2026-10-19

## Read-only boot recipe captured

Authorized sudo capture: work/boot-recipe-wih_9p_g/receipt.json, recipe.json and
summary.json. Twenty bounded regular files captured, root ownership/nonwritable
ancestry verified, file identity checked before/after/current entry. The privileged
reader is literal source passed to isolated Python; it imports no project modules.
No captured config was executed. No private key file opened, no boot write or build.
Recipe SHA256:1494c5aa29c67098279e696cf1c8d2318b7288d8234ec72266db6c555b8f8a34.
Reader SHA256:a7ee878651535065d1a19aaf940ed19b57915ff87cf7c9a7a60d84c41f9c72cc.
New tool: tools/capture-boot-recipe.py. Source compilation passed.

The base mkinitcpio.conf selects udev/encrypt, but zen.conf overrides HOOKS with
systemd/sd-encrypt and retains Plymouth, autodetect, microcode, KMS and keyboard.
No conf.d drop-ins were present. Reproducing the base file alone would be wrong.
Plymouth selects themes/fonts/plugins dynamically; their input bytes, tool/library
closure and firmware/module selection are still required for an isolated control.
The20files are a recipe capture, not a complete reproducible-build input set.
The previous UKI capture remains the comparison reference; recheck freshness before
any later signing/trial. No signing or privileged build is authorized by this receipt.

## Test-only observer timeout diagnostic

Added --diagnostic-observer-timeout {30,60} to tools/test-two-boot-luks.py. Requires
normal observer; changes only an appended disposable-image drop-in. Production
service remains5seconds/64MiB. Report explicitly marks production timing unproved,
including if the relaxed run passes. Existing Secure Boot/masked/full-suite passes
were reused; not rerun.

First run: work/two-boot-luks-_ghfgxam/report.json, FAIL. Provisioning succeeded;
TPM-backed root reached native systemd and PCR11 before unlock matched, but observer
record was absent. The fixture had omitted the new drop-in parent directory, so the
kernel could not create that file. Corrected by appending the directory before the
drop-in. Also route this test-only observer's stderr to the guest serial console.
No production unit timeout or output destination changed.

Corrected run: work/two-boot-luks-lq4h6xp1/report.json, PASS with explicit
30second TEST timeout. Provision49.93s/target52.23s. Native enter/leavePCR11
match independent calculations; actual vdb-backed encrypted root auto-unlocked
without input; passive record survived; fresh second mapping rejected after
leave-initrd with signature present and policy diagnostic. This establishes
functionality under relaxedTCG timing only. The unchanged production5second cap
still has no passing firmware proof. Missing/stale/wrong-ref/modified-signature
and manual firmware cases remain pending. No laptop boot modifications.
