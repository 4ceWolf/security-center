# Boot gate integration investigation — no live deployment

2026-10-15, installed systemd 262. The installed sd-encrypt build hook includes systemd-cryptsetup-generator, systemd-cryptsetup, TPM token plugin, TPM drivers and console password agent. Postboot systemctl cat systemd-cryptsetup@root.service finds no unit; this is not evidence that initramfs did not generate/run it.

Ran tools/probe-cryptsetup-generator.py unprivileged with a fake LUKS UUID, an empty fixture crypttab, SYSTEMD_IN_INITRD=1 and SYSTEMD_PROC_CMDLINE override. Output lives only in work/generator-probe-x644wwpv. No units installed, daemon reloads, devices opened, unlock attempts or host command-line changes.

Normal fixture generated a unit with ExecStart invoking systemd-cryptsetup attach testroot, the fake UUID path, no explicit keyfile and tpm2-device=auto. Its ordering includes cryptsetup-pre.target, udev and systemd-tpm2-setup-early.service, followed by the mapper blockdev target and cryptsetup.target. A second fixture containing password-cache=no instead of the TPM option preserves the structure with the changed options string.

This proves generator behavior only. It does NOT prove that removing the TPM option excludes all automatic key sources or that a manual passphrase was used. The manual branch must separately disable token/keyfile/credential/cache alternatives or invoke a verified manual-only API, then record actual successful method. Do not connect this fixture to the laptop's root volume.

A gate ordered merely Before=cryptsetup.target is insufficient: cryptsetup's own unit is also before that target and may race it. The gate must precede the actual attach invocation on every path. A failed prerequisite that prevents the whole cryptsetup unit from running is also insufficient because it can suppress the intended manual fallback. The design needs an explicit, tested choice of TPM-capable versus manual-only unlock, not just a failed condition.

Available test tools: qemu-system-x86_64, readable /dev/kvm, OVMF firmware files, installed Zen/LTS kernels. swtpm command absent. No test VM has yet been booted. A disposable VM must use an ephemeral fake disk, fresh test-only software TPM and test keys; never passthrough host TPM, real root disk or real signing keys. Network disabled, fixed memory budget, explicit timeout and cleanup. Future virtual-machine memory is a temporary testing cost and must be reported separately from the resident security stack budget.

Required VM matrix: TPM normal success, denied/unknown device -> manual path, scan error/timeout, manual wrong/correct secret, TPM absence, gate crash, alternate generator paths, distress trigger/power loss, storage replay, restoration failure, preserved original-policy semantics. Synthetic evaluator tests do not replace these.

Security blockers for live enforcement remain: antirollback preboot state, older signed/authorized UKI bypass, trustworthy device enumeration and TPM/manual evidence. Do not alter existing TPM enrollment or PCR7 + signed PCR11 policy to experiment. The next risky step requires a concrete reviewed design and recovery checkpoint.

Primary source for generator test environment: https://github.com/systemd/systemd/blob/main/src/cryptsetup/cryptsetup-generator.c . Local installed hook and actual generator output are authoritative for this machine.

Update: disposable guest manual-LUKS test now passes; swtpm and dependencies installed for the next stage. See testing.md and tools/test-luks-vm.py. Earlier missing-emulator/no-VM statements are historical.

Update: software-TPM guest auto-unlock and explicit manual-only mechanics now tested; changed virtual PCR7 blocks TPM unlock and manual slot0 still works. Evidence work/luks-vm-dzjo1q2e. Actual systemd gate and signed-PCR11 integration remain outstanding.

Update: signed-PCR11 with policyref initrd now passes isolated positive/negative tests, including wrong reference and reauthorization without reenrollment. Evidence work/luks-vm-jhcsdk9v. Actual measured UKI/Secure Boot, gate ordering and antirollback state remain untested.

Systemd PID1 ordering and service-result-to-manual dispatch are now VM-tested for both successful and failed check services. See testing.md. Combined systemd switch-root and production cryptsetup-generator replacement remain outstanding; do not equate the fixture with a deployed gate.

## Interactive recovery investigation
The guest harness now exercises the installed cryptsetup interactive terminal path, explicitly selecting manual slot0 and disabling external token plugins. No keyfile is passed to the interactive open command. A disposable pseudo-terminal supplies test-only input and verifies terminal echo is disabled before sending it. Tests cover wrong input, Ctrl-C cancellation, input timeout and correct input while a valid guest TPM enrollment/signature exists. The gate dispatcher must select only the manual callback, including when the actual check-service result is failed. Failure cases must leave no mapper; success must create one and report manual provenance.

The test harness verifies callback completion outside the dispatcher's exception handler, preventing a swallowed test assertion from masquerading as a successful negative test. Test-only secrets never come from the laptop. The fixture key has no trailing newline so it can be entered at a terminal; all existing keyfile/TPM scenarios continue to use the same disposable bytes.

This does not yet implement the production console ownership/password-agent integration. Multiple competing generated cryptsetup services, Plymouth/console handoff, repeated interactive recovery after cancellation and hardware keyboard availability need explicit integration tests. The production implementation should let cryptsetup own the credential input; the status daemon must never receive the passphrase. Preserve slot0 and prohibit automatic key sources on the manual branch. No host initramfs or enrollment was modified.

## Actual generated-service override in a disposable guest
Added vm-generated-unit.py and vm-generated-unlock.py fixtures. The installed systemd-cryptsetup-generator creates a service from a disposable crypttab entry for /dev/vda with valid TPM options. A drop-in clears ExecStart and selects the dispatcher, with Wants+After on the device-check service. The test loads this real generated unit in guest PID1, inspects the effective ExecStart, starts it with deliberately wrong manual input, confirms no mapper and a failed service, resets the failure, starts with the correct disposable key, confirms mapper creation, then stops the service through its generated detach command. Both adapter attempts must be manual only.

The first run failed because the newly added minimal udev daemon lacked device-mapper completion rules: correct mapping creation waited for a notification that never arrived. Added the installed 10-dm.rules and95-dm-notify.rules plus dmsetup to the guest. Kept failure evidence work/luks-vm-d0fm6o2x/report.json. The proposed Type override was removed after verifying the generator already uses oneshot/RemainAfterExit; it was not the cause. Corrected failed-check run work/luks-vm-s6bq1krn/report.json passed in14.6s.

Coverage limits: this is a generated service exercised in a minimal guest manager, with crypttab source /dev/vda and explicit noauto startup for test control. It does not test all automatic generator entry paths, UUID resolution, duplicate mappings, all stock initrd targets/udev rules, or the laptop's signed mkinitcpio/UKI. Some optional unit dependencies are absent in this minimal image. Do not interpret this as authorization or readiness to deploy a root-unlock override. The fixture manual adapter uses a guest keyfile; the separate terminal tests establish interactive behavior. Production must join these paths with correct console ownership and recovery before a reviewed boot candidate.
