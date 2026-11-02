# Firmware and installed controls progress — 2026-10-19

## Installed monitor update complete

Owner authorized installation and approved exact candidate523f21c367cd83a30fa099249768f085b51997a51ea8472b20772921c4bdb1c5.
Protected transaction txn-39dca112763236821d3352cbde3a490f installed31files/36FIMpaths.
Published reference c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437.
Current post-restart snapshot again reports integrity lockdown, recording telemetry,
and zero changed/unreadable monitored files. Two saved receiver candidates preserved.
Live administrator export/privacy/unsupported-operation tests passed. No erase.
No new baseline approval is pending. See installed-controls-baseline-review.md.

## Actual disposable Secure Boot acceptance passed

work/secureboot-guest-r0yipipj/report.json.
Three cases passed: correctly signed image boots with SecureBoot=1/SetupMode=0;
unsigned and payload-tampered images receive explicit BdsDxe rejection. Native
enter/leave PCR11 measurements match the independent extracted-section calculation.
Fresh disposable PK/KEK/db and copied OVMF variables only; no host keys/firmware.
The first setup missed db enrollment and correctly failed signed acceptance. The
next signed attempt exceeded60s; the final bounded150s run passed in60.55s.
Negative cases stop on explicit firmware rejection, not absence of a Linux marker.

Tool: tools/test-uefi-secureboot.py, project-local virt-firmware26.9 venv under
work/firmware-tools-a169cjz6. Upstream: https://gitlab.com/kraxel/virt-firmware.
CLI reference: https://man.archlinux.org/man/extra/virt-firmware/virt-fw-vars.1.en.
No global package installation; private build dependencies do not run as services.

## Actual working laptop image captured and verified read-only

work/current-uki-qo1bvv4d/receipt.json and section-review.json. Current UKI SHA256
df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987.
EFI signature verified with the current public certificate; embedded PCR public key
matches the separately captured public key. SHA256 PCR11/initrd signature matches
policy calculated independently from extracted sections and its signature verifies.
No private key read, signing, installation or boot entry change.

Initrd is189,358,649bytes; offline parser stored-image ceiling raised128→256MiB
with all decoded/member/count/time limits preserved. Bounded inventory succeeded:
355earlymembers +2069mainmembers. Conservative effective-path review refuses
usr/lib/firmware mode conflict across segments. Existing known-good image remains
unchanged; this is a production review barrier, not an observed compromise.

## Two-boot measured LUKS: observer-masked case passed

Current final evidence: work/two-boot-luks-uly1qq4h/report.json and
work/two-boot-luks-final-negative.log. Separate provisioning and target UKIs booted
through OVMF with one persistent software TPM/VARS/data disk. Both native
enter-initrd and leave-initrd PCR11 values exactly match independent calculations.
The target has no provisioning script/manual secret/private signer, receives no
input, automatically unlocks the encrypted root and reaches native systemd on the
actual vdb-backed mapper. A fresh post-root second mapping fails with the saved
signature present and a policy-related diagnostic. No physical TPM/disk exposed.

The observer was deliberately masked: this proves its absence does not break stock
unlock and switch-root. It does NOT prove the normal observer case. The earlier
22w6sxfs run passed the same profile; the final run strengthens signature/device/
policy-error checks. Scripts: tools/test-two-boot-luks.py, tests/two-boot/*.py.
Provisioning fixture: arch-observer-build-xwx5shof; target base3ga34q76. All are test
fixtures, not laptop candidates. The random ASCII manual credential is retained
only in the private trial folder for later manual-recovery tests; never report it.

Normal TCG observer exceeded its unchanged5s cap and therefore did not retain an
observation. One early fixture checker15s cap was too short; raised to60s for that
TEST checker only. Real observer unit remains5s/64MiB. Another fixture root lacked
os-release/native init and was corrected without changing any laptop configuration.
KVM attempts with host/Haswell CPU and plain/secure firmware did not reach the
firmware console and were stopped or timed out. None is a passing boot test.

Missing/stale/wrong-ref signatures, modified initrd/manual recovery and the normal
observer on this two-boot path remain unpassed. Previous direct-kernel guest tests
are distinct evidence; do not combine them into a completed firmware matrix.
Further routine guest coverage is possible under the existing contract; production
image/signing, coverage/hotplug and legacy authorization remain Astra checkpoints.

## RAM evidence and limits

Earlier signed-in Cockpit cgroup observation charged1,085,800,448bytes, dominated by
~1GB file cache in the login scope. That is a real cgroup charge, not a200MB pass.
The session's observed processes together had about49MiB RSS; full contemporaneous
process breakdown was not retained, so do not infer a precise active-total pass.
Current session is closed. Fresh background-only observation:31,444,992 summed
process RSS,50,286,592 total cgroup charges. Details:
work/installer/authenticated-memory.json and authenticated-memory-breakdown.json.
The latter explicitly reports authenticated_session_present:false. No global
session/PAM policy or arbitrary memory cap was changed to improve a benchmark.
