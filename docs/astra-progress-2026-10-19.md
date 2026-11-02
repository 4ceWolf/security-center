# Specialist continuation — 2026-10-19

Owner resumed work, requested no password/authentication prompts, and authorized a
swap-related baseline correction if necessary. No protected files were changed.

## Completed in source and read-only review

- Added tools/effective_initrd.py and nine tests, after documenting
  effective-initrd-design.md. Fresh image bytes are replayed in archive order,
  resolving archive-root symlinks, rejecting escapes/cycles, missing/invalid
  parents, root replacement and conflicting effective-path duplicates. Complete
  semantic deltas include directories and aliases. No extraction or signing.
- Full Python suite: 354 passed, work/astra-validation-2026-10-19.log.
- Applied strict review to the captured synthetic Arch fixture. It refuses
  usr/lib/firmware: early archive mode0700, main archive0755. Evidence:
  work/effective-arch-initrd-refusal.json. Do not silently normalize this conflict
  or treat the fixture as a production candidate. The production capture and
  dependency-closure work remain outstanding.
- Swap review: existing zram plus active8GiB /swap/swapfile; findmnt/lsblk place
  the file on the Btrfs root backed by the existing LUKS mapping. Root-peer
  collector reports zero monitored file changes/unreadable paths. Swap/fstab
  are outside current fixed FIM scope; no baseline replacement is needed for
  this observed change. work/swap-review-2026-10-19.json.

## Firmware work: measured phase evidence, unfinished acceptance

Added tools/test-uefi-phase.py after firmware-probe-design.md. Uses private copied
OVMF variables, fresh software TPM, read-only project-local virtual FAT, no network,
no physical disk/TPM/ESP and an unsigned UKI containing the complete test initrd.
Expected SHA256 PCR11 values come from extracted final UKI sections via the host
systemd-measure, not the running guest PCR. No credentials or encryption enrollment
are present in this probe. Each run has a bounded timeout and subprocess cleanup.

work/uefi-phase-jxib1zot/report.json records actual native firmware execution:
ConditionSecurity=measured-os accepted, native initrd phase active/success,
enter-initrd PCR11 exactly equals expected; stopping the native phase unit changes
PCR11 to the independently calculated enter-initrd:leave-initrd value. This is an
explicit service stop, NOT switch-root or cryptographic unseal-rejection proof.
That original report remains passed:false because SecureBoot/SetupMode variables
were unavailable in this OVMF build. Do not rewrite historical evidence.

Current probe distinguishes measurement_passed from Secure Boot state. Missing
variables are unavailable, never an enabled/disabled assertion. Secure Boot-capable
OVMF testing timed out before Linux. Early TPM SRK setup also failed in the guest;
this requires diagnosis before the encrypted-root acceptance test. Firmware runs
have shown startup hangs: a single successful measurement is not reliable overall
boot acceptance. Failed/hung runs and console diagnostics are retained under
work/uefi-phase-*. No successful Secure Boot or TPM-unlock claim is made.

## Remaining original scope

The original project is not in final installation-only cleanup. Read-only monitor,
FIM, event history, normal integrity boot and the telemetry recorder are installed.
Telemetry controls/resource bounds/passive-reader release is built but staged.
Native enforcement integrations and authenticated combined-memory checks remain.
The boot handover/device gate still needs full two-boot signed-policy/firmware
acceptance, production capture and exact image delta, topology/hotplug/recovery
validation, and legacy-image/header bypass resolution. Distress needs actual
antirollback authorization and owner recovery integration; prototypes do not count
as installed protection. Optional malware scanning is not deployed.

A conversational estimate of40–50% remaining reflects these major unfinished
features; it is not an engineering-time forecast or a measured completion metric.
See STATUS.md and the original project brief for scope rather than test counts.

## Telemetry request

Owner requested00:00–12:00 for the past three nights. Interpreted October17–19,
Asia/Karachi. Available current24h endpoint covers October19 completely; older
saved snapshot only covers October18 after14:00. Longer private history needs
administrator access; sudo -n refused and no interactive prompt was attempted.
See telemetry-review-2026-10-19.md for hourly readings and explicit missing fields.
All1440 reported samples carry a source-issue flag whose details are not exposed
by this endpoint. CPU/RAM/battery each have1440 numeric values. Do not claim full
source coverage or invent temperatures/process peaks/discharge measurements.

## Deployment and rollback

No installed code, baseline, TPM, LUKS, boot defaults, policy, PAM or signing keys
changed. Recorder remains enabled. No production telemetry was erased. Existing
review bundle monitor-iwww5mjl is unchanged; new offline tools are not part of it.
Rollback of this work means removing its project-local tools/tests/artifacts only.
No password, reboot or physical interaction was requested.
