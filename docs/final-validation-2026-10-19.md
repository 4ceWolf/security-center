# Final safe validation — 2026-10-19

User requested testing followed by stopping work. All executed checks passed.
The project remains incomplete; unimplemented/interactive milestones below were
not tested or inferred successful. No installation, policy change, production erase,
administrator prompt, reboot or laptop sleep action occurred.

Evidence folder: /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l

## Executed checks

- Full Python suite:345passed,0failures.
- Three JavaScript suites: dashboard states/history, trusted-device workflow and
  telemetry download/clear-history/privacy/busy/error/focus/cache behavior.
- Actual Firefox synthetic fixture: local JSON download, Tab/Escape/cancel/focus,
  error recovery,320CSSpx at actual200% browser zoom plus540/1080px layouts.
- All six Arch image guest profiles passed:stock auto-unlock,masked observer,
  exit failure,timeout,OOM and manual recovery after actual virtual TPM refusal.
- Two additional integrated-recovery guests passed:success and failure checker,
  interactive wrong/cancel/timeout/correct recovery, signed-PCR negatives and
  encrypted-root switch-root. No disposable passphrase appeared in consoles.
- Offline disposable UKI construction/signature verification and corrupted-signature
  rejection passed. This is not a UEFI/Secure Boot execution test.
- Existing359-file observer capture verified;31-file/36-path review release verified.
- Telemetry worker crash/restart/graceful shutdown/degraded-storage rehearsal passed.
-35second temporary user-service resource rehearsal passed, real SQLite integrity
  check and graceful shutdown passed. MemoryPeak 10641408B;
 40MiB max,24MiB high,5%CPU,8tasks,0restarts and no OOM events. The trial was stopped.
  This is a disposable user-service test, not production DynamicUser attestation.
- Large synthetic raw/hourly exports passed; source database unchanged; process
  peakRSS 26416KiB including fixture construction. Browser/Cockpit excluded.

## Installed read-only verification

Collector and telemetry service remain enabled/active with0restarts. Cockpit socket
is enabled/listening and web service was inactive. Service properties are saved in
services-after.txt. Telemetry stayed fresh/current-boot with0consecutive failures;
samples advanced from 1220 to 1224 during validation. Hourly history remained available.
Secure Boot enabled flag and integrity lockdown observed. FIM reported0filechanges
and0unreadablefiles. Secure Boot flag alone does not attest the complete measured chain.

## Results by evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Full Python suite | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/python.log |
| ui.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/ui.log |
| trust-ui.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/trust-ui.log |
| telemetry-ui.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/telemetry-ui.log |
| browser.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/browser.log |
| export-budget.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/export-budget.log |
| offline-uki.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/offline-uki.log |
| worker-lifecycle.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/worker-lifecycle.log |
| worker-budget.log | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/worker-budget.log |
| Arch guest: success | PASS | /home/user/Projects/security-center/work/luks-vm-d1c33z75/report.json |
| Arch guest: masked | PASS | /home/user/Projects/security-center/work/luks-vm-gg4heiln/report.json |
| Arch guest: failed | PASS | /home/user/Projects/security-center/work/luks-vm-t6vpztne/report.json |
| Arch guest: timeout | PASS | /home/user/Projects/security-center/work/luks-vm-yig6hhyq/report.json |
| Arch guest: memory | PASS | /home/user/Projects/security-center/work/luks-vm-maasoet3/report.json |
| Arch guest: manual | PASS | /home/user/Projects/security-center/work/luks-vm-pvvra58e/report.json |
| integrated-recovery-failure.log | PASS | /home/user/Projects/security-center/work/luks-vm-wfubs0cy/report.json |
| integrated-recovery-success.log | PASS | /home/user/Projects/security-center/work/luks-vm-4ykldwvb/report.json |
| Installed live checks | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/live-checks.json |
| Release contents | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/release.log |
| Captured observer package | PASS | /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/observer-package.log |

## Deliberately outstanding

- Actual UEFI/stub/PCR phase execution and firmware Secure Boot acceptance/rejection.
- Physical laptop one-time boot/manual recovery,peripheral/input/Wi-Fi/sleep/wake/DMA.
- Authenticated live Cockpit,privileged on-demand helper and total signed-in memory.
- Production diagnostic download/erase; clear requires the owner to choose it.
- Installation/new exact baseline approval,USBGuard/AppArmor/OpenSnitch enforcement,
  strong Distress antirollback/PAM and recovery integration.

No test is claimed for an unavailable or unimplemented component. The eight guest
boots use test virtual disks/software TPM only; their root-volume/key operations
do not touch the laptop disk or TPM. Owner hardware and Astra checkpoints remain.

## State left behind

Production telemetry continues; no existing security service was stopped. The temporary
Firefox profiles/QEMU/software-TPM processes and resource-test user service are stopped.
Disposable evidence stays under the project. Older worker/budget summary files were
copied to this folder as previous-*.json before the tools refreshed their standard
work/telemetry reports. No production history was deleted. All new code remains staged.

Work is stopped at the user request. Resume from STATUS.md and the exact release
review in monitor-controls-release-review.md; do not repeat finished checks or infer
baseline approval from this test request.
