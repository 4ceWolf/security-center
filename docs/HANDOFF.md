> Current entry point: [STATUS.md](STATUS.md), updated2026-10-19. The30-file
> candidate3464d566... was already explicitly approved and published on2026-10-18;
> older pending-approval statements below are historical. New staged releases
> need their own approval. See telemetry-controls-implementation.md for latest UI work.

# Paused at user request — 2026-10-14
Historical pause; user requested Continue on 2026-10-14. Work resumed after a confirmed reboot.

Completed: Phase 0 documents; runtime integrity trial; Arch Cockpit package installed with required dependencies; read-only collector and Security Center extension installed root-owned; loopback-only 127.0.0.1:9090. Source under this project. Freeze exception applies only here.

Integrity is NOT persistent. Shutdown/reboot returns to original unlocked-down boot configuration. No UKI, command line, PCR policy, LUKS token or slots changed. Preserve slots 0/2 and PCR7 + signed PCR11 policyref initrd. LTS deliberately unsigned.

MVP module checks now work: Secure Boot, lockdown, LUKS, firewall, services. TPM unlock method unknown; AppArmor absent; preboot gate/handover not implemented. Timeline bounded to latest 120 journal entries. Never call whole system verified.

Tests: five collector unit tests passed, JS syntax and systemd unit checks passed. Fixed isolated Python import path. LUKS status uses sysfs to avoid privileged device-mapper control. Restricted socket rejects unsupported requests. Host integration test PASSED before pause: non-wheel user denied socket access; stopping collector left firewall and lockdown active; collector restarted.

Memory sample before authenticated Cockpit UI verification: collector 45.5 MiB current (mostly reclaimable file cache), Cockpit service 7.7 MiB current; combined about 53 MiB. Peak collector about 48.5 MiB and Cockpit 11.8 MiB. Authenticated cockpit-bridge/browser memory not yet measured, so full UI-open budget is not established. User logged into Cockpit but UI has not been inspected.

Next: verify browser page, basic interactions, narrow layout, stale/error states, and actual total service memory with authenticated session; save test results. Update README status. Document installation rollback and record hashes already in backups/mvp-install.json. No new services should be added until MVP verified.

Then coordinate runtime hardware/sleep tests and explicit review of a separate signed UKI candidate for permanent integrity. Do not overwrite current good image, change signing keys or re-enroll TPM. Later phases remain design only, especially PAM, device gates, distress and TPM NV.

Continuation progress: user resumed after reboot; read-only checks and unit/UI-state tests completed. Source cockpit/app.js has a tested stale/error-state fix not yet copied to root-owned installation. Privileged read-only UKI inspection is waiting for polkit authentication (exec session 13330). Before boot-image work, user asked to confirm known manual LUKS passphrase and whether this boot auto-unlocked; no answer received yet. Do not regenerate/deploy boot security material without required review/recovery checkpoint.

Latest: owner confirmed auto-unlock and knowledge of manual passphrase. Candidate build and staging SUCCEEDED. tools/prepare-integrity-candidate.py and stage-integrity-test.py executed. Root report in /var/lib/security-center/integrity-candidate-20261014-235319. Candidate and original hashes recorded in changes.md. New Visor entry appended; default unchanged. Pending real test boot; see NEXT-BOOT.md. Root-installed Cockpit app.js correction confirmed deployed. No browser control capability currently available; live UI validation still pending.

Test boot SUCCESS: owner confirms auto-unlock/desktop; boot 25885964-3944-4827-af1a-6a0fc4803708 verifies lockdown=integrity with enforcement. Automated services/GPU checks passed. Await owner sound and sleep/wake/Wi-Fi test before normal image/build promotion. Keep original signed image recoverable.

Latest: owner compatibility tests PASSED; integrity candidate PROMOTED to normal image and future build cmdline. Original signed image kept in pre-integrity recovery entry; redundant test image deleted. Read changes.md and NEXT-BOOT.md. No normal-path reboot yet, but byte-identical payload booted successfully. MVP UI visual/authenticated-memory verification and remaining project phases are still outstanding.

Phase 2 read-only adapters now installed (14 modules total). See changes.md for testing and rollback. Headless desktop/narrow preview inspected, but actual authenticated Cockpit integration still needs user/live-browser validation. Temporary preview server stopped. Pear Desktop listener *:9863 observed, not changed. Remaining major work includes durable/searchable event history, real AppArmor/OpenSnitch/USBGuard enforcement planning, security auditing/FIM, trusted handover/device gate, and Distress Mode; none may be called complete.

Latest: persistent event history and search installed via tools/update-history.py. Root/wheel API exposes cached sanitized history, SQLite root0600 under /var/lib/security-center-monitor, max2000/30days. Read docs/event-history.md. Tests pass; live initial history available. Full incremental journald cursor ingestion remains pending, as do actual Cockpit authenticated validation, optional enforcement, FIM/audit, preboot handover/gate, distress.

Latest: initial read-only configuration audit deployed and live-verified (15 modules). See configuration-audit.md. Four sysctls/eight files+ancestors; kernel.kptr_restrict=0 flagged, unchanged. 16 tests and UI state suite pass. Peak collector ~48.5 MiB. Remaining: complete journal ingestion, FIM, broader audits/tool integrations, authenticated UI+memory, trusted handover/device gate/Distress implementation and recovery tests. Full goal remains active.

Latest: initial FIM scanner deployed, 16 modules; 17 fixed files readable. Baseline intentionally NOT created/approved. Next prepare a concrete baseline candidate, verify hashes against installed records/boot configuration history, and request explicit approval per implementation plan before accepting it. Further FIM directory policies/package attribution and other major stages remain. See file-integrity.md. 22 tests pass, peak ~48.5 MiB.

First FIM baseline candidate prepared, NOT approved. SHA256 fdf02980a1b203ba194962a409052560286172c13e3c46a8242ccf6f818d6add; 14/17 files match installation/promotion records, three boot configs current observations only. See baseline-review.md. Approval helper verifies exact candidate and current files, atomic no-overwrite publication; 25 tests pass. Await explicit owner approval before real acceptance.

## 2026-10-15 — owner-approved FIM baseline active
Owner explicitly approved the prepared 17-file candidate. Ran tools/approve-file-baseline.py with exact SHA256 fdf02980a1b203ba194962a409052560286172c13e3c46a8242ccf6f818d6add through pkexec. Re-scan matched the candidate; baseline published root-private without replacement. Next scheduled live snapshot at 08:37:11 UTC reported approved=true, 0 file changes, 0 unreadable files, history available. No monitored file changed during this operation. Later installed code updates will correctly require review/rebaseline; do not auto-accept.

Offline policies/device_gate.py added (NOT installed in initramfs or service). Exact multi-field device matching, transport-coverage requirement, duplicate/conflicting policy rejection, fail-manual malformed evidence, and distress manual-only semantics. Five new tests; 30 Python tests total pass. This is decision logic only; inventory provenance, topology classification, race handling, cryptsetup ordering, and real recovery/boot tests remain outstanding.

## 2026-10-15 — offline Distress Mode transition tests
Added policies/distress.py and tests/test_distress.py. Deterministic immutable transition model preserves original policy digest and requires separate recovery and later reboot/restoration evidence. 37 Python tests pass, including interrupted phases and policy conflict cases. No installed files or live settings changed; approved FIM baseline remains untouched. Strong preboot-visible persistence, antirollback, trusted evidence adapters, PAM and real failure/recovery tests remain required before deployment. See distress-mode.md.

2026-10-15 boot integration investigation: unprivileged installed systemd 262 generator probe passed for fake normal/no-TPM-option fixtures. Evidence work/generator-probe-x644wwpv/report.json; see boot-gate-integration-review.md. Establishes direct attach ordering requirement, not manual-unlock security. QEMU/KVM/OVMF present, swtpm absent. No VM booted, boot files changed, units installed or devices opened. Next work: isolated actual unlock/failure test harness with test-only TPM/disk; unresolved antirollback/old-UKI bypass remain live deployment blockers.

## 2026-10-15 — first disposable LUKS VM test passed
Created tools/test-luks-vm.py: unprivileged initramfs assembly from installed binaries and selected modules, fake 64 MiB disk, KVM/QEMU, 384 MiB guest memory, no network, no host block-device/TPM passthrough, 120-second process bound. Guest booted the installed Zen kernel directly (not Secure Boot), formatted only /dev/vda with a deliberately weak test-only PBKDF2 credential, rejected the wrong test secret, accepted the correct test secret, opened and closed an actual device-mapper mapping, then powered off. No user credentials were used. Return code 0 in 0.69 seconds. Evidence: work/luks-vm-io_5cw4m/report.json and console.log. Temporary 384 MiB VM allocation is separate from resident security-service budget. Test disk and generated initramfs retained for inspection; disposable artifacts may be removed after no process uses them.

Installed test dependencies through authenticated pacman -S --needed --noconfirm swtpm: fuse2 2.9.9-6, libtpms 0.10.2-1, swtpm 0.10.2-1. 0.86 MiB download, 2.75 MiB installed. Pacman verified signatures/integrity; package hooks ran sysusers/tmpfiles/udev reload and Snapper root snapshots 485/486. No TPM enrollment or boot settings changed. No emulator launched yet. Removal, if no other packages require them: review pacman reverse dependencies then remove these three test-only additions; preserve test evidence separately. Do not remove shared dependencies blindly.

Next: extend isolated VM with test-only software TPM, exercise TPM-capable versus manual-only unlock, then actual failure/order tests. First result proves manual cryptsetup mechanics in a guest, not TPM fallback, initramfs device-gate enforcement, real laptop manual recovery, or strong Distress Mode.

## 2026-10-15 — disposable software-TPM unlock and failure recovery passed
Extended tools/test-luks-vm.py with --tpm. Each run starts a fresh swtpm instance and state directory, connected exclusively by Unix socket to the disposable QEMU guest. Cleanup terminates/reaps the emulator in finally; no host TPM or host block devices are exposed. Test-only TPM enrollment binds PCR7 in a fresh guest LUKS volume; it does NOT reproduce the laptop's signed-PCR11/Secure Boot setup.

Initial TPM success run: work/luks-vm-4kpih_u3, return 0, 1.31s. Auto unlock succeeded; explicit cryptsetup --disable-external-tokens --key-slot 0 manual path rejected the wrong test key and accepted the correct key despite a valid TPM token. This establishes the low-level branch mechanics, not the final interactive password adapter or systemd gate integration.

First policy-mismatch attempt correctly FAILED the harness (work/luks-vm-fojs4oko). systemd-pcrextend returned success while explicitly skipping measurement because the guest was not booted with measured-OS support. TPM unlock therefore still succeeded. This was a test setup failure, not evidence that TPM policy ignores PCR changes. Replaced that measurement step with guest-only tpm2_pcrextend and before/after tpm2_pcrread comparison. Test secret files now mode0600 to eliminate permissive-mode warning.

Final run: work/luks-vm-dzjo1q2e/report.json and console.log, return 0, 1.75s. All required markers checked, including actual PCR change, TPM policy-mismatch rejection with no mapping, and successful explicit manual recovery afterward. VM and emulator exited; guest allocation 384 MiB. No laptop boot/PCR/LUKS/TPM settings changed. No installed Security Center files changed, so approved FIM baseline remains applicable.

Still untested: signed PCR11/initrd policy, Secure Boot VM chain, missing TPM path, actual device-gate invocation/order, interactive recovery password agent, persistent distress antirollback, and old authorized UKI bypass. Do not deploy this guest script on the host or represent these results as live laptop recovery tests.

## 2026-10-15 — signed-PCR11/initrd guest policy tests passed
Extended tools/test-luks-vm.py with --signed-pcr (implies --tpm). Fresh RSA keys generated only inside the disposable guest; no laptop signing material copied or used. systemd-measure signs the current virtual PCR11 value with policyref=initrd, and systemd-cryptenroll enrolls the disposable disk with direct PCR7 plus public-key PCR11 and initrd policy reference. Signature is checked during enrollment. Guest directly boots a kernel/initramfs; it does not use firmware Secure Boot or a measured UKI.

First signed run work/luks-vm-_ziwymzx passed in 2.8s. Extended run work/luks-vm-jhcsdk9v passed in 3.32s, exit0, every required marker present. Verified: valid signed policy unlocks; changed PCR11 makes the old signature unusable; freshly authorized PCR11 signature restores unlock without re-enrollment; same signing key with wrong policyref is rejected and creates no mapping; changed PCR7 still rejects TPM unlock even with valid PCR11 authorization; explicit manual slot0 recovery succeeds. Existing wrong/correct manual tests also pass with TPM token present.

384 MiB temporary VM, no network or host disk/TPM passthrough. swtpm/QEMU terminated/reaped. Keys created inside guest RAM disappear at shutdown; test TPM state and disposable disk remain under work for inspection. No host boot/enrollment/monitored-code changes. This models policy semantics, not the actual laptop boot measurements, trust handover, gate or Distress persistence.

Next: integrate policy choice and evidence handling into an isolated boot test, including device-scan failure and missing-TPM paths. Full live gate still requires trusted inventory, antirollback state/old-image bypass review and explicit recovery checkpoint.

## 2026-10-15 — policy-to-unlock dispatch tested inside VM
Added undeployed initramfs/unlock_dispatch.py: obtains a decision before calling an unlock adapter; only literal allow=true and manual_required=false permits TPM. Failed/exceptional decisions select manual directly. Failed TPM selects manual fallback. Adapter results must be literal True; failures never claim unlock. Adapters are responsible for deadlines, evidence provenance and serialization; this core is not a deployed security boundary.

Added tests/vm-gate-scenarios.py and --gate to tools/test-luks-vm.py. Guest contains the actual Python device policy and dispatcher. Synthetic inventories drive real guest TPM/cryptsetup operations. Verified invocation lists: allow -> TPM only; unknown external device/incomplete inventory/scan exception/distress -> manual only; wrong manual credential leaves mapping absent; missing TPM -> TPM failure then manual success. Device discovery and systemd ordering are not simulated by these claims.

Initial run work/luks-vm-uof6wb_f passed. Added a disposable-guest command-line marker guard to prevent accidental standalone host execution of the guest test script. Final run work/luks-vm-t_u0y7zc/report.json passed with all markers, exit0, 4.1s, 384 MiB transient guest. Includes all prior signed-PCR11/initrd, wrong-reference and PCR7 mismatch tests. 40 Python unit tests pass, including malformed decisions and adapter timeouts/failures. No installed collector, FIM baseline, laptop boot or TPM settings changed.

Remaining: real bounded inventory acquisition, topology approval, stable observation/hotplug policy, trusted decision provenance, actual systemd unlock-unit ordering/manual password agent, preboot antirollback state, Secure Boot VM chain and old-image bypass analysis before live checkpoint.

## 2026-10-15 — owner-approved mouse/keyboard receiver exception recorded
Owner says external attachments are charger and receiver, keyboard usually off, and explicitly asks to trust receiver. Live USB scan identifies A4tech 09da:0025 with no serial, mouse+keyboard interfaces. Saved undeployed policies/normal-devices.candidate.json using PCI controller + USB route canonical identity; see approved-receiver.md. Includes both interfaces, does not disable keyboard capability. Internal topology still unapproved, no live gate changes. Three tests verify normal acceptance, changed port/interfaces denial, distress rejection; 43 Python tests pass. This exception must be carried into the future actual inventory/gate integration, not forgotten or replaced by class-wide HID trust.

## 2026-10-15 — bounded USB inventory with stable receiver identity
Added policies/device_inventory.py, read-only and undeployed. Bounded sysfs attributes and directory enumeration, strict USB ID parsing, declared interface-count validation, PCI-controller/USB-route identity, two-sample change detection. Live host scan matches approved A4tech receiver exactly at pci:0000:00:14.0/usb:1, with keyboard+mouse interfaces and no serial. Also observes fixed camera and Bluetooth without silently approving them as internal.

Fixed device_gate.identity to preserve legitimate duplicate interface-class triples as a multiset instead of rejecting them. Live internal Bluetooth has two e0:01:01 interfaces; extra/missing interfaces still alter identity. 47 Python tests pass, including incomplete scan, attribute bounds, sample change, unknown transport coverage and interface multiplicity.

USB observation reports usb_observation_complete=true, but overall complete=false: Thunderbolt/external PCI coverage and trusted internal topology are still unresolved. Feeding this partial report to the gate denies TPM; it cannot accidentally green-light an incomplete full-system scan. Two matching samples are observations, not a hotplug lock. Root hubs are excluded and require separate controller topology validation. No boot/service installation or FIM baseline changes.

## 2026-10-15 — PCI/Thunderbolt observation and DMA coverage gap
Added undeployed policies/platform_inventory.py: bounded PCI identities/topology, Thunderbolt domains/router entries retained without trust classification, repeated-sample changes and missing buses treated as incomplete. Does not infer physical power-only, approved platform topology or DMA protection. 50 Python tests pass.

Live result saved work/platform-observation.json: 20 PCI functions, registered Thunderbolt bus with zero entries, no scan errors, no IOMMU group links. Further read-only kernel evidence: CONFIG_IOMMU_SUPPORT=y, CONFIG_INTEL_IOMMU=y, CONFIG_INTEL_IOMMU_DEFAULT_ON not set; firmware DMAR table exists; /sys/class/iommu empty; current kernel command line has no Intel IOMMU enable option. Therefore active DMA remapping is not established and must not be shown as secure. Firmware capability alone is insufficient. No kernel parameters or firmware settings changed.

Next decision: investigate/prepare an isolated DMA-remapping compatibility test and separate reviewed boot candidate if live IOMMU enablement is desired within the device-security design. Preserve approved FIM reference and existing signed recovery; such a boot change must use the explicit boot/recovery checkpoint. Empty Thunderbolt enumeration is not proof that every external PCI path is impossible. Internal topology baseline still needs verification across boots/power states before live gate deployment.

## 2026-10-15 — actual virtual USB enumeration to unlock integration passed
The --gate VM now attaches a QEMU xHCI controller and virtual USB mouse, includes the real device_inventory.py scanner and xHCI module dependencies, and enumerates kernel sysfs inside the guest. This is a virtual wired mouse, not a wireless receiver emulator or passthrough of the owner's receiver.

Guest assertions: exactly one USB peripheral discovered with complete USB interface evidence; with other-transport coverage supplied as an explicit fixture, the unapproved observed peripheral selects manual only; with the observed peripheral explicitly trusted, the actual partial scanner report still selects manual only because platform coverage is incomplete. Both cases use real guest LUKS operations and verify adapter call order and mapping state. No TPM attempt occurs on these denied decisions.

Evidence work/luks-vm-682nhujf/report.json and console.log, exit0, all required markers, 4.52s, 384 MiB transient guest. All earlier signed-PCR11/initrd positive/negative tests and recovery tests also passed. QEMU and swtpm completed/cleaned up. No live host enforcement, boot parameters, TPM state or monitored files changed.

Remaining integration gates unchanged: complete platform coverage approved across boots/power states, actual systemd dependency/serialization and interactive manual agent, boot-bound handover with honest trust level, rollback-resistant Distress state and old-image bypass evaluation. Current partial scanner must not be turned into complete=true in production.

## 2026-10-15 — boot-bound observation record implementation and VM I/O tests
Added undeployed initramfs/handover.py. Strict bounded schema, current kernel boot UUID, boottime timestamp, observed unlock method/ordered attempts, device-policy decision, explicit attested=false. Rejects contradictory claims, future/nonfinite timestamps, replay across boots, duplicate JSON fields and unknown provenance claims. Root-owned mode0700 directory and regular mode0600 file required; final paths reject symlinks, read size capped4096 bytes. Publish uses fsync plus no-overwrite atomic link; existing record is never replaced. Fixed trusted /run ancestry remains a future adapter requirement.

54 Python tests pass. VM scenario adapters now publish and consume real root-private records after each unlock outcome, check exact method and attested=false, reject cross-boot reads and duplicate publication. VM also rejects unsafe file permissions and directory symlinks. Full --gate run work/luks-vm-plj65_ze/report.json passed all prior TPM/USB tests plus VM_HANDOVER_IO_PASS, exit0,4.48s,384MiB guest.

Not deployed or integrated into dashboard. No claim of initramfs provenance from the file alone: privileged users can fabricate it. Same-boot replay/root forgery are not solved by boot-ID binding. Firmware/TPM verification claims remain separate and absent. Next test must demonstrate /run record retention through actual switch-root to mounted encrypted root; current VM tests producer/consumer within one early environment only. No host boot/service/FIM changes.

## 2026-10-15 — handover survives actual encrypted-root switch
Added --switch-root to the disposable harness (implies gate/signed-PCR tests). Guest now mounts /run as tmpfs, opens its disposable LUKS volume explicitly through manual slot0, verifies the mapping, publishes a root-unlock observation, formats/mounts ext4 within that guest mapping, copies test runtime files, moves /run and executes util-linux switch_root into a new PID1 shell on encrypted root. Post-root verifier confirms ext4 root, active handover_root mapping, same kernel boot ID, retained manual unlock observation and attested=false. No real disks/TPM passed through.

Initial retention test work/luks-vm-w_8mto9s passed using an earlier scenario record. Tightened it to publish evidence specifically after successful final root mapping; final work/luks-vm-c0ri8g6p/report.json passed, exit0, 5.34s, all prior TPM/gate/USB markers plus VM_HANDOVER_SWITCH_ROOT_PASS. Temporary guest RAM384MiB; disposable raw disk256MiB. VM shuts down normally and software TPM is reaped.

This proves controlled runtime-record retention across util-linux switch_root in a guest. It does not verify systemd's live mkinitcpio switch-root path, signed UKI provenance, firmware Secure Boot, root-forgery resistance, persistent Distress state, or real laptop manual recovery. Test secrets and freshly generated keys remain guest-only/test-only. No installed host files or approved FIM baseline changed. Next integration must preserve those distinctions and retain explicit boot-change review.

## Systemd ordering and actual service-result dispatch verified
Added --systemd-gate success|failure to tools/test-luks-vm.py. Real systemd PID1 executes a bounded oneshot device-check fixture, then a Wants+After dependent unlock-test service. The dependent service verifies the check completion marker and actual systemd active/failed state before running disk operations. Requires is deliberately not used for this fixture: a failed check must not suppress manual recovery. This is a proposed unit relationship in a disposable guest, not production cryptsetup-generator replacement.

First run work/luks-vm-peczn0d3 timed out before tests because minimal image omitted systemd-executor; systemd reported manager allocation failure. Added the helper and direct console logging. Subsequent ordering tests succeeded for both service outcomes (qv67ttdq and c15z96hh). Extended guest scenario to read actual service result: failure raises evidence error and dispatches manual only; success still requires actual scanner coverage, currently incomplete, and therefore also dispatches manual only. It checks adapter call order, unlock return and real mapping state.

Final evidence: work/luks-vm-e4ymgcsv/report.json failure-service case passed in7.03s; work/luks-vm-t2j13jly/report.json success-service case passed in6.68s. Exit0, all required markers including VM_GATE_SYSTEMD_SERVICE_EVIDENCE_PASS. Prior signed-PCR11, policyref, PCR7 mismatch, manual fallback and USB checks passed in both. 384MiB temporary guest. No host boot/security/FIM changes.

Combined real-systemd switch-root remains unimplemented (CLI rejects that combination rather than implying coverage). Existing util-linux switch-root retention test is separate. Production generated-unit integration, trusted device coverage, interactive credential agent, Secure Boot chain and antirollback/old-image bypass work remain required before deployment.

## Combined systemd-to-encrypted-root handover test passed
Enabled --systemd-gate success|failure together with --switch-root. Test image identifies itself as initrd, runs actual systemd PID1 with explicit default target, waits for device-check service before unlock-test service, then requests systemd SwitchRoot to the guest's mounted LUKS/ext4 root. Systemd carries /run into the new root; the post-root verifier consumes the root-unlock record and checks boot ID, method, non-attested status, ext4 root and live encrypted mapping. Final PID1 is a test shell, not the laptop's normal system manager.

Initial combined runs completed the guest checks, but the host reporter marked failure because terminal control sequences preceded VM_HANDOVER_SWITCH_ROOT_PASS on its line. Kept those failed reports; fixed the marker producer with a leading newline rather than weakening required assertions. Fresh final runs: work/luks-vm-e6hmkplb/report.json (failed check service, passed8.39s) and work/luks-vm-hgj9ds1f/report.json (successful check service, passed7.74s). Both exit0 and every required marker present. 384MiB temporary guest,256MiB disposable disk, no host block devices/TPM/network. VM and emulator cleanup completed.

This closes the earlier combined-systemd-switch-root test gap. Still not equivalent to production signed mkinitcpio/UKI integration or firmware Secure Boot. Real inventory trust, interactive manual credentials, persistent antirollback/old-UKI bypass, dashboard provenance and owner hardware/recovery tests remain outstanding. No host boot or installed collector changes.

## Incremental journal reader installed; replacement baseline approved
Replaced global latest120 sampling with bounded256 forward batches of allowlisted system-manager lifecycle entries. Exact cursor existence checked before resume; missing anchor creates coverage-gap event and replays retained30days. SQLite commits cursor and normalized events together; UI exposes backlog/unavailable/gap, private cursor never returned. Existing journal deletions between anchors may remain undetected; this is explicitly not a complete audit trail.

63 Python tests passed, including restart/batch/gap/spoofed-source, cursor rollback, exact-baseline replacement and prior-reference archive checks; UI regression passed. tools/check-journal-history.py read-only host verification recovered208 events in2batches and reopened DB each time. Same-limit transient systemd run passed:48.5MiB memory peak,7.1MiB swap. Actual root collector update started successfully; caught up with history/journal available, backlogfalse, no auto restarts. No host boot/TPM/enrollment/device policy changed.

Installed via tools/update-journal-history.py; rollback copies/manifest under backups/journal-before-u8bjwowr. Four changed installed files collector.py/history.py/daemon.py/app.js. Before update all17 approved FIM files matched. Prepared replacement with tools/prepare-file-baseline.py --replacement; user explicitly approved candidate168eeb6da0a25d26aed6c6f874ef9d08837d319502ab55f68f5a00061d60e151. Applied tools/approve-file-baseline.py with that candidate and exact previous baseline filedigest d1b47615c7eb18eba84b39c1ce156c8c2fd81c7c34c7c3cbe528f661f098fd62. Tool succeeded, checks scan exactly, archives prior baseline before atomic replacement. Review docs/journal-baseline-review.md.

Remaining: authenticated live Cockpit UI + whole-stack memory, production signed preboot/interactive manual fallback integration, full topology trust, persistent rollback-resistant Distress, and optional native security integrations. Do not mark goal complete. No old baseline approval should be reused for future modifications.

## Interactive manual recovery through the gate dispatcher verified
Added tests/vm-interactive-recovery.py to gate VM runs. Actual cryptsetup terminal input uses explicit manual slot0, external tokens disabled, no keyfile, one try and a2-second input timeout. A controlling pseudo-terminal verifies echo disabled before sending disposable input and checks the known test passphrase never appears in captured output. Wrong input, Ctrl-C and timeout fail with no mapping even while a valid guest TPM token exists; correct input opens the mapping and reports manual method. The dispatcher receives actual check-service failure evidence or an explicit manual decision; every scenario asserts zero TPM calls. Assertions must finish inside the callback and are checked again outside the dispatcher's exception handling.

The fixture keyfile now omits its trailing newline to permit typing the same disposable password. This only changes newly generated guest test disks/keys; host credentials and enrollment remain untouched. Initial direct-terminal run and preliminary dispatcher run passed; final strengthened assertions are present byte-for-byte in both final images.

Final reports: work/luks-vm-6emf4tej/report.json (successful service,15.77s) and work/luks-vm-0c7q0we8/report.json (failed service). Both passed all interactive markers, existing signedPCR11/initrd and PCR7 tests, USB decisions and actual systemd switch-root handover. Guest384MiB, no host disk/TPM/network; processes exited and emulator cleanup completed.63 Python tests also passed.

Not deployed into the laptop boot path. Production generated-unit replacement/console ownership, physical keyboard/manual recovery, retry behavior and firmware Secure Boot integration remain unverified; topology, antirollback and old-image bypass constraints remain. See boot-gate-integration-review.md. Installed collector and approved file baseline unchanged this turn.

## Generated cryptsetup service integration tested off-device
Actual installed generator now runs inside the guest to produce systemd-cryptsetup@generated_test.service with valid guest TPM options. Drop-in clears original ExecStart and inserts the tested gate dispatcher, Wants+After device-check.service. Guest PID1 loads/starts the generated service. Wrong manual key fails with no mapper; correct key opens it; generated ExecStop detaches it. Effective ExecStart checked; only manual callback observed. Unit uses explicit noauto fixture startup and /dev/vda, not full production UUID/automatic activation. Missing optional stock initrd targets are documented; no full mkinitcpio/firmware claim.

First run d0fm6o2x failed on correct-key attempt because newly running minimal udev lacked DM completion rules; preserved report. Added installed10-dm.rules,95-dm-notify.rules and dmsetup, preserving actual generated oneshot type. Final failure-service s6bq1krn passed14.6s; success-service7tu3k6jq passed12.5s. Final guest test scripts match workspace byte-for-byte. Existing terminal fallback, signedPCR11/initrd/PCR7, USB and switch-root checks passed.63 Python tests pass. Guest384MiB temporary; no network/host disk/TPM access; guests and emulators exited.

User's05:05 heartbeat permits unattended safe work only; do not request authentication, approval, reboot or hardware tests while asleep. Leave any such steps pending until user returns. This turn changed project test code/docs only; installed collector remains active with zero restarts and ~53MB peak. Approved baseline untouched. Remaining production boot/authentication changes retain existing review checkpoints.

## Design/build-first direction and durable Distress prototype
User explicitly requested continued work without prompts and recommended designing/building every system before implementation/deployment. Added docs/system-build-plan.md covering all major systems, authority/interfaces, failure gates, resource/privilege boundaries and separate deployment stages. No permission is inferred for pending risky changes. Continue safe local design/build/tests; do not prompt for auth/reboot/hardware/confirmation during this work.

Added undeployed policies/distress_store.py and tests/test_distress_store.py. Bounded canonical state,0600 durable atomic file publication followed by independent digest witness update, strict disagreement, explicit initial provisioning, sequence/policy continuity. Witness is an abstract trusted-adapter contract; fixtures are memory/file ONLY and confer no real antirollback security. Caller requires trusted private directory/ancestors, serialized authorized reducer transitions; no production TPM/PAM/shutdown adapter.73 Python tests passed, including child-process termination at all3commit boundaries and complete recovery cycle. Documented precise limits in distress-mode.md. No installed/approved-baseline files changed.

Next safe work: complete concrete hardware-witness design and old-authorized-image threat analysis, or native integration implementations/fixtures under project tree. Production adoption requires the existing explicit security checkpoints; do not represent a simulated witness as enforcement.

## Native confinement observation build
User returned and permits normal continuation; earlier design/build-before-deployment preference remains. Added docs/native-confinement-build.md contract before code. Added securityd/confinement.py and staged collector integration, plus fresh-install dependency list. Corrected prior misleading secure rating from merely one enforcing profile: coverage stays unverified. Bounded profile-mode counts and important-process observations use only comm/stat/LSM labels, no argv/environment. PID reuse, malformed labels, fallback provenance, truncated/unreadable samples handled explicitly.

82 Python tests pass (9new). Live read-only module reports AppArmor not enabled (kernel parameter N). AppArmor/OpenSnitch/USBGuard packages absent in local package query. No installation/boot/enforcement changes this turn and live approved baseline untouched.

IMPORTANT: staged collector now imports confinement.py. Do not rerun historical partial updater scripts against current source; they omit this dependency. Before deployment build a coherent upgrade manifest, include new file in FIM scope with explicit migration preserving17-file previous reference, then reviewed replacement baseline. Fresh install tool file list updated but not run. Project goal remains incomplete; native enforcement not installed.

## Coherent monitor release build
Added tools/build-monitor-release.py and seven tests. Fixed13-file source/destination mapping, bounded source reads, static stdlib/local dependency check, no final symlink/escaped member paths, per-file hashes and FIM coverage validation. Project-local release snapshot work/releases/monitor-ubz3zvzm built and verified. Staged integrity.PATHS now18files including confinement.py; installed scope/baseline remains17files untouched.89 Python tests pass.

No deployment. docs/monitor-release-build.md records build guarantees/limits and pending coherent updater plus explicit cross-scope baseline migration. Existing approve/prepare tools expect exact scope; do not deploy changed integrity.py then auto-rebaseline. Historical partial updaters remain unsuitable for current staged source. Next safe work can build/test17->18 scope migration and transactional updater entirely with temporary fixtures before review/deployment. Full goal incomplete.

## Baseline scope migration and rollback planning built
Added tools/baseline_migration.py pure validator: exact prior/release digests, old approved scope continuity, exact before/after scans, no removals/preexisting additions, reviewed release hashes/root0644, unchanged unrelated files, unapproved candidate carrying predecessor/release identities. Rollback planner refuses all operations on later-change conflicts and distinguishes restoring originals from removing newly installed files. No writes/privileged actions/approval implicit.

Nine new tests pass;98 project Python tests pass. docs/monitor-release-build.md updated with guarantees and explicit integration limits. Live17-file baseline remains unchanged; staged18-file release not installed. Need transactional executor/backups/crash recovery and actual reviewed scope migration before deployment. Do not treat this pure planner as an installed updater or user approval.

## Fixture transaction executor built and crash-tested
Added tools/fixture_transaction.py and8tests. Restricted marked disposable root, bounded relative target set, hashes/backups before journal, atomic fsync file replacement with planned metadata, resumable apply/rollback, preflight conflict refusal, no reapply after rollback. Child-process exit after each file and during rollback tested; restoration verifies bytes/mode/mtime and removes only added files.106 project tests pass.

No live installation/baseline/service changes. Explicitly not production installer: trusted fixture ancestry/serialized caller, no hostile-path-race protection or authenticated manifest; no service controls. docs/monitor-release-build.md records remaining production transaction/health/privilege and migration gaps. Keep user design/build-first preference and approval checkpoints; do not deploy this fixture against system paths.

## Actual packaged daemon/runtime and memory-limit rehearsal
Staged daemon main accepts explicit Python-call socket/database/owner arguments with unchanged production CLI defaults. Added tools/check-monitor-release-runtime.py: builds verified release, launches actual daemon via isolated Python, requires16modules, rejects invalidrequest, verifies private cursor absent, force-kills/restarts and confirms historical events preserved, checks socket cleanup and database-failure module isolation. No mocks for collector/history/socket behavior; current user permissions, isolated DB/socket. All child processes reaped.

Reports monitor-rhsxy4iv and monitor-a42nuir2 runtime-report.json passed with122events before/226after. Second entire rehearsal ran in transient user cgroup MemoryHigh48M/Max80M:48.4MiB peak,23.1MiB swap,3.752s,success.106unit tests pass. Latest packaged source snapshot monitor-a42nuir2 supersedes older snapshot for staged daemon changes. No installed files or baseline changed.

Still required: coherent privileged executor and baseline scope migration, root service/access hardening validation and authenticated Cockpit UI/whole-stack memory. Tests do not establish protected root evidence or production deployment. User remains design/build-first; no prompts needed for this isolated work.

## USBGuard observation adapter build
Extended staged adapters.py USBGuard beyond service presence: fixed read-only list-devices query only when active, bounded subprocess stdout/time, unique numeric ID + target + VID:PID parsing, opaque bounded attributes display, allow/block/reject counts with policy_verified=false. No auto trust or policy changes. User receiver fixture retains mouse+keyboard interfaces. Service absent on actual laptop; staged read-only call reports not installed.

116Python tests pass (10new tests). Packaged runtime monitor-ta3f179g passed all16modules, invalidrequest, crash history and databasefailure checks; subsequent helper change only made8s timeout injectable for actual timeout unit test. docs/usbguard-adapter-build.md documents primary references, tests and partial attribute-parser limits. No installed files/USB settings/baseline changes. New release snapshot needed to capture final staged helper signature before any upgrade; no live USBGuard integration proof yet.

## OpenSnitch configuration observation and native history correlation
Built fixed-default-path read-only rule inventory inside staged adapters.py. Bounded directory/file/aggregate bytes; no-follow opens and file/directory change checks; configured action/enable/precedence/operator-category metadata only. Names, filenames, descriptions, command/env matching data never exported. Always policy_verified=false; disk configuration not live-daemon enforcement. Primary upstream rule-format reference in docs/opensnitch-adapter-build.md. Native install/coexistence not performed.

History fingerprints now include OpenSnitch inventory and USBGuard decisions/counts; USB devices sorted by ID to avoid ordering-only changes.126Python tests pass. Packaged real-daemon rehearsal run this turn verifies latest bundle, crash/restart persistence and failure isolation; see newest runtime-report.json. Installed host files and18-vs17baseline migration status unchanged. No permission prompt or live setting change.

## Process module built,17-module packaged runtime verified
Added staged bounded process_observations in adapters.py, Applications UI grouping and finding-only history fingerprint.512PID bound,128findings max; stat/status/comm/exe-link only, no cmdline/environ/processmemory. PID starttime recheck; deleted link is review observation not malware claim; zombies counted even without exe while coverage remains incomplete. No process actions.

133Python tests (7new) and UI regression pass. Release monitor-2cr2som8 runtime-report passed17modules, crashrestart123->227events, invalidrequest, DBfailure isolation, socketcleanup. Read-only unprivileged live sample321metadata records,0deletionfindings,246exeunavailable/changed,completefalse. Details docs/process-monitor-build.md. No installed files/baseline changes. Latest staged release snapshot now2cr2som8; still requires coherent privileged deployment+baseline migration and root/liveUI validation.

## Staged preboot dashboard consumer integrated
collector.preboot reads proposed /run/security-center-boot/boot.json via shared initramfs/handover.py. Missing unknown, unreadable unavailable, invalid/stale attention; valid manual/TPM reports never secure/attested and can_authorize_actions=false. Shared parser already validates currentboot/schema/ownership/permissions/attempt order. No live producer record or gate deployed.

Canonical initramfs source maps to installed library handover.py in release builder/fresh installer. Staged FIM now19paths vs live17; release14files. Updated import closure checks and runtime runner to assemble declared library destinations rather than source layout; source journal tests/tools add initramfs search path.139Python tests pass, standalone journal subset passes. Release monitor-4ep_gn1n runtime-report passed17modules,123->227history persistence, badrequest/DBfailure/socketcleanup. No installed files/baseline/boot changes. Docs handover-design.md and monitor-release-build.md updated; previous18path migration plans superseded by exact latest19path scope.

## Diagnostic telemetry requirement added and first recorder built

User2026-10-16 explicitly requested battery percentages/discharge rates, CPU
heat/usage, busiest processes, RAM, averages and broad laptop diagnostics.
Design-first contract in docs/telemetry-design.md; scope added to system-build-plan.
New securityd/telemetry.py is standalone, NOT imported by installed/staged daemon
or release manifest yet. Finite tools/record-telemetry.py writes private local
work/telemetry/diagnostics.sqlite, with read-only --summary for latest/hourly means.
Default30s, up to24h/2880detailed rows,90days/2160hourly summaries,64MiB DB ceiling.
No argv/env/paths/serials/network contents/media/uploads. Process comm/PID/start
and approximateRSS retained; CPUone-core100%, no short-lived process capture.

First actual host capture3samples/2s:128metrics,18,928KiB peakRSS,0.115CPU seconds,
4.106elapsed,45,056-byte DB. CPU/percore, memory/swap, pressure, load, frequency,
filesystemcapacity, whole-disk/networkrates, sensors, battery and top5CPU/RAM.
Partitions with no diskseq explicitly omitted. Sensorhwmon indices may change
across boots; hourly mixedboot marker and rawbootID are not identityproof.
Sleep/longgaps/firstsample/reboot suppress rates; PID/network/disk counter identity
and resets handled. Missing sources explicit, no false zero filling.

156Python tests pass including17telemetry tests. Full-suite fixture initially
failed because another test set a stricter umask; fixture now chmods its intended
unsafe directory explicitly. FullDB test verifies transaction failure preserves
previous data. Standalone summary readback passed.
Synthetic retention run tools/check-telemetry-storage.py passed5208writes,
retained2880raw/2160hourly,44,298,240-byte DB,71.643s. Report
work/telemetry/retention-report.json. This exercised current host128metric set
with synthetic timestamps, NOT real92day testing. Its run began before the
small subsequent hourly mixedboot/issue metadata addition (unit-tested), which
did not alter retention logic. Temporary stress DB cleaned up, process exited.

No continuous recorder installed/running yet. Capture tool finishes after its
sample limit; do not imply ongoing collection. Next telemetry work: service
lifecycle/health, protected query/export/erase, Cockpit history charts, sustained
resource test and coherent deployment. No installed files, boot settings or
approved baseline changed. Live17file vs staged19file baseline scope still;
telemetry not yet included in release/FIM scope. Keep larger security goal active.

## Telemetry worker lifecycle and dashboard health (resumed after pause)

User explicitly paused, goal markedpaused; later explicitly saidcontinue. On
resume polled existing exec62645: completed successfully, not rerun. Actual
worker trial proved SIGKILL/restart2->4records, graceful stop, degraded DBpath and
recovery; childpeak23,876KiB. No surviving trial workers. Report
work/telemetry/worker-report.json.

Built telemetry_worker.py, proposed DynamicUser unit, Store exclusive private
DBlocks + workerlock, health publication/retry/shutdown.170Python tests pass
(7worker,7health added to156previous), UIregression pass. Unit systemd-analyze
verify passed. No production namespace/quotas/sustained battery/resource test
claim. Worker health errors contain exceptiontype only; no rawexceptions.

telemetry_health.py fixed backingpath /var/lib/private/security-center-telemetry/
health.json verifies nofollow/privatefile+parent owner, boundedpayload, types,
currentboot/boottime freshness. Statusrecording is unknown/nonattested; stale,
stopped,degraded attention. Integrated18thcollector module and Applicationscard.
No DBhistory API/charts/export/erase yet. Static service proposal remains
uninstalled/disabled. Fresh MVP installer copies newdependencies+unit but only
enables originalservices. Do not rerun freshinstaller onexistinginstall.

Coherent release now18files/23FIM paths vsinstalled17. Release
work/releases/monitor-4j9dftzg/runtime-report.json passed18modules,
124->233history crashrestart,invalidrequest,DBfailureisolation,socketcleanup;
58,740KiB childpeak (includes packaged daemon collectors, not fullstack).
After that run, runtimecheck requiredmodule set explicitly addedtelemetry; report
already confirms18modules. No shippedsource changes after releasebuild thisturn.
Docs telemetry-design and monitor-release-build updated. Livebaseline/service,
boot/TPM/LUKS untouched. Next: protected bounded telemetryhistory query/UI,
actual isolated service resource/permission rehearsal and coherent reviewed
baseline migration/deployment. Broader security/Distress goal remainsincomplete.

## Bounded telemetry history and user-authorized Logitech candidate

Added telemetry_query.py: fixed read-only hourly SQL, private location, bounded
record/output/cache/deadline, numeric summary validation, sample means/min/max,
explicit missing metrics/hours and mixed-boot indicators. Local capture tool
--history24/168/2160 performs only readback. Saved host DB readback passed
onehour/23missing. Staged daemon now returns default24hour/fourmetric history
with independent availability status; malformed/missing DB does not hide other
modules. No browser controls/charts yet. New file included in release/fresh
installer/FIM:19files,24paths versus live17. Release monitor-3ke_4sjk runtime
passed18modules,124->233events, failure isolation, invalidrequest, socketcleanup,
58,480KiB childpeak. Tests exercise query read-only hash preservation, bounds,
injection strings, corrupt data, missing files, deadline and daemon isolation.

The pending test session34196 no longer existed when checked after the user's
new request. Full suite rerun after receiver change:181tests pass, authoritative.

User explicitly requested trusting connected Logitech USB receiver. Actual
repeated sysfs observation and lsusb identify046d:c542 LogitechM185, no serial,
controller0000:00:14.0 route1, singlemouse interface03:01:02. Added exact identity
to normal-devices.candidate.json, preserving original09da:0025 entry. Evidence
work/logitech-receiver-observation.json and docs/receiver-trust.md. Test allows
exact receiver in synthetic complete normal inventory, refuses changedport or
addedkeyboardinterface, keeps distressmanual. Realfullinventory remainsincomplete.
No live USBGuard/preboot policy exists; trust is a user-approved staged candidate,
not active enforcement. No installed services, bootsettings or baseline changed.
Next: history UI, actualservice permissions/resources and coherent approved
migration/deployment; preserve larger unfinishedsecurity/Distress goal.

## Telemetry hourly UI built

Applied design-partner skill for narrow existing-dashboard implementation.
Added semantic Laptopdiagnostics table and labeled4metric selector in existing
index/app/style files.24hour slots, means/min/max/counts, missinghours/readings,
mixedboot/sourcegap coverage, stale/empty/unavailable states. Bounded scroll
region with preserved scroll position; no addeddependencies. Node UIregression
passes expanded telemetrycases, includingscrollpreservation. No Python changes
thisturn; last181suite result stillapplicable.

Firefox headless isolated projectprofile previews inspected at1280 and320px
using real savedtrial history plus mockedCockpit transport, labeledLOCALPREVIEW.
Artifacts work/telemetry-ui/wide.png andnarrow.png. Initialwide capture predates
28rem scrollingheight cap; narrow includesit. Both predate finalscrollposition
preservation/id-only change. No liveauthenticated/keyboard/screenreader/200%zoom
claim. Fresh release/runtime after finalUI change is newest monitor release;
see runtime-report.json. No installedfiles/baseline/boot changes. Release scope
still19files/24FIMpaths vs live17. Continuousrecorder stillnotenabled.

Next meaningful work: actualcontrolled telemetry service permission/resource
rehearsal, coherentprivileged deployment/approvedscope migration, additional
telemetry metric/history coverage and deploymentchecks. Larger nativeenforcement,
preboot/antirollback/Distress systems remainunfinished; do notmarkgoalcomplete.

## Actual worker cgroup budget rehearsal

Added tools/check-telemetry-budget.py, ran actual worker in ephemeraluserunit
telemetry-budget-ozil53vs.service,projecttempstate. EffectiveMemoryHigh24MiB,
Max40MiB,CPU5%(50ms/sec),Tasks8,NoNewPrivileges,RuntimeMax75s.35.35s ataccelerated
2s interval:18records,127metrics,peakcharge10,465,280bytes,swap0,CPU387,262,000ns,
zero high/max/OOM events and0restarts. Gracefulhealthstopped andSQLiteintegrity
passed. Work/telemetry/budget-report.json. Tool cleans unit andtemporaryDB;
terminalsession91202 confirmedexit0; subsequentunitstateinactive. No background
trial left. CPUquotaassertion addedafterrun; recorded50ms value satisfiesit.

Installed security-center stillactive0restarts,current48,181,248bytes,
peak52,338,688bytes. Cockpitwebserviceinactive/socketactive. This is notfullstack
200MB validation andnotDynamicUser/productionnamespace orlongtermpower test.
Cgroupcharge differsfromRSS; do notsubstitute10MiB forprior23.3MiBRSSclaim.
No shippedsource/installedfile/baseline/bootchange. Latestrelease remains
monitor-cxur12e7 (18modules,19files,24FIMpaths). Newhelper/documentation only.
Nextactualservicepermission/sandboxcheck stillrequirescontrolledprivilegedtest;
coherentupdater/exactreviewedbaseline migration andremainingnative/preboot/
Distress work stillpending. Goalactive, notblocked orcomplete.

## Concrete current-installed upgrade review prepared

Added tools/prepare-monitor-upgrade.py and5tests. It builds/verifies release,
scans exact24path scope, classifies all19releasefiles, attempts fixedrootprivate
baseline read and emits project-only review/JSON. Never grantsapproval/deployable;
missingbaseline is explicitlyunverified, not assumedclean. Checks exactscope,
metadata/hashdifferences, drift/additions whenbaselineavailable, no scope removal.

Actualreview work/upgrades/upgrade-15imz02u/review.md (plan.json alongside),
release monitor-qxrs91pf:7add8replace4unchanged0unreadable. Approvedbaseline
read PermissionError, so privilegedcontinuity remainspending. Prior17scope
history notsubstituted.186Python tests pass. No installedfiles/services/baseline
changed. Newrelease code is same shippedsource as prior runtimevalidated
monitor-cxur12e7; newhelper only is notpartofrelease. Reviewhashes/statedrollback
are notprotectedbackups orinstallationauthority. Next implement/rehearseactual
protectedroottransaction/servicehealth/rollback pipeline then exactcheckpoint;
user's design/build-first andno unnecessaryprompts remainapplicable.

## Protected file-operation layer implemented and failure-tested

Added tools/protected_files.py with productionroot constructor and separate
markedfixture constructor. Fixed19monitor-path allowlist matches release exactly;
boot/baseline excluded. Directory-fd traversal, nofollow, owner/writepermissions,
regular/singlelink/size/identity checks; atomic same-directory temp payload,
fchown/fchmod/optionalmtime/fsync, expectedstate recheck thenrename+dirfsync.
Exactexpectedstate requiredforremove. NoCLI/service/approval actions.

196Python tests pass (10new). Symlinkancestor/target,hardlinks,writablefile/dir,
concurrentcontentchanges, add/remove,restorebytes+mode+mtime,allowlists and actual
childexit before/afterpublish tested. Nohostrootmutations. Processcrash doesnot
provepowercut durability. Orphantemp possibleafterdeathbeforepublish; higher
transactionjournal musttrackcleanup. Caller stillmustholdprotectedrootlock,
savebackup/intent andproveaddedfile beforedelete. Rootpeers trusted/serialized
outsidehelper. Next integrate protectedtransaction journal withservice lifecycle,
postinstallhealth andexplicitbaseline approval. Existingfixture_transaction.py
stillfixtureonly; do notpromoteit ashostinstaller. Livebaseline/service/boot
unchanged; latestshippedrelease stillmonitor-qxrs91pf (samecodeasruntimevalidated
cxur12e7). No goalcompletion/blocker claim.

## Durable protected transaction library built

Added tools/protected_transaction.py. Fixed /var/lib/security-center-updates under
ProtectedFiles' heldroot; private0700dirs/0600files/nofollow/owner/singlelink checks,
exclusiveflock, pertransactionhexID, durable old/newpayloads thenpreparedjournal.
Before/afterhashes+metadata+plannedmtime allow resume afterrename-beforejournal.
Preflights ALL payloads/backups/currentstates before writes; apply idempotent,
rollback exactoldbytes/mode/mtime orremoveadded, refuse laterconflicts/reapply
rolledback. Beforemetadata must have restorablegid/mode. Reviewedreleasedigest
is continuitydata, notauthorization. Baseline/bootoutsidefileallowlist.

204fullPython tests passed; finalmetadatarestriction followedby18protectedtests
passing. Actualchildexits atintent/payloadfsync/publish/finalverification andduring
rollback allresume/restore. Tamper/exclusivelock/symlink/pathescape/lateredit cases
pass. Nohostrootstate creation orinstalledfilewrite: allmarkedfixtures. Newcode
is installer-libraryonly, notshippingmonitorrelease; lastreleaseunchanged.

Remaininginstaller work: service lifecycle + health coordination andcrashstates,
actualreviewedbaseline/release binding, protectedtransactionarchive/orphantemp
cleanup, coherentactivation andexplicitreplacementbaselinecheckpoint. Do not
expose libraryasdeploymentCLI yet. Larger native/preboot/Distress work remains.

## Service/file coordinator and live read-only health adapter

Added tools/monitor_services.py and service_transaction.py. Fixedtwo units,
rootrequiredformutations, noenable/disable. Capturesrunningbools, refusestransitional
states; failed/notinstalled are notrunning. Collectorhealth checks sameboot/fresh
schema/read_only, unique requiredmodules, historyavailable, SO_PEERCREDroot UID
and PIDequals serviceMainPID. Uses fixedGETsocket only. No overallsecure demand.

Durableservices.json phases around stop/fileapply/reload/restore/health; saves
priorrunningstate+oldmoduleids, preservesinactive telemetry. Onfailure rollback
files then priorrunningstate+oldhealth. Interrupt rollback resumesrollback.
Terminalreceipt idempotent, notnewlivenesscheck. Rollbackfailure propagateswith
pendingjournal. NoCLI/exposedauthority added; reviewedrelease/baseline binding
stillcallerrequirement. Telemetryspecifichealth foralreadyrunningrecordernotyet
implemented; currentinstalledrecorder isabsent/inactive.

211Python tests passed (7new). Serviceaction tests usefakecontroller+actual
protectedfixturefiles: startfailure restoresoldfiles,interruptedinstall/rollback
resumes, disabledtelemetry staysdisabled. No actualsystemdrestarttested. Live
readonlyadaptercheck passed existingcollector16modules/freshsnapshot/history,
rootpeerPIDmatchedMainPID. security-centertrue,telemetryfalse. Noinstalledfile,
service,baseline,bootmutation. Nextrelease/baselineauthorizationbinding and
cleanup/recoveryintegration, then controlledprivilegedvalidation+explicitbaseline
approval. Largergoalremainsunfinished.

## Exact reviewed-input binding implemented

Added tools/release_binding.py and10tests. Captured manifest/priorbaseline bytes
must match externallyreviewed digests; duplicatekeys rejected. Fixed19files,
exactdestinations/contenthashes/dependencyclosure/24scope, old5readonlysettings
retained, alloldmetadata/content matchesbefore,7newpaths mustbemissing. Private
unchangedbootfilepermissions preserved (initialoverstrict0644check was corrected
forreadonlypaths after inspecting realreview evidence). Identicaltargets excluded
fromwrites; fulltarget_contents stillavailableforwhole-releaseverification.

capture_bundle reads fixedmembers via nofollow and verifies SAME returnedbytes,
preventing re-readsubstitution. Realmonitor-qxrs91pf captureverified19files;
noinstallation. Tests221passed, including capturedbytesstableafter sourcechange,
changedsource recapturerefused, injectedtarget/payload/scope/digest/drift checks.
The actualrootprivatebaseline remainsunreadable; onlyreleasecapture waslive,
fullbindingtests useexplicitfixtures. No approval inferred/generated.

Stillneed deploymententrypoint binding these immutableinputs to protectedjournal,
currentrootbaseline read/scans underlock, protectedarchive/orphancleanup,
actualservicepermissionvalidation andexactreplacementbaseline approval. Service
coordinator alreadybuilt butnotyetcalledagainsthost. No installed/service/boot
changes. Shippingreleaseunchanged; tools/docs onlythisturn. Goalactiveunfinished.

## 2026-10-18: receiver reconfirmed and management design

Fresh host device_inventory observation matches the existing approved Logitech
046d:c542 receiver on pci:0000:00:14.0/usb:1, no serial, interface 03:01:02.
USB observation had no errors; full transport coverage remains incomplete.
No policy widening, duplicate entry, installed or boot changes.
User requested Cockpit trusted-device management. Recorded concrete workflow,
authorization boundary, pending/active distinctions and acceptance/build order
in docs/trusted-device-management.md. This is a design, not implemented controls.

## 2026-10-18: Sol candidate-management slice built; Astra review checkpoint

User switched to Sol Medium, authorized continuation and asked to stop/tell them
when Astra is needed. Built policies/trust_policy.py + trust_store.py and
on-demand tools/device-trust-helper.py, plus connected/saved/review/add/remove
Cockpit controls in existing UI files. Narrow fixed operations; Cockpit
superuser require, isolated Python, no automatic elevation. Root-private SQLite
holds candidate policy plus prior-policy/audit transactionally, exclusive lock,
200 audit records/64 MiB bound. Root actor only; not human attribution.

Adds are helper-observed exact identities, rechecked on apply; malformed,
ambiguous/partial observations, changed interfaces/ports and stale review refuse.
Removal works when disconnected. Internal entries preserved. Distress semantics
unchanged. User's Logitech matches live view (3 USB observations, 2 saved
receivers, Logitech saved+connected). work/trust-ui/host-observation.json.
Candidate save changes no USBGuard or boot policy; activation shown not deployed.

236 Python tests passed, both Node suites passed. Real child interruption tests
SQLite rollback/reopen; fixture helper dispatch integration. Actual nonroot CLI
returns authorization_required. Simulated Firefox wide/narrow screenshots
inspected under work/trust-ui; live Cockpit/elevation/keyboard/screenreader/zoom
and full memory target not verified. No new background service introduced.

Latest artifacts: work/releases/device-trust-18exhhl2 (6 files) and
work/releases/monitor-12mp6a1j (19 files/24 FIM scope). New helper's files, seed
and private state are not yet included in protected deployment/baseline handling.
Monitor-only install would leave management unavailable. No live files, service,
baseline, boot, LUKS or TPM changes. Older staged installer libraries remain as
before; entrypoint/cleanup/telemetry activation still pending.

Stopping at user's requested Astra checkpoint: review privileged helper/storage
and extend reviewed deployment boundaries before activation, then preboot/native
integration. See docs/trusted-device-management.md for exact behavior and gaps.
Goal is unfinished; this is a model handoff, not completion or an approval request.

## 2026-10-18: focused Astra security review completed

User requested Astra only for specialist work, then hand back to Sol. Reviewed
trust model/store/helper/Cockpit privilege boundary. Fixed loss-of-state fallback
that could reintroduce removed trust, persisted first seed/initialization metadata,
made production management require existing state, and preserved committed save
receipts when post-save USB scan fails. Nonblocking file opens before type checks.
Production bootstrap now requires Store(initialize=True), new directory, invoked
by reviewed installer only; Store() does not create missing directory/lock/DB.
Root rollback of the entire directory is outside this protection's guarantees.

242 Python tests passed. No live installation or boot/TPM/LUKS changes. UI unchanged.
Prior trust bundles are superseded by work/releases/device-trust-q_sjj4d9;
capture and review its exact manifest digest before any deployment.
Monitor-12mp6a1j remains the current UI bundle. No baseline approval inferred.

Next Sol work and deployment constraints are in docs/trusted-device-security-review.md.
Finish protected installer integration, explicit fresh-state initialization handling,
coherent trust/monitor package scope, telemetry and real authenticated UI checks.
Return to Astra for actual preboot/TPM/Distress architecture and activation review.
Do not redo this review solely to change models. User-requested handoff now reached.

## 2026-10-18: combined release deployed through protected runtime

Sol continued Astra's handoff. Unified fixed release/allowlist/FIM to 25 immutable
files / 30 scope paths (13 additions, 8 replacements, 4 unchanged against live
installation). Mutable trust SQLite state is outside immutable FIM. Retired the
old install-mvp.py bypass. Added monitor_deployment.py, trust_initialization.py,
root-only deploy-monitor.py CLI and hash-pinned installer capture/bootstrap.
Current runtime contains 14 source files including the reviewed trust model so
preserved state can be checked even after a file rollback removed helper code.

Deployment holds update + baseline-approval locks, binds captured baseline/release
bytes, saves backups and service state, records trust initialization intent,
restores old running services on failure, checks root peer/fresh 18-module health,
and emits only an unapproved candidate. Helper takes shared update lock before
imports and operations. Fresh private bytecode-prefix avoids stale project caches.
Only new /etc/security-center directory creation is allowed; rollback retains it
empty. Explicit baseline scope-expansion approval was repaired; it no longer
requires the prior reference to already have the new scope.

Native administrator authentication worked. Live prior baseline digest:
19f88b6f672ea2390c30a72b05d53e551aac5b21774025590dd3200e39cfc5f9.
First installed txn-dda0c8739edbc6fd60d0410a73d9b8ee; helper list and unsupported
operation checks passed. First telemetry start failed because DynamicUser's
root-owned StateDirectory symlink was rejected; validation stopped it and kept
startup disabled. Fixed worker to resolve only the exact root-owned managed alias
to the fixed private directory, preserving actual-directory ownership/privacy
checks. Added regression tests for exact alias, wrong target and wrong owner.

Actually rolled the first file/service transaction back and confirmed old health,
then prepared/applied corrected release monitor-18cuezjm, SHA256
93266f0ab6039ccbd0af047652f617486cab8831f9e8ad2ca29fc6331cf6aeb6,
using runtime-67ewzatg, SHA256
68efe5dad7923b5894fb6ba1551667776a696bc5c10aed75fb636cb9bd0118b2.
New transaction txn-6678cfb8b8fae4b4b0a5a78763e0adcf is installed/healthy and
awaiting explicit replacement-baseline approval. Root candidate SHA256:
3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee.
The old 6e57... candidate is superseded; do not ask approval for it.
Root candidate is in /var/lib/security-center-monitor/baseline-review/<SHA>.json.
No baseline approval, boot/TPM/LUKS or enforcement changes were performed.

260 Python tests pass. UI source unchanged after both Node suites passed. Actual
root prepare/apply, file rollback, service restart/old-health restoration and
corrected reapply succeeded. No file baseline drift was accepted or auto-approved.
Live telemetry validation is pending in the current turn; append its result before
claiming it records or is enabled. Authenticated Cockpit UI and full stack memory
verification remain pending. Telemetry export/deletion and advanced integrations
remain unfinished. Evidence: work/installer/*.{stdout,stderr} and protected journals.

### Live corrected telemetry validation passed

Captured validator a408d545545b9e479b369387840dda4d972dbd1d0496fe004c23f1244a4f80a2
ran through native administrator authentication. Corrected service recorded 2
samples at 30-second interval, zero collection/storage failures and zero restarts;
DynamicUser UID 64936, capability bound zero, 40 MiB MemoryMax. Database quick_check
and actual hourly query passed (1 populated hour). Service enabled at startup.
Recorder MemoryCurrent 10,297,344 B / MemoryPeak 11,608,064 B; monitor current
48,619,520 B / peak 50,900,992 B; idle Cockpit socket current 167,936 B. Combined
background current 59,084,800 B (~56.35 MiB / 59 MB). Cockpit web service inactive,
so authenticated full-stack/UI verification is not claimed. Root helper list and
unsupported-operation refusal passed; device candidates were not edited.

Replacement 30-file baseline remains UNAPPROVED. Exact owner review is now
available at docs/monitor-telemetry-baseline-review.md; candidate SHA256
3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee,
previous reference SHA256 19f88b6f672ea2390c30a72b05d53e551aac5b21774025590dd3200e39cfc5f9.
On owner approval, use the corrected tools/approve-file-baseline.py as captured
root code with those exact --approved-candidate-sha256 and
--approved-previous-baseline-sha256 values; the updated scope-expansion logic is
not an installed web action. Recheck current file metadata first; no silent
rebaseline. State/private DBs and startup enablement do not change that candidate.

Original project still unfinished. Sol can handle authenticated UI verification,
telemetry export/deletion controls, richer monitoring and installer cleanup.
Preboot/TPM/Distress remains Astra checkpoint. Keep current normal integrity boot,
PCR7 + signed-PCR11 initrd policy, TPM enrollment and manual LUKS recovery intact.

## 2026-10-18: local diagnostic export built while baseline approval waits

Previous goal turn made live deployment progress. The pending request for exact
30-file baseline approval has not been answered; an automatic continuation is
not approval. Installed immutable files and the candidate remain unchanged.

Added standalone tools/export-telemetry.py and nine tests. Read-only fixed-path
production CLI (admin required), separate fixed project --trial path, all metrics
hourly 1..2160h or raw 1..24h, process names/PIDs/peaks excluded unless explicitly
included. Closed export fields exclude arguments/env/exe paths/unknown fields.
SQLite consistent read-only transaction, query-only/trusted-schema off, 512 KiB
cache, 262 KiB rows, five-second deadline, row ceilings and 32 MiB private spooled
output. No partial JSON is emitted on validation/size/deadline failure.

269 Python tests pass. Actual saved trial export: 13,459 B, one hour, 128 metrics,
2,159 missing hours in a 90-day request; process details absent. Artifact
work/telemetry/export-trial.json. No production-data export, upload, deletion,
new root prompt or installed change. Recorder independently active/enabled,
zero restarts, 10,563,584 B current cgroup memory at the check.

Updated docs/telemetry-design.md with a current-status banner to prevent earlier
historical not-installed entries being mistaken for current state. Export contract
and privacy/resource/coverage limits: docs/telemetry-export.md. Production export
requires captured/pinned code before root authentication; do not execute mutable
project files as root. No installed helper/download UI exists for export yet.
Next baseline approval remains candidate 3464d566366ba1b7adde1957d4828073cefd959aab8dc164b082b440c3956bee;
never substitute a new candidate or infer approval from this continuation.

## 2026-10-18: next Astra checkpoint prepared

Previous goal turn made progress on read-only export (269 tests). Prepared focused
preboot handoff after re-reading actual gate/inventory code and current docs.
Fresh same-boot root-peer snapshot reports integrity lockdown and Secure Boot
variable enabled (not measured-chain verification). Sysfs: 3 USB, 20 PCI, 0
Thunderbolt entries, no platform sample errors; all-transport completeness false
and platform classification unapproved. Internal allowlist remains empty.
Artifact work/preboot-readiness-20261018.json. No installed/boot/TPM changes.

Next specialist questions are all-transport/internal/hotplug coverage, every TPM
unlock path and old-signed-UKI bypass, and the Distress/TPM witness trust boundary.
Exact current evidence/reusable components/checkpoints and ordinary-work status
are in docs/astra-preboot-handoff.md. Owner asked to stop Sol at this checkpoint
and reserve Astra for those decisions. Baseline candidate 3464d566... approval
remains separately pending; no approval inferred from automatic continuation.

## 2026-10-19 — Sol continuation: telemetry controls complete in staging

Current authoritative status: STATUS.md. Both receivers remain saved candidates;
preboot/USBGuard enforcement is not deployed. The old30-file candidate3464d566...
was already approved/published by the specialist follow-up in changes.md. Do not
ask for that approval again. Nothing in this turn changed the installed baseline.

Built Cockpit local JSON download/process opt-in/clear-history review, fixed
recorder/delete summary race, added fixed administrator helper and schema checks,
protected release/FIM integration, real browser download/keyboard/focus/error/320px/
200%zoom checks. Python345PASS after additional adapter memory bounds and new-module
deployment-health validation. Existing dashboard/trust plus new telemetry JS suites
pass. Large synthetic24hraw/90dayhourly exports complete with DB hash unchanged,
whole benchmark peak26,568KiB; no owner records read/exported/deleted by this work.

Latest unapproved release:work/releases/monitor-iwww5mjl (31files/36FIMpaths),
manifest f635d6df7cf81cd5b0fd03588a8594d861da2bcbd0f7625f89e77c93f4b07a00.
Captured installer:work/installer/runtime-80gg6yxk/runtime.json,
SHA34f3d508f18dd22fdbb9c2f75e000bee3d59f52f9644e39ae6b5270bc9367182.
No root prepare/apply/baseline migration for this release has occurred. It includes
previously staged passive-reader/UI code, not a laptop initrd observer installation.

Read-only installed service observation:collector37,695,488B,recorder13,438,976B,
idleCockpitsocket12,288B;51,146,752B total (~48.8MiB),zero collector/recorder restarts.
Cockpit web service inactive; full authenticated200MB target remains unmeasured.
No login/authentication/reboot/physical interaction requested. No process launched
by the completed browser/VM checks is intentionally left resident.

Details:telemetry-controls-design.md,telemetry-controls-implementation.md,
adapter-resource-bounds.md. Test/script outputs under work. Failed intermediate
browser/test runs are retained and distinguished from the final passes.

Sol owner-dependent next:reviewed captured deployment, new exact baseline approval,
authenticated UI and full memory verification. Astra next:measured-observation-next-
contract.md, firmware phase/Secure Boot guest execution and exact production image
boundary; preboot enforcement/hotplug/DMA/legacy image-header bypass; Distress
antirollback/PAM/recovery. User explicitly permits Sol to defer Astra tasks and
continue independent routine work. No cryptographic/authentication decisions made.

Prepared exact source/file review:monitor-controls-release-review.md. Current byte
comparison against recorded installed observations:7changed,18identical,6unobserved
previous bytes. These are packaging observations, not privileged baseline metadata.
No approval question sent; a fresh protected preflight is still required.

## 2026-10-19 — final validation; stopped at owner request

See final-validation-2026-10-19.md and /home/user/Projects/security-center/work/final-validation-2026-10-19-_jbygx_l/summary.json.
All executed automated/read-only/disposable checks passed; no live deployment or
production erase. Production telemetry stays enabled/running. User asked to stop
after tests; do not continue project work unless subsequently authorized.

## 2026-10-19 — owner resumed specialist work; no authentication prompts

Supersedes the previous stop-at-owner-request entry. See astra-progress-2026-10-19.md.
Nine new archive-alias tests, full354PASS; synthetic Arch image deliberately refuses
production review due to0700→0755 duplicate firmware directory. Actual UEFI native
enter/leave PCR11 measurements match independent expectations in jxib1zot, but
Secure Boot variables absent and other firmware runs hang; full acceptance remains
unfinished. tools/test-uefi-phase.py is test-only. No laptop boot changes.
Swap active on encrypted root; installed FIM clean, no baseline update needed.
User requested three midnight–noon telemetry windows: October19 summary available,
October17/18 inaccessible through unprivileged history. Details and source-issue
coverage caveat: telemetry-review-2026-10-19.md. Do not prompt for a password.

## 2026-10-19 — owner removes Distress; Sol owns normal preboot work

Distress Mode is out of scope, not deferred. Original brief now begins with an
explicit superseding scope amendment; README/STATUS reflect this. Historical
prototypes remain inert reference; none was deployed. Follow
sol-preboot-handoff-2026-10-19.md for the concrete next steps and unchanged boot/
TPM/manual-recovery checkpoints. Owner authorized sudo specifically to read older
telemetry including temperatures/watts; do not generalize to boot changes.

Authorized telemetry export completed: work/authorized-telemetry-8c6jo3k6/hourly.json.
25hourlyrows begin October18 at14:00PKT; earlier requested windows absent from export.
Full October19 midnight–noon temperature/power report:
telemetry-authorized-review-2026-10-19.md. Battery power0W while plugged in; no total
laptop watts measured. Authentication permission was for reading telemetry only.

## 2026-10-19 — current Sol firmware checkpoint (authoritative)

Full details: firmware-enforcement-results-2026-10-19.md. Monitor release is installed
and candidate523f21c3… approved/published as c1f12cc6…; no old approval is pending.
Protected transaction txn-39dca112763236821d3352cbde3a490f; FIM clean across restart.
New approved baseline means ordinary rollback CLI guard now refuses old baseline:
use a separately reviewed recovery sequence if ever needed, not blind rollback.

Completed guest Secure Boot3cases: work/secureboot-guest-r0yipipj/report.json.
Final two-boot observer-masked pass: work/two-boot-luks-uly1qq4h/report.json.
Actual encrypted-root TPM auto-unlock, native switch-root, exact independent
enter/leavePCR11 and failed second TPM mapping after leave. Saved signature/device
presence and policy-diagnostic checks passed. Private test manual credential stays
only in that trial directory, not in target image/reports. No host keys/TPM writes.

Normal observer times out underTCG5s cap (unchanged), so that profile is not passed.
KVM host/Haswell/plain/secure attempts did not reach firmware console; failures
retained. All child VMs/software TPMs must be stopped before handoff. Further
missing/stale/wrong-ref/modified-image/manual firmware cases are still pending.
354PythonPASS; source compile and actual final guest pass for subsequent fixture edits.

Working laptop capture: work/current-uki-qo1bvv4d. Public certificates only; outer
EFI and initrd PCR11/refinitrd signature independently verified. Actual initrd
189,358,649B; offline parser bound256MiB now permits inventory355+2069members.
Conservative effective validator refuses directory metadata transitions. See
raw-path-transitions.json; this is diagnostic, not approval or a merged filesystem.

Astra next: exact production control/candidate inputs and archive transitions;
normal gate hardware/internal/hotplug/DMA scope and older authorized image/header
bypass. No production signing, staging, reboot, TPM enrollment, slot edits, PAM or
policy weakening authorized by these test passes. Distress remains removed.
Routine remaining guest coverage may continue under measured-observation-next-contract.

## 2026-10-19 — Astra archive review and preboot decisions

See astra-preboot-decisions-2026-10-19.md. Added exact-image, exact-ordered
directory transition ledger support to offline effective_initrd review; strict
defaults unchanged. Current capture resolves2424records/2405paths/9transitions,
approved=false. Twelve affected tests passed (three new); no full-suite/VM repeat.
Result:work/current-uki-qo1bvv4d/effective-reviewed.json. Ledger:
docs/current-initrd-directory-policy.json. No installed or boot changes. Normal
gate limitations, remaining implementation and owner trial checkpoints documented.

## 2026-10-19 — Sol recipe capture and observer diagnostic

See sol-recipe-and-observer-2026-10-19.md. Read-only20-file recipe capture
work/boot-recipe-wih_9p_g confirms Zen hook override, no config drop-ins; full
runtime closure remains incomplete. New capture helper compiled and succeeded.
New TEST-only timeout diagnostic initially failed due omitted parent directory;
fixed, final work/two-boot-luks-lq4h6xp1/report.json PASS with30seconds. Observer
record survives measured TPM root unlock/switch-root and post-phase unseal fails.
Production5second timing remains unproved; no installed configuration changed.
Existing passing full suite and Secure Boot/masked cases reused.

## 2026-10-19 — owner removes custom preboot; unattended postboot work

Owner removed custom preboot gating/observation rollout from scope, preserving
existing Secure Boot/integrity/TPM/manual recovery. Distress remains removed.
Brief/README/STATUS/implementation plan updated; historical code/docs retained.
Owner then left and requested no prompts. No sudo/authentication requested.

Staged Cockpit automatic-unlock recovery review and stale/error handling; it clearly
says actual repair is not installed. No passphrase field or enrollment command.
Offline recovery preflight in modules/unlock_recovery_plan.py refuses missing
manual-passphrase/backup/cause/boot/policy evidence and always returns
repair_authorized=false. Actual authenticated repair remains unfinished; see
automatic-unlock-recovery-design.md. Do not reset a working enrollment for testing.

Collector/deployment health no longer require preboot or boot_observation modules;
17retained module identifiers. Historical readers remain; no preboot deployment.
Trust copy now describes postboot policy candidates. Existing installed UI remains
unchanged. Tests:5collector+5recovery-preflight+27adapter+9deployment Python PASS;
new recovery JS plus existing UI-state/trust JS PASS. Existing firmware/full-suite
passes reused, no VM run. Release static validation/build PASS.

Release work/releases/monitor-o8ib655z,31files/36FIMpaths, manifest
3a2fbd9154ced8a0845b1cab95fd0386898fe946eba0557241ebb0ae18c54764.
Unprivileged HOST comparison:27identical/4changed/0unavailable; see
work/scope-recovery-staging.json. No protected prepare/apply or new baseline yet.
New installer runtime work/installer/runtime-r5p6009t/runtime.json, SHA
12b63512241aa145834d7d34a5023f110f86463a6a44253e369a5c0ef8db167e.
Older runtime/module-count assumptions do not cover this release. Exact new baseline
approval is pending future protected installation, not available as a candidate yet.

Read-only current service/package/LSM audit completed. Collector/telemetry/firewall
active, no failed units; AppArmor/USBGuard/OpenSnitch absent; AppArmor disabled in
current LSM. Actual installs, USB/input compatibility, network coexistence, boot
maintenance, signed-in RAM and disk-repair auth remain owner-dependent. See
postboot-remaining-work.md. No production changes or extra resident services.

## 2026-10-19 — owner authorizes prompts; native packages and USB trial

Authoritative:postboot-installed-progress-2026-10-19.md. USBGuard/AppArmor/OpenSnitch
packages installed with normal signature verification (initial missing signature
resolved via exact Arch archive signature). No repo refresh/kernel upgrade.
Scope/recovery release INSTALLED in txn-bd7cbae1d23fdf074e3fd81482cafc7f,17modules,
exact candidate2039b424681401638c682d272df92dc44af2e5284bb76bb30c24191d72a2ca50
awaits the owner's already-sent approval question. Priorc1f12cc6… remains reference;
4expected changed files,0unreadable. Do not reprompt unless needed to clarify a reply.

USBGuard active RUNTIME trial only, disabled at boot; both saved receivers covered,
7current device states kept, new unknown devices blocked. Rules8allow+block.
Protected backup /var/lib/security-center-usbguard-trial-x8y8a10y; prepared guarded
rollback tool tools/rollback-usbguard-trial.py NOT executed. First trial's unsupported
runtime parameter query caused automatic rollback; corrected retry passed. Eight
native rule matcher cases passed. Physical receiver reconnect/input question sent,
pending. Do not enable at boot before that result. Candidate editor still does not
change active native policy; accurate copy/live management pending next reviewedUI.

OpenSnitch isolated namespace native queue-rule coexistence PASS, no hostnetwork/rules
changed, no real traffic/BPF proof. HostOpenSnitch/AppArmor remain inactive/disabled;
AppArmor LSM needs reviewed boot maintenance, not just package install. Collector+
recorder+USBGuard~65.7MiB current cgroup charge, excludes signed-inCockpit/OpenSnitch.
ActualTPM repair remains unfinished, no laptop enrollment or keyslot changes.

## 2026-10-19 — baseline approved, physical USB pass, persistent USBGuard

Owner approved candidate2039b424… and reported Logitech reconnect/mouse/internal
keyboard/touchpad all worked. Exact reference published1570242abaee6a65ce72adc914843ac0e0f74fc90938f8004d97e09e535f6997;
oldc1f12cc6… archived, currentFIM0changes/0unreadable. Do not re-ask these questions.
USBGuard exact tested policy active+enabled; future-boot service execution not yet
observed. Candidate editor/native policy bridge and native-config FIM coverage pending.

See postboot-promotion-2026-10-19.md. HostOpenSnitch before/deny/recovery trial failed
and automatically restored config/stopped daemon; currentlyinactive/disabled. No
approved functional app-blocking claim. No more blind retries: instrument queue
delivery/process attribution/rule load and cache state first. Native isolated queue
coexistence pass remains valid separate evidence. ThreeAppArmor profiles compile
offline against explicitABI4; LSM stilldisabled, no profiles loaded.
Background collector/recorder/USBGuard~56.2MiB current charge, fullCockpit200MB test
stillpending. ActualTPM-repair backend and credential-safe enrollment protocol
stillunfinished. No reboot/boot-image/TPM/LUKS/signing changes.

## 2026-10-19 — Intel GPU monitor check

User requested diagnosis. Unprivileged intel_gpu_top fails PMU Permission denied;
no CAP_PERFMON/file caps, perf_event_paranoid2. Administrator bounded sample PASS,
engineJSON/no errors under integrity. Inir ResourceUsage.qml disables Intel backend
after a sample with no busy value. See intel-gpu-monitor-diagnosis-2026-10-19.md.
No permission/global perf/boot/widget changes, no driver crash established. Fix not
applied; do not attribute change to recent package/security work without evidence.

## 2026-10-19 — GPU monitor fixed at owner request

User asked to fix. Root-owned intel_gpu_top now CAP_PERFMON only, ACL execution only
root/kyoUID1000. Normal-account sampling and exact widget command PASS; nobody
execution denied. Restarted onlyinir.service (active). Global perfparanoid2/integrity
unchanged, binary content unchanged. Owner-scoped package-update hook/helper installed,
manual hook action PASS, actual package upgrade not run. Protected metadata backup
/var/lib/security-center-gpu-monitor-kkeezrxp. No extra resident daemon. See
intel-gpu-monitor-diagnosis-2026-10-19.md for receipts/persistence/rollback and future
FIM coverage note. Supersedes earlier fix-not-applied entry. Larger postboot project
still pending as documented in postboot-promotion-2026-10-19.md.

## 2026-10-19 — owner requested protected header-backup relocation

Moved the16MiB home-directory .img to
/home/user/Projects/security-center/docs/recovery-backups/luks-header-before-tpm-reenroll.img.
Contents verified unchanged; root:root0600, directory0700; old home path removed.
Current recovery/TPM/brief references updated; .gitignore excludes protected folder.
No live disk header/TPM/slot or boot change. Receipt:work/header-backup-move.json.

## 2026-10-20 — repair deferred, TPM disable control installed

Owner deferred automatic-unlock repair to future ideas. docs/ideas.md preserves the
request/design; no reenrollment implementation or specialist repair test is now an
active completion requirement. Existing read-only recovery review retained.

Installed the requested on-demand disable control in Cockpit (refresh dashboard).
Administrator review, explicit acknowledgment, native disk-passphrase proof for
manual slot0, fresh root-private verified header backup, exact-state recapture and
one-token-only removal. Every keyslot/unrelated metadata field must be unchanged;
no keyslot deletion, TPM clear, boot rebuild, reenrollment or automatic reboot.
No credential is returned to browser/log/argv/file. No new daemon/polling. See
docs/tpm-unlock-disable.md for native-session assumptions and interruption/boot limits.

Tests: 11 transaction unit tests, 7 release tests, 10 release-binding tests,
9 deployment tests, 4 installer-capture tests, 8 protected-transaction tests passed.
Native regular-file disposable LUKS2 test passed: header backup readable, slot0 proof
before/after, exact synthetic TPM token removal, all keyslots/unrelated data preserved.
New disable UI and existing recovery review/UI-state/trust UI tests passed. Initial
trust/UI-state invocations omitted their required source argument; corrected runs
passed, with no code change. Historical passing suites were reused rather than
rerun wholesale. Native passphrase dialog and actual physical boot not exercised.

Release monitor-dgoalocr:33files/38FIMpaths, manifest
680ee30318c6fd33f6408818b8c62f85ec767c07f7e9d9c5f40728de71b4e2f1.
Installer runtime rhpf4v53:334f0f0c7a814a77e40314c337e5df10ce4b429191ddebe428bae602779c0e50.
Protected transaction txn-b81a137903c71e6b512b0266fcac3e2c installed successfully.
Six intended changed/added paths include trust-editor copy correction: candidates
are distinguished from live USBGuard rules. Device candidate behavior unchanged.
Root read-only installed helper review PASSED; token1 remains present. All33installed
file hashes matched. No disable invocation, disk credential prompt, enrollment,
keyslot, TPM, PCR, signing key or boot modification occurred.

Owner explicitly approved candidate
fbffa043adc034bac274eac983fbdf929b007f81b6b67f9a0e81c31d9fb0cb8f.
Published reference58eab555dda3f5b84f0192fa0f44a918c1a9f662a26f271819b83effa6a932db;
prior1570242a… archived. Final direct38-file scan0changes/0unreadable; collector,
telemetry and USBGuard remain active. Approval changes the file reference only;
automatic unlock remains enabled. Do not re-ask this approval.

Receipts: work/installer/unlock-disable-{inspect,prepare,apply}.json,
work/unlock-disable-installed-check.json, work/unlock-disable-baseline-publication.json,
work/unlock-disable-final-integrity.json. Review:docs/tpm-disable-baseline-review.md.
Broader project work remains as previously documented; this request did not activate
OpenSnitch/AppArmor or implement the native USB policy editor bridge.

## 2026-10-20 — native controls, approved reference and network scope change

Native USB editing is installed: exact-rule review, keyboard warning, two-minute
proposal, protected state/audit, future-reconnect behavior, and refusal to remove
internal/controller rules. Both saved receivers remain trusted. Real redundant-block
IPC append/remove test restored exact original policy and current authorizations.
Read-only installed helper/listing and keyboard-bearing receiver review passed. No
real receiver trust was removed as a test. Evidence: work/native-usb-ipc-test.json,
work/postboot-final-installed-check.json. USB policy SHA256 remains
544cb3ef7774b444206121e649cf956cdbf3d8094db984d5040ccca7c9fe4cff.

Owner approved offline AppArmor candidate, then separate test entry. Candidate SHA256
9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2,
normal image df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987.
Default entry0 and remember_last0 preserved, same kernel/initrd/public PCR key,
verified signatures, no LUKS/TPM changes or reboot. Dedicated two-profile unit is
installed disabled; package-wide AppArmor remains disabled. Actual trial boot,
compatibility, real enforcement and separately approved promotion remain pending.
Candidate/staging receipts: work/apparmor-candidate-build.json,
work/apparmor-staging.json. Promotion/enable/test tools are drafts, not runtime proof.

Protected final native-controls transaction txn-053efb44ae9c22599ab967192efcc6e2,
release monitor-6ktev0px (37 files/42 monitored paths). Exact candidate
2604fbc267c336aefb1ab4a15f9f626c489e148ab52719313ab5f34138c1fdab was owner approved
and published as b731cd86767d993ca744e91d18a14a20fc76074e96637bb29eff253d10b0e4d9.
Direct42-file scan found0changes/0unreadable. Earlier f45f5c59… was rolled back and
superseded, never published. Do not ask again for either historical reference.
Final service-stack measurements with Cockpit signed in:112.21–114.26MiB including
then-running OpenSnitch daemon; excludes browser/shared desktop/optional native GUI.

### Owner request: remove OpenSnitch; networking owner-managed

Package opensnitch1.7.2-4 removed with pacman -R only; no recursive dependency purge.
Its transient user GUI stopped; daemon disabled/stopped; its configuration, service
override, private verification state and prior native trial backups moved to the
root-only archive docs/history/opensnitch-removal-private-20261020. Private GUI config
is archived there too; no app rules, connection database or raw process data were
printed. Journal history is retained; no global log purge. Package/service/process
and autostart checks found no remaining active OpenSnitch. Existing
machine_care_guard table compared byte-for-byte using nft -s before/after: unchanged.
Receipt: work/opensnitch-removal-20261020.json. No other network policy changed.

Dashboard Open/Stop controls and collector OpenSnitch adapter are removed in source.
Read-only firewall/listener observations remain. Generic network_policy.py is now
an inert docstring-only compatibility file: no imports, operations or OpenSnitch
references. Keeping its fixed monitored path avoids silently shrinking the approved
integrity scope. Old implementation/tests are archived under docs/history; native
trial tools are retired there. Ideas/scope/user guide updated. Saved historical
records do not authorize reinstalling it. Running collector goes from17to16 modules.

Affected checks: adapters3, release binding10, deployment9, retained history5 tests
passed. History first run still expected removed OpenSnitch events; obsolete cases
were archived/removed and retained USB drift coverage passed. Real Firefox synthetic
USB fixture passed review/cancel/apply/keyboard/admin-denial/escaped-string checks and
asserted no network-launch controls: work/usb-controls-browser-en1is44m/report.json.
This does not claim automated access to the user's signed-in Cockpit browser.

Prepared removal release monitor-wsm8y_z1, manifest SHA256
 ee649315e177527e71911f191454f68bef35ce7c7d5e00b0c11f8281ebe981bf.
Captured installer runtime-7m2fkcuh SHA256
14c701fde8e065b8d90ca2a70de6581c8e5d45a1e5af7cb1ec5b407858bc635c.
Launcher: work/installer/run-network-removal-update.py. Installation/reference status
will be appended below. Current approved reference remains b731cd86… until exact
replacement approval/publication. Do not publish the previous candidate as this one.

### Removal handoff: application removed; dashboard deployment pending

The dashboard installer's read-only inspection requested a second administrator
password. No password was provided for several minutes, so only that unanswered
prompt was cancelled; inspect returned1 with no privileged writes. No removal-release
prepare/apply occurred, and no replacement candidate exists yet. Installed code and
approved reference remain the final native-controls version b731cd86…; it can still
show a now-uninstalled OpenSnitch observation/card. Do not claim dashboard removal is
installed. Package/daemon/GUI/config removal itself succeeded and is independently
recorded. Source cleanup and retained device/browser tests are complete.

Resume with captured work/install-network-removal-once.py: one administrator prompt
covers prepare+apply of the reviewed removal release. It preserves42-file scope and
records work/installer/network-removal-combined.json. Then verify installed files,
16-module snapshot, telemetry and USB integrity; prepare the exact replacement review
and obtain owner approval before publishing it. No exact approval is requested now
because there is no installed candidate yet. Seven release-validator tests also pass.
A passive post-removal service memory sample was59.98MiB across collector, telemetry,
USBGuard and cockpit.service; excludes browser/shared desktop and other Cockpit scopes,
so do not compare it as an identical aggregate to earlier detailed measurements.

### Removal dashboard installed after owner requested authentication

Owner said “ok prompt”; the combined captured installer succeeded. Transaction
txn-ca929f2f433d936114321f9000af4e24 applied monitor-wsm8y_z1. Candidate
350c5194000d7b1bb4c2f18bc1d60eb3a8f63909ab3053700cb7e13f578aedca replaces
b731cd86767d993ca744e91d18a14a20fc76074e96637bb29eff253d10b0e4d9.
All37 installed hashes match;16modules; no OpenSnitch module/package; persistent
history available; telemetry recording after the next refresh; USB7allowed/0blocked
with native policy/config unchanged and verified; integrity lockdown/firewall active.
The six reported FIM changes exactly match the intended dashboard/adapter edits.
No unreadable files. Exact replacement approval/publication remains pending.
Review: docs/opensnitch-removal-baseline-review.md. Receipt:
work/installer/network-removal-combined.json. Verification:
work/network-removal-installed-check.json, reusable work/verify-network-removal.py.
Earlier installation-pending statements are superseded by this completed transaction.

### Removal reference approved/published; final verification passed

Owner explicitly approved candidate350c5194000d7b1bb4c2f18bc1d60eb3a8f63909ab3053700cb7e13f578aedca.
Captured exact publisher returned0 and archived the prior reference. Receipt:
work/network-removal-baseline-publication.json. A no-prompt direct root-check attempt
was refused because authentication was not cached; no additional prompt or mutation
occurred. Instead, the already-running root collector's fresh11:16:02UTC snapshot
verified approved baseline,0file changes/0unreadable across its fixed42paths. All37
release-file hashes also match. Telemetry recording, USB7allowed/0blocked/0rejected,
native USB policy/config verified unchanged, integrity lockdown and default-drop
firewall observation intact;16modules and no OpenSnitch module/package. Evidence:
work/network-removal-installed-check.json. No removal approval remains pending.
The published JSON's separate whole-file SHA was not read; use a fresh protected
inspect for that digest before preparing any later installer transaction. Do not
mistake the candidate SHA for the separately serialized approved baseline SHA.
Networking is owner-managed. Remaining broader project gate is the separately staged
AppArmor runtime trial/compatibility and later explicit promotion, not this removal.

### Owner requested AppArmor testing — current boot still lacks AppArmor

Read-only pretrial check: /sys/module/apparmor/parameters/enabled=N; active LSM list
capability,landlock,lockdown,yama,bpf; current cmdline retains lockdown=integrity but
has no apparmor=1/explicit AppArmor LSM list. Both selected-profile and package-wide
AppArmor units are inactive/disabled. A kernel enforcement test cannot execute in
this boot. No profile was loaded, service enabled or reboot initiated. Earlier offline
compile/signature tests are not runtime enforcement evidence and were not repeated.
Unprivileged current boot-image/menu reads were denied; do not claim current hashes
were independently reverified here. Prior explicitly approved staging receipt remains
work/apparmor-staging.json. Check receipt work/apparmor-pretrial-check-20261020.json.
Next: owner manually selects the staged “Arch Linux Zen - AppArmor test” entry,
reports disk-unlock/desktop behavior, then inspect live security state and run the
bounded disposable enforcement test with administrator authentication. Keep normal
entry as default and recovery. No AppArmor promotion has been authorized/executed.

## AppArmor trial succeeded — exact normal promotion awaits approval

Kernel AppArmor=Y/LSM membership and integrity lockdown confirmed after owner reboot.
Owner reports automatic disk unlock, Wi-Fi, wake, keyboard/mouse and sound worked.
Disposable real allow/deny enforcement passed and cleaned up. Hash-pinned native
profile files and selected loader unit verified, then only avahi-daemon/lsb_release
loaded in enforce mode; dedicated unit active/enabled. Avahi inactive, not restarted;
lsb_release has no automatic attachment. Desktop-wide confinement is not claimed.
No failed units; FIM0changes/0unreadable; existing boot/TPM/LUKS state untouched.
Details/evidence: docs/apparmor-trial-results.md, work/apparmor-enforcement-check.json,
work/apparmor-selected-{enablement,runtime-check}.json.

Reviewed local enable tool now verifies exact installed unit hash and private lock
ownership/permissions before starting it. No installed source/code changed in this
stage; selected unit activation is the intended explicit runtime policy operation.

Initial normal-promotion read-only preflight refused insufficient free boot space for
its redundant two-copy procedure, before writes. Receipt preserved as
work/apparmor-promotion-review-initial-space-check.json. Revised promotion copies only
signed recovery then atomically renames staged tested image over normal, preserving
65MiB reserve and all other images. Revised read-only preflight passed. Normal and
test signatures/hashes, menu, future command-line source, current trial state and
manual LUKS slot0 verified. LUKS metadata only fingerprinted, never dumped to reports.

Exact proposal ef926c04fd7f2b1f80664f086ed2036324d3b9057de45dc848aeb1bfc749b34f;
source6646d848c9a42e75868768ed362ded52094995c034d2aa8e8448a9adc164afa1.
Concrete review docs/apparmor-promotion-review.md; read-only receipt
work/apparmor-promotion-review.json. Captured work/apply-approved-apparmor-promotion.py
is prepared but NOT RUN. Require exact owner approval before promotion; afterward
verify boot files/manual slot/metadata unchanged and prepare a separately approved
FIM replacement. Current boot normal/default and builder cmdline remain unchanged.

### Exact AppArmor promotion approved, applied and independently verified

Owner explicitly approved proposal ef926c04fd7f2b1f80664f086ed2036324d3b9057de45dc848aeb1bfc749b34f.
Captured work/apply-approved-apparmor-promotion.py returned0. Normal image is the exact
boot-tested9a3528a7…; signed previousdf39115e… retained as pre-AppArmor recovery.
Menu6e178f7e…; builder cmdlinec5591f72…; default0. No reboot or TPM/LUKS changes.
Receipt work/apparmor-promotion-result.json. Read-only independent root verification
rechecked all boot hashes, exact original LUKS metadata fingerprint, manual slot0,
two selected enforcing profiles and temporary profile absent. All41other monitored
files equal prior metadata/hash exactly; only /etc/miku-boot/zen.cmdline changed,
with original ownership/permissions. No release installation or scope expansion.

Current previous approved reference (read during protected preparation):
90b39d5e6cd95644644c9352e6e8f35389c995a5c84fd90a9e0a56353cd4aa25
(the approved OpenSnitch-removal reference; do not confuse with candidate350c5194…).
Prepared candidate91953e86a252e8e8def57031fe3490f8cbb4abbdf0dc76d291b78547a1097a6a,
42paths/oneintendedchange. Separate explicit owner baseline approval still pending.
Review docs/apparmor-final-baseline-review.md; preparation receipt
work/apparmor-final-reference-preparation.json. No candidate auto-publication occurred.
Normal-path reboot remains unperformed, distinguished from actual candidate boot.

### Final reference approved/published; scoped delivery complete

Owner explicitly approved91953e86a252e8e8def57031fe3490f8cbb4abbdf0dc76d291b78547a1097a6a.
Captured pinned publisher returned0 and archived90b39d5e… prior reference. In the same
privileged operation, independently scanned42paths:0changes/0unreadable. Current
approved reference f3eeb1556cc9ba9eeb43afddd5b88acb3202a8401ada26a53590d9e83b2cf5cf.
Receipt work/apparmor-final-reference-publication.json. No repeated approval needed.
Current STATUS/user guide/recovery/completion docs updated; no pending scope build or
approval remains. Normal-path reboot is unperformed, while the promoted image bytes
already passed actual trial boot and owner compatibility checks. Signed recovery
path has verified previous working image bytes, not a newly claimed recovery boot.
Do not continue deferred features, broaden profiles, reboot, or run duplicate tests
on an unattended continuation. Read completion-20261020.md and current STATUS first.

Final fresh collector snapshot11:28:13UTC also confirms0file changes/0unreadable,
0failed system units, telemetry recording, Secure Boot/integrity/encrypted root,
USB7allowed/0blocked/0rejected and2AppArmor profiles enforcing. Persistent history
available. Receipt work/apparmor-final-stack-check.json. AppArmor coverage remains
explicitly unverified for the wider desktop; its attention label is not an enforcement
failure or an instruction to load every package profile.

## 2026-10-21 — completed-project continuation retired

Scheduled continuation inspected current STATUS and the final handoff. The agreed
scope is already delivered; no construction approval is pending. No duplicate tests,
new scope, administrator prompt, reboot or security-policy changes were attempted.
Deleted obsolete discuss-laptop-security continuation automation so it no longer
wakes this completed project. Existing normal-path/recovery-path boot-test limits
remain documented; they were not inferred as performed. No user action is required.
