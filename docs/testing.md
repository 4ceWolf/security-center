# Test ledger
PASS (inspection): host identified; actual Zen preset/config found; Secure Boot enabled; signed current Zen UKI; LUKS slots 0/2; TPM token references 2; header backup present/root-only; custom firewall active; Snapper root/home configs; all 212 loaded modules report signatures; kernel supports lockdown.
LIMITATION: module signer strings alone are not a fresh cryptographic validation of every on-disk module.
NOT RUN: owner manual-passphrase verification, signed fallback selection, TPM unseal-specific evidence, post-change reboot, sleep/wake, external peripherals, any preboot gate or distress test.
PASS: runtime integrity trial and automated GPU/service checks; see changes.md. Persistent boot enforcement NOT DEPLOYED.

MVP tests: collector exception/timeout/malformed output, stale status, access denied, daemon stopped, Cockpit unavailable, unprivileged access, path/command injection attempts, journal secret redaction, resource limits.
Later: firmware change, absent TPM, manual recovery, allowed/unknown HID/storage/hub, unplug races, interrupted distress transition, wrong credentials, normal reboot restoration, unauthorized reset/replay, old-image bypass. These require disposable-machine tests before live deployment.

## Post-restart continuation — 2026-10-14
New boot ID 9e3e9c00-8395-4406-bdfb-5b44a25bd9ad. Collector/socket automatically active, no restarts. Integrity reset to none as expected. Secure Boot, active encrypted root, token slot 2/PCR7/signed PCR11/initrd and actual firewall reported correctly.
Five collector tests pass again. New UI logic test passes fresh, unavailable, filtering after failure, stale, recovered states. This is a DOM test double, not visual/browser verification. Browser control tools unavailable in this continuation; signed-in page and responsive rendering remain unverified.
Latest sampled service accounting: collector 44,199,936 bytes, Cockpit 6,356,992 bytes (about 48.2 MiB combined). No authenticated cockpit-bridge running. This does not establish the logged-in footprint.
UI source fix prevents stale secure heading after a connection error and filter change; root-owned installed copy still needs deployment following administrator authentication.

## Successful integrity test boot
Owner reports automatic disk unlock and successful desktop login. Boot ID 25885964-3944-4827-af1a-6a0fc4803708. Verified embedded command line includes lockdown=integrity and runtime state is none [integrity] confidentiality. Collector reports current boot, Secure Boot enabled, encrypted root and active default-drop firewall. No failed system units. NetworkManager, Bluetooth, tuned, machine-care firewall and WARP active. intel_gpu_top produced GPU telemetry. Collector memory sample 45,236,224 bytes (~43.1 MiB); Cockpit inactive/on-demand.
Automatic unlock evidence is owner-reported, not inferred from a token. Sound and normal sleep/wake/reconnect owner checks pending before promotion to normal default/build.

## 2026-10-15 — initial configuration audit deployed
Added read-only audit.py, collector registration, evidence-aware history fingerprints and Audit navigation. No security policy changed or new service added. Deployment tools/update-audit.py succeeded with previous files/manifest retained in backups/audit-before; see configuration-audit.md for scope and rollback.
16 Python tests passed. UI fresh/error/stale/recovery/search/pagination tests passed after supplying the required app.js argument (initial invocation omitted it). Live installed API: 15 modules, 12 audit checks, one finding (kernel.kptr_restrict=0), zero unverified audit checks, no unavailable modules, history available. Service active, NRestarts=0, MemoryCurrent=10,870,784 bytes and MemoryPeak=50,835,456 bytes (~48.5 MiB). Authenticated combined stack memory remains unmeasured. No remediation applied.
Earlier live history restart test also completed: all 16 pre-restart events persisted; 18 events afterward and 14 modules at that stage.

## 2026-10-15 — bounded file-integrity scanner deployed
Installed integrity.py with 17 fixed files, 1 MiB per-file bound, symlink/special-file refusal and change-during-read checks. Added File integrity navigation and history fingerprints. No baseline accepted: status remains unknown pending explicit baseline review. All 17 files readable in installed service, 16 modules total. 22 Python tests and UI regression tests passed. NRestarts=0; MemoryPeak=50,851,840 bytes (~48.5 MiB), current=10,248,192 bytes. Source/installed deployment through tools/update-integrity-monitor.py, prior copies at backups/integrity-monitor-before. See file-integrity.md for limitations and rollback. No boot/authentication/security-policy changes.

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

## Interactive manual recovery through the gate dispatcher verified
Added tests/vm-interactive-recovery.py to gate VM runs. Actual cryptsetup terminal input uses explicit manual slot0, external tokens disabled, no keyfile, one try and a2-second input timeout. A controlling pseudo-terminal verifies echo disabled before sending disposable input and checks the known test passphrase never appears in captured output. Wrong input, Ctrl-C and timeout fail with no mapping even while a valid guest TPM token exists; correct input opens the mapping and reports manual method. The dispatcher receives actual check-service failure evidence or an explicit manual decision; every scenario asserts zero TPM calls. Assertions must finish inside the callback and are checked again outside the dispatcher's exception handling.

The fixture keyfile now omits its trailing newline to permit typing the same disposable password. This only changes newly generated guest test disks/keys; host credentials and enrollment remain untouched. Initial direct-terminal run and preliminary dispatcher run passed; final strengthened assertions are present byte-for-byte in both final images.

Final reports: work/luks-vm-6emf4tej/report.json (successful service,15.77s) and work/luks-vm-0c7q0we8/report.json (failed service). Both passed all interactive markers, existing signedPCR11/initrd and PCR7 tests, USB decisions and actual systemd switch-root handover. Guest384MiB, no host disk/TPM/network; processes exited and emulator cleanup completed.63 Python tests also passed.

Not deployed into the laptop boot path. Production generated-unit replacement/console ownership, physical keyboard/manual recovery, retry behavior and firmware Secure Boot integration remain unverified; topology, antirollback and old-image bypass constraints remain. See boot-gate-integration-review.md. Installed collector and approved file baseline unchanged this turn.

## Generated cryptsetup service integration tested off-device
Actual installed generator now runs inside the guest to produce systemd-cryptsetup@generated_test.service with valid guest TPM options. Drop-in clears original ExecStart and inserts the tested gate dispatcher, Wants+After device-check.service. Guest PID1 loads/starts the generated service. Wrong manual key fails with no mapper; correct key opens it; generated ExecStop detaches it. Effective ExecStart checked; only manual callback observed. Unit uses explicit noauto fixture startup and /dev/vda, not full production UUID/automatic activation. Missing optional stock initrd targets are documented; no full mkinitcpio/firmware claim.

First run d0fm6o2x failed on correct-key attempt because newly running minimal udev lacked DM completion rules; preserved report. Added installed10-dm.rules,95-dm-notify.rules and dmsetup, preserving actual generated oneshot type. Final failure-service s6bq1krn passed14.6s; success-service7tu3k6jq passed12.5s. Final guest test scripts match workspace byte-for-byte. Existing terminal fallback, signedPCR11/initrd/PCR7, USB and switch-root checks passed.63 Python tests pass. Guest384MiB temporary; no network/host disk/TPM access; guests and emulators exited.

User's05:05 heartbeat permits unattended safe work only; do not request authentication, approval, reboot or hardware tests while asleep. Leave any such steps pending until user returns. This turn changed project test code/docs only; installed collector remains active with zero restarts and ~53MB peak. Approved baseline untouched. Remaining production boot/authentication changes retain existing review checkpoints.

### Diagnostic telemetry stage (2026-10-16)
-156Python tests pass, including17new sampling/storage tests.
-Live finite capture:3samples,128metrics,18,928KiB peakRSS,0.115CPU seconds.
-Read-only latest/hourly summary round-trip passed.
-Synthetic92day+detail retention:5208writes;2880samples/2160hours retained;
44,298,240bytes. See work/telemetry/retention-report.json. No sustained-field or
whole-stack memory claim. No continuous service installed.

### Telemetry lifecycle and health integration
170Python tests and UI state regression pass. Proposed telemetry unit passes
systemd-analyze verify. Real worker SIGKILL/restart persistence, graceful stop,
storage failure/recovery passed (worker-report.json,23,876KiB childpeak).
Packaged18module collector runtime passed inmonitor-4j9dftzg; history124->233,
invalidrequest/DBfailure/socketcleanup checks passed. No installed-service or
whole-stack memory validation implied. Stagedrelease18files/FIM23paths.

### History query and Logitech candidate
181Python tests passed. Read-only history round-trip over saved host sample
passed. Packaged runtime monitor-3ke_4sjk passed18modules and crash/restart
history preservation. Logitech exact-match/changed-port/extra-interface/Distress
cases pass against synthetic complete inventory; no live enforcement claim.

### Telemetry resource limits
Actual worker in temporary user cgroup passed35.35s/18samples at2sinterval,
24MiBhigh/40MiBmax/5%CPU/8tasks. Peakcharge10,465,280bytes,swap0,
CPU0.387262seconds,zeroOOM/restarts/limit events. Graceful stop andSQLiteintegrity
passed; temporaryunit/state cleaned. See work/telemetry/budget-report.json.
Not productionDynamicUser orwholeCockpit-stack validation.

### Concrete upgrade review
186Python tests pass including5review tests. Actual installed fixedpath scan:
7additions,8replacements,4identical,0unreadable;24pathscope. Baseline permission
failure explicitly marks continuity unverified. Review is project-only and grants
no deployment/baseline approval. No service or installed-file mutation performed.

### Protected monitor file operations
196Python tests pass, including10new protected-path/atomic-write tests. Actual
childexit before/afterrename leaves complete old/new payloads. Exact restore
bytes/mode/mtime, concurrent-change refusal, symlink/hardlink/unsafepermissions
and allowlist boundaries checked in disposable fixtures. No hostroot writes or
power-failure test; caller transaction/backup/service integration remainspending.

### Protected durable transaction
204fullPython tests passed;18protected tests repeated successfully after final
metadata-restoration restriction. Realchildexit at intent/payloadsync/rename/
finalfilecheck and duringrollback: resumableapply andexactrestore passed. Backup
tamper, duplicatewriter, statepathsymlink/escape andlatereditconflicts refused.
Disposable fixture roots only; no live privileged deployment claimed.

### Service coordination
211Python tests pass. Simulated service lifecycle plus protected fixture files
covers startupfailure/rollback, interrupted apply/rollback andinactive recorder
preservation. Actual read-only live collector check passed rootpeer/MainPID,
currentboot/freshness,16module response andhistoryavailable. No live restart or
DynamicUser deployment validation claimed.

### Exact reviewed release/baseline binding
221Python tests passed,10binding cases. Actual19file release capture verified
same returnedbytes without installing. Rootprivate baseline notread, so full
livebaseline continuity is notclaimed. Privateunchangedboot modes and identical
installed-file preservation checked; substitution/drift/scope changes rejected.

### 2026-10-18: trusted-device candidate management
236 Python tests pass (15 added policy/store/helper cases). Exact observed
identity, changed interface/port/disconnection, stale policy, duplicates, malformed
input and oversized input are covered. Store tests include retained previous
policy/audit, stale second writer, transaction failure after audit, symlink/
hardlink/permissions, exclusive lock, and actual child exit with an uncommitted
SQLite transaction. Helper dispatch tests cover list/review/apply/remove, forbidden
fields/operations, observation recheck; actual unprivileged CLI refuses access.

Both Node suites pass. New management suite covers no automatic elevation,
fixed argv/require-root, review/cancel/add/save/remove, keyboard warning, focus,
authorization denial, in-flight exclusion and unavailable-helper states. Firefox
simulated previews at 1280/320 CSS px were inspected. This is not authenticated
Cockpit or real keyboard/screen-reader/zoom verification. Host observation was
read-only; Logitech matched saved candidate. No privileged installation or boot
change performed. Whole-stack 200 MB verification remains pending.

### Focused Astra trust-state recovery review
242 full Python tests passed. Added six regression cases for persisted seed,
lost/empty database, missing policy, no implicit production bootstrap and a failed
scan after a committed save. Existing process-crash and state/identity tests pass.
No installed or boot state changed; authenticated helper deployment remains pending.

### Combined protected deployment and DynamicUser compatibility
260 Python tests pass, plus both Node UI suites passed before the worker-only
production fix. Added deployment orchestration, immutable installer capture,
new fixed seed-directory and expanded-baseline approval tests. Real host root
inspection, protected prepare/apply, rollback with old monitor health restoration,
and corrected reapply passed. No replacement baseline approved.

Initial actual DynamicUser start failed on its managed StateDirectory symlink;
validation stopped it. Worker now accepts only that exact root-owned alias to
its fixed private path and retains ownership/privacy checks on the target.
Unit regressions cover accepted alias, rejected target and rejected owner.
Actual second start/recording verification is still pending as of this entry.

### Corrected live recording and installed helper
Actual second DynamicUser start passed: two samples/30s interval, no failures,
nonroot UID, zero capabilities, 40 MiB limit, no restarts. Private DB quick_check
and populated hourly query passed. Enabled at startup. Current monitor+recorder+
idle Cockpit socket memory 59,084,800 bytes; authenticated Cockpit was inactive.
Root collector 18-module health and installed helper list/refusal passed. No actual
Cockpit add/remove interaction or full authenticated-stack budget claim.

### Read-only diagnostic JSON export
269 Python tests pass. Nine new export cases verify raw/hourly values/coverage,
private process default/opt-in with secret-bearing unknown fields omitted,
time-window filtering, unchanged DB bytes, missing/private/link checks, malformed
and nonfinite records, deadline and output cap with no partial success. Actual
saved host trial exported 128 metrics in one hour, 13,459 bytes; missing hours
remain explicit. No production export/download or deletion verified. Live
recorder remains active/enabled with no restarts; baseline approval still pending.

## Generated service with interactive recovery — 2026-10-18

New `tests/vm-preboot-integration.py`, selected by
`tools/test-luks-vm.py --systemd-gate failure --switch-root --integrated-recovery`,
joins actual generated-unit execution with terminal-owned cryptsetup input.
The guest reuses the generated service/drop-in and udev setup, then replaces its
keyfile fixture adapter with an interactive adapter. Four sequential starts cover
wrong input, Ctrl-C, input timeout and correct input. Checks require an actual
hidden-input prompt, expected command result and mapper state, manual-only attempt
receipt, and successful detach. All input is disposable; the laptop passphrase,
disk and TPM are never exposed. The full guest still exercises the existing
software-TPM/signed-PCR11 tests and systemd switch-root handover tests.

Initial run `work/luks-vm-vq1o738t/report.json` failed when reset-failed was called
on a service already unloaded after stop. Corrected the harness to load/query its
state and reset only a failed service, and isolated the setup script in a child
rather than sharing Python globals. Corrected failed-checker run
`work/luks-vm-h3mvwixc/report.json` passed all four integrated recovery cases plus
all previous markers, exit0,21.23s. Test VM uses384MiB temporarily, no network,
host block devices or host TPM. The supervisor also rejects a test secret appearing
in captured guest console output in subsequent runs.

Limits: this is still a controlled generated noauto /dev/vda mapping, not the
contract's automatic UUID/cmdline path coverage. The final switch-root mapping is
opened separately by the existing fixture, not the interactive generated mapping.
The guest lacks a full journal pipeline; checking available journal output is
supplemental, not proof of production credential secrecy. Console checks and PTY
echo checks are actual evidence. No hardware inventory/late-hotplug enforcement,
old-image revocation, production password agent or NV antirollback is established.
The contract's complete combined production-like boot remains pending; this stage
closes only the generated-service/interactive-adapter gap.

Successful-checker run `work/luks-vm-07q7rh87/report.json` also passed, exit0,
14.66s, including all four generated-service interactive cases, switch-root,
existing signed-PCR11 checks and the added whole-console test-secret exclusion.
Three targeted dispatcher unit tests passed. No full-suite rerun was needed for
this guest-only harness addition; no claim that the entire project was retested.

## Automatic UUID sources and one mapping through handover — 2026-10-18

Extended the same guest integration with two more recovery attempts. The first
uses crypttab UUID=; the second supplies rd.luks.name/options to the actual
cryptsetup generator through its test environment. Both omit noauto, require a
real generated cryptsetup.target dependency, and start the target rather than the
mapping service directly. Copied the installed persistent-storage udev rules into
the guest; the UUID symlink must be created by udev and resolve to the guest disk.
Effective ExecStart must still select the reviewed test adapter, excluding the
stock attach command. Both automatic-source cases use actual hidden terminal input.

Kept initial generator EEXIST failure (luks-vm-pnn0yog6); each subsequent fixture
now removes its prior unit before regeneration. Intermediate run luks-vm-1injcf8b
passed both automatic-source cases with the old separate switch-root mapping.
A later same-mapping run luks-vm-pc_mw7ty correctly failed: retaining the final
mapping prevented the older PCR-mismatch recovery test from reopening the disk.
Reordered integration after those earlier tests; no failure assertions were removed.

The final cmdline-generated mapping is now retained for root formatting/mount and
systemd switch-root when --switch-root is requested. No second open is issued for
handover. The post-root check compares the actual root device number with that
mapping, verifies its sysfs backing disk is vda, and consumes the same-boot manual
observation (still attested=False). This is a disposable guest with shell final
PID1, not the laptop's signed mkinitcpio image. The generator is exercised after
fixture setup using controlled env inputs, not by a complete stock cold-boot
initrd target graph. This stage does not resolve duplicate alternative unlock
paths, production console ownership, trusted scanner evidence, late hotplug,
old signed images/headers, or Distress antirollback. Those contract requirements
remain open even if all these markers pass.

Final source passed both checker outcomes with the same mapping carried through:
`work/luks-vm-djphr8e6/report.json` (failure,23.43s) and
`work/luks-vm-e0u94rst/report.json` (success,15.56s), both exit0. Each includes
AUTO_CRYPTTAB, AUTO_CMDLINE, INTEGRATED_SAME_MAPPING and all earlier required
markers. Whole-console test-secret exclusion passed. Three dispatcher unit tests
also passed. No full project suite or hardware enforcement claim is made.

## Gate evidence parser integrated — 2026-10-18

See gate-record-build.md. Six new parser tests and actual guest filesystem rejection
cases added. Full Python suite275passed. Generated-service adapter now loads a
bounded current-boot/policy record and the actual checker result; failures go
manual through the dispatcher. Guest success/failure runs pu4hiyxr (17.61s) and
xjsysuz0 (24.28s) both passed every prior marker and the new filesystem checks.
No host boot changes. This is staged evidence consumption, not production
inventory supervision, hotplug protection or rollback-resistant enforcement.

## Actual supervised observation producer — 2026-10-18

See gate-observer-build.md. Three new observer tests; Python suite278passed.
Guest producer records real USB/platform counts/errors and a bounded policy hash,
always requiring manual recovery. Actual systemd starts it with a five-second
budget; a hung sleep fixture separately verifies timeout, termination and rejection
of prior evidence after failure. Generated recovery consumes the real observer
record/service state. Both guest outcomes hmvd8gsn/2pczwf29 passed all old/new
markers; initial missing hashlib/logging dependency failure xp8wjgqt is retained.
No host installation. Complete platform coverage, hotplug, alternate unlock paths
and production boot graph remain pending; observation producer cannot authorize TPM.

## Alternate generated-service TPM bypass regression — 2026-10-18

See alternate-unlock-test.md. Real generator creates two names for the guest's
same LUKS UUID. The gated one refuses; the ungated stock attach actually unlocks
through the valid virtual TPM/signed-PCR11 before PCR7 changes. A bounded exact
unit-name-set check rejects this duplicate candidate fixture. This is a reproduced
bypass and regression requirement, not an installed general-purpose image auditor.
Both checker-outcome guests passed all old/new markers: bpf8c6he (27.99s),
z2wazwcb (20.42s), exit0. Host security configuration remains unchanged.

## Reusable generated-unit snapshot auditor — 2026-10-18

See unlock-candidate-audit.md. Eight tests added; final Python suite286passed.
Guest negative duplicate-service fixture and both positive automatic UUID cases now
call the same bounded auditor on real generator fragments/ordered drop-ins.
Failure/success guest runs lpj22qqw/_52di9fk passed, all previous markers retained.
The final checker-Requires veto was covered by final unit/success-guest checks.
Snapshot validation is not a complete image/runtime-path audit or signing approval.

## Captured and sealed initrd input — 2026-10-18

See initrd-artifact-manifest.md. Complete single-newc member metadata/hashes are
captured from the same sealed compressed descriptor passed to QEMU. Report pins
manifest/initrd digests and508member count. Four new parser/mutation tests; Python
suite290passed. Guest failure/success ft74_a4d/wpldnf_g passed all previous tests;
latest success run also verified writes to the sealed object fail. Independent
post-run saved-artifact parse/hash matched the first report's complete manifest.
This captures exact test initrd bytes, not kernel/firmware/UKI or runtime attestation.

## Native initrd startup and encrypted-root systemd — 2026-10-18

New --cold-boot observe|failed|timeout scenarios, described in native-initrd-boot-test.md,
run native generators against actual guest cmdline in a fresh PID1 startup,
native sysroot/root-fs/parse-etc/cleanup/switch-root, actual manual console input,
and final-root systemd verification. Corrected /run1777 provisioning defect found
by stronger evidence assertions; preserved failed bgjerfu4 report. Final observe,
timeout and failed cases 0or82ac1/yr10m1tw/gn3iyuf_ all passed runtime/generated-unit,
checker-state/result, manual mapping and same-boot post-root checks. Python
suite292passed. No firmware/UKI, laptop topology, graphical password agent or
production recovery readiness claim. Provisioning uses only disposable material.

## Native retry/cancellation/exhaustion — 2026-10-18

See native-manual-retry.md. Six new coordinator tests; Python suite298passed.
Native startup guest cases wrong/cancel/timeout each require explicit confirmation
then reach encrypted-root systemd on manual attempt2: djlx8ags,58lymliq,9o57v7yh.
Three-attempt exhaustion455l9_j0 verifies no mapper/handover/root transition and no
TPM attempt. All use actual controlling-console input and whole-console secret
exclusion. Source guard, bounded service and private evidence remain staged only.

## 2026-10-18 — Astra focused native review and observer contract

Fixed staged unlock_candidate_audit.py dependency handling: reject empty dependency
assignments rather than clear earlier requirements, reject unsupported quoted/
expanded forms, reject direct checker BindsTo/Conflicts/Before. Allow only the exact
stock generated blockdev %i dependency in fragment Wants/Before, expanded with the
reviewed mapping. Purpose: avoid falsely accepting a graph that suppresses manual
recovery. Four regression tests added; all 13 auditor tests PASS using
`python3 -m unittest discover -s tests -p 'test_unlock_candidate_audit.py' -v`.
The earlier full-suite result remains 298; the full suite was not rerun this pass.

Native regression command: `flatpak-spawn --host
--directory=/home/user/Projects/security-center /usr/bin/python3
tools/test-luks-vm.py --cold-boot observe --cold-input wrong` (one command).
Initial run work/luks-vm-l4s23m7o failed conservatively because the stricter parser
rejected the stock blockdev %i form. Preserved evidence; no unlock occurred.
After the narrowly scoped parser support above, work/luks-vm-sa_40bno/report.json
PASS in8.45s: actual generated/runtime graph, observer, wrong then correct manual
input, encrypted-root switch-root, same-boot handover, no secret in console.
No host disks/TPM/network exposed. VM and emulator exited. No other VM profiles
rerun; their earlier evidence describes the earlier source version.

Created docs/observation-image-contract.md: source review limits, staged independent
observation schema/module/hook, stock unlock preserved, bounded observer failure,
manifest/build and owner boot checkpoints. Both Astra handoffs point to it.
No installed files, baseline, host boot image/default, keys, TPM/LUKS or PAM changed.
Rollback: staged source/docs only; do not deploy the guest adapter. Keep the parser
regression fix; any replacement must preserve dependency safety tests.
Next: Sol implements the staged observer contract. Production boot approval and
cryptographic Distress design remain separate checkpoints.

## 2026-10-18 — Sol passive observer staged

Implemented independent bounded initrd observation record/producer/isolated entry,
oneshot unit and mkinitcpio-hook draft; added read-only collector/Cockpit Boot row
and release/FIM/protected-path source integration (27 deployed files/32 FIM paths
in future release). No installed files or approved baseline changed.
312 Python tests passed; 10 observation/status tests and Cockpit DOM tests passed
after the last wording change. Native guest stock TPM unlock passed with successful,
absent, crashed, timed-out and memory-killed observer. Successful observer peaked
about7.5–7.8MB; actual current-boot record retained through switch-root, postboot
producer refused, file metadata/publication negative checks passed.
See observation-implementation.md for exact commands, passing/failing report paths,
limitations, current read-only build inspection, rollback and remaining tasks.
Full Arch image/runtime packaging, native stock manual fallback and authenticated
UI tests remain. No host boot/enrollment/PAM changes or deployment approval.

## 2026-10-18 — stock recovery and actual Arch builder validation

Native stock systemd console fallback PASS after actual virtual-PCR7 TPM refusal
(work/luks-vm-ou2rqzto); observation remains unlock_method=unknown. Regressed latest
verifier ordering for success/absent/failed; actual SIGKILL-before-publication and
file-entry replacement negatives PASS in work/luks-vm-74v_kaft.
Captured fixed observer package/runtime (359files); six tamper/path/metadata tests
plus installed-marker coverage bring full Python suite to319PASS. Isolated imports
PASS. Actual mkinitcpio42.2 build inside unprivileged bubblewrap/fakeroot PASS:
work/arch-observer-build-z7r5273a,37,628,651B unsigned disposable initrd. Failed
namespace-ownership build evidence retained; no host privilege requested/granted.
See observation-implementation.md follow-up for exact hashes, commands, scope,
rollback and remaining full-image boot/segment/signing checks. No laptop installation,
boot/key/authentication/enrollment/baseline change. Full project remains active.

## 2026-10-18 — actual Arch image boot and segment inventory

Booted the exact unsigned mkinitcpio artifact plus a declared provisioning/test
supplement. Native Arch /init, units/generators/rules/drivers and existing executable
bytes preserved; disposable /arch-provision selected by rdinit then execs /init.
All six scenarios PASS: observer success/masked/failure/timeout/OOM and stock manual
recovery after actual TPM policy refusal. Newest fully parsed/sealed-input manual
report work/luks-vm-1q5daial passes7.63s,1615ordered members, no secret exposure.
Parser now inventories both observed base segments (653early+898main) plus fixture
archive. Six malformed-archive tests and four fixture-path/substitution tests bring
host suite to329PASS, work/arch-observation-python-tests.log.
The actual native PCR phase unit is skipped: ConditionSecurity=measured-os false
for direct kernel boot. Firmware/stub/Secure Boot and real phase transitions remain
unverified. No laptop boot/key/PAM/enrollment/baseline change.
Next specialist checkpoint: astra-observation-image-review.md, including exact
reports/hashes, parser/runtime review, production recipe/library collision handling
and a disposable signed-UKI phase test contract. Full project remains incomplete.

## 2026-10-19 — unattended observer review and offline UKI verification

Fixed bounded package reads (FIFO/aggregate limits) and observation JSON nesting/
numeric overflow rejection. Host suite333PASS. New captured package2prwhlwf and
Arch build3ga34q76; direct-kernel auto guestp5zjkg0f/manualgy6vhobtPASS. Added offline
disposable PCR-signed UKI builder: extracted-section policy/signature check and
altered-signature refusalPASS, work/observation-uki-test-l4q3zo2c. No UEFI boot or
Secure Boot claim; no live laptop mutation. Initial SPKI fingerprint mismatch is
retained as failed m7mfiaq1, corrected to PKCS1. Full evidence/limits/pending steps:
overnight-progress-2026-10-19.md and measured-observation-next-contract.md.

## 2026-10-19 — Sol telemetry owner controls, staged

Added Cockpit JSON download/privacy opt-in and explicit clear-history review; fixed
append/deletion summary race using IMMEDIATE transactions. Fixed helper operations,
update-lock/import protection, schema/bounds/confirmation validation. No real deletion
or installation. Python339PASS and three JS suitesPASS. Actual Firefox local fixture
download/keyboard/focus/error/320CSSpx+200%zoom checksPASS: telemetry-controls-browser-tdoiiq2a.
Read-only installed background memory51,146,752B; authenticated Cockpit still unmeasured.
Captured review release monitor-ascsvybw,31files/36FIMpaths, approvalsfalse. Full details,
failed intermediate tests, hashes, rollback and pending work: telemetry-controls-implementation.md.

## 2026-10-19 — Sol memory bounds, export budget and current handoff

General read-only adapters now use bounded1MiB/8s pipe handling; directory and
parsed inventories cap before sorting/return. Actual child timeout/overflow/status/
UTF8 tests and current-host read-only checks passed. Deployment health now requires
boot_observation presence. Final Python345PASS; UI suites/browser evidence unchanged.
Latest review bundle monitor-iwww5mjl,31files/36FIMpaths, unapproved; captured
installer runtime80gg6yxk. Large synthetic exports completed with DB unchanged and
26,568KiB benchmark peakRSS. See adapter-resource-bounds.md for exact hashes/results,
limitations and first benchmark correction. README/STATUS/HANDOFF now distinguish
already-approved installed baseline from staged releases. No host installation,
production export/erase, enforcement, boot, auth, TPM/LUKS or baseline mutation.

## 2026-10-19 — requested final safe validation and stop

Python345PASS;3JSsuitesPASS;actual Firefox fixturePASS;6Archstock-observationguest
profiles+2interactive recoveryguestsPASS;offlineUKI/package/release verificationPASS;
worker lifecycle/resource and large synthetic export testsPASS. Live telemetry fresh
with advancing samples,0failures,installed FIM0changes. No deployment,production
erase,root prompt or boot/policy change. All launched trials stopped. Work stopped
at owner request; interactive/unimplemented/Astra milestones remain untested.
Detailed scope/evidence:final-validation-2026-10-19.md.

## 2026-10-19 specialist continuation

354Python tests pass (`python3 -m unittest discover -s tests` on host), including
nine new effective-initrd tests. tools/test-uefi-phase.py boots actual OVMF/UKI;
jxib1zot demonstrates independently matching native enter/leave PCR11 values,
but its overall report remains false (Secure Boot variables absent). Other firmware
attempts failed or timed out; see astra-progress-2026-10-19.md and private work logs.
No overall Secure Boot/TPM unlock acceptance or laptop changes claimed.

## 2026-10-19 Sol firmware continuation

354PythonPASS (work/sol-preboot-tests-2026-10-19.log). Actual guest enrolled-key Secure
Boot signed/unsigned/tampered3casesPASS in secureboot-guest-r0yipipj. Final actual
provision+target firmware/LUKS/TPM bootsPASS for observer-masked profile in
 two-boot-luks-uly1qq4h: no target credential/input, real encrypted-root switch-root,
independently matched PCR11 and post-phase second-mapping rejection with saved
signature and policy-related diagnostic. Normal observerTCG/KVM cases remain failed,
not skipped/passed. Exact failures and remaining matrix:
firmware-enforcement-results-2026-10-19.md. Host boot configuration unchanged.

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

## 2026-10-20 OpenSnitch retirement

Package removal and inactive process/service checks passed. Existing machine_care_guard
firewall table unchanged across removal. No orphan dependency purge. Retained tests:
adapters3, history5, release binding10, protected deployment9 passed. Browser fixture
work/usb-controls-browser-en1is44m/report.json passed retained USB flows and absence
of removed network controls. Historical OpenSnitch tests archived, not represented
as acceptance criteria. History's initial obsolete OpenSnitch cases failed before
being retired; USB policy-change event coverage remains. No boot or TPM tests repeated.

Removal deployment and approved-reference publication completed. Final fresh root
collector snapshot verified approved baseline with0changes/0unreadable; separate
unprivileged comparison matched all37 installed release hashes. Telemetry recording,
16collector modules, USB policy/config verification and original firewall intact.
Receipt: work/network-removal-installed-check.json. Owner exact approval and publisher
success: work/network-removal-baseline-publication.json. No new boot/TPM operations.

## AppArmor runtime trial — 2026-10-20

Actual trial kernel AppArmor=Y and LSM membership, integrity lockdown active. Disposable
profile real permitted/denied reads passed, temporary profile removed successfully.
Owner reports automatic disk unlock, Wi-Fi, sound, keyboard/mouse and sleep/wake worked.
Selected unit and two packaged profiles hash-verified; only avahi-daemon/lsb_release
loaded/enforcing; unit enabled. No Avahi restart or blanket desktop coverage claim.
Current collector reports2enforce/0complain,0failed units and0file changes/unreadable.
Receipts: work/apparmor-enforcement-check.json, work/apparmor-selected-runtime-check.json.
Normal-promotion first read-only preflight refused its excessive two-copy disk-space
requirement before writes. Revised single-copy/atomic-move procedure preflight passed,
including signatures/hashes/current boot/cmdline/menu/manual slot0, with65MiB reserve.
Promotion remains unexecuted pending exact approval; this is not promotion proof.

Exact AppArmor promotion owner approved, applied and independently verified: signed
normal/recovery/menu/cmdline hashes match approved proposal; LUKS metadata unchanged;
manual slot0 present; selected profiles enforce; temporary test profile absent.
Only zen.cmdline changed within42paths,41other records equal prior exactly. Owner
approved exact replacement91953e86…; publisher succeeded and immediate privileged
42-file scan found0changes/0unreadable. Current reference f3eeb155… . Normal-path reboot
and renamed recovery-path boot not performed; successful candidate boot/unchanged
previous recovery bytes are separately recorded evidence, not fabricated boots.
