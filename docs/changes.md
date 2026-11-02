# Change log

## 2026-10-14 18:14 PKT — runtime integrity trial
Purpose: validate kernel integrity lockdown before altering signed boot images.
Previous: none. New: integrity, running session only.
Operation: root wrote integrity\n to /sys/kernel/security/lockdown through a polkit-authorized Python invocation. No persistent boot configuration changed.
Before checks: expected manual/TPM slots 0/2, direct PCR7, signed PCR11, initrd policyref and SRK presence asserted from metadata. Root-only before/after evidence under backups/lockdown-trial-20261014.
After checks: running state none [integrity] confidentiality; SHA256 hashes of current Zen UKI, cmdline, UKI config and preset unchanged; complete LUKS metadata unchanged.
Automated smoke checks: GPU PMU output still available; machine-care firewall, WARP, NetworkManager, Bluetooth and tuned active; powersave profile active; no failed system services; kernel log confirms lockdown activation.
Not tested: interactive sleep/wake, new device hotplug, restart of every driver, post-change boot.
Rollback: normal reboot; this trial cannot be lowered in the running kernel. No reboot initiated.

## 2026-10-14 — separate integrity candidate built
User confirmed automatic unlock after reboot and knowledge of manual LUKS passphrase; instructed continuation. Built /var/lib/security-center/integrity-candidate-20261014-235319/candidate.efi from the working UKI using tools/prepare-integrity-candidate.py.
Original SHA256: bf068f1b35abe22f42d93f07cb7c5926a08548c8801a975139c0beac9a451eda.
Candidate SHA256: c5a8cf3cb1ca56b79b140199ebee81404440bab19c12a612a039f315e0034fa6.
Verified: existing db certificate signature; unchanged kernel/initramfs bytes; embedded lockdown=integrity addition; PCR public key matches current enrolled key; SHA256 PCR11 initrd-reference policy present; original UKI/config and full LUKS metadata unchanged.
The candidate is not yet boot tested or deployed. Offline checks do not prove automatic unseal on the next boot. Root-only build report/logs and known-good copy are in the candidate directory. Rollback for this offline stage: leave candidate undeployed.
Installed Cockpit app.js now matches tested source SHA256 a194702aca395f3b357141035d79419427fe48a540debc81f15f5a2a3af6ae64. The stale/error-state correction is deployed.

## Separate integrity test boot entry staged
Installed validated candidate at /boot/EFI/Linux/arch-linux-zen-integrity-test.efi and appended a Visor entry named “Arch Linux Zen - integrity test”. Original default remains entry 0; remember_last=0. Normal image and LUKS metadata verified unchanged. No reboot initiated. Signature verified again after copy. Staging record: /var/lib/security-center/integrity-candidate-20261014-235319/staging.json.
Menu backup: same directory /boot.conf.before-test. Exact original menu SHA256 b066d9f6ef50de2451e379de045035e47e7839c9055e34a71c6d95f67c8eae59; staged menu SHA256 d72f253f7b0b7a05ec3820dd617c2005faf0212c4b52382d6699200daf016d9a.
Rollback helper tools/rollback-integrity-test.py verifies both files still match the staged hashes before restoring the menu and removing only the added test image. Candidate and known-good backup remain on encrypted root.
Pending owner reboot selection and automatic-unlock confirmation. Permanent normal build/default not changed.

## Integrity promotion after owner compatibility tests
Owner reports sound, sleep/wake and Wi-Fi reconnection all normal. Promoted byte-identical validated candidate to /boot/EFI/Linux/arch-linux-zen.efi. Added lockdown=integrity to /etc/miku-boot/zen.cmdline (actual preset build source). Default entry remains 0. Preserved original signed UKI as /boot/EFI/Linux/arch-linux-zen-pre-integrity.efi and replaced the test menu entry with “Arch Linux Zen - pre-integrity recovery”. Removed only the redundant test image after verifying normal/recovery hashes and signatures.
Root record: /var/lib/security-center/integrity-candidate-20261014-235319/promotion/result.json. Full LUKS metadata unchanged. Current normal image SHA256 c5a8cf3cb1ca56b79b140199ebee81404440bab19c12a612a039f315e0034fa6; recovery image SHA256 bf068f1b35abe22f42d93f07cb7c5926a08548c8801a975139c0beac9a451eda. No reboot initiated. Normal-path selection awaits next routine reboot; its payload has already booted and passed owner tests.
Rollback: choose pre-integrity recovery in Visor if needed, then explicitly run tools/rollback-integrity-promotion.py as administrator after review. It refuses files changed since promotion. This supersedes rollback-integrity-test.py.

## 2026-10-15 — read-only monitoring adapters
Added adapters.py collectors for OpenSnitch/USBGuard service availability, bounded sysfs USB inventory, local pacman update availability, root Snapper metadata and TCP listeners. Added Devices, Updates and Recovery navigation in Cockpit. No additional enforcement daemon installed/enabled and no policies changed. Existing 60-second cache, 3-worker limit and 80 MiB hard/48 MiB soft collector ceilings remain.
Installed copies match source through tools/update-monitoring.py; prior collector/UI and install record backed up root-only under backups/phase2-readonly-before. Rollback requires stopping security-center.service, restoring backed-up collector.py/app.js/index.html and prior install record, removing only newly added adapters.py after checking later modifications, then restarting. Review hashes before rollback; do not overwrite later work blindly.
Eight Python tests and the UI fresh/error/stale/recovery state tests passed. All 14 modules returned structured results after installation (no unavailable modules). Local update database reports zero known upgrades, but oldest database is ~61 hours old: this is NOT an up-to-date/security-clean verdict. Snapshot directory/metadata observed; no restore test.
Headless Firefox rendered a separate local preview using a saved sanitized snapshot at 1280x1000 and 390x844. Inspected both screenshots: desktop rows and narrow stacking are readable. This tests rendering, not authenticated Cockpit integration or keyboard/screen-reader behavior. Preview server was loopback-only and stopped after screenshots. Preview browser used an isolated project work profile and exited.
New listener check detected *:9863 owned by electron PID 6042 in app-com.github.th-ch.youtube-music scope; executable /usr/lib/electron42/electron with Pear Desktop app.asar. No app setting changed. Existing firewall drop policy remains; external reachability not tested.
Collector observed MemoryPeak 50,716,672 bytes (~48.4 MiB), NRestarts=0 with added checks. Authenticated cockpit-bridge/browser memory still unmeasured.

## 2026-10-15 — persistent event history
Added history.py and protected StateDirectory security-center-monitor. Daemon now indexes normalized journal events and explicitly labeled observations/state changes. Added bounded search/pagination controls and increased fixed client response cap to 2 MiB. No new daemon or network listener. Retention 2,000 events / 30 days; SQLite main database ceiling 4096 pages. Deployment backups: backups/history-before.
12 Python tests passed; UI tests passed fresh/error/stale/recovery plus 100-event paging, search and empty results. Installed service produced history_status available, 16 initial events, no unavailable modules. Database 24,576 bytes mode0600; direct read as kyo denied. Collector peak 50,761,728 bytes (~48.4 MiB), no automatic restarts. Complete journal coverage remains outstanding: latest120-per-poll sampling can miss events and is explicitly labeled.

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

### 2026-10-16: diagnostic telemetry build
Added local bounded sampler/history, finite capture/summary tool and retention
rehearsal. Battery, CPU/thermal/process, RAM, pressure, frequency, disk/network
and filesystem metrics; hourly means/peaks; privacy and invalid-rate handling.
156tests pass; actual capture~18.5MiBRSS; synthetic retention~42.2MiBDB. Design and
pending deployment documented. Installed security service/baseline unchanged.

### Telemetry lifecycle and staged health card
Added exclusive writer locks, supervised-worker proposal, private health reports,
error recovery and safe shutdown. Read-only staged collector/card shows diagnostic
recording health with freshness checks.170tests pass; packaged18module runtime
passes. No deployment or baselineapproval changes; newstagedscope23paths.

2026-10-18: Built staged trusted-device policy editor, private transactional state,
fixed on-demand administrator helper and Cockpit review/add/remove controls.
236 Python tests and two Node UI suites passed. Live read-only Logitech match;
simulated wide/narrow browser review inspected. Bundles device-trust-18exhhl2 and
monitor-12mp6a1j are review-only. No installed or preboot changes. Stopped for
Astra review before privileged deployment, per user's model-handoff preference.

2026-10-18 (Astra review): removed silent seed fallback after lost trust state,
restricted production initialization to reviewed installation, persisted initial
policy/marker and retained successful commit receipts on follow-up scan failure.
242 Python tests passed; concrete Sol deployment handoff documented in
trusted-device-security-review.md. No privileged deployment or boot changes.

2026-10-18 (Sol deployment): combined 25-file/30-scope update installed through
captured root runtime and protected journal. Fixed DynamicUser managed alias
compatibility after real startup failure; actually rolled original files/services
back and applied corrected release monitor-18cuezjm. 260 Python tests pass.
Telemetry now records every 30s and is enabled at startup; 2-sample live check,
nonroot/no-capabilities, DB/history and no restarts passed. Background memory ~59 MB,
full authenticated Cockpit unverified. Replacement file baseline 3464d566... remains
pending explicit owner approval; review docs/monitor-telemetry-baseline-review.md.

2026-10-18: Added staged bounded read-only local JSON telemetry export, raw/hourly
all-metric options and explicit process-detail opt-in. 269 Python tests pass;
saved host trial export succeeded (128 metrics). No installed files or baseline
changed while exact replacement-baseline approval remains pending. Added clear
current-status banner to telemetry docs; historical staging notes retained.

2026-10-18 (specialist follow-up): owner approved exact candidate 3464d566….
Captured approval script rechecked all 30 files and archived prior baseline
19f88b6f…. Published reference b160da7e…; independent privileged comparison and
archive hash verification passed. Root-peer PID matched the running collector;
its refreshed status reports approved baseline, zero changes, zero unreadable
files. Telemetry reports fresh recording, 31 samples this run, zero consecutive
failures. Evidence: work/installer/baseline-approved-verification.json and
baseline-approved-live-monitor.json. Initial cached collector response preceded
approval refresh; later live response verifies adoption. No restart required.

Added docs/preboot-implementation-contract.md after reviewing existing gate,
platform inventory, unlock dispatcher, generated-service guest adapter and
handover code against primary systemd/Linux/cryptsetup documentation. Defined
combined automatic systemd/interactive guest integration and explicit acceptance
cases. Highlighted retained old LUKS headers/sealed objects as well as old UKIs;
new NV-aware software cannot constrain legacy unseal objects. This is a concrete
next-stage contract, not a completed cryptographic migration or enforcement claim.
No production boot, TPM, NV, LUKS, PAM or installed immutable files changed.
No new code tests claimed for this documentation-only design work. Sol can now
implement the guest integration; specialist review returns before concrete TPM
protocol or host boot/authentication migration.

2026-10-18 (Sol, usage-conscious pass): added guest-only generated-service terminal
recovery integration and --integrated-recovery harness option. Four real PTY cases
(wrong, cancel, timeout, correct) run through actual systemd-generated service;
checks include disabled input echo, mapper state, manual-only receipts and detach.
Preserved initial unloaded-service reset failure evidence; corrected harness and
passed failure/success checker guests: luks-vm-h3mvwixc (21.23s) and
luks-vm-07q7rh87 (14.66s), including prior TPM/PCR11 and switch-root assertions.
Three dispatcher tests passed. Console contains no disposable secret. No installed
files, baseline, host boot/authentication or enrollment changed. Next: automatic
UUID/cmdline generation and using the same verified mapping for switch-root;
current noauto fixture and separate final mapping remain explicit limitations.
See docs/testing.md. Further specialist review is not needed for these routine
isolated guest tasks; hardware/cryptographic migration remains checkpointed.

2026-10-18 (Sol continuation): extended generated-service integration to actual
udev UUID discovery, crypttab and rd.luks.name/options source generation without
noauto, and target-driven activation. Retained the last manually opened mapping
through systemd switch-root; post-root checks compare device numbers and sysfs
backing disk. Preserved failed runs for generator EEXIST and an older test's
conflicting second open. Corrected fixture generation/order without removing
failure assertions. Final success/failure checker guests passed: djphr8e6 and
e0u94rst; all old markers plus automatic-source/same-mapping checks. Three dispatcher
tests passed. See testing.md for limits: controlled generator environment and
minimal guest are not a full stock cold boot, trusted inventory or production
credential agent. Host boot, TPM, baseline and installed code remain untouched.

2026-10-18 (Sol): implemented staged initramfs/gate_record.py, strict bounded
current-boot/policy/mode/freshness parser and no-follow private root-file reader.
Six new tests; full Python suite275passed. Added root-only guest acceptance and
refusal checks for metadata, symlink/hardlink, oversized/missing files and FIFO.
Integrated reader into generated-service manual recovery fixture with actual
checker service state. Both checker outcome guests passed: pu4hiyxr/xjsysuz0,
including prior signed-PCR11, UUID-target terminal recovery and same-mapping
switch-root checks. No installed files, baseline, TPM/LUKS, boot or authentication
changed. See docs/gate-record-build.md for remaining provenance/coverage limits.

2026-10-18 (Sol continuation): added guest-only gate_observer.py observation
producer, bounded policy validation/hash, real USB/platform sampling, private
atomic records and diagnostic counts/errors. It always denies TPM until coverage
and enforcement can be established separately. Added actual PID1 oneshot/timeout
supervision test and integrated its record/service state into generated recovery.
Fixed missing minimal-guest hashlib/logging dependencies after retaining failure.
Python suite278passed; success/failure guest runs hmvd8gsn and2pczwf29 passed,
including all previous checks. No host boot, token, authentication, installed
baseline or resident-service changes. Next: alternate unlock-path audit and a
complete disposable cold-boot graph, before reviewed production observation image.

2026-10-18 (Sol): added vm-alternate-unlock.py to integrated guest scenarios.
Reproduced actual valid-TPM unlock through a second generated service while the
intended gated service refuses. Exact duplicate service-set mismatch is detected
by the negative candidate fixture. Inspected effective PID1 commands and actual
mapper; closed it and removed fixture unit files before continuing. Both checker
outcomes bpf8c6he/z2wazwcb passed prior/new markers. This new evidence makes an
all-path candidate audit a mandatory next build requirement, but is not itself
a deployed auditor or a fix for older authorized UKIs/headers. No installed code,
boot/TPM/authentication state or FIM reference changed. See alternate-unlock-test.md.

2026-10-18 (Sol): added reusable unlock_candidate_audit.py for bounded generated
service snapshots, exact reviewed unit/source/options/gate command and supported
drop-in reset/order rules. Rejects duplicate unlock names, explicit keyfiles,
stock/additional start commands, unsupported execution/environment directives and
checker Requires that could suppress recovery. Eight tests; final Python suite286
passed. Connected the auditor to actual guest duplicate and automatic UUID cases;
lpj22qqw/_52di9fk passed all prior markers. Documented explicit boundaries: complete
image/helper hashes, effective runtime overrides and non-unit/legacy boot paths
remain unverified. No production signing/boot/TPM/baseline changes. Next routine
work is complete candidate-image capture and cold-boot/runtime graph verification.

2026-10-18 (Sol): added bounded non-extracting single-newc artifact inventory and
exact manifest comparison, including all file hashes/metadata and symlink targets.
VM harness captures the sealed compressed initrd descriptor it actually passes to
QEMU; report pins manifest and compressed digests. Kernel remains outside this
binding. Four new tests; Python suite290passed. Both checker outcomes ft74_a4d and
wpldnf_g passed prior checks; final run tested actual write refusal after sealing.
Independently reparsed saved artifact matched report/manifest. About22MB temporary
sealed image copy; no additional resident service or installed configuration.
Manifests remain unapproved captures. Production image review/signing and complete
cold-boot/runtime graph verification remain pending. See initrd-artifact-manifest.md.

2026-10-18 (Sol): added fresh-manager native initrd scenarios with actual generator
startup, root-device/mount path, native parse-etc/cleanup/switch-root and final-root
systemd. Manual console callback owns no keyfile or external token; host sends only
disposable input after real prompt, requires that input was sent and checks no echo
in the whole console. Runtime graph and generated snapshot assertions are outside
fallback-catching code. Corrected early /run tmpfs permissions after secure-reader
rejection; failed report retained. Final observe/failed/timeout profiles passed:
0or82ac1/gn3iyuf_/yr10m1tw. Python suite292passed, including builder host-path refusal
and fixed console audit. No host boot, TPM/LUKS, authentication or installed-file
changes. Production agent/retry, platform policy, signed candidate and legacy
cryptographic enforcement remain pending. See native-initrd-boot-test.md.

2026-10-18 (Sol): bounded manual-only retry coordinator and separate guest console
adapter source. Actual native startup tests pass wrong input, Ctrl-C and timeout
followed by explicit retry/correct entry; exhaustion after3failures stays locked
without handover. Python suite298passed. Reports djlx8ags/58lymliq/9o57v7yh/455l9_j0.
Fresh host root-peer collector still reports zero FIM drift and telemetry recording;
background monitored units ~58.6MB. All host boot/authentication/enrollment and
installed files untouched. Reached owner-requested specialist review checkpoint
before production laptop boot integration; concrete docs/astra-native-review.md
lists new code, evidence, limitations and exact review requests. Not project completion.

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

## 2026-10-19 — owner requested telemetry only

Verified installed security-center-telemetry.service is already enabled at startup
and active/running,0restarts,9,715,712B current cgroup memory. Collector reports
fresh current-boot recording at30s interval,1216samples this run,0consecutive failures,
and11populated hours of available history. No enable/restart was necessary.
No staged UI/helper/adapter release, boot, enforcement or baseline change applied.

## 2026-10-19 — requested final safe validation and stop

Python345PASS;3JSsuitesPASS;actual Firefox fixturePASS;6Archstock-observationguest
profiles+2interactive recoveryguestsPASS;offlineUKI/package/release verificationPASS;
worker lifecycle/resource and large synthetic export testsPASS. Live telemetry fresh
with advancing samples,0failures,installed FIM0changes. No deployment,production
erase,root prompt or boot/policy change. All launched trials stopped. Work stopped
at owner request; interactive/unimplemented/Astra milestones remain untested.
Detailed scope/evidence:final-validation-2026-10-19.md.

## 2026-10-19 specialist continuation

Added offline effective_initrd.py + nine failure/delta tests, UEFI phase probe and
preimplementation design docs. Full354PythonPASS; synthetic directory-mode conflict
refused; native measured UEFI enter/leave evidence captured with remaining failures
explicit. Swap FIM review required no baseline change. Telemetry midnight–noon review
reports only accessible October19 data. See astra-progress-2026-10-19.md for purpose,
files, evidence, limitations and rollback. No installed/protected configuration changed.

## 2026-10-19 owner scope reduction and authorized telemetry read

Removed Distress Mode from active project scope in project-brief.txt, STATUS.md,
README.md and HANDOFF.md; retained historical prototypes without deploying anything.
Prepared sol-preboot-handoff-2026-10-19.md. Documentation-only change needs no runtime
baseline or regression rerun. No installed Distress component existed to uninstall.

Owner-approved graphical sudo export succeeded using exact reviewed exporter bytes
embedded in python3 -I -c; fixed96-hour read-only query, no mutable root imports.
Private output work/authorized-telemetry-8c6jo3k6,25rows,earliest October18 at14:00PKT.
October17/18 requested morning windows absent from current database export.
October19 temperatures/power/usage summarized in telemetry-authorized-review-2026-10-19.md.
Battery0W with AC online is not total laptop power. No protected configuration,
boot/TPM/LUKS/baseline or database content changed; no rollback required.

## 2026-10-19 Sol completed install and firmware test groundwork

Installed reviewed31file release with protected transaction, live19module/export/
privacy/device preservation checks, owner-approved36path baseline523f21c3… published
as c1f12cc6…; FIM clean after restart. Current evidence and recovery guard limitation:
installed-controls-baseline-review.md and firmware-enforcement-results-2026-10-19.md.

Added disposable enrolled-key Secure Boot harness, corrected missing db certificate
and bounded rejection markers;3actualfirmwarecasesPASS. Added two distinct measured
UKIs/provisioning and no-secret target/native-root checker; final observer-masked
casePASS including post-phase TPM policy rejection. Normal observer/time/hardware
acceleration failure remains explicit. Test-only extra provisioning binaries added
as optional flag to unsigned Arch fixture builder; none installed on the laptop.

Authenticated read-only capture of current working UKI/public certs, streamed PE
section inventory and independent EFI/PCR signature verification complete. Offline
stored-image cap128→256MiB for observed189MBinitrd, other bounds unchanged; conservative
metadata conflict still refuses effective approval. No signing key/hostTPM/boot file
mutation. Baseline installation is the only live change; no history deletion or
Distress deployment. Tools/design/commands/reports and next checkpoints linked in
firmware-enforcement-results-2026-10-19.md and HANDOFF.md. No production boot rollback
required; baseline-approved monitor rollback requires explicit recovery review.

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

## 2026-10-20 — owner-managed networking

Removed OpenSnitch package/daemon/on-demand GUI/startup override and archived its
private state. Preserved existing firewall exactly. Removed its dashboard controls,
collector adapter and event-fingerprint specialization; kept USB management and
read-only network observations. Generic network_policy module is an inert monitored
compatibility placeholder to preserve static FIM scope. Retired feature saved in
ideas and historical sources. See HANDOFF for installation/reference receipts.

## AppArmor actual trial and selected profiles

Owner boot-tested AppArmor and confirmed automatic unlock and hardware compatibility.
Disposable kernel enforcement test passed/removed. Dedicated two-profile loader is
active/enabled after exact native unit/profile hash checks. Most apps unconfined;
Avahi inactive, no service restart to manufacture an attachment result. Local enable
tool strengthened unit/lock checks. Promotion tool now offers exact read-only review,
pinned input hashes, explicit apply/owner-trial flags and a bound proposal digest.
Revised promotion retains a signed recovery copy then atomically moves the tested
image over normal, avoiding redundant boot-partition space. Read-only review passed;
normal image, build cmdline and menu remain unchanged until exact approval.
