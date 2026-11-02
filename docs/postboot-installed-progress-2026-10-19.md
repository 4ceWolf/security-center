# Installed postboot progress — 2026-10-19

Owner returned and authorized prompts/continued work. This supersedes the previous
owner-away hold. No TPM enrollment, LUKS slot or boot image/default was changed.

## Packages installed, signature verification retained

USBGuard1.1.4-11, AppArmor4.1.7-1, OpenSnitch1.7.2-4 and11dependencies installed.
Logs: work/postboot-package-install.log (failed download; no packages changed),
work/postboot-package-retry.log (successful signed transaction). Missing exact
AppArmor signature retrieved from Arch archive; package signature verification
remained enabled. No repository refresh/full system or kernel upgrade. Snapper
pre/post root snapshots509/510. Installed files total69.12MiB is disk space, not RAM.

## Scope/recovery dashboard installed; baseline awaiting approval

Protected transaction txn-bd7cbae1d23fdf074e3fd81482cafc7f applied monitor-o8ib655z.
Source release manifest3a2fbd9154ced8a0845b1cab95fd0386898fe946eba0557241ebb0ae18c54764.
Collector health17modules; both originally active services restored. Read-only
recovery review now installed; actual repair backend remains unfinished. No automatic
enrollment command is exposed. Exact new36-path candidate:
2039b424681401638c682d272df92dc44af2e5284bb76bb30c24191d72a2ca50.
Prior reference c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437.
Approval question sent, not assumed answered. Until publication the four expected
installed file changes show attention;0unreadable in current snapshot.
Review:postboot-scope-baseline-review.md. Receipts:work/installer/scope-recovery-*.

## USBGuard runtime trial active, boot persistence not enabled

Native generated7device rules captured read-only. Four root controllers, Logitech
046d:c542, camera13d3:540a and Bluetooth8087:0aaa observed; latter two kernel port
connection type=hardwired. Allow rules preserve exact descriptor/parent hash and port.
Existing approved absent A4tech09da:0025 has explicit serial/parent/port and exact
keyboard+mouse interface multiset; no descriptor hash invented for the absent receiver.
Device-provided identifiers remain spoofable. Keep candidate trust separately from
active native policy; editing the Cockpit candidate list does NOT yet update these rules.

Candidate9rules (8allow + block), SHA
544cb3ef7774b444206121e649cf956cdbf3d8094db984d5040ccca7c9fe4cff.
Config SHA76ae7da93d8ac00521c7fd1387ce20f81c8942f7e6b335d53cef568ec59bbdae.
Present devices/controllers=keep, inserted=apply-policy, default new authorization
none, implicit policy=block. Root-only IPC, LinuxAudit, HidePII=true. Keeping present
state is deliberate: this is not validation of every device already attached before
daemon startup. Runtime only, not preboot protection. Disabled at boot until owner
reconnect/input test. Internal AT keyboard/i8042 and I2C touchpad observed outsideUSB.

First activation auto-rolled back after health checker queried PresentDevicePolicy,
which is configuration-only, not a native runtime get-parameter. Controller defaults
confirmed restored to1. Corrected checker queries only supported parameters. Second
trial passed, all7existing device authorization states unchanged. Protected backup:
/var/lib/security-center-usbguard-trial-x8y8a10y. Receipt:work/usbguard-trial-output.json.
No device deliberately disconnected or blocked as a live test.

Native parser check succeeded;8native matching tests PASS: both receivers match,
wrong ID/port/hash/serial and extra/missing interfaces fail. These are offline native
matcher tests, not physical insertion proof. Source:tools/usbguard-rule-check.cpp,
tools/test-usbguard-rule-match.cpp. Owner reconnect question pending. Do not enable
at boot before response and verification. Existing dashboard candidate copy about
undeployed enforcement predates this trial; its editor still changes candidates only.
Update that copy with the next reviewed dashboard change before normal promotion.

Rollback: tools/rollback-usbguard-trial.py is prepared, NOT executed. It authenticates,
checks exact current policy digests/root-private backup, disables/stops onlyUSBGuard,
restores its two config files and saved controller authorized_default values. Stopping
the daemon alone is insufficient because RestoreControllerDeviceState=false leaves
defaults changed. Restore affects postbootUSB only, no firewall/boot/TPM change.
Root-private backup paths are authoritative; don't restore from mutable project copies.

## OpenSnitch isolated coexistence passed; host service inactive

tools/test-opensnitch-namespace.py runs in private user/network/PID namespaces, no
physical network or host rules. Synthetic preexisting default-drop table preserved
during daemon and after shutdown; native queue rule observed. PASS:
work/opensnitch-namespace-fwswb99m/report.json. Earlier4s8s7u9v FAIL retained: checker
incorrectly expected branded table name; actual tables mangle/filter. Corrected test
requires actual queue expression and saves full during-ruleset.json. BPF/process-event
facilities cannot run in user namespace and are not proved. No real traffic enforcement
or host firewall coexistence acceptance yet. Fixture children terminated.

Review found defaults flush connections on startup; staged fixture disables that,
disables system-wide firewall rules and uses local IPC/proc monitor. No hostOpenSnitch
config/start/enable applied. Avoid starting it blindly with packaged defaults.
AppArmor service still inactive and LSM disabled; actual confinement requires a separate
reviewed boot-maintenance decision and owner reboot. Package installation isn't protection.

## Resource snapshot, not full active-stack acceptance

work/postboot-memory-current.txt: collector49,217,536B, recorder15,761,408B,
USBGuard3,907,584B (~65.7MiB combined cgroup charge), zero automatic restarts.
Excludes signed-in Cockpit/browser and inactiveOpenSnitch. Full200MB target remains
unverified. Telemetry active; current secureboot/integrity/encrypted-root checks secure.

## Pending

Owner exact baseline approval/publication; physical Logitech reconnect/input result;
USB policy management inCockpit + accurate active/candidate copy and persistence;
actualOpenSnitch traffic/coexistence + application controls; AppArmor boot/profile
rollout decision; real automatic-unlock repair transaction/tests/review; signed-inRAM
and final recovery/installed validation. Do not claim project complete.
