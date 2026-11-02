# Approved baseline and persistent USB protection — 2026-10-19

Owner approved exact candidate2039b424681401638c682d272df92dc44af2e5284bb76bb30c24191d72a2ca50
and reported Logitech same-port reconnect, mouse, internal keyboard and touchpad all
worked. Approval applies to the36-path scope/recovery update, not future file changes.

Captured publisher SHA5f4428518f0c60cde3254a9bd7b795fbba547a60223e7dc5c413b9796764b6a2
ran with a root-private temporary bytecode cache and rechecked all current files.
Prior c1f12cc6c20258d933992601b1f93ef543e9e2dc152779ca8b848794a5f23437 archived.
Published reference SHA:
1570242abaee6a65ce72adc914843ac0e0f74fc90938f8004d97e09e535f6997.
Receipt:work/postboot-approval-and-usb-enable.log; independently read from protected
reference in work/opensnitch-trial-diagnostics.log. Current collector reports0changed/
0unreadable. Approval satisfied: do not ask for2039b424… again.

## USBGuard promoted

Rechecked exact tested config and rules hashes plus active native runtime parameters.
Enabled usbguard.service; active+enabled, zero automatic restarts. No reboot performed.
Original8allow+block policy retained. New insertions evaluated; already present devices
kept, so this does not establish prior-device trust. Candidate editor still only saves
candidates, not live native rules. Next UI/native-management update must correct old
undeployed copy and connect explicit reviewed native-policy operations. That is pending.
Also extend FIM scope to native USBGuard policy/config with a separately reviewed update;
current clean36-path reference does not monitor those newly installed native files.

Owner's physical reconnect is a live acceptance result; next-boot startup has not yet
been observed. Postboot protection only. Existing Secure Boot/lockdown/TPM/manual
recovery unchanged. Prepared rollback tool targets the exact tested backup and now
also disables service persistence if explicitly invoked; not executed.

## OpenSnitch native-host test failed and rolled back

New tools/trial-opensnitch-postboot.py captures root-private before-state and retains
machine_care_guard. It disables connection flushing and system-wide native firewall
configuration, selects proc monitoring, local private-user socket and journald output;
default allow/queue bypass preserve existing access during the test. A private
root-owned copy ofcurl is the only intended application-deny target. No real user
application receives a deny rule. Manual disk credentials are unrelated and untouched.

First run stopped at a failed six-second pre-start probe before enabling the daemon.
Normal direct HTTPS subsequently worked. Second run with larger bounds reached daemon
startup but did not establish scoped deny plus recovery, so it stopped the daemon,
removed the temporary rule/program, and restored its two configuration files. Logs:
work/opensnitch-host-trial-first-error.log, work/opensnitch-host-trial-error.log,
work/opensnitch-trial-diagnostics.log. Native journal shows orderly shutdown; a queue
close timeout warning occurred. No host enforcement acceptance and no persistence.
Do not label this as a compatibility verdict or guess the root cause. Distinguish
process attribution, rule loading/cache timing and actual queue delivery in the next
diagnostic. Save per-probe result and bounded native state before further reruns.
Earlier isolated native queue/table coexistence PASS remains separate evidence.

Actual current opensnitchd.service=inactive/disabled; no temporary deny rule is intended
to remain. Rollback receipts independently queried in work/opensnitch-rollback-verification.json.
No changes made to working machine-care firewall rules; current collector still reports
default-drop inbound protection loaded. Do not flush the whole nftables ruleset.

## AppArmor offline checks

Three packaged profiles (avahi-daemon, unix-chkpwd, lsb_release) compiled with explicit
ABI4.0, skip-kernel-load and skip-cache. PASS receipt:
work/apparmor-offline-profile-checks.json. This does not establish running-kernel
compatibility or enforcement. Current AppArmor LSM is disabled. A reviewed boot change,
small profile rollout and owner compatibility/reboot checkpoint remain necessary.
Do not enable all shipped profiles or re-sign a boot image as an implicit side effect.

## Current resources and remaining work

work/postboot-promoted-services.txt: collector43,884,544B + recorder11,468,800B +
USBGuard3,534,848B =~56.2MiB cgroup charge, zero automatic restarts. Excludes signed-in
Cockpit/browser, inactiveOpenSnitch and futureAppArmor. Full200MB target still open.
work/postboot-promoted-snapshot.json:17modules, Secure Boot/integrity/firewall secure,
FIM0changes/0unreadable, telemetry recording reported, USBGuard7allowed/0blocked.
Observed daemon decisions remain unknown policy verification, not automatically green.

Pending: native USB controls inCockpit and new policy FIM scope, OpenSnitch functional
app-deny diagnosis, AppArmor activation/profile review, actual TPM-repair backend and
disposable tests preserving initrd-only signed policy, authenticated UI/full memory
and final recovery/installed validation. Preboot gate and Distress remain removed.
No automatic reboot or TPM/LUKS/signing-key operation included in these steps.
