# Native manual-recovery retry — staged guest work, 2026-10-18

`initramfs/manual_recovery.py` adds bounded manual-only coordination: at most three
adapter attempts, success only on exact True, and an explicit True retry decision
after each failed attempt. It handles no credentials and has no TPM operation.
Unexpected adapter exceptions propagate instead of being silently treated as an
ordinary wrong passphrase. Adapters remain responsible for deadlines and verifying
actual mappings. This is not installed in the laptop initramfs or authentication.

The native guest adapter is now a separate captured source file,
`tests/vm-cold-unlock.py`, refusing outside the marked disposable guest. Cryptsetup
continues to own hidden input with slot0, external token plugins disabled and no
keyfile. Each failed attempt verifies no mapper and no successful handover before
showing a retry prompt. Retry input is also hidden, bounded to five seconds and
accepts only Enter. No entered text or exception message is logged by the retry
coordinator. A successful retry remains manual; it never reconsiders TPM permission.

The parent supervisor catches SIGINT while cryptsetup runs so Ctrl-C can cancel
the credential child without killing recovery. The child exec resets the caught
handler; actual cancellation is tested through the native controlling console.
Parent signal and terminal settings are restored in finally blocks. Test budgets
are five seconds for credential input, eight for its subprocess, five for retry
confirmation and45for the mapping service. These fixture timings are not a proposed
human-facing laptop password-agent configuration.

The host test driver now supports --cold-input correct|wrong|cancel|timeout|exhaust.
It waits for each actual passphrase prompt, sends only the matching disposable
input, and confirms each retry separately. Timeout sends nothing on the first
prompt. Exhaust sends three wrong inputs and must verify no mapper, no handover
and no root transition. The guest powers off after checking that negative case;
this is a fixture action, not proposed production behavior. For successful cases,
only the intended correct input is allowed to lead to encrypted-root systemd.
All console output must exclude the disposable passphrase. Tests assert exact
attempt counts outside the dispatcher's exception handling, so swallowed assertions
cannot masquerade as successful recovery.

Six unit tests cover immediate success, wrong-then-correct, bounded exhaustion,
strict retry consent/limits/success and propagation of adapter failures. Full Python
suite298passed. Actual native wrong-input run djlx8ags passed in8.14s; failed-checker
plus Ctrl-C run58lymliq passed in7.84s. Both verified two attempts, no mapping after
the first failure, explicit retry, manual success and final encrypted-root systemd.

Existing native boot/kernel/firmware and topology limits still apply. Production
console-agent/UI design, rejection/timeout at the retry menu itself, persistent
recovery after exhaustion, real keyboards and owner tests remain pending. The
read-only handover is not authority to restore Distress, and these tests do not
establish actual owner authentication. No host boot, LUKS, TPM, PAM, installed code
or FIM reference changed. Test RAM/disk/keys remain disposable.

Final timeout-checker plus input-timeout run9o57v7yh passed in18.38s, recovering on
the second attempt. Native exhaustion run455l9_j0 passed in5.45s after exactly
three failures and two confirmations, with no mapper, successful handover or root
transition. Both retained runtime/generated-unit checks and secret exclusion.
Fresh host collector check (work/native-review-host-status.json) reports zero
installed-file changes/unreadable files and ongoing telemetry. Monitor+recorder+
idle Cockpit socket measured58,568,704bytes (~58.6MB); full authenticated Cockpit
memory remains unmeasured. No additional resident checker has been installed.
