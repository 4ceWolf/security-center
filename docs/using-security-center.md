# Using Security Center

Open http://127.0.0.1:9090 on this laptop and sign in as kyo. The page is local-only.
Most checks are observations; expand a protection row to see the evidence and limits.
An allowed USB device or running daemon alone is not proof that a policy is correct.

## Devices

Use **Manage live trusted devices** for the actual USBGuard rules. Review the complete
identity, port, interfaces and exact rule change before applying. A receiver with a
keyboard interface is called out explicitly. Internal/hardwired devices and controller
rules cannot be removed here. Current devices stay connected; reconnect a device to
apply changed trust. Moving ports can require a new review. USB identifiers can be
imitated, so trust only hardware you recognize.

The older **Trusted devices** candidate editor remains a separate planning list.
Saving a candidate does not change live rules. Both earlier approved receivers remain
in the native rules. Postboot protection does not enforce a custom preboot device gate;
already present devices are kept under the selected startup availability policy.

## Networking

Networking is owner-managed. OpenSnitch and its controls were removed at your request.
Existing firewall and listening-service observations remain read-only. Security Center
makes no networking changes. The previous integration is retained in ideas.md.

## Diagnostic history

Battery percentage/power/discharge, CPU use/temperature, memory and process summaries
are recorded locally by the bounded telemetry service. Use the chart selectors and
local exports. Exports omit process details unless you explicitly select them.
Clearing saved diagnostic history needs administrator confirmation and does not stop
future recording; it is not a claim of forensic erasure. Missing sensor readings mean
unavailable, not zero temperature/power. See telemetry docs for exact retention/fields.

## Disk unlock

Automatic TPM unlock remains enabled. **Disable TPM automatic unlock** first prepares
an administrator review, then requires explicit confirmation and a native disk-passphrase
check. The administrator password and disk passphrase are different credentials.
Never send either in chat. After successful disabling, future startup needs the disk
passphrase. The current desktop stays open. There is no re-enable/repair button:
repair is a future idea requiring separate reviewed recovery work.

## AppArmor protection and recovery

The AppArmor test boot and disposable enforcement check passed. The selected native
avahi-daemon and lsb_release profiles are enforcing; most desktop apps remain
unconfined. The package-wide loader is not enabled. No network service was started
or restarted to manufacture a process-confinement result.

The owner-approved tested image is now at the normal signed boot path. The previous
signed normal image is kept as **Arch Linux Zen - pre-AppArmor recovery** in the menu.
Default entry0 is unchanged. Automatic disk unlock worked in the actual candidate
boot; its image bytes are now the normal image. The normal-path reboot itself has
not been performed. Manual LUKS slot0 and the TPM policy remain unchanged.

See apparmor-trial-results.md and apparmor-promotion-review.md for exact evidence.
