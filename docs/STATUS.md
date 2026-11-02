# Security Center — current status, 2026-10-20

AppArmor trial boot and disposable kernel enforcement PASSED. Owner confirms automatic
disk unlock, Wi-Fi, sound, keyboard/mouse and sleep/wake. Two selected native profiles
are loaded/enforcing and their dedicated loader enabled. Most desktop apps remain
unconfined; no blanket coverage claim. Actual Avahi attachment was not demonstrated
because its service is inactive; lsb_release has no automatic attachment.

Secure Boot, integrity lockdown, encrypted root/manual recovery slot, telemetry and
USBGuard remain healthy. No failed system units; current file reference clean.
Native USB management is installed; both approved receivers remain trusted. Native
policy/config fingerprints verified; currently7allowed/0blocked/0rejected. Existing
receiver reconnect/input compatibility had already passed.

OpenSnitch package, GUI, daemon, startup and active configuration are removed. Existing
firewall rules were verified unchanged. Networking is owner-managed; remaining
firewall/listener observations are read-only. Integration saved in ideas.md. Removal
candidate350c5194… was explicitly approved and published; no removal approval remains.
Its final fresh collector scan:0file changes/0unreadable, all37release hashes match.

TPM automatic unlock remains enabled. Disable button is installed but never invoked.
TPM repair is deferred to ideas. Custom preboot gating/handover rollout and Distress
are removed from scope. No TPM/key/LUKS policy changes are authorized by AppArmor work.

## Current scope delivered

Exact boot promotion ef926c04… was owner approved, applied and independently verified.
Normal image is the boot-tested9a3528a7…; signed previousdf39115e… retained as
pre-AppArmor recovery. Menu/build-source hashes match the reviewed proposal; TPM/LUKS
metadata unchanged, manual slot0 preserved. Default index0 remains unchanged.

Owner approved final file candidate91953e86… and publication succeeded. Current
approved reference SHA256:
f3eeb1556cc9ba9eeb43afddd5b88acb3202a8401ada26a53590d9e83b2cf5cf
Direct privileged42-file verification:0changes/0unreadable. No approvals pending for
the current scoped delivery. See completion-20261020.md and HANDOFF for receipts.
Do not keep building deferred features or repeating completed tests unattended.

A later normal-path reboot is distinct from the successful candidate boot. No
reboot has been initiated. Most desktop applications remain unconfined; neither
profile count nor completion means comprehensive application isolation. Broader
profiles or deferred features require a new owner request. Periodic updates and
ordinary maintenance remain ongoing responsibilities, not unfinished construction.

Detailed current evidence: apparmor-trial-results.md, apparmor-promotion-review.md,
HANDOFF.md. User guide: using-security-center.md. Historical status remains under
history/ and is superseded where current scope differs.
