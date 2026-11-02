# AppArmor trial results — 2026-10-20

The owner booted the previously approved AppArmor test image and confirmed:
“disk unlocked automatically. wifi, wake, keyboard n mouse n sound worked”.
Kernel7.2.10-zen1-1-zen reports AppArmor=Y and AppArmor in the active LSM list.
Integrity lockdown remains enforced. Fresh collector observed Secure Boot enabled,
encrypted root/manual recovery slot present, telemetry recording, USBGuard7allowed,
no failed system units and0file changes/0unreadable.

A disposable named profile allowed its permitted file read and denied its forbidden
file read. The tool removed only that temporary profile/files and returned success.
Evidence: work/apparmor-enforcement-check.json; its error log is empty. This proves
kernel enforcement of that fixture, not all desktop application confinement.

The fixed two-profile unit was hash-verified against the installed release before
start/enable, along with both native profile hashes. Update lock directory/file
ownership and permissions are now checked by the local enable tool. Loaded/enforcing:
avahi-daemon and lsb_release. Dedicated service active/enabled; package-wide service
not enabled by this operation. No authentication-helper profile requested. Evidence:
work/apparmor-selected-enablement.json and work/apparmor-selected-runtime-check.json.
Avahi is inactive: no running Avahi process was claimed confined or started just for
this test. lsb_release has no automatic attachment. Most desktop apps remain
unconfined; Security Center correctly reports application coverage unverified.

After these trial checks, the owner separately approved exact normal promotion.
The tested image is now at the normal path; the previous signed image is retained
as pre-AppArmor recovery. Default index, TPM/LUKS enrollment and keys are unchanged.
The final file reference was separately approved and published. See
apparmor-promotion-review.md and apparmor-final-baseline-review.md.
