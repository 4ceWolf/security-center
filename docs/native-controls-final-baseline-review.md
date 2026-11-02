# Final candidate, superseding the earlier f45f5c59… request

This final revision adds an explicit stop button because native window closing can
hide the GUI in the tray. The earlier unapproved transaction was safely rolled back,
then this reviewed revision installed. Scope/counts stay42/nine intended changes.
Only the exact candidate below should be approved/published.

# Native postboot controls — exact file reference review, 2026-10-20

Installed and independently checked: live USB rule review/apply controls, native
application-firewall window open/stop controls, native configuration integrity checks and
history tracking. The selected AppArmor profile unit is installed **disabled**;
profile loading and test-boot promotion are still separate pending checks.

Approving this reference records nine intended code/unit changes in a42-file scope
and archives the previous reference. It does not change USB trust, disk unlock,
TPM, signing keys, default boot entry or reboot the laptop.

Exact candidate SHA256:
2604fbc267c336aefb1ab4a15f9f626c489e148ab52719313ab5f34138c1fdab
Prior approved reference:
58eab555dda3f5b84f0192fa0f44a918c1a9f662a26f271819b83effa6a932db
Protected transaction:txn-053efb44ae9c22599ab967192efcc6e2
Release manifest:0a7cef21084954cfce924833b399634300f3dedb8a2a26d27fda53baff0ab121

Changed/new paths:
- /usr/local/lib/security-center/usb_policy.py
- /usr/local/lib/security-center/device-trust-helper.py
- /usr/local/lib/security-center/network_policy.py
- /usr/local/lib/security-center/adapters.py
- /usr/local/lib/security-center/history.py
- /usr/local/lib/security-center/integrity.py
- /usr/local/share/cockpit/security_center/index.html
- /usr/local/share/cockpit/security_center/usb-controls.js
- /etc/systemd/system/security-center-apparmor.service

The four new reference paths are usb_policy.py, network_policy.py, usb-controls.js,
and security-center-apparmor.service. Native USB policy/config and OpenSnitch
config/startup-override hashes are checked through their pinned adapters and explicit
per-policy root-private references; they are not silently added as mutable files to
the static code baseline. An owner-confirmed native USB rule change updates only its
specific audited reference, not this generic code baseline.

Evidence: affected transaction/release/adapter/history tests and Firefox synthetic
UI flows passed. Native USB IPC persistent append/remove passed using a redundant
block, with exact policy restoration and no device authorization changes. Real
OpenSnitch allow/deny/recovery passed with a private probe and the original firewall
preserved. Root-only installed native list/review checks do not apply any rule.
AppArmor candidate signed and staged with owner approval; actual boot/enforcement
and compatibility remain pending. Signed-in service memory measured93–125MiB across
three samples, including OpenSnitch and Cockpit, excluding the browser/native UI window.

## Approved and published

Owner approved exact candidate2604fbc267c336aefb1ab4a15f9f626c489e148ab52719313ab5f34138c1fdab.
Published reference b731cd86767d993ca744e91d18a14a20fc76074e96637bb29eff253d10b0e4d9.
Direct42-file scan:0changes,0unreadable. A subsequent owner request removes OpenSnitch;
that scope update needs its own replacement reference, not another approval here.
