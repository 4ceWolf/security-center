# Superseded candidate — do not publish

The f45f5c59… candidate below was superseded before approval/publication to add an
explicit stop control for the native GUI (closing its window only hides it).
Use native-controls-final-baseline-review.md for the final candidate. Any reply to
this older candidate does not approve different bytes. Its transaction is rolled
back before installing the final release; prior approved reference58eab555… remains.

# Native postboot controls — exact file reference review, 2026-10-20

Installed and independently checked: live USB rule review/apply controls, native
application-firewall window launcher, native configuration integrity checks and
history tracking. The selected AppArmor profile unit is installed **disabled**;
profile loading and test-boot promotion are still separate pending checks.

Approving this reference records nine intended code/unit changes in a42-file scope
and archives the previous reference. It does not change USB trust, disk unlock,
TPM, signing keys, default boot entry or reboot the laptop.

Exact candidate SHA256:
f45f5c593bd8cc680573e41cf58bb8bc4ae6becd8cc7360f103de5371ac358ba
Prior approved reference:
58eab555dda3f5b84f0192fa0f44a918c1a9f662a26f271819b83effa6a932db
Protected transaction:txn-b01e2e9f26ea10771bca157d40b936bc
Release manifest:cbb5e5ab57b7a737ef7835637b74376633f2b1d729f4a379e5b211b6cca8b010

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
