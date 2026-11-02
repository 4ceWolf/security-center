# USBGuard read-only adapter

Contract: check native service availability first; only query an active daemon with the fixed `/usr/bin/usbguard list-devices` argv. Never call allow/block/reject, generate-policy or service enablement. Current authorization is not an assertion that the policy is correct or the device is trusted.

Primary references consulted:
- https://github.com/USBGuard/usbguard/blob/main/doc/man/usbguard.1.adoc — list-devices and internal numeric device IDs.
- https://usbguard.github.io/documentation/dbus/doc-org.usbguard.Devices.html — device-specific rule target represents current authorization; returned order is not guaranteed.
- https://usbguard.github.io/documentation/rule-language — device/interface/port identity attributes.

Built in securityd/adapters.py. A bounded pipe reader limits stdout to1MiB and runtime8seconds, kills/reaps a failed/timed-out command, discards command stderr and exposes a generic unavailable state. Parser limits256devices and8192characters per record, verifies unique uint32numeric IDs, allow/block/reject target and VID:PID. Remaining rule attributes are deliberately opaque display text, not a policy parser or executable instructions. Unknown syntax fails unavailable; no partial result is labeled complete. UI already uses textContent for evidence rendering.

Running/query-success remains unknown with policy_verified=false; the summary shows allow/block/reject counts. Blocked devices are not automatically incidents. Missing daemon reports not installed; active daemon/query failure reports unavailable. No identity is silently adopted as trusted, including the user's serial-less receiver. The receiver fixture preserves both03:01:01and03:01:02interfaces in displayed attributes.

Ten new tests cover fixed query, absent/inactive behavior, daemon access failure, duplicate/invalid/oversized records, empty inventory, hostile-looking display strings, both receiver interfaces, process stdout cap, timeout and exit failure.116project tests pass. Read-only laptop check confirms USBGuard is not installed. Full packaged-daemon rehearsal monitor-ta3f179g passed16modules, crash/restart history, invalid request and database failure isolation before the timeout parameter was made injectable for its dedicated unit test (default still8seconds).

Not installed/deployed; actual native USBGuard output on this laptop still needs validation after a reviewed native installation. Preserve input/recovery access and explicitly approved topology before any enforcement. This adapter adds no persistent service and makes no root policy changes. Future integration should normalize detailed attributes via a verified native parser/interface and add native authorization event ingestion; opaque attributes do not satisfy those later capabilities.
