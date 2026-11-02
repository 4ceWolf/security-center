# Owner-approved external receiver

Owner reports currently connected external devices are power and the mouse receiver, which also supports a keyboard normally switched off. Owner explicitly requested adding the receiver as trusted.

Observed 2026-10-15: A4tech 2.4G Wireless Device; manufacturer HS6209; VID:PID 09da:0025; bcdDevice 0200; no USB serial exposed. Interfaces: HID boot keyboard 03:01:01 and HID boot mouse 03:01:02. Trust includes both advertised interfaces regardless of whether the paired keyboard is powered on. This does not disable keyboard input from the receiver.

Physical path at observation: /sys/devices/pci0000:00/0000:00:14.0/usb3/3-1. Policy uses controller PCI address 0000:00:14.0 plus USB route 1, rather than the boot-dependent bus number 3. Canonical identifier: pci:0000:00:14.0/usb:1. Real inventory acquisition must emit that same canonical form. Moving to another port, changing interface set, product ID or advertised serial requires review. Identifiers are spoofable, especially without a serial; this is an operational exception, not cryptographic identity.

Saved policies/normal-devices.candidate.json with this explicit external exception. Internal topology remains empty/unapproved, so this is NOT a deployable full-machine allowlist. Do not use a synthetic complete=true fixture as proof that actual hardware inventory is complete. No root-installed or preboot policy changed.

Distress Mode remains power-only: this receiver is a normal-mode exception and is denied in distress. Charger acceptance cannot be inferred from absence in USB inventory. Integrated camera and Bluetooth were observed as fixed internal USB devices, but were not silently added to the approved policy.

Rollback: remove the receiver entry from the undeployed candidate after owner review. No installed enforcement depends on this file yet.
