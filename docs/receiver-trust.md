# Approved external receiver candidates

The user has authorized both receivers below for normal-mode trust. They remain
in `policies/normal-devices.candidate.json`; this is not deployed USBGuard or
preboot enforcement. Distress Mode does not allow trusted external exceptions.

| Receiver | USB ID | Serial | Physical route | Interface classes |
| --- | --- | --- | --- | --- |
| Existing A4tech | 09da:0025 | Not exposed | pci:0000:00:14.0/usb:1 | Keyboard 03:01:01 and mouse 03:01:02 |
| Logitech M185 | 046d:c542 | Not exposed | pci:0000:00:14.0/usb:1 | Mouse 03:01:02 |

The Logitech addition was explicitly requested on 2026-10-16 while connected.
Two consecutive sysfs inventories agreed, without USB observation errors; lsusb
also identified the Logitech M185. The existing receiver was not connected in
this observation and its prior authorization was retained. Evidence is in
`work/logitech-receiver-observation.json`.

Neither receiver exposes a serial number. Matching therefore uses USB ID,
physical controller/route and the full interface multiset. These descriptors
can be spoofed; this is a narrow allowlist, not cryptographic device identity.
A different port or added keyboard interface will not match the Logitech entry.
The test verifies those cases and that Distress still denies a TPM attempt.
It uses a synthetic complete inventory: real all-transport coverage remains
incomplete, and internal devices have not been approved through this addition.

Rechecked on 2026-10-18 at the user's request: the connected Logitech receiver
still exactly matches the approved candidate (ID, absent serial, route and
mouse-only interface). No duplicate or broader trust rule was needed. Host USB
observation reported no errors; all-transport preboot coverage is still incomplete.
Cockpit management requirements are in `docs/trusted-device-management.md`.
