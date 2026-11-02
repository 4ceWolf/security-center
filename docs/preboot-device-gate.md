# Device gate — future phase
No gate installed. Baseline the internal USB topology across multiple boots and power states. Do not trust HID class alone. Use combined IDs/interfaces/port/topology only as an operational policy, not proof of device identity. Investigate USB4/Thunderbolt/PCIe/IOMMU separately.

Gate must run before every automatic TPM unlock attempt; verify systemd generator/unit dependencies and alternative unlock paths. Unknown/failed scanning sends normal boot to manual recovery. Observe-only rollout first. Preserve usable internal keyboard.

Distress power-only policy requires accurate monitor/dock detection and an explicit recovery escape path. A software flag on the ESP can be removed/replayed by physical attackers. Do not call that fail-secure cryptographic enforcement. Old authorized UKIs may bypass a new software gate; resolve this before deployment claims.

## Offline evaluator implemented
policies/device_gate.py evaluates supplied inventory/policy data only. It is not deployed. All USB/Thunderbolt/external-PCI transport coverage must be claimed complete by the input; this evaluator cannot verify that claim. Identity matching uses transport, vendor/product, serial (may be empty), physical port and exact interface set. Policy marking a device internal must come from separately reviewed topology; never trust device self-description. Identity fields can be spoofed and do not provide cryptographic authentication.

Normal mode permits a TPM attempt only when every observed device matches an explicit internal or trusted-external record. Unknown devices, malformed/incomplete evidence, policy conflicts and bounds failures require manual recovery. Distress rejects trusted-external exceptions and always requires manual LUKS, even with acceptable devices. A rejected device state must also gate the later owner-authentication recovery transition; that integration is not implemented.

Power-only/display detection, enumeration completeness/stability, late hotplug, non-USB transport discovery, internal-keyboard verification, signed-initramfs integration, generator ordering and alternate/old UKI bypass are unresolved. No real machine allowlist has been approved. Tests use synthetic fixtures only and do not prove live preboot safety. Rollback of this stage is removal of offline source/tests; no host setting was changed.

Update: actual policy + unlock dispatcher now execute inside the disposable VM with synthetic inventories. Real virtual TPM/manual operations confirm rejected inventories never invoke the TPM adapter. No real hardware inventory collector or systemd unit integration yet. See testing.md for evidence and exact scope.

Read-only USB acquisition now implemented in policies/device_inventory.py and live-tested against the approved receiver. Full-device inventory remains incomplete and explicitly denies automatic unlock. See testing.md; this is not an installed preboot gate.

Platform observation implemented separately in policies/platform_inventory.py. Current host shows 20 PCI functions/no Thunderbolt entries, but no active IOMMU evidence. Kernel supports Intel IOMMU but does not default it on; DMAR exists. Treat DMA isolation as unverified pending dedicated review/testing; do not silently add a boot option. See testing.md.
