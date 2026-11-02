# Threat model and limits
Protect against network exposure, accidental misconfiguration, ordinary malicious programs, opportunistic physical access and suspicious device attachment. Kernel integrity lockdown narrows privileged kernel modification paths. Root compromise can still read decrypted files, kill monitoring, alter future policy/configuration and forge ordinary root-owned records. No local dashboard proves the absence of compromise.

Trust anchors: firmware Secure Boot keys, signed UKI, kernel, existing TPM PCR7 plus signed PCR11 policy, manual LUKS recovery secret. Existing signing private keys on the running encrypted root are highly privileged assets; a root attacker may abuse them. Their presence limits resistance to sustained root compromise.

A USB VID/PID/serial or topology is spoofable. Root-only volatile handover protects against unprivileged modification, not root forgery. A local signature using a root-readable key is not independent attestation. Verified claims need evidence with explicit provenance and freshness.

A device check that only suppresses one initramfs cryptsetup invocation does not necessarily prevent an attacker from attempting the same TPM token through another authorized boot path. Old signed images may still be authorized. A genuine enforced device/distress gate requires TPM policy design or a constrained trusted unlock path and rollback analysis. Do not advertise a software-only flag as cryptographic protection.

Physical device detection cannot prove power-only for every charger, display, Thunderbolt or internal bus. USB-C docks can expose multiple functions; PCIe DMA needs separate IOMMU/firmware investigation.

Denial of service: fail to manual recovery on ambiguous gate state, never destroy keys. Distress state reset requires authenticated owner recovery and boot-bound evidence; root auth alone cannot prove the LUKS passphrase was used. Do not infer it.

Out of scope initially: remote attestation verifier, protection from compromised firmware/kernel, covert recording, anti-forensic destruction, automatic malware eradication.
