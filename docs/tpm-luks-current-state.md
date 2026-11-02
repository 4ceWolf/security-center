# Existing TPM repair
User-reported history: changing a BIOS USB-boot setting caused “TPM policy does not match current system state.” TPM was not cleared. A header backup was saved as /home/user/Projects/security-center/docs/recovery-backups/luks-header-before-tpm-reenroll.img (root:root 0600). The existing embedded PCR public key was recovered and reused. TPM re-enrollment replaced old slot 1 with slot 2; manual slot 0 remained. User confirms auto-unlock now works.

Reported enrollment parameters: /dev/nvme0n1p2; direct PCR7; signed PCR11; SHA256; policyref initrd; RSA primary; SRK enabled; PIN disabled; PCRLock disabled. Approximate historical command (NOT to rerun): systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 --tpm2-public-key=<existing-public-key> --tpm2-public-key-pcrs=11 --tpm2-public-key-policyref=initrd /dev/nvme0n1p2.

Current inspection confirms slots 0 and 2 and token 1 of type systemd-tpm2 referencing slot 2. Metadata uses tpm2-pcrs and underscore-form fields tpm2_pubkey_pcrs, tpm2_pubkey_ref, tpm2_srk; collectors must not assume only hyphenated field names. Private material and TPM sealed blobs must not be exposed in UI or logs.

PCR7 configuration changes and authorized PCR11 measurements are different issues. A token being present is not proof of successful unseal. The current cryptsetup journal only records start/finish, so unlock method remains unproven from those logs. Do not modify enrollment to implement lockdown or temporary distress.
