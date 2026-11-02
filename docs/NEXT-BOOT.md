# Next routine boot
Use the normal **Arch Linux Zen** entry. It now contains the exact integrity-enabled image already boot-tested. Automatic TPM unlock and desktop operation succeeded in the candidate test; the owner also confirmed sound, sleep/wake and Wi-Fi.

After the next routine reboot, confirm normal entry selection and automatic unlock. Run tools/check-integrity-boot.py for enforcement checks. No immediate forced reboot is required.

If needed, choose **Arch Linux Zen - pre-integrity recovery** for the original signed image. Preserve Secure Boot and TPM settings. The manual LUKS passphrase remains available.
