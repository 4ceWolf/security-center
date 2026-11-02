# Actual Arch test-image boot — disposable integration design, 2026-10-18

Boot the exact successful unsigned mkinitcpio artifact, plus a separately inventoried
fixture archive. The original Arch image bytes and native /init, units, generators,
udev rules, drivers and observer payload remain in the input. A fixed test-only
/arch-provision is selected as kernel rdinit to format the disposable vda, prepare
a minimal encrypted test root and enroll a fresh software TPM before executing
Arch's existing /init. This is explicit fixture provisioning, not laptop code.

Supplement only missing provisioning executables/libraries, standalone test scripts,
disposable known /key and /wrong, test policies, and a small reviewed list of /etc
fixtures/dependency overrides. No replacement of /init or /usr native executables,
units/generators/udev rules/observer. Match overlaps byte-for-byte or refuse. The
policy source-digest and root-mapping-specific test dependency files are explicit
fixture changes. Preserve base image and generated-tree manifest hashes in report.
The complete combined compressed input is sealed before QEMU receives its fd.
The supplemental archive has its own strict single-newc inventory; the base's early
CPIO + zstd layout remains separately byte-bound and not yet fully decoded by our
single-archive parser. No claim of complete segment analysis or Secure Boot.

Keep stock generated root attach and native target/mount/switch-root. Root uses the
fixture name cold_root, not the captured production mapping root. No host disks,
TPM, network, firmware/UKI or real credentials. Success must retain existing native
stock checks and observation file negatives. Failures are retained and diagnosed;
do not mask native PCR phase, agent or generator differences to obtain a pass.
