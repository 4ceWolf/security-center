# Security Center delivery — 2026-10-20

Current owner-approved scope is installed and verified. No approval is pending.

- Secure Boot, kernel integrity lockdown, encrypted root, working TPM automatic
  unlock and manual recovery slot are preserved. The TPM-disable control is installed
  but was never invoked on this laptop. TPM repair remains a future idea.
- Local Cockpit dashboard, persistent bounded observations, integrity checks,
  diagnostic telemetry and its export/clear controls are installed. Existing passing
  tests were reused; affected changes received targeted checks and installed verification.
- Postboot USBGuard and exact native trust review/apply controls are installed. Both
  saved receivers remain trusted, including keyboard-interface warnings. Native
  policy/config fingerprints verified;7current devices allowed. Earlier physical
  receiver reconnect/input check passed. No fake serial was invented.
- OpenSnitch removed at owner request; existing independent firewall preserved.
  Networking owner-managed. Its experiment is kept inert in ideas/history.
- AppArmor actual trial and disposable allowed/denied reads passed, temporary profile
  removed. Owner confirmed auto-unlock, Wi-Fi, sound, inputs and sleep/wake. Only
  avahi-daemon/lsb_release profiles loaded/enforcing. Avahi inactive and not restarted;
  lsb_release has no automatic attachment. Most desktop apps remain unconfined.
- Exact approved tested image promoted to normal; previous signed image kept as
  pre-AppArmor recovery. Future Zen build cmdline retains AppArmor. Normal default
  index0 unchanged; no automatic reboot or TPM/key/LUKS policy mutation.
- Final approved reference42paths: f3eeb1556cc9ba9eeb43afddd5b88acb3202a8401ada26a53590d9e83b2cf5cf.
  Immediate privileged scan0changes/0unreadable. Previous reference archived.

Memory: three earlier detailed active-stack samples were112.21–114.26MiB including
the since-removed OpenSnitch daemon, excluding browser/shared desktop/optional GUI.
AppArmor uses kernel profiles and a bounded oneshot loader, not another persistent
userspace daemon. No new whole-stack peak measurement was made after this rollout;
the200MB preference is not a guarantee for browser or optional GUI memory.

Normal image SHA256:9a3528a78f353c79328779300e00b3907730ef789ebf12795192208617cfcda2.
Recovery image SHA256:df39115ec7c3017987f1b9dad95d05026ebc93edb45d75b542aa693c9fb0d987.
Recovery instructions: postboot-recovery-20261020.md. User guide: using-security-center.md.
Final receipts: work/apparmor-promotion-result.json,
work/apparmor-final-reference-preparation.json,
work/apparmor-final-reference-publication.json, work/apparmor-final-stack-check.json.

Limits: the normal-path reboot itself was not repeated; identical image bytes were
actually booted as the test entry. The new recovery menu path was not separately
boot-tested; its signed bytes equal the previous working normal image. No live TPM
disable or disaster-recovery operation was performed to prove a destructive path.
Local monitoring is not a root-compromise-resistant attestation or malware guarantee.
Custom preboot enforcement/handover and Distress are removed, not unfinished tasks.
OpenSnitch and TPM repair remain deferred ideas. Future expansions need a new request.
