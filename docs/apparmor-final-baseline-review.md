# AppArmor final file-reference review — 2026-10-20

The owner-approved AppArmor promotion completed and its exact image/menu/build-source
hashes were independently rechecked. Both selected native profiles enforce; the
actual test boot, permitted/denied read and owner hardware compatibility checks passed.
TPM/LUKS metadata is byte-for-byte unchanged; manual slot0 is present. The previous
signed image is preserved as pre-AppArmor recovery. No reboot was initiated.

Exactly one of42monitored files changed:
/etc/miku-boot/zen.cmdline
Before SHA256: e5fb9b71aeca275dd894ba339c870d0af7dad77aa68995248107611e00227d75
After SHA256: c5591f7221b885e4fd67e67ed02629651859c75eea6582c113bfb5440af50313
This appends apparmor=1 and lsm=landlock,lockdown,yama,integrity,apparmor,bpf to future
Zen image builds, matching the already boot-tested candidate. Ownership/permissions
match the prior reference. All41other monitored file records match exactly; no scope
was added/removed. No automatic acceptance of other changes occurred.

Approval updates only the change-detection reference and archives the previous one.
The implementation plan requires “Approve baselines explicitly.” It does not change
boot files, TPM, LUKS, device trust, network rules or trigger another reboot.

Exact candidate SHA256:
91953e86a252e8e8def57031fe3490f8cbb4abbdf0dc76d291b78547a1097a6a
Previous approved reference SHA256:
90b39d5e6cd95644644c9352e6e8f35389c995a5c84fd90a9e0a56353cd4aa25
Approved boot-promotion proposal:
ef926c04fd7f2b1f80664f086ed2036324d3b9057de45dc848aeb1bfc749b34f

Evidence: work/apparmor-promotion-result.json,
work/apparmor-final-reference-preparation.json, work/apparmor-enforcement-check.json,
work/apparmor-selected-runtime-check.json. The normal-path reboot itself is still
unperformed; the exact candidate image has already booted successfully. Most desktop
apps remain unconfined; two loaded profiles are not blanket application coverage.

## Approved, published and verified

Owner explicitly approved exact candidate91953e86… above. Captured publisher succeeded
and archived the previous reference. Current approved baseline SHA256:
f3eeb1556cc9ba9eeb43afddd5b88acb3202a8401ada26a53590d9e83b2cf5cf
Immediate privileged42-file scan:0changes/0unreadable. Receipt:
work/apparmor-final-reference-publication.json. No repeat approval is needed.
