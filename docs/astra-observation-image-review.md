# Astra checkpoint — observation package and measured UKI design, 2026-10-18

Sol implemented the staged observation-image contract through real Arch initrd
assembly and disposable boot. Next work crosses the production signed/measured
image boundary. Review only hard security issues and give Sol a concrete next
contract; preserve owner quota. No physical laptop image/signing/deployment/enrollment
or authentication change has been performed. Full project remains incomplete.

## Completed inputs and evidence

- initramfs/boot_observation.py, boot_observer.py, observation_entry.py and
  units/security-center-observation.service. Root-local bounded single record;
  unknown unlock/no enforcement/no attestation. Guest-only policy validator reused
  without publishing its deny decision. New record is separate from handover.py.
- initramfs/install/security-center-observation: staged hook includes selected
  Python runtime and fixed payload/config/unit/mapping-only dependency file.
- securityd/boot_observation_status.py, collector/Cockpit Boot registration;
  release/FIM/protected-file source allowlists extended to27/32. Installed25/30
  release and approved reference remain unchanged. Future source release captured
  at work/releases/monitor-yd7weseu predates the latest status marker test refinement;
  rebuild before any deployment proposal, do not treat that snapshot as latest.
- tools/observation_package.py + build-observation-package.py. Captured fixed input
  tree work/observation-package-emig3wgo,359files; input digest
  48d4a513a8f5d344ac6915879798fd8160c487366270cd10adc956e79cc7dee6.
  Runtime import test succeeded with only captured usr/lib64/etc available.
- tools/test-arch-observation-build.py: isolated unprivileged bwrap/fakeroot,
  synthetic /etc, read-only installed /usr+captured payload, --nopost, explicit
  config, no preset/UKI/signing/host boot/TPM/block/network access. Exact successful
  work/arch-observer-build-z7r5273a unsigned37,628,651B image SHA256
  1e5f2dbd97f27488182cf914530de0b6dac3b3192cf76536f09127ec702d89eb.
  Installed /usr tool source is not a pre-captured reproducible build environment.
- tools/arch_boot_fixture.py supplements that exact artifact, preserving native
  Arch /init, units/generators, rules/modules and existing native executable bytes.
  Explicit /arch-provision performs disposable formatting/enrollment before exec
  /init. Native helpers can be Arch BusyBox applets rather than hand-fixture ELF
  copies; keep the base helpers, do not overwrite them to match fixtures. Test-only
  /etc overrides and provisioning assets are declared. Original image and supplement
  bytes are combined and sealed; strict fixture archive inventory remains separate.
- tools/arch_initrd_manifest.py: bounded nonextracting parser for the observed
  early-newc + zstd-newc base, metadata and content digests for EVERY member in both
  ordered segments. Preserves raw names; accepts ./ and directory trailing slash,
  zero-link single payloads and <=10KiB zero archive padding (actual early padding
  was6400B). Rejects hardlinked payloads, special nodes, duplicate normalized names,
  unsafe names, truncation, trailing archive data, unsupported compression. External
  zstd bounded by15s/256MiB; temporary input under project work. Does not authorize
  an image or prove cross-segment/symlink runtime behavior. New module needs review.
  Early segment653members, main898members. Later report total includes supplement.

Python329testsPASS on host, including six archive negatives and four fixture-path/
substitution tests. Log work/arch-observation-python-tests.log. Earlier suite319
passed before these additions. Existing UI DOM regression passed; authenticated
Cockpit interaction/full active memory remains unverified.

Native Arch profile reports (work/luks-vm-*/report.json):
4u9shkgt successful observer; o416auxj masked observer;0ky6pari exit failure;
c36vmtu0 timeout; lwah0jmu memory OOM; wz_osdtg stock manual recovery after PCR7
mismatch. All passed exact generated/effective stock attach and encrypted-root
systemd, record presence/absence and postboot refusal. In the original minimal
native image, genuinely missing observer also passed; in the Arch image the unit
is embedded, so unavailable-unit test uses a mask, not a false missing-unit claim.
f4owq6lq exposed that distinction and its failed report is preserved.

Newest fully parsed/sealed-input successes:
- toeeek23, success6.62s, both base segments + fixture inventory bound. Its report
  member_count predates the total-count label correction; manifest itself is full.
- 1q5daial, stock manual recovery7.63s,1615ordered members, observer peak7,655,424B,
  actual PCR7 mismatch rejects TPM, one normal systemd console-agent input succeeds,
  no secret in console, no invented unlock provenance.
Both include actual producer SIGKILL before publication, record no-overwrite,
metadata/FIFO/symlink/hardlink/bounds negatives and file-entry replacement detection.
No guest helper process remains live. Previous intermediate aborted assembly/build
attempts are preserved in work and docs, not accepted as passes.

## Critical remaining trust gap — phase behavior

These boots use QEMU direct kernel/initrd, not UEFI/systemd-stub/Secure Boot.
The actual Arch systemd-pcrphase-initrd.service exists but ConditionSecurity=
measured-os is FALSE. Latest manual report explicitly records
VM_STOCK_PCRPHASE_CONDITION_NO. Tests sign fresh virtual PCR11/current+initrd-ref,
but do not exercise firmware/stub measurements or enter/leave-initrd transitions.
Do not claim they establish a laptop signed-UKI unseal or copy their current-PCR
signing shortcut into a production build. Future real UKI phase correctness must be
verified with the current config/public key and a disposable signed/stub boot.

## Review tasks / next narrow contract

1. Review new observation producer/reader, parser/decompressor bounds, package
   capture/verify and hook for hard boundary flaws. Privileged publisher must use
   captured bytes; none of these unapproved manifests grants root execution.
2. Decide exact separate laptop observation-image construction: preserve current
   kernel/stub/cmdline/PCR public key/normal default/recovery, add only observer
   payload+mapping dependency, fully account for library collisions/aliases and
   archive overrides. The generic synthetic Arch test image omits the laptop's
   Plymouth/autodetect/microcode/kms recipe and must NOT become its boot candidate.
   Do not silently append potentially conflicting runtime libraries to an existing
   image. Define source capture, permitted byte delta and signing verification.
3. Give Sol the disposable UEFI/systemd-stub signed-PCR11/initrd acceptance test
   contract that covers the phase gap above. Test-only keys/virtual firmware state
   only; no laptop TPM/keys/firmware changes. Keep software-gating/old-image/header
   bypass limitations explicit; strong Distress remains a separate design.
4. Return concrete Sol work and exact owner checkpoints for any later host build,
   signing, entry staging, one-time boot, recovery verification and promotion.
   Existing manual-slot0 and normal TPM path must remain. No re-enrollment to make
   an observation trial pass.

Read-only current host inspection: normal Zen preset points to /etc/miku-boot/zen.conf
and /boot/EFI/Linux/arch-linux-zen.efi. Effective config is systemd/sd-encrypt with
Plymouth, autodetect/microcode/kms, zstd -T1 -3; cmdline maps LUKS UUID to root,
tpm2-device=auto, Btrfs @, lockdown=integrity. /etc/miku-boot/zen-uki.conf exists
root0600,size395 but unprivileged read was denied; /boot traversal also denied.
Do not assume historical image SHA/stub still matches after updates. Historical
prepare-integrity-candidate.py documents the previous inspected workflow but is
NOT suitable to run again: it assumes no lockdown argument and identical initrd,
writes outside the current project scope, and has older source-hash assumptions.
Native admin authentication is already user-authorized, but production image work
still needs the explicit staged review checkpoint. Never request a password in chat.

Other ordinary remaining scope: authenticated UI and full RAM measurement,
telemetry export/download/erase UI, other enforcement integrations, device physical
classification/hotplug/DMA, Distress protocol/PAM and owner hardware recovery tests.
Do not redefine the project as complete because this observation stage passes.

## 2026-10-19 follow-up

Focused review completed; source fixes and new offline construction checks recorded
in overnight-progress-2026-10-19.md. Next contract is measured-observation-next-contract.md.
Firmware/stub execution and physical candidate approval remain pending. New source
requires the newly captured package/build, not the earlier artifacts above.
