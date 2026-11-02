# Passive initrd observer implementation — 2026-10-18

Status: staged source and disposable-guest integration. No laptop deployment,
boot image/signature, TPM enrollment, LUKS slots, default entry, PAM or approved
FIM baseline changed. The full project and hardware review remain incomplete.

## Implemented

initramfs/boot_observation.py provides a strict bounded single-record schema and
root-private no-follow read/publication. It checks current boot, finite ordered
sample times and exact diagnostic codes/counts. Historical records remain valid
through the current boot. Atomic hard-link publication refuses overwrite; final
record must be single-link after temporary cleanup. Interrupted publication can
leave absent evidence; readers never interpret a partial file as success.

initramfs/boot_observer.py samples read-only USB/PCI/Thunderbolt observations and
validates the embedded candidate policy. It keeps attested=false, coverage=false,
unlock_method=unknown and enforcement=not_enabled. The guest-only gate observer
is reused solely for policy validation; its temporary decision is discarded and
never published. Raw scanner error strings are reduced to fixed codes. The fixed
isolated entrypoint inserts only /usr/lib/security-center-observation. Postboot
execution refuses before inventory/publication when /etc/initrd-release is absent.
Root remains trusted and can forge local records; this is not attestation.

The staged oneshot has 5s start/1s stop bounds, 64MiB MemoryMax, private retained
runtime directory, no console input and no resident process after collection.
The mkinitcpio install-hook draft includes a selected Python runtime and fixed
payload/config/unit inputs. It has only had a syntax check, NOT a full mkinitcpio
build or runtime/dependency completeness review. A captured image package and
exact input manifest/publisher are still required before it can be installed.

securityd/boot_observation_status.py and collector registration add an independent
read-only status. Cockpit Boot includes the row and safely renders evidence through
its existing textContent path. Missing, not-installed, rejected, incomplete and
observed-with-limitations states cannot report secure or infer unlock provenance.
The candidate trust store remains distinct from the embedded policy digest.
Release/FIM/protected-file source allowlists include both new postboot modules
(27 release files, 32 total monitored paths). Installed release remains the prior
25-file/30-path release. No new candidate baseline has been approved or requested.

## Native guest evidence

Run on host through flatpak-spawn --host --directory=/home/user/Projects/security-center:
`/usr/bin/python3 tools/test-luks-vm.py --stock-observation MODE`.
The native fixture retains actual generated stock systemd-cryptsetup attach and
its TPM-only headless options. It adds only Wants/After the observer. The verifier
checks generated/effective commands and graph, actual root backing device and
successful service; host driver refuses unexpected credential prompts. The test
record itself always reports unlock method unknown. Fresh disposable software TPM
uses PCR7 + signed PCR11/initrd. No host TPM, disk or network is exposed.

| Scenario | Evidence directory under work/ | Result |
| --- | --- | --- |
| Observer success, retained record and postboot refusal | luks-vm-4f00bude | PASS, 7.55s, observer peak 7,839,744B |
| Success plus private-file negative tests | luks-vm-4y43z03f | PASS, 7.84s, observer peak 7,540,736B |
| Observer missing | luks-vm-sr5e8jpa | PASS, 7.74s, stock TPM unlock |
| Observer exits unsuccessfully | luks-vm-q0g1zx_w | PASS, 7.74s, stock TPM unlock |
| Observer times out | luks-vm-u8cpli8i | PASS, 13.42s, Result=timeout, stock TPM unlock |
| Observer killed by memory limit | luks-vm-6yu8705m | PASS, 8.05s, Result=oom-kill, stock TPM unlock |

The successful-file case rejects world-readable files, additional hardlinks,
symlinks, FIFOs, oversized content, duplicate publication, incomplete pending files
and writable parent directory. These checks run as guest root on actual /run.
No disposable password appears in console. Sealed initrd descriptor and complete
single-newc manifest identify the exact bytes for every report. The source manifest
is a claim, not artifact authorization; mutated failure fixtures are bound by the
final archive manifest. Kernel/firmware are outside this archive binding.

Preserved failure reports: luks-vm-dpbwv3k7 exposed that the minimal guest lacked
independent udev-trigger activation when the observer was absent. That fixture was
stopped, recorded failed, and corrected with an initrd-target udev dependency.
luks-vm-9dm8ihta and luks-vm-64dt78qz exposed verifier timing/reexecution after initrd
cleanup had discarded failure state. Verifier now runs before cleanup and remains
active to prevent reexecution. No production failure policy was relaxed.

Python suite: 312 tests PASS (work/observation-python-tests.log). After a subsequent
status wording refinement, the 10 observation/status tests PASS again. Cockpit DOM
regressions PASS including Boot filtering and explicit enforcement limits. This is
not authenticated browser verification. Hook bash syntax check PASS. Early suite
failures while integrating new release paths were corrected by matching the
protected-file allowlist and explicit 27/32-file test expectations; no deployment
verifier was bypassed. All launched guest/emulator sessions finished.

## Read-only laptop build inspection

Current /etc/mkinitcpio.d/linux-zen.preset points at /etc/miku-boot/zen.conf,
/boot/vmlinuz-linux-zen and /boot/EFI/Linux/arch-linux-zen.efi. The effective Zen
config overrides the base config with systemd/sd-encrypt hooks and zstd -T1 -3.
Current command line maps the LUKS UUID to root, uses tpm2-device=auto, Btrfs @ and
lockdown=integrity. root-mapping for an eventual production package is therefore
root, not cold_root. Do not run the normal preset to build this observer.
/etc/miku-boot/zen-uki.conf could not be read without administrator access; its
signing recipe is still unverified in this pass. No password prompt was requested.
The host kernel used by the new guests is now 7.2.10-zen1-1-zen, per actual harness;
prior 7.2.9 observations are historical.

## Remaining ordinary implementation before specialist image checkpoint

- Native stock password-agent recovery after deliberately invalid guest TPM policy
  (current stock tests are headless TPM positives/failure-of-observer cases).
- Test final verifier ordering with success/absent/failed profiles after the latest
  verifier-only timing correction; existing passing reports above predate that
  correction except timeout/memory. Do not erase their exact manifest distinction.
- Explicit installed-marker tests and producer-death during actual publication,
  plus changed-during-read/path ancestry adversarial cases.
- Capture the full runtime/package, validate the mkinitcpio hook in a full Arch
  disposable image, manifest all segments/dependencies, and propose a separate
  signed-image build with exact commands/outputs/rollback. Do not install yet.
- Authenticated Cockpit verification and full active memory, download/erase/export
  controls and other original project features remain outstanding.

Rollback for this milestone is removal of staged source registration/payload as one
reviewed release change; installed laptop state needs no rollback. Any future
installation must use captured immutable release bytes and the existing transaction
and explicit baseline approval. The boot package is a separate approval boundary.

## Follow-up — stock manual fallback and captured package, 2026-10-18

Stock native fallback now PASS: work/luks-vm-ou2rqzto/report.json,7.11s. The fixture
extends virtual PCR7 after enrollment, actually confirms a headless TPM attach
fails and leaves no mapping, then boots the real generated service with headless
removed. The installed systemd console path/service and tty password agent handle
one disposable passphrase request; the unchanged stock attach opens the guest disk
and reaches encrypted-root systemd. No custom manual adapter is invoked. The
observer still records unlock_method=unknown; test evidence is separate. The
headless-positive profiles still refuse any unexpected password prompt.
This is correct-input stock fallback only, not native stock wrong/cancel/timeout
coverage or real laptop Argon2id/keyboard/recovery verification.

Current verifier-ordering regression reports all PASS:
success work/luks-vm-7qo7y9_e (8.15s), absent work/luks-vm-x2540_zd (9.88s),
failed work/luks-vm-lvhn4j50 (7.90s). Timeout/memory reports from the preceding pass
use the same retained-before-cleanup verifier design. Further success run
work/luks-vm-74v_kaft (7.94s) includes an actual forked producer killed with SIGKILL
at publication: no boot.json becomes available. It also replaces the final directory
entry during a reader check; the reader detects the inode mismatch. Both negatives
are additional to the earlier metadata/FIFO/symlink/hardlink bounds.

New tools/observation_package.py + build-observation-package.py capture fixed
observer code/unit/hook/policy, selected installed Python stdlib/extensions and ELF
dependencies into a new project-local tree. No host files are installed. The source
manifest excludes itself and source.sha256; final package manifest binds captured
bytes/metadata and that digest file. verify rejects member changes, unsafe paths,
symlink metadata/root, manifest mismatch and unexpected installed/approved flags.
Six new package tests pass. An additional installed-marker status test distinguishes
not-installed from installed-but-record-missing. Full Python suite319PASS, recorded
in work/observation-python-tests.log.

Capture command: `/usr/bin/python3 tools/build-observation-package.py --mapping root`
through the host flatpak-spawn wrapper. Captured package:
work/observation-package-emig3wgo,359files, inputs SHA256
48d4a513a8f5d344ac6915879798fd8160c487366270cd10adc956e79cc7dee6.
A separate unprivileged bwrap with only its captured usr/lib64/etc and synthetic
proc/dev/tmp successfully imports the observer and inventory dependencies. No full
host library tree was available to that import test. This is import completeness,
not full runtime or image approval. See observation-package-design.md.

`/usr/bin/python3 tools/test-arch-observation-build.py --package
/home/user/Projects/security-center/work/observation-package-emig3wgo` (one command,
host wrapper) builds an UNSIGNED disposable initrd using actual mkinitcpio42.2 inside
bubblewrap with synthetic /etc, read-only installed /usr plus captured payload,
no host /boot, signing keys, TPM, block devices or network. --nopost, explicit
synthetic config, no preset or UKI option. fakeroot supplies package ownership
metadata inside the unprivileged namespace; it grants no host administrator rights.
A first attempt work/arch-observer-build-vbmj58s1 failed because its output directory
was absent, then because host-root ownership is unmapped in the namespace. Preserve
those logs; neither result was accepted. The repeatable tool uses fakeroot.

Successful result: work/arch-observer-build-z7r5273a/report.json. Returncode0;
37,628,651B image SHA256
1e5f2dbd97f27488182cf914530de0b6dac3b3192cf76536f09127ec702d89eb.
Generated-tree manifest898members, SHA256
4ea97249c8803a511cde8644b1909d665db65b4d3cc6b714e9b4634bdfedd2dd.
The tool checks exact captured observer/record/unit/source-digest inclusion and the
dependency-only mapping drop-in. lsinitcpio identifies an early CPIO plus zstd main
image and Python/systemd-cryptsetup/password-agent binaries. The generated-tree
manifest is not a parser of every archive segment or proof that this image boots.
Installed tool/package versions and the resulting artifact are recorded, but the
whole installed /usr tool source was not pre-captured as a reproducible build input.

Remaining before laptop image proposal: boot the actual Arch-built disposable image,
inspect/bind every archive segment and complete runtime, validate production signing
recipe read-only (protected file still needs administrator authentication), prepare
exact separate UKI build/rollback manifest for specialist/owner checkpoints. No
host image has been built, signed, installed or selected; this file is an unsigned
test initrd, never the normal preset output. Actual root mapping in its captured
package is root; guest-only cold_root fixtures remain separate. No TPM/NV/LUKS/PAM
change and no new baseline approval occurred. All test handles completed.

## 2026-10-18 — actual Arch image boot and segment inventory

Booted the exact unsigned mkinitcpio artifact plus a declared provisioning/test
supplement. Native Arch /init, units/generators/rules/drivers and existing executable
bytes preserved; disposable /arch-provision selected by rdinit then execs /init.
All six scenarios PASS: observer success/masked/failure/timeout/OOM and stock manual
recovery after actual TPM policy refusal. Newest fully parsed/sealed-input manual
report work/luks-vm-1q5daial passes7.63s,1615ordered members, no secret exposure.
Parser now inventories both observed base segments (653early+898main) plus fixture
archive. Six malformed-archive tests and four fixture-path/substitution tests bring
host suite to329PASS, work/arch-observation-python-tests.log.
The actual native PCR phase unit is skipped: ConditionSecurity=measured-os false
for direct kernel boot. Firmware/stub/Secure Boot and real phase transitions remain
unverified. No laptop boot/key/PAM/enrollment/baseline change.
Next specialist checkpoint: astra-observation-image-review.md, including exact
reports/hashes, parser/runtime review, production recipe/library collision handling
and a disposable signed-UKI phase test contract. Full project remains incomplete.
