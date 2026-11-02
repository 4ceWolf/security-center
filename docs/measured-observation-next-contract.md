# Measured observation image: next implementation contract

2026-10-19. Specialist review of the staged observer/package/Arch inventory code.
This is a design and implementation contract, not approval of a laptop boot image.
No protected host configuration, signing key, ESP or hardware TPM was accessed.

## Review disposition

The observer remains passive history. Its record cannot establish TPM unlock,
Secure Boot, device authorization, absence of hotplug or DMA protection. The root
publisher/reader permissions protect against ordinary users, not malicious root.
The initrd marker is an environment guard, not proof of when code executed.
Wants/After preserves stock unlock availability in the tested guest scenarios.
The service is resource-limited but not a complete filesystem/device sandbox.

Two defects were repaired in source: observation decoding now converts excessive
JSON nesting and numeric overflow to normal rejection; staging package verification
uses bounded nonblocking regular-file reads with before/after/current-entry checks,
and enforces capture's total-byte and member-count limits. FIFO substitution is
rejected rather than hanging. These are reliability/boundary repairs, not evidence
of an observed attack. Package verification is still unprivileged staging validation;
it does not secure mutable ancestors against an active writer or authorize a later
privileged process to reread project paths. Such a publisher must capture its own
immutable bytes and verify those bytes against a separately approved digest.

The Arch parser has explicit image/member/decoded/entry/time bounds, inventories
both supported segments and does not extract. Its result is not an effective merged
filesystem. Symlink ancestry, archive ordering and repeated paths across segments
must be resolved before any production delta is accepted. Do not turn a successful
inventory result into permission to append runtime files or sign an image.

The hook reads its runtime from the build namespace. Capturing a package alone does
not prove the namespace used exactly those inputs: the synthetic test also sees
installed /usr. Production needs an isolated captured input set, with final-byte
checks, rather than treating this synthetic build as reproducible or approved.

## Disposable measured-boot test design

Use a separate project-local harness, fresh software TPM, private copied OVMF VARS,
installed read-only OVMF CODE, project-local virtual disk/ESP, and fresh disposable
PCR signing keys. No physical TPM/block device, host ESP, efivarfs write, firmware
update, laptop signing key or network. Record tool/firmware/kernel/stub hashes.
Do not repurpose the current direct-kernel success reports as measured-boot passes.

Read-only preflight found OVMF_CODE.4m.fd, OVMF_CODE.secboot.4m.fd and OVMF_VARS.4m.fd
under /usr/share/edk2/x64; installed ukify and systemd-stub are present. A
virt-fw-vars executable/module was not found in the inspected locations. This is
not proof that Secure Boot provisioning is impossible; it means that branch needs
its own inspected disposable-variable provisioning implementation. Do not install
packages or touch host firmware merely to satisfy the test.

First test measured UEFI boot, reporting Secure Boot separately as disabled unless
verified enabled inside the guest. QEMU must execute an EFI UKI through OVMF, not
pass the Linux kernel using the current -kernel/-initrd shortcut. Put the complete
initrd and exact guest command line inside the UKI. Do not use external initrd
supplements or command-line overrides that escape the measured payload inventory.

Build PCR signatures from the completed UKI section inputs, not current guest PCRs.
Installed /usr/bin/ukify defines INITRD_PCR_POLICY as (['enter-initrd'], 'initrd');
its --sign-initrd-pcrs option explicitly generates that policy. Inspect the resulting
.pcrsig and .pcrpkey and independently calculate expected SHA256 PCR11 for the exact
sections and phase path. Do not accidentally authorize all phases or an empty phase
under the initrd policy reference. Signature generation alone is not the test.

Use two boots with the SAME disposable disk, software TPM and copied firmware vars:

1. Provisioning boot creates the test encrypted volume/manual secret, test root and
   token with PCR7 plus the disposable PCR public key/PCR11/initrd policy reference.
   Keep the private PCR key outside the guest. Use the test manual secret for
   provisioning. Any enrollment validation must match this provisioning image's
   signed phase, or explicitly use the enrollment tool's supported deferred-policy
   verification; never pretend enrollment is a successful later unlock.
2. Target boot contains no formatting/enrollment commands, unlock secret, PCR private
   key, or code that signs current PCRs. It uses the ordinary generated stock root
   mapping and signature/public-key discovery from the UKI. Its initrd runs the real
   native PCR phase unit and observer; root must unlock without test-driver input.

The existing /arch-provision wrapper embeds disposable credentials and enrolls
before PID1, so it cannot serve as this target image. Keep it in the existing test
family. Reusing the kernel/runtime/observer code is fine; reusing that bootstrap
would invalidate this acceptance test.

Required evidence: measured-os true; native phase unit ConditionResult true and
Result success; actual enter-initrd PCR11 equals independent calculation before
stock attach; stock generated/effective command unchanged; no alternate root unlock
service; no prompt/input for auto-unlock; encrypted root reaches native systemd;
observation survives; leave-initrd changes PCR11 and the initrd-only signature can
no longer unseal after switch-root. Record measurements and public fingerprints,
not tokens/passphrases/private keys. Test stale/missing signature and wrong policy
reference with cached keys disabled and no existing mapping; each must reject TPM
and preserve the stock manual recovery path. A modified initrd with an old PCR
signature must fail TPM even if its EFI signature is separately valid.

Repeat observer success, masked, exit failure, timeout and OOM on the measured path.
Each must preserve original stock unlock behavior and bounded observer delay.
Measure active observer peak. Keep test-driver secrets out of captured consoles.
Tests must fail on absent measurements/markers, not silently skip assertions.

Secure Boot is a second, separately reported branch: enroll only disposable guest
PK/KEK/db in copied VARS, sign with disposable key, verify guest SecureBoot=1 and
SetupMode=0, accept signed target and reject an unsigned/tampered counterpart before
Linux runs. Firmware-only rejection needs a bounded firmware/serial outcome, not
just absence of a Linux marker. Do not conflate a measured but unsigned boot with
this branch. Update2026-10-19: the disposable UEFI phase and enrolled-key Secure Boot branches now pass; see firmware-enforcement-results-2026-10-19.md. Two-boot encrypted-root acceptance and production integration remain unfinished. Offline UKI construction and extracted-section policy/signature verification are now implemented separately; see overnight-progress-2026-10-19.md.

## Separate laptop image construction

Protected current ukify configuration and installed image require a later owner-
available authenticated capture. Never infer these from old hashes or guest recipes.
Capture the current image, all PE sections, stub/kernel versions and hashes, effective
mkinitcpio configuration/hooks, command line, microcode, PCR public key/fingerprint,
public signing certificate, signer configuration and default/recovery entries. Keep
private keys out of project reports. Any host update invalidates a stale comparison.

Prefer rebuilding a control and candidate initrd from ONE immutable captured input
set and the actual laptop recipe. First show that the control matches the installed
semantic contents. Enumerate any nonsemantic metadata variation explicitly; no
blanket exclusion of differing directories or libraries. If control cannot explain
the installed image, stop the production path rather than loosening the comparator.
The candidate adds only the observer runtime/config/unit and root-mapping dependency.
Keep Plymouth, autodetect, microcode, KMS, compression and existing stock encryption
hooks. The synthetic VM recipe is not an acceptable laptop substitute.

Resolve every archive member in extraction order. For each payload, record archive,
raw path, canonical effective path, type/mode/owner, content hash and symlink target.
Reject alias cycles, path escapes, unexpected special files/hardlink forms, conflicting
parent types and unexpected duplicate payloads. Arch /bin,/lib,/lib64 aliases require
explicit resolution, not string-prefix comparison. An added runtime file resolving
to an existing path must match its existing bytes/type/metadata exactly or stop for
review; never overwrite libc/loader/native helpers to satisfy Python. Runtime and
extension dependencies must close within the candidate, verified without host library
fallback. Preserve early microcode bytes/order and inventory all archive segments.

Before signing, compare complete candidate UKI sections against captured working UKI.
Only reviewed .initrd, necessary .pcrsig and resulting PE signature/checksum/layout
changes may differ. Kernel/stub/cmdline/public PCR key and other payload sections
must retain their reviewed bytes; stop on newly introduced sections or profiles.
Preserve existing policy reference and signing workflow. Verify both EFI signature
and signed PCR policy for the intended enter-initrd phase independently. Do not use
re-enrollment or broaden policy to make a candidate boot succeed.

## Owner checkpoints, deferred while sleeping

1. Authenticated read-only current-image/config capture when the owner is available.
2. Exact reviewed immutable build inputs, unsigned output/delta report and signing
   invocation before accessing existing signing keys or performing a privileged build.
3. Explicit separate ESP filename/entry and unchanged default/recovery before staging.
4. Owner confirms manual recovery and approves one-time trial; no automatic reboot.
5. Owner reports actual automatic unlock, desktop, sound/input/Wi-Fi/sleep/wake and
   recovery result before any default promotion. Inspect boot evidence independently.
6. Any installed monitor/FIM change gets a fresh release manifest and the established
   explicit replacement-baseline approval; earlier approvals do not cover new bytes.

Failure keeps the known-good entry/default and manual slot0. No TPM clearing, token
migration, LUKS slot edits, key rotation or PCR weakening is included. Removing a
separate trial entry/image requires identifying those exact artifacts. Old signed
images and saved LUKS headers remain bypasses of a software-only device gate; this
pass does not solve strong Distress/antirollback/PAM or physical hotplug/DMA coverage.
