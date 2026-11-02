# Astra review: next preboot implementation contract

2026-10-19. This reviews offline source and saved evidence; it does not authorize
signing, boot staging, TPM changes, or default promotion. Distress is out of scope.

## Completed archive decision

The captured working initrd has exactly nine repeated directories changing only
0700 to0755. Their ownership, empty payload, hash and mtime agree. These transitions
are explicitly represented in current-initrd-directory-policy.json, bound to image
SHA256 2d4180ea48fd31d8354e7db770c0b60a4c7a5470452e09d72f2dfb8a296046e8.
The kernel unpacker's directory branch performs mkdir, chown and chmod for directory
entries, including an existing directory. Source inspected:
https://github.com/torvalds/linux/blob/v6.12/init/initramfs.c#L366-L370
This is a reference for the narrow directory interpretation, not verification of
every extraction behavior of the installed Zen kernel. No general extractor is built.

New offline review_with_directory_policy accepts only the exact ordered transitions
for the exact input digest, and only empty directories with0700→0755 and otherwise
identical semantic metadata. Missing, extra, malformed or different transitions
refuse. Regular-file replacements, library changes, symlink/type replacements,
ownership changes and other permission changes remain refused. review/compare keep
their strict defaults. The policy is a review ledger, not a cryptographic credential;
untrusted callers supplying a ledger gain no deployment authority.

Actual replay: work/current-uki-qo1bvv4d/effective-reviewed.json has2424ordered
records,2405effective paths,9reviewed transitions, approved=false. Every raw member
remains represented. This supersedes the earlier claim that the working image cannot
be reviewed at all. It does NOT demonstrate a reproducible control/candidate build,
runtime closure, current host freshness or approval to sign.

Validation:12affected tests passed, including3new tests covering exact application,
digest/path/segment/metadata mismatch, missing/unused/malformed exceptions and
refusal to authorize file or world-writable directory changes. Existing alias,
cycle, escape, replacement and complete-delta tests remain passing. Full suite and
firmware passes were not repeated because these inputs were unchanged.

## Normal gate security boundary

Implement a gate for the selected reviewed boot image. It must choose between an
ordinary TPM-capable attempt and a verified manual-only path. A passing inventory
is permission to attempt TPM, never evidence that TPM unlocked root. Unknown devices,
missing transport coverage, scan failure, changed observations, timeout and policy
errors must select manual recovery. No gate failure may silently restore automatic
unlock through the generated unit or a second mapper.

A software device gate cannot revoke older signed images or old authorized token/
header combinations. Existing recovery images must be preserved. Therefore do not
claim protection against an attacker deliberately booting an older authorized image.
A requirement to prevent that bypass would need a separate antirollback/revocation
and recovery design plus explicit owner authorization; do not invent TPM NV state,
change enrollment, remove recoveries or weaken the existing PCR policy for this work.
This limit must appear in the dashboard/owner trial review before deployment.

A snapshot also does not guarantee absence of later hotplug, spoofing or DMA. Do not
mark collection complete simply because two scans match or Thunderbolt sysfs is empty.
The actual transport/port profile must establish which controllers can attach external
USB/PCIe devices, and which paths the collector covers. An absent or ambiguous path
requires manual recovery. IOMMU isolation is a separate property and remains unverified.
Do not add kernel parameters as a side effect of a device policy installation.

For a stronger continuous USB claim, implement and guest-test default-denied device
and interface authorization before driver binding, then explicit authorization of
reviewed devices and an orderly postboot handover. A Python scan after drivers bind
cannot supply that property. This is a distinct implementation with internal-keyboard
and recovery risks; do not claim it is covered by the current evaluator.

## Concrete implementation sequence for Sol

1. Keep all existing passing evidence. The missing two-boot cases are normal observer,
   missing/stale/wrong-reference PCR signatures, modified initrd with old policy
   signature, and manual recovery. Run each only after its fixture changes are reviewed.
   TCG exceeding5seconds is an unpassed production-bound timing check. A test-only
   relaxed timeout may diagnose functionality, but must be labeled separately and
   must not become a production timeout change or an original-cap pass. KVM startup
   failures need not be repeatedly retried without a new diagnosis.
2. Capture the remaining current build recipe and input closure read-only: effective
   mkinitcpio config including drop-ins; actual hook scripts, kernel/module/firmware,
   stub/runtime/tool bytes and metadata. Capture immutable inputs once and bind the
   build and review to those bytes. Do not execute mutable project imports as root.
   Do not copy private signing keys. Recheck working UKI hash when preparing a trial.
3. Build a control and candidate in isolation. Review all differences against the
   working effective map. Directory exceptions for a new digest require their own
   explicit ledger and review; never automatically copy permission from the old digest.
   Preserve early microcode order/bytes. Close dependencies without host-library fallback.
   The first candidate may remain passive observation; do not label it enforcement.
4. Before an enforcement candidate, complete hardware classification and the generated
   root-unlock adapter. Receiver candidates are not an internal-device allowlist. The
   Intel Bluetooth and Azurewave camera observations do not authorize internal status.
   Record stable controller topology across boot/power states and verify the built-in
   keyboard remains available for manual recovery; leave physical tests to the owner.
5. Review actual final generated units/drop-ins for every root mapping and automatic
   key source. Replace the selected attach path with the tested dispatcher while
   preserving detach behavior. Manual recovery must use only manual slot0, with token,
   keyfile, credential and password-cache alternatives excluded. Cryptsetup owns the
   passphrase input. The dashboard never receives it. Test failure/cancel/retry,
   Plymouth ownership and duplicate mapping attempts before signing this candidate.
6. At the existing checkpoints, present exact unsigned section delta, immutable input
   digest and existing-key signing invocation; then a separate trial filename/entry,
   unchanged default/recovery, and one-time boot/manual-recovery trial. No automatic
   reboot, token re-enrollment, slot change, or default promotion is included here.

## Saved evidence to reuse

- Secure Boot three cases: work/secureboot-guest-r0yipipj/report.json.
- Two-boot observer-masked TPM/root/PCR proof: work/two-boot-luks-uly1qq4h/report.json.
- Existing full354Python pass: work/sol-preboot-tests-2026-10-19.log.
- Actual public-only working image capture: work/current-uki-qo1bvv4d.
- Installed approved baseline and live checks: firmware-enforcement-results-2026-10-19.md.

No production files, baseline, boot image, TPM, LUKS, firmware keys or services were
changed in this review. The remaining engineering and owner trial are real work;
this review does not make the whole Security Center complete.
