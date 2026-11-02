# Overnight progress — 2026-10-19

## Result

Completed the focused observer/image-boundary review, repaired two failure cases,
rebuilt the disposable Arch image, repeated the affected automatic/manual recovery
checks, and added an isolated offline PCR-signed UKI construction/verification test.
No laptop installation, ESP/default boot change, signing-key access, TPM/LUKS/PAM
change, reboot, authentication prompt or baseline replacement occurred. The full
Security Center project is not complete.

## Source changes and verification

- tools/observation_package.py: bounded nonblocking no-follow regular-file reads;
  before/after/current-entry identity checks; total bytes and member-count limits.
  Prevents FIFO blocking and oversized aggregate captures during staging verification.
  Not a privileged publisher and not protection against mutable parent directories.
- initramfs/boot_observation.py: excessive JSON nesting and huge numeric timestamps
  now produce ValueError, so the consumer follows its normal rejected-record path.
- tests/test_observation_package.py and tests/test_boot_observation.py: four new
  regressions covering those failures. Host Python suite: **333 tests passed**, no
  skips shown, work/overnight-review-python-tests.log.
- tools/test-observation-uki-build.py: isolated offline construction with disposable
  PCR key, explicit empty ukify config, captured test initrd/kernel/stub, no host
  /etc, TPM, ESP or network. Exact embedded initrd/kernel/public-key verification;
  independently recomputes policy using extracted PE sections, compares the single
  SHA256 PCR11/initrd policy, checks RSA key fingerprint and OpenSSL signature;
  corrupted signature must reject. The generated image has no outer EFI signature
  and was NOT booted. Its absence of a provisioning/root fixture is intentional;
  it is not the next boot-test image or a laptop candidate.

New package: work/observation-package-2prwhlwf,359 files,
inputs SHA256 639e678055015690c4bd04e64a2706aa81ba2bb72c1eac5855b956c93c07baa8.
New isolated Arch build: work/arch-observer-build-3ga34q76,898 generated members,
37,628,482 bytes; image SHA256
 d552be675a8aaf0764f8dc1e95762e225f906d758c19d38ab0ddaeb9922742a8.
Build log: work/overnight-review-arch-build.log.

New direct-kernel guest results (fresh virtual disks/software TPM, no physical disk
or TPM and no network):

| Scenario | Evidence | Result |
| --- | --- | --- |
| Stock automatic unlock, observer success | work/luks-vm-p5zjkg0f/report.json | PASS,6.27s,observer peak7,655,424B |
| Actual TPM failure, stock manual recovery | work/luks-vm-gy6vhobt/report.json | PASS,7.07s,observer peak7,815,168B |

Both retain the observation across switch-root, reject postboot generation, pass
actual file-publication/race/metadata negatives and keep the disposable secret out
of console logs. Both explicitly report the PCR phase condition FALSE. These are
regressions for the new decoder bytes, not proof of measured firmware boot.

Offline UKI: /home/user/Projects/security-center/work/observation-uki-test-l4q3zo2c.
UKI SHA256 cfd89f5bf20b6a05ccd091dca97d3131e5032fe800fdcddebdaf159015a2ad81.
Report and public expected-policy/signatures are stored there. No private key is
printed or embedded. Disposable private test keys stay in their private project
work directories, file0600, and are never laptop keys. The initial construction-only
run nse58spd is not the verified result. An intermediate fingerprint check m7mfiaq1
failed because the harness initially used SPKI instead of systemd's PKCS1 RSA DER
fingerprint; its artifacts and review-outcome.json remain. Corrected verification
and altered-signature rejection passed in l4q3zo2c. Failed attempts are not passes.

## Next implementation and pending owner steps

See measured-observation-next-contract.md for the complete next contract. The next
safe implementation is a separate two-boot UEFI/software-TPM fixture: provisioning
boot followed by a target image with no embedded unlock secret, enrollment code or
PCR private key; real enter/leave-initrd measurements and stock unlock must pass.
Then test disposable guest Secure Boot separately. Existing firmware and ukify are
available; guest-variable provisioning tooling still needs implementation/inspection.
These firmware boot tests remain unfinished; offline signing does not replace them.

Owner-dependent steps remain deferred, with no question sent:

1. Authenticated read-only capture of current protected UKI recipe/image.
2. Exact immutable production inputs/delta/signing proposal approval.
3. Separate ESP file/entry staging approval with default/recovery preserved.
4. Manual recovery availability and one-time boot trial, followed by physical
   sound/input/Wi-Fi/sleep/wake and recovery validation before promotion.
5. Any new installed release requires its own exact FIM baseline approval.

Other unfinished scope remains authenticated Cockpit interaction/full active RAM,
telemetry download/erase UI, device enforcement and physical classification/hotplug/
DMA, and the separate strong Distress/antirollback/PAM design. No new overall percent
is claimed. Current installed release and approved baseline stay unchanged.

## Limits and rollback

The ~7.3–7.5MiB observer measurements are transient guest process peaks, not total
laptop/Cockpit RAM. No new resident service was added. All changes are staged under
the project. Rollback is limited to reverting the described source changes and
removing only the named disposable artifacts if desired; nothing on the live boot
path needs undoing. Older captured packages/images no longer represent current
observer source and must not be submitted as a new candidate.
