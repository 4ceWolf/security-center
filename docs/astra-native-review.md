# Next Astra checkpoint — native preboot code review, 2026-10-18

The owner asked Sol to stop when specialist review is needed, with9% usage remaining
at the start of this implementation pass. Review the staged security boundary and
next production observation-image design; do not redo routine implementation or
claim the full Security Center is complete. Work remains under this project.

## Concrete state ready to review

Installed corrected monitor/telemetry/device editor remains unchanged. The owner
approved candidate3464d566… and reference b160da7e… was published/verified. Fresh
work/native-review-host-status.json, from a root-peer-PID-verified collector, reports
zero file drift and ongoing telemetry. Measured background monitor+recorder+idle
socket ~58.6MB; full authenticated Cockpit interaction/memory still unverified.

Staged code since the earlier architectural handoff:

- initramfs/gate_record.py: exact bounded current-boot/policy/freshness parser and
  root-private/no-follow reader. Callback/service state remains part of the trust
  boundary. It is neither attestation nor proof of physical device coverage.
- initramfs/gate_observer.py: guest-only observer; validates policy, samples real
  USB/platform data, publishes private atomic decision and count/error summary.
  ALWAYS denies TPM. It cannot be installed unchanged as an enforcement gate.
- initramfs/unlock_candidate_audit.py: conservative generated-unit/ordered-drop-in
  snapshot check. Unknown syntax, duplicate units, stock commands, keyfiles,
  unreviewed options or checker Requires refuse. Fixed console directives only.
  It does NOT verify a whole image, helper hashes, omitted units, generator-early/
  late/runtime/transient paths, other executables or old authorized images.
- tools/initrd_manifest.py and VM harness: bounded complete single-newc member
  inventory, unapproved manifest and sealed gzip descriptor actually passed to
  QEMU. Kernel, firmware and runtime mutation are outside this byte binding.
- initramfs/manual_recovery.py: pure bounded manual-only retry coordinator.
- tests/vm-cold-unlock.py and tools/cold_boot_fixture.py: actual native-initrd guest
  adapter/builder, controlling-console cryptsetup, runtime and snapshot assertions,
  SIGINT supervisor handling and hidden bounded retry confirmation. Guest entry
  refuses outside marked test VM; builder refuses outside project guest paths.

## Actual evidence, without expanding its meaning

Python suite298passed. No new privileged deployment, boot image rebuild, token/key
change, PAM change or FIM reference replacement occurred in these implementation
passes. All test disks, software TPMs, keys and entered passwords are disposable.

Earlier generated-service guest tests cover signed-PCR11/initrd positives and
negatives, actual systemd service ordering, real wrong/cancel/timeout/correct PTY
input, UUID crypttab/cmdline target activation, observer timeout, invalid record
files and same-mapping switch-root. A second generated service actually TPM-unlocks
the guest while the intended gated service refuses: regression proves the bypass
risk rather than merely describing it. See alternate-unlock-test.md.

Native --cold-boot modes provision a test disk BEFORE first systemd PID1, close the
preparation mapper, then use actual kernel-cmdline generators and native initrd
root/mount/parse-etc/cleanup/switch-root units. Final-root service verifies systemd
PID1, root device identity and same-boot manual handover (attested=False). This
is a minimal Linux/software-TPM guest, not firmware/UKI or full Arch mkinitcpio/Btrfs.
Optional units/libraries are missing; errors remain in logs. Provisioning uses weak
fixture PBKDF2 only; laptop Argon2id slot0 is untouched.

A stronger assertion found /run mounted1777 in the early fixture. Corrected the
fixture to0755; never weakened the reader. Preserved bgjerfu4 failure report.
Corrected native core profiles0or82ac1/gn3iyuf_/yr10m1tw passed observe/fail/timeout.
Native retry reports: djlx8ags wrong-then-correct;58lymliq failed-checker+Ctrl-C;
9o57v7yh timeout-checker+input-timeout;455l9_j0 three-attempt exhaustion. Failed
attempts have no mapper/handover; successful retries reach encrypted-root systemd;
exhaustion does not. Secret exclusion and exact attempt counts checked.

## Specialist review requested now

1. Review consumer/producer provenance, failure semantics, parser assumptions,
   snapshot-auditor boundaries and native console SIGINT/terminal recovery code.
   Hard fixes belong here; implementation polish/tests can return to Sol. In
   particular, do not treat limited shlex parsing or a supplied unit map as proof
   that every possible unlock path was inventoried.
2. Define the narrow production OBSERVATION image/package and its review contract.
   It must preserve current TPM auto-unlock and normal integrity boot. Current
   guest adapters clear ExecStart and force manual; they are test enforcement
   fixtures and must NOT be copied into a first host observation deployment.
   An observer that does not own unlock must not invent manual/TPM provenance to
   fit handover.py. Inventory observations need a separate honest interface.
3. Explicitly retain the distinction between software gating and cryptographic
   enforcement. Old signed UKIs, saved headers and legacy sealed objects remain
   possible bypasses. No NV/pcrlock/token/key-slot/firmware migration is authorized.
   Do not improvise hardware state or reenroll to get a test passing.
4. Return a concrete small implementation contract to Sol: reviewed source/image
   manifest, allowed initramfs hook/unit integration, observation record/UI states,
   build/signing verification and exact owner boot/recovery checkpoints. Actual
   laptop boot, keys/enrollment and authentication stay behind existing approvals.

Real keyboard/topology approval, late-hotplug and external DMA coverage, native
menu rejection/timeout and persistent recovery after exhaustion, full graphical
credential agent, actual signed UKI chain and owner hardware tests remain pending.
Cockpit authenticated tests and telemetry export/download/erase UI also remain
ordinary work. Do not silently narrow the original full-project requirements.

## 2026-10-18 focused Astra review completed

Read observation-image-contract.md for findings, the staged observer interface,
exact allowed integration, tests and owner deployment checkpoints. The staged unit
auditor dependency-reset defect was fixed; installed laptop configuration unchanged.
Sol owns the next implementation. This is not production boot approval.

Latest checkpoint: astra-observation-image-review.md (real Arch boot and archive
segments complete; measured UKI phase/production recipe review now required).
