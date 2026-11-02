# Astra review and Sol implementation contract — 2026-10-18

Status: staged implementation authorized; laptop deployment is NOT approved by this
review. This completes the focused specialist checkpoint, not the full project.

## Review result

Reviewed gate_record.py, gate_observer.py, unlock_candidate_audit.py,
manual_recovery.py, handover.py, unlock_dispatch.py, device_inventory.py,
platform_inventory.py, initrd_manifest.py, vm-cold-unlock.py and the native fixture
integration. The existing evidence remains useful within its documented guest
boundary. This is a focused source review, not independent attestation or a complete
security audit of all build dependencies.

Fixed a concrete false acceptance in unlock_candidate_audit.py: an empty Requires=
was interpreted as clearing earlier dependencies. systemd dependencies are additive;
a mandatory checker could remain and suppress manual recovery. Empty dependency
assignments now refuse, as do quoted/expanded dependency forms the parser cannot
model (except the exact generated blockdev %i dependency, expanded using the
reviewed mapping). Direct checker BindsTo, Conflicts and Before edges also refuse. Regression
coverage includes the hidden Requires case and those direct failure/cycle edges.
Local source: installed systemd.unit(5), drop-in example discussion, explicitly
states dependencies cannot be reset to an empty list. ExecStart reset semantics
remain separate and unchanged.

The auditor still cannot establish transitive dependency safety, aliases, escaped
unit-name equivalence, omitted drop-ins or complete effective runtime state. Its
accepted result is only a constrained snapshot result. Never use it as a TPM
permission predicate. Validate the loaded graph in a guest as well.

The gate reader's bounded schema/current-boot/policy/age checks and private ancestry
are appropriate for its root-local threat model. Root can forge these observations;
freshness is not hotplug exclusion. The producer assumes its supervisor controls
parent ancestry. Its two output files are not one transaction. Do not combine them
as authoritative evidence. The new observer below uses one record and a separate
fixed directory; do not weaken gate_record or overload handover.py.

The retry coordinator is intentionally credential-free and bounded. The native
adapter's caught parent SIGINT permits a child to cancel; retry-menu termios settings
are restored in finally. Production readiness is NOT established: killing a stuck
credential child can leave terminal state/input behind, SIGTERM bypasses ordinary
finally cleanup, and menu rejection/timeout and persistent recovery after exhaustion
need explicit tests. Preserve original terminal state around the entire credential
session and flush stale input before a new prompt in any future production adapter.
No such adapter belongs in this observation release.

## Next small deliverable for Sol

Build a separate observation-only path in staging, with no unlock implementation:

1. initramfs/boot_observation.py: strict encoder/reader for ONE fixed private
   /run/security-center-observation/boot.json. Bound record to 64 KiB; strict types,
   duplicate-field rejection, bounded counts/errors, finite ordered CLOCK_BOOTTIME
   start/end, current boot ID. Root-owned ancestry without group/other write;
   directory0700; regular no-follow single-link file0600; before/after identity
   checks. Atomic single publication; no overwrite of an existing record this boot.
2. initramfs/boot_observer.py: bounded read-only USB/platform collection; embedded
   candidate-policy digest, no TPM, cryptsetup, authentication, authorization writes
   or Distress state transitions. Keep the guest-only gate_observer unchanged.
3. A staged mkinitcpio install hook and security-center-observation.service, plus an
   explicit mapping-specific dependency drop-in for the reviewed root mapping.
   Do not install them into /etc or /usr/lib on the laptop yet.
4. A read-only collector module and Cockpit rendering for this schema. Saved trust
   candidates and embedded image policy must be labelled separately. They can differ.
5. Guest tests, source/image manifests and a proposed separate-image build report.
   Return for exact-image review before host image build/sign/install or reboot.

## Record and UI contract

Required fields: schema_version=1, producer=security-center-initrd-observer-v1,
boot_id, source_manifest_sha256, policy_sha256, started_boottime,
finished_boottime, observation_only=true, attested=false, coverage_complete=false,
unlock_method=unknown, enforcement=not_enabled, usb/pci/thunderbolt counts,
bounded scanner error codes and bounded limitations. Optional descriptor inventory
must have exact validated fields and explicit item/byte bounds; never log arbitrary
sysfs strings, passphrases, tokens or keys. Render all strings as text, never HTML.
The source digest is a claim bound to a reviewed artifact, not self-authentication;
it excludes the manifest itself and is not the final UKI digest.

A postboot consumer checks current boot, fixed expected schema/producer and sample
time no later than current uptime. Do NOT apply the gate's five-second freshness
limit to a historical observation retained for the whole boot. Label its age and
scope. Do not combine it with current connected-device state as one observation.

UI states: not installed; observation unavailable (missing/malformed/wrong boot);
observed with limitations; observation incomplete (scanner errors). Every state
says device enforcement is not enabled and unlock method is unknown. No verified
boot/clean policy/TPM unlock/manual recovery claim may be inferred from this record.
Secure Boot and integrity keep their own independently collected statuses. A late
restart must not manufacture a preboot observation. Invalid data cannot clear a
Distress flag or approve a trust candidate.

## Initrd ordering and resource limits

Proposed guest-tested unit: root oneshot, DefaultDependencies=no, Wants+After the
existing udev-trigger service, fixed executable with isolated Python imports,
UMask0077, RuntimeDirectory0700, retained runtime directory through switch-root,
TimeoutStartSec5, TimeoutStopSec1, KillMode=control-group. No restart loop, shell,
console access, network, device writes or credential access. Retention and cleanup
must be proven with the actual initrd cleanup graph, not assumed from a directive.
Stage a MemoryMax64MiB limit and measure actual peak/runtime in the full candidate;
if libraries exceed it, report failure and adjust through review rather than remove
bounds. No new resident daemon. This transient budget is not a measurement of
combined authenticated Cockpit RAM.

The mapping-specific drop-in adds only Wants=security-center-observation.service
and After=security-center-observation.service. No Requires/BindsTo, no ExecStart/
ExecStop replacement, no changed cryptsetup options/environment/credentials,
no timeout override on the stock unlock service. Observer failure must leave the
original TPM attempt and original manual fallback available after a bounded delay.
Do not add a dependency that creates a root-mount/udev-settle cycle. No blanket
cryptsetup template override. Determine exact mapping from the current reviewed
build, not the cold_root fixture. A missing observer also must not block boot.

## Build and acceptance evidence

Pin source bytes, interpreter and imported modules, native libraries, unit/hook
bytes and symlink metadata, embedded policy and package versions. Review an exact
allowlisted delta against the working build. Include kernel, microcode, stub,
command line, initrd segments, PCR public-key/signature sections and final UKI hash.
The single-newc guest parser does not support arbitrary Arch concatenated/compressed
initrds: unsupported layouts refuse; do not silently omit early archives/segments.
No signing keys or secret token blobs in manifests. Build inputs must be captured
before any privileged step; root must not execute mutable project paths.

Guest acceptance: stock TPM auto-unlock with successful observer; observer absent,
crashed, killed by memory limit and timed out all still permit stock TPM unlock;
TPM failure still reaches the stock manual agent; malformed/stale records produce
unknown UI, never enforcement; actual switch-root retains a current-boot record;
postboot restart cannot create one; interrupted publication leaves absent/valid
record only. Verify the effective generated root command/options unchanged and
absence of alternate unexpected root-volume services. Test with stock agents, not
the custom manual-only guest adapter. Record observer time/peak memory and ensure
no tests assert unlock provenance from the observation record.

Before a host build/signing proposal, inspect current mkinitcpio/UKI recipes read-only
and produce exact commands/outputs/rollback; no use of the normal preset that could
overwrite the current image. Existing PCR7 + signed PCR11/initrd enrollment and
public key stay unchanged. Verify the candidate signature and authorized PCR11
measurement using the existing reviewed signing workflow. A signature alone does
not prove successful automatic unlock; firmware/TPM execution needs an owner test.

Owner checkpoint: review exact separate image, boot entry and known-good recovery
path, confirm manual recovery availability, then approve the one-time boot trial.
Preserve default Zen image/entry and manual slot0. No default promotion until owner
reports auto-unlock/desktop and normal input/sleep/wake and evidence agrees. Recovery:
select unchanged known-good entry; remove only the separately identified candidate
entry/image after review. Later FIM updates use the existing explicit baseline
approval process. No re-enrollment to fix a candidate failure.

## Boundaries that remain with Astra

Old authorized images, saved LUKS headers and legacy sealed objects can bypass a
new software-only gate. This observation release neither closes nor claims to close
that gap. Existing cryptographic-migration and Distress NV/PAM questions remain
separate specialist checkpoints. No TPM, NV, LUKS slot, firmware or authentication
change is authorized here. Internal topology, built-in input, late hotplug and DMA
coverage remain unverified. Full project scope is unchanged.

Sol may now implement the staged observation deliverable and ordinary telemetry/UI
work. Stop for specialist review at the exact candidate-image boundary or a new
cryptographic/authentication design decision; do not grow the guest-only manual
adapter into a laptop production unlock path as a shortcut.

Implementation progress: see observation-implementation.md for staged code and
native stock-unlock tests. No candidate laptop image is approved or built.
