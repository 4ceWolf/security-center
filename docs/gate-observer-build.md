# Supervised gate observation producer — staged, 2026-10-18

`initramfs/gate_observer.py` reads the existing USB and platform collectors,
validates a bounded policy snapshot, binds its SHA256 and current boot to a strict
decision record, and writes a private diagnostic summary. Its executable entry
point refuses outside the explicitly marked disposable guest. No host boot files,
TPM policy, LUKS slots, authentication or FIM reference are changed.

The observer ALWAYS requires manual recovery. Even empty/error-free device lists
or a scanner's completeness flag cannot grant TPM permission. Current transport
coverage, approved topology and hotplug control do not justify that permission.
An observation-only producer is one component of the staged implementation, not
completion of the project's enforced gate. Its normal-mode record is not Distress
state and cannot clear it.

The bounded snapshot rejects malformed/duplicate JSON and invalid/conflicting
identities, records the start CLOCK_BOOTTIME and refuses a result older than five
seconds. Summary contains device counts and collector errors; no disk keys,
credentials, command lines or media. It does not classify devices as internal.
Decision and summary are published with private temporary files, fsync, atomic
rename and directory fsync. Only decision.json is consumed as the strict record;
summary and decision are not an atomic pair. The fixed runtime directory must be
created by the supervisor beneath trusted /run ancestry. A failed operation must
be rejected by checking the actual service result, regardless of a prior record.

Guest systemd supervision uses a oneshot, five-second start timeout, one-second
stop timeout, KillMode=control-group, RuntimeDirectory mode0700 and RemainAfterExit.
The separate hung-fixture test runs an actual 30-second sleep under a one-second
start timeout. It requires systemd Result=timeout, MainPID=0 and completion within
six seconds. It then confirms failed checker evidence cannot reuse a previous
record. This exercises actual PID1 supervision, not mocked timeout exceptions.
It does not prove every descendant or uninterruptible kernel operation can always
be killed at an exact deadline. No observer daemon runs after the oneshot exits.

The generated recovery adapter now consumes the observer's record using its
expected embedded guest-policy digest and current boot. Actual observer and
original device-check service states remain separate vetoes. Stale records and
any failed checker select manual through the existing dispatcher. Full production
checker ordering, credential agents, complete inventory, late hotplug and
cryptographic replay/legacy-image protection remain pending review/integration.

Three observer unit tests cover permanent denial, scan age and policy refusal;
full Python suite278passed. First guest run luks-vm-xp8wjgqt failed because the
minimal Python image lacked hashlib's blake2 dependency and logging fallback.
The guest packer was extended; original failure evidence is preserved.

Corrected success/failure checker guests both passed: hmvd8gsn (19.21s) and
2pczwf29 (26.93s), exit0. Reports under work/luks-vm-*/report.json include
VM_OBSERVER_SUPERVISION_PASS and every earlier terminal, signed-PCR11, UUID-target,
filesystem record and same-mapping switch-root marker. Whole-console disposable
secret exclusion passed. Temporary guest RAM384MiB, no host disk/TPM/network.
