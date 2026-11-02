# Gate decision record — staged, 2026-10-18

`initramfs/gate_record.py` implements the next record-consumption part of the
preboot contract. It is not installed and does not grant production enforcement.
No boot image, host policy, enrollment or approved FIM baseline changed.

The bounded byte parser requires exact schema, duplicate-free JSON, current boot
ID, expected policy SHA256 and mode, successful checker result, strict boolean
flags, and finite nonnegative CLOCK_BOOTTIME samples no older than five seconds.
Future samples, contradictory decisions, incomplete coverage permitting TPM and
Distress permitting TPM are rejected. Missing or invalid evidence raises; the
existing dispatcher selects manual recovery. No credential input is accepted.

The filesystem reader opens fixed decision.json beneath a caller's reviewed
absolute directory using directory descriptors and no-follow opens throughout.
Ancestry must be root owned and not writable by group/others; final directory is
0700. The file must be root owned, regular,0600,single-link and at most8192bytes.
Reads are nonblocking; metadata is checked before/after and against the directory
entry to detect replacement. Root forgery, rollback by trusted root, hostile mounts
and post-read hotplug are outside this reader's guarantee. A future installed
adapter must hardcode its location and authenticate its producer; this is not a
user-selected path API. A fresh record does not prove physical device coverage.

Six unit tests cover exact acceptance, context/service mismatch, invalid ages and
schema, malformed/duplicate JSON, strict decisions, and denial under incomplete
coverage/Distress. Rejected records are exercised through the dispatcher to verify
no TPM callback and manual recovery. The full Python suite passes275tests.

`tests/vm-gate-record.py` adds actual root-owned guest file checks: accepted valid
fixture, rejected public/writeable modes and directory, missing file, symlink,
hardlink, oversized record and FIFO without hanging. The final guest record denies
TPM because coverage is incomplete. Generated-service terminal tests now consume
it using the actual checker service result instead of their previous hardcoded
denial. When the record ages out, it continues through manual recovery. Filesystem
acceptance of an allowed fixture never invokes the real host or guest TPM.

Initial complete success-checker run: work/luks-vm-pu4hiyxr/report.json, exit0,
17.61s, all prior TPM/PCR11, terminal, UUID-target and same-mapping handover checks
plus VM_GATE_RECORD_FILESYSTEM_PASS. Guest RAM384MiB temporary, network disabled,
no host disk or TPM exposure. Production scanner supervision, policy snapshot
publication, complete transport inventory, hotplug closure and cryptographic
legacy-path/Distress enforcement remain separate pending contract work. No claim
that the record reader implements them or authenticates manual owner recovery.

Final failed-checker run work/luks-vm-xjsysuz0/report.json passed, exit0,24.28s,
including every record/filesystem, terminal/UUID and same-mapping marker. Both
checker outcomes therefore retain usable recovery with the integrated parser.
