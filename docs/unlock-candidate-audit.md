# Generated unlock candidate auditor — staged, 2026-10-18

`initramfs/unlock_candidate_audit.py` replaces the alternate-service fixture's
local name-set assertion with a reusable, conservative snapshot check. It has no
host installation, image-signing action, privileged command API or runtime unlock
authority. Accepted output is explicitly marked snapshot_only=True.

Inputs are the complete collected generated cryptsetup service map, each fragment
and ordered drop-ins, and a separately reviewed expected mapping, volume aliases,
exact generator options and gate command. The caller is responsible for collecting
EVERY generated unit; missing data or a dishonest caller cannot be detected here.
Current profile permits exactly one reviewed service and refuses extra services,
including unrelated volumes requiring their own review. Root aliases are explicit,
not inferred by filename, and must come from a trusted candidate volume inventory.

The checker requires the original generated attach to use the reviewed mapping,
source alias, no explicit keyfile and exact options; matching detach; oneshot and
RemainAfterExit. It applies the supported ExecStart reset/append semantics across
ordered drop-ins, requires exactly the reviewed gate argv, and checks Wants+After
for the checker. A Requires on that checker is rejected because failure could
suppress manual recovery. Stock/additional starts, execution pre/post hooks,
environment/root/user overrides, unknown directives, service expansions, line
continuations, duplicate/unordered drop-ins and oversized inputs require review.
It supports a limited known generator syntax, not arbitrary systemd unit syntax.

Eight unit tests cover a valid snapshot and refusals for duplicate/missing units,
source/keyfile/options mismatch, retained stock/additional commands, unknown
execution/environment directives, missing/reset/required checker ordering,
continuations/expansions and duplicate drop-ins. Full Python suite286passed.

Guest integration now invokes this auditor on ACTUAL generated files, not synthetic
unit strings alone. The two-service bypass fixture is rejected; its isolated gated
service snapshot is accepted for command/order checks. Both automatic UUID crypttab
and cmdline scenarios audit every matching generated service file and ordered
drop-in before asking PID1 to start cryptsetup.target. Existing runtime ExecStart
inspection, actual mapping and terminal checks remain in place.

Limits: a file snapshot is not an effective-runtime-unit inventory or whole-image
integrity proof. It does not authenticate helper code, source snapshots, expected
metadata, package versions or signatures. It does not exclude commands outside
cryptsetup units, transient/runtime overrides, other generators, alternate initrd
or bootloader paths, credentials handled by helper code, emergency commands, or old
signed images/headers. Nor does it establish timeout policy, hotplug enforcement
or actual manual-owner recovery. Approved helper hashes, complete image manifests,
cold-boot/runtime checks and reviewed cryptographic migration remain required
before enforcement/signing claims. No production candidate builder has been
connected to this library yet. Its acceptance cannot authorize signing or TPM use.

First guest with the reusable checker passed in failure mode:
work/luks-vm-lpj22qqw/report.json, exit0,29.99s, all prior/new markers. The later
Requires-checker veto was added after this first run and covered in final unit
checks and the next successful-checker run. No installed security state changed.

Final successful-checker run work/luks-vm-_52di9fk/report.json passed, exit0,
20.67s, including reusable-auditor calls on duplicate and both normal UUID cases,
with all existing recovery, supervision and same-mapping switch-root assertions.
Final Python suite286passed after adding the required-checker refusal.
