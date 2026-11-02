# Live postboot device trust management — 2026-10-20

Keep the saved candidate editor as a planning tool, and add explicit native USBGuard
policy management in Cockpit. No action changes boot, controller defaults or current
device authorization. Explain that changes apply on reconnect; present devices stay
connected. Internal/hardwired devices and controller rules cannot be removed here.

Root helper exposes list/review/apply only. Additions select a helper-observed native
device ID and generate a full descriptor/hash/parent/port/interface allow rule from
that observation. Browser-provided rules, paths and commands are prohibited. Removals
select one current external allow-rule ID. Never delete catch-all block or internal
rules. Keep exact native parser semantics by using native daemon IPC to add/remove.

Every proposal binds exact before-policy hash, native rules, selected device/rule,
boot identity and a two-minute timestamp. Display before/after rule text and hashes.
Apply needs an explicit owner confirmation and administrator authorization. Re-read
all state and reject drift. Serialize helper changes and installation using the
existing protected update lock; durably journal old policy and pending action first.

Use one persistent native append-rule before the final block rule, or one remove-rule.
Compare post-operation runtime rules to the exact expected rule sequence (allowing only
the daemon's canonical equals spelling), and persistent policy to that runtime set.
Do not use allow-device/block-device/reject-device, restart the daemon, disconnect
inputs or change implicit/present/inserted policy settings. Never turn an observation
of allow into a claim that hardware identity is cryptographically authenticated.

On failed/interrupted mutation preserve pending state and fail closed for new editing;
review live policy and the protected backup before any recovery. Do not automatically
restore stale rules over an unrelated administrator change. Success keeps a bounded
root-private audit with before/after policy hashes and a protected recovery copy.
Static helper/UI/config code belongs in the approved file baseline. Mutable live rules
need an explicit reviewed per-change reference/journal, not silent generic acceptance
of arbitrary disk edits. Dashboard must report unexpected native policy/config drift.

Test pure generation/validation, stale state, refused internal/controller removals,
keyboard warning, injection strings, simultaneous helper/installer, failed native IPC,
interrupted commit, exact post-state and persistence. Native parser/IPC test uses an
isolated namespace or native temporary rule with no matching device; never remove
owner receiver trust as a test. Owner's prior reconnect pass remains valid evidence
for the unchanged receiver policy, not proof of this new editor.
