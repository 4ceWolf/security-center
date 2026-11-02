# Arch Linux Security Center
Status: active development. Custom preboot device enforcement and initrd handover
rollout were removed from scope by the owner on 2026-10-19; earlier source/tests
remain historical. Distress also remains removed. Existing Secure Boot, normal
integrity boot, TPM disk unlock, Cockpit, telemetry and trusted-device candidate
management are retained. Remaining work is postboot protection, automatic-unlock
recovery, final UI/memory checks and recovery documentation. Start with
[current status](docs/STATUS.md).

This project follows docs/project-brief.txt, with kernel lockdown integrity mode added as a first-class security module and deployment milestone. The user authorized an exception to the Projects freeze for this project only.

Read docs/current-state-audit.md, architecture.md, threat-model.md, implementation-plan.md, and recovery.md before implementation. docs/testing.md distinguishes observations from unperformed boot tests. docs/tpm-luks-current-state.md records the previous TPM repair.

Enforcement remains independent of the dashboard. Unknown/unavailable must never appear green. Never infer TPM unlock success merely from the presence of a token. No keys, password history, camera or microphone data belong in this source tree.
