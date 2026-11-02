# First file-integrity baseline — awaiting owner approval

Candidate SHA256: fdf02980a1b203ba194962a409052560286172c13e3c46a8242ccf6f818d6add

Root-only candidate: /var/lib/security-center-monitor/baseline-review/fdf02980a1b203ba194962a409052560286172c13e3c46a8242ccf6f818d6add.json

17 files scanned successfully. Fourteen match previously recorded installation or boot-promotion hashes. Three existing configuration files have only current observations in the selected comparison records: /etc/miku-boot/zen.conf, /etc/miku-boot/zen-uki.conf and /etc/mkinitcpio.d/linux-zen.preset. Approval means accepting their current hashes as the starting reference; it is not independent proof that they are safe.

Scope: four Zen boot configuration files, Security Center service and Cockpit socket configuration, seven installed Python modules, four Cockpit assets. Contents are not copied into the baseline, only hashes and metadata. No private keys, TPM blobs or passwords included.

The candidate remains approved=false. No active baseline exists. Explicit approval is required by docs/implementation-plan.md stage 3: “Approve baselines explicitly.”

On approval, tools/approve-file-baseline.py requires the exact candidate digest, rechecks all 17 current files against that candidate, and publishes a root-private baseline atomically without replacing an existing baseline. If files changed since review, it refuses and requires another review. Acceptance does not change boot/encryption/firewall/authentication settings.

Rollback: remove only the approved baseline after checking its candidate digest; monitoring returns to unknown/unapproved. Keep the reviewed candidate and logs. No existing protection depends on this baseline.

Tests: successful exact-candidate acceptance in an isolated temporary directory, refusal to overwrite, candidate-tamper rejection and changed-file rejection. All 25 Python tests passed. Approval helper has NOT been run against the real baseline.

## Approval completed
Owner approved this exact candidate; published after a matching re-scan. Live collector verified approved=true and zero changes/unreadable files at 2026-10-15 08:37:11 UTC. Earlier pending statements above describe the preapproval review.
