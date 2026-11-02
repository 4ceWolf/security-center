# Design and build before deployment

Owner direction: finish designs and project-local builds first. Do not prompt for authentication, confirmation, reboot or hardware actions during unattended work. Installation and enabling enforcement are separate release stages. Existing approval checkpoints still apply; this plan grants no permission to modify TPM, LUKS, PAM or boot policy.

## System contracts and release gates

| System | Inputs and authority | Output/enforcement | Project build and failure gates | Deployment remains pending until |
|---|---|---|---|---|
| Boot protection | Existing signed Zen UKI, firmware Secure Boot, PCR7 and signed PCR11/initrd | Kernel lockdown integrity; preserved manual slot0 | Candidate signature/PCR continuity and recovery image; already boot-tested integrity candidate | Every further boot change has its own reviewed image and owner recovery test |
| Device gate | Bounded USB/PCI/Thunderbolt enumeration, explicit versioned inventory approval | Decision before the actual root attach invocation; missing evidence means manual | Unknown devices, changed interfaces/ports, incomplete enumeration, timeout, hotplug race; generated-service and terminal guest tests | Complete platform inventory, signed mkinitcpio integration, old-image bypass and physical recovery resolved |
| Handover | Actual unlock result, kernel boot ID, immutable policy digest, producer identity | Bounded observation with explicit trust level; never assert attestation from a root file | Tampering, permissions, replay, missing state, systemd switch-root | Production producer/consumer and trusted provenance verified |
| Distress state | Verified trigger and owner-recovery evidence; original policy digest; independent rollback witness | Durable strict state before shutdown acknowledgement; manual-only until verified restoration | File/witness disagreement, write failure, power loss at each commit step, stale NORMAL replay, retrigger | Antirollback backend and older authorized-image bypass resolved without weakening existing PCR policy |
| Authentication/shutdown | Narrow authenticated action; separate distress and normal-owner paths | Distress never authenticates a normal session; shutdown only after durable strict state | Isolated PAM service fixtures, timeout/rate limit, interrupted shutdown, no secret logs | SDDM/lock/console integration reviewed and owner-tested; no live PAM work unattended |
| nftables/OpenSnitch | Existing machine-care/WARP ownership; application/network evidence | Existing firewall plus application rules enforced independently of Cockpit | Coexistence/rule rollback, DNS/WARP reconnect, agent loss, temporary-rule expiry | Application exceptions and independent enforcement verified; no replacement of current firewall |
| AppArmor | Installed LSM configuration and reviewed native profiles | Kernel enforcement independent of UI | Complain observations before enforce, denial/error visibility, rollback | Boot LSM requirements and application compatibility tested |
| USBGuard | Explicit internal devices and approved receiver identity/interfaces | Postboot native device authorization | Enumeration during daemon loss, hotplug, input-device recovery, default deny boundaries | Owner input access and trusted topology verified; no blind generated allowlist |
| FIM/audit | Fixed root-owned baseline; metadata/hashes, bounded configuration checks | Observations, change attribution with uncertainty | Symlink/race/permission failures, baseline approval, package transactions | Reviewed expanded baseline; never equate a package transaction with proof of legitimate change |
| Malware/process monitoring | On-demand native scanner, bounded process/service metadata | Findings with evidence; no automatic deletion/quarantine | Missing/stale scanner definitions, cancellation, resource limits, false positives | Selected scanner/resource policy reviewed; no always-on heavy engine |
| Updates/recovery | Local package data, Snapper, actual signed boot entries and backup metadata | Availability/age/recovery observations | Offline stale databases, missing snapshots, unsigned fallback | No recovery readiness claim without an actual usable path |
| Cockpit/actions | Root/wheel fixed read API; separately authorized named actions | Human status, advanced evidence, unavailable/stale states, audit trail | Module/daemon/UI failure, malformed output, privilege rejection, memory limit | Authenticated live UI and total-stack memory verified; actions never accept shell text |

## Resource and privilege boundaries

Target roughly200MB resident for the additional stack. Current collector uses bounded worker concurrency and an80MiB hard service limit; Cockpit is loopback/socket-activated. New collectors must use bounded results, deadlines and independent errors. Distress/device logic belongs in the boot/native enforcement layer; a dashboard crash cannot turn enforcement off. The384MiB disposable VM is temporary test overhead, not a permanent service.

Build artifacts must label simulated evidence, undeployed adapters and observed versus verified claims. Local software storage cannot be advertised as TPM antirollback. Root-held signing keys and older authorized UKIs remain material trust limitations. Do not hide these behind a successful reducer or VM test.

## Release sequence

1. Complete contracts, implementations and failure tests under this project.
2. Produce a versioned deployment manifest, exact changes, resource results and rollback for each system.
3. Stop at required interactive/security checkpoints; continue unrelated safe builds.
4. Deploy one reviewed increment and gather actual owner/hardware evidence.
5. Update the approved FIM reference only after explicit approval of that exact candidate.

Current work status: see STATUS.md. The durable Distress store prototype and passive observation/guest tests are already built; production TPM provisioning, firmware-phase testing and authentication remain absent. Do not repeat the old next-build task.

## Added requirement: local diagnostic telemetry (2026-10-16)

User explicitly requested battery/discharge, temperatures, CPU/process activity,
RAM, averages and broad diagnosis-oriented telemetry history. Contract and
staged implementation: docs/telemetry-design.md, securityd/telemetry.py.
Separate bounded SQLite history, private files, no upload or secret-bearing
process fields. Finite current-user capture tool and synthetic retention checker
exist. Continuous service lifecycle and history/query/dashboard integration are installed.
Export/erase UI/helper is now built and tested in staging; reviewed installation,
authenticated interaction and whole-stack resource verification remain pending.
Keep this requirement in scope alongside the security/boot systems; it does
not replace them. No existing approved FIM baseline changes in this stage.
