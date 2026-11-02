# Architecture proposal
## Enforcement and control
Keep Secure Boot, TPM/LUKS, nftables, AppArmor and USBGuard independent. securityd collects evidence; Cockpit renders status and later requests narrowly authorized actions. Daemon/UI failure cannot remove rules or unlock storage.

Initial daemon: Python standard library with read-only collectors and bounded subprocess timeouts, absolute executable paths, argv arrays, no shell commands from clients. Collect on a timer; serve cached JSON via a root-owned Unix socket. A root collector may be required for nftables/LUKS metadata; a read-only broker must expose only sanitized fixed-schema results to the authenticated owner. Never expose raw tokens, signing keys or arbitrary paths/commands. Alternative MVP: authenticated Cockpit bridge requests fixed read-only snapshot command, installed root-owned; avoid a separate listening TCP API.

Cockpit listens only on loopback initially. No new LAN firewall exception. Root-owned installation must not execute user-writable project source. Authentication does not authorize arbitrary security mutations. Later privileged actions each receive a distinct polkit action, arguments validated against a fixed schema, and an audit event.

## Module contract
id, name, status (secure/attention/action_required/unavailable/unknown), severity, summary, description, last_check, evidence, events, actions. Each collector has a timeout and catches errors independently. Aggregate status reflects material failures; unavailable controls are visibly unavailable, never silently green. No overall VERIFIED BOOT claim from only EFI state or a token.

Modules: secureboot, tpm, luks, lockdown, preboot, firewall, opensnitch, apparmor, usbguard, integrity (file monitoring, distinct from lockdown), audit, processes, services, malware, updates, snapshots, distress.

## Events
Journald as primary source; normalized bounded local SQLite index later. timestamp, monotonic time where available, boot ID, source, severity, stable dedup key, sanitized message, evidence provenance. Bounded retention and query limits. First observation is not an event proving something happened.

## UI
Cockpit pages from brief; first release read-only Overview and Boot/Network/Application evidence plus timeline. Human summary with expandable technical evidence. Clearly mark not-installed, not-checked and stale states. Future controls are disabled until implemented, never decorative working-looking buttons.

## Resource budget
No full Wazuh. No permanent full-filesystem scans. Cache slow checks (60–300 seconds), event journal cursor, file monitoring restricted to security configuration. Measure idle RSS/CPU and set bounded service resources after testing. Optional ClamAV only on demand; no resident database required for initial phases.
