# Resource budget
User target: ideally below 200 MiB additional memory for the security services. Browser renderer memory is measured/reported separately. No claim for the eventual full stack until measured.

MVP: one Python daemon, three bounded concurrent checks, 60-second cache, no database/index daemon. Cockpit socket activation, no PCP or full Wazuh. Collector soft ceiling 48 MiB and hard ceiling 80 MiB, 32 tasks, 20% one CPU. This ceiling is a guardrail, not expected consumption. Root-only collector responds to GET on a local wheel-readable Unix socket; no TCP backend.

Measure idle collector cgroup memory, Cockpit service memory when active, and authenticated cockpit-bridge sessions separately. Report cgroup current/peak and process RSS when available; shared pages mean summing RSS overcounts. The backend must continue serving cached evidence without rescanning on every UI request. Heavy malware scans and FIM baselines are on-demand and have separate peak budgets.

Future services are added individually only after their incremental footprint is measured. If the combined footprint exceeds target, reduce polling, use timers/on-demand integrations, or revise scope explicitly. Do not use MemoryMax as proof of successful operation: look for OOM kills/restarts.
