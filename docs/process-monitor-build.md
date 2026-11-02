# Process observation contract

Read at most512numeric /proc entries. Per process read bounded stat/status/comm and the executable symlink only. Never read cmdline, environ, memory, open file contents or credentials. Recheck start time after sampling to reject PID reuse. Record aggregate counts and at most128 review findings, not an unbounded process dump.

Deleted executable links are review findings because normal package updates can produce them; they are not malware verdicts. Zombies are lifecycle observations, not attacks. Missing/denied/exited process evidence makes coverage incomplete. Report sampling scope and uncertainty explicitly. No killing, renicing, tracing or remediation actions. This is a polling observation, not a historical execution audit or process identity attestation.

Show the module in Applications and record meaningful review-finding changes in history without making ordinary PID churn a continuous event stream. Keep installed daemon unchanged until the staged release is reviewed.

## Built and validated
Staged adapters.py provides process_observations; Cockpit Applications includes processes. History fingerprints track the review findings/truncation flags while ignoring ordinary aggregate process-count churn. Metadata for processes without readable executable links still contributes to aggregate UID/zombie counts after start-time consistency checks, but executable coverage remains incomplete. No executable path is exported; findings contain PID/start-time/name/effectiveUID and the deletion observation only.

Seven new tests cover credential omission, deleted-executable interpretation, missing links, zombie counts without exe, PID reuse, enumeration limit and history churn.133Python tests and the JS UI state regression pass. Actual packaged daemon now exposes17modules; work/releases/monitor-2cr2som8/runtime-report.json passed crash/restart persistence (123events before/227after), unsupported-request rejection, database isolation and cleanup.

Read-only unprivileged laptop sample observed321process metadata records,0deleted-executable findings,246unreadable executable/changed-evidence counts, no enumeration truncation; coverage correctly false. This is not evidence of malware absence or a root-privileged scan. Kernel/exited processes and permission restrictions can prevent exe reads. No host process or installed service was modified.
