# Local diagnostic export

Built/tested 2026-10-18. tools/export-telemetry.py is a standalone read-only
exporter. It is staged tooling, not an installed helper or a Cockpit download
button. It changes no recorder, security setting, policy or approved baseline.

The fixed production database is
/var/lib/private/security-center-telemetry/diagnostics.sqlite; the CLI accepts
no arbitrary database path or SQL. Production use requires administrator access.
The separate --trial option reads only the existing project trial database as
the current user. A privileged runner must capture/pin the standalone source
bytes before authentication; do not run an editable project file directly as root.

Options:

- --resolution hourly (default), --hours 1..2160 (default 24): all recorded metrics,
  sample counts, sums, means, minima, maxima, rate/source coverage, boot coverage
  and explicit missing-hour count. Current hour can be partial.
- --resolution raw, --hours 1..24: exact retained observations including battery
  state, interval gaps, numeric metrics and source-issue counts. Missing samples
  and metrics are not filled with zeros. Source error text is not exported.
- --include-processes: explicitly include the short-name/PID/start-tick/CPU/RSS
  process lists or hourly peaks. These details are excluded by default. Arguments,
  environment, executable paths and unexpected stored fields are never copied.
- --trial: select the fixed project trial recording. No collection or upload.

JSON output goes to stdout only. The tool does not accept a privileged output
path. Save exports to private files; sharing them is an explicit owner action.
It performs no upload, media capture, listening service or command execution.

The reader uses mode=ro, query_only, trusted_schema=OFF, a 512 KiB SQLite cache,
262 KiB record bound and a five-second processing deadline. It reads one consistent
SQLite transaction. At most 2,880 raw or 2,160 hourly rows are accepted; exceeding
the bound fails rather than truncating. A private temporary spool spills to an anonymous/private temporary file after
a 512 KiB threshold; individual record and JSON buffers add to that threshold,
with a 32 MiB total export cap. Completed validated output is emitted only after
all rows pass checks, so malformed data, timeout or size failure produces no
partial successful export. Output transport failure can still leave a partial
file at the caller; a valid export must parse as a complete JSON document.

The CLI trusts the fixed private filesystem ancestry. It is not a database
attestation or a general API for attacker-controlled paths. Diagnostic values
and boot IDs are local observations, not authenticated security evidence.
Hourly summaries are sample means, not time-weighted averages. The hour's boot
coverage is retained; sensor indices may change between boots. Current-hour
summaries can reflect clock adjustments within the bucket. Old summaries with
missing optional coverage fields retain unknown/null rather than invented facts.

## Evidence

269 full Python tests passed. Nine export tests cover raw/hourly values, gaps,
coverage, privacy default/opt-in, closed process fields, old/future sample filter,
database hash unchanged, missing DB not created, permissions, hardlinks/symlinks,
invalid options, nonfinite/duplicate/mismatched JSON, size failure and deadline.

Actual saved host trial export succeeded: 13,459 bytes, one populated hourly row,
128 metrics, 2,159 missing hours in the requested 90-day window. Process details
were omitted. The private artifact is work/telemetry/export-trial.json. This is
historical project trial data, not a claim that the production recorder has 90
days of history. The continuously running production recorder was independently
active/enabled with zero restarts during this stage. No production export or
Cockpit download control has been exercised yet.

Remaining: authorized captured production export, download integration and owner
export/delete controls. Do not delete real records without an explicit request.

## 2026-10-19 staged Cockpit integration

Download and deliberate history-removal controls are now implemented in source, with
fixed on-demand helper and concurrency tests. They are not installed or approved.
See telemetry-controls-design.md and telemetry-controls-implementation.md for evidence,
privacy defaults, current review release and remaining authenticated checks.
