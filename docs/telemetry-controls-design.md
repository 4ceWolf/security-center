# Telemetry owner controls — staged design, 2026-10-19

Purpose: finish local JSON download and deliberate history removal in the existing
Cockpit diagnostics section. No background endpoint, resident process, upload or
new third-party dependency. Implementation remains staged until a reviewed release
is installed. Do not delete production history during development/testing.

The fixed on-demand helper is launched by Cockpit's administrator bridge only on
an owner click. It accepts one bounded JSON request on stdin and no CLI arguments,
paths or SQL. Operations are export and erase. Export uses the existing bounded,
read-only exporter with raw1..24/hourly1..2160 hours and process details excluded
unless explicitly opted in. JSON goes to stdout, then a browser-local Blob download;
no privileged destination file or network send. A download-start message does not
claim the browser saved a file. Invalid/partial output creates no Blob/download.

Erase requires an explicit inline review and an exact confirmation request. It
clears ONLY raw samples and hourly summaries in the fixed telemetry SQLite DB.
It preserves the database/inode/owner/schema/locks and recording service, trust
state, security event history and boot configuration. Ongoing recording continues;
new samples can appear immediately. This is logical deletion, not forensic erasure;
previous downloads/backups/snapshots and already loaded pages may still hold data.
The review explicitly states this. No production erase is authorized by UI work.

Concurrency: both recorder append and erase begin an IMMEDIATE SQLite transaction
BEFORE reading summaries. SQLite serializes the complete read/modify/write operation.
The lifetime single-recorder flock remains as before; the narrow maintenance
operation does not take it or start another recorder. Short SQLite lock timeout
and processing deadline return busy/unavailable without partial commits. Verify
with a separate process racing a paused append, not only a sequential mock.
Reject schema surprises, triggers, linked/public/nonregular DBs and missing DBs;
never create a missing DB. Trusted fixed private ancestry remains the threat model,
not arbitrary untrusted paths or defense against malicious root.

The installed helper holds the existing protected update shared lock during imports
and execution, uses isolated Python, and disables project bytecode caching. Installed
modules, helper and UI join the captured release, protected installer allowlist and
FIM scope; building the release is not deployment or baseline approval.

UI extends the existing diagnostics section/styles: labeled resolution/window,
process opt-in, explicit administrator wording, live status, disabled controls
while a request runs. Erase review is nonmodal, focuses Cancel first, supports
Escape/cancel and returns focus to the trigger. No automatic elevation on load,
refresh or filter. Empty/denied/busy/uninstalled/invalid-response states remain
recoverable. After erase, discard only the previously displayed telemetry history,
then request fresh collector evidence; do not claim its cached snapshot is new.

Validation: export privacy, fixed request shape, no path/SQL injection, malformed
requests, actual concurrent append/erase, rollback on failure, missing/linked DB
refusal, preserved DB/schema/owner and next sample. UI tests cover download failure,
no automatic prompt, privacy defaults, cancel, confirmation, busy, denial, stale
history, focus and output bounds. Browser checks at320px and wide/200% equivalent
layout; authenticated production interaction and full live RAM stay pending.
