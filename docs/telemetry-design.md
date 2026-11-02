# Local diagnostic telemetry

Current status (2026-10-18): continuous telemetry is installed, recording every
30 seconds and enabled at startup. Live DynamicUser/no-capability, private storage,
history and memory checks passed. The entries below are a chronological build
record; statements that a service is not installed describe those earlier stages.
Staged local JSON export is documented in docs/telemetry-export.md. Authenticated
Cockpit interaction, full-stack memory and owner download/erase controls remain
pending. See docs/HANDOFF.md for authoritative current deployment details.

Requested 2026-10-16. Build and test before installing. This adds diagnostic
history, separate from security-event history and its approved file baseline.

The recorder samples every 30 seconds while awake. Detailed samples retain at
most 24 hours / 2,880 rows; hourly summaries retain at most 90 days / 2,160 rows.
SQLite is capped at 64 MiB (excluding a bounded transaction journal), with a
512 KiB page cache. A separate process isolates recorder failures. Target RSS
is below 25 MiB; measure before deployment against the whole-stack 200 MB goal.

Collect host/per-core CPU busy and iowait percentages, load, available/used RAM,
cache, swap, pressure stalls, per-device disk and per-interface network rates,
hardware temperatures/fans, battery capacity, energy, charging/discharging
power, voltage, wear/cycles and the five largest observed CPU/RAM processes.
Also record frequency-policy readings and root/home filesystem capacity.
Only process short names, PID/start ticks and RSS/CPU are retained: no arguments,
environment, paths, URLs, packets, SSIDs, serial numbers or media. Short process
names are still private application-activity data. Data is local, directory0700
and database0600, with no upload or listening server.

Rates require two samples from the same boot and stable counter identity.
First samples, counter decreases, reused PIDs, long gaps and suspend intervals
have no invented rate. CPU excludes double-counted guest ticks. Process CPU
uses one logical CPU =100%, so multithreaded processes may exceed100%. RSS is
approximate and includes shared pages; do not sum it as system RAM use.
Disk/interface rates are per source; stacked devices/tunnels must not be summed.
Disk rates require diskseq to distinguish replacement; partitions without that
identifier are explicitly omitted. Sensor names include hwmon index and chip;
indices can change across boots. Do not compare individual sensor series across
boots without checking their identity. Sample boot IDs remain available.
The top list covers surviving observed processes, not short-lived tasks between
samples. Missing/unreadable sources and enumeration bounds are explicit.

Hourly summaries store per-metric sample count, sum, minimum and maximum. The
average is an observed-sample mean, NOT a time-weighted all-hour average; gaps
and sample counts remain visible. Rate metrics describe the preceding interval,
assigned to the ending sample's hour. No interpolation across sleep or downtime.
Hourly process peaks preserve which observed process was busiest/largest.
Retention is both age- and row-bounded, including backward clock jumps.

Initial tool supports finite captures and read-only summaries. Continuous
installation, dashboard charts, export/erase controls, full retention stress
test and full-stack resource validation remain separate deployment work. No
root permission, boot change or approved-baseline change is needed for trials.

Primary interface references:
- https://docs.kernel.org/filesystems/proc.html
- https://docs.kernel.org/power/power_supply_class.html
- https://docs.kernel.org/hwmon/sysfs-interface.html

## Built and checked

`securityd/telemetry.py` implements sampling and bounded SQLite storage.
`tools/record-telemetry.py` runs finite captures (default3 at30-second intervals)
and `--summary` reads the latest sample and hourly means/peaks without writes.
Project data lives in `work/telemetry/diagnostics.sqlite`; no system service is
installed and the tool stops when its requested samples are complete.

First host capture:3samples at2-second intervals,128metrics in the final sample,
18,928KiB peak RSS,0.115CPU seconds,4.106seconds elapsed,45,056-byte DB.
This short capture is not a sustained resource benchmark. Partitions omit rate
metrics because they lack diskseq; whole-disk data remains available. Fans and
other optional sensors are recorded only when the kernel exposes them. GPU,
SMART/NVMe health queries and per-application grouping are not implemented.

Hourly summaries expose metric counts, sample means, peaks, issue counts and
mixed-boot markers. Sensor series in mixed-boot hours need identity review.
Storage cap failures raise an error and roll back the current transaction,
preserving earlier history; continuous service health reporting is still to be
built. The64MiB cap takes precedence over the nominal retention duration on
machines with many more metrics. No authentication or anti-tamper claim is made
for this diagnostic history.

156project Python tests pass, including17telemetry tests. Initial full-suite run
found the privacy-permission fixture depended on the inherited umask; the
fixture now explicitly sets the intended unsafe mode before verifying rejection.
Production permission enforcement did not need weakening.

## Background lifecycle and monitor integration

Staged telemetry_worker.py uses a30s interval, exclusive worker/DB locks, atomic
private health publication and interruptible SIGTERM/SIGINT shutdown. SQLite or
sampling errors publish degraded status with exception TYPE only, close the DB
and retry at the normal interval. No catch-up bursts, no deletion/recreation of
corrupt data. Failure to publish health terminates the worker; supervisor restart
is bounded. Lock files stay in place; kernel locks release on process death.
The finite capture tool also uses the exclusive DB lock through Store.

Proposed service uses DynamicUser, private StateDirectory, no capabilities,
24MiB MemoryHigh/40MiB MemoryMax,5% CPU quota and bounded restart. It is included
in staged release/fresh-install lists but NOT enabled by the fresh MVP installer
and NOT installed on this laptop. Syntax verification passed; actual DynamicUser
namespace, sensor visibility, quota behavior and power overhead still require a
controlled service test. /home filesystem capacity is measured using /home,
not the service account's home directory.

Collector telemetry_health reads the fixed backing path
/var/lib/private/security-center-telemetry/health.json without symlink traversal.
It requires private regular file/parent permissions and matching ownership;
fixed trusted system ancestry is assumed. It rejects malformed health and
classifies old/future/other-boot reports as stale. Fresh recording is a diagnostic
self-report, not an attestation or security-success claim. No DB/process list is
exported to the dashboard yet. Applications includes the diagnostic health card;
ordinary sample-count changes do not generate security-history events.

Worker runtime test passed actual SIGKILL/restart (2records ->4), orderly stop,
storage-unavailable status and subsequent recovery; peak childRSS23,876KiB.
Report work/telemetry/worker-report.json.170Python tests and existing UI state
regression pass. The worker test process completed during the user's pause; its
terminal handle/result was checked on explicit resume, without relaunching it.

## Bounded history retrieval

Added telemetry_query.py with read-only SQLite access, query-only/trusted-schema
settings, a 512 KiB cache, a two-second query deadline, bounded record size and
512 KiB output ceiling. Fixed hourly query uses bound SQL parameters. Selection
supports one to eight metric names and 24/168/2160-hour windows; oversized
results fail explicitly rather than silently omitting history. Names select
JSON fields only and cannot supply SQL or commands. The caller must supply a
trusted private path; browser-provided database paths are not supported.

Returns observed-sample mean/min/max/count, gaps, partial-source issue counts
and mixed-boot flags. Missing readings remain null; missing hours are counted.
`record-telemetry.py --history 24` reads the project's saved history without
collecting. Actual saved sample readback returned one hour and23missing hours.

The staged daemon includes the default four-metric/24-hour history in its
existing read-only snapshot. A missing DB yields not_recorded; malformed or
unavailable history yields unavailable without suppressing security modules.
No new command endpoint or database writes are introduced. Chart rendering,
longer-window UI controls and deployment are still pending.

## Staged hourly display

The existing Cockpit page now includes Laptop diagnostics: a labeled native
measurement selector for CPU/RAM/battery/discharge and a semantic hourly table.
It renders24hour slots with observed means/min/max/counts, distinguishes no
samples from missing metric readings, and preserves mixedboot/sourcegap notes.
An unavailable/missing history response clears the table; a failed refresh keeps
previous history with an explicit stale warning. Scroll position survives render.
No chart dependency or extra background process was added.

Node UI regression covers selection, missing readings/hours, failed refresh,
empty/unavailable/notrecorded states and scroll preservation. Firefox headless
screenshots at1280px and320px were inspected using the saved diagnostic trial
and an explicitly labeled local preview in work/telemetry-ui. Narrow table
scrolling is local; rendered preview is not an authenticated Cockpit check.
Keyboard, screen-reader,200%zoom and live authenticated checks remain pending.
The local Firefox profile is separate from the user's existing browser profile.

## Worker resource-limit rehearsal

`tools/check-telemetry-budget.py` runs the actual worker in a temporary user
service, with MemoryHigh24MiB, MemoryMax40MiB, TasksMax8, CPUQuota5%,
NoNewPrivileges, private umask and a75s safety lifetime. The tool stops it and
checks graceful health plus SQLite integrity before removing trial state.

Completed35.35seconds at an accelerated2second interval:18samples,127metrics,
10,465,280-byte peak cgroup memory charge,0swap,0high/max/OOM events,
0restarts,387,262,000ns CPU time. Effective CPU quota50ms persecond was read
back. Report: work/telemetry/budget-report.json. The explicit quota assertion
was added to the helper after this successful run; recorded value already met it.

This is cgroup accounting, not the earlier23,876KiB processRSS measurement; shared
pages and accounting attribution differ. It does not validate DynamicUser,
production filesystem namespaces or sustained battery overhead. Installed monitor
was independently active with0restarts,48,181,248bytes current and52,338,688bytes
peak cgroup memory. Cockpit web service was inactive, so the full authenticated
stack's200MB target remains unverified. The trial user unit is now inactive and
its temporary database removed; continuous telemetry is still not deployed.
