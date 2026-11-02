# Telemetry controls — Sol implementation, 2026-10-19

Status: implemented and tested in staging. No installation, production export or
production deletion occurred. Existing approved baseline remains unchanged.
Read telemetry-controls-design.md for the pre-implementation contract.

## Behavior and changed sources

Cockpit diagnostics now has local JSON download with raw/hourly windows and private
process details explicitly opt-in. Clearing history is a separate inline review;
Keep history receives initial focus, Escape/cancel restore the trigger, and no
administrator request occurs until download or final clear confirmation. Buttons
are disabled in flight. Errors offer a retry without exposing backend exceptions.
The browser reports download started, rather than claiming the file was saved.

- cockpit/index.html, style.css, new telemetry-controls.js: controls, privacy text,
  asynchronous feedback, output bounds, local Blob download and URL cleanup.
- cockpit/app.js: suppress previously cached telemetry after confirmed deletion
  until a collector snapshot generated after the helper's server timestamp arrives.
- securityd/telemetry_actions.py: strict4KiB JSON request with exact fields,
  duplicate rejection, fixed export/erase operations, required confirmation token.
  Erase uses only the fixed private database in production. It requires the exact
  two-table schema, rejects unexpected tables/triggers/columns, public/linked/FIFO
  or oversized databases; no missing database creation. A single bounded IMMEDIATE
  SQLite transaction removes samples/hourly summaries in place. It preserves inode,
  owner, schema, locks and service. Logical deletion only, not forensic erasure.
- tools/telemetry-helper.py: installed-root path only, no CLI arguments or arbitrary
  command/file/SQL inputs. Cockpit superuser=require is the authorization boundary.
  Holds the existing protected-update shared lock during imports/operation and
  disables preexisting module bytecode use. Export imports the existing exporter;
  erase emits a receipt and best-effort fixed-content journal audit. Actor means
  root execution, not independently identified human. A lost response can leave
  outcome uncertain, so the UI says to check current history before retrying.
- securityd/telemetry.py: append now begins IMMEDIATE before reading the hourly
  summary. This closes a lost-update race where an append could read an old summary,
  deletion commit, then the append restore old history. No database format change.
- tools/build-monitor-release.py, tools/protected_files.py, securityd/integrity.py:
  all four new installed files are captured/protected/monitored. Existing deployment
  and binding tests now expect31installedfiles/36FIMpaths. Their validation logic
  remains enabled. No bypass or automatic approval was added.

The exporter remains the existing read-only tools/export-telemetry.py, installed as
telemetry_export.py when deployment is approved. No new resident daemon, listener,
network connection, dependency or regular wakeup was introduced. Native SQLite
locking serializes the short maintenance operation with the single recorder; the
lifetime recorder flock is not bypassed to run another recorder.

## Executed verification

Commands ran as the ordinary host user through flatpak-spawn --host with the
project as working directory:

```
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
/usr/bin/node tests/test-ui-state.cjs cockpit/app.js
/usr/bin/node tests/test-trust-ui.cjs cockpit/app.js
/usr/bin/node tests/test-telemetry-controls.cjs
/usr/bin/python3 tools/test-telemetry-browser.py
/usr/bin/python3 tools/build-monitor-release.py
/usr/bin/python3 tools/telemetry-helper.py
```

Full Python suite: **339 passed**, work/telemetry-controls-full-tests-2.log.
Six new tests cover strict requests/privacy, explicit confirmation, in-place erase/
next sample, missing/symlink/hardlink/FIFO/public DB refusal, unexpected schema and
trigger names, rollback after the first deletion, and a real separate-process
append holding the IMMEDIATE lock. Concurrent erase gets busy, then succeeds after
the append; subsequent samples start a new summary. No real recordings were erased.
The initial full-suite failure was an outdated32-path expected count, corrected to
36; its failed log remains work/telemetry-controls-full-tests.log.

All three JavaScript suites passed. New tests cover exact helper/superuser options,
no automatic elevation, process privacy opt-in/default, raw window bounds, complete
JSON download/URL cleanup, confirmation/cancel/Escape/focus, busy/denied/malformed
responses and cached-history suppression after deletion.
The nonroot helper invocation refused with authorization_required before imports
or database access. Privileged helper execution is NOT claimed tested.

Actual Firefox fixture passed:
work/telemetry-controls-browser-tdoiiq2a/report.json.
It loaded only a separately labeled synthetic local preview, never Cockpit or the
production helper. Verified a real JSON file landed in the private fixture download
folder with processes excluded; native Tab/Escape, safe initial/restored focus;
confirmation, denial and cached-history behavior. Screenshots at1080/540CSSpx and
actual200% page zoom at320CSSpx have no document overflow. Narrow screenshot was
visually inspected. Browser automation's privileged context is enabled ONLY in a
throwaway synthetic profile to set browser page zoom; no user profile is opened.
The fixture Firefox process is stopped after testing.

Earlier browser attempts are preserved: the first checked an empty download file
before Firefox finished writing (fixed bounded complete-JSON wait); the second
proved500px, not320px, because Firefox clamps desktop windows; the third correctly
failed when content key actions did not change browser zoom. The final harness sets
actual page zoom in the disposable browser context and asserts320px/DPR2. Failed
attempts are not narrow-layout passes. Logs: work/telemetry-controls-browser*.log.

Untested: authenticated Cockpit, production download/erase, screen-reader behavior,
combined active Cockpit RAM, sustained overhead and a deployed release. No accessibility
certification or full production readiness is claimed.

## Current memory observation

Read-only systemctl show during this run:

| Installed component | Current cgroup bytes | State |
| --- | ---: | --- |
| security-center.service | 37,695,488 | active,0restarts |
| security-center-telemetry.service | 13,438,976 | active,0restarts |
| cockpit.socket | 12,288 | listening |
| cockpit.service | unavailable | inactive |

Combined observed background charge51,146,752bytes, about48.8MiB. This is one
observation, not peak/exclusive process RSS or a signed-in Cockpit measurement.
The approximately200MB full-stack goal remains unverified. These staged controls
add no resident service; on-demand export/browser memory is still unmeasured.

## Captured review release and rollback

work/releases/monitor-ascsvybw,31files/36FIMpaths.
Manifest SHA2562ad7214cfcaa6021c7b78df4fb10099f797ea66bd153d5064e39751214a60491.
The release builder verified fixed destinations, static imports, hashes and complete
FIM coverage. deployment_approved=false,baseline_approved=false. It also includes
previously staged initrd observation reader/UI, which is not a deployed observer.
The first intermediate release7pxyrr89 predates the schema-review refinement; use
ascsvybw for review. Rebuild if any product source changes after this checkpoint.

Installation still needs the established captured installer/authentication process
and explicit exact replacement-baseline approval. Current installation remains the
prior25file/30path release. No live files need rollback. To undo staged work revert
the listed source changes and four new files; keep test evidence. Deleting saved
records from the UI, once installed, cannot restore them; backups/downloads are
separate and not deleted. Owner should export first when records may be useful.

## Deferred Astra work

Real UEFI/stub phase execution, production image delta/signing, preboot enforcement,
Distress antirollback/PAM and physical device/DMA decisions remain at their existing
specialist checkpoints. This telemetry work makes no boot/key/policy changes.
