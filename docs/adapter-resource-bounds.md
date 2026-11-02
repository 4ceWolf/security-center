# Read-only adapter resource bounds — 2026-10-19

Built/tested in staging. Purpose: keep the lightweight collector's command and
inventory handling bounded. No service policy, package installation, boot or live
collector file was changed. See STATUS.md and telemetry-controls-implementation.md.

## Change and limits

securityd/adapters.py's general command wrapper previously used capture_output,
which bounded execution time but accumulated stdout and stderr without a byte cap.
It now delegates to the existing pipe reader:1MiB stdout,8seconds, discarded stderr,
strict UTF8 and killed/reaped child on limit/timeout/failure. The reader now accepts
an explicit internal set of return codes, preserving pacman-Qu exit0/1 semantics.
Systemctl status, local package availability and TCP listener checks use this path.
USBGuard already used the same bounded reader. No browser-supplied command API exists.

Directory inventories now cap entries before sorting/filtering:USB sysfs4096entries,
256observeddevices; package sync metadata256entries; root snapshot metadata4096entries.
Update/listener output also caps4096parsedrecords. Exceeding a bound rejects the module
result; it cannot return a partial list as a complete all-clear. Existing collector
module isolation/unavailable handling remains. USB identifiers are still observations,
not authenticated identity or policy enforcement. No automatic device action occurs.

Five tests in tests/test_adapter_bounds.py run real children for huge stdout,
blocked command timeout, accepted/rejected exit status and invalid UTF8; assert the
wrapper uses bounded transport; exercise pre-sort entry and parsed record limits.
Full suite344PASS after these changes; after the deployment-health addition below,
final suite345PASS:work/sol-controls-final-tests.log. Three earlier JavaScript suites
remain applicable; these changes do not modify UI bytes.

Actual ordinary-user host checks using staged adapter source returned:
listeners:secure,0non-loopbackTCP listeners;updates:unknown,0updates in LOCAL database;
telemetry service:unknown,running/policy not checked. These are the limited adapter
observations, not proof of a firewall policy, online package freshness or service
configuration. No host mutation or new authentication happened.

## Release health

tools/monitor_deployment.py now requires the new boot_observation module identifier
in a new-release health response. Otherwise an old collector could satisfy the
prior18-module list despite omitting the staged reader. New regression rejects the
old set and accepts the reader's presence. Presence is health only, not an assertion
that initrd observation/enforcement is installed or trusted. tools/build-installer-
runtime.py captured this code for later hash-pinned review; it was not executed as root.

## Exact latest review artifacts

Combined review bundle (telemetry controls + adapter limits + previously staged reader):
work/releases/monitor-iwww5mjl,31installedfiles/36FIMpaths.
release.json SHA256:
f635d6df7cf81cd5b0fd03588a8594d861da2bcbd0f7625f89e77c93f4b07a00.
Builder verification passed. deployment_approved=false,baseline_approved=false.

Captured installer runtime:
work/installer/runtime-80gg6yxk/runtime.json,14sources.
SHA25634f3d508f18dd22fdbb9c2f75e000bee3d59f52f9644e39ae6b5270bc9367182.
Compilation/capture succeeded; no root preparation, authentication or deployment.
Do not execute editable project scripts directly as root. Recheck current protected
baseline/metadata with the established captured bootstrap when the owner is available.
No previous approval covers the new bytes or additional FIM paths. The approved
installed25file/30path reference is unchanged. No baseline candidate for this release
has been created in the protected store yet; do not invent its digest from release.json.

Rollback: no installed files need undoing. Revert the staged adapter/wrapper/health
source changes if desired and rebuild review artifacts; do not substitute older
bundle bytes under a new approved hash. Reversion does not touch boot/security policy.

## Export memory evidence

New tools/check-telemetry-export-budget.py creates only synthetic project-local
recordings:128metrics,2880rawrows,2160hourlyrows; database33,964,032B. Corrected run
work/telemetry-export-budget-yljl5df9/report.json:

| Export | JSON bytes | Duration |
| --- | ---: | ---: |
|24h raw |11,252,689 |0.315s |
|24h hourly |269,087 |0.011s |
|2160h hourly |24,170,931 |0.831s |

All completed; source DB hash unchanged. Whole benchmark process peakRSS26,568KiB
(~25.9MiB), including fixture generation. Browser/Cockpit/helper authorization and
full on-demand stack are excluded. The first run's58,860KiB peak was inflated by the
benchmark hashing the entire33MBDB with read_bytes. The corrected benchmark hashes
in64KiB chunks and reran from a fresh process; both artifacts/logs remain. Neither
run exported or erased owner data. These are synthetic values, not laptop averages.

The stored fake databases are project-local test evidence, not new telemetry services.
The approximate200MB combined target still needs authenticated live measurement.
