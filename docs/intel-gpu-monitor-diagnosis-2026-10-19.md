# Intel GPU monitoring diagnosis — 2026-10-19

User reported intel_gpu_top monitoring stopped. Reproduced unprivileged tool failure:
Failed to initialize PMU! (Permission denied); tool says CAP_PERFMON is required.
intel-gpu-tools2.6-1, GPU enumerates as Alder Lake-P via i915/card1/renderD128.
perf_event_paranoid=2, no file capabilities on /usr/bin/intel_gpu_top. Lockdown
integrity remains active. No intel_gpu_top coredump found. No monitor process left
running after the check, as expected for the widget's short on-demand collector.

Desktop source ~/.config/quickshell/inir/services/ResourceUsage.qml runs the tool
unprivileged with a one-second timeout/500ms period. If no busy value is parsed, it
sets _gpuUsageSource=none and marks GPU usage unavailable. This means a denied first
sample disables further collection until the source is reinitialized. No desktop
source or inir service was edited/restarted. inir NoNewPrivileges=no, no ambient caps.

Authorized administrator sample (-J -s200 -n2) completed0, produced engine JSON,
no stderr. Receipt:work/intel-gpu-top-diagnosis.json. Root sampling works with current
integrity mode; do not blame USBGuard or a GPU crash from this evidence. No proof
of when/how the access state changed; earlier successful configuration wasn't captured.
No global perf setting, capability, group, sudoers, boot, driver or service changed.

For a future fix, prefer scoped access for the monitoring tool/account over relaxing
perf access globally. Evaluate permission scope before adding file capabilities.
Kernel primary reference:https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html

## Owner requested fix — applied and verified

Granted only CAP_PERFMON to the root-owned native /usr/bin/intel_gpu_top. Execute
permission is restricted by ACL to root and UID1000(kyo), with owning group/others
having no access. Existing contents SHA256 unchanged:
d6242e8c7676129e23decc111905ab2197e209f1e60cde6d77e2d4478766c9fc.
No CAP_SYS_ADMIN, global perf relaxation or extra privilege on the desktop shell.
perf_event_paranoid remains2; lockdown remainsintegrity. Protected original metadata:
/var/lib/security-center-gpu-monitor-kkeezrxp/before.json.

Normal account finite sampling passed; unrelated nobody account execution denied.
Widget's exact timeout1/drmcard1/JSON/500ms command produced8busy values without
stderr (highest49.097102% in that window). Timeout124 is expected for this command,
not the original Permission denied failure. Restarted only inir.service successfully
(active) to reset its disabled backend. No desktop source or boot settings edited.

Persistence installed: /etc/pacman.d/hooks/90-security-center-intel-gpu-monitor.hook
and /usr/local/libexec/security-center-intel-gpu-monitor-permissions.py. The post-
transaction hook targets only installation/upgrades of usr/bin/intel_gpu_top. The
isolated root helper verifies a regular root-owned nonwritable file, package owner
intel-gpu-tools and UID1000, refuses unexpected extra capabilities, and reapplies
only the restricted ACL/CAP_PERFMON. No extra resident service. Manual hook action
passed; an actual package upgrade trigger was not executed as a test. Final widget-
command check passed after hook installation. Receipts:work/intel-gpu-monitor-fix.json,
intel-gpu-widget-check.json,intel-gpu-monitor-update-hook.json,intel-gpu-final-check.json.
Source templates are under packaging/. Add these maintenance files and native tool
metadata to the future expanded monitoring scope; current36-path FIM doesn't cover
these new artifacts. Existing reference was not changed or automatically approved.

Rollback when explicitly requested: verify target/package and the above before-state;
remove this exact hook/helper, remove tool capability with setcap -r, remove the new
ACL with setfacl -b, restore original mode0755. Ownership/root:root and binary bytes
were preserved. A user-space shell restart resets the backend after any later fix.
