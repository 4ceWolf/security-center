# OpenSnitch configuration observation contract

Use only the fixed default rules directory /etc/opensnitchd/rules. Inspect bounded regular JSON files without following symlinks. Report configured enabled/disabled actions and opaque content fingerprints. Never export rule names, filenames, descriptions or operator data: auto-generated names and match values may contain command lines or environment values. Do not execute or compile rule expressions.

File observations do not establish that the running daemon loaded this directory, that its live rule set matches disk, or that packet interception works. Report policy_verified=false and identify default-path-only scope. Missing/unreadable/malformed/changing evidence stays unavailable or incomplete. Custom rule paths, temporary in-memory rules, connection events and machine-care/WARP coexistence require later native integration tests.

Primary reference: https://github.com/evilsocket/opensnitch/wiki/Rules documents default rule storage, enabled/action/precedence/operator fields and rule-name generation. No native package installation or firewall changes in this build.

## Built and tested
Staged adapters.py now scans at most256rule files,1024directory entries,64KiB per file and4MiB total bytes. Uses no-follow directory-relative opens, rejects nonregular files, checks file identities before/after and directory identity across enumeration. Sorted opaque content fingerprints make observations independent of directory order. Unknown operator types remain unknown; no regular expression or rule evaluator runs.

Only enabled, precedence, action, operator category and opaque hash leave the parser. Rule names, file names, descriptions, operand and operator data never enter the exported inventory. Counting configured rules does not infer active packet filtering. The native service can be active while a custom rules path or reload error makes the observed default directory unrelated to live policy.

Native inventory is now included in history fingerprints. OpenSnitch content changes and USBGuard device decisions can generate a state-change observation even when totals remain equal. USBGuard records are sorted by numeric ID to prevent enumeration-order-only events. Event summaries still contain no rule contents/serials.

126Python tests pass, including sensitive-content omission, symlink/directory rejection, invalid flags/duplicate JSON, malformed/oversized rules, disabled count, absent/inaccessible state, unsupported operators, same-count policy changes and USB order stability. These tests use fixtures; no live OpenSnitch daemon is installed or queried for active policy. Actual package/IPC/network/firewall coexistence tests remain pending. No deployed files or native policies changed.
