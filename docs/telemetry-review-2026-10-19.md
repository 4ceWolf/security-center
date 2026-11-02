# Telemetry review — 2026-10-19

Superseded by [authorized full-metric review](telemetry-authorized-review-2026-10-19.md) after owner-approved sudo access.

Requested windows: October 17, 18 and 19, 00:00 inclusive to 12:00 exclusive, Asia/Karachi (UTC+05:00). At the latest retrieval October 19 noon had passed; the initial commentary calling it partial was superseded by the current timestamp.

Only October 19 is available through the installed unprivileged 24-hour snapshot. The private long-term database was not accessed: noninteractive sudo reported authentication required. No password prompt was requested. October 17/18 are unavailable in this report, not proven absent from the database. The earlier saved October 18 collector snapshot begins at 14:00 local and does not cover either requested earlier window.

October 19: 1,440 samples, 120 per hour. CPU mean 7.39%, observed peak 22.04%; RAM mean 63.54%, range 46.68–79.82%; battery 76–77%. Discharge watts unavailable. CPU temperatures, process peaks and the other stored metrics are not exposed by this installed default history response.

All 1,440 samples have at least one source-issue flag. The endpoint omits its details, so this report cannot identify the affected source. The listed CPU/RAM/battery metrics each have 1,440 numeric readings. Do not interpret this as full telemetry coverage, zero discharge or a diagnosis of the issue. Means are sample-weighted, not time-weighted.

| Hour PKT | CPU mean % | RAM mean % | Battery range % |
| --- | ---: | ---: | ---: |
| 00:00 | 7.16 | 60.80 | 77–77 |
| 01:00 | 7.67 | 62.47 | 77–77 |
| 02:00 | 6.88 | 61.50 | 77–77 |
| 03:00 | 6.83 | 63.49 | 77–77 |
| 04:00 | 6.99 | 63.43 | 77–77 |
| 05:00 | 7.40 | 62.89 | 77–77 |
| 06:00 | 7.25 | 64.27 | 77–77 |
| 07:00 | 6.95 | 64.01 | 77–77 |
| 08:00 | 7.89 | 64.50 | 77–77 |
| 09:00 | 7.90 | 64.35 | 77–77 |
| 10:00 | 7.69 | 65.54 | 77–77 |
| 11:00 | 8.12 | 65.22 | 76–77 |

Evidence: work/telemetry-review-2026-10-19/current-snapshot.json (root-peer-checked local socket); summary.json. No private database export, telemetry deletion, privilege change or external upload.
