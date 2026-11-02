# Authorized telemetry history review — 2026-10-19

Supersedes the earlier access-limited report. Owner authorized sudo for this read-only export. The graphical sudo prompt succeeded; reviewed exporter bytes were embedded directly in isolated Python, SHA256 f6b12f58443c1f30de33a57f5a952b18064be2dfc861c4479a22a96edca0c690. No database content, configuration or permissions changed. Export is private under work/authorized-telemetry-8c6jo3k6.

Requested windows: October17,18,19,00:00–12:00 Asia/Karachi. A96-hour query returned25 hourly rows starting October18 at14:00 local. October17/18 midnight–noon records are absent from the current database export; no averages can be reconstructed. This does not establish whether they were never collected or removed earlier.

October19 has1440 samples,120 in every hour. CPU average7.39%, peak22.04%; RAM average63.54%, peak79.82%; battery76–77%. CPU package mean64.70°C, peak95°C; hottest individual core peak96°C. NVMe composite mean44.15°C, peak52.85°C; NVMe Sensor1 mean52.46°C, peak65.85°C. Labels were verified read-only against current host sysfs; sensor numbering may change between boots.

Battery power_w is0W for all1440 readings and ADP0.online is1 throughout. No battery discharge_w metric exists in this window. This is not zero laptop consumption: battery-reported flow does not measure wall input or total system power. No historical total-power watts exist among exported metrics.

Every sample carries at least one source-issue flag; this exporter omits the underlying issue text. Numeric CPU/RAM/battery/coretemp/NVMe metrics above each have1440 readings. Missing discharge/other sources are not filled with zero. Hourly aggregates cannot give exact times of individual temperature spikes.

| Hour PKT | CPU mean % | RAM mean % | CPU package mean / max °C | SSD composite mean / max °C | Battery W |
| --- | ---: | ---: | ---: | ---: | ---: |
| 00:00 | 7.2 | 60.8 | 60.1 / 95 | 40.5 / 52.9 | 0.0 |
| 01:00 | 7.7 | 62.5 | 66.5 / 93 | 44.3 / 48.9 | 0.0 |
| 02:00 | 6.9 | 61.5 | 63.8 / 76 | 43.4 / 43.9 | 0.0 |
| 03:00 | 6.8 | 63.5 | 63.5 / 72 | 43.4 / 44.9 | 0.0 |
| 04:00 | 7.0 | 63.4 | 63.6 / 71 | 43.3 / 43.9 | 0.0 |
| 05:00 | 7.4 | 62.9 | 64.4 / 75 | 43.6 / 44.9 | 0.0 |
| 06:00 | 7.3 | 64.3 | 63.3 / 68 | 43.6 / 44.9 | 0.0 |
| 07:00 | 6.9 | 64.0 | 63.6 / 74 | 44.4 / 45.9 | 0.0 |
| 08:00 | 7.9 | 64.5 | 66.2 / 72 | 45.2 / 45.9 | 0.0 |
| 09:00 | 7.9 | 64.3 | 66.7 / 71 | 45.8 / 45.9 | 0.0 |
| 10:00 | 7.7 | 65.5 | 66.6 / 71 | 45.9 / 46.9 | 0.0 |
| 11:00 | 8.1 | 65.2 | 67.9 / 76 | 46.5 / 50.9 | 0.0 |

The recorded process peak is short-name Main at104.7% of one CPU core and maximum observed RSS approximately1.91GiB. The name alone does not identify its application. qemu-system-x86 also appears near one core during the disposable boot tests. Process CPU percentages use one-core units and differ from whole-machine CPU percentages.

No system change or diagnostic remediation is inferred from these readings. No telemetry erase, upload or broader sudo operation was performed.
