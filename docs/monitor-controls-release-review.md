# Prepared monitor update review — 2026-10-19

Review only; no approval is requested or inferred in this unattended stage.
The new candidate is fully built and tested in the project; it is not installed.

Release: work/releases/monitor-iwww5mjl

Manifest SHA256: f635d6df7cf81cd5b0fd03588a8594d861da2bcbd0f7625f89e77c93f4b07a00

31 fixed installed files,36FIMpaths. Python345PASS; dashboard/trust/telemetry JS suitesPASS;
Firefox synthetic download, focus/keyboard, denial and320CSSpx/200%zoom checksPASS.
Export benchmark128metrics/2880raw/2160hourly passed; benchmark peak26,568KiB.

## Intended behavior

Adds diagnostic JSON downloads and deliberate saved-history removal through a fixed
administrator helper; fixes recorder/delete serialization; caps status-command and
directory output; adds the previously staged passive observation reader/status row.
This does not install an initrd observer, activate device enforcement, change boot/
TPM/LUKS/PAM, or delete any recording during installation. New actions run only on
owner clicks through the administrator bridge. No automatic admin prompt on refresh.

## Captured source comparison

The previous-file hashes below are unprivileged packaging observations, not current
approved metadata or an installer authority. A fresh protected preflight is mandatory.
Missing observations do not independently prove a file was absent.

Changed observed files: 7. Identical observed files: 18. Unobserved previous bytes: 6.

| Source | Observed change | New SHA256 |
| --- | --- | --- |
| securityd/collector.py | changed | 39c4e684cce69766c47551b848b1d4f0d5ef785534fa2ebbb0f7b4239de9f4b8 |
| securityd/adapters.py | changed | e2057f9cd9b290cf7930cf395b546ef474950d2115c2f0a29c045c51e5c714e8 |
| securityd/integrity.py | changed | 19f865aa06ac6c7cb5905b32f4b7746a030ea3501b91df6c755d3571b5300a15 |
| securityd/telemetry.py | changed | 66ea19f13159e36909d85ea35136dff408be022383dc68d4be1a9c4024afc1b6 |
| cockpit/index.html | changed | 92a892b3f7cfe9301774c6d465da3ec8aa94253a3436678a9836a1189d29c71a |
| cockpit/app.js | changed | d5602729fb2a34625a9be7807dba8afd2039b3af7b546e81f1b80b7f30ac5927 |
| cockpit/style.css | changed | 41921c8c89fbeebb10de5a934477ff828265c83ec48747ca0f5660123144f9d3 |
| policies/device_gate.py | identical | 2a06e14f872cc9bd456f1b84a188ee07d4a3b6b084b04d114320cab40579a9d1 |
| policies/device_inventory.py | identical | 9137d4acb593d3f0b2c8a2ead30ce58ffaaaf9948252f098b566c04f35375275 |
| policies/trust_policy.py | identical | 6cdb63e8a6fd6450c6526cbbad928a1f075d1278e6be42a34d87f1de801019ee |
| policies/trust_store.py | identical | 1ffc31f5302fb0677f6bca13d6170c0d39a29f31a6126c1e93c9a039009b8727 |
| tools/device-trust-helper.py | identical | cf66e8b04b5616822cfbc60534b78654a5b388d316978b4222c974031e94db59 |
| policies/normal-devices.candidate.json | identical | 1914828742f1c1294a3eaf0c09de3811394e5797ad6091e6bea62e1cfbbc96e6 |
| initramfs/handover.py | identical | 65f719561ab9349b10852b8120dc03eed970c77e0ddaed42fb7f4d6943387732 |
| securityd/daemon.py | identical | 0a8fbbb0a5d7cf6a7942f35da838d7cdf234153f6ab3922300f18a5ca7ba8f45 |
| securityd/client.py | identical | 2dcf4c1030452abdfa28d4395a82aa9174c0d7d240c98a90bc462f8e89a94eaf |
| securityd/history.py | identical | 5f2441e587b6cccc6f7c45d50750877a5551bb20809c85351abc710f40ef9dac |
| securityd/audit.py | identical | 2fc862b278734f89c0923362fe4a2bd34b516b3b2579620a3e0c1a8599c698f1 |
| securityd/confinement.py | identical | 125832915abe216a13dc103e5a3b2583a5cdd5129e58a9d56058b1ee07f4f1aa |
| securityd/telemetry_worker.py | identical | 94dfa9e183c7a7c4c1291ee0d344a332a8539748a6ef8afaf317636b8b1d3f9b |
| securityd/telemetry_health.py | identical | f6872690c69759a9cffd94a08f348b30b4cca2de03982669354f0912a421dae1 |
| securityd/telemetry_query.py | identical | 6ad42475884d5500c5f9d26df677b57a2f3912f23108122c89a49a366fbf02e8 |
| cockpit/manifest.json | identical | e446615e23aa74954245fddc71c0e86ebaad2ae33c9e02e5b09ce4c315ea6481 |
| packaging/security-center.service | identical | 8a33b3aa0a2bf84b01dad076f58ce8b811f536e9c3a3775b8690167ad2aca7cc |
| packaging/security-center-telemetry.service | identical | e1f34a90564994cffd152f16f06af2fe9d0ce70e5a6011c57f2ccc29baa74b1c |
| tools/telemetry-helper.py | not observed | 0a6a3ea58be0a3bbd4ca059fda1d9793024bd8cca0fe7642cd05de60296a95c2 |
| tools/export-telemetry.py | not observed | f6b12f58443c1f30de33a57f5a952b18064be2dfc861c4479a22a96edca0c690 |
| initramfs/boot_observation.py | not observed | c9a3ebfb8cd39ca4452fc07784c1132b1b796e30a75cc13b5f66f6a9943e1eff |
| securityd/boot_observation_status.py | not observed | 952957355e7d43180a94d296a0454946f779e9b1323c1a672cab688380b986bf |
| securityd/telemetry_actions.py | not observed | 1ac3f6db94922c19560b3d422c4b61c642dac872aaa446aa41a2f42004150732 |
| cockpit/telemetry-controls.js | not observed | 301083286584ca8ce76dfc426db1fba25bcfa345ee9f0fa4b91d922ea63dfe61 |

## Deployment and recovery gates

Captured installer runtime:work/installer/runtime-80gg6yxk/runtime.json,14sources.
SHA25634f3d508f18dd22fdbb9c2f75e000bee3d59f52f9644e39ae6b5270bc9367182.
Current release and installer bytes were independently compared against current
project sources after all changes; both match. No privileged runtime was executed.

When the owner is available, use the existing hash-pinned bootstrap workflow to
authenticate and inspect the installed baseline/file metadata, prepare the protected
transaction, then apply the reviewed release. Preserve the existing service state
and use protected backups/rollback if files, service health or trust state differ.
The deployment health check now requires19module identifiers, including the new
observation reader. An unknown/not-installed observation is expected until its
separate boot-image milestone; no green verification may be inferred from it.

A NEW exact36-path baseline candidate will be generated only by that protected
transaction. Its SHA is not the release manifest SHA and is not available yet.
The owner must approve that exact candidate using the established process; the
already-approved30-path reference remains the prior reference and is archived on
successful new approval. Do not reuse candidate3464d566... as approval of new bytes.

After deployment, verify the real Cockpit controls, safe cancel/denial behavior,
actual download privacy and signed-in total memory. Do not execute production clear
as an installation test: removal needs the owner to choose it explicitly. Any
lost clear receipt leaves outcome uncertain; check fresh current history before retry.

Rollback uses the protected transaction backups and saved service state, not copies
from an arbitrary project directory. No live files currently need rollback. Full
details:telemetry-controls-implementation.md and adapter-resource-bounds.md.
