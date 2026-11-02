# Fresh-manager native initrd boot test — 2026-10-18

New `--cold-boot observe|failed|timeout` scenarios in tools/test-luks-vm.py use
systemd's actual initrd startup/generator/mount/switch-root sequence. They are
separate from the earlier explicit service-start integration scenarios, which
retain their own required markers. No host boot files or enrollment are modified.

## What the guest actually does

A test-only provisioning wrapper first loads guest drivers, formats its disposable
LUKS/ext4 disk, populates a minimal final root, closes that preparation mapping and
enrolls its fresh software TPM with PCR7 plus signed-PCR11/initrd. All passwords
and signing material are disposable. The fixture uses fast PBKDF2 parameters to
keep tests quick; they are NOT recommendations or changes to laptop slot0.
Provisioning is setup, not evidence that the preboot gate has authorized an unlock.

The wrapper then execs a fresh systemd PID1. Installed native cryptsetup/fstab
generators run normally, reading the actual guest kernel command line and writing
/run/systemd/generator. No SYSTEMD_PROC_CMDLINE test override, daemon-reload, explicit
cryptsetup service start or test-directed switch-root request is used on this path.
Native initrd.target, root-device/root-fs targets, sysroot.mount, parse-etc,
cleanup and switch-root units drive the sequence. Targets plus required selected
services/sockets come from the installed systemd262 package. The guest remains
minimal; optional services/libraries are absent and warnings remain visible.

A mapping-specific drop-in clears the stock attach and selects the guest adapter,
Wants+After the observer, with a30second service timeout and native controlling
console. The snapshot auditor checks actual generated files/ordered drop-ins.
The adapter separately verifies PID1's actual ExecStart and Wants/After/Requires
properties, requiring the observer and excluding Requires that could block manual
recovery. It verifies expected observer ActiveState and Result OUTSIDE dispatcher
exception handling, so failed test assertions cannot turn into apparent recovery
success. Observe mode also validates the real current denial record before dispatch.

Observer mode never grants TPM permission: inventory/hotplug coverage remains
unverified. The failed mode runs a deliberately failing checker; timeout mode runs
a30second sleep killed by the five-second oneshot budget. All three must reach the
same manual-only slot0 path. Cryptsetup itself owns hidden console input, uses no
keyfile, disables external token plugins and gets one attempt. The host harness
waits for an actual prompt before sending ONLY the disposable guest passphrase
through QEMU stdin; it requires that input was sent and that the whole console
contains no copy of the secret. Guest code verifies mapper backing before recording
successful manual provenance; the TPM callback must never be selected.

Native cleanup/switch-root carries /run into the encrypted root and reexecutes
systemd there. A minimal final-root service verifies PID1 is systemd, the current
root mount is ext4 on the SAME verified mapper, and the private same-boot handover
reports manual with attested=False. It then emits final markers and powers off.
QEMU still boots the sealed initrd descriptor and records its complete manifest.

## Failure found and correction

Early run work/luks-vm-momsw3bs established native switch-root but did not explicitly require a
valid observer record; failed record reads could correctly select manual. Stronger
assertions in work/luks-vm-bgjerfu4 exposed /run mounted with default tmpfs1777,
which the secure ancestry reader properly rejected. Corrected the provisioning
mount to explicit mode0755. No security-reader permission check was weakened.
The failed QEMU was identified by its exact unique disposable disk argument and
terminated after the unhandled failure was diagnosed; parent produced its failed
report and reaped the software TPM. Failure evidence is retained. The harness now
also stops a cold guest on an unhandled traceback rather than waiting idly.

The prior failed-checker run wkfarpfs passed its earlier checks but predates that
mount correction and final runtime graph assertions. Use final reports below for
current coverage. Corrected observe run work/luks-vm-0or82ac1/report.json passed,
exit0,8.04s; timeout run work/luks-vm-yr10m1tw/report.json passed, exit0,13.10s.
Both include actual runtime graph, generated snapshot, checker state, manual unlock
and final-root markers. Timeout mode separately checks systemd Result=timeout.

## Limits and remaining work

This is a disposable Linux-kernel/software-TPM guest with provisioning before PID1,
not a firmware/UKI measured cold boot of the laptop. It does not use the laptop's
mkinitcpio image, Btrfs root, graphical console/Plymouth, physical keyboard, TPM,
policy keys or actual owner credentials. The boot kernel is not bound by the initrd
manifest. Not every optional initrd unit, generator or runtime executable is
included. This is meaningful native core-path coverage, not a whole-platform proof.

Cold mode currently tests one correct manual entry; cancellation/wrong input/retry
are covered by earlier controlled generated-service tests, not yet by this native
sequence. A usable production password agent/retry/recovery design still needs
integration and owner tests. Complete platform approval, hotplug closure, full
candidate-image review, alternative/legacy authorization revocation, Distress
hardware witness and owner restoration remain unimplemented/unauthorized here.

The builder refuses paths outside its fixed disposable project guest directories
before copying anything. Unit tests cover that host-path guard and fixed console
redirection acceptance/refusal in the snapshot auditor. Full Python suite292passed.
All guest runs use384MiB temporary RAM, a disposable sparse disk, no network,
no host block devices and no host TPM. No additional resident service is installed.

Final explicit failed-checker run work/luks-vm-gn3iyuf_/report.json passed, exit0,
7.98s, including all final runtime/snapshot/state/manual/post-root assertions and
the fixed provisioning mount. All three native profiles now have passing reports.
Report option flags describe packaged capabilities; cold mode's required markers
are its native sequence, not evidence that every older fixture ran in that guest.
