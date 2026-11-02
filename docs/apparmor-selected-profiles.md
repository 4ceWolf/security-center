# Small AppArmor rollout — 2026-10-20

A dedicated oneshot unit loads only the packaged avahi-daemon and lsb_release
profiles. The package-wide apparmor.service remains disabled. The authentication
helper unix-chkpwd is deliberately excluded from this rollout.

The Avahi profile attaches to future /usr/bin or /usr/sbin avahi-daemon executions;
the unit orders profile loading before that service starts. Loading a profile does
not retroactively confine a process that was already running unconfined. The
lsb_release profile has no automatic attachment: its own comments restrict it to
explicit transitions from other profiles. Do not count ordinary shell invocations
of lsb_release as confined. Most desktop applications still have no profile.

Both native profiles passed offline ABI4 compilation and are now loaded/enforcing
after the successful actual AppArmor trial. The dedicated unit is active/enabled.
Do not enable every shipped profile or restart authentication/network services just
to raise a profile count. The UI reports actual profile and observed process modes
and does not call kernel enablement complete application coverage.

After the owner selects the AppArmor test image: verify Secure Boot/integrity,
root encryption/manual slot, AppArmor=Y and LSM membership. Then load only these
profiles and run a disposable named-profile allowed/denied file-read test to prove
kernel enforcement. Check actual Avahi attachment separately; a stopped service
is not a confined running process. Keep promotion of the trial image gated on
owner compatibility results. Disabling/removing only these profiles is a separate
controlled rollback; it does not change disk encryption or boot selection.
