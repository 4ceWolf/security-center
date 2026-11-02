# AppArmor observation contract — staged build

Read the fixed kernel enabled parameter and bounded securityfs profile list. Count enforce, complain, kill, unconfined and unknown modes separately. A single enforcing profile is not sufficient to label whole-machine confinement secure. Show missing/unreadable evidence independently of disabled enforcement.

Sample up to512 process directories, reading only bounded comm and AppArmor label attributes. Observe a fixed set of relevant application names. Never read command lines, environments or credentials. Record PID start time before/after reads to reject PID reuse. Process exit/permission races mean incomplete observation, not proof of confinement. Prefer the AppArmor-specific proc attribute; generic attr/current is a compatibility fallback with explicit provenance. The display is a point-in-time sample; process names can be changed and are not authenticated application identity.

No actions, profile loading, package installation or LSM/boot changes. The collector must report coverage unverified even when all sampled processes look confined. Required tests cover disabled/missing state, mixed profile modes, malformed/oversized input, unconfined applications, process races and inaccessible evidence. Deployment is separate and would change the approved collector file baseline.

## Built and tested
securityd/confinement.py now supplies the staged collector's AppArmor observations. Profile reads are capped at1MiB/4096records; process enumeration stops at512entries. PID start times reject reuse during sampling, and missing labels/permission failures make the sample incomplete. AppArmor-specific labels are preferred; generic attribute fallback is explicitly identified. No result claims complete application coverage.

Nine new tests pass;82 project Python tests pass overall. A read-only check on the actual laptop returns AppArmor not enabled, consistent with its kernel parameter N. No installed collector files or enforcement settings changed.

Packaging: the fresh-install file list includes confinement.py. Existing installation upgrade is NOT ready to run: deploy collector.py and confinement.py together, include the new module in an explicitly reviewed FIM scope migration, and prepare a replacement baseline retaining prior-file continuity. Historical update scripts are not suitable for this staged source snapshot because they omit the new dependency. The current17-file baseline and live collector remain untouched. This is a build artifact, not a claim that AppArmor is installed or enforcing.
