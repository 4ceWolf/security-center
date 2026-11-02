# Alternate generated unlock path — reproduced in guest, 2026-10-18

The disposable guest now demonstrates the concrete bypass risk from replacing
only one root-unlock service. This is new attack evidence, not a claim that the
laptop has been exploited or that all alternate paths have been discovered.

`tests/vm-alternate-unlock.py` runs before the existing virtual-PCR7 mismatch test,
while the freshly enrolled guest PCR7/signed-PCR11(initrd) policy is valid. It uses
the real cryptsetup generator to create two service names for the SAME actual
LUKS UUID, resolved through udev. Both are noauto so the fixture controls starts.
Only one receives a gate drop-in; the second retains the stock attach command.
Actual loaded ExecStart values are inspected in the guest PID1.

The gated service selects manual-only with an intentionally unsuccessful manual
fixture callback, reports failure and creates no mapper. The second generated
service then starts successfully and creates a mapper on /dev/vda through the
guest's valid TPM enrollment/signature. Its generated '-' key argument, headless
operation and disabled password cache are retained; no terminal input or test
keyfile is supplied to that service. The mapping is verified and then detached.
The negative fixture's exact generated-root-service name set differs from the
single reviewed name, so it is marked rejected by the fixture's candidate check.
Both fixture unit files/drop-in are removed before the rest of the test proceeds.

Important scope: the rejection assertion checks this bounded generated fixture.
It is NOT a deployed builder auditor, runtime interlock, system-wide command
inventory or protection against old signed images. The deliberately ungated
service is allowed to execute only to prove the bypass in a disposable guest.
A future candidate builder must enumerate all generated definitions and effective
drop-ins for every root-volume alias and reject unreviewed paths BEFORE signing.
A malicious authorized older image can bypass a new builder and remains a separate
cryptographic migration problem. Manual emergency commands likewise require a
clear recovery/threat boundary rather than an assertion that no alternatives exist.

This establishes an explicit regression scenario required by the preboot contract.
The existing original device-check service may be failed while the ungated service
succeeds; ordering the intended service after the checker cannot constrain a
separate service that has no such dependency. Preserve manual slot0 and the current
host enrollment. No host disk/TPM, boot image, authentication, approved baseline or
installed files are touched by these guest tests.

First failure-checker run: work/luks-vm-bpf8c6he/report.json passed, exit0,27.99s,
including VM_ALTERNATE_UNLOCK_BYPASS_REPRODUCED and
VM_ALTERNATE_UNLOCK_CANDIDATE_REJECTED plus all prior supervision, terminal/UUID,
signed-PCR11 and same-mapping switch-root checks. Guest384MiB temporary, no network
or host device exposure. Reused udev setup now checks the existing control socket
before attempting to start another guest daemon.

Final successful-checker run work/luks-vm-z2wazwcb/report.json also passed,
exit0,20.42s, with both new bypass/rejection markers and all prior markers.
No full Python-suite rerun was performed for this guest-only scenario addition.
