# Future ideas

## Repair TPM automatic unlock from Security Center

Deferred by the owner on 2026-10-20. Preserve the read-only review and staged preflight;
do not spend implementation or testing time on reenrollment until requested again.
Design and safety questions: automatic-unlock-recovery-design.md. This is not an
active project-completion requirement. In particular, preserve manual slot0 and the
existing signed initrd PCR policy; never silently broaden it to permit desktop repair.

## Optional OpenSnitch integration

Deferred and uninstalled at the owner's request on 2026-10-20. Networking is
owner-managed. Do not reinstall or continue this integration unless requested.
Historical implementation and test records are retained under docs/history and work.
The native scoped allow/deny/recovery test had passed after removing the redundant
CLI rules-path loader; v1.7.2 rule publication also needed a Write notification.
An on-demand GUI required substantial additional RAM and could remain in its tray.
Any future implementation needs a fresh design, resource review and explicit request.
