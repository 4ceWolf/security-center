# TPM disable control — exact baseline review, 2026-10-20

The requested disable button and root helper are installed. Automatic unlock is
still enabled; no disk passphrase, token removal or reboot was invoked.

Approval records the installed 38-file scope as the file-change reference, archives
the prior reference and clears expected code-change alerts. It does not disable
TPM unlock or approve any future disk changes.

Exact candidate SHA256:
fbffa043adc034bac274eac983fbdf929b007f81b6b67f9a0e81c31d9fb0cb8f

Prior approved reference:
1570242abaee6a65ce72adc914843ac0e0f74fc90938f8004d97e09e535f6997

Protected transaction: txn-b81a137903c71e6b512b0266fcac3e2c
Release manifest: 680ee30318c6fd33f6408818b8c62f85ec767c07f7e9d9c5f40728de71b4e2f1

Changed or newly added paths:
- /usr/local/lib/security-center/trust_policy.py
- /usr/local/lib/security-center/tpm-unlock-helper.py
- /usr/local/lib/security-center/integrity.py
- /usr/local/share/cockpit/security_center/index.html
- /usr/local/share/cockpit/security_center/app.js
- /usr/local/share/cockpit/security_center/unlock-controls.js

New scope entries are tpm-unlock-helper.py and unlock-controls.js. Remaining source
changes correct the trust-candidate/editor text and mark repair as a future idea.
The helper runs on demand and adds no daemon. See tpm-unlock-disable.md for safeguards
and test limits. No real token removal, native owner passphrase or reboot test was
performed. Native disposable-disk transaction tests passed with a synthetic TPM token.

Owner approved this exact candidate in chat. Published reference:
58eab555dda3f5b84f0192fa0f44a918c1a9f662a26f271819b83effa6a932db.
Final38-file direct scan0changes/0unreadable. No further approval pending.
