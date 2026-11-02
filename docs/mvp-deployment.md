# Read-only MVP deployment
Arch package: cockpit (standard repository), only required dependencies. No optional PCP, storage, machines or PackageKit add-ons requested.

Source: ~/Projects/security-center. Installed root-owned code: /usr/local/lib/security-center. Cockpit extension: /usr/local/share/cockpit/security_center. Unit: /etc/systemd/system/security-center.service. Cockpit socket drop-in: /etc/systemd/system/cockpit.socket.d/security-center-local.conf. Listener: 127.0.0.1:9090 only. No firewall exception.

The custom page uses an unprivileged Cockpit process to run the fixed client, which can only request a sanitized cached snapshot. Socket and runtime directory restrict access to root/wheel. Existing Cockpit administrative features remain governed by Cockpit authentication/polkit; this extension does not grant privilege escalation or expose mutation actions.

No frontend strings are interpreted as root commands. Each collector has bounded subprocess timeouts and fixed arguments. Raw journal messages, LUKS tokens, key material and process arguments are not returned. Root installation is a copy, never a symlink into the user-writable project.

Installation record: backups/mvp-install.json (root-only). Rollback: stop and disable security-center.service and cockpit.socket, remove only the recorded new files after verifying their hashes, daemon-reload. Existing firewall and encryption remain independent. Remove newly installed packages only after checking later dependencies; do not blindly autoremove.
