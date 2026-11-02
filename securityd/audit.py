"""Bounded, read-only configuration assessment; no automatic remediation."""
import pathlib
import stat

SYSCTLS = (
    ('kernel.dmesg_restrict', {1}, 'Restricts kernel log access',
     'Review diagnostic needs before enabling kernel.dmesg_restrict=1.'),
    ('kernel.kptr_restrict', {1, 2}, 'Restricts exposure of kernel pointers through %pK',
     'Review debugging needs before choosing kernel.kptr_restrict=1 or 2.'),
    ('fs.protected_hardlinks', {1}, 'Restricts hardlinks to files owned by other users',
     'Review compatibility before enabling fs.protected_hardlinks=1.'),
    ('fs.protected_symlinks', {1}, 'Restricts following symlinks in sticky world-writable directories',
     'Review compatibility before enabling fs.protected_symlinks=1.'),
)
PATHS = (
    '/etc/miku-boot/zen.cmdline', '/etc/miku-boot/zen.conf',
    '/etc/miku-boot/zen-uki.conf', '/etc/mkinitcpio.d/linux-zen.preset',
    '/etc/systemd/system/security-center.service',
    '/usr/local/lib/security-center/daemon.py',
    '/usr/local/lib/security-center/collector.py',
    '/usr/local/share/cockpit/security_center/app.js',
)


def assess_sysctl(name, accepted, explanation, remediation):
    row = dict(id=name, explanation=explanation, remediation=remediation)
    try:
        value = int(pathlib.Path('/proc/sys', name.replace('.', '/')).read_text().strip())
        row.update(status='secure' if value in accepted else 'attention', evidence={'value': value})
    except (OSError, ValueError):
        row.update(status='unavailable', evidence={'reason': 'Value unreadable or invalid'})
    return row


def assess_path(path):
    row = dict(id=path, explanation='Checks ownership and write permissions of this file and its parent directories.',
               remediation='Review ownership and group/other write access; do not change permissions blindly.')
    evidence = []
    try:
        p = pathlib.Path(path)
        for entry in (p, *p.parents):
            info = entry.lstat()
            # A symlink needs target/ancestor assessment; never report it as checked.
            if stat.S_ISLNK(info.st_mode):
                row.update(status='unknown', evidence={'reason': 'Symlink requires target review', 'path': str(entry)})
                return row
            expected_type = stat.S_ISREG(info.st_mode) if entry == p else stat.S_ISDIR(info.st_mode)
            evidence.append({'path': str(entry), 'uid': info.st_uid, 'gid': info.st_gid,
                             'mode': oct(stat.S_IMODE(info.st_mode)),
                             'needs_review': info.st_uid != 0 or bool(info.st_mode & 0o022) or not expected_type})
        row.update(status='attention' if any(e['needs_review'] for e in evidence) else 'secure', evidence=evidence)
    except OSError:
        row.update(status='unavailable', evidence={'reason': 'Path missing or metadata inaccessible'})
    return row


def configuration():
    checks = [assess_sysctl(*spec) for spec in SYSCTLS] + [assess_path(p) for p in PATHS]
    attention = sum(c['status'] == 'attention' for c in checks)
    unverified = sum(c['status'] in ('unavailable', 'unknown') for c in checks)
    status = 'attention' if attention else 'unknown' if unverified else 'secure'
    return {'status': status,
            'summary': f'{attention} configuration findings; {unverified} checks unverified',
            'details': {'checks': checks, 'automatic_remediation': False,
                        'scope': 'Four runtime sysctls and eight fixed security files plus parent directory metadata. No file contents read.',
                        'limitations': 'Not a full host audit, ACL assessment, file-integrity baseline, or persistent sysctl verification.'}}
