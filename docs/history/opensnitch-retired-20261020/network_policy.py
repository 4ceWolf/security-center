"""Read-only pinned native app-firewall configuration and saved functional evidence."""
import json
from usb_policy import read,sha

CONFIG='/etc/opensnitchd/default-config.json'
SYSTEM='/etc/opensnitchd/system-fw.json'
OVERRIDE='/etc/systemd/system/opensnitchd.service.d/20-security-center.conf'
PROOF='/var/lib/security-center-opensnitch-state/verification.json'
EXPECTED={CONFIG:'d61ba4cafabda1cc3c5a5b0782bbcca1511bb275796f493601d848ec5a719c15',
          SYSTEM:'1dea5767bc86f39270cb47d9daaae693d3e8fdefc6cfe283b94cdf22e3c99f08',
          OVERRIDE:sha(b'[Service]\nExecStart=\nExecStart=/usr/bin/opensnitchd\n')}


def verify():
    hashes={path:sha(read(path)) for path in EXPECTED}
    evidence=json.loads(read(PROOF))
    if not isinstance(evidence,dict):raise ValueError('Invalid saved native test')
    passed=(evidence.get('schema_version')==1 and evidence.get('functional_test_passed') is True
            and evidence.get('scoped_test_program_blocked') is True and evidence.get('connectivity_recovered') is True
            and evidence.get('original_firewall_preserved') is True
            and evidence.get('configuration_sha256')=={path:EXPECTED[path] for path in (CONFIG,SYSTEM)}
            and evidence.get('override_sha256')==EXPECTED[OVERRIDE])
    return {'configuration_verified':hashes==EXPECTED,'saved_functional_test_passed':passed,
            'test_at_unix':evidence.get('test_at_unix'),'configuration_sha256':hashes,
            'expected_configuration_sha256':EXPECTED,'default_action':'allow',
            'unknown_applications_blocked':False,
            'note':'Saved scoped test plus current configuration hashes; not a continuous per-rule enforcement test.'}
