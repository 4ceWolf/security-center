"""Read-only passive initrd inventory status, independent of unlock handover."""
import pathlib
import time
from boot_observation import consume


def configuration():
    details = {'device_enforcement': 'Not enabled', 'unlock_method': 'Unknown',
               'attested': False, 'can_authorize_actions': False,
               'saved_trust_candidates': 'Independent of the embedded image policy'}
    def result(status, summary, **extra):
        return dict(status=status, summary=summary, details=dict(details, **extra))
    try:
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        data = consume(boot)
    except FileNotFoundError:
        if not pathlib.Path('/etc/security-center-observation/source.sha256').is_file():
            return result('unknown', 'Initrd observer not installed', observation_state='not_installed')
        return result('unknown', 'Initrd observation unavailable', observation_state='unavailable')
    except (OSError, ValueError, TypeError, KeyError):
        return result('attention', 'Initrd observation unavailable: record rejected', observation_state='unavailable')
    return result('attention' if data['errors'] else 'unknown',
                  'Initrd observation incomplete' if data['errors'] else 'Initrd devices observed with limitations',
                  observation_state='incomplete' if data['errors'] else 'observed_with_limitations',
                  age_seconds=max(0, time.clock_gettime(time.CLOCK_BOOTTIME)-data['finished_boottime']),
                  counts=data['counts'], scanner_errors=data['errors'], limitations=data['limitations'],
                  embedded_policy_sha256=data['policy_sha256'], source_manifest_sha256=data['source_manifest_sha256'])
