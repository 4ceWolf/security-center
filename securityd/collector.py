"""Fixed, read-only host collectors. Never return TPM blobs or shell history."""
import concurrent.futures
import datetime
import json
import pathlib
import subprocess
from adapters import ADAPTERS
from handover import consume as consume_handover
from confinement import configuration as confinement_configuration
from audit import configuration
from integrity import configuration as file_integrity
from telemetry_health import configuration as telemetry_configuration
from boot_observation_status import configuration as boot_observation_configuration


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(args, timeout=8):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
    if proc.returncode:
        raise RuntimeError('Command unavailable or access denied: ' + args[0])
    return proc.stdout


def result(status, summary, **details):
    return {'status': status, 'summary': summary, 'details': details}


def secureboot():
    matches = list(pathlib.Path('/sys/firmware/efi/efivars').glob('SecureBoot-*'))
    if not matches:
        return result('unknown', 'Secure Boot state unavailable')
    data = matches[0].read_bytes()
    if len(data) < 5:
        raise ValueError('Invalid EFI variable')
    enabled = data[4] == 1
    return result('secure' if enabled else 'action_required',
                  'Secure Boot enabled' if enabled else 'Secure Boot disabled',
                  source='UEFI SecureBoot variable', measured_chain_verified=False)


def lockdown():
    value = pathlib.Path('/sys/kernel/security/lockdown').read_text().strip()
    mode = value.split('[')[1].split(']')[0]
    cmdline = pathlib.Path('/proc/cmdline').read_text()
    return result('secure' if mode in ('integrity', 'confidentiality') else 'attention',
                  'Kernel lockdown: ' + mode, mode=mode,
                  boot_parameter_present='lockdown=' in cmdline,
                  persistence='Boot parameter present' if 'lockdown=' in cmdline else 'Not established; current activation may be temporary')


def tpm():
    devices = [p.name for p in pathlib.Path('/sys/class/tpm').glob('tpm[0-9]*')]
    return result('unknown' if devices else 'attention',
                  'TPM detected; unseal not tested' if devices else 'No TPM detected',
                  devices=devices, usable='Not tested', unlock_method='Unknown')


def extract_luks(data):
    slots = data.get('keyslots', {})
    tokens = []
    for token in data.get('tokens', {}).values():
        if token.get('type') != 'systemd-tpm2':
            continue
        def field(*names):
            return next((token[n] for n in names if n in token), None)
        tokens.append({'keyslots': token.get('keyslots', []),
                       'direct_pcrs': field('tpm2-pcrs', 'tpm2-hash-pcrs'),
                       'signed_pcrs': field('tpm2_pubkey_pcrs', 'tpm2-pubkey-pcrs'),
                       'policy_reference': field('tpm2_pubkey_ref', 'tpm2-pubkey-ref'),
                       'pcr_bank': token.get('tpm2-pcr-bank'),
                       'srk_present': bool(field('tpm2_srk', 'tpm2-srk'))})
    return {'slots': list(slots), 'manual_slot_0_present': '0' in slots,
            'manual_passphrase_tested': False, 'tokens': tokens,
            'unlock_method': 'Unknown; token configuration is not unlock evidence'}


def luks():
    data = json.loads(run(['/usr/bin/cryptsetup', 'luksDump', '--dump-json-metadata', '/dev/nvme0n1p2']))
    details = extract_luks(data)
    active = any((p/'dm/name').read_text().strip() == 'root'
                 and (p/'dm/uuid').read_text().startswith('CRYPT-LUKS2-')
                 and (p/'slaves/nvme0n1p2').exists()
                 for p in pathlib.Path('/sys/block').glob('dm-*'))
    good = details['manual_slot_0_present'] and active
    return result('secure' if good else 'action_required',
                  'Encrypted root active; recovery slot present' if good else 'Review encrypted root or recovery slot', **details)


def firewall():
    data = json.loads(run(['/usr/bin/nft', '-j', 'list', 'ruleset']))
    chains = [v['chain'] for v in data.get('nftables', []) if 'chain' in v]
    evidence = [{k: c.get(k) for k in ('family', 'table', 'name', 'hook', 'policy')} for c in chains if c.get('hook')]
    guarded = any(c.get('family') == 'inet' and c.get('hook') == 'input' and c.get('policy') == 'drop' for c in chains)
    return result('secure' if guarded else 'attention',
                  'Default-drop inbound policy loaded' if guarded else 'Review inbound firewall policy',
                  chains=evidence, note='Policy presence does not validate every exception or external reachability')


def apparmor():
    return confinement_configuration()


def services():
    failed = run(['/usr/bin/systemctl', '--failed', '--no-legend', '--plain', '--no-pager']).splitlines()
    return result('attention' if failed else 'secure',
                  str(len(failed)) + ' failed system units',
                  units=[line.split()[0] for line in failed if line.split()])


HANDOVER_DIRECTORY='/run/security-center-boot'


def preboot():
    # Fixed /run ancestry; no caller-supplied path. Root forgery remains possible.
    details={'boot_trust':'Not attested','can_authorize_actions':False,
             'distress':'Not deployed','record_current_boot':False}
    try:
        boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        record=consume_handover(HANDOVER_DIRECTORY,boot_id)
    except FileNotFoundError:
        return result('unknown','No preboot observation record available',**details)
    except (PermissionError,OSError):
        return result('unavailable','Preboot observation cannot be read safely',**details)
    except (ValueError,TypeError,KeyError):
        return result('attention','Preboot observation rejected: invalid, stale or contradictory',**details)
    details.update(record_current_boot=True,reported_unlock_method=record['unlock']['method'],
                   reported_attempts=record['unlock']['attempts'],device_decision=record['device_decision'],
                   observed_boottime=record['observed_boottime'],producer=record['producer'],
                   note='Root-private observation only. A privileged process can forge this file; it cannot authorize unlock, restoration or verified-boot claims.')
    if not record['unlock']['unlocked']:
        return result('attention','Preboot record reports an unsuccessful unlock',**details)
    summary='Manual recovery unlock reported' if record['unlock']['method']=='manual' else 'TPM unlock reported'
    return result('unknown',summary+'; provenance not attested',**details)


COLLECTORS = {'secureboot': ('Secure Boot', secureboot), 'lockdown': ('Kernel protection', lockdown),
              'tpm': ('TPM', tpm), 'luks': ('Disk encryption', luks),
              'firewall': ('Firewall', firewall), 'apparmor': ('Application confinement', apparmor),
              'services': ('System services', services)}
COLLECTORS.update(ADAPTERS)
COLLECTORS['audit'] = ('Configuration audit', configuration)
COLLECTORS['integrity'] = ('File integrity', file_integrity)
# Custom preboot observation/gating removed from scope; historical readers retained.
COLLECTORS['telemetry'] = ('Laptop diagnostics', telemetry_configuration)


def collect_one(identifier, name, callback):
    try:
        item = callback()
    except Exception as exc:
        item = result('unavailable', 'Check unavailable', error_type=type(exc).__name__)
    item.update(id=identifier, name=name, last_check=now(), actions=[])
    return item


JOURNAL_LIMIT = 256
JOURNAL_FIELDS = '__CURSOR,MESSAGE,UNIT,_PID,_UID,_COMM,_BOOT_ID,__REALTIME_TIMESTAMP'
JOURNAL_UNITS = ('systemd-cryptsetup@root.service', 'machine-care-firewall.service', 'security-center.service')


def journal_rows(options, filtered=True):
    args = ['/usr/bin/journalctl', '--system', '-o', 'json', '--no-pager',
            '--output-fields=' + JOURNAL_FIELDS, *options]
    if filtered:
        args += ['_PID=1', '_UID=0', '_COMM=systemd']
        args += ['UNIT=' + unit for unit in JOURNAL_UNITS]
    output = run(args)
    if len(output) > 2 * 1024 * 1024:
        raise ValueError('Journal batch exceeds limit')
    rows = [json.loads(line) for line in output.splitlines() if line.strip()]
    if len(rows) > JOURNAL_LIMIT or any(not isinstance(row, dict) for row in rows):
        raise ValueError('Invalid journal batch')
    return rows


def journal_batch(cursor=None):
    # Check exact presence: journalctl may seek to a nearby entry after rotation.
    gap = False
    if cursor is not None:
        if not isinstance(cursor, str) or not cursor or len(cursor) > 2048 or any(ord(c) < 32 for c in cursor):
            raise ValueError('Invalid saved cursor')
        anchor = journal_rows(['--cursor=' + cursor, '-n', '+1'], filtered=False)
        gap = not anchor or anchor[0].get('__CURSOR') != cursor
    options = ['-n', '+' + str(JOURNAL_LIMIT)]
    options += ['--after-cursor=' + cursor] if cursor and not gap else ['--since=-30days']
    rows = journal_rows(options)
    events = []
    for entry in rows:
        point = entry.get('__CURSOR')
        if not isinstance(point, str) or not point or len(point) > 2048 or any(ord(c) < 32 for c in point):
            raise ValueError('Invalid journal cursor')
        # UNIT/MESSAGE are client fields. Require journald's trusted PID/UID/COMM.
        if (entry.get('_PID'), entry.get('_UID'), entry.get('_COMM')) != ('1', '0', 'systemd'):
            continue
        unit, message = entry.get('UNIT'), entry.get('MESSAGE')
        if unit not in JOURNAL_UNITS or not isinstance(message, str):
            continue
        lifecycle = next((term for term in ('Started ', 'Finished ', 'Failed ', 'Stopped ') if message.startswith(term)), None)
        if lifecycle:
            events.append({'timestamp': int(entry['__REALTIME_TIMESTAMP']) / 1000000,
                           'boot_id': entry.get('_BOOT_ID'), 'source': unit,
                           'severity': 'attention' if lifecycle == 'Failed ' else 'info',
                           'summary': unit + ': ' + lifecycle.strip().lower()})
    return {'events': events, 'cursor': rows[-1]['__CURSOR'] if rows else (None if gap else cursor),
            'gap': gap, 'backlog': len(rows) == JOURNAL_LIMIT,
            'coverage': 'retained journal only; deletions between checks cannot always be detected'}


def timeline():
    return journal_batch()['events']


def snapshot(include_timeline=True):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(collect_one, i, n, fn) for i, (n, fn) in COLLECTORS.items()]
        modules = [f.result() for f in futures]
    try:
        events = timeline() if include_timeline else []
        event_status = 'available'
    except Exception:
        events, event_status = [], 'unavailable'
    states = {m['status'] for m in modules}
    overall = 'action_required' if 'action_required' in states else ('attention' if states - {'secure'} else 'secure')
    return {'schema_version': 1, 'generated_at': now(),
            'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'overall': overall, 'read_only': True, 'modules': modules,
            'events': events, 'event_status': event_status}


if __name__ == '__main__':
    print(json.dumps(snapshot()))
