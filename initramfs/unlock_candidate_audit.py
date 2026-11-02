"""Conservative generated-unit snapshot check, not whole-image attestation.

Caller must collect every generated unit and ordered drop-in from the candidate.
Helper hashes, runtime overrides, other executables and legacy images require
separate review. Never use this function as a runtime TPM authorization predicate.
"""
import re
import shlex

UNIT_KEYS = {'Description', 'Documentation', 'SourcePath', 'DefaultDependencies',
             'After', 'Before', 'Wants', 'Requires', 'BindsTo', 'Conflicts', 'IgnoreOnIsolate'}
SERVICE_KEYS = {'Type', 'RemainAfterExit', 'TimeoutSec', 'TimeoutStartSec', 'TimeoutStopSec',
                'KeyringMode', 'OOMScoreAdjust', 'ImportCredential', 'ExecStart', 'ExecStop',
                'StandardInput','StandardOutput','StandardError','TTYPath','TTYReset'}


def entries(text, dropin=False):
    if not isinstance(text, str) or len(text.encode()) > 65536:
        raise ValueError('Unit text exceeds bound')
    section = None
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.endswith('\\'):
            raise ValueError('Unsupported line continuation')
        if line in ('[Unit]', '[Service]'):
            section = line[1:-1]
            continue
        if section is None or '=' not in line:
            raise ValueError('Unsupported unit syntax')
        key, value = (part.strip() for part in line.split('=', 1))
        allowed = UNIT_KEYS if section == 'Unit' else SERVICE_KEYS
        if key not in allowed or (dropin and section == 'Service' and key not in {'ExecStart', 'TimeoutStartSec', 'TimeoutStopSec','StandardInput','StandardOutput','StandardError','TTYPath','TTYReset'}):
            raise ValueError('Unreviewed unit directive')
        if section == 'Unit' and key in {'Wants', 'After', 'Requires', 'BindsTo', 'Conflicts', 'Before'}:
            # Dependency lists cannot be cleared with an empty assignment. Refuse
            # it rather than incorrectly hiding an earlier mandatory dependency.
            if not value or any(char in value for char in ('"', "'", '$')):
                raise ValueError('Unsupported dependency syntax')
            if '%' in value and not (not dropin and key in {'Before', 'Wants'}
                                      and value == 'blockdev@dev-mapper-%i.target'):
                raise ValueError('Unsupported dependency expansion')
        fixed={'StandardInput':'tty','StandardOutput':'tty','StandardError':'tty','TTYPath':'/dev/console','TTYReset':'yes'}
        if section == 'Service' and key in fixed and value != fixed[key]:
            raise ValueError('Unreviewed console redirection')
        if section == 'Service' and ('\\' in value or '$' in value or '%' in value):
            raise ValueError('Unsupported service expansion')
        out.append((section, key, value))
    return out


def argv(value):
    if not value or len(value) > 4096:
        raise ValueError('Invalid command size')
    try:
        return shlex.split(value)
    except ValueError:
        raise ValueError('Unsupported command quoting') from None


def audit(snapshot, expected_unit, mapping, root_sources, expected_options, gate_argv,
          checker='device-check.service'):
    try:
        if not isinstance(snapshot, dict) or len(snapshot) > 128 or set(snapshot) != {expected_unit}:
            raise ValueError('Unexpected or duplicate generated unlock service')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', mapping) or expected_unit != 'systemd-cryptsetup@'+mapping+'.service':
            raise ValueError('Invalid reviewed mapping')
        if (not isinstance(root_sources, (set, tuple, list)) or not 1 <= len(root_sources) <= 16
                or any(not isinstance(x, str) or not x.startswith('/dev/') or len(x) > 256 for x in root_sources)):
            raise ValueError('Invalid reviewed volume aliases')
        if not isinstance(gate_argv, list) or not gate_argv or any(not isinstance(x, str) for x in gate_argv):
            raise ValueError('Invalid reviewed gate command')
        item = snapshot[expected_unit]
        if not isinstance(item, dict) or set(item) != {'fragment', 'dropins'}:
            raise ValueError('Invalid unit snapshot')
        fragment = entries(item['fragment'])
        starts = [v for s,k,v in fragment if s == 'Service' and k == 'ExecStart']
        stops = [v for s,k,v in fragment if s == 'Service' and k == 'ExecStop']
        if len(starts) != 1 or len(stops) != 1:
            raise ValueError('Unexpected generated command count')
        command = argv(starts[0])
        if (len(command) != 6 or command[:3] != ['/usr/bin/systemd-cryptsetup', 'attach', mapping]
                or command[3] not in root_sources or command[4] not in ('', '-', 'none')
                or command[5] != expected_options):
            raise ValueError('Generated source, key argument or options differ')
        if argv(stops[0]) != ['/usr/bin/systemd-cryptsetup', 'detach', mapping]:
            raise ValueError('Unexpected detach command')
        if [v for s,k,v in fragment if (s,k)==('Service','Type')] != ['oneshot']:
            raise ValueError('Expected oneshot service')
        if [v for s,k,v in fragment if (s,k)==('Service','RemainAfterExit')] != ['yes']:
            raise ValueError('Expected retained mapping service')
        dropins = item['dropins']
        if not isinstance(dropins, list) or len(dropins) > 16:
            raise ValueError('Invalid ordered drop-ins')
        combined = list(fragment)
        names = []
        for drop in dropins:
            if (not isinstance(drop, dict) or set(drop) != {'name','text'}
                    or not isinstance(drop['name'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.conf', drop['name'])):
                raise ValueError('Invalid drop-in snapshot')
            names.append(drop['name'])
            combined.extend(entries(drop['text'], dropin=True))
        if names != sorted(set(names)):
            raise ValueError('Duplicate or unordered drop-ins')
        dependencies = {key: set() for key in ('Wants', 'After', 'Requires', 'BindsTo', 'Conflicts', 'Before')}
        for section, key, value in combined:
            if section == 'Unit' and key in dependencies:
                dependencies[key].update(value.replace('%i', mapping).split())
        effective = []
        for section, key, value in combined:
            if (section,key) == ('Service','ExecStart'):
                if not value:
                    effective.clear()
                else:
                    effective.append(argv(value))
        if effective != [gate_argv]:
            raise ValueError('Stock or additional start command remains')
        if any(checker in dependencies[key] for key in ('Requires', 'BindsTo', 'Conflicts', 'Before')):
            raise ValueError('Checker dependency could suppress manual recovery')
        if checker not in dependencies['Wants'] or checker not in dependencies['After']:
            raise ValueError('Missing checker completion ordering')
        return dict(accepted=True, snapshot_only=True, unit_count=1,
                    limitation='Generated-unit snapshot only; image/helper/runtime provenance not verified')
    except (ValueError, TypeError, KeyError) as error:
        return dict(accepted=False, snapshot_only=True, reason=str(error))
