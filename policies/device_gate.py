"""Offline policy evaluator only. No device discovery, TPM calls or boot hooks."""
MAX_DEVICES = 128
FIELDS = {'transport', 'vendor', 'product', 'serial', 'port', 'interfaces'}
TRANSPORTS = {'usb', 'thunderbolt', 'pci-external'}


def identity(item):
    if not isinstance(item, dict) or set(item) != FIELDS:
        raise ValueError('Device identity fields incomplete')
    if any(not isinstance(item[k], str) or len(item[k]) > 256 for k in FIELDS - {'interfaces'}):
        raise ValueError('Invalid identity text')
    if item['transport'] not in TRANSPORTS or not all(item[k] for k in ('vendor','product','port')):
        raise ValueError('Unsupported transport or missing identity')
    interfaces = item['interfaces']
    if not isinstance(interfaces, list) or not interfaces or len(interfaces) > 32:
        raise ValueError('Missing interface inventory')
    if any(not isinstance(i,str) or not i or len(i)>64 for i in interfaces):
        raise ValueError('Invalid interface inventory')
    # Distinct USB interfaces can legitimately have identical class triples.
    # Sorting preserves multiplicity; adding/removing one still changes identity.
    return tuple(item[k] for k in ('transport','vendor','product','serial','port')) + (tuple(sorted(interfaces)),)


def evaluate(inventory, policy, mode='normal'):
    """Input completeness is a collector claim, not established by this evaluator."""
    deny = {'allow_tpm_attempt': False, 'manual_recovery_required': True}
    try:
        if mode not in ('normal','distress'):
            raise ValueError('Unknown mode')
        if set(inventory) != {'schema_version','complete','transports_checked','devices'}:
            raise ValueError('Invalid inventory schema')
        if inventory['schema_version'] != 1 or inventory['complete'] is not True:
            raise ValueError('Incomplete inventory')
        if not isinstance(inventory['transports_checked'],list) or set(inventory['transports_checked']) != TRANSPORTS:
            raise ValueError('Transport coverage incomplete')
        if set(policy) != {'schema_version','internal','trusted_external'} or policy['schema_version'] != 1:
            raise ValueError('Invalid policy schema')
        collections = [inventory['devices'],policy['internal'],policy['trusted_external']]
        if any(not isinstance(c,list) or len(c)>MAX_DEVICES for c in collections):
            raise ValueError('Inventory or policy exceeds limit')
        devices, internal, trusted = [list(map(identity,c)) for c in collections]
        if any(len(set(c)) != len(c) for c in (devices,internal,trusted)) or set(internal) & set(trusted):
            raise ValueError('Duplicate or conflicting identities')
        # Even legitimate trusted external peripherals are forbidden in distress.
        allowed = set(internal) | (set(trusted) if mode=='normal' else set())
        rejected = [i for i,item in enumerate(devices) if item not in allowed]
        if rejected:
            return dict(deny,reason='Unapproved external-device state',rejected_indexes=rejected)
        if mode == 'distress':
            return dict(deny,reason='Distress requires manual unlock even with acceptable devices',recovery_device_state='acceptable')
        return {'allow_tpm_attempt': True, 'manual_recovery_required': False,
                'reason': 'All observed devices match the supplied policy'}
    except (ValueError,KeyError,TypeError):
        return dict(deny,reason='Invalid, incomplete or unsupported policy evidence')
