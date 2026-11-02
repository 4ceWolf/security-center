"""Bounded candidate-policy editing. No boot, USBGuard or filesystem operations."""
import copy
import hashlib
import json
import re
import time
from device_gate import identity, MAX_DEVICES

MAX_BYTES = 262144
HEX = re.compile(r'^[0-9a-f]{4}$')
PORT = re.compile(r'^pci:[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]/usb:[1-9][0-9]*(?:\.[1-9][0-9]*)*$')
INTERFACE = re.compile(r'^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def validate_device(value):
    key = identity(value)
    if any(any(ord(c) < 32 or ord(c) == 127 for c in value[k])
           for k in ('transport', 'vendor', 'product', 'serial', 'port')):
        raise ValueError('Control characters in identity')
    if value['transport'] == 'usb':
        if not HEX.fullmatch(value['vendor']) or not HEX.fullmatch(value['product']):
            raise ValueError('Invalid USB identifier')
        if not PORT.fullmatch(value['port']) or not all(INTERFACE.fullmatch(i) for i in value['interfaces']):
            raise ValueError('Invalid USB route or interface')
    return key


def validate(policy):
    if not isinstance(policy, dict) or set(policy) != {'schema_version', 'internal', 'trusted_external'}:
        raise ValueError('Invalid policy fields')
    if type(policy['schema_version']) is not int or policy['schema_version'] != 1:
        raise ValueError('Unsupported policy version')
    seen = set()
    for group in ('internal', 'trusted_external'):
        items = policy[group]
        if not isinstance(items, list) or len(items) > MAX_DEVICES:
            raise ValueError('Policy exceeds device limit')
        for item in items:
            key = validate_device(item)
            if key in seen:
                raise ValueError('Duplicate or conflicting device')
            seen.add(key)
    if len(canonical(policy)) > MAX_BYTES:
        raise ValueError('Policy exceeds byte limit')
    return copy.deepcopy(policy)


def decode(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Input exceeds byte limit')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def revision(policy):
    return hashlib.sha256(canonical(validate(policy))).hexdigest()


def device_id(device):
    validate_device(device)
    normalized = copy.deepcopy(device)
    normalized['interfaces'].sort()
    return hashlib.sha256(canonical(normalized)).hexdigest()


def observed(inventory):
    if not isinstance(inventory, dict) or inventory.get('usb_observation_complete') is not True or inventory.get('errors') != []:
        raise ValueError('USB observation unavailable')
    devices = inventory.get('devices')
    if not isinstance(devices, list) or len(devices) > MAX_DEVICES:
        raise ValueError('Invalid observation')
    result = {}
    for device in devices:
        validate_device(device)
        if device['transport'] != 'usb':
            continue
        key = device_id(device)
        if key in result:
            raise ValueError('Ambiguous device observation')
        result[key] = copy.deepcopy(device)
    return result


def propose(policy, inventory, action, selected):
    """Use a helper-observed device for additions, never browser-supplied identity."""
    policy = validate(policy)
    if action not in ('add', 'remove') or not isinstance(selected, str) or not re.fullmatch('[0-9a-f]{64}', selected):
        raise ValueError('Unsupported device operation')
    saved = {device_id(d): d for d in policy['trusted_external']}
    if action == 'add':
        devices = observed(inventory)
        if selected not in devices:
            raise ValueError('Device disconnected or changed')
        device = devices[selected]
        if selected in saved or any(device_id(d) == selected for d in policy['internal']):
            raise ValueError('Device already approved')
    else:
        if selected not in saved:
            raise ValueError('Saved device no longer exists')
        device = saved[selected]
    return {'schema_version': 1, 'action': action, 'base_revision': revision(policy),
            'device_id': selected, 'device': copy.deepcopy(device)}


def apply(policy, inventory, proposal):
    policy = validate(policy)
    if not isinstance(proposal, dict) or set(proposal) != {'schema_version', 'action', 'base_revision', 'device_id', 'device'}:
        raise ValueError('Invalid proposal')
    expected = propose(policy, inventory, proposal['action'], proposal['device_id'])
    if canonical(proposal) != canonical(expected):
        raise ValueError('Policy or device changed since review')
    result = copy.deepcopy(policy)
    if proposal['action'] == 'add':
        result['trusted_external'].append(expected['device'])
    else:
        result['trusted_external'] = [d for d in result['trusted_external'] if device_id(d) != proposal['device_id']]
    return validate(result)


def view(policy, inventory):
    policy = validate(policy)
    try:
        connected = observed(inventory)
        observation = 'available'
    except ValueError:
        connected = {}
        observation = 'unavailable'
    trusted = {device_id(d): d for d in policy['trusted_external']}
    internal = {device_id(d) for d in policy['internal']}
    return {'schema_version': 1, 'revision': revision(policy), 'observation_status': observation,
            'observed_at': int(time.time()) if observation == 'available' else None,
            'activation': {'preboot': 'outside_scope', 'postboot': 'not_managed_by_candidate_editor'},
            'connected': [{'id': k, 'device': d, 'saved': k in trusted, 'internal': k in internal} for k, d in connected.items()],
            'saved': [{'id': k, 'device': d, 'connected': (k in connected if observation == 'available' else None)} for k, d in trusted.items()]}
