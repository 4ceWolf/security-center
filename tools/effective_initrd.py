"""Conservative archive-root alias review; never extract, authorize or sign.

Only consume fresh parser output in original order. Do not replay a saved JSON
object: serialization with sorted keys can destroy the extraction order.
"""
import stat
import hashlib
from arch_initrd_manifest import inspect, MAX_ENTRIES

FIELDS = ('mode', 'uid', 'gid', 'size', 'sha256', 'mtime', 'symlink_target')
MAX_LINKS = 40
MAX_COMPONENTS = 4096


def semantic(item):
    return {key: item[key] for key in FIELDS if key in item}


def _resolve(name, entries, follow_final=False, require_parents=True):
    pending = name.split('/')
    resolved = []
    links = 0
    steps = 0
    while pending:
        steps += 1
        if steps > MAX_COMPONENTS:
            raise ValueError('Path resolution exceeds bound')
        component = pending.pop(0)
        if component in ('', '.'):
            continue
        if component == '..':
            if not resolved:
                raise ValueError('Symlink escapes archive root')
            resolved.pop()
            continue
        key = '/'.join(resolved + [component])
        item = entries.get(key)
        traversed = bool(pending) or follow_final
        if item and stat.S_ISLNK(item['mode']) and traversed:
            links += 1
            if links > MAX_LINKS:
                raise ValueError('Cyclic or excessive symlink chain')
            target = item['symlink_target']
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
            if len(pending) > MAX_COMPONENTS:
                raise ValueError('Symlink expansion exceeds bound')
            continue
        if pending and require_parents:
            if item is None or not stat.S_ISDIR(item['mode']):
                raise ValueError('Missing or non-directory parent: ' + key)
        resolved.append(component)
    return '/'.join(resolved) or '.'


def _replay(manifest, directory_transitions=()):
    """Internal: manifest comes directly from inspect(), never caller JSON."""
    entries = {'.': {'mode': stat.S_IFDIR | 0o755, 'uid': 0, 'gid': 0}}
    explicit_root = False
    records = []
    transitions = iter(directory_transitions)
    expected = next(transitions, None)
    applied = []
    for segment_index, segment in enumerate(manifest['segments']):
        for name, item in segment['files'].items():
            if len(records) >= MAX_ENTRIES:
                raise ValueError('Combined member count exceeds bound')
            path = _resolve(name, entries)
            if path == '.' and not stat.S_ISDIR(item['mode']):
                raise ValueError('Archive root must remain a directory')
            previous = entries.get(path)
            if path == '.' and not explicit_root:
                previous = None
                explicit_root = True
            if previous is not None and semantic(previous) != semantic(item):
                transition = {'path': path, 'segment': segment_index,
                              'before': semantic(previous), 'after': semantic(item)}
                # Deliberately narrow: empty directory 0700 -> 0755 only.
                # All other metadata must agree, including ownership and mtime.
                before, after = semantic(previous), semantic(item)
                permitted = (previous['mode'] == stat.S_IFDIR | 0o700
                             and item['mode'] == stat.S_IFDIR | 0o755
                             and previous['size'] == item['size'] == 0
                             and {k: v for k, v in before.items() if k != 'mode'}
                             == {k: v for k, v in after.items() if k != 'mode'})
                if not permitted or transition != expected:
                    raise ValueError('Conflicting repeated effective path: ' + path)
                applied.append(transition)
                expected = next(transitions, None)
            entries[path] = item
            records.append({'segment': segment_index, 'order': len(records),
                            'name': name, 'raw_name': item['raw_name'],
                            'effective_path': path, 'repeated': previous is not None,
                            'metadata': semantic(item)})
    if expected is not None:
        raise ValueError('Unused directory transition authorization')
    for name, item in entries.items():
        if stat.S_ISLNK(item['mode']):
            _resolve(name, entries, follow_final=True, require_parents=False)
    if not explicit_root:
        del entries['.']
    return {'schema_version': 1, 'approved': False,
            'image_sha256': manifest['image_sha256'],
            'segments': [{key: value for key, value in segment.items() if key != 'files'}
                         for segment in manifest['segments']],
            'records': records,
            'reviewed_directory_transitions': applied,
            'effective': {name: semantic(item) for name, item in entries.items()}}


def review(raw):
    return _replay(inspect(raw))


def review_with_directory_policy(raw, policy):
    """Offline review only. Caller supplies a separately reviewed exact-image ledger.

    This is not a signature/trust mechanism and never approves a boot image.
    Default review/compare remain strict; no automatic exception discovery.
    """
    if (not isinstance(policy, dict)
            or set(policy) != {'schema_version', 'image_sha256', 'transitions'}
            or policy['schema_version'] != 1
            or not isinstance(policy['transitions'], list)
            or len(policy['transitions']) > MAX_ENTRIES):
        raise ValueError('Invalid directory transition policy')
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != policy['image_sha256']:
        raise ValueError('Directory transition policy image mismatch')
    for item in policy['transitions']:
        if (not isinstance(item, dict)
                or set(item) != {'path', 'segment', 'before', 'after'}
                or not isinstance(item['path'], str)
                or type(item['segment']) is not int
                or not isinstance(item['before'], dict)
                or not isinstance(item['after'], dict)):
            raise ValueError('Invalid directory transition entry')
    return _replay(inspect(raw), policy['transitions'])


def compare(before_raw, after_raw):
    before, after = review(before_raw), review(after_raw)
    left, right = before['effective'], after['effective']
    return {'schema_version': 1, 'approved': False,
            'before_sha256': before['image_sha256'], 'after_sha256': after['image_sha256'],
            'added': sorted(right.keys() - left.keys()),
            'removed': sorted(left.keys() - right.keys()),
            'changed': [{'path': key, 'before': left[key], 'after': right[key]}
                        for key in sorted(left.keys() & right.keys()) if left[key] != right[key]],
            'byte_identical': before_raw == after_raw}
