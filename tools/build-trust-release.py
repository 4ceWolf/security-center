#!/usr/bin/python3
"""Capture a review-only device-management bundle. Never installs files."""
import ast
import hashlib
import json
import pathlib
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = {**{'policies/'+name:'/usr/local/lib/security-center/'+name for name in
            ('device_gate.py','device_inventory.py','trust_policy.py','trust_store.py')},
         'tools/device-trust-helper.py':'/usr/local/lib/security-center/device-trust-helper.py',
         'policies/normal-devices.candidate.json':'/etc/security-center/normal-devices.candidate.json'}


def build(root=ROOT):
    # Candidate UI is delivered separately by the existing monitor bundle.
    contents = {}
    for name in FILES:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Source escaped project')
        with path.open('rb') as stream: raw = stream.read(262145)
        if len(raw) > 262144: raise ValueError('Oversized source')
        contents[name] = raw
    local = {pathlib.Path(name).stem for name in contents if name.endswith('.py')}
    import sys
    for name, raw in contents.items():
        if not name.endswith('.py'): continue
        for node in ast.walk(ast.parse(raw)):
            imports = [entry.name.split('.')[0] for entry in node.names] if isinstance(node, ast.Import) else [(node.module or '').split('.')[0]] if isinstance(node, ast.ImportFrom) else []
            if isinstance(node, ast.ImportFrom) and node.level: raise ValueError('Unexpected relative import')
            if any(dependency not in local and dependency not in sys.stdlib_module_names for dependency in imports):
                raise ValueError('Unbundled helper dependency')
    # Check the envelope of the captured seed bytes that will be reviewed.
    # Avoid running project modules during packaging; JSON structure is checked
    # by runtime policy validation and the policy tests. Only syntax/dependencies
    # and exact captured bytes are established here.
    seed = json.loads(contents['policies/normal-devices.candidate.json'])
    if not isinstance(seed, dict) or seed.get('schema_version') != 1:
        raise ValueError('Unsupported candidate seed')
    parent = root / 'work/releases'; parent.mkdir(parents=True, exist_ok=True)
    folder = pathlib.Path(tempfile.mkdtemp(prefix='device-trust-', dir=parent))
    records = []
    for name, raw in contents.items():
        target = folder/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        records.append({'source':name, 'destination':FILES[name], 'sha256':hashlib.sha256(raw).hexdigest(), 'uid':0, 'gid':0, 'mode':0o644})
    manifest = {'schema_version':1, 'files':records, 'deployment_approved':False,
                'baseline_approved':False, 'enforcement':'not_deployed',
                'limitations':['Review bundle only; no privileged installation or Cockpit authentication tested.',
                               'Installer, protected-file allowlist and integrity baseline integration are pending.',
                               'Actor attribution records root execution, not an authenticated human identity.',
                               'Saved policies do not affect boot images or USBGuard.']}
    (folder/'release.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    return folder

if __name__ == '__main__':
    print(json.dumps({'release':str(build()),'files':len(FILES),'installed':False}))
