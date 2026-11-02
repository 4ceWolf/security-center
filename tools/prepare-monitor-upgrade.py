#!/usr/bin/python3
"""Read-only installed-state comparison and project-local upgrade review."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'securityd'))
from integrity import inspect, open_fixed
spec=importlib.util.spec_from_file_location('release_builder',ROOT/'tools/build-monitor-release.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)


def compare(manifest, observations, baseline=None):
    paths=manifest['fim_paths']
    if set(observations)!=set(paths):raise ValueError('Exact target-scope observations required')
    records=[]
    for item in manifest['files']:
        before=observations[item['destination']]
        state=before.get('state')
        if state=='missing':action='add'
        elif state=='present':
            action='unchanged' if before['sha256']==item['sha256'] and (before['uid'],before['gid'],before['mode'])==(0,0,0o644) else 'replace'
        else:action='unreadable'
        records.append(dict(source=item['source'],destination=item['destination'],action=action,
                            observed_before=before,proposed_sha256=item['sha256']))
    baseline_state='unavailable'
    drift=[];added=[]
    if baseline is not None:
        if baseline.get('schema_version')!=1 or baseline.get('approved') is not True or not isinstance(baseline.get('files'),dict):
            raise ValueError('Invalid approved baseline')
        old=baseline['files']
        if not set(old).issubset(paths):raise ValueError('Baseline scope would be removed')
        baseline_state='observed'
        drift=[p for p,value in old.items() if observations[p]!=value]
        added=sorted(set(paths)-set(old))
    return dict(schema=1,deployable=False,approval_granted=False,files=records,
                target_scope=paths,baseline_state=baseline_state,baseline_drift=drift,
                scope_additions=added if baseline is not None else None,
                unchanged_scope_files={p:observations[p] for p in paths if p not in {r['destination'] for r in records}},
                checkpoints=['Privileged exact prior-baseline continuity check',
                             'Reviewed release digest and coherent root-owned transaction backups',
                             'Service stop/install/reload/restart and read-only health checks',
                             'Explicit approval of exact replacement baseline; no automatic rebaseline',
                             'Separate telemetry activation after production identity/sandbox validation'],
                rollback='Restore protected backups for replaced files, remove only newly added unchanged files, restore prior service state and baseline. Refuse to overwrite later changes.')


def main():
    folder=release.build();manifest=release.verify(folder)
    observations={path:inspect(path) for path in manifest['fim_paths']}
    baseline=None;baseline_sha=None;baseline_error=None
    try:
        import os,stat
        fd=open_fixed('/var/lib/security-center-monitor/integrity-baseline.json')
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('Unsafe baseline')
            raw=stream.read(65537)
        if len(raw)>65536:raise ValueError('Oversized baseline')
        baseline=json.loads(raw);baseline_sha=hashlib.sha256(raw).hexdigest()
    except (OSError,ValueError) as error:
        baseline_error=type(error).__name__
    plan=compare(manifest,observations,baseline)
    plan.update(release=str(folder),release_sha256=hashlib.sha256((folder/'release.json').read_bytes()).hexdigest(),
                baseline_sha256=baseline_sha,baseline_read_error=baseline_error)
    parent=ROOT/'work/upgrades';parent.mkdir(exist_ok=True)
    target=Path(tempfile.mkdtemp(prefix='upgrade-',dir=parent))
    (target/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    lines=['# Monitor upgrade review','',
           'Review only: no files installed, services changed, or baseline approved.','',
           f'Release: `{folder.name}`',f'Release manifest SHA256: `{plan["release_sha256"]}`','',
           f'Target integrity scope: {len(manifest["fim_paths"])} files.',
           'Existing approved baseline: '+('read and compared' if baseline is not None else 'not readable without administrator access; continuity not verified')+'.','',
           '| Action | Installed path |','| --- | --- |']
    lines += [f'| {r["action"]} | `{r["destination"]}` |' for r in plan['files']]
    lines += ['', '## Required deployment checkpoints','']+['- '+s for s in plan['checkpoints']]
    lines += ['', '## Rollback','',plan['rollback'],'',
              'The JSON plan contains exact source hashes and observed installed metadata. It is user-owned review data, not privileged installation authority. The installer must repeat checks after acquiring its protected transaction lock. No boot configuration, TPM/LUKS enrollment or USB policy is deployed by this monitor release.']
    (target/'review.md').write_text('\n'.join(lines)+'\n')
    counts={action:sum(r['action']==action for r in plan['files']) for action in ('add','replace','unchanged','unreadable')}
    print(json.dumps(dict(review=str(target/'review.md'),release=str(folder),actions=counts,
                         baseline_state=plan['baseline_state'],target_scope=len(manifest['fim_paths'])),indent=2))


if __name__=='__main__':main()
