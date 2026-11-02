#!/usr/bin/python3
"""Prepare a private candidate only; explicit approval is a separate operation."""
import argparse, datetime, hashlib, json, os, pathlib, sys
sys.path.insert(0, '/usr/local/lib/security-center')
import integrity
if os.geteuid() != 0:
    raise SystemExit('Administrator authentication required')
parser=argparse.ArgumentParser()
parser.add_argument('--replacement', action='store_true')
args=parser.parse_args()
os.umask(0o077)
project = pathlib.Path('/home/user/Projects/security-center')
record = json.loads((project/'backups/mvp-install.json').read_text())
expected = {item['path']: item['sha256'] for item in record['files']}
promotion = json.loads(pathlib.Path('/var/lib/security-center/integrity-candidate-20261014-235319/promotion/result.json').read_text())
expected[promotion['cmdline']] = promotion['cmdline_sha256']
files = integrity.scan()
if any(value['state'] != 'present' for value in files.values()):
    raise SystemExit('Candidate refused: one or more files unreadable')
evidence = {}
for name, item in files.items():
    if name in expected:
        if item['sha256'] != expected[name]:
            raise SystemExit('Candidate refused: prior hash mismatch at '+name)
        evidence[name] = 'Matches previous installation or boot-promotion record'
    else:
        evidence[name] = 'Current observation only; no independent prior hash in selected records'
previous_path=pathlib.Path(integrity.BASELINE)
previous_digest=None
changed_paths=[]
if previous_path.exists():
    if not args.replacement:
        raise SystemExit('An approved baseline already exists; review before replacing')
    previous=integrity.load_baseline()
    previous_digest=hashlib.sha256(previous_path.read_bytes()).hexdigest()
    changes,unavailable=integrity.compare(files,previous)
    if unavailable:raise SystemExit('Unreadable files prevent replacement review')
    changed_paths=[item['path'] for item in changes]
elif args.replacement:
    raise SystemExit('No existing baseline to replace')
when = datetime.datetime.now(datetime.timezone.utc).isoformat()
candidate = {'schema_version':1, 'approved':False, 'generated_at':when, 'files':files}
if previous_digest:
    candidate['replaces_baseline_sha256']=previous_digest
raw = (json.dumps(candidate, sort_keys=True, indent=2)+'\n').encode()
digest = hashlib.sha256(raw).hexdigest()
folder = pathlib.Path('/var/lib/security-center-monitor/baseline-review')
folder.mkdir(mode=0o700, exist_ok=True)
path = folder/(digest+'.json')
with path.open('xb') as out:
    out.write(raw); out.flush(); os.fsync(out.fileno())
report = {'candidate_sha256':digest,'candidate_path':str(path), 'approved':False,
          'files':len(files),'evidence':evidence,
          'replaces_baseline_sha256':previous_digest,'changed_paths':changed_paths,
          'limitations':'Hash matches establish continuity with local records, not malware-free or root-compromise-resistant trust.'}
(folder/(digest+'.review.json')).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
