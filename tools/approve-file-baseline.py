#!/usr/bin/python3
"""Run only after owner approval of the exact candidate digest. No web action."""
import argparse, datetime, fcntl, hashlib, json, os, pathlib, sys, tempfile
sys.path.insert(0, '/usr/local/lib/security-center')
import integrity
parser = argparse.ArgumentParser()
parser.add_argument('--approved-candidate-sha256', required=True)
parser.add_argument('--approved-previous-baseline-sha256')
args = parser.parse_args()
digest = args.approved_candidate_sha256
if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
    raise SystemExit('Expected exact reviewed SHA256')
if os.geteuid() != 0:
    raise SystemExit('Administrator authentication required')
os.umask(0o077)
folder = pathlib.Path('/var/lib/security-center-monitor/baseline-review')
with os.fdopen(integrity.open_fixed(str(folder/(digest+'.json'))), 'rb') as stream:
    info = os.fstat(stream.fileno())
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise SystemExit('Candidate permissions invalid')
    raw = stream.read(65537)
if len(raw)>65536 or hashlib.sha256(raw).hexdigest() != digest:
    raise SystemExit('Candidate differs from reviewed digest')
data=json.loads(raw)
if data.get('schema_version') != 1 or data.get('approved') is not False:
    raise SystemExit('Invalid candidate schema')
previous_digest=args.approved_previous_baseline_sha256
if data.get('replaces_baseline_sha256') != previous_digest:
    raise SystemExit('Replacement requires approval of the exact previous baseline')
if previous_digest is not None and (len(previous_digest)!=64 or any(c not in '0123456789abcdef' for c in previous_digest)):
    raise SystemExit('Invalid previous baseline digest')
# Serialize cooperating baseline approvals; root tampering remains outside this trust model.
lock=os.open(str(pathlib.Path(integrity.BASELINE).parent/'.baseline-approval.lock'),
             os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
fcntl.flock(lock,fcntl.LOCK_EX)
current=integrity.scan()
if any(value['state']!='present' for value in current.values()) or current != data.get('files'):
    raise SystemExit('Files changed since review; prepare and review a new candidate')
data.update(approved=True, approved_candidate_sha256=digest,
            approved_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
path=pathlib.Path(integrity.BASELINE)
fd,temp=tempfile.mkstemp(prefix='.baseline-', dir=path.parent)
try:
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,sort_keys=True,indent=2)
        stream.flush();os.fsync(stream.fileno())
    if previous_digest is None:
        # First approval never replaces an existing reference.
        os.link(temp,path)
    else:
        with os.fdopen(integrity.open_fixed(str(path)), 'rb') as stream:
            prior=stream.read(65537)
        if len(prior)>65536 or hashlib.sha256(prior).hexdigest()!=previous_digest:
            raise SystemExit('Previous baseline changed since review')
        previous=json.loads(prior)
        if previous.get('schema_version')!=1 or previous.get('approved') is not True or not isinstance(previous.get('files'),dict) or not set(previous['files']).issubset(data['files']):
            raise SystemExit('Previous baseline invalid or scope removed')
        archive=path.parent/('integrity-baseline-'+previous_digest+'.json')
        try:os.link(path,archive)
        except FileExistsError:
            if archive.read_bytes()!=prior:raise SystemExit('Archived baseline differs')
        os.replace(temp,path)

    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
finally:
    if os.path.exists(temp):os.unlink(temp)
    os.close(lock)
print('Exact reviewed candidate approved. Existing protections unchanged.')
