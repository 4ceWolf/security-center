"""Fixed native USBGuard policy review; no caller-supplied rules or paths."""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
from integrity import open_fixed

RULES='/etc/usbguard/rules.conf'
CONFIG='/etc/usbguard/usbguard-daemon.conf'
STATE=pathlib.Path('/var/lib/security-center-usb-policy')
INITIAL='544cb3ef7774b444206121e649cf956cdbf3d8094db984d5040ccca7c9fe4cff'
CONFIG_SHA='76ae7da93d8ac00521c7fd1387ce20f81c8942f7e6b335d53cef568ec59bbdae'
MAX=65536


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def normalize(line):
    # USBGuard's native serializer omits the default equality set operator.
    # Avoid modifying device-provided quoted strings.
    return re.sub(r'("(?:[^"\\]|\\.)*"|with-interface equals )',
                  lambda m:'with-interface ' if m[0]=='with-interface equals ' else m[0],line)


def parse(raw):
    if not isinstance(raw,str) or len(raw)>MAX:raise ValueError('Oversized native inventory')
    records=[];seen=set()
    for line in raw.splitlines():
        match=re.fullmatch(r'([0-9]{1,10}): (allow|block|reject)(?: (.*))?',line)
        if not match or len(line)>8192:raise ValueError('Unsupported native record')
        key=int(match[1])
        if key in seen or key>4294967295:raise ValueError('Invalid native ID')
        seen.add(key);rule=match[2]+(' '+match[3] if match[3] else '')
        records.append({'id':key,'rule':rule})
    if len(records)>256:raise ValueError('Too many records')
    return records


def attribute(rule,name):
    # Parse quoted fields using JSON string escaping, which covers native USBGuard
    # escaping of quotes/backslashes. Unknown escape syntax fails closed.
    parts=re.findall(r'"(?:[^"\\]|\\.)*"|[^\s{}]+|[{}]',rule)
    for i,item in enumerate(parts[:-1]):
        if item==name:
            value=parts[i+1]
            if not value.startswith('"'):raise ValueError('Unquoted identity field')
            return json.loads(value)
    raise ValueError('Identity field missing')


def external(rule):
    try:
        route=attribute(rule,'via-port')
        if not re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*(?:\.[1-9][0-9]*)*',route):return False
        try:
            if attribute(rule,'with-connect-type')=='hardwired':return False
        except ValueError:pass
        return bool(re.match(r'^(?:allow|block|reject) id [0-9a-f]{4}:[0-9a-f]{4} ',rule))
    except (ValueError,TypeError):return False


def has_keyboard(rule):
    unquoted=re.sub(r'"(?:[^"\\]|\\.)*"','',rule)
    interfaces=re.search(r'with-interface (?:equals )?(\{[^}]*\}|[0-9a-f:]+)',unquoted)
    return bool(interfaces and re.search(r'(?<![0-9a-f:])03:01:01(?![0-9a-f:])',interfaces[1]))


def selected(state,action,key):
    if action not in ('add','remove') or type(key) is not int:raise ValueError('Unsupported operation')
    pool=state['devices'] if action=='add' else state['rules']
    found=[item for item in pool if item['id']==key]
    if len(found)!=1 or not external(found[0]['rule']):raise ValueError('External device required')
    rule=found[0]['rule']
    if action=='remove':
        if not rule.startswith('allow '):raise ValueError('Only external allow rules may be removed')
    else:
        rule='allow '+rule.split(' ',1)[1]
        # Add only a full native device observation with descriptor and parent hash.
        for name in ('hash','parent-hash','serial','via-port'):attribute(rule,name)
        if ' with-interface ' not in rule:raise ValueError('Missing interfaces')
        if any(normalize(item['rule'])==normalize(rule) for item in state['rules']):raise ValueError('Already trusted')
    return rule


def propose(state,action,key,issued=None):
    if not state['rules'] or state['rules'][-1]['rule']!='block':raise ValueError('Final block rule required')
    rule=selected(state,action,key)
    after=[item['rule'] for item in state['rules']]
    if action=='add':after.insert(len(after)-1,rule)
    else:after=[item['rule'] for item in state['rules'] if item['id']!=key]
    return {'schema_version':1,'action':action,'selected_id':key,'rule':rule,
            'before_sha256':state['policy_sha256'],'after_rules':after,
            'state_sha256':sha(canonical(state)),
            'issued_at':int(time.time()) if issued is None else issued,
            'keyboard':has_keyboard(rule)}


def validate(review,state,now=None):
    if not isinstance(review,dict) or type(review.get('issued_at')) is not int:raise ValueError('Invalid review')
    now=int(time.time()) if now is None else now
    if not 0<=now-review['issued_at']<=120:raise ValueError('Review expired')
    expected=propose(state,review.get('action'),review.get('selected_id'),review['issued_at'])
    if canonical(expected)!=canonical(review):raise ValueError('Policy or device changed')


def read(path):
    fd=open_fixed(str(path))
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or info.st_size>MAX:
            raise PermissionError('Unsafe native policy state')
        raw=stream.read(MAX+1)
    if len(raw)>MAX:raise ValueError('Oversized policy')
    return raw


def command(args):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                          env={'PATH':'/usr/bin','LC_ALL':'C'},timeout=15)
    if result.returncode or len(result.stdout)>MAX:raise RuntimeError('Native operation failed')
    return result.stdout.decode('utf-8')


def reference():
    try:
        info=STATE.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise PermissionError('Unsafe reference directory')
        value=json.loads(read(STATE/'reference.json'))
        if value.get('phase')!='committed' or not re.fullmatch('[0-9a-f]{64}',value.get('policy_sha256','')):
            raise ValueError('Pending native change requires administrator recovery')
        return value['policy_sha256']
    except FileNotFoundError:
        if STATE.exists():raise ValueError('Missing reference requires recovery')
        return INITIAL


def check_integrity():
    expected=reference();actual=sha(read(RULES));config=sha(read(CONFIG))
    return {'policy_verified':actual==expected and config==CONFIG_SHA,'rules_sha256':actual,
            'expected_rules_sha256':expected,'configuration_sha256':config,
            'expected_configuration_sha256':CONFIG_SHA}


def capture():
    integrity=check_integrity()
    if not integrity['policy_verified']:raise ValueError('Unexpected native policy/configuration drift')
    if command(['/usr/bin/systemctl','is-active','usbguard.service']).strip()!='active':raise ValueError('USBGuard inactive')
    rules=parse(command(['/usr/bin/usbguard','list-rules']))
    devices=parse(command(['/usr/bin/usbguard','list-devices']))
    persistent=[normalize(line.strip()) for line in read(RULES).decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if persistent!=[normalize(item['rule']) for item in rules]:raise ValueError('Live and persistent rules differ')
    # Recapture policy/config after native IPC to reject concurrent privileged edits.
    if check_integrity()!=integrity:raise ValueError('Policy changed during capture')
    return {'policy_sha256':integrity['rules_sha256'],'rules':rules,'devices':devices,
            'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def atomic(name,value):
    fd,tmp=tempfile.mkstemp(prefix='.pending-',dir=STATE)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,STATE/name)
        fd=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def apply(review):
    """Caller holds the protected EXCLUSIVE update lock across this operation."""
    before=capture();validate(review,before)
    raw=read(RULES)
    if not STATE.exists():
        # Fixed parent must be root-owned and non-writable by other users.
        parent=os.open('/var/lib',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            info=os.fstat(parent)
            if info.st_uid!=0 or info.st_mode&0o022:raise PermissionError('Unsafe state parent')
            os.mkdir(STATE.name,0o700,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
    backup='before-'+review['before_sha256']+'.json'
    if not (STATE/backup).exists():atomic(backup,{'policy':raw.decode(),'policy_sha256':sha(raw)})
    # reference.json is durable mutation intent. Interrupted writes never bootstrap trust.
    atomic('reference.json',{'phase':'pending','proposal':review,'previous_sha256':sha(raw),'backup':backup})
    if review['action']=='add':
        previous=before['rules'][-2]['id'] if len(before['rules'])>1 else 0
        command(['/usr/bin/usbguard','append-rule','--after',str(previous),review['rule']])
    else:command(['/usr/bin/usbguard','remove-rule',str(review['selected_id'])])
    observed=parse(command(['/usr/bin/usbguard','list-rules']))
    current=read(RULES)
    expected=[normalize(line) for line in review['after_rules']]
    persistent=[normalize(line.strip()) for line in current.decode().splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if [normalize(item['rule']) for item in observed]!=expected or persistent!=expected or sha(read(CONFIG))!=CONFIG_SHA:
        raise RuntimeError('Native change needs administrator recovery')
    result={'phase':'committed','policy_sha256':sha(current),'previous_sha256':sha(raw),
            'action':review['action'],'rule':review['rule'],'committed_at':int(time.time()),
            'current_devices_changed':False,'reconnect_required':True}
    atomic('reference.json',result)
    atomic('change-'+str(time.time_ns())+'.json',result)
    events=sorted(STATE.glob('change-*.json'))
    for old in events[:-200]:old.unlink()
    # Bound retained recovery history to the latest 200 reviewed transitions.
    backups=sorted(STATE.glob('before-*.json'),key=lambda p:p.stat().st_mtime_ns)
    for old in backups[:-200]:old.unlink()
    return result


def view():
    state=capture()
    return {'schema_version':1,'policy_sha256':state['policy_sha256'],
            'connected_external':[dict(item,already_trusted=any(normalize(r['rule'])==normalize('allow '+item['rule'].split(' ',1)[1]) for r in state['rules'])) for item in state['devices'] if external(item['rule'])],
            'trusted_external':[item for item in state['rules'] if item['rule'].startswith('allow ') and external(item['rule'])],
            'current_devices_changed':False,'scope':'Postboot; future reconnects only'}
