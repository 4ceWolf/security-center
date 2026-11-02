"""Bounded read-only AppArmor observations; never claim complete app coverage."""
import pathlib,re
ENABLED=pathlib.Path('/sys/module/apparmor/parameters/enabled')
PROFILES=pathlib.Path('/sys/kernel/security/apparmor/profiles')
PROC=pathlib.Path('/proc')
IMPORTANT={'firefox','zen','chromium','sshd','cockpit-ws','NetworkManager'}
MAX_PROCESSES=512

def read(path,limit):
    with path.open('r',errors='strict') as stream:value=stream.read(limit+1)
    if len(value)>limit:raise ValueError('Oversized confinement evidence')
    return value.strip()

def label(value):
    if value=='unconfined':return {'profile':None,'mode':'unconfined'}
    match=re.fullmatch(r'(.+) \(([^()]*)\)',value)
    if not match or len(value)>2048:raise ValueError('Invalid confinement label')
    profile,mode=match.groups()
    return {'profile':profile,'mode':mode if mode in {'enforce','complain','kill','unconfined','prompt'} else 'unknown'}

def profiles(value):
    if len(value)>1024*1024:raise ValueError('Oversized profiles')
    lines=value.splitlines()
    if len(lines)>4096:raise ValueError('Too many profiles')
    entries=[label(line) for line in lines]
    counts={mode:sum(item['mode']==mode for item in entries) for mode in ('enforce','complain','kill','unconfined','prompt','unknown')}
    return {'counts':counts,'total':len(entries)}

def start_time(directory):
    # comm in stat may contain spaces or parentheses: fields after its last ')' are fixed.
    fields=read(directory/'stat',8192).rsplit(')',1)[1].split()
    return int(fields[19])

def processes():
    selected=[];checked=0;unreadable=0;truncated=False
    # Stop enumeration at the bound instead of materializing an unbounded PID list.
    for directory in PROC.iterdir():
        if not directory.name.isdecimal():continue
        if checked>=MAX_PROCESSES:truncated=True;break
        checked+=1
        try:
            before=start_time(directory)
            name=read(directory/'comm',64)
            if name not in IMPORTANT:continue
            source='apparmor-specific'
            try:value=read(directory/'attr/apparmor/current',2048)
            except FileNotFoundError:
                source='generic-attribute';value=read(directory/'attr/current',2048)
            current=label(value)
            if start_time(directory)!=before:raise ValueError('Process changed during observation')
            selected.append({'pid':int(directory.name),'name':name,**current,'source':source})
        except (OSError,ValueError,IndexError,UnicodeError):unreadable+=1
    return {'observed':selected,'processes_checked':checked,'unreadable_or_changed':unreadable,
            'truncated':truncated,'complete':not truncated and unreadable==0,
            'identity_note':'Process names are hints, not authenticated application identity; no command lines are read'}

def configuration():
    details={'coverage_verified':False}
    try:enabled=read(ENABLED,8)
    except OSError:
        return {'status':'unavailable','summary':'AppArmor enabled state unavailable','details':details}
    if enabled=='N':return {'status':'attention','summary':'AppArmor is not enabled','details':details}
    if enabled!='Y':raise ValueError('Invalid enabled state')
    details['enabled']=True
    try:details['profiles']=profiles(read(PROFILES,1024*1024))
    except (OSError,ValueError,UnicodeError):
        return {'status':'unavailable','summary':'AppArmor enabled; profile evidence unavailable','details':details}
    try:details['applications']=processes()
    except OSError:details['applications']={'complete':False,'error':'Process evidence unavailable'}
    counts=details['profiles']['counts']
    applications=details['applications']
    weak=any(item['mode'] not in ('enforce','kill') for item in applications.get('observed',[]))
    attention=not (counts['enforce']+counts['kill']) or bool(counts['complain']+counts['unconfined']) or weak
    return {'status':'attention' if attention else 'unknown',
            'summary':f"AppArmor: {counts['enforce']} enforcing, {counts['complain']} complain profiles; application coverage unverified",
            'details':details}
