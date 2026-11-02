OPENSNITCH_RULES='/etc/opensnitchd/rules'


def opensnitch_rule(raw):
    if len(raw)>65536:raise ValueError('Oversized rule')
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('Duplicate rule field')
            value[key]=item
        return value
    data=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(data,dict):raise ValueError('Invalid rule')
    if type(data.get('enabled')) is not bool or type(data.get('precedence',False)) is not bool:
        raise ValueError('Invalid rule flags')
    if data.get('action') not in ('allow','deny','reject'):raise ValueError('Invalid rule action')
    operator=data.get('operator')
    if not isinstance(operator,dict):raise ValueError('Missing rule operator')
    kind=operator.get('type')
    if kind not in ('simple','regexp','network','lists','list','range'):kind='unknown'
    return {'fingerprint':hashlib.sha256(raw).hexdigest(),'enabled':data['enabled'],
            'precedence':data.get('precedence',False),'action':data['action'],'operator_type':kind}


def opensnitch_inventory():
    rules=[];failed=0;truncated=False;total=0;entries=0
    fd=open_fixed(OPENSNITCH_RULES)
    try:
        before=os.fstat(fd)
        if not stat.S_ISDIR(before.st_mode):raise ValueError('Not a rule directory')
        with os.scandir(fd) as iterator:
            for entry in iterator:
                entries+=1
                if entries>1024:truncated=True;break
                if not entry.name.endswith('.json'):continue
                if len(rules)+failed>=256:truncated=True;break
                child=None
                try:
                    child=os.open(entry.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                    initial=os.fstat(child)
                    if not stat.S_ISREG(initial.st_mode) or initial.st_size>65536:raise ValueError('Invalid rule file')
                    with os.fdopen(child,'rb',closefd=False) as stream:raw=stream.read(65537)
                    total+=len(raw)
                    if total>4*1024*1024:truncated=True;break
                    final=os.fstat(child);current=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                    if identity(initial)!=identity(final) or identity(final)!=identity(current):raise ValueError('Rule changed')
                    rules.append(opensnitch_rule(raw))
                except (OSError,ValueError,RecursionError):failed+=1
                finally:
                    if child is not None:os.close(child)
        if identity(before)!=identity(os.fstat(fd)):failed+=1
        check=open_fixed(OPENSNITCH_RULES)
        try:
            if identity(os.fstat(check))!=identity(os.fstat(fd)):failed+=1
        finally:os.close(check)
    finally:os.close(fd)
    return {'rules':sorted(rules,key=lambda r:r['fingerprint']),'unreadable_or_invalid':failed,
            'truncated':truncated,'complete':not failed and not truncated,
            'scope':'Default directory only; live daemon loading and temporary rules not verified'}


def opensnitch():
    state=service_status('opensnitchd.service','OpenSnitch')
    if not state['details'].get('installed'):return state
    try:inventory=opensnitch_inventory()
    except (OSError,ValueError):
        return result('unavailable','OpenSnitch rule configuration unavailable',
                      active=state['details'].get('active'),policy_verified=False)
    counts={target:sum(rule['enabled'] and rule['action']==target for rule in inventory['rules'])
            for target in ('allow','deny','reject')}
    counts['disabled']=sum(not rule['enabled'] for rule in inventory['rules'])
    try:
        from network_policy import verify
        native=verify()
    except (OSError,ValueError,PermissionError):
        native={'configuration_verified':False,'saved_functional_test_passed':False,'evidence_unavailable':True}
    status='unknown' if state['details'].get('active') and inventory['complete'] else 'attention'
    if state['details'].get('active') and not native.get('configuration_verified'):status='action_required'
    return result(status,f"OpenSnitch: {counts['deny']} deny rules; new applications allowed by default",
                  active=state['details'].get('active'),policy_verified=False,native_configuration=native,
                  inventory=inventory,counts=counts,
                  note='Saved native app-blocking test is separate from current per-rule enforcement. Open the on-demand firewall window for connection details and app decisions.')


