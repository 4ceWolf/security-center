#!/usr/bin/python3
"""Unprivileged generator probe. Writes disposable unit text; starts no units."""
import json, os, pathlib, subprocess, tempfile
root=pathlib.Path('/home/user/Projects/security-center/work')
root.mkdir(exist_ok=True)
folder=pathlib.Path(tempfile.mkdtemp(prefix='generator-probe-',dir=root))
uuid='11111111-2222-3333-4444-555555555555'
report={}
for label,options in [('normal','tpm2-device=auto'),('without-tpm-option','password-cache=no')]:
    case=folder/label
    for name in ('normal','early','late'):(case/name).mkdir(parents=True)
    crypttab=case/'crypttab';crypttab.write_text('')
    env=dict(os.environ,SYSTEMD_IN_INITRD='1',SYSTEMD_CRYPTTAB=str(crypttab),
             SYSTEMD_PROC_CMDLINE=f'rd.luks.name={uuid}=testroot rd.luks.options={uuid}={options}',
             SYSTEMD_LOG_LEVEL='warning')
    result=subprocess.run(['/usr/lib/systemd/system-generators/systemd-cryptsetup-generator',
                           str(case/'normal'),str(case/'early'),str(case/'late')],
                          env=env,capture_output=True,text=True,timeout=15,check=True)
    unit=case/'normal/systemd-cryptsetup@testroot.service'
    if not unit.is_file():raise RuntimeError('Expected generated unit absent')
    text=unit.read_text()
    assert uuid in text and 'ExecStart=' in text
    report[label]={'unit':str(unit),'directives':[line for line in text.splitlines() if line.startswith(('ExecStart=','Before=','After=','Requires=','Wants=','DefaultDependencies='))]}
(folder/'report.json').write_text(json.dumps(report,indent=2))
print(json.dumps({'folder':str(folder),'results':report},indent=2))
