"""Read-only adapters: never install, enable or change enforcement."""
import datetime
import hashlib
import json
import os
import stat
from integrity import open_fixed, identity
from confinement import read as read_proc, start_time
import pathlib
import re
import selectors
import subprocess
import time
import xml.etree.ElementTree as ET


def result(status, summary, **details):
    return {'status': status, 'summary': summary, 'details': details}


def command(args, accepted=(0,)):
    return bounded_command(args, accepted=accepted)


def service_status(unit, label):
    output = command(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState'])
    fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    if fields.get('LoadState') == 'not-found':
        return result('unknown', label + ' is not installed', unit=unit, installed=False, policy_verified=False)
    active = fields.get('ActiveState') == 'active'
    return result('unknown' if active else 'attention',
                  label + (' is running; policy not checked' if active else ' is not active'),
                  unit=unit, installed=True, active=active, policy_verified=False)


def bounded_entries(directory, limit):
    """Bound enumeration before sorting, including entries later filtered out."""
    entries=[]
    for path in directory.iterdir():
        if len(entries)>=limit:raise ValueError('Directory inventory exceeds observation bound')
        entries.append(path)
    return sorted(entries)


def bounded_command(args, limit=1024*1024, timeout=8, accepted=(0,)):
    """Fixed internal commands only. Bound pipe consumption, duration and cleanup."""
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={'PATH':'/usr/bin','LC_ALL':'C'}) as process:
        output=bytearray();deadline=time.monotonic()+timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise TimeoutError('Adapter timeout')
                    if not selector.select(remaining):raise TimeoutError('Adapter timeout')
                    chunk=process.stdout.read1(65536)
                    if not chunk:break
                    output.extend(chunk)
                    if len(output)>limit:raise ValueError('Adapter output limit exceeded')
                process.wait(timeout=max(.01,deadline-time.monotonic()))
            if process.returncode not in accepted:raise RuntimeError('Adapter unavailable')
            return output.decode('utf-8',errors='strict')
        finally:
            if process.poll() is None:process.kill();process.wait()


def parse_usbguard_devices(output):
    if len(output)>1024*1024:raise ValueError('USBGuard inventory too large')
    lines=output.splitlines()
    if len(lines)>256:raise ValueError('USBGuard device limit exceeded')
    devices=[];seen=set()
    for line in lines:
        if len(line)>8192:raise ValueError('USBGuard device record too large')
        match=re.fullmatch(r'([0-9]{1,10}): (allow|block|reject) id ([0-9a-fA-F]{4}):([0-9a-fA-F]{4})(?: (.*))?',line)
        if not match:raise ValueError('Unsupported USBGuard device format')
        identifier,target,vendor,product,attributes=match.groups()
        identifier=int(identifier)
        if identifier>4294967295 or identifier in seen:raise ValueError('Duplicate or invalid USBGuard ID')
        seen.add(identifier)
        devices.append({'device_id':identifier,'authorization':target,'vendor_id':vendor.lower(),
                        'product_id':product.lower(),'attributes_text':attributes or '',
                        'trust':'Not assessed'})
    return sorted(devices,key=lambda item:item['device_id'])


def usbguard():
    state=service_status('usbguard.service','USBGuard')
    if not state['details'].get('active'):return state
    try:
        devices=parse_usbguard_devices(bounded_command(['/usr/bin/usbguard','list-devices']))
    except (OSError,ValueError,RuntimeError,TimeoutError,subprocess.SubprocessError):
        return result('unavailable','USBGuard is running; device decisions unavailable',
                      active=True,policy_verified=False)
    counts={target:sum(d['authorization']==target for d in devices) for target in ('allow','block','reject')}
    try:
        from usb_policy import check_integrity
        native=check_integrity()
    except (OSError,ValueError,PermissionError):
        native={'policy_verified':False,'reference_unavailable':True}
    return result('unknown' if native.get('policy_verified') else 'action_required',f"USBGuard: {counts['allow']} allowed, {counts['block']} blocked, {counts['reject']} rejected",
                  active=True,policy_verified=native.get('policy_verified',False),native_policy_integrity=native,devices=devices,counts=counts,
                  note='Current daemon decisions only; an allowed device is not proof of trusted identity or correct policy')


def usb_inventory():
    devices = []
    # Read only small attributes. Device-provided strings are data, never commands/HTML.
    def attr(directory, name):
        try:
            with (directory / name).open() as f:
                return f.read(256).strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None
    for p in bounded_entries(pathlib.Path('/sys/bus/usb/devices'), 4096):
        if ':' in p.name or not (p / 'idVendor').exists():
            continue
        devices.append({'path': p.name, 'vendor_id': attr(p, 'idVendor'),
                        'product_id': attr(p, 'idProduct'), 'product': attr(p, 'product'),
                        'manufacturer': attr(p, 'manufacturer'), 'serial': attr(p, 'serial'),
                        'authorized': attr(p, 'authorized'), 'device_class': attr(p, 'bDeviceClass'),
                        'trust': 'Not assessed'})
        if len(devices)>256:raise ValueError('USB inventory exceeds observation bound')
    return result('unknown', str(len(devices)) + ' USB devices observed; trust not assessed',
                  devices=devices, preboot_gate='Outside project scope',
                  note='Includes root hubs and internal devices; identity attributes can be spoofed')


def updates():
    databases = [p for p in bounded_entries(pathlib.Path('/var/lib/pacman/sync'), 256) if p.name.endswith('.db')]
    if not databases:
        return result('unavailable', 'No local package database available')
    age = max(0, time.time() - min(p.stat().st_mtime for p in databases))
    output = command(['/usr/bin/pacman', '-Qu'], accepted=(0, 1))
    packages = []
    for line in output.splitlines():
        if len(packages)>=4096:raise ValueError('Update inventory exceeds observation bound')
        parts = line.split()
        if len(parts) >= 4 and parts[2] == '->':
            packages.append({'package': parts[0], 'installed': parts[1], 'available': parts[3]})
        elif parts:
            raise ValueError('Unexpected package output')
    return result('attention' if packages else 'unknown',
                  str(len(packages)) + ' updates in the local package database',
                  packages=packages, oldest_database_age_hours=round(age / 3600, 1),
                  freshness='Local database only; online availability not checked',
                  aur_updates='Not checked', security_advisories='Not checked')


def snapshots():
    root = pathlib.Path('/.snapshots')
    if not root.exists():
        return result('attention', 'Root snapshot directory not found')
    numbered = sorted((p for p in bounded_entries(root, 4096) if p.name.isdigit()), key=lambda p: int(p.name))
    latest = []
    for directory in reversed(numbered[-5:]):
        info = directory / 'info.xml'
        if not info.is_file():
            continue
        if info.stat().st_size > 65536:
            raise ValueError('Oversized snapshot metadata')
        xml = ET.fromstring(info.read_text())
        latest.append({'number': directory.name, 'date': xml.findtext('date'), 'type': xml.findtext('type')})
    return result('unknown' if latest else 'attention',
                  str(len(numbered)) + ' root snapshots found; restore not tested',
                  recent=latest, home_snapshots='Not inspected by this restricted service',
                  note='Snapshots do not back up the EFI partition; boot recovery is separate')


def listeners():
    output = command(['/usr/bin/ss', '-H', '-lnt'])
    addresses = []
    for line in output.splitlines():
        if len(addresses)>=4096:raise ValueError('Listener inventory exceeds observation bound')
        fields = line.split()
        if len(fields) < 5:
            raise ValueError('Unexpected socket output')
        addresses.append(fields[3])
    def loopback(value):
        host = value.rsplit(':', 1)[0].strip('[]').split('%', 1)[0]
        return host.startswith('127.') or host == '::1'
    exposed = [a for a in addresses if not loopback(a)]
    return result('attention' if exposed else 'secure',
                  str(len(exposed)) + ' non-loopback TCP listeners',
                  tcp_listeners=addresses, non_loopback=exposed,
                  note='A listening socket is not proof of internet exposure; UDP and firewall paths need separate checks')


PROCESS_ROOT=pathlib.Path('/proc')
PROCESS_LIMIT=512


def process_observations():
    sampled=0;observed=0;root_count=0;zombies=0;unavailable=0
    findings=[];truncated=False;finding_overflow=False
    for directory in PROCESS_ROOT.iterdir():
        if not directory.name.isdecimal():continue
        if sampled>=PROCESS_LIMIT:truncated=True;break
        sampled+=1
        try:
            before=start_time(directory)
            name=read_proc(directory/'comm',64)
            state=read_proc(directory/'stat',8192).rsplit(')',1)[1].split()[0]
            status=read_proc(directory/'status',16384)
            uid_lines=[line for line in status.splitlines() if line.startswith('Uid:')]
            if len(uid_lines)!=1:raise ValueError('UID unavailable')
            uids=uid_lines[0].split()[1:]
            if len(uids)!=4 or any(not value.isdecimal() for value in uids):raise ValueError('Invalid UID')
            effective=int(uids[1])
            try:executable=os.readlink(directory/'exe')
            except OSError:executable=None
            if executable is not None and len(executable)>4096:raise ValueError('Oversized executable path')
            if start_time(directory)!=before:raise ValueError('Process changed')
            observed+=1;root_count+=effective==0;zombies+=state=='Z'
            unavailable+=executable is None
            if executable is not None and executable.endswith(' (deleted)'):
                if len(findings)<128:
                    findings.append({'pid':int(directory.name),'start_time_ticks':before,
                                     'name':name,'effective_uid':effective,'finding':'Executable link reports deleted'})
                else:finding_overflow=True
        except (OSError,ValueError,IndexError,UnicodeError):unavailable+=1
    return result('attention' if findings or finding_overflow else 'unknown',
                  f'{observed} processes observed; {len(findings)} executable-deletion findings'+(' (additional findings omitted)' if finding_overflow else ''),
                  sampled=sampled,observed=observed,effective_root=root_count,zombies=zombies,
                  unreadable_or_changed=unavailable,truncated=truncated,findings_truncated=finding_overflow,
                  complete=not truncated and not unavailable and not finding_overflow,
                  findings=sorted(findings,key=lambda item:(item['pid'],item['start_time_ticks'])),
                  note='Deleted executable links can follow ordinary updates; no malware verdict. Process names are not authenticated identity. Polling can miss short-lived processes; unavailable evidence includes kernel/exited processes without executable links.')


ADAPTERS = {'usbguard': ('USB enforcement', usbguard), 'devices': ('USB inventory', usb_inventory),
            'updates': ('Package updates', updates), 'snapshots': ('Recovery snapshots', snapshots),
            'listeners': ('Listening services', listeners), 'processes': ('Process observations', process_observations)}
