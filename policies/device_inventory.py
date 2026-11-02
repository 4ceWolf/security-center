"""Read-only USB observations. Not a complete preboot device inventory."""
import itertools
import json
import os
import pathlib
import re

PCI = re.compile(r'^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$')
USB = re.compile(r'^\d+-\d+(?:\.\d+)*$')


def entries(path, limit=256):
    with os.scandir(path) as iterator:
        result=list(itertools.islice(iterator,limit+1))
    if len(result)>limit:raise ValueError('Enumeration exceeds bound')
    return sorted((pathlib.Path(x.path) for x in result),key=lambda p:p.name)


def read(path, optional=False):
    try:
        with path.open() as f:value=f.read(257)
    except FileNotFoundError:
        if optional:return ''
        raise
    if len(value)>256:raise ValueError('Attribute exceeds bound')
    return value.strip()


def hex_value(path, digits):
    value=read(path).lower()
    if not re.fullmatch('[0-9a-f]{'+str(digits)+'}',value):raise ValueError('Invalid USB attribute')
    return value


def observe(device):
    resolved=device.resolve(strict=True)
    controllers=[p for p in resolved.parts if PCI.fullmatch(p)]
    if not controllers:raise ValueError('USB controller provenance unavailable')
    route=read(device/'devpath')
    if not re.fullmatch(r'\d+(?:\.\d+)*',route) or route=='0':raise ValueError('Invalid peripheral route')
    interfaces=[]
    for p in entries(device,128):
        if p.name.startswith(device.name+':'):
            interfaces.append(':'.join(hex_value(p/name,2) for name in ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol')))
    declared=int(read(device/'bNumInterfaces'),16)
    if not interfaces or len(interfaces)!=declared:raise ValueError('Interfaces incomplete')
    identity={'transport':'usb','vendor':hex_value(device/'idVendor',4),
              'product':hex_value(device/'idProduct',4),'serial':read(device/'serial',True),
              'port':f'pci:{controllers[-1]}/usb:{route}','interfaces':sorted(interfaces)}
    return identity


def sample(bus):
    devices=[];errors=[]
    try:
        for path in entries(bus):
            if ':' in path.name or re.fullmatch(r'usb\d+',path.name):continue
            if not USB.fullmatch(path.name):
                errors.append('Unrecognized USB entry');continue
            try:devices.append(observe(path))
            except (OSError,ValueError):errors.append('Unreadable or incomplete peripheral: '+path.name)
    except (OSError,ValueError):errors.append('USB enumeration unavailable or over limit')
    return sorted(devices,key=lambda x:x['port']),errors


def collect(bus=pathlib.Path('/sys/bus/usb/devices')):
    first,errors1=sample(bus);second,errors2=sample(bus)
    errors=errors1+errors2
    if first!=second:errors.append('USB inventory changed between samples')
    return {'schema_version':1,'complete':False,'transports_checked':['usb'],
            'devices':second,'usb_observation_complete':not errors,'errors':errors,
            'limitations':['Thunderbolt and external PCI discovery not implemented',
                          'Repeated reads do not prevent subsequent hotplug',
                          'USB root hubs omitted; internal/peripheral classification needs approved topology']}

if __name__=='__main__':print(json.dumps(collect(),indent=2))
