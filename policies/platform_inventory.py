"""Read-only platform observations; no inferred internal-device approvals."""
import json
import pathlib
import re
from device_inventory import entries, read, PCI


def pci_sample(bus):
    devices=[];errors=[]
    try:
        for device in entries(bus):
            try:
                if not PCI.fullmatch(device.name):raise ValueError('Unexpected address')
                item={'address':device.name,'topology':[p for p in device.resolve(strict=True).parts if PCI.fullmatch(p)]}
                for key,digits in (('vendor',4),('device',4),('class',6)):
                    value=read(device/key).lower()
                    if not re.fullmatch('0x[0-9a-f]{'+str(digits)+'}',value):raise ValueError('Invalid PCI attribute')
                    item[key]=value
                item['iommu_group_present']=(device/'iommu_group').exists()
                devices.append(item)
            except (OSError,ValueError):errors.append('PCI evidence unavailable: '+device.name)
    except (OSError,ValueError):errors.append('PCI enumeration unavailable or over limit')
    return devices,errors


def thunderbolt_sample(bus):
    devices=[];errors=[]
    try:
        for device in entries(bus):
            # Keep domains/routers/all entries; do not silently classify any as trusted.
            item={'entry':device.name}
            for name in ('unique_id','vendor_name','device_name','authorized','security'):
                value=read(device/name,optional=True)
                if value:item[name]=value
            if not device.exists():raise ValueError('Entry disappeared')
            devices.append(item)
    except (OSError,ValueError):errors.append('Thunderbolt enumeration unavailable, unstable or over limit')
    return devices,errors


def collect(pci_bus=pathlib.Path('/sys/bus/pci/devices'),tb_bus=pathlib.Path('/sys/bus/thunderbolt/devices')):
    first,errors=pci_sample(pci_bus);second,err=pci_sample(pci_bus);errors+=err
    tb_first,err=thunderbolt_sample(tb_bus);errors+=err
    tb_second,err=thunderbolt_sample(tb_bus);errors+=err
    if first!=second:errors.append('PCI observations changed between samples')
    if tb_first!=tb_second:errors.append('Thunderbolt observations changed between samples')
    return {'schema_version':1,'pci':second,'thunderbolt':tb_second,'errors':errors,
            'observation_complete':not errors,'platform_policy_approved':False,
            'limitations':['No assertion of physical power-only state or firmware DMA protection',
                          'No internal/external classification; every baseline entry requires review',
                          'Missing IOMMU groups are observations, not a firmware capability verdict',
                          'Matching samples do not prevent subsequent hotplug or a malicious device']}

if __name__=='__main__':print(json.dumps(collect(),indent=2))
