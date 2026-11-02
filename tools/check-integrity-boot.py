#!/usr/bin/python3
"""Non-mutating post-boot checks. Owner must report automatic/manual unlock."""
from pathlib import Path
import json,subprocess
cmdline=Path('/proc/cmdline').read_text().strip()
lockdown=Path('/sys/kernel/security/lockdown').read_text().strip()
data=json.loads(subprocess.check_output(['/usr/bin/python3','-I','/usr/local/lib/security-center/client.py'],text=True))
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
checks={'integrity_in_boot_command_line':'lockdown=integrity' in cmdline.split(),
        'integrity_enforced':'[integrity]' in lockdown,
        'collector_matches_current_boot':data.get('boot_id')==boot,
        'secure_boot_reported_enabled':any(m['id']=='secureboot' and m['status']=='secure' for m in data.get('modules',[])),
        'firewall_reported_active':any(m['id']=='firewall' and m['status']=='secure' for m in data.get('modules',[])),
        'luks_reported_active':any(m['id']=='luks' and m['status']=='secure' for m in data.get('modules',[]))}
print(json.dumps({'boot_id':boot,'checks':checks,'unlock_method':'Owner confirmation required; not inferred',
                  'sleep_wake':'Owner test required'},indent=2))
raise SystemExit(0 if all(checks.values()) else 1)
