import copy
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
from unlock_candidate_audit import audit

NAME='systemd-cryptsetup@root.service'
SOURCE='/dev/disk/by-uuid/11111111-2222-3333-4444-555555555555'
OPTS='tpm2-device=auto'
FRAGMENT=f'''[Unit]
After=cryptsetup-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/systemd-cryptsetup attach root '{SOURCE}' '' '{OPTS}'
ExecStop=/usr/bin/systemd-cryptsetup detach root
'''
DROP='''[Unit]
Wants=device-check.service
After=device-check.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /gate.py
'''

class AuditTests(unittest.TestCase):
 def setUp(self):
  self.snapshot={NAME:dict(fragment=FRAGMENT,dropins=[dict(name='50-gate.conf',text=DROP)])}
 def check(self, snapshot=None):
  return audit(self.snapshot if snapshot is None else snapshot,NAME,'root',{SOURCE},OPTS,['/usr/bin/python3','/gate.py'])
 def test_reviewed(self):self.assertTrue(self.check()['accepted'])
 def test_fixed_console_only(self):
  s=copy.deepcopy(self.snapshot)
  s[NAME]['dropins'][0]['text'] += 'StandardInput=tty\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTTYReset=yes\n'
  self.assertTrue(self.check(s)['accepted'])
  for old,new in (('/dev/console','/tmp/input'),('StandardInput=tty','StandardInput=file:/tmp/input')):
   bad=copy.deepcopy(s);bad[NAME]['dropins'][0]['text']=bad[NAME]['dropins'][0]['text'].replace(old,new)
   self.assertFalse(self.check(bad)['accepted'])
 def test_extra_or_missing_units(self):
  for snap in ({},dict(self.snapshot,extra=self.snapshot[NAME])):
   self.assertFalse(self.check(snap)['accepted'])
 def test_source_keyfile_options(self):
  for old,new in ((SOURCE,'/dev/other'),("''",'/key'),(OPTS,'tpm2-device=none')):
   s=copy.deepcopy(self.snapshot);s[NAME]['fragment']=FRAGMENT.replace(old,new)
   self.assertFalse(self.check(s)['accepted'])
 def test_stock_or_second_command_remains(self):
  for text in ('',DROP.replace('ExecStart=\n',''),DROP+'ExecStart=/usr/bin/true\n'):
   s=copy.deepcopy(self.snapshot);s[NAME]['dropins']=[dict(name='50-gate.conf',text=text)]
   self.assertFalse(self.check(s)['accepted'])
 def test_unknown_execution_or_environment(self):
  for line in ('ExecStartPre=/bin/true','Environment=PYTHONPATH=/tmp','RootDirectory=/tmp','User=nobody'):
   s=copy.deepcopy(self.snapshot);s[NAME]['dropins'][0]['text'] += line+'\n'
   self.assertFalse(self.check(s)['accepted'])
 def test_ordering_reset_or_wrong(self):
  for text in (DROP.replace('After=device-check.service','After=other.service'),DROP+'[Unit]\nAfter=\n',DROP+'[Unit]\nRequires=device-check.service\n'):
   s=copy.deepcopy(self.snapshot);s[NAME]['dropins'][0]['text']=text
   self.assertFalse(self.check(s)['accepted'])
 def test_line_continuation_is_not_misread_as_ordering(self):
  s=copy.deepcopy(self.snapshot)
  s[NAME]['dropins'][0]['text']=DROP.replace('After=device-check.service','Description=continued\\\nAfter=device-check.service')
  self.assertFalse(self.check(s)['accepted'])
 def test_dependency_reset_cannot_hide_required_checker(self):
  s=copy.deepcopy(self.snapshot)
  s[NAME]['fragment']=FRAGMENT.replace('[Unit]', '[Unit]\nRequires=device-check.service')
  s[NAME]['dropins'][0]['text'] += '[Unit]\nRequires=\n'
  self.assertFalse(self.check(s)['accepted'])
 def test_checker_binding_conflict_or_cycle_refused(self):
  for key in ('BindsTo','Conflicts','Before'):
   s=copy.deepcopy(self.snapshot)
   s[NAME]['dropins'][0]['text'] += '[Unit]\n'+key+'=device-check.service\n'
   self.assertFalse(self.check(s)['accepted'])
 def test_quoted_dependency_refused(self):
  s=copy.deepcopy(self.snapshot)
  s[NAME]['dropins'][0]['text'] += '[Unit]\nRequires="device-check.service"\n'
  self.assertFalse(self.check(s)['accepted'])
 def test_generated_blockdev_instance_only(self):
  s=copy.deepcopy(self.snapshot)
  s[NAME]['fragment']=FRAGMENT.replace('[Unit]', '[Unit]\nBefore=blockdev@dev-mapper-%i.target\nWants=blockdev@dev-mapper-%i.target')
  self.assertTrue(self.check(s)['accepted'])
  s[NAME]['dropins'][0]['text'] += '[Unit]\nRequires=%i.service\n'
  self.assertFalse(self.check(s)['accepted'])
 def test_unsupported_expansion_or_duplicate_dropin(self):
  s=copy.deepcopy(self.snapshot);s[NAME]['dropins']*=2
  self.assertFalse(self.check(s)['accepted'])
  s=copy.deepcopy(self.snapshot);s[NAME]['fragment']=FRAGMENT.replace('attach root','attach %i')
  self.assertFalse(self.check(s)['accepted'])

if __name__=='__main__':unittest.main()
