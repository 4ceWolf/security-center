import io
import pathlib
import stat
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from initrd_manifest import inspect_newc, verify


def archive(items):
    out=bytearray()
    for ino,(name,mode,data) in enumerate(items+[('TRAILER!!!',0,b'')]):
        fields=[ino,mode,0,0,1,0,len(data),0,0,0,0,len(name.encode())+1,0]
        out.extend(b'070701'+''.join(f'{n:08x}' for n in fields).encode())
        out.extend(name.encode()+b'\0');out.extend(b'\0'*(-len(out)%4))
        out.extend(data);out.extend(b'\0'*(-len(out)%4))
    return bytes(out)

class ManifestTests(unittest.TestCase):
 def capture(self,items):return inspect_newc(io.BytesIO(archive(items)))
 def test_files_modes_symlinks_and_no_approval(self):
  data=self.capture([('a',stat.S_IFDIR|0o755,b''),('a/helper',stat.S_IFREG|0o755,b'code'),('link',stat.S_IFLNK|0o777,b'a/helper')])
  self.assertEqual(len(data['files']),3);self.assertFalse(data['approved'])
  self.assertEqual(data['files']['link']['symlink_target'],'a/helper')
  self.assertTrue(verify(data,data))
 def test_content_mode_and_new_file_changes_refused(self):
  base=self.capture([('helper',stat.S_IFREG|0o755,b'code')])
  for items in ([('helper',stat.S_IFREG|0o755,b'evil')], [('helper',stat.S_IFREG|0o777,b'code')],
                [('helper',stat.S_IFREG|0o755,b'code'),('extra.service',stat.S_IFREG|0o644,b'unit')]):
   with self.assertRaises(ValueError):verify(self.capture(items),base)
 def test_unsafe_duplicate_special_or_missing_parent(self):
  for items in ([('../bad',stat.S_IFREG,b'')],[('/bad',stat.S_IFREG,b'')],
                [('a',stat.S_IFREG,b''),('a',stat.S_IFREG,b'')],
                [('a',stat.S_IFIFO,b'')],[('a/b',stat.S_IFREG,b'')],
                [('a',stat.S_IFLNK,b'/tmp'),('a/b',stat.S_IFREG,b'')]):
   with self.subTest(items=items),self.assertRaises(ValueError):self.capture(items)
 def test_truncated_or_appended(self):
  raw=archive([('helper',stat.S_IFREG,b'abc')])
  for bad in (raw[:-1],raw+b'extra',b'bad'):
   with self.assertRaises(ValueError):inspect_newc(io.BytesIO(bad))

if __name__=='__main__':unittest.main()
