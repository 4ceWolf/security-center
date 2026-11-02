import io
import pathlib
import stat
import subprocess
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from arch_initrd_manifest import newc, inspect
from test_initrd_manifest import archive

class ArchManifestTests(unittest.TestCase):
    def test_trailing_directory_slash_and_zero_link_symlink(self):
        raw=archive([('bin',stat.S_IFLNK|0o777,b'usr/bin'),('usr/',stat.S_IFDIR|0o755,b'')])
        raw=raw[:38]+b'00000000'+raw[46:]
        data,end=newc(raw)
        self.assertIn('usr',data['files']);self.assertEqual(data['files']['usr']['raw_name'],'usr/')
        self.assertEqual(end,len(raw))
    def test_duplicate_normalized_names_refused(self):
        raw=archive([('./usr/',stat.S_IFDIR|0o755,b''),('usr',stat.S_IFDIR|0o755,b'')])
        with self.assertRaises(ValueError):newc(raw)
    def test_unsafe_special_and_hardlink_payload_refused(self):
        for items in ([('../escape',stat.S_IFREG,b'x')],[('device',stat.S_IFBLK,b'')]):
            with self.assertRaises(ValueError):newc(archive(items))
        raw=archive([('a',stat.S_IFREG|0o644,b'x')]);raw=raw[:38]+b'00000002'+raw[46:]
        with self.assertRaises(ValueError):newc(raw)
    def test_truncation_and_invalid_padding_refused(self):
        raw=archive([('a',stat.S_IFREG|0o644,b'x')])
        for size in (0,6,109,len(raw)-1):
            with self.assertRaises(ValueError):newc(raw[:size])
        changed=bytearray(raw);changed[113]=1
        with self.assertRaises(ValueError):newc(bytes(changed))
    def test_metadata_and_payload_hash_captured(self):
        raw=archive([('a',stat.S_IFREG|0o600,b'content')])
        data,_=newc(raw)
        self.assertEqual(data['files']['a']['mode'],stat.S_IFREG|0o600)
        other,_=newc(archive([('a',stat.S_IFREG|0o600,b'changed')]))
        self.assertNotEqual(data['files']['a']['sha256'],other['files']['a']['sha256'])

    @unittest.skipUnless(pathlib.Path('/usr/bin/zstd').exists(),'Host zstd required')
    def test_full_segment_capture_and_trailing_refusal(self):
        early=archive([('early_cpio',stat.S_IFREG|0o644,b'1')])
        main=archive([('init',stat.S_IFLNK|0o777,b'usr/lib/systemd/systemd')])
        def image(payload):
            compressed=subprocess.check_output(['/usr/bin/zstd','-q','--stdout'],input=payload)
            return early+b'\0'*6400+compressed
        data=inspect(image(main+b'\0'*512))
        self.assertFalse(data['approved']);self.assertEqual(len(data['segments']),2)
        self.assertEqual(data['segments'][1]['files']['init']['symlink_target'],'usr/lib/systemd/systemd')
        for payload in (main+b'extra',main+main):
            with self.assertRaises(ValueError):inspect(image(payload))
        with self.assertRaises(ValueError):inspect(early+b'\0'*10241+image(main)[len(early)+6400:])
if __name__=='__main__':unittest.main()
