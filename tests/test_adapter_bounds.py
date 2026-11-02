import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'securityd'))
import adapters


class BoundsTests(unittest.TestCase):
    def test_pipe_output_limit_and_timeout(self):
        with self.assertRaises(ValueError):
            adapters.bounded_command([sys.executable,'-c','import sys; sys.stdout.buffer.write(b"x"*4000000)'],limit=1024)
        started=time.monotonic()
        with self.assertRaises(TimeoutError):
            adapters.bounded_command([sys.executable,'-c','import time; time.sleep(5)'],timeout=.1)
        self.assertLess(time.monotonic()-started,2)
    def test_accepted_status_and_utf8(self):
        self.assertEqual(adapters.bounded_command([sys.executable,'-c','print("none");raise SystemExit(1)'],accepted=(0,1)),'none\n')
        with self.assertRaises(RuntimeError):
            adapters.bounded_command([sys.executable,'-c','raise SystemExit(2)'],accepted=(0,1))
        with self.assertRaises(UnicodeError):
            adapters.bounded_command([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"\\xff")'])
    def test_general_command_uses_bounded_reader(self):
        with patch.object(adapters,'bounded_command',return_value='result') as bounded:
            self.assertEqual(adapters.command(['/usr/bin/pacman','-Qu'],accepted=(0,1)),'result')
        bounded.assert_called_once_with(['/usr/bin/pacman','-Qu'],accepted=(0,1))
    def test_directory_limit_precedes_sort_and_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            for name in ('c','a','b'):(root/name).touch()
            self.assertEqual([p.name for p in adapters.bounded_entries(root,3)],['a','b','c'])
            with self.assertRaises(ValueError):adapters.bounded_entries(root,2)
    def test_too_many_listeners_and_updates_refuse_partial_result(self):
        line='LISTEN 0 10 127.0.0.1:9090 0.0.0.0:*\n'
        with patch.object(adapters,'command',return_value=line*4097):
            with self.assertRaises(ValueError):adapters.listeners()
        package='some-package 1.0 -> 2.0\n'
        with patch.object(adapters,'bounded_entries',return_value=[pathlib.Path(__file__)]),patch.object(adapters,'command',return_value=package*4097):
            # Use a real file for the database age observation; only the suffix
            # selects it as database metadata in this disposable test.
            with tempfile.TemporaryDirectory() as directory:
                path=pathlib.Path(directory)/'test.db';path.touch()
                with patch.object(adapters,'bounded_entries',return_value=[path]):
                    with self.assertRaises(ValueError):adapters.updates()


if __name__=='__main__':unittest.main()
