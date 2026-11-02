"""Root metadata/publication negative tests, only in the disposable guest."""
import copy
import os
import pathlib
import stat
import select
import signal
import sys
assert 'security_center_test_vm=1' in pathlib.Path('/proc/cmdline').read_text().split()
sys.path.insert(0, '/usr/lib/security-center-observation')
from boot_observation import consume, publish
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
data = consume(boot)
directory = pathlib.Path('/run/observation-file-tests')
directory.mkdir(mode=0o700)
filename = directory/'boot.json'

def refused(callback):
    try: callback()
    except (OSError, ValueError): return
    raise AssertionError('Unsafe observation accepted')

publish(data, str(directory))
assert consume(boot, str(directory)) == data
refused(lambda: publish(data, str(directory)))
original = filename.read_bytes()
filename.chmod(0o644)
refused(lambda: consume(boot, str(directory)))
filename.chmod(0o600)
os.link(filename, directory/'extra')
refused(lambda: consume(boot, str(directory)))
(directory/'extra').unlink()
filename.unlink(); filename.symlink_to('/run/security-center-observation/boot.json')
refused(lambda: consume(boot, str(directory)))
filename.unlink(); os.mkfifo(filename, 0o600)
refused(lambda: consume(boot, str(directory)))
filename.unlink(); filename.write_bytes(b' '*65537); filename.chmod(0o600)
refused(lambda: consume(boot, str(directory)))
filename.unlink()
# An interrupted publication can leave a private pending inode, never boot.json.
(directory/'.pending-interrupted').write_bytes(original[:20])
refused(lambda: consume(boot, str(directory)))
(directory/'.pending-interrupted').unlink()
directory.chmod(0o777)
refused(lambda: publish(data, str(directory)))
directory.chmod(0o700)
# Kill a real producer after its complete pending inode is flushed, before link
# publication. SIGKILL deliberately prevents its finally cleanup from running.
import boot_observation as records
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(read_fd)
    def pause_publication(*args, **kwargs):
        os.write(write_fd, b'1')
        signal.pause()
    records.os.link = pause_publication
    try: publish(data, str(directory))
    finally: os._exit(2)
os.close(write_fd)
try:
    assert select.select([read_fd], [], [], 3)[0], 'Producer did not reach publication'
    assert os.read(read_fd, 1) == b'1'
finally:
    os.kill(child, signal.SIGKILL)
    _, status = os.waitpid(child, 0)
    os.close(read_fd)
assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
assert not filename.exists()
refused(lambda: consume(boot, str(directory)))
for pending in directory.glob('.pending-*'): pending.unlink()
# Replace the final directory entry after reading the opened inode. The reader
# must compare its fd with the current entry and reject the changed identity.
publish(data, str(directory))
original_stat = records.os.stat
replaced = False
def replaced_stat(name, *args, **kwargs):
    global replaced
    if name == 'boot.json' and kwargs.get('dir_fd') is not None and not replaced:
        replaced = True
        filename.rename(directory/'previous')
        filename.write_bytes(original); filename.chmod(0o600)
    return original_stat(name, *args, **kwargs)
records.os.stat = replaced_stat
try: refused(lambda: consume(boot, str(directory)))
finally: records.os.stat = original_stat
assert replaced
filename.unlink();(directory/'previous').unlink()
directory.rmdir()
print('\nVM_OBSERVATION_FILES_PASS', flush=True)
