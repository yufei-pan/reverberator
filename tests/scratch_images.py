'''
Real filesystems for the tests that need one: a loop image under REVERB_SCRATCH, which also makes it safe to flush, as nothing
else lives there. Keep REVERB_SCRATCH private; a tmpfs folder such as /dev/shm/reverb-r20-<task> keeps the live disks out of it.
'''
import contextlib
import os
import shutil
import subprocess
import tempfile

import pytest

SCRATCH = os.environ.get('REVERB_SCRATCH')
# what the live vault disks report in /sys/fs/f2fs/<disk>/features, less pin_file, which mkfs does not set
F2FS_FEATURES = 'extra_attr,inode_checksum,flexible_inline_xattr,sb_checksum'
F2FS_OPTIONS = ('loop,lazytime,noatime,background_gc=on,gc_merge,nodiscard,user_xattr,inline_xattr,acl,inline_data,inline_dentry,flush_merge,'
	'extent_cache,mode=lfs,active_logs=6,checkpoint_merge,fsync_mode=posix')
needs_f2fs = pytest.mark.skipif(not SCRATCH or os.geteuid() != 0 or not shutil.which('mkfs.f2fs'),
	reason='needs REVERB_SCRATCH, root and mkfs.f2fs')


@contextlib.contextmanager
def f2fs_mount(tmp: str, size_mib: int):
	'''
	The mount point of a new f2fs of size_mib, with the live disks' features and mount options, in a folder of its own under
	tmp. All of it goes at the end: the mount, its loop device (mount -o loop frees it at the umount), the image, and tmp
	itself once nothing else is in it.
	'''
	os.makedirs(tmp, exist_ok=True)
	work = tempfile.mkdtemp(prefix='f2fs-', dir=tmp)
	image, mount_point = os.path.join(work, 'image'), os.path.join(work, 'mnt')
	try:
		with open(image, 'wb') as f:
			f.truncate(size_mib << 20)
		subprocess.run(['mkfs.f2fs', '-q', '-f', '-O', F2FS_FEATURES, image], check=True, stdout=subprocess.DEVNULL)
		os.mkdir(mount_point)
		subprocess.run(['mount', '-t', 'f2fs', '-o', F2FS_OPTIONS, image, mount_point], check=True)
		try:
			yield mount_point
		finally:
			subprocess.run(['umount', mount_point], check=True)
	finally:
		shutil.rmtree(work)
		with contextlib.suppress(OSError):
			os.rmdir(tmp)
