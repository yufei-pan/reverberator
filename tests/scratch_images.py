'''
Real filesystems for the tests that need one: a loop image under REVERB_SCRATCH, which also makes it safe to flush, as nothing
else lives there. Keep REVERB_SCRATCH private; a tmpfs folder such as /dev/shm/reverb-r20-<task> keeps the live disks out of it.
'''
import contextlib
import os
import random
import re
import shutil
import subprocess
import tempfile
import time

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


class NotOurLoopImage(Exception):
	'''A flush or a shutdown asked of anything but a loop image this test process attached under REVERB_SCRATCH.'''


# how often a loop device is asked for (LoopImage.attach())
ATTACH_TRIES = 6
# the loop devices this process attached: device -> its image
ATTACHED = {}


def our_mount_point(path: str) -> str:
	'''
	The mount point holding path, as long as path is under REVERB_SCRATCH and findmnt says its source is a /dev/loop* this
	process attached (ATTACHED), its backing file being the image it attached there. NotOurLoopImage, with nothing done,
	otherwise: this host holds many live f2fs mounts, and a shutdown of one takes a production backup filesystem down.
	'''
	scratch = os.environ.get('REVERB_SCRATCH')
	if not scratch or not os.path.isabs(scratch):
		raise NotOurLoopImage(f'REVERB_SCRATCH is {scratch!r}, no absolute path')
	root = os.path.realpath(scratch) + '/'
	real = os.path.realpath(path)
	if not (real + '/').startswith(root):
		raise NotOurLoopImage(f'{real} is not under {root}')
	found = subprocess.run(['findmnt', '-n', '-r', '-o', 'SOURCE,TARGET', '--target', real], capture_output=True, text=True)
	source, _, target = found.stdout.strip().partition(' ')
	if found.returncode != 0 or not re.fullmatch(r'/dev/loop[0-9]+', source):
		raise NotOurLoopImage(f'{real} is on {source or "nothing findmnt names"}, no loop device')
	if source not in ATTACHED:
		raise NotOurLoopImage(f'{source} was not attached by this test')
	backing = subprocess.run(['losetup', '-n', '-O', 'BACK-FILE', source], capture_output=True, text=True).stdout.strip()
	if backing != ATTACHED[source] or not backing.startswith(root) or not target.startswith(root):
		raise NotOurLoopImage(f'{source} holds {backing!r} mounted at {target!r}, not the image this test attached')
	return target


def flush_scratch(path: str) -> None:
	'''syncfs of the loop image holding path (our_mount_point()), the only way a test flushes a filesystem by itself.'''
	subprocess.run(['sync', '-f', our_mount_point(path)], check=True)


def shut_down_scratch(path: str) -> None:
	'''
	f2fs_io shutdown 2 of the loop image holding path (our_mount_point()): the filesystem stops with no checkpoint, and what
	it held dirty is lost, as at a power loss. The only way a test calls f2fs_io.
	'''
	subprocess.run(['f2fs_io', 'shutdown', '2', our_mount_point(path)], check=True, stdout=subprocess.DEVNULL)


class LoopImage:
	'''
	A new f2fs of size_mib on a loop device this process attached, as f2fs_mount() has it, which can be mounted again after a shutdown.
	source, when given, is an image to start from, copied sparse, in place of a new one; mount_point, a folder of the caller's to mount it
	at, in place of one beside the image. keep, set before the end, is where the image goes then, in place of being removed.
	'''
	def __init__(self, tmp: str, size_mib: int, source: str = None, mount_point: str = None):
		self.tmp = tmp
		self.size_mib = size_mib
		self.source = source
		self.given_mount_point = mount_point
		self.keep = None

	def mount(self) -> None:
		subprocess.run(['mount', '-t', 'f2fs', '-o', F2FS_OPTIONS.removeprefix('loop,'), self.device, self.mount_point], check=True)

	def attach(self) -> None:
		'''
		The image on a loop device. losetup -f finds a free device and then sets it up, so two runs at once can find the same one and the second exits 1:
		it is tried again, a few times, as nothing of the test has begun.
		'''
		for attempt in range(ATTACH_TRIES):
			found = subprocess.run(['losetup', '-f', '--show', self.image], capture_output=True, text=True)
			if found.returncode == 0:
				break
			time.sleep(random.uniform(0.05, 0.3) * (attempt + 1))
		else:
			raise subprocess.CalledProcessError(found.returncode, found.args, found.stdout, found.stderr)
		self.device = found.stdout.strip()
		ATTACHED[self.device] = self.image

	def detach(self) -> None:
		ATTACHED.pop(self.device)
		subprocess.run(['losetup', '-d', self.device], check=True)

	def remount(self) -> None:
		'''
		The image, shut down, mounted again on a loop device of its own. A container started meanwhile holds a copy of the mount
		until it ends, which keeps the stopped filesystem alive through the umount, and a mount of the same device gets that
		one back, with no recovery and EIO from every fsync. Stopped, it writes nothing when it goes at last.
		'''
		subprocess.run(['umount', self.mount_point], check=True)
		self.detach()
		self.attach()
		self.mount()

	def __enter__(self) -> 'LoopImage':
		os.makedirs(self.tmp, exist_ok=True)
		self.work = tempfile.mkdtemp(prefix='f2fs-', dir=self.tmp)
		self.image, self.mount_point = os.path.join(os.path.realpath(self.work), 'image'), self.given_mount_point or os.path.join(self.work, 'mnt')
		self.device = None
		try:
			if self.source is not None:
				subprocess.run(['cp', '--sparse=always', self.source, self.image], check=True)
			else:
				with open(self.image, 'wb') as f:
					f.truncate(self.size_mib << 20)
				subprocess.run(['mkfs.f2fs', '-q', '-f', '-O', F2FS_FEATURES, self.image], check=True, stdout=subprocess.DEVNULL)
			os.makedirs(self.mount_point, exist_ok=True)
			self.attach()
			self.mount()
		except BaseException:
			self.__exit__()
			raise
		return self

	def __exit__(self, *_) -> None:
		try:
			if os.path.ismount(self.mount_point):
				subprocess.run(['umount', self.mount_point], check=True)
		finally:
			if self.device is not None:
				self.detach()
			if self.keep is not None:
				os.replace(self.image, self.keep)
			shutil.rmtree(self.work)
			with contextlib.suppress(OSError):
				os.rmdir(self.tmp)
