'''
Real filesystems for the tests that need one: a loop image under REVERB_SCRATCH, which also makes it safe to flush, as nothing
else lives there. Keep REVERB_SCRATCH private; a tmpfs folder such as /dev/shm/reverb-r20-<task> keeps the live disks out of it.
'''
import contextlib
import fcntl
import itertools
import os
import random
import re
import shutil
import struct
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


# CAP_SYS_ADMIN's bit in a capability set (linux/capability.h): mount and dm need it, and root in a container lacks it
CAP_SYS_ADMIN = 21


def may_mount() -> bool:
	'''Whether this process holds CAP_SYS_ADMIN, by /proc/self/status.'''
	with open('/proc/self/status', encoding='ascii') as f:
		effective = next(line for line in f if line.startswith('CapEff:'))
	return bool(int(effective.split()[1], 16) >> CAP_SYS_ADMIN & 1)


def missing(*tools: str, scratch: bool = True, dm: bool = False) -> list:
	'''What a test of a real filesystem needs and this machine lacks, by name: a skip's reason names each, as a skip at the VM gate is a failure.'''
	lacking = ['REVERB_SCRATCH'] if scratch and not SCRATCH else []
	if os.geteuid() != 0:
		lacking.append('root')
	elif not may_mount():
		lacking.append('CAP_SYS_ADMIN')
	lacking += [tool for tool in tools if not shutil.which(tool)]
	if dm and not os.path.exists('/dev/mapper/control'):
		lacking.append('dm-mod (no /dev/mapper/control)')
	return lacking


DM_MISSING = missing('dmsetup', 'losetup', 'blockdev', 'mkfs.ext4', 'mount', 'umount', 'sync', dm=True)
needs_dm = pytest.mark.skipif(bool(DM_MISSING), reason=f'needs {", ".join(DM_MISSING)}, for ext4 on dm-linear over a loop image')
MOUNT_MISSING = missing('mount', 'umount', 'findmnt', scratch=False)
needs_mount = pytest.mark.skipif(bool(MOUNT_MISSING), reason=f'needs {", ".join(MOUNT_MISSING)}, to mount a tmpfs')


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
	'''
	A flush or a shutdown asked of anything but a loop image this test process attached under REVERB_SCRATCH; a table load, sync
	or umount of anything but the dm device or the tmpfs this test made.
	'''


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


def attach_loop(image: str) -> str:
	'''
	image on a free loop device, its path. losetup -f finds a free device and then sets it up, so two runs at once can find the
	same one and the second exits 1: it is tried again, a few times, as nothing of the test has begun.
	'''
	for attempt in range(ATTACH_TRIES):
		found = subprocess.run(['losetup', '-f', '--show', image], capture_output=True, text=True)
		if found.returncode == 0:
			return found.stdout.strip()
		time.sleep(random.uniform(0.05, 0.3) * (attempt + 1))
	raise subprocess.CalledProcessError(found.returncode, found.args, found.stdout, found.stderr)


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
		'''The image on a loop device (attach_loop()), which this process may then flush and shut down.'''
		self.device = attach_loop(self.image)
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


# FS_IOC_FIEMAP, _IOWR('f', 11, struct fiemap): struct fiemap is 32 bytes, and each struct fiemap_extent after it 56 (linux/fiemap.h)
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_HEADER, FIEMAP_EXTENT = 32, 56
# an extent with no place on the device yet: unknown, or held for delayed allocation
FIEMAP_EXTENT_UNKNOWN, FIEMAP_EXTENT_DELALLOC = 0x2, 0x4
# the extents asked for at once: a test's file of a few hundred KiB, written at once on a near-empty disk, has one or two
FIEMAP_COUNT = 64


def extents_of(path: str) -> list:
	'''[(byte offset on the device, bytes)] of the file's data by FIEMAP, with no sync first, so a dirty file keeps its pages dirty.'''
	buffer = bytearray(struct.pack('=QQIIII', 0, 2**64 - 1, 0, 0, FIEMAP_COUNT, 0) + bytes(FIEMAP_EXTENT * FIEMAP_COUNT))
	fd = os.open(path, os.O_RDONLY)
	try:
		fcntl.ioctl(fd, FS_IOC_FIEMAP, buffer)
	finally:
		os.close(fd)
	mapped = struct.unpack_from('=I', buffer, 20)[0]
	assert 0 < mapped < FIEMAP_COUNT, f'{path}: {mapped} extents'
	extents = []
	for at in range(FIEMAP_HEADER, FIEMAP_HEADER + FIEMAP_EXTENT * mapped, FIEMAP_EXTENT):
		_, physical, length = struct.unpack_from('=QQQ', buffer, at)
		flags = struct.unpack_from('=I', buffer, at + 40)[0]
		assert not flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC), f'{path}: an extent with no place yet (flags {flags:#x})'
		extents.append((physical, length))
	return extents


# the dm devices of this process are named reverb-werr-<pid>-<n>
DM_NAMES = itertools.count(1)
SECTOR = 512


class FailingDisk:
	'''
	ext4 on a dm-linear device over a loop image under REVERB_SCRATCH, mounted nodelalloc, so a file's blocks are placed at
	write(2) and FIEMAP finds them before writeback, and data=writeback, so no journal commit writes a file's data before its own
	writeback (under data=ordered an fsync of any file, the manifest's say, would). fail(extents) puts those byte ranges of the
	device on dm's error target, so their next write fails as a disk's write error does; heal() puts the plain table back.
	Everything goes at the end: the mount, the dm device, the loop device and the image. Each call that writes or syncs checks
	first that the filesystem at the mount point is on this disk's dm device.
	'''
	def __init__(self, tmp: str, size_mib: int):
		self.tmp = tmp
		self.size_mib = size_mib

	def __enter__(self) -> 'FailingDisk':
		os.makedirs(self.tmp, exist_ok=True)
		self.work = os.path.realpath(tempfile.mkdtemp(prefix='ext4-', dir=self.tmp))
		self.image, self.mount_point = os.path.join(self.work, 'image'), os.path.join(self.work, 'mnt')
		self.loop = self.name = None
		self.mounted = self.failing = False
		try:
			with open(self.image, 'wb') as f:
				f.truncate(self.size_mib << 20)
			self.loop = attach_loop(self.image)
			self.sectors = int(subprocess.run(['blockdev', '--getsz', self.loop], check=True, capture_output=True, text=True).stdout)
			name = f'reverb-werr-{os.getpid()}-{next(DM_NAMES)}'
			# no udev sync: the device's node comes from devtmpfs, by its kernel name, with or without udev
			subprocess.run(['dmsetup', 'create', '--noudevsync', name], input=self.table([]), text=True, check=True)
			self.name = name
			found = subprocess.run(['dmsetup', 'info', '-c', '--noheadings', '-o', 'major,minor', '--separator', ':', self.name], check=True, capture_output=True, text=True)
			major, minor = (int(number) for number in found.stdout.strip().split(':'))
			self.rdev = os.makedev(major, minor)
			self.device = os.path.join('/dev', os.path.basename(os.readlink(f'/sys/dev/block/{major}:{minor}')))
			assert os.stat(self.device).st_rdev == self.rdev, self.device
			subprocess.run(['mkfs.ext4', '-q', '-F', self.device], check=True, stdout=subprocess.DEVNULL)
			os.mkdir(self.mount_point)
			subprocess.run(['mount', '-t', 'ext4', '-o', 'nodelalloc,data=writeback', self.device, self.mount_point], check=True)
			self.mounted = True
			self.check(self.mount_point)
		except BaseException:
			self.__exit__()
			raise
		return self

	def check(self, path: str) -> None:
		'''NotOurLoopImage, with nothing done, unless path is under this disk's mount point and on its dm device.'''
		real = os.path.realpath(path)
		if not self.mounted or not (real + '/').startswith(self.mount_point + '/') or os.stat(real).st_dev != self.rdev:
			raise NotOurLoopImage(f'{real} is not on the dm device {self.name} this test made')

	def table(self, failing: list) -> str:
		'''The device's table: linear over the loop device, but failing, [(first sector, sectors)], on the error target.'''
		lines, at = [], 0
		for start, count in sorted(failing):
			assert start >= at and start + count <= self.sectors, (start, count)
			if start > at:
				lines.append(f'{at} {start - at} linear {self.loop} {at}')
			lines.append(f'{start} {count} error')
			at = start + count
		if at < self.sectors:
			lines.append(f'{at} {self.sectors - at} linear {self.loop} {at}')
		return '\n'.join(lines) + '\n'

	def load(self, table: str) -> None:
		'''
		table in place of the device's: suspended with no freeze of the filesystem (--nolockfs), as a freeze writes out
		everything dirty first, which is what must stay dirty until the table fails it.
		'''
		self.check(self.mount_point)
		subprocess.run(['dmsetup', 'suspend', '--nolockfs', '--noudevsync', self.name], check=True)
		try:
			subprocess.run(['dmsetup', 'load', self.name], input=table, text=True, check=True)
		finally:
			subprocess.run(['dmsetup', 'resume', '--noudevsync', self.name], check=True)

	def fail(self, extents: list) -> None:
		'''The byte ranges of extents (extents_of()) fail every write from now on, until heal().'''
		self.load(self.table([(offset // SECTOR, -(-length // SECTOR)) for offset, length in extents]))
		self.failing = True

	def heal(self) -> None:
		self.load(self.table([]))
		self.failing = False

	def sync_elsewhere(self) -> int:
		'''Another program's syncfs of this disk, by sync -f: its exit status, 1 when the sync met a write error.'''
		self.check(self.mount_point)
		return subprocess.run(['sync', '-f', self.mount_point], stderr=subprocess.DEVNULL).returncode

	def syncfs(self, fd: int) -> int:
		'''The real syncfs(2) binding (conftest's REAL_LIBC_SYNCFS), of an fd on this disk only: as rv.LIBC_SYNCFS, the product's syncs.'''
		from tests.conftest import REAL_LIBC_SYNCFS
		assert os.fstat(fd).st_dev == self.rdev, f'fd {fd} ({os.readlink(f"/proc/self/fd/{fd}")}) is not on the dm device {self.name}'
		return REAL_LIBC_SYNCFS(fd)

	def __exit__(self, *_) -> None:
		try:
			try:
				if self.failing:
					self.heal()
			finally:
				if self.mounted:
					self.check(self.mount_point)
					subprocess.run(['umount', self.mount_point], check=True)
					self.mounted = False
		finally:
			try:
				if self.name is not None:
					subprocess.run(['dmsetup', 'remove', '--noudevsync', '--retry', self.name], check=True)
			finally:
				if self.loop is not None:
					subprocess.run(['losetup', '-d', self.loop], check=True)
				shutil.rmtree(self.work)
				with contextlib.suppress(OSError):
					os.rmdir(self.tmp)


# the tmpfs mounts of this process are named reverb-test-<pid>-<n>
TMPFS_NAMES = itertools.count(1)


class ScratchTmpfs:
	'''
	A tmpfs of its own at folder, as a disk at its mount point (root only). swap() puts a new one there, as a disk swapped at
	its mount point: the old one leaves by umount -l and lives on while a handle holds it. Each umount checks first that the
	mount at folder is this one's, by its source name, and the end leaves nothing of it mounted.
	'''
	def __init__(self, folder: str):
		self.folder = os.path.realpath(folder)
		self.source = None

	def mount(self) -> None:
		os.makedirs(self.folder, exist_ok=True)
		self.source = f'reverb-test-{os.getpid()}-{next(TMPFS_NAMES)}'
		# a few small files: a tmpfs takes only what it holds
		subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=64m', self.source, self.folder], check=True)

	def unmount(self) -> None:
		found = subprocess.run(['findmnt', '-n', '-r', '-o', 'SOURCE', '--mountpoint', self.folder], capture_output=True, text=True)
		if found.returncode != 0 or found.stdout.split()[-1:] != [self.source]:
			raise NotOurLoopImage(f'the mount at {self.folder} is {found.stdout.strip()!r}, not the tmpfs {self.source} this test mounted')
		subprocess.run(['umount', '-l', self.folder], check=True)
		self.source = None

	def swap(self) -> None:
		self.unmount()
		self.mount()

	def __enter__(self) -> 'ScratchTmpfs':
		self.mount()
		return self

	def __exit__(self, *_) -> None:
		if self.source is not None:
			self.unmount()
