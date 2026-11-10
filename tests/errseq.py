'''
The kernel's rule for writeback errors, at the syncfs(2) binding (rv.LIBC_SYNCFS), for the tests of what a vault sync hears.
Linux keeps a filesystem's newest writeback error in its superblock (sb->s_wb_err, lib/errseq.c): an error moves its counter
on only once someone has seen the one before it (errseq_set()), an open samples it into the file (do_dentry_open():
errseq_sample() gives 0 while no one has seen the newest error, so the file's first check reports it), and a syncfs reports
what changed since its file's sample and marks it seen (fs/sync.c). So a syncfs reports an error once to each file that was
open when it happened, and to one opened later only while no syncfs has seen it. Read in the kernel's source, not run: the
VM's real write error test (tests/test_vault_write_error.py) checks the rule on the kernel.

One model per filesystem, by st_dev. os.open and os.close are wrapped on the os module, which the product shares, so each fd
it opens is sampled at its open and forgotten at its close; an fd never seen opened samples at its first syncfs.
'''
import ctypes
import errno
import os
import stat
import threading

import reverberator as rv


class Errseq:
	def __init__(self, monkeypatch):
		# st_dev: [counter, whether the newest error was seen]
		self.filesystems = {}
		# fd: its sample of its filesystem's counter
		self.cursors = {}
		# ('open', path, fd) for each folder os.open gave, ('close', fd) for each fd closed, ('syncfs', fd, the path it is open on,
		# st_dev, errno or 0) for each syncfs, in order
		self.events = []
		self.lock = threading.Lock()
		real_open, real_close = os.open, os.close

		def opened(path, flags, *args, **kwargs):
			fd = real_open(path, flags, *args, **kwargs)
			self.sample(fd)
			if flags & os.O_DIRECTORY:
				self.events.append(('open', os.fsdecode(path), fd))
			return fd

		def closed(fd):
			with self.lock:
				if self.cursors.pop(fd, None) is not None:
					self.events.append(('close', fd))
			return real_close(fd)
		monkeypatch.setattr(os, 'open', opened)
		monkeypatch.setattr(os, 'close', closed)
		monkeypatch.setattr(rv, 'LIBC_SYNCFS', self.syncfs)

	def state(self, dev:int) -> list:
		return self.filesystems.setdefault(dev, [0, True])

	def sample(self, fd:int) -> None:
		try:
			dev = os.fstat(fd).st_dev
		except OSError:
			return
		with self.lock:
			counter, seen = self.state(dev)
			self.cursors[fd] = counter if seen else 0

	def fail(self, path:str) -> None:
		'''A writeback error on the filesystem holding path, which no one has seen.'''
		with self.lock:
			state = self.state(os.stat(path).st_dev)
			if state[1]:
				state[0] += 1
			state[1] = False

	def seen_elsewhere(self, path:str) -> None:
		'''Another program's syncfs of the filesystem holding path: its newest error is seen.'''
		with self.lock:
			self.state(os.stat(path).st_dev)[1] = True

	def syncfs(self, fd:int) -> int:
		try:
			st = os.fstat(fd)
		except OSError as e:
			ctypes.set_errno(e.errno)
			return -1
		if fd not in self.cursors:
			self.sample(fd)
		with self.lock:
			state = self.state(st.st_dev)
			code = 0
			if self.cursors[fd] != state[0]:
				state[1] = True
				self.cursors[fd] = state[0]
				code = errno.EIO
			self.events.append(('syncfs', fd, fd_path(fd), st.st_dev, code))
		if code:
			ctypes.set_errno(code)
			return -1
		return 0

	def synced(self) -> list:
		'''(path the fd is open on, errno or 0) of each syncfs, in order.'''
		return [(path, code) for _, _, path, _, code in (event for event in self.events if event[0] == 'syncfs')]


def fd_path(fd:int) -> str:
	'''The path an fd is open on, as /proc says it.'''
	try:
		return os.readlink(f'/proc/self/fd/{fd}')
	except OSError:
		return f'fd {fd}'


def open_folders(path:str) -> list:
	'''The fds of this process open on the folder at path, or on one below it: what a unit left open.'''
	real = os.path.realpath(path)
	found = []
	for name in os.listdir('/proc/self/fd'):
		try:
			target = os.readlink(f'/proc/self/fd/{name}')
			if (target == real or target.startswith(real + '/')) and stat.S_ISDIR(os.stat(f'/proc/self/fd/{name}').st_mode):
				found.append(target)
		except OSError:
			continue
	return found
