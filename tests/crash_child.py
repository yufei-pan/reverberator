'''
A batch or a retry run in a forked child that is killed before its n-th change of the job vault, as the service's
control-group kill or a power loss cuts the daemon. The child is forked from the test process (a spawn costs an import per
kill point), under isolated_runtime()'s patches: no real syncfs can reach the filesystem under the vault.

An audit hook counts each mutating call under the job vault; VaultManifest.commit and rename_exchange, which no audit
event sees, count through wrappers. The kill goes to the child's own process group, so the cp and rm it started die with it,
and the parent waits until the group is gone, so nothing races the retry.
'''
import errno
import itertools
import json
import os
import signal
import sys
import threading
import time
import traceback
from collections import Counter, namedtuple, OrderedDict

import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS, stop_fs_signature_monitor
from tests.crash_batches import OPTIONS, UNREADABLE, batch3_of

# killed: SIGKILL ended it. committed: do_backup's answer, None when it did not return. steps: the calls counted, None when
# killed. counts: {kind: calls}. error: the child's traceback, when one ended it
Outcome = namedtuple('Outcome', ['killed', 'committed', 'steps', 'counts', 'error'])

# audit event -> (kind of call, the index of the argument naming the path it changes)
MUTATING_EVENTS = {'os.rename': ('rename', 1), 'os.mkdir': ('mkdir', 0), 'os.symlink': ('symlink', 1), 'os.link': ('link', 1),
	'os.remove': ('remove', 0), 'os.rmdir': ('rmdir', 0), 'os.truncate': ('truncate', 0), 'os.chmod': ('chmod', 0),
	'os.chown': ('chown', 0), 'os.utime': ('utime', 0), 'os.setxattr': ('setxattr', 0), 'os.removexattr': ('removexattr', 0)}
# the argument naming the folder a path is relative to, for the events that take one (shutil.rmtree removes by it)
DIR_FD_ARGUMENT = {'os.rename': 3, 'os.mkdir': 2, 'os.symlink': 2, 'os.link': 3, 'os.remove': 1, 'os.rmdir': 1, 'os.chmod': 2, 'os.chown': 3, 'os.utime': 3}
WRITING_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


class KillPoints:
	'''
	Counts the mutating calls under job_vault, by kind; kills the process group before the kill_at-th, once before_kill()
	has run: a power loss model shuts the filesystem down there. flush_at, (step, call), makes that model's checkpoint: call runs
	before that step.
	'''
	def __init__(self, job_vault: str, kill_at: int = None, before_kill = None, flush_at: tuple = None):
		self.prefix = os.path.abspath(job_vault) + '/'
		self.kill_at = kill_at
		self.before_kill = before_kill
		self.flush_at = flush_at
		self.steps = itertools.count(1)
		self.lock = threading.Lock()
		self.counts = Counter()

	def step(self, kind: str) -> None:
		with self.lock:
			number = next(self.steps)
			if self.flush_at is not None and number == self.flush_at[0]:
				self.flush_at[1]()
			if number == self.kill_at:
				if self.before_kill is not None:
					self.before_kill()
				os.killpg(0, signal.SIGKILL)
			self.counts[kind] += 1

	def under_vault(self, path, dir_fd=None) -> bool:
		if isinstance(path, int):
			try:
				path = os.readlink(f'/proc/self/fd/{path}')
			except OSError:
				return False
		else:
			path = os.fsdecode(path)
			if dir_fd not in (None, -1) and not os.path.isabs(path):
				try:
					path = os.path.join(os.readlink(f'/proc/self/fd/{dir_fd}'), path)
				except OSError:
					return False
		return (os.path.abspath(path) + '/').startswith(self.prefix)

	def hook(self, event: str, args: tuple) -> None:
		if event in MUTATING_EVENTS:
			kind, at = MUTATING_EVENTS[event]
			fd_at = DIR_FD_ARGUMENT.get(event)
			if self.under_vault(args[at], None if fd_at is None else args[fd_at]):
				self.step(kind)
		elif event == 'open':
			path, _, flags = args
			if path is not None and isinstance(flags, int) and flags & WRITING_FLAGS and self.under_vault(path):
				self.step('open')
		elif event == 'subprocess.Popen':
			if any(isinstance(arg, (str, bytes)) and self.under_vault(arg) for arg in args[1]):
				self.step('Popen')

	def counted(self, kind: str, function):
		def wrapper(*args, **kwargs):
			self.step(kind)
			return function(*args, **kwargs)
		return wrapper


def failing_copy_command(real):
	'''copy_command, a copy of a name ending UNREADABLE failing as cp fails on a file it may not read: root reads any file.'''
	def command(source_path, dest_path):
		if source_path.endswith(UNREADABLE):
			message = f"cp: cannot open '{source_path}' for reading: Permission denied"
			return ['sh', '-c', 'printf "%s\\n" "$1" >&2; exit 1', 'sh', message, dest_path]
		return real(source_path, dest_path)
	return command


def enospc_at(number: int, job_vault: str) -> None:
	'''From now on in this child, the number-th link, symlink or mkdir under job_vault fails as a full disk fails it.'''
	prefix = os.path.abspath(job_vault) + '/'
	calls = itertools.count(1)
	def failing(real, at):
		def call(*args, **kwargs):
			if (os.path.abspath(os.fsdecode(args[at])) + '/').startswith(prefix) and next(calls) == number:
				raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), args[at])
			return real(*args, **kwargs)
		return call
	os.link, os.symlink, os.mkdir = failing(os.link, 1), failing(os.symlink, 1), failing(os.mkdir, 0)


def reset_module_state() -> None:
	'''The module as a process started just now has it: no thread of the parent runs here, and nothing is remembered.'''
	rv.GREEN_LIGHT.set()
	rv.RESTORE_STOP.clear()
	for remembered in (rv.VERSION_MOVES, rv.VERSION_MOVES_WARNED, rv.PRUNE_ABORTED, rv.PRUNE_SALT_MISSING, rv.VAULTS_WITH_VERSIONS,
			rv.JOB_LOCK_UNCHECKED, rv.REAL_VAULT_FOLDERS, rv.ROOT_META_TROUBLE, rv.VAULT_UNITS):
		remembered.clear()
	rv.is_version_folder_name.cache_clear()
	rv.is_previous_version_name.cache_clear()
	rv.FS_SIGNATURE_MONITOR = rv.fs_signature_monitor()
	rv.STATUS_BOARD = None
	# no thread of the parent can hold one of these here, but one could have when the fork took the copy
	rv.LOG_LOCK = threading.RLock()
	rv.REAL_VAULT_FOLDERS_LOCK = threading.Lock()
	rv.VERSION_MOVES_LOCK = threading.Lock()
	rv.BACKUP_SEMAPHORE = threading.Semaphore(2 * os.cpu_count())


def in_child(job, kill_at, work, fault=None, before_kill=None, flush_at=None, points=None) -> Outcome:
	'''
	Run work(), which gives do_backup's committed answer, in a forked child that dies before its kill_at-th mutating call
	under the job vault. fault, when given, is called in the child with the module, to patch what the run must meet;
	'enospc:<n>' makes the n-th link, symlink or mkdir under the job vault fail with ENOSPC. before_kill runs in the child
	just before it dies, flush_at as KillPoints has it. points, when given, counts in place of a KillPoints made of those.
	'''
	# a real syncfs would flush the live filesystem under /tmp: only isolated_runtime()'s fixture makes a fork safe
	assert rv.sync_vault_filesystems is not REAL_SYNC_VAULT_FILESYSTEMS, 'a kill run outside isolated_runtime()'
	# no thread of this process may be caught holding a lock by the fork
	stop_fs_signature_monitor()
	rv.GREEN_LIGHT.set()
	sys.stdout.flush()
	sys.stderr.flush()
	reader, writer = os.pipe()
	pid = os.fork()
	if pid == 0:
		try:
			os.close(reader)
			os.setpgid(0, 0)
			points = points or KillPoints(job.job_vault, kill_at, before_kill, flush_at)
			reset_module_state()
			rv.copy_command = failing_copy_command(rv.copy_command)
			rv.VaultManifest.commit = points.counted('commit', rv.VaultManifest.commit)
			if hasattr(rv, 'rename_exchange'):
				rv.rename_exchange = points.counted('exchange', rv.rename_exchange)
			if isinstance(fault, str):
				enospc_at(int(fault.partition(':')[2]), job.job_vault)
			elif fault is not None:
				fault(rv)
			sys.addaudithook(points.hook)
			committed = work()
			result = {'committed': committed, 'steps': sum(points.counts.values()), 'counts': points.counts, 'error': None}
		except BaseException:
			result = {'committed': None, 'steps': None, 'counts': {}, 'error': traceback.format_exc()}
		try:
			os.write(writer, json.dumps(result).encode())
		finally:
			# nothing of pytest's runs in the child
			os._exit(0)
	os.close(writer)
	with os.fdopen(reader, 'rb') as f:
		written = f.read()
	_, status = os.waitpid(pid, 0)
	# until the group is gone: its cp or rm could still be writing into the vault
	deadline = time.monotonic() + 30
	while True:
		try:
			os.killpg(pid, 0)
		except ProcessLookupError:
			break
		except PermissionError:
			break
		assert time.monotonic() < deadline, f'the process group of the crash child {pid} is still there'
		time.sleep(0.001)
	if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
		return Outcome(True, None, None, {}, None)
	if not written:
		return Outcome(False, None, None, {}, f'the crash child ended with no result, status {status:#x}')
	result = json.loads(written)
	return Outcome(False, result['committed'], result['steps'], result['counts'], result['error'])


def run_do_backup(job, entries, options=None, **kwargs) -> bool:
	_, manifest, committed = rv.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, **{**OPTIONS, **(options or {})}, **kwargs)
	manifest.close()
	return committed


def kill_run(job, kill_at=None, fault=None, options=None, before_kill=None, flush_at=None) -> Outcome:
	'''Batch 3, as the backuper runs a fresh batch, killed before its kill_at-th mutating call; uncut when None. options go over OPTIONS.'''
	def work():
		entries, touched = batch3_of(job)
		return run_do_backup(job, entries, options, touched=touched, matched_since=time.time_ns())
	return in_child(job, kill_at, work, fault, before_kill, flush_at)


def retry(job, kill_at=None, fault=None, options=None) -> Outcome:
	'''What the daemon's restart runs: the scan, then a full comparison and a backup of what differs.'''
	return in_child(job, kill_at, lambda: run_do_backup(job, OrderedDict(), options, matched_since=time.time_ns()), fault)
