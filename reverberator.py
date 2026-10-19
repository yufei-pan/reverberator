#! /usr/bin/env python3
import multiCMD
import TSVZ
import inotify_simple
import Tee_Logger
import argparse
import xxhash
import pathspec

from collections import deque
from collections import Counter
import time
from collections import namedtuple
from collections import OrderedDict
import os
import threading
import functools
import sys
import signal
import resource
import datetime
import unicodedata
import re
import glob
import select
import contextlib
import sqlite3
import tempfile
import stat
import errno
import fcntl
import marshal
import zlib
from concurrent.futures import Future, ThreadPoolExecutor
import shutil
import uuid
from shutil import copystat

# for the lib wrapping aroung inotify, I tried
# wtr-wather, watchdog, watchfiles
# None of them seem to work well with the most basic tests
# I need it to work with:
# 1. able to notice changes recursively
# 2. able to notice changes in the folders
# 3. do not incorrectly group move events
# 4. recognize mkdir -p properly
# 5. notice umount events and notify properly
# 6. notice mount events and notify properly
# 7. compatible with symlink events 


__version__ = 0.37

## WIP

# @dataclass
# class ChangeEvent:
# 	monotonic_time:float
# 	# type can be file or dir.
# 	type:str
# 	# if type is dir, event can be create 
# 	#  ( need to recursively copy everything as inotifywait does not caputre mkdir -p properly for all sub folders),
# 	#  ,delete, attrib, move
# 	# if type is file, event can be delete, change, attrib, move
# 	# move detection will be handled by monitor if moved_from moved_to events were captured. 
# 	# it will use an tsv storing all the path inode number and hash to detect move.
# 	event:str
# 	path:str
# 	moved_from:str = None


# if type is dir, event can be create 
#  ( need to recursively copy everything as inotifywait does not caputre mkdir -p properly for all sub folders),
#  ,delete, attrib, move
# if type is file, event can be delete, change, attrib, move
# move detection will be handled by monitor if moved_from moved_to events were captured. 
# it will use an tsv storing all the path inode number and hash to detect move.
CHANGED_EVENT_HEADER = ['monotonic_time', 'is_dir', 'event', 'path','moved_from']
BACKUP_ENTRY_VALUES_HEADER = ['iso_time','event','source_path']
BACKUP_JOURNAL_HEADER = ['at_path','iso_time','event','source_path']
REVERB_RULE_TSV_HEADER = ['Job Name (Unique Key)', 'Path Monitoring', 'Vault Path','Monitoring File System Signature', 
		'Minium snapshot interval', 'Maximum snapshot interval','Keep 1 Compelete Backup', 
		'Only Sync Attributes (permissions)', 'Keep N versions', 'Backup Size Limit', 
		'Vault File System Signature', 'Skip List File']
REVERB_RULE_HEADER = ['job_name', 'mon_path','vault_path', 'mon_fs_signature', 
		'min_shapshot_time','max_shapshot_time' , 'keep_one_complete_backup', 
		'only_sync_attributes', 'keep_n_versions', 'backup_size_limit',
		'vault_fs_signature', 'skip_list_file']
SKIP_LIST_COLUMN_DESCRIPTIONS = ('A gitignore style list of paths not to back up, matched relative to the monitored path', 'Relative paths resolve against the rule file folder. Once a job has used patterns, set none to back up everything')
VAULT_ENTRY_HEADER = ['version_number','path','timestamp','size','inode']
VAULT_INFO_HEADER = ['vault_info_dict', 'vault_size' , 'vault_inodes']
VAULT_TIMESTAMP_FORMAT = '%Y-%m-%d_%H-%M-%S_%z'
MANIFEST_RECORD_HEADER = ['kind','size','mtime_ns','mode','uid','gid','hash','link','unchecked']

CONTENT_FILE_EXTENSION_NAME = '.modified_contents.nsv'
PENDING_TRANSACTIONS_FILE_NAME = '.reverberator_pending_transactions.nsv'
MANIFEST_FILE_NAME = '.reverberator_manifest.sqlite'

ChangeEvent = namedtuple('ChangeEvent', CHANGED_EVENT_HEADER)
BackupEntryValues = namedtuple('BackupEntryValues', BACKUP_ENTRY_VALUES_HEADER)

def strip_suffix(s, suffix):
	'''
	Remove a trailing suffix when present.

	Examples:
		>>> strip_suffix('hello.txt', '.txt')
		'hello'
		>>> strip_suffix('hello', '.txt')
		'hello'
		>>> strip_suffix('hello.txt', '')
		'hello.txt'
	'''
	return s[:-len(suffix)] if suffix and s.endswith(suffix) else s

def strip_prefix(s, prefix):
	'''
	Remove a leading prefix when present.

	Examples:
		>>> strip_prefix('V12--2026-01-01', 'V')
		'12--2026-01-01'
		>>> strip_prefix('hello', 'V')
		'hello'
		>>> strip_prefix('hello', '')
		'hello'
	'''
	return s[len(prefix):] if prefix and s.startswith(prefix) else s

def as_folder_entry(rel_path:str) -> str:
	'''
	Normalize a relative folder path for tracking sets (always ends with '/').

	Examples:
		>>> as_folder_entry('foo')
		'foo/'
		>>> as_folder_entry('foo/')
		'foo/'
		>>> as_folder_entry('a/b')
		'a/b/'
	'''
	# tracking sets store folder entries with a trailing slash; normalize to that convention
	return rel_path if rel_path.endswith('/') else rel_path + '/'

def read_memory_state(proc_root:str = '/proc', cgroup_root:str = '/sys/fs/cgroup') -> tuple:
	'''
	(available bytes, total bytes, stall percent): the tighter of the machine and the limits of this process's cgroups,
	and the largest share of the last minute their tasks spent stalled waiting for memory. What cannot be read is None.

	Examples:
		>>> available, total, stall = read_memory_state()
		>>> available is None or 0 <= available <= total
		True
	'''
	available = total = stall = None
	try:
		meminfo = {}
		with open(os.path.join(proc_root, 'meminfo')) as f:
			for line in f:
				name, _, value = line.partition(':')
				if value.split():
					meminfo[name] = int(value.split()[0]) * 1024
		available, total = meminfo['MemAvailable'], meminfo['MemTotal']
	except (OSError, KeyError, ValueError):
		pass
	pressure_files = [os.path.join(proc_root, 'pressure', 'memory')]
	try:
		with open(os.path.join(proc_root, 'self', 'cgroup')) as f:
			cgroup_path = next((line[3:].strip() for line in f if line.startswith('0::')), None)
	except OSError:
		cgroup_path = None
	if cgroup_path is not None:
		# a limit on any cgroup up the tree applies to this process too
		parts = [part for part in cgroup_path.split('/') if part]
		for depth in range(len(parts), -1, -1):
			cgroup = os.path.join(cgroup_root, *parts[:depth])
			pressure_files.append(os.path.join(cgroup, 'memory.pressure'))
			try:
				limits = []
				for name in ('memory.max', 'memory.high'):
					try:
						with open(os.path.join(cgroup, name)) as f:
							value = f.read().strip()
					except FileNotFoundError:
						continue
					if value.isdigit():
						limits.append(int(value))
				if limits:
					with open(os.path.join(cgroup, 'memory.current')) as f:
						headroom = max(min(limits) - int(f.read()), 0)
					if available is None or headroom < available:
						available, total = headroom, min(limits)
			except (OSError, ValueError):
				pass
	for path in pressure_files:
		try:
			with open(path) as f:
				for line in f:
					if line.startswith('some '):
						for field in line.split()[1:]:
							name, _, value = field.partition('=')
							if name == 'avg60':
								stall = max(stall or 0.0, float(value))
		except (OSError, ValueError):
			pass
	return available, total, stall

class ChangeEventQueue:
	'''
	A job's change events waiting for the backuper, oldest first. Callers hold the job's to_process_lock.

	Events are kept zlib compressed in blocks of QUEUE_BLOCK_EVENTS. As the queue grows, it drops the modify and attrib
	events the backup conversion would skip anyway, and once longer than QUEUE_KEEP_EVENTS it becomes one full scan
	when memory runs short. A queued full scan absorbs every later event, as the backuper compares the whole tree for it.
	A 'scan' event (compare that one folder with the vault) is kept like any other event.

	Examples:
		>>> queue = ChangeEventQueue('/m')
		>>> for t in range(3):
		...     queue.append(ChangeEvent(float(t), False, 'modify', '/m/log', None))
		>>> queue.append(ChangeEvent(3.0, False, 'create', '/m/new', None))
		>>> queue.append(ChangeEvent(3.5, True, 'scan', '/m/disk', None))
		>>> queue.compact()
		>>> [(event.monotonic_time, event.event) for event in queue]
		[(2.0, 'modify'), (3.0, 'create'), (3.5, 'scan')]
		>>> taken = queue.take()
		>>> (len(taken), len(queue))
		(3, 0)
		>>> queue.append(ChangeEvent(4.0, False, 'full_scan', '/m', None))
		>>> queue.append(ChangeEvent(5.0, False, 'modify', '/m/log', None))
		>>> [event.event for event in queue]
		['full_scan']
	'''
	def __init__(self, monitor_path:str = ''):
		self.monitor_path = monitor_path
		self.clear()

	def clear(self):
		# (event count, zlib compressed marshal of the events' fields), oldest first
		self._blocks = []
		# the newest events, not packed yet
		self._recent = []
		self._count = 0
		self._packed_bytes = 0
		self._full_scan = None
		self._compact_at = QUEUE_COMPACT_EVENTS
		self._next_memory_check = 0.0

	def __len__(self):
		return self._count

	def __bool__(self):
		return self._count > 0

	@property
	def full_scan_requested(self) -> bool:
		return self._full_scan is not None

	def nbytes(self) -> int:
		'''Roughly how much memory the queued events take.'''
		return self._packed_bytes + len(self._recent) * QUEUED_EVENT_BYTES

	def __iter__(self):
		if self._full_scan is not None:
			yield self._full_scan
			return
		for _, block in self._blocks:
			for fields in marshal.loads(zlib.decompress(block)):
				yield ChangeEvent(*fields)
		yield from self._recent

	def __reversed__(self):
		if self._full_scan is not None:
			yield self._full_scan
			return
		yield from reversed(self._recent)
		for _, block in reversed(self._blocks):
			for fields in reversed(marshal.loads(zlib.decompress(block))):
				yield ChangeEvent(*fields)

	@staticmethod
	def _pack(events) -> tuple:
		# marshal only ever reads back blocks this queue packed in memory, never data from a file or another process
		return len(events), zlib.compress(marshal.dumps([tuple(event) for event in events]), 1)

	def append(self, event:ChangeEvent):
		if self._full_scan is not None:
			# the backuper compares the whole tree for a full scan, which covers this event
			return
		if event.event == 'full_scan':
			self.clear()
			self._full_scan = event
			self._count = 1
			return
		self._recent.append(event)
		self._count += 1
		if len(self._recent) >= QUEUE_BLOCK_EVENTS:
			block = self._pack(self._recent)
			self._blocks.append(block)
			self._packed_bytes += len(block[1])
			self._recent = []
		if self._count >= self._compact_at:
			# compacting holds every distinct path it meets: check memory first, and wait while it would not fit
			if self._count > QUEUE_KEEP_EVENTS and self._give_up_if_memory_short():
				return
			if self._count <= QUEUE_KEEP_EVENTS or self._compaction_fits():
				self.compact()
			else:
				self._compact_at = 2 * self._count
		if self._count > QUEUE_KEEP_EVENTS and time.monotonic() >= self._next_memory_check:
			self._give_up_if_memory_short()

	def _give_up_if_memory_short(self) -> bool:
		'''Replace the queue with one full scan when memory is short, and say whether it did.'''
		self._next_memory_check = time.monotonic() + MEMORY_CHECK_SECONDS
		reason = self._memory_short()
		if reason:
			watcherTeeLogToTl(self.monitor_path,f'{self._count} events queued and {reason}: replacing them with a full scan',error=True)
			self.append(ChangeEvent(time.monotonic(),False,'full_scan',self.monitor_path,None))
		return bool(reason)

	def _compaction_fits(self) -> bool:
		available, _, _ = read_memory_state()
		return available is None or self._count * COMPACTION_EVENT_BYTES <= available * QUEUE_MEMORY_SHARE

	def prepend(self, events):
		'''Put events back in front of the queue, as a backup that did not commit hands its batch back.'''
		if self._full_scan is not None:
			return
		events = list(events)
		for event in events:
			if event.event == 'full_scan':
				self.append(event)
				return
		blocks = [self._pack(events[i:i + QUEUE_BLOCK_EVENTS]) for i in range(0, len(events), QUEUE_BLOCK_EVENTS)]
		self._blocks[:0] = blocks
		self._packed_bytes += sum(len(block) for _, block in blocks)
		self._count += len(events)

	def take(self) -> 'ChangeEventQueue':
		'''Move every queued event into a new queue and empty this one, as the backuper takes its batch.'''
		taken = ChangeEventQueue(self.monitor_path)
		taken._blocks, taken._recent, taken._count = self._blocks, self._recent, self._count
		taken._packed_bytes, taken._full_scan = self._packed_bytes, self._full_scan
		self.clear()
		return taken

	def compact(self):
		'''
		Drop each modify or attrib event whose path's next event is the same kind, unless a later move takes the path
		as its source: the backup conversion keeps only the last of such a run, so the batch converts the same.
		'''
		drop = bytearray(self._count)
		next_touch = {}
		later_move_sources = set()
		index = self._count
		for event in reversed(self):
			index -= 1
			# keyed like change_events_to_backup_entries keys its entries
			path = os.path.abspath(event.path) + ('/' if event.is_dir else '')
			if event.event in ('modify','attrib') and next_touch.get(path) == event.event and path not in later_move_sources:
				drop[index] = 1
				continue
			next_touch[path] = event.event if event.moved_from is None else 'move'
			if event.moved_from is not None:
				source = os.path.abspath(event.moved_from) + ('/' if event.is_dir else '')
				next_touch[source] = 'move'
				later_move_sources.add(source)
		dropped = drop.count(1)
		if dropped:
			# packed again a block at a time, so compacting never holds every event unpacked
			blocks = []
			batch = []
			for event, gone in zip(self, drop):
				if not gone:
					batch.append(event)
					if len(batch) == QUEUE_BLOCK_EVENTS:
						blocks.append(self._pack(batch))
						batch = []
			self._blocks, self._recent = blocks, batch
			self._packed_bytes = sum(len(block) for _, block in blocks)
			self._count -= dropped
		self._compact_at = max(QUEUE_COMPACT_EVENTS, 2 * self._count)

	def _memory_short(self) -> str:
		'''Why memory is too short to keep queueing events, or '' when it is not.'''
		available, total, stall = read_memory_state()
		if stall is not None and stall >= MEMORY_STALL_PERCENT:
			return f'tasks stalled on memory {stall:.0f}% of the last minute'
		if available is not None and total:
			if available < total * MEMORY_LOW_FRACTION:
				return f'only {format_bytes(available,use_1024_bytes=True,to_str=True)}B of memory is available'
			held = self.nbytes()
			if held > (available + held) * QUEUE_MEMORY_SHARE:
				return f'they hold {format_bytes(held,use_1024_bytes=True,to_str=True)}B of {format_bytes(available + held,use_1024_bytes=True,to_str=True)}B available'
		return ''

def append_change_event(to_process:ChangeEventQueue, to_process_lock:threading.Lock, event:ChangeEvent):
	with to_process_lock:
		to_process.append(event)

class SkipList:
	'''A gitignore-style list of paths below a monitored folder that are not backed up.
	Patterns match paths relative to the monitored folder, folders carrying a trailing "/". The monitored folder itself is never skipped.'''
	def __init__(self, monitor_path:str, lines=(), source:str = ''):
		self.monitor_path = monitor_path
		self.source = source
		try:
			self._spec = pathspec.GitIgnoreSpec.from_lines(lines)
		except re.error as error:
			# a pattern pathspec accepts can still compile to a bad regex, such as the reversed range in [z-a]
			raise ValueError(f'Invalid skip pattern: {error}') from error
		# comments and blank lines compile to no pattern, so they never reach the fingerprint
		self.patterns = [p.pattern for p in self._spec.patterns if p.include is not None]
		self.fingerprint = xxhash.xxh64('\n'.join(self.patterns).encode('utf-8')).hexdigest() if self.patterns else ''
		self.location_dependent = any(self._location_dependent(p) for p in self.patterns)

	@classmethod
	def load(cls, monitor_path:str, path:str):
		'''Read a skip list file; OSError and ValueError (bad pattern, bad regex or encoding) propagate.'''
		with open(path, 'r', encoding='utf-8-sig') as f:
			# universal newlines already turned CR and CRLF into LF; splitlines() would also split on form feeds and the like
			return cls(monitor_path, f.read().split('\n'), path)

	@staticmethod
	def _location_dependent(pattern:str) -> bool:
		'''Whether a pattern depends on where an entry sits, not only on its own name.
		>>> [SkipList._location_dependent(p) for p in ['*.tmp','**/cache/','!keep','/top','a/b','!/top','a/**']]
		[False, False, False, True, True, True, True]
		'''
		if pattern.startswith('!'):
			pattern = pattern[1:]
		while pattern.startswith('**/'):
			pattern = pattern[3:]
		if pattern.endswith('/'):
			pattern = pattern[:-1]
		return '/' in pattern

	def __bool__(self) -> bool:
		return bool(self.patterns)

	def skips(self, rel:str) -> bool:
		'''Whether a root-relative path (trailing "/" for folders) is skipped.
		Callers guarantee its parent folder is not skipped, so only the entry itself is checked.'''
		if rel in ('', '/') or not self.patterns:
			return False
		return self._spec.match_file(rel)

	def skips_path(self, path:str, is_dir:bool) -> bool:
		'''Like skips() for an absolute path; the root and paths outside it are never skipped.'''
		if not self.patterns:
			return False
		root = self.monitor_path.rstrip('/')
		path = path.rstrip('/')
		if not path.startswith(root + '/'):
			return False
		return self.skips(path[len(root) + 1:] + ('/' if is_dir else ''))

	def folder_rel(self, folder_path:str) -> str:
		'''The root-relative path of a folder with a trailing "/", or "" for the root.'''
		root = self.monitor_path.rstrip('/')
		folder_path = folder_path.rstrip('/')
		if folder_path == root:
			return ''
		return folder_path[len(root) + 1:] + '/'

def skip_list_change(recorded, current:str, explicit_none:bool) -> str:
	'''Compare a job's recorded skip list fingerprint (None when never recorded) with the current one.
	Dropping a recorded list needs an explicit "none" so a missing or empty file cannot silently back up everything.
	>>> skip_list_change(None, '', False), skip_list_change('a', 'a', False)
	('unchanged', 'unchanged')
	>>> skip_list_change(None, 'a', False), skip_list_change('a', 'b', True)
	('changed', 'changed')
	>>> skip_list_change('a', '', False), skip_list_change('a', '', True)
	('refuse', 'changed')
	'''
	if recorded is None:
		return 'unchanged' if current == '' else 'changed'
	if recorded == current:
		return 'unchanged'
	if current == '' and not explicit_none:
		return 'refuse'
	return 'changed'

class JobStartup:
	'''
	Loads a job's skip list once, after its filesystems are ready, and shares it between the job's two threads.
	The backuper loads it and sets loaded either way; the watcher waits for loaded before adding any watch, and sets
	watching once its watches are in place, so the backuper decides on resuming pending transactions after both.
	'''
	def __init__(self, job_name:str, monitor_path:str, skip_list_path:str = None, explicit_none:bool = False):
		self.job_name = job_name
		self.monitor_path = monitor_path
		self.skip_list_path = skip_list_path
		self.explicit_none = explicit_none
		self.skip_list = None
		# 'unchanged' or 'changed' against the fingerprint recorded in the vault, once loaded
		self.change = None
		self.failed = False
		# once load failed: why, and whether only a config change can fix it (so the job is not retried)
		self.failure_reason = None
		self.permanent = False
		self.loaded = threading.Event()
		self.watching = threading.Event()

	def load(self, recorded_fingerprint) -> bool:
		'''Load the list and compare it with the vault's recorded fingerprint; False when the job must not run.'''
		ok = False
		try:
			try:
				if self.skip_list_path is None:
					skip_list = SkipList(self.monitor_path)
				else:
					skip_list = SkipList.load(self.monitor_path, self.skip_list_path)
			except (OSError, ValueError) as e:
				# a missing or unreadable file may be on a disk still on its way; an undecodable file or a bad pattern
				# (ValueError, UnicodeDecodeError among them) needs a config change
				self.permanent = isinstance(e, ValueError)
				self.failure_reason = f'cannot load skip list file {self.skip_list_path}: {e}'
				backuperTeeLogToTl(self.job_name,f'Cannot load skip list file {self.skip_list_path} for job {self.job_name}: {e}. Not backing up this job',error=True)
				return False
			self.change = skip_list_change(recorded_fingerprint, skip_list.fingerprint, self.explicit_none)
			if self.change == 'refuse':
				reason = f'{self.skip_list_path} has no patterns' if self.skip_list_path is not None else 'its Skip List File names no file'
				self.permanent = True
				self.failure_reason = f'backed up with skip patterns, but {reason}: set its Skip List File to none to back up everything'
				backuperTeeLogToTl(self.job_name,f'Job {self.job_name} was backed up with skip patterns, but {reason}. Not backing up this job: set its Skip List File to none to back up everything',error=True)
				return False
			self.skip_list = skip_list
			if self.skip_list_path is not None:
				source = self.skip_list_path
			else:
				source = 'Skip List File none' if self.explicit_none else 'no Skip List File'
			backuperTeeLogToTl(self.job_name,f'Skip list: {len(skip_list.patterns)} patterns from {source}',ok=True)
			ok = True
			return True
		except Exception as e:
			# without a JobControl the backuper stops every job on an error it catches, so anything else fails only this
			# one here; it is not permanent, as nothing says a config change would fix it
			import traceback
			self.failure_reason = f'unexpected error loading skip list file {self.skip_list_path}: {type(e).__name__}: {e}'
			backuperTeeLogToTl(self.job_name,f'Unexpected error loading skip list file {self.skip_list_path} for job {self.job_name}. Not backing up this job\n{traceback.format_exc()}',error=True)
			return False
		finally:
			# the watcher reads failed once loaded is set, so an unexpected error counts as a failure too
			self.failed = not ok
			self.loaded.set()

class JobFailure(Exception):
	'''Why a job cannot go on. Permanent failures need a config change, so the job is not retried.'''
	def __init__(self, reason:str, permanent:bool = False):
		super().__init__(reason)
		self.reason = reason
		self.permanent = permanent

class JobControl:
	'''
	One job's state across its attempts, shared by its watcher and backuper.
	The threads report a failure here instead of clearing GREEN_LIGHT, so only this job stops; the first failure of an
	attempt is the one kept. committed is set once the attempt has committed a backup.
	'''
	def __init__(self, job_name:str):
		self.job_name = job_name
		self.running = threading.Event()
		self.failure = None
		self.committed = threading.Event()
		self._lock = threading.Lock()

	def start_attempt(self):
		with self._lock:
			self.failure = None
			self.committed.clear()
			self.running.set()

	def fail(self, reason:str, permanent:bool = False):
		with self._lock:
			if self.failure is None:
				self.failure = JobFailure(reason, permanent)
			self.running.clear()

	def should_run(self) -> bool:
		return GREEN_LIGHT.is_set() and self.running.is_set()

	def mark_committed(self):
		self.committed.set()

def job_log(job_name:str, text:str) -> str:
	'''Log a job's marker line at error level, where log alerts look for it, and return it.'''
	line = f'reverberator job {job_name} {text}'
	tl.teeerror(line)
	return line

def daemon_error_log(reason:str) -> str:
	'''Log the marker line for the daemon exiting on an error at error level, and return it.'''
	line = f'reverberator EXITING with error: {reason}'
	tl.teeerror(line)
	return line

ReverbRule = namedtuple('ReverbRule', REVERB_RULE_HEADER)
VaultEntry = namedtuple('VaultEntry', VAULT_ENTRY_HEADER)
VaultInfo = namedtuple('VaultInfo', VAULT_INFO_HEADER)
ManifestRecord = namedtuple('ManifestRecord', MANIFEST_RECORD_HEADER)
# a copy queued on an executor, which finish_copies() puts in place
PendingCopy = namedtuple('PendingCopy', ['task', 'source_path', 'temp_path', 'dest_path'])

# by defualt, set the max backup threads to 2* the number of cores
BACKUP_SEMAPHORE = threading.Semaphore(2*os.cpu_count())

DEFAULT_SNAPSHOT_DELAY = 60
DEFAULT_MAX_DELAY = 86400
DEFAULT_KEEP_ONE_COMPLETE_BACKUP = True
DEFAULT_ONLY_SYNC_ATTRIBUTES = True
DEFAULT_KEEP_N_VERSIONS = 0
DEFAULT_BACKUP_SIZE_LIMIT = '5%'

DEFAULT_POLL_WAIT_SECONDS = 3.0
POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS

def apply_poll_wait_from_env():
	'''Set POLL_WAIT_SECONDS from REVERB_POLL_WAIT_SECONDS. Invalid/missing → 3.0.'''
	global POLL_WAIT_SECONDS
	raw = os.environ.get('REVERB_POLL_WAIT_SECONDS')
	if raw is None or not str(raw).strip():
		POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS
		return POLL_WAIT_SECONDS
	try:
		POLL_WAIT_SECONDS = float(raw)
	except (TypeError, ValueError):
		POLL_WAIT_SECONDS = DEFAULT_POLL_WAIT_SECONDS
	return POLL_WAIT_SECONDS

apply_poll_wait_from_env()

MOVE_PAIR_TIMEOUT_SECONDS = 30

# a failed job waits JOB_RETRY_FIRST_SECONDS before its next attempt, twice as long after each failure in a row up to
# JOB_RETRY_MAX_SECONDS, and starts over once an attempt ran JOB_RETRY_RESET_SECONDS before failing
DEFAULT_JOB_RETRY_FIRST_SECONDS = 60
DEFAULT_JOB_RETRY_MAX_SECONDS = 3600
JOB_RETRY_FIRST_SECONDS = DEFAULT_JOB_RETRY_FIRST_SECONDS
JOB_RETRY_MAX_SECONDS = DEFAULT_JOB_RETRY_MAX_SECONDS
JOB_RETRY_RESET_SECONDS = 3600
# a job waiting for a disk or path logs nothing for DISK_WAIT_GRACE_SECONDS, then an alert every DISK_WAIT_REPEAT_SECONDS
DEFAULT_DISK_WAIT_GRACE_SECONDS = 900
DISK_WAIT_GRACE_SECONDS = DEFAULT_DISK_WAIT_GRACE_SECONDS
DISK_WAIT_REPEAT_SECONDS = 3600
# the filesystem signature monitor re-checks a pair that failed this often, as a re-created path changes no mount
FS_RECHECK_SECONDS = 60
# the exit status when every job is stopped: only a rule or skip list fix helps, so systemd is told not to restart
EXIT_ALL_STOPPED = 3

def env_seconds(name:str, default:float) -> float:
	'''Seconds from the environment variable name. Missing, unparsable, not above 0 or infinite → default.'''
	try:
		value = float(os.environ[name])
	except (KeyError, ValueError):
		return default
	return value if 0 < value < float('inf') else default

def apply_job_timing_from_env():
	'''Set the job retry timing from REVERB_JOB_RETRY_FIRST_SECONDS and REVERB_JOB_RETRY_MAX_SECONDS. Invalid/missing → the defaults.'''
	global JOB_RETRY_FIRST_SECONDS
	global JOB_RETRY_MAX_SECONDS
	global DISK_WAIT_GRACE_SECONDS
	JOB_RETRY_FIRST_SECONDS = env_seconds('REVERB_JOB_RETRY_FIRST_SECONDS', DEFAULT_JOB_RETRY_FIRST_SECONDS)
	JOB_RETRY_MAX_SECONDS = env_seconds('REVERB_JOB_RETRY_MAX_SECONDS', DEFAULT_JOB_RETRY_MAX_SECONDS)
	DISK_WAIT_GRACE_SECONDS = env_seconds('REVERB_DISK_WAIT_GRACE_SECONDS', DEFAULT_DISK_WAIT_GRACE_SECONDS)

apply_job_timing_from_env()

def job_retry_delay(failures:int) -> float:
	'''
	Seconds before the next attempt of a job that failed this many attempts in a row.

	Examples:
		>>> [job_retry_delay(n) for n in (1, 2, 3, 7, 8)] == [60, 120, 240, 3600, 3600]
		True
	'''
	# the exponent stops growing long after the cap is reached, so months of failures cannot overflow a float
	return min(JOB_RETRY_FIRST_SECONDS * 2 ** min(failures - 1, 64), JOB_RETRY_MAX_SECONDS)

MOUNTINFO_PATH = '/proc/self/mountinfo'

ARG_MAX = os.sysconf('SC_ARG_MAX')
ARGUMENT_LIMIT = (ARG_MAX - 4096) // 2048

COOKIE_DICT_MAX_SIZE = 16384
# queued change events are kept zlib compressed in blocks of this many, about 15 bytes an event instead of about 210
QUEUE_BLOCK_EVENTS = 4096
QUEUED_EVENT_BYTES = 210
# compacting holds about this much per queued event at most, and writing pending transactions out about this much per row
COMPACTION_EVENT_BYTES = 250
PENDING_ROW_BYTES = 700
# a queue this long drops the events the backup conversion would skip, and again each time it doubles
QUEUE_COMPACT_EVENTS = 16384
# a queue longer than this becomes one full scan when memory runs short: tasks stall on memory for MEMORY_STALL_PERCENT
# of the last minute, less than MEMORY_LOW_FRACTION of the memory (or of a cgroup limit) is available, or the queue
# would hold more than QUEUE_MEMORY_SHARE of the memory available to it. it reads the memory state every MEMORY_CHECK_SECONDS
QUEUE_KEEP_EVENTS = 65536
MEMORY_STALL_PERCENT = 10.0
MEMORY_LOW_FRACTION = 0.05
QUEUE_MEMORY_SHARE = 0.25
MEMORY_CHECK_SECONDS = 30
# wds: for a folder, the watches at or below it when it moved away, so they can go if its move never pairs
COOKIE_VALUE = namedtuple('COOKIE_VALUE',['wd','path','isDir','wds'],defaults=((),))

GREEN_LIGHT = threading.Event()
GREEN_LIGHT.set()

def wait_for_path(job:JobControl, flag:threading.Event, path:str, what:str, clock = time.monotonic) -> bool:
	'''
	Wait until flag is set and path is a directory. Returns False when the job (with job None, GREEN_LIGHT) says stop.
	Logs nothing for DISK_WAIT_GRACE_SECONDS, then an alert, repeated every DISK_WAIT_REPEAT_SECONDS.
	'''
	running = GREEN_LIGHT.is_set if job is None else job.should_run
	started = clock()
	next_alert = started + DISK_WAIT_GRACE_SECONDS
	while running():
		if flag.is_set() and os.path.isdir(path):
			return True
		if flag.is_set():
			# the filesystem is ready but the path is not there yet, so the flag cannot end the wait
			time.sleep(POLL_WAIT_SECONDS)
		else:
			flag.wait(POLL_WAIT_SECONDS)
		now = clock()
		if now >= next_alert and job is not None:
			waited = now - started
			job_log(job.job_name, f'FAILED: waiting {int(waited // 60)} min for {path}: {what}')
			next_alert = now + DISK_WAIT_REPEAT_SECONDS
	return False

WATCH_RESULT_OK = 'ok'
WATCH_RESULT_INIT_FAILED = 'init_failed'
WATCH_RESULT_SELF_DESTRUCT = 'self_destruct'

WATCHER_LOG_PREFIX = '👀'
BACKUPER_LOG_PREFIX = '📥'

HASH_SIZE = 1<<16
# threads per job comparing entries in delta generation: the vault disks serve many lookups at once
COMPARE_THREADS = 32
# the kernel also gives up resolving a path after 40 links
MAX_CHAINED_LINKS = 40
# manifest rows written or read per statement: enough to amortise sqlite calls, little to hold
MANIFEST_BATCH_SIZE = 10000
# a copy is written under a name of its own with this suffix, in its destination's folder, until it succeeded
PARTIAL_COPY_SUFFIX = '.reverberator-partial'
# how long a failed backup waits for its stopped copies before it gives up on them
COPY_STOP_WAIT_SECONDS = 60
# a stopping daemon waits less: a stopped command is killed within about a second ( multiCMD sends SIGKILL a second after SIGTERM )
COPY_STOP_GRACE_SECONDS = 2
# what cp says when a copy's contents arrived but some of its metadata could not be kept
COPY_METADATA_FAILURES = ('failed to preserve ownership', 'failed to preserve authorship', 'preserving permissions for',
	'preserving times for', 'setting permissions for', 'setting attribute', 'getting attribute', 'listing attributes',
	'extended attributes', 'security context')
# what cp says when the source changed under the copy, which a later event covers
COPY_SOURCE_REPLACED = 'replaced while being copied'

DEBUG = False

SAMPLE_REVERB_RULE_FILE = '''
Job Name (Unique Key)	Path Monitoring	Vault Path	Monitoring File System Signature	Minium snapshot interval	Maximum snapshot interval	Keep 1 Compelete Backup	Only Sync Attributes (permissions) 	Keep N versions	Backup Size Limit	Vault File System Signature	Skip List File
# The name for the Job, will store in folder with this name 	The path to monitor file changes 	The Path to store the version history vault 	The UUID > Label > Device Name for the monitoring path	The minimum amount of time the script will wait before backup. 	The maximum amount of time the script will wait after IO before backup.	When vault is empty, copy entire monitorig path to vault instead of using links	Do not backup file content upon attr change	How many max versions of the file to keep in vault 	Keep purging old versions until 1 left if vault size exceed this limit. Use comma (,) to seperate multiple rules. Stricter (smaller) limits take precedence	The UUID > Label > path for the vault file system	A gitignore style list of paths not to back up, matched relative to the monitored path
# need to be unique for path distinction	Please use absolute path 	Please use absolute path	will auto record if not set, use string literal N/A if does not care about FS ( can be inefficient ) 	Will only backup upon X seconds of inactivity 	Will backup even if the content is still buzy after X seconds.	If true, can take long to initialize / fail to initialize if backup space is small 	If true, file attr change will get synced to the most recent file backup 	set to 0 for infinity	Maybe inaccurate on CoW File systems. Use 0 for infinity, % numbers refer to disk usage %, use leading i to represent inodes	Will auto record if not set, use string literal N/A if does not care about FS	Relative paths resolve against the rule file folder. Once a job has used patterns, set none to back up everything
# Incomplete V* directories (no .modified_contents.nsv) are removed on startup.
# If you need data from a partial backup after a crash/stop, copy it out before restarting.
#_defaults_#		/var/reverbs/	auto	60	86400	True	True	0	5%,i5%	auto	
'''

tl = Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=False,noLog=True)

#%% ---- Main CLI Functions ----
def run_job(job:JobControl, start_attempt, clock = time.monotonic, persist_pending = None) -> str:
	'''
	Supervise one job: run its attempts until the daemon stops ('exit') or the job fails for good ('stopped').

	start_attempt(job, attempt) starts an attempt's threads and returns them. An attempt ends when the job fails or one
	of its threads ends, and all of its threads have exited before anything else happens, so the next attempt never
	races them. A failure only a config change can fix stops the job. Any other is retried after job_retry_delay, which
	grows with each failed attempt in a row and starts over once an attempt ran JOB_RETRY_RESET_SECONDS.
	persist_pending() runs when the daemon stops after the job failed, as the backuper keeps a failed job's queue in
	memory for its next attempt.
	'''
	global GREEN_LIGHT
	failures = 0
	attempt = 0
	while GREEN_LIGHT.is_set():
		attempt += 1
		job.start_attempt()
		started = clock()
		threads = start_attempt(job, attempt)
		recovering = failures > 0
		while GREEN_LIGHT.is_set() and job.failure is None:
			if recovering and job.committed.is_set():
				job_log(job.job_name, f'RECOVERED after {failures} failed attempts')
				recovering = False
			ended = next((thread for thread in threads if not thread.is_alive()), None)
			# read after the thread ended: one that ended as the daemon stops is not a failure
			if ended is not None and GREEN_LIGHT.is_set():
				job.fail(f'{ended.name} exited unexpectedly')
				break
			time.sleep(POLL_WAIT_SECONDS)
		job.running.clear()
		for thread in threads:
			thread.join()
		ran = clock() - started
		if recovering and job.committed.is_set():
			job_log(job.job_name, f'RECOVERED after {failures} failed attempts')
		if not GREEN_LIGHT.is_set():
			break
		failure = job.failure
		if failure.permanent:
			job_log(job.job_name, f'STOPPED: {failure.reason}')
			return 'stopped'
		failures = 1 if ran >= JOB_RETRY_RESET_SECONDS else failures + 1
		delay = job_retry_delay(failures)
		job_log(job.job_name, f'FAILED: {failure.reason}; retrying in {int(delay)}s')
		deadline = time.monotonic() + delay
		while GREEN_LIGHT.is_set() and time.monotonic() < deadline:
			time.sleep(max(min(POLL_WAIT_SECONDS, deadline - time.monotonic()), 0))
	if job.failure is not None and persist_pending is not None:
		persist_pending()
	return 'exit'

class MonitorGate:
	'''
	For a rule kept because its monitored path was missing at parse time, with no filesystem signature to gate on.
	resolve() waits until the path exists and has a signature, then registers that pair with FS_SIGNATURE_MONITOR in
	place of the ungated one, so the job never reads or watches the tree before its disk is identified.
	'''
	def __init__(self, path:str, flag:threading.Event, signature:str):
		self.path = path
		self.flag = flag
		self.signature = signature
		self.resolved = False

	def resolve(self, job:JobControl) -> bool:
		'''Returns False when the job (or the daemon) is stopped before the signature is known.'''
		if self.resolved:
			return True
		always = threading.Event()
		always.set()
		if not wait_for_path(job, always, self.path, 'monitored path not there yet'):
			return False
		signature = None
		started = time.monotonic()
		next_alert = started + DISK_WAIT_GRACE_SECONDS
		while job.should_run():
			if os.path.isdir(self.path):
				signatures = get_fs_signatures(self.path)
				if signatures and signatures[0]:
					signature = signatures[0]
					break
			job.running.wait(min(FS_RECHECK_SECONDS, POLL_WAIT_SECONDS))
			now = time.monotonic()
			if now >= next_alert:
				job_log(job.job_name, f'FAILED: waiting {int((now - started) // 60)} min for {self.path}: monitored filesystem signature unknown')
				next_alert = now + DISK_WAIT_REPEAT_SECONDS
		if signature is None:
			return False
		new_flag = FS_SIGNATURE_MONITOR.register(self.path, signature)
		FS_SIGNATURE_MONITOR.unregister(self.path, self.signature, self.flag)
		self.flag, self.signature, self.resolved = new_flag, signature, True
		return True

def job_attempt_starter(job_name:str, startup_args:tuple, watcher_args:tuple, backuper_args:tuple, monitor_gate:MonitorGate = None, monitor_signature:str = None):
	'''
	A start_attempt for run_job: each attempt starts the job's watcher and backuper, sharing a fresh JobStartup.
	startup_args are JobStartup's, watcher_args and backuper_args their function's positional arguments before startup.
	With a monitor_gate, nothing starts until it has resolved the monitored filesystem's signature, and its flag is
	the monitored filesystem flag from then on (watcher_args[0] and backuper_args[7] are the ungated one).
	monitor_signature is the rule's, which the watcher hands to the filesystem monitor when its root disappears.
	'''
	def start_attempt(job:JobControl, attempt:int) -> list:
		w_args, b_args, signature = watcher_args, backuper_args, monitor_signature
		if monitor_gate is not None:
			if not monitor_gate.resolve(job):
				return []
			w_args = (monitor_gate.flag, *watcher_args[1:])
			b_args = (*backuper_args[:7], monitor_gate.flag, *backuper_args[8:])
			signature = monitor_gate.signature
		startup = JobStartup(*startup_args)
		threads = [
			threading.Thread(target=watcher, args=(*w_args, startup, job, signature), name=f'{job_name} watcher', daemon=True),
			threading.Thread(target=backuper, args=(*b_args, startup, job), name=f'{job_name} backuper', daemon=True),
		]
		started = []
		try:
			for thread in threads:
				thread.start()
				started.append(thread)
		except RuntimeError as e:
			# out of threads: the attempt fails once the ones that did start have ended, and is retried
			job.fail(f'cannot start its threads: {e}')
		return started
	return start_attempt

def persist_failed_job_queue(job_name:str, monitor_path:str, vault_path:str, to_process:ChangeEventQueue, to_process_lock:threading.Lock):
	'''
	Save a failed job's queue as its pending transactions when the daemon stops.
	Nothing was watched since the job failed, so replaying the queue would miss what changed meanwhile: it is saved as
	a full scan request (which the queue folds everything queued into), as the job's next attempt would have done.
	'''
	with to_process_lock:
		to_process.append(ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
	persist_pending_transactions(job_name=job_name, vault_path=vault_path, to_process=to_process, to_process_lock=to_process_lock)

def supervise_job(results:list, index:int, job:JobControl, start_attempt, persist_pending):
	'''A job's supervisor thread: runs the job and records how it ended in results[index].'''
	results[index] = run_job(job, start_attempt, persist_pending=persist_pending)

def main():
	'''The console entry point: runs the daemon, and exits 1 with a marker line when it fails.'''
	try:
		run_daemon()
	except Exception as e:
		import traceback
		tl.teeerror(traceback.format_exc())
		daemon_error_log(f'{type(e).__name__}: {e}')
		sys.exit(1)

def run_daemon():
	global BACKUP_SEMAPHORE
	global COMPARE_THREADS
	global tl
	global GREEN_LIGHT
	global DEFAULT_SNAPSHOT_DELAY
	global DEFAULT_MAX_DELAY
	global DEFAULT_KEEP_ONE_COMPLETE_BACKUP
	global DEFAULT_ONLY_SYNC_ATTRIBUTES
	global DEFAULT_KEEP_N_VERSIONS
	global DEFAULT_BACKUP_SIZE_LIMIT
	global DEBUG
	apply_poll_wait_from_env()
	apply_job_timing_from_env()
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	args, argString = get_args()
	tl = Tee_Logger.teeLogger(systemLogFileDir=args.log_dir, programName=args.program_name, compressLogAfterMonths=0, deleteLogAfterYears=args.log_delete_years, suppressPrintout=args.quiet, noLog=args.no_log,callerStackDepth=4,in_place_compression='xz')
	tl.teeprint(argString)
	if args.verbose:
		DEBUG = True
	if args.drop_sample_reverb_rule_file:
		rule_path = os.path.abspath(args.rule_path)
		with open(rule_path, 'w', encoding='utf-8') as f:
			f.write(SAMPLE_REVERB_RULE_FILE.strip() + '\n')
		tl.teeok(f'Dropped sample rule file at {rule_path}')
		return
	# warn the user if reverberator is not run as root
	if os.geteuid() != 0:
		tl.teeerror('Warning: reverberator is not run as root, dynamic nofile tuning will not work. And file permissions can cause errors.')
	irm = inotify_resource_manager()
	if args.threads == 0:
		# set the max backup threads to 200k, which is usually about the max for a user set in ulimit. pratically unlimited.
		BACKUP_SEMAPHORE = threading.Semaphore(200000)
	elif args.threads < 0:
		# set the max backup threads to -threads * number of cores
		BACKUP_SEMAPHORE = threading.Semaphore(-args.threads * os.cpu_count())
	else:
		BACKUP_SEMAPHORE = threading.Semaphore(args.threads)
	COMPARE_THREADS = max(1, args.compare_threads)
	# parse the rule file
	rules = parse_rules(args.rule_path)
	if not rules:
		tl.teeerror(f'Error: Rule file {args.rule_path} appears empty after parsing.')
		daemon_error_log(f'rule file {args.rule_path} has no rules')
		sys.exit(1)
	# one supervisor per job runs its watcher and backuper, and starts them again after a failure
	supervisors = []
	results = [None] * len(rules)
	colliding = colliding_job_names(rules)
	for index, reverb_rule in enumerate(rules):
		job_name = reverb_rule.job_name
		if job_name in colliding:
			# rows sharing a job name would share one vault folder: each is stopped at once, nothing of it starts
			def start_colliding(job:JobControl, attempt:int, job_name = job_name) -> list:
				job.fail(f'{colliding[job_name]} rows clean up to the job name {job_name}', permanent=True)
				return []
			supervisor = threading.Thread(target=supervise_job,args=(results,index,JobControl(job_name),start_colliding,None),name=f'{job_name} supervisor',daemon=True)
			supervisor.start()
			supervisors.append(supervisor)
			continue
		monitor_path = reverb_rule.mon_path
		monitor_path_signature = reverb_rule.mon_fs_signature
		min_snapshot_delay_seconds = DEFAULT_SNAPSHOT_DELAY
		try:
			min_snapshot_delay_seconds = int(reverb_rule.min_shapshot_time)
		except Exception as _:
			tl.teeerror(f'Error: Rule {job_name} has invalid min_snapshot_delay_seconds value: {reverb_rule.min_shapshot_time}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_SNAPSHOT_DELAY}")
		max_shapshot_delay_seconds = DEFAULT_MAX_DELAY
		try:
			max_shapshot_delay_seconds = int(reverb_rule.max_shapshot_time)
		except Exception as _:
			tl.teeerror(f'Error: Rule {job_name} has invalid max_snapshot_delay_seconds value: {reverb_rule.max_shapshot_time}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_MAX_DELAY}")
			max_shapshot_delay_seconds = DEFAULT_MAX_DELAY
		vault_path = reverb_rule.vault_path
		if reverb_rule.keep_one_complete_backup.lower() == 'none':
			keep_one_complete_backup = DEFAULT_KEEP_ONE_COMPLETE_BACKUP
		else:
			keep_one_complete_backup = reverb_rule.keep_one_complete_backup.lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		if reverb_rule.only_sync_attributes.lower() == 'none':
			only_sync_attributes = DEFAULT_ONLY_SYNC_ATTRIBUTES
		else:
			only_sync_attributes = reverb_rule.only_sync_attributes.lower() in ['true','yes','1','t','y','on','enable','enabled','en','e']
		keep_n_versions = DEFAULT_KEEP_N_VERSIONS
		try:
			keep_n_versions = int(reverb_rule.keep_n_versions)
		except Exception as _:
			tl.teeerror(f'Error: Rule {job_name} has invalid keep_n_versions value: {reverb_rule.keep_n_versions}')
			tl.teeprint(f"Reverting to default value: {DEFAULT_KEEP_N_VERSIONS}")
		backup_size_limit = reverb_rule.backup_size_limit
		vault_path_signature = reverb_rule.vault_fs_signature
		job_vault = os.path.join(vault_path, job_name)
		remove_incomplete_vault_versions(job_vault)
		# kept across the job's attempts, so a retry loses nothing queued
		to_process = ChangeEventQueue(monitor_path)
		to_process_lock = threading.Lock()
		to_process_flag = threading.Event()
		monitor_fs_flag = FS_SIGNATURE_MONITOR.register(monitor_path,monitor_path_signature)
		# every attempt loads the skip list again once the job's filesystems are ready, then decides on resuming pending transactions
		startup_args = (job_name, monitor_path, resolve_skip_list_path(reverb_rule.skip_list_file, args.rule_path), reverb_rule.skip_list_file.strip().lower() == 'none')
		watcher_args = (monitor_fs_flag,monitor_path,to_process,to_process_lock,to_process_flag,irm,min_snapshot_delay_seconds,max_shapshot_delay_seconds)
		backuper_args = (job_name,to_process,to_process_lock,monitor_path,vault_path,vault_path_signature,to_process_flag,monitor_fs_flag,keep_one_complete_backup,only_sync_attributes,keep_n_versions,backup_size_limit,args.journal)
		gate = None
		if not os.path.exists(monitor_path) and monitor_path_signature.strip().lower() in ('', 'auto'):
			gate = MonitorGate(monitor_path, monitor_fs_flag, monitor_path_signature)
		start_attempt = job_attempt_starter(job_name, startup_args, watcher_args, backuper_args, gate, monitor_path_signature)
		persist_pending = functools.partial(persist_failed_job_queue, job_name, monitor_path, vault_path, to_process, to_process_lock)
		tl.info(f'Backup thread will keep one complete backup: {keep_one_complete_backup}, only sync attributes: {only_sync_attributes}, keep n versions: {keep_n_versions}, backup size limit: {backup_size_limit}')
		supervisor = threading.Thread(target=supervise_job,args=(results,index,JobControl(job_name),start_attempt,persist_pending),name=f'{job_name} supervisor',daemon=True)
		supervisor.start()
		supervisors.append(supervisor)
		tl.teeok(f'Started job {job_name} watching {monitor_path}:{monitor_path_signature} into vault {vault_path}:{vault_path_signature}')
	for supervisor in supervisors:
		supervisor.join()
	if not GREEN_LIGHT.is_set():
		tl.teeok('All jobs have exited. Exiting main thread.')
		return
	if all(result == 'stopped' for result in results):
		daemon_error_log('every job is stopped')
		sys.exit(EXIT_ALL_STOPPED)
	# only a stop ends a job's supervisor without stopping the job, so one of them failed
	raise RuntimeError(f'job supervisors ended without a stop: {results}')

def signal_handler(sig, frame):
	global GREEN_LIGHT
	global tl
	'''
	Handle the Ctrl C signal

	Args:
		sig (int): The signal
		frame (frame): The frame

	Returns:
		None
	'''
	if GREEN_LIGHT.is_set():
		tl.teeerror('Ctrl C caught, cleanning up and exiting... ( can take up to 5 seconds )')
		GREEN_LIGHT.clear()
	else:
		tl.teeerror('Ctrl C caught again, exiting immediately!')
		# wait for 0.1 seconds to allow the threads to exit
		time.sleep(0.1)
		sys.exit(1)

def get_args(args = None):
	'''
	Parse the arguments

	Args:
		args (list): The arguments

	Returns:
		args (Namespace): The parsed arguments
		argString (str): The non defualt arguments in string format

	Example:
		>>> get_args(['-ld','/tmp','--verbose','--threads=4','rule.tsv'])[0]
		Namespace(log_dir='/tmp', program_name='reverberator', log_delete_years=2, quiet=False, no_log=False, verbose=True, threads=4, compare_threads=32, journal=False, drop_sample_reverb_rule_file=False, rule_path='rule.tsv')
		>>> get_args(['-ld','/tmp','-pn','reverb','--log_delete_years=3','--quiet','--verbose','--threads=4','rule.tsv'])[1].partition('--')[2]
		"log_dir=\'/tmp\' --program_name=\'reverb\' --log_delete_years=\'3\' --quiet=\'True\' --verbose=\'True\' --threads=\'4\' \'rule.tsv\'"
		>>> get_args([])[0].rule_path
		'reverb_rule.tsv'
		>>> get_args(['--journal'])[0].journal
		True
		>>> get_args(['-t','0'])[0].threads
		0
	'''
	global __version__
	lib_vers = f'inotify_simple {inotify_simple.__version__}; xxhash {xxhash.VERSION}; Tee_Logger {Tee_Logger.__version__}; multiCMD {multiCMD.__version__}; TSVZ {TSVZ.__version__}'
	class MixedHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
		pass
	parser = argparse.ArgumentParser(
		description=(
			"reverberator watches source paths from a TSV rule file and creates recursive, "
			"versioned backups in configured vault locations."
		),
		epilog=(
			"Examples:\n"
			"  reverberator reverb_rule.tsv\n"
			"  reverberator --verbose --threads 4 /etc/reverb/custom_rules.tsv\n\n"
			"Thread mode:\n"
			"  --threads < 0 : multiplier of CPU count (e.g. -2 => 2x CPU count)\n"
			"  --threads = 0 : use a very large worker pool (200000)\n"
			"  --threads > 0 : exact worker thread count"
		),
		formatter_class=lambda prog: MixedHelpFormatter(
			prog,
			max_help_position=32,
			width=100
		)
	)
	parser.add_argument("-ld","--log_dir", type=str, help="Directory where log files are written.", default='/var/log')
	parser.add_argument("-pn","--program_name", type=str, help="Program name used as the log subdirectory.", default='reverberator')
	parser.add_argument("-ldy","--log_delete_years", type=int, help="Delete log files older than this many years.", default=2)
	parser.add_argument('-q', '--quiet', action='store_true', help='Suppress stdout output (errors may still be emitted).')
	parser.add_argument('-nl','--no_log', action='store_true', help='Disable writing log files to disk.')
	parser.add_argument('-v','--verbose','--debug', action='store_true', help='Enable verbose debug logging.')
	parser.add_argument('-V', '--version', action='version', version=f"%(prog)s {__version__} with {lib_vers}; reverb (REcursive VERsioning Backup) generator by pan@zopyr.us")
	parser.add_argument('-t','--threads', type=int, help='Worker thread count policy for backup processing (see thread mode details below).', default=-2)
	parser.add_argument('-ct','--compare_threads', type=int, help='Threads per job comparing the monitored tree against the vault in delta generation.', default=COMPARE_THREADS)
	parser.add_argument('-j','--journal', action='store_true', help='Write backup actions to a journal file in the vault path.')
	parser.add_argument('--drop_sample_reverb_rule_file', '--drop-sample-rule', action='store_true', help='Write SAMPLE_REVERB_RULE_FILE to RULE_PATH and exit.')
	parser.add_argument('rule_path', metavar='RULE_PATH', type=str, nargs='?', default='reverb_rule.tsv', help='Path to the TSV rule-definition file.')
	try:
		args = parser.parse_intermixed_args(args)
	except Exception as _:
		#eprint(f"Error while parsing arguments: {e!r}")
		# try to parse the arguments using parse_known_args
		args, unknown = parser.parse_known_args(args)
		# if there are unknown arguments, we will try to parse them again using parse_args
		if unknown:
			print(f"Error: Unrecognized arguments: {unknown!r}", file=sys.stderr)
			sys.exit(2)
	#print(f'Arguments: {vars(args)}')
	default_args_dict = vars(parser.parse_args([]))
	# format a long format argument of what the user supplied and echo it back
	startArgs = [f'> {sys.argv[0]}']
	for argumentName, value in vars(args).items():
		if value != default_args_dict[argumentName]:
			if argumentName == 'rule_path':
				continue
			if isinstance(value, list):
				for v in value:
					startArgs.append(f'--{argumentName}=\'{v}\'')
			else:
				startArgs.append(f'--{argumentName}=\'{value}\'')
	startArgs.append(f'\'{args.rule_path}\'')
	return args, ' '.join(startArgs)

def upgrade_rule_file_header(rule_file:str) -> bool:
	'''
	Upgrade an old 11 column rule file in place by adding the Skip List File column to the header
	and to the stock comment rows. Every other byte, including line endings, is kept.

	Args:
		rule_file (str): The rule file

	Returns:
		changed (bool): Whether the file was rewritten
	'''
	rule_file = os.path.realpath(rule_file)
	with open(rule_file, 'r', newline='', encoding='utf-8') as f:
		text = f.read()
	lines = text.split('\n')
	def cells_of(line:str) -> list:
		return line.rstrip('\r').split('\t')
	if [cell.strip() for cell in cells_of(lines[0])] != REVERB_RULE_TSV_HEADER[:-1]:
		return False
	def with_suffix(line:str, suffix:str) -> str:
		body = line.rstrip('\r')
		return body + suffix + line[len(body):]
	lines[0] = '\t'.join(REVERB_RULE_TSV_HEADER) + lines[0][len(lines[0].rstrip('\r')):]
	for i, line in enumerate(lines[1:], 1):
		for index, prefix in enumerate(('# The name for the Job', '# need to be unique')):
			if line.startswith(prefix) and len(cells_of(line)) == len(REVERB_RULE_TSV_HEADER) - 1:
				lines[i] = with_suffix(line, '\t' + SKIP_LIST_COLUMN_DESCRIPTIONS[index])
	replace_file_text(rule_file, '\n'.join(lines))
	return True

def replace_file_text(path:str, text:str):
	'''
	Replace a text file's content through a temp file in the same folder, fsynced before the rename so a crash cannot
	leave an empty file in its place. The mode and owner are kept; path must already be the real path.
	'''
	directory = os.path.dirname(os.path.abspath(path))
	fd, temp_path = tempfile.mkstemp(dir=directory, prefix='.' + os.path.basename(path) + '.')
	try:
		with os.fdopen(fd, 'w', newline='', encoding='utf-8') as f:
			f.write(text)
			f.flush()
			os.fsync(f.fileno())
		original = os.stat(path)
		os.chmod(temp_path, stat.S_IMODE(original.st_mode))
		try:
			os.chown(temp_path, original.st_uid, original.st_gid)
		except OSError:
			pass
		os.replace(temp_path, path)
	except BaseException:
		if os.path.exists(temp_path):
			os.remove(temp_path)
		raise

def rewrite_rule_rows(rule_file:str, rows:dict) -> None:
	'''
	Replace rule rows in place. rows maps the job name cell as written in the file to its new full row.
	For each key the last line whose first cell (stripped) equals it becomes the new row and earlier lines with that
	key are removed (TSVZ already ignored them); every other line is kept byte for byte, line endings included.

	Args:
		rule_file (str): The rule file
		rows (dict): Written job name cell -> new row (list of cells)
	'''
	if not rows:
		return
	rule_file = os.path.realpath(rule_file)
	with open(rule_file, 'r', newline='', encoding='utf-8') as f:
		lines = f.read().split('\n')
	last_index = {}
	for i, line in enumerate(lines):
		key = line.split('\t', 1)[0].strip()
		if key in rows and not key.startswith('#'):
			last_index[key] = i
	result = []
	for i, line in enumerate(lines):
		key = line.split('\t', 1)[0].strip()
		if key not in last_index:
			result.append(line)
		elif last_index[key] == i:
			result.append('\t'.join(rows[key]) + line[len(line.rstrip('\r')):])
	replace_file_text(rule_file, '\n'.join(result))

def resolve_skip_list_path(cell:str, rule_file:str) -> str:
	'''
	Resolve the Skip List File cell to a path, None when the job has no skip list.

	>>> resolve_skip_list_path('', '/etc/r/rules.tsv') is None
	True
	>>> resolve_skip_list_path(' None ', '/etc/r/rules.tsv') is None
	True
	>>> resolve_skip_list_path('skip.txt', '/etc/r/rules.tsv')
	'/etc/r/skip.txt'
	>>> resolve_skip_list_path('/x/skip', '/etc/r/rules.tsv')
	'/x/skip'
	'''
	cell = cell.strip()
	if cell.lower() in ('', 'auto', 'none'):
		return None
	return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(rule_file)), cell))

def parse_rules(rule_file:str):
	'''
	Parse the rule file using TSVZ and fill in the defaults and auto fields

	Args:
		rule_file (str): The rule file

	Returns:
		rules (list): The rules
	'''
	# will read and parse the rule file using tsvz.
	# this will also responsible for filling in the defaults and auto fields and generating actual rules
	# and append to the end if the rule is not "explicit"
	# explicit: no fields empty / auto
	# will also exit if the rule file is not valid ( broken beyond repair ) / does not exit
	global DEBUG
	global DEFAULT_SNAPSHOT_DELAY
	global DEFAULT_KEEP_ONE_COMPLETE_BACKUP
	global DEFAULT_ONLY_SYNC_ATTRIBUTES
	global DEFAULT_KEEP_N_VERSIONS
	global DEFAULT_BACKUP_SIZE_LIMIT
	global tl
	global REVERB_RULE_TSV_HEADER
	if not os.path.exists(rule_file):
		tl.teeerror(f'Error: Rule file {rule_file} does not exist.')
		daemon_error_log(f'rule file {rule_file} does not exist')
		sys.exit(1)
	try:
		if upgrade_rule_file_header(rule_file):
			tl.info(f'Upgraded rule file {rule_file} header with the Skip List File column.')
	except (OSError, ValueError) as e:
		# ValueError: a compressed or non UTF-8 rule file, which TSVZ still reads
		tl.teelog(f'Warning: Cannot upgrade rule file {rule_file} ({e}). The Skip List File column cannot be used until the header is upgraded.',level='warning')

	rules = TSVZ.readTabularFile(rule_file,header=REVERB_RULE_TSV_HEADER,verifyHeader=True,strict=False,verbose=DEBUG)
	if DEBUG:
		tl.teeprint(f'Parsed rules: \n{rules}')
	else:
		tl.info(f'Parsed rules: \n{rules}')
	if not rules:
		tl.teeerror(f'Error: Rule file {rule_file} appears empty after parsing.')
		daemon_error_log(f'rule file {rule_file} has no rules')
		sys.exit(1)
	# fill in empty / auto and append:
	rulesToUpdate = {}
	returnReverbRules = []
	for ruleName in rules:
		ruleList = list(rules[ruleName]) + [''] * (len(REVERB_RULE_HEADER) - len(rules[ruleName]))
		if DEBUG:
			tl.teeprint(f'Checking rule: {ruleList}')
		ruleUpdated = False
		inRule = OrderedDict(zip(REVERB_RULE_HEADER, ruleList))
		# job_name
		if not inRule['job_name']:
			tl.teelog(f'Warning: Rule {ruleName} has empty Job Name. Ignoring rule...',level='warning')
			continue
		cleanedJobName = slugify(inRule['job_name'])
		if cleanedJobName != inRule['job_name']:
			tl.teelog(f'Warning: Rule {ruleName} has dirty Job Name. Changing to {cleanedJobName}',level='warning')
			inRule['job_name'] = cleanedJobName
			ruleUpdated = True
		# mon_path
		if not inRule['mon_path']:
			tl.teelog(f'Warning: Rule {ruleName} has empty Path Monitoring. Ignoring rule...',level='warning')
			continue
		mon_path_exists = os.path.exists(inRule['mon_path'])
		if not mon_path_exists:
			tl.teelog(f'Warning: Rule {ruleName} has Path Monitoring: {inRule["mon_path"]} which does not exist, the job will wait for it',level='warning')
		newSourcePath = os.path.realpath(inRule['mon_path']) if mon_path_exists else inRule['mon_path']
		if newSourcePath != inRule['mon_path']:
			tl.teelog(f'Warning: Rule {ruleName} has dirty Path Monitoring. Changing to {newSourcePath}',level='warning')
			inRule['mon_path'] = newSourcePath
			ruleUpdated = True
		# vault_path
		if not inRule['vault_path']:
			tl.teelog(f'Warning: Rule {ruleName} has empty Vault Path. Ignoring rule...',level='warning')
			continue
		if is_subpath(inRule['vault_path'],inRule['mon_path']):
			tl.teelog(f'Warning: Rule {ruleName} has Vault Path: {inRule["vault_path"]} which is a subpath of the source path. Ignoring rule...',level='warning')
			continue
		# mon_fs_signature
		if not mon_path_exists:
			pass
		elif not inRule["mon_fs_signature"] or inRule["mon_fs_signature"].lower() == 'auto':
			signatures = get_fs_signatures(inRule["mon_path"])
			if signatures and signatures[0]:
				inRule["mon_fs_signature"] = signatures[0]
				tl.teelog(f'Auto filled Monitoring File System Signature for {ruleName}: {inRule["mon_fs_signature"]}',level='info')
				ruleUpdated = True
			else:
				tl.teelog(f'Warning: Rule {ruleName} failed to get the fs signature, disabling fs monitoring for this run...',level='warning')
				inRule["mon_fs_signature"] = 'auto'
		# min_shapshot_time
		if not inRule["min_shapshot_time"] or inRule["min_shapshot_time"].lower() == 'none':
			inRule["min_shapshot_time"] = '0'
			tl.info(f'Zeroed Minium snapshot time for {ruleName}: {inRule["min_shapshot_time"]}')
			ruleUpdated = True
		elif inRule["min_shapshot_time"].lower() == 'auto':
			inRule["min_shapshot_time"] = str(DEFAULT_SNAPSHOT_DELAY)
			tl.info(f'Auto filled Minium snapshot time for {ruleName}: {inRule["min_shapshot_time"]}')
			ruleUpdated = True
		# max_shapshot_time
		if not inRule["max_shapshot_time"] or inRule["max_shapshot_time"].lower() == 'none':
			inRule["max_shapshot_time"] = str(DEFAULT_MAX_DELAY)
			tl.info(f'Auto filled Maximum snapshot time for {ruleName}: {inRule["max_shapshot_time"]}')
			ruleUpdated = True
		elif inRule["max_shapshot_time"].lower() == 'auto':
			inRule["max_shapshot_time"] = str(DEFAULT_MAX_DELAY)
			tl.info(f'Auto filled Maximum snapshot time for {ruleName}: {inRule["max_shapshot_time"]}')
			ruleUpdated = True
		# keep_one_complete_backup
		if not inRule["keep_one_complete_backup"] or inRule["keep_one_complete_backup"].lower() == 'auto' or inRule["keep_one_complete_backup"].lower() == 'none':
			inRule["keep_one_complete_backup"] = str(DEFAULT_KEEP_ONE_COMPLETE_BACKUP)
			tl.info(f'Auto filled Keep 1 Compelete Backup for {ruleName}: {inRule["keep_one_complete_backup"]}')
			ruleUpdated = True
		# only_sync_attributes
		if not inRule["only_sync_attributes"] or inRule["only_sync_attributes"].lower() == 'auto' or inRule["only_sync_attributes"].lower() == 'none':
			inRule["only_sync_attributes"] = str(DEFAULT_ONLY_SYNC_ATTRIBUTES)
			tl.info(f'Auto filled Only Sync Attributes for {ruleName}: {inRule["only_sync_attributes"]}')
			ruleUpdated = True
		# keep_n_versions
		if not inRule["keep_n_versions"] or inRule["keep_n_versions"].lower() == 'none':
			inRule["keep_n_versions"] = '0'
			tl.info(f'Zeroed Keep N versions for {ruleName}: {inRule["keep_n_versions"]}')
			ruleUpdated = True
		elif inRule["keep_n_versions"].lower() == 'auto':
			inRule["keep_n_versions"] = str(DEFAULT_KEEP_N_VERSIONS)
			tl.info(f'Auto filled Keep N versions for {ruleName}: {inRule["keep_n_versions"]}')
			ruleUpdated = True
		# backup_size_limit
		if not inRule["backup_size_limit"] or inRule["backup_size_limit"].lower() == 'auto' or inRule["backup_size_limit"].lower() == 'none':
			inRule["backup_size_limit"] = DEFAULT_BACKUP_SIZE_LIMIT
			tl.info(f'Auto filled Backup Size Limit for {ruleName}: {inRule["backup_size_limit"]}')
			ruleUpdated = True
		# vault_fs_signature
		if not inRule["vault_fs_signature"] or inRule["vault_fs_signature"].lower() == 'auto':
			if not os.path.exists(inRule["vault_path"]):
				# try create it 
				try:
					os.makedirs(inRule["vault_path"],exist_ok=True)
				except Exception as _:
					tl.teelog(f'Warning: Rule {ruleName} with {inRule["vault_path"]} does not exist and failed to create it. Ignoring rule...',level='warning')
					continue
			signatures = get_fs_signatures(inRule["vault_path"])
			if signatures and signatures[0]:
				inRule["vault_fs_signature"] = signatures[0]
				tl.teelog(f'Auto filled Vault File System Signature for {ruleName}: {inRule["vault_fs_signature"]}',level='info')
				ruleUpdated = True
			else:
				tl.teelog(f'Warning: Rule {ruleName} failed to get the fs signature, disabling fs monitoring for this run...',level='warning')
				inRule["vault_fs_signature"] = 'auto'
		# check if the rule is explicit
		if ruleUpdated:
			tl.info(f'Updating rule {ruleName}: {inRule}')
			rulesToUpdate[ruleName] = list(inRule.values())
		returnReverbRules.append(ReverbRule(**inRule))
	# rewrite the updated rows in place once; a row whose cleaned name collides with another's is left as written,
	# as renaming it would merge the two rows in the file
	colliding = colliding_job_names(returnReverbRules)
	rulesToUpdate = {name:row for name,row in rulesToUpdate.items() if row[0] not in colliding}
	if rulesToUpdate:
		try:
			rewrite_rule_rows(rule_file,rulesToUpdate)
		except (OSError, ValueError) as e:
			# ValueError: a compressed or non UTF-8 rule file; the rules in memory are still right
			tl.teelog(f'Warning: Cannot write the filled in rows back to {rule_file} ({e}).',level='warning')
	return returnReverbRules

def colliding_job_names(rules:list) -> dict:
	'''
	The job names used by more than one rule, with how many rules use each.

	>>> colliding_job_names([ReverbRule('a', *['']*11), ReverbRule('b', *['']*11), ReverbRule('a', *['']*11)])
	{'a': 2}
	'''
	counts = Counter(rule.job_name for rule in rules)
	return {name:count for name,count in counts.items() if count > 1}

def slugify(value, allow_unicode=False):
	"""
	Taken from https://github.com/django/django/blob/master/django/utils/text.py
	Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
	dashes to single dashes. Remove characters that aren't alphanumerics,
	underscores, or hyphens. Convert to lowercase. Also strip leading and
	trailing whitespace, dashes, and underscores.

	Examples:
		>>> slugify('My Job Name!')
		'my-job-name'
		>>> slugify('  spaces--and___underscores  ')
		'spaces-and___underscores'
		>>> slugify('über')
		'uber'
		>>> slugify('café', allow_unicode=True)
		'café'
	"""
	value = str(value)
	if allow_unicode:
		value = unicodedata.normalize('NFKC', value)
	else:
		value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
	value = re.sub(r'[^\w\s-]', '', value.lower())
	return re.sub(r'[-\s]+', '-', value).strip('-_')

#%% ---- IRM ----
class inotify_resource_manager:
	def __init__(self):
		global DEBUG
		self.current_user_instances = 0
		self.current_user_watches = 0
		self.can_set_max_queued_events = True
		self.can_set_max_user_instances = True
		self.can_set_max_user_watches = True
		self.can_set_max_no_files = True
		self.can_set_max_no_files_user = True
		self.debug = DEBUG
		self.max_queued_events = self.getSysctlValues('fs.inotify.max_queued_events')
		self.max_user_instances = self.getSysctlValues('fs.inotify.max_user_instances')
		self.max_user_watches = self.getSysctlValues('fs.inotify.max_user_watches')
		self.max_no_files = self.getSysctlValues('fs.file-max')
		try:
			soft , hard = resource.getrlimit(resource.RLIMIT_NOFILE)
			if soft < hard:
				resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
			self.max_no_files_user = hard
		except Exception as _:
			self.max_no_files_user = 0

	def __iter__(self):
		for key in self.__dict__.keys():
			yield key, getattr(self,key)

	def __str__(self):
		# do not include the can_set in the string representation
		return str(dict((k, v) for k, v in self.__dict__.items() if not k.startswith('can_set_')))
	
	def __repr__(self):
		return str(dict(self))

	def getSysctlValues(self,field):
		global tl
		try:
			rtn = multiCMD.run_command(['sysctl',field],timeout=1,quiet=not self.debug)
			if rtn and rtn[0]:
				return int(rtn[0].split('=')[-1].strip())
		except Exception as _:
			import traceback
			tl.error(traceback.format_exc())
			tl.error(f'Failed to get {field} value')
		return 0
	
	def setSysctlValues(self,field,value,value_name):
		global tl
		try:
			if not getattr(self,f'can_set_{value_name}'):
				return False
			if value is ...:
				value = getattr(self,value_name)
			# check if the current value is less
			rtn = self.getSysctlValues(field)
			if rtn and rtn > value:
				tl.info(f'Current {field} is already higher than {value}')
				setattr(self,value_name,rtn)
				return False
			rc = multiCMD.run_command(['sudo','sysctl',f'{field}={value}'],timeout=1,quiet=not self.debug,return_code_only=True)
			if self.debug:
				tl.teeprint(f'sudo sysctl {field}={value} return code = {rc}')
			else:
				tl.info(f'sudo sysctl {field}={value} return code = {rc}')
			if rc:
				if self.debug:
					tl.teeprint(f'Failed to set {field} to {value}')
				else:
					tl.info(f'Failed to set {field} to {value}')
				setattr(self,f'can_set_{value_name}',False)
				if rtn:
					setattr(self,value_name,rtn)
				return False
			else:
				tl.teeok(f'Increased inotify {field} to {value}')
				setattr(self,value_name,value)
				return True
		except Exception as _:
			try:
				import traceback
				tl.error(traceback.format_exc())
				tl.teeerror(f'Failed to set {field} = {value} for {value_name}')
				setattr(self,f'can_set_{value_name}',False)
				rtn = self.getSysctlValues(field)
				if rtn:
					setattr(self,value_name,rtn)
				else:
					setattr(self,value_name,-1)
			except Exception as _:
				tl.teeerror(f'Failed to set {field} value')
		return False

	def increaseInotifyMaxQueueEvents(self,max_events:int = ...):
		if not self.can_set_max_queued_events:
			return False
		return self.setSysctlValues('fs.inotify.max_queued_events',max_events,'max_queued_events')

	def increaseInotifyMaxUserInstances(self,max_instances:int = ...):
		if not self.can_set_max_user_instances:
			return False
		return self.setSysctlValues('fs.inotify.max_user_instances',max_instances,'max_user_instances')

	def increaseInotifyMaxUserWatches(self,max_watches:int = ...):
		if not self.can_set_max_user_watches:
			return False
		rtn = self.setSysctlValues('fs.inotify.max_user_watches',max_watches,'max_user_watches')
		rtn2 = self.increaseNoFiles(max_watches)
		return rtn and rtn2

	def increaseNoFiles(self,nofile:int = ...):
		global tl
		if not self.can_set_max_no_files_user:
			return False
		if nofile is ...:
			nofile = self.max_no_files
		# attempt to increase the open file limit
		try:
			# check if the current value is less
			if resource.getrlimit(resource.RLIMIT_NOFILE)[0] > nofile:
				if self.debug:
					tl.teeprint(f'Current open file limit is already higher than {nofile}')
				else:
					tl.info(f'Current open file limit is already higher than {nofile}')
				self.max_no_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
				return False
			rtn = self.__increaseSystemNoFiles(nofile)
			resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
			tl.teeok(f'Increased open file limit to {nofile}')
			self.max_no_files = nofile
			return rtn
		except Exception as _:
			import traceback
			tl.error(traceback.format_exc())
			tl.teeerror(f'Failed to increase open file limit to {nofile}')
			self.can_set_max_no_files_user = False
			return False

	def __increaseSystemNoFiles(self,nofile:int):
		if not self.can_set_max_no_files:
			return False
		return self.setSysctlValues('fs.file-max',nofile,'max_no_files')

	def increaseUserInstances(self,count:int = 1):
		self.current_user_instances += count
		if self.max_user_instances <= self.current_user_instances:
			self.increaseInotifyMaxUserInstances(self.max_user_instances * 2)
		return self.current_user_instances
	
	def decreaseUserInstances(self,count:int = 1):
		self.current_user_instances -= count
		return self.current_user_instances
	
	def increaseUserWatches(self,count:int = 1):
		self.current_user_watches += count
		if self.max_user_watches <= self.current_user_watches:
			self.increaseInotifyMaxUserWatches(self.max_user_watches * 2)
		return self.current_user_watches
	
	def decreaseUserWatches(self,count:int = 1):
		self.current_user_watches -= count
		return self.current_user_watches

class inotify_usage:
	'''
	What one watchFolder run took from the shared inotify_resource_manager, which it forwards everything to.
	Closing a run's inotify instance frees all of its watches, so leaving the with block gives back exactly what the run
	counted, however it ends: a job's retries do not add up in the shared counts.
	'''
	def __init__(self, irm:inotify_resource_manager):
		self.irm = irm
		self.instances = 0
		self.watches = 0

	def __getattr__(self, name):
		return getattr(self.irm, name)

	def __enter__(self):
		return self

	def __exit__(self, *exc_info):
		self.irm.decreaseUserWatches(self.watches)
		self.irm.decreaseUserInstances(self.instances)
		self.watches = self.instances = 0
		return False

	def increaseUserInstances(self,count:int = 1):
		self.instances += count
		return self.irm.increaseUserInstances(count)

	def decreaseUserInstances(self,count:int = 1):
		self.instances -= count
		return self.irm.decreaseUserInstances(count)

	def increaseUserWatches(self,count:int = 1):
		self.watches += count
		return self.irm.increaseUserWatches(count)

	def decreaseUserWatches(self,count:int = 1):
		self.watches -= count
		return self.irm.decreaseUserWatches(count)

#%% ---- Watcher ----
def watcher(monitor_fs_flag:threading.Event,monitor_path:str,to_process:ChangeEventQueue,to_process_lock:threading.Lock,to_process_flag:threading.Event,irm:inotify_resource_manager,min_snapshot_delay_seconds:int=DEFAULT_SNAPSHOT_DELAY,max_shapshot_delay_seconds:int=DEFAULT_MAX_DELAY,startup:JobStartup = None,job:JobControl = None,monitor_signature:str = None):
	global GREEN_LIGHT
	# main monitoring function to deal with one reverb. with a job, a failure stops only that job, and so does the job failing
	running = GREEN_LIGHT.is_set if job is None else job.should_run
	while running():
		if not wait_for_path(job, monitor_fs_flag, monitor_path, 'monitored filesystem not ready'):
			return False
		skip_list = watching = None
		if startup is not None:
			# no watch is added until the backuper has loaded the job's skip list
			while running() and not startup.loaded.is_set():
				startup.loaded.wait(POLL_WAIT_SECONDS)
			if startup.loaded.is_set() and startup.failed:
				# only this job stops: the other jobs keep running
				watcherTeeLogToTl(monitor_path,f'Skip list for {monitor_path} failed to load, not watching it',error=True)
				if job is not None:
					# the same failure the backuper reports, so whichever thread reports first, the job sees one verdict
					job.fail(startup.failure_reason, permanent=startup.permanent)
				return False
			skip_list, watching = startup.skip_list, startup.watching
		if not running():
			watcherTeeLogToTl(monitor_path,f'Exiting watcher thread for {monitor_path}',ok=True)
			return False
		result = watchFolder(monitor_path=monitor_path,to_process=to_process,to_process_lock=to_process_lock,to_process_flag=to_process_flag,irm=irm,min_snapshot_delay_seconds=min_snapshot_delay_seconds,max_shapshot_delay_seconds=max_shapshot_delay_seconds,skip_list=skip_list,watching=watching,job=job)
		if result == WATCH_RESULT_INIT_FAILED or result is False:
			if job is None:
				watcherTeeLogToTl(monitor_path,f'Watch init/loop failed for {monitor_path}; requesting shutdown',error=True)
				GREEN_LIGHT.clear()
			else:
				watcherTeeLogToTl(monitor_path,f'Watch init/loop failed for {monitor_path}',error=True)
				job.fail(f'watching {monitor_path} failed')
			return False
		if result == WATCH_RESULT_SELF_DESTRUCT:
			watcherTeeLogToTl(monitor_path,f'Watch root disappeared for {monitor_path}; waiting for filesystem recovery',error=True)
			if monitor_signature is not None:
				# the flag stays set until the monitor sees the mount table change, which would let the wait pass at once
				FS_SIGNATURE_MONITOR.invalidate(monitor_path, monitor_signature)

def watchFolder(monitor_path:str,to_process:ChangeEventQueue,to_process_lock:threading.Lock,to_process_flag:threading.Event,irm:inotify_resource_manager,discard_new_recursive_folder_events_until_read:bool = True,min_snapshot_delay_seconds:int=DEFAULT_SNAPSHOT_DELAY,max_shapshot_delay_seconds:int=DEFAULT_MAX_DELAY,skip_list:'SkipList' = None,watching:threading.Event = None,job:JobControl = None):
	global COOKIE_DICT_MAX_SIZE
	global DEBUG
	global GREEN_LIGHT
	flags = inotify_simple.flags
	watch_flags = flags.MODIFY | flags.ATTRIB | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE | flags.DELETE | flags.DELETE_SELF | flags.MOVE_SELF | flags.UNMOUNT | flags.Q_OVERFLOW
	selfDestructMask = flags.UNMOUNT | flags.DELETE_SELF | flags.MOVE_SELF
	cookieDic = OrderedDict()
	wdDic = bidict()
	pendingMoveFromEvents = OrderedDict()
	newDirWDs = set()
	processPending = False
	move_pair_timeout = max(min_snapshot_delay_seconds, MOVE_PAIR_TIMEOUT_SECONDS)
	# the inner mounts followed (path -> fingerprint), from a table read before any watch is added: every mount change
	# after it shows in a table the monitor hands over later
	inner_mounts = watched_inner_mounts(current_mount_table(), monitor_path, skip_list)
	# the newest mount table from the monitor, until the loop takes it
	latest_mount_table = [None]
	mount_table_lock = threading.Lock()
	def store_mount_table(mount_table):
		with mount_table_lock:
			latest_mount_table[0] = mount_table
	irm = inotify_usage(irm)
	irm.increaseUserInstances()
	with irm, inotify_simple.INotify() as inotify_obj, FS_SIGNATURE_MONITOR.subscription(store_mount_table):
		job_name = None if job is None else job.job_name
		mainWatchDescriptor = initializeFolderWatchers(inotify_obj,monitor_path,wdDic,irm,watch_flags,skip_list=skip_list,job_name=job_name)
		if mainWatchDescriptor == -1:
			watcherTeeLogToTl(monitor_path,f'Failed to initialize folder watchers for {monitor_path}',error=True)
			return WATCH_RESULT_INIT_FAILED
		if watching is not None:
			watching.set()
		lastReadTime = time.monotonic()
		lastProcessTime = time.monotonic()
		# with a job, also stop once it failed, so its supervisor can join this thread
		running = GREEN_LIGHT.is_set if job is None else job.should_run
		while running():
			read_delay = max(min(POLL_WAIT_SECONDS, min_snapshot_delay_seconds), 0.00001)
			events =  inotify_obj.read(timeout=read_delay * 1000)
			if processPending and not to_process_flag.is_set():
				# the backuper took the batch, so its recursive folder copies run from now on: record events in those folders again.
				# check before the delays below can signal again, as a fresh signal hides that the batch was taken
				newDirWDs.clear()
				processPending = False
				lastProcessTime = time.monotonic()
			with mount_table_lock:
				mount_table, latest_mount_table[0] = latest_mount_table[0], None
			if mount_table is not None and follow_inner_mounts(inotify_obj,monitor_path,mount_table,inner_mounts,wdDic,irm,watch_flags,to_process,to_process_lock,skip_list,job_name):
				# like an event, so the backuper waits for the tree to settle before comparing the folders
				lastReadTime = time.monotonic()
			now = time.monotonic()
			expired_move_cookies = [cookie for cookie, change_event in pendingMoveFromEvents.items() if now - change_event.monotonic_time > move_pair_timeout]
			for cookie in expired_move_cookies:
				if DEBUG:
					watcherTeeLogToTl(monitor_path,f'Adding expired unmatched move_from as delete for cookie {cookie}')
				# also drop the cookie so a late MOVED_TO is treated as a create instead of a move from a deleted source
				cookie_value = cookieDic.pop(cookie,None)
				if cookie_value is not None and cookie_value.wds:
					# the folder left for a place with no watch (out of the tree, or into a skipped folder) and took its
					# watches along: they would report its new contents under the old path. gone before its delete is queued
					remove_moved_away_watches(inotify_obj,wdDic,irm,cookie_value.path,cookie_value.wds,watch_flags)
				append_change_event(to_process, to_process_lock, pendingMoveFromEvents.pop(cookie))
			if not events:
				if to_process and not to_process_flag.is_set() and time.monotonic() - lastReadTime > min_snapshot_delay_seconds:
					watcherTeeLogToTl(monitor_path,'Timeout elapsed, signaling backuper to process')
					to_process_flag.set()
					processPending = True
				continue
			if to_process and not to_process_flag.is_set() and time.monotonic() - lastProcessTime > max_shapshot_delay_seconds:
				watcherTeeLogToTl(monitor_path,'Max Delay timeout elapsed, signaling backuper to process')
				to_process_flag.set()
				processPending = True
			lastReadTime = time.monotonic()
			if DEBUG:
				decodedEvents = [[event.wd, flags.from_mask(event.mask),event.cookie, event.name] for event in events]
				watcherTeeLogToTl(monitor_path,'\n'+multiCMD.pretty_format_table(decodedEvents,header=['wd', 'mask','cookie','name']))
			monTime = time.monotonic()
			for event in events:
				if event.mask & flags.Q_OVERFLOW:
					watcherTeeLogToTl(monitor_path,'Queue overflow, event maybe lost',error=True)
					watcherTeeLogToTl(monitor_path,'Attempting to increase inotify max_queued_events')
					irm.increaseInotifyMaxQueueEvents(irm.max_queued_events * 2)
					# events were lost: request a full rescan so the backuper delta-generates against the latest version
					append_change_event(to_process, to_process_lock, ChangeEvent(monTime,False,'full_scan',monitor_path,None))
					continue
				isDir = True if event.mask & flags.ISDIR else False
				if event.mask & selfDestructMask:
					if event.wd == mainWatchDescriptor:
						# if UNMOUNT or IGNORED or DELETE_SELF, MOVE_SELF, return false
						watcherTeeLogToTl(monitor_path,'Main dir self destruct event detected, terminating')
						append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'self_destruct',monitor_path,None))
						return WATCH_RESULT_SELF_DESTRUCT
					elif event.mask & flags.DELETE_SELF:
						watcherTeeLogToTl(monitor_path,f'Sub dir delete self event detected, removing watch for {wdDic.get(event.wd,None)}')
						wdDic.pop(event.wd, None)
						irm.decreaseUserWatches()
						continue
					elif event.mask & flags.UNMOUNT:
						# the disk mounted inside the tree went away and took this watch along. watching the path again
						# here raised for each of its folders that is gone now; the mount table change re-watches the
						# mount point folder it uncovers (follow_inner_mounts)
						if event.wd in wdDic:
							watcherTeeLogToTl(monitor_path,f'Sub dir unmount event detected, dropping the watch for {wdDic[event.wd]}')
							del wdDic[event.wd]
							irm.decreaseUserWatches()
						else:
							watcherTeeLogToTl(monitor_path,f'Sub dir unmount event detected, but watch not in wdDic found for {event.wd}')
						continue
					elif event.mask & flags.MOVE_SELF:
						watcherTeeLogToTl(monitor_path,'Sub dir move self event detected, skipping')
						continue
				if not event.name:
					watcherTeeLogToTl(monitor_path,'Event name not found, ignoring event')
					continue
				if event.wd not in wdDic:
					watcherTeeLogToTl(monitor_path,f'Watch descriptor {event.wd} not found in wdDic {wdDic}, ignoring event')
					continue
				eventPath = os.path.join(wdDic[event.wd],event.name)
				skipped = skip_list is not None and skip_list.skips_path(eventPath,isDir)
				if discard_new_recursive_folder_events_until_read and event.wd in newDirWDs:
					watcherTeeLogToTl(monitor_path,f'Discarding event for new recursive folder {wdDic[event.wd]}')
					if isDir and not skipped and event.mask & (flags.CREATE | flags.MOVED_TO):
						# the recursive copy holds this folder, but it still needs watches for later changes,
						# and a folder moved in keeps its watches under its old path until they are added again here
						initializeFolderWatchers(inotify_obj,os.path.join(wdDic[event.wd],event.name),wdDic,irm,watch_flags,newDirWDs,skip_list=skip_list,job_name=job_name)
					if isDir and event.mask & flags.MOVED_TO and event.cookie in cookieDic:
						# the source stays in cookieDic so it still expires into its delete; its old-path watches are stale now
						remove_watches_under(inotify_obj,wdDic,irm,cookieDic[event.cookie].path)
					continue
				if skipped and not event.mask & (flags.MOVED_FROM | flags.MOVED_TO):
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Skipping event for skipped path {eventPath}')
					continue
				if event.mask & flags.CREATE:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Create event detected for {eventPath}')
					if isDir:
						initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags,newDirWDs,skip_list=skip_list,job_name=job_name)
					append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.DELETE:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Delete event detected for {eventPath}')
					append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'delete',eventPath,None))
				elif event.mask & flags.ATTRIB:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Attrib event detected for {eventPath}')
					append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'attrib',eventPath,None))
				elif event.mask & flags.MOVED_FROM:
					if skipped:
						# no cookie is recorded, so a matching MOVED_TO is handled as a create
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Skipping move from event for skipped path {eventPath}')
						continue
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Move from event detected for {eventPath}')
					cookieDic[event.cookie] = COOKIE_VALUE(event.wd,eventPath,isDir,watches_under(wdDic,eventPath) if isDir else ())
					while len(cookieDic) > COOKIE_DICT_MAX_SIZE:
						watcherTeeLogToTl(monitor_path,'Cookie dictionary is full, popping oldest item')
						evicted_cookie,cookie_value = cookieDic.popitem(last=False)
						# drop the matching pending move_from so its expiry does not emit a second delete
						pendingMoveFromEvents.pop(evicted_cookie,None)
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Adding delete event for {cookie_value.path}')
						if cookie_value.wds:
							remove_moved_away_watches(inotify_obj,wdDic,irm,cookie_value.path,cookie_value.wds,watch_flags)
						append_change_event(to_process, to_process_lock, ChangeEvent(monTime,cookie_value.isDir,'delete',cookie_value.path,None))
					#append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'move',eventPath,None))
					pendingMoveFromEvents[event.cookie] = ChangeEvent(monTime,isDir,'delete',eventPath,None)
				elif event.mask & flags.MOVED_TO:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Move to event detected for {eventPath}')
					if skipped:
						# the destination is not backed up: a known source is gone from the backup, otherwise there is nothing to record
						if event.cookie in cookieDic:
							cookie_value = cookieDic.pop(event.cookie)
							pendingMoveFromEvents.pop(event.cookie,None)
							append_change_event(to_process, to_process_lock, ChangeEvent(monTime,cookie_value.isDir,'delete',cookie_value.path,None))
							if cookie_value.isDir:
								remove_watches_under(inotify_obj,wdDic,irm,cookie_value.path)
						elif DEBUG:
							watcherTeeLogToTl(monitor_path,f'Skipping move to event for skipped path {eventPath}')
						continue
					if event.cookie in cookieDic:
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Cookie found for {event.cookie}')
							watcherTeeLogToTl(monitor_path,f'Adding move event for {cookieDic[event.cookie].path} to {eventPath}')
						cookie_value = cookieDic.pop(event.cookie)
						pendingMoveFromEvents.pop(event.cookie,None)
						append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'move',eventPath,cookie_value.path))
						if isDir:
							# we need to update wdDic to reflect the new path,
							# including all descendant watches of the moved directory.
							# iterate over a snapshot as wdDic mutates its inverse mapping on assignment
							old_path_norm = cookie_value.path.rstrip('/')
							old_prefix = old_path_norm + '/'
							new_path_norm = eventPath.rstrip('/')
							for wd, wd_path in list(wdDic.items()):
								wd_path_norm = wd_path.rstrip('/')
								if wd_path_norm == old_path_norm:
									new_wd_path = new_path_norm
								elif wd_path_norm.startswith(old_prefix):
									new_wd_path = new_path_norm + '/' + wd_path_norm[len(old_prefix):]
								else:
									continue
								if wd_path.endswith('/'):
									new_wd_path += '/'
								if DEBUG:
									watcherTeeLogToTl(monitor_path,f'Updating wdDic entry {wd}: {wd_path} -> {new_wd_path}')
								wdDic[wd] = new_wd_path
							if skip_list is not None and skip_list.location_dependent:
								rewatch_moved_folder(inotify_obj,eventPath,wdDic,irm,watch_flags,skip_list)
					else:
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Cookie not found for {event.cookie}')
							watcherTeeLogToTl(monitor_path,f'Treating move as create event for {eventPath}')
						if isDir:
							initializeFolderWatchers(inotify_obj,eventPath,wdDic,irm,watch_flags,newDirWDs,skip_list=skip_list,job_name=job_name)
						append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'create',eventPath,None))
				elif event.mask & flags.MODIFY:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Modify event detected for {eventPath}')
					append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'modify',eventPath,None))
				else:
					watcherTeeLogToTl(monitor_path,f'Unprocessed event {event}')
	return WATCH_RESULT_OK

def watcherTeeLogToTl(monitor_path:str,message:str,error=False,ok=False):
	global tl
	global DEBUG
	message = f'{WATCHER_LOG_PREFIX}| {monitor_path} | ' + message
	if error:
		tl.teeerror(message,callerStackDepth=4)
	elif ok:
		tl.teeok(message,callerStackDepth=4)
	elif DEBUG:
		tl.teeprint(message,callerStackDepth=4)
	else:
		tl.info(message,callerStackDepth=4)

class bidict(dict):
	'''
	Bidirectional dict mapping keys to values with an inverse index.

	Examples:
		>>> d = bidict({1: '/a', 2: '/b'})
		>>> d.inverse['/a']
		[1]
		>>> d[1] = '/c'
		>>> '/a' in d.inverse
		False
		>>> d.inverse['/c']
		[1]
		>>> del d[2]
		>>> '/b' in d.inverse
		False
	'''
	# Credit: https://stackoverflow.com/users/1422096/basj
	# https://stackoverflow.com/questions/3318625/how-to-implement-an-efficient-bidirectional-hash-table
	def __init__(self, *args, **kwargs):
		super(bidict, self).__init__(*args, **kwargs)
		self.inverse = {}
		for key, value in self.items():
			self.inverse.setdefault(value, []).append(key) 

	def __setitem__(self, key, value):
		if key in self:
			old = self[key]
			self.inverse[old].remove(key)
			if not self.inverse[old]:
				del self.inverse[old]
		super(bidict, self).__setitem__(key, value)
		self.inverse.setdefault(value, []).append(key) 

	def __delitem__(self, key):
		self.inverse.setdefault(self[key], []).remove(key)
		if self[key] in self.inverse and not self.inverse[self[key]]: 
			del self.inverse[self[key]]
		super(bidict, self).__delitem__(key)

def initializeFolderWatchers(inotify_obj:inotify_simple.INotify,monitor_path:str,wdDic:dict,irm:inotify_resource_manager,watch_flags:int,newDirWds = None,skip_list:'SkipList' = None,job_name:str = None):
	if not os.path.exists(monitor_path):
		return -1
	irm.increaseUserWatches()
	watcherTeeLogToTl(monitor_path,f'Adding watch for {monitor_path}')
	try:
		parentWatchDescriptor = inotify_obj.add_watch(monitor_path, watch_flags)
	except Exception as e:
		watcherTeeLogToTl(monitor_path,f'Failed to add watch for {monitor_path}: {e}',error=True)
		# counted above but never taken: an inner mount that keeps failing would add up over a long run
		irm.decreaseUserWatches()
		return -1
	if newDirWds is not None:
		newDirWds.add(parentWatchDescriptor)
	wdDic[parentWatchDescriptor] = monitor_path
	unreadable = []
	allFolders = get_all_folders(monitor_path,skip_list,unreadable)
	# an unreadable folder gets no watch: nothing can be told about what is in it
	unreadable_folders = {folder.rstrip('/') for folder, _ in unreadable if folder.rstrip('/') != monitor_path.rstrip('/')}
	for folder, error in unreadable:
		if folder.rstrip('/') in unreadable_folders:
			watcherTeeLogToTl(monitor_path,f'Not watching unreadable folder {folder}: {error}',error=True)
	allFolders = [folder for folder in allFolders if folder.rstrip('/') not in unreadable_folders]
	watcherTeeLogToTl(monitor_path,f'Adding watch for {len(allFolders)} sub folders')
	irm.increaseUserWatches(len(allFolders))
	for folder in allFolders:
		try:
			childWd = inotify_obj.add_watch(folder, watch_flags)
			if newDirWds is not None:
				newDirWds.add(childWd)
			wdDic[childWd] = folder
		except Exception as e:
			watcherTeeLogToTl(monitor_path,f'Failed to add watch for {folder}: {e}',error=True)
			irm.decreaseUserWatches()
			continue
	return parentWatchDescriptor

def watches_under(wdDic:bidict,folder_path:str) -> tuple:
	'''The watch descriptors mapped to folder_path or below it.'''
	folder_norm = folder_path.rstrip('/')
	prefix = folder_norm + '/'
	return tuple(wd for wd, wd_path in wdDic.items() if wd_path.rstrip('/') == folder_norm or wd_path.startswith(prefix))

def remove_watches_under(inotify_obj:inotify_simple.INotify,wdDic:bidict,irm:inotify_resource_manager,folder_path:str) -> int:
	'''Remove the watch on folder_path and every watch below it; returns how many were removed.'''
	folder_norm = folder_path.rstrip('/')
	prefix = folder_norm + '/'
	removed = 0
	for wd, wd_path in list(wdDic.items()):
		wd_norm = wd_path.rstrip('/')
		if wd_norm != folder_norm and not wd_norm.startswith(prefix):
			continue
		try:
			inotify_obj.rm_watch(wd)
		except OSError:
			pass
		del wdDic[wd]
		irm.decreaseUserWatches()
		removed += 1
	return removed

def follow_inner_mounts(inotify_obj:inotify_simple.INotify,monitor_path:str,mount_table:list,inner_mounts:dict,wdDic:bidict,irm:inotify_resource_manager,watch_flags:int,to_process:ChangeEventQueue,to_process_lock:threading.Lock,skip_list:'SkipList' = None,job_name:str = None) -> int:
	'''
	Bring the watches in line with a new mount table. Each inner mount mounted, unmounted or replaced since inner_mounts
	(path -> fingerprint, updated here) is watched again from what is there now, and gets a 'scan' event so the backuper
	compares that folder with the vault. Returns how many folders it queued.
	An unmounted disk's watches go with its IN_UNMOUNT events, or here if those come later (a lazy unmount sends none
	while the disk is still in use); the mount point folder it uncovers is watched in their place.
	'''
	current = watched_inner_mounts(mount_table, monitor_path, skip_list)
	queued = 0
	for mount_point in sorted(current.keys() | inner_mounts.keys()):
		fingerprint = current.get(mount_point)
		if fingerprint == inner_mounts.get(mount_point):
			continue
		if fingerprint is not None and not os.path.isdir(mount_point):
			# a file mounted over a file, or a disk that does not answer: nothing to watch, looked at again with the next table
			continue
		change = 'mounted' if mount_point not in inner_mounts else 'unmounted' if fingerprint is None else 'replaced'
		watcherTeeLogToTl(monitor_path,f'Inner mount {mount_point} {change}, watching what is there now and comparing it with the vault')
		remove_watches_under(inotify_obj,wdDic,irm,mount_point)
		# not into newDirWDs: the scan compares what is there already, and later events in it are recorded as they come
		initializeFolderWatchers(inotify_obj,mount_point,wdDic,irm,watch_flags,skip_list=skip_list,job_name=job_name)
		if fingerprint is None:
			del inner_mounts[mount_point]
		else:
			inner_mounts[mount_point] = fingerprint
		# queued after its watches are in place, so the comparison cannot run first and miss a change made in between
		append_change_event(to_process, to_process_lock, ChangeEvent(time.monotonic(),True,'scan',mount_point,None))
		queued += 1
	return queued

def remove_moved_away_watches(inotify_obj:inotify_simple.INotify,wdDic:bidict,irm:inotify_resource_manager,folder_path:str,wds,watch_flags:int) -> int:
	'''
	Remove the watches a folder took along when it moved away and its move never paired; returns how many were removed.
	Of wds, the watches at or below folder_path when it moved, only those still mapped there go, and not one that inotify
	hands back for the folder now at its path: a folder moved back brings its old watches, a folder created there has new ones.
	'''
	folder_norm = folder_path.rstrip('/')
	prefix = folder_norm + '/'
	removed = 0
	for wd in wds:
		wd_path = wdDic.get(wd)
		if wd_path is None:
			continue
		wd_norm = wd_path.rstrip('/')
		if wd_norm != folder_norm and not wd_norm.startswith(prefix):
			continue
		try:
			# watching a folder that already has a watch returns that watch, unchanged with the same flags
			current_wd = inotify_obj.add_watch(wd_norm, watch_flags | inotify_simple.flags.ONLYDIR | inotify_simple.flags.DONT_FOLLOW)
		except OSError:
			current_wd = None
		if current_wd == wd:
			continue
		if current_wd is not None and current_wd not in wdDic:
			# a folder there with no watch yet gets one when its create event is read
			try:
				inotify_obj.rm_watch(current_wd)
			except OSError:
				pass
		try:
			inotify_obj.rm_watch(wd)
		except OSError:
			pass
		del wdDic[wd]
		irm.decreaseUserWatches()
		removed += 1
	return removed

def rewatch_moved_folder(inotify_obj:inotify_simple.INotify,folder_path:str,wdDic:bidict,irm:inotify_resource_manager,watch_flags:int,skip_list:'SkipList') -> None:
	'''After a folder moved, make its watches match what the skip list wants at the new location.'''
	wanted = get_all_folders(folder_path,skip_list)
	wanted_norm = {folder.rstrip('/') for folder in wanted}
	folder_norm = folder_path.rstrip('/')
	prefix = folder_norm + '/'
	watched = set()
	for wd, wd_path in list(wdDic.items()):
		if wd not in wdDic:
			continue
		wd_norm = wd_path.rstrip('/')
		if wd_norm == folder_norm or not wd_norm.startswith(prefix):
			continue
		if wd_norm in wanted_norm:
			watched.add(wd_norm)
		else:
			remove_watches_under(inotify_obj,wdDic,irm,wd_path)
	for folder in wanted:
		if folder.rstrip('/') in watched:
			continue
		irm.increaseUserWatches()
		try:
			wdDic[inotify_obj.add_watch(folder,watch_flags)] = folder
		except Exception as e:
			watcherTeeLogToTl(folder_path,f'Failed to add watch for {folder}: {e}',error=True)
			irm.decreaseUserWatches()

def iter_tree_entries(path:str, rel_prefix:str = '', list_folders_first:bool = False, skip = None, errors:list = None):
	'''
	Walk path depth first, yielding (entry_path, rel_path, is_dir) with each folder right before its contents.
	Folder paths end with /. Symlinks to folders are not followed and come out as files.
	Nothing is listed up front, so walking a tree of 500k entries holds only the open folders of one branch.
	With list_folders_first, each folder is read in full before its entries are yielded, so the caller can replace
	entries as it goes: renaming into a folder still being read can make the listing skip an entry (through mergerfs
	the entry can move to another branch).
	skip(rel_path) -> bool leaves an entry out; a skipped folder is not descended into.
	A folder that cannot be read is logged, and (its rel_prefix, error) is appended to errors when given: its entries
	are missing from the walk, which is not the same as being deleted. The walk root reports rel_prefix as given.

	Examples:
		>>> import tempfile
		>>> root = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(root, 'd', 'e'))
		>>> open(os.path.join(root, 'd', 'e', 'f'), 'w').close()
		>>> os.symlink('d', os.path.join(root, 'link'))
		>>> sorted((rel_path, is_dir) for _, rel_path, is_dir in iter_tree_entries(root))
		[('d/', True), ('d/e/', True), ('d/e/f', False), ('link', False)]
		>>> [entry_path == os.path.join(root, rel_path) for entry_path, rel_path, _ in iter_tree_entries(root)]
		[True, True, True, True]
		>>> sorted(rel_path for _, rel_path, _ in iter_tree_entries(root, skip=lambda rel: rel == 'd/e/'))
		['d/', 'link']
		>>> import shutil; shutil.rmtree(root)
	'''
	try:
		with os.scandir(path) as entries:
			if list_folders_first:
				entries = list(entries)
			for entry in entries:
				rel_path = rel_prefix + entry.name
				if entry.is_dir(follow_symlinks=False):
					if skip is not None and skip(rel_path + '/'):
						continue
					yield entry.path + '/', rel_path + '/', True
					yield from iter_tree_entries(entry.path, rel_path + '/', list_folders_first, skip, errors)
				else:
					if skip is not None and skip(rel_path):
						continue
					yield entry.path, rel_path, False
	except Exception as e:
		if errors is not None:
			errors.append((rel_prefix, e))
		watcherTeeLogToTl(path,f'Error scanning {path}: {e}',error=True)

def unreadable_path(root:str, rel:str) -> str:
	'''The absolute path of the folder rel (relative to root, '' for root itself).'''
	return os.path.join(root, rel).rstrip('/') or '/'

def log_unreadable(job_name:str, root:str, errors:list, reported:set = None):
	'''Log one UNREADABLE line for each unreadable folder in errors, as collected by a walk of root.
	reported holds the paths already logged by this backup, so a folder walked twice is logged once.'''
	for rel, error in errors:
		path = unreadable_path(root, rel)
		if reported is not None:
			if path in reported:
				continue
			reported.add(path)
		job_log(job_name, f'UNREADABLE: {path}: {error}; keeping its last backed-up copy')

def get_all_folders(path, skip_list:'SkipList' = None, errors:list = None):
	'''The folders under path. Unreadable ones are in the list too, and appended to errors as (absolute path, error).'''
	rel_base = '' if skip_list is None else skip_list.folder_rel(path)
	walk_errors = []
	folders = [entry_path for entry_path, _, is_dir in iter_tree_entries(path, rel_base, skip=None if skip_list is None else skip_list.skips, errors=walk_errors) if is_dir]
	if errors is not None:
		errors.extend((unreadable_path(path, rel[len(rel_base):]), error) for rel, error in walk_errors)
	return folders


def load_pending_transactions_for_resume(job_name:str, monitor_path:str, vault_path:str, to_process:ChangeEventQueue, skip_list:'SkipList' = None) -> bool:
	# stored inside the per-job vault folder so jobs sharing a vault path do not clobber each other
	pending_transactions_path = os.path.join(vault_path, job_name, PENDING_TRANSACTIONS_FILE_NAME)
	if not os.path.exists(pending_transactions_path):
		return False
	try:
		pending_mtime = os.path.getmtime(pending_transactions_path)
	except Exception as e:
		backuperTeeLogToTl(job_name, f'Failed to read pending transactions timestamp for {pending_transactions_path}: {e}', error=True)
		return False
	latest_monitor_change = get_monitor_path_most_recent_change_time(monitor_path, skip_list)
	# Resume only when the latest monitor-path mtime is at least 1 second older
	# than the pending file (no filesystem changes after the pending snapshot).
	should_resume = latest_monitor_change <= pending_mtime - 1.0
	if not should_resume:
		backuperTeeLogToTl(job_name, 'Pending transactions file exists but did not pass resume timestamp check. Falling back to delta generation.')
		try:
			os.remove(pending_transactions_path)
		except Exception as e:
			backuperTeeLogToTl(job_name, f'Failed to remove skipped pending transactions file {pending_transactions_path}: {e}', error=True)
		return False
	loaded_count = 0
	available, _, _ = read_memory_state()
	# reading the file holds every row as Python lists, about four times the file's size
	if available is not None and os.path.getsize(pending_transactions_path) * 4 > available * QUEUE_MEMORY_SHARE:
		backuperTeeLogToTl(job_name, f'Pending transactions file {pending_transactions_path} is too large for the memory available, requesting a full scan instead', error=True)
		to_process.append(ChangeEvent(time.monotonic(), False, 'full_scan', monitor_path, None))
		try:
			os.remove(pending_transactions_path)
		except Exception as e:
			backuperTeeLogToTl(job_name, f'Failed to remove pending transactions file {pending_transactions_path}: {e}', error=True)
		return True
	try:
		pending_rows_raw = TSVZ.readTabularFile(
			pending_transactions_path,
			header=CHANGED_EVENT_HEADER,
			verifyHeader=True,
			strict=False,
			verbose=DEBUG,
			defaults=[],
			correctColumnNum=len(CHANGED_EVENT_HEADER)
		)
		with open(pending_transactions_path, 'rb') as f:
			# one line per row after the header
			written_rows = sum(chunk.count(b'\n') for chunk in iter(lambda: f.read(1 << 20), b'')) - 1
		if pending_rows_raw and len(pending_rows_raw) != written_rows:
			# rows are keyed by their time when read back, and files written before times were spaced apart lose
			# every row sharing one. replaying the rest would skip those changes, so compare the whole tree instead
			backuperTeeLogToTl(job_name, f'Read {len(pending_rows_raw)} of {written_rows} pending transactions, requesting a full scan instead')
			pending_rows_raw = {}
			to_process.append(ChangeEvent(time.monotonic(), False, 'full_scan', monitor_path, None))
			loaded_count += 1
		for row in pending_rows_raw.values():
			moved_from = row[4]
			if moved_from == '':
				moved_from = None
			to_process.append(ChangeEvent(
				float(row[0]),
				row[1] in (True, 'True', 'true', '1', 1),
				row[2],
				row[3],
				moved_from
			))
			loaded_count += 1
		try:
			os.remove(pending_transactions_path)
		except Exception as e:
			backuperTeeLogToTl(job_name, f'Failed to remove pending transactions file {pending_transactions_path}: {e}', error=True)
		backuperTeeLogToTl(job_name, f'Loaded {loaded_count} pending transactions from {pending_transactions_path}')
	except Exception as e:
		backuperTeeLogToTl(job_name, f'Failed to load pending transactions from {pending_transactions_path}: {e}', error=True)
		to_process.clear()
		try:
			os.remove(pending_transactions_path)
		except Exception as e:
			backuperTeeLogToTl(job_name, f'Failed to remove pending transactions file {pending_transactions_path}: {e}', error=True)
		loaded_count = 0
	return loaded_count > 0

def get_monitor_path_most_recent_change_time(monitor_path:str, skip_list:'SkipList' = None) -> float:
	latest_mtime = 0.0
	paths_to_scan = [monitor_path]
	while paths_to_scan:
		current_path = paths_to_scan.pop()
		try:
			current_stat = os.stat(current_path, follow_symlinks=False)
			latest_mtime = max(latest_mtime, current_stat.st_mtime)
		except Exception as e:
			watcherTeeLogToTl(monitor_path, f'Error reading stat for {current_path}: {e}', error=True)
			# what cannot be read cannot be shown unchanged
			return float('inf')
		if os.path.isdir(current_path) and not os.path.islink(current_path):
			try:
				with os.scandir(current_path) as entries:
					for entry in entries:
						if skip_list is not None and skip_list.skips_path(entry.path, entry.is_dir(follow_symlinks=False)):
							continue
						paths_to_scan.append(entry.path)
			except Exception as e:
				watcherTeeLogToTl(monitor_path, f'Error scanning {current_path}: {e}', error=True)
				return float('inf')
	return latest_mtime

def check_fs_signature(path:str,signature:str):
	'''
	Return whether path still lives on the filesystem identified by signature.

	When signature is empty, ``N/A``, or ``auto``, monitoring is not gated on FS identity.

	Examples:
		>>> check_fs_signature('/tmp', 'N/A')
		True
		>>> check_fs_signature('/tmp', 'auto')
		True
		>>> check_fs_signature('/tmp', '')
		True
	'''
	# not: as findmnt not garenteed to have inode number, and lsblk have more fileds anyway.
		# use findmnt --json --output SOURCE,TARGET,FSTYPE,LABEL,UUID,PARTLABEL,PARTUUID,SIZE,USE%,FSROOT --target 
		# if FS UUID is not available / not match, try part uuid, then fs label, then part label, then dev path
	# df --no-sync --output=source,ipcent,pcent,target for use percentage
	# lsblk --raw --paths --output=kname,label,model,name,partlabel,partuuid,uuid,serial,fstype,wwn <dev> for infos
	if not signature or signature == 'N/A' or signature == 'auto':
		return True
	pathSignatures = get_fs_signatures(path)
	if not pathSignatures:
		return False
	return signature in pathSignatures

def get_fs_signatures(path:str) -> list:
	global DEBUG
	# df --no-sync --output=source,ipcent,pcent,target for use percentage
	# lsblk --raw --paths --output=kname,label,model,name,partlabel,partuuid,uuid,serial,fstype,wwn <dev> for infos
	rtnHost = multiCMD.run_command(['df','--no-sync','--output=source',path],timeout=60,quiet=not DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or len(rtnHost.stdout) <= 1:
		return []
	deviceName = rtnHost.stdout[1].split()[0]
	rtnHost = multiCMD.run_command(['lsblk','--raw','--output=uuid,label,partuuid,partlabel,wwn,serial,model,name,kname,pkname',deviceName],timeout=60,quiet=not DEBUG,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or len(rtnHost.stdout) <= 1:
		return [deviceName]
	fields = rtnHost.stdout[1].split()
	# lsblk do \x escape for some characters, we need to unescape them
	fields = [bytes(f, 'utf-8').decode('unicode_escape') for f in fields if f]
	return fields

def parse_mount_table(mountinfo:bytes) -> list:
	r'''
	Parse /proc/self/mountinfo content into (mount_point, fingerprint) pairs in kernel order.

	The fingerprint (mount id, device, fs root, source) changes whenever the mount is replaced,
	and later entries stack on top of earlier ones at the same mount point.

	Examples:
		>>> table = parse_mount_table(b'22 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n'
		...     b'40 22 8:17 /data /mnt/my\\040disk rw - xfs /dev/sdb1 rw\n')
		>>> [mount_point for mount_point, _ in table]
		['/', '/mnt/my disk']
		>>> table[1][1]
		(b'40', b'8:17', b'/data', b'/dev/sdb1')
		>>> parse_mount_table(b'garbage\n')
		[]
	'''
	mount_table = []
	for line in mountinfo.splitlines():
		fields = line.split()
		if len(fields) < 5:
			continue
		# optional fields end at a lone '-', followed by fs type and source
		try:
			source = fields[fields.index(b'-', 6) + 2]
		except (ValueError, IndexError):
			source = b''
		# mountinfo octal-escapes space, tab, newline and backslash
		mount_point = re.sub(rb'\\([0-7]{3})', lambda m: bytes([int(m.group(1), 8)]), fields[4])
		mount_table.append((os.fsdecode(mount_point), (fields[0], fields[2], fields[3], source)))
	return mount_table

def mount_fingerprint(mount_table:list, path:str):
	'''
	Fingerprint of the mount containing path: the deepest mount point, topmost when stacked.

	Examples:
		>>> table = [('/', ('root',)), ('/mnt', ('a',)), ('/mnt', ('b',)), ('/mnt2', ('c',))]
		>>> mount_fingerprint(table, '/mnt/x/y')
		('b',)
		>>> mount_fingerprint(table, '/mnt2x')
		('root',)
		>>> mount_fingerprint([], '/mnt') is None
		True
	'''
	fingerprint = None
	deepest = -1
	for mount_point, mount_id in mount_table:
		if mount_point == '/' or path == mount_point or path.startswith(mount_point + '/'):
			if len(mount_point) >= deepest:
				deepest = len(mount_point)
				fingerprint = mount_id
	return fingerprint

def inner_mount_points(mount_table:list, monitor_path:str) -> list:
	'''
	The mount points in mount_table (as parse_mount_table gives it) strictly under monitor_path once resolved, sorted.

	Examples:
		>>> table = [('/', ('1',)), ('/tmp/reverb_doctest/m', ('2',)), ('/tmp/reverb_doctest/m/disk', ('3',)),
		...     ('/tmp/reverb_doctest/m/a b', ('4',)), ('/tmp/reverb_doctest/m/disk', ('5',)), ('/tmp/reverb_doctest/mx', ('6',))]
		>>> inner_mount_points(table, '/tmp/reverb_doctest/m/')
		['/tmp/reverb_doctest/m/a b', '/tmp/reverb_doctest/m/disk']
		>>> inner_mount_points(table, '/')[:2]
		['/tmp/reverb_doctest/m', '/tmp/reverb_doctest/m/a b']
		>>> inner_mount_points([], '/tmp/reverb_doctest/m')
		[]
	'''
	root = os.path.realpath(monitor_path)
	prefix = root.rstrip('/') + '/'
	return sorted({mount_point for mount_point, _ in mount_table if mount_point != root and mount_point.startswith(prefix)})

def current_mount_table() -> list:
	'''The mount table now, as parse_mount_table gives it; [] when it cannot be read.'''
	try:
		with open(MOUNTINFO_PATH, 'rb') as f:
			return parse_mount_table(f.read())
	except Exception:
		return []

def watched_inner_mounts(mount_table:list, monitor_path:str, skip_list:'SkipList' = None) -> dict:
	'''
	The inner mounts a watcher of monitor_path follows: each mount point strictly under it, as a path under monitor_path
	as given, mapped to the fingerprint of what is mounted there (the topmost of stacked mounts). A mount point the skip
	list leaves out, or one in a folder it leaves out, is not followed.

	Examples:
		>>> table = [('/', ('1',)), ('/tmp/reverb_doctest/m/disk', ('2',)), ('/tmp/reverb_doctest/m/disk', ('3',)),
		...     ('/tmp/reverb_doctest/m/cache/usb', ('4',))]
		>>> watched_inner_mounts(table, '/tmp/reverb_doctest/m/')
		{'/tmp/reverb_doctest/m/cache/usb': ('4',), '/tmp/reverb_doctest/m/disk': ('3',)}
		>>> watched_inner_mounts(table, '/tmp/reverb_doctest/m', SkipList('/tmp/reverb_doctest/m', ['cache/']))
		{'/tmp/reverb_doctest/m/disk': ('3',)}
	'''
	real_root = os.path.realpath(monitor_path)
	mounts = {}
	for mount_point in inner_mount_points(mount_table, monitor_path):
		rel = os.path.relpath(mount_point, real_root)
		if skip_list is not None:
			# skips() checks an entry alone, so every folder on the way down is checked
			parts = rel.split('/')
			if any(skip_list.skips('/'.join(parts[:depth]) + '/') for depth in range(1, len(parts) + 1)):
				continue
		mounts[os.path.join(monitor_path, rel)] = mount_fingerprint(mount_table, mount_point)
	return mounts

class fs_signature_monitor:
	'''
	One shared daemon thread keeping a flag per (path, signature) pair set while the path lives
	on the filesystem identified by signature.

	Replaces a findmnt --poll subprocess (plus its multiCMD threads) per path: /proc/self/mountinfo
	raises POLLPRI on every mount table change, the same signal findmnt --poll waits on. A pair is
	only re-checked (df + lsblk) when the mount containing its path changes, like findmnt --target,
	and rules sharing a path share that check. Every mount table it reads also goes to its subscribers
	(watchers following the mounts inside their trees).
	'''
	def __init__(self, mountinfo_path:str = MOUNTINFO_PATH):
		self.mountinfo_path = mountinfo_path
		self.lock = threading.Lock()
		# (path, signature) -> [threading.Event], one per register() call
		self.flags = {}
		# (path, signature) -> fingerprint of the mount containing path at its last check
		self.fingerprints = {}
		# (path, signature) -> result of its last check
		self.states = {}
		# (path, signature) -> bumped by invalidate(), so a check that started before it does not store its stale result
		self.generations = {}
		# token -> callback(mount_table), told each time the mount table is read
		self.subscribers = {}
		self.thread = None
		self.wake_r, self.wake_w = os.pipe()
		os.set_blocking(self.wake_r, False)
		os.set_blocking(self.wake_w, False)

	def register(self, path:str, signature:str) -> threading.Event:
		'''
		Get a flag for path / signature. Every caller gets its own Event, so a caller clearing
		it (watcher on self destruct) stays blocked until the containing mount changes.
		'''
		fs_event = threading.Event()
		key = (path, signature)
		with self.lock:
			if self.states.get(key):
				fs_event.set()
			self.flags.setdefault(key, []).append(fs_event)
		self.start()
		return fs_event

	def start(self):
		with self.lock:
			if self.thread is None or not self.thread.is_alive():
				# mount changes were not observed while stopped
				self.fingerprints.clear()
				self.thread = threading.Thread(target=self.run, name='fs_signature_monitor', daemon=True)
				self.thread.start()
		self.wake()

	def unregister(self, path:str, signature:str, fs_event:threading.Event):
		key = (path, signature)
		with self.lock:
			fs_events = self.flags.get(key, [])
			if fs_event in fs_events:
				fs_events.remove(fs_event)
			if not fs_events:
				self.flags.pop(key, None)
				self.fingerprints.pop(key, None)
				self.states.pop(key, None)

	def subscribe(self, callback) -> object:
		'''
		Have callback(mount_table) run on the monitor thread each time it reads the mount table: once right after
		subscribing, then on every mount table change and every periodic re-check. Returns a token for unsubscribe().
		The callback runs outside the monitor's lock (it takes its own) and must not block.
		'''
		token = object()
		with self.lock:
			self.subscribers[token] = callback
		# start() wakes the monitor: its next pass is the call right after subscribing
		self.start()
		return token

	def unsubscribe(self, token):
		'''Stop calling a subscriber back; a pass already under way may still call it once.'''
		with self.lock:
			self.subscribers.pop(token, None)

	@contextlib.contextmanager
	def subscription(self, callback):
		'''subscribe() for the length of a with block.'''
		token = self.subscribe(callback)
		try:
			yield token
		finally:
			self.unsubscribe(token)

	def notify(self, mount_table:list):
		'''Hand a mount table to every subscriber; one that raises is logged and does not keep it from the others.'''
		with self.lock:
			callbacks = list(self.subscribers.values())
		for callback in callbacks:
			try:
				callback(mount_table)
			except Exception:
				import traceback
				watcherTeeLogToTl(self.mountinfo_path, traceback.format_exc(), error=True)

	def invalidate(self, path:str, signature:str):
		'''Clear every flag of a pair now and have the monitor check it again, as a watched root was unmounted or removed.'''
		key = (path, signature)
		with self.lock:
			for fs_event in self.flags.get(key, []):
				fs_event.clear()
			if key in self.flags:
				self.states[key] = False
			self.fingerprints.pop(key, None)
			self.generations[key] = self.generations.get(key, 0) + 1
		self.wake()

	def wake(self):
		try:
			os.write(self.wake_w, b'\0')
		except BlockingIOError:
			# pipe full: a wake up is already pending
			pass

	def check_changed(self, recheck_failed:bool = False):
		'''
		Re-check every pair whose containing mount changed since its last check, and with recheck_failed those whose last
		check failed. The mount table read for it goes to the subscribers first.
		'''
		try:
			with open(self.mountinfo_path, 'rb') as f:
				mount_table = parse_mount_table(f.read())
		except Exception:
			# not handed to the subscribers: they would take every inner mount for unmounted
			mount_table = []
		else:
			# before the signature checks, so a slow df or lsblk does not hold back a watcher following an inner mount
			self.notify(mount_table)
		with self.lock:
			keys = list(self.flags)
		for key in keys:
			path, signature = key
			fingerprint = mount_fingerprint(mount_table, os.path.realpath(path))
			with self.lock:
				if self.fingerprints.get(key, ...) == fingerprint and (self.states.get(key) or not recheck_failed):
					continue
				generation = self.generations.get(key, 0)
			fs_ok = check_fs_signature(path, signature)
			with self.lock:
				if key not in self.flags or self.generations.get(key, 0) != generation:
					continue
				changed = self.states.get(key) != fs_ok
				self.fingerprints[key] = fingerprint
				self.states[key] = fs_ok
				for fs_event in self.flags[key]:
					if fs_ok:
						fs_event.set()
					else:
						fs_event.clear()
			if changed:
				watcherTeeLogToTl(path, f'FS signature {signature} for {path} ' + ('verified.' if fs_ok else 'does not match, pausing.'))

	def run(self):
		global GREEN_LIGHT
		poller = select.poll()
		poller.register(self.wake_r, select.POLLIN)
		mountinfo_file = None
		try:
			mountinfo_file = open(self.mountinfo_path, 'rb')
			# the mount table always polls readable, POLLPRI | POLLERR only fire on a change
			poller.register(mountinfo_file.fileno(), select.POLLPRI)
		except Exception as e:
			watcherTeeLogToTl(self.mountinfo_path, f'Failed to watch mount table, fs signatures will not be re-checked on mount changes: {e}', error=True)
		recheck_at = 0.0
		try:
			while True:
				with self.lock:
					# decided under the lock so register() never hands a pair to an exiting thread
					if not GREEN_LIGHT.is_set():
						self.thread = None
						return
				try:
					self.check_changed(recheck_failed=time.monotonic() >= recheck_at)
				except Exception:
					import traceback
					watcherTeeLogToTl(self.mountinfo_path, traceback.format_exc(), error=True)
				# a pair that failed is re-checked every FS_RECHECK_SECONDS: a deleted and re-created path changes no mount
				recheck_at = time.monotonic() + FS_RECHECK_SECONDS
				while GREEN_LIGHT.is_set() and not poller.poll(int(max(POLL_WAIT_SECONDS * 1000, 1))):
					if time.monotonic() >= recheck_at:
						break
				try:
					while os.read(self.wake_r, 4096):
						pass
				except BlockingIOError:
					pass
		finally:
			if mountinfo_file is not None:
				mountinfo_file.close()

FS_SIGNATURE_MONITOR = fs_signature_monitor()

#%% ---- Backup ----
def backuper(job_name:str,to_process:ChangeEventQueue,to_process_lock:threading.Lock,monitor_path:str,vault_path:str,vault_path_signature:str,
			 to_process_flag:threading.Event,monitor_fs_flag:threading.Event=None,
			 keep_one_complete_backup:bool = DEFAULT_KEEP_ONE_COMPLETE_BACKUP, 
			 only_sync_attributes:bool = DEFAULT_ONLY_SYNC_ATTRIBUTES, keep_n_versions:int = DEFAULT_KEEP_N_VERSIONS, 
			 backup_size_limit:str = DEFAULT_BACKUP_SIZE_LIMIT, log_journal:bool = False, startup:JobStartup = None, job:JobControl = None):
	global BACKUP_SEMAPHORE
	global BACKUP_ENTRY_VALUES_HEADER
	global GREEN_LIGHT
	# main function for handling the backup for one reverb. with a job, a failure stops only that job, and so does the job failing
	running = GREEN_LIGHT.is_set if job is None else job.should_run
	if monitor_fs_flag is None:
		# no monitor fs gating requested: use an always-set event
		monitor_fs_flag = threading.Event()
		monitor_fs_flag.set()
	vault_fs_flag = None
	manifest = None
	skip_list = None
	# the batch taken and not committed yet: however the backuper stops, it goes back to the front of the queue, a full
	# comparison as a full scan request
	backupEntries = OrderedDict()
	full_comparison = False
	try:
		# if the vault path does not exist, create it
		if not os.path.lexists(vault_path):
			try:
				os.makedirs(vault_path,exist_ok=True)
			except Exception as e:
				if job is None:
					watcherTeeLogToTl(monitor_path,f'Warning: Vault path {vault_path} does not exist and failed to create it. Backuper Stopped!',error=True)
				else:
					watcherTeeLogToTl(monitor_path,f'Vault path {vault_path} does not exist and failed to create it: {e}',error=True)
					job.fail(f'vault path {vault_path} does not exist and cannot be created: {e}')
				return
		vault_fs_flag = FS_SIGNATURE_MONITOR.register(vault_path,vault_path_signature)
		wait_for_path(job, vault_fs_flag, vault_path, 'vault filesystem not ready')
		wait_for_path(job, monitor_fs_flag, monitor_path, 'monitored filesystem not ready')
		if startup is not None and running():
			# the list is read now that both filesystems are ready, so one on a disk that mounts late still loads
			job_vault = os.path.join(vault_path,job_name)
			recorded = None
			if os.path.isdir(job_vault):
				manifest = VaultManifest(job_vault)
				recorded = manifest.skip_fingerprint
			if not startup.load(recorded):
				# only this job stops: its watcher sees the failure and exits too
				if job is not None:
					job.fail(startup.failure_reason, permanent=startup.permanent)
				return
			skip_list = startup.skip_list
			# events the watcher queues from here on are not missed by a replay of the pending transactions
			while running() and not startup.watching.is_set():
				startup.watching.wait(POLL_WAIT_SECONDS)
			if not running():
				# stopping before deciding: leave the pending transactions file for the next start, unless the watcher
				# already queued events, as saving those alone over it would drop the rest
				with to_process_lock:
					if to_process:
						to_process.append(ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
				return
			restored = ChangeEventQueue(monitor_path)
			resumed = False
			if startup.change == 'unchanged':
				resumed = load_pending_transactions_for_resume(job_name, monitor_path, vault_path, restored, skip_list)
			else:
				backuperTeeLogToTl(job_name,'Skip list differs from the one the last backup used, comparing the whole tree',ok=True)
				pending_transactions_path = os.path.join(job_vault,PENDING_TRANSACTIONS_FILE_NAME)
				if os.path.lexists(pending_transactions_path):
					# they were filtered by the old list
					backuperTeeLogToTl(job_name,f'Discarding pending transactions {pending_transactions_path} as the skip list changed')
					try:
						os.remove(pending_transactions_path)
					except OSError as e:
						backuperTeeLogToTl(job_name,f'Failed to remove pending transactions file {pending_transactions_path}: {e}',error=True)
			with to_process_lock:
				if resumed:
					to_process.prepend(list(restored))
				else:
					# a full scan absorbs whatever the watcher queued meanwhile
					to_process.append(ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
		with to_process_lock:
			if to_process:
				backuperTeeLogToTl(job_name, f'Found {len(to_process)} events queued at startup')
			to_process_temp = to_process.take()
		if to_process_temp:
			if to_process_temp.full_scan_requested:
				backuperTeeLogToTl(job_name, 'Events queued at startup contain a full_scan request, forcing delta generation')
				full_comparison = True
			else:
				backupEntries = change_events_to_backup_entries(to_process_temp)
				backuperTeeLogToTl(job_name, f'Converted events queued at startup into {len(backupEntries)} backup entries')
		vaultInfo = None
		# to_process: ChangeEventQueue of ChangeEvent(monotonic_time, is_dir, event, path, moved_from), oldest first
		while running():
			wait_for_path(job, vault_fs_flag, vault_path, 'vault filesystem not ready')
			if not running():
				break
			# do_backup compares the whole tree for an empty batch
			full_comparison = full_comparison or not backupEntries
			vaultInfo,manifest,committed = do_backup(backupEntries,job_name=job_name,monitor_path=monitor_path,vault_path=vault_path,
				  keep_one_complete_backup=keep_one_complete_backup,only_sync_attributes=only_sync_attributes, keep_n_versions=keep_n_versions, 
				  backup_size_limit=backup_size_limit, log_journal=log_journal,vaultInfo=vaultInfo,manifest=manifest,skip_list=skip_list)
			if not committed:
				# the batch goes back to the queue on the way out
				if GREEN_LIGHT.is_set():
					if job is None:
						backuperTeeLogToTl(job_name,'Backup did not commit while daemon is running; requesting shutdown',error=True)
						GREEN_LIGHT.clear()
					else:
						backuperTeeLogToTl(job_name,'Backup did not commit while daemon is running',error=True)
						job.fail('backup did not commit')
				break
			backupEntries.clear()
			full_comparison = False
			if job is not None:
				job.mark_committed()
			while not backupEntries and not full_comparison and running():
				while running() and not to_process_flag.is_set():
					to_process_flag.wait(POLL_WAIT_SECONDS)
				if not running():
					break
				with to_process_lock:
					backuperTeeLogToTl(job_name,f'Backuper processing, {len(to_process)} events to process')
					to_process_temp = to_process.take()
				to_process_flag.clear()
				if to_process_temp.full_scan_requested:
					# events were lost (e.g. inotify queue overflow): discard the partial batch and
					# let do_backup delta-generate against the latest version instead
					backuperTeeLogToTl(job_name,'Full scan requested, forcing delta generation')
					full_comparison = True
				else:
					backupEntries = change_events_to_backup_entries(to_process_temp)
					backuperTeeLogToTl(job_name,f'Converted {len(to_process_temp)} events to {len(backupEntries)} backup entries')
			if log_journal:
				journalPath = os.path.join(vault_path,job_name,'journal.tsv')
				log_events_to_journal(backupEntries,journalPath)
	except JobFailure as e:
		backuperTeeLogToTl(job_name, f'Job failed: {e.reason}', error=True)
		if job is None:
			GREEN_LIGHT.clear()
		else:
			job.fail(e.reason, e.permanent)
	except Exception as e:
		import traceback
		backuperTeeLogToTl(job_name, traceback.format_exc(), error=True)
		if job is None:
			GREEN_LIGHT.clear()
		else:
			job.fail(f'{type(e).__name__}: {e}')
	finally:
		if full_comparison or backupEntries:
			# for the job's next attempt, or the pending transactions when the daemon stops
			with to_process_lock:
				if full_comparison:
					to_process.append(ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
				else:
					to_process.prepend(backup_entries_to_change_events(backupEntries))
		if manifest is not None:
			manifest.close()
		if vault_fs_flag is not None:
			FS_SIGNATURE_MONITOR.unregister(vault_path,vault_path_signature,vault_fs_flag)
		# on a job failure the daemon goes on: the queue stays in memory for the job's next attempt
		if job is None or not GREEN_LIGHT.is_set():
			persist_pending_transactions(job_name=job_name, vault_path=vault_path, to_process=to_process, to_process_lock=to_process_lock)

def backuperTeeLogToTl(path:str,message:str,error=False,ok=False,warning=False,debug=False):
	global tl
	global DEBUG
	message = f'{BACKUPER_LOG_PREFIX}| {path} | ' + message
	if error:
		tl.teeerror(message,callerStackDepth=4)
	elif ok:
		tl.teeok(message,callerStackDepth=4)
	elif warning:
		tl.teewarning(message,callerStackDepth=4)
	elif debug:
		if DEBUG:
			tl.teedebug(message,callerStackDepth=4)
		else:
			tl.debug(message,callerStackDepth=4)
	elif DEBUG:
		tl.teeprint(message,callerStackDepth=4)
	else:
		tl.info(message,callerStackDepth=4)

def change_events_to_backup_entries(change_events:deque) -> OrderedDict:
	'''
	Collapse a chronological batch of watcher ChangeEvents into backup entries.

	Examples use fixed ``/tmp/reverb_doctest/...`` paths so results are stable across cwd.

	Examples:
		>>> entries = change_events_to_backup_entries(deque([
		...     ChangeEvent(1.0, False, 'modify', '/tmp/reverb_doctest/a', None),
		...     ChangeEvent(2.0, False, 'delete', '/tmp/reverb_doctest/a', None),
		... ]))
		>>> len(entries)
		1
		>>> entries['/tmp/reverb_doctest/a'].event
		'delete'
		>>> change_events_to_backup_entries(deque([
		...     ChangeEvent(1.0, False, 'create', '/tmp/reverb_doctest/new', None),
		...     ChangeEvent(2.0, False, 'delete', '/tmp/reverb_doctest/new', None),
		... ]))
		OrderedDict()
		>>> move = change_events_to_backup_entries(deque([
		...     ChangeEvent(1.0, False, 'move', '/tmp/reverb_doctest/b', '/tmp/reverb_doctest/a'),
		... ]))
		>>> move['/tmp/reverb_doctest/b'].event
		'move'
		>>> move['/tmp/reverb_doctest/b'].source_path
		'/tmp/reverb_doctest/a'
		>>> list(change_events_to_backup_entries(deque([
		...     ChangeEvent(1.0, True, 'create', '/tmp/reverb_doctest/d', None),
		... ])).keys())[0]
		'/tmp/reverb_doctest/d/'
		>>> import io, contextlib
		>>> _buf_out, _buf_err = io.StringIO(), io.StringIO()
		>>> with contextlib.redirect_stdout(_buf_out), contextlib.redirect_stderr(_buf_err):
		...     _out = change_events_to_backup_entries(deque([
		...         ChangeEvent(1.0, True, 'self_destruct', '/tmp/reverb_doctest', None),
		...     ]))
		>>> _out
		OrderedDict()
		>>> change_events_to_backup_entries(deque([ChangeEvent(1.0, True, 'scan', '/tmp/reverb_doctest/m', None)]))
		OrderedDict()
	'''
	# possibile events are create, delete, attrib, move, modify ( and scan, a folder the backuper compares itself )
	# CHANGED_EVENT_HEADER = ['monotonic_time', 'is_dir', 'event', 'path','moved_from']
	# BACKUP_ENTRY_VALUES_HEADER = ['iso_time','event','source_path']
	# collapse the change events
	# for a single file, only these events will be kept:
	# 	modify, attrib, move, delete ( create will be treated as modify as we will be copying the entire file )
	# 	modify will be exclusive to file
	# for a single directory, only the following kinds of events will be kept:
	# 	create, delete, attrib, move ( modify should not be possible but just in case, it will be treated as create )
	# 	folder create will recursively copy all its contents 
	# 	create should be exclusive to folder
	# Only move what with a moved_from will be kept, all moves without moved_from will be treated as delete
	# will get the iso_time using (datetime.datetime.now() - datetime.timedelta(seconds=time.monotonic() - monTime)).isoformat())
	# will indicate if a path is a dir by making sure it ends with /
	# self_destruct events ( monitor root deleted / moved / unmounted ) are logged and skipped: vault history is kept 
	global DEBUG
	backuperTeeLogToTl('convertor','Converting the following change events to backup entries')
	if DEBUG:
		backuperTeeLogToTl('convertor','\n'+multiCMD.pretty_format_table(list(change_events),header = CHANGED_EVENT_HEADER))
	backup_entries = OrderedDict()
	pendingMoveSourceParents = set()
	moveSourceToDestDict = {}
	for changeEvent in reversed(change_events):
		# get the absolute path
		to_add = True
		abs_path = os.path.abspath(changeEvent.path)
		if changeEvent.moved_from:
			abs_moved_from = os.path.abspath(changeEvent.moved_from)
			if changeEvent.is_dir:
				abs_moved_from += '/'
		else:
			abs_moved_from = None
		event = changeEvent.event
		if changeEvent.is_dir:
			abs_path += '/'
		if DEBUG:
			backuperTeeLogToTl(abs_path,f'Processing {event} with source {abs_moved_from}')
		if event == 'self_destruct':
			# the monitored root itself was deleted / moved / unmounted.
			# do not turn this into vault operations ( we want to keep the existing history ),
			# just surface it loudly and skip.
			backuperTeeLogToTl(abs_path,f'Monitor root self destructed ({abs_path}), keeping existing vault content untouched',error=True)
			continue
		if event == 'scan':
			# a folder to compare with the vault (an inner mount came or went), not an entry of its own
			continue
		# pre handle move events
		if event == 'move':
			if abs_moved_from:
				pendingMoveSourceParents.add(abs_moved_from)
				if abs_path in moveSourceToDestDict:
					# chain move, we will modify the chronologically later move event's source to this event's source
					finialTarget = moveSourceToDestDict[abs_path]
					moveSourceToDestDict[abs_moved_from] = finialTarget
					del moveSourceToDestDict[abs_path]
					if finialTarget in backup_entries:
						backup_entries[finialTarget] = BackupEntryValues(backup_entries[finialTarget].iso_time,backup_entries[finialTarget].event,abs_moved_from)
						if DEBUG:
							if backup_entries[finialTarget].event != 'move':
								backuperTeeLogToTl(abs_path,f'  Chain move (now {backup_entries[finialTarget].event}) from {abs_moved_from} through {abs_path} to {finialTarget}')
							else:
								backuperTeeLogToTl(abs_path,f'  Chain move from {abs_moved_from} through {abs_path} to {finialTarget}')
					else:
						# this means the later move event was deleted, no need to update it
						if DEBUG:
							backuperTeeLogToTl(abs_path,f'  Already removed chain move event from {abs_moved_from} through {abs_path} to {finialTarget}')
						if abs_path in backup_entries:
							if DEBUG:
								backuperTeeLogToTl(abs_path,f'    Removing {backup_entries[abs_path].event} event on {abs_path}')
							del backup_entries[abs_path]
					to_add = False
				else:
					moveSourceToDestDict[abs_moved_from] = abs_path
			else:
				if abs_path in pendingMoveSourceParents:
					# we have handled this event's children, so we can ignore this event
					pendingMoveSourceParents.remove(abs_path)
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Skipping child move event {abs_path}')
					to_add = False
				else:
					# virgin move, treat as create
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Virgin move event {abs_path}')
					event = 'create'
		elif abs_path in moveSourceToDestDict:
			# This means the path was chronologically later moved.
			# the event can be 'create', 'modify', 'attrib', 'delete' at this point
			# in all cases, as we cannot simply perform a recursive link as a move in the backup, ( need to backup source data )
			# we will break the move event into a delete of source and a {event} of dest
			# here, escalate the current event to the chronologically later move
			moveDest = moveSourceToDestDict[abs_path]
			if event == 'delete':
				# Later move-from means dest should not become delete. A paired
				# move relocates the referenced copy. Recreate-then-move already
				# escalated dest to create, which does not remove the old source,
				# so still record a source delete.
				if DEBUG:
					backuperTeeLogToTl(abs_path,f'Delete event detected immediately before a move with {abs_path} as source. Ignoring delete')
				if moveDest in backup_entries and backup_entries[moveDest].event == 'create':
					to_add = True
				else:
					to_add = False
					continue
			else:
				if event == 'attrib':
					# escalate to check file content also as it is not possible to sync attrib only to a symlink
					event = 'modify'
				if DEBUG:
					backuperTeeLogToTl(abs_path,f'  Seperating move event from {abs_path} to {moveDest}')
				if moveDest in backup_entries:
					if event == 'create':
						to_add = False
						escalated_event = 'create'
					else:
						escalated_event = event
						event = 'delete'
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'    Escalating {backup_entries[moveDest].event} to {escalated_event} at {backup_entries[moveDest].iso_time} on {moveDest}')
					backup_entries[moveDest] = BackupEntryValues(backup_entries[moveDest].iso_time,escalated_event,abs_path)
				else:
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'    Already removed event on {moveDest}, skipping escalating')
					if abs_path in backup_entries:
						if DEBUG:
							backuperTeeLogToTl(abs_path,f'    Removing {backup_entries[abs_path].event} event on {abs_path}')
						del backup_entries[abs_path]
					continue
			
		# handle repeated events on the same path
		if abs_path in backup_entries:
			if DEBUG:
				backuperTeeLogToTl(abs_path,f'  {abs_path} already exists in backup entries')
			# handle repeated events on the same path
			later_event_on_path = backup_entries[abs_path].event
			if event == 'create':
				if later_event_on_path == 'delete':
					# if the path was new and then chronologically later deleted, then we ignore both events
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Skipping event as Creating {abs_path} that is later deleted.')
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'  Removing delete event {abs_path}:{backup_entries[abs_path]} as it was created in this iteration')
					del backup_entries[abs_path]
					to_add = False
				elif later_event_on_path in ('modify','attrib'):
					# this is a new file that is later modified. We need to remove the later entry add this create instead.
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Escalating later {later_event_on_path} event to create on {abs_path}')
					del backup_entries[abs_path]
				elif later_event_on_path == 'move':
					# this is a new file that later got moved to. we can safely ignore this event
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Skipping event as Creating {abs_path} that is later moved to.')
					to_add = False
			elif later_event_on_path in ('delete','modify','move','create'):
				# if the path is chronologically later deleted, then we simply do not need to perform backups
				# if the path is chronologically later modified, because the current event can be modify / attrib / move / delete , in all cases we will ignore this event
				# if the path is chronologically later moved to, meaning it was later overwriiten moved to. We do not care what it had been done to before then.
				# in this version of reverberator, create is a complete file tree copy, so if it is chronologically later "created", all previoud events no longer matter.
				# in the case of move, because we are skipping this event without adding it to the move sources,
				# the next chronological move event of the source will be treated as a delete
				if event == 'move':
					# we also need to add a event to remove the source 
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Moving to {abs_path} that is later {later_event_on_path}d.')
					if later_event_on_path == 'delete':
						if DEBUG:
							backuperTeeLogToTl(abs_path,f'  Removing delete event {abs_path}:{backup_entries[abs_path]} as it was created by move in this iteration')
						del backup_entries[abs_path]
					abs_path = abs_moved_from
					abs_moved_from = None
					event = 'delete'
				else:
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Skipping {event} on {abs_path}')
					to_add = False
			elif later_event_on_path == 'attrib':
				if event in ('attrib','delete'):
					# delete: the path was chronologically later attributed, so it must exist later, thus we ignore the delete
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Skipping dup {event} on {abs_path}')
					to_add = False
				if event in ('modify', 'create', 'move'):
					# we need to escalate the chronologically later event to modify / create / move as attrib only copies the metadata
					if DEBUG:
						backuperTeeLogToTl(abs_path,f'Escalating attrib event to {event} on {abs_path}')
					del backup_entries[abs_path]
		if to_add:
			# derive the wall clock time of this specific event from its monotonic timestamp
			iso_time = (datetime.datetime.now() - datetime.timedelta(seconds=time.monotonic() - changeEvent.monotonic_time)).isoformat()
			backuperTeeLogToTl(abs_path,f'Adding {event} on {abs_path} at {iso_time} with source {abs_moved_from}')
			backup_entries[abs_path] = BackupEntryValues(iso_time,event,abs_moved_from)
			backup_entries.move_to_end(abs_path,last=False)
	backuperTeeLogToTl('convertor','Converted backup entries')
	if DEBUG:
		backuperTeeLogToTl('convertor','\n'+multiCMD.pretty_format_table(backup_entries,header = ['path'] + BACKUP_ENTRY_VALUES_HEADER))
	return backup_entries

def log_events_to_journal(backup_entries:dict,journal_path:str):
	# this function will log the journal of the changes
	# the journal will be a nsv file with the following fields:
	# monotonic_time, event, type, path
	# this will be used to recover the changes in the case of a crash
	global tl
	lines = [[path,entry.iso_time,entry.event,entry.source_path] for path,entry in backup_entries.items()]
	TSVZ.appendLinesTabularFile(journal_path,lines,header = BACKUP_JOURNAL_HEADER,createIfNotExist = True,verifyHeader = True,strict=False,teeLogger=tl)

def backup_entries_to_change_events(backup_entries:dict) -> list:
	'''
	Convert in-flight backup entries back to ChangeEvents for pending persistence.
	'''
	events = []
	base = time.monotonic()
	for i, (path, values) in enumerate(backup_entries.items()):
		is_dir = path.endswith('/')
		moved_from = values.source_path if values.event == 'move' else None
		events.append(ChangeEvent(base + (i * 0.001), is_dir, values.event, path, moved_from))
	return events

def check_walk_errors(job_name:str, monitor_path:str, errors:list, manifest:'VaultManifest' = None, reported:set = None):
	'''After a first-backup walk of monitor_path: fail the job when its root could not be read, else log each unreadable folder.'''
	root_error = next((error for rel, error in errors if not rel), None)
	if root_error is not None:
		if manifest is not None:
			manifest.rollback()
		raise JobFailure(f'cannot read {monitor_path}: {root_error}')
	log_unreadable(job_name, monitor_path, errors, reported)

def do_backup(backup_entries:dict,
			 job_name:str,monitor_path:str,vault_path:str,
			 keep_one_complete_backup:bool, 
			 only_sync_attributes:bool, keep_n_versions:int , 
			 backup_size_limit:str,log_journal:bool = False,
			 vaultInfo:VaultInfo = None,manifest:'VaultManifest' = None,skip_list:'SkipList' = None):
	# returns (vaultInfo, manifest, committed): pass both back in for the next backup of this job
	# move events sync attrs from source where the vault entry is a real file/dir ( see do_reverb_backup )
	global DEBUG
	global BACKUP_SEMAPHORE
	global BACKUP_JOURNAL_HEADER
	global VAULT_TIMESTAMP_FORMAT
	global CONTENT_FILE_EXTENSION_NAME
	global GREEN_LIGHT
	global BACKUP_ENTRY_VALUES_HEADER
	# this function will do the actual backup
	skip = None if skip_list is None else skip_list.skips
	job_vault = os.path.join(vault_path,job_name)
	if not os.path.lexists(job_vault):
		try:
			os.makedirs(job_vault,exist_ok=True)
		except Exception as _:
			backuperTeeLogToTl(job_name,f'Warning: Vault path {job_vault} does not exist and failed to create it. Backuper Stopped!',error=True)
			if vaultInfo is None:
				vaultInfo = VaultInfo({}, 0, 0)
			return vaultInfo, manifest, False
	# a manifest opened here is closed here if the backup raises, as the caller never gets it back
	reported = set()
	opened_manifest = manifest is None
	if opened_manifest:
		manifest = VaultManifest(job_vault)
	try:
		if log_journal:
			journalPath = os.path.join(job_vault,'journal.tsv')
			TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),f'start_reverb_backup_{len(backup_entries)}_enties',job_vault],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
		backuperTeeLogToTl(job_name,'-'* 60)
		backuperTeeLogToTl(job_name,f'Backing up {monitor_path} to {job_vault}')
		# NOTE: intentionally not holding BACKUP_SEMAPHORE here: the AsyncExecutors below
		# acquire permits from the same semaphore per command, and holding a permit while
		# waiting for them deadlocks when permits are exhausted (e.g. --threads 1).
		# do the actual backup
		# get the latest current version path
		if not vaultInfo or not vaultInfo.vault_info_dict:
			vaultInfo = get_vault_info(job_vault_path=job_vault)
		vault_info_dict = vaultInfo.vault_info_dict
		vault_size = vaultInfo.vault_size
		vault_inodes = vaultInfo.vault_inodes
		if not vault_info_dict:
			backuperTeeLogToTl(job_name,f'Failed to get any version for {job_vault}, treating the vault as new.',error=True)
			this_version_number = 0
			this_timestamp = datetime.datetime.now().astimezone().strftime(VAULT_TIMESTAMP_FORMAT)
			backup_folder = os.path.join(job_vault,f'V0--{this_timestamp}')
			os.makedirs(backup_folder,exist_ok=True)
			manifest.begin()
			if keep_one_complete_backup:
				backuperTeeLogToTl(job_name,f'Creating a complete backup of {monitor_path} to {backup_folder}',ok=True)
				if log_journal:
					TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),'initial_complete_backup',backup_folder],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
				manifest.reset(backup_folder)
				mcae = multiCMD.AsyncExecutor(semaphore=BACKUP_SEMAPHORE,quiet=not DEBUG)
				pending = []
				try:
					# the walk yields each folder before its contents
					walk_errors = []
					for monitorEntry, relativePath, isDir in iter_tree_entries(monitor_path,skip=skip,errors=walk_errors):
						backupEntryPath = os.path.join(backup_folder,relativePath)
						manifest.add(relativePath,dirty=True)
						if isDir:
							os.makedirs(backupEntryPath,exist_ok=True)
							copy_file_meta(monitorEntry,backupEntryPath)
						else:
							cp_af_copy_path(monitorEntry,backupEntryPath,mcae,pending)
					# copies still running must stop writing before a failed root orphans this version
					while GREEN_LIGHT.is_set() and mcae.runningThreads:
						mcae.wait(timeout=POLL_WAIT_SECONDS)
					if GREEN_LIGHT.is_set():
						finish_copies(pending,manifest,backup_folder,job_name,reported)
				finally:
					# however the backup ends, no copy is left writing into this version, nor a partial file in it
					stop_copies(mcae,pending,backup_folder)
				mcae.cleanup(timeout=POLL_WAIT_SECONDS)
				check_walk_errors(job_name,monitor_path,walk_errors,manifest,reported)
				record_dirty_entries(manifest,backup_folder,monitor_path)
			else:
				backuperTeeLogToTl(job_name,f'Creating a referenced backup of {monitor_path} to {backup_folder}',ok=True)
				if log_journal:
					TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),'initial_referenced_backup',backup_folder],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
				walk_errors = []
				manifest.rebuild(backup_folder,tree_path=monitor_path,skip=skip,errors=walk_errors)
				check_walk_errors(job_name,monitor_path,walk_errors,manifest,reported)
				do_referenced_copy(monitor_path,backup_folder,manifest)
		else:
			# Now we have made sure the vault is within the size limit, we can proceed to do the backup
			latest_version_info = vault_info_dict[next(reversed(vault_info_dict))]
			if not backup_entries:
				backuperTeeLogToTl(job_name,'Empty backup entries, Delta generating backup entries')
				delta_generate_backup_entries(backupEntries=backup_entries,latest_version_info=latest_version_info,monitor_path=monitor_path,manifest=manifest,skip_list=skip_list,job_name=job_name,reported=reported)
				if not GREEN_LIGHT.is_set():
					# a partial delta would be kept as pending transactions, and a restart replays those instead of comparing again
					backup_entries.clear()
					backuperTeeLogToTl(job_name, 'Delta generation interrupted; not creating a new version', error=True)
					return VaultInfo(vault_info_dict, vault_size, vault_inodes), manifest, False
				if log_journal:
					TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),f'delta_generated_{len(backup_entries)}_differences',monitor_path],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
					log_events_to_journal(backup_entries,journalPath)
			if not backup_entries:
				backuperTeeLogToTl(job_name, 'No differences after delta; skipping new version', ok=True)
				# the walk completed with no differences, so the tree matches the manifest under this skip list
				manifest.begin()
				manifest.set_skip_fingerprint(skip_list.fingerprint if skip_list is not None else '')
				manifest.commit()
				if vaultInfo is None:
					vaultInfo = VaultInfo(vault_info_dict, vault_size, vault_inodes)
				return vaultInfo, manifest, True
			estimated_backup_size, estimated_backup_inode_change = get_backup_size_inode(backup_entries=backup_entries,only_sync_attributes=only_sync_attributes,last_vault_version_path = latest_version_info.path,monitor_path = monitor_path,skip_list = skip_list)
			backuperTeeLogToTl(job_name,f'Estimated backup size {estimated_backup_size} and estimated backup inodes change {estimated_backup_inode_change}')
			estimated_backup_inode = latest_version_info.inode + estimated_backup_inode_change
			backuperTeeLogToTl(job_name,f'Estimated backup inodes {estimated_backup_inode}')
			vault_fs_size, vault_fs_inode = get_path_fs_info(vault_path)
			backuperTeeLogToTl(job_name,f'Got vault fs size {vault_fs_size} and vault fs inode {vault_fs_inode}')
			backup_limit_size, backup_limit_inode = get_backup_limits_from_str(backup_size_limit=backup_size_limit,vault_fs_size=vault_fs_size,vault_fs_inode=vault_fs_inode)
			backuperTeeLogToTl(job_name,f'Calculated backup size limit {backup_limit_size} and backup inode limit {backup_limit_inode}')
			backuperTeeLogToTl(job_name,f'Vault size {vault_size} and vault inodes {vault_inodes}')
			if backup_limit_size:
				while vault_size + estimated_backup_size > backup_limit_size:
					backuperTeeLogToTl(job_name,f'Vault size {vault_size} + estimated backup size {estimated_backup_size} exceeds backup size limit {backup_limit_size}')
					# we need to remove the oldest version
					removed_size, removed_inodes = decrement_stepper(vault_info_dict)
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			if backup_limit_inode:
				while vault_inodes + estimated_backup_inode > backup_limit_inode:
					backuperTeeLogToTl(job_name,f'Vault inodes {vault_inodes} + estimated backup inodes {estimated_backup_inode} exceeds backup inode limit {backup_limit_inode}')
					# we need to remove the oldest version
					removed_size, removed_inodes = decrement_stepper(vault_info_dict)
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			while keep_n_versions and len(vault_info_dict) >= keep_n_versions:
				backuperTeeLogToTl(job_name,f'Vault has {len(vault_info_dict)} versions, exceeding keep n versions {keep_n_versions}')
				# we need to remove the oldest version
				removed_size, removed_inodes = decrement_stepper(vault_info_dict)
				vault_size -= removed_size
				vault_inodes -= removed_inodes
				if not removed_size and not removed_inodes:
					break
			this_version_number = latest_version_info.version_number + 1
			this_timestamp = datetime.datetime.now().astimezone().strftime(VAULT_TIMESTAMP_FORMAT)
			backup_folder = os.path.join(job_vault,f'V{this_version_number}--{this_timestamp}')
			os.makedirs(backup_folder,exist_ok=True)
			backuperTeeLogToTl(job_name,f'Creating a reverb backup of {monitor_path} to {backup_folder}',ok=True)
			do_reverb_backup(backup_entries,backup_folder,latest_version_info,only_sync_attributes,manifest,monitor_path,skip_list,job_name,reported)
		backup_finished = GREEN_LIGHT.is_set()
		if not backup_finished:
			backuperTeeLogToTl(job_name, f'Backup incomplete for {backup_folder}; not writing content file', error=True)
			manifest.rollback()
			if vaultInfo is None:
				vaultInfo = VaultInfo(vault_info_dict, vault_size, vault_inodes)
			return vaultInfo, manifest, False
		# check the size of the backup
		this_size, this_inodes = measure_version_usage(manifest, backup_folder)
		vault_size += this_size
		vault_inodes += this_inodes
		backup_size_str = format_bytes(this_size,use_1024_bytes=True,to_str=True).replace(' ','_')
		backup_inode_str = format_bytes(this_inodes,use_1024_bytes=False,to_str=True).replace(' ','')
		content_file_name = f'{backup_folder}--{backup_size_str}B-{backup_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
		content_file_content = [[path] + list(values) for path,values in backup_entries.items()]
		# commit before the content file: without one the version is removed at startup, and a manifest
		# describing a removed version is listed again from the vault
		manifest.set_skip_fingerprint(skip_list.fingerprint if skip_list is not None else '')
		manifest.commit(backup_folder)
		TSVZ.appendLinesTabularFile(content_file_name,content_file_content,header = ['path']+ BACKUP_ENTRY_VALUES_HEADER,createIfNotExist = True,verifyHeader = True,strict=False,teeLogger=tl,verbose=DEBUG)
		backuperTeeLogToTl(job_name,f'Created new backup at {backup_folder} with {content_file_name}',ok=True)
		# create the current version symlink
		vault_info_dict[this_version_number] = VaultEntry(this_version_number,backup_folder,this_timestamp,this_size,this_inodes)
		# swapped in under a temporary name, so the link is never missing
		temp_link = os.path.join(job_vault,'.current_version.tmp')
		if os.path.lexists(temp_link):
			os.unlink(temp_link)
		os.symlink(os.path.basename(backup_folder),temp_link,target_is_directory=True)
		os.replace(temp_link,os.path.join(job_vault,'current_version'))
		if log_journal:
			tracked_files, tracked_folders = manifest.counts()
			TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),f'end_reverb_backup_{tracked_files}files_{tracked_folders}folders_tracked',job_vault],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
		return VaultInfo(vault_info_dict,vault_size,vault_inodes), manifest, True
	except BaseException:
		if opened_manifest:
			manifest.close()
		raise

def pending_transaction_rows(events) -> list:
	'''
	Rows to persist the queued events with.

	Examples:
		>>> [row[0] for row in pending_transaction_rows([ChangeEvent(5.0, False, 'create', '/m/a', None), ChangeEvent(5.0, False, 'create', '/m/b', None)])]
		[5.0, 5.000001]
	'''
	rows = []
	last_time = None
	for event in events:
		# rows are keyed by their time when read back, and events from one inotify read share it: space them apart
		event_time = event.monotonic_time
		if last_time is not None and event_time <= last_time:
			event_time = last_time + 1e-6
		last_time = event_time
		rows.append([
			event_time,
			event.is_dir,
			event.event,
			event.path,
			event.moved_from if event.moved_from is not None else ''
		])
	return rows

def persist_pending_transactions(job_name:str, vault_path:str, to_process:'ChangeEventQueue', to_process_lock:threading.Lock=None):
	def rows_for(queue):
		available, _, _ = read_memory_state()
		if available is not None and len(queue) * PENDING_ROW_BYTES > available * QUEUE_MEMORY_SHARE:
			# writing every row holds them all as Python objects: a full scan at the next start covers them instead
			backuperTeeLogToTl(job_name, f'{len(queue)} pending transactions are too many to write out with the memory available, saving a full scan request instead', error=True)
			return pending_transaction_rows([ChangeEvent(time.monotonic(), False, 'full_scan', getattr(queue, 'monitor_path', ''), None)])
		return pending_transaction_rows(queue)
	if to_process_lock is not None:
		with to_process_lock:
			pending_rows = rows_for(to_process)
	else:
		pending_rows = rows_for(to_process)
	if not pending_rows:
		return
	job_vault = os.path.join(vault_path, job_name)
	pending_transactions_path = os.path.join(job_vault, PENDING_TRANSACTIONS_FILE_NAME)
	try:
		os.makedirs(job_vault, exist_ok=True)
		if os.path.exists(pending_transactions_path):
			os.remove(pending_transactions_path)
		TSVZ.appendLinesTabularFile(
			pending_transactions_path,
			pending_rows,
			header=CHANGED_EVENT_HEADER,
			createIfNotExist=True,
			verifyHeader=True,
			strict=False,
			teeLogger=tl,
			verbose=DEBUG
		)
		backuperTeeLogToTl(job_name, f'Saved {len(pending_rows)} pending transactions to {pending_transactions_path}')
	except Exception as e:
		backuperTeeLogToTl(job_name, f'Failed to save pending transactions to {pending_transactions_path}: {e}', error=True)

def remove_incomplete_vault_versions(job_vault_path: str) -> list:
	'''
	Delete V* version directories that have no matching content file.

	A version is committed only when its content file exists. Incomplete
	directories left after a crash/stop are removed on startup.

	Returns:
		list: Absolute paths of deleted version directories.
	'''
	deleted = []
	if not os.path.isdir(job_vault_path):
		return deleted
	# Map version dir path -> whether a content file was seen
	version_dirs = {}
	content_for = set()
	try:
		for entry in os.scandir(job_vault_path):
			name = entry.name
			if not (name.startswith('V') and '--' in name):
				continue
			version_number_str = strip_prefix(name, 'V').partition('--')[0]
			if not version_number_str.isdigit():
				continue
			if CONTENT_FILE_EXTENSION_NAME in name:
				if entry.is_file():
					vault_path = entry.path.rpartition('--')[0]
					content_for.add(vault_path)
			elif entry.is_dir():
				version_dirs[entry.path] = True
	except Exception as e:
		backuperTeeLogToTl(job_vault_path, f'Error scanning for incomplete versions: {e}', error=True)
		return deleted
	for vault_dir in list(version_dirs):
		if vault_dir in content_for:
			continue
		backuperTeeLogToTl(
			job_vault_path,
			f'Removing incomplete version (no content file): {vault_dir}',
			error=True,
		)
		try:
			multiCMD.run_command(['rm', '-rf', vault_dir], quiet=not DEBUG, return_code_only=True)
			deleted.append(vault_dir)
		except Exception as e:
			backuperTeeLogToTl(job_vault_path, f'Failed to remove incomplete version {vault_dir}: {e}', error=True)
	return deleted

def get_vault_info(job_vault_path:str,recalculate:bool=False) -> VaultInfo:
	# job vault subfolder should follow: V{version}--{ISO8601ish time}
	# ex. V0--2021-01-01_00-00-00_-0800
	global DEBUG
	global VAULT_TIMESTAMP_FORMAT
	global CONTENT_FILE_EXTENSION_NAME
	if not os.path.exists(job_vault_path):
		backuperTeeLogToTl(job_vault_path, f'Job vault path {job_vault_path} does not exist', error=True)
		return VaultInfo({},0,0)
	# if the symlink is broken, we will try to find the latest version folder
	vault_info_dict = {}
	vault_size = 0
	vault_inodes = 0
	orphan_entries = set()
	content_file_to_delete = set()
	try:
		for entry in os.scandir(job_vault_path):
			if entry.name.startswith('V') and '--' in entry.name:
				version_number_str = strip_prefix(entry.name, 'V').partition('--')[0]
				if version_number_str.isdigit():
					version_number = int(version_number_str)
					if CONTENT_FILE_EXTENSION_NAME not in entry.name:
						if entry.is_dir():
							orphan_entries.add(entry.path)
					elif entry.is_file():
						try:
							vault_path = entry.path.rpartition('--')[0]
							if not os.path.exists(vault_path):
								backuperTeeLogToTl(job_vault_path,f'Vault path {vault_path} for content {entry.name} does not exist, deleting content file...',error=True)
								content_file_to_delete.add(entry.path)
								continue
							orphan_entries.discard(vault_path)
							if not recalculate:
								entry_name = strip_suffix(entry.name, CONTENT_FILE_EXTENSION_NAME)
								entry_size_inode_str = entry_name.rpartition('--')[2]
								entry_size_str = entry_size_inode_str.partition('-')[0].replace('_','')
								entry_size = format_bytes(entry_size_str,to_int=True)
								entry_inode_str = entry_size_inode_str.rpartition('-')[2].replace('_ino','')
								entry_inode = format_bytes(entry_inode_str,to_int=True)
								vault_size += entry_size
								vault_inodes += entry_inode
								entry_timestamp = datetime.datetime.strptime(entry.name.partition('--')[2].rpartition('--')[0],VAULT_TIMESTAMP_FORMAT).timestamp()
								#VAULT_ENTRY_HEADER = ['version_number','path','timestamp','size','inode']
							else:
								# we will recalculate the size and inodes for the folders and rename the folders accordingly
								entry_size = get_path_size(vault_path)
								entry_inode = get_path_inodes(vault_path)
								vault_size += entry_size
								vault_inodes += entry_inode
								backup_size_str = format_bytes(entry_size,use_1024_bytes=True,to_str=True).replace(' ','_')
								backup_inode_str = format_bytes(entry_inode,use_1024_bytes=False,to_str=True).replace(' ','')
								entry_timestamp = datetime.datetime.strptime(entry.name.partition('--')[2].rpartition('--')[0],VAULT_TIMESTAMP_FORMAT).timestamp()
								new_entry_name = f'V{version_number}--{datetime.datetime.fromtimestamp(entry_timestamp).astimezone().strftime(VAULT_TIMESTAMP_FORMAT)}--{backup_size_str}B-{backup_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
								if entry.name != new_entry_name:
									backuperTeeLogToTl(job_vault_path,f'Renaming {entry.name} to {new_entry_name}')
									try:
										new_entry_path = os.path.join(job_vault_path,new_entry_name)
										os.rename(entry.path,new_entry_path)
									except Exception as e:
										backuperTeeLogToTl(job_vault_path,f'Error renaming {entry.name} to {new_entry_name}: {e}',error=True)
							vault_info_dict[version_number] = VaultEntry(version_number,vault_path,entry_timestamp,entry_size,entry_inode)
						except Exception as _:
							import traceback
							backuperTeeLogToTl(job_vault_path,f'Error processing {entry.name}: {traceback.format_exc()}',error=True)
		for entry in content_file_to_delete:
			try:
				os.remove(entry)
			except Exception as e:
				backuperTeeLogToTl(job_vault_path,f'Error deleting {entry}: {e}',error=True)
		# scandir order is not guaranteed: a content file may be seen before its
		# V* directory, so discard indexed paths before treating leftovers as orphans.
		for ve in vault_info_dict.values():
			orphan_entries.discard(ve.path)
		for entry in orphan_entries:
			backuperTeeLogToTl(
				job_vault_path,
				f'Removing incomplete orphan version (no content file): {entry}',
				error=True,
			)
			try:
				multiCMD.run_command(['rm', '-rf', entry], quiet=not DEBUG, return_code_only=True)
			except Exception as e:
				backuperTeeLogToTl(job_vault_path, f'Error removing orphan {entry}: {e}', error=True)
	except PermissionError:
		backuperTeeLogToTl(job_vault_path,f'Permission error while scanning {job_vault_path}',error=True)
	except Exception as _:
		# never let a malformed vault entry kill the backuper thread
		import traceback
		backuperTeeLogToTl(job_vault_path,f'Error scanning {job_vault_path}: {traceback.format_exc()}',error=True)
	return VaultInfo(OrderedDict(sorted(vault_info_dict.items())), vault_size, vault_inodes)

def is_subpath(child, parent):
	'''
	Checks if child is a subpath of parent

	Parameters:
		child (str): The child path
		parent (str): The parent path

	Returns:
		bool: True if child is a subpath of parent, False otherwise

	Examples:
		>>> is_subpath('/usr/local/bin', '/usr/local')
		True
		>>> is_subpath('/usr/local/bin', '/usr/local/bin')
		True
		>>> is_subpath('/usr', '/usr/local/bin/python')
		False
		>>> is_subpath('/usr/local/', '/usr/local/bin/python')
		False
		>>> is_subpath('/tmp/a/b', '/tmp/a')
		True
		>>> is_subpath('/tmp/a', '/tmp/a/b')
		False
	'''
	child = os.path.realpath(child)
	parent = os.path.realpath(parent)
	common = os.path.commonpath([child, parent])
	return common == parent

def _dir_create_prefix(dir_path:str) -> str:
	return dir_path if dir_path.endswith('/') else dir_path + '/'

def path_covered_by_dir_create(path:str, dir_path:str) -> bool:
	'''True if path is strictly inside dir_path (dir create covers recursive copy).'''
	prefix = _dir_create_prefix(dir_path)
	if path == prefix or path == prefix.rstrip('/'):
		return False
	return path.startswith(prefix)

def prune_entries_covered_by_dir_creates(backup_entries:dict) -> OrderedDict:
	'''
	Drop create/modify/attrib entries covered by an ancestor directory create.

	Directory creates recursively copy their trees, so child create/modify/attrib
	(and nested directory creates) are redundant and unsafe to replay first.
	Deletes and moves are kept.
	'''
	dir_creates = [p for p, values in backup_entries.items()
				   if values.event == 'create' and p.endswith('/')]
	# Also treat paths marked as dirs via trailing slash only (backup entries use /)
	pruned = OrderedDict()
	for path, values in backup_entries.items():
		if values.event in ('create', 'modify', 'attrib'):
			if any(path_covered_by_dir_create(path, d) for d in dir_creates):
				continue
		pruned[path] = values
	return pruned

def order_backup_entries_for_replay(backup_entries:dict) -> OrderedDict:
	'''
	Order entries so vault replay is safe with async cp/rm:

	1. deletes, deepest paths first (children before parents)
	2. create/modify/attrib, shallowest first (parents before children)
	3. moves last, preserving relative order
	'''
	deletes = []
	moves = []
	rest = []
	for path, values in backup_entries.items():
		if values.event == 'delete':
			deletes.append((path, values))
		elif values.event == 'move':
			moves.append((path, values))
		else:
			rest.append((path, values))
	deletes.sort(key=lambda pv: (-pv[0].rstrip('/').count(os.sep), -len(pv[0]), pv[0]))
	rest.sort(key=lambda pv: (pv[0].rstrip('/').count(os.sep), len(pv[0]), pv[0]))
	ordered = OrderedDict()
	for path, values in deletes + rest + moves:
		ordered[path] = values
	return ordered

def prepare_backup_entries_for_replay(backup_entries:dict) -> OrderedDict:
	'''Prune redundant child ops under dir creates, then order for safe replay.'''
	return order_backup_entries_for_replay(prune_entries_covered_by_dir_creates(backup_entries))

def partial_copy_path(dest_path:str) -> str:
	'''
	A new name in dest_path's folder for one copy to dest_path to be written under until it succeeded. It is unique to
	that copy, so it never names an entry of the version, whatever the monitored tree holds, nor another copy's file.

	Examples:
		>>> first, second = partial_copy_path('/vault/job/V1--x/d/a.txt'), partial_copy_path('/vault/job/V1--x/d/a.txt')
		>>> os.path.dirname(first), first.endswith(PARTIAL_COPY_SUFFIX), first != second
		('/vault/job/V1--x/d', True, True)
	'''
	return os.path.join(os.path.dirname(dest_path), '.' + uuid.uuid4().hex + PARTIAL_COPY_SUFFIX)

def remove_entry(path:str):
	'''Remove what is at path, a folder with everything in it; nothing there is fine.'''
	try:
		if os.path.isdir(path) and not os.path.islink(path):
			shutil.rmtree(path)
		else:
			os.remove(path)
	except FileNotFoundError:
		pass

def replace_entry(temp_path:str, dest_path:str):
	'''Put temp_path in dest_path's place. A real folder there is removed first, as is anything a folder cannot be renamed over.'''
	if os.path.isdir(dest_path) and not os.path.islink(dest_path):
		shutil.rmtree(dest_path)
	elif os.path.isdir(temp_path) and not os.path.islink(temp_path) and os.path.lexists(dest_path):
		os.remove(dest_path)
	os.replace(temp_path, dest_path)

def source_readable(path:str) -> bool:
	'''
	Whether path can be read: it can be looked up and, for a regular file, opened.

	Examples:
		>>> with tempfile.TemporaryDirectory() as folder:
		...     open(os.path.join(folder, 'a.txt'), 'w').close()
		...     print(source_readable(os.path.join(folder, 'a.txt')), source_readable(os.path.join(folder, 'gone.txt')))
		True False
	'''
	try:
		if stat.S_ISREG(os.lstat(path).st_mode):
			os.close(os.open(path, os.O_RDONLY | os.O_NONBLOCK))
	except OSError:
		return False
	return True

def copy_command(source_path:str, dest_path:str) -> list:
	'''
	The cp command copying source_path to dest_path, run with the C locale so it reports in the words finish_copies() reads.

	Examples:
		>>> copy_command('/m/a', '/v/.t.reverberator-partial')
		['env', 'LC_ALL=C', 'cp', '-af', '--reflink=auto', '--sparse=always', '/m/a', '/v/.t.reverberator-partial']
	'''
	return ['env', 'LC_ALL=C', 'cp', '-af', '--reflink=auto', '--sparse=always', source_path, dest_path]

def cp_af_copy_path(source_path:str,dest_path:str,mcae:multiCMD.AsyncExecutor = ...,pending:list = None):
	'''
	Copy source_path to dest_path with cp -a, written under partial_copy_path(dest_path): dest_path stays as it is until
	the copy succeeded, so a failed copy never loses what the version held there.

	Without mcae the copy runs now, takes dest_path's place when it succeeded, and its exit code is returned. On mcae it
	is queued, appended to pending as a PendingCopy and its task returned; finish_copies() puts it in place. Returns False
	when nothing is copied.
	'''
	global DEBUG
	if mcae is not ... and pending is None:
		raise ValueError(f'copying {source_path} on an executor needs a pending list to finish the copy from')
	if not os.path.lexists(source_path):
		# the source vanished between its event and this copy, which short lived
		# files such as git's index.stash.<pid> do routinely. dest is left alone:
		# an inherited link there still references the previous version's copy,
		# and dropping it would lose that reference for nothing.
		backuperTeeLogToTl(path=source_path,error=True,message=f'Not copying {source_path} to {dest_path}: source no longer exists')
		return False
	if os.path.lexists(dest_path):
		if dest_path == '/':
			backuperTeeLogToTl(path=source_path,error=True,message='Cannot copy as root directory')
			return False
		# a symlink there is replaced, never followed: realpath follows the link (e.g.
		# .venv/bin/python3.13 -> python3 -> /usr/bin/python3), so dest and source
		# can resolve to the same path and falsely trip the subpath guard.
		if not os.path.islink(dest_path) and is_subpath(dest_path,source_path):
			backuperTeeLogToTl(path=source_path,error=True,message=f'Cannot copy {source_path} to {dest_path} as it is a subpath of the source')
			return False
	dest_parent = os.path.dirname(dest_path)
	if dest_parent and not os.path.isdir(dest_parent):
		os.makedirs(dest_parent, exist_ok=True)
	temp_path = partial_copy_path(dest_path)
	while os.path.lexists(temp_path):
		# only this copy ever removes or renames its partial file, so it never takes over a path already there
		temp_path = partial_copy_path(dest_path)
	command = copy_command(source_path,temp_path)
	if mcae is not ...:
		task = mcae.run_command(command)
		pending.append(PendingCopy(task, source_path, temp_path, dest_path))
		return task
	try:
		returncode = multiCMD.run_command(command,quiet=not DEBUG,return_code_only=True,wait_for_return=True)
		if returncode == 0:
			replace_entry(temp_path, dest_path)
	finally:
		# gone once it took dest_path's place; a failed or interrupted copy leaves no partial file
		remove_entry(temp_path)
	return returncode

def discard_copies(pending:list):
	'''Remove the partial files of the copies in pending, which will not be finished, and empty it.'''
	for copy in pending:
		try:
			remove_entry(copy.temp_path)
		except OSError as e:
			backuperTeeLogToTl(path=copy.temp_path,error=True,message=f'Failed to remove the partial copy {copy.temp_path}: {e}')
	pending.clear()

def cp_message(line:str) -> str:
	'''
	What cp itself says in a line, before the first quoted path ( cp: <message> '<path>'... ), where no file name can put words.

	Examples:
		>>> cp_message("cp: preserving times for '/v/failed to preserve ownership/x': Operation not permitted")
		'cp: preserving times for '
	'''
	return re.split('[\'"]', line, maxsplit=1)[0]

def cp_error(line:str) -> str:
	'''
	What cp says in a line after the last quoted path ( ...'<path>': <error> ), where no file name can put words either.

	Examples:
		>>> cp_error("cp: error reading '/m/No such file or directory': Input/output error")
		': Input/output error'
	'''
	return re.split('[\'"]', line)[-1]

def copy_metadata_failure(line:str, temp_name:str) -> bool:
	'''
	Whether a line cp wrote only says some metadata of the copy written to the partial file named temp_name (a base
	name) could not be kept: it names that file, and cp's message says so.

	Examples:
		>>> name = '.0f.reverberator-partial'
		>>> copy_metadata_failure(f"cp: failed to preserve ownership for '/v/{name}': Operation not permitted", name)
		True
		>>> copy_metadata_failure(f"cp: error writing '/v/failed to preserve ownership/{name}': No space left on device", name)
		False
	'''
	return temp_name in line and any(phrase in cp_message(line) for phrase in COPY_METADATA_FAILURES)

def cp_shown_prefix(path:str) -> str:
	'''
	The start of path that cp prints as it is under the C locale, which escapes bytes that are not printable ASCII and
	quotes some characters.

	Examples:
		>>> cp_shown_prefix('/m/a b.txt'), cp_shown_prefix('/m/café'), cp_shown_prefix("/m/a'b")
		('/m/a b.txt', '/m/caf', '/m/a')
	'''
	for index, char in enumerate(path):
		if not ' ' <= char <= '~' or char in '\'"\\$`':
			return path[:index]
	return path

def copy_failure_side(source_path:str, temp_path:str, lines:list) -> str:
	'''
	Where a failed copy of source_path into temp_path failed, from the lines cp wrote: 'vanished' when the source is
	gone (or was replaced under the copy), 'source' when it could not be read, and 'vault' when writing the copy failed.
	cp names the path it failed on, and only what no file name can forge counts: a line naming this copy's own partial
	file is the vault's, whether or not the source is still there; any other naming the source (or what is under it, as
	far as cp prints it unescaped) is the source's, and gone when cp's error after the path says so. Without such a line
	the source is tried, and what cannot be told apart is the vault's.

	Examples:
		>>> temp = '/v/.0f.reverberator-partial'
		>>> copy_failure_side('/', temp, [f"cp: cannot create regular file '{temp}': No such file or directory"])
		'vault'
		>>> copy_failure_side('/', temp, ["cp: error reading '/': Input/output error"])
		'source'
		>>> copy_failure_side('/', temp, ["cp: cannot stat '/': No such file or directory"]), copy_failure_side('/nowhere/gone', temp, [])
		('vanished', 'vanished')
		>>> copy_failure_side('/nowhere/gone', temp, [f"cp: error writing '{temp}': No space left on device"])
		'vault'
	'''
	vault = source = vanished = False
	temp_name = os.path.basename(temp_path)
	shown_source = cp_shown_prefix(source_path)
	for line in lines:
		if copy_metadata_failure(line, temp_name):
			continue
		if temp_name in line:
			vault = True
		elif shown_source and shown_source in line:
			error = cp_error(line)
			if os.strerror(errno.ENOENT) in error or COPY_SOURCE_REPLACED in error:
				vanished = True
			else:
				source = True
	if vault:
		return 'vault'
	if not os.path.lexists(source_path):
		return 'vanished'
	if source:
		return 'source'
	if vanished:
		return 'vanished'
	return 'vault' if source_readable(source_path) else 'source'

def finish_copies(pending:list, manifest:'VaultManifest', version_path:str, job_name:str, reported:set = None) -> None:
	'''
	Put the copies of pending in place once the executor has finished them, and empty pending.

	A copy that succeeded takes its destination's place, as does one for which cp only reported metadata of its partial
	file it could not keep (a warning says so): a failed read or write of the contents gets a line of its own. One that
	failed leaves the destination as it was, keeping the last backed-up copy, when its source failed: silently when the
	source is gone, with an UNREADABLE line (once per backup, with reported) when it could not be read. A destination holding nothing then stops being tracked in manifest, whose paths
	are relative to version_path. When writing into the vault is what failed, JobFailure is raised once every copy is
	dealt with.
	'''
	failure = None
	done = 0
	try:
		for copy in pending:
			lines = [line.strip() for line in copy.task.stderr if line.strip()]
			error = '; '.join(lines)
			succeeded = copy.task.returncode == 0
			temp_name = os.path.basename(copy.temp_path)
			if not succeeded and lines and all(copy_metadata_failure(line, temp_name) for line in lines) and os.path.lexists(copy.temp_path):
				backuperTeeLogToTl(path=copy.source_path,warning=True,message=f'Copied {copy.source_path} to {copy.dest_path} without all of its metadata: {error}')
				succeeded = True
			if succeeded:
				replace_entry(copy.temp_path, copy.dest_path)
			else:
				remove_entry(copy.temp_path)
				side = copy_failure_side(copy.source_path, copy.temp_path, lines)
				if side == 'vault':
					if failure is None:
						cause = error or f'cp exited with {copy.task.returncode}'
						failure = JobFailure(f'copying {copy.source_path} into the vault failed: {cause}')
				else:
					if side == 'vanished':
						backuperTeeLogToTl(path=copy.source_path,debug=True,message=f'Not copying {copy.source_path}: it no longer exists; keeping its last backed-up copy')
					elif reported is None or copy.source_path not in reported:
						if reported is not None:
							reported.add(copy.source_path)
						job_log(job_name, f'UNREADABLE: {copy.source_path}: {error or "copy failed"}; keeping its last backed-up copy')
					if not os.path.lexists(copy.dest_path):
						manifest.discard(os.path.relpath(copy.dest_path, version_path))
			done += 1
	finally:
		# an error above leaves no partial file of the copies it did not reach
		rest = pending[done:]
		pending.clear()
		discard_copies(rest)
	if failure is not None:
		raise failure

def stop_copies(mcae:multiCMD.AsyncExecutor, pending:list, version_path:str):
	'''
	Stop what still runs on mcae, then discard the copies of pending, which will not be finished.

	Running commands are killed and waited for, as a retry removes the uncommitted version_path they write into: for
	COPY_STOP_WAIT_SECONDS at most, COPY_STOP_GRACE_SECONDS once the daemon is stopping. The ones still running then are
	named in an error line and left to finish on their own.
	'''
	mcae.stop(timeout=0)
	deadline = time.monotonic() + COPY_STOP_WAIT_SECONDS
	while mcae.runningThreads:
		if not GREEN_LIGHT.is_set():
			deadline = min(deadline, time.monotonic() + COPY_STOP_GRACE_SECONDS)
		wait = min(POLL_WAIT_SECONDS, deadline - time.monotonic())
		if wait <= 0:
			break
		mcae.wait(timeout=wait)
	if mcae.runningThreads:
		running = [' '.join(task.command) for task in mcae.tasks if task.is_alive()]
		shown = '; '.join(running[:10]) + (f'; and {len(running) - 10} more' if len(running) > 10 else '')
		backuperTeeLogToTl(path=version_path,error=True,message=f'{len(running)} stopped commands still running after {COPY_STOP_WAIT_SECONDS}s, no longer waiting for them: {shown}')
	discard_copies(pending)

def do_referenced_copy(source_path:str,backup_folder:str,manifest:'VaultManifest',relative=False) -> bool:
	'''
	Recreate the folders tracked in manifest under backup_folder and link each tracked file to its copy under source_path.

	Entries missing from source_path are dropped from the manifest. Returns False when the backup was interrupted.
	'''
	global BACKUP_SEMAPHORE
	global GREEN_LIGHT
	backuperTeeLogToTl(path=source_path,message=f'Creating a referenced copy of {source_path} to {backup_folder}')
	# rows are read as they are linked and dropped afterwards: changing a table while reading it is undefined in sqlite
	missing = []
	for folder in manifest.iter_folders():
		source_folder = os.path.join(source_path,folder)
		backup_folder_path = os.path.join(backup_folder,folder)
		if not os.path.lexists(source_folder):
			backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked folder missing from {source_path}: {folder}')
			missing.append(folder)
			continue
		os.makedirs(backup_folder_path,exist_ok=True)
		copy_file_meta(source_folder,backup_folder_path)
		if not GREEN_LIGHT.is_set():
			backuperTeeLogToTl(path=source_path,error=True,message='Backup process interrupted, stopping')
			return False
	for file in manifest.iter_files():
		# use ln -fsrLT to do a relative symlink
		# ln --symbolic --logical --force --no-target-directory
		source_file_real = os.path.join(source_path,file)
		backup_file_path = os.path.join(backup_folder,file)
		if not os.path.lexists(source_file_real):
			# the tracked list claims a file this version does not have. linking it
			# anyway produces a dangling link that every later version inherits and
			# chains onto, so drop the entry here and let the list self heal.
			backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked file missing from {source_path}: {file}')
			missing.append(file)
			continue
		if relative:
			source_file = os.path.relpath(source_file_real,os.path.dirname(backup_file_path))
		else:
			source_file = os.path.abspath(source_file_real)
		# note: no longer using --logical as we are moving to use chained symlinks to reduce run time disk IO
		#taskObj = multiCMD.run_command(['ln','-fsLT',source_file,backup_file_path],quiet=True,return_object=True,wait_for_return=False,sem=BACKUP_SEMAPHORE)
		#mcae.run_command(['ln','-fsT',source_file,backup_file_path])
		if os.path.lexists(backup_file_path):
			os.remove(backup_file_path)
		os.symlink(source_file, backup_file_path)
		if not GREEN_LIGHT.is_set():
			backuperTeeLogToTl(path=source_path,error=True,message='Backup process interrupted, stopping')
			return False
	manifest.discard_many(missing)
	return True

def copy_file_meta(source_file:str,backup_file_path:str):
	try:
		# copy the file metadata
		copystat(source_file,backup_file_path)
		st = os.stat(source_file)
		if os.name == 'posix':
			os.chown(backup_file_path, st.st_uid, st.st_gid)
		os.utime(backup_file_path, (st.st_atime, st.st_mtime))
		return True
	except Exception as _:
		backuperTeeLogToTl(path=source_file,error=True,message=f'Failed to copy metadata {source_file} -> {backup_file_path}')
		import traceback
		backuperTeeLogToTl(path=source_file,error=True,message=traceback.format_exc())
		return False

def get_path_size(*path:str):
	global DEBUG
	# this function gets the actual size of a path
	# du --bytes -s <path>
	if DEBUG:
		startTime = time.perf_counter()
	rtn = multiCMD.run_command(['du','--block-size=1','-csP',*path],quiet=not DEBUG)
	if DEBUG:
		backuperTeeLogToTl(path='get_path_size',message=f'took {time.perf_counter()-startTime} seconds')
	if rtn and rtn[-1] and rtn[-1].partition('\t')[0].isdigit():
		return int(rtn[-1].partition('\t')[0])
	else:
		return 0

def get_path_inodes(*path:str):
	global DEBUG
	# this function gets the number of inodes in a path
	# df --inodes -s <path>
	if DEBUG:
		startTime = time.perf_counter()
	rtn = multiCMD.run_command(['du','--inodes','-csP',*path],quiet=not DEBUG)
	if DEBUG:
		backuperTeeLogToTl(path='get_path_inodes',message=f'took {time.perf_counter()-startTime} seconds')
	if rtn and rtn[-1] and rtn[-1].partition('\t')[0].isdigit():
		return int(rtn[-1].partition('\t')[0])
	else:
		return 0

def format_bytes(size, use_1024_bytes=None, to_int=False, to_str=False,str_format='.2f'):
	"""
	Format the size in bytes to a human-readable format or vice versa.
	From hpcp: https://github.com/yufei-pan/hpcp

	Args:
		size (int or str): The size in bytes or a string representation of the size.
		use_1024_bytes (bool, optional): Whether to use 1024 bytes as the base for conversion. If None, it will be determined automatically. Default is None.
		to_int (bool, optional): Whether to convert the size to an integer. Default is False.
		to_str (bool, optional): Whether to convert the size to a string representation. Default is False.
		str_format (str, optional): The format string to use when converting the size to a string. Default is '.2f'.

	Returns:
		int or str: The formatted size based on the provided arguments.

	Examples:
		>>> format_bytes(1500, use_1024_bytes=False)
		'1.50 K'
		>>> format_bytes('1.5 GiB', to_int=True)
		1610612736
		>>> format_bytes('1.5 GiB', to_str=True)
		'1.50 Gi'
		>>> format_bytes(1610612736, use_1024_bytes=True, to_str=True)
		'1.50 Gi'
		>>> format_bytes(1610612736, use_1024_bytes=False, to_str=True)
		'1.61 G'
		>>> format_bytes('500M', to_int=True)
		500000000
		>>> format_bytes('512Mi', to_int=True)
		536870912
		>>> format_bytes(0, to_str=True)
		'0.00 '
	"""
	if to_int or isinstance(size, str):
		if isinstance(size, int):
			return size
		elif isinstance(size, str):
			# Use regular expression to split the numeric part from the unit, handling optional whitespace
			match = re.match(r"(\d+(\.\d+)?)\s*([a-zA-Z]*)", size)
			if not match:
				if to_str:
					return size
				backuperTeeLogToTl(path='format_bytes',error=True,message="Invalid size format. Expected format: 'number [unit]', e.g., '1.5 GiB' or '1.5GiB'")
				backuperTeeLogToTl(path='format_bytes',message=f"Got: {size}")
				return 0
			number, _, unit = match.groups()
			number = float(number)
			unit = unit.strip().lower()
			unit = strip_suffix(unit, 'b')
			# Define the unit conversion dictionary
			if unit.endswith('i'):
				# this means we treat the unit as 1024 bytes if it ends with 'i'
				use_1024_bytes = True
			elif use_1024_bytes is None:
				use_1024_bytes = False
			unit = strip_suffix(unit, 'i')
			if use_1024_bytes:
				power = 2**10
			else:
				power = 10**3
			unit_labels = {'': 0, 'k': 1, 'm': 2, 'g': 3, 't': 4, 'p': 5}
			if unit not in unit_labels:
				if to_str:
					return size
				backuperTeeLogToTl(path='format_bytes',error=True,message=f"Invalid unit '{unit}'. Expected one of {list(unit_labels.keys())}")
				return 0
			if to_str:
				return format_bytes(size=int(number * (power ** unit_labels[unit])), use_1024_bytes=use_1024_bytes, to_str=True, str_format=str_format)
			# Calculate the bytes
			return int(number * (power ** unit_labels[unit]))
		else:
			try:
				return int(size)
			except Exception as _:
				return 0
	elif to_str or isinstance(size, int) or isinstance(size, float):
		if isinstance(size, str):
			try:
				size = strip_suffix(strip_suffix(size.lower().strip(), 'b'), 'B')
				size = float(size)
			except Exception as _:
				return size
		# size is in bytes
		if use_1024_bytes or use_1024_bytes is None:
			power = 2**10
			n = 0
			power_labels = {0 : '', 1: 'Ki', 2: 'Mi', 3: 'Gi', 4: 'Ti', 5: 'Pi'}
			while size >= power:
				size /= power
				n += 1
			return f"{size:{str_format}}{' '}{power_labels[n]}"
		else:
			power = 10**3
			n = 0
			power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T', 5: 'P'}
			while size >= power:
				size /= power
				n += 1
			return f"{size:{str_format}}{' '}{power_labels[n]}"
	else:
		try:
			return format_bytes(float(size), use_1024_bytes)
		except Exception as e:
			import traceback
			backuperTeeLogToTl(path='format_bytes',error=True,message=f"Error: {e}")
			backuperTeeLogToTl(path='format_bytes',message=traceback.format_exc())
			backuperTeeLogToTl(path='format_bytes',error=True,message="Invalid size: {size}")
		return 0

def folder_range_end(folder:str) -> str:
	'''
	Smallest path sorting after every path under folder (which ends with /), to select a folder's rows as a range.

	Examples:
		>>> folder_range_end('a/b/')
		'a/b0'
		>>> 'a/b/' < 'a/b/zz' < folder_range_end('a/b/') <= 'a/b0'
		True
	'''
	return folder[:-1] + chr(ord(folder[-1]) + 1)

class VaultManifest:
	'''
	The entries of a job's latest committed version and what the vault holds for each, kept in sqlite in the job vault.

	Paths are relative to the version folder, and folder paths end with /. Delta generation compares the monitored
	tree against the recorded size, mtime, mode, owner and tail hash, so it reads the vault only for unverified rows
	(no record yet), which it then records. Rows a backup writes are dirty until they are recorded from the new
	version, before its changes commit. kind is d (folder), f (regular file), o (other file type), l (symlink, its
	target in link) or r (a referenced backup's link to the monitored file itself). A file copied by a backup stays
	unchecked until delta generation reads the copy back from the vault, as a crash can keep its bytes from the disk.

	Examples:
		>>> import tempfile
		>>> with tempfile.TemporaryDirectory() as job_vault:
		...     manifest = VaultManifest(job_vault)
		...     manifest.begin()
		...     for rel in ('a/', 'a/x.txt', 'a/y.txt', 'b.txt', 'c.txt'):
		...         manifest.add(rel)
		...     manifest.move_tree('a/', 'd/')
		...     manifest.discard('b.txt')
		...     manifest.commit(os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800'))
		...     manifest.close()
		...     reopened = VaultManifest(job_vault)
		...     print(reopened.describes(os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800')), reopened.folders, reopened.files)
		...     reopened.close()
		True ['d/'] ['c.txt', 'd/x.txt', 'd/y.txt']
	'''
	SCHEMA = '1'
	UNVERIFIED = 'kind = NULL, size = NULL, mtime_ns = NULL, mode = NULL, uid = NULL, gid = NULL, hash = NULL, link = NULL, unchecked = NULL, dirty = 0'

	def __init__(self, job_vault:str):
		self.path = os.path.join(job_vault, MANIFEST_FILE_NAME)
		try:
			self._open()
		except sqlite3.DatabaseError as e:
			# it only records what the vault holds: start over, and delta generation reads the vault again
			backuperTeeLogToTl(path=self.path,error=True,message=f'Discarding unreadable manifest: {e}')
			for suffix in ('', '-journal'):
				try:
					os.remove(self.path + suffix)
				except FileNotFoundError:
					pass
			self._open()

	def _open(self):
		# transactions are explicit: a backup's changes commit together with the version they describe
		self.conn = sqlite3.connect(self.path, isolation_level=None)
		try:
			self.conn.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID')
			schema = self.conn.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
			if schema is None or schema[0] != self.SCHEMA:
				self.conn.execute('DROP TABLE IF EXISTS entries')
				self.conn.execute('DELETE FROM meta')
				self.conn.execute("INSERT INTO meta VALUES ('schema', ?)", (self.SCHEMA,))
			self.conn.execute('CREATE TABLE IF NOT EXISTS entries(path TEXT PRIMARY KEY, kind TEXT, size INTEGER, mtime_ns INTEGER, '
				'mode INTEGER, uid INTEGER, gid INTEGER, hash TEXT, link TEXT, unchecked INTEGER, dirty INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID')
			self.conn.execute('CREATE INDEX IF NOT EXISTS dirty_entries ON entries(path) WHERE dirty')
			self.conn.execute('CREATE TEMP TABLE IF NOT EXISTS seen(path TEXT PRIMARY KEY) WITHOUT ROWID')
		except BaseException:
			self.conn.close()
			raise

	def close(self):
		if self.conn is not None:
			# an open transaction rolls back
			self.conn.close()
			self.conn = None

	def begin(self):
		if not self.conn.in_transaction:
			self.conn.execute('BEGIN')

	def commit(self, version_path:str = None):
		'''Commit, recording that the rows now describe version_path when it is given.'''
		if version_path is not None:
			self._set_version(version_path)
		if self.conn.in_transaction:
			self.conn.execute('COMMIT')

	def rollback(self):
		if self.conn.in_transaction:
			self.conn.execute('ROLLBACK')

	def _set_version(self, version_path:str):
		self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('version', ?)", (os.path.basename(os.path.normpath(version_path)),))

	@property
	def skip_fingerprint(self):
		'''The skip list fingerprint recorded with the last committed state, or None when never recorded.'''
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'skip_fingerprint'").fetchone()
		return None if row is None else row[0]

	def set_skip_fingerprint(self, fingerprint:str):
		'''Record fingerprint; the caller holds the transaction.'''
		self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('skip_fingerprint', ?)", (fingerprint,))

	def describes(self, version_path:str) -> bool:
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
		return row is not None and row[0] == os.path.basename(os.path.normpath(version_path))

	def reset(self, version_path:str):
		'''Drop every row: the manifest now describes an empty version_path.'''
		self.conn.execute('DELETE FROM entries')
		self._set_version(version_path)

	def rebuild(self, version_path:str, tree_path:str = None, skip = None, errors:list = None):
		'''Track everything under tree_path (version_path by default) as unverified, describing version_path.'''
		self.reset(version_path)
		batch = []
		for _, rel, _ in iter_tree_entries(tree_path or version_path, skip=skip if tree_path else None, errors=errors):
			batch.append((rel,))
			if len(batch) >= MANIFEST_BATCH_SIZE:
				self.conn.executemany('INSERT OR REPLACE INTO entries(path) VALUES (?)', batch)
				batch.clear()
		self.conn.executemany('INSERT OR REPLACE INTO entries(path) VALUES (?)', batch)

	def lookup(self, rel:str):
		'''The record for rel (all None when unverified), or None when rel is not tracked.'''
		row = self.conn.execute('SELECT kind, size, mtime_ns, mode, uid, gid, hash, link, unchecked FROM entries WHERE path = ?', (rel,)).fetchone()
		return None if row is None else ManifestRecord(*row)

	def add(self, rel:str, dirty:bool = False):
		'''Track rel without a record: dirty when this backup wrote it, so it is recorded before the backup commits.'''
		self.conn.execute('INSERT OR REPLACE INTO entries(path, dirty) VALUES (?, ?)', (rel, int(dirty)))

	def discard(self, rel:str):
		self.conn.execute('DELETE FROM entries WHERE path = ?', (rel,))

	def discard_many(self, rels):
		self.conn.executemany('DELETE FROM entries WHERE path = ?', ((rel,) for rel in rels))

	def remove_tree(self, folder:str):
		'''Stop tracking folder and everything under it.'''
		self.conn.execute('DELETE FROM entries WHERE path >= ? AND path < ?', (folder, folder_range_end(folder)))

	def iter_under(self, folder:str):
		'''Tracked paths strictly under folder (which ends with /), sorted.'''
		for (path,) in self.conn.execute('SELECT path FROM entries WHERE path > ? AND path < ? ORDER BY path', (folder, folder_range_end(folder))):
			yield path

	def move_tree(self, src_folder:str, dst_folder:str):
		'''
		Track src_folder and everything under it as dst_folder instead, replacing what dst_folder held.
		The moved rows become unverified: a moved link that changed folder depth no longer resolves.
		'''
		if src_folder.startswith(dst_folder) or dst_folder.startswith(src_folder):
			# a folder cannot move into itself or onto its parent
			return
		self.remove_tree(dst_folder)
		self.discard(dst_folder[:-1])
		self.conn.execute(f'UPDATE entries SET path = ? || substr(path, ?), {self.UNVERIFIED} WHERE path >= ? AND path < ?',
			(dst_folder, len(src_folder) + 1, src_folder, folder_range_end(src_folder)))

	def set_records(self, records):
		'''Store (rel, record) pairs, leaving rel unverified where the record is None, and clear their dirty marks.'''
		unverified = []
		recorded = []
		for rel, record in records:
			if record is None:
				unverified.append((rel,))
			else:
				recorded.append((*record, rel))
		self.conn.executemany(f'UPDATE entries SET {self.UNVERIFIED} WHERE path = ?', unverified)
		self.conn.executemany('UPDATE entries SET kind = ?, size = ?, mtime_ns = ?, mode = ?, uid = ?, gid = ?, hash = ?, link = ?, '
			'unchecked = ?, dirty = 0 WHERE path = ?', recorded)

	def take_dirty(self, limit:int) -> list:
		return [rel for (rel,) in self.conn.execute('SELECT path FROM entries WHERE dirty LIMIT ?', (limit,))]

	def iter_folders(self):
		# sorted, so every folder comes before the folders inside it
		for (rel,) in self.conn.execute("SELECT path FROM entries WHERE substr(path, -1) = '/' ORDER BY path"):
			yield rel

	def iter_files(self):
		for (rel,) in self.conn.execute("SELECT path FROM entries WHERE substr(path, -1) != '/' ORDER BY path"):
			yield rel

	@property
	def folders(self) -> list:
		return list(self.iter_folders())

	@property
	def files(self) -> list:
		return list(self.iter_files())

	def counts(self) -> tuple:
		'''(files, folders) tracked.'''
		total, folders = self.conn.execute("SELECT count(*), total(substr(path, -1) = '/') FROM entries").fetchone()
		return total - int(folders), int(folders)

	def clear_seen(self):
		self.conn.execute('DELETE FROM temp.seen')

	def mark_seen(self, rels):
		self.conn.executemany('INSERT OR IGNORE INTO temp.seen VALUES (?)', ((rel,) for rel in rels))

	def mark_seen_under(self, folder:str):
		'''Mark every tracked row strictly under folder (which ends with /) seen: a folder that could not be read keeps its entries.'''
		self.conn.execute('INSERT OR IGNORE INTO temp.seen SELECT path FROM entries WHERE path > ? AND path < ?', (folder, folder_range_end(folder)))

	def unseen(self) -> list:
		'''Tracked paths not marked seen since clear_seen().'''
		return [rel for (rel,) in self.conn.execute('SELECT path FROM entries WHERE path NOT IN (SELECT path FROM temp.seen) ORDER BY path')]

	def prefetch(self):
		'''Read the database file in one pass, so the lookups that follow do not each seek the vault disks.'''
		buffer = bytearray(1 << 16)
		try:
			with open(self.path, 'rb', buffering=0) as f:
				while f.readinto(buffer):
					pass
		except OSError:
			pass

def entry_kind(mode:int) -> str:
	'''
	Manifest kind of an lstat mode.

	Examples:
		>>> [entry_kind(mode) for mode in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK, stat.S_IFIFO)]
		['d', 'f', 'l', 'o']
	'''
	if stat.S_ISDIR(mode):
		return 'd'
	if stat.S_ISREG(mode):
		return 'f'
	if stat.S_ISLNK(mode):
		return 'l'
	return 'o'

def vault_version_number(version_folder_name:str):
	'''
	Examples:
		>>> vault_version_number('V12--2021-01-01_00-00-00_-0800')
		12
		>>> vault_version_number('current_version') is None
		True
	'''
	match = re.match(r'V(\d+)--', version_folder_name)
	return int(match.group(1)) if match else None

def is_chained_link(resolved:str, job_vault:str, link_path:str) -> bool:
	'''
	Whether the link at link_path, resolving to resolved, points into another version of job_vault: that is how a
	version links an unchanged entry (under its old name if it moved since). A symlink backed up as one resolves
	within its own version, if into the vault at all.

	Examples:
		>>> is_chained_link('/v/job/V3--2021/a/b.txt', '/v/job', '/v/job/V4--2021/a/b.txt')
		True
		>>> is_chained_link('/v/job/V3--2021/old/b.txt', '/v/job', '/v/job/V4--2021/new/b.txt')
		True
		>>> is_chained_link('/v/job/V4--2021/b.txt', '/v/job', '/v/job/V4--2021/a/link')
		False
		>>> is_chained_link('/elsewhere/b.txt', '/v/job', '/v/job/V4--2021/a/link')
		False
	'''
	prefix = job_vault.rstrip('/') + '/'
	if not resolved.startswith(prefix) or not link_path.startswith(prefix):
		return False
	target_version = resolved[len(prefix):].partition('/')[0]
	return vault_version_number(target_version) is not None and target_version != link_path[len(prefix):].partition('/')[0]

def read_vault_record(version_path:str, rel:str, monitor_path:str):
	'''
	Record what version_path holds at rel, following the links that chain an unchanged entry back to its copy.
	Returns None when there is nothing readable there.
	'''
	entry = os.path.abspath(os.path.join(version_path, rel))
	try:
		if rel.endswith('/'):
			st = os.lstat(entry)
			if not stat.S_ISDIR(st.st_mode):
				return None
			return ManifestRecord('d', None, None, st.st_mode, st.st_uid, st.st_gid, None, None, 0)
		job_vault = os.path.dirname(os.path.abspath(version_path))
		monitor_entry = os.path.abspath(os.path.join(monitor_path, rel))
		for _ in range(MAX_CHAINED_LINKS):
			st = os.lstat(entry)
			if not stat.S_ISLNK(st.st_mode):
				break
			target = os.readlink(entry)
			resolved = os.path.abspath(os.path.join(os.path.dirname(entry), target))
			if resolved == monitor_entry:
				# a referenced backup links to the monitored file itself
				return ManifestRecord('r', None, None, None, None, None, None, None, 0)
			if not is_chained_link(resolved, job_vault, entry):
				# a symlink that was backed up as one, or a moved link that no longer reaches its version
				return ManifestRecord('l', None, None, st.st_mode, st.st_uid, st.st_gid, None, target, 0)
			entry = resolved
		else:
			return None
		kind = entry_kind(st.st_mode)
		file_hash = hash_file(entry, st.st_size) if kind == 'f' else None
		return ManifestRecord(kind, st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid, file_hash, None, 0)
	except OSError:
		return None

def read_copied_record(version_path:str, rel:str, monitor_path:str):
	'''read_vault_record() for an entry a backup just wrote: its file is still unchecked, as it was read from memory.'''
	record = read_vault_record(version_path, rel, monitor_path)
	return record._replace(unchecked=1) if record is not None and record.kind == 'f' else record

def record_dirty_entries(manifest:VaultManifest, version_path:str, monitor_path:str):
	'''Record what version_path holds for the rows this backup wrote, reading them on a compare pool.'''
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		while GREEN_LIGHT.is_set():
			rels = manifest.take_dirty(MANIFEST_BATCH_SIZE)
			if not rels:
				return
			manifest.set_records(zip(rels, pool.map(lambda rel: read_copied_record(version_path, rel, monitor_path), rels)))

def count_batch(pool, batch:list, allocated, total_bytes:int, inodes:int) -> tuple:
	for blocks in pool.map(allocated, batch):
		if blocks is not None:
			total_bytes += blocks
			inodes += 1
	return total_bytes, inodes

def measure_version_usage(manifest:VaultManifest, version_path:str) -> tuple:
	'''(bytes, inodes) a version holds, du style: allocated blocks of version_path and every row of manifest, lstat on a compare pool.'''
	def allocated(rel:str):
		try:
			return os.lstat(os.path.join(version_path, rel)).st_blocks * 512
		except OSError:
			backuperTeeLogToTl(path=version_path, message=f'{rel} is missing from the version, not counted')
			return None
	try:
		total_bytes = os.lstat(version_path).st_blocks * 512
	except OSError:
		return 0, 0
	inodes = 1
	def rows():
		yield from manifest.iter_folders()
		yield from manifest.iter_files()
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		batch = []
		for rel in rows():
			batch.append(rel)
			if len(batch) >= MANIFEST_BATCH_SIZE:
				total_bytes, inodes = count_batch(pool, batch, allocated, total_bytes, inodes)
				batch = []
		total_bytes, inodes = count_batch(pool, batch, allocated, total_bytes, inodes)
	return total_bytes, inodes

def compare_monitor_entry(monitor_entry:str, monitor_stat:os.stat_result, record:ManifestRecord):
	'''The event monitor_entry needs against record, what the vault holds for it, or None when it is unchanged.'''
	if record.kind == 'r':
		# the vault entry is this very file
		return None
	kind = entry_kind(monitor_stat.st_mode)
	if kind != record.kind:
		return 'modify'
	attrs_differ = (monitor_stat.st_mode, monitor_stat.st_uid, monitor_stat.st_gid) != (record.mode, record.uid, record.gid)
	if kind == 'd':
		return 'attrib' if attrs_differ else None
	if kind == 'l':
		return 'modify' if os.readlink(monitor_entry) != record.link else None
	if monitor_stat.st_size != record.size or monitor_stat.st_mtime_ns != record.mtime_ns:
		return 'modify'
	# the tail catches contents rewritten in place without moving the mtime
	if kind == 'f' and hash_file(monitor_entry, monitor_stat.st_size) != record.hash:
		return 'modify'
	return 'attrib' if attrs_differ else None

def compare_entry(monitor_entry:str, rel:str, record:ManifestRecord, version_path:str, monitor_path:str):
	'''
	Compare one tracked entry for delta generation, on the compare pool.
	Returns (event or None, a record read from the vault to store or None).
	'''
	found = None
	if record.kind is None:
		found = read_vault_record(version_path, rel, monitor_path)
		if found is None:
			backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Cannot read {os.path.join(version_path, rel)} from the vault, treating as create')
			return 'create', None
		record = found
	elif record.unchecked:
		# a crash soon after a backup can leave its copies at the right size and mtime over bytes that never reached the disk
		found = read_vault_record(version_path, rel, monitor_path)
		if found is None or (found.size, found.mtime_ns, found.hash) != (record.size, record.mtime_ns, record.hash):
			backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Vault copy at {os.path.join(version_path, rel)} does not match its record, copying again')
			return 'modify', None
	try:
		monitor_stat = os.lstat(monitor_entry)
	except OSError:
		backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Error getting stat for {monitor_entry}, treating as create')
		return 'create', found
	try:
		return compare_monitor_entry(monitor_entry, monitor_stat, record), found
	except Exception as e:
		backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Error comparing {monitor_entry}: {e}, treating as modify')
		return 'modify', found

def delta_generate_backup_entries(backupEntries:dict,latest_version_info:VaultEntry,monitor_path:str,manifest:VaultManifest = None,skip_list:'SkipList' = None,job_name:str = '',reported:set = None) -> VaultManifest:
	'''
	Add to backupEntries what changed in monitor_path since the latest version, comparing against its manifest.

	Unchanged entries are recognised from the recorded size, mtime, mode, owner and tail hash, so only the monitored
	side is read. The vault is read for unverified rows, which then get recorded, and for unchecked copies, which a
	crash may have left without their bytes.
	A folder that cannot be read keeps its tracked entries and is logged as UNREADABLE; when the monitored root itself
	cannot be read, JobFailure is raised before anything is recorded as deleted.
	Returns the manifest, opened in the job vault when none is given.
	'''
	if manifest is None:
		manifest = VaultManifest(os.path.dirname(os.path.abspath(latest_version_info.path)))
	version_path = latest_version_info.path
	start_time = time.monotonic()
	manifest.prefetch()
	manifest.begin()
	if not manifest.describes(version_path):
		backuperTeeLogToTl(path=monitor_path,message=f'Manifest does not describe {version_path}, listing it to read from the vault')
		manifest.rebuild(version_path)
	manifest.clear_seen()
	pending = deque()
	seen = []
	compared = 0
	recorded = 0
	walk_errors = []
	def settle(limit):
		nonlocal recorded
		while len(pending) > limit:
			monitor_entry, rel, outcome = pending.popleft()
			event, found = outcome.result() if isinstance(outcome, Future) else outcome
			if found is not None:
				manifest.set_records(((rel, found),))
				recorded += 1
			if event:
				backupEntries[monitor_entry] = BackupEntryValues(datetime.datetime.now().isoformat(),event,None)
	# results are taken in walk order, so a new tree still lists each folder before its contents
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		for monitor_entry, rel, _ in iter_tree_entries(monitor_path,skip=None if skip_list is None else skip_list.skips,errors=walk_errors):
			if not GREEN_LIGHT.is_set():
				break
			record = manifest.lookup(rel)
			if record is None:
				pending.append((monitor_entry, rel, ('create', None)))
			else:
				compared += 1
				seen.append(rel)
				if len(seen) >= MANIFEST_BATCH_SIZE:
					manifest.mark_seen(seen)
					seen.clear()
				pending.append((monitor_entry, rel, pool.submit(compare_entry, monitor_entry, rel, record, version_path, monitor_path)))
			settle(COMPARE_THREADS * 4)
		settle(0)
	manifest.mark_seen(seen)
	root_error = next((error for rel, error in walk_errors if not rel), None)
	if root_error is not None:
		manifest.rollback()
		raise JobFailure(f'cannot read {monitor_path}: {root_error}')
	for rel, _ in walk_errors:
		manifest.mark_seen_under(rel)
	log_unreadable(job_name, monitor_path, walk_errors, reported)
	if GREEN_LIGHT.is_set():
		# only a complete walk tells deleted entries from ones it did not reach
		for rel in manifest.unseen():
			backuperTeeLogToTl(path=monitor_path,message=f'Deleted file/folder {os.path.join(monitor_path,rel)}')
			backupEntries[os.path.join(monitor_path,rel)] = BackupEntryValues(datetime.datetime.now().isoformat(),'delete',None)
	# what was read from the vault holds whether or not a new version follows
	manifest.commit(version_path)
	backuperTeeLogToTl(path=monitor_path,message=f'Compared {compared} tracked entries in {time.monotonic() - start_time:.1f}s, {recorded} read from the vault, {len(backupEntries)} differences')
	return manifest

def hash_file(path,size = ...,full_hash=False):
	'''
	Hash file contents with xxhash (last HASH_SIZE bytes unless full_hash is True).

	Examples:
		>>> digest = hash_file(__file__, full_hash=True)
		>>> len(digest) == 16
		True
		>>> digest == hash_file(__file__, full_hash=True)
		True
	'''
	#From hpcp: https://github.com/yufei-pan/hpcp
	global HASH_SIZE
	if HASH_SIZE <= 0:
		# Do not hash
		return ''
	if size == ...:
		try:
			size = max(os.lstat(path).st_size,4096)
		except Exception as _:
			# if the file does not exist / cannot be accessed, return empty hash
			backuperTeeLogToTl(path='hash_file',error=True,message=f'Error getting size for {path}')
			return ''
	hasher = xxhash.xxh64()
	# a file swapped for a FIFO after its lstat would block a plain open forever with no writer
	with open(path, 'rb', opener=lambda file, flags: os.open(file, flags | os.O_NONBLOCK | os.O_NOCTTY)) as f:
		if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
			raise OSError(errno.EINVAL, 'Not a regular file', path)
		# regular files ignore O_NONBLOCK, but drop it in case a filesystem passes it on
		fcntl.fcntl(f.fileno(), fcntl.F_SETFL, fcntl.fcntl(f.fileno(), fcntl.F_GETFL) & ~os.O_NONBLOCK)
		if not full_hash:
			# Only hash the last hash_size bytes, in one read: the disk seeks once for them either way
			f.seek(-min(HASH_SIZE,size), os.SEEK_END)
			hasher.update(f.read(HASH_SIZE))
		else:
			for chunk in iter(lambda: f.read(1 << 20), b''):
				hasher.update(chunk)
	return hasher.hexdigest()

def inside_folders(path:str, folders:set, start:int = 0) -> bool:
	'''
	Whether path lies strictly inside one of folders (paths ending with /), checking its parent folders from index start.
	Same notion as path_covered_by_dir_create, in one set lookup per parent.

	>>> inside_folders('/m/a/b/c', {'/m/a/'}), inside_folders('/m/a/b/', {'/m/a/'})
	(True, True)
	>>> inside_folders('/m/a/', {'/m/a/'}), inside_folders('/m/a', {'/m/a/'}), inside_folders('/m/ab', {'/m/a/'})
	(False, False, False)
	'''
	end = len(path.rstrip('/'))
	i = path.find('/', start)
	while i != -1 and i < end:
		if path[:i + 1] in folders:
			return True
		i = path.find('/', i + 1)
	return False

def get_unskipped_size_inodes(path:str, skip_list:'SkipList', count_size:bool = True, count_inodes:bool = True) -> tuple:
	'''
	The disk usage in bytes and the inode count of path and, for a folder (ending with /), of what the skip list leaves
	below it, for a copy that leaves the skipped paths out. Skipped folders are not descended into, and entries that
	vanish are left out. Each name is counted, as the replay copies each name of a hard-linked file on its own.
	'''
	try:
		blocks = os.lstat(path).st_blocks
	except OSError:
		return 0, 0
	size = blocks * 512 if count_size else 0
	inodes = 1 if count_inodes else 0
	if not path.endswith('/'):
		return size, inodes
	for entry_path, _, _ in iter_tree_entries(path, skip_list.folder_rel(path), skip=skip_list.skips):
		try:
			blocks = os.lstat(entry_path).st_blocks
		except OSError:
			continue
		if count_size:
			size += blocks * 512
		if count_inodes:
			inodes += 1
	return size, inodes

def get_backup_size_inode(backup_entries:dict,only_sync_attributes:bool,last_vault_version_path:str,monitor_path:str,skip_list:'SkipList' = None): 
	'''
	This function gets the size of the backup entries

	Parameters:
		backup_entries (dict): The backup entries
		only_sync_attributes (bool): Whether to only sync the attributes
		last_vault_version_path (str): The path of the last vault version
		monitor_path (str): The path of the monitored path
		skip_list (SkipList): The job's skip list; with patterns, folders are measured without their skipped contents

	Returns:
		tuple: The size and inode change compared to previous backup of the backup entries
	'''
	# BACKUP_ENTRY_VALUES_HEADER = ['iso_time','event','source_path']
	# event can be create, modify, attrib, move, delete
	total_size = 0
	total_inode_change = 0
	path_pending_to_get_size = []
	path_pending_to_get_inode_add = []
	path_pending_to_get_inode_del = []
	# du would count skipped caches the copy leaves out, and the size limit would prune history to make room for them
	walk_folders = bool(skip_list)
	if walk_folders:
		# du counts an argument inside another only once, and so must the walks: a full comparison queues an entry for
		# every folder and file of a new tree. a folder create holds the bytes and inodes below it, a sized folder
		# modify or attrib only the bytes
		sized_folders = set()
		created_folders = set()
		for entry, values in backup_entries.items():
			if entry.endswith('/'):
				if values.event == 'create':
					created_folders.add(entry)
					sized_folders.add(entry)
				elif values.event == 'modify' or (not only_sync_attributes and values.event == 'attrib'):
					sized_folders.add(entry)
		# entries lie below the monitored folder, so only parents from it down can hold them
		parents_from = len(monitor_path.rstrip('/'))
	for entry in backup_entries:
		if walk_folders and backup_entries[entry].event != 'delete':
			event = backup_entries[entry].event
			if event in ('create', 'modify') or (not only_sync_attributes and event == 'attrib'):
				count_size = not inside_folders(entry, sized_folders, parents_from)
				# we do not count inode change for attrib / modify / move events
				count_inodes = event == 'create' and not inside_folders(entry, created_folders, parents_from)
				if count_size or count_inodes:
					entry_size, entry_inodes = get_unskipped_size_inodes(entry, skip_list, count_size, count_inodes)
					total_size += entry_size
					total_inode_change += entry_inodes
			continue
		if backup_entries[entry].event == 'create' :
			path_pending_to_get_size.append(entry)
			if entry.endswith('/'):
				# this is a directory
				path_pending_to_get_inode_add.append(entry)
			else:
				total_inode_change += 1
		elif backup_entries[entry].event == 'modify' or (not only_sync_attributes and backup_entries[entry].event == 'attrib'):
			path_pending_to_get_size.append(entry)
			# we do not count inode change for attrib / modify / move events
		elif backup_entries[entry].event == 'delete':
			if entry.endswith('/'):
				# this is a directory
				vault_entry_path = os.path.join(last_vault_version_path,os.path.relpath(entry,monitor_path))
				path_pending_to_get_inode_del.append(vault_entry_path)
			else:
				# this is a file
				total_inode_change -= 1
			# size will not decrease as we are not backing up the full content, but inodes will decrease as we are using symlinks
		if len(path_pending_to_get_size) > ARGUMENT_LIMIT:
			total_size += get_path_size(*path_pending_to_get_size)
			path_pending_to_get_size = []
		if len(path_pending_to_get_inode_add) > ARGUMENT_LIMIT:
			total_inode_change += get_path_inodes(*path_pending_to_get_inode_add)
			path_pending_to_get_inode_add = []
		if len(path_pending_to_get_inode_del) > ARGUMENT_LIMIT:
			total_inode_change -= get_path_inodes(*path_pending_to_get_inode_del)
			path_pending_to_get_inode_del = []
	if path_pending_to_get_size:
		total_size += get_path_size(*path_pending_to_get_size)
	if path_pending_to_get_inode_add:
		total_inode_change += get_path_inodes(*path_pending_to_get_inode_add)
	if path_pending_to_get_inode_del:
		total_inode_change -= get_path_inodes(*path_pending_to_get_inode_del)
	return total_size, total_inode_change

def get_path_fs_info(path:str):
	# this function gets the filesystem usage information of a path
	# df --no-sync --output=size,itotal <path>
	# rtn = multiCMD.run_command(['df','--no-sync','--output=size,itotal',path],quiet=not DEBUG)
	# if rtn and rtn[-1]:
	# 	try:
	# 		size, inodes = rtn[-1].split(maxsplit=1)
	# 		return int(size), int(inodes)
	# 	except:
	# 		pass
	# use os.statvfs instead
	try:
		result = os.statvfs(path)
		size = result.f_frsize * result.f_blocks
		inodes = result.f_files
		return size, inodes
	except Exception as e:
		backuperTeeLogToTl(path=path,error=True,message=f'Error getting filesystem info for {path}: {e}')
	return 0,0

def get_backup_limits_from_str(backup_size_limit:str,vault_fs_size:int,vault_fs_inode:int) -> tuple:
	'''
	This function gets the backup limits from a string.
	Use 0 for infinity, % numbers refer to disk usage %, use leading i to represent inodes, use comma to seperate multiple rules
	Stricter (smaller) limits take precedence

	Parameters:
		backup_size_limit (str): The backup size limit string

	Returns:
		tuple: The backup size and inode limits

	Examples:
		>>> get_backup_limits_from_str('0', 1000, 200)
		(0, 0)
		>>> get_backup_limits_from_str('', 1000, 200)
		(0, 0)
		>>> get_backup_limits_from_str('5%', 1000, 200)
		(50, 0)
		>>> get_backup_limits_from_str('i5%', 1000, 200)
		(0, 10)
		>>> get_backup_limits_from_str('5%,i5%', 1000, 200)
		(50, 10)
		>>> get_backup_limits_from_str('1G,500M', 1000, 200)
		(500000000, 0)
		>>> get_backup_limits_from_str('i1000,i500', 1000, 200)
		(0, 500)
	'''
	backup_size_limit = backup_size_limit.strip().lower()
	if not backup_size_limit or backup_size_limit == '0':
		return 0, 0
	backup_size_limits = backup_size_limit.split(',')
	rtn_size_limit = 0
	rtn_inode_limit = 0
	for limit in backup_size_limits:
		size_limit = -1
		inode_limit = -1
		if limit.endswith('%'):
			limit = strip_suffix(limit, '%')
			if limit.startswith('i'):
				try:
					inode_limit = int(float(strip_prefix(limit, 'i')) * vault_fs_inode // 100)
					if vault_fs_inode and inode_limit == 0:
						# if vault has inodes but we cannot use any, set inode limit to 1
						inode_limit = 1
				except Exception as _:
					pass
			else:
				try:
					size_limit = int(float(limit) * vault_fs_size // 100)
					if vault_fs_size and size_limit == 0:
						size_limit = 1
				except Exception as _:
					pass
		elif limit.startswith('i'):
			try:
				inode_limit = int(format_bytes(strip_prefix(limit, 'i'),to_int=True))
			except Exception as _:
				pass
		else:
			try:
				size_limit = int(format_bytes(limit,to_int=True))
			except Exception as _:
				pass
		if inode_limit > 0:
			if rtn_inode_limit == 0 or inode_limit < rtn_inode_limit:
				rtn_inode_limit = inode_limit
		if size_limit > 0:
			if rtn_size_limit == 0 or size_limit < rtn_size_limit:
				rtn_size_limit = size_limit
	return rtn_size_limit, rtn_inode_limit

def refresh_vault_entry_size_metadata(entry:VaultEntry) -> VaultEntry:
	'''Recalculate size/inode from disk and rename content file to match.'''
	new_size = get_path_size(entry.path)
	new_inode = get_path_inodes(entry.path)
	old_size_str = format_bytes(entry.size,use_1024_bytes=True,to_str=True).replace(' ','_')
	old_inode_str = format_bytes(entry.inode,use_1024_bytes=False,to_str=True).replace(' ','')
	old_content = f'{entry.path}--{old_size_str}B-{old_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
	new_size_str = format_bytes(new_size,use_1024_bytes=True,to_str=True).replace(' ','_')
	new_inode_str = format_bytes(new_inode,use_1024_bytes=False,to_str=True).replace(' ','')
	new_content = f'{entry.path}--{new_size_str}B-{new_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
	if os.path.lexists(old_content) and old_content != new_content:
		try:
			os.rename(old_content,new_content)
		except Exception as e:
			backuperTeeLogToTl(path=entry.path,error=True,message=f'Error renaming content file {old_content} -> {new_content}: {e}')
	elif not os.path.lexists(new_content) and not os.path.lexists(old_content):
		pass
	return VaultEntry(entry.version_number,entry.path,entry.timestamp,new_size,new_inode)

def decrement_stepper(vault_info_dict:OrderedDict) -> tuple:
	'''
	Remove the oldest vault version and materialize the next version's symlinks.

	Examples:
		>>> decrement_stepper(OrderedDict([(0, VaultEntry(0, '/tmp/x', 0, 0, 0))]))
		(0, 0)
		>>> decrement_stepper(OrderedDict())
		(0, 0)
	'''
	global DEBUG
	global CONTENT_FILE_EXTENSION_NAME
	# this function remove the oldest reverb from path
	if len(vault_info_dict) < 2:
		# we cannot step as there is less than 2 availble reverbs
		return 0 , 0
	backuperTeeLogToTl(path='decrement_stepper',message='Running stepper to remove oldest reverb',ok=True)
	referenceVersionNumber, referenceVaultEntry = vault_info_dict.popitem(last=False)
	referenceVaultPath = os.path.abspath(referenceVaultEntry.path)
	if referenceVaultPath == '/':
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message='Attempting to remove root, skipping')
		backuperTeeLogToTl(path=referenceVaultPath,message=referenceVaultEntry)
		return 0 , 0
	#reference_content_file_path = f'{referenceVaultPath}--{format_bytes(referenceVaultEntry.size,use_1024_bytes=True,to_str=True).replace(" ","_")}B-{format_bytes(referenceVaultEntry.inode,use_1024_bytes=False,to_str=True).replace(" ","")}_ino{CONTENT_FILE_EXTENSION_NAME}'
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Recursively removing V{referenceVersionNumber}: {referenceVaultPath}')
	vaultInfoIter = iter(vault_info_dict)
	applyingVersionNumber = next(vaultInfoIter)
	applyingVaultEntry = vault_info_dict[applyingVersionNumber]
	backup_size_str = format_bytes(applyingVaultEntry.size,use_1024_bytes=True,to_str=True).replace(' ','_')
	backup_inode_str = format_bytes(applyingVaultEntry.inode,use_1024_bytes=False,to_str=True).replace(' ','')
	content_file_path = f'{applyingVaultEntry.path}--{backup_size_str}B-{backup_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
	if not os.path.lexists(content_file_path):
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Content file {content_file_path} does not exist, creating a new one...')
		content_file_path = ''
	# now we need to go through all files in the applying vault entry
	# find all symlinks that is referencing an files in the reference vault entry
	# if it is in movedPath, we apply the new path to the symlink
	# if it is not in movedPath, this means it is first reference, thus
	#   we remove the symlink in the appying vault, move the file to the new location, and add the pair to movedPath
	backuperTeeLogToTl(path=referenceVaultPath,message=f"Dealing with {applyingVersionNumber}: {applyingVaultEntry.path}")
	new_size = applyingVaultEntry.size
	block_size = os.statvfs(referenceVaultPath).f_frsize
	materialize_failed = False
	# walked instead of listed up front, as the next version links every tracked file (500k+ for big jobs).
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another
	for file, _, is_dir in iter_tree_entries(applyingVaultEntry.path, list_folders_first=True):
		if is_dir:
			continue
		if os.path.islink(file):
			linkTarget = os.path.abspath(os.path.join(os.path.dirname(file), os.readlink(file)))
			if linkTarget.startswith(referenceVaultPath):
				# this means we need to move the file to the new location
				# get the relative path of the target
				if DEBUG:
					backuperTeeLogToTl(path=referenceVaultPath,message=f'Moving {linkTarget} to {file}')
				try:
					new_size += max(os.lstat(linkTarget).st_size,block_size)
					new_size -= max(os.lstat(file).st_size,block_size)
				except Exception as e:
					if DEBUG:
						backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error getting size of {file}: {e}')
				try:
					os.rename(linkTarget,file)
				except Exception as e:
					if os.path.lexists(linkTarget):
						# the target is still there but we could not move it, so removing the
						# reference vault would destroy the only copy. keep it and retry later.
						materialize_failed = True
						backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error moving {linkTarget} to {file}: {e}')
						continue
					# the target is already gone, so this link was dangling before we touched it.
					# removing the reference vault loses nothing that is not already lost, and
					# keeping the link would carry the broken reference forward into every later
					# version. drop it and keep stepping, as aborting here wedges retention forever.
					try:
						new_size -= max(os.lstat(file).st_size,block_size)
					except Exception as sizeError:
						if DEBUG:
							backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error getting size of {file}: {sizeError}')
					try:
						os.remove(file)
					except Exception as removeError:
						backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error removing dangling link {file} -> {linkTarget}: {removeError}')
					else:
						backuperTeeLogToTl(path=referenceVaultPath,message=f'Removed dangling link {file} -> {linkTarget} as the target is already missing')
					continue
			elif DEBUG:
				backuperTeeLogToTl(path=referenceVaultPath,message=f'Not moving {linkTarget} to {file}')
				backuperTeeLogToTl(path=referenceVaultPath,message=f'{os.path.abspath(linkTarget)} not in {referenceVaultPath}')
	if materialize_failed:
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Aborting removal of {referenceVaultPath} because materializing linked files failed')
		new_dict = OrderedDict()
		new_dict[referenceVersionNumber] = referenceVaultEntry
		new_dict.update(vault_info_dict)
		vault_info_dict.clear()
		vault_info_dict.update(new_dict)
		vault_info_dict[referenceVersionNumber] = refresh_vault_entry_size_metadata(vault_info_dict[referenceVersionNumber])
		vault_info_dict[applyingVersionNumber] = refresh_vault_entry_size_metadata(vault_info_dict[applyingVersionNumber])
		return 0, 0
	#V0--2021-01-01_00-00-00_-0800
	if new_size != applyingVaultEntry.size:
		backup_size_str = format_bytes(new_size,use_1024_bytes=True,to_str=True).replace(' ','_')
		new_content_file_path = f'{applyingVaultEntry.path}--{backup_size_str}B-{backup_inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'
		if content_file_path:
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Renaming {content_file_path} to {new_content_file_path}')
			try:
				os.rename(content_file_path,new_content_file_path)
			except Exception as e:
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error renaming {content_file_path} to {new_content_file_path}: {e}')
				#continue
		else:
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Creating content file {new_content_file_path}')
			try:
				TSVZ.appendTabularFile(new_content_file_path,[],header = ['path']+ BACKUP_ENTRY_VALUES_HEADER,createIfNotExist = True,verifyHeader = True,strict=False,teeLogger=tl,verbose=DEBUG)
			except Exception as e:
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error creating content file {new_content_file_path}: {e}')
				#continue
	# if DEBUG:
	# 	backuperTeeLogToTl(path=referenceVaultPath,message=f'As we are now using chained links, we are only removing the next entry. we are not looping though the whole vault.')
	# break
	# remove the reference vault entry
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Removing {referenceVaultPath}')
	removingSize = get_path_size(referenceVaultPath)
	removingInodes = get_path_inodes(referenceVaultPath)
	#os.remove(path=reference_content_file_path)
	paths_to_remove = glob.glob(referenceVaultPath+'*',recursive=False)
	multiCMD.run_command(['rm','-rf',*paths_to_remove],quiet=not DEBUG,return_code_only=True)
	return removingSize, removingInodes

def do_reverb_backup(backup_entries:dict,backup_folder:str,latest_version_info:VaultEntry,
					 only_sync_attributes:bool,manifest:VaultManifest,monitor_path:str,skip_list:'SkipList' = None,job_name:str = None,reported:set = None) -> VaultManifest:
	'''
	Create backup_folder as a referenced copy of the latest version, then replay backup_entries onto it.

	manifest is updated to describe backup_folder inside a transaction the caller commits once the version is complete.
	'''
	global BACKUP_SEMAPHORE
	global GREEN_LIGHT
	if reported is None:
		reported = set()
	backup_entries = prepare_backup_entries_for_replay(backup_entries)
	backuperTeeLogToTl(path=monitor_path,message=f'Running reverb backup with {len(backup_entries)} entires to {backup_folder}',ok=True)
	def copy_path(isDir,monitor_path,source_real_path,source_relative_path,file_vault_real_path,backup_folder,mcae):
		if not os.path.lexists(source_real_path):
			# recording a path we cannot copy makes the tracked list lie about this
			# version, and the next referenced copy turns every such entry into a
			# dangling link that all later versions inherit. skip it instead.
			backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not tracking {source_relative_path}: source no longer exists')
			return
		if isDir:
			manifest.add(as_folder_entry(source_relative_path),dirty=True)
			os.makedirs(file_vault_real_path,exist_ok=True)
			copy_file_meta(source_file=source_real_path,backup_file_path=file_vault_real_path)
			walk_errors = []
			rel_base = as_folder_entry(source_relative_path)
			for subRealPath, subRelativePath, subIsDir in iter_tree_entries(source_real_path,rel_base,skip=None if skip_list is None else skip_list.skips,errors=walk_errors):
				subVaultPath = os.path.join(backup_folder,subRelativePath)
				if subIsDir:
					manifest.add(subRelativePath,dirty=True)
					os.makedirs(subVaultPath,exist_ok=True)
					copy_file_meta(source_file=subRealPath,backup_file_path=subVaultPath)
					continue
				if not os.path.lexists(subRealPath):
					backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not tracking {subRelativePath}: source no longer exists')
					continue
				manifest.add(subRelativePath,dirty=True)
				cp_af_copy_path(source_path=subRealPath,dest_path=subVaultPath,mcae=mcae,pending=pending)
			log_unreadable(monitor_path if job_name is None else job_name,monitor_path,walk_errors,reported)
		else:
			manifest.add(source_relative_path,dirty=True)
		# we just copy the entire folder / file ( for recursive create purposes )
			cp_af_copy_path(source_path=source_real_path,dest_path=file_vault_real_path,mcae=mcae,pending=pending)
	def delete_path(isDir,vault_real_path,relative_path,mcae):
		if isDir:
			# we just remove the folder
			if os.path.abspath(vault_real_path) == '/':
				# we cannot remove root
				backuperTeeLogToTl(path=vault_real_path,error=True,message='Attempting to remove root, skipping')
			else:
				mcae.run_command(['rm','-rf',vault_real_path])
			# also stops tracking all the files and subfolders in the folder
			manifest.remove_tree(as_folder_entry(relative_path))
		else:
			# we just remove the file
			mcae.run_command(['rm','-f',vault_real_path])
			manifest.discard(relative_path)
	def wait_for_async_commands(mcae):
		while GREEN_LIGHT.is_set() and mcae.runningThreads:
			mcae.wait(timeout=POLL_WAIT_SECONDS)
		if GREEN_LIGHT.is_set():
			# what was copied takes its place before anything renames, removes or records it
			finish_copies(pending,manifest,backup_folder,monitor_path if job_name is None else job_name,reported)
	def recheck_moved_folder(folder_rel,mcae):
		# a location-dependent pattern may judge the moved contents differently at the new place
		under = list(manifest.iter_under(folder_rel))
		newly_skipped = []
		for rel in under:
			if newly_skipped and rel.startswith(newly_skipped[-1]) and newly_skipped[-1].endswith('/'):
				# inside a folder already collected, removing that folder removes this too
				continue
			if skip_list.skips(rel):
				newly_skipped.append(rel)
		for rel in newly_skipped:
			delete_path(isDir=rel.endswith('/'),vault_real_path=os.path.join(backup_folder,rel),relative_path=rel.rstrip('/'),mcae=mcae)
		wait_for_async_commands(mcae)
		copied = None
		walk_errors = []
		for sub_real_path,sub_rel,sub_is_dir in iter_tree_entries(os.path.join(monitor_path,folder_rel),folder_rel,skip=skip_list.skips,errors=walk_errors):
			if copied is not None and sub_rel.startswith(copied):
				continue
			if manifest.lookup(sub_rel) is None:
				copy_path(isDir=sub_is_dir,monitor_path=monitor_path,source_real_path=sub_real_path,
				  source_relative_path=sub_rel.rstrip('/'),file_vault_real_path=os.path.join(backup_folder,sub_rel),
				  backup_folder=backup_folder,mcae=mcae)
				# a copied folder took everything below it along; a copied file has nothing below it
				copied = sub_rel if sub_is_dir else None
		log_unreadable(monitor_path if job_name is None else job_name,monitor_path,walk_errors,reported)
	# this function does the actual backup using a referenced version and a change list to copy the source from
	# reverb backup flow:
	#   do referenced copy of the last version to the current backup folder 
	#   replay the changes chronologically ( to respect moves )
	manifest.begin()
	if not manifest.describes(latest_version_info.path):
		backuperTeeLogToTl(path=monitor_path,message=f'Manifest does not describe {latest_version_info.path}, listing it')
		manifest.rebuild(latest_version_info.path)
	if not do_referenced_copy(source_path=latest_version_info.path,backup_folder=backup_folder,manifest=manifest,relative=True):
		return manifest
	backuperTeeLogToTl(path=monitor_path,message='Tracking {} files and {} folders'.format(*manifest.counts()))
	mcae = multiCMD.AsyncExecutor(semaphore=BACKUP_SEMAPHORE,quiet=not DEBUG)
	# copies queued on mcae, put in place by each wait for it
	pending = []
	need_delete_barrier = False
	try:
		for event_source_real_path, event_values in backup_entries.items():
			backuperTeeLogToTl(path=monitor_path,message=f'Processing {event_source_real_path} {event_values}')
			event_relative_path = os.path.relpath(path=event_source_real_path,start=monitor_path)
			file_vault_target_path = os.path.join(backup_folder,event_relative_path)
			isDir = event_source_real_path.endswith('/')
			# create, modify, attrib, move, delete
			if event_values.event == 'delete':
				delete_path(isDir=isDir,vault_real_path=file_vault_target_path,relative_path=event_relative_path,mcae=mcae)
				need_delete_barrier = True
				continue
			if need_delete_barrier:
				# finish async rms before creates/moves recreate overlapping paths
				wait_for_async_commands(mcae)
				need_delete_barrier = False
			if event_values.event in {'create','modify'}:
				# we just over write the vault file with the source file
				copy_path(isDir=isDir,monitor_path=monitor_path,source_real_path=event_source_real_path,
				 source_relative_path=event_relative_path,
				 file_vault_real_path=file_vault_target_path,backup_folder=backup_folder,mcae=mcae)
			elif event_values.event == 'attrib':
				if isDir:
					# we just copy the folder metadata
					os.makedirs(file_vault_target_path,exist_ok=True)
					copy_file_meta(event_source_real_path,file_vault_target_path)
					manifest.add(as_folder_entry(event_relative_path),dirty=True)
				else:
					if only_sync_attributes:
						# we just copy the file metadata
						# ensure parent exists when prior version lacked this path
						parent_dir = os.path.dirname(file_vault_target_path)
						if parent_dir:
							os.makedirs(parent_dir, exist_ok=True)
						copy_file_meta(event_source_real_path,file_vault_target_path)
					else:
						# we copy the file
						cp_af_copy_path(source_path=event_source_real_path,dest_path=file_vault_target_path,mcae=mcae,pending=pending)
					manifest.add(event_relative_path,dirty=True)
			elif event_values.event == 'move':
				link_source_relative_path = os.path.relpath(event_values.source_path,monitor_path)
				link_target_relative_path = event_relative_path
				if isDir:
					if os.path.abspath(file_vault_target_path) == '/':
						# we cannot remove root
						backuperTeeLogToTl(path=file_vault_target_path,error=True,message='Attempting to move root, skipping')
						continue
					# also moves all the files and subfolders in the folder
					manifest.move_tree(as_folder_entry(link_source_relative_path),as_folder_entry(link_target_relative_path))
					manifest.add(as_folder_entry(link_target_relative_path))
				else:
					manifest.discard(link_source_relative_path)
					manifest.add(link_target_relative_path)
				# we need to wait for copy threads to finish to allow rename
				wait_for_async_commands(mcae)
				link_source_backup_real_path = os.path.join(backup_folder,link_source_relative_path)
				link_target_backup_real_path = os.path.join(backup_folder,link_target_relative_path)
				try:
					if os.path.lexists(link_target_backup_real_path):
						os.remove(link_target_backup_real_path)
					os.rename(link_source_backup_real_path,link_target_backup_real_path)
					backuperTeeLogToTl(path=monitor_path,message=f'Moved {link_source_backup_real_path} to {link_target_backup_real_path}')
					# sync the current attrs from the source onto the moved vault entry,
					# but never through a chained symlink: that would rewrite the previous version's metadata
					if isDir or not os.path.islink(link_target_backup_real_path):
						copy_file_meta(event_source_real_path,link_target_backup_real_path)
				except Exception as _:
					backuperTeeLogToTl(path=monitor_path,error=True,message=f'Failed to move {link_source_backup_real_path} to {link_target_backup_real_path}')
					import traceback
					backuperTeeLogToTl(path=monitor_path,error=True,message=traceback.format_exc())
					backuperTeeLogToTl(path=monitor_path,message='Doing delete & copy instead')
					# if we fail to move, we just copy the file
					copy_path(isDir=isDir,monitor_path=monitor_path,
					  source_real_path=event_source_real_path,
					  source_relative_path=event_relative_path,
					  file_vault_real_path=file_vault_target_path,backup_folder=backup_folder,mcae=mcae)
					delete_path(isDir=isDir,vault_real_path=link_source_backup_real_path,
					  relative_path=link_source_relative_path,mcae=mcae)
					wait_for_async_commands(mcae)
				# the copy fallback keeps the rows move_tree moved too, so both ways need the re-check
				if isDir and skip_list is not None and skip_list.location_dependent:
					recheck_moved_folder(as_folder_entry(link_target_relative_path),mcae)
		if need_delete_barrier:
			wait_for_async_commands(mcae)
		wait_for_async_commands(mcae)
	finally:
		# however the backup ends, no copy is left writing into this version, nor a partial file in it
		stop_copies(mcae,pending,backup_folder)
	if mcae.runningThreads or not GREEN_LIGHT.is_set():
		backuperTeeLogToTl(path=monitor_path,error=True,message='Reverb backup interrupted before copy threads finished')
		return manifest
	record_dirty_entries(manifest,backup_folder,monitor_path)
	return manifest

if __name__ == "__main__":
	main()
# %%
