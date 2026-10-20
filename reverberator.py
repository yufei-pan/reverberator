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
import json
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


__version__ = 0.38

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

	def load(self, recorded_fingerprint, trusted:bool = True) -> bool:
		'''
		Load the list and compare it with the vault's recorded fingerprint; False when the job must not run.
		When the recorded fingerprint is not trusted (the manifest does not describe the latest version), a list that
		looks unchanged counts as changed, so the whole tree is compared.
		'''
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
			if self.change == 'unchanged' and not trusted:
				self.change = 'changed'
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
		self.last_success = None
		self._state = 'starting'
		self._detail = ''
		self._since = time.time()
		self._retry_at = None
		self._failures = 0
		# the waits for a disk now going on, oldest first, as [token, path, what, started]
		self._waits = []

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
		with self._lock:
			self.last_success = time.time()
			self._publish()

	def set_state(self, state:str, detail:str = '', retry_at:float = None, failures:int = 0):
		'''Record the job's state (starting, running, retrying or stopped) and publish it; a wait going on shows over it.'''
		with self._lock:
			self._state, self._detail, self._since = state, detail, time.time()
			self._retry_at, self._failures = retry_at, failures
			self._publish()

	def begin_wait(self, path:str, what:str) -> object:
		'''Note the job waiting for path, and return the token end_wait takes.'''
		token = object()
		with self._lock:
			self._waits.append([token, path, what, time.time()])
			self._publish()
		return token

	def end_wait(self, token):
		with self._lock:
			self._waits = [wait for wait in self._waits if wait[0] is not token]
			self._publish()

	def _publish(self):
		'''Publish the record to the status board. The caller holds the lock, which keeps the records in order.'''
		board = STATUS_BOARD
		if board is None:
			return
		state, detail, since = self._state, self._detail, self._since
		if self._waits:
			state, detail, since = 'waiting', f'{self._waits[0][1]}: {self._waits[0][2]}', self._waits[0][3]
		board.write_job(self.job_name, {'job': self.job_name, 'state': state, 'detail': detail, 'since': since,
			'retry_at': self._retry_at, 'failures': self._failures, 'last_success': self.last_success, 'updated': time.time()})

DEFAULT_STATE_DIR = '/run/reverberator'

def state_dir_path(override:str = None) -> str:
	'''
	The folder the daemon publishes its status in: override, else $REVERB_STATE_DIR, else DEFAULT_STATE_DIR.
	>>> state_dir_path('/x')
	'/x'
	'''
	return override or os.environ.get('REVERB_STATE_DIR') or DEFAULT_STATE_DIR

def process_start_ticks(pid:int) -> int:
	'''
	When process pid started, in clock ticks after boot (field 22 of its /proc stat), or None when unreadable.
	With the pid it tells a running daemon from a stale file whose pid another process took.
	>>> process_start_ticks(os.getpid()) > 0
	True
	'''
	try:
		with open(f'/proc/{pid}/stat', 'rb') as f:
			text = f.read().decode('utf-8', 'replace')
		# the command name in the first fields can hold spaces and brackets, so count from the last )
		return int(text[text.rindex(')') + 1:].split()[19])
	except (OSError, ValueError, IndexError):
		return None

class StatusBoard:
	'''
	The daemon's status files in state_dir: daemon.json for the daemon and job-<name>.json for each job, for the status
	command. A write never raises: the first error is logged and the rest are not, as a status must not stop a backup.
	'''
	def __init__(self, state_dir:str, rule_path:str):
		self.state_dir = state_dir
		self._failed = False
		self._write('daemon.json', {'pid': os.getpid(), 'start_ticks': process_start_ticks(os.getpid()), 'version': __version__,
			'started_at': time.time(), 'rule_path': rule_path})

	def write_job(self, job_name:str, record:dict):
		self._write(f'job-{job_name}.json', record)

	def _write(self, name:str, record:dict):
		temp = None
		try:
			os.makedirs(self.state_dir, exist_ok=True)
			fd, temp = tempfile.mkstemp(prefix='.tmp-', dir=self.state_dir)
			with os.fdopen(fd, 'w', encoding='utf-8') as f:
				json.dump(record, f)
			os.chmod(temp, 0o644)
			os.replace(temp, os.path.join(self.state_dir, name))
			temp = None
		except (OSError, ValueError, TypeError) as e:
			if not self._failed:
				self._failed = True
				tl.teeerror(f'Cannot write status files in {self.state_dir}: {e}')
		finally:
			if temp is not None:
				with contextlib.suppress(OSError):
					os.remove(temp)

STATUS_BOARD = None

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
# the exit status when every job is stopped, or the rule file is missing or holds no job: only a rule or skip list fix
# helps, so systemd is told not to restart
EXIT_ALL_STOPPED = 3
# the exit statuses of the status, history and restore commands: what was asked could not be done, or was asked wrongly
EXIT_COMMAND_FAILED = 1
EXIT_USAGE = 2

def env_seconds(name:str, default:float) -> float:
	'''Seconds from the environment variable name. Missing, unparsable, not above 0 or infinite → default.'''
	try:
		value = float(os.environ[name])
	except (KeyError, ValueError):
		return default
	return value if 0 < value < float('inf') else default

def apply_job_timing_from_env():
	'''
	Set the job retry timing from REVERB_JOB_RETRY_FIRST_SECONDS and REVERB_JOB_RETRY_MAX_SECONDS, and the disk wait's
	grace period before its first alert from REVERB_DISK_WAIT_GRACE_SECONDS. Invalid/missing → the defaults.
	'''
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

def wait_for_path(job:JobControl, flag:threading.Event, path:str, what:str, clock = time.monotonic, alert:bool = True) -> bool:
	'''
	Wait until flag is set and path is a directory. Returns False when the job (with job None, GREEN_LIGHT) says stop.
	Logs nothing for DISK_WAIT_GRACE_SECONDS, then an alert, repeated every DISK_WAIT_REPEAT_SECONDS; with alert False,
	never, for a wait another thread of the job alerts for.
	'''
	running = GREEN_LIGHT.is_set if job is None else job.should_run
	started = clock()
	next_alert = started + DISK_WAIT_GRACE_SECONDS
	token = None
	try:
		while running():
			if flag.is_set() and os.path.isdir(path):
				return True
			if token is None and job is not None:
				token = job.begin_wait(path, what)
			if flag.is_set():
				# the filesystem is ready but the path is not there yet, so the flag cannot end the wait
				time.sleep(POLL_WAIT_SECONDS)
			else:
				flag.wait(POLL_WAIT_SECONDS)
			now = clock()
			if now >= next_alert and job is not None and alert:
				waited = now - started
				job_log(job.job_name, f'FAILED: waiting {int(waited // 60)} min for {path}: {what}')
				next_alert = now + DISK_WAIT_REPEAT_SECONDS
		return False
	finally:
		if token is not None:
			job.end_wait(token)

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
# vault folders known to be real, kept so the many links through one folder look at it once
REAL_VAULT_FOLDERS_KEPT = 16384
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
		job.set_state('starting')
		started = clock()
		try:
			threads = start_attempt(job, attempt)
		except Exception as e:
			# starting the attempt failed: it counts as that attempt's failure, with no thread to join
			threads = []
			if isinstance(e, JobFailure):
				job.fail(e.reason, e.permanent)
			else:
				job.fail(f'{type(e).__name__}: {e}')
		if job.failure is None:
			job.set_state('running')
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
			job.set_state('stopped', failure.reason, failures=failures)
			return 'stopped'
		failures = 1 if ran >= JOB_RETRY_RESET_SECONDS else failures + 1
		delay = job_retry_delay(failures)
		job_log(job.job_name, f'FAILED: {failure.reason}; retrying in {int(delay)}s')
		job.set_state('retrying', failure.reason, time.time() + delay, failures)
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
		signature = None
		started = time.monotonic()
		next_alert = started + DISK_WAIT_GRACE_SECONDS
		# a lookup runs df and lsblk: at once when the path is there, then again every FS_RECHECK_SECONDS while it is
		looked_up_at = None
		token = None
		try:
			while job.should_run():
				present = os.path.isdir(self.path)
				if not present:
					looked_up_at = None
				elif looked_up_at is None or time.monotonic() - looked_up_at >= FS_RECHECK_SECONDS:
					looked_up_at = time.monotonic()
					signatures = get_fs_signatures(self.path)
					if signatures and signatures[0]:
						signature = signatures[0]
						break
				what = 'monitored filesystem signature unknown' if present else 'monitored path not there yet'
				if token is None:
					token = job.begin_wait(self.path, what)
				# job.running stays set while the job runs, so waiting on it would not wait at all
				time.sleep(POLL_WAIT_SECONDS)
				now = time.monotonic()
				if now >= next_alert:
					job_log(job.job_name, f'FAILED: waiting {int((now - started) // 60)} min for {self.path}: {what}')
					next_alert = now + DISK_WAIT_REPEAT_SECONDS
		finally:
			if token is not None:
				job.end_wait(token)
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
	global GREEN_LIGHT
	try:
		results[index] = run_job(job, start_attempt, persist_pending=persist_pending)
	except Exception as e:
		import traceback
		tl.teeerror(traceback.format_exc())
		daemon_error_log(f'supervisor of job {job.job_name} crashed: {type(e).__name__}: {e}')
		results[index] = 'crashed'
		# the other jobs stop cleanly and save their pending transactions; main exits 1
		GREEN_LIGHT.clear()

COMMANDS = ('status', 'history', 'restore')

def main(argv:list = None):
	'''The console entry point: runs a command when argv starts with one, else the daemon, and exits 1 with a marker line when it fails.'''
	argv = sys.argv[1:] if argv is None else argv
	if argv and argv[0] in COMMANDS:
		sys.exit(run_command(argv))
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
	global STATUS_BOARD
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
	try:
		STATUS_BOARD = StatusBoard(state_dir_path(), os.path.abspath(args.rule_path))
	except Exception as e:
		tl.teeerror(f'Cannot publish status files: {e}')
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
		sys.exit(EXIT_ALL_STOPPED)
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
	if 'crashed' in results:
		raise RuntimeError(f'a job supervisor crashed: {results}')
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

def parse_rules(rule_file:str, read_only:bool = False):
	'''
	Parse the rule file using TSVZ and fill in the defaults and auto fields

	Args:
		rule_file (str): The rule file
		read_only (bool): For the commands: change nothing on disk, so no header upgrade, no vault folder made, no
			signature looked up (those cells stay as written) and nothing written back, and a missing or empty
			rule file raises RuleFileError rather than ending the process

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
		if read_only:
			raise RuleFileError(f'Rule file {rule_file} does not exist.')
		tl.teeerror(f'Error: Rule file {rule_file} does not exist.')
		daemon_error_log(f'rule file {rule_file} does not exist')
		sys.exit(EXIT_ALL_STOPPED)
	try:
		if read_only:
			pass
		elif upgrade_rule_file_header(rule_file):
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
		if read_only:
			raise RuleFileError(f'Rule file {rule_file} has no rules.')
		tl.teeerror(f'Error: Rule file {rule_file} appears empty after parsing.')
		daemon_error_log(f'rule file {rule_file} has no rules')
		sys.exit(EXIT_ALL_STOPPED)
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
		if not mon_path_exists or read_only:
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
		if read_only:
			pass
		elif not inRule["vault_fs_signature"] or inRule["vault_fs_signature"].lower() == 'auto':
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
	if rulesToUpdate and not read_only:
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
	root_lost = False
	while running():
		# at the start the backuper waits for the same filesystem and alerts for both; once the root was lost only this waits
		if not wait_for_path(job, monitor_fs_flag, monitor_path, 'monitored filesystem not ready', alert=root_lost):
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
		result = watchFolder(monitor_path=monitor_path,to_process=to_process,to_process_lock=to_process_lock,to_process_flag=to_process_flag,irm=irm,min_snapshot_delay_seconds=min_snapshot_delay_seconds,max_shapshot_delay_seconds=max_shapshot_delay_seconds,skip_list=skip_list,watching=watching,job=job,root_returned=root_lost)
		if result == WATCH_RESULT_INIT_FAILED or result is False:
			if job is None:
				watcherTeeLogToTl(monitor_path,f'Watch init/loop failed for {monitor_path}; requesting shutdown',error=True)
				GREEN_LIGHT.clear()
			else:
				watcherTeeLogToTl(monitor_path,f'Watch init/loop failed for {monitor_path}',error=True)
				job.fail(f'watching {monitor_path} failed')
			return False
		# the self_destruct event queued for it changes nothing in the vault: the next watch of the root compares it
		root_lost = result == WATCH_RESULT_SELF_DESTRUCT
		if result == WATCH_RESULT_SELF_DESTRUCT:
			watcherTeeLogToTl(monitor_path,f'Watch root disappeared for {monitor_path}; waiting for filesystem recovery',error=True)
			if monitor_signature is not None:
				# the flag stays set until the monitor sees the mount table change, which would let the wait pass at once
				FS_SIGNATURE_MONITOR.invalidate(monitor_path, monitor_signature)

def watchFolder(monitor_path:str,to_process:ChangeEventQueue,to_process_lock:threading.Lock,to_process_flag:threading.Event,irm:inotify_resource_manager,discard_new_recursive_folder_events_until_read:bool = True,min_snapshot_delay_seconds:int=DEFAULT_SNAPSHOT_DELAY,max_shapshot_delay_seconds:int=DEFAULT_MAX_DELAY,skip_list:'SkipList' = None,watching:threading.Event = None,job:JobControl = None,root_returned:bool = False):
	global COOKIE_DICT_MAX_SIZE
	global DEBUG
	global GREEN_LIGHT
	flags = inotify_simple.flags
	watch_flags = flags.MODIFY | flags.ATTRIB | flags.MOVED_FROM | flags.MOVED_TO | flags.CREATE | flags.DELETE | flags.DELETE_SELF | flags.MOVE_SELF | flags.UNMOUNT | flags.Q_OVERFLOW
	selfDestructMask = flags.UNMOUNT | flags.DELETE_SELF | flags.MOVE_SELF
	cookieDic = OrderedDict()
	wdDic = bidict()
	pendingMoveFromEvents = OrderedDict()
	# the same move-outs by normalized path (path -> {cookie: None}, oldest first), so a create finds those at its path
	# without going through all of them. a path can have more than one: a folder renamed in brings another entry there
	pendingMoveFromPaths = {}
	def add_pending_move_from(cookie,change_event:ChangeEvent):
		pop_pending_move_from(cookie)
		pendingMoveFromEvents[cookie] = change_event
		pendingMoveFromPaths.setdefault(change_event.path.rstrip('/'),{})[cookie] = None
	def pop_pending_move_from(cookie) -> ChangeEvent:
		change_event = pendingMoveFromEvents.pop(cookie,None)
		if change_event is not None:
			path_norm = change_event.path.rstrip('/')
			cookies = pendingMoveFromPaths.get(path_norm)
			if cookies is not None:
				cookies.pop(cookie,None)
				if not cookies:
					del pendingMoveFromPaths[path_norm]
		return change_event
	def queue_pending_move_from_at(path:str,monTime:float):
		# something new is at the path a folder or file moved away from: that move was not a deletion that can wait,
		# or the delete it expires into would land after this create and remove what is there
		for cookie in list(pendingMoveFromPaths.get(path.rstrip('/'),())):
			cookie_value = cookieDic.pop(cookie,None)
			if cookie_value is not None and cookie_value.wds:
				remove_moved_away_watches(inotify_obj,wdDic,irm,cookie_value.path,cookie_value.wds,watch_flags)
			append_change_event(to_process, to_process_lock, pop_pending_move_from(cookie))
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
		if root_returned:
			# the root came back after it was lost (remounted, or deleted and made again): nothing tells what changed in
			# it meanwhile, so the backuper compares the whole tree with the vault, now that its changes are watched
			append_change_event(to_process, to_process_lock, ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
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
				append_change_event(to_process, to_process_lock, pop_pending_move_from(cookie))
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
						if wdDic.pop(event.wd, None) is not None:
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
						elif DEBUG:
							# follow_inner_mounts already removed it, with every other watch of the disk: one line per folder
							watcherTeeLogToTl(monitor_path,f'Sub dir unmount event detected, but watch not in wdDic found for {event.wd}')
						continue
					elif event.mask & flags.MOVE_SELF:
						watcherTeeLogToTl(monitor_path,'Sub dir move self event detected, skipping')
						continue
				if not event.name:
					if event.mask & flags.IGNORED:
						# the kernel dropped a watch, as ours do when we remove one or its folder is deleted
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Watch {event.wd} ignored by the kernel')
						continue
					watcherTeeLogToTl(monitor_path,'Event name not found, ignoring event')
					continue
				if event.wd not in wdDic:
					watcherTeeLogToTl(monitor_path,f'Watch descriptor {event.wd} not found, ignoring event')
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
					queue_pending_move_from_at(eventPath,monTime)
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
						pop_pending_move_from(evicted_cookie)
						if DEBUG:
							watcherTeeLogToTl(monitor_path,f'Adding delete event for {cookie_value.path}')
						if cookie_value.wds:
							remove_moved_away_watches(inotify_obj,wdDic,irm,cookie_value.path,cookie_value.wds,watch_flags)
						append_change_event(to_process, to_process_lock, ChangeEvent(monTime,cookie_value.isDir,'delete',cookie_value.path,None))
					#append_change_event(to_process, to_process_lock, ChangeEvent(monTime,isDir,'move',eventPath,None))
					add_pending_move_from(event.cookie,ChangeEvent(monTime,isDir,'delete',eventPath,None))
				elif event.mask & flags.MOVED_TO:
					if DEBUG:
						watcherTeeLogToTl(monitor_path,f'Move to event detected for {eventPath}')
					if skipped:
						# the destination is not backed up: a known source is gone from the backup, otherwise there is nothing to record
						if event.cookie in cookieDic:
							cookie_value = cookieDic.pop(event.cookie)
							pop_pending_move_from(event.cookie)
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
						pop_pending_move_from(event.cookie)
						# what moved away from the destination is gone before the move lands on its name, or its late
						# delete would remove the moved-in entry
						queue_pending_move_from_at(eventPath,monTime)
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
						queue_pending_move_from_at(eventPath,monTime)
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

def raise_queue_limit_for_removals(irm:inotify_resource_manager,count:int):
	'''Removing a watch queues an IN_IGNORED event: make room first when count of them would fill half the queue.'''
	if count > irm.max_queued_events / 2:
		irm.increaseInotifyMaxQueueEvents(max(irm.max_queued_events * 2, count * 2))

def remove_watches_under(inotify_obj:inotify_simple.INotify,wdDic:bidict,irm:inotify_resource_manager,folder_path:str) -> int:
	'''Remove the watch on folder_path and every watch below it; returns how many were removed.'''
	folder_norm = folder_path.rstrip('/')
	prefix = folder_norm + '/'
	removed = 0
	raise_queue_limit_for_removals(irm,len(watches_under(wdDic,folder_path)))
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
	raise_queue_limit_for_removals(irm,len(wds))
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
		try:
			is_file_mount = not stat.S_ISDIR(os.lstat(mount_point).st_mode)
		except OSError:
			# a disk that does not answer stays followed: it is paused, not unmounted
			is_file_mount = False
		if is_file_mount:
			# a file bind mount: no folder to watch or compare
			continue
		if skip_list is not None and skips_folder_or_parent(skip_list.skips, rel + '/'):
			continue
		mounts[os.path.join(monitor_path, rel)] = mount_fingerprint(mount_table, mount_point)
	return mounts

def skips_folder_or_parent(skip, rel:str) -> bool:
	'''
	Whether skip(rel) leaves out the folder rel (ending with /) or a folder it is in: skip checks an entry alone.

	Examples:
		>>> skips_folder_or_parent(lambda rel: rel == 'a/', 'a/b/c/')
		True
		>>> skips_folder_or_parent(lambda rel: rel == 'a/', 'ab/')
		False
		>>> skips_folder_or_parent(None, 'a/')
		False
	'''
	if skip is None:
		return False
	parts = rel.rstrip('/').split('/')
	return any(skip('/'.join(parts[:depth]) + '/') for depth in range(1, len(parts) + 1))

def inner_mount_rels(mount_table:list, monitor_path:str, skip = None) -> set:
	'''
	The inner mount points in mount_table, as folder rels of monitor_path, but those skip leaves out or that are in a
	folder it leaves out.

	Examples:
		>>> table = [('/', ('1',)), ('/tmp/reverb_doctest/m/disk', ('2',)), ('/tmp/reverb_doctest/m/a/usb', ('3',))]
		>>> sorted(inner_mount_rels(table, '/tmp/reverb_doctest/m'))
		['a/usb/', 'disk/']
		>>> sorted(inner_mount_rels(table, '/tmp/reverb_doctest/m', lambda rel: rel == 'a/'))
		['disk/']
	'''
	real_root = os.path.realpath(monitor_path)
	rels = {os.path.relpath(mount_point, real_root) + '/' for mount_point in inner_mount_points(mount_table, monitor_path)}
	return {rel for rel in rels if not skips_folder_or_parent(skip, rel)}

def paused_inner_mounts(monitor_path:str, remembered:list, mount_table:list, skip = None) -> set:
	'''
	The remembered inner mount points (folder rels of monitor_path) that are paused: not mounted in mount_table, with
	their folder there and empty, as an unmounted disk leaves it, or a folder that cannot be looked at. Walks leave a
	paused folder out and keep what the vault holds for it. A folder that is gone, is not a folder, or holds entries of
	its own is not paused: it is backed up as what it now is, which is how a user retires an inner disk. Neither is one
	that skip (a skip list's skips) leaves out, or that is in a folder it leaves out.
	'''
	mounted = inner_mount_rels(mount_table, monitor_path)
	paused = set()
	for rel in remembered:
		if rel in mounted or skips_folder_or_parent(skip, rel):
			continue
		folder = os.path.join(monitor_path, rel.rstrip('/'))
		try:
			if not stat.S_ISDIR(os.lstat(folder).st_mode):
				continue
			with os.scandir(folder) as entries:
				if next(entries, None) is None:
					paused.add(rel)
		except (FileNotFoundError, NotADirectoryError):
			continue
		except OSError:
			# whether its disk is back cannot be told: it stays paused, and remembered, until it can
			paused.add(rel)
	return paused

def inner_mounts_to_remember(monitor_path:str, remembered:list, paused:set, *mount_tables, skip = None) -> list:
	'''
	The inner mount points a backup records with its committed state: those mounted in any of mount_tables, the paused
	ones, and the remembered ones inside a paused folder, which went away with its disk. Nothing is forgotten when no
	table could be read. Those skip leaves out, or that are in a folder it leaves out, are not recorded.

	Examples:
		>>> table = [('/', ('1',)), ('/tmp/reverb_doctest/m/new', ('2',))]
		>>> inner_mounts_to_remember('/tmp/reverb_doctest/m', ['old/', 'old/inner/', 'retired/'], {'old/'}, table, [])
		['new/', 'old/', 'old/inner/']
		>>> inner_mounts_to_remember('/tmp/reverb_doctest/m', ['retired/'], set(), [])
		['retired/']
		>>> inner_mounts_to_remember('/tmp/reverb_doctest/m', ['old/', 'old/inner/'], {'old/'}, table, skip=lambda rel: rel in ('new/', 'old/inner/'))
		['old/']
	'''
	tables = [table for table in mount_tables if table]
	if not tables:
		return sorted(rel for rel in remembered if not skips_folder_or_parent(skip, rel))
	kept = set(paused)
	for table in tables:
		kept |= inner_mount_rels(table, monitor_path, skip)
	kept.update(rel for rel in remembered if any(rel.startswith(folder) for folder in paused))
	return sorted(rel for rel in kept if not skips_folder_or_parent(skip, rel))

def skip_paused(skip, paused:set):
	'''
	A walk's skip predicate (or None) that also leaves out the paused folders.

	Examples:
		>>> skip = skip_paused(lambda rel: rel == 'cache/', {'disk/'})
		>>> [skip(rel) for rel in ('disk/', 'cache/', 'disk', 'other/')]
		[True, True, False, False]
		>>> skip_paused(None, set()) is None
		True
	'''
	if not paused:
		return skip
	if skip is None:
		return lambda rel: rel in paused
	return lambda rel: rel in paused or skip(rel)

def check_monitored_mount(monitor_path:str, mount_table:list, root_mount) -> None:
	'''
	Raise JobFailure when the mount holding monitor_path is no longer root_mount (not checked when None): another
	filesystem shown there, compared with the vault, would read as its entries deleted.

	Examples:
		>>> check_monitored_mount('/tmp/reverb_doctest/m', [('/', ('1',))], ('1',))
		>>> try:
		...     check_monitored_mount('/tmp/reverb_doctest/m', [('/', ('1',)), ('/tmp/reverb_doctest/m', ('2',))], ('1',))
		... except JobFailure as e:
		...     print(e.reason)
		the monitored filesystem changed under /tmp/reverb_doctest/m
	'''
	if root_mount is not None and mount_fingerprint(mount_table, os.path.realpath(monitor_path)) != root_mount:
		raise JobFailure(f'the monitored filesystem changed under {monitor_path}')

def scan_scopes(monitor_path:str, folders) -> list:
	'''
	The folder rels of monitor_path that scan events naming folders ask to compare, outer folders absorbing the folders
	inside them; [''] when one names monitor_path itself. A folder outside monitor_path is left out.

	Examples:
		>>> scan_scopes('/m', ['/m/a/b', '/m/c', '/m/a', '/m/a/b/', '/m/a b', '/elsewhere'])
		['a b/', 'a/', 'c/']
		>>> scan_scopes('/m/', ['/m/x', '/m'])
		['']
		>>> scan_scopes('/m', [])
		[]
	'''
	root = os.path.abspath(monitor_path)
	prefix = root.rstrip('/') + '/'
	rels = set()
	for folder in folders:
		path = os.path.abspath(folder)
		if path == root:
			return ['']
		if path.startswith(prefix):
			rels.add(path[len(prefix):] + '/')
	scopes = []
	# sorted, a folder comes right before the folders inside it
	for rel in sorted(rels):
		if not scopes or not rel.startswith(scopes[-1]):
			scopes.append(rel)
	return scopes

def drop_entries_under(backup_entries:dict, folder_paths:list) -> int:
	'''
	Drop the backup entries at or under any of folder_paths (absolute, ending with /), whose vault entries a comparison
	of that folder, or its pause, decides instead; returns how many went. A move out of such a folder copies its
	destination instead, as the vault entry it would take stays the folder's, and a move into one deletes its source.

	Examples:
		>>> entries = OrderedDict((path, BackupEntryValues('t', event, source)) for path, event, source in [
		...     ('/m/d/', 'attrib', None), ('/m/d/f', 'modify', None), ('/m/d', 'create', None), ('/m/dx', 'modify', None),
		...     ('/m/out/', 'move', '/m/d/sub/'), ('/m/d/in', 'move', '/m/src'), ('/m/e/in', 'move', '/m/d/x')])
		>>> drop_entries_under(entries, ['/m/d/', '/m/e/'])
		5
		>>> [(path, values.event) for path, values in entries.items()]
		[('/m/dx', 'modify'), ('/m/out/', 'create'), ('/m/src', 'delete')]
	'''
	def under(path):
		return any(path == folder[:-1] or path.startswith(folder) for folder in folder_paths)
	dropped = [path for path in backup_entries if under(path)]
	for path, values in list(backup_entries.items()):
		if values.event == 'move' and not under(path) and under(values.source_path):
			backup_entries[path] = BackupEntryValues(values.iso_time, 'create', None)
	for path in dropped:
		values = backup_entries.pop(path)
		if values.event == 'move' and not under(values.source_path):
			backup_entries.setdefault(values.source_path, BackupEntryValues(values.iso_time, 'delete', None))
	return len(dropped)

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
				recheck_failed = time.monotonic() >= recheck_at
				try:
					self.check_changed(recheck_failed=recheck_failed)
				except Exception:
					import traceback
					watcherTeeLogToTl(self.mountinfo_path, traceback.format_exc(), error=True)
				# a pair that failed is re-checked every FS_RECHECK_SECONDS: a deleted and re-created path changes no mount.
				# counted from the pass that re-checked them, so mount table changes coming more often cannot put it off
				if recheck_failed:
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
def compare_scanned_folders(backup_entries:dict,scan_folders:list,job_name:str,monitor_path:str,vault_path:str,vaultInfo:VaultInfo = None,
			 manifest:'VaultManifest' = None,skip_list:'SkipList' = None,root_mount = None,reported:set = None) -> tuple:
	'''
	Fold a batch's scan events (scan_folders, the folders they name) into its backup_entries: each scanned folder is
	compared with the latest version, and what that finds replaces the batch's entries at or under it. A folder inside
	another scanned one is compared with it, and one in a paused inner mount compares nothing.
	Returns (vaultInfo, manifest, full_comparison): full_comparison asks for the whole tree instead, for a scan of the
	monitored path itself or a vault with no version yet. JobFailure is raised, before anything is compared, when the
	monitored path no longer shows the filesystem root_mount fingerprints. reported holds the unreadable paths this batch
	already logged.
	'''
	scopes = scan_scopes(monitor_path,scan_folders)
	if scopes == ['']:
		return vaultInfo, manifest, True
	if not scopes:
		return vaultInfo, manifest, False
	mount_table = current_mount_table()
	check_monitored_mount(monitor_path,mount_table,root_mount)
	job_vault = os.path.join(vault_path,job_name)
	if not vaultInfo or not vaultInfo.vault_info_dict:
		vaultInfo = get_vault_info(job_vault_path=job_vault)
	if not vaultInfo.vault_info_dict:
		# nothing to compare with: the first backup copies the whole tree
		return vaultInfo, manifest, True
	# a manifest opened here is closed here if the comparison raises, as the caller never gets it back
	opened_manifest = manifest is None
	if opened_manifest:
		manifest = VaultManifest(job_vault)
	try:
		latest_version_info = vaultInfo.vault_info_dict[next(reversed(vaultInfo.vault_info_dict))]
		paused = paused_inner_mounts(monitor_path,manifest.inner_mounts,mount_table,None if skip_list is None else skip_list.skips)
		backuperTeeLogToTl(job_name,f'Comparing {", ".join(scopes)} with the vault')
		drop_entries_under(backup_entries,[os.path.abspath(os.path.join(monitor_path,rel)) + '/' for rel in scopes])
		if reported is None:
			reported = set()
		for scope_rel in scopes:
			if not GREEN_LIGHT.is_set():
				break
			found = OrderedDict()
			delta_generate_backup_entries(found,latest_version_info,monitor_path,manifest=manifest,skip_list=skip_list,job_name=job_name,
				reported=reported,scope_rel=scope_rel,paused=paused)
			backup_entries.update(found)
	except BaseException:
		if opened_manifest:
			manifest.close()
		raise
	return vaultInfo, manifest, False

def scan_events(scan_folders:list) -> list:
	'''The scan events naming scan_folders, to hand a batch that did not commit back to the queue.'''
	base = time.monotonic()
	return [ChangeEvent(base + (i * 0.001),True,'scan',folder,None) for i, folder in enumerate(scan_folders)]

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
	# the folders its scan events name, compared with the vault before it is backed up
	scan_folders = []
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
		# batches are compared with the vault only while the monitored path shows the filesystem it shows now
		root_mount = mount_fingerprint(current_mount_table(),os.path.realpath(monitor_path))
		if startup is not None and running():
			# the list is read now that both filesystems are ready, so one on a disk that mounts late still loads
			job_vault = os.path.join(vault_path,job_name)
			recorded = None
			if os.path.isdir(job_vault):
				manifest = VaultManifest(job_vault)
				recorded = manifest.skip_fingerprint
			trusted = True
			if manifest is not None:
				# a manifest that does not describe the latest version cannot vouch for the fingerprint it recorded
				latest_version = get_vault_info(job_vault).vault_info_dict
				trusted = not latest_version or manifest.describes(latest_version[next(reversed(latest_version))].path)
			if not startup.load(recorded,trusted):
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
		if not running():
			# stopping: the restored events stay queued for the pending transactions
			return
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
				scan_folders = [event.path for event in to_process_temp if event.event == 'scan']
				backuperTeeLogToTl(job_name, f'Converted events queued at startup into {len(backupEntries)} backup entries and {len(scan_folders)} folders to compare')
		vaultInfo = None
		# to_process: ChangeEventQueue of ChangeEvent(monotonic_time, is_dir, event, path, moved_from), oldest first
		while running():
			wait_for_path(job, vault_fs_flag, vault_path, 'vault filesystem not ready')
			if not running():
				break
			# an unreadable path is reported once for the batch, by its comparison or its backup
			reported = set()
			if scan_folders and not full_comparison:
				vaultInfo,manifest,full_comparison = compare_scanned_folders(backupEntries,scan_folders,job_name,monitor_path,vault_path,
					vaultInfo=vaultInfo,manifest=manifest,skip_list=skip_list,root_mount=root_mount,reported=reported)
				if not running():
					break
				if full_comparison:
					backupEntries.clear()
				elif not backupEntries:
					backuperTeeLogToTl(job_name,'Compared folders match the vault; no new version for this batch',ok=True)
					# done, as a full comparison finding no differences is
					if job is not None:
						job.mark_committed()
			else:
				# do_backup compares the whole tree for an empty batch
				full_comparison = full_comparison or not backupEntries
			if backupEntries or full_comparison:
				vaultInfo,manifest,committed = do_backup(backupEntries,job_name=job_name,monitor_path=monitor_path,vault_path=vault_path,
					  keep_one_complete_backup=keep_one_complete_backup,only_sync_attributes=only_sync_attributes, keep_n_versions=keep_n_versions, 
					  backup_size_limit=backup_size_limit, log_journal=log_journal,vaultInfo=vaultInfo,manifest=manifest,skip_list=skip_list,root_mount=root_mount,
					  reported=reported)
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
				if job is not None:
					job.mark_committed()
			backupEntries.clear()
			scan_folders = []
			full_comparison = False
			while not backupEntries and not full_comparison and not scan_folders and running():
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
					scan_folders = [event.path for event in to_process_temp if event.event == 'scan']
					backuperTeeLogToTl(job_name,f'Converted {len(to_process_temp)} events to {len(backupEntries)} backup entries and {len(scan_folders)} folders to compare')
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
		if full_comparison or backupEntries or scan_folders:
			# for the job's next attempt, or the pending transactions when the daemon stops. the scans go back too, so
			# their folders are compared again with what is there then
			with to_process_lock:
				if full_comparison:
					to_process.append(ChangeEvent(time.monotonic(),False,'full_scan',monitor_path,None))
				else:
					to_process.prepend(backup_entries_to_change_events(backupEntries) + scan_events(scan_folders))
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
		# Tee_Logger before 6.42 has no teewarning or teedebug
		getattr(tl,'teewarning',tl.teeprint)(message,callerStackDepth=4)
	elif debug:
		if DEBUG:
			getattr(tl,'teedebug',tl.teeprint)(message,callerStackDepth=4)
		else:
			tl.info(message,callerStackDepth=4)
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
			 vaultInfo:VaultInfo = None,manifest:'VaultManifest' = None,skip_list:'SkipList' = None,root_mount = None,reported:set = None):
	# returns (vaultInfo, manifest, committed): pass both back in for the next backup of this job
	# root_mount: the fingerprint of the mount the monitored path showed when the job started, when it is to be checked
	# reported: the unreadable paths already logged for this batch, so each is logged once
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
	if reported is None:
		reported = set()
	opened_manifest = manifest is None
	if opened_manifest:
		manifest = VaultManifest(job_vault)
	try:
		# inner mounts the backup has seen and that are unmounted now are paused: every walk below leaves them out, and
		# they keep what the vault holds for them
		mount_table = current_mount_table()
		check_monitored_mount(monitor_path,mount_table,root_mount)
		remembered_mounts = manifest.inner_mounts
		paused = paused_inner_mounts(monitor_path,remembered_mounts,mount_table,skip)
		if paused:
			backuperTeeLogToTl(job_name,f'Inner mounts not mounted, keeping their last backed-up contents: {", ".join(sorted(paused))}')
		walk_skip = skip_paused(skip,paused)
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
					for monitorEntry, relativePath, isDir in iter_tree_entries(monitor_path,skip=walk_skip,errors=walk_errors):
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
					# however the backup ends, no copy is left writing into this version. a copy finish_copies did not reach
					# means this V0 is not committed: the whole folder is removed as an orphan ( on the next attempt, or at
					# startup after a stop ), so unlinking each partial file of a large tree first would only hold up the stop
					stop_copies(mcae,pending,backup_folder,discard=False)
				mcae.cleanup(timeout=POLL_WAIT_SECONDS)
				check_walk_errors(job_name,monitor_path,walk_errors,manifest,reported)
				record_dirty_entries(manifest,backup_folder,monitor_path)
			else:
				backuperTeeLogToTl(job_name,f'Creating a referenced backup of {monitor_path} to {backup_folder}',ok=True)
				if log_journal:
					TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),'initial_referenced_backup',backup_folder],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
				walk_errors = []
				manifest.rebuild(backup_folder,tree_path=monitor_path,skip=walk_skip,errors=walk_errors)
				check_walk_errors(job_name,monitor_path,walk_errors,manifest,reported)
				do_referenced_copy(monitor_path,backup_folder,manifest)
		else:
			# Now we have made sure the vault is within the size limit, we can proceed to do the backup
			latest_version_info = vault_info_dict[next(reversed(vault_info_dict))]
			if not backup_entries:
				backuperTeeLogToTl(job_name,'Empty backup entries, Delta generating backup entries')
				delta_generate_backup_entries(backupEntries=backup_entries,latest_version_info=latest_version_info,monitor_path=monitor_path,manifest=manifest,skip_list=skip_list,job_name=job_name,reported=reported,paused=paused)
				if not GREEN_LIGHT.is_set():
					# a partial delta would be kept as pending transactions, and a restart replays those instead of comparing again
					backup_entries.clear()
					backuperTeeLogToTl(job_name, 'Delta generation interrupted; not creating a new version', error=True)
					return VaultInfo(vault_info_dict, vault_size, vault_inodes), manifest, False
				# a disk unmounted while the walk ran was walked as the empty folder it left: what the walk found under it is
				# dropped, so its rows are linked forward as for a disk paused before the walk. the same goes for the root
				walked_table = current_mount_table()
				check_monitored_mount(monitor_path,walked_table,root_mount)
				seen_mounts = sorted(set(remembered_mounts) | inner_mount_rels(mount_table,monitor_path,skip))
				unmounted = paused_inner_mounts(monitor_path,seen_mounts,walked_table,skip) - paused
				if unmounted:
					dropped = drop_entries_under(backup_entries,[os.path.abspath(os.path.join(monitor_path,rel)) + '/' for rel in unmounted])
					backuperTeeLogToTl(job_name,f'Inner mounts unmounted during the comparison, keeping their last backed-up contents: {", ".join(sorted(unmounted))}; dropped {dropped} backup entries')
					paused = paused | unmounted
				if log_journal:
					TSVZ.appendTabularFile(journalPath,[monitor_path,datetime.datetime.now().isoformat(),f'delta_generated_{len(backup_entries)}_differences',monitor_path],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)
					log_events_to_journal(backup_entries,journalPath)
			elif paused:
				# what the watcher saw in a paused folder before its disk went is compared when the disk is back
				dropped = drop_entries_under(backup_entries,[os.path.abspath(os.path.join(monitor_path,rel)) + '/' for rel in paused])
				if dropped:
					backuperTeeLogToTl(job_name,f'Dropped {dropped} backup entries in unmounted inner mounts')
					if not backup_entries:
						backuperTeeLogToTl(job_name,'No backup entries left outside unmounted inner mounts',ok=True)
			if not backup_entries:
				backuperTeeLogToTl(job_name, 'No differences after delta; skipping new version', ok=True)
				# no differences after a complete walk, or none left outside paused folders: the tree matches the
				# manifest under this skip list
				manifest.begin()
				manifest.set_skip_fingerprint(skip_list.fingerprint if skip_list is not None else '')
				manifest.set_inner_mounts(inner_mounts_to_remember(monitor_path,remembered_mounts,paused,mount_table,current_mount_table(),skip=skip))
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
					removed_size, removed_inodes = prune_oldest(vault_info_dict,job_name)
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			if backup_limit_inode:
				while vault_inodes + estimated_backup_inode > backup_limit_inode:
					backuperTeeLogToTl(job_name,f'Vault inodes {vault_inodes} + estimated backup inodes {estimated_backup_inode} exceeds backup inode limit {backup_limit_inode}')
					# we need to remove the oldest version
					removed_size, removed_inodes = prune_oldest(vault_info_dict,job_name)
					vault_size -= removed_size
					vault_inodes -= removed_inodes
					if not removed_size and not removed_inodes:
						break
			while keep_n_versions and len(vault_info_dict) >= keep_n_versions:
				backuperTeeLogToTl(job_name,f'Vault has {len(vault_info_dict)} versions, exceeding keep n versions {keep_n_versions}')
				# we need to remove the oldest version
				removed_size, removed_inodes = prune_oldest(vault_info_dict,job_name)
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
		# a disk mounted while this backup walked is remembered too
		manifest.set_inner_mounts(inner_mounts_to_remember(monitor_path,remembered_mounts,paused,mount_table,current_mount_table(),skip=skip))
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

def stop_copies(mcae:multiCMD.AsyncExecutor, pending:list, version_path:str, discard:bool = True):
	'''
	Stop what still runs on mcae, then discard the copies of pending, which will not be finished.

	Running commands are killed and waited for, as a retry removes the uncommitted version_path they write into: for
	COPY_STOP_WAIT_SECONDS at most, COPY_STOP_GRACE_SECONDS once the daemon is stopping. The ones still running then are
	named in an error line and left to finish on their own.
	With discard False, pending is only emptied: for a version_path that is never committed now, whose partial files go
	with it when it is removed.
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
	if discard:
		discard_copies(pending)
	else:
		pending.clear()

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

	@property
	def inner_mounts(self) -> list:
		'''The inner mount points (folder rels ending with /) recorded with the last committed state, [] when never recorded.'''
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'inner_mounts'").fetchone()
		return [] if row is None else json.loads(row[0])

	def set_inner_mounts(self, rels:list):
		'''Record the inner mount points (folder rels ending with /); the caller holds the transaction.'''
		self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('inner_mounts', ?)", (json.dumps(list(rels)),))

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
		A move to another folder depth re-targets the links it carries (see retarget_moved_links); the moved rows stay
		unverified, so the next comparison reads them once.
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

	def unseen_under(self, folder:str) -> list:
		'''Tracked paths at or under folder (which ends with /) not marked seen since clear_seen().'''
		return [rel for (rel,) in self.conn.execute('SELECT path FROM entries WHERE path >= ? AND path < ? AND path NOT IN (SELECT path FROM temp.seen) ORDER BY path',
			(folder, folder_range_end(folder)))]

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
	try:
		return int(match.group(1)) if match else None
	except ValueError:
		# more digits than int() reads from a string: a link's text, never a version folder
		return None

# chain links name few versions, so each name is parsed once for all the links naming it
@functools.lru_cache(maxsize=1024)
def is_version_folder_name(name:str) -> bool:
	'''
	Whether name is a whole version folder name: V<n>-- and the timestamp the version was made at.

	Examples:
		>>> [is_version_folder_name(name) for name in ('V3--2021-01-01_00-00-00_-0800', 'V3--2021', 'current_version',
		...     'V3--2021-01-01_00-00-00_-0800--1.00_KiB-1_ino.modified_contents.nsv')]
		[True, False, False, False]
	'''
	if vault_version_number(name) is None:
		return False
	try:
		datetime.datetime.strptime(name.partition('--')[2], VAULT_TIMESTAMP_FORMAT)
	except ValueError:
		return False
	return True

# (version folder, folder) pairs found real: the folder is a real folder reached from the version folder through real
# folders only. only those answers are kept, as the daemon alone writes a version's folders and never uses a version
# folder's name again, while a folder missing or refused now may be a version's real folder later
REAL_VAULT_FOLDERS = OrderedDict()
REAL_VAULT_FOLDERS_LOCK = threading.Lock()

class UncheckedVaultLink(Exception):
	'''
	Whether a vault link is a chain link cannot be told, as a folder on the way to its target cannot be looked at (an
	I/O error, say). The link may be its version's only way to a file, so reading and pruning never take it for a
	user's symlink.
	'''

def is_real_folder_under(top:str, folder:str) -> bool:
	'''
	Whether a path through folder stays in top: top is a real folder, and folder is top or under it with no symlink
	from top down to folder. A missing folder on the way, or a file, is fine, as nothing goes through it; a name too
	long for any folder is not. Raises UncheckedVaultLink, and nothing else, when a folder on the way cannot be looked
	at, as that tells neither way.

	Examples:
		>>> import tempfile
		>>> top = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(top, 'a', 'b'))
		>>> os.symlink(os.path.join(top, 'a'), os.path.join(top, 'l'))
		>>> [is_real_folder_under(top, os.path.join(top, *rel)) for rel in ((), ('a',), ('a', 'b'), ('l',), ('l', 'b'), ('missing', 'b'))]
		[True, True, True, False, False, True]
		>>> [is_real_folder_under(os.path.join(top, *rel), top) for rel in (('a',), ('l',), ('missing',))]
		[False, False, False]
		>>> is_real_folder_under(top, os.path.join(top, 'a' * 300, 'b'))
		False
		>>> try:
		...     is_real_folder_under(top, os.path.join(top, 'a' + chr(0), 'b'))
		... except UncheckedVaultLink:
		...     print('cannot tell')
		cannot tell
		>>> import shutil; shutil.rmtree(top)
	'''
	if folder != top and not folder.startswith(top + '/'):
		return False
	if (top, folder) in REAL_VAULT_FOLDERS:
		return True
	parts = folder[len(top) + 1:].split('/') if folder != top else []
	path = top
	# walked down from top, so a crafted link thousands of folders deep stops at its first folder that is not real
	for depth in range(len(parts) + 1):
		if depth:
			path = f'{path}/{parts[depth - 1]}'
		if (top, path) in REAL_VAULT_FOLDERS:
			continue
		try:
			mode = os.lstat(path).st_mode
		except (FileNotFoundError, NotADirectoryError):
			# nothing goes through a missing folder, but the version folder must be there
			return depth > 0
		except OSError as e:
			if e.errno == errno.ENAMETOOLONG:
				# a name or path too long to use: the daemon reaches its copies by path, so none is behind it
				return False
			raise UncheckedVaultLink(e) from e
		except ValueError as e:
			raise UncheckedVaultLink(e) from e
		if not stat.S_ISDIR(mode):
			# a symlink could lead anywhere, nothing goes through anything else
			return depth > 0 and not stat.S_ISLNK(mode)
		with REAL_VAULT_FOLDERS_LOCK:
			REAL_VAULT_FOLDERS[(top, path)] = None
			if len(REAL_VAULT_FOLDERS) > REAL_VAULT_FOLDERS_KEPT:
				REAL_VAULT_FOLDERS.popitem(last=False)
	return True

def chain_link_target(job_vault:str, link_text:str, link_path:str):
	'''
	Where the relative link at link_path with link_text points, if it is a chain link; None for any other link, such
	as a user's symlink backed up as one, even one shaped like a chain link.
	The daemon links an unchanged entry of a version to the version just before it: ../ up to the job vault, that
	version's folder and the entry's path in it, a text a move to another folder depth keeps. Only that form counts:
	the folder named must be the one numbered one below the version holding link_path, by its whole name, and a real
	folder with no symlink down to the target's parent (by is_real_folder_under()), so a backed-up folder symlink never
	leads out of it. A chain link whose target is gone is still one. Raises UncheckedVaultLink as is_real_folder_under()
	does.

	Examples:
		>>> import tempfile
		>>> job_vault = tempfile.mkdtemp()
		>>> for name in ('V2--2021-01-01_00-00-00_-0800', 'V3--2021-01-01_00-00-00_-0800', 'V3--x'):
		...     os.makedirs(os.path.join(job_vault, name, 'a'))
		>>> os.symlink(job_vault, os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'l'))
		>>> link_path = os.path.join(job_vault, 'V4--2021-01-02_00-00-00_-0800', 'deep', 'er', 'x')
		>>> [chain_link_target(job_vault, text, link_path)[len(job_vault):] for text in (
		...     '../V3--2021-01-01_00-00-00_-0800/a/x', '../../../../V3--2021-01-01_00-00-00_-0800/a/x')]
		['/V3--2021-01-01_00-00-00_-0800/a/x', '/V3--2021-01-01_00-00-00_-0800/a/x']
		>>> [chain_link_target(job_vault, text, link_path) for text in ('/abs/V3--2021-01-01_00-00-00_-0800/x', 'lib/x',
		...     '../V3--2021-01-01_00-00-00_-0800', '../notaversion/x', '../V3--2021-01-01_00-00-00_-0800/a/../../../etc/x',
		...     '../V2--2021-01-01_00-00-00_-0800/a/x', '../V3--2020-01-01_00-00-00_-0800/a/x', '../V3--x/a/x',
		...     '../V3--2021-01-01_00-00-00_-0800/l/a/x')]
		[None, None, None, None, None, None, None, None, None]
		>>> chain_link_target(job_vault, '../V3--2021-01-01_00-00-00_-0800/missing/x', link_path)[len(job_vault):]
		'/V3--2021-01-01_00-00-00_-0800/missing/x'
		>>> chain_link_target(job_vault, '../V3--2021-01-01_00-00-00_-0800/a/x', os.path.join(job_vault, 'elsewhere', 'x')) is None
		True
		>>> import shutil; shutil.rmtree(job_vault)
	'''
	parts = link_text.split('/')
	ups = 0
	while ups < len(parts) and parts[ups] == '..':
		ups += 1
	rel = parts[ups + 1:]
	# a .. after the version folder could name a path outside the vault
	if not ups or not rel or any(part in ('', '.', '..') for part in rel):
		return None
	name = parts[ups]
	number = vault_version_number(name)
	vault = os.path.abspath(job_vault)
	link_path = os.path.abspath(link_path)
	if number is None or not link_path.startswith(vault + '/'):
		return None
	own_number = vault_version_number(link_path[len(vault) + 1:].partition('/')[0])
	if own_number is None or number != own_number - 1 or not is_version_folder_name(name):
		return None
	target = os.path.join(vault, name, *rel)
	return target if is_real_folder_under(os.path.join(vault, name), os.path.dirname(target)) else None

def strict_chain_hop(job_vault:str, link_path:str, link_text:str):
	'''
	Where the link at link_path with link_text leads if it is a chain link, else None. A relative link is one by
	chain_link_target(); an absolute one, as older daemons wrote them, when its text names an older version of
	job_vault and no symlink in that version lies on the way to the target (by is_real_folder_under()). Raises
	UncheckedVaultLink, and nothing else, when that cannot be told.

	Examples:
		>>> import tempfile
		>>> job_vault = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'a'))
		>>> os.symlink(job_vault, os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'l'))
		>>> link_path = os.path.join(job_vault, 'V4--2021-01-02_00-00-00_-0800', 'a', 'u')
		>>> strict_chain_hop(job_vault, link_path, job_vault + '/V3--2021-01-01_00-00-00_-0800/a/../a/u')[len(job_vault):]
		'/V3--2021-01-01_00-00-00_-0800/a/u'
		>>> [strict_chain_hop(job_vault, link_path, text) for text in ('/elsewhere/u', '../lib/x', job_vault + '/V3--2021-01-01_00-00-00_-0800/l/u',
		...     job_vault + '/V5--2021-01-03_00-00-00_-0800/a/u')]
		[None, None, None, None]
		>>> import shutil; shutil.rmtree(job_vault)
	'''
	if not os.path.isabs(link_text):
		return chain_link_target(job_vault, link_text, link_path)
	resolved = os.path.normpath(link_text)
	vault = os.path.abspath(job_vault)
	link_path = os.path.abspath(link_path)
	if not is_chained_link(resolved, vault, link_path):
		return None
	version = resolved[len(vault) + 1:].partition('/')[0]
	own_number = vault_version_number(link_path[len(vault) + 1:].partition('/')[0])
	# the daemon only ever linked a version to an older one
	if own_number is None or vault_version_number(version) >= own_number:
		return None
	return resolved if is_real_folder_under(os.path.join(vault, version), os.path.dirname(resolved)) else None

def chain_hop(job_vault:str, link_path:str, link_text:str):
	'''strict_chain_hop(), but None (not a chain link) also when that cannot be told. Never raises.'''
	try:
		return strict_chain_hop(job_vault, link_path, link_text)
	except UncheckedVaultLink:
		return None

def retarget_chain_link(job_vault:str, link_path:str) -> bool:
	'''
	Rewrite the relative chain link at link_path (by chain_link_target()) to the text that reaches its target from where
	it now sits. True if it was rewritten; a link already reaching it, or any other link, keeps its text.
	'''
	link_text = os.readlink(link_path)
	try:
		target = chain_link_target(job_vault, link_text, link_path)
	except UncheckedVaultLink:
		# reading and pruning still find its version, whatever folder depth its text is for
		return False
	if target is None:
		return False
	new_text = os.path.relpath(target, os.path.dirname(link_path))
	if new_text == link_text:
		return False
	# put in place by a rename, so the link is never missing
	temp_path = partial_copy_path(link_path)
	os.symlink(new_text, temp_path)
	try:
		os.replace(temp_path, link_path)
	except BaseException:
		remove_entry(temp_path)
		raise
	return True

def retarget_moved_links(job_vault:str, moved_path:str) -> int:
	'''
	retarget_chain_link() for the vault entry a move put at moved_path: the link itself, or every link under a folder.
	Returns how many links were rewritten.
	'''
	if os.path.islink(moved_path):
		return int(retarget_chain_link(job_vault, moved_path))
	if not os.path.isdir(moved_path):
		# a copy this backup made
		return 0
	rewritten = 0
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another
	for path, _, is_dir in iter_tree_entries(moved_path, list_folders_first=True):
		if not is_dir and os.path.islink(path):
			rewritten += retarget_chain_link(job_vault, path)
	return rewritten

def is_chained_link(resolved:str, job_vault:str, link_path:str) -> bool:
	'''
	Whether the link at link_path, resolving to resolved, points into another version of job_vault: that is how a
	version links an unchanged entry (under its old name if it moved since). A symlink backed up as one resolves
	within its own version, if into the vault at all. strict_chain_hop() judges absolute links, as older daemons wrote
	them, by it; relative ones go by chain_link_target().

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
	Returns None when there is nothing readable there, or a link there cannot be told for a chain link or not.
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
			resolved = strict_chain_hop(job_vault, entry, target)
			if resolved is None:
				if os.path.isabs(target) and os.path.normpath(target) == monitor_entry:
					# a referenced backup links to the monitored file itself
					return ManifestRecord('r', None, None, None, None, None, None, None, 0)
				# a symlink that was backed up as one
				return ManifestRecord('l', None, None, st.st_mode, st.st_uid, st.st_gid, None, target, 0)
			entry = resolved
		else:
			return None
		kind = entry_kind(st.st_mode)
		file_hash = hash_file(entry, st.st_size) if kind == 'f' else None
		return ManifestRecord(kind, st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid, file_hash, None, 0)
	except (OSError, UncheckedVaultLink):
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

def iter_scope_entries(monitor_path:str, scope_rel:str, skip = None, errors:list = None):
	'''
	Walk the folder scope_rel (ending with /) of monitor_path as iter_tree_entries walks the whole tree, the folder itself
	first, as the walk of its parent would list it. Nothing is yielded when it is gone; when it cannot be looked at,
	(scope_rel, error) is appended to errors like a folder that cannot be read.
	'''
	path = os.path.join(monitor_path, scope_rel.rstrip('/'))
	try:
		mode = os.lstat(path).st_mode
	except (FileNotFoundError, NotADirectoryError):
		return
	except OSError as e:
		if errors is not None:
			errors.append((scope_rel, e))
		backuperTeeLogToTl(path=path,error=True,message=f'Error scanning {path}: {e}')
		return
	if not stat.S_ISDIR(mode):
		# no longer a folder: the entry in its place
		if skip is None or not skip(scope_rel[:-1]):
			yield path, scope_rel[:-1], False
		return
	yield path + '/', scope_rel, True
	yield from iter_tree_entries(path, scope_rel, skip=skip, errors=errors)

def delta_generate_backup_entries(backupEntries:dict,latest_version_info:VaultEntry,monitor_path:str,manifest:VaultManifest = None,skip_list:'SkipList' = None,job_name:str = '',reported:set = None,scope_rel:str = '',paused:set = None) -> VaultManifest:
	'''
	Add to backupEntries what changed in monitor_path since the latest version, comparing against its manifest.

	Unchanged entries are recognised from the recorded size, mtime, mode, owner and tail hash, so only the monitored
	side is read. The vault is read for unverified rows, which then get recorded, and for unchecked copies, which a
	crash may have left without their bytes.
	A folder that cannot be read keeps its tracked entries and is logged as UNREADABLE; when the monitored root itself
	cannot be read, JobFailure is raised before anything is recorded as deleted.
	With scope_rel, a folder rel ending with /, only that folder is compared: it is looked up like any entry, and only
	tracked rows at or under it can be found deleted.
	The paused inner mounts (paused_inner_mounts, from the remembered ones and the mount table now when not given) are
	not walked and keep their tracked rows; a scope that is skipped or inside a paused folder compares nothing.
	Returns the manifest, opened in the job vault when none is given.
	'''
	if manifest is None:
		manifest = VaultManifest(os.path.dirname(os.path.abspath(latest_version_info.path)))
	if paused is None:
		paused = paused_inner_mounts(monitor_path, manifest.inner_mounts, current_mount_table(), None if skip_list is None else skip_list.skips)
	skip = skip_paused(None if skip_list is None else skip_list.skips, paused)
	if scope_rel:
		if skips_folder_or_parent(skip, scope_rel):
			backuperTeeLogToTl(path=monitor_path,message=f'Not comparing {scope_rel}: it is skipped or in an unmounted inner mount')
			return manifest
		try:
			# a scope missing along with the monitored root is not a deleted scope
			os.stat(monitor_path)
		except OSError as e:
			raise JobFailure(f'cannot read {monitor_path}: {e}')
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
	if scope_rel:
		walk = iter_scope_entries(monitor_path,scope_rel,skip=skip,errors=walk_errors)
		# the scope as a file, before it became a folder: no row under the scope, so not found deleted there
		file_rel = scope_rel[:-1]
		stale_file = manifest.lookup(file_rel) is not None
	else:
		walk = iter_tree_entries(monitor_path,skip=skip,errors=walk_errors)
		stale_file = False
	# results are taken in walk order, so a new tree still lists each folder before its contents
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		for monitor_entry, rel, _ in walk:
			if not GREEN_LIGHT.is_set():
				break
			if stale_file and rel == file_rel:
				stale_file = False
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
	# a folder that could not be read keeps its entries, and so does the scope when it could not be looked at
	manifest.mark_seen(rel for rel, _ in walk_errors)
	for rel, _ in walk_errors:
		manifest.mark_seen_under(rel)
	# an unmounted inner disk keeps its last backed-up contents
	manifest.mark_seen(paused)
	for rel in paused:
		manifest.mark_seen_under(rel)
	log_unreadable(job_name, monitor_path, walk_errors, reported)
	if GREEN_LIGHT.is_set():
		# only a complete walk tells deleted entries from ones it did not reach
		deleted = manifest.unseen_under(scope_rel) if scope_rel else manifest.unseen()
		if stale_file and not any(rel == scope_rel for rel, _ in walk_errors):
			deleted.insert(0, file_rel)
		for rel in deleted:
			backuperTeeLogToTl(path=monitor_path,message=f'Deleted file/folder {os.path.join(monitor_path,rel)}')
			backupEntries[os.path.join(monitor_path,rel)] = BackupEntryValues(datetime.datetime.now().isoformat(),'delete',None)
	# what was read from the vault holds whether or not a new version follows
	manifest.commit(version_path)
	compared_what = f' under {scope_rel}' if scope_rel else ''
	backuperTeeLogToTl(path=monitor_path,message=f'Compared {compared} tracked entries{compared_what} in {time.monotonic() - start_time:.1f}s, {recorded} read from the vault, {len(backupEntries)} differences')
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

def restore_lock_path(job_name:str, state_dir:str = None) -> str:
	'''
	The lock file a restore shares with the daemon's pruning of job_name.
	>>> restore_lock_path('j', '/x')
	'/x/job-j.restore.lock'
	'''
	return os.path.join(state_dir_path(state_dir), f'job-{job_name}.restore.lock')

class RestoreLock:
	'''
	Held while a command reads old versions of a job: the daemon keeps backing up but postpones removing the oldest
	version meanwhile. A shared flock, so it goes with the process and a killed restore never leaves it behind.
	'''
	def __init__(self, job_name:str, state_dir:str = None, stream = sys.stderr):
		self.job_name = job_name
		self.state_dir = state_dir
		self.stream = stream
		self.fd = None

	def __enter__(self):
		os.makedirs(state_dir_path(self.state_dir), exist_ok=True)
		self.fd = os.open(restore_lock_path(self.job_name, self.state_dir), os.O_RDWR | os.O_CREAT, 0o600)
		try:
			try:
				fcntl.flock(self.fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
			except BlockingIOError:
				print(f'Waiting for reverberator to finish removing an old version of {self.job_name}', file=self.stream, flush=True)
				fcntl.flock(self.fd, fcntl.LOCK_SH)
		except BaseException:
			os.close(self.fd)
			self.fd = None
			raise
		return self

	def __exit__(self, *exc_info):
		if self.fd is not None:
			os.close(self.fd)
			self.fd = None
		return False

def prune_oldest(vault_info_dict:OrderedDict, job_name:str) -> tuple:
	'''
	decrement_stepper while no restore holds the job's lock; when one does, postpone and return (0, 0) so the retention
	loops stop. A lock file that cannot be opened (no state folder) does not hold pruning back.
	'''
	try:
		fd = os.open(restore_lock_path(job_name), os.O_RDWR | os.O_CREAT, 0o600)
	except OSError:
		return decrement_stepper(vault_info_dict)
	try:
		try:
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
		except BlockingIOError:
			backuperTeeLogToTl(job_name,'Postponing removal of the oldest version: a restore is reading the vault')
			return 0, 0
		return decrement_stepper(vault_info_dict)
	finally:
		os.close(fd)

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
	job_vault = os.path.dirname(referenceVaultPath)
	# walked instead of listed up front, as the next version links every tracked file (500k+ for big jobs).
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another
	for file, _, is_dir in iter_tree_entries(applyingVaultEntry.path, list_folders_first=True):
		if is_dir:
			continue
		if os.path.islink(file):
			# a link an older daemon moved to another folder depth still names its version, though its text no longer reaches it.
			# a user's symlink is left as it is, however it is shaped
			try:
				linkTarget = strict_chain_hop(job_vault, file, os.readlink(file))
			except UncheckedVaultLink as e:
				# it may be this version's only way to a file in the reference vault, so keep that, as for a failed move
				materialize_failed = True
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error checking whether {file} links into {referenceVaultPath}: {e}')
				continue
			if linkTarget is not None and linkTarget.startswith(referenceVaultPath):
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
				backuperTeeLogToTl(path=referenceVaultPath,message=f'Not moving {linkTarget} to {file}: not a chain link into {referenceVaultPath}')
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
					if link_source_relative_path.rstrip('/').count('/') != link_target_relative_path.rstrip('/').count('/'):
						# the relative links moved to another folder depth no longer reach the versions holding the copies
						retarget_moved_links(os.path.dirname(backup_folder),link_target_backup_real_path)
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

# --- the status, history and restore commands read the vault through these, and write nothing ---

class CommandError(Exception):
	'''A command cannot do what was asked: message is for the user, code the exit status (a usage error unless said).'''
	def __init__(self, message:str, code:int = EXIT_USAGE):
		super().__init__(message)
		self.message = message
		self.code = code

class RuleFileError(Exception):
	'''The rule file is missing or holds no rule, as parse_rules(read_only=True) finds it.'''

def job_vault_path(rule:ReverbRule) -> str:
	'''The folder a job keeps its versions in.'''
	return os.path.join(rule.vault_path, rule.job_name)

def find_job(rules:list, path:str, job_name:str = None) -> tuple:
	'''
	The rule monitoring path, and path relative to its monitored path: (rule, rel), rel '' for the monitored path
	itself, with no leading or trailing slash. A relative path is relative to the working folder, or to the job's
	monitored path when job_name names the job. Of the jobs whose monitored path holds the path (on a folder
	boundary), the one with the longest monitored path is taken. Raises CommandError, naming what there is, when no
	job fits.

	Examples:
		>>> rules = [ReverbRule('top', '/m', *['']*10), ReverbRule('sub', '/m/sub', *['']*10)]
		>>> [(rule.job_name, rel) for rule, rel in (find_job(rules, p) for p in ('/m/sub/x', '/m/subway/x', '/m/sub/', '/m'))]
		[('sub', 'x'), ('top', 'subway/x'), ('sub', ''), ('top', '')]
		>>> find_job(rules, 'a/b', job_name='top')[1]
		'a/b'
		>>> try:
		...     find_job(rules, '/elsewhere')
		... except CommandError as e:
		...     print(e.message)
		/elsewhere is not under any job's monitored path (/m, /m/sub)
	'''
	if job_name is not None:
		candidates = [rule for rule in rules if rule.job_name == job_name]
		if not candidates:
			raise CommandError(f'No job named {job_name}; the jobs are {", ".join(rule.job_name for rule in rules)}')
		path = os.path.join(candidates[0].mon_path, path)
	else:
		candidates = rules
	path = os.path.abspath(path)
	best = None
	for rule in candidates:
		mon_path = rule.mon_path.rstrip('/')
		if (path == mon_path or path.startswith(mon_path + '/')) and (best is None or len(mon_path) > len(best[1])):
			best = (rule, mon_path)
	if best is None:
		where = f"job {job_name}'s monitored path ({candidates[0].mon_path})" if job_name is not None else f"any job's monitored path ({', '.join(rule.mon_path for rule in rules)})"
		raise CommandError(f'{path} is not under {where}')
	return best[0], path[len(best[1]) + 1:]

KeptVersion = namedtuple('KeptVersion', ['number', 'path', 'name', 'timestamp', 'size', 'inodes', 'change_list'])

def parse_change_list_name(name:str):
	'''
	The version a change list file name stands for: (number, folder name, timestamp, size, inodes), None when name is not
	one. The name is the version folder's, then --<size>-<inodes>_ino and the change list extension.

	Examples:
		>>> parse_change_list_name('V3--2021-01-01_00-00-00_-0800--1.50_KiB-12_ino.modified_contents.nsv')[:2]
		(3, 'V3--2021-01-01_00-00-00_-0800')
		>>> parse_change_list_name('V3--2021-01-01_00-00-00_-0800') is None
		True
		>>> parse_change_list_name('V3--x--1_KiB-1_ino.modified_contents.nsv') is None
		True
	'''
	if not name.endswith(CONTENT_FILE_EXTENSION_NAME):
		return None
	number = vault_version_number(name)
	folder_name, _, size_inodes = strip_suffix(name, CONTENT_FILE_EXTENSION_NAME).rpartition('--')
	if number is None or not is_version_folder_name(folder_name):
		return None
	try:
		timestamp = datetime.datetime.strptime(folder_name.partition('--')[2], VAULT_TIMESTAMP_FORMAT).timestamp()
		size = format_bytes(size_inodes.partition('-')[0].replace('_',''), to_int=True)
		inodes = format_bytes(size_inodes.rpartition('-')[2].replace('_ino',''), to_int=True)
	except Exception:
		return None
	return number, folder_name, timestamp, size, inodes

def list_versions(job_vault:str) -> list:
	'''
	The versions job_vault keeps, oldest first, as KeptVersion. A version is kept when its folder and its change list are
	both there; one without the other, such as an unfinished backup, is left out and left alone.
	'''
	try:
		names = os.listdir(job_vault)
	except (FileNotFoundError, NotADirectoryError):
		return []
	versions = []
	for name in names:
		parsed = parse_change_list_name(name)
		if parsed is None:
			continue
		number, folder_name, timestamp, size, inodes = parsed
		path = os.path.join(job_vault, folder_name)
		if os.path.isdir(path):
			versions.append(KeptVersion(number, path, folder_name, timestamp, size, inodes, os.path.join(job_vault, name)))
	return sorted(versions, key=lambda version: version.number)

ResolvedEntry = namedtuple('ResolvedEntry', ['kind', 'path', 'detail'])

def chain_form_missing_version(job_vault:str, link_path:str, link_text:str):
	'''
	The name of the version folder a relative link names when the link has the form of a chain link, (../)+<name>/<rel>
	with <name> the version just below the link's own, but that folder does not exist; else None.

	Examples:
		>>> chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', '../../V3--2021-01-01_00-00-00_-0800/a/x')
		'V3--2021-01-01_00-00-00_-0800'
		>>> chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', '../../V2--2021-01-01_00-00-00_-0800/a/x') is None
		True
		>>> chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', '/abs/V3--2021-01-01_00-00-00_-0800/a/x') is None
		True
	'''
	parts = link_text.split('/')
	ups = 0
	while ups < len(parts) and parts[ups] == '..':
		ups += 1
	rel = parts[ups + 1:]
	if not ups or not rel or any(part in ('', '.', '..') for part in rel):
		return None
	name = parts[ups]
	vault = os.path.abspath(job_vault)
	link_path = os.path.abspath(link_path)
	if not link_path.startswith(vault + '/') or not is_version_folder_name(name):
		return None
	own_number = vault_version_number(link_path[len(vault) + 1:].partition('/')[0])
	if own_number is None or vault_version_number(name) != own_number - 1:
		return None
	try:
		os.lstat(os.path.join(vault, name))
	except (FileNotFoundError, NotADirectoryError):
		return name
	except (OSError, ValueError):
		pass
	return None

def resolve_version_entry(job_vault:str, version_path:str, rel:str, monitor_path:str) -> ResolvedEntry:
	'''
	Where the content of rel in the version at version_path really is, following the links that chain an unchanged entry
	back to the version holding its copy (the rule read_vault_record() follows, however many versions back).
	The kind is 'file' or 'folder' (path is the real copy), 'symlink' (a user's symlink backed up as one; path is the
	link), 'referenced' (a link to the monitored file itself; path is the link), 'missing' (the version has no such
	entry), 'dangling' (a chain leads to nothing, or is too long) or 'unreadable' (a link or folder could not be
	looked at); detail says what and where for the last two.
	'''
	vault = os.path.abspath(job_vault)
	entry = os.path.abspath(os.path.join(version_path, rel))
	hops = 0
	# every hop goes down a version, so the walk ends by itself; this only bounds it should a link ever not
	own_number = vault_version_number(os.path.basename(os.path.abspath(version_path)))
	max_hops = (own_number or 0) + 1
	# lstat follows the symlinks among rel's folders, so they must be real ones: a backed-up folder symlink holds no
	# files of the version, and what lies behind it is the live file
	version_top = os.path.abspath(version_path)
	try:
		# the version's own root has no folders above it in the version, and its lstat below checks it
		real_folders = not rel or is_real_folder_under(version_top, os.path.dirname(entry))
	except UncheckedVaultLink as e:
		return ResolvedEntry('unreadable', entry, str(e))
	if not real_folders:
		path = version_top
		for part in os.path.dirname(entry)[len(version_top) + 1:].split('/'):
			path = os.path.join(path, part) if part else path
			if os.path.islink(path):
				return ResolvedEntry('missing', entry, f'{part} is a symlink in {os.path.basename(version_top)}')
		return ResolvedEntry('missing', entry, f'{rel} is not in {os.path.basename(version_top)}')
	while True:
		# the entry's path in the version it is found in, which a move since the link was made may have changed
		in_vault = entry.startswith(vault + '/')
		entry_rel = entry[len(vault) + 1:].partition('/')[2] if in_vault else rel
		try:
			st = os.lstat(entry)
		except (FileNotFoundError, NotADirectoryError):
			if not hops:
				return ResolvedEntry('missing', entry, f'{rel} is not in {os.path.basename(version_path)}')
			return ResolvedEntry('dangling', entry, f'{entry_rel} is missing from {entry[len(vault) + 1:].partition("/")[0]}')
		except OSError as e:
			return ResolvedEntry('unreadable', entry, str(e))
		if not stat.S_ISLNK(st.st_mode):
			return ResolvedEntry('folder' if stat.S_ISDIR(st.st_mode) else 'file', entry, '')
		try:
			text = os.readlink(entry)
			hop = strict_chain_hop(vault, entry, text)
		except (OSError, UncheckedVaultLink) as e:
			return ResolvedEntry('unreadable', entry, str(e))
		if hop is None:
			missing = chain_form_missing_version(vault, entry, text)
			if missing is not None:
				return ResolvedEntry('dangling', entry, f'{missing} is missing')
			if os.path.isabs(text) and os.path.normpath(text) == os.path.join(monitor_path, entry_rel):
				return ResolvedEntry('referenced', entry, text)
			return ResolvedEntry('symlink', entry, text)
		hops += 1
		if hops > max_hops:
			return ResolvedEntry('dangling', entry, 'too many links in the chain')
		entry = hop

ChangeRow = namedtuple('ChangeRow', ['path', 'iso_time', 'event', 'source_path'])

CHANGE_LIST_ESCAPES = {'</sep/>':'<sep>', '</LF/>':'<LF>', '<sep>':'\0', '<LF>':'\n'}
CHANGE_LIST_ESCAPE_PATTERN = re.compile('|'.join(re.escape(token) for token in CHANGE_LIST_ESCAPES))

def unescape_change_list_field(text:str) -> str:
	'''
	The field as it was before TSVZ wrote it into a change list: its <sep> and <LF> stand for a delimiter and a line feed,
	and </sep/> and </LF/> for the text <sep> and <LF>. Read in one pass, so no replacement is read again, and
	trailing spaces are kept.

	Examples:
		>>> unescape_change_list_field('a</sep/>b</LF/>c<LF>d<sep>e ')
		'a<sep>b<LF>c\\nd\\x00e '
		>>> unescape_change_list_field('</LF/>')
		'<LF>'
	'''
	return CHANGE_LIST_ESCAPE_PATTERN.sub(lambda match: CHANGE_LIST_ESCAPES[match.group(0)], text)

def iter_change_list(path:str):
	'''Yield each ChangeRow of the change list at path (a header, then NUL separated fields to a line), reading line by line.'''
	with open(path, 'r', encoding='utf-8', errors='surrogateescape', newline='\n') as f:
		next(f, None)
		for line in f:
			line = line.rstrip('\n')
			if not line:
				continue
			fields = [unescape_change_list_field(field) for field in line.split('\0')]
			fields += [''] * (4 - len(fields))
			source = fields[3]
			yield ChangeRow(fields[0], fields[1], fields[2], None if source in ('', 'None') else source)

# --- the commands: status here, history and restore behind the same front door ---

def get_command_args(argv:list) -> argparse.Namespace:
	'''
	Parse a command's arguments: argv[0] is the command.

	Examples:
		>>> get_command_args(['status', '--rule', 'r.tsv']).rule
		'r.tsv'
		>>> get_command_args(['history', '/a/b', '--files']).files
		True
		>>> get_command_args(['restore', '/a/b', '--version', '3', '--yes']).version
		3
	'''
	common = argparse.ArgumentParser(add_help=False)
	common.add_argument('--rule', metavar='PATH', default=None, help='The rule file; by default the one the running (or last run) daemon recorded')
	common.add_argument('--state_dir', metavar='DIR', default=None, help=f'The daemon status folder, default $REVERB_STATE_DIR or {DEFAULT_STATE_DIR}')
	where = argparse.ArgumentParser(add_help=False)
	where.add_argument('path', help='A file or folder under a monitored path')
	where.add_argument('--job', metavar='NAME', default=None, help='The job, when the path is relative to its monitored path')
	parser = argparse.ArgumentParser(prog='reverberator.py', description='Look at what the daemon backs up, and restore it')
	commands = parser.add_subparsers(dest='command', required=True)
	commands.add_parser('status', parents=[common], help='Show the daemon and each job')
	history = commands.add_parser('history', parents=[common, where], help='Show the versions that changed a path')
	history.add_argument('--files', action='store_true', help='For a folder, list each changed file')
	restore = commands.add_parser('restore', parents=[common, where], help='Copy a path back from a version')
	restore.add_argument('dest', nargs='?', default=None, help='Where to restore to')
	restore.add_argument('--version', type=int, default=None, help='The version number to restore from')
	restore.add_argument('--at', default=None, help='Restore the newest version at or before this time')
	restore.add_argument('--in-place', dest='in_place', action='store_true', help='Restore over the original path')
	restore.add_argument('--threads', type=int, default=os.cpu_count(), help='Copies to run at once')
	restore.add_argument('--yes', action='store_true', help='Do not ask for confirmation')
	return parser.parse_args(argv)

DaemonStatus = namedtuple('DaemonStatus', ['record', 'alive', 'jobs'])

def read_json_record(path:str):
	'''The JSON object in the file at path, or None when it is unreadable or not an object.'''
	try:
		with open(path, 'r', encoding='utf-8') as f:
			record = json.load(f)
	except (OSError, ValueError):
		return None
	return record if isinstance(record, dict) else None

def read_status(state_dir:str) -> DaemonStatus:
	'''
	What the daemon published in state_dir: its record (None when missing), whether that daemon is alive (its pid runs
	with the recorded start time, so a pid another process took does not count) and each job's record by job name.
	Unreadable or malformed files read as missing. Nothing is written.
	'''
	record = read_json_record(os.path.join(state_dir, 'daemon.json'))
	if record is not None and not (isinstance(record.get('pid'), int) and isinstance(record.get('start_ticks'), int)
			and isinstance(record.get('started_at'), (int, float)) and not isinstance(record.get('pid'), bool)):
		record = None
	alive = record is not None and process_start_ticks(record['pid']) == record['start_ticks']
	jobs = {}
	try:
		names = sorted(os.listdir(state_dir))
	except OSError:
		names = []
	for name in names:
		if name.startswith('job-') and name.endswith('.json'):
			job_record = read_json_record(os.path.join(state_dir, name))
			if job_record is not None and isinstance(job_record.get('job'), str) and job_record.get('state') in JOB_STATES:
				jobs[job_record['job']] = job_record
	return DaemonStatus(record, alive, jobs)

JOB_STATES = ('starting', 'running', 'waiting', 'retrying', 'stopped')

def command_rule_path(args, status:DaemonStatus) -> str:
	'''The rule file a command reads: --rule, else the one the daemon recorded (running or not), else a CommandError.'''
	if args.rule:
		return args.rule
	if status.record is not None and status.record.get('rule_path'):
		return status.record['rule_path']
	raise CommandError('No running daemon recorded a rule file here: give the rule file with --rule PATH')

def load_command_rules(rule_path:str) -> list:
	'''The rules in the rule file for a command, read without changing anything and without printing anything.'''
	try:
		# TSVZ prints a header mismatch dump for a rule file whose header was never upgraded
		with open(os.devnull, 'w') as quiet, contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
			rules = parse_rules(rule_path, read_only=True)
	except RuleFileError as e:
		raise CommandError(str(e))
	except (OSError, ValueError) as e:
		raise CommandError(f'Cannot read rule file {rule_path}: {e}')
	if not rules:
		raise CommandError(f'Rule file {rule_path} has no jobs')
	return rules

VaultNumbers = namedtuple('VaultNumbers', ['present', 'versions', 'size', 'inodes', 'size_limit', 'inode_limit', 'keep_n'])

def vault_numbers(rule:ReverbRule) -> VaultNumbers:
	'''What a job's vault holds and what limits it: sizes summed from its versions, limits as the backuper works them out.'''
	versions = list_versions(job_vault_path(rule))
	size_limit, inode_limit = get_backup_limits_from_str(rule.backup_size_limit, *get_path_fs_info(rule.vault_path))
	try:
		keep_n = int(rule.keep_n_versions)
	except ValueError:
		keep_n = 0
	return VaultNumbers(os.path.isdir(job_vault_path(rule)), len(versions), sum(v.size for v in versions),
		sum(v.inodes for v in versions), size_limit, inode_limit, keep_n)

def show_size(size:int, limit:int = None) -> str:
	'''
	A byte count for people, or 'no limit' when limit is 0.
	>>> show_size(1536), show_size(0, 0)
	('1.50 KiB', 'no limit')
	'''
	if limit == 0:
		return 'no limit'
	return format_bytes(size, use_1024_bytes=True, to_str=True).rstrip() + 'B'

def show_count(count:int, limit:int = None) -> str:
	'''
	A count for people, or 'no limit' when limit is 0.
	>>> show_count(126750), show_count(5, 0)
	('126.75 K', 'no limit')
	'''
	if limit == 0:
		return 'no limit'
	return format_bytes(count, use_1024_bytes=False, to_str=True).strip()

def show_time(epoch:float, clock_only:bool = False) -> str:
	'''A local time for people: date and minute, or only the minute of the day.'''
	return time.strftime('%H:%M' if clock_only else '%Y-%m-%d %H:%M', time.localtime(epoch))

def job_state_phrase(record, daemon_alive:bool, daemon_started) -> str:
	'''
	How a job is doing, from its status record (None when it has none): last known when the daemon is not alive or the
	record is older than this daemon run.
	>>> job_state_phrase(None, True, 0)
	'unknown'
	>>> job_state_phrase({'state': 'stopped', 'detail': 'why', 'updated': 5}, False, 0)
	'last known: stopped: why'
	'''
	if record is None:
		return 'unknown'
	state, detail = record['state'], record.get('detail') or ''
	number = lambda key, default = 0: record.get(key) if isinstance(record.get(key), (int, float)) else default
	if state == 'waiting':
		phrase = f'waiting for disk since {show_time(number("since"), True)}: {detail}'
	elif state == 'retrying':
		phrase = f'retrying at {show_time(number("retry_at"), True)} after {int(number("failures"))} failed attempts: {detail}'
	elif state == 'stopped':
		phrase = f'stopped: {detail}'
	else:
		phrase = state
	stale = daemon_started is not None and number('updated') < daemon_started
	return phrase if daemon_alive and not stale else f'last known: {phrase}'

def format_job_status(rule:ReverbRule, record, status:DaemonStatus, width:int) -> list:
	'''The lines for one job, the name first and the rest indented under it.'''
	started = status.record['started_at'] if status.record is not None else None
	indent = ' ' * (width + 2)
	lines = [f'{rule.job_name:<{width}}  {job_state_phrase(record, status.alive, started)}']
	try:
		numbers = vault_numbers(rule)
		versions = list_versions(job_vault_path(rule))
		if versions:
			newest, oldest = versions[-1], versions[0]
			lines.append(f'{indent}last backup {show_time(newest.timestamp)} (V{newest.number})')
			lines.append(f'{indent}{numbers.versions} versions (limit {numbers.keep_n or "no limit"}), oldest V{oldest.number} {show_time(oldest.timestamp)}')
		else:
			lines.append(f'{indent}no versions yet')
		if not os.path.isdir(rule.vault_path) or not os.listdir(rule.vault_path):
			lines.append(f'{indent}vault not mounted: {rule.vault_path}')
		elif numbers.present:
			lines.append(f'{indent}vault {show_size(numbers.size)} / limit {show_size(numbers.size_limit, numbers.size_limit)}, '
				f'{show_count(numbers.inodes)} inodes / limit {show_count(numbers.inode_limit, numbers.inode_limit)}')
	except OSError as e:
		# a stale mount or a permission error on one vault must not stop the others showing
		lines = lines[:1] + [f'{indent}vault not readable: {rule.vault_path}: {e}']
	return lines

def format_status(status:DaemonStatus, rules:list, rule_path:str) -> str:
	'''The status command's text: the daemon, then each job in the rule file.'''
	record = status.record
	if record is None:
		header = 'reverberator is not running'
	elif status.alive:
		header = f'reverberator {record.get("version", "?")}, running since {show_time(record["started_at"])} (pid {record["pid"]}), rules {rule_path}'
	else:
		header = f'reverberator is not running (last started {show_time(record["started_at"])})'
	width = max(len(rule.job_name) for rule in rules)
	lines = [header, '']
	for rule in rules:
		lines += format_job_status(rule, status.jobs.get(rule.job_name), status, width)
	return '\n'.join(lines)

def status_command(args) -> int:
	'''Print the daemon's and each job's state. Exits 0 whatever it finds.'''
	status = read_status(state_dir_path(args.state_dir))
	rule_path = command_rule_path(args, status)
	print(format_status(status, load_command_rules(rule_path), rule_path))
	return 0

def run_command(argv:list) -> int:
	'''Run the command argv names and return its exit status; a CommandError prints its message on stderr.'''
	global tl
	args = get_command_args(argv)
	old_tl = tl
	# library logging stays off the output
	tl = Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=True, noLog=True)
	try:
		command = COMMAND_FUNCTIONS.get(args.command)
		if command is None:
			raise CommandError(f'The {args.command} command is not available yet')
		return command(args)
	except CommandError as e:
		print(e.message, file=sys.stderr)
		return e.code
	except KeyboardInterrupt:
		print('Interrupted', file=sys.stderr)
		return EXIT_COMMAND_FAILED
	finally:
		tl = old_tl

# the history and restore commands add their functions here
COMMAND_FUNCTIONS = {'status': status_command}

if __name__ == "__main__":
	main()
# %%
