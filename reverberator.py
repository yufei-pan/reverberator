#! /usr/bin/env python3
import multiCMD
import TSVZ
import inotify_simple
import Tee_Logger
import argparse
import atexit
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
import hashlib
import select
import contextlib
import inspect
import sqlite3
import json
import tempfile
import stat
import array
import errno
import fcntl
import marshal
import zlib
from concurrent.futures import Future, ThreadPoolExecutor
import shutil
import uuid
import urllib.parse
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


__version__ = 0.43

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
	round_tripped says that some of the events lost their raw form: a batch handed back after a backup that did not
	commit, or loaded from the pending transactions, holds only its collapsed entries (backup_entries_to_change_events()).
	prepend() and the pending load set it for events other than scans, and take() moves it to the batch it takes.

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
		>>> queue.prepend([ChangeEvent(3.0, False, 'modify', '/m/new', None)])
		>>> queue.round_tripped, queue.take().round_tripped, queue.round_tripped
		(True, True, False)
		>>> queue.append(ChangeEvent(4.0, False, 'full_scan', '/m', None))
		>>> queue.append(ChangeEvent(5.0, False, 'modify', '/m/log', None))
		>>> [event.event for event in queue]
		['full_scan']
	'''
	def __init__(self, monitor_path:str = ''):
		self.monitor_path = monitor_path
		self.clear()

	def clear(self):
		self.round_tripped = False
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
		if any(event.event != 'scan' for event in events):
			# scans name folders compared whole, which lose nothing
			self.round_tripped = True
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
		taken.round_tripped = self.round_tripped
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

	def deciding_pattern(self, rel:str, is_dir:bool) -> 'str | None':
		'''
		The pattern that skips a root-relative path, or the first skipped folder above it, as the walk never goes into a
		skipped folder; None when nothing skips it.
		>>> skip = SkipList('/m', ['build/', '*.tmp', '!keep.tmp', 'cache/', '!cache/keep'])
		>>> [skip.deciding_pattern(rel, is_dir) for rel, is_dir in (('build/x', False), ('cache/keep', False),
		...     ('a/b.tmp', False), ('a/keep.tmp', False), ('build', True), ('build', False), ('', True))]
		['build/', 'cache/', '*.tmp', None, 'build/', None, None]
		'''
		parts = rel.strip('/').split('/') if self.patterns and rel.strip('/') else []
		for depth in range(1, len(parts) + 1):
			entry = '/'.join(parts[:depth]) + ('/' if depth < len(parts) or is_dir else '')
			result = self._spec.check_file(entry)
			if result.include:
				return self._spec.patterns[result.index].pattern
		return None

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

class VaultScanError(JobFailure):
	'''
	The job vault cannot be read whole, or holds what its scan cannot be certain of (read_job_vault()): nothing was
	deleted, and the job's attempt fails with its FAILED marker, so no backup prunes or writes on a partial view. The
	next attempt reads the vault again.
	'''

class JobControl:
	'''
	One job's state across its attempts, shared by its watcher and backuper.
	The threads report a failure here instead of clearing GREEN_LIGHT, so only this job stops; the first failure of an
	attempt is the one kept. committed is set once the attempt has committed a backup.
	'''
	def __init__(self, job_name:str, shown_name:str = None):
		self.job_name = job_name
		# what the job's marker lines call it: row-<n> for a job whose cleaned name is empty, which log alerts accept
		self.shown_name = job_name if shown_name is None else shown_name
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
		# the status records, taken in order under _lock and written outside it, one at a time ( _write() )
		self._writing = threading.Lock()
		self._published = 0
		self._written = 0

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
			record = self._publish()
		self._write(record)

	def set_state(self, state:str, detail:str = '', retry_at:float = None, failures:int = 0):
		'''Record the job's state (starting, running, retrying or stopped) and publish it; a wait going on shows over it.'''
		with self._lock:
			self._state, self._detail, self._since = state, detail, time.time()
			self._retry_at, self._failures = retry_at, failures
			record = self._publish()
		self._write(record)

	def begin_wait(self, path:str, what:str) -> object:
		'''Note the job waiting for path, and return the token update_wait and end_wait take.'''
		token = object()
		with self._lock:
			self._waits.append([token, path, what, time.time()])
			record = self._publish()
		self._write(record)
		return token

	def update_wait(self, token, what:str):
		'''Say what the wait of token waits for now, publishing it when that changed; the wait keeps its start.'''
		with self._lock:
			wait = next((wait for wait in self._waits if wait[0] is token), None)
			if wait is None or wait[2] == what:
				return
			wait[2] = what
			record = self._publish()
		self._write(record)

	def end_wait(self, token):
		with self._lock:
			self._waits = [wait for wait in self._waits if wait[0] is not token]
			record = self._publish()
		self._write(record)

	def _publish(self) -> tuple:
		'''
		The record for the status board, as (its number in the order taken, the record). The caller holds the lock and
		hands it to _write() once it has let go of it, so a status folder that stalls holds up no thread that only takes
		the lock, such as fail() or should_run().
		'''
		state, detail, since = self._state, self._detail, self._since
		if self._waits:
			state, detail, since = 'waiting', f'{self._waits[0][1]}: {self._waits[0][2]}', self._waits[0][3]
		self._published += 1
		return self._published, {'job': self.job_name, 'state': state, 'detail': detail, 'since': since,
			'retry_at': self._retry_at, 'failures': self._failures, 'last_success': self.last_success, 'updated': time.time()}

	def _write(self, published:tuple):
		'''Write a record _publish() took to the status board, unless one taken after it is written already.'''
		board = STATUS_BOARD
		# the jobs whose name cleaned up to nothing would all write job-.json: status shows them from the rule file
		if board is None or self.job_name == '':
			return
		number, record = published
		with self._writing:
			if number > self._written:
				self._written = number
				board.write_job(self.job_name, record)

DEFAULT_STATE_DIR = '/run/reverberator'

def state_dir_path(override:str = None) -> str:
	'''
	The folder the daemon publishes its status in: override, else $REVERB_STATE_DIR, else DEFAULT_STATE_DIR.
	>>> state_dir_path('/x')
	'/x'
	'''
	return override or os.environ.get('REVERB_STATE_DIR') or DEFAULT_STATE_DIR

def process_start_ticks(pid:int) -> 'int | None':
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
		# the jobs' threads write at the same time, and only one of them logs the first error
		self._failed_lock = threading.Lock()
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
			with self._failed_lock:
				first, self._failed = not self._failed, True
			if first:
				tl.teeerror(log_text(f'Cannot write status files in {self.state_dir}: {e}'))
		finally:
			if temp is not None:
				with contextlib.suppress(OSError):
					os.remove(temp)

STATUS_BOARD = None

# re-entrant: the SIGTERM handler logs from the main thread, which may be mid-line
LOG_LOCK = threading.RLock()

class LockedLogger:
	'''
	A Tee_Logger whose every call runs holding LOG_LOCK, so each logged line reaches the output whole.

	Tee_Logger prints a line's text and its line break as two writes; a marker another thread logs
	between them lands mid-line, where the log alerts never see it.
	A missing method raises AttributeError, so getattr(tl, name, fallback) still falls back.
	This wrapper is one more stack frame, so a caller depth of 0 or more is passed on one deeper.
	'''
	def __init__(self, wrapped):
		self.wrapped = wrapped
		# method name -> {parameter name: its position among the positional arguments or None}, for the two
		# parameters the wrapper acts on
		self._params = {}

	def __getattr__(self, name):
		if name in ('wrapped', '_params'):
			# not set yet, as on a copy: no loop through self.wrapped
			raise AttributeError(name)
		value = getattr(self.wrapped, name)
		if not callable(value):
			return value
		# a partial adds no stack frame of its own: _call is the one frame between caller and logger
		return functools.partial(self._call, name, value)

	def _positions(self, name, method):
		if name not in self._params:
			try:
				params = list(inspect.signature(method).parameters.values())
			except (TypeError, ValueError):
				params = []
			found = {}
			for position, param in enumerate(params):
				if param.name in ('callerStackDepth', 'msg'):
					found[param.name] = position if param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD) else None
			self._params[name] = found
		return self._params[name]

	def _call(self, name, method, /, *args, **kwargs):
		positions = self._positions(name, method)
		if 'callerStackDepth' in positions:
			position = positions['callerStackDepth']
			if position is not None and position < len(args):
				args = args[:position] + (self._one_deeper(args[position]),) + args[position + 1:]
			else:
				kwargs['callerStackDepth'] = self._one_deeper(kwargs.get('callerStackDepth', ...))
		if 'msg' in positions:
			position = positions['msg']
			if position is not None and position < len(args):
				if isinstance(args[position], str):
					args = args[:position] + (self._cut_lines(args[position]),) + args[position + 1:]
			elif isinstance(kwargs.get('msg'), str):
				kwargs['msg'] = self._cut_lines(kwargs['msg'])
		with LOG_LOCK:
			return method(*args, **kwargs)

	@staticmethod
	def _cut_lines(text):
		# as cut_line's own check: no line of it can be over the limit
		if len(text) * 4 <= LOG_LINE_LIMIT:
			return text
		return '\n'.join(cut_line(line) for line in text.split('\n'))

	def _one_deeper(self, depth):
		# a negative depth would make Tee_Logger name this wrapper as the caller: every logger that writes a log file
		# passes an explicit depth (run_daemon's uses 4)
		if depth is ...:
			depth = getattr(self.wrapped, 'callerStackDepth', -1)
		# a negative depth is Tee_Logger's "find the caller" default
		return depth + 1 if isinstance(depth, int) and depth >= 0 else depth

# how long a write to stdout or stderr waits for LOG_LOCK before it writes without it
WHOLE_LINE_WAIT_SECONDS = 5
# how long it waits instead after its thread's last wait timed out
WHOLE_LINE_RETRY_SECONDS = 0.1
# gave_up: this thread's last wait for LOG_LOCK timed out, on either stream, so a thread that gave up on stdout does not
# wait the full time again on stderr
WHOLE_LINE_LOCAL = threading.local()

class WholeLineStream:
	'''
	A text stream that holds each thread's text until its line ends, then writes the whole line at once, holding LOG_LOCK
	(or, past WHOLE_LINE_WAIT_SECONDS, without it: see _log_lock).

	Other code in the daemon (multiCMD, TSVZ, Tee_Logger's own threads, a thread's traceback) writes a line to
	stdout or stderr in pieces; a marker written between the pieces would sit mid-line, where the log alerts never
	see it.
	A held part is written as a line of its own when it outgrows twice LOG_LINE_LIMIT characters (tl's own longest line,
	a cut line plus its level tag or colour codes, is longer than the limit), when the next line is written after its
	thread has ended, when its thread dies with an uncaught exception, or by write_held() at exit, so no text is dropped. flush() does not write
	held parts: that would put a part mid-line.
	Every other attribute (fileno, isatty, encoding, buffer, ...) is the wrapped stream's.
	'''
	def __init__(self, stream):
		self.stream = stream
		# thread -> the part of a line it has written without its line break; an entry exists only while it holds one
		self._held = {}

	def __getattr__(self, name):
		if name in ('stream', '_held'):
			# not set yet, as on a copy: no loop through self.stream
			raise AttributeError(name)
		return getattr(self.stream, name)

	@contextlib.contextmanager
	def _log_lock(self):
		# the caller may hold a library lock (a logging handler's, say) that a LOG_LOCK holder is waiting for: after a
		# while the write goes ahead without LOG_LOCK, as a hang would silence every marker. The cost: this thread's
		# lines stay whole, but until it gets the lock again they are not ordered against other threads' writes.
		# A thread that holds LOG_LOCK already (LockedLogger printing, the SIGTERM handler) gets it at once.
		# A thread whose wait timed out waits only WHOLE_LINE_RETRY_SECONDS until it gets the lock again: the many
		# writes of a traceback it prints cost one long wait, not one each, while a lock held by an ordinary log call
		# is still waited for.
		# accepted: a signal handler that raises (the second signal's exit) right after the acquire, before the try,
		# leaves LOG_LOCK owned; that window is microseconds and on the force-exit path
		locked = LOG_LOCK.acquire(timeout=WHOLE_LINE_RETRY_SECONDS if getattr(WHOLE_LINE_LOCAL, 'gave_up', False) else WHOLE_LINE_WAIT_SECONDS)
		WHOLE_LINE_LOCAL.gave_up = not locked
		try:
			yield
		finally:
			if locked:
				LOG_LOCK.release()

	def write(self, text:str) -> int:
		if not isinstance(text, str):
			raise TypeError(f'write() argument must be str, not {type(text).__name__}')
		with self._log_lock():
			thread = threading.current_thread()
			# taken out first: a part being written is not held again if the stream raises
			joined = self._held.pop(thread, '') + text
			end = joined.rfind('\n') + 1
			out, rest = joined[:end], joined[end:]
			if len(rest) > 2 * LOG_LINE_LIMIT:
				# a writer that never ends its line: memory stays bounded. The cap is twice the limit because tl's own
				# longest line (a cut line and its tag or colour codes) is over the limit, and print writes its line
				# break as a separate write: a part cut earlier would leave that break as an empty record
				out, rest = joined + '\n', ''
			try:
				if out:
					if self._held:
						# parts of other threads: those that ended are written ahead, as lines of their own
						self._write_parts([part for other in list(self._held) if not other.is_alive() and (part := self._held.pop(other, None))])
					self.stream.write(out)
					self.stream.flush()
			finally:
				if rest:
					# after a write on this thread that came in while this one wrote (a signal handler's, say): this
					# text was written before that one's
					self._held[thread] = rest + self._held.pop(thread, '')
		return len(text)

	def writelines(self, lines):
		for line in lines:
			self.write(line)

	def flush(self):
		# no LOG_LOCK: it writes no held text, so it has no line to keep whole
		self.stream.flush()

	def write_held(self):
		'''Write every thread's held part as a line of its own, as at exit.'''
		with self._log_lock():
			self._write_parts([part for thread in list(self._held) if (part := self._held.pop(thread, None))])
			self.stream.flush()

	def write_held_of_this_thread(self):
		'''Write the calling thread's held part, if any, as a line of its own.'''
		with self._log_lock():
			if part := self._held.pop(threading.current_thread(), None):
				self._write_parts([part])
				self.stream.flush()

	def _write_parts(self, parts):
		for part in parts:
			try:
				self.stream.write(part + '\n')
			except (OSError, ValueError):
				# one the stream cannot take (a character it cannot encode, say) is skipped, not the rest
				pass

def install_daemon_output():
	'''Make the daemon's stdout and stderr WholeLineStreams that write their held parts at exit, and set threading.excepthook to log_thread_exception; a repeated call changes nothing.'''
	for name in ('stdout', 'stderr'):
		stream = getattr(sys, name)
		if stream is not None and not isinstance(stream, WholeLineStream):
			wrapped = WholeLineStream(stream)
			setattr(sys, name, wrapped)
			atexit.register(wrapped.write_held)
	threading.excepthook = log_thread_exception

def log_thread_exception(args) -> None:
	'''
	threading.excepthook: log a thread's uncaught exception through tl at error level, escaped and whole.

	The thread's unfinished stdout or stderr text is written as a line of its own first, so it is not glued to the
	traceback. When logging fails the escaped text goes to the log file, then to stderr; Python's own hook runs only when
	the text cannot be built, so no fallback writes unescaped text.
	'''
	if args.exc_type is SystemExit:
		return
	try:
		import traceback
		name = args.thread.name if args.thread is not None else '?'
		text = log_text(f'Uncaught exception in thread {name}:\n' + ''.join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)).rstrip('\n'))
	except Exception:
		threading.__excepthook__(args)
		return
	for stream in (sys.stdout, sys.stderr):
		if isinstance(stream, WholeLineStream):
			with contextlib.suppress(Exception):
				stream.write_held_of_this_thread()
	try:
		tl.teeerror(text)
		return
	except Exception:
		pass
	try:
		tl.error(text)
	except Exception:
		pass
	try:
		sys.stderr.write(text + '\n')
	except Exception:
		pass

def job_log(job_name:str, text:str) -> str:
	'''Log a job's marker line at error level, where log alerts look for it, and return it.'''
	line = cut_line(shown(f'reverberator job {job_name} {text}'))
	tl.teeerror(line)
	return line

def daemon_error_log(reason:str) -> str:
	'''Log the marker line for the daemon exiting on an error at error level, and return it.'''
	line = cut_line(shown(f'reverberator EXITING with error: {reason}'))
	tl.teeerror(line)
	return line

class NamelessJobName(str):
	'''The cleaned job name '' of a rule whose name has nothing left after cleanup; raw is the name as written.'''
	def __new__(cls, raw:str):
		self = super().__new__(cls, '')
		self.raw = raw
		return self

def raw_job_name(rule) -> str:
	'''The name a rule is called in messages: the job name, or the name as written when it cleaned up to nothing.'''
	return getattr(rule.job_name, 'raw', rule.job_name)

def nameless_reason(rule_path:str, raw:str = None) -> str:
	'''Why a job whose name cleaned up to nothing is stopped; raw, when given, is the name as written.'''
	return f"its name{'' if raw is None else f' {raw!r}'} has no letters, digits, '-' or '_' left after cleanup; rename it in {rule_path}"

def nameless_start(rule_path:str, rule):
	'''The start function of a nameless row's supervisor: it fails the job at once, naming this rule's own name. The rule is bound here, so a later row cannot change what it quotes.'''
	raw = raw_job_name(rule)
	def start(job:JobControl, attempt:int) -> list:
		job.fail(nameless_reason(rule_path, raw), permanent=True)
		return []
	return start

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
# a new version copies a file again from the vault rather than link it through more links than its name's threshold,
# from RECOPY_MIN_HOPS to RECOPY_MAX_HOPS (see recopy_threshold()): two below the kernel's 40, which counts every link on
# a path, such as a user's symlink at the end of a chain or the current_version link at its start
RECOPY_MIN_HOPS = 32
RECOPY_MAX_HOPS = 38
# vault folders known to be real, kept so the many links through one folder look at it once
REAL_VAULT_FOLDERS_KEPT = 16384
# manifest rows written or read per statement: enough to amortise sqlite calls, little to hold
MANIFEST_BATCH_SIZE = 10000
# a copy is written under a name of its own with this suffix, in its destination's folder, until it succeeded
PARTIAL_COPY_SUFFIX = '.reverberator-partial'
# the length of the vault's secret for the names pruning links copies under (vault_prune_salt())
PRUNE_SALT_BYTES = 16
# how long a failed backup waits for its stopped copies before it gives up on them
COPY_STOP_WAIT_SECONDS = 60
# a stopping daemon waits less: a stopped command is killed within about a second ( multiCMD sends SIGKILL a second after SIGTERM )
COPY_STOP_GRACE_SECONDS = 2
# a restore puts its copies in place every RESTORE_COPY_BATCH of them, so a whole job's are never all waiting at once
RESTORE_COPY_BATCH = 1000
# copies a restore runs at once unless --threads says otherwise: enough to keep a disk busy, not so many that the
# daemon's own backups to the same vault disk crawl meanwhile
DEFAULT_RESTORE_THREADS = 4
# a restore's progress line is rewritten this often on a terminal, and written again this often anywhere else
RESTORE_PROGRESS_TERMINAL_SECONDS = 1
RESTORE_PROGRESS_LINE_SECONDS = 60
# while a restore copies, these signals only set RESTORE_STOP, which it looks at every RESTORE_WAIT_SECONDS at most:
# a KeyboardInterrupt raised inside the executor's bookkeeping can leave it waiting forever for a thread long gone
RESTORE_STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
RESTORE_STOP = threading.Event()
RESTORE_WAIT_SECONDS = 0.1
# a restore's summary repeats this many of its failures, and of its warnings: each was written as it happened
RESTORE_SUMMARY_LINES = 20
# the entries a restore's marker names as kept without all of their metadata: at most this many, and this many bytes of them
RESTORE_MARKER_UNSET_LIMIT = 1000
RESTORE_MARKER_UNSET_BYTES = 1 << 20
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

tl = LockedLogger(Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=False,noLog=True))

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
			job_log(job.shown_name, f'STOPPED: {failure.reason}')
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
				else:
					# the path can appear, or go again, while the wait lasts
					job.update_wait(token, what)
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
		tl.teeerror(log_text(traceback.format_exc()))
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
		# the daemon only: the commands print prompts without a line break
		install_daemon_output()
		run_daemon()
	except Exception as e:
		import traceback
		tl.teeerror(log_text(traceback.format_exc()))
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
	tl = LockedLogger(Tee_Logger.teeLogger(systemLogFileDir=args.log_dir, programName=args.program_name, compressLogAfterMonths=0, deleteLogAfterYears=args.log_delete_years, suppressPrintout=args.quiet, noLog=args.no_log,callerStackDepth=4,in_place_compression='xz'))
	tl.teeprint(log_text(argString))
	if args.verbose:
		DEBUG = True
	if args.drop_sample_reverb_rule_file:
		rule_path = os.path.abspath(args.rule_path)
		with open(rule_path, 'w', encoding='utf-8') as f:
			f.write(SAMPLE_REVERB_RULE_FILE.strip() + '\n')
		tl.teeok(log_text(f'Dropped sample rule file at {rule_path}'))
		return
	try:
		STATUS_BOARD = StatusBoard(state_dir_path(), os.path.abspath(args.rule_path))
	except Exception as e:
		tl.teeerror(log_text(f'Cannot publish status files: {e}'))
	# warn the user if reverberator is not run as root
	if os.geteuid() != 0:
		tl.teeerror(log_text('Warning: reverberator is not run as root, dynamic nofile tuning will not work. And file permissions can cause errors.'))
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
		tl.teeerror(log_text(f'Error: Rule file {args.rule_path} appears empty after parsing.'))
		daemon_error_log(f'rule file {args.rule_path} has no rules')
		sys.exit(EXIT_ALL_STOPPED)
	# one supervisor per job runs its watcher and backuper, and starts them again after a failure
	supervisors = []
	results = [None] * len(rules)
	colliding = colliding_job_names(rules)
	for index, reverb_rule in enumerate(rules):
		job_name = reverb_rule.job_name
		if job_name == '':
			# a name with nothing left would make the vault root the job's vault: stopped at once, before anything touches it
			# the marker calls it by its row, as the log alerts only accept a name of letters, digits, '-' and '_'
			supervisor = threading.Thread(target=supervise_job,args=(results,index,JobControl(job_name,f'row-{index + 1}'),nameless_start(args.rule_path,reverb_rule),None),name=f'row-{index + 1} supervisor',daemon=True)
			supervisor.start()
			supervisors.append(supervisor)
			continue
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
			tl.teeerror(log_text(f'Error: Rule {job_name} has invalid min_snapshot_delay_seconds value: {reverb_rule.min_shapshot_time}'))
			tl.teeprint(log_text(f"Reverting to default value: {DEFAULT_SNAPSHOT_DELAY}"))
		max_shapshot_delay_seconds = DEFAULT_MAX_DELAY
		try:
			max_shapshot_delay_seconds = int(reverb_rule.max_shapshot_time)
		except Exception as _:
			tl.teeerror(log_text(f'Error: Rule {job_name} has invalid max_snapshot_delay_seconds value: {reverb_rule.max_shapshot_time}'))
			tl.teeprint(log_text(f"Reverting to default value: {DEFAULT_MAX_DELAY}"))
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
			tl.teeerror(log_text(f'Error: Rule {job_name} has invalid keep_n_versions value: {reverb_rule.keep_n_versions}'))
			tl.teeprint(log_text(f"Reverting to default value: {DEFAULT_KEEP_N_VERSIONS}"))
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
		tl.info(log_text(f'Backup thread will keep one complete backup: {keep_one_complete_backup}, only sync attributes: {only_sync_attributes}, keep n versions: {keep_n_versions}, backup size limit: {backup_size_limit}'))
		supervisor = threading.Thread(target=supervise_job,args=(results,index,JobControl(job_name),start_attempt,persist_pending),name=f'{job_name} supervisor',daemon=True)
		supervisor.start()
		supervisors.append(supervisor)
		tl.teeok(log_text(f'Started job {job_name} watching {monitor_path}:{monitor_path_signature} into vault {vault_path}:{vault_path_signature}'))
	for supervisor in supervisors:
		supervisor.join()
	if 'crashed' in results:
		raise RuntimeError(f'a job supervisor crashed: {results}')
	if not GREEN_LIGHT.is_set():
		tl.teeok(log_text('All jobs have exited. Exiting main thread.'))
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
		# cleared first: the log call takes LOG_LOCK, which a thread blocked on a full journal may hold, and the shutdown
		# must start (and a second signal take the other branch) without it
		GREEN_LIGHT.clear()
		tl.teeerror(log_text('Ctrl C caught, cleanning up and exiting... ( can take up to 5 seconds )'))
	else:
		tl.teeerror(log_text('Ctrl C caught again, exiting immediately!'))
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
			"Commands (see each one's --help):\n"
			"  reverberator status\n"
			"  reverberator history PATH\n"
			"  reverberator restore PATH [DEST | --in-place]\n\n"
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

def fsync_path(path:str, folder:bool = False) -> None:
	'''
	fsync the file, or the folder, at path, so a crash leaves what was written to it, or the names in it, on disk. A
	filesystem that cannot sync (EINVAL, ENOTSUP) is passed over; any other error raises.
	'''
	fd = os.open(path, os.O_RDONLY | (os.O_DIRECTORY if folder else os.O_NOFOLLOW))
	try:
		os.fsync(fd)
	except OSError as e:
		if e.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP):
			raise
	finally:
		os.close(fd)

# the private folder write_change_list() writes a change list in before renaming it into place: made by mkdtemp() in
# the job vault, which no reader takes for a version or a change list, and removed by remove_incomplete_vault_versions()
# when a crash leaves it
CHANGE_LIST_FOLDER_PREFIX = '.reverberator-change-list-'

def write_change_list(content_file_name:str, rows:list) -> None:
	'''
	Write a new version's change list, its commit marker, whole or not at all: into a private folder of its own in the
	job vault (mkdtemp(), CHANGE_LIST_FOLDER_PREFIX), fsynced, renamed into place, the job vault fsynced, then the
	private folder removed. No reader ever sees part of its rows, a crash before the rename leaves the version uncommitted,
	removed at the next start, and no name planted or raced in the job vault can take the rows elsewhere. A failed sync
	of the folder after the rename is only logged, as the version is committed by then.
	'''
	job_vault = os.path.dirname(os.path.abspath(content_file_name))
	private = tempfile.mkdtemp(prefix=CHANGE_LIST_FOLDER_PREFIX,dir=job_vault)
	temp_path = os.path.join(private,os.path.basename(content_file_name))
	try:
		TSVZ.appendLinesTabularFile(temp_path,rows,header = ['path']+ BACKUP_ENTRY_VALUES_HEADER,createIfNotExist = True,verifyHeader = True,strict=False,teeLogger=tl,verbose=False)
		fsync_path(temp_path)
		os.replace(temp_path,content_file_name)
		try:
			fsync_path(job_vault,folder=True)
		except OSError as e:
			backuperTeeLogToTl(content_file_name,f'Could not sync the folder of {content_file_name} to disk: {e}',warning=True)
	finally:
		# empty once the list is in place; one a crash leaves, or one not emptied here, is removed at the next start
		with contextlib.suppress(OSError):
			os.remove(temp_path)
		with contextlib.suppress(OSError):
			os.rmdir(private)

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

def resolve_skip_list_path(cell:str, rule_file:str) -> 'str | None':
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
		tl.teeerror(log_text(f'Error: Rule file {rule_file} does not exist.'))
		daemon_error_log(f'rule file {rule_file} does not exist')
		sys.exit(EXIT_ALL_STOPPED)
	try:
		if read_only:
			pass
		elif upgrade_rule_file_header(rule_file):
			tl.info(log_text(f'Upgraded rule file {rule_file} header with the Skip List File column.'))
	except (OSError, ValueError) as e:
		# ValueError: a compressed or non UTF-8 rule file, which TSVZ still reads
		tl.teelog(log_text(f'Warning: Cannot upgrade rule file {rule_file} ({e}). The Skip List File column cannot be used until the header is upgraded.'),level='warning')

	rules = TSVZ.readTabularFile(rule_file,header=REVERB_RULE_TSV_HEADER,verifyHeader=True,strict=False,verbose=False)
	if DEBUG:
		tl.teeprint(log_text(f'Parsed rules: \n{rules}'))
	else:
		tl.info(log_text(f'Parsed rules: \n{rules}'))
	if not rules:
		if read_only:
			raise RuleFileError(f'Rule file {rule_file} has no rules.')
		tl.teeerror(log_text(f'Error: Rule file {rule_file} appears empty after parsing.'))
		daemon_error_log(f'rule file {rule_file} has no rules')
		sys.exit(EXIT_ALL_STOPPED)
	# fill in empty / auto and append:
	rulesToUpdate = {}
	returnReverbRules = []
	for ruleName in rules:
		ruleList = list(rules[ruleName]) + [''] * (len(REVERB_RULE_HEADER) - len(rules[ruleName]))
		if DEBUG:
			tl.teeprint(log_text(f'Checking rule: {ruleList}'))
		ruleUpdated = False
		inRule = OrderedDict(zip(REVERB_RULE_HEADER, ruleList))
		# job_name
		if not inRule['job_name']:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has empty Job Name. Ignoring rule...'),level='warning')
			continue
		cleanedJobName = slugify(inRule['job_name'])
		if not cleanedJobName:
			# kept as written for the messages and the row in the file; the job is stopped, not renamed
			tl.teelog(log_text(f'Warning: Rule {ruleName} has a Job Name with nothing left after cleanup. The job will be stopped.'),level='warning')
			inRule['job_name'] = NamelessJobName(inRule['job_name'])
		elif cleanedJobName != inRule['job_name']:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has dirty Job Name. Changing to {cleanedJobName}'),level='warning')
			inRule['job_name'] = cleanedJobName
			ruleUpdated = True
		# mon_path
		if not inRule['mon_path']:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has empty Path Monitoring. Ignoring rule...'),level='warning')
			continue
		mon_path_exists = os.path.exists(inRule['mon_path'])
		if not mon_path_exists:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has Path Monitoring: {inRule["mon_path"]} which does not exist, the job will wait for it'),level='warning')
		newSourcePath = os.path.realpath(inRule['mon_path']) if mon_path_exists else inRule['mon_path']
		if newSourcePath != inRule['mon_path']:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has dirty Path Monitoring. Changing to {newSourcePath}'),level='warning')
			inRule['mon_path'] = newSourcePath
			ruleUpdated = True
		# vault_path
		if not inRule['vault_path']:
			tl.teelog(log_text(f'Warning: Rule {ruleName} has empty Vault Path. Ignoring rule...'),level='warning')
			continue
		if is_subpath(inRule['vault_path'],inRule['mon_path']):
			tl.teelog(log_text(f'Warning: Rule {ruleName} has Vault Path: {inRule["vault_path"]} which is a subpath of the source path. Ignoring rule...'),level='warning')
			continue
		# mon_fs_signature
		if not mon_path_exists or read_only:
			pass
		elif not inRule["mon_fs_signature"] or inRule["mon_fs_signature"].lower() == 'auto':
			signatures = get_fs_signatures(inRule["mon_path"])
			if signatures and signatures[0]:
				inRule["mon_fs_signature"] = signatures[0]
				tl.teelog(log_text(f'Auto filled Monitoring File System Signature for {ruleName}: {inRule["mon_fs_signature"]}'),level='info')
				ruleUpdated = True
			else:
				tl.teelog(log_text(f'Warning: Rule {ruleName} failed to get the fs signature, disabling fs monitoring for this run...'),level='warning')
				inRule["mon_fs_signature"] = 'auto'
		# min_shapshot_time
		if not inRule["min_shapshot_time"] or inRule["min_shapshot_time"].lower() == 'none':
			inRule["min_shapshot_time"] = '0'
			tl.info(log_text(f'Zeroed Minium snapshot time for {ruleName}: {inRule["min_shapshot_time"]}'))
			ruleUpdated = True
		elif inRule["min_shapshot_time"].lower() == 'auto':
			inRule["min_shapshot_time"] = str(DEFAULT_SNAPSHOT_DELAY)
			tl.info(log_text(f'Auto filled Minium snapshot time for {ruleName}: {inRule["min_shapshot_time"]}'))
			ruleUpdated = True
		# max_shapshot_time
		if not inRule["max_shapshot_time"] or inRule["max_shapshot_time"].lower() == 'none':
			inRule["max_shapshot_time"] = str(DEFAULT_MAX_DELAY)
			tl.info(log_text(f'Auto filled Maximum snapshot time for {ruleName}: {inRule["max_shapshot_time"]}'))
			ruleUpdated = True
		elif inRule["max_shapshot_time"].lower() == 'auto':
			inRule["max_shapshot_time"] = str(DEFAULT_MAX_DELAY)
			tl.info(log_text(f'Auto filled Maximum snapshot time for {ruleName}: {inRule["max_shapshot_time"]}'))
			ruleUpdated = True
		# keep_one_complete_backup
		if not inRule["keep_one_complete_backup"] or inRule["keep_one_complete_backup"].lower() == 'auto' or inRule["keep_one_complete_backup"].lower() == 'none':
			inRule["keep_one_complete_backup"] = str(DEFAULT_KEEP_ONE_COMPLETE_BACKUP)
			tl.info(log_text(f'Auto filled Keep 1 Compelete Backup for {ruleName}: {inRule["keep_one_complete_backup"]}'))
			ruleUpdated = True
		# only_sync_attributes
		if not inRule["only_sync_attributes"] or inRule["only_sync_attributes"].lower() == 'auto' or inRule["only_sync_attributes"].lower() == 'none':
			inRule["only_sync_attributes"] = str(DEFAULT_ONLY_SYNC_ATTRIBUTES)
			tl.info(log_text(f'Auto filled Only Sync Attributes for {ruleName}: {inRule["only_sync_attributes"]}'))
			ruleUpdated = True
		# keep_n_versions
		if not inRule["keep_n_versions"] or inRule["keep_n_versions"].lower() == 'none':
			inRule["keep_n_versions"] = '0'
			tl.info(log_text(f'Zeroed Keep N versions for {ruleName}: {inRule["keep_n_versions"]}'))
			ruleUpdated = True
		elif inRule["keep_n_versions"].lower() == 'auto':
			inRule["keep_n_versions"] = str(DEFAULT_KEEP_N_VERSIONS)
			tl.info(log_text(f'Auto filled Keep N versions for {ruleName}: {inRule["keep_n_versions"]}'))
			ruleUpdated = True
		# backup_size_limit
		if not inRule["backup_size_limit"] or inRule["backup_size_limit"].lower() == 'auto' or inRule["backup_size_limit"].lower() == 'none':
			inRule["backup_size_limit"] = DEFAULT_BACKUP_SIZE_LIMIT
			tl.info(log_text(f'Auto filled Backup Size Limit for {ruleName}: {inRule["backup_size_limit"]}'))
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
					tl.teelog(log_text(f'Warning: Rule {ruleName} with {inRule["vault_path"]} does not exist and failed to create it. Ignoring rule...'),level='warning')
					continue
			signatures = get_fs_signatures(inRule["vault_path"])
			if signatures and signatures[0]:
				inRule["vault_fs_signature"] = signatures[0]
				tl.teelog(log_text(f'Auto filled Vault File System Signature for {ruleName}: {inRule["vault_fs_signature"]}'),level='info')
				ruleUpdated = True
			else:
				tl.teelog(log_text(f'Warning: Rule {ruleName} failed to get the fs signature, disabling fs monitoring for this run...'),level='warning')
				inRule["vault_fs_signature"] = 'auto'
		# check if the rule is explicit
		if ruleUpdated:
			tl.info(log_text(f'Updating rule {ruleName}: {inRule}'))
			rulesToUpdate[ruleName] = list(inRule.values())
		returnReverbRules.append(ReverbRule(**inRule))
	# rewrite the updated rows in place once; a row whose cleaned name collides with another's is left as written,
	# as renaming it would merge the two rows in the file; a row whose name cleaned to nothing is left as written too
	colliding = colliding_job_names(returnReverbRules)
	rulesToUpdate = {name:row for name,row in rulesToUpdate.items() if row[0] not in colliding and row[0] != ''}
	if rulesToUpdate and not read_only:
		try:
			rewrite_rule_rows(rule_file,rulesToUpdate)
		except (OSError, ValueError) as e:
			# ValueError: a compressed or non UTF-8 rule file; the rules in memory are still right
			tl.teelog(log_text(f'Warning: Cannot write the filled in rows back to {rule_file} ({e}).'),level='warning')
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
			task = multiCMD.run_command(['sysctl',field],timeout=1,quiet=True,return_object=True)
			rtn = task.stdout
			if self.debug:
				# quiet, so multiCMD shows nothing: sysctl's error text is logged here
				tl.teeprint(log_text(f'sysctl {field}: {rtn}' + (f' {task.stderr}' if task.stderr else '')))
			if rtn and rtn[0]:
				return int(rtn[0].split('=')[-1].strip())
		except Exception as _:
			import traceback
			tl.error(log_text(traceback.format_exc()))
			tl.error(log_text(f'Failed to get {field} value'))
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
				tl.info(log_text(f'Current {field} is already higher than {value}'))
				setattr(self,value_name,rtn)
				return False
			task = multiCMD.run_command(['sudo','sysctl',f'{field}={value}'],timeout=1,quiet=True,return_object=True)
			rc = task.returncode
			if self.debug:
				# quiet, so multiCMD shows nothing: sudo's and sysctl's error text is logged here
				tl.teeprint(log_text(f'sudo sysctl {field}={value} return code = {rc}' + (f' {task.stderr}' if task.stderr else '')))
			else:
				tl.info(log_text(f'sudo sysctl {field}={value} return code = {rc}'))
			if rc:
				if self.debug:
					tl.teeprint(log_text(f'Failed to set {field} to {value}'))
				else:
					tl.info(log_text(f'Failed to set {field} to {value}'))
				setattr(self,f'can_set_{value_name}',False)
				if rtn:
					setattr(self,value_name,rtn)
				return False
			else:
				tl.teeok(log_text(f'Increased inotify {field} to {value}'))
				setattr(self,value_name,value)
				return True
		except Exception as _:
			try:
				import traceback
				tl.error(log_text(traceback.format_exc()))
				tl.teeerror(log_text(f'Failed to set {field} = {value} for {value_name}'))
				setattr(self,f'can_set_{value_name}',False)
				rtn = self.getSysctlValues(field)
				if rtn:
					setattr(self,value_name,rtn)
				else:
					setattr(self,value_name,-1)
			except Exception as _:
				tl.teeerror(log_text(f'Failed to set {field} value'))
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
					tl.teeprint(log_text(f'Current open file limit is already higher than {nofile}'))
				else:
					tl.info(log_text(f'Current open file limit is already higher than {nofile}'))
				self.max_no_files = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
				return False
			rtn = self.__increaseSystemNoFiles(nofile)
			resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
			tl.teeok(log_text(f'Increased open file limit to {nofile}'))
			self.max_no_files = nofile
			return rtn
		except Exception as _:
			import traceback
			tl.error(log_text(traceback.format_exc()))
			tl.teeerror(log_text(f'Failed to increase open file limit to {nofile}'))
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
	# the whole line is cut once, so that its notice counts every byte left out
	message = log_text(f'{WATCHER_LOG_PREFIX}| {monitor_path} | {message}')
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
			verbose=False,
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
		times = [float(row[0]) for row in pending_rows_raw.values()]
		# the times are of the monotonic clock, which starts again at each boot: rows written before this boot, or with a
		# time this boot's clock has not reached, are moved by one offset, so the newest is when the file was written on
		# this boot's clock ( now, for a file dated in the future ), and their order and spacing stay
		offset = 0.0
		if times and (pending_mtime < time.time() - time.monotonic() - 1.0 or max(times) > time.monotonic()):
			offset = time.monotonic() - (time.time() - min(pending_mtime, time.time())) - max(times)
			if pending_mtime > time.time():
				why = 'are dated in the future, so the clock was set back since they were written'
			elif pending_mtime < time.time() - time.monotonic() - 1.0:
				why = 'were written before this boot'
			else:
				why = "hold times this boot's clock has not reached"
			backuperTeeLogToTl(job_name, f'Pending transactions {pending_transactions_path} {why}, moving their times by {offset:.0f}s')
		for event_time, row in zip(times, pending_rows_raw.values()):
			# the paths as pending_transaction_rows() wrote them
			moved_from = row[4]
			if moved_from == '':
				moved_from = None
			to_process.append(ChangeEvent(
				event_time + offset,
				row[1] in (True, 'True', 'true', '1', 1),
				row[2],
				stored_name(row[3]),
				None if moved_from is None else stored_name(moved_from)
			))
			loaded_count += 1
		if any(row[2] != 'scan' for row in pending_rows_raw.values()) and not to_process.full_scan_requested:
			# a batch handed back before the stop was saved as its collapsed entries only
			to_process.round_tripped = True
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
	rtnHost = multiCMD.run_command(['df','--no-sync','--output=source',path],timeout=60,quiet=True,return_object=True)
	if rtnHost.returncode != 0 or not rtnHost.stdout or len(rtnHost.stdout) <= 1:
		return []
	deviceName = rtnHost.stdout[1].split()[0]
	rtnHost = multiCMD.run_command(['lsblk','--raw','--output=uuid,label,partuuid,partlabel,wwn,serial,model,name,kname,pkname',deviceName],timeout=60,quiet=True,return_object=True)
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

def mount_holding(mount_table:list, path:str):
	'''
	(mount point, source) of the mount holding path, the one mount_fingerprint() finds; None when the table has none.

	Examples:
		>>> mount_holding([('/', (b'1', b'8:1', b'/', b'/dev/sda1')), ('/mnt/a', (b'2', b'8:17', b'/', b'/dev/sdb1'))], '/mnt/a/x')
		('/mnt/a', '/dev/sdb1')
		>>> mount_holding([], '/mnt') is None
		True
	'''
	fingerprint = mount_fingerprint(mount_table, path)
	if fingerprint is None:
		return None
	# the mount id makes a fingerprint the one of a single mount
	return next(point for point, mount in mount_table if mount == fingerprint), os.fsdecode(fingerprint[3])

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
	# what its raw events touched, verified after its replay; None for a full comparison or a batch of scans only
	touched = None
	full_comparison = False
	# whether the batch is one handed back or resumed, whose events are only its collapsed entries
	round_tripped = False
	def batch_scopes(batch):
		scopes = touched_scopes(batch, monitor_path)
		return scopes if scopes.subtrees or scopes.paths else None
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
				backupEntries = change_events_to_backup_entries(to_process_temp,monitor_path)
				scan_folders = [event.path for event in to_process_temp if event.event == 'scan']
				touched = batch_scopes(to_process_temp)
				round_tripped = to_process_temp.round_tripped
				backuperTeeLogToTl(job_name, f'Converted events queued at startup into {len(backupEntries)} backup entries and {len(scan_folders)} folders to compare')
		vaultInfo = None
		# to_process: ChangeEventQueue of ChangeEvent(monotonic_time, is_dir, event, path, moved_from), oldest first
		while running():
			wait_for_path(job, vault_fs_flag, vault_path, 'vault filesystem not ready')
			if not running():
				break
			# an unreadable path is reported once for the batch, by its comparison or its backup
			reported = set()
			# whether the whole tree is compared right after this batch
			follow_up = False
			if scan_folders and not full_comparison:
				vaultInfo,manifest,full_comparison = compare_scanned_folders(backupEntries,scan_folders,job_name,monitor_path,vault_path,
					vaultInfo=vaultInfo,manifest=manifest,skip_list=skip_list,root_mount=root_mount,reported=reported)
				if not running():
					break
				if full_comparison:
					backupEntries.clear()
				elif not backupEntries and touched is None:
					backuperTeeLogToTl(job_name,'Compared folders match the vault; no new version for this batch',ok=True)
					# done, as a full comparison finding no differences is
					if job is not None:
						job.mark_committed()
			else:
				# do_backup compares the whole tree for an empty batch, and only what its events touched for a batch whose
				# events collapsed to no entry
				full_comparison = full_comparison or (not backupEntries and touched is None)
			if backupEntries or full_comparison or touched is not None:
				vaultInfo,manifest,committed = do_backup(backupEntries,job_name=job_name,monitor_path=monitor_path,vault_path=vault_path,
					  keep_one_complete_backup=keep_one_complete_backup,only_sync_attributes=only_sync_attributes, keep_n_versions=keep_n_versions, 
					  backup_size_limit=backup_size_limit, log_journal=log_journal,vaultInfo=vaultInfo,manifest=manifest,skip_list=skip_list,root_mount=root_mount,
					  reported=reported,touched=None if full_comparison else touched)
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
				if round_tripped and not full_comparison:
					# the collapse can drop a path its entries no longer name, as git's ref deleted after a rename over it:
					# the verification compared only what they name, so the whole tree is compared next, as at a start
					# with nothing to resume. it runs now, without waiting for the watcher's signal, and the queue is left
					# to the watcher: its new folders' events are recorded again only once it sees its batch taken
					backuperTeeLogToTl(job_name,'The batch backed up was handed back or resumed, keeping only its collapsed entries: comparing the whole tree next')
					follow_up = True
			backupEntries.clear()
			scan_folders = []
			touched = None
			# a stop before it runs saves it as a full scan request, as any full comparison
			full_comparison = follow_up
			round_tripped = False
			# a batch whose events collapsed to no entry is backed up too, as what they touched can differ from the vault
			while not backupEntries and not full_comparison and not scan_folders and touched is None and running():
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
					backupEntries = change_events_to_backup_entries(to_process_temp,monitor_path)
					scan_folders = [event.path for event in to_process_temp if event.event == 'scan']
					touched = batch_scopes(to_process_temp)
					round_tripped = to_process_temp.round_tripped
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
		if full_comparison or backupEntries or scan_folders or touched is not None:
			# for the job's next attempt, or the pending transactions when the daemon stops. the scans go back too, so
			# their folders are compared again with what is there then. a batch whose events collapsed to no entry has
			# none to hand back for what they touched: the whole tree is compared instead
			with to_process_lock:
				if full_comparison or (touched is not None and not backupEntries):
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
	# the whole line is cut once, so that its notice counts every byte left out
	message = log_text(f'{BACKUPER_LOG_PREFIX}| {path} | {message}')
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

def touched_scopes(events, monitor_path:str) -> 'TouchedScopes':
	'''
	What a batch's raw watcher events touched in monitor_path, for the comparison after its replay: each event's path
	and each move's source, as the collapse into backup entries can lose some of them.
	A folder created, deleted or moved is a subtree (its rel ending with /), compared with everything under it; a folder
	whose attributes or contents changed is a path ending with /, compared alone; a file is a path. Each name is also
	compared as the other kind, as the batch may not say what it replaced: a file as a subtree, whose walk finds it and
	any rows of a folder it replaced, and a folder as the file path. Scans, full scans, self destructs, the root itself
	and paths outside monitor_path are left out, and so is a scope inside a subtree (a path inside one above it: its own
	subtree can be skipped by a pattern for folders, which the file is not).

	Examples:
		>>> touched_scopes([ChangeEvent(1.0, True, 'move', '/m/E', '/m/D'), ChangeEvent(2.0, False, 'modify', '/m/E/f', None),
		...     ChangeEvent(3.0, True, 'attrib', '/m/A', None), ChangeEvent(4.0, False, 'move', '/m/b', '/m/a'),
		...     ChangeEvent(5.0, True, 'attrib', '/m', None), ChangeEvent(6.0, True, 'create', '/m/N', '/elsewhere'),
		...     ChangeEvent(7.0, True, 'scan', '/m/S', None)], '/m')
		TouchedScopes(subtrees=['D/', 'E/', 'N/', 'a/', 'b/'], paths=['A', 'A/', 'D', 'E', 'N', 'a', 'b'])
		>>> touched_scopes([ChangeEvent(1.0, False, 'modify', '/etc/x', None), ChangeEvent(2.0, True, 'attrib', '/', None)], '/')
		TouchedScopes(subtrees=['etc/x/'], paths=['etc/x'])
	'''
	root = os.path.abspath(monitor_path)
	def rel_of(path):
		rel = os.path.relpath(os.path.abspath(path), root)
		# the root itself, or a path outside it, is None
		return None if rel == '.' or rel == '..' or rel.startswith('../') else rel
	subtrees = set()
	paths = set()
	for event in events:
		if event.event in ('scan', 'full_scan', 'self_destruct'):
			continue
		rels = [rel_of(event.path)]
		if event.event == 'move' and event.moved_from:
			rels.append(rel_of(event.moved_from))
		rels = [rel for rel in rels if rel is not None]
		if event.is_dir and event.event in ('create', 'delete', 'move'):
			subtrees.update(rel + '/' for rel in rels)
		elif event.is_dir:
			# chmod, touch or setfattr on a folder change only the folder
			paths.update(rel + '/' for rel in rels)
		else:
			paths.update(rels)
			# a file made where a folder was ( rm -rf L; echo > L ) leaves that folder's rows under L/
			subtrees.update(rel + '/' for rel in rels)
		if event.is_dir:
			# a folder made where a file was leaves the file's row
			paths.update(rels)
	subtrees = sorted(rel for rel in subtrees if not inside_folders(rel, subtrees))
	kept = set(subtrees)
	def covered(rel):
		# by a subtree above it, or for a folder by its own subtree
		folders = scope_folders(rel)
		return any(folder in kept for folder in (folders if rel.endswith('/') else folders[:-1]))
	return TouchedScopes(subtrees, sorted(rel for rel in paths if not covered(rel)))

def change_events_to_backup_entries(change_events:deque, monitor_path:str = None) -> OrderedDict:
	'''
	Collapse a chronological batch of watcher ChangeEvents into backup entries.

	An event on monitor_path itself (by default the monitored path of a ChangeEventQueue given), such as the attrib the
	watcher reports for the root folder, gives no entry: the version folder is no entry of itself. Nor does a move onto
	itself, as a folder moved away and back in one batch collapses to; the comparison after the replay checks it.

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
		>>> change_events_to_backup_entries(deque([ChangeEvent(1.0, True, 'attrib', '/tmp/reverb_doctest', None),
		...     ChangeEvent(2.0, True, 'move', '/tmp/reverb_doctest/D2', '/tmp/reverb_doctest/D'),
		...     ChangeEvent(3.0, True, 'move', '/tmp/reverb_doctest/D', '/tmp/reverb_doctest/D2')]), '/tmp/reverb_doctest/')
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
	if monitor_path is None:
		monitor_path = getattr(change_events, 'monitor_path', '') or None
	root = None if monitor_path is None else os.path.abspath(monitor_path)
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
		if os.path.abspath(changeEvent.path) == root:
			# the monitored root itself ( an attrib on it ): its version is the version folder, no entry of it
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
	for path in [path for path, values in backup_entries.items() if values.event == 'move' and values.source_path == path]:
		# moved away and back ( mv D D2; mv D2 D ): nothing to rename
		backuperTeeLogToTl(path,f'Dropping the move of {path} onto itself')
		del backup_entries[path]
	backuperTeeLogToTl('convertor','Converted backup entries')
	if DEBUG:
		backuperTeeLogToTl('convertor','\n'+multiCMD.pretty_format_table(backup_entries,header = ['path'] + BACKUP_ENTRY_VALUES_HEADER))
	return backup_entries

def entry_row(path:str, values:'BackupEntryValues') -> list:
	'''
	The row a change list or the journal records the backup entry of path with. TSVZ writes a lone surrogate as '?', so
	both paths are written as storable_name() gives them, which iter_change_list() turns back.

	Examples:
		>>> entry_row('/m/b\\udcff', BackupEntryValues('t', 'move', '/m/a')), entry_row('/m/c', BackupEntryValues('t', 'create', None))
		(['/m/b\\U0010fe00\\U0010ffff', 't', 'move', '/m/a'], ['/m/c', 't', 'create', None])
	'''
	source = values.source_path
	return [storable_name(path), values.iso_time, values.event, source if source is None else storable_name(source)]

def log_to_journal(journal_path:str, at_path:str, event:str, source_path:str):
	'''Add a row for one step of a backup to the journal, its paths as entry_row() writes them.'''
	TSVZ.appendTabularFile(journal_path,[storable_name(at_path),datetime.datetime.now().isoformat(),event,storable_name(source_path)],teeLogger=tl,header=BACKUP_JOURNAL_HEADER,createIfNotExist=True,verifyHeader=True,strict=False)

def log_events_to_journal(backup_entries:dict,journal_path:str):
	# this function will log the journal of the changes
	# the journal will be a nsv file with the following fields:
	# monotonic_time, event, type, path
	# this will be used to recover the changes in the case of a crash
	global tl
	lines = [entry_row(path,entry) for path,entry in backup_entries.items()]
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

def drop_unmounted_entries(backup_entries:dict, job_name:str, monitor_path:str, root_mount, remembered_mounts:list, mount_table:list, skip, paused:set, walk:str) -> set:
	'''
	After a walk of the monitored tree (named by walk in the log): a disk unmounted while it ran was walked as the empty
	folder it left, so what the walk found under it is dropped from backup_entries, and its rows are linked forward as
	for a disk paused before the walk. JobFailure is raised when the monitored root itself shows another filesystem than
	root_mount. mount_table is the one read before the walk, remembered_mounts the inner mounts the manifest recorded.
	Returns paused with the inner mounts that went away added.
	'''
	walked_table = current_mount_table()
	check_monitored_mount(monitor_path,walked_table,root_mount)
	seen_mounts = sorted(set(remembered_mounts) | inner_mount_rels(mount_table,monitor_path,skip))
	unmounted = paused_inner_mounts(monitor_path,seen_mounts,walked_table,skip) - paused
	if unmounted:
		dropped = drop_entries_under(backup_entries,[os.path.abspath(os.path.join(monitor_path,rel)) + '/' for rel in unmounted])
		backuperTeeLogToTl(job_name,f'Inner mounts unmounted during the {walk}, keeping their last backed-up contents: {", ".join(sorted(unmounted))}; dropped {dropped} backup entries')
	return paused | unmounted

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
			 vaultInfo:VaultInfo = None,manifest:'VaultManifest' = None,skip_list:'SkipList' = None,root_mount = None,reported:set = None,
			 touched:'TouchedScopes' = None):
	# returns (vaultInfo, manifest, committed): pass both back in for the next backup of this job
	# root_mount: the fingerprint of the mount the monitored path showed when the job started, when it is to be checked
	# reported: the unreadable paths already logged for this batch, so each is logged once
	# touched: touched_scopes() of the batch's raw events, verified after the replay ( see do_reverb_backup ); a full
	# comparison has none. with no backup_entries, only the touched scopes are compared with the latest version: a new
	# version, its replay verified with touched, is made only when they differ
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
			log_to_journal(journalPath,monitor_path,f'start_reverb_backup_{len(backup_entries)}_enties',job_vault)
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
		# the files the new version copied again from the vault, and those of them its batch then wrote over
		recopied = []
		recopies_rewritten = set()
		# what the verification of the replay fixed, written after the batch's own rows
		verified = []
		if not vault_info_dict:
			backuperTeeLogToTl(job_name,f'Failed to get any version for {job_vault}, treating the vault as new.',error=True)
			this_version_number = 0
			this_timestamp = datetime.datetime.now().astimezone().strftime(VAULT_TIMESTAMP_FORMAT)
			backup_folder = os.path.join(job_vault,f'V0--{this_timestamp}')
			if not make_version_folder(job_name,backup_folder):
				return VaultInfo(vault_info_dict, vault_size, vault_inodes), manifest, False
			manifest.begin()
			if keep_one_complete_backup:
				backuperTeeLogToTl(job_name,f'Creating a complete backup of {monitor_path} to {backup_folder}',ok=True)
				if log_journal:
					log_to_journal(journalPath,monitor_path,'initial_complete_backup',backup_folder)
				manifest.reset(backup_folder)
				mcae = multiCMD.AsyncExecutor(semaphore=BACKUP_SEMAPHORE,quiet=True)
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
					log_to_journal(journalPath,monitor_path,'initial_referenced_backup',backup_folder)
				walk_errors = []
				# its files are links to the monitored ones, not copies, but the chains of later versions end in it as they
				# would at a copy ( a re-copy copies such a link as it is ), so they count as copied in V0
				manifest.rebuild(backup_folder,tree_path=monitor_path,skip=walk_skip,errors=walk_errors,copy_version=this_version_number)
				check_walk_errors(job_name,monitor_path,walk_errors,manifest,reported)
				do_referenced_copy(monitor_path,backup_folder,manifest)
		else:
			# Now we have made sure the vault is within the size limit, we can proceed to do the backup
			latest_version_info = vault_info_dict[next(reversed(vault_info_dict))]
			if not backup_entries:
				if touched is None:
					backuperTeeLogToTl(job_name,'Empty backup entries, Delta generating backup entries')
				else:
					# events that cancel out in the collapse ( a file replaced, then deleted ) can still have changed the
					# tree: what they touched is compared, and what differs is replayed and verified as a batch is
					backuperTeeLogToTl(job_name,'The batch collapsed to no backup entries, comparing the places it touched with the vault')
				delta_generate_backup_entries(backupEntries=backup_entries,latest_version_info=latest_version_info,monitor_path=monitor_path,manifest=manifest,skip_list=skip_list,job_name=job_name,reported=reported,
					scope_rel='' if touched is None else touched,paused=paused)
				if not GREEN_LIGHT.is_set():
					# a partial delta would be kept as pending transactions, and a restart replays those instead of comparing again
					backup_entries.clear()
					backuperTeeLogToTl(job_name, 'Delta generation interrupted; not creating a new version', error=True)
					return VaultInfo(vault_info_dict, vault_size, vault_inodes), manifest, False
				paused = drop_unmounted_entries(backup_entries,job_name,monitor_path,root_mount,remembered_mounts,mount_table,skip,paused,'comparison')
				if log_journal:
					log_to_journal(journalPath,monitor_path,f'delta_generated_{len(backup_entries)}_differences',monitor_path)
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
			this_version_number = latest_version_info.version_number + 1
			# the monitored paths the committed versions were written under, as this backup's own connection reads them:
			# pruning and the chains of the re-copy tell their links by them
			monitor_paths = manifest_monitor_paths(manifest)
			# the files whose link chains would pass their threshold are copied again from the vault, so the size limit
			# counts them too ( a copy in a link's place takes no inode more ). removing the oldest version moves its
			# copies into the next one, which shortens their chains: they are counted again after each removal.
			# a file this batch deletes is not copied again; one it writes over is ( batch_rewrites() ), so a copy of it that
			# fails leaves no chain past its threshold, but its bytes are counted once, and its own entry, not a recopy row,
			# says what the version did with it. the batch is read for that only when a file is due
			def count_recopies():
				oldest_kept = next(iter(vault_info_dict))
				# a pass each time: the chains are walked again after each removal
				moves = VaultMoves(job_vault,monitor_path,monitor_paths)
				rels = recopy_rels(manifest,this_version_number,oldest_kept,job_vault,latest_version_info.path,moves)
				rewritten, deleted = batch_rewrites(backup_entries,monitor_path,only_sync_attributes,rels) if rels else (set(), set())
				rels = [rel for rel in rels if rel not in deleted]
				return oldest_kept, rels, rewritten, recopy_size([rel for rel in rels if rel not in rewritten],job_vault,latest_version_info.path,moves)
			recopies_oldest, recopies, recopies_rewritten, recopies_size = count_recopies()
			if recopies:
				backuperTeeLogToTl(job_name,f'{len(recopies)} files to copy again from the vault, as their link chains would pass their limit: estimated size {recopies_size}')
			estimated_backup_inode = latest_version_info.inode + estimated_backup_inode_change
			backuperTeeLogToTl(job_name,f'Estimated backup inodes {estimated_backup_inode}')
			vault_fs_size, vault_fs_inode = get_path_fs_info(vault_path)
			backuperTeeLogToTl(job_name,f'Got vault fs size {vault_fs_size} and vault fs inode {vault_fs_inode}')
			backup_limit_size, backup_limit_inode = get_backup_limits_from_str(backup_size_limit=backup_size_limit,vault_fs_size=vault_fs_size,vault_fs_inode=vault_fs_inode)
			backuperTeeLogToTl(job_name,f'Calculated backup size limit {backup_limit_size} and backup inode limit {backup_limit_inode}')
			backuperTeeLogToTl(job_name,f'Vault size {vault_size} and vault inodes {vault_inodes}')
			# why the loops below postponed removing a version: each loop tries again, but only the first says so
			postponed = []
			# the vault's secret for the names pruning links copies under, read from its file (made, the first time) when a
			# removal is first tried
			prune_salt = []
			def remove_oldest() -> bool:
				# prune_oldest(), vault_size and vault_inodes kept the sums of the versions' records: whether the oldest version
				# went, the only sign of progress, as finishing a removal cut short frees nothing more, and a removal kept
				# can change the records too, by the links it replaced first
				nonlocal vault_size, vault_inodes
				if not prune_salt:
					prune_salt.append(vault_prune_salt(job_vault, job_name, manifest))
				oldest = next(iter(vault_info_dict))
				removed_size, removed_inodes = prune_oldest(vault_info_dict,job_name,monitor_path,postponed,monitor_paths=monitor_paths,prune_salt=prune_salt[0])
				vault_size -= removed_size
				vault_inodes -= removed_inodes
				return next(iter(vault_info_dict), None) != oldest
			if backup_limit_size:
				while vault_size + estimated_backup_size + recopies_size > backup_limit_size:
					backuperTeeLogToTl(job_name,f'Vault size {vault_size} + estimated backup size {estimated_backup_size + recopies_size} exceeds backup size limit {backup_limit_size}')
					# we need to remove the oldest version
					if not remove_oldest():
						break
					if recopies:
						recopies_oldest, recopies, recopies_rewritten, recopies_size = count_recopies()
			if backup_limit_inode:
				while vault_inodes + estimated_backup_inode > backup_limit_inode:
					backuperTeeLogToTl(job_name,f'Vault inodes {vault_inodes} + estimated backup inodes {estimated_backup_inode} exceeds backup inode limit {backup_limit_inode}')
					# we need to remove the oldest version
					if not remove_oldest():
						break
			while keep_n_versions and len(vault_info_dict) >= keep_n_versions:
				backuperTeeLogToTl(job_name,f'Vault has {len(vault_info_dict)} versions, exceeding keep n versions {keep_n_versions}')
				# we need to remove the oldest version
				if not remove_oldest():
					break
			if recopies and next(iter(vault_info_dict)) != recopies_oldest:
				recopies_oldest, recopies, recopies_rewritten, recopies_size = count_recopies()
			this_timestamp = datetime.datetime.now().astimezone().strftime(VAULT_TIMESTAMP_FORMAT)
			backup_folder = os.path.join(job_vault,f'V{this_version_number}--{this_timestamp}')
			if not make_version_folder(job_name,backup_folder):
				return VaultInfo(vault_info_dict, vault_size, vault_inodes), manifest, False
			backuperTeeLogToTl(job_name,f'Creating a reverb backup of {monitor_path} to {backup_folder}',ok=True)
			def recheck_mounts(fixes):
				# the verification walked the tree too
				nonlocal paused
				paused = drop_unmounted_entries(fixes,job_name,monitor_path,root_mount,remembered_mounts,mount_table,skip,paused,'verification')
			do_reverb_backup(backup_entries,backup_folder,latest_version_info,only_sync_attributes,manifest,monitor_path,skip_list,job_name,reported,
				recopy=recopies,recopied=recopied,touched=touched,paused=paused,verified=verified,recheck_mounts=recheck_mounts)
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
		# a copy made again is no change: its own event, which history and the restore picker pass over. one the
		# verification then deleted, by itself or with a folder above it, is gone from the version
		recopy_time = datetime.datetime.now().isoformat()
		verified_deletes = {os.path.relpath(path,monitor_path) + ('/' if path.endswith('/') else '') for path,values in verified if values.event == 'delete'}
		content_file_content = [entry_row(os.path.join(monitor_path,rel),BackupEntryValues(recopy_time,'recopy',None)) for rel in recopied
			if rel not in recopies_rewritten and rel not in verified_deletes and not inside_folders(rel,verified_deletes)]
		content_file_content += [entry_row(path,values) for path,values in backup_entries.items()]
		content_file_content += [entry_row(path,values) for path,values in verified]
		# commit before the content file: without one the version is removed at startup, and a manifest
		# describing a removed version is listed again from the vault
		manifest.set_skip_fingerprint(skip_list.fingerprint if skip_list is not None else '')
		# a disk mounted while this backup walked is remembered too
		manifest.set_inner_mounts(inner_mounts_to_remember(monitor_path,remembered_mounts,paused,mount_table,current_mount_table(),skip=skip))
		# the change list's rows are absolute paths: which monitored path they are read under
		manifest.note_monitor_path(this_version_number,monitor_path)
		manifest.commit(backup_folder)
		write_change_list(content_file_name,content_file_content)
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
			log_to_journal(journalPath,monitor_path,f'end_reverb_backup_{tracked_files}files_{tracked_folders}folders_tracked',job_vault)
		return VaultInfo(vault_info_dict,vault_size,vault_inodes), manifest, True
	except BaseException:
		if opened_manifest:
			manifest.close()
		raise

def make_version_folder(job_name:str, path:str) -> bool:
	'''
	Make path, the folder of the version a backup is about to write, which must not be there: the referenced copy and
	the complete backup write into it as into an empty folder of their own, and a leftover of that name (an attempt
	that did not commit, in the same second) could hold a link they would write through. When something is there,
	an error line says so and nothing is made: the attempt fails, the next one gets a name of its own, and the leftover
	goes at the next start, as any incomplete version does (remove_incomplete_vault_versions()). Other errors are
	raised.
	'''
	try:
		os.mkdir(path)
	except FileExistsError:
		backuperTeeLogToTl(job_name,f'Not backing up into {path}: something is there already, left by an attempt that did not commit; this attempt fails and writes nothing',error=True)
		return False
	return True

def pending_transaction_rows(events) -> list:
	'''
	Rows to persist the queued events with.

	Examples:
		>>> [row[0] for row in pending_transaction_rows([ChangeEvent(5.0, False, 'create', '/m/a', None), ChangeEvent(5.0, False, 'create', '/m/b', None)])]
		[5.0, 5.000001]
		>>> pending_transaction_rows([ChangeEvent(1.0, False, 'move', '/m/b\\udcff', '/m/a')])[0][3:]
		['/m/b\\U0010fe00\\U0010ffff', '/m/a']
	'''
	rows = []
	last_time = None
	for event in events:
		# rows are keyed by their time when read back, and events from one inotify read share it: space them apart
		event_time = event.monotonic_time
		if last_time is not None and event_time <= last_time:
			event_time = last_time + 1e-6
		last_time = event_time
		# TSVZ writes a lone surrogate as '?': the paths go in as storable_name() gives them
		rows.append([
			event_time,
			event.is_dir,
			event.event,
			storable_name(event.path),
			storable_name(event.moved_from) if event.moved_from is not None else ''
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
			verbose=False
		)
		backuperTeeLogToTl(job_name, f'Saved {len(pending_rows)} pending transactions to {pending_transactions_path}')
	except Exception as e:
		backuperTeeLogToTl(job_name, f'Failed to save pending transactions to {pending_transactions_path}: {e}', error=True)

# what a change list's name holds after its version folder's name and --: the size and inodes it records, as
# change_list_path() writes them (format_bytes(), its spaces as _ or left out), and the change list extension
CHANGE_LIST_RECORD = re.compile(r'([0-9]+(?:\.[0-9]+)?)_?((?:[KMGTP]i)?)B-([0-9]+(?:\.[0-9]+)?)([KMGTP]?)_ino' + re.escape(CONTENT_FILE_EXTENSION_NAME))

def change_list_record(rest:str):
	'''
	(size, inodes) as rest, a change list's name after its version folder's name and --, records them; None when rest
	is not that.

	Examples:
		>>> [change_list_record(rest) for rest in ('12.00_KiB-4.00_ino.modified_contents.nsv', '1.50_GiB-1.50K_ino.modified_contents.nsv', '1_B-1_ino.modified_contents.nsv')]
		[(12288, 4), (1610612736, 1500), (1, 1)]
		>>> [change_list_record(rest) for rest in ('12--00_KiB-4.00_ino.modified_contents.nsv', '12.00_KiB-4.00_ino', '12.0.modified_contents.nsv', '١_B-1_ino.modified_contents.nsv')]
		[None, None, None, None]
	'''
	match = CHANGE_LIST_RECORD.fullmatch(rest)
	if match is None:
		return None
	size_number, size_unit, inodes_number, inodes_unit = match.groups()
	return format_bytes(size_number + size_unit, to_int=True), format_bytes(inodes_number + inodes_unit, use_1024_bytes=False, to_int=True)

# what read_job_vault() found in a job vault: versions, {number: VaultEntry} with the size and inodes its change list
# records; change_lists, {number: that list's path}; orphans, the paths of the version folders without a change list that
# may go; stale, the paths of the change lists whose version folder is not there and whose number no folder there
# carries; kept, the names of the entries kept as they are, though they name no folder there (whose name cannot be read,
# or of a number a folder there carries); unfinished, the private folders of change lists a crash cut off before
# write_change_list() renamed them into place
VaultListing = namedtuple('VaultListing', ['versions', 'change_lists', 'orphans', 'stale', 'kept', 'unfinished'])

def read_job_vault(job_vault_path:str) -> VaultListing:
	'''
	What job_vault_path holds, read whole before anything in it is deleted; None when there is no job vault (it is not
	there: FileNotFoundError alone says so).

	A version folder is a folder (not a link to one) named V<n>--<timestamp>, n in ASCII digits and the timestamp
	VAULT_TIMESTAMP_FORMAT's (is_version_folder_name()); any other folder is no version, and is left alone. An entry of
	any type but a version folder belongs, as a change list, to each folder whose name, then --, begins its own name,
	matched by name before anything is parsed, so a list whose name cannot be read, or that is no file, still keeps its
	folder from being taken for an orphan. A version is a version folder with one change list, a regular file whose name
	is the folder's, --, and the record change_list_record() reads.

	A version folder without a change list, an orphan, may go only when no committed version is there, or when its
	number is above the newest (a backup that did not commit) or below the oldest (a removal cut short, which
	materialised every link into it first); one between them is a committed version whose list the listing did not
	show. A change list that names no folder there is stale, to be deleted, only when it is a regular file, its folder's
	name is well formed, that folder is not there, and no folder there carries its number. Any other entry that names no
	folder there is kept, and holds back the orphans of its number (every orphan when its number cannot be read).

	Raises VaultScanError, with nothing to be deleted, when the job vault cannot be looked at or listed, or an entry in
	it cannot; when an entry with a version folder's name is a link; when an entry named after a folder there cannot be
	read as its change list (a committed version would be left out silently); when two version folders have one number,
	or one has two change lists; when an entry with a change list's name for no folder there is no regular file, or
	names a version folder that cannot be told gone; and when an orphan may not go.
	'''
	try:
		os.lstat(job_vault_path)
	except FileNotFoundError:
		return None
	except OSError as e:
		raise VaultScanError(f'cannot look at the vault {job_vault_path}: {e}')
	# every folder named V...--, by name: its path; and every entry so named but a version folder, as (name, path,
	# regular file), each looked at as itself, never through a link
	folders = {}
	entries = []
	unfinished = []
	try:
		for entry in os.scandir(job_vault_path):
			name = entry.name
			if name.startswith(CHANGE_LIST_FOLDER_PREFIX):
				if entry.is_dir(follow_symlinks=False):
					unfinished.append(entry.path)
				continue
			if not (name.startswith('V') and '--' in name):
				continue
			version_form = is_version_folder_name(name)
			if version_form and entry.is_symlink():
				raise VaultScanError(f'{name} in {job_vault_path} has a version folder\'s name but is a link')
			is_dir = entry.is_dir(follow_symlinks=False)
			if is_dir:
				folders[name] = entry.path
			if not (is_dir and version_form):
				entries.append((name, entry.path, entry.is_file(follow_symlinks=False)))
	except VaultScanError:
		raise
	except Exception as e:
		raise VaultScanError(f'cannot list the vault {job_vault_path}: {e}')
	try:
		numbered = {}
		for name in folders:
			if is_version_folder_name(name):
				number = vault_version_number(name)
				if number in numbered:
					raise VaultScanError(f'two version folders in {job_vault_path} are numbered {number}: {numbered[number]} and {name}')
				numbered[number] = name
		version_folders = set(numbered.values())
		# the numbers the folders there carry, version folders or not
		carried = {vault_version_number(name) for name in folders} - {None}
		# each version folder's change lists, and every folder some entry is named after
		own = {name: [] for name in version_folders}
		claimed = set()
		kept = []
		# the numbers of the orphans the kept entries may be the lists of, and whether one's number cannot be read
		held_back = set()
		hold_all = False
		gone = []
		for name, path, is_file in entries:
			owners = []
			at = name.find('--')
			while at != -1:
				if name[:at] in folders:
					owners.append(name[:at])
				at = name.find('--', at + 1)
			if owners:
				claimed.update(owners)
				usable = [owner for owner in owners if is_file and owner in version_folders and change_list_record(name[len(owner) + 2:]) is not None]
				if not usable:
					raise VaultScanError(f'{name} in {job_vault_path} is named after the folder {owners[-1]}, but cannot be read as its change list (a regular file named after it and its record)')
				for owner in usable:
					own[owner].append(name)
				continue
			# no folder there is named in it: its version folder is the name up to its second --
			first, _, rest = name.partition('--')
			stamp, _, record = rest.partition('--')
			folder = f'{first}--{stamp}'
			number = vault_version_number(name)
			if is_version_folder_name(folder) and change_list_record(record) is not None:
				if not is_file:
					raise VaultScanError(f'{name} in {job_vault_path} has a change list\'s name but is no regular file')
				if number not in carried:
					gone.append((folder, path))
					continue
			kept.append(name)
			if number is None:
				hold_all = True
			else:
				held_back.add(number)
		versions = {}
		change_lists = {}
		orphans = []
		for number, name in sorted(numbered.items()):
			if len(own[name]) > 1:
				raise VaultScanError(f'the version folder {name} in {job_vault_path} has {len(own[name])} change lists: {", ".join(sorted(own[name]))}')
			if not own[name]:
				if name not in claimed:
					orphans.append((number, name))
				continue
			change_list = own[name][0]
			size, inodes = change_list_record(change_list[len(name) + 2:])
			timestamp = datetime.datetime.strptime(name.partition('--')[2], VAULT_TIMESTAMP_FORMAT).timestamp()
			versions[number] = VaultEntry(number, folders[name], timestamp, size, inodes)
			change_lists[number] = os.path.join(job_vault_path, change_list)
		for number, name in orphans:
			if hold_all or number in held_back:
				raise VaultScanError(f'{name} in {job_vault_path} has no change list, and {", ".join(sorted(kept))}, which name no folder there, may be its')
			if versions and min(versions) < number < max(versions):
				raise VaultScanError(f'{name} in {job_vault_path} has no change list, though versions {min(versions)} and {max(versions)} around it are committed: its list may not have been listed')
		stale = []
		for folder, path in gone:
			# not listed: only a folder that is not there is gone
			try:
				os.lstat(os.path.join(job_vault_path, folder))
			except (FileNotFoundError, NotADirectoryError):
				stale.append(path)
				continue
			except OSError as e:
				raise VaultScanError(f'cannot tell whether {folder}, which {os.path.basename(path)} records, is gone: {e}')
			raise VaultScanError(f'{os.path.basename(path)} records {folder}, which is in {job_vault_path} but was not listed as a folder')
	except VaultScanError:
		raise
	except Exception as e:
		raise VaultScanError(f'cannot read the vault {job_vault_path}: {type(e).__name__}: {e}')
	return VaultListing(versions, change_lists, [folders[name] for _, name in orphans], stale, sorted(kept), unfinished)

def remove_orphan(job_vault_path:str, path:str) -> bool:
	'''rm -rf of path, a version folder without a change list in job_vault_path: whether it is gone.'''
	backuperTeeLogToTl(job_vault_path, f'Removing incomplete orphan version (no content file): {path}', error=True)
	try:
		multiCMD.run_command(['rm', '-rf', path], quiet=True, return_code_only=True)
	except Exception as e:
		backuperTeeLogToTl(job_vault_path, f'Error removing orphan {path}: {e}', error=True)
	try:
		os.lstat(path)
	except (FileNotFoundError, NotADirectoryError):
		return True
	except OSError as e:
		backuperTeeLogToTl(job_vault_path, f'Cannot tell whether the orphan {path} went: {e}', error=True)
		return False
	backuperTeeLogToTl(job_vault_path, f'Failed to remove the orphan {path}', error=True)
	return False

def remove_incomplete_vault_versions(job_vault_path: str) -> list:
	'''
	At the daemon's start: remove the version folders without a change list, which a crash or a stop leaves (a version
	is committed only when its change list is there), and the private folders of change lists a crash cut off, once the
	whole vault was read for certain (read_job_vault()). A vault that cannot be loses nothing: the error is logged, and
	the job's own scan fails on it too.

	Returns:
		list: Absolute paths of deleted version directories.
	'''
	deleted = []
	try:
		listing = read_job_vault(job_vault_path)
	except VaultScanError as e:
		backuperTeeLogToTl(job_vault_path, f'Not removing incomplete versions, nothing in the vault is removed: {e.reason}', error=True)
		return deleted
	if listing is None:
		return deleted
	for path in listing.unfinished:
		backuperTeeLogToTl(job_vault_path, f'Removing unfinished change list: {path}', error=True)
		try:
			shutil.rmtree(path)
		except OSError as e:
			backuperTeeLogToTl(job_vault_path, f'Failed to remove unfinished change list {path}: {e}', error=True)
	for path in listing.orphans:
		if remove_orphan(job_vault_path, path):
			deleted.append(path)
	return deleted

# the job vaults (absolute paths) a scan of this daemon found committed versions in: one that is not there afterwards
# went away under the daemon (as a mergerfs branch dropping out shows it), and is no new vault to start at V0 in
VAULTS_WITH_VERSIONS = set()

def get_vault_info(job_vault_path:str,recalculate:bool=False) -> VaultInfo:
	'''
	The versions job_vault_path holds, oldest first, each with the size and inodes its change list records, or with
	recalculate, what du measures (the list renamed to record it). A job vault that is not there is an empty one, unless
	a scan of this daemon found committed versions in it (VAULTS_WITH_VERSIONS): it fails then, as a backup would start
	a whole V0 beside them once it came back.

	The scan deletes only what it is certain of, once the whole vault was read (read_job_vault()): the change lists of
	version folders that are not there, and the version folders without a change list that may go, the orphans of
	backups that did not commit and of removals cut short. Raises VaultScanError, having deleted nothing, when the vault
	cannot be read whole or for certain, and (after the deletions) when an orphan cannot be removed, as the next backup
	would make a version of its number beside it. The caller's job then fails its attempt, with its FAILED marker: no
	backup prunes or writes on a partial view.
	'''
	# job vault subfolder should follow: V{version}--{ISO8601ish time}
	# ex. V0--2021-01-01_00-00-00_-0800
	try:
		listing = read_job_vault(job_vault_path)
	except VaultScanError as e:
		backuperTeeLogToTl(job_vault_path, f'Cannot read the vault, nothing in it is removed: {e.reason}', error=True)
		raise
	if listing is None:
		if os.path.abspath(job_vault_path) in VAULTS_WITH_VERSIONS:
			reason = f'the vault {job_vault_path} is not there, though this daemon found versions in it: not starting it again'
			backuperTeeLogToTl(job_vault_path, f'Cannot read the vault: {reason}', error=True)
			raise VaultScanError(reason)
		backuperTeeLogToTl(job_vault_path, f'Job vault path {job_vault_path} does not exist', error=True)
		return VaultInfo({},0,0)
	if listing.versions:
		VAULTS_WITH_VERSIONS.add(os.path.abspath(job_vault_path))
	for name in listing.kept:
		backuperTeeLogToTl(job_vault_path, f'Keeping {name}: it names no folder there, and its name does not say it is the change list of a version gone', error=True)
	for path in listing.stale:
		backuperTeeLogToTl(job_vault_path, f'Vault path {path.rpartition("--")[0]} for content {os.path.basename(path)} does not exist, deleting content file...', error=True)
		try:
			os.remove(path)
		except Exception as e:
			backuperTeeLogToTl(job_vault_path, f'Error deleting {path}: {e}', error=True)
	kept = [path for path in listing.orphans if not remove_orphan(job_vault_path, path)]
	if kept:
		raise VaultScanError(f'cannot remove the incomplete versions {", ".join(kept)}, and a backup would make a version of their number beside them')
	vault_info_dict = OrderedDict()
	vault_size = 0
	vault_inodes = 0
	for number, entry in sorted(listing.versions.items()):
		if recalculate:
			# we will recalculate the size and inodes for the folders and rename the folders accordingly
			entry = entry._replace(size=get_path_size(entry.path), inode=get_path_inodes(entry.path))
			change_list = listing.change_lists[number]
			new_change_list = change_list_path(entry.path, entry.size, entry.inode)
			if change_list != new_change_list:
				backuperTeeLogToTl(job_vault_path,f'Renaming {os.path.basename(change_list)} to {os.path.basename(new_change_list)}')
				try:
					os.rename(change_list,new_change_list)
				except Exception as e:
					backuperTeeLogToTl(job_vault_path,f'Error renaming {os.path.basename(change_list)} to {os.path.basename(new_change_list)}: {e}',error=True)
		vault_size += entry.size
		vault_inodes += entry.inode
		vault_info_dict[number] = entry
	return VaultInfo(vault_info_dict, vault_size, vault_inodes)


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

class NotARealFolder(OSError):
	'''What a backup would write or remove in a version lies behind a link there (see real_folders_to()).'''

def is_entry_rel(rel:str) -> bool:
	'''
	Whether rel names an entry below a version folder, as manifest rows do (a folder's rel ending with /): relative, and
	no part of it empty, . or .., so it is neither the version folder itself nor anything outside it.

	Examples:
		>>> [is_entry_rel(rel) for rel in ('a', 'a/b/', '.hidden', 'a..b', '', '.', './', '/', '/etc/x', 'a/../b', 'a/./b', 'a//b', '..', 'a//')]
		[True, True, True, True, False, False, False, False, False, False, False, False, False, False]
	'''
	if not rel or rel.startswith('/'):
		return False
	return all(part not in ('', '.', '..') for part in (rel[:-1] if rel.endswith('/') else rel).split('/'))

def real_folders_to(version_path:str, rel:str, make:bool = False, missing_ok:bool = False) -> bool:
	'''
	Whether every folder between version_path and the entry of rel in it (a folder's rel ending with /) is a real folder
	there: not a link, a file or nothing. Only then does what is written or removed at rel stay inside version_path, as
	the path to it follows no link. With make, the missing ones are made, as real folders; with missing_ok, a missing
	one is no obstacle (nothing below it exists to follow), and nothing is made. A rel that is no entry below the
	version (is_entry_rel(): absolute, the version itself, or with a . or .. part) is never one.

	Examples:
		>>> import tempfile
		>>> version = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(version, 'd', 'e'))
		>>> os.symlink('d', os.path.join(version, 'link'))
		>>> [real_folders_to(version, rel) for rel in ('d/e/f', 'd/e/', 'link', 'link/f', 'link/e/f', 'gone/f')]
		[True, True, True, False, False, False]
		>>> real_folders_to(version, 'gone/f', missing_ok=True), real_folders_to(version, 'new/sub/f', make=True), os.path.isdir(os.path.join(version, 'new', 'sub'))
		(True, True, True)
		>>> [real_folders_to(version, rel, make=True, missing_ok=True) for rel in ('', '.', './', 'd/../link/f', 'd/./e/f', '..', '../x', '/etc/x', 'd//e')]
		[False, False, False, False, False, False, False, False, False]
		>>> import shutil; shutil.rmtree(version)
	'''
	if not is_entry_rel(rel):
		return False
	path = version_path
	for part in rel.strip('/').split('/')[:-1]:
		path = os.path.join(path, part)
		try:
			if not stat.S_ISDIR(os.lstat(path).st_mode):
				return False
		except FileNotFoundError:
			if missing_ok:
				return True
			if not make:
				return False
			try:
				# its parent was found or made a real folder just before
				os.mkdir(path)
			except FileExistsError:
				if not os.path.isdir(path) or os.path.islink(path):
					return False
			except OSError:
				return False
		except OSError:
			return False
	return True

def file_in_place_of_folder(version_path:str, rel:str):
	'''
	The rel (ending with /) of the first folder above rel in version_path that is a file or another entry that is no
	folder and no link, as a file made where a folder was leaves it; None when the folders above are real, or the first
	one that is not is a link, missing or cannot be looked at.

	Examples:
		>>> import tempfile
		>>> version = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(version, 'd'))
		>>> open(os.path.join(version, 'd', 'f'), 'w').close()
		>>> os.symlink('d', os.path.join(version, 'link'))
		>>> [file_in_place_of_folder(version, rel) for rel in ('d/f/x', 'd/f/sub/', 'd/x', 'link/f/x', 'gone/x')]
		['d/f/', 'd/f/', None, None, None]
		>>> import shutil; shutil.rmtree(version)
	'''
	parts = rel.rstrip('/').split('/')[:-1]
	for depth in range(1, len(parts) + 1):
		try:
			mode = os.lstat(os.path.join(version_path, *parts[:depth])).st_mode
		except OSError:
			return None
		if stat.S_ISLNK(mode):
			return None
		if not stat.S_ISDIR(mode):
			return '/'.join(parts[:depth]) + '/'
	return None

def make_real_folder(path:str) -> bool:
	'''
	Make path, in a real folder of a version being written (real_folders_to()), a real folder: an entry of another kind
	there is removed first, a link as a link, never followed. False, with an error line, when that cannot be done.
	'''
	try:
		try:
			if stat.S_ISDIR(os.lstat(path).st_mode):
				return True
			os.remove(path)
		except FileNotFoundError:
			pass
		os.mkdir(path)
		return True
	except OSError as e:
		backuperTeeLogToTl(path=path,error=True,message=f'Cannot make the folder {path}: {e}')
		return False

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
		returncode = multiCMD.run_command(command,quiet=True,return_code_only=True,wait_for_return=True)
		if returncode == 0:
			replace_entry(temp_path, dest_path)
	finally:
		# gone once it took dest_path's place; a failed or interrupted copy leaves no partial file
		remove_entry(temp_path)
	return returncode

def discard_copies(pending:list, version_path:str = None):
	'''
	Remove the partial files of the copies in pending, which will not be finished, and empty it. With version_path, the
	version they were made in, one whose folder there is no longer a real folder is left alone: it went with the folder
	it was made in, and removing it would reach through a link (real_folders_to()).
	'''
	for copy in pending:
		if version_path is not None and not real_folders_to(version_path, os.path.relpath(copy.temp_path, version_path), missing_ok=True):
			continue
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

def finish_copies(pending:list, manifest:'VaultManifest', version_path:str, job_name:str, reported:set = None) -> list:
	'''
	Put the copies of pending in place once the executor has finished them, and empty pending.

	A copy that succeeded takes its destination's place, as does one for which cp only reported metadata of its partial
	file it could not keep (a warning says so): a failed read or write of the contents gets a line of its own. One that
	failed leaves the destination as it was, keeping the last backed-up copy, when its source failed: silently when the
	source is gone, with an UNREADABLE line (once per backup, with reported) when it could not be read. A destination holding nothing then stops being tracked in manifest, whose paths
	are relative to version_path. Each copy put in place is recorded in manifest as held by version_path, in the
	transaction committing that version, and returned (as its path relative to version_path). When writing into the
	vault is what failed, JobFailure is raised once every copy is dealt with.
	'''
	failure = None
	done = 0
	copied = []
	try:
		for copy in pending:
			lines = [line.strip() for line in copy.task.stderr if line.strip()]
			error = '; '.join(lines)
			succeeded = copy.task.returncode == 0
			temp_name = os.path.basename(copy.temp_path)
			if not succeeded and lines and all(copy_metadata_failure(line, temp_name) for line in lines) and os.path.lexists(copy.temp_path):
				backuperTeeLogToTl(path=copy.source_path,warning=True,message=f'Copied {copy.source_path} to {copy.dest_path} without all of its metadata: {error}')
				succeeded = True
			if succeeded and not real_folders_to(version_path, os.path.relpath(copy.dest_path, version_path), missing_ok=True):
				# a folder above it is now a link or a file in the version: the copy is not put in place through it, and its
				# partial file is left alone, as removing it would reach through the link too. it went with the folder it was
				# made in ( a missing one took it along, and fails the copy as before )
				manifest.discard(os.path.relpath(copy.dest_path, version_path))
				backuperTeeLogToTl(path=copy.source_path,error=True,message=f'Not putting the copy of {copy.source_path} in place at {copy.dest_path}: a folder above it in the version is not a real folder; not tracking it')
			elif succeeded:
				replace_entry(copy.temp_path, copy.dest_path)
				copied.append(os.path.relpath(copy.dest_path, version_path))
			else:
				if real_folders_to(version_path, os.path.relpath(copy.temp_path, version_path), missing_ok=True):
					# a partial file that cannot be removed would be committed with the version
					remove_entry(copy.temp_path)
				else:
					# it went with the folder it was made in, which a link or a file has replaced: removing it would reach through
					backuperTeeLogToTl(path=copy.source_path,message=f'Leaving the partial copy {copy.temp_path}: a folder above it in the version is not a real folder')
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
		version = vault_version_number(os.path.basename(os.path.normpath(version_path)))
		if version is not None:
			manifest.set_copy_version(copied, version)
	finally:
		# an error above leaves no partial file of the copies it did not reach
		rest = pending[done:]
		pending.clear()
		discard_copies(rest, version_path)
	if failure is not None:
		raise failure
	return copied

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
		discard_copies(pending, version_path)
	else:
		pending.clear()

def do_referenced_copy(source_path:str,backup_folder:str,manifest:'VaultManifest',relative=False) -> bool:
	'''
	Recreate the folders tracked in manifest under backup_folder and link each tracked file to its copy under source_path.

	Entries missing from source_path are dropped from the manifest; one that cannot be looked at stays tracked, and is
	made or linked as ever, with an error line, as dropping it would leave it out of the new version. Returns False when
	the backup was interrupted.
	'''
	def missing_from_source(path:str, kind:str, rel:str) -> bool:
		# only an entry that is not there is missing: ENOTDIR says so too, for one below a name that is a file there now
		try:
			os.lstat(path)
		except (FileNotFoundError, NotADirectoryError):
			return True
		except OSError as e:
			backuperTeeLogToTl(path=source_path,error=True,message=f'Cannot look at tracked {kind} {rel} in {source_path}, keeping it: {e}')
		return False
	global BACKUP_SEMAPHORE
	global GREEN_LIGHT
	backuperTeeLogToTl(path=source_path,message=f'Creating a referenced copy of {source_path} to {backup_folder}')
	# rows are read as they are linked and dropped afterwards: changing a table while reading it is undefined in sqlite
	missing = []
	for folder in manifest.iter_folders():
		source_folder = os.path.join(source_path,folder)
		backup_folder_path = os.path.join(backup_folder,folder)
		if not is_entry_rel(folder):
			# such as './', which daemons before 0.43 wrote for the attrib event of the monitored root
			backuperTeeLogToTl(path=source_path,warning=True,message=f'Dropping a tracked row that names no folder below the version: {folder!r}')
			missing.append(folder)
			continue
		if missing_from_source(source_folder, 'folder', folder):
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
		if not is_entry_rel(file):
			backuperTeeLogToTl(path=source_path,warning=True,message=f'Dropping a tracked row that names no file below the version: {file!r}')
			missing.append(file)
			continue
		if missing_from_source(source_file_real, 'file', file):
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
	'''
	Copy source_file's mode, times, owner and extended attributes onto backup_file_path. A symlink at backup_file_path
	is never followed, even named with a trailing / as a folder's rel is: it gets only its own owner and times, from
	source_file's own (by lstat), as a link has no mode or extended attributes of its own here. A symlink source_file
	onto anything else is refused, with an error line: what it leads to is another entry, whose metadata is not its own.
	Returns whether it worked; an error line says why not.
	'''
	try:
		# a trailing / makes the kernel follow a link to a folder
		entry = backup_file_path.rstrip('/') or backup_file_path
		source = source_file.rstrip('/') or source_file
		if os.path.islink(entry):
			# a user's symlink backed up as one can lead anywhere, out of the vault say
			st = os.lstat(source)
			if os.name == 'posix':
				os.lchown(entry, st.st_uid, st.st_gid)
			os.utime(entry, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
			return True
		if os.path.islink(source):
			# the monitored entry became a symlink while the version still holds a copy of what it was
			backuperTeeLogToTl(path=source_file,error=True,message=f'Not copying the metadata of {source_file} onto {backup_file_path}: it is a symlink, and {backup_file_path} is not one')
			return False
		# copy the file metadata
		copystat(source_file,backup_file_path)
		st = os.stat(source_file)
		if os.name == 'posix':
			os.chown(backup_file_path, st.st_uid, st.st_gid)
		# to the nanosecond, as copystat set them: times passed as floats come back up to a few hundred ns off
		os.utime(backup_file_path, ns=(st.st_atime_ns, st.st_mtime_ns))
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
	rtn = multiCMD.run_command(['du','--block-size=1','-csP',*path],quiet=True)
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
	rtn = multiCMD.run_command(['du','--inodes','-csP',*path],quiet=True)
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

# a name os.fsdecode() gives with a lone surrogate for each byte that is not UTF-8 cannot go into sqlite or TSVZ as it
# is: it is stored with each such byte as NAME_ESCAPE and one of U+10FF80..U+10FFFF, and NAME_ESCAPE itself doubled.
# all of them are at the very end of Unicode, where names hardly go, and every UTF-8 name without NAME_ESCAPE is
# stored as it is
NAME_ESCAPE = '\U0010fe00'
STORABLE_NAME_ESCAPES = re.compile(f'[{NAME_ESCAPE}\udc80-\udcff]')
STORED_NAME_ESCAPES = re.compile(f'{NAME_ESCAPE}([{NAME_ESCAPE}\U0010ff80-\U0010ffff])')

def storable_name(text:str) -> str:
	'''
	text, a name or path as os.fsdecode() gives it, as valid Unicode that stored_name() turns back into text exactly.
	Each character is escaped on its own, so a folder's stored path starts every stored path under it. The 128 bytes
	that are not UTF-8 encode to UTF-8 (which never raises) as 128 different stored forms.

	Examples:
		>>> storable_name('café'), storable_name('a/b/')
		('café', 'a/b/')
		>>> storable_name('bad\\udcff.txt') == 'bad' + NAME_ESCAPE + '\\U0010ffff' + '.txt'
		True
		>>> storable_name(NAME_ESCAPE) == NAME_ESCAPE * 2
		True
		>>> storable_name('d\\udcff/' + 'x\\udc80') == storable_name('d\\udcff/') + storable_name('x\\udc80')
		True
		>>> len({storable_name(os.fsdecode(bytes([byte]))).encode('utf-8') for byte in range(0x80, 0x100)})
		128
	'''
	if text.isascii():
		return text
	return STORABLE_NAME_ESCAPES.sub(storable_char, text)

def storable_char(match) -> str:
	'''What storable_name() stores for the one character STORABLE_NAME_ESCAPES matched.'''
	c = match.group(0)
	return NAME_ESCAPE + (NAME_ESCAPE if c == NAME_ESCAPE else chr(ord(c) - 0xdc00 + 0x10ff00))

def stored_name(text:str) -> str:
	'''
	The name storable_name() gave text for, exactly. NAME_ESCAPE followed by anything else, which storable_name() never
	writes, is kept as it is.

	Examples:
		>>> lookalike = 'x' + NAME_ESCAPE + '\\U0010ff80'
		>>> stored_name(storable_name(lookalike)) == lookalike, stored_name(lookalike) == 'x\\udc80'
		(True, True)
		>>> names = [os.fsdecode(bytes([byte])) for byte in range(0x80, 0x100)]
		>>> [stored_name(storable_name(name)) for name in names] == names
		True
		>>> stored_name('café'), stored_name(NAME_ESCAPE + 'a') == NAME_ESCAPE + 'a'
		('café', True)
	'''
	if NAME_ESCAPE not in text:
		return text
	return STORED_NAME_ESCAPES.sub(stored_char, text)

def stored_char(match) -> str:
	'''The character stored_name() reads back from the escape STORED_NAME_ESCAPES matched.'''
	c = match.group(1)
	return NAME_ESCAPE if c == NAME_ESCAPE else chr(ord(c) - 0x10ff00 + 0xdc00)

def folder_range_end(folder:str) -> str:
	'''
	Smallest path sorting after every path under folder (which ends with /), to select a folder's rows as a range.
	A folder's stored path (storable_name()) ends with / too, and bounds the stored paths under it.

	Examples:
		>>> folder_range_end('a/b/')
		'a/b0'
		>>> 'a/b/' < 'a/b/zz' < folder_range_end('a/b/') <= 'a/b0'
		True
		>>> folder = storable_name('d\\udcff/')
		>>> folder < storable_name('d\\udcff/' + NAME_ESCAPE) < folder_range_end(folder) <= storable_name('d\\udcff0')
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
	Paths and link targets are stored through storable_name() and read back through stored_name(), so a name that is
	not UTF-8 is tracked like any other; rows sort by stored path, in which a folder still comes right before the paths
	under it. copy_version is the number of the version a backup copied a file into (set_copy_version()), kept while
	later versions link to that copy and when the file moves, NULL when not known. Pruning moves copies into the oldest
	version kept without changing it, which effective_copy_version() allows for.

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
	SCHEMA = '2'
	# the entries columns of schema '1', which schema '2' follows with copy_version
	SCHEMA_1_COLUMNS = ('path TEXT PRIMARY KEY, kind TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER, uid INTEGER, gid INTEGER, '
		'hash TEXT, link TEXT, unchecked INTEGER, dirty INTEGER NOT NULL DEFAULT 0')
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
			if schema is not None and schema[0] == '1':
				self._upgrade()
			elif schema is None or schema[0] != self.SCHEMA:
				self.conn.execute('DROP TABLE IF EXISTS entries')
				self.conn.execute('DELETE FROM meta')
				self.conn.execute("INSERT INTO meta VALUES ('schema', ?)", (self.SCHEMA,))
			# copy_version comes last, where upgrading a schema '1' database adds it
			self.conn.execute(f'CREATE TABLE IF NOT EXISTS entries({self.SCHEMA_1_COLUMNS}, copy_version INTEGER) WITHOUT ROWID')
			self.conn.execute('CREATE INDEX IF NOT EXISTS dirty_entries ON entries(path) WHERE dirty')
			self.conn.execute('CREATE TEMP TABLE IF NOT EXISTS seen(path TEXT PRIMARY KEY) WITHOUT ROWID')
		except BaseException:
			self.conn.close()
			raise

	def _upgrade(self):
		'''
		Upgrade a schema '1' database in place, in one transaction: every row and what meta holds (the version described,
		the skip list fingerprint, the inner mounts) stay, so no full comparison follows and nothing is read from the vault.
		'''
		try:
			self.begin()
			self._upgrade_from_schema_1()
			self.commit()
		except sqlite3.OperationalError as e:
			# a locked, full or failing disk: closing the connection rolls the upgrade back, and the database stays at
			# schema '1' for the job's next attempt instead of being discarded at the cost of a full comparison
			raise JobFailure(f'cannot upgrade the vault database {self.path}: {e}') from e

	def _upgrade_from_schema_1(self):
		'''The statements upgrading a schema '1' database, in the transaction _upgrade() holds.'''
		# 0.39 committed a new database's schema and its entries table one after the other: a crash between the two left
		# no table, which holds no rows either
		self.conn.execute(f'CREATE TABLE IF NOT EXISTS entries({self.SCHEMA_1_COLUMNS}) WITHOUT ROWID')
		self.conn.execute('ALTER TABLE entries ADD COLUMN copy_version INTEGER')
		# schema '1' stored names as they are: NAME_ESCAPE in one (rare, as it is a private use code point) is doubled to
		# read back the same. the rows holding it move out and back in, as sqlite checks the key row by row, and a name
		# doubled first can be another row's name until that one is doubled too
		self.conn.execute('CREATE TEMP TABLE escaped AS SELECT * FROM entries WHERE instr(path, ?)', (NAME_ESCAPE,))
		self.conn.execute('DELETE FROM entries WHERE path IN (SELECT path FROM temp.escaped)')
		self.conn.execute('UPDATE temp.escaped SET path = replace(path, ?, ?)', (NAME_ESCAPE, NAME_ESCAPE * 2))
		self.conn.execute('INSERT INTO entries SELECT * FROM temp.escaped')
		self.conn.execute('DROP TABLE temp.escaped')
		self.conn.execute('UPDATE entries SET link = replace(link, ?, ?) WHERE instr(link, ?)', (NAME_ESCAPE, NAME_ESCAPE * 2, NAME_ESCAPE))
		# json.dumps() wrote the inner mounts in ASCII, NAME_ESCAPE as the \u escapes of its UTF-16 pair
		escape = json.dumps(NAME_ESCAPE)[1:-1]
		self.conn.execute("UPDATE meta SET value = replace(value, ?, ?) WHERE key = 'inner_mounts'", (escape, escape * 2))
		self.conn.execute("UPDATE meta SET value = ? WHERE key = 'schema'", (self.SCHEMA,))

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

	@property
	def in_transaction(self) -> bool:
		return self.conn.in_transaction

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
		return [] if row is None else [stored_name(rel) for rel in json.loads(row[0])]

	def set_inner_mounts(self, rels:list):
		'''Record the inner mount points (folder rels ending with /); the caller holds the transaction.'''
		self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('inner_mounts', ?)", (json.dumps([storable_name(rel) for rel in rels]),))

	@property
	def monitor_paths(self) -> list:
		'''
		The monitored paths the job's versions were written under, as [(first version number, path)], oldest first: each
		path holds from its version on, until the next. [] when never recorded, as before 0.44.
		'''
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'monitor_paths'").fetchone()
		return [] if row is None else [(int(number), stored_name(path)) for number, path in json.loads(row[0])]

	def note_monitor_path(self, version_number:int, monitor_path:str):
		'''
		Record that the version numbered version_number is written under monitor_path, when the last path recorded is
		another one or none is; the caller holds the transaction. The rows of a version's change list are absolute
		monitored paths, read under this path (VersionMoves.of_committed()). Pairs from version_number on are dropped
		first: they are of versions gone, as when a vault is started over with its manifest kept.
		'''
		recorded = self.monitor_paths
		pairs = [(number, path) for number, path in recorded if number < version_number]
		monitor_path = os.path.abspath(monitor_path)
		if pairs == recorded and pairs and pairs[-1][1] == monitor_path:
			return
		if not pairs or pairs[-1][1] != monitor_path:
			pairs.append((version_number, monitor_path))
		self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('monitor_paths', ?)", (json.dumps([[number, storable_name(path)] for number, path in pairs]),))

	def stored_prune_salt(self):
		'''
		The secret for pruning's temp names a daemon before 0.44 kept in meta as hex (prune_salt), which every user who can
		read the manifest can read: vault_prune_salt() makes the vault's secret file with it, once, then drops the row
		(forget_prune_salt()). None when there is none, or it is not PRUNE_SALT_BYTES bytes.
		'''
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'prune_salt'").fetchone()
		if row is None:
			return None
		try:
			salt = bytes.fromhex(row[0])
		except (TypeError, ValueError):
			return None
		return salt if len(salt) == PRUNE_SALT_BYTES else None

	def forget_prune_salt(self):
		'''
		Drop the prune_salt row, once the vault's secret file holds a secret (with the caller's transaction, if one is
		open). secure_delete zeroes it where it was: a freed page keeps a deleted row's bytes in the file otherwise.
		'''
		was = self.conn.execute('PRAGMA secure_delete').fetchone()[0]
		self.conn.execute('PRAGMA secure_delete = ON')
		try:
			self.conn.execute("DELETE FROM meta WHERE key = 'prune_salt'")
		finally:
			self.conn.execute(f'PRAGMA secure_delete = {int(was)}')

	def describes(self, version_path:str) -> bool:
		row = self.conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
		return row is not None and row[0] == os.path.basename(os.path.normpath(version_path))

	def reset(self, version_path:str):
		'''Drop every row: the manifest now describes an empty version_path.'''
		self.conn.execute('DELETE FROM entries')
		self._set_version(version_path)

	def rebuild(self, version_path:str, tree_path:str = None, skip = None, errors:list = None, copy_version:int = None):
		'''
		Track everything under tree_path (version_path by default) as unverified, describing version_path, each file with
		copy_version (None: not known).
		'''
		self.reset(version_path)
		batch = []
		for _, rel, is_dir in iter_tree_entries(tree_path or version_path, skip=skip if tree_path else None, errors=errors):
			batch.append((storable_name(rel), None if is_dir else copy_version))
			if len(batch) >= MANIFEST_BATCH_SIZE:
				self.conn.executemany('INSERT OR REPLACE INTO entries(path, copy_version) VALUES (?, ?)', batch)
				batch.clear()
		self.conn.executemany('INSERT OR REPLACE INTO entries(path, copy_version) VALUES (?, ?)', batch)

	def lookup(self, rel:str):
		'''The record for rel (all None when unverified), or None when rel is not tracked.'''
		row = self.conn.execute('SELECT kind, size, mtime_ns, mode, uid, gid, hash, link, unchecked FROM entries WHERE path = ?', (storable_name(rel),)).fetchone()
		if row is None:
			return None
		record = ManifestRecord(*row)
		return record if record.link is None else record._replace(link=stored_name(record.link))

	def dirty_rels(self) -> set:
		'''The rels of the rows this backup wrote and has not recorded yet.'''
		return {stored_name(rel) for (rel,) in self.conn.execute('SELECT path FROM entries WHERE dirty')}

	def add(self, rel:str, dirty:bool = False):
		'''
		Track rel without a record: dirty when this backup wrote it, so it is recorded before the backup commits. A
		tracked rel keeps its copy version, as its entry still leads to that copy until a new copy is recorded (one that
		failed, or an attribute change synced onto a link, leaves the link there). A rel that names no entry below the
		version (is_entry_rel(), such as './' for the version folder itself) is not tracked, with an error line.
		'''
		if not is_entry_rel(rel):
			backuperTeeLogToTl(path=self.path,error=True,message=f'Not tracking {rel!r}: it names no entry below the version')
			return
		path = storable_name(rel)
		self.conn.execute('INSERT OR REPLACE INTO entries(path, dirty, copy_version) VALUES (?, ?, (SELECT copy_version FROM entries WHERE path = ?))',
			(path, int(dirty), path))

	def discard(self, rel:str):
		self.conn.execute('DELETE FROM entries WHERE path = ?', (storable_name(rel),))

	def discard_many(self, rels):
		self.conn.executemany('DELETE FROM entries WHERE path = ?', ((storable_name(rel),) for rel in rels))

	def remove_tree(self, folder:str):
		'''Stop tracking folder and everything under it.'''
		folder = storable_name(folder)
		self.conn.execute('DELETE FROM entries WHERE path >= ? AND path < ?', (folder, folder_range_end(folder)))

	def iter_under(self, folder:str):
		'''Tracked paths strictly under folder (which ends with /), sorted.'''
		folder = storable_name(folder)
		for (path,) in self.conn.execute('SELECT path FROM entries WHERE path > ? AND path < ? ORDER BY path', (folder, folder_range_end(folder))):
			yield stored_name(path)

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
		# substr() counts characters, as len() does on the stored path
		src, dst = storable_name(src_folder), storable_name(dst_folder)
		self.conn.execute(f'UPDATE entries SET path = ? || substr(path, ?), {self.UNVERIFIED} WHERE path >= ? AND path < ?',
			(dst, len(src) + 1, src, folder_range_end(src)))

	def move_file(self, src:str, dst:str):
		'''
		Track the file src as dst instead, replacing what dst held, as move_tree() does for a folder: unverified, and with
		src's copy version, as the vault entry moving with it leads to the same copy. dst is tracked even when src is not.
		'''
		self.discard(dst)
		if not self.conn.execute(f'UPDATE entries SET path = ?, {self.UNVERIFIED} WHERE path = ?', (storable_name(dst), storable_name(src))).rowcount:
			self.add(dst)

	def set_records(self, records):
		'''Store (rel, record) pairs, leaving rel unverified where the record is None, and clear their dirty marks.'''
		unverified = []
		recorded = []
		for rel, record in records:
			if record is None:
				unverified.append((storable_name(rel),))
			else:
				if record.link is not None:
					record = record._replace(link=storable_name(record.link))
				recorded.append((*record, storable_name(rel)))
		self.conn.executemany(f'UPDATE entries SET {self.UNVERIFIED} WHERE path = ?', unverified)
		self.conn.executemany('UPDATE entries SET kind = ?, size = ?, mtime_ns = ?, mode = ?, uid = ?, gid = ?, hash = ?, link = ?, '
			'unchecked = ?, dirty = 0 WHERE path = ?', recorded)

	def mark_unchecked(self, rels):
		'''Mark the file records of rels unchecked, keeping the rest: each is a new copy of what it records, which delta generation reads back.'''
		self.conn.executemany("UPDATE entries SET unchecked = 1 WHERE path = ? AND kind = 'f'", ((storable_name(rel),) for rel in rels))

	def set_copy_version(self, rels, version:int):
		'''Record that the version numbered version holds the copy of each file of rels; the caller holds the transaction.'''
		self.conn.executemany('UPDATE entries SET copy_version = ? WHERE path = ?', ((version, storable_name(rel)) for rel in rels))

	def take_dirty(self, limit:int) -> list:
		return [stored_name(rel) for (rel,) in self.conn.execute('SELECT path FROM entries WHERE dirty LIMIT ?', (limit,))]

	def iter_folders(self):
		# sorted, so every folder comes before the folders inside it
		for (rel,) in self.conn.execute("SELECT path FROM entries WHERE substr(path, -1) = '/' ORDER BY path"):
			yield stored_name(rel)

	def iter_files(self):
		for (rel,) in self.conn.execute("SELECT path FROM entries WHERE substr(path, -1) != '/' ORDER BY path"):
			yield stored_name(rel)

	def iter_files_with_copy_version(self):
		'''(rel, copy version) of every tracked file, sorted; the copy version is None when not known.'''
		for rel, copy_version in self.conn.execute("SELECT path, copy_version FROM entries WHERE substr(path, -1) != '/' ORDER BY path"):
			yield stored_name(rel), copy_version

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
		self.conn.executemany('INSERT OR IGNORE INTO temp.seen VALUES (?)', ((storable_name(rel),) for rel in rels))

	def mark_seen_under(self, folder:str):
		'''Mark every tracked row strictly under folder (which ends with /) seen: a folder that could not be read keeps its entries.'''
		folder = storable_name(folder)
		self.conn.execute('INSERT OR IGNORE INTO temp.seen SELECT path FROM entries WHERE path > ? AND path < ?', (folder, folder_range_end(folder)))

	def unseen(self) -> list:
		'''Tracked paths not marked seen since clear_seen().'''
		return [stored_name(rel) for (rel,) in self.conn.execute('SELECT path FROM entries WHERE path NOT IN (SELECT path FROM temp.seen) ORDER BY path')]

	def unseen_under(self, folder:str) -> list:
		'''Tracked paths at or under folder (which ends with /) not marked seen since clear_seen().'''
		folder = storable_name(folder)
		return [stored_name(rel) for (rel,) in self.conn.execute('SELECT path FROM entries WHERE path >= ? AND path < ? AND path NOT IN (SELECT path FROM temp.seen) ORDER BY path',
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
		>>> [vault_version_number(name) for name in ('V²--2021-01-01_00-00-00_-0800', 'V٣--2021-01-01_00-00-00_-0800')]
		[None, None]
	'''
	# ASCII digits only: \d and isdigit() take digits of other scripts (and ², which int() then refuses)
	match = re.match(r'V([0-9]+)--', version_folder_name)
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
# folder's name again, while a folder missing or refused now may be a version's real folder later. pruning a version
# drops its pairs ( forget_real_vault_folders() ), as a link naming it is no chain link from then on
REAL_VAULT_FOLDERS = OrderedDict()
REAL_VAULT_FOLDERS_LOCK = threading.Lock()

def forget_real_vault_folders(version_path:str):
	'''
	Drop the pairs REAL_VAULT_FOLDERS holds for the version folder version_path (absolute and normalised), as pruning
	removed it: a link naming it is no chain link from then on.

	Examples:
		>>> REAL_VAULT_FOLDERS[('/v/V1', '/v/V1/a')] = REAL_VAULT_FOLDERS[('/v/V10', '/v/V10/a')] = None
		>>> forget_real_vault_folders('/v/V1')
		>>> [('/v/V1', '/v/V1/a') in REAL_VAULT_FOLDERS, ('/v/V10', '/v/V10/a') in REAL_VAULT_FOLDERS]
		[False, True]
		>>> forget_real_vault_folders('/v/V10')
	'''
	under = version_path + '/'
	with REAL_VAULT_FOLDERS_LOCK:
		for key in [key for key in REAL_VAULT_FOLDERS if key[1] == version_path or key[1].startswith(under)]:
			del REAL_VAULT_FOLDERS[key]

class UncheckedVaultLink(Exception):
	'''
	Whether a vault link is a chain link cannot be told, as a folder on the way to its target, or the target itself,
	cannot be looked at (an I/O error, say). The link may be its version's only way to a file, so reading and pruning
	never take it for a user's symlink. UnexplainedChainLink, raised when the version's rows cannot tell, is one too.
	'''

def is_real_folder_under(top:str, folder:str) -> bool:
	'''
	Whether a path through folder stays in top: top is a real folder, and folder is top or under it with no symlink
	from top down to folder. A missing folder on the way, or a file, is fine, as nothing goes through it; a name too
	long for any folder is not. Raises UncheckedVaultLink, and nothing else, when a folder on the way cannot be looked
	at, as that tells neither way. Both paths must be absolute and normalised (no '.', '..', '//' or trailing /), as
	the callers make them: folder is matched against top as text, so '/v/V3/../x' would count as under '/v/V3'.

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

def parse_chain_text(job_vault:str, link_text:str, link_path:str):
	'''
	The version folder name and the parts of the path in it that the relative link at link_path with link_text names,
	and how many ../ the text starts with, as (version_name, rel_parts, ups), when the text has the form of a chain
	link; else None. The form is (../)+<name>/<rel>: <name> the whole name of the version folder numbered one below the
	one in job_vault holding link_path, and <rel> one or more parts, none of them '', '.' or '..', which could lead out
	of that version. Any count of ../ has the form, as daemons before 0.39 kept the text when a move took the link to
	another folder depth: vault_chain_hop() judges the count by the version's moves. Nothing on disk is looked at
	either: chain_link_target() checks the folders on the way, chain_form_missing_version() the version.

	Examples:
		>>> link_path = '/v/job/V4--2021-01-02_00-00-00_-0800/deep/x'
		>>> parse_chain_text('/v/job', '../../V3--2021-01-01_00-00-00_-0800/a/x', link_path)
		('V3--2021-01-01_00-00-00_-0800', ['a', 'x'], 2)
		>>> parse_chain_text('/v/job/', '../V3--2021-01-01_00-00-00_-0800/x', link_path)
		('V3--2021-01-01_00-00-00_-0800', ['x'], 1)
		>>> [parse_chain_text('/v/job', text, link_path) for text in ('/v/job/V3--2021-01-01_00-00-00_-0800/x',
		...     'V3--2021-01-01_00-00-00_-0800/x', '../V3--2021-01-01_00-00-00_-0800', '../V3--2021-01-01_00-00-00_-0800/',
		...     '../V3--2021-01-01_00-00-00_-0800/a/../x', '../V3--2021-01-01_00-00-00_-0800/./x', '../V3--2021-01-01_00-00-00_-0800//x',
		...     '../V2--2021-01-01_00-00-00_-0800/x', '../V3--x/x', '../notaversion/x')]
		[None, None, None, None, None, None, None, None, None, None]
		>>> [parse_chain_text('/v/job', '../V3--2021-01-01_00-00-00_-0800/x', path) for path in (
		...     '/elsewhere/V4--2021-01-02_00-00-00_-0800/x', '/v/job/current_version/x')]
		[None, None]
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
	return name, rel, ups

def chain_link_target(job_vault:str, link_text:str, link_path:str):
	'''
	Where the relative link at link_path with link_text points, if it is a chain link by the rule; None for any other
	link, such as a user's symlink backed up as one.
	The daemon links an unchanged entry of a version to the version just before it: ../ up to the job vault, that
	version's folder and the entry's path in it. A link counts when its text has that form (parse_chain_text(), its
	../ not counted here), the version folder it names is there, and the folders from it down to the target's parent
	are real folders or missing ones (by is_real_folder_under()), so a backed-up folder symlink never leads out of it.
	By the text alone, a user's symlink of that very form, naming the previous version's folder by its whole name, is
	taken for a chain link: vault_chain_hop() tells them apart by the version's moves. A chain link whose target is
	gone is still one. Raises UncheckedVaultLink as is_real_folder_under() does.

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
	parsed = parse_chain_text(job_vault, link_text, link_path)
	if parsed is None:
		return None
	name, rel, _ = parsed
	vault = os.path.abspath(job_vault)
	target = os.path.join(vault, name, *rel)
	return target if is_real_folder_under(os.path.join(vault, name), os.path.dirname(target)) else None

def strict_chain_hop(job_vault:str, link_path:str, link_text:str):
	'''
	Where the link at link_path with link_text leads if it is a chain link by its text alone (chain_link_target()),
	else None. An absolute link is never one: no released daemon wrote absolute chain links, and a scan of the live
	vaults found none, while a user's symlink to a backed-up copy has just that form. Raises UncheckedVaultLink, and
	nothing else, when that cannot be told. vault_chain_hop() adds the version's moves, which tell a user's symlink in the relative form apart.

	Examples:
		>>> import tempfile
		>>> job_vault = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'a'))
		>>> os.symlink(job_vault, os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'l'))
		>>> link_path = os.path.join(job_vault, 'V4--2021-01-02_00-00-00_-0800', 'a', 'u')
		>>> strict_chain_hop(job_vault, link_path, '../../V3--2021-01-01_00-00-00_-0800/a/u')[len(job_vault):]
		'/V3--2021-01-01_00-00-00_-0800/a/u'
		>>> [strict_chain_hop(job_vault, link_path, text) for text in ('/elsewhere/u', '../lib/x', '../../V3--2021-01-01_00-00-00_-0800/l/u',
		...     job_vault + '/V3--2021-01-01_00-00-00_-0800/a/u', job_vault + '/V3--2021-01-01_00-00-00_-0800/a/../a/u')]
		[None, None, None, None, None]
		>>> import shutil; shutil.rmtree(job_vault)
	'''
	if os.path.isabs(link_text):
		return None
	return chain_link_target(job_vault, link_text, link_path)

def chain_hop(job_vault:str, link_path:str, link_text:str):
	'''strict_chain_hop(), but None (not a chain link) also when that cannot be told. Never raises.'''
	try:
		return strict_chain_hop(job_vault, link_path, link_text)
	except UncheckedVaultLink:
		return None

# the moves of committed versions, each read from its change list once: (version folder, the monitored path its rows
# are read under), both absolute, -> VersionMoves. rows once written never change (pruning renames a change list, rows
# and all), so an answer from a list that was read is kept; one that found no list, or could not read it, is not, as
# it may be there later. kept by how many rows they hold in all (a big list's rels cost tens of MB), the least
# recently used going first, though never the last one kept: a pass holds its own (VaultMoves). VERSION_MOVES_WARNED
# holds the versions a warning was logged for, as their rows cannot be used
VERSION_MOVES = OrderedDict()
VERSION_MOVES_WARNED = OrderedDict()
VERSION_MOVES_ROWS_KEPT = 200000
VERSION_MOVES_KEPT = 1024
VERSION_MOVES_LOCK = threading.Lock()

def remember_version_moves(table:OrderedDict, key:tuple, value) -> None:
	'''
	Keep value for key in table, one of VERSION_MOVES (bounded by VERSION_MOVES_ROWS_KEPT rows in all) and
	VERSION_MOVES_WARNED (bounded by VERSION_MOVES_KEPT entries), dropping the least recently used past the bound.
	'''
	with VERSION_MOVES_LOCK:
		table[key] = value
		table.move_to_end(key)
		if table is VERSION_MOVES:
			held = sum(moves.rows for moves in table.values())
			while len(table) > 1 and held > VERSION_MOVES_ROWS_KEPT:
				held -= table.popitem(last=False)[1].rows
		while len(table) > VERSION_MOVES_KEPT:
			table.popitem(last=False)

def forget_version_moves(version_path:str) -> None:
	'''Drop what VERSION_MOVES and VERSION_MOVES_WARNED hold for the version at version_path, as pruning removed it.'''
	version_path = os.path.abspath(version_path)
	with VERSION_MOVES_LOCK:
		for table in (VERSION_MOVES, VERSION_MOVES_WARNED):
			for key in [key for key in table if key[0] == version_path]:
				del table[key]

def read_recorded_monitor_paths(job_vault:str, timeout:float = 1) -> tuple:
	'''
	(record, locked) for recorded_monitor_paths(), waiting up to timeout seconds for a lock on the manifest: locked
	says that record is None because a write holds the manifest, as a big backup's does, so a read later can succeed.
	'''
	path = os.path.join(job_vault, MANIFEST_FILE_NAME)
	if not os.path.exists(path):
		return [], False
	try:
		# quoted as bytes, so a vault path that is not UTF-8 is opened as it is
		conn = sqlite3.connect(f'file:{urllib.parse.quote(os.fsencode(path))}?mode=ro', uri=True, timeout=timeout)
		try:
			row = conn.execute("SELECT value FROM meta WHERE key = 'monitor_paths'").fetchone()
		finally:
			conn.close()
		return ([] if row is None else [(int(number), stored_name(monitor)) for number, monitor in json.loads(row[0])]), False
	except sqlite3.DatabaseError as e:
		if 'not a database' in str(e) or 'malformed' in str(e) or 'no such table' in str(e):
			# started over when next opened, with no record
			return [], False
		return None, isinstance(e, sqlite3.OperationalError) and ('locked' in str(e) or 'busy' in str(e))
	except (OSError, ValueError, TypeError):
		return None, False

def recorded_monitor_paths(job_vault:str):
	'''
	The monitored paths the versions of job_vault were written under, as VaultManifest.monitor_paths records them,
	read without changing the manifest: [] when it records none (no manifest, versions written before 0.44, or one
	started over), None when it cannot be read now (locked for over a second, say).
	'''
	return read_recorded_monitor_paths(job_vault)[0]

def command_monitor_paths(job_vault:str, stream = None):
	'''
	recorded_monitor_paths() for the history and restore commands: while a write of the daemon holds the manifest, it
	waits, as for the restore lock, saying so once on stream (sys.stderr as it is now when None). None, said once too,
	when the record cannot be read for any other reason: the links of versions whose rows it would place are then
	judged by their text alone. Each try waits RESTORE_WAIT_SECONDS at most, so a stop signal a restore turned into
	RESTORE_STOP ends the wait soon after, as a KeyboardInterrupt.
	'''
	stream = sys.stderr if stream is None else stream
	recorded, locked = read_recorded_monitor_paths(job_vault, timeout=0)
	if locked:
		print(f'Waiting for reverberator to finish writing the vault database of {job_vault}', file=stream, flush=True)
	while locked:
		if RESTORE_STOP.is_set():
			raise KeyboardInterrupt
		recorded, locked = read_recorded_monitor_paths(job_vault, timeout=RESTORE_WAIT_SECONDS)
	if recorded is None:
		print("Note: the vault's record of monitored paths cannot be read; links are judged by their text", file=stream, flush=True)
	return recorded

def written_under(monitor_paths:list, number:int, monitor_path:str) -> str:
	'''
	The monitored path the version numbered number was written under: the last of monitor_paths ([first version,
	path], oldest first) starting at or below it. A version below the first pair, written before 0.44 recorded any, is
	taken for the first pair's path, the one the job had when the record began, as the job's path now (monitor_path,
	used only when nothing is recorded, None when not known) may have changed since.

	Examples:
		>>> pairs = [(0, '/a'), (3, '/b')]
		>>> [written_under(pairs, n, '/now') for n in (0, 2, 3, 9)], written_under([(4, '/b')], 2, '/now'), written_under([], 2, '/now')
		(['/a', '/a', '/b', '/b'], '/b', '/now')
	'''
	found = monitor_paths[0][1] if monitor_paths else monitor_path
	for first, path in monitor_paths:
		if first <= number:
			found = path
	return found

class VersionMoves:
	'''
	A version's move rows, applied in their order, and the rels its rows land on, which tell its chain links from
	users' symlinks of the same form (vault_chain_hop()). moves holds them as (source_rel, dest_rel, is_folder): rels
	of the monitored path the version was written under, with no leading /, a folder's ending with /, and source_rel
	None for a move row without a source. Rows whose event is move are the moves; an escalated create or modify
	carrying a source renamed nothing in the vault. The rels every row of any event lands on (the monitored root's
	own left out) are kept by their hash, which explains() asks, or not at all for the version being written, every
	entry of which its moves explain. usable is False when the rows cannot tell: the change list is missing,
	unreadable, cut short (its last line unended, as by a crash in the middle of an append, before 0.44 wrote change
	lists whole) or holds no rows (every version after the first has one), or a row lies outside the monitored path;
	why says which.
	of_committed() reads a committed version's change list, once, when first asked; applied() takes the moves the
	replay of the version being written has made, before its change list exists.

	Examples:
		>>> moves = VersionMoves.applied([('d/x', 'e/x', False), ('d/', 'f/', True), ('f/y', 'y', False), (None, 'n/', True)])
		>>> moves.usable, moves.takes('d/x', 'e/x'), moves.takes('d/z/w', 'f/z/w'), moves.takes('d/y', 'y'), moves.takes('d/x', 'f/x')
		(True, True, True, True, False)
		>>> moves.takes('a', 'a'), moves.takes('a', 'n/a'), moves.takes('a', 'n/b/c')
		(True, None, None)
		>>> moves.touches('d/x'), moves.touches('d/q'), moves.touches('e/x'), moves.touches('a')
		(True, True, False, False)
		>>> rows = VersionMoves(moves=[], landed={'a/', 'b/x'})
		>>> rows.explains('a/u/v'), rows.explains('b/x'), rows.explains('b/y'), moves.explains('anything')
		(True, True, False, True)
	'''
	def __init__(self, moves:list = None, usable:bool = True, why:str = '', key:tuple = None, change_list_folder:str = None,
			landed = None):
		self._moves = moves
		self._landed = None if landed is None else frozenset(hash(rel) for rel in landed)
		self._usable = usable
		self.why = why
		# (version folder, the monitored path its rows are read under) of a committed version; None for the version
		# being written
		self.key = key
		# the job vault to find a committed version's change list in, until it is read
		self._job_vault = change_list_folder
		self.rows = 0
		self._lock = threading.Lock()

	@classmethod
	def of_committed(cls, job_vault:str, version_path:str, monitor_path:str, monitor_paths:list = None) -> 'VersionMoves':
		'''
		The moves of the committed version at version_path, as its change list records them under the monitored path
		the version was written under (written_under()): by monitor_paths (VaultManifest.monitor_paths; read from
		job_vault's manifest when None), or monitor_path, the job's path now, when they record none. When the record
		cannot be read (the manifest locked, say), or no path is known, the rows cannot be used: read under a path they
		were not written under, they could refuse a real chain link. Kept by the version and the path its rows are read
		under, so an answer read under one path is never given for another. The list is found by listing job_vault for
		the version folder's name, not by the sizes its name records, and is read when an answer first needs it: a
		version whose links all sit where the text says needs no rows.
		'''
		version_path = os.path.abspath(version_path)
		recorded = recorded_monitor_paths(job_vault) if monitor_paths is None else monitor_paths
		if recorded is None:
			return cls.unreadable_record(version_path)
		number = vault_version_number(os.path.basename(version_path))
		monitor = written_under(recorded, -1 if number is None else number, monitor_path)
		if monitor is None:
			return cls(moves=[], usable=False, why='the monitored path it was written under is not known', key=(version_path, ''))
		key = (version_path, os.path.abspath(monitor))
		with VERSION_MOVES_LOCK:
			known = VERSION_MOVES.get(key)
			if known is not None:
				VERSION_MOVES.move_to_end(key)
				return known
		return cls(moves=None, usable=False, key=key, change_list_folder=os.path.abspath(job_vault), landed=())

	@classmethod
	def unreadable_record(cls, version_path:str) -> 'VersionMoves':
		'''The moves of the committed version at version_path when the record of monitored paths cannot be read.'''
		return cls(moves=[], usable=False, why='the record of the monitored paths its versions were written under cannot be read', key=(os.path.abspath(version_path), ''))

	@classmethod
	def applied(cls, moves:list) -> 'VersionMoves':
		'''
		The moves the replay of the version being written has applied, as (source_rel, dest_rel, is_folder) in its
		order. The replay made every entry of the version, so a link they do not explain is not one of its chain links.
		'''
		return cls(moves=list(moves), usable=True)

	def _read(self) -> None:
		'''Read a committed version's moves, the first time they are asked for.'''
		with self._lock:
			if self._job_vault is None:
				return
			version_path, monitor = self.key
			moves, landed, why, lasting = read_version_moves(self._job_vault, version_path, monitor)
			self._moves, self._usable, self.why = moves or [], moves is not None, why
			self._landed = landed
			# what it holds: a rel for each row landing somewhere, and the moves among them
			self.rows = max(len(self._moves), len(landed))
			self._job_vault = None
		if lasting:
			remember_version_moves(VERSION_MOVES, self.key, self)

	@property
	def moves(self) -> list:
		self._read()
		return self._moves

	@property
	def usable(self) -> bool:
		self._read()
		return self._usable

	def lands_without_source(self, rel:str) -> bool:
		'''Whether a move row without a source lands on rel or on a folder above it.'''
		return any(source is None and (dest.rstrip('/') == rel or rel.startswith(dest.rstrip('/') + '/'))
			for source, dest, _ in self.moves)

	def takes(self, source_rel:str, dest_rel:str) -> 'bool | None':
		'''
		Whether the moves, applied in order to a file or to a folder and what is under it, take source_rel to dest_rel;
		None when that cannot be told, as a move row without a source lands on dest_rel or a folder above it.
		'''
		if self.lands_without_source(dest_rel):
			return None
		path = source_rel
		for source, dest, is_folder in self.moves:
			if source is None:
				continue
			if is_folder:
				if path.startswith(source):
					path = dest + path[len(source):]
			elif path == source:
				path = dest
		return path == dest_rel

	def touches(self, rel:str) -> bool:
		'''Whether any move applies to rel, itself or a folder above it: the first one to do so meets rel unmoved.'''
		return any(source is not None and (rel.startswith(source) if is_folder else rel == source)
			for source, _, is_folder in self.moves)

	def tells(self, named:str, rel:str, version_name:str) -> tuple:
		'''
		(verdict, why) for a link of the chain form at rel naming named in the version below, whose text is not the one
		the referenced copy writes at rel, by usable rows: True for a chain link, the moves taking named to rel (rel
		being named takes a move too, such as away and back); False for a user's symlink, a row landing on rel or a
		folder above it otherwise; None when that cannot be told, as no row lands there, or a move row without a
		source does (vault_chain_hop()). why says why for None, naming the version as version_name.
		'''
		taken = self.takes(named, rel)
		if taken is None:
			return None, f'a move without a source in {version_name} lands on {rel}'
		# a link at its own path with another depth's text is one only when a move took it away and back
		if taken and (named != rel or self.touches(named)):
			return True, ''
		if self.explains(rel):
			return False, ''
		return None, f'no row of {version_name} lands on {rel}, so its rows may be of another monitored path'

	def explains(self, rel:str) -> bool:
		'''
		Whether a row of the version, of any event, lands on rel or on a folder above it, so the rows account for what
		the version holds there. A user's symlink always has one: the create that copied it or a folder above it, a
		fix of the verification or a full comparison's create. A chain link under rows of another monitored path
		(shifted, when no record says which path the version was written under) has none, short of a collision.
		'''
		self._read()
		if self._landed is None:
			return True
		if hash(rel) in self._landed or hash(rel + '/') in self._landed:
			return True
		parts = rel.split('/')
		return any(hash('/'.join(parts[:depth]) + '/') in self._landed for depth in range(1, len(parts)))

def change_list_rows_ended(change_list:str) -> tuple:
	'''
	(ended, complete_rows) of the change list at change_list: whether its last line ends with a line feed, and, when it
	does not, how many rows came whole before the cut (its header not counted). complete_rows is None when ended.
	'''
	with open(change_list, 'rb') as f:
		f.seek(0, os.SEEK_END)
		if not f.tell():
			return False, 0
		f.seek(-1, os.SEEK_END)
		if f.read(1) == b'\n':
			return True, None
		f.seek(0)
		lines = sum(chunk.count(b'\n') for chunk in iter(lambda: f.read(1 << 20), b''))
	return False, max(lines - 1, 0)

def read_change_list_moves(change_list:str, monitor:str) -> tuple:
	'''
	(moves, landed, why, lasting, had_rows) for read_version_moves(), from the one change list at change_list, under
	the monitored path monitor (absolute and normalised). landed holds hashes of the rels.
	'''
	prefix = monitor if monitor.endswith('/') else monitor + '/'
	def rel_of(path:str):
		# the rule's monitored path as typed made the row, so './' or '//' in it are read as the path they name
		folder = path.endswith('/')
		path = os.path.normpath(path)
		if path == monitor:
			return ''
		return path[len(prefix):] + ('/' if folder else '') if path.startswith(prefix) else None
	moves = []
	landed = set()
	rows = 0
	try:
		ended, complete_rows = change_list_rows_ended(change_list)
		if not ended:
			# told before any row, as its last row may have lost its source, or more of its path
			return None, frozenset(), 'its change list was cut short in its last row', True, complete_rows > 0
		for row in iter_change_list(change_list):
			rows += 1
			dest = rel_of(row.path)
			source = None if row.source_path is None else rel_of(row.source_path)
			if dest is None or (row.source_path is not None and source is None):
				return None, frozenset(), f'a row outside {monitor} ({row.path if dest is None else row.source_path}), which it was backed up from', True, True
			if dest:
				landed.add(hash(dest))
			if row.event == 'move':
				moves.append((source, dest, dest.endswith('/')))
	except (OSError, ValueError) as e:
		return None, frozenset(), f'its change list cannot be read: {e}', False, False
	if not rows:
		return None, frozenset(), 'its change list has no rows', True, False
	return moves, frozenset(landed), '', True, True

def read_version_moves(job_vault:str, version_path:str, monitor:str) -> tuple:
	'''
	(moves, landed, why, lasting) for VersionMoves.of_committed(): the move rows of the change list of the version at
	version_path, which job_vault is listed for, as (source_rel, dest_rel, is_folder) under monitor, the monitored path
	it was written under (absolute and normalised), and the hashes of the rels all its rows land on; moves is None, and
	why says why, when the rows cannot be used. lasting says whether every list was read in full, so the answer is the
	same every time. Of two lists for one version (pruning makes a header-only one when the name it works out from the
	recorded sizes is not there), the one with rows counts.
	'''
	name = os.path.basename(version_path)
	try:
		change_lists = sorted(entry for entry in os.listdir(job_vault) if (parse_change_list_name(entry) or (None, None))[1] == name)
	except (OSError, ValueError) as e:
		return None, frozenset(), f'the job vault cannot be listed: {e}', False
	if not change_lists:
		return None, frozenset(), 'it has no change list', False
	read = [read_change_list_moves(os.path.join(job_vault, entry), monitor) for entry in change_lists]
	moves, landed, why, _, _ = next((found for found in read if found[4]), read[0])
	return moves, landed, why, all(found[3] for found in read)

class UnexplainedChainLink(UncheckedVaultLink):
	'''
	A link of the chain form whose version's rows neither take it there nor account for it otherwise: no row lands on
	it or a folder above it, or a move row without a source does. Such a link can be a chain link under rows that
	cannot reveal it, so pruning and reading follow target, the hop its text names, as for a chain link.
	'''
	def __init__(self, message:str, target:str):
		super().__init__(message)
		self.target = target

def vault_chain_hop(job_vault:str, link_path:str, link_text:str, moves:VersionMoves) -> 'str | None':
	'''
	Where the link at link_path with link_text leads if it is a chain link of its version, whose moves are moves; else
	None, as for a user's symlink backed up as one. Raises UncheckedVaultLink, and nothing else, when that cannot be
	told: UnexplainedChainLink, carrying the hop, when the rows cannot tell. With R the link's path in its version, R'
	the path its text names in the version below and u its count of ../, a link the text rule takes
	(strict_chain_hop(): relative, the previous version's whole name, real folders on the way), whose target is not a
	real folder (the daemon links files only), is a chain link when:
	- R' is R and u is R's own depth + 1, the text the referenced copy writes: no rows are read;
	- else, when the moves take R' to R. Any u is then fine, as a retarget that failed, or a daemon before 0.39, keeps
	  the old text; R' being R takes a move too, such as away and back.
	It is not one when the moves do not take it there and a row of the version lands on R or a folder above it, as
	every user's symlink has one (VersionMoves.explains()). With no such row, or with a move row without a source
	landing there, that cannot be told: the rows of a version written under a monitored path that no record names
	may be shifted. A version whose rows cannot be used (usable is False) goes by the text alone, u not counted, as
	refusing a moved chain link would lose its copy; one warning is logged for each such version.

	Examples:
		>>> import tempfile
		>>> job_vault = tempfile.mkdtemp()
		>>> os.makedirs(os.path.join(job_vault, 'V3--2021-01-01_00-00-00_-0800', 'a', 'f'))
		>>> link_path = os.path.join(job_vault, 'V4--2021-01-02_00-00-00_-0800', 'a', 'u')
		>>> none, moved = VersionMoves.applied([]), VersionMoves.applied([('b/u', 'a/u', False)])
		>>> vault_chain_hop(job_vault, link_path, '../../V3--2021-01-01_00-00-00_-0800/a/u', none)[len(job_vault):]
		'/V3--2021-01-01_00-00-00_-0800/a/u'
		>>> [vault_chain_hop(job_vault, link_path, text, none) for text in ('../V3--2021-01-01_00-00-00_-0800/a/u',
		...     '../../V3--2021-01-01_00-00-00_-0800/b/u', '../../V3--2021-01-01_00-00-00_-0800/a/f',
		...     job_vault + '/V3--2021-01-01_00-00-00_-0800/a/u')]
		[None, None, None, None]
		>>> [vault_chain_hop(job_vault, link_path, text, moved)[len(job_vault):] for text in ('../../V3--2021-01-01_00-00-00_-0800/b/u',
		...     '../V3--2021-01-01_00-00-00_-0800/b/u')]
		['/V3--2021-01-01_00-00-00_-0800/b/u', '/V3--2021-01-01_00-00-00_-0800/b/u']
		>>> try:
		...     vault_chain_hop(job_vault, link_path, '../../V3--2021-01-01_00-00-00_-0800/b/u', VersionMoves(moves=[], landed={'c/'}))
		... except UnexplainedChainLink as e:
		...     print('cannot tell, by the text', e.target[len(job_vault):])
		cannot tell, by the text /V3--2021-01-01_00-00-00_-0800/b/u
		>>> import shutil; shutil.rmtree(job_vault)
	'''
	# strict_chain_hop() and chain_link_target(), keeping the parse
	parsed = None if os.path.isabs(link_text) else parse_chain_text(job_vault, link_text, link_path)
	if parsed is None:
		return None
	name, named_parts, ups = parsed
	vault = os.path.abspath(job_vault)
	target = os.path.join(vault, name, *named_parts)
	if not is_real_folder_under(os.path.join(vault, name), os.path.dirname(target)):
		return None
	# told before any row, so no row can make pruning rename a folder onto a link
	try:
		if stat.S_ISDIR(os.lstat(target).st_mode):
			# the daemon links files only, and makes every folder a real one
			return None
	except (FileNotFoundError, NotADirectoryError):
		# a chain link whose copy is gone is still one
		pass
	except OSError as e:
		if e.errno == errno.ENAMETOOLONG:
			# a name too long to use: the daemon reaches its copies by path, so none is behind it
			return None
		raise UncheckedVaultLink(e) from e
	except ValueError as e:
		raise UncheckedVaultLink(e) from e
	version_name, _, rel = os.path.abspath(link_path)[len(vault) + 1:].partition('/')
	named = '/'.join(named_parts)
	if named == rel and ups == rel.count('/') + 1:
		return target
	if not moves.usable:
		if moves.key is not None and moves.key not in VERSION_MOVES_WARNED:
			remember_version_moves(VERSION_MOVES_WARNED, moves.key, None)
			backuperTeeLogToTl(path=moves.key[0],warning=True,message=f'Telling the moved links of {version_name} by their text alone, as its moves cannot be used: {moves.why}')
		return target
	verdict, why = moves.tells(named, rel, version_name)
	if verdict is None:
		raise UnexplainedChainLink(why, target)
	return target if verdict else None

class CommittedMoves:
	'''
	VersionMoves.of_committed() of a version of vault (a VaultMoves), made when an answer first needs it, so a link
	sitting where its text says, which needs no rows, never has the record of monitored paths read either.
	'''
	def __init__(self, vault:'VaultMoves', version_path:str):
		self._vault = vault
		self._version_path = version_path
		self._moves = None
		self._lock = threading.Lock()

	def _get(self) -> VersionMoves:
		with self._lock:
			if self._moves is None:
				recorded = self._vault.record()
				if recorded is None:
					self._moves = VersionMoves.unreadable_record(self._version_path)
				else:
					self._moves = VersionMoves.of_committed(self._vault.job_vault, self._version_path, self._vault.monitor_path, recorded)
			return self._moves

	def __getattr__(self, name):
		return getattr(self._get(), name)

class VaultMoves:
	'''
	The VersionMoves of the versions of job_vault, each asked for once and held for a whole pass (a removal of the
	oldest version, a history, a restore, a backup's reads of the vault), so a pass reads each change list once,
	however few VERSION_MOVES keeps meanwhile; release() lets a pass that is done with a version drop it. monitor_paths
	is the record of the monitored paths the versions were written under (VaultManifest.monitor_paths: the daemon's
	own connection gives it, as a read of its own could find the manifest locked by the daemon's own write); when None
	it is read_record(job_vault) (recorded_monitor_paths() when None), once, the first time a link needs rows.
	monitor_path is the job's path now, None when not known. writing is the folder of the version a backup is writing,
	which has no change list yet: its links go by their text alone, with no warning, as before 0.44.
	'''
	def __init__(self, job_vault:str, monitor_path:str = None, monitor_paths:list = None, writing:str = None, read_record = None):
		self.job_vault = os.path.abspath(job_vault)
		self.monitor_path = monitor_path
		self.monitor_paths = monitor_paths
		self.writing = None if writing is None else os.path.abspath(writing)
		self._read_record = recorded_monitor_paths if read_record is None else read_record
		self._record_read = monitor_paths is not None
		self._held = {}
		self._lock = threading.Lock()
		self._record_lock = threading.Lock()

	def record(self):
		'''The record of monitored paths, read the first time it is asked for; None when it cannot be read.'''
		with self._record_lock:
			if not self._record_read:
				self.monitor_paths = self._read_record(self.job_vault)
				self._record_read = True
			return self.monitor_paths

	def of(self, version) -> VersionMoves:
		'''The moves of version: a version folder's path, or anything with one as its path, such as a KeptVersion.'''
		path = os.path.abspath(getattr(version, 'path', version))
		with self._lock:
			held = self._held.get(path)
		if held is not None:
			return held
		if path == self.writing:
			moves = VersionMoves(moves=[], usable=False, why='it is being written')
		else:
			moves = CommittedMoves(self, path)
		with self._lock:
			return self._held.setdefault(path, moves)

	def release(self, version) -> None:
		'''Drop what is held for version (as of() takes it), once the pass will not ask for it again.'''
		with self._lock:
			self._held.pop(os.path.abspath(getattr(version, 'path', version)), None)

	def holding(self, path:str) -> 'VersionMoves | None':
		'''The moves of the version folder of job_vault that holds path, None when no folder of job_vault does.'''
		path = os.path.abspath(path)
		if not path.startswith(self.job_vault + '/'):
			return None
		return self.of(os.path.join(self.job_vault, path[len(self.job_vault) + 1:].partition('/')[0]))

	def hop(self, link_path:str, link_text:str) -> 'str | None':
		'''vault_chain_hop() of the link at link_path with link_text, by the moves of the version holding it.'''
		# an absolute link, or one outside the vault, is never a chain link: no rows to read for it
		moves = None if os.path.isabs(link_text) else self.holding(link_path)
		return None if moves is None else vault_chain_hop(self.job_vault, link_path, link_text, moves)

	def follow(self, link_path:str, link_text:str) -> 'str | None':
		'''
		hop(), but a link whose version's rows cannot tell (UnexplainedChainLink) is followed to the hop its text names,
		as reading and pruning follow a chain link. Raises UncheckedVaultLink when the link cannot be looked at.
		'''
		try:
			return self.hop(link_path, link_text)
		except UnexplainedChainLink as e:
			return e.target

def manifest_monitor_paths(manifest:VaultManifest):
	'''
	VaultManifest.monitor_paths, read on the daemon's own connection, for VaultMoves; None when that cannot be read, so
	the record is read from the manifest instead, and the rows count as unusable when that cannot be read either.
	'''
	try:
		return manifest.monitor_paths
	except (sqlite3.Error, ValueError, TypeError):
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

def retarget_moved_links(job_vault:str, moved_path:str, errors:list = None) -> int:
	'''
	retarget_chain_link() for the vault entry a move put at moved_path: the link itself, or every link under a folder.
	Returns how many links were rewritten. With errors, a link that cannot be rewritten and a folder that cannot be read
	are appended to it as (path, error) and the others are rewritten all the same: the links left keep their text,
	which still names their versions, so reading and pruning find their copies (chain_link_target() does not count the
	../). Without, the first link that cannot be rewritten raises.
	'''
	def retarget(path:str) -> bool:
		if errors is None:
			return retarget_chain_link(job_vault, path)
		try:
			return retarget_chain_link(job_vault, path)
		except OSError as e:
			errors.append((path, e))
			return False
	if os.path.islink(moved_path):
		return int(retarget(moved_path))
	if not os.path.isdir(moved_path):
		# a copy this backup made
		return 0
	rewritten = 0
	walk_errors = None if errors is None else []
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another
	for path, _, is_dir in iter_tree_entries(moved_path, list_folders_first=True, errors=walk_errors):
		if not is_dir and os.path.islink(path):
			rewritten += retarget(path)
	if walk_errors:
		errors.extend((unreadable_path(moved_path, rel), error) for rel, error in walk_errors)
	return rewritten

def effective_copy_version(recorded, oldest_kept:int):
	'''
	The number of the version holding a file's copy, from the one recorded when it was copied (None when not known) and
	the oldest version kept. Pruning a version moves its copies into the next one, which is then the oldest kept, so a
	recorded version older than that names where the copy is now.

	Examples:
		>>> effective_copy_version(4, 2), effective_copy_version(0, 5), effective_copy_version(None, 5)
		(4, 5, None)
	'''
	return None if recorded is None else max(recorded, oldest_kept)

ChainEnd = namedtuple('ChainEnd', ['number', 'path', 'st'])

def chain_end(job_vault:str, version_path:str, rel:str, moves:'VaultMoves' = None):
	'''
	Where the chain starting at version_path's file rel ends, as a ChainEnd: the number of the version folder holding
	it, its path and its lstat. The end is a copy, a user's symlink backed up as one or a referenced backup's link,
	each link told by the moves of its version (moves, a VaultMoves for the pass; one reading the manifest's record
	when None, which knows no monitored path for a version the record does not name). Each hop names an older version
	than the last, so the walk ends within as many hops as there are versions below version_path, however many more
	links than the kernel follows that is. None when the chain cannot be followed: a folder of rel in version_path is
	not a real folder (by is_real_folder_under()), an entry on the chain is missing or cannot be read, or a link on it
	cannot be looked at (UncheckedVaultLink).
	'''
	vault = os.path.abspath(job_vault)
	if moves is None:
		moves = VaultMoves(vault)
	number = vault_version_number(os.path.basename(os.path.normpath(version_path)))
	entry = os.path.abspath(os.path.join(version_path, rel))
	try:
		# a folder symlink would lead out of the version, to the monitored file say; each hop checks its own way down
		if not is_real_folder_under(os.path.abspath(version_path), os.path.dirname(entry)):
			return None
	except UncheckedVaultLink:
		return None
	while number is not None:
		try:
			st = os.lstat(entry)
			if not stat.S_ISLNK(st.st_mode):
				return ChainEnd(number, entry, st)
			hop = moves.follow(entry, os.readlink(entry))
		except (OSError, UncheckedVaultLink):
			return None
		if hop is None:
			return ChainEnd(number, entry, st)
		hop_number = vault_version_number(hop[len(vault) + 1:].partition('/')[0])
		if hop_number is None or hop_number >= number:
			# never so for a chain link, which names an older version: the walk only goes down
			return None
		entry, number = hop, hop_number
	return None

def learn_copy_version(job_vault:str, version_path:str, rel:str, moves:'VaultMoves' = None):
	'''
	The number of the version whose folder holds the end of the chain starting at version_path's file rel (a copy, a
	user's symlink backed up as one or a referenced backup's link), by chain_end(); None when the chain cannot be followed.
	'''
	end = chain_end(job_vault, version_path, rel, moves)
	return None if end is None else end.number

def recopy_threshold(rel:str) -> int:
	'''
	The most links a new version may chain to the copy of the file rel before it copies it again, from RECOPY_MIN_HOPS to
	RECOPY_MAX_HOPS by a hash of its name: files unchanged since the same version are not all copied again in one
	version, and each keeps its threshold across runs and versions.

	Examples:
		>>> recopy_threshold('a.txt'), recopy_threshold('bad\\udcff.txt')
		(38, 37)
	'''
	return RECOPY_MIN_HOPS + xxhash.xxh32(storable_name(rel).encode('utf-8')).intdigest() % (RECOPY_MAX_HOPS - RECOPY_MIN_HOPS + 1)

def recopy_rels(manifest:VaultManifest, new_version:int, oldest_kept:int, job_vault:str, latest_version_path:str, moves:'VaultMoves' = None) -> list:
	'''
	The files new_version is to copy again from the vault, sorted: those whose link chain would pass their
	recopy_threshold(), as new_version - effective_copy_version() says. While new_version is no more than RECOPY_MIN_HOPS
	above oldest_kept no chain can, so nothing is read at all: a job keeping 32 versions or fewer never pays for it.
	Otherwise a file whose copy version is not known (upgraded from schema '1') learns it from its chain in the latest
	version, read on a compare pool, and the vault database records it, committed unless a transaction was open already,
	as what is read from the vault holds whether or not a new version follows. One whose chain cannot be followed stays
	unknown, and is linked as ever. moves tells the links on the chains (chain_end()).
	'''
	if new_version - oldest_kept <= RECOPY_MIN_HOPS:
		return []
	own_transaction = not manifest.in_transaction
	manifest.begin()
	if not manifest.describes(latest_version_path):
		backuperTeeLogToTl(path=job_vault,message=f'Manifest does not describe {latest_version_path}, listing it')
		manifest.rebuild(latest_version_path)
	due = []
	unknown = []
	# the rows are read in full before any is written, as changing a table while reading it is undefined in sqlite
	for rel, recorded in manifest.iter_files_with_copy_version():
		if recorded is None:
			unknown.append(rel)
		elif new_version - effective_copy_version(recorded, oldest_kept) > recopy_threshold(rel):
			due.append(rel)
	learned = 0
	if unknown:
		with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
			for start in range(0, len(unknown), MANIFEST_BATCH_SIZE):
				if not GREEN_LIGHT.is_set():
					# stopping: no version follows, and what was learned is kept
					break
				batch = unknown[start:start + MANIFEST_BATCH_SIZE]
				by_version = {}
				for rel, version in zip(batch, pool.map(lambda rel: learn_copy_version(job_vault, latest_version_path, rel, moves), batch)):
					if version is None:
						continue
					by_version.setdefault(version, []).append(rel)
					if new_version - effective_copy_version(version, oldest_kept) > recopy_threshold(rel):
						due.append(rel)
				for version, rels in by_version.items():
					manifest.set_copy_version(rels, version)
					learned += len(rels)
		backuperTeeLogToTl(path=job_vault,message=f'Learned which version holds the copy of {learned} of {len(unknown)} files from their chains in {latest_version_path}')
	if own_transaction:
		manifest.commit()
	return sorted(due)

def batch_rewrites(backup_entries:dict, monitor_path:str, only_sync_attributes:bool, rels) -> tuple:
	'''
	(rewritten, deleted): which files of rels the batch backup_entries writes over, or removes, in the version it makes,
	by its own entry or that of a folder above it. The replay deletes first, then copies, then moves.
	- deleted: the file or a folder above it is deleted, so a copy of it made again from the vault would be gone before
	  anything else happens to it.
	- rewritten: the batch creates or modifies it, moves another file onto it, copies it for an attribute change (when
	  not only_sync_attributes), or creates or moves onto a folder above it, whose tree it copies file by file.
	A file moved away, or in a folder moved away, is neither, as the move takes its entry along.

	Examples:
		>>> entries = OrderedDict((path, BackupEntryValues('t', event, source)) for path, event, source in (('/m/a', 'modify', None),
		...     ('/m/d/', 'create', None), ('/m/c', 'delete', None), ('/m/e/', 'delete', None), ('/m/f', 'move', '/m/g'),
		...     ('/m/h', 'attrib', None), ('/m/k/', 'move', '/m/n/'), ('/m/d/p', 'move', '/m/d/q')))
		>>> rels = ['a', 'd/b', 'c', 'e/x', 'e/d/b', 'f', 'g', 'h', 'k/y', 'n/z', 'd/q', 'o']
		>>> [sorted(found) for found in batch_rewrites(entries, '/m', True, rels)]
		[['a', 'd/b', 'f', 'k/y'], ['c', 'e/d/b', 'e/x']]
		>>> 'h' in batch_rewrites(entries, '/m', False, rels)[0]
		True
	'''
	written, written_folders, deleted_files, deleted_folders, moved, moved_folders = set(), set(), set(), set(), set(), set()
	for path, values in backup_entries.items():
		rel = os.path.relpath(path, monitor_path)
		if rel == '.':
			continue
		# a folder's rel ends with /, as inside_folders() reads them
		folder = path.endswith('/')
		suffix = '/' if folder else ''
		if values.event == 'delete':
			(deleted_folders if folder else deleted_files).add(rel + suffix)
		elif values.event in ('create', 'modify', 'move') or (values.event == 'attrib' and not only_sync_attributes and not folder):
			(written_folders if folder else written).add(rel + suffix)
		if values.event == 'move' and values.source_path:
			(moved_folders if folder else moved).add(os.path.relpath(values.source_path, monitor_path) + suffix)
	rewritten, deleted = set(), set()
	for rel in rels:
		if rel in deleted_files or inside_folders(rel, deleted_folders):
			deleted.add(rel)
		elif rel in moved or inside_folders(rel, moved_folders):
			continue
		elif rel in written or inside_folders(rel, written_folders):
			rewritten.add(rel)
	return rewritten, deleted

def recopy_size(rels:list, job_vault:str, latest_version_path:str, moves:'VaultMoves' = None) -> int:
	'''
	The bytes copying rels again from the vault adds to a version: the size of the file each one's chain in the latest
	version ends at (chain_end(), by moves), nothing for a link, nor for a chain that cannot be followed, which keeps
	its link.
	'''
	total = 0
	for rel in rels:
		end = chain_end(job_vault, latest_version_path, rel, moves)
		if end is not None and stat.S_ISREG(end.st.st_mode):
			total += end.st.st_size
	return total

def read_vault_record(version_path:str, rel:str, monitor_path:str, moves:'VaultMoves' = None):
	'''
	Record what version_path holds at rel, following the links that chain an unchanged entry back to its copy, each
	told by the moves of its version (moves, a VaultMoves for the pass; one reading the manifest's record when None).
	Returns None when there is nothing readable there, or a link there cannot be looked at (UncheckedVaultLink).
	'''
	entry = os.path.abspath(os.path.join(version_path, rel))
	try:
		if rel.endswith('/'):
			st = os.lstat(entry)
			if not stat.S_ISDIR(st.st_mode):
				return None
			return ManifestRecord('d', None, None, st.st_mode, st.st_uid, st.st_gid, None, None, 0)
		job_vault = os.path.dirname(os.path.abspath(version_path))
		if moves is None:
			moves = VaultMoves(job_vault, monitor_path)
		monitor_entry = os.path.abspath(os.path.join(monitor_path, rel))
		for _ in range(MAX_CHAINED_LINKS):
			st = os.lstat(entry)
			if not stat.S_ISLNK(st.st_mode):
				break
			target = os.readlink(entry)
			resolved = moves.follow(entry, target)
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

def read_copied_record(version_path:str, rel:str, monitor_path:str, moves:'VaultMoves' = None):
	'''read_vault_record() for an entry a backup just wrote: its file is still unchecked, as it was read from memory.'''
	record = read_vault_record(version_path, rel, monitor_path, moves)
	return record._replace(unchecked=1) if record is not None and record.kind == 'f' else record

def record_dirty_entries(manifest:VaultManifest, version_path:str, monitor_path:str):
	'''
	Record what version_path, the version this backup is writing, holds for the rows it wrote, reading them on a
	compare pool: its own links by their text alone, those of the committed versions below by their moves.
	'''
	moves = VaultMoves(os.path.dirname(os.path.abspath(version_path)), monitor_path, manifest_monitor_paths(manifest), writing=version_path)
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		while GREEN_LIGHT.is_set():
			rels = manifest.take_dirty(MANIFEST_BATCH_SIZE)
			if not rels:
				return
			manifest.set_records(zip(rels, pool.map(lambda rel: read_copied_record(version_path, rel, monitor_path, moves), rels)))

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

def kernel_cannot_follow(version_path:str, rel:str, record:ManifestRecord) -> bool:
	'''
	Whether version_path holds at rel a chain of links to the file record was read from that the kernel cannot follow.
	Daemons before 0.39 kept a link's text when a move took it to another folder depth, so it no longer reaches the
	copy: read_vault_record() still finds the copy by chain_link_target(), but browsing the vault does not, nor does
	copy_file_meta() syncing attributes through the link.
	'''
	if record.kind not in ('f', 'o'):
		# a folder is never a link, and a user's symlink or a referenced backup's link is not followed
		return False
	entry = os.path.join(version_path, rel)
	return os.path.islink(entry) and not os.path.exists(entry)

def read_version_record(version_path:str, rel:str, monitor_path:str, fresh:bool = False, moves:'VaultMoves' = None):
	'''
	read_vault_record(), for a fresh version_path: one a backup is still writing, where a regular file in the version
	itself (reached by no link) is a copy this backup made, so its record stays unchecked, as read_copied_record() gives.
	'''
	record = read_vault_record(version_path, rel, monitor_path, moves)
	if fresh and record is not None and record.kind == 'f':
		try:
			copied = stat.S_ISREG(os.lstat(os.path.join(version_path, rel)).st_mode)
		except OSError:
			copied = False
		if copied:
			record = record._replace(unchecked=1)
	return record

def compare_entry(monitor_entry:str, rel:str, record:ManifestRecord, version_path:str, monitor_path:str, fresh:bool = False, moves:'VaultMoves' = None):
	'''
	Compare one tracked entry for delta generation, on the compare pool; with fresh, version_path is the version a
	backup is writing (read_version_record()). moves tells the vault's links, as read_vault_record() says.
	Returns (event or None, a record read from the vault to store or None).
	'''
	found = None
	if record.kind is None:
		found = read_version_record(version_path, rel, monitor_path, fresh, moves)
		if found is None:
			backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Cannot read {os.path.join(version_path, rel)} from the vault, treating as create')
			return 'create', None
		record = found
	elif record.unchecked:
		# a crash soon after a backup can leave its copies at the right size and mtime over bytes that never reached the disk
		found = read_version_record(version_path, rel, monitor_path, fresh, moves)
		if found is None or (found.size, found.mtime_ns, found.hash) != (record.size, record.mtime_ns, record.hash):
			backuperTeeLogToTl(path=monitor_entry,error=True,message=f'Vault copy at {os.path.join(version_path, rel)} does not match its record, copying again')
			return 'modify', None
	if found is not None and kernel_cannot_follow(version_path, rel, found):
		# copied again, the new version holds a real copy; the link stays in the older versions until pruning materialises it
		backuperTeeLogToTl(path=monitor_entry,message=f'{os.path.join(version_path, rel)} links to its copy by a path the kernel cannot follow, as a move to another folder depth left it before 0.39, copying again')
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

# what a comparison covers: subtrees are folder rels ending with /, each compared with everything under it ('' for the
# whole tree), and paths are file rels or folder rels ending with /, each compared alone
TouchedScopes = namedtuple('TouchedScopes', ['subtrees', 'paths'])

def scope_folders(rel:str) -> list:
	'''
	The subtree scopes that cover rel, outermost first: the whole tree, each folder above rel, and rel itself as a
	folder, whose walk finds rel whatever it now is.

	Examples:
		>>> scope_folders('a/b.txt')
		['', 'a/', 'a/b.txt/']
		>>> scope_folders('D/')
		['', 'D/']
	'''
	parts = rel.rstrip('/').split('/')
	return [''] + ['/'.join(parts[:depth]) + '/' for depth in range(1, len(parts) + 1)]

def scope_path_entry(monitor_path:str, rel:str, skip = None, errors:list = None):
	'''
	The entry at rel of monitor_path (a file rel, or a folder rel ending with /) as (entry path, rel, is_dir), the way
	the walk of its parent would yield it: under the rel of what it now is, which can be the other kind. None when it
	is gone or skip leaves it out; when it cannot be looked at, (rel, error) is appended to errors as for a folder that
	cannot be read.
	'''
	name = rel.rstrip('/')
	path = os.path.join(monitor_path, name)
	try:
		is_dir = stat.S_ISDIR(os.lstat(path).st_mode)
	except (FileNotFoundError, NotADirectoryError):
		return None
	except OSError as e:
		if errors is not None:
			errors.append((rel, e))
		backuperTeeLogToTl(path=path,error=True,message=f'Error scanning {path}: {e}')
		return None
	entry_rel = name + '/' if is_dir else name
	if skip is not None and skip(entry_rel):
		return None
	return (path + '/' if is_dir else path), entry_rel, is_dir

def compare_scopes(backup_entries:dict, manifest:VaultManifest, version_path:str, monitor_path:str, scopes:TouchedScopes, skip = None, paused:set = frozenset(), job_name:str = '', reported:set = None, trusted = frozenset(), attributes:bool = True, fresh:bool = False) -> int:
	'''
	Add to backup_entries what differs between scopes of monitor_path and the manifest rows describing version_path,
	in the caller's transaction: nothing is begun, committed or rolled back here, so the rows can be the ones a backup
	is still writing, and version_path the version it is writing. Returns the number of tracked entries compared.

	The vault is read, at version_path only, for unverified rows and unchecked copies, and what is read is recorded, as
	delta_generate_backup_entries() describes. The trusted rels are rows this backup wrote from the monitored tree and
	has not recorded yet: they are compared for presence, and for kind as far as their rel tells a folder from a file,
	and never read back, so their copies stay unchecked. With fresh, version_path is that uncommitted version, and a
	file read there as a real file of its own (a re-copy, or a copy a move carried) is recorded unchecked too.
	Without attributes, attribute-only differences are left out.
	Each subtree is walked, and the rows at or under it the walk did not find are deleted (every such row for the whole
	tree); each path is looked up alone, a folder without its contents, and the root is never one. A scope nested in a
	subtree is compared once, with the subtree, and so is an entry two paths name. The scopes are taken in the order of
	their rels, so a folder comes before what lies under it.
	A folder that cannot be read keeps its tracked entries and is logged as UNREADABLE; when the monitored root itself
	cannot be read, before the pass or at its end, JobFailure is raised before anything is found deleted. skip (a skip list's skips) and the paused
	inner mounts leave entries out of the walks; the paused ones keep their tracked rows, and a scope that is skipped or
	in a paused folder compares nothing. The vault's links are told by the moves of their versions (VaultMoves), by
	the record of monitored paths on the manifest's own connection.
	'''
	start_time = time.monotonic()
	skip = skip_paused(skip, paused)
	moves = VaultMoves(os.path.dirname(os.path.abspath(version_path)), monitor_path, manifest_monitor_paths(manifest), writing=version_path if fresh else None)
	subtrees = []
	covered = set()
	# outermost first, as a folder's rel is shorter than any rel under it
	for rel in sorted(set(scopes.subtrees), key=len):
		if rel and any(folder in covered for folder in scope_folders(rel)):
			continue
		if rel and skips_folder_or_parent(skip, rel):
			backuperTeeLogToTl(path=monitor_path,message=f'Not comparing {rel}: it is skipped or in an unmounted inner mount')
			continue
		covered.add(rel)
		subtrees.append(rel)
	subtrees.sort()
	paths = []
	for rel in sorted(set(scopes.paths)):
		if not rel.strip('/'):
			# the root is compared only as the whole tree
			continue
		if any(folder in covered for folder in scope_folders(rel)):
			continue
		parent = rel.rstrip('/').rpartition('/')[0]
		if (parent and skips_folder_or_parent(skip, parent + '/')) or (skip is not None and skip(rel)):
			continue
		paths.append(rel)
	if paths or any(subtrees):
		try:
			# a scope missing along with the monitored root is not a deleted scope
			os.stat(monitor_path)
		except OSError as e:
			raise JobFailure(f'cannot read {monitor_path}: {e}')
	manifest.clear_seen()
	pending = deque()
	seen = []
	compared = 0
	recorded = 0
	walk_errors = []
	path_errors = []
	def settle(limit):
		nonlocal recorded
		while len(pending) > limit:
			monitor_entry, rel, outcome = pending.popleft()
			event, found = outcome.result() if isinstance(outcome, Future) else outcome
			if found is not None:
				manifest.set_records(((rel, found),))
				recorded += 1
			if event and (attributes or event != 'attrib'):
				backup_entries[monitor_entry] = BackupEntryValues(datetime.datetime.now().isoformat(),event,None)
	def walk(rel):
		return iter_scope_entries(monitor_path,rel,skip=skip,errors=walk_errors) if rel else iter_tree_entries(monitor_path,skip=skip,errors=walk_errors)
	# a subtree as a file, before it became a folder: no row under the subtree, so not found deleted there
	stale_files = {rel[:-1] for rel in subtrees if rel and manifest.lookup(rel[:-1]) is not None}
	# the tracked paths gone from the tree, or now of the other kind
	gone = []
	# results are taken in walk order, so a new tree still lists each folder before its contents
	with ThreadPoolExecutor(max_workers=COMPARE_THREADS) as pool:
		def compare(monitor_entry, rel):
			nonlocal compared
			record = manifest.lookup(rel)
			if record is None:
				pending.append((monitor_entry, rel, ('create', None)))
			else:
				compared += 1
				seen.append(rel)
				if len(seen) >= MANIFEST_BATCH_SIZE:
					manifest.mark_seen(seen)
					seen.clear()
				if rel in trusted:
					# this backup just copied it from the tree, as the kind its rel tells
					pending.append((monitor_entry, rel, (None, None)))
				else:
					pending.append((monitor_entry, rel, pool.submit(compare_entry, monitor_entry, rel, record, version_path, monitor_path, fresh, moves)))
			settle(COMPARE_THREADS * 4)
		# the entries the paths found, as X and X/ name the same one
		path_entries = set()
		# subtrees and paths in the order of their rels: a folder named only as a path comes before a subtree under it
		for rel, is_subtree in sorted([(rel, True) for rel in subtrees] + [(rel, False) for rel in paths]):
			if not GREEN_LIGHT.is_set():
				break
			if is_subtree:
				for monitor_entry, entry_rel, _ in walk(rel):
					if not GREEN_LIGHT.is_set():
						break
					stale_files.discard(entry_rel)
					compare(monitor_entry, entry_rel)
				continue
			errors = len(path_errors)
			entry = scope_path_entry(monitor_path, rel, skip=skip, errors=path_errors)
			if entry is not None and entry[1] not in path_entries:
				path_entries.add(entry[1])
				compare(entry[0], entry[1])
			if (entry is None or entry[1] != rel) and len(path_errors) == errors and manifest.lookup(rel) is not None:
				gone.append(rel)
		settle(0)
	manifest.mark_seen(seen)
	root_error = next((error for rel, error in walk_errors if not rel), None)
	if root_error is not None:
		raise JobFailure(f'cannot read {monitor_path}: {root_error}')
	if GREEN_LIGHT.is_set() and (paths or subtrees):
		try:
			# a root gone during the pass would leave every scope after that point looking deleted
			os.stat(monitor_path)
		except OSError as e:
			raise JobFailure(f'cannot read {monitor_path}: {e}')
	# a folder that could not be read keeps its entries, and so does a subtree when it could not be looked at
	manifest.mark_seen(rel for rel, _ in walk_errors)
	for rel, _ in walk_errors:
		manifest.mark_seen_under(rel)
	# an unmounted inner disk keeps its last backed-up contents
	paused_here = [rel for rel in paused if any(folder in covered for folder in scope_folders(rel))]
	manifest.mark_seen(paused_here)
	for rel in paused_here:
		manifest.mark_seen_under(rel)
	log_unreadable(job_name, monitor_path, walk_errors + path_errors, reported)
	if GREEN_LIGHT.is_set():
		# only a complete walk tells deleted entries from ones it did not reach
		deleted = []
		for rel in subtrees:
			if rel[:-1] in stale_files and not any(error_rel == rel for error_rel, _ in walk_errors):
				deleted.append(rel[:-1])
			deleted.extend(manifest.unseen_under(rel) if rel else manifest.unseen())
		deleted.extend(gone)
		for rel in deleted:
			backuperTeeLogToTl(path=monitor_path,message=f'Deleted file/folder {os.path.join(monitor_path,rel)}')
			backup_entries[os.path.join(monitor_path,rel)] = BackupEntryValues(datetime.datetime.now().isoformat(),'delete',None)
	if paths or len(subtrees) != 1:
		count = len(subtrees) + len(paths)
		compared_what = f' in {count} touched scope{"" if count == 1 else "s"}'
	else:
		compared_what = f' under {subtrees[0]}' if subtrees[0] else ''
	backuperTeeLogToTl(path=monitor_path,message=f'Compared {compared} tracked entries{compared_what} in {time.monotonic() - start_time:.1f}s, {recorded} read from the vault, {len(backup_entries)} differences')
	return compared

def sweep_version_folder(manifest:VaultManifest, version_path:str, scopes:TouchedScopes) -> tuple:
	'''
	Make the folder of the version a backup is writing, version_path, agree with the manifest rows describing it under
	each subtree of scopes. Returns (removed, missing), as rels (a folder's ending with /):
	- removed: each entry there that no row tracks, as a failed rename's copy fallback can leave one, is removed. A link
	  is removed as a link, never followed, and a folder that holds tracked entries is looked into instead.
	- missing: the tracked rels at or under each subtree that have no entry of their kind there.
	A tracked rel whose place lies behind a link or a file of the version (a folder above it, or for a folder its own
	entry, is not a real folder) cannot be held there: its row is dropped and it is counted as removed, never as missing,
	as copying it would write through the link.
	Only what lies in version_path through real folders is looked at or removed, and never version_path itself.
	'''
	removed = []
	missing = []
	subtrees = set(scopes.subtrees)
	if '' in subtrees:
		# the whole version
		subtrees = {''}
	for scope in sorted(subtrees):
		if scope and inside_folders(scope, subtrees):
			continue
		# the entries found in the version, and the folders that could not be listed, whose rows are not missing
		found = set()
		unlisted = []
		folders = []
		if not scope:
			folders.append((version_path, ''))
		else:
			parent_real = True
			parts = scope.rstrip('/').split('/')
			for depth in range(1, len(parts)):
				try:
					parent_real = stat.S_ISDIR(os.lstat(os.path.join(version_path, *parts[:depth])).st_mode)
				except FileNotFoundError:
					parent_real = False
				except OSError as e:
					backuperTeeLogToTl(path=version_path,error=True,message=f'Cannot look at {os.path.join(version_path, *parts[:depth])}: {e}')
					parent_real = False
					unlisted.append(scope)
				if not parent_real:
					break
			if parent_real:
				name = scope[:-1]
				try:
					is_dir = stat.S_ISDIR(os.lstat(os.path.join(version_path, name)).st_mode)
				except FileNotFoundError:
					is_dir = None
				except OSError as e:
					backuperTeeLogToTl(path=version_path,error=True,message=f'Cannot look at {os.path.join(version_path, name)}: {e}')
					is_dir = None
					unlisted.append(scope)
				if is_dir is not None:
					folders = sweep_entry(manifest, version_path, os.path.join(version_path, name), scope if is_dir else name, is_dir, found, removed)
		while folders:
			folder_path, folder_rel = folders.pop()
			try:
				with os.scandir(folder_path) as listing:
					entries = [(entry.path, entry.name, entry.is_dir(follow_symlinks=False)) for entry in listing]
			except OSError as e:
				backuperTeeLogToTl(path=version_path,error=True,message=f'Cannot list {folder_path}: {e}')
				unlisted.append(folder_rel)
				continue
			for path, name, is_dir in sorted(entries, key=lambda entry: entry[1]):
				folders.extend(sweep_entry(manifest, version_path, path, folder_rel + name + ('/' if is_dir else ''), is_dir, found, removed))
		tracked = [rel for rel in (scope, scope[:-1]) if rel and manifest.lookup(rel) is not None]
		tracked += list(manifest.iter_under(scope)) if scope else list(manifest.iter_folders()) + list(manifest.iter_files())
		for rel in tracked:
			if rel in found or any(rel.startswith(folder) or rel + '/' == folder for folder in unlisted):
				continue
			entry = os.path.join(version_path, rel.rstrip('/'))
			if not real_folders_to(version_path, rel, missing_ok=True) or (rel.endswith('/') and os.path.lexists(entry) and (os.path.islink(entry) or not os.path.isdir(entry))):
				backuperTeeLogToTl(path=version_path,message=f'Not tracking {rel}: its place in the version is behind a link or a file')
				manifest.discard(rel)
				removed.append(rel)
			else:
				missing.append(rel)
	return removed, missing

def sweep_entry(manifest:VaultManifest, version_path:str, path:str, rel:str, is_dir:bool, found:set, removed:list) -> list:
	'''
	sweep_version_folder() for the entry at path, rel in version_path: kept and added to found when it is tracked,
	removed and appended to removed when not. Returns [(path, rel)] for a folder to look into, else [].
	'''
	if manifest.lookup(rel) is not None:
		found.add(rel)
		return [(path, rel)] if is_dir else []
	if is_dir and next(manifest.iter_under(rel), None) is not None:
		# not tracked itself, yet holding tracked entries
		return [(path, rel)]
	if rel.strip('/') in ('', '.') or not os.path.normpath(path).startswith(os.path.normpath(version_path) + '/'):
		# never the version itself, nor anything outside it
		return []
	if not real_folders_to(version_path, rel):
		# a folder above it is not a real folder of the version ( the walk only goes through real ones ): removing it
		# would reach through a link
		backuperTeeLogToTl(path=version_path,error=True,message=f'Not removing {path}: a folder above it in the version is not a real folder')
		return []
	try:
		# a link is unlinked, never followed; a real folder goes with everything in it
		remove_entry(path)
	except OSError as e:
		backuperTeeLogToTl(path=version_path,error=True,message=f'Cannot remove {path}, which the version does not track: {e}')
		return []
	backuperTeeLogToTl(path=version_path,message=f'Removed {path}, which the version does not track')
	removed.append(rel)
	return []

def delta_generate_backup_entries(backupEntries:dict,latest_version_info:VaultEntry,monitor_path:str,manifest:VaultManifest = None,skip_list:'SkipList' = None,job_name:str = '',reported:set = None,scope_rel = '',paused:set = None) -> VaultManifest:
	'''
	Add to backupEntries what changed in monitor_path since the latest version, comparing against its manifest
	(compare_scopes() over the whole tree, or scope_rel) in a transaction of its own, which it commits.

	Unchanged entries are recognised from the recorded size, mtime, mode, owner and tail hash, so only the monitored
	side is read. The vault is read for unverified rows, which then get recorded, and for unchecked copies, which a
	crash may have left without their bytes.
	A folder that cannot be read keeps its tracked entries and is logged as UNREADABLE; when the monitored root itself
	cannot be read, JobFailure is raised before anything is recorded as deleted.
	With scope_rel, a folder rel ending with /, only that folder is compared: it is looked up like any entry, and only
	tracked rows at or under it can be found deleted. scope_rel can also be a TouchedScopes, as touched_scopes() gives
	for a batch: only its scopes are compared, as compare_scopes() compares them.
	The paused inner mounts (paused_inner_mounts, from the remembered ones and the mount table now when not given) are
	not walked and keep their tracked rows; a scope that is skipped or inside a paused folder compares nothing.
	Returns the manifest, opened in the job vault when none is given.
	'''
	if manifest is None:
		manifest = VaultManifest(os.path.dirname(os.path.abspath(latest_version_info.path)))
	skips = None if skip_list is None else skip_list.skips
	if paused is None:
		paused = paused_inner_mounts(monitor_path, manifest.inner_mounts, current_mount_table(), skips)
	scopes = scope_rel if isinstance(scope_rel, TouchedScopes) else TouchedScopes([scope_rel], [])
	if scope_rel:
		# checked before the transaction, as a scope compared nothing in leaves the manifest as it is. compare_scopes()
		# passes over each touched scope that is skipped
		if not isinstance(scope_rel, TouchedScopes) and skips_folder_or_parent(skip_paused(skips, paused), scope_rel):
			backuperTeeLogToTl(path=monitor_path,message=f'Not comparing {scope_rel}: it is skipped or in an unmounted inner mount')
			return manifest
		try:
			# a scope missing along with the monitored root is not a deleted scope
			os.stat(monitor_path)
		except OSError as e:
			raise JobFailure(f'cannot read {monitor_path}: {e}')
	version_path = latest_version_info.path
	manifest.prefetch()
	manifest.begin()
	if not manifest.describes(version_path):
		backuperTeeLogToTl(path=monitor_path,message=f'Manifest does not describe {version_path}, listing it to read from the vault')
		manifest.rebuild(version_path)
	try:
		compare_scopes(backupEntries, manifest, version_path, monitor_path, scopes, skip=skips, paused=paused, job_name=job_name, reported=reported)
	except JobFailure:
		manifest.rollback()
		raise
	# what was read from the vault holds whether or not a new version follows
	manifest.commit(version_path)
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
	# rtn = multiCMD.run_command(['df','--no-sync','--output=size,itotal',path],quiet=True)
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

def change_list_path(version_path:str, size:int, inodes:int) -> str:
	'''
	The change list of the version at version_path whose name records size bytes and inodes, rounded as format_bytes()
	writes them (parse_change_list_name() reads them back).

	Examples:
		>>> change_list_path('/v/job/V1--2021-01-01_00-00-00_-0800', 12288, 4)
		'/v/job/V1--2021-01-01_00-00-00_-0800--12.00_KiB-4.00_ino.modified_contents.nsv'
	'''
	size_str = format_bytes(size,use_1024_bytes=True,to_str=True).replace(' ','_')
	inode_str = format_bytes(inodes,use_1024_bytes=False,to_str=True).replace(' ','')
	return f'{version_path}--{size_str}B-{inode_str}_ino{CONTENT_FILE_EXTENSION_NAME}'

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
	def __init__(self, job_name:str, state_dir:str = None, stream = None):
		self.job_name = job_name
		self.state_dir = state_dir
		# None: sys.stderr as it is when the lock is taken, not as it was at import
		self.stream = stream
		self.fd = None

	def __enter__(self):
		os.makedirs(state_dir_path(self.state_dir), exist_ok=True)
		# never through a symlink, which could lead to a file elsewhere when the state folder can be written by others
		self.fd = os.open(restore_lock_path(self.job_name, self.state_dir), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
		try:
			try:
				fcntl.flock(self.fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
			except BlockingIOError:
				print(f'Waiting for reverberator to finish removing an old version of {self.job_name}', file=sys.stderr if self.stream is None else self.stream, flush=True)
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

# job name -> when the FAILED marker saying its restore lock cannot be checked is next due, by the clock prune_oldest()
# is given, while it cannot be. each job's backuper alone sets its own key
RESTORE_LOCK_UNCHECKED = {}
# job name -> when the FAILED marker saying decrement_stepper() cannot remove its oldest version is next due, by the
# clock it is given, while it cannot. each job's backuper alone sets its own key
PRUNE_ABORTED = {}
# the jobs decrement_stepper() has warned that it names its temps without the vault's secret
PRUNE_SALT_MISSING = set()

def prune_oldest(vault_info_dict:OrderedDict, job_name:str, monitor_path:str, postponed:list = None, clock = time.monotonic, monitor_paths:list = None,
		prune_salt:bytes = None) -> tuple:
	'''
	decrement_stepper while no restore holds the job's lock; when one does, postpone and return (0, 0) so the retention
	loops stop. Without a state folder nothing can hold the lock, so it prunes; any other failure to lock postpones too.
	A lock that cannot be checked (opened, or tried) for DISK_WAIT_GRACE_SECONDS gets a FAILED marker, repeated every
	DISK_WAIT_REPEAT_SECONDS while it lasts, as no version is removed meanwhile and the vault keeps growing.
	postponed is a list a backup hands each of its calls: a call that postpones appends why, and only the first of them
	logs it, so a backup says it once. monitor_path, monitor_paths, clock and prune_salt go to decrement_stepper.
	'''
	lock_path = restore_lock_path(job_name)
	def postpone(reason:str, cannot_check:OSError = None) -> tuple:
		if cannot_check is None:
			RESTORE_LOCK_UNCHECKED.pop(job_name, None)
		else:
			now = clock()
			if now >= RESTORE_LOCK_UNCHECKED.setdefault(job_name, now + DISK_WAIT_GRACE_SECONDS):
				job_log(job_name, f'FAILED: cannot check the restore lock {lock_path}: {cannot_check}; pruning postponed')
				RESTORE_LOCK_UNCHECKED[job_name] = now + DISK_WAIT_REPEAT_SECONDS
		if not postponed:
			backuperTeeLogToTl(job_name,f'Postponing removal of the oldest version: {reason}',error=cannot_check is not None)
		if postponed is not None:
			postponed.append(reason)
		return 0, 0
	try:
		# never through a symlink, which could lead to a file elsewhere when the state folder can be written by others
		fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
	except (FileNotFoundError, NotADirectoryError):
		# no state folder, so no restore can be holding a lock
		RESTORE_LOCK_UNCHECKED.pop(job_name, None)
		return decrement_stepper(vault_info_dict, job_name, monitor_path, monitor_paths, clock, prune_salt)
	except OSError as e:
		# the lock may be held right now: a check that failed is never taken as permission to remove
		return postpone(f'cannot open the restore lock: {e}', e)
	try:
		try:
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
		except BlockingIOError:
			return postpone('a restore is reading the vault')
		except OSError as e:
			return postpone(f'cannot take the restore lock: {e}', e)
		RESTORE_LOCK_UNCHECKED.pop(job_name, None)
		return decrement_stepper(vault_info_dict, job_name, monitor_path, monitor_paths, clock, prune_salt)
	finally:
		os.close(fd)

# the errors of os.link() that say the filesystem (or this pair of folders on it) cannot hard link: pruning then moves
# that copy instead. ENOSYS is sshfs's without its hard link extension, and rclone's
NO_HARD_LINK_ERRNOS = frozenset({errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOSYS})

# the file in a job vault that holds its secret for the names pruning links copies under (vault_prune_salt()): of the
# daemon's user alone, mode 0600, as the manifest is readable by every user who can read the vault
PRUNE_SALT_FILE_NAME = '.reverberator_prune_salt'

def vault_prune_salt(job_vault:str, job_name:str, manifest:'VaultManifest' = None):
	'''
	The job vault's secret for the names pruning hard links copies under (prune_link_path()): PRUNE_SALT_BYTES random
	bytes in its file PRUNE_SALT_FILE_NAME, made the first time they are asked for, so a restart or a remount names a
	temp the same as the run that made it, and no user can work a name out.

	The file is made with O_CREAT, O_EXCL and O_NOFOLLOW at mode 0600 (and fchmod to it, whatever the umask), then synced
	with the job vault; when another made it first, the file that won is read. A file there is taken only when it is,
	opened with O_NOFOLLOW, a regular file of the daemon's own user (root) at mode 0600 holding exactly PRUNE_SALT_BYTES
	bytes, and it is never deleted or written over. A secret a daemon before 0.44 kept in manifest's meta (which every
	user can read) is the one the file is made with, so a temp a cut off run left keeps its name, and its row is dropped
	once the file holds a secret. None, with a warning, when there is no secret to be had: pruning then names its temps
	by the copy's inode alone, for this run.
	'''
	path = os.path.join(job_vault, PRUNE_SALT_FILE_NAME)
	def without(why:str):
		backuperTeeLogToTl(job_name, f"The vault's secret for the names pruning links copies under {why}: this run names them by the copy's inode alone", warning=True)
		return None
	def read_secret():
		# the secret the file holds, None when it is not there; ValueError says why one there is not taken
		try:
			# O_NONBLOCK: a FIFO put there must not hold the backup
			fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
		except FileNotFoundError:
			return None
		except OSError as e:
			raise ValueError(f'cannot be read from {path}: {e}')
		try:
			st = os.fstat(fd)
			if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
				raise ValueError(f'is not taken from {path}: it is not a regular file of user {os.geteuid()} with mode 0600')
			secret = b''
			while len(secret) <= PRUNE_SALT_BYTES:
				read = os.read(fd, PRUNE_SALT_BYTES + 1 - len(secret))
				if not read:
					break
				secret += read
		except OSError as e:
			raise ValueError(f'cannot be read from {path}: {e}')
		finally:
			os.close(fd)
		if len(secret) != PRUNE_SALT_BYTES:
			raise ValueError(f'is not taken from {path}: it holds {"more than " if len(secret) > PRUNE_SALT_BYTES else ""}{len(secret)} bytes, not {PRUNE_SALT_BYTES}')
		return secret
	def make_secret(secret:bytes) -> bool:
		# the file made to hold secret, synced with the job vault: False when another was there first. raises OSError
		try:
			fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
		except FileExistsError:
			return False
		try:
			os.fchmod(fd, 0o600)
			left = memoryview(secret)
			while left:
				left = left[os.write(fd, left):]
			os.fsync(fd)
		except BaseException:
			# the file this call made, and nothing else: it holds no whole secret, and would be refused from now on
			try:
				if same_inode(os.lstat(path), os.fstat(fd)):
					os.remove(path)
			except OSError:
				pass
			os.close(fd)
			raise
		os.close(fd)
		try:
			fsync_path(job_vault, folder=True)
		except OSError as e:
			# the file holds the whole secret, synced: only its name may not outlast a crash, and one made again then names
			# a temp a cut off run left otherwise, which stays a stray
			backuperTeeLogToTl(job_name, f"The vault's secret for pruning's temp names was made in {path}, but {job_vault} cannot be synced: {e}", warning=True)
		return True
	stored = None
	if manifest is not None:
		try:
			stored = manifest.stored_prune_salt()
		except sqlite3.Error as e:
			backuperTeeLogToTl(job_name, f"Cannot read the manifest for a secret an older daemon kept there: {e}", warning=True)
	try:
		secret = read_secret()
		if secret is None:
			made = os.urandom(PRUNE_SALT_BYTES) if stored is None else stored
			try:
				won = make_secret(made)
			except OSError as e:
				return without(f'cannot be made in {path}: {e}')
			secret = made if won else read_secret()
			if secret is None:
				return without(f'went from {path} as it was made')
	except ValueError as e:
		return without(str(e))
	if stored is not None:
		try:
			manifest.forget_prune_salt()
		except sqlite3.Error as e:
			backuperTeeLogToTl(job_name, f"Cannot drop from the manifest the secret an older daemon kept there: {e}", warning=True)
	return secret

def prune_link_path(link_path:str, copy_st:os.stat_result, salt:bytes) -> str:
	'''
	The name beside the chain link at link_path that pruning hard links the copy copy_st was read from under, before
	renaming it over the link: of the partial copy form (PARTIAL_COPY_NAME), and the same every time for one link and
	one copy, so a run cut off between the two finds what it made. The monitored tree can hold a file of that form
	beside the link's, which is backed up as any other and which pruning never removes, as it cannot tell what it is:
	the name is a keyed hash (BLAKE2b) of the link's name and the copy's inode under salt, the vault's secret
	(vault_prune_salt()), so no monitored file can be given it to stop every prune; of those alone when salt is
	None. The device is left out: a FUSE mount gets its number when it is mounted, and a remount would rename a temp.

	Examples:
		>>> copy, other = (os.stat_result((stat.S_IFREG | 0o600, ino, 7, 1, 0, 0, 6, 0, 0, 0)) for ino in (11, 12))
		>>> path = prune_link_path('/vault/job/V1--x/d/a.txt', copy, bytes(16))
		>>> os.path.dirname(path), PARTIAL_COPY_NAME.fullmatch(os.path.basename(path)) is not None
		('/vault/job/V1--x/d', True)
		>>> path == prune_link_path('/vault/job/V1--x/d/a.txt', copy, bytes(16)), path == prune_link_path('/vault/job/V1--x/d/a.txt', other, bytes(16))
		(True, False)
		>>> path == prune_link_path('/vault/job/V1--x/d/a.txt', copy, bytes(15) + b'1'), path == prune_link_path('/vault/job/V1--x/d/a.txt', copy, None)
		(False, False)
	'''
	folder, name = os.path.split(link_path)
	digest = hashlib.blake2b(os.fsencode(name) + b'\0' + str(copy_st.st_ino).encode(), digest_size=16, key=salt or b'')
	return os.path.join(folder, '.' + digest.hexdigest() + PARTIAL_COPY_SUFFIX)

def same_inode(first:os.stat_result, second:os.stat_result) -> bool:
	return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)

class PathHashes:
	'''
	A set of keys (paths, or (st_dev, st_ino) pairs) kept by their 64-bit hash() alone, in one array with open
	addressing: 12 to 24 bytes a key, a fraction of what a set of ints takes, as pruning's walk notes every copy it
	books, and on a filesystem that cannot hard link every copy it moves, and a big job's next version links 500k+ of
	them. Two keys of one hash count as one, which at worst gives a dangling link a copy of the other's bytes, or leaves
	a copy out of the next version's record, in decrement_stepper(); it never loses a file.

	Examples:
		>>> held = PathHashes()
		>>> for i in range(1000):
		...     held.add(f'/v/V0/{i}')
		>>> '/v/V0/7' in held, '/v/V0/999' in held, '/v/V0/1000' in held, len(held)
		(True, True, False, 1000)
	'''
	def __init__(self):
		# 0 marks a free slot, so a hash of 0 is kept as 1
		self._slots = array.array('q', bytes(8 * 16))
		self._count = 0

	@staticmethod
	def _slot(slots:array.array, key:int) -> int:
		# where key is, or the free slot it would go in: probed in turn from its own
		mask = len(slots) - 1
		at = key & mask
		while slots[at] and slots[at] != key:
			at = (at + 1) & mask
		return at

	def add(self, key) -> None:
		key = hash(key) or 1
		at = self._slot(self._slots, key)
		if self._slots[at]:
			return
		self._slots[at] = key
		self._count += 1
		if self._count * 3 > len(self._slots) * 2:
			# two thirds full: twice the slots, each key put in again
			old, self._slots = self._slots, array.array('q', bytes(16 * len(self._slots)))
			for key in old:
				if key:
					self._slots[self._slot(self._slots, key)] = key

	def __contains__(self, key) -> bool:
		key = hash(key) or 1
		return self._slots[self._slot(self._slots, key)] == key

	def __len__(self) -> int:
		return self._count

def decrement_stepper(vault_info_dict:OrderedDict, job_name:str, monitor_path:str, monitor_paths:list = None, clock = time.monotonic,
		prune_salt:bytes = None) -> tuple:
	'''
	Remove the oldest vault version and materialize the next version's symlinks: each of the next version's chain
	links into the oldest one is replaced by a hard link to the copy it names (prune_link_path() with prune_salt, the
	vault's secret, or the copy's inode alone, with one warning a job, when it is None; then a rename over the link),
	so the oldest version stays whole until it is removed, and a run cut off anywhere loses nothing: the next run finds
	the links left. Where the filesystem cannot hard link (NO_HARD_LINK_ERRNOS), the copy is moved in
	the link's place, as before 0.44. The links are told by vault_chain_hop() with the next version's moves
	(VersionMoves.of_committed(), under monitor_path and monitor_paths, the record of the monitored paths the versions
	were written under, read from the manifest when None): a user's symlink is left as it is, whatever its text, and a
	link whose rows cannot tell (UnexplainedChainLink) is taken for a chain link, as refusing one would lose its copy.
	Two links naming one copy (one of them a user's link the rows could not tell) each get it. A version, change list,
	link or copy that cannot be looked at, linked or moved, or a removal that fails, keeps the oldest version: the
	removal is aborted, and job_name's FAILED marker logged, then again every DISK_WAIT_REPEAT_SECONDS by clock while it
	lasts, as no version is removed meanwhile and the vault keeps growing. Only a folder that is not there is gone: a
	kept oldest version whose folder is gone, as a removal cut short leaves it, is finished by removing what is left of
	its paths.
	Each version's record of what it holds, which its change list's name keeps and a restart sums, is kept in du's
	measure (st_blocks * 512, and an inode an entry), never by st_nlink, which mergerfs can show stale for a second
	after a link: a copy materialised moves from the oldest version's record to the next one's, once a run however many
	links name it (by its inode, in a PathHashes), and the link it replaces, or a dangling link dropped, leaves the
	next one's. Both records are written, by renaming the change lists, before the removal, so a run cut off then, or a
	removal cut short, leaves them true, and when it is aborted. Returns how far the two records went down in all,
	(bytes, inodes), so the caller's sums of every version's record (vault_size, vault_inodes) stay theirs whether or
	not the oldest version went: the oldest version's record and what the next one lost, when it went; never less than
	nothing, so no prune raises the caller's sums, though a copy two links name that an aborted run booked for one and
	its rerun for the other is booked twice, and the next version's record then holds one copy more than it does.

	Examples:
		>>> decrement_stepper(OrderedDict([(0, VaultEntry(0, '/tmp/x', 0, 0, 0))]), 'job', '/m')
		(0, 0)
		>>> decrement_stepper(OrderedDict(), 'job', '/m')
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
		# still the oldest, so the caller sees nothing removed
		vault_info_dict[referenceVersionNumber] = referenceVaultEntry
		vault_info_dict.move_to_end(referenceVersionNumber, last=False)
		return 0 , 0
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Recursively removing V{referenceVersionNumber}: {referenceVaultPath}')
	vaultInfoIter = iter(vault_info_dict)
	applyingVersionNumber = next(vaultInfoIter)
	applyingVaultEntry = vault_info_dict[applyingVersionNumber]
	job_vault = os.path.dirname(referenceVaultPath)
	# the books, each [bytes, inodes]: the copies the next version took from the reference vault, the entries it no
	# longer holds (the links replaced, the dangling links dropped), and the copies made for it besides (for a second
	# link naming a copy the walk moved)
	transferred, unlinked, copied = [0, 0], [0, 0], [0, 0]
	def book(books:list, st:os.stat_result) -> None:
		books[0] += st.st_blocks * 512
		books[1] += 1
	# the copies hard linked into the next version this run, by inode, so two links naming one copy (one of them a user's
	# link the rows could not tell) book it once. one moved needs no note: another link naming it finds it gone, and
	# gets a copy of its own (copied), so the move path, which notes every copy it moves already, holds no more
	booked = PathHashes()
	if prune_salt is None and job_name not in PRUNE_SALT_MISSING:
		PRUNE_SALT_MISSING.add(job_name)
		backuperTeeLogToTl(path=referenceVaultPath,warning=True,message="The vault's secret for the names pruning links copies under cannot be had: they go by the copy's inode alone")
	# the records as the change lists' names hold them, and those lists (None for a version without one)
	reference_record, applying_record = referenceVaultEntry, applyingVaultEntry
	reference_list = applying_list = None
	# whether the records were written, once a call: None until they are
	records_written = None
	def there(path:str):
		# True when path is there, False when it is not (ENOTDIR too: a name above it is no folder), None when that cannot
		# be told
		try:
			os.lstat(path)
		except (FileNotFoundError, NotADirectoryError):
			return False
		except OSError:
			return None
		return True
	def change_list_of(entry:VaultEntry):
		# the change list holding entry's record: by the name the record makes, else the version's own found by listing
		# the job vault (as a rename that reported an error can leave it); None when it has none. raises OSError when
		# that cannot be told
		expected = change_list_path(entry.path, entry.size, entry.inode)
		try:
			os.lstat(expected)
			return expected
		except (FileNotFoundError, NotADirectoryError):
			pass
		name = os.path.basename(os.path.abspath(entry.path))
		found = sorted(listed for listed in os.listdir(job_vault) if (parse_change_list_name(listed) or (None, None))[1] == name)
		return os.path.join(job_vault, found[0]) if found else None
	def record(change_list:str, entry:VaultEntry, size:int, inodes:int, make:bool = False):
		# change_list renamed for entry to record size and inodes: entry as it now records, None when that failed. a
		# version without a list has no other record, or, with make, gets one, as one without is removed at startup
		written = entry._replace(size=size, inode=inodes)
		new_path = change_list_path(entry.path, size, inodes)
		if change_list == new_path:
			return written
		if change_list is None:
			if not make:
				return written
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Creating content file {new_path}')
			try:
				# whole or not at all, as every change list is
				write_change_list(new_path,[])
			except Exception as e:
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error creating content file {new_path}: {e}')
				return None
			return written
		backuperTeeLogToTl(path=referenceVaultPath,message=f'Renaming {change_list} to {new_path}')
		try:
			os.rename(change_list,new_path)
		except OSError as e:
			# a rename that moved the list and then reported an error is done
			if not (there(change_list) is False and there(new_path)):
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error renaming {change_list} to {new_path}: {e}')
				return None
		return written
	def write_records() -> bool:
		# both records written, the next version's first on purpose: whether its was. a run cut off between the two
		# leaves only the reference vault's record high, by the copies it gave, and that is the version this prune is
		# removing; one of its that cannot be written stays high the same way until the removal takes it. when the next
		# version's cannot be written, neither is, and the removal aborts: both stay as they were, high by the links
		# replaced, an overstatement, which over-prunes by those links' blocks. that holds only until the rerun: it finds
		# those links replaced already, so it books neither them nor the copies they became, and once the reference vault
		# goes, the next version's record is low by the copies the aborted run linked (less the links' blocks), which
		# under-prunes by them
		nonlocal reference_record, applying_record, records_written
		if records_written is None:
			records_written = True
			if transferred[1] or unlinked[1] or copied[1]:
				written = record(applying_list, applyingVaultEntry,
					max(0, applyingVaultEntry.size - unlinked[0] + transferred[0] + copied[0]),
					max(0, applyingVaultEntry.inode - unlinked[1] + transferred[1] + copied[1]), make=True)
				if written is None:
					records_written = False
				else:
					applying_record = vault_info_dict[applyingVersionNumber] = written
					reference_record = record(reference_list, referenceVaultEntry, max(0, referenceVaultEntry.size - transferred[0]),
						max(0, referenceVaultEntry.inode - transferred[1])) or reference_record
		return records_written
	def went_down(kept:bool) -> tuple:
		# how far the two records went down in all, the reference vault's with it when it went, but never less than
		# nothing: a prune raising the caller's sums would remove more versions than the limit asks for
		size = applying_record.size + (reference_record.size if kept else 0)
		inodes = applying_record.inode + (reference_record.inode if kept else 0)
		return (max(0, referenceVaultEntry.size + applyingVaultEntry.size - size),
			max(0, referenceVaultEntry.inode + applyingVaultEntry.inode - inodes))
	def keep_oldest(why:str) -> tuple:
		# the reference vault stays, back at the front of vault_info_dict, with the records written, and the job's FAILED
		# marker says so
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Aborting removal of {referenceVaultPath} because {why}')
		now = clock()
		if now >= PRUNE_ABORTED.get(job_name, now):
			job_log(job_name, f'FAILED: cannot remove {referenceVaultPath}, as {why}; it is kept, and the vault keeps growing')
			PRUNE_ABORTED[job_name] = now + DISK_WAIT_REPEAT_SECONDS
		write_records()
		new_dict = OrderedDict()
		new_dict[referenceVersionNumber] = reference_record
		new_dict.update(vault_info_dict)
		vault_info_dict.clear()
		vault_info_dict.update(new_dict)
		return went_down(True)
	def remove_paths(paths:list) -> bool:
		# rm -rf of paths, the reference vault's own: whether they went
		if paths and multiCMD.run_command(['rm','-rf',*paths],quiet=True,return_code_only=True):
			return False
		forget_real_vault_folders(referenceVaultPath)
		forget_version_moves(referenceVaultPath)
		PRUNE_ABORTED.pop(job_name, None)
		return True
	def own_paths() -> list:
		# the reference vault's folder and its change lists (its name, --, and a record change_list_record() reads), and
		# nothing else named like them, such as a user's V0--<timestamp>.stray beside it. raises OSError when the job
		# vault cannot be listed
		folder = os.path.basename(referenceVaultPath)
		return sorted(os.path.join(job_vault, name) for name in os.listdir(job_vault)
			if name == folder or (name.startswith(folder + '--') and change_list_record(name[len(folder) + 2:]) is not None))
	# only a folder that is not there is gone: one that cannot be looked at may hold every copy the next version links
	try:
		os.lstat(referenceVaultPath)
	except FileNotFoundError:
		# a removal cut short took the folder, once its links were all materialised and the records written: what is left
		# goes, and its record with it
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'{referenceVaultPath} is already gone: removing what is left of it')
		try:
			left = own_paths()
		except OSError as e:
			return keep_oldest(f'the job vault cannot be listed for what is left of it: {e}')
		if not remove_paths(left):
			return keep_oldest('rm -rf of what was left of it failed')
		return went_down(False)
	except OSError as e:
		return keep_oldest(f'it cannot be looked at: {e}')
	try:
		reference_list = change_list_of(referenceVaultEntry)
		applying_list = change_list_of(applyingVaultEntry)
	except OSError as e:
		return keep_oldest(f'its change list, or that of {applyingVaultEntry.path}, cannot be looked at: {e}')
	if applying_list is None:
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Content file {change_list_path(applyingVaultEntry.path, applyingVaultEntry.size, applyingVaultEntry.inode)} does not exist, creating a new one...')
	backuperTeeLogToTl(path=referenceVaultPath,message=f"Dealing with {applyingVersionNumber}: {applyingVaultEntry.path}")
	materialize_failed = False
	def failed(message:str) -> None:
		nonlocal materialize_failed
		materialize_failed = True
		backuperTeeLogToTl(path=referenceVaultPath,error=True,message=message)
	def remove_if_target(path:str, target_st:os.stat_result) -> None:
		# a name pruning linked to the copy, removed only while it is still the copy's
		with contextlib.suppress(OSError):
			if same_inode(os.lstat(path), target_st):
				os.remove(path)
	def share_moved_copy(copy:str, link:str, link_st:os.stat_result):
		# a copy of copy, with its metadata, put in place of link by a rename, while link is still the walk's symlink: its
		# lstat(), None when it failed
		temp_path = partial_copy_path(link)
		try:
			shutil.copyfile(copy,temp_path,follow_symlinks=False)
			if not copy_file_meta(copy,temp_path):
				return None
			made = os.lstat(temp_path)
			if not same_inode(os.lstat(link), link_st):
				backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Not copying {copy} to {link}: it is no longer the link')
				return None
			os.replace(temp_path,link)
			return made
		except OSError as e:
			backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error copying {copy} to {link}: {e}')
			return None
		finally:
			with contextlib.suppress(OSError):
				os.remove(temp_path)
	# the copies a filesystem without hard links made this walk move out of the reference vault, so a second link
	# naming one gets its bytes too: one moved to the link at its own path by the hash of its path alone (PathHashes),
	# as every unchanged file of a big job is one, any other by target -> the link it now stands in place of
	moved_home = PathHashes()
	moved_away = {}
	def moved_to(target:str):
		# where this walk moved target, None when it did not
		if target in moved_away:
			return moved_away[target]
		if target in moved_home:
			return os.path.join(applyingVaultEntry.path, target[len(referenceVaultPath) + 1:])
		return None
	def note_moved(target:str, link:str):
		if link[len(applyingVaultEntry.path):] == target[len(referenceVaultPath):]:
			moved_home.add(target)
		else:
			moved_away[target] = link
	def drop_dangling(file:str, file_st:os.stat_result, linkTarget:str) -> None:
		# the target is gone: moved into this version by this walk for another link (one of the two a user's link the rows
		# could not tell), whose copy this one gets too; else the link was dangling before. removing the reference vault
		# loses nothing that is not already lost, and keeping the link would carry the broken reference forward into every
		# later version. drop it and keep stepping, as aborting here wedges retention forever
		taken = moved_to(linkTarget)
		if taken is not None:
			backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'{file} and {taken} both link to {linkTarget}: one is a user\'s link that cannot be told from a chain link, so both get its copy')
			made = share_moved_copy(taken, file, file_st)
			if made is None:
				failed(f'Error giving {file} the copy of {linkTarget} that {taken} took')
				return
			book(unlinked, file_st)
			book(copied, made)
			return
		try:
			# only while it is still the link the walk saw: whatever stands there now is not removed
			if not same_inode(os.lstat(file), file_st):
				raise OSError(errno.EEXIST, 'it is no longer the link', file)
			os.remove(file)
		except Exception as removeError:
			backuperTeeLogToTl(path=referenceVaultPath,error=True,message=f'Error removing dangling link {file} -> {linkTarget}: {removeError}')
		else:
			book(unlinked, file_st)
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Removed dangling link {file} -> {linkTarget} as the target is already missing')
	def move_copy(file:str, file_st:os.stat_result, linkTarget:str, target_st:os.stat_result) -> bool:
		# the copy moved in place of the link, for a filesystem that cannot hard link it: whether it is there now
		try:
			still_the_link = same_inode(os.lstat(file), file_st)
		except OSError as e:
			failed(f'Error looking at {file}: {e}')
			return False
		if not still_the_link:
			failed(f'Not moving {linkTarget} to {file}: it is no longer the link')
			return False
		try:
			os.rename(linkTarget,file)
		except Exception as e:
			try:
				landed = same_inode(os.lstat(file), target_st)
			except OSError:
				landed = False
			if not landed:
				# the copy may still be in the reference vault, which removing would destroy: kept, and tried again later
				failed(f'Error moving {linkTarget} to {file}: {e}')
				return False
			# the rename moved the copy and then reported an error: the copy is in place
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Moving {linkTarget} to {file} reported {e}, but the copy is in place')
		note_moved(linkTarget, file)
		return True
	def link_copy(file:str, file_st:os.stat_result, linkTarget:str, target_st:os.stat_result):
		# the copy hard linked in place of the link: True when it is there, False when it failed and the walk aborts, None
		# when the filesystem cannot hard link it
		temp_path = prune_link_path(file, target_st, prune_salt)
		try:
			# the link itself when the copy is a user's symlink stored in the version
			os.link(linkTarget,temp_path,follow_symlinks=False)
		except FileExistsError:
			# its own link, from a run cut off before the rename; anything else is never removed: what it is cannot be told
			try:
				left_by_a_run = same_inode(os.lstat(temp_path), target_st)
			except OSError as e:
				failed(f'Error looking at {temp_path}: {e}')
				return False
			if not left_by_a_run:
				failed(f'Not linking {linkTarget} to {file}: {temp_path} is there already, and is not its copy')
				return False
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Linking {linkTarget} to {file} again from {temp_path}, which an earlier run left')
		except OSError as e:
			if e.errno in NO_HARD_LINK_ERRNOS:
				return None
			failed(f'Error linking {linkTarget} to {temp_path}: {e}')
			return False
		try:
			if not same_inode(os.lstat(file), file_st):
				remove_if_target(temp_path, target_st)
				failed(f'Not linking {linkTarget} to {file}: it is no longer the link')
				return False
			os.rename(temp_path,file)
		except Exception as e:
			try:
				landed = same_inode(os.lstat(file), target_st)
			except OSError:
				landed = False
			if not landed:
				remove_if_target(temp_path, target_st)
				failed(f'Error linking {linkTarget} to {file}: {e}')
				return False
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Linking {linkTarget} to {file} reported {e}, but the copy is in place')
		return True
	# the next version's rows, read once for the whole walk
	moves = VaultMoves(job_vault,monitor_path,monitor_paths).of(applyingVaultEntry.path)
	# walked instead of listed up front, as the next version links every tracked file (500k+ for big jobs).
	# each folder is read in full before its links are replaced, so a replaced link cannot make the walk skip another.
	# a folder that cannot be listed, or an entry that cannot be looked at, may hold this version's only way to a copy
	# in the reference vault, so the reference vault is kept
	walk_errors = []
	for file, _, is_dir in iter_tree_entries(applyingVaultEntry.path, list_folders_first=True, errors=walk_errors):
		if is_dir:
			continue
		try:
			file_st = os.lstat(file)
		except FileNotFoundError as e:
			if PARTIAL_COPY_NAME.fullmatch(os.path.basename(file)):
				# a name a cut off run linked a copy under, listed with its folder before this walk renamed it over its link
				continue
			failed(f'Error looking at {file}: {e}')
			continue
		except OSError as e:
			failed(f'Error looking at {file}: {e}')
			continue
		if not stat.S_ISLNK(file_st.st_mode):
			continue
		# a link an older daemon moved to another folder depth still names its version, though its text no longer reaches it.
		# a user's symlink is left as it is, however it is shaped, and so is a link naming a folder: the daemon links
		# files only, so no folder is ever put in place of a link
		try:
			linkTarget = vault_chain_hop(job_vault, file, os.readlink(file), moves)
		except UnexplainedChainLink as e:
			# the rows cannot tell: it may be this version's only way to its copy, which is kept as for a chain link
			linkTarget = e.target
		except (UncheckedVaultLink, OSError) as e:
			# it may be this version's only way to a file in the reference vault, so keep that
			failed(f'Error checking whether {file} links into {referenceVaultPath}: {e}')
			continue
		if linkTarget is None or not linkTarget.startswith(referenceVaultPath + '/'):
			if DEBUG:
				backuperTeeLogToTl(path=referenceVaultPath,message=f'Not materialising {file}: not a chain link into {referenceVaultPath}')
			continue
		try:
			target_st = os.lstat(linkTarget)
		except (FileNotFoundError, NotADirectoryError):
			# ENOTDIR: a name on the way to it is a file in the reference vault, so it is not there either
			drop_dangling(file, file_st, linkTarget)
			continue
		except OSError as e:
			failed(f'Error looking at {linkTarget}: {e}')
			continue
		if stat.S_ISDIR(target_st.st_mode):
			# never so for a link vault_chain_hop() takes: no folder is put in place of a link
			continue
		if DEBUG:
			backuperTeeLogToTl(path=referenceVaultPath,message=f'Materialising {linkTarget} at {file}')
		linked = link_copy(file, file_st, linkTarget, target_st)
		moved = linked is None
		if moved:
			linked = move_copy(file, file_st, linkTarget, target_st)
		if linked:
			# the copy is the next version's now, in place of the link
			if (target_st.st_dev, target_st.st_ino) not in booked:
				if not moved:
					booked.add((target_st.st_dev, target_st.st_ino))
				book(transferred, target_st)
			book(unlinked, file_st)
	for rel, error in walk_errors:
		failed(f'Error listing {unreadable_path(applyingVaultEntry.path, rel)}: {error}')
	if materialize_failed:
		return keep_oldest(f'materializing the links of {applyingVaultEntry.path} into it failed')
	# before the removal, so a run cut off from here on leaves records a restart reads true
	if not write_records():
		return keep_oldest(f'the change list of {applyingVaultEntry.path} cannot be renamed for what it now holds')
	backuperTeeLogToTl(path=referenceVaultPath,message=f'Removing {referenceVaultPath}')
	try:
		paths_to_remove = own_paths()
	except OSError as e:
		return keep_oldest(f'the job vault cannot be listed: {e}')
	if os.path.join(job_vault, os.path.basename(referenceVaultPath)) not in paths_to_remove:
		return keep_oldest('its folder was not found listing the job vault')
	if not remove_paths(paths_to_remove):
		if there(referenceVaultPath) is False:
			# the folder went, and all it held with it: what is left of the version holds nothing, and the next prune
			# finishes it
			reference_record = reference_record._replace(size=0, inode=0)
		return keep_oldest('rm -rf of its paths failed')
	return went_down(False)

def do_reverb_backup(backup_entries:dict,backup_folder:str,latest_version_info:VaultEntry,
					 only_sync_attributes:bool,manifest:VaultManifest,monitor_path:str,skip_list:'SkipList' = None,job_name:str = None,reported:set = None,
					 recopy:list = (),recopied:list = None,touched:TouchedScopes = None,paused:set = frozenset(),verified:list = None,
					 recheck_mounts = None) -> VaultManifest:
	'''
	Create backup_folder as a referenced copy of the latest version, then replay backup_entries onto it.

	The files of recopy (rels, as recopy_rels() gives them) are copied again from the end of their chains in the latest
	version, before the replay: the vault's copy, as it is there, never the monitored file, which may have changed
	since. Each one copied is appended to recopied. One whose chain cannot be followed (an error line names it), or
	whose copy fails, keeps its link. Their records stay those of the copies they were made from, only unchecked, as a
	crash can keep any new copy's bytes from the disk.
	With touched (touched_scopes() of the batch's raw events), the replay is verified once its copies are in place: the
	touched scopes are compared with the monitored tree (compare_scopes(), its paused inner mounts keeping their
	entries), what differs is replayed the same way, then entries no row tracks are removed from backup_folder under
	the touched subtrees and tracked ones missing there are copied (sweep_version_folder()). Each fix is appended to
	verified as a (monitored path, BackupEntryValues) pair, a folder's path ending with /: the comparison's entries,
	then a delete for each entry removed, then a create for each one missing; one the replay could not apply is left
	out. recheck_mounts(fixes), when given, runs once the comparison walked the tree: it drops the fixes under inner
	mounts unmounted meanwhile, and raises JobFailure when the monitored root's filesystem changed.
	manifest is updated to describe backup_folder inside a transaction the caller commits once the version is complete.
	'''
	global BACKUP_SEMAPHORE
	global GREEN_LIGHT
	if reported is None:
		reported = set()
	backup_entries = prepare_backup_entries_for_replay(backup_entries)
	backuperTeeLogToTl(path=monitor_path,message=f'Running reverb backup with {len(backup_entries)} entires to {backup_folder}',ok=True)
	# the links of the committed versions, on the chains the re-copy and the attribute sync follow, are told by their
	# versions' moves, held for this backup
	committed_moves = VaultMoves(os.path.dirname(os.path.abspath(backup_folder)),monitor_path,manifest_monitor_paths(manifest))
	# the folders a file now stands in place of, each logged once
	replaced_folders = set()
	def not_through_link(rel,isDir,doing):
		# a folder above rel in the new version is a link (or a file): what is done there would reach through it, out of
		# the version. the version cannot hold rel there, so its rows go
		backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not {doing} {os.path.join(backup_folder,rel)}: a folder above it in the version is not a real folder; not tracking it')
		if isDir:
			manifest.remove_tree(as_folder_entry(rel))
		else:
			manifest.discard(rel)
	def copy_path(isDir,monitor_path,source_real_path,source_relative_path,file_vault_real_path,backup_folder,mcae):
		# returns whether the entry is tracked and copied ( or queued ), as every write into the version goes through real
		# folders of it only
		if not os.path.lexists(source_real_path):
			# recording a path we cannot copy makes the tracked list lie about this
			# version, and the next referenced copy turns every such entry into a
			# dangling link that all later versions inherit. skip it instead.
			backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not tracking {source_relative_path}: source no longer exists')
			return False
		source_relative_path = source_relative_path.rstrip('/')
		file_vault_real_path = file_vault_real_path.rstrip('/')
		if not real_folders_to(backup_folder,source_relative_path,make=True):
			not_through_link(source_relative_path,isDir,'copying to')
			return False
		if isDir:
			if not make_real_folder(file_vault_real_path):
				manifest.remove_tree(as_folder_entry(source_relative_path))
				return False
			# whatever stood at its place is gone
			manifest.discard(source_relative_path)
			manifest.add(as_folder_entry(source_relative_path),dirty=True)
			copy_file_meta(source_file=source_real_path,backup_file_path=file_vault_real_path)
			walk_errors = []
			rel_base = as_folder_entry(source_relative_path)
			# a folder that could not be made: nothing is copied under it
			unmade = None
			for subRealPath, subRelativePath, subIsDir in iter_tree_entries(source_real_path,rel_base,skip=None if skip_list is None else skip_list.skips,errors=walk_errors):
				if unmade is not None and subRelativePath.startswith(unmade):
					continue
				subVaultPath = os.path.join(backup_folder,subRelativePath)
				if subIsDir:
					# the walk lists each folder before its contents, so its parent was made a real folder just before
					if not make_real_folder(subVaultPath.rstrip('/')):
						unmade = subRelativePath
						continue
					manifest.discard(subRelativePath[:-1])
					manifest.add(subRelativePath,dirty=True)
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
		return True
	def replaced_folder(folder_rel):
		# one line for each folder of the version a file now stands in place of, however many of its rows go
		if folder_rel not in replaced_folders:
			replaced_folders.add(folder_rel)
			backuperTeeLogToTl(path=monitor_path,message=f'Dropping the rows under {os.path.join(backup_folder,folder_rel)}: a file is in its place in the version')
	def delete_path(isDir,vault_real_path,relative_path,mcae):
		# never with a trailing /, which makes rm follow a link in the entry's place
		vault_real_path = vault_real_path.rstrip('/')
		relative_path = relative_path.rstrip('/')
		if relative_path in ('', '.'):
			backuperTeeLogToTl(path=vault_real_path,error=True,message='Attempting to remove the version itself, skipping')
			return
		if not real_folders_to(backup_folder,relative_path,missing_ok=True):
			in_place = file_in_place_of_folder(backup_folder,relative_path)
			if in_place is not None:
				# a file made where a folder above it was ( rm -rf L; echo > L ): nothing of it is in the version, its rows go
				replaced_folder(in_place)
				if isDir:
					manifest.remove_tree(as_folder_entry(relative_path))
				else:
					manifest.discard(relative_path)
				return
			# nothing of it is in the version but through that link: only its rows go
			not_through_link(relative_path,isDir,'removing')
			return
		if isDir:
			# we just remove the folder
			if os.path.abspath(vault_real_path) == '/':
				# we cannot remove root
				backuperTeeLogToTl(path=vault_real_path,error=True,message='Attempting to remove root, skipping')
			elif os.path.isdir(vault_real_path) and not os.path.islink(vault_real_path):
				# an entry of another kind in its place is another row's ( a link that replaced the folder ), and stays
				mcae.run_command(['rm','-rf',vault_real_path])
			elif os.path.lexists(vault_real_path) and not os.path.islink(vault_real_path):
				replaced_folder(as_folder_entry(relative_path))
			# also stops tracking all the files and subfolders in the folder
			manifest.remove_tree(as_folder_entry(relative_path))
		else:
			# we just remove the file
			mcae.run_command(['rm','-f',vault_real_path])
			manifest.discard(relative_path)
	def sync_attributes(source_real_path,relative_path):
		# onto the version's entry of a file ( its folders are real: real_folders_to() ), which a chain link leaves where
		# the latest copy is, as only_sync_attributes has it: the end of the chain gets them. a user's symlink, in the
		# version or at the chain's end, gets only its own owner and times ( copy_file_meta() ), never what it points to.
		# the chain is followed from its first hop, in a committed version: nothing is judged, nor remembered
		# ( is_real_folder_under() ), about the folders of this one, which the replay can still change
		# the end must be of the monitored entry's kind. the first hop, in this version, still goes by the text alone (the
		# version's moves are not known yet), and chain_end() tells the links of the committed versions by their moves,
		# so a user's link whose text has a chain link's form ( ../<the version before>/D/f ) is the chain's end there;
		# the check still guards a chain that ends anywhere else, such as a folder
		entry = os.path.abspath(os.path.join(backup_folder,relative_path))
		if not os.path.islink(entry):
			return copy_file_meta(source_real_path,entry)
		def refuse(why):
			backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not syncing the attributes of {source_real_path} onto {entry}: {why}')
			return False
		vault = os.path.dirname(os.path.abspath(backup_folder))
		try:
			hop = strict_chain_hop(vault,entry,os.readlink(entry))
		except (OSError,UncheckedVaultLink):
			return refuse('its link chain cannot be followed')
		if hop is None:
			end_path, end_mode = entry, stat.S_IFLNK
		else:
			hop_version = hop[len(vault) + 1:].partition('/')[0]
			end = chain_end(vault,os.path.join(vault,hop_version),hop[len(vault) + len(hop_version) + 2:],committed_moves)
			if end is None:
				return refuse('its link chain cannot be followed')
			if stat.S_ISDIR(end.st.st_mode):
				return refuse(f'its link chain ends at the folder {end.path}')
			end_path, end_mode = end.path, end.st.st_mode
		try:
			source_is_link = stat.S_ISLNK(os.lstat(source_real_path).st_mode)
		except OSError as e:
			return refuse(f'it cannot be looked at: {e}')
		if stat.S_ISLNK(end_mode) and not source_is_link:
			try:
				text = os.readlink(end_path)
			except OSError:
				text = None
			if text is not None and os.path.isabs(text) and os.path.normpath(text) == os.path.abspath(source_real_path):
				# a referenced backup's link to the monitored file itself, whose contents it is: nothing of its own to sync
				return True
		if stat.S_ISLNK(end_mode) != source_is_link:
			kinds = ('a symlink', 'not one') if source_is_link else ('not a symlink', 'a symlink')
			return refuse(f'it is {kinds[0]}, and its link chain ends at {end_path}, which is {kinds[1]}')
		return copy_file_meta(source_real_path,end_path)
	def wait_for_async_commands(mcae):
		# returns the rels of the copies put in place
		while GREEN_LIGHT.is_set() and mcae.runningThreads:
			mcae.wait(timeout=POLL_WAIT_SECONDS)
		if not GREEN_LIGHT.is_set():
			return []
		# what was copied takes its place before anything renames, removes or records it
		return finish_copies(pending,manifest,backup_folder,monitor_path if job_name is None else job_name,reported)
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
	def replay(entries):
		# entries as prepare_backup_entries_for_replay() orders them. returns {path: whether it was applied}: a create or
		# modify whose source is gone, or whose place in the version lies behind a link, is not
		applied = {}
		need_delete_barrier = False
		for event_source_real_path, event_values in entries.items():
			applied[event_source_real_path] = True
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
				applied[event_source_real_path] = copy_path(isDir=isDir,monitor_path=monitor_path,source_real_path=event_source_real_path,
				 source_relative_path=event_relative_path,
				 file_vault_real_path=file_vault_target_path,backup_folder=backup_folder,mcae=mcae)
			elif event_values.event == 'attrib':
				# the parents a prior version lacked are made, as real folders
				if not real_folders_to(backup_folder,event_relative_path,make=True):
					not_through_link(event_relative_path,isDir,'syncing attributes onto')
					applied[event_source_real_path] = False
					continue
				if isDir:
					if os.path.lexists(file_vault_target_path) and (os.path.islink(file_vault_target_path) or not os.path.isdir(file_vault_target_path)):
						# the folder's metadata would go through the link, or onto another row's entry
						backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not syncing the attributes of {event_source_real_path} onto {file_vault_target_path}, which is not a real folder in the version')
						applied[event_source_real_path] = False
						continue
					# we just copy the folder metadata
					os.makedirs(file_vault_target_path,exist_ok=True)
					copy_file_meta(event_source_real_path,file_vault_target_path)
					manifest.add(as_folder_entry(event_relative_path),dirty=True)
				else:
					if only_sync_attributes:
						# we just copy the file metadata
						sync_attributes(event_source_real_path,event_relative_path)
					else:
						# we copy the file
						cp_af_copy_path(source_path=event_source_real_path,dest_path=file_vault_target_path,mcae=mcae,pending=pending)
					manifest.add(event_relative_path,dirty=True)
			elif event_values.event == 'move':
				link_source_relative_path = os.path.relpath(event_values.source_path,monitor_path)
				link_target_relative_path = event_relative_path
				if isDir and os.path.abspath(file_vault_target_path) == '/':
					# we cannot remove root
					backuperTeeLogToTl(path=file_vault_target_path,error=True,message='Attempting to move root, skipping')
					continue
				# we need to wait for copy threads to finish to allow rename, and the copies they made are recorded under
				# the names they were made for before those rows move
				wait_for_async_commands(mcae)
				if isDir:
					# also moves all the files and subfolders in the folder
					manifest.move_tree(as_folder_entry(link_source_relative_path),as_folder_entry(link_target_relative_path))
					manifest.add(as_folder_entry(link_target_relative_path))
				else:
					manifest.move_file(link_source_relative_path,link_target_relative_path)
				link_source_backup_real_path = os.path.join(backup_folder,link_source_relative_path)
				link_target_backup_real_path = os.path.join(backup_folder,link_target_relative_path)
				try:
					if not real_folders_to(backup_folder,link_source_relative_path,missing_ok=True) or not real_folders_to(backup_folder,link_target_relative_path,missing_ok=True):
						# renaming would reach through the link, out of the version
						raise NotARealFolder(f'a folder above {link_source_backup_real_path} or {link_target_backup_real_path} in the version is not a real folder')
					if os.path.lexists(link_target_backup_real_path):
						os.remove(link_target_backup_real_path)
					os.rename(link_source_backup_real_path,link_target_backup_real_path)
					backuperTeeLogToTl(path=monitor_path,message=f'Moved {link_source_backup_real_path} to {link_target_backup_real_path}')
					if link_source_relative_path.rstrip('/').count('/') != link_target_relative_path.rstrip('/').count('/'):
						# the relative links moved to another folder depth no longer reach the versions holding the copies.
						# the move stands when some cannot be rewritten: their text still names their versions, and the
						# rows move_tree / move_file moved stay unverified, so the next comparison reads them ( and copies
						# again a file whose link the kernel cannot follow )
						retarget_errors = []
						try:
							retarget_moved_links(os.path.dirname(backup_folder),link_target_backup_real_path,retarget_errors)
						except Exception as e:
							retarget_errors.append((link_target_backup_real_path,e))
						for retarget_path,retarget_error in retarget_errors:
							backuperTeeLogToTl(path=monitor_path,error=True,message=f'Cannot re-target the links at {retarget_path}, moved to another folder depth: {retarget_error}; '
								'they keep their text, which still names their versions, and the next comparison checks them')
					# sync the current attrs from the source onto the moved vault entry, but never through a symlink: a chained
					# one would rewrite the previous version's metadata, and gets none. a user's symlink gets its own owner and
					# times only ( copy_file_meta() )
					if not os.path.islink(link_target_backup_real_path) or chain_hop(os.path.dirname(os.path.abspath(backup_folder)),
							link_target_backup_real_path,os.readlink(link_target_backup_real_path)) is None:
						copy_file_meta(event_source_real_path,link_target_backup_real_path)
				except NotARealFolder as e:
					backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not renaming {link_source_backup_real_path} to {link_target_backup_real_path}: {e}; doing delete & copy instead')
					copy_path(isDir=isDir,monitor_path=monitor_path,
					  source_real_path=event_source_real_path,
					  source_relative_path=event_relative_path,
					  file_vault_real_path=file_vault_target_path,backup_folder=backup_folder,mcae=mcae)
					delete_path(isDir=isDir,vault_real_path=link_source_backup_real_path,
					  relative_path=link_source_relative_path,mcae=mcae)
					wait_for_async_commands(mcae)
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
		return applied
	def verify():
		# what the batch's events touched is compared with the monitored tree, and the version fixed where they differ:
		# the collapse into one entry per path cannot replay every order of moves, re-creations and deletes. the rows this
		# replay copied are compared for presence only, so their copies stay unchecked, and attribute-only differences are
		# left to the attribute handling, which syncs them onto the latest copy, wherever it lives
		fixes = OrderedDict()
		compare_scopes(fixes, manifest, backup_folder, monitor_path, touched, None if skip_list is None else skip_list.skips, paused,
			monitor_path if job_name is None else job_name, reported, trusted=manifest.dirty_rels(), attributes=False, fresh=True)
		if not GREEN_LIGHT.is_set():
			return
		if recheck_mounts is not None:
			# a disk unmounted while the comparison walked looks emptied
			recheck_mounts(fixes)
		def applied_fixes(entries, results):
			# a fix is recorded once the version holds it: one the replay passed over ( its source gone, or its place behind
			# a link ), or whose copy failed, is not. an entry the replay left to a folder create above it is in that folder
			for path, values in entries.items():
				rel = os.path.relpath(path, monitor_path) + ('/' if path.endswith('/') else '')
				tracked = manifest.lookup(rel) is not None
				if results.get(path, True) and tracked != (values.event == 'delete'):
					yield path, values
		applied = {}
		if fixes:
			backuperTeeLogToTl(path=monitor_path,message=f'Fixing {len(fixes)} differences between {backup_folder} and the touched places of the monitored tree')
			applied = replay(prepare_backup_entries_for_replay(fixes))
			wait_for_async_commands(mcae)
			if not GREEN_LIGHT.is_set():
				return
		# a copy fallback of a failed rename can leave entries in the version that no row tracks
		removed, missing = sweep_version_folder(manifest, backup_folder, touched)
		fix_time = datetime.datetime.now().isoformat()
		missing_entries = OrderedDict((os.path.join(monitor_path, rel), BackupEntryValues(fix_time, 'create', None)) for rel in missing)
		copied = {}
		if missing_entries:
			backuperTeeLogToTl(path=monitor_path,message=f'Copying {len(missing_entries)} tracked entries missing from {backup_folder}')
			copied = replay(prepare_backup_entries_for_replay(missing_entries))
			wait_for_async_commands(mcae)
		if verified is not None:
			verified.extend(applied_fixes(fixes, applied))
			verified.extend((os.path.join(monitor_path, rel), BackupEntryValues(fix_time, 'delete', None)) for rel in removed)
			verified.extend(applied_fixes(missing_entries, copied))
	# this function does the actual backup using a referenced version and a change list to copy the source from
	# reverb backup flow:
	#   do referenced copy of the last version to the current backup folder 
	#   replay the changes chronologically ( to respect moves )
	mcae = None
	# copies queued on mcae, put in place by each wait for it
	pending = []
	try:
		manifest.begin()
		if not manifest.describes(latest_version_info.path):
			backuperTeeLogToTl(path=monitor_path,message=f'Manifest does not describe {latest_version_info.path}, listing it')
			manifest.rebuild(latest_version_info.path)
		if not do_referenced_copy(source_path=latest_version_info.path,backup_folder=backup_folder,manifest=manifest,relative=True):
			return manifest
		backuperTeeLogToTl(path=monitor_path,message='Tracking {} files and {} folders'.format(*manifest.counts()))
		mcae = multiCMD.AsyncExecutor(semaphore=BACKUP_SEMAPHORE,quiet=True)
		if recopy:
			# over the links the referenced copy just made: a copy that fails leaves the link
			job_vault = os.path.dirname(os.path.abspath(backup_folder))
			for rel in recopy:
				if not GREEN_LIGHT.is_set():
					break
				if not real_folders_to(backup_folder,rel):
					backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not copying {rel} again from the vault: a folder above it in {backup_folder} is not a real folder')
					continue
				end = chain_end(job_vault,latest_version_info.path,rel,committed_moves)
				if end is None or stat.S_ISDIR(end.st.st_mode):
					what = 'cannot be followed' if end is None else f'ends at the folder {end.path}'
					backuperTeeLogToTl(path=monitor_path,error=True,message=f'Not copying {rel} again from the vault: its link chain in {latest_version_info.path} {what}; linking it as it was, by more links than its limit')
					continue
				cp_af_copy_path(source_path=end.path,dest_path=os.path.join(backup_folder,rel),mcae=mcae,pending=pending)
			copied = wait_for_async_commands(mcae)
			manifest.mark_unchecked(copied)
			if recopied is not None:
				recopied.extend(copied)
			backuperTeeLogToTl(path=monitor_path,message=f'Copied {len(copied)} of {len(recopy)} files again from the vault, as their link chains would pass their limit')
		replay(backup_entries)
		wait_for_async_commands(mcae)
		if touched is not None and GREEN_LIGHT.is_set():
			verify()
	finally:
		try:
			# however the backup ends, no copy is left writing into this version, nor a partial file in it
			if mcae is not None:
				stop_copies(mcae,pending,backup_folder)
		finally:
			# nothing about the folders of a version still being written may be taken as known later ( the replay can make
			# one a link after it was looked at ): only committed versions keep their answers
			forget_real_vault_folders(os.path.abspath(backup_folder))
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
		candidates = [rule for rule in rules if rule.job_name == job_name and job_name]
		if not candidates:
			raise CommandError(f'No job named {job_name}; the jobs are {", ".join(rule.job_name for rule in rules if rule.job_name)}')
		path = os.path.join(candidates[0].mon_path, path)
	else:
		candidates = [rule for rule in rules if rule.job_name]
	path = os.path.abspath(path)
	def holder(path:str):
		best = None
		for rule in candidates:
			mon_path = rule.mon_path.rstrip('/')
			if (path == mon_path or path.startswith(mon_path + '/')) and (best is None or len(mon_path) > len(best[1])):
				best = (rule, mon_path)
		return best
	best = holder(path)
	if best is None and path != '/':
		# typed through a symlink above a monitored path: the path with the longest folder of it that exists resolved
		# (the name itself is kept, as a monitored symlink is backed up as one)
		resolved = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
		best = holder(resolved)
		if best is not None:
			path = resolved
	if best is None:
		where = f"job {job_name}'s monitored path ({candidates[0].mon_path})" if job_name is not None else f"any job's monitored path ({', '.join(rule.mon_path for rule in rules if rule.job_name)})"
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

def chain_form_missing_version(job_vault:str, link_path:str, link_text:str, moves:VersionMoves = None):
	'''
	The name of the version folder a link names when the link is a chain link by the rule for its place but that
	folder does not exist; else None, as for a user's symlink. The rule is vault_chain_hop()'s: the text has the form
	of a chain link (parse_chain_text()) and is the one the referenced copy writes at its own path, or moves, its
	version's moves, take the path it names there, or cannot tell. When moves cannot be used (or is None), only the
	text for its own path counts: nothing is lost by showing any other text as the symlink it may be, while calling it
	dangling would refuse its restore. An absolute link never has that form, as for strict_chain_hop(): a user's
	symlink into a version since pruned is a symlink, not a dangling chain link.

	Examples:
		>>> chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', '../../V3--2021-01-01_00-00-00_-0800/a/x')
		'V3--2021-01-01_00-00-00_-0800'
		>>> [chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', text) for text in (
		...     '../../V2--2021-01-01_00-00-00_-0800/a/x', '../V3--2021-01-01_00-00-00_-0800/a/x', '../../V3--2021-01-01_00-00-00_-0800/b/x')]
		[None, None, None]
		>>> chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', '../../V3--2021-01-01_00-00-00_-0800/b/x',
		...     VersionMoves.applied([('b/x', 'a/x', False)]))
		'V3--2021-01-01_00-00-00_-0800'
		>>> [chain_form_missing_version('/v/job', '/v/job/V4--2021-01-02_00-00-00_-0800/a/x', text) for text in (
		...     '/v/job/V3--2021-01-01_00-00-00_-0800/a/x', '/v/job/V2--2021-01-01_00-00-00_-0800/a/x',
		...     '/abs/V3--2021-01-01_00-00-00_-0800/a/x', '/v/job/V5--2021-01-03_00-00-00_-0800/a/x', '/v/job/lib/x')]
		[None, None, None, None, None]
		>>> chain_form_missing_version('/v/job', '/v/job/current_version/a/x', '../../V3--2021-01-01_00-00-00_-0800/a/x') is None
		True
	'''
	parsed = parse_chain_text(job_vault, link_text, link_path)
	if parsed is None:
		return None
	name, named_parts, ups = parsed
	try:
		os.lstat(os.path.join(os.path.abspath(job_vault), name))
		return None
	except (FileNotFoundError, NotADirectoryError):
		pass
	except (OSError, ValueError):
		return None
	vault = os.path.abspath(job_vault)
	version_name, _, rel = os.path.abspath(link_path)[len(vault) + 1:].partition('/')
	named = '/'.join(named_parts)
	if named == rel and ups == rel.count('/') + 1:
		return name
	if moves is None or not moves.usable:
		return None
	# None: the rows cannot tell, so it may be a chain link, as reading takes it
	return None if moves.tells(named, rel, version_name)[0] is False else name

def resolve_version_entry(job_vault:str, version_path:str, rel:str, monitor_path:str, moves:'VaultMoves' = None) -> ResolvedEntry:
	'''
	Where the content of rel in the version at version_path really is, following the links that chain an unchanged entry
	back to the version holding its copy (the rule read_vault_record() follows, however many versions back), each told
	by the moves of its version (moves, a VaultMoves for the pass; one reading the manifest's record when None).
	The kind is 'file' or 'folder' (path is the real copy), 'symlink' (a user's symlink backed up as one; path is the
	link), 'referenced' (a link to the monitored file itself; path is the link), 'missing' (the version has no such
	entry), 'dangling' (a chain leads to nothing, or is too long) or 'unreadable' (a link or folder could not be
	looked at); detail says what and where for the last two.
	'''
	vault = os.path.abspath(job_vault)
	if moves is None:
		moves = VaultMoves(vault, monitor_path)
	entry = os.path.abspath(os.path.join(version_path, rel))
	hops = 0
	# every hop goes down a version, so the walk ends by itself; this only bounds it should a link ever not
	own_number = vault_version_number(os.path.basename(os.path.abspath(version_path)))
	if own_number is None:
		# a folder without a number (not one list_versions gives) can chain to any version in the vault
		try:
			own_number = len(os.listdir(vault))
		except OSError as e:
			return ResolvedEntry('unreadable', os.path.abspath(os.path.join(version_path, rel)), str(e))
	max_hops = own_number + 1
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
			hop = moves.follow(entry, text)
		except (OSError, UncheckedVaultLink) as e:
			return ResolvedEntry('unreadable', entry, str(e))
		if hop is None:
			missing = chain_form_missing_version(vault, entry, text, moves.holding(entry))
			if missing is not None:
				return ResolvedEntry('dangling', entry, f'{missing} is missing')
			# a rule keeps a monitored path that is missing as typed, so it is normalised as the link's text is
			if os.path.isabs(text) and os.path.normpath(text) == os.path.abspath(os.path.join(monitor_path, entry_rel)):
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
	if '<' not in text:
		return text
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
			# the paths as entry_row() wrote them; a list written before 0.40 holds no NAME_ESCAPE, so reads as it is
			yield ChangeRow(stored_name(fields[0]), fields[1], fields[2], None if source in ('', 'None') else stored_name(source))

# --- the commands: status here, history and restore behind the same front door ---

def get_command_args(argv:list) -> argparse.Namespace:
	'''
	Parse a command's arguments: argv[0] is the command.

	Examples:
		>>> get_command_args(['status', '--rule', 'r.tsv']).rule
		'r.tsv'
		>>> get_command_args(['status', '--json']).json, get_command_args(['status']).json
		(True, False)
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
	status = commands.add_parser('status', parents=[common], help='Show the daemon and each job')
	status.add_argument('--json', action='store_true', help='Print it as one JSON object, made from the same data as the text')
	history = commands.add_parser('history', parents=[common, where], help='Show the versions that changed a path')
	history.add_argument('--files', action='store_true', help='For a folder, list each changed file')
	restore = commands.add_parser('restore', parents=[common, where], help='Copy a path back from a version')
	restore.add_argument('dest', nargs='?', default=None, help='Where to restore to')
	restore.add_argument('--version', type=int, default=None, help='The version number to restore from')
	restore.add_argument('--at', default=None, help='Restore the newest version at or before this time')
	restore.add_argument('--in-place', dest='in_place', action='store_true', help='Restore at the original path, moving what is there aside first')
	restore.add_argument('--threads', type=int, default=DEFAULT_RESTORE_THREADS, help=f'Copies to run at once (default {DEFAULT_RESTORE_THREADS})')
	restore.add_argument('--yes', action='store_true', help='Do not ask for confirmation')
	restore.add_argument('--accept', action='store_true', help='Keep the result of a folder restore that did not complete as it is: copy nothing, give its folders their metadata and end it')
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

def rule_keep_n(rule:ReverbRule) -> int:
	'''
	How many versions a rule keeps, 0 for no limit (and for a value that is not a number).
	>>> rule_keep_n(ReverbRule('j', '/m', '/v', *[''] * 5, '5', *[''] * 3)), rule_keep_n(ReverbRule('j', '/m', '/v', *[''] * 9))
	(5, 0)
	'''
	try:
		return int(rule.keep_n_versions)
	except (TypeError, ValueError):
		return 0

def vault_numbers(rule:ReverbRule, versions:list = None) -> VaultNumbers:
	'''What a job's vault holds and what limits it: sizes summed from its versions (list_versions() unless given), limits as the backuper works them out.'''
	if versions is None:
		versions = list_versions(job_vault_path(rule))
	size_limit, inode_limit = get_backup_limits_from_str(rule.backup_size_limit, *get_path_fs_info(rule.vault_path))
	return VaultNumbers(os.path.isdir(job_vault_path(rule)), len(versions), sum(v.size for v in versions),
		sum(v.inodes for v in versions), size_limit, inode_limit, rule_keep_n(rule))

def show_size(size:int, limit:int = None) -> str:
	'''
	A byte count for people, or 'no limit' when limit is 0; below 1 KiB as a whole number.
	>>> show_size(1536), show_size(0, 0), show_size(0), show_size(512)
	('1.50 KiB', 'no limit', '0 B', '512 B')
	'''
	if limit == 0:
		return 'no limit'
	if size < 1024:
		return f'{size} B'
	return format_bytes(size, use_1024_bytes=True, to_str=True).rstrip() + 'B'

def show_count(count:int, limit:int = None) -> str:
	'''
	A count for people, or 'no limit' when limit is 0; below 1000 as a whole number.
	>>> show_count(126750), show_count(5, 0), show_count(4)
	('126.75 K', 'no limit', '4')
	'''
	if limit == 0:
		return 'no limit'
	if count < 1000:
		return str(count)
	return format_bytes(count, use_1024_bytes=False, to_str=True).strip()

def show_time(epoch:float, clock_only:bool = False) -> str:
	'''A local time for people: date and minute, or only the minute of the day.'''
	return time.strftime('%H:%M' if clock_only else '%Y-%m-%d %H:%M', time.localtime(epoch))

def log_text(text) -> str:
	'''
	text as it is safe to put in a log line, as file names and exception messages are anyone's to choose and a name with
	a line break could forge a marker line that log alerts act on: shown(), except that a line break stays one, with
	four spaces after it so that no continuation line can start with a marker.
	>>> print(log_text('a\\nreverberator job x FAILED: y\\x1b'))
	a
	    reverberator job x FAILED: y\\x1b
	>>> log_text('caf\\u00e9 \\udcff')
	'café \\\\xff'
	'''
	# each line is cut with its indent, so that a second cut of the text finds nothing to cut
	return '\n'.join(cut_line(('    ' if number else '') + shown(piece)) for number, piece in enumerate(str(text).split('\n')))

# journald splits a line longer than its LineMax (48K bytes) into records of their own, and the second could start
# with a marker: no line this program logs holds more than this many bytes, its cut notice included (16384
# four-byte characters are 64K)
LOG_LINE_LIMIT = 16384

def cut_line(line:str) -> str:
	'''
	line, or a start of whole characters that leaves room for a notice of how many bytes were left out (room for as many
	digits as the line's own byte count has), so that the result is at most LOG_LINE_LIMIT bytes of UTF-8 (a lone
	surrogate counts three) and cutting it again changes nothing.
	>>> cut_line('plain')
	'plain'
	>>> cut_line('x' * (LOG_LINE_LIMIT + 3))[-17:]
	' \u2026(25 more bytes)'
	>>> len(cut_line('x' * LOG_LINE_LIMIT))
	16384
	>>> cut_line('\u65e5' * 6000)[-20:]
	'\u65e5 \u2026(1638 more bytes)'
	>>> len(cut_line('\U0001f600' * 5000).encode())
	16381
	>>> cut_line(cut_line('x' * 20000)) == cut_line('x' * 20000)
	True
	'''
	if len(line) * 4 <= LOG_LINE_LIMIT:
		return line
	data = line.encode('utf-8', 'surrogatepass')
	if len(data) <= LOG_LINE_LIMIT:
		return line
	# the notice is at most as long as the one for all the bytes
	end = LOG_LINE_LIMIT - len(f' \u2026({len(data)} more bytes)'.encode())
	# a continuation byte at the cut belongs to a character that starts before it
	while data[end] & 0xC0 == 0x80:
		end -= 1
	return f"{data[:end].decode('utf-8', 'surrogatepass')} \u2026({len(data) - end} more bytes)"

def shown(text) -> str:
	'''
	text as it is safe to print on a terminal, as monitored names are anyone's to choose and the commands run as root:
	each control or format character (a newline, an escape...) and each line or paragraph separator as a visible
	escape, and a byte of a name that is not UTF-8 (a lone surrogate, as os.fsdecode() gives it) as that byte.
	>>> print(shown('café \\x1b[31mred\\tnext\\nline \\udcff\\u202e'), shown('plain'))
	café \\x1b[31mred\\x09next\\x0aline \\xff\\u202e plain
	'''
	text = str(text)
	if text.isprintable():
		return text
	pieces = []
	for c in text:
		category = unicodedata.category(c)
		if category[0] != 'C' and category not in ('Zl', 'Zp'):
			pieces.append(c)
			continue
		code = ord(c)
		if 0xdc80 <= code <= 0xdcff:
			# the byte os.fsdecode() could not decode
			code -= 0xdc00
		pieces.append(f'\\x{code:02x}' if code < 0x100 else f'\\u{code:04x}' if code < 0x10000 else f'\\U{code:08x}')
	return ''.join(pieces)

def record_number(record, key:str):
	'''
	The number a status record holds at key, or None when it has no record or no number there.
	>>> record_number({'a': 3, 'b': 'x'}, 'a'), record_number({'a': 3, 'b': 'x'}, 'b'), record_number(None, 'a')
	(3, None, None)
	'''
	value = record.get(key) if record is not None else None
	return value if isinstance(value, (int, float)) else None

def job_record_last_known(record, daemon_alive:bool, daemon_started) -> bool:
	'''
	Whether a job's status record (None when it has none) gives only its last known state: the daemon is not alive, or
	the record is older than this daemon run. A job with no record is unknown, not last known.
	>>> job_record_last_known({'updated': 5}, True, 4), job_record_last_known({'updated': 5}, True, 6), job_record_last_known(None, False, None)
	(False, True, False)
	'''
	if record is None:
		return False
	return not daemon_alive or (daemon_started is not None and (record_number(record, 'updated') or 0) < daemon_started)

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
	number = lambda key: record_number(record, key) or 0
	if state == 'waiting':
		phrase = f'waiting for disk since {show_time(number("since"), True)}: {detail}'
	elif state == 'retrying':
		phrase = f'retrying at {show_time(number("retry_at"), True)} after {int(number("failures"))} failed attempts: {detail}'
	elif state == 'stopped':
		phrase = f'stopped: {detail}'
	else:
		phrase = state
	return f'last known: {phrase}' if job_record_last_known(record, daemon_alive, daemon_started) else phrase

def daemon_view(status:DaemonStatus, rule_path:str) -> dict:
	'''
	The daemon as the status command shows it: whether it is alive, and the pid, version and start time it recorded
	(None when it left no record; a daemon that is not alive keeps those of its last run), and the rule file read.
	'''
	record = status.record or {}
	version = record.get('version')
	return {'alive': status.alive, 'pid': record.get('pid'), 'version': shown(version) if isinstance(version, str) else version,
		'started_at': record.get('started_at'), 'rule_path': shown(rule_path)}

def job_view(rule:ReverbRule, record, status:DaemonStatus, rule_path:str) -> dict:
	'''
	One job as the status command shows it, from its status record (None when it has none) and its vault: its state
	(unknown with no record), the phrase status prints for it (job_state_phrase()) and whether that is only the last
	known state, the record's detail, failures, retry_at and since; the number and time of the newest kept version
	(last_backup, the time the version folder is named with) and of the oldest one, None when there is none; how many
	versions are kept and the limit (keep, 0 for none); and the vault: its path, whether it is mounted, its size and
	inodes with their limits (0 for none, None where status prints no vault line), or the error that kept it from
	being read (mounted and versions are then None). A job whose name cleans up to nothing is stopped from the rule
	file alone, whether or not the daemon runs, and has no vault folder (vault None). Texts are escaped as shown()
	prints them, as they can quote monitored names.
	'''
	view = {'job': shown(raw_job_name(rule)), 'state': 'unknown', 'phrase': '', 'last_known': False, 'detail': '', 'failures': 0,
		'retry_at': None, 'since': None, 'last_backup': None, 'last_version': None, 'oldest_backup': None, 'oldest_version': None,
		'versions': 0, 'keep': rule_keep_n(rule), 'vault': None}
	if not rule.job_name:
		reason = nameless_reason(rule_path)
		view.update(state='stopped', phrase=shown(f'stopped: {reason}'), detail=shown(reason))
		return view
	started = status.record['started_at'] if status.record is not None else None
	view.update(phrase=shown(job_state_phrase(record, status.alive, started)), last_known=job_record_last_known(record, status.alive, started))
	if record is not None:
		view.update(state=record['state'], detail=shown(record.get('detail') or ''), failures=int(record_number(record, 'failures') or 0),
			retry_at=record_number(record, 'retry_at'), since=record_number(record, 'since'))
	vault = view['vault'] = {'path': shown(rule.vault_path), 'mounted': None, 'error': None, 'size': None, 'size_limit': None,
		'inodes': None, 'inode_limit': None}
	try:
		versions = list_versions(job_vault_path(rule))
		numbers = vault_numbers(rule, versions)
		mounted = os.path.isdir(rule.vault_path) and bool(os.listdir(rule.vault_path))
	except OSError as e:
		# a stale mount or a permission error on one vault must not stop the others showing
		vault['error'] = shown(e)
		view['versions'] = None
		return view
	vault['mounted'] = mounted
	view['versions'] = len(versions)
	if versions:
		newest, oldest = versions[-1], versions[0]
		view.update(last_backup=newest.timestamp, last_version=newest.number, oldest_backup=oldest.timestamp, oldest_version=oldest.number)
	if mounted and numbers.present:
		vault.update(size=numbers.size, size_limit=numbers.size_limit, inodes=numbers.inodes, inode_limit=numbers.inode_limit)
	return view

def status_view(status:DaemonStatus, rules:list, rule_path:str) -> dict:
	'''
	What the status command shows, which its text (status_text()) and --json are both made from: the daemon
	(daemon_view()) and each job in the rule file's order (job_view()).
	'''
	return {'daemon': daemon_view(status, rule_path),
		'jobs': [job_view(rule, status.jobs.get(rule.job_name) if rule.job_name else None, status, rule_path) for rule in rules]}

def format_job_status(view:dict, width:int) -> list:
	'''The lines for one job of status_view(), the name first and the rest indented under it.'''
	indent = ' ' * (width + 2)
	lines = [f'{view["job"]:<{width}}  {view["phrase"]}']
	vault = view['vault']
	if vault is None:
		return lines
	if vault['error'] is not None:
		return lines + [f'{indent}vault not readable: {vault["path"]}: {vault["error"]}']
	if view['last_version'] is not None:
		keep = f'limit {view["keep"]}' if view['keep'] else 'no limit'
		lines.append(f'{indent}last backup {show_time(view["last_backup"])} (V{view["last_version"]})')
		lines.append(f'{indent}{view["versions"]} versions ({keep}), oldest V{view["oldest_version"]} {show_time(view["oldest_backup"])}')
	else:
		lines.append(f'{indent}no versions yet')
	if not vault['mounted']:
		lines.append(f'{indent}vault not mounted: {vault["path"]}')
	elif vault['size'] is not None:
		size_limit = 'no limit' if vault['size_limit'] == 0 else f'limit {show_size(vault["size_limit"])}'
		inode_limit = 'no limit' if vault['inode_limit'] == 0 else f'limit {show_count(vault["inode_limit"])}'
		lines.append(f'{indent}vault {show_size(vault["size"])} / {size_limit}, {show_count(vault["inodes"])} inodes / {inode_limit}')
	return lines

def status_text(view:dict) -> str:
	'''The status command's text for a status_view(): the daemon, then each job in the rule file.'''
	daemon = view['daemon']
	if daemon['started_at'] is None:
		header = 'reverberator is not running'
	elif daemon['alive']:
		version = '?' if daemon['version'] is None else daemon['version']
		header = f'reverberator {version}, running since {show_time(daemon["started_at"])} (pid {daemon["pid"]}), rules {daemon["rule_path"]}'
	else:
		header = f'reverberator is not running (last started {show_time(daemon["started_at"])})'
	width = max(len(job['job']) for job in view['jobs'])
	lines = [header, '']
	for job in view['jobs']:
		lines += format_job_status(job, width)
	# the view's texts are escaped already; this keeps any line that is not
	return '\n'.join(shown(line) for line in lines)

def format_status(status:DaemonStatus, rules:list, rule_path:str) -> str:
	'''The status command's text: the daemon, then each job in the rule file.'''
	return status_text(status_view(status, rules, rule_path))

def status_command(args) -> int:
	'''
	Print the daemon's and each job's state: as text, or with --json as one JSON object on one line, both made from
	status_view() so that they cannot disagree. Exits 0 whatever it finds.
	'''
	status = read_status(state_dir_path(args.state_dir))
	rule_path = command_rule_path(args, status)
	view = status_view(status, load_command_rules(rule_path), rule_path)
	print(json.dumps(view) if args.json else status_text(view))
	return 0

HistoryRow = namedtuple('HistoryRow', ['version', 'event', 'size', 'source', 'counts', 'files'])

# what a change list row can record, as a folder's history counts them
CHANGE_EVENTS = ('create', 'modify', 'attrib', 'move', 'delete')

PathChanges = namedtuple('PathChanges', ['row', 'moved_from', 'moved_to', 'counts', 'files', 'recopied'])

def path_changes(change_list:str, path:str, folder:bool = False, list_files:bool = True) -> PathChanges:
	'''
	What the change list at change_list says about path, an absolute monitored path, read once as it streams in: the
	path's own row (None when it has none); where a move of it, or of a folder above it, took it from (moved_from) or
	to (moved_to), else None; and for a folder, how many rows lie below it by event (counts) and each one's
	(event, path below the folder) in the list's order, folders keeping their trailing '/' (files; None unless
	list_files). The folder's own row is not counted below it; a move out of the folder counts as a delete, listed as
	('moved_away', the path it left). A file the version copied again from the vault is no change: its recopy row is
	neither the path's row nor counted, and only sets recopied.
	'''
	own = path.rstrip('/')
	prefix = own + '/'
	row_found = moved_from = moved_to = None
	# the nearest folder above the path that moved tells where it went
	from_depth = to_depth = 0
	counts = dict.fromkeys(CHANGE_EVENTS, 0) if folder else None
	files = [] if folder and list_files else None
	recopied = False
	for row in iter_change_list(change_list):
		its_own = row.path.rstrip('/') == own
		if row.event == 'recopy':
			recopied = recopied or its_own
			continue
		if its_own:
			row_found = row
		elif folder and row.path.startswith(prefix) and row.event in counts:
			counts[row.event] += 1
			if files is not None:
				files.append((row.event, row.path[len(prefix):]))
		elif folder and row.event == 'move' and row.source_path and row.source_path.startswith(prefix) and row.source_path != prefix:
			# moved out of the folder: gone from it
			counts['delete'] += 1
			if files is not None:
				files.append(('moved_away', row.source_path[len(prefix):]))
		if row.event != 'move' or not row.source_path:
			continue
		source = row.source_path
		if its_own:
			moved_from, from_depth = source.rstrip('/'), len(prefix)
		elif row.path.endswith('/') and prefix.startswith(row.path) and len(row.path) > from_depth:
			moved_from, from_depth = source.rstrip('/') + '/' + own[len(row.path):], len(row.path)
		if source.rstrip('/') == own:
			moved_to, to_depth = row.path.rstrip('/'), len(prefix)
		elif source.endswith('/') and prefix.startswith(source) and len(source) > to_depth:
			moved_to, to_depth = row.path.rstrip('/') + '/' + own[len(source):], len(source)
	return PathChanges(row_found, moved_from, moved_to, counts, files, recopied)

def history_entry(job_vault:str, version:KeptVersion, monitor_path:str, rel:str, moves:'VaultMoves' = None) -> tuple:
	'''
	How version holds rel: its ResolvedEntry, and the path the entry's own chain link (told by version's moves, as
	resolve_version_entry() tells it) names in the older version it links to, None when the entry is not a chain link.
	'''
	vault = os.path.abspath(job_vault)
	if moves is None:
		moves = VaultMoves(vault, monitor_path)
	resolved = resolve_version_entry(job_vault, version.path, rel, monitor_path, moves)
	if resolved.kind == 'missing' or not rel:
		return resolved, None
	entry = os.path.join(os.path.abspath(version.path), rel)
	try:
		hop = moves.follow(entry, os.readlink(entry))
	except (OSError, ValueError, UncheckedVaultLink):
		# not a link, or one that cannot be looked at, as resolved says
		hop = None
	return resolved, None if hop is None else hop[len(vault) + 1:].partition('/')[2]

def resolved_size(resolved:ResolvedEntry):
	'''The size of the file a version holds, None for anything else or a copy that cannot be looked at.'''
	if resolved.kind != 'file':
		return None
	try:
		return os.lstat(resolved.path).st_size
	except OSError:
		return None

def held_event(changes:PathChanges, resolved:ResolvedEntry, moved_from:str, held_before:bool) -> tuple:
	'''
	(event, source) for a version that holds a path and changed it: its change list row's event when that fits a path
	the version holds; else a move when the entry came from another path; else a creation when the version below
	lacked it, or 'changed'. A link that leads nowhere or cannot be read is 'changed' unless its row says more. A move
	row that names no source takes moved_from, where the entry's chain link leads, as the source.
	'''
	row = changes.row
	if row is not None and row.event in ('create', 'modify', 'attrib', 'move'):
		if row.event != 'move':
			return row.event, None
		# a move row without a source leaves it to the chain
		return 'move', moved_from if changes.moved_from is None else changes.moved_from
	if resolved.kind in ('dangling', 'unreadable'):
		return 'changed', None
	if moved_from is not None:
		return 'move', moved_from
	return ('changed' if held_before else 'create'), None

def path_history(job_vault:str, versions:list, monitor_path:str, rel:str, folder:bool, list_files:bool = True, moves:'VaultMoves' = None):
	'''
	Yield the HistoryRows of file_history() or folder_history(), newest first, each as it is found: the version folders
	tell when the path changed, the change lists what. Each version's entry is resolved once, its links told by moves
	(a VaultMoves for the whole pass, made here when None), and a version's change list is read only when that version
	or the one below it holds the path.
	'''
	path = os.path.join(monitor_path, rel) if rel else monitor_path
	if not versions:
		return
	if moves is None:
		# one pass: each version's rows are read once, however many versions are walked
		moves = VaultMoves(job_vault, monitor_path)
	# walking down, the entry of the version below is the next one's own
	below = history_entry(job_vault, versions[-1], monitor_path, rel, moves)
	for index in range(len(versions) - 1, -1, -1):
		version = versions[index]
		resolved, hop_rel = below
		held = resolved.kind != 'missing'
		size = None if folder else resolved_size(resolved)
		if not index:
			# not a change: what it changed from is no longer kept, so its change list is not read
			if held:
				yield HistoryRow(version, 'oldest', size, None, dict.fromkeys(CHANGE_EVENTS, 0) if folder else None,
					[] if folder and list_files else None)
			continue
		below = history_entry(job_vault, versions[index - 1], monitor_path, rel, moves)
		# every chain from here on starts below version, so its rows are no longer needed
		moves.release(version)
		held_before = below[0].kind != 'missing'
		if not held and not held_before:
			continue
		changes = path_changes(version.change_list, path, folder, list_files)
		if held:
			# a version's folders are real folders; a file is unchanged when it links to the same path in an older version,
			# or holds a copy of it made again from the vault
			changed = (not held_before or changes.row is not None or (folder and any(changes.counts.values()))
				or (not folder and hop_rel != rel and not changes.recopied))
			if changed:
				moved_from = os.path.join(monitor_path, hop_rel) if hop_rel not in (None, rel) else changes.moved_from
				event, source = held_event(changes, resolved, moved_from, held_before)
				yield HistoryRow(version, event, size, source, changes.counts, changes.files)
		else:
			event = 'delete' if changes.moved_to is None else 'moved_away'
			yield HistoryRow(version, event, None, changes.moved_to, changes.counts, changes.files)

def path_kind(job_vault:str, versions:list, monitor_path:str, rel:str, moves:'VaultMoves' = None) -> str:
	'''
	Whether rel is a 'folder' or a 'file' (anything else held for it too, such as a symlink) in the newest version that
	holds it, None when no kept version does. The monitored path itself is a folder. moves tells the vault's links, as
	resolve_version_entry() says.
	'''
	if not rel:
		return 'folder'
	found = None
	for version in reversed(versions):
		kind = resolve_version_entry(job_vault, version.path, rel, monitor_path, moves).kind
		if kind == 'folder':
			return 'folder'
		if kind == 'unreadable':
			# held, but an older version may still tell what it is
			found = 'file'
		elif kind != 'missing':
			return 'file'
	return found

def file_history(job_vault:str, versions:list, monitor_path:str, rel:str, moves:'VaultMoves' = None) -> list:
	'''
	The HistoryRows of a file (or symlink) at rel, newest first, from the kept versions (oldest first, as list_versions()
	gives them). A version is listed when its entry is not a chain link to the same path in an older version (a chain
	link to another path is a move from it), when it lacks the entry the version below held (delete, or moved_away when
	its change list moved the path, or a folder above it, elsewhere), or when its change list has a row for the path
	(such as an attribute change, which the version's link does not show); the row gives the event when it has one.
	The oldest kept version is listed as 'oldest' when it holds the entry. A change list is read once, streamed, and only when the version or the one below holds the entry.
	'''
	return list(path_history(job_vault, versions, monitor_path, rel, folder=False, moves=moves))

def folder_history(job_vault:str, versions:list, monitor_path:str, rel:str, list_files:bool = True, moves:'VaultMoves' = None) -> list:
	'''
	The HistoryRows of the folder at rel ('' for the monitored path), newest first: a version is listed when its change
	list has rows below the folder (counted by event, and each with its path below the folder in files unless
	list_files is False), or a row for the folder itself, or when the folder appears or goes in it (as its own row or a
	move of a folder above it says, else create or delete); the oldest kept version holding it is listed as 'oldest'.
	'''
	return list(path_history(job_vault, versions, monitor_path, rel, folder=True, list_files=list_files, moves=moves))

HISTORY_LABELS = {'create': 'created', 'modify': 'modified', 'attrib': 'attributes changed', 'delete': 'deleted',
	'changed': 'changed', 'oldest': 'oldest kept copy'}

def history_label(row:HistoryRow) -> str:
	'''
	What happened to the path in a row's version, for people.
	>>> version = KeptVersion(1, '/v/V1', 'V1', 0.0, 0, 0, '/v/V1.nsv')
	>>> [history_label(HistoryRow(version, event, None, source, None, None)) for event, source in (
	...     ('modify', None), ('move', '/m/a'), ('moved_away', '/m/b'), ('oldest', None))]
	['modified', 'moved from /m/a', 'moved to /m/b', 'oldest kept copy']
	'''
	if row.event == 'move':
		return f'moved from {row.source}' if row.source else 'moved'
	if row.event == 'moved_away':
		return f'moved to {row.source}'
	return HISTORY_LABELS.get(row.event, row.event)

def counts_phrase(counts:dict) -> str:
	'''
	What changed under a folder in a version, for people.
	>>> counts_phrase({'create': 2, 'modify': 0, 'attrib': 1, 'move': 0, 'delete': 3})
	'2 created, 0 modified, 3 deleted, 1 attributes changed'
	'''
	phrase = f'{counts["create"]} created, {counts["modify"]} modified, {counts["delete"]} deleted'
	if counts['move']:
		phrase += f', {counts["move"]} moved'
	if counts['attrib']:
		phrase += f', {counts["attrib"]} attributes changed'
	return phrase

def format_history_row(row:HistoryRow, kind:str) -> str:
	'''
	A version's line in a history: its number and time, then for a file what happened and the size of the copy, for a
	folder the counts of what changed under it, after what happened to the folder itself if anything did.
	'''
	line = f'V{row.version.number}  {show_time(row.version.timestamp)}  '
	if kind != 'folder':
		line += history_label(row) + ('' if row.size is None else f'  {show_size(row.size)}')
	elif row.event == 'changed':
		line += counts_phrase(row.counts)
	else:
		line += history_label(row) + (f'; {counts_phrase(row.counts)}' if any(row.counts.values()) else '')
	# a moved-from or moved-to path is a monitored name
	return shown(line)

def history_lines(rule:ReverbRule, job_vault:str, rows, kind:str, show_files:bool):
	'''Yield the history command's lines: the job and its vault, then a line per row (any iterable), a folder's changed paths under each when show_files.'''
	yield shown(f'job {rule.job_name}, vault {job_vault}')
	for row in rows:
		yield format_history_row(row, kind)
		if show_files and row.files:
			for event, rel in row.files:
				yield shown(f'    {event} {rel}')

def format_history(rule:ReverbRule, job_vault:str, rows:list, kind:str, show_files:bool) -> str:
	'''The history command's text: history_lines() joined.'''
	return '\n'.join(history_lines(rule, job_vault, rows, kind, show_files))

def never_backed_up(rule:ReverbRule, rule_path:str, rel:str, typed_folder:bool = False) -> str:
	'''
	Say the path at rel was never backed up, naming the pattern that skips it when the job's skip list reads and has one.
	A folder is what the live tree says, or what the path was typed as (typed_folder: it ended with a slash), as a
	folder skipped and since removed has no live tree; no kept version holds the path, so none can tell.
	'''
	path = os.path.join(rule.mon_path, rel) if rel else rule.mon_path
	skip_list_path = resolve_skip_list_path(rule.skip_list_file, rule_path)
	pattern = None
	if skip_list_path is not None:
		try:
			skip_list = SkipList.load(rule.mon_path, skip_list_path)
		except (OSError, ValueError):
			skip_list = None
		if skip_list is not None:
			pattern = skip_list.deciding_pattern(rel, typed_folder or (os.path.isdir(path) and not os.path.islink(path)))
	message = f'{path} was never backed up'
	return shown(message if pattern is None else f'{message}; it matches the skip pattern {pattern}')

@contextlib.contextmanager
def command_restore_lock(job_name:str, state_dir:str = None):
	'''Hold job_name's RestoreLock for a command; a lock it cannot take is a CommandError, not a traceback.'''
	lock = RestoreLock(job_name, state_dir)
	try:
		lock.__enter__()
	except OSError as e:
		raise CommandError(f'Cannot take the restore lock of job {job_name}, which keeps its versions while they are read: {e}', EXIT_COMMAND_FAILED)
	try:
		yield lock
	finally:
		lock.__exit__(None, None, None)

def require_job_vault(job_vault:str):
	'''
	A CommandError unless job_vault is a folder: a disk not mounted leaves an empty mount point, which is no reason to say
	nothing was backed up. Any other error looking at it is raised as it is.
	'''
	try:
		there = stat.S_ISDIR(os.stat(job_vault).st_mode)
	except (FileNotFoundError, NotADirectoryError):
		there = False
	if not there:
		raise CommandError(f'The vault {job_vault} is not there (is its disk mounted?)', EXIT_COMMAND_FAILED)

def history_command(args) -> int:
	'''Print the versions in which a file or folder changed, newest first. Exits 0 once shown, a path never backed up too.'''
	rule_path = command_rule_path(args, read_status(state_dir_path(args.state_dir)))
	rule, rel = find_job(load_command_rules(rule_path), args.path, args.job)
	job_vault = job_vault_path(rule)
	# taken before the versions are listed, so the list is the one left by a removal of the oldest version under way
	output_closed = False
	with command_restore_lock(rule.job_name, args.state_dir):
		try:
			require_job_vault(job_vault)
			versions = list_versions(job_vault)
			# the moves of each version, read once for the whole command, and the record of monitored paths once, when a
			# link first needs rows, waiting while the daemon writes the manifest
			moves = VaultMoves(job_vault, rule.mon_path, read_record=command_monitor_paths)
			kind = path_kind(job_vault, versions, rule.mon_path, rel, moves) if versions else None
			if kind is not None:
				# each row is printed as it is found, so a job's whole history is never held; the lock is held all the while,
				# so pruning waits for the output to be read (in a pager, say)
				rows = path_history(job_vault, versions, rule.mon_path, rel, folder=kind == 'folder', list_files=args.files and kind == 'folder', moves=moves)
				lines = history_lines(rule, job_vault, rows, kind, args.files)
				# an OSError from the next line is the vault's; one from writing it is the reader's going away
				for line in lines:
					try:
						print(line)
					except OSError:
						output_closed = True
						break
				try:
					sys.stdout.flush()
				except OSError:
					output_closed = True
		except OSError as e:
			raise CommandError(f'The vault {job_vault} cannot be read: {e}', EXIT_COMMAND_FAILED)
	if output_closed:
		# nobody is reading: stop without a message, and without Python's error for the buffered text at exit
		try:
			os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
		except (OSError, ValueError, AttributeError):
			pass
		return EXIT_COMMAND_FAILED
	if kind is None:
		# the header alone, then why there is nothing to show
		print(format_history(rule, job_vault, [], 'file', False) + '\n' + never_backed_up(rule, rule_path, rel, args.path.endswith('/')))
	return 0

# --- restore: a file, a folder or a whole job copied out of a kept version ---

# the times --at reads besides a version folder's own, all in local time
AT_TIME_FORMATS = ('%Y-%m-%d', '%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%dT%H:%M:%S')
# a folder restore marks its target as its own unfinished output with this file at the top of it, until it is complete
RESTORE_MARKER_NAME = '.reverberator-restore'
# the names partial_copy_path() gives, which a restore killed outright leaves behind
PARTIAL_COPY_NAME = re.compile(r'\.[0-9a-f]{32}' + re.escape(PARTIAL_COPY_SUFFIX))

def parse_at_time(text:str) -> float:
	'''
	The time --at names, as an epoch: YYYY-MM-DD, YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS (a T in place of the space too)
	in local time, or a version folder's time with its offset. Anything else is a CommandError.
	>>> parse_at_time('2021-01-01_00-00-00_-0800')
	1609488000.0
	'''
	text = text.strip()
	for time_format in (VAULT_TIMESTAMP_FORMAT,) + AT_TIME_FORMATS:
		try:
			# a time without an offset is a naive one, which timestamp() takes as local
			return datetime.datetime.strptime(text, time_format).timestamp()
		except ValueError:
			continue
	raise CommandError(f"Cannot read the time {text}: give YYYY-MM-DD, YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS in local time, or a version folder's time such as 2021-01-01_00-00-00_-0800")

def version_ranges(numbers) -> str:
	'''
	Version numbers for people, each run of them as a range.
	>>> version_ranges([0, 1, 2, 5, 7, 8]), version_ranges([])
	('V0-V2, V5, V7-V8', 'none')
	'''
	runs = []
	for number in numbers:
		if runs and number == runs[-1][1] + 1:
			runs[-1][1] = number
		else:
			runs.append([number, number])
	return ', '.join(f'V{first}' if first == last else f'V{first}-V{last}' for first, last in runs) or 'none'

def restore_candidates(job_vault:str, versions:list, monitor_path:str, rel:str, kind:str, moves:'VaultMoves' = None) -> list:
	'''The HistoryRows of the versions that hold rel, a 'file' or a 'folder' as kind says, and differ: newest first, as history lists them.'''
	if kind == 'folder':
		# the picker shows no paths, and a whole job's would all be held at once
		rows = folder_history(job_vault, versions, monitor_path, rel, list_files=False, moves=moves)
	else:
		rows = file_history(job_vault, versions, monitor_path, rel, moves)
	return [row for row in rows if row.event not in ('delete', 'moved_away')]

def choose_version(candidates:list, versions:list, holds, version:int = None, at:str = None, stdin = None, stderr = None) -> KeptVersion:
	'''
	The kept version (of versions, oldest first) to restore from, holds(KeptVersion) saying whether a version holds the
	path: number version; else the newest from at or before the time at; else the only one of candidates (as
	restore_candidates() gives them), named on stderr; else the one the user picks from a numbered list of them, asked
	on stdin, which must be a terminal. The list and the question go to stderr, which stays on the terminal when the
	restore's own output is redirected. A version not kept or not holding the path, no version at or before at and no
	terminal to ask on are CommandErrors; a pick cancelled with q (or the end of stdin) is one with EXIT_COMMAND_FAILED.
	stdin and stderr are sys.stdin and sys.stderr unless given.
	'''
	stdin = sys.stdin if stdin is None else stdin
	stderr = sys.stderr if stderr is None else stderr
	holding = lambda: version_ranges(kept.number for kept in versions if holds(kept))
	if version is not None and at is not None:
		raise CommandError('Give --version or --at, not both')
	if version is not None:
		chosen = next((kept for kept in versions if kept.number == version), None)
		if chosen is None:
			raise CommandError(f'V{version} is not kept; the kept versions are {version_ranges(kept.number for kept in versions)}')
		if not holds(chosen):
			raise CommandError(f'V{version} does not hold that path; the kept versions holding it are {holding()}')
		return chosen
	if at is not None:
		limit = parse_at_time(at)
		for kept in reversed(versions):
			if kept.timestamp <= limit and holds(kept):
				return kept
		raise CommandError(f'No kept version holding that path is from {at} or before; the kept versions holding it are {holding()}')
	if stdin is None or not stdin.isatty():
		raise CommandError('Choose the version to restore with --version N or --at TIME (the history command lists them): there is no terminal to ask on')
	if not candidates:
		raise CommandError('No kept version holds that path')
	# a folder's rows count what changed under it
	kind = 'file' if candidates[0].counts is None else 'folder'
	if len(candidates) == 1:
		print(f'Restoring the one version that differs: {format_history_row(candidates[0], kind)}', file=stderr)
		return candidates[0].version
	width = len(str(len(candidates)))
	print('The versions that differ, newest first:', file=stderr)
	for number, row in enumerate(candidates, 1):
		print(f'  {number:>{width}}  {format_history_row(row, kind)}', file=stderr)
	while True:
		print(f'Restore which version? [1-{len(candidates)}, q to cancel] ', end='', file=stderr, flush=True)
		answer = stdin.readline()
		# nothing at all is the end of stdin, unlike an empty line
		if not answer or answer.strip().lower() == 'q':
			raise CommandError('Cancelled', EXIT_COMMAND_FAILED)
		try:
			number = int(answer.strip())
		except ValueError:
			number = 0
		if 1 <= number <= len(candidates):
			return candidates[number - 1].version
		print(f'Enter a number from 1 to {len(candidates)}, or q to cancel', file=stderr)

def unfinished_note(target:str) -> str:
	'''What a folder restore that did not complete leaves at target until it is run again, with or without --accept.'''
	owner = 'root' if os.geteuid() == 0 else f'uid {os.geteuid()}'
	return f'Until then {target} stays private (mode 0700) and its folders stay owned by {owner}, without their own modes and times'

class RestoreReport:
	'''
	What a restore did: the entries it restored and their bytes, the entries it kept as an earlier run had restored them,
	and failures and warnings as (path below the monitored path, reason). Each is written to stderr by fail() and warn()
	as it happens, and counted; only the first RESTORE_SUMMARY_LINES of each are kept, for the summary, as a restore of
	a damaged vault can have hundreds of thousands. restore_entry() fills in the version, the path and the target it
	restores, the marker of a folder target while it is there, and whether it left a folder target private as not
	everything was restored.
	'''
	def __init__(self):
		self.version = None
		self.rel = ''
		self.target = None
		self.marker = None
		self.restored = 0
		self.kept = 0
		self.bytes = 0
		self.failures = []
		self.failed = 0
		self.warnings = []
		self.warned = 0
		# the entries (rels, in the order they came) kept or restored without all of their metadata, as far as a marker records
		self.unset = {}
		self.left_private = False
		# set once the folders began to be given their owners, which a stop leaves half done
		self.handing_over = False
		# set once the target itself began to be given its owner: nothing is written by its path after that
		self.target_handing_over = False
		# with --accept: kept as it was, and how many folders it handed to their owners
		self.accepted = False
		self.handed_over = 0
		# the first line comes a period after the start, so a quick restore writes none
		self.progress_at = time.monotonic()
		self.progress_width = 0
		# set once a write of the progress fails (a closed pipe, a hung-up terminal): it is not tried again
		self.progress_failed = False

	def note(self, word:str, rel:str, reason:str) -> None:
		'''Write the line "word rel: reason" on stderr now, starting a line of its own where a progress line is being rewritten.'''
		try:
			if self.progress_width and sys.stderr.isatty():
				sys.stderr.write('\r' + ' ' * self.progress_width + '\r')
			sys.stderr.write(shown(f'{word} {rel or "."}: {reason}') + '\n')
			sys.stderr.flush()
		except (OSError, ValueError):
			# nowhere to write it: the summary has the first of them
			pass

	def fail(self, rel:str, reason:str) -> None:
		'''Record that rel was not restored, and say so now.'''
		self.failed += 1
		if len(self.failures) < RESTORE_SUMMARY_LINES:
			self.failures.append((rel, reason))
		self.note('FAILED', rel, reason)

	def warn(self, rel:str, reason:str) -> None:
		'''Record a warning about rel, and say so now.'''
		self.warned += 1
		if len(self.warnings) < RESTORE_SUMMARY_LINES:
			self.warnings.append((rel, reason))
		self.note('WARNING', rel, reason)

	def note_unset(self, rel:str) -> None:
		'''Remember rel as an entry without all of its metadata, for the marker, up to RESTORE_MARKER_UNSET_LIMIT of them.'''
		if len(self.unset) < RESTORE_MARKER_UNSET_LIMIT:
			self.unset[rel] = None

	def entry_rel(self, path:str) -> str:
		'''The path below the monitored path that path, in the target, restores.'''
		below = os.path.relpath(path, self.target)
		if below == '.':
			return self.rel
		return os.path.join(self.rel, below) if self.rel else below

	def progress(self, stream, done:bool = False):
		'''
		Write the progress line on stream: rewritten in place on a terminal, at most every RESTORE_PROGRESS_TERMINAL_SECONDS,
		and a line every RESTORE_PROGRESS_LINE_SECONDS anywhere else. done ends a terminal's line once the restore is over.
		'''
		if self.progress_failed:
			return
		terminal = stream.isatty()
		if done and not (terminal and self.progress_width):
			return
		now = time.monotonic()
		if not done and now - self.progress_at < (RESTORE_PROGRESS_TERMINAL_SECONDS if terminal else RESTORE_PROGRESS_LINE_SECONDS):
			return
		self.progress_at = now
		line = f'restored {self.restored} entries, {show_size(self.bytes)}'
		try:
			if terminal:
				# padded over what a longer line before it left
				stream.write('\r' + line.ljust(self.progress_width) + ('\n' if done else ''))
				self.progress_width = max(self.progress_width, len(line))
			else:
				stream.write(line + '\n')
			stream.flush()
		except (OSError, ValueError):
			# a broken pipe, or EIO once the terminal hung up: the restore carries on without progress lines
			self.progress_failed = True

	def summary(self) -> str:
		'''What was restored, from which version to where, then each entry restored without all of its metadata and each one not restored.'''
		if self.accepted:
			head = f'Kept {self.target} as it is, restored from V{self.version.number}: gave {self.handed_over} folders their own metadata, copied nothing'
		else:
			head = f'Restored {self.restored} entries ({show_size(self.bytes)})'
			if self.version is not None:
				head += f' from V{self.version.number} to {self.target}'
			if self.kept:
				head += f', keeping {self.kept} already there'
		lines = [head]
		lines += [f'WARNING {rel or "."}: {reason}' for rel, reason in self.warnings]
		if self.warned > len(self.warnings):
			lines.append(f'{self.warned - len(self.warnings)} more warnings: shown above as they happened')
		lines += [f'FAILED {rel or "."}: {reason}' for rel, reason in self.failures]
		if self.failed > len(self.failures):
			lines.append(f'{self.failed - len(self.failures)} more failed: shown above as they happened')
		if self.failed and self.marker is not None:
			lines.append(f'{self.failed} failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {unfinished_note(self.target)}')
		elif self.left_private:
			lines.append(f'Left {self.target} private (mode 0700), as not everything was restored')
		# the paths, details and cp's messages can quote monitored names
		return '\n'.join(shown(line) for line in lines)

def place_new_entry(temp_path:str, dest_path:str):
	'''
	Put temp_path at dest_path only while nothing is there, never replacing what is: as a hard link of temp_path itself
	(a symlink too), which leaves temp_path for the caller to remove, or where the filesystem has no hard links by a
	rename once dest_path is found free. FileExistsError when something is there.
	'''
	try:
		os.link(temp_path, dest_path, follow_symlinks=False)
	except FileExistsError:
		raise
	except OSError as e:
		if e.errno not in (errno.EPERM, errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP):
			raise
		# the name could still be taken between the look and the rename, which only a link rules out
		if os.path.lexists(dest_path):
			raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dest_path)
		os.rename(temp_path, dest_path)

def finish_restore_copies(pending:list, report:RestoreReport) -> None:
	'''
	Put the copies of pending in place once the executor has finished them, as finish_copies() does for a backup, and
	empty pending. A copy that succeeded takes its destination's place and counts as restored, as does one for which cp
	only reported metadata it could not keep (a warning says so); one that failed leaves no partial file and is a
	failure saying what cp said. The report's target itself, a restored file or symlink in a folder anyone may write
	in, never replaces what appeared there meanwhile (place_new_entry()); what is inside a folder target, which only
	this restore can write in, takes its destination's place.
	'''
	done = 0
	try:
		for copy in pending:
			rel = report.entry_rel(copy.dest_path)
			lines = [line.strip() for line in copy.task.stderr if line.strip()]
			error = '; '.join(lines)
			succeeded = copy.task.returncode == 0
			temp_name = os.path.basename(copy.temp_path)
			if not succeeded and lines and all(copy_metadata_failure(line, temp_name) for line in lines) and os.path.lexists(copy.temp_path):
				report.warn(rel, f'copied without all of its metadata: {error}')
				report.note_unset(rel)
				succeeded = True
			if succeeded:
				try:
					if copy.dest_path == report.target:
						place_new_entry(copy.temp_path, copy.dest_path)
						# the hard link left it, a rename did not
						discard_copies([copy])
					else:
						replace_entry(copy.temp_path, copy.dest_path)
				except FileExistsError:
					succeeded, error = False, f'{copy.dest_path} appeared while restoring; left untouched'
				except OSError as e:
					succeeded, error = False, str(e)
			if succeeded:
				report.restored += 1
				try:
					st = os.lstat(copy.dest_path)
				except OSError:
					st = None
				if st is not None and stat.S_ISREG(st.st_mode):
					# the contents restored: a symlink's text is no file's
					report.bytes += st.st_size
			else:
				report.fail(rel, error or f'cp exited with {copy.task.returncode}')
				discard_copies([copy])
			done += 1
	finally:
		# an error above leaves no partial file of the copies it did not reach
		rest = pending[done:]
		pending.clear()
		discard_copies(rest)

def restore_failure(resolved:ResolvedEntry, version:KeptVersion):
	'''Why the entry version holds, as resolve_version_entry() found it, cannot be copied out: None for a file or a user's symlink.'''
	if resolved.kind in ('file', 'symlink'):
		return None
	if resolved.kind == 'dangling':
		return f'dangling vault link: {resolved.detail}'
	if resolved.kind == 'referenced':
		# the link leads to the live file, which is not that version's
		return 'not held in the vault (referenced backup)'
	if resolved.kind == 'unreadable':
		return f'unreadable in the vault: {resolved.detail}'
	if resolved.kind == 'missing':
		return f'not in V{version.number}: {resolved.detail}'
	# a folder where the walk found a link
	return f'a vault link to a folder: {resolved.path}'

def restore_folder_meta(source:str, dest:str):
	'''
	Give dest, a folder a restore made, the vault folder source's extended attributes, mode and times, then its owner
	as the very last step. All of it is done on dest as opened, not followed if it is a symlink: once another user owns
	the folder they could rename it and put a symlink in its place, and nothing may reach through that. None once all
	of it is done, else the error that stopped it, for the warning. (copy_file_meta() works by path, as the daemon's
	vault is no other user's to change.)
	'''
	try:
		held = os.lstat(source)
		fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
	except OSError as e:
		return str(e)
	try:
		try:
			names = os.listxattr(source, follow_symlinks=False)
		except OSError as e:
			if e.errno not in (errno.ENOTSUP, errno.ENODATA, errno.EINVAL):
				raise
			names = []
		for name in names:
			try:
				os.setxattr(fd, name, os.getxattr(source, name, follow_symlinks=False))
			except OSError as e:
				# what copystat() lets go too: an attribute this filesystem or user cannot set
				if e.errno not in (errno.EPERM, errno.ENOTSUP, errno.ENODATA, errno.EINVAL):
					raise
		os.chmod(fd, stat.S_IMODE(held.st_mode))
		os.utime(fd, ns=(held.st_atime_ns, held.st_mtime_ns))
		os.chown(fd, held.st_uid, held.st_gid)
		return None
	except OSError as e:
		return str(e)
	finally:
		os.close(fd)

def read_restore_marker(target:str):
	'''
	What the marker of an unfinished folder restore at the top of target holds, {"job", "path", "version"} and, when
	it names any, "unset": the rels of the entries kept without all of their metadata; None when
	target is not a folder (a symlink to one is not) or holds no marker. Picking a marker up lets a restore write into
	the folder, so only one this user wrote counts: a marker in a folder another user owns or can write to, one that is
	not a regular file of this user's, or one that cannot be read is a CommandError saying what was found.
	'''
	try:
		st = os.lstat(target)
	except (FileNotFoundError, NotADirectoryError):
		return None
	if not stat.S_ISDIR(st.st_mode):
		return None
	marker = os.path.join(target, RESTORE_MARKER_NAME)
	unreadable = lambda reason: CommandError(f'{marker} cannot be read as a restore marker: {reason}; restore somewhere else, or move {target} out of the way')
	try:
		held = os.lstat(marker)
	except (FileNotFoundError, NotADirectoryError):
		return None
	except OSError as e:
		raise unreadable(e)
	if st.st_uid != os.geteuid():
		found = f'{target} holds a restore marker, but the folder belongs to uid {st.st_uid}'
	elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
		found = f'{target} holds a restore marker, but other users can write to the folder'
	elif not stat.S_ISREG(held.st_mode):
		found = f'{marker} is not a regular file'
	elif held.st_uid != os.geteuid():
		found = f'{marker} belongs to uid {held.st_uid}'
	else:
		found = None
	if found is not None:
		# whoever planted it could swap what is in the folder for a symlink while the restore writes there
		raise CommandError(f'{found}: not picking up a restore from it; restore somewhere else, or move {target} out of the way')
	try:
		fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
		try:
			opened = os.fstat(fd)
			if (opened.st_dev, opened.st_ino) != (held.st_dev, held.st_ino):
				raise ValueError('it was replaced while being read')
			# a marker is a short line, and a long list of rels: more than this is no marker
			data = os.read(fd, RESTORE_MARKER_UNSET_BYTES + (1 << 16))
		finally:
			os.close(fd)
		record = json.loads(data.decode('utf-8'))
	except (OSError, ValueError) as e:
		raise unreadable(e)
	if not isinstance(record, dict) or not all(isinstance(record.get(key), str) for key in ('job', 'path', 'version')):
		raise unreadable('it does not name a job, a path and a version')
	found = {key: record[key] for key in ('job', 'path', 'version')}
	if 'unset' in record:
		if not isinstance(record['unset'], list) or not all(isinstance(rel, str) for rel in record['unset']):
			raise unreadable('its list of entries without all of their metadata is not a list of paths')
		found['unset'] = record['unset']
	return found

def write_restore_marker(target:str, job_name:str, rel:str, version:KeptVersion, unset:list = ()) -> str:
	'''
	Mark target, the folder a restore of rel of job_name from version writes into, as its own unfinished output, and
	return the marker's path. It is written under a partial name, readable by this user alone, and renamed into place,
	so the marker is there whole or not at all. unset, the rels of the entries kept without all of their metadata, is
	written as far as RESTORE_MARKER_UNSET_LIMIT of them and RESTORE_MARKER_UNSET_BYTES go; written again, the marker
	replaces the one before.
	'''
	marker = os.path.join(target, RESTORE_MARKER_NAME)
	temp = partial_copy_path(marker)
	# ASCII, a name that is not UTF-8 included
	record = {'job': job_name, 'path': rel, 'version': version.name}
	listed, size = [], 0
	for entry in unset:
		size += len(json.dumps(entry)) + 2
		if len(listed) >= RESTORE_MARKER_UNSET_LIMIT or size > RESTORE_MARKER_UNSET_BYTES:
			break
		listed.append(entry)
	if listed:
		record['unset'] = listed
	data = json.dumps(record).encode('ascii')
	fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
	try:
		with os.fdopen(fd, 'wb') as f:
			f.write(data)
			f.flush()
			# a restore stopped by a crash is picked up from it
			os.fsync(f.fileno())
		os.rename(temp, marker)
	except BaseException:
		with contextlib.suppress(OSError):
			os.unlink(temp)
		raise
	return marker

def move_aside(path:str) -> str:
	'''
	Rename path out of the way of a restore in place, to <path>.before-restore-<YYYY-MM-DD_HH-MM-SS> next to it (-1, -2
	... added while that is taken), and return the new path. It is only renamed, never copied: a symlink is moved as it is.
	>>> top = tempfile.mkdtemp()
	>>> os.symlink('nowhere', os.path.join(top, 'a'))
	>>> aside = move_aside(os.path.join(top, 'a'))
	>>> os.listdir(top) == [os.path.basename(aside)], os.readlink(aside), re.fullmatch(r'a\\.before-restore-[0-9_-]{19}', os.path.basename(aside)) is not None
	(True, 'nowhere', True)
	>>> shutil.rmtree(top)
	'''
	stamp = time.strftime('%Y-%m-%d_%H-%M-%S')
	aside = f'{path}.before-restore-{stamp}'
	number = 0
	# the restored path's folder is one only root or this user can write in (unsafe_folder_on_path()), or a sticky one
	# where another user could only take this name for an entry of their own, which the rename would replace
	while os.path.lexists(aside):
		number += 1
		aside = f'{path}.before-restore-{stamp}-{number}'
	os.rename(path, aside)
	return aside

def make_restore_folder(dest:str):
	'''
	Make the folder dest for a restore to fill, or take the one already there when it is a real folder of this user's,
	as an earlier run of the restore leaves it: None when dest can be restored into, else why not. What is in the way is
	left as it is: a symlink is never followed, and a folder another user owns is not used, as they could swap what is
	in it for a symlink while the restore writes there.
	'''
	try:
		os.mkdir(dest)
		return None
	except FileExistsError:
		pass
	return folder_refusal(os.lstat(dest))

def folder_refusal(st:os.stat_result):
	'''Why what lstat() found as st is not a folder a restore writes into, a real folder of this user's; None when it is one.'''
	if stat.S_ISLNK(st.st_mode):
		return 'a symlink is in its place, which is not followed'
	if not stat.S_ISDIR(st.st_mode):
		return 'something other than a folder is in its place'
	if st.st_uid != os.geteuid():
		return f'the folder in its place belongs to uid {st.st_uid}'
	return None

def extended_attributes(path:str) -> dict:
	'''The extended attributes of path itself (a symlink is not followed) as name -> value, without the SELinux label, which the policy gives a new file whatever the copy says.'''
	try:
		names = os.listxattr(path, follow_symlinks=False)
	except OSError as e:
		if e.errno not in (errno.ENOTSUP, errno.ENODATA, errno.EINVAL):
			raise
		return {}
	return {name: os.getxattr(path, name, follow_symlinks=False) for name in names if name != 'security.selinux'}

def already_restored(source:str, dest:str) -> bool:
	'''
	Whether dest is what restoring source, a vault file or a user's symlink, leaves: a regular file, or a symlink with
	source's text, of source's type and mode, size, mtime, owner and extended attributes. Neither is followed.
	'''
	try:
		held, there = os.lstat(source), os.lstat(dest)
		if (there.st_mode, there.st_size, there.st_mtime_ns, there.st_uid, there.st_gid) != (held.st_mode, held.st_size, held.st_mtime_ns, held.st_uid, held.st_gid):
			return False
		if extended_attributes(source) != extended_attributes(dest):
			return False
		if stat.S_ISLNK(held.st_mode):
			return os.readlink(source) == os.readlink(dest)
	except OSError:
		return False
	return stat.S_ISREG(held.st_mode)

def remove_stale_partials(folder:str, held:str) -> None:
	'''
	Remove from folder, one of a restore's output folders, the partial files an earlier run killed while copying left:
	the names partial_copy_path() gives, that are not folders and that held, the vault folder it restores, does not
	hold too. Nothing is followed.
	'''
	with os.scandir(folder) as entries:
		for entry in entries:
			if PARTIAL_COPY_NAME.fullmatch(entry.name) and not entry.is_dir(follow_symlinks=False) and not os.path.lexists(os.path.join(held, entry.name)):
				os.unlink(entry.path)

def lock_restore_target(fd:int, target:str):
	'''
	Take the lock a run of a restore holds on its target folder target, open as fd, for as long as it writes there:
	exclusive, so a CommandError when another run holds it, and released when fd is closed (or the run is killed). A
	filesystem that cannot lock a folder, as NFS cannot, leaves runs there not kept apart.
	'''
	try:
		fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except BlockingIOError:
		raise CommandError(f'{target}: another run of this restore, or another program, holds a lock on it; let that finish first')
	except OSError:
		pass

def claim_restore_target(target:str, check = None) -> int:
	'''
	Take target, a folder a restore writes into, for this run alone (lock_restore_target()) and make it private while it
	does, on the folder as opened: returns the fd holding the lock, for the caller to close once done. A CommandError
	unless it is a real folder (not a symlink) of this user's, or while another run holds it. check, when given, is
	called once the lock is held and before anything about the folder is changed, and may raise to refuse it.
	'''
	try:
		fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
	except OSError as e:
		raise CommandError(f'{target} is not a folder to restore into: {e}')
	try:
		lock_restore_target(fd, target)
		if check is not None:
			check()
		owner = os.fstat(fd).st_uid
		if owner != os.geteuid():
			raise CommandError(f'{target} belongs to uid {owner}: not restoring into it')
		os.fchmod(fd, 0o700)
	except BaseException:
		os.close(fd)
		raise
	return fd

def restore_entry(job_vault:str, version:KeptVersion, monitor_path:str, rel:str, target:str, threads:int, report:RestoreReport, resume:bool = False, aside:str = None, marked:bool = False, moves:'VaultMoves' = None) -> None:
	'''
	Copy what version holds at rel ('' for the monitored path) to target, filling report in. Nothing in the vault is
	written: it is only read from.

	A file or a user's symlink is one checked copy of the entry its chain links lead to (cp -a copies a symlink as a
	symlink), put at target only while nothing is there. A folder target is made by this restore alone (anything there
	is a CommandError, naming aside, where a restore in place moved what was there) with mode 0700, or with resume is
	the folder already there, made 0700: the unfinished output of an earlier run of this same restore, or for the whole
	job in place the empty monitored path (the caller checks which). It is marked as this restore's own
	(write_restore_marker()) before anything is copied, and the folder is walked in the version: its folders are made as
	they are met and its files copied, threads at a time, each copy put in place every RESTORE_COPY_BATCH of them. Once
	all are, and nothing failed, the marker goes and each folder gets the vault folder's metadata, the ones inside it
	first and the target last, so nothing copied into it changes its times afterwards. While anything failed, or when
	the restore stops, the marker stays and every folder is left as this restore made it, the target 0700, for a run of
	the same restore to pick up.
	A dangling chain, a link to the live file of a referenced backup, an entry that cannot be read, a failed copy or an
	OSError is a failure of that entry alone; so is a folder whose place holds a symlink, something else or another
	user's folder, which is left as it is and never written through: nothing in it is restored. With resume, an entry
	already there as restoring it leaves it (already_restored()) is kept, anything else in its place is replaced by a
	copy, and partial files a killed run left are removed. With marked, the folder target was found holding this
	restore's marker: it is read again once the target is locked, and a CommandError when it has gone meanwhile; the
	entries it names as kept without all of their metadata come back as warnings when they are kept again, and the
	marker a run leaves names those it knows of (RESTORE_MARKER_UNSET_LIMIT at most). However the restore ends, no partial file is left in target:
	a RESTORE_STOP_SIGNALS signal stops it, as a KeyboardInterrupt, once its copies can be stopped.
	'''
	report.version, report.rel, report.target = version, rel, target
	RESTORE_STOP.clear()
	handlers = {}
	mcae = multiCMD.AsyncExecutor(semaphore=threading.Semaphore(max(1, threads)), quiet=True)
	pending = []
	# (vault folder, restored folder, rel) in walk order: each folder before what is in it
	folders = []
	# the folder target's fd, holding the lock that keeps another run of this restore out until this one is done
	lock = None
	# what an earlier run's marker names as kept without all of its metadata, less what this run has met again
	earlier = {}
	written = []

	def check_stop():
		if RESTORE_STOP.is_set():
			raise KeyboardInterrupt

	def finish_batch():
		while mcae.runningThreads:
			# the executor may give each thread that long, so one check never waits much more than RESTORE_WAIT_SECONDS
			mcae.wait(timeout=RESTORE_WAIT_SECONDS / max(1, len(mcae.runningThreads)))
			check_stop()
			report.progress(sys.stderr)
		finish_restore_copies(pending, report)
		# the executor keeps every task it ran, which for a whole job would add up
		mcae.cleanup(timeout=0)

	def restore_one(resolved:ResolvedEntry, entry_rel:str, dest:str):
		reason = restore_failure(resolved, version)
		if reason is None and cp_af_copy_path(resolved.path, dest, mcae, pending) is False:
			reason = f'{resolved.path} is gone from the vault'
		if reason is not None:
			report.fail(entry_rel, reason)

	def clear_partials(folder:str, held:str, entry_rel:str):
		try:
			remove_stale_partials(folder, held)
		except OSError as e:
			report.warn(entry_rel, f'partial files an earlier run left could not be removed: {e}')

	try:
		if threading.current_thread() is threading.main_thread():
			# only the main thread can set them, and only it gets them
			for sig in RESTORE_STOP_SIGNALS:
				handlers[sig] = signal.signal(sig, lambda signum, frame: RESTORE_STOP.set())
		if moves is None:
			moves = VaultMoves(job_vault, monitor_path)
		resolved = resolve_version_entry(job_vault, version.path, rel, monitor_path, moves)
		if resolved.kind != 'folder':
			try:
				restore_one(resolved, rel, target)
			except OSError as e:
				report.fail(rel, str(e))
		else:
			# private until it is complete: nobody else can look in, nor put anything in for the copies to write through;
			# and this run's alone
			try:
				if not resume:
					# made by this restore alone
					try:
						os.mkdir(target, 0o700)
					except FileExistsError:
						if aside is not None:
							raise CommandError(f'{target} was taken meanwhile, right after what was there was moved aside to {aside}: nothing was restored; run the restore again to move that aside too', EXIT_COMMAND_FAILED)
						raise target_exists(target)
				def look_again():
					# the run whose output this was may have finished while this one waited for the lock
					nonlocal earlier, written
					earlier = dict.fromkeys(held_marker(target, os.path.basename(job_vault), rel, version).get('unset', ()))
					written = list(earlier)
				lock = claim_restore_target(target, look_again if marked else None)
			except OSError as e:
				report.fail(rel, str(e))
				return
			report.restored += 1
			folders.append((resolved.path, target, rel))
			try:
				# the job vault's folder bears the job's name
				report.marker = write_restore_marker(target, os.path.basename(job_vault), rel, version, written)
			except OSError as e:
				report.fail(rel, f"cannot mark it as this restore's output: {e}")
				report.left_private = True
				return
			if resume:
				clear_partials(target, resolved.path, rel)
			# the walk rels (ending with /) of the folders not restored, whose contents are not either
			refused = set()
			skip = lambda walk_rel: os.path.dirname(walk_rel.rstrip('/')) + '/' in refused
			errors = []
			for entry_path, walk_rel, is_dir in iter_tree_entries(resolved.path, skip=skip, errors=errors):
				below = walk_rel.rstrip('/')
				entry_rel = os.path.join(rel, below) if rel else below
				dest = os.path.join(target, below)
				try:
					if os.path.basename(below) == RESTORE_MARKER_NAME:
						# backed up while a restore into the monitored path was under way: this restore's own stays in its
						# place, and one deeper down marks an unfinished restore that is none of this one's
						report.warn(entry_rel, 'not restored: it is the marker of a restore under way when this version was taken')
						if is_dir:
							refused.add(walk_rel)
					elif is_dir:
						try:
							reason = make_restore_folder(dest)
						except OSError as e:
							reason = str(e)
						if reason is not None:
							report.fail(entry_rel, f'{reason}: nothing in it was restored')
							refused.add(walk_rel)
						else:
							if resume:
								clear_partials(dest, entry_path.rstrip('/'), entry_rel)
							report.restored += 1
							folders.append((entry_path.rstrip('/'), dest, entry_rel))
					else:
						entry = resolve_version_entry(job_vault, version.path, entry_rel, monitor_path, moves)
						there = None
						if resume:
							try:
								there = os.lstat(dest)
							except FileNotFoundError:
								pass
						if there is not None and stat.S_ISDIR(there.st_mode):
							# a copy put in its place would remove the folder with all in it
							report.fail(entry_rel, 'a folder is in its place, which is left as it is')
						elif there is not None and restore_failure(entry, version) is None and already_restored(entry.path, dest):
							report.kept += 1
							if entry_rel in earlier:
								del earlier[entry_rel]
								report.warn(entry_rel, 'kept as an earlier run restored it, which could not set all of its metadata')
								report.note_unset(entry_rel)
						else:
							earlier.pop(entry_rel, None)
							restore_one(entry, entry_rel, dest)
				except OSError as e:
					report.fail(entry_rel, str(e))
				check_stop()
				if len(pending) >= RESTORE_COPY_BATCH:
					finish_batch()
				report.progress(sys.stderr)
			for walk_rel, error in errors:
				below = walk_rel.rstrip('/')
				report.fail(os.path.join(rel, below) if rel else below, f'unreadable in the vault: {error}')
		finish_batch()
		if report.failed:
			# a folder handed to its owner now could be swapped for a symlink before a re-run writes into it
			report.left_private = bool(folders)
			return
		hand_over_folders(folders, report, check_stop)
	finally:
		try:
			# however the restore ends, no copy is left writing into target, nor a partial file in it
			stop_copies(mcae, pending, target)
		finally:
			if report.marker is not None and not report.target_handing_over:
				# the marker this run leaves: what it knows of, and what it did not get to meet again
				unset = list(report.unset) + [entry for entry in earlier if entry not in report.unset]
				if unset != written:
					with contextlib.suppress(OSError):
						write_restore_marker(target, os.path.basename(job_vault), rel, version, unset)
			for sig, handler in handlers.items():
				# None: a handler set from outside Python, which cannot be set back
				signal.signal(sig, signal.SIG_DFL if handler is None else handler)
			if lock is not None:
				os.close(lock)

def hand_over_folders(folders:list, report:RestoreReport, check_stop = None) -> None:
	'''
	Give each of folders, (vault folder, restored folder, rel) in walk order with the target first, the vault folder's
	metadata (restore_folder_meta()), counting in report.handed_over those given all of it: backwards, so every folder
	comes after the folders inside it and the target last. Its marker goes just before the target's own metadata: a run
	stopped among the folders before still leaves a restore to pick up, and removing it later would change the
	target's times. check_stop, when given, is called before each folder (so before the marker goes), and may raise to
	stop the run.
	'''
	for source, dest, entry_rel in reversed(folders):
		if check_stop is not None:
			check_stop()
		if dest == report.target and report.marker is not None:
			try:
				os.unlink(report.marker)
				report.marker = None
			except OSError as e:
				report.warn(entry_rel, f'{RESTORE_MARKER_NAME} could not be removed: {e}')
		report.handing_over = True
		if dest == report.target:
			report.target_handing_over = True
		error = restore_folder_meta(source, dest)
		if error is None:
			report.handed_over += 1
		else:
			report.warn(entry_rel, f'restored without all of its metadata: {error}')

def accept_restore(job_vault:str, version:KeptVersion, monitor_path:str, rel:str, target:str, report:RestoreReport, moves:'VaultMoves' = None) -> None:
	'''
	Keep the unfinished output of a folder restore of rel from version at target as it is (--accept), filling report
	in: copy nothing, but give its folders the metadata the version's folders have and end the restore, its marker
	removed (hand_over_folders()). The caller checks the marker. Only the real folders of this user's a restore leaves
	are handed over; anything else in a folder's place is left as it is with all under it, a warning saying so, as is
	a folder already its vault folder's owner's, which a run stopped while handing them over left with all under it
	handed over too. Partial files a killed run left are removed.
	'''
	report.version, report.rel, report.target, report.accepted = version, rel, target, True
	report.marker = os.path.join(target, RESTORE_MARKER_NAME)
	unset = []
	def look_again():
		# the run whose output this was may have finished while this one waited for the lock
		unset.extend(held_marker(target, os.path.basename(job_vault), rel, version, accept=True).get('unset', ()))
	lock = claim_restore_target(target, look_again)
	try:
		for entry_rel in unset:
			report.warn(entry_rel, 'kept without all of its metadata: an earlier run could not set it')
		resolved = resolve_version_entry(job_vault, version.path, rel, monitor_path, moves)
		if resolved.kind != 'folder':
			raise CommandError(f'Cannot keep {target} as it is: V{version.number} holds no folder there now ({restore_failure(resolved, version) or resolved.kind})', EXIT_COMMAND_FAILED)
		folders = [(resolved.path, target, rel)]
		refused = set()
		skip = lambda walk_rel: os.path.dirname(walk_rel.rstrip('/')) + '/' in refused
		errors = []

		def clear_partials(folder:str, held:str, entry_rel:str):
			try:
				remove_stale_partials(folder, held)
			except OSError as e:
				report.warn(entry_rel, f'partial files an earlier run left could not be removed: {e}')
		clear_partials(target, resolved.path, rel)
		for entry_path, walk_rel, is_dir in iter_tree_entries(resolved.path, skip=skip, errors=errors):
			if not is_dir:
				continue
			below = walk_rel.rstrip('/')
			entry_rel = os.path.join(rel, below) if rel else below
			dest = os.path.join(target, below)
			held = entry_path.rstrip('/')
			try:
				st = os.lstat(dest)
			except FileNotFoundError:
				# never made, so nothing under it was restored either
				refused.add(walk_rel)
				continue
			except OSError as e:
				refused.add(walk_rel)
				report.warn(entry_rel, f'{e}: left as it is')
				continue
			reason = folder_refusal(st)
			if reason is None and os.path.basename(below) != RESTORE_MARKER_NAME:
				clear_partials(dest, held, entry_rel)
				folders.append((held, dest, entry_rel))
				continue
			refused.add(walk_rel)
			try:
				vault_st = os.lstat(held)
			except OSError:
				vault_st = None
			if stat.S_ISDIR(st.st_mode) and vault_st is not None and (st.st_uid, st.st_gid) == (vault_st.st_uid, vault_st.st_gid):
				# handed over already, deepest first, so all under it was too
				continue
			report.warn(entry_rel, f'{reason or "not one this restore made"}: left as it is')
		for walk_rel, error in errors:
			below = walk_rel.rstrip('/')
			report.warn(os.path.join(rel, below) if rel else below, f'unreadable in the vault: {error}; the folders under it keep what the restore gave them')
		hand_over_folders(folders, report)
	finally:
		os.close(lock)

def unsafe_folder_on_path(path:str):
	'''
	The first folder from / down to path (itself a folder, its symlinks resolved) that a user other than root and this
	process's could change: owned by someone else, or writable by its group or others without the sticky bit, so that
	whoever writes there could rename what lies below it and put a symlink in its place. None when there is none; a
	folder that cannot be looked at counts as one.
	>>> top = tempfile.mkdtemp()
	>>> os.makedirs(os.path.join(top, 'open', 'mine'))
	>>> os.chmod(os.path.join(top, 'open'), 0o777)
	>>> unsafe_folder_on_path(os.path.join(top, 'open', 'mine')) == os.path.join(os.path.realpath(top), 'open')
	True
	>>> os.chmod(os.path.join(top, 'open'), 0o1777)
	>>> unsafe_folder_on_path(os.path.join(top, 'open', 'mine')) is None
	True
	>>> shutil.rmtree(top)
	'''
	parts = [part for part in os.path.realpath(path).split('/') if part]
	for depth in range(len(parts) + 1):
		folder = '/' + '/'.join(parts[:depth])
		try:
			st = os.lstat(folder)
		except OSError:
			return folder
		if st.st_uid not in (0, os.geteuid()):
			return folder
		if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not st.st_mode & stat.S_ISVTX:
			return folder
	return None

def unsafe_folder_reason(folder:str) -> str:
	'''Why unsafe_folder_on_path() named folder: it cannot be looked at (and why), or another user can change it.'''
	try:
		os.lstat(folder)
	except OSError as e:
		return f'{folder} cannot be looked at: {e}'
	return f'another user can change {folder}'

def target_exists(target:str) -> CommandError:
	'''The refusal of a restore whose target is already there.'''
	return CommandError(f'{target} already exists: restore into another folder, or move it out of the way first')

def restore_target(rules:list, dest:str, rel:str, monitor_path:str, typed:str = None) -> str:
	'''
	Where restoring rel puts it: into the folder dest, dest/<its name> (the monitored path's own name for the whole
	job); with dest None, in place, its own path in the monitored path. It is built on the folder it goes in with its
	symlinks resolved, the folder every check is made on (for the whole job in place, the monitored path itself is
	resolved). A CommandError when that folder is not one, when another user could change a folder on the way to it
	(unsafe_folder_on_path()), when in place a symlink on the way leads somewhere else now, when the target lies inside
	any job's vault, or in place holds one. typed is the destination as it was typed, which a message shows beside the
	folder it resolved to when they differ. What is at the target is check_target()'s to look at.
	'''
	if dest is not None:
		# a symlink on the way could be pointed elsewhere after the checks: only the folder found now is used
		folder = os.path.realpath(dest)
		target = os.path.join(folder, os.path.basename(rel) or os.path.basename(monitor_path.rstrip('/')))
	elif rel:
		place = os.path.join(monitor_path, rel)
		folder = os.path.realpath(os.path.dirname(place))
		target = os.path.join(folder, os.path.basename(rel))
		if folder != os.path.normpath(os.path.join(os.path.realpath(monitor_path), os.path.dirname(rel))):
			raise CommandError(f'Not restoring in place: {os.path.dirname(place)} leads to {folder} now, not to the folder it was; restore into a folder instead')
	else:
		# the monitored path is restored into, not replaced
		target = os.path.realpath(monitor_path)
		folder = os.path.dirname(target)
	# the destination as typed, and where it leads
	named = folder if typed is None or typed == folder else f'{typed} (resolved to {folder})'
	if not os.path.isdir(folder):
		if dest is not None:
			raise CommandError(f'{named} is not a folder: give an existing folder to restore into')
		raise CommandError(f'Not restoring in place: {folder} is not a folder now; restore the folder it was in place first, or restore into a folder')
	unsafe = unsafe_folder_on_path(folder)
	if unsafe is not None:
		# the copies are written by path: one who can rename a folder on the way could send them anywhere
		if dest is None:
			raise CommandError(f'Not restoring in place: {unsafe_folder_reason(unsafe)}; restore into a folder only you (or root) can write to instead')
		raise CommandError(f'Not restoring into {named}: {unsafe_folder_reason(unsafe)}; pick a destination only you (or root) can write to')
	for rule in rules:
		if is_subpath(target, rule.vault_path):
			raise CommandError(f'{target} is inside the vault {rule.vault_path}: restore somewhere else')
		if dest is None and is_subpath(rule.vault_path, target):
			# moved aside, the vault would go with it
			raise CommandError(f'Not restoring in place: {target} holds the vault {rule.vault_path}; restore into a folder instead')
	return target

def require_empty_root(root:str):
	'''
	A CommandError unless root, a job's monitored path, is a folder of this user's holding nothing but maybe an empty
	lost+found: the whole job is restored in place only into such a folder, as a disk replacing the one lost holds, for
	the monitored path cannot be moved aside (it is often a mount point).
	'''
	instead = 'restore the whole job into a folder instead'
	try:
		st = os.lstat(root)
		if not stat.S_ISDIR(st.st_mode):
			raise CommandError(f'{root} is not a folder: {instead}')
		if st.st_uid != os.geteuid():
			raise CommandError(f'{root} belongs to uid {st.st_uid}: not restoring into it; {instead}')
		names = os.listdir(root)
		found = os.path.join(root, 'lost+found')
		empty = not names or (names == ['lost+found'] and stat.S_ISDIR(os.lstat(found).st_mode) and not os.listdir(found))
	except OSError as e:
		raise CommandError(f'{root} cannot be looked at: {e}; {instead}')
	if not empty:
		raise CommandError(f'{root} is not empty: the whole job is restored in place only into an empty folder (an empty lost+found is fine); restore it into a folder instead')

def nothing_to_accept(target:str) -> CommandError:
	'''The refusal of --accept where no unfinished restore of the same path and version is.'''
	return CommandError(f'{target} holds no unfinished restore to keep: --accept keeps the result of a folder restore that did not complete, given the same path and version')

def check_marker_matches(target:str, marker:dict, job_name:str, rel:str, version:KeptVersion = None) -> None:
	'''A CommandError unless marker, which read_restore_marker() read at target, is the one of a restore of rel of job_name (from version, once it is picked).'''
	if (marker['job'], marker['path']) != (job_name, rel) or (version is not None and marker['version'] != version.name):
		raise CommandError(f'{target} holds the unfinished restore of job {marker["job"]}, path {marker["path"] or "."}, version {marker["version"]}: run that restore again to finish it, or move it out of the way')

def held_marker(target:str, job_name:str, rel:str, version:KeptVersion, accept:bool = False) -> dict:
	'''
	The marker of the restore at target, read again once this run holds the lock on it: the run whose output it was may
	have finished, or been replaced, since check_target() looked. A CommandError when there is none (with accept, the
	refusal of an --accept with nothing to accept) or it is another restore's.
	'''
	marker = read_restore_marker(target)
	if marker is None:
		if accept:
			raise nothing_to_accept(target)
		raise CommandError(f'{target} no longer holds an unfinished restore: another run finished it, or moved it away, meanwhile; run the restore again')
	check_marker_matches(target, marker, job_name, rel, version)
	return marker

def move_target_aside(target:str):
	'''
	Move what is at target, the path a restore in place goes to, aside (move_aside()), say where and return it. A
	folder another run of the restore is filling, just made and not marked yet, is not: a CommandError says so.
	'''
	lock = None
	try:
		if stat.S_ISDIR(os.lstat(target).st_mode):
			lock = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
			lock_restore_target(lock, target)
		aside = move_aside(target)
	except OSError as e:
		raise CommandError(f'Cannot move {target} aside: {e}', EXIT_COMMAND_FAILED)
	finally:
		if lock is not None:
			os.close(lock)
	print(shown(f'Moved {target} aside to {aside}'), flush=True)
	return aside

def check_target(target:str, job_name:str, rel:str, in_place:bool, version:KeptVersion = None, accept:bool = False) -> str:
	'''
	What restoring rel of job_name (from version, once it is picked) to target does with what is there: 'new' when
	nothing is, 'resume' when an earlier run of this same restore left its unfinished output there (as
	read_restore_marker() reads its marker), in place 'move aside' when anything else is, and 'into root' for the whole
	job, restored into its empty monitored path (require_empty_root()). A CommandError otherwise: the marker of another
	restore, or a destination's name already taken. With accept, whatever is there but a marker is nothing to accept
	(nothing_to_accept()): the marker is read once, here, and 'resume' is the only answer that goes on.
	'''
	marker = read_restore_marker(target)
	if marker is not None:
		check_marker_matches(target, marker, job_name, rel, version)
		return 'resume'
	if accept:
		raise nothing_to_accept(target)
	if not os.path.lexists(target):
		return 'new'
	if not in_place:
		raise target_exists(target)
	if rel:
		return 'move aside'
	require_empty_root(target)
	return 'into root'

def confirm_whole_job_in_place(job_name:str, version:KeptVersion, versions:list, root:str, status:DaemonStatus, yes:bool, resuming:bool, stdin = None, stderr = None):
	'''
	Before the whole job is restored in place into root from version, one of versions (the kept ones, oldest first): say
	which filesystem that writes to (the mount holding root as the mount table has it, so an empty mount point whose
	disk is not mounted shows the disk under it) with its free space and what the versions up to version took in the
	vault, and while status shows the daemon alive and job_name not stopped, that the job will back the restore up as
	one large change; then, unless yes, ask whether to go on. A version's recorded size is only what it copied, but the
	oldest kept version holds the whole tree it was made from: less free space than that is a CommandError when
	starting afresh (a restore picked up has some of it in place), and less than all of them together up to version is
	said to be a restore that may not fit. No terminal on stdin to ask on is a CommandError, as is any answer but yes
	(with EXIT_COMMAND_FAILED). stdin and stderr are sys.stdin and sys.stderr unless given (what it says is a prompt, which stays on the terminal when the output is redirected).
	'''
	stdin = sys.stdin if stdin is None else stdin
	stderr = sys.stderr if stderr is None else stderr
	# the folder it would be made in, when it is not there yet
	there = root if os.path.lexists(root) else os.path.dirname(root)
	mount = mount_holding(current_mount_table(), there)
	where = f'the filesystem mounted at {mount[0]} ({mount[1]})' if mount is not None else 'a filesystem the mount table does not show'
	try:
		st = os.statvfs(there)
	except OSError as e:
		raise CommandError(f'Cannot tell how much space {there} has: {e}', EXIT_COMMAND_FAILED)
	free = st.f_bavail * st.f_frsize
	oldest = versions[0]
	# each file of version is a copy one of these made: at most all of them together
	most = sum(kept.size for kept in versions if kept.number <= version.number)
	if not resuming and free < oldest.size:
		raise CommandError(f'Not restoring the whole job into {root}: {where} has {show_size(free)} free, less than the {show_size(oldest.size)} the oldest kept version, V{oldest.number}, took in the vault; is the right disk mounted there? Restore into a folder instead')
	took = f'V{oldest.number}' if oldest.number == version.number else f'V{oldest.number} to V{version.number}'
	lines = [f'Restoring the whole job into {root}, on {where}: {show_size(free)} free, {took} took {show_size(most)} in the vault']
	if not resuming and free < most:
		lines.append(f'V{version.number} may not fit: its files can come from any of {took}, more than the free space')
	record = status.jobs.get(job_name)
	if status.alive and (record is None or record['state'] != 'stopped'):
		lines.append(f'reverberator is running job {job_name}, which will back the restore up as one large change')
	if not yes and (stdin is None or not stdin.isatty()):
		raise CommandError(f'{"; ".join(lines)}: give --yes to go on, as there is no terminal to ask on')
	for line in lines:
		# the paths, the mount's source and the job's name are anyone's to choose
		print(shown(line), file=stderr)
	if yes:
		return
	print('Continue? [y/N] ', end='', file=stderr, flush=True)
	if stdin.readline().strip().lower() not in ('y', 'yes'):
		raise CommandError('Cancelled', EXIT_COMMAND_FAILED)

def restore_command(args) -> int:
	'''
	Copy a file, a folder or a whole job out of a kept version into a destination folder, or with --in-place back to its
	own path, moving what is there aside first (the whole job only into its empty monitored path, once asked). A folder
	restore that stopped or failed part way is picked up by running it again, or kept as it is by running it again
	with --accept. One run of a restore into a target at a time. Exits 0 once everything was restored (or kept),
	EXIT_COMMAND_FAILED when anything was not (each named), EXIT_USAGE when it cannot start.
	'''
	if args.in_place and args.dest is not None:
		raise CommandError('Give a destination folder or --in-place, not both')
	if not args.in_place and args.dest is None:
		raise CommandError('Give the folder to restore into, or --in-place')
	if args.threads is None or args.threads < 1:
		raise CommandError('--threads must be at least 1')
	# resolved once: the typed path is not looked at again, whatever its symlinks point to later
	dest = None if args.in_place else os.path.realpath(args.dest)
	rule_path = command_rule_path(args, read_status(state_dir_path(args.state_dir)))
	rules = load_command_rules(rule_path)
	rule, rel = find_job(rules, args.path, args.job)
	job_vault = job_vault_path(rule)
	# taken before the versions are listed and held to the last copy, so the daemon removes none of them meanwhile
	with command_restore_lock(rule.job_name, args.state_dir):
		try:
			require_job_vault(job_vault)
			versions = list_versions(job_vault)
			# the moves of each version, read once for the whole command, and the record of monitored paths once, when a
			# link first needs rows, waiting while the daemon writes the manifest
			moves = VaultMoves(job_vault, rule.mon_path, read_record=command_monitor_paths)
			kind = path_kind(job_vault, versions, rule.mon_path, rel, moves) if versions else None
			if kind is None:
				raise CommandError(never_backed_up(rule, rule_path, rel, args.path.endswith('/')))
			# refused before a version is picked, and again once one is, as picking can take a while
			target = restore_target(rules, dest, rel, rule.mon_path, args.dest)
			first = check_target(target, rule.job_name, rel, args.in_place, accept=args.accept)
			holds = lambda version: resolve_version_entry(job_vault, version.path, rel, rule.mon_path, moves).kind != 'missing'
			# only the picker shows them, and for a whole job they come from every change list
			picking = args.version is None and args.at is None and sys.stdin is not None and sys.stdin.isatty()
			candidates = restore_candidates(job_vault, versions, rule.mon_path, rel, kind, moves) if picking else []
			version = choose_version(candidates, versions, holds, args.version, args.at, sys.stdin, sys.stderr)
		except OSError as e:
			raise CommandError(f'The vault {job_vault} cannot be read: {e}', EXIT_COMMAND_FAILED)
		target = restore_target(rules, dest, rel, rule.mon_path, args.dest)
		if args.in_place and not rel and not args.accept:
			# the daemon as it is now, not before the picking; asked before the monitored path is looked at for the last
			# time, as an answer can take a while
			confirm_whole_job_in_place(rule.job_name, version, versions, target, read_status(state_dir_path(args.state_dir)), args.yes, first == 'resume', sys.stdin, sys.stderr)
		# with --accept, a marker there is one of this restore's or a CommandError
		found = check_target(target, rule.job_name, rel, args.in_place, version, accept=args.accept)
		aside = None
		if found == 'move aside':
			# the live entry is moved only for a version that can put something in its place
			try:
				entry = resolve_version_entry(job_vault, version.path, rel, rule.mon_path, moves)
			except OSError:
				entry = None
			if entry is None or entry.kind == 'folder' or restore_failure(entry, version) is None:
				aside = move_target_aside(target)
		report = RestoreReport()
		try:
			if args.accept:
				accept_restore(job_vault, version, rule.mon_path, rel, target, report, moves)
			else:
				restore_entry(job_vault, version, rule.mon_path, rel, target, args.threads, report, resume=found in ('resume', 'into root'), aside=aside, marked=found == 'resume', moves=moves)
		except KeyboardInterrupt:
			if report.marker is None:
				raise
			if report.handing_over:
				# the folders handed over are another user's now, which a run again refuses to write into
				raise CommandError(f'Interrupted: the restore was stopped while giving its folders their owners; finish it by running the same restore again with --accept. {unfinished_note(target)}', EXIT_COMMAND_FAILED)
			raise CommandError(f'Interrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {unfinished_note(target)}', EXIT_COMMAND_FAILED)
		finally:
			report.progress(sys.stderr, done=True)
	print(report.summary())
	return EXIT_COMMAND_FAILED if report.failed else 0

def run_command(argv:list) -> int:
	'''Run the command argv names and return its exit status; a CommandError prints its message on stderr.'''
	global tl
	args = get_command_args(argv)
	old_tl = tl
	# library logging stays off the output
	tl = LockedLogger(Tee_Logger.teeLogger(systemLogFileDir='/dev/null', programName='reverberator', compressLogAfterMonths=0, deleteLogAfterYears=0, suppressPrintout=True, noLog=True))
	try:
		return COMMAND_FUNCTIONS[args.command](args)
	except CommandError as e:
		# it can quote a typed or a monitored path
		print(shown(e.message), file=sys.stderr)
		return e.code
	except KeyboardInterrupt:
		print('Interrupted', file=sys.stderr)
		return EXIT_COMMAND_FAILED
	finally:
		tl = old_tl

COMMAND_FUNCTIONS = {'status': status_command, 'history': history_command, 'restore': restore_command}

if __name__ == "__main__":
	main()
# %%
