import errno
import os
import time
from collections import namedtuple, OrderedDict
from datetime import datetime

import TSVZ
import reverberator as rv

JobPaths = namedtuple('JobPaths', ['root', 'monitor', 'vault', 'job_name', 'job_vault', 'rule_path'])


def create_job(root: str, job_name: str = 'job') -> JobPaths:
	monitor = os.path.join(root, 'monitor')
	vault = os.path.join(root, 'vault')
	os.makedirs(monitor, exist_ok=True)
	os.makedirs(vault, exist_ok=True)
	return JobPaths(root, monitor, vault, job_name, os.path.join(vault, job_name), os.path.join(root, 'rule.tsv'))


def write_tree(root: str, tree: dict) -> None:
	os.makedirs(root, exist_ok=True)
	for rel, content in tree.items():
		rel_norm = rel.rstrip('/')
		dest = os.path.join(root, rel_norm)
		if content is None or rel.endswith('/'):
			os.makedirs(dest, exist_ok=True)
			continue
		parent = os.path.dirname(dest)
		if parent:
			os.makedirs(parent, exist_ok=True)
		with open(dest, 'w', encoding='utf-8') as f:
			f.write(content)


def seed_monitor(job: JobPaths, tree: dict) -> None:
	write_tree(job.monitor, tree)


def tracked_manifest(job_vault: str, version_dir: str, files=(), folders=()) -> 'rv.VaultManifest':
	'''A committed manifest tracking files and folders as version_dir's unverified entries.'''
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.reset(version_dir)
	for rel in [*folders, *files]:
		manifest.add(rel)
	manifest.commit(version_dir)
	return manifest


def rule_row(job: JobPaths, min_snapshot: str = '1', max_snapshot: str = '86400',
		mon_fs_signature: str = 'N/A', vault_fs_signature: str = 'N/A',
		keep_one_complete_backup: str = 'True', only_sync_attributes: str = 'True',
		keep_n_versions: str = '0', backup_size_limit: str = '0', skip_list_file: str = '') -> list:
	return [
		job.job_name, job.monitor, job.vault, mon_fs_signature, min_snapshot, max_snapshot,
		keep_one_complete_backup, only_sync_attributes, keep_n_versions, backup_size_limit,
		vault_fs_signature, skip_list_file,
	]


def write_rule(job: JobPaths, min_snapshot: str = '1', max_snapshot: str = '86400',
		mon_fs_signature: str = 'N/A', vault_fs_signature: str = 'N/A',
		keep_one_complete_backup: str = 'True', only_sync_attributes: str = 'True',
		keep_n_versions: str = '0', backup_size_limit: str = '0', skip_list_file: str = '',
		extra_rows=()) -> str:
	row = rule_row(job, min_snapshot, max_snapshot, mon_fs_signature, vault_fs_signature,
		keep_one_complete_backup, only_sync_attributes, keep_n_versions, backup_size_limit, skip_list_file)
	os.makedirs(os.path.dirname(job.rule_path) or '.', exist_ok=True)
	with open(job.rule_path, 'w', encoding='utf-8') as f:
		f.write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n')
		f.write('\t'.join(row) + '\n')
		for extra in extra_rows:
			f.write(('\t'.join(extra) if not isinstance(extra, str) else extra) + '\n')
	return job.rule_path


def content_file_path(version_dir: str) -> str:
	size_s = rv.format_bytes(rv.get_path_size(version_dir), use_1024_bytes=True, to_str=True).replace(' ', '_')
	ino_s = rv.format_bytes(rv.get_path_inodes(version_dir), use_1024_bytes=False, to_str=True).replace(' ', '')
	return f'{version_dir}--{size_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}'


def write_change_list(path: str, monitor: str, rows) -> str:
	'''
	A change list at path as do_backup() writes one: each row (rel, event, source rel or None), a folder's rels ending
	with /, made absolute under monitor.
	'''
	lines = [rv.entry_row(os.path.join(monitor, rel), rv.BackupEntryValues(
		datetime.now().isoformat(), event, None if source is None else os.path.join(monitor, source))) for rel, event, source in rows]
	TSVZ.appendLinesTabularFile(path, lines, header=['path'] + rv.BACKUP_ENTRY_VALUES_HEADER, createIfNotExist=True,
		verifyHeader=True, strict=False, teeLogger=rv.tl, verbose=False)
	return path


def write_committed_version(job: JobPaths, version: int, tree: dict,
		timestamp: str = '2021-01-01_00-00-00_-0800', current: bool = True, rows=None, monitor: str = None) -> str:
	'''
	A committed version of tree. Its change list holds the header only, or with rows the rows as write_change_list()
	writes them, under monitor (the job's monitored path by default).
	'''
	os.makedirs(job.job_vault, exist_ok=True)
	version_dir = os.path.join(job.job_vault, f'V{version}--{timestamp}')
	write_tree(version_dir, tree)
	content = content_file_path(version_dir)
	if rows is not None:
		write_change_list(content, job.monitor if monitor is None else monitor, rows)
	else:
		with open(content, 'w', encoding='utf-8') as f:
			f.write('path\tiso_time\tevent\tsource_path\n')
	if current:
		link = os.path.join(job.job_vault, 'current_version')
		if os.path.lexists(link):
			os.remove(link)
		os.symlink(os.path.basename(version_dir), link, target_is_directory=True)
	return version_dir


def write_incomplete_version(job: JobPaths, version: int, tree: dict,
		timestamp: str = '2021-01-02_00-00-00_-0800') -> str:
	os.makedirs(job.job_vault, exist_ok=True)
	version_dir = os.path.join(job.job_vault, f'V{version}--{timestamp}')
	write_tree(version_dir, tree)
	return version_dir


def write_pending(job: JobPaths, events: list) -> str:
	os.makedirs(job.job_vault, exist_ok=True)
	path = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	if os.path.exists(path):
		os.remove(path)
	rows = [[
		event.monotonic_time,
		event.is_dir,
		event.event,
		event.path,
		event.moved_from if event.moved_from is not None else '',
	] for event in events]
	TSVZ.appendLinesTabularFile(
		path, rows, header=rv.CHANGED_EVENT_HEADER,
		createIfNotExist=True, verifyHeader=True, strict=False, teeLogger=rv.tl, verbose=False,
	)
	return path


def committed_versions(job: JobPaths) -> list:
	if not os.path.isdir(job.job_vault):
		return []
	found = []
	for name in sorted(os.listdir(job.job_vault)):
		if not (name.startswith('V') and '--' in name):
			continue
		if rv.CONTENT_FILE_EXTENSION_NAME in name:
			continue
		path = os.path.join(job.job_vault, name)
		if not os.path.isdir(path):
			continue
		if os.path.isfile(content_file_path(path)):
			found.append(path)
	return found


def run_backup(job: JobPaths, entries=None, **kwargs) -> list:
	'''
	One committed backup as the backuper runs it: empty entries delta generate against the latest version.
	kwargs override do_backup's keywords, such as keep_n_versions.
	'''
	options = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	options.update(kwargs)
	_, manifest, committed = rv.do_backup(
		OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, **options,
	)
	manifest.close()
	assert committed is True
	return committed_versions(job)


def latest_version(job: JobPaths) -> 'rv.VaultEntry':
	info = rv.get_vault_info(job.job_vault)
	return info.vault_info_dict[next(reversed(info.vault_info_dict))]


def event_entry(job: JobPaths, rel: str, event: str, source_rel: str = None) -> tuple:
	'''A backup entry for rel (a folder when it ends with /) as the backuper queues it, moved from source_rel for a move.'''
	source = None if source_rel is None else os.path.join(job.monitor, source_rel)
	return os.path.join(job.monitor, rel), rv.BackupEntryValues(datetime.now().isoformat(), event, source)


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.05, message: str = 'condition not met') -> None:
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if predicate():
			return
		time.sleep(interval)
	raise AssertionError(message)


def wait_for_committed_count(job: JobPaths, count: int, timeout: float = 10.0) -> list:
	wait_until(
		lambda: len(committed_versions(job)) >= count,
		timeout=timeout,
		message=f'expected >= {count} committed versions, got {committed_versions(job)} in {job.job_vault}',
	)
	return committed_versions(job)


class FakePool:
	'''
	mergerfs pools in a fake mount table file: a fuse.mergerfs line per pool and an xfs line per branch, mount ids
	counted up from 100. read() stands in for rv.read_pool_branches. Every change rewrites the file and wakes the monitor.
	'''
	ROOT_LINE = '22 1 8:1 / / rw - ext4 /dev/sda1 rw\n'

	def __init__(self, tmp_path, monkeypatch, monitor):
		self.tmp_path = str(tmp_path)
		self.monkeypatch = monkeypatch
		self.monitor = monitor
		self.mountinfo_path = os.path.join(self.tmp_path, 'fake_mountinfo')
		self.next_id = 100
		# (real mount point, line), in kernel order
		self.lines = []
		# real mount point of a pool -> its branch list as mergerfs gives it
		self.pools = {}
		self.unreadable_pools = {}
		self.failing = {}
		self.reads = 0
		self.write()

	def write(self):
		with open(self.mountinfo_path, 'w', encoding='utf-8') as f:
			f.write(self.ROOT_LINE + ''.join(line for _, line in self.lines))
		self.monitor.wake()

	def named(self, branch:str) -> str:
		'''A bare name is a folder in tmp_path/disks.'''
		return os.path.join(self.tmp_path, 'disks', branch) if '/' not in branch else branch

	def branch_path(self, branch:str) -> str:
		return os.path.realpath(self.named(branch))

	def line(self, mount_point:str, fstype:str, source:str) -> tuple:
		mount_id = self.next_id
		self.next_id += 1
		return mount_point, f'{mount_id} 22 0:{mount_id} / {mount_point} rw - {fstype} {source} rw\n'

	def add(self, mount_point:str, branches:list) -> list:
		'''A pool at mount_point over branches (paths, or bare names made in tmp_path/disks); the branches' real paths.'''
		os.makedirs(mount_point, exist_ok=True)
		pool = os.path.realpath(mount_point)
		listed = [self.named(b) for b in branches]
		for branch in listed:
			os.makedirs(branch, exist_ok=True)
		real = [os.path.realpath(b) for b in listed]
		self.pools[pool] = listed
		self.lines.append(self.line(pool, 'fuse.mergerfs', 'pool'))
		self.lines.extend(self.line(b, 'xfs', '/dev/fake') for b in real)
		self.write()
		return real

	def drop(self, branch:str):
		'''The branch's line goes; its folder stays, as a disk's mount point does.'''
		real = self.branch_path(branch)
		self.lines = [(point, line) for point, line in self.lines if point != real]
		self.write()

	def mount(self, branch:str):
		'''The branch is mounted again, with a new mount id.'''
		self.lines.append(self.line(self.branch_path(branch), 'xfs', '/dev/fake'))
		self.write()

	def fail_statvfs(self, branch:str, err:int = errno.EIO):
		if not self.failing:
			real_statvfs = os.statvfs

			def statvfs(path):
				code = self.failing.get(os.path.realpath(os.fspath(path)))
				if code is not None:
					raise OSError(code, os.strerror(code))
				return real_statvfs(path)
			self.monkeypatch.setattr(os, 'statvfs', statvfs)
		self.failing[self.branch_path(branch)] = err
		self.write()

	def unreadable(self, mount_point:str, err:int = errno.ENOTSUP):
		self.unreadable_pools[os.path.realpath(mount_point)] = err
		self.write()

	def read(self, mount_point:str) -> list:
		self.reads += 1
		pool = os.path.realpath(mount_point)
		err = self.unreadable_pools.get(pool, None if pool in self.pools else errno.ENODATA)
		if err is not None:
			raise OSError(err, os.strerror(err))
		return list(self.pools[pool])


def reverberator_script() -> str:
	return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverberator.py'))
