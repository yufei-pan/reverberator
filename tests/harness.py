import errno
import os
import subprocess
import threading
import time
from collections import namedtuple, OrderedDict
from datetime import datetime

import TSVZ
import reverberator as rv
from tests.vault_oracle import VERSION_LIST, landing, read_view, version_number

JobPaths = namedtuple('JobPaths', ['root', 'monitor', 'vault', 'job_name', 'job_vault', 'rule_path'])


def create_job(root: str, job_name: str = 'job') -> JobPaths:
	monitor = os.path.join(root, 'monitor')
	vault = os.path.join(root, 'vault')
	os.makedirs(monitor, exist_ok=True)
	os.makedirs(vault, exist_ok=True)
	return JobPaths(root, monitor, vault, job_name, os.path.join(vault, job_name), os.path.join(root, 'rule.tsv'))


def fstab_escape(mount_point: str) -> str:
	'''A mount point as fstab (and mountinfo) write it: backslash, space, tab and newline octal-escaped.'''
	return ''.join({'\\': '\\134', ' ': '\\040', '\t': '\\011', '\n': '\\012'}.get(c, c) for c in mount_point)


def write_fstab(*mount_points: str) -> str:
	'''Write rv.FSTAB_PATH naming mount_points, one line each; the path.'''
	with open(rv.FSTAB_PATH, 'w', encoding='utf-8') as f:
		f.write(''.join(f'/dev/fake{i} {fstab_escape(mount_point)} xfs defaults 0 0\n' for i, mount_point in enumerate(mount_points)))
	return rv.FSTAB_PATH


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


def probe_link(folder: str, length: int):
	'''The lstat of a symlink of length bytes of text made in folder and removed again, or None where the filesystem refuses a text so long.'''
	path = os.path.join(folder, f'.link-probe-{os.getpid()}-{threading.get_ident()}')
	try:
		os.symlink('a' * length, path)
	except OSError as e:
		if e.errno == errno.ENAMETOOLONG:
			return None
		raise
	try:
		return os.lstat(path)
	finally:
		os.unlink(path)


def link_text_limit(*folders: str) -> int:
	'''
	The longest symlink text, in bytes, that each of folders takes, as its filesystem answers: the kernel's 4095 on ext4 and f2fs, 1023 on XFS.
	A test of a long link builds its link at the size this gives, not at a size one filesystem happens to take.
	'''
	limits = []
	for folder in folders:
		low, high = 1, 4095
		while low < high:
			middle = (low + high + 1) // 2
			if probe_link(folder, middle) is None:
				high = middle - 1
			else:
				low = middle
		limits.append(low)
	return min(limits)


def link_text_taking_a_block(folder: str):
	'''
	The shortest symlink text, in bytes, whose link takes a block of folder's filesystem (st_blocks above 0), or None where even the longest text the
	filesystem takes sits in the inode. A short text sits in the inode: 59 bytes or fewer on ext4, 336 on XFS with 512-byte inodes, about 3.4 KB on f2fs
	with inline_data. A test that needs a link which takes space builds one at least this long.
	'''
	low, high = 1, link_text_limit(folder)
	if not probe_link(folder, high).st_blocks:
		return None
	while low < high:
		middle = (low + high) // 2
		if probe_link(folder, middle).st_blocks:
			high = middle
		else:
			low = middle + 1
	return low


def copy_now(writer, source: str, rel: str):
	"""A copy of source to rel of the writer's tree, made and put in place now, as the replay queues and ends it: cp's exit code, or False when nothing is copied."""
	writer.record(rel, True)
	writer.flush_if_needed()
	writer._folders_for_copy(source, rel)
	return rv.cp_af_copy_path(source_path=source, dest_path=writer.path(rel))


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


def get_path_size(*paths: str) -> int:
	'''The bytes du gives paths, each inode counted once, as the vault's size records measure it.'''
	out = subprocess.run(['du', '--block-size=1', '-csP', *paths], capture_output=True, text=True).stdout
	last = out.rstrip('\n').rpartition('\n')[2].partition('\t')[0]
	return int(last) if last.isdigit() else 0


def charge(path: str, vault: str) -> int:
	'''
	What the size estimate charges for the entry at path, copied into vault: a regular file the smaller of its blocks and
	its size rounded up to the vault filesystem's block, anything else its blocks.
	'''
	st = os.lstat(path)
	if not os.path.isfile(path) or os.path.islink(path):
		return st.st_blocks * 512
	block = os.statvfs(vault).f_frsize
	return min(st.st_blocks * 512, (st.st_size + block - 1) // block * block)


def content_file_path(version_dir: str) -> str:
	size_s = rv.format_bytes(get_path_size(version_dir), use_1024_bytes=True, to_str=True).replace(' ', '_')
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


def write_scan_leftover(job: JobPaths) -> str:
	'''What only a scan of a design R vault takes away, a file left in its staging folder: its path, gone once the job's scan ran.'''
	path = os.path.join(job.job_vault, rv.STAGING_NAME, 'leftover')
	os.makedirs(os.path.dirname(path), exist_ok=True)
	open(path, 'w').close()
	return path


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
	'''The committed versions' folders, the oldest first: those with a change list, whatever its name counts, as a list on design R names no du of its folder.'''
	if not os.path.isdir(job.job_vault):
		return []
	names = os.listdir(job.job_vault)
	listed = {match[1] for match in map(VERSION_LIST.fullmatch, names) if match is not None}
	# by version number, as V10 sorts before V9 as text
	return [os.path.join(job.job_vault, name) for name in sorted(listed & set(names), key=lambda name: (rv.vault_version_number(name) or 0, name))
		if os.path.isdir(os.path.join(job.job_vault, name))]


def change_list_of(version_dir: str) -> str:
	'''The path of the change list of the version in version_dir, whatever its name counts.'''
	job_vault, name = os.path.split(version_dir)
	lists = [other for other in os.listdir(job_vault) if (match := VERSION_LIST.fullmatch(other)) is not None and match[1] == name]
	assert len(lists) == 1, lists
	return os.path.join(job_vault, lists[0])


def file_read_at(job_vault: str, folder_name: str, rel: str):
	'''(device, inode) of what the version in folder_name reads at rel, by the oracle's own walk; None when it reads nothing there.'''
	place = landing(job_vault, folder_name, rel)
	if place is None:
		return None
	st = os.lstat(os.path.join(job_vault, *place))
	return st.st_dev, st.st_ino


def folder_before(version: str) -> str:
	'''The name of the folder of the version before version.'''
	job_vault, name = os.path.split(version)
	return max((other for other in os.listdir(job_vault) if version_number(other) is not None and version_number(other) < version_number(name)), key=version_number)


def reads_the_file_before(version: str, rel: str, was: str = None) -> bool:
	'''
	Whether rel of version is the very file the version before it reads at was (rel by default), as a file a batch moved or left
	alone is: no copy of it was made. What 0.54 showed by a chain link, design R shows by the inode a forward or a hard link reaches.
	'''
	job_vault, name = os.path.split(version)
	held = file_read_at(job_vault, name, rel)
	return held is not None and held == file_read_at(job_vault, folder_before(version), rel if was is None else was)


def carried_from_before(version: str, rel: str) -> bool:
	'''Whether rel of version is a file the version before it reads anywhere: reads_the_file_before() with no path to name.'''
	job_vault, name = os.path.split(version)
	inodes = {}
	read_view(job_vault, folder_before(version), inodes)
	return file_read_at(job_vault, name, rel) in inodes.values()


# the 0.54 daemon of the running test when it is one on 0.54 (conftest.py): tests/legacy054.py's Legacy054
LEGACY = None


def daemon():
	'''The module that writes the vaults of the running test: the 0.54 one for a test on 0.54, or a patch of rv never reaches its batches.'''
	return rv if LEGACY is None else LEGACY.module


def prune_before_a_batch(job: JobPaths, keep: int) -> None:
	'''The product's prune of a 0.54 vault down to keep versions less one, as a batch runs it before its version: what the tests of that prune build on.'''
	versions = rv.get_vault_info(job.job_vault).vault_info_dict
	if not keep or len(versions) < keep:
		return
	# read without opening the manifest: opening a 0.54 manifest would upgrade it
	monitor_paths = rv.recorded_monitor_paths(job.job_vault)
	postponed, salt = [], rv.vault_prune_salt(job.job_vault, job.job_name)
	while len(versions) >= keep:
		oldest = next(iter(versions))
		rv.prune_oldest(versions, job.job_name, job.monitor, postponed, monitor_paths=monitor_paths, prune_salt=salt)
		if next(iter(versions), None) == oldest:
			break


def run_backup(job: JobPaths, entries=None, **kwargs) -> list:
	'''
	One committed backup as the backuper runs it: empty entries delta generate against the latest version.
	kwargs override do_backup's keywords, such as keep_n_versions. A test on 0.54 gets it from the 0.54 daemon.
	'''
	if LEGACY is not None:
		prune_before_a_batch(job, kwargs.pop('keep_n_versions', 0))
		LEGACY.backup(job, entries, **kwargs)
		return committed_versions(job)
	options = dict(only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
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
	mergerfs pools in a fake mount table file: a fuse.mergerfs line per pool and an xfs or f2fs line per branch, mount
	ids counted up from 100. read() stands in for rv.read_pool_branches and statx_mount() for rv.statx_mount, whose
	unique mount ids count up from 1000 on every mount. An f2fs branch's source is a /dev/mapper-like link to a dm-<n>
	device in tmp_path/dev, with its cp_status in f2fs_sysfs, found by its major:minor in sys_dev_block. Every change rewrites the file and wakes the monitor.
	'''
	ROOT_LINE = '22 1 8:1 / / rw - ext4 /dev/sda1 rw\n'
	# ckpt_flags as the live f2fs disks show them: CP_CRC_RECOVERY_FLAG (0x40) | CP_COMPACT_SUM_FLAG (0x4)
	F2FS_WHOLE = 0x44

	def __init__(self, tmp_path, monkeypatch, monitor):
		self.tmp_path = str(tmp_path)
		self.monkeypatch = monkeypatch
		self.monitor = monitor
		self.mountinfo_path = os.path.join(self.tmp_path, 'fake_mountinfo')
		self.f2fs_sysfs = os.path.join(self.tmp_path, 'sys_fs_f2fs')
		self.sys_dev_block = os.path.join(self.tmp_path, 'sys_dev_block')
		self.next_id = 100
		self.next_unique_id = 1000
		# (real mount point, line, mountinfo id, unique id), in kernel order
		self.lines = []
		# real mount point -> (fstype, source, mountinfo id) of its last mount
		self.mounted_as = {}
		# real mount point of a pool -> its branch list as mergerfs gives it
		self.pools = {}
		self.unreadable_pools = {}
		# real path -> errno its statx raises (fail_disk())
		self.failing = {}
		self.reads = 0
		self.write()

	def write(self):
		# whole or not at all, as the kernel's table reads: a job reading it half written would see the monitored filesystem change
		with open(self.mountinfo_path + '.new', 'w', encoding='utf-8') as f:
			f.write(self.ROOT_LINE + ''.join(line for _, line, _, _ in self.lines))
		os.replace(self.mountinfo_path + '.new', self.mountinfo_path)
		self.monitor.wake()

	def named(self, branch:str) -> str:
		'''A bare name is a folder in tmp_path/disks.'''
		return os.path.join(self.tmp_path, 'disks', branch) if '/' not in branch else branch

	def branch_path(self, branch:str) -> str:
		return os.path.realpath(self.named(branch))

	def line(self, mount_point:str, fstype:str, source:str, mount_id:int = None) -> tuple:
		if mount_id is None:
			mount_id = self.next_id
			self.next_id += 1
		self.next_unique_id += 1
		self.mounted_as[mount_point] = (fstype, source, mount_id)
		return mount_point, f'{mount_id} 22 0:{mount_id} / {fstab_escape(mount_point)} rw - {fstype} {source} rw\n', mount_id, self.next_unique_id

	def f2fs_source(self, branch:str) -> str:
		'''A /dev/mapper-like link to a dm-<n> device for a new f2fs branch, whose cp_status says it is whole.'''
		device = f'dm-{self.next_id}'
		os.makedirs(os.path.join(self.tmp_path, 'dev', 'mapper'), exist_ok=True)
		source = os.path.join(self.tmp_path, 'dev', 'mapper', os.path.basename(branch))
		os.symlink(os.path.join('..', device), source)
		os.makedirs(os.path.join(self.f2fs_sysfs, device, 'stat'))
		self.set_f2fs_flags(source, self.F2FS_WHOLE)
		self.add_block_device(f'0:{self.next_id}', device)
		return source

	def add_block_device(self, major_minor:str, device:str):
		'''/sys/dev/block/<major:minor> leading to a device folder named device, as sysfs has it.'''
		os.makedirs(self.sys_dev_block, exist_ok=True)
		os.makedirs(os.path.join(self.tmp_path, 'sys_devices', device), exist_ok=True)
		os.symlink(os.path.join('..', 'sys_devices', device), os.path.join(self.sys_dev_block, major_minor))

	def f2fs_status(self, branch:str) -> str:
		'''The cp_status file of an f2fs branch.'''
		source = self.mounted_as[self.branch_path(branch)][1]
		return os.path.join(self.f2fs_sysfs, os.path.basename(os.path.realpath(source)), 'stat', 'cp_status')

	def set_f2fs_flags(self, source:str, flags:int):
		with open(os.path.join(self.f2fs_sysfs, os.path.basename(os.path.realpath(source)), 'stat', 'cp_status'), 'w') as f:
			f.write(f'{flags:x}\n')

	def add(self, mount_point:str, branches:list, fstype:str = 'xfs') -> list:
		'''
		A pool at mount_point over branches (paths, or bare names made in tmp_path/disks) of fstype xfs or f2fs; the
		branches' real paths.
		'''
		os.makedirs(mount_point, exist_ok=True)
		pool = os.path.realpath(mount_point)
		listed = [self.named(b) for b in branches]
		for branch in listed:
			os.makedirs(branch, exist_ok=True)
		real = [os.path.realpath(b) for b in listed]
		self.pools[pool] = listed
		self.lines.append(self.line(pool, 'fuse.mergerfs', 'pool'))
		self.lines.extend(self.line(b, fstype, self.f2fs_source(b) if fstype == 'f2fs' else '/dev/fake') for b in real)
		self.write()
		return real

	def add_mount(self, mount_point:str, fstype:str = 'xfs') -> str:
		'''A plain mount (source /dev/fake, or an f2fs one's as add() makes it) at mount_point, made when missing; its real path.'''
		os.makedirs(mount_point, exist_ok=True)
		real = os.path.realpath(mount_point)
		self.lines.append(self.line(real, fstype, self.f2fs_source(real) if fstype == 'f2fs' else '/dev/fake'))
		self.write()
		return real

	def join(self, pool_mount:str, mount_point:str, name:str) -> str:
		'''A new disk mounted at mount_point joins the pool at pool_mount as a branch, its folder name; the branch's real path.'''
		branch = os.path.join(self.add_mount(mount_point), name)
		os.makedirs(branch, exist_ok=True)
		self.pools[os.path.realpath(pool_mount)].append(branch)
		self.write()
		return branch

	def drop(self, branch:str):
		'''The branch's (or a pool's) line goes; its folder stays, as a disk's mount point does.'''
		real = self.branch_path(branch)
		self.lines = [line for line in self.lines if line[0] != real]
		self.write()

	def mount(self, branch:str, same_id:bool = False):
		'''
		The branch (or a pool) is mounted again: a new unique mount id, and a new mountinfo id unless same_id, as the
		kernel reuses them.
		'''
		real = self.branch_path(branch)
		fstype, source, mount_id = self.mounted_as[real]
		self.lines.append(self.line(real, fstype, source, mount_id if same_id else None))
		self.write()

	def fail_disk(self, branch:str, err:int = errno.EIO):
		'''
		The branch's filesystem shuts down and stays mounted, as a dying disk's does: an f2fs one sets CP_ERROR_FLAG
		in its checkpoint and still answers statx, any other one (or a pool) fails statx with err, as XFS does.
		'''
		real = self.branch_path(branch)
		fstype, source, _ = self.mounted_as[real]
		if fstype == 'f2fs':
			self.set_f2fs_flags(source, self.F2FS_WHOLE | 0x8)
		else:
			self.failing[real] = err
		self.write()

	def recover(self, branch:str):
		'''The failure fail_disk() gave the branch ends.'''
		real = self.branch_path(branch)
		fstype, source, _ = self.mounted_as[real]
		if fstype == 'f2fs':
			self.set_f2fs_flags(source, self.F2FS_WHOLE)
		self.failing.pop(real, None)
		self.write()

	def unreadable(self, mount_point:str, err:int = errno.ENOTSUP):
		self.unreadable_pools[os.path.realpath(mount_point)] = err
		self.write()

	def statx_mount(self, path:str) -> tuple:
		'''(unique mount id, whether path is a mount root) as rv.statx_mount gives them, and its errors.'''
		real = os.path.realpath(path)
		code = self.failing.get(real)
		if code is None and not os.path.lexists(real):
			code = errno.ENOENT
		if code is not None:
			raise OSError(code, os.strerror(code), path)
		on_top = [unique_id for point, _, _, unique_id in self.lines if point == real]
		# a path that is no mount root is on the root filesystem
		return (on_top[-1], True) if on_top else (1, False)

	def read(self, mount_point:str) -> list:
		self.reads += 1
		pool = os.path.realpath(mount_point)
		err = self.unreadable_pools.get(pool, None if pool in self.pools else errno.ENODATA)
		if err is not None:
			raise OSError(err, os.strerror(err), os.path.join(mount_point, '.mergerfs'))
		return list(self.pools[pool])


def scripted_watch(monkeypatch, monitor:str, reads:list, flag=None, queue=None, watches:dict = None, irm=None, **watch_kwargs) -> tuple:
	'''
	Run rv.watchFolder on monitor, in this thread, with an inotify that returns each item of reads in turn and then stops.
	An item is a list of (mask, name, cookie) on the root watch (wd 1), or of (mask, name, cookie, wd) on another folder's
	watch (each folder the watcher adds gets the next wd from 2), or a callable taking the queue and returning such a
	list. After the last item the fake clears rv.GREEN_LIGHT (conftest sets it again) and returns [].
	With watches (a dict), the watcher's own walk runs on the folders on disk, and the fake hands out watches as the kernel
	does, one per folder, kept in watches as (st_dev, st_ino) -> wd from 1 (the root): watching a folder that is gone
	raises ENOENT, and a folder watched again, at any name, gets its watch back.
	Returns (queue, flag, returned): returned holds the wall clock ns at which each read returned.
	'''
	queue = rv.ChangeEventQueue(monitor) if queue is None else queue
	flag = threading.Event() if flag is None else flag
	returned = []
	Event = namedtuple('Event', ['wd', 'mask', 'cookie', 'name'])
	pending = list(reads)
	class FakeINotify:
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def read(self, timeout=None):
			if not pending:
				rv.GREEN_LIGHT.clear()
				returned.append(time.time_ns())
				return []
			item = pending.pop(0)
			item = item(queue) if callable(item) else item
			returned.append(time.time_ns())
			return [Event(event[3] if len(event) > 3 else 1, event[0], event[2], event[1]) for event in item]
		def add_watch(self, path, mask):
			if watches is None:
				return 1
			st = os.stat(path)
			key = (st.st_dev, st.st_ino)
			if key not in watches:
				watches[key] = next_kernel_wd[0]
				next_kernel_wd[0] += 1
			return watches[key]
		def rm_watch(self, wd):
			if watches is not None:
				for key in [key for key, held in watches.items() if held == wd]:
					del watches[key]
	next_wd = [2]
	next_kernel_wd = [1]
	def initialize(inotify_obj, monitor_path, wdDic, irm, watch_flags, newDirWds=None, **kwargs):
		# wd 1 is the root only: any other folder gets a watch of its own, which a scripted event names in its 4th field
		wd = 1 if monitor_path == monitor else next_wd[0]
		if wd != 1:
			next_wd[0] += 1
			if newDirWds is not None:
				newDirWds.add(wd)
		wdDic[wd] = monitor_path
		return wd
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	if watches is None:
		monkeypatch.setattr(rv, 'initializeFolderWatchers', initialize)
	rv.watchFolder(monitor, queue, threading.Lock(), flag, rv.inotify_resource_manager() if irm is None else irm, **watch_kwargs)
	return queue, flag, returned


def reverberator_script() -> str:
	'''What a test runs as reverberator.py in a process of its own: its entry point, never syncing the filesystem under the basetemp (daemon_without_syncfs.py).'''
	return os.path.abspath(os.path.join(os.path.dirname(__file__), 'daemon_without_syncfs.py'))
