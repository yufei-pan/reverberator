import os
import shutil
from collections import deque
from collections import OrderedDict
import threading

import reverberator as rv
import pytest
from tests.harness import committed_versions, create_job, get_path_size, path_inodes, run_backup, seed_monitor, tracked_manifest

pytestmark = pytest.mark.unit


# --- get_vault_info() removes incomplete versions ---

def test_deletes_vdir_without_content_file_keeps_committed(tmp_path):
	job_vault = str(tmp_path)
	committed = os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800')
	orphan = os.path.join(job_vault, 'V2--2021-01-02_00-00-00_-0800')
	os.makedirs(committed)
	os.makedirs(orphan)
	with open(os.path.join(committed, 'f.txt'), 'w') as f:
		f.write('x')
	content = (
		f'{committed}--1_B-1_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
	)
	with open(content, 'w') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	# the commit's current_version: what says V2 is the attempt after the latest commit (Task 2b)
	os.symlink(os.path.basename(committed), os.path.join(job_vault, 'current_version'))
	info = rv.get_vault_info(job_vault)
	assert os.path.isdir(committed)
	assert os.path.isfile(content)
	assert not os.path.isdir(orphan)
	assert list(info.vault_info_dict) == [1]


# --- get_vault_info() and orphan versions ---

def test_orphan_dir_is_removed_not_indexed(tmp_path):
	# a first backup that did not commit: a V0 alone, with no record and no change list (Task 2b fix round 2)
	job_vault = str(tmp_path)
	# the manifest the backup opened before making V0, recording no version
	rv.VaultManifest(job_vault).close()
	orphan = os.path.join(job_vault, 'V0--2021-01-03_00-00-00_-0800')
	os.makedirs(orphan)
	with open(os.path.join(orphan, 'x'), 'w') as f:
		f.write('y')
	info = rv.get_vault_info(job_vault)
	assert not os.path.isdir(orphan)
	assert 0 not in info.vault_info_dict


def test_a_lone_orphan_that_is_no_v0_is_kept(tmp_path):
	# no first backup leaves a V3: its list, current_version and manifest may all be out of the listing
	job_vault = str(tmp_path)
	orphan = os.path.join(job_vault, 'V3--2021-01-03_00-00-00_-0800')
	os.makedirs(orphan)
	with pytest.raises(rv.VaultScanError):
		rv.get_vault_info(job_vault)
	assert os.path.isdir(orphan)


# --- the watcher when its watch cannot start ---

def test_watcher_clears_green_light_when_watchfolder_fails(tmp_path, monkeypatch):
	rv.GREEN_LIGHT.set()
	monitor_fs_flag = threading.Event()
	monitor_fs_flag.set()
	monkeypatch.setattr(rv, 'watchFolder', lambda *a, **k: 'init_failed')
	rv.watcher(
		monitor_fs_flag,
		str(tmp_path),
		deque(),
		threading.Lock(),
		threading.Event(),
		rv.inotify_resource_manager(),
	)
	assert not rv.GREEN_LIGHT.is_set()


def test_watchfolder_reports_self_destruct_without_clearing_green_light(monkeypatch):
	rv.GREEN_LIGHT.set()

	class FakeEvent:
		def __init__(self, wd, mask):
			self.wd = wd
			self.mask = mask
			self.cookie = 0
			self.name = ''

	class FakeINotify:
		def __enter__(self):
			return self

		def __exit__(self, *args):
			return False

		def read(self, timeout=None):
			return [FakeEvent(42, rv.inotify_simple.flags.UNMOUNT)]

	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', lambda *a, **k: 42)
	result = rv.watchFolder(
		'/monitor',
		rv.ChangeEventQueue('/monitor'),
		threading.Lock(),
		threading.Event(),
		rv.inotify_resource_manager(),
	)
	assert result == 'self_destruct'
	assert rv.GREEN_LIGHT.is_set()


# --- the backuper when a batch does not commit ---

def test_uncommitted_backup_while_green_light_set_clears_green_light_and_requeues_nothing(tmp_path, monkeypatch):
	tmp = str(tmp_path)
	rv.GREEN_LIGHT.set()
	os.makedirs(os.path.join(tmp, 'monitor'))
	calls = []
	def uncommitted(*args, **kwargs):
		calls.append(args)
		return None, None, False
	monkeypatch.setattr(rv, 'do_backup', uncommitted)
	to_process = rv.ChangeEventQueue(os.path.join(tmp, 'monitor'))
	to_process.append(rv.ChangeEvent(1, False, 'modify', os.path.join(tmp, 'monitor', 'f.txt'), None))
	monitor_fs_flag = threading.Event()
	monitor_fs_flag.set()
	rv.backuper(
		'job',
		to_process,
		threading.Lock(),
		os.path.join(tmp, 'monitor'),
		os.path.join(tmp, 'vault'),
		'N/A',
		threading.Event(),
		monitor_fs_flag,
	)
	# the backuper took the batch and ran it: an error before do_backup() would leave the same three states
	assert len(calls) == 1
	# the batch is not handed back: the next start compares the whole tree
	assert len(to_process) == 0
	assert not os.path.lexists(os.path.join(tmp, 'vault', 'job', rv.PENDING_TRANSACTIONS_FILE_NAME))
	assert not rv.GREEN_LIGHT.is_set()


# --- do_backup() commits nothing once the green light is cleared ---

def test_cleared_green_light_skips_content_file_and_current_version(tmp_path, monkeypatch):
	# with no committed version behind it, do_backup() returns at its lock take, before any copy and before the commit gate: so V0 is
	# committed first, a change is backed up as V1, and the stop comes after the copies, as a stop signal does mid-batch
	paths = create_job(str(tmp_path))
	seed_monitor(paths, {'f.txt': 'x'})
	v0 = run_backup(paths)[0]
	seed_monitor(paths, {'g.txt': 'y'})
	current = os.path.join(paths.job_vault, 'current_version')
	assert os.readlink(current) == os.path.basename(v0)
	copied = []
	real_copy = rv.do_reverb_backup
	def copy_then_stop(*args, **kwargs):
		real_copy(*args, **kwargs)
		copied.append(rv.GREEN_LIGHT.is_set())
		rv.GREEN_LIGHT.clear()
	monkeypatch.setattr(rv, 'do_reverb_backup', copy_then_stop)
	try:
		_, manifest, committed = rv.do_backup(
			{},
			job_name=paths.job_name,
			monitor_path=paths.monitor,
			vault_path=paths.vault,
			only_sync_attributes=True,
			keep_n_versions=0,
			backup_size_limit='0',
		)
	finally:
		rv.GREEN_LIGHT.set()
	manifest.close()
	# the batch's copies ran with the light on, and it was off at the gate: the stop is the gate's
	assert copied == [True]
	assert not committed
	assert committed_versions(paths) == [v0]
	assert os.readlink(current) == os.path.basename(v0)


# --- an empty batch makes no version ---

def test_no_new_version_when_delta_empty(tmp_path, monkeypatch):
	paths = create_job(str(tmp_path))
	monitor, vault, job, job_vault = paths.monitor, paths.vault, paths.job_name, paths.job_vault
	seed_monitor(paths, {'a.txt': 'hi'})
	v0 = run_backup(paths)[0]
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', lambda backupEntries, latest_version_info, monitor_path, **_: None)
	vault_info = rv.get_vault_info(job_vault)
	rv.GREEN_LIGHT.set()
	info, tracking, committed = rv.do_backup(
		{},
		job_name=job,
		monitor_path=monitor,
		vault_path=vault,
		only_sync_attributes=True,
		keep_n_versions=0,
		backup_size_limit='0',
		log_journal=False,
		vaultInfo=vault_info,
	)
	assert committed
	versions = [p for p in os.listdir(job_vault) if p.startswith('V') and os.path.isdir(os.path.join(job_vault, p))]
	assert versions == [os.path.basename(v0)]
	tracking.close()


# --- cp_af_copy_path() onto a symlink that resolves like its source ---

def test_symlink_dest_resolving_like_source_is_replaced(tmp_path):
	'''Dest symlink that realpaths to the same target as source must not trip is_subpath.'''
	root = str(tmp_path)
	src_dir = os.path.join(root, 'src')
	dst_dir = os.path.join(root, 'dst')
	os.makedirs(src_dir)
	os.makedirs(dst_dir)
	real_target = os.path.join(root, 'real_python')
	with open(real_target, 'w') as f:
		f.write('bin')
	# Source chain: python3.13 -> python3 -> real_target (like a venv)
	os.symlink(real_target, os.path.join(src_dir, 'python3'))
	src = os.path.join(src_dir, 'python3.13')
	os.symlink('python3', src)
	# Prior vault entry left the same relative symlink chain
	os.symlink(real_target, os.path.join(dst_dir, 'python3'))
	dst = os.path.join(dst_dir, 'python3.13')
	os.symlink('python3', dst)
	assert os.path.realpath(src) == os.path.realpath(dst)
	assert rv.is_subpath(dst, src)  # documents the false-positive
	old = os.stat(dst, follow_symlinks=False).st_ino
	ok = rv.cp_af_copy_path(src, dst)
	# return_code_only: 0 means success, and a refusal returns False, which equals 0
	assert ok is not False and ok == 0
	assert os.path.islink(dst)
	assert os.readlink(dst) == 'python3'
	# replaced, not left as it was: the copy was made beside it, so the old link's inode was still taken while the new one's was made
	assert os.stat(dst, follow_symlinks=False).st_ino != old


# --- a folder's delete updates the tracking sets ---

def test_dir_delete_updates_tracking_sets_without_runtime_error(tmp_path):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'sub/a.txt': 'a', 'keep.txt': 'k'})
	run_backup(job)
	shutil.rmtree(os.path.join(job.monitor, 'sub'))
	entries = OrderedDict([
		(os.path.join(job.monitor, 'sub') + '/', rv.BackupEntryValues('t', 'delete', None)),
	])
	rv.GREEN_LIGHT.set()
	run_backup(job, entries)
	result = rv.VaultManifest(job.job_vault)
	assert 'sub/a.txt' not in result.files
	assert 'sub/' not in result.folders
	assert 'keep.txt' in result.files
	result.close()


# --- decrement_stepper(): a step that succeeds, and one that aborts ---

def make_pair(root):
	# V0 real file, V1 symlink to V0 file
	v0 = os.path.join(root, 'V0--2021-01-01_00-00-00_-0800')
	v1 = os.path.join(root, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v0)
	os.makedirs(v1)
	with open(os.path.join(v0, 'a.txt'), 'w') as f:
		f.write('data')
	# relative, as the daemon links: an absolute link is a user's symlink since 0.44
	os.symlink(os.path.join('..', os.path.basename(v0), 'a.txt'), os.path.join(v1, 'a.txt'))
	# content files with parseable names (use get_path_size after)
	for path, ver in ((v0, 0), (v1, 1)):
		sz = get_path_size(path)
		ino = path_inodes(path)
		sz_s = rv.format_bytes(sz, use_1024_bytes=True, to_str=True).replace(' ', '_')
		ino_s = rv.format_bytes(ino, use_1024_bytes=False, to_str=True).replace(' ', '')
		with open(f'{path}--{sz_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}', 'w') as f:
			f.write('path\tiso_time\tevent\tsource_path\n')
	d = OrderedDict([
		(0, rv.VaultEntry(0, v0, 0, get_path_size(v0), path_inodes(v0))),
		(1, rv.VaultEntry(1, v1, 1, get_path_size(v1), path_inodes(v1))),
	])
	return d, v0, v1


def test_successful_step_removes_oldest(tmp_path):
	root = str(tmp_path)
	d, v0, v1 = make_pair(root)
	removed_size, removed_inodes = rv.decrement_stepper(d, 'job', os.path.join(root, 'monitor'))
	assert not os.path.isdir(v0)
	assert os.path.isfile(os.path.join(v1, 'a.txt'))
	assert not os.path.islink(os.path.join(v1, 'a.txt'))
	assert 0 not in d
	assert removed_size + removed_inodes > 0


def test_materialize_failure_keeps_oldest_and_restores_dict(tmp_path):
	root = str(tmp_path)
	d, v0, v1 = make_pair(root)
	real_rename = os.rename

	def boom(src, dst):
		if os.path.basename(src) == 'a.txt' or os.path.basename(dst) == 'a.txt':
			raise OSError('simulated')
		return real_rename(src, dst)

	os.rename = boom
	try:
		removed_size, removed_inodes = rv.decrement_stepper(d, 'job', os.path.join(root, 'monitor'))
	finally:
		os.rename = real_rename
	assert (removed_size, removed_inodes) == (0, 0)
	assert os.path.isdir(v0)
	assert 0 in d
	assert os.path.islink(os.path.join(v1, 'a.txt'))


def test_dangling_link_into_reference_does_not_block_removal(tmp_path):
	root = str(tmp_path)
	d, v0, v1 = make_pair(root)
	# the real file vanished from the oldest version, so V1's link is
	# already dangling before the stepper ever touches it
	os.remove(os.path.join(v0, 'a.txt'))
	text = os.readlink(os.path.join(v1, 'a.txt'))

	removed_size, removed_inodes = rv.decrement_stepper(d, 'job', os.path.join(root, 'monitor'))

	assert not os.path.isdir(v0)
	assert 0 not in d
	# left as it is: it reads as missing either way, and a user's link of its form stays the user's (final fix g)
	assert os.readlink(os.path.join(v1, 'a.txt')) == text
	assert removed_size + removed_inodes > 0


def test_chained_dangling_links_drain_across_successive_steps(tmp_path):
	# mirrors the production shape: V2 -> V1 -> V0, where V0's real file is
	# already gone, so every step must keep making progress
	root = str(tmp_path)
	d, v0, v1 = make_pair(root)
	v2 = os.path.join(root, 'V2--2021-01-03_00-00-00_-0800')
	os.makedirs(v2)
	# relative, as the daemon links: an absolute link is a user's symlink since 0.44
	os.symlink(os.path.join('..', os.path.basename(v1), 'a.txt'), os.path.join(v2, 'a.txt'))
	sz = get_path_size(v2)
	ino = path_inodes(v2)
	sz_s = rv.format_bytes(sz, use_1024_bytes=True, to_str=True).replace(' ', '_')
	ino_s = rv.format_bytes(ino, use_1024_bytes=False, to_str=True).replace(' ', '')
	with open(f'{v2}--{sz_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}', 'w') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	d[2] = rv.VaultEntry(2, v2, 2, sz, ino)
	os.remove(os.path.join(v0, 'a.txt'))

	rv.decrement_stepper(d, 'job', os.path.join(root, 'monitor'))
	assert not os.path.isdir(v0)
	assert list(d) == [1, 2]

	rv.decrement_stepper(d, 'job', os.path.join(root, 'monitor'))
	assert not os.path.isdir(v1)
	assert list(d) == [2]
	# V1's dangling link, left as it was, is what V2 holds now: it names V0, which is gone
	assert os.readlink(os.path.join(v2, 'a.txt')) == os.path.join('..', os.path.basename(v0), 'a.txt')
	assert not os.path.exists(os.path.join(v2, 'a.txt'))
