'''
Round 9, Task 4: mergerfs does not implement fsyncdir, so a folder fsync through the pool reaches no disk. A vault folder
is fsynced on each branch of its pool that holds it, for the change list's placement, the pruning secret, and after
current_version moves.
'''
import errno
import os
import subprocess
import sys
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.harness import committed_versions, event_entry, seed_monitor
from tests.test_vault_scan import (cut_off_at_the_swap, keep_modified, link_number, private_folders, restart_and_scan, run_backup,
	three_versions, vault_names)

pytestmark = pytest.mark.unit


def recording_fsync(monkeypatch, failing=()):
	'''
	rv.fsync_path replaced by a recorder of (path, folder), raising EIO for the paths in failing and FileNotFoundError for
	a folder that is not there: the list.
	'''
	calls = []
	def fsync(path, folder=False):
		if not os.path.isdir(path):
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		calls.append((path, folder))
		if path in failing:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
	monkeypatch.setattr(rv, 'fsync_path', fsync)
	return calls


def pool_with_job(tmp_path, fake_pool, holding):
	'''A pool at tmp_path/pool over branches a, b and c, with job/ made on the branches in holding: the job's path, the branches.'''
	pool = str(tmp_path / 'pool')
	os.makedirs(pool)
	branches = fake_pool.add(pool, ['a', 'b', 'c'])
	for name, branch in zip('abc', branches):
		if name in holding:
			os.makedirs(os.path.join(branch, 'job'))
	os.makedirs(os.path.join(pool, 'job'), exist_ok=True)
	return os.path.join(pool, 'job'), branches


def test_a_folder_on_a_pool_is_flushed_on_each_branch_holding_it(tmp_path, fake_pool, monkeypatch):
	job_path, (a, b, c) = pool_with_job(tmp_path, fake_pool, ['a', 'c'])
	calls = recording_fsync(monkeypatch)
	rv.fsync_vault_folder(job_path)
	assert calls == [(os.path.join(a, 'job'), True), (os.path.join(c, 'job'), True)]


def test_a_folder_off_any_pool_is_flushed_itself(tmp_path, monkeypatch):
	path = str(tmp_path / 'job')
	os.makedirs(path)
	calls = recording_fsync(monkeypatch)
	rv.fsync_vault_folder(path)
	assert calls == [(path, True)]


def test_an_error_on_one_branch_still_flushes_the_others(tmp_path, fake_pool, monkeypatch):
	job_path, (a, b, c) = pool_with_job(tmp_path, fake_pool, ['a', 'c'])
	calls = recording_fsync(monkeypatch, failing=[os.path.join(a, 'job')])
	with pytest.raises(OSError) as failure:
		rv.fsync_vault_folder(job_path)
	assert failure.value.errno == errno.EIO
	assert calls == [(os.path.join(a, 'job'), True), (os.path.join(c, 'job'), True)]


def recording_syncfs(monkeypatch, failing=()):
	'''rv.syncfs_folder replaced by a recorder of paths, raising EIO for those in failing and FileNotFoundError for a folder not there.'''
	calls = []
	def syncfs(path):
		if not os.path.isdir(path):
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		calls.append(path)
		if path in failing:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	return calls


def test_the_vault_sync_on_a_pool_reaches_each_branch_holding_it(tmp_path, fake_pool, monkeypatch):
	job_path, (a, b, c) = pool_with_job(tmp_path, fake_pool, ['a', 'c'])
	calls = recording_syncfs(monkeypatch)
	results = REAL_SYNC_VAULT_FILESYSTEMS(job_path)
	assert calls == [os.path.join(a, 'job'), os.path.join(c, 'job')]
	assert results == {a: None, c: None}


def test_the_vault_sync_on_a_pool_gives_each_branch_its_result(tmp_path, fake_pool, monkeypatch):
	job_path, (a, b, c) = pool_with_job(tmp_path, fake_pool, ['a', 'c'])
	calls = recording_syncfs(monkeypatch, failing=[os.path.join(a, 'job')])
	results = REAL_SYNC_VAULT_FILESYSTEMS(job_path)
	assert calls == [os.path.join(a, 'job'), os.path.join(c, 'job')]
	assert results[c] is None and results[a].errno == errno.EIO and set(results) == {a, c}


def test_the_vault_sync_off_any_pool_reaches_the_vault_itself(tmp_path, monkeypatch):
	path = str(tmp_path / 'job')
	os.makedirs(path)
	calls = recording_syncfs(monkeypatch)
	results = REAL_SYNC_VAULT_FILESYSTEMS(path)
	assert calls == [path]
	assert results == {rv.mount_holding(rv.read_mount_table(), os.path.realpath(path))[0]: None}


def test_the_vault_sync_off_any_pool_gives_an_error_other_than_a_missing_folder_as_the_disks_result(tmp_path, monkeypatch):
	path = str(tmp_path / 'job')
	os.makedirs(path)
	recording_syncfs(monkeypatch, failing=[path])
	results = REAL_SYNC_VAULT_FILESYSTEMS(path)
	assert list(results.values())[0].errno == errno.EIO and list(results) == [rv.mount_holding(rv.read_mount_table(), os.path.realpath(path))[0]]


def test_the_vault_sync_off_any_pool_raises_for_a_vault_that_is_gone(tmp_path, monkeypatch):
	calls = recording_syncfs(monkeypatch)
	with pytest.raises(FileNotFoundError):
		REAL_SYNC_VAULT_FILESYSTEMS(str(tmp_path / 'gone'))
	assert calls == []


def test_the_vault_sync_raises_when_the_branch_list_cannot_be_read(tmp_path, fake_pool, monkeypatch):
	job_path, _ = pool_with_job(tmp_path, fake_pool, ['a', 'c'])
	def unreadable(mount_point):
		raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))
	monkeypatch.setattr(rv, 'read_pool_branches', unreadable)
	calls = recording_syncfs(monkeypatch)
	with pytest.raises(OSError):
		REAL_SYNC_VAULT_FILESYSTEMS(job_path)
	assert calls == []


def test_the_commit_flushes_the_job_vault_after_the_swap(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	steps = []
	def recording(owner, name):
		real = getattr(owner, name)
		def wrapper(*args, **kwargs):
			steps.append((name, args))
			return real(*args, **kwargs)
		monkeypatch.setattr(owner, name, wrapper)
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert committed
	seed_monitor(job, {'b.txt': 'b'})
	for name in ('prepare_change_list', 'swap_current_version', 'fsync_vault_folder', 'place_change_list'):
		recording(rv, name)
	recording(rv.VaultManifest, 'commit')
	_, manifest, committed = rv.do_backup(OrderedDict([event_entry(job, 'b.txt', 'create')]), job_name=job.job_name,
		monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert committed
	names = [name for name, _ in steps]
	start = names.index('prepare_change_list')
	assert names[start:start + 5] == ['prepare_change_list', 'commit', 'swap_current_version', 'fsync_vault_folder', 'place_change_list']
	assert steps[start + 3][1] == (job.job_vault,)


def test_the_change_list_and_the_salt_are_flushed_through_the_helper(tmp_path, monkeypatch):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	flushed = []
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushed.append)
	content = os.path.join(job_vault, 'V0--x.nsv')
	rv.place_change_list(content, rv.prepare_change_list(content, []))
	assert flushed == [job_vault]
	assert rv.vault_prune_salt(job_vault, 'job') is not None
	assert flushed == [job_vault, job_vault]


def test_a_failed_flush_after_the_swap_fails_the_attempt_and_the_next_scan_cleans_up(tmp_path, monkeypatch, capsys):
	# the list would be placed ahead of a link that is not on its disk: it stays in its private folder instead
	job = three_versions(tmp_path)
	state = []
	real_swap, real_flush = rv.swap_current_version, rv.fsync_vault_folder
	def swapping(job_vault, text):
		real_swap(job_vault, text)
		state.append(text)
	def flushing(path):
		if state:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_flush(path)
	monkeypatch.setattr(rv, 'swap_current_version', swapping)
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushing)
	with pytest.raises(rv.JobFailure, match=f'cannot sync {job.job_vault} to disk after moving current_version: .*Input/output error') as failure:
		run_backup(job, keep_modified(job, 'unflushed'))
	assert failure.value.permanent is False
	monkeypatch.undo()
	attempt = os.path.join(job.job_vault, state[0])
	assert link_number(job) == 3 and os.path.isdir(attempt) and len(private_folders(job)) == 1
	assert [kept.number for kept in rv.list_versions(job.job_vault)] == [0, 1, 2]
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []


def test_the_undo_of_a_cut_off_commit_is_flushed_before_anything_is_removed(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	attempt = cut_off_at_the_swap(job)
	events = []
	real_flush = rv.fsync_vault_folder
	def flushing(path):
		events.append(('flush', link_number(job)))
		return real_flush(path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushing)
	for name in ('remove_unfinished_change_lists', 'remove_orphan'):
		real = getattr(rv, name)
		monkeypatch.setattr(rv, name, lambda *args, _real=real, _name=name: events.append((_name,)) or _real(*args))
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2]
	assert events[0] == ('flush', 2) and events[1:] == [('remove_unfinished_change_lists',), ('remove_orphan',)]


def test_an_undo_that_cannot_be_flushed_fails_the_scan_and_removes_nothing(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	attempt = cut_off_at_the_swap(job)
	def flushing(path):
		raise OSError(errno.EIO, os.strerror(errno.EIO), path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushing)
	removed, scanned = restart_and_scan(job)
	assert removed == [] and isinstance(scanned, rv.VaultScanError) and 'cannot undo the records' in str(scanned)
	assert os.path.isdir(attempt) and len(private_folders(job)) == 1
	monkeypatch.undo()
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []


# --- the manifest's rollback journal is kept, and its first appearance flushed ---

def journal_of(job_vault):
	return os.path.join(job_vault, rv.MANIFEST_FILE_NAME + '-journal')


def test_the_manifest_has_its_journal_and_flushes_the_vault_at_every_open(tmp_path, monkeypatch):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	flushed = []
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushed.append)
	manifest = rv.VaultManifest(job_vault)
	try:
		assert manifest.conn.execute('PRAGMA journal_mode').fetchone()[0] == 'truncate'
		assert os.path.exists(journal_of(job_vault)) and flushed == [job_vault]
		manifest.begin()
		manifest.add('a.txt')
		manifest.commit(os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800'))
		assert os.path.exists(journal_of(job_vault)) and flushed == [job_vault]
	finally:
		manifest.close()
	# once per open, with the journal there
	rv.VaultManifest(job_vault).close()
	assert flushed == [job_vault, job_vault]
	# one a daemon before this left none between transactions, or a rollback took, is made again, and flushed
	os.remove(journal_of(job_vault))
	rv.VaultManifest(job_vault).close()
	assert os.path.exists(journal_of(job_vault)) and flushed == [job_vault] * 3


def test_the_journal_is_truncated_after_a_big_commit_and_stays(tmp_path):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	version = os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800')
	manifest = rv.VaultManifest(job_vault)
	try:
		assert manifest.conn.execute('PRAGMA journal_mode').fetchone()[0] == 'truncate'
		manifest.begin()
		rels = [f'd/{"a_fairly_long_file_name_" * 4}{i:05d}.txt' for i in range(20000)]
		for rel in rels:
			manifest.add(rel)
		manifest.commit(version)
		manifest.begin()
		manifest.discard_many(rels)
		manifest.commit(version)
		assert os.path.getsize(os.path.join(job_vault, rv.MANIFEST_FILE_NAME)) > 1_000_000
		assert os.path.getsize(journal_of(job_vault)) == 0
	finally:
		manifest.close()


def test_a_rollback_then_the_next_open_makes_and_flushes_the_journal_again(tmp_path, monkeypatch):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	rv.VaultManifest(job_vault).close()
	hot_kept_journal(job_vault)
	# recorded_latest_version() reads in the journal's default mode: its rollback takes the journal away
	rv.recorded_latest_version(job_vault)
	assert not os.path.exists(journal_of(job_vault))
	flushed = []
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushed.append)
	rv.VaultManifest(job_vault).close()
	assert os.path.exists(journal_of(job_vault)) and flushed == [job_vault]


def test_a_flush_that_fails_at_open_fails_it_and_the_next_open_flushes_again(tmp_path, monkeypatch):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	def failing(path):
		raise OSError(errno.EIO, os.strerror(errno.EIO), path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', failing)
	with pytest.raises(OSError):
		rv.VaultManifest(job_vault)
	flushed = []
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushed.append)
	rv.VaultManifest(job_vault).close()
	assert flushed == [job_vault]


def test_forgetting_the_recorded_version_keeps_the_journal_too(tmp_path):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.commit(os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800'))
	manifest.close()
	os.remove(journal_of(job_vault))
	rv.forget_manifest_meta(job_vault)
	assert os.path.exists(journal_of(job_vault))
	assert rv.recorded_latest_version(job_vault).recorded is None


def hot_kept_journal(job_vault):
	'''A write transaction on the manifest killed in its middle, in TRUNCATE mode, by a process of its own: a hot journal.'''
	code = ('import os, sqlite3, sys\n'
		'conn = sqlite3.connect(sys.argv[1], isolation_level=None)\n'
		'conn.execute("PRAGMA journal_mode = TRUNCATE")\n'
		'conn.execute("PRAGMA cache_size = 1")\n'
		'conn.execute("BEGIN IMMEDIATE")\n'
		'for i in range(2000):\n'
		'    conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"junk{i}", "x" * 500))\n'
		'os._exit(9)\n')
	subprocess.run([sys.executable, '-c', code, os.path.join(job_vault, rv.MANIFEST_FILE_NAME)], check=False)
	with open(journal_of(job_vault), 'rb') as f:
		assert f.read(8) != bytes(8)


def test_a_hot_kept_journal_is_rolled_back(tmp_path):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.commit(os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800'))
	manifest.close()
	hot_kept_journal(job_vault)
	assert rv.recorded_latest_version(job_vault).recorded == 'V0--2021-01-01_00-00-00_-0800'
	hot_kept_journal(job_vault)
	manifest = rv.VaultManifest(job_vault)
	try:
		assert manifest.conn.execute("SELECT count(*) FROM meta WHERE key LIKE 'junk%'").fetchone()[0] == 0
	finally:
		manifest.close()


def test_an_empty_journal_is_no_hot_one(tmp_path):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.commit(os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800'))
	manifest.close()
	assert os.path.getsize(journal_of(job_vault)) == 0
	assert rv.recorded_latest_version(job_vault).recorded == 'V0--2021-01-01_00-00-00_-0800'
	assert rv.read_recorded_monitor_paths(job_vault) == ([], False)


def test_the_scan_and_a_restart_leave_the_journal_alone(tmp_path):
	job = three_versions(tmp_path)
	journal = journal_of(job.job_vault)
	assert os.path.exists(journal)
	before = vault_names(job)
	removed, scanned = restart_and_scan(job)
	assert removed == [] and scanned == [0, 1, 2] and os.path.exists(journal) and vault_names(job) == before
