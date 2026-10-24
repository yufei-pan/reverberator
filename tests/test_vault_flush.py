'''
Round 9, Task 4: mergerfs does not implement fsyncdir, so a folder fsync through the pool reaches no disk. A vault folder
is fsynced on each branch of its pool that holds it, for the change list's placement, the pruning secret, and after
current_version moves.
'''
import errno
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import committed_versions, event_entry, seed_monitor

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


def test_a_failed_flush_after_the_swap_still_commits(job, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	real = rv.fsync_vault_folder
	failed = []
	def flushing(path):
		if not failed:
			failed.append(path)
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real(path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushing)
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert committed and failed == [job.job_vault] and len(committed_versions(job)) == 1
	assert os.readlink(os.path.join(job.job_vault, 'current_version')) == os.path.basename(committed_versions(job)[0])
	out = capsys.readouterr()
	assert f'Could not sync {job.job_vault} to disk after moving current_version' in out.out + out.err
