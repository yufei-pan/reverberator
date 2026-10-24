import errno
import os
import sys
import tracemalloc
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions, content_file_path, write_tree

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def _two_versions_symlink_pair(job):
	'''V0 real file, V1 symlink to V0 file, both committed.'''
	seed_monitor(job, {'a.txt': 'data'})
	v0 = write_committed_version(job, 0, {'a.txt': 'data'}, timestamp='2021-01-01_00-00-00_-0800', current=False)
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	# relative, as the daemon links: an absolute link is a user's symlink since 0.44, which pruning leaves dangling
	os.symlink(os.path.join('..', os.path.basename(v0), 'a.txt'), os.path.join(v1, 'a.txt'))
	with open(content_file_path(v1), 'w', encoding='utf-8') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	link = os.path.join(job.job_vault, 'current_version')
	if os.path.lexists(link):
		os.remove(link)
	os.symlink(os.path.basename(v1), link, target_is_directory=True)
	return v0, v1


def test_keep_n_versions_2_steps_before_v2(job):
	v0, v1 = _two_versions_symlink_pair(job)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('data2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	info = rv.get_vault_info(job.job_vault)
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=2, backup_size_limit='0',
		vaultInfo=info,
	)
	assert not os.path.isdir(v0)
	# V0's copy moved into V1 in place of the link
	assert not os.path.islink(os.path.join(v1, 'a.txt')) and open(os.path.join(v1, 'a.txt')).read() == 'data'
	names = [os.path.basename(p) for p in committed_versions(job)]
	assert any(n.startswith('V1') or n.startswith('V2') for n in names)


def test_tiny_size_limit_still_creates_version_if_stepper_cannot_free(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	write_committed_version(job, 0, {'a.txt': 'hello'})
	monkeypatch.setattr(rv, 'decrement_stepper', lambda d, *args, **kwargs: (0, 0))
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	info = rv.get_vault_info(job.job_vault)
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='1',
		vaultInfo=info,
	)
	assert len(committed_versions(job)) >= 2


def test_inode_limit_i1_attempts_stepper(job, monkeypatch):
	called = []
	seed_monitor(job, {'a.txt': 'hello'})
	write_committed_version(job, 0, {'a.txt': 'hello'})
	real = rv.decrement_stepper

	def wrap(d, *args, **kwargs):
		called.append(True)
		return real(d, *args, **kwargs)

	monkeypatch.setattr(rv, 'decrement_stepper', wrap)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello2')
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='i1',
		vaultInfo=rv.get_vault_info(job.job_vault),
	)
	assert called


@pytest.mark.parametrize('how', ['link', 'move'])
def test_stepper_memory_does_not_grow_with_the_version(job, monkeypatch, how):
	# a big job's next version links 500k+ files: listing them all before moving any cost hundreds of MB per backup.
	# on a filesystem that cannot hard link, each copy is moved, and the walk notes every one (review7 P5: a set of
	# their hashes went past the bound)
	if how == 'move':
		def link(source, dest, *args, **kwargs):
			raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), source)
		monkeypatch.setattr(rv.os, 'link', link)
	def peak_for(files):
		root = os.path.join(job.root, f'tree{files}')
		v0 = os.path.join(root, 'V0--2021-01-01_00-00-00_-0800')
		v1 = os.path.join(root, 'V1--2021-01-02_00-00-00_-0800')
		names = [f'd{i % 50:02d}/{"a_fairly_long_file_name_" * 2}{i:05d}.txt' for i in range(files)]
		write_tree(v0, dict.fromkeys(names, 'x'))
		for name in names:
			link = os.path.join(v1, name)
			os.makedirs(os.path.dirname(link), exist_ok=True)
			os.symlink(os.path.relpath(os.path.join(v0, name), os.path.dirname(link)), link)
		versions = OrderedDict([(0, rv.VaultEntry(0, v0, 0, 1, 1)), (1, rv.VaultEntry(1, v1, 0, 1, 1))])
		# each with its change list: the prune stops for a next version without one (Task 2b)
		for version in (v0, v1):
			content = rv.change_list_path(version, 1, 1)
			rv.place_change_list(content, rv.prepare_change_list(content, []))
		tracemalloc.start()
		try:
			before = tracemalloc.get_traced_memory()[0]
			rv.decrement_stepper(versions, 'job', os.path.join(root, 'monitor'))
			peak = tracemalloc.get_traced_memory()[1] - before
		finally:
			tracemalloc.stop()
		assert not os.path.exists(v0)
		assert all(os.path.isfile(os.path.join(v1, name)) and not os.path.islink(os.path.join(v1, name)) for name in names)
		return peak, sum(sys.getsizeof(os.path.join(v1, name)) + 8 for name in names)

	# a first pass, so what any first call sets up once is not counted
	peak_for(200)
	small, small_paths = peak_for(1000)
	large, large_paths = peak_for(4000)
	assert large - small < (large_paths - small_paths) / 4
