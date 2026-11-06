import errno
import os
import sys
import tracemalloc
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import run_backup, seed_monitor, committed_versions, write_tree
from tests.vault_oracle import read_view

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def _modify(job, text):
	'''The batch of a.txt written with text.'''
	open(os.path.join(job.monitor, 'a.txt'), 'w').write(text)
	return OrderedDict([(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None))])


def _two_versions(job):
	'''V0 and V1, a real tree that V0 forwards to, both committed, with b.txt in both and a.txt new in V1.'''
	seed_monitor(job, {'a.txt': 'data', 'b.txt': 'b'})
	run_backup(job)
	return run_backup(job, _modify(job, 'data1'))


def test_keep_n_versions_2_steps_before_v2(job):
	v0, v1 = _two_versions(job)
	entries = _modify(job, 'data2')
	info = rv.get_vault_info(job.job_vault)
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True,
		keep_n_versions=2, backup_size_limit='0',
		vaultInfo=info,
	)[1].close()
	assert not os.path.isdir(v0)
	# nothing of V0 was needed by a later version: V1 reads as it did
	view = read_view(job.job_vault, os.path.basename(v1))
	assert view['a.txt'].kind == 'f' and open(os.path.join(v1, 'a.txt')).read() == 'data1' and view['b.txt'].kind == 'f'
	names = [os.path.basename(p) for p in committed_versions(job)]
	assert [n.partition('--')[0] for n in names] == ['V1', 'V2']


def test_tiny_size_limit_still_creates_version_if_stepper_cannot_free(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	monkeypatch.setattr(rv, 'prune_tree_version', lambda d, *args, **kwargs: (0, 0))
	entries = _modify(job, 'hello2')
	info = rv.get_vault_info(job.job_vault)
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='1',
		vaultInfo=info,
	)[1].close()
	assert len(committed_versions(job)) >= 2


def test_inode_limit_i1_attempts_stepper(job, monkeypatch):
	called = []
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	run_backup(job, _modify(job, 'hello1'))
	real = rv.prune_tree_version

	def wrap(d, *args, **kwargs):
		called.append(True)
		return real(d, *args, **kwargs)

	monkeypatch.setattr(rv, 'prune_tree_version', wrap)
	entries = _modify(job, 'hello2')
	rv.do_backup(
		entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='i1',
		vaultInfo=rv.get_vault_info(job.job_vault),
	)[1].close()
	assert called


@pytest.mark.on_054
@pytest.mark.parametrize('how', ['link', 'move'])
def test_stepper_memory_does_not_grow_with_the_version(job, monkeypatch, how):
	# a big job's next version links 500k+ files: listing them all before moving any cost hundreds of MB per backup.
	# on a filesystem that cannot hard link, each copy is moved, and the walk notes every one (review7 P5: a set of
	# their hashes went past the bound)
	# the walk holds up to REFERENCED_COPY_WINDOW chunks of its entries at once (round 15), a bound of its own: kept below
	# the trees measured here
	monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', 8)
	monkeypatch.setattr(rv, 'REFERENCED_COPY_WINDOW', 4)
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

	# the real folders earlier tests found are dropped: the chain ground truth copies them around each prune, inside the
	# measure, so their number, which the whole run sets, would decide the peaks
	rv.REAL_VAULT_FOLDERS.clear()
	# a first pass, so what any first call sets up once is not counted
	peak_for(200)
	small, small_paths = peak_for(1000)
	large, large_paths = peak_for(4000)
	assert large - small < (large_paths - small_paths) / 4
