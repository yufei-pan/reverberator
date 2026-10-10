import os
import shutil
import tracemalloc
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version

pytestmark = pytest.mark.unit


def test_delta_unchanged_file_not_added(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	os.utime(os.path.join(job.monitor, 'a.txt'), ns=(os.lstat(os.path.join(v0, 'a.txt')).st_atime_ns, os.lstat(os.path.join(v0, 'a.txt')).st_mtime_ns))
	entries = OrderedDict()
	latest = rv.VaultEntry(0, v0, 0, 1, 1)
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert os.path.join(job.monitor, 'a.txt') not in entries


def test_delta_changed_content_is_modify(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('world')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'a.txt')].event == 'modify'


def test_delta_new_and_deleted(job):
	seed_monitor(job, {'keep.txt': 'k'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k', 'gone.txt': 'g'})
	open(os.path.join(job.monitor, 'new.txt'), 'w').write('n')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'new.txt')].event == 'create'
	assert entries[os.path.join(job.monitor, 'gone.txt')].event == 'delete'


def chained_versions(job, names):
	# V0 holds real copies (cp -a keeps mtimes), V1 and V2 are referenced copies whose
	# files are symlinks chained back to V0, like the vault after daily backups
	v0 = os.path.join(job.job_vault, 'V0--2021-01-01_00-00-00_-0800')
	for name in names:
		rv.cp_af_copy_path(os.path.join(job.monitor, name), os.path.join(v0, name))
	previous = v0
	for version in (1, 2):
		current = os.path.join(job.job_vault, f'V{version}--2021-01-0{version + 1}_00-00-00_-0800')
		os.makedirs(current)
		rv.do_referenced_copy(previous, current, relative=True)
		previous = current
	assert all(os.path.islink(os.path.join(previous, name)) for name in names)
	return v0, rv.VaultEntry(2, previous, 0, 1, 1)


def test_delta_unchanged_files_behind_chained_links_not_added(job):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	_, latest = chained_versions(job, ['a.txt', 'sub/b.txt'])
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert entries == OrderedDict()


def test_delta_changed_file_behind_chained_link_is_modify(job):
	seed_monitor(job, {'a.txt': 'hello'})
	_, latest = chained_versions(job, ['a.txt'])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello, longer')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert entries[os.path.join(job.monitor, 'a.txt')].event == 'modify'


def test_delta_same_size_and_mtime_new_content_behind_chained_link_is_modify(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0, latest = chained_versions(job, ['a.txt'])
	source = os.path.join(job.monitor, 'a.txt')
	open(source, 'w').write('jello')
	vault_stat = os.lstat(os.path.join(v0, 'a.txt'))
	os.utime(source, ns=(vault_stat.st_atime_ns, vault_stat.st_mtime_ns))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert entries[source].event == 'modify'


def test_delta_new_tree_lists_each_folder_before_its_contents(job):
	seed_monitor(job, {'keep.txt': 'k', 'new/sub/f.txt': 'f', 'new/g.txt': 'g'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k'})
	os.utime(os.path.join(job.monitor, 'keep.txt'), ns=(0, os.lstat(os.path.join(v0, 'keep.txt')).st_mtime_ns))
	entries = OrderedDict()
	tracking = rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	paths = list(entries)
	assert {p: v.event for p, v in entries.items()} == {os.path.join(job.monitor, p): 'create' for p in ('new/', 'new/sub/', 'new/sub/f.txt', 'new/g.txt')}
	for path in paths:
		parent = os.path.dirname(path.rstrip('/')) + '/'
		assert parent not in entries or paths.index(parent) < paths.index(path)
	assert (tracking.files, tracking.folders) == (['keep.txt'], [])


def test_delta_holds_little_beyond_the_tracking_lists_it_returns(job):
	# every restart compares trees of 500k+ entries: listing both of them as absolute paths
	# on top of the relative lists kept for tracking cost ~3.7x what the comparison returns
	tree = {f'd{d:02d}/s{s:02d}/{"a_fairly_long_file_name_" * 2}{f:03d}.txt': 'x' for d in range(10) for s in range(10) for f in range(30)}
	seed_monitor(job, tree)
	v0 = os.path.join(job.job_vault, 'V0--2021-01-01_00-00-00_-0800')
	shutil.copytree(job.monitor, v0, symlinks=True)
	entries = OrderedDict()
	tracemalloc.start()
	try:
		before = tracemalloc.get_traced_memory()[0]
		tracking = rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
		kept, peak = tracemalloc.get_traced_memory()
	finally:
		tracemalloc.stop()
	assert entries == OrderedDict()
	assert len(tracking.files) == len(tree) and len(tracking.folders) == 110
	assert peak - before < 2 * (kept - before)
