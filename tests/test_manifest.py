import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, tracked_manifest, run_backup, latest_version, event_entry

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def count_vault_reads(monkeypatch):
	reads = []
	read = rv.read_vault_record

	def counting(version_path, rel, monitor_path, *args):
		reads.append(rel)
		return read(version_path, rel, monitor_path, *args)
	monkeypatch.setattr(rv, 'read_vault_record', counting)
	return reads


def test_backup_records_what_the_new_version_holds(job):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	v0 = run_backup(job)[0]
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.describes(v0)
	assert (manifest.folders, manifest.files) == (['sub/'], ['a.txt', 'sub/b.txt'])
	record = manifest.lookup('a.txt')
	copy = os.lstat(os.path.join(v0, 'a.txt'))
	assert (record.kind, record.size, record.mtime_ns, record.hash) == ('f', 5, copy.st_mtime_ns, rv.hash_file(os.path.join(v0, 'a.txt'), 5))
	# read right after copying, so possibly from memory: the next start reads it back from the disk
	assert record.unchecked == 1
	manifest.close()


def test_cold_start_reads_each_copy_back_once_then_only_the_monitored_side(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	reads = count_vault_reads(monkeypatch)
	assert len(run_backup(job)) == 1
	assert sorted(reads) == ['a.txt', 'sub/b.txt']
	reads.clear()
	assert len(run_backup(job)) == 1
	assert reads == []


def test_unchecked_copy_missing_its_bytes_is_copied_again(job):
	# a crash mid copy can leave the size and mtime in place over space whose bytes never reached the disk
	seed_monitor(job, {'a.txt': 'hello'})
	copy = os.path.join(run_backup(job)[0], 'a.txt')
	st = os.lstat(copy)
	with open(copy, 'r+b') as f:
		f.write(b'\0' * st.st_size)
	os.utime(copy, ns=(st.st_atime_ns, st.st_mtime_ns))
	versions = run_backup(job)
	assert len(versions) == 2
	assert open(os.path.join(versions[1], 'a.txt')).read() == 'hello'


def test_content_rewritten_keeping_size_and_mtime_is_modify_without_reading_the_vault(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	run_backup(job)
	source = os.path.join(job.monitor, 'a.txt')
	st = os.lstat(source)
	open(source, 'w').write('jello')
	os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))
	reads = count_vault_reads(monkeypatch)
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries[source].event == 'modify'
	assert reads == []


def test_relative_symlink_is_not_copied_again_at_each_start(job):
	seed_monitor(job, {'lib/x.txt': 'x'})
	os.symlink('lib', os.path.join(job.monitor, 'lib64'))
	run_backup(job)
	assert len(run_backup(job)) == 1


def test_attribute_change_is_attrib(job):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	source = os.path.join(job.monitor, 'a.txt')
	os.chmod(source, 0o600)
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == OrderedDict([(source, entries[source])]) and entries[source].event == 'attrib'


def test_moved_folder_is_read_from_the_vault_again(job, monkeypatch):
	seed_monitor(job, {'sub/x.txt': 'x'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	run_backup(job, OrderedDict([
		(os.path.join(job.monitor, 'moved') + '/', rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')),
	]))
	reads = count_vault_reads(monkeypatch)
	assert len(run_backup(job)) == 2
	assert sorted(reads) == ['moved/', 'moved/x.txt']


def test_folder_moved_to_another_depth_needs_no_copy(job):
	# the links inside a folder moved to another depth are re-targeted, so they still reach the version holding the copies
	seed_monitor(job, {'sub/x.txt': 'x', 'deep/er/p.txt': 'p'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'deep', 'er', 'sub'))
	run_backup(job, OrderedDict([event_entry(job, 'deep/er/sub/', 'move', 'sub/')]))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == {}
	copy = os.path.join(latest_version(job).path, 'deep', 'er', 'sub', 'x.txt')
	assert os.path.islink(copy) and open(copy).read() == 'x'


def test_manifest_for_another_version_is_listed_again_from_the_vault(job):
	# a version whose content file was never written is removed at startup, but the manifest committed before it
	seed_monitor(job, {'a.txt': 'hello', 'new.txt': 'n'})
	v0 = os.path.join(job.job_vault, 'V0--2021-01-01_00-00-00_-0800')
	os.makedirs(v0)
	rv.cp_af_copy_path(os.path.join(job.monitor, 'a.txt'), os.path.join(v0, 'a.txt'))
	tracked_manifest(job.job_vault, os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800'), ['gone.txt']).close()
	entries = OrderedDict()
	manifest = rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert {path: values.event for path, values in entries.items()} == {os.path.join(job.monitor, 'new.txt'): 'create'}
	assert manifest.describes(v0) and manifest.lookup('a.txt').kind == 'f'
	manifest.close()


def test_interrupted_backup_leaves_the_manifest_on_the_previous_version(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = run_backup(job)[0]
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello again')
	real = rv.record_dirty_entries

	def stop_then_record(*args):
		rv.GREEN_LIGHT.clear()
		real(*args)
	monkeypatch.setattr(rv, 'record_dirty_entries', stop_then_record)
	_, manifest, committed = rv.do_backup(
		OrderedDict([(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None))]),
		job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0',
	)
	manifest.close()
	assert committed is False
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.describes(v0) and reopened.lookup('a.txt').size == len('hello')
	reopened.close()


def test_unreadable_manifest_is_started_over(job):
	os.makedirs(job.job_vault)
	with open(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), 'wb') as f:
		f.write(b'not a database' * 100)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.files == [] and not manifest.describes(os.path.join(job.job_vault, 'V0--x'))
	manifest.close()
