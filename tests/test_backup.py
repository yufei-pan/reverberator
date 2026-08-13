import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions

pytestmark = pytest.mark.unit

# Abort / empty-delta / dir-delete tracking live in tests/test_crash_safety.py.


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def test_v0_complete_copy_is_not_symlink_into_monitor(job):
	seed_monitor(job, {'a.txt': 'hello'})
	info, tracking, committed = rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0',
	)
	assert committed is True
	versions = committed_versions(job)
	assert len(versions) == 1
	dest = os.path.join(versions[0], 'a.txt')
	assert os.path.isfile(dest)
	assert not os.path.islink(dest)
	assert open(dest).read() == 'hello'
	assert 'a.txt' in tracking.files


def test_v0_referenced_copy_symlinks_into_monitor(job):
	seed_monitor(job, {'a.txt': 'hello'})
	info, tracking, committed = rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=False, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0',
	)
	assert committed is True
	dest = os.path.join(committed_versions(job)[0], 'a.txt')
	assert os.path.islink(dest)
	assert os.path.realpath(dest) == os.path.realpath(os.path.join(job.monitor, 'a.txt'))


def test_journal_written_when_enabled(job):
	seed_monitor(job, {'a.txt': 'hello'})
	rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0', log_journal=True,
	)
	assert os.path.isfile(os.path.join(job.job_vault, 'journal.tsv'))


def test_reverb_create_modify_delete_attrib_move_file_and_dir(job):
	seed_monitor(job, {'keep.txt': 'k', 'old.txt': 'o', 'sub/x.txt': 'x'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k', 'old.txt': 'o', 'sub/x.txt': 'x'})
	os.makedirs(os.path.join(job.monitor, 'newdir'), exist_ok=True)
	open(os.path.join(job.monitor, 'newdir', 'n.txt'), 'w').write('n')
	open(os.path.join(job.monitor, 'keep.txt'), 'w').write('k2')
	os.remove(os.path.join(job.monitor, 'old.txt'))
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	os.chmod(os.path.join(job.monitor, 'keep.txt'), 0o640)
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'keep.txt'), rv.BackupEntryValues('t', 'modify', None)),
		(os.path.join(job.monitor, 'old.txt'), rv.BackupEntryValues('t', 'delete', None)),
		(os.path.join(job.monitor, 'newdir') + '/', rv.BackupEntryValues('t', 'create', None)),
		(os.path.join(job.monitor, 'moved') + '/', rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')),
	])
	latest = rv.VaultEntry(0, v0, 0, 1, 1)
	tracking = rv.TrackingFilesFolders(['keep.txt', 'old.txt', 'sub/x.txt'], ['sub/'])
	rv.GREEN_LIGHT.set()
	result = rv.do_reverb_backup(entries, v1, latest, True, tracking, job.monitor)
	assert os.path.isfile(os.path.join(v1, 'keep.txt'))
	assert open(os.path.join(v1, 'keep.txt')).read() == 'k2'
	assert not os.path.lexists(os.path.join(v1, 'old.txt'))
	assert os.path.isfile(os.path.join(v1, 'newdir', 'n.txt'))
	assert os.path.lexists(os.path.join(v1, 'moved', 'x.txt'))
	assert 'old.txt' not in result.files
	assert 'keep.txt' in result.files


def test_attrib_only_sync_vs_copy(job):
	seed_monitor(job, {'a.txt': 'same'})
	v0 = write_committed_version(job, 0, {'a.txt': 'same'})
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	for only_sync, label in ((True, 'sync'), (False, 'copy')):
		v = os.path.join(job.job_vault, f'V-{label}')
		os.makedirs(v)
		entries = OrderedDict([
			(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'attrib', None)),
		])
		latest = rv.VaultEntry(0, v0, 0, 1, 1)
		rv.do_reverb_backup(entries, v, latest, only_sync, rv.TrackingFilesFolders(['a.txt'], []), job.monitor)
		assert os.path.lexists(os.path.join(v, 'a.txt'))


def test_move_rename_failure_falls_back_to_copy_delete(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'data'})
	v0 = write_committed_version(job, 0, {'a.txt': 'data'})
	os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt'))
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	real_rename = os.rename

	def boom(src, dst):
		if os.path.basename(dst) == 'b.txt':
			raise OSError('simulated')
		return real_rename(src, dst)

	monkeypatch.setattr(os, 'rename', boom)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'b.txt'), rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'a.txt'))),
	])
	rv.do_reverb_backup(
		entries, v1, rv.VaultEntry(0, v0, 0, 1, 1), True,
		rv.TrackingFilesFolders(['a.txt'], []), job.monitor,
	)
	assert os.path.isfile(os.path.join(v1, 'b.txt'))
	assert open(os.path.join(v1, 'b.txt')).read() == 'data'
