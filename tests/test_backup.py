import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions, tracked_manifest, run_backup, event_entry

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


def test_v0_is_a_complete_copy_whatever_the_rule_says(job):
	seed_monitor(job, {'a.txt': 'hello'})
	info, tracking, committed = rv.do_backup(
		{}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=False, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0',
	)
	assert committed is True
	dest = os.path.join(committed_versions(job)[0], 'a.txt')
	# Keep 1 Complete Backup False made a link into the monitored tree on 0.54: on design R the first version is the tree
	assert not os.path.islink(dest) and not os.path.samefile(dest, os.path.join(job.monitor, 'a.txt'))
	assert open(dest).read() == 'hello'


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
	run_backup(job)
	os.makedirs(os.path.join(job.monitor, 'newdir'), exist_ok=True)
	open(os.path.join(job.monitor, 'newdir', 'n.txt'), 'w').write('n')
	open(os.path.join(job.monitor, 'keep.txt'), 'w').write('k2')
	os.remove(os.path.join(job.monitor, 'old.txt'))
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	os.chmod(os.path.join(job.monitor, 'keep.txt'), 0o640)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'keep.txt'), rv.BackupEntryValues('t', 'modify', None)),
		(os.path.join(job.monitor, 'old.txt'), rv.BackupEntryValues('t', 'delete', None)),
		(os.path.join(job.monitor, 'newdir') + '/', rv.BackupEntryValues('t', 'create', None)),
		(os.path.join(job.monitor, 'moved') + '/', rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')),
	])
	v1 = run_backup(job, entries)[-1]
	assert os.path.isfile(os.path.join(v1, 'keep.txt'))
	assert open(os.path.join(v1, 'keep.txt')).read() == 'k2'
	assert not os.path.lexists(os.path.join(v1, 'old.txt'))
	assert os.path.isfile(os.path.join(v1, 'newdir', 'n.txt'))
	assert os.path.lexists(os.path.join(v1, 'moved', 'x.txt'))
	result = rv.VaultManifest(job.job_vault)
	assert 'old.txt' not in result.files
	assert 'keep.txt' in result.files
	result.close()


@pytest.mark.parametrize('only_sync', [True, False])
def test_attrib_only_sync_vs_copy(job, only_sync):
	seed_monitor(job, {'a.txt': 'same'})
	run_backup(job)
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'attrib', None)),
	])
	v1 = run_backup(job, entries, only_sync_attributes=only_sync)[-1]
	assert os.lstat(os.path.join(v1, 'a.txt')).st_mode & 0o777 == 0o600


def test_move_rename_failure_falls_back_to_copy_delete(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'data'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt'))
	real_rename = os.rename

	def boom(src, dst):
		if os.path.basename(dst) == 'b.txt':
			raise OSError('simulated')
		return real_rename(src, dst)

	monkeypatch.setattr(os, 'rename', boom)
	entries = OrderedDict([
		(os.path.join(job.monitor, 'b.txt'), rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'a.txt'))),
	])
	v1 = run_backup(job, entries)[-1]
	assert os.path.isfile(os.path.join(v1, 'b.txt'))
	assert open(os.path.join(v1, 'b.txt')).read() == 'data'


def test_vanished_source_is_not_recorded_in_tracking(job):
	# a short-lived file (git's index.stash.<pid>) is gone by the time the
	# backup replays its create event; it must not enter the tracking list
	seed_monitor(job, {'keep.txt': 'k'})
	run_backup(job)
	gone = os.path.join(job.monitor, '.git', 'index.stash.4242')
	open(os.path.join(job.monitor, 'keep.txt'), 'w').write('k2')
	entries = OrderedDict([
		(gone, rv.BackupEntryValues('t', 'create', None)),
		(os.path.join(job.monitor, 'keep.txt'), rv.BackupEntryValues('t', 'modify', None)),
	])
	v1 = run_backup(job, entries)[-1]
	result = rv.VaultManifest(job.job_vault)
	assert '.git/index.stash.4242' not in result.files
	assert not os.path.lexists(os.path.join(v1, '.git', 'index.stash.4242'))
	# the rest of the backup must still succeed
	assert os.path.isfile(os.path.join(v1, 'keep.txt'))
	assert 'keep.txt' in result.files
	result.close()


def test_copy_keeps_inherited_link_when_source_vanished(job):
	# losing the inherited reference would drop the previous version's copy
	v0 = write_committed_version(job, 0, {'a.txt': 'a'})
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	dest = os.path.join(v1, 'a.txt')
	os.symlink(os.path.join(v0, 'a.txt'), dest)
	rv.GREEN_LIGHT.set()
	rc = rv.cp_af_copy_path(source_path=os.path.join(job.monitor, 'a.txt'), dest_path=dest)
	assert rc is False
	assert os.path.islink(dest)
	assert os.path.exists(dest)


def test_current_version_is_swapped_atomically(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	rv.do_backup({}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True,
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')[1].close()
	link = os.path.join(job.job_vault, 'current_version')
	first = os.readlink(link)
	removed = []
	monkeypatch.setattr(rv.os, 'remove', lambda path, *a, **k: removed.append(path) if path == link else os.unlink(path))
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	rv.do_backup({os.path.join(job.monitor, 'b.txt'): rv.BackupEntryValues('t', 'create', None)}, job_name=job.job_name,
		monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0')[1].close()
	assert link not in removed and os.readlink(link) != first
	assert not os.path.lexists(os.path.join(job.job_vault, '.current_version.tmp'))



def test_committed_versions_are_in_version_order_past_v9(job):
	seed_monitor(job, {'a.txt': '0'})
	run_backup(job)
	for n in range(1, 11):
		with open(os.path.join(job.monitor, 'a.txt'), 'w') as f:
			f.write(str(n))
		latest = run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'modify')]))[-1]
	assert os.path.basename(latest).startswith('V10--')
	assert [rv.vault_version_number(os.path.basename(path)) for path in committed_versions(job)] == list(range(11))
