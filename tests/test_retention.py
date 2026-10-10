import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version, committed_versions, content_file_path

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
	os.symlink(os.path.join(v0, 'a.txt'), os.path.join(v1, 'a.txt'))
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
	names = [os.path.basename(p) for p in committed_versions(job)]
	assert any(n.startswith('V1') or n.startswith('V2') for n in names)


def test_tiny_size_limit_still_creates_version_if_stepper_cannot_free(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	write_committed_version(job, 0, {'a.txt': 'hello'})
	monkeypatch.setattr(rv, 'decrement_stepper', lambda d: (0, 0))
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

	def wrap(d):
		called.append(True)
		return real(d)

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
