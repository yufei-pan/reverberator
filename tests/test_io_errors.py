import errno
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fail_scandir(monkeypatch, failing_path, err):
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == os.path.abspath(failing_path).rstrip('/'):
			raise OSError(err, os.strerror(err), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)


def test_unreadable_folder_keeps_entries_and_logs_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', **{f'big/f{i}.txt': str(i) for i in range(500)}})
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'big'), errno.EIO)
	capsys.readouterr()
	_backup(job)[1].close()
	v1 = committed_versions(job)[1]
	assert len(os.listdir(os.path.join(v1, 'big'))) == 500
	out = capsys.readouterr()
	assert (out.out + out.err).count(f'reverberator job {job.job_name} UNREADABLE: {os.path.join(job.monitor, "big")}') == 1


def test_unreadable_root_fails_the_job_without_deletions(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	_fail_scandir(monkeypatch, job.monitor, errno.ENOTCONN)
	with pytest.raises(rv.JobFailure):
		_backup(job)
	assert len(committed_versions(job)) == 1


def test_unreadable_folder_in_first_backup_is_reported(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', 'locked/b.txt': 'b'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'locked'), errno.EACCES)
	_backup(job)[1].close()
	out = capsys.readouterr()
	assert 'UNREADABLE: ' + os.path.join(job.monitor, 'locked') in out.out + out.err


def test_resume_check_refuses_after_a_read_error(job, monkeypatch):
	seed_monitor(job, {'d/a.txt': 'a'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'd'), errno.EIO)
	assert rv.get_monitor_path_most_recent_change_time(job.monitor) == float('inf')
