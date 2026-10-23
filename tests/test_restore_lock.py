import errno
import fcntl
import os
import signal
import subprocess
import sys
import select
import threading
import time
import pytest
import reverberator as rv
from collections import OrderedDict
from tests.harness import seed_monitor, run_backup, event_entry
from tests.test_log_text import alerting_lines

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def _numbers(job):
	return [v.number for v in rv.list_versions(job.job_vault)]


def _change(job, round_number):
	with open(os.path.join(job.monitor, 'a.txt'), 'w', encoding='utf-8') as f:
		f.write(f'data {round_number}')
	return OrderedDict([event_entry(job, 'a.txt', 'modify')])


def _three_versions(job):
	seed_monitor(job, {'a.txt': 'data'})
	run_backup(job, keep_n_versions=3)
	for i in (1, 2):
		run_backup(job, _change(job, i), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2]


def test_restore_lock_path_is_in_the_state_folder(tmp_path):
	assert rv.restore_lock_path('job') == str(tmp_path / 'state' / 'job-job.restore.lock')
	assert rv.restore_lock_path('job', '/x') == '/x/job-job.restore.lock'


def test_pruning_waits_while_a_restore_holds_the_lock(job):
	_three_versions(job)
	with rv.RestoreLock('job'):
		run_backup(job, _change(job, 3), keep_n_versions=3)
		assert _numbers(job) == [0, 1, 2, 3]
	run_backup(job, _change(job, 4), keep_n_versions=3)
	assert _numbers(job) == [2, 3, 4]


def test_pruning_resumes_after_the_restoring_process_is_killed(job, tmp_path):
	_three_versions(job)
	code = 'import sys, reverberator as rv\nwith rv.RestoreLock("job"):\n\tprint("held", flush=True)\n\tsys.stdin.read()\n'
	env = dict(os.environ, REVERB_STATE_DIR=str(tmp_path / 'state'), PYTHONPATH=os.path.dirname(rv.__file__))
	proc = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
	try:
		# a child that never gets there must fail the test, not hang it
		assert select.select([proc.stdout], [], [], 10)[0], 'the restoring process never took the lock'
		assert proc.stdout.readline().strip() == b'held'
		run_backup(job, _change(job, 3), keep_n_versions=3)
		assert _numbers(job) == [0, 1, 2, 3]
	finally:
		proc.send_signal(signal.SIGKILL)
		proc.wait()
		proc.stdin.close()
		proc.stdout.close()
	run_backup(job, _change(job, 4), keep_n_versions=3)
	assert _numbers(job) == [2, 3, 4]


def test_restore_lock_waits_for_a_running_prune(tmp_path, capsys):
	path = rv.restore_lock_path('job')
	os.makedirs(os.path.dirname(path))
	fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
	fcntl.flock(fd, fcntl.LOCK_EX)
	entered = threading.Event()
	def restore():
		with rv.RestoreLock('job', stream=sys.stderr):
			entered.set()
	thread = threading.Thread(target=restore)
	thread.start()
	try:
		assert not entered.wait(0.3)
		assert 'Waiting for reverberator to finish removing an old version of job' in capsys.readouterr().err
	finally:
		fcntl.flock(fd, fcntl.LOCK_UN)
		os.close(fd)
		thread.join(5)
	assert entered.is_set()


def test_pruning_without_a_state_folder_proceeds(job, tmp_path, monkeypatch):
	blocker = tmp_path / 'not-a-folder'
	blocker.write_text('x')
	monkeypatch.setenv('REVERB_STATE_DIR', str(blocker))
	_three_versions(job)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job)[0] >= 1


def _logged_errors(monkeypatch):
	errors = []
	real = rv.backuperTeeLogToTl
	def record(*args, **kwargs):
		if kwargs.get('error'):
			errors.append(kwargs.get('message', args[1] if len(args) > 1 else ''))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return errors


@pytest.mark.parametrize('code', [errno.EMFILE, errno.EACCES])
def test_pruning_is_postponed_when_the_lock_file_cannot_be_opened(job, monkeypatch, code):
	_three_versions(job)
	errors = _logged_errors(monkeypatch)
	lock_path = rv.restore_lock_path('job')
	real_open = os.open
	def fake_open(path, *args, **kwargs):
		if path == lock_path:
			raise OSError(code, os.strerror(code))
		return real_open(path, *args, **kwargs)
	monkeypatch.setattr(os, 'open', fake_open)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	assert errors


def test_pruning_is_postponed_when_the_lock_cannot_be_taken(job, monkeypatch):
	_three_versions(job)
	os.makedirs(os.path.dirname(rv.restore_lock_path('job')), exist_ok=True)
	errors = _logged_errors(monkeypatch)
	real_flock = fcntl.flock
	def fake_flock(fd, operation):
		if operation == fcntl.LOCK_EX | fcntl.LOCK_NB:
			raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))
		return real_flock(fd, operation)
	monkeypatch.setattr(fcntl, 'flock', fake_flock)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	assert errors


def _logged_lines(monkeypatch):
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		lines.append(str(message))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def test_a_postponed_removal_is_logged_once_per_backup(job, monkeypatch):
	_three_versions(job)
	lines = _logged_lines(monkeypatch)
	with rv.RestoreLock('job'):
		# over the size limit, the inode limit and the version count: each retention loop tries to remove a version
		run_backup(job, _change(job, 3), keep_n_versions=3, backup_size_limit='1B,i1')
	assert _numbers(job) == [0, 1, 2, 3]
	assert len([line for line in lines if line.startswith('Postponing removal of the oldest version')]) == 1


def test_the_lock_file_is_never_opened_through_a_symlink(job, tmp_path):
	_three_versions(job)
	lock_path = rv.restore_lock_path('job')
	os.makedirs(os.path.dirname(lock_path))
	elsewhere = tmp_path / 'elsewhere'
	os.symlink(elsewhere, lock_path)
	# pruning is postponed, as for any lock that cannot be checked, and a restore cannot take it
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	with pytest.raises(OSError) as raised:
		with rv.RestoreLock('job'):
			pass
	assert raised.value.errno == errno.ELOOP
	assert not os.path.lexists(elsewhere)


def _unopenable_locks(monkeypatch, failing):
	real_open = os.open
	def fake_open(path, *args, **kwargs):
		if str(path).endswith('.restore.lock') and failing[0]:
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, *args, **kwargs)
	monkeypatch.setattr(os, 'open', fake_open)


def _unlockable_locks(monkeypatch, failing):
	real_flock = fcntl.flock
	def fake_flock(fd, operation):
		if operation == fcntl.LOCK_EX | fcntl.LOCK_NB and failing[0]:
			raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))
		return real_flock(fd, operation)
	monkeypatch.setattr(fcntl, 'flock', fake_flock)


@pytest.mark.parametrize('make_failing', [_unopenable_locks, _unlockable_locks])
def test_a_lock_that_cannot_be_checked_raises_an_hourly_marker_after_the_grace(tmp_path, monkeypatch, capsys, make_failing):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 900)
	monkeypatch.setattr(rv, 'DISK_WAIT_REPEAT_SECONDS', 3600)
	monkeypatch.setattr(rv, 'RESTORE_LOCK_UNCHECKED', {})
	os.makedirs(tmp_path / 'state')
	failing = [True]
	make_failing(monkeypatch, failing)
	def prune_at(now, job_name='job'):
		capsys.readouterr()
		assert rv.prune_oldest(OrderedDict(), job_name, '/monitor', clock=lambda: now) == (0, 0)
		return alerting_lines(capsys.readouterr().out)
	assert prune_at(0) == [] and prune_at(899) == []
	markers = prune_at(900)
	lock_path = rv.restore_lock_path('job')
	assert len(markers) == 1 and f'reverberator job job FAILED: cannot check the restore lock {lock_path}: ' in markers[0]
	error = os.strerror(errno.EACCES if make_failing is _unopenable_locks else errno.ENOLCK)
	assert error in markers[0].partition(lock_path)[2] and markers[0].count('; pruning postponed') == 1
	# tracked per job: another job's lock fails from now on
	assert prune_at(900, 'other') == []
	assert prune_at(1000) == [] and prune_at(1799, 'other') == [] and len(prune_at(1800, 'other')) == 1
	assert prune_at(4499) == [] and len(prune_at(4500)) == 1
	# checked again, the lock starts a new grace when it next fails
	failing[0] = False
	assert prune_at(5000) == []
	failing[0] = True
	assert prune_at(5001) == [] and prune_at(5900) == [] and len(prune_at(5901)) == 1


def test_restore_lock_default_stream_is_the_stderr_of_the_moment(tmp_path, capsys):
	path = rv.restore_lock_path('job')
	os.makedirs(os.path.dirname(path))
	fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
	fcntl.flock(fd, fcntl.LOCK_EX)
	entered = threading.Event()
	def restore():
		with rv.RestoreLock('job'):
			entered.set()
	thread = threading.Thread(target=restore)
	thread.start()
	try:
		assert not entered.wait(0.3)
		assert 'Waiting for reverberator to finish removing an old version of job' in capsys.readouterr().err
	finally:
		fcntl.flock(fd, fcntl.LOCK_UN)
		os.close(fd)
		thread.join(5)
	assert entered.is_set()


def test_pruning_holds_the_lock_while_the_oldest_version_is_removed(job, monkeypatch):
	_three_versions(job)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	os.makedirs(os.path.dirname(rv.restore_lock_path('job')), exist_ok=True)
	seen = []
	real = rv.decrement_stepper
	def stepping(vault_info_dict, *args, **kwargs):
		# what a restore starting now finds: the lock taken, so it waits for this removal
		fd = os.open(rv.restore_lock_path('job'), os.O_RDWR)
		try:
			try:
				fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
				seen.append('free')
				fcntl.flock(fd, fcntl.LOCK_UN)
			except BlockingIOError:
				seen.append('held')
		finally:
			os.close(fd)
		return real(vault_info_dict, *args, **kwargs)
	monkeypatch.setattr(rv, 'decrement_stepper', stepping)
	assert rv.prune_oldest(info, 'job', job.monitor) != (0, 0)
	assert seen == ['held'] and _numbers(job) == [1, 2]
	# and released afterwards
	with rv.RestoreLock('job'):
		pass
