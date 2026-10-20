import errno
import fcntl
import os
import signal
import subprocess
import sys
import threading
import time
import pytest
import reverberator as rv
from collections import OrderedDict
from tests.harness import seed_monitor, run_backup, event_entry

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
	assert _numbers(job)[0] >= 2


def test_pruning_resumes_after_the_restoring_process_is_killed(job, tmp_path):
	_three_versions(job)
	code = 'import sys, reverberator as rv\nwith rv.RestoreLock("job"):\n\tprint("held", flush=True)\n\tsys.stdin.read()\n'
	env = dict(os.environ, REVERB_STATE_DIR=str(tmp_path / 'state'), PYTHONPATH=os.path.dirname(rv.__file__))
	proc = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
	try:
		assert proc.stdout.readline().strip() == b'held'
		run_backup(job, _change(job, 3), keep_n_versions=3)
		assert _numbers(job) == [0, 1, 2, 3]
	finally:
		proc.send_signal(signal.SIGKILL)
		proc.wait()
		proc.stdin.close()
		proc.stdout.close()
	run_backup(job, _change(job, 4), keep_n_versions=3)
	assert _numbers(job)[0] >= 2


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
