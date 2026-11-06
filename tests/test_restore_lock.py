import errno
import fcntl
import os
import shutil
import signal
import subprocess
import sys
import select
import threading
import time
import pytest
import reverberator as rv
from collections import OrderedDict, deque
from tests.harness import seed_monitor, run_backup, event_entry, write_rule, wait_until
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


def _state():
	os.makedirs(rv.state_dir_path(), exist_ok=True)


class Held:
	'''A lock of kind held the way a command holds it, from another open file, until released.'''
	def __init__(self, kind, operation=fcntl.LOCK_SH):
		_state()
		self.fd = os.open(rv.job_lock_path('job', kind), os.O_RDWR | os.O_CREAT, 0o600)
		fcntl.flock(self.fd, operation)

	def release(self):
		if self.fd is not None:
			os.close(self.fd)
			self.fd = None


def _free(kind):
	'''Whether the lock of kind can be taken exclusive right now.'''
	fd = os.open(rv.job_lock_path('job', kind), os.O_RDWR | os.O_CREAT, 0o600)
	try:
		fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
		return True
	except BlockingIOError:
		return False
	finally:
		os.close(fd)


def _logged_lines(monkeypatch):
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		lines.append(str(message))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def _logged_errors(monkeypatch):
	errors = []
	real = rv.backuperTeeLogToTl
	def record(*args, **kwargs):
		if kwargs.get('error'):
			errors.append(kwargs.get('message', args[1] if len(args) > 1 else ''))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return errors


class Backup(threading.Thread):
	'''One backup of the batch entries in a thread of its own: committed is do_backup's answer.'''
	def __init__(self, job, entries, **kwargs):
		super().__init__(daemon=True)
		self.job, self.entries, self.kwargs = job, entries, kwargs
		self.committed = None
		self.error = None
		self.start()

	def run(self):
		options = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
		options.update(self.kwargs)
		if 'control' in options:
			options['job'] = options.pop('control')
		try:
			_, manifest, self.committed = rv.do_backup(self.entries, job_name=self.job.job_name, monitor_path=self.job.monitor, vault_path=self.job.vault, **options)
			manifest.close()
		except BaseException as e:
			self.error = e


WAITING = 'Waiting for a restore of job to finish before backing up'


def test_job_lock_paths_are_in_the_state_folder(tmp_path):
	for kind in ('backup', 'restore', 'history'):
		assert rv.job_lock_path('job', kind) == str(tmp_path / 'state' / f'job-job.{kind}.lock')
	assert rv.job_lock_path('job', 'restore', '/x') == '/x/job-job.restore.lock'


def test_history_or_a_restore_at_its_prompt_postpones_pruning_but_not_the_backup(job):
	_three_versions(job)
	# what history, and a restore at its picker or prompt, hold: the history lock alone
	with rv.JobLock('job'):
		run_backup(job, _change(job, 3), keep_n_versions=3)
		assert _numbers(job) == [0, 1, 2, 3]
	run_backup(job, _change(job, 4), keep_n_versions=3)
	assert _numbers(job) == [2, 3, 4]


def test_pruning_resumes_after_the_holding_process_is_killed(job, tmp_path):
	_three_versions(job)
	code = 'import sys, reverberator as rv\nwith rv.JobLock("job"):\n\tprint("held", flush=True)\n\tsys.stdin.read()\n'
	env = dict(os.environ, REVERB_STATE_DIR=str(tmp_path / 'state'), PYTHONPATH=os.path.dirname(rv.__file__))
	proc = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
	try:
		# a child that never gets there must fail the test, not hang it
		assert select.select([proc.stdout], [], [], 10)[0], 'the holding process never took the lock'
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


@pytest.mark.parametrize('kind, waiting', [('history', 'removing an old version'), ('backup', 'a backup'), ('restore', 'a backup')])
def test_a_command_lock_waits_for_the_daemon(tmp_path, capsys, kind, waiting):
	daemon = Held(kind, fcntl.LOCK_EX)
	entered = threading.Event()
	def command():
		with rv.JobLock('job', kind, stream=sys.stderr):
			entered.set()
	thread = threading.Thread(target=command)
	thread.start()
	try:
		assert not entered.wait(0.3)
		assert f'Waiting for reverberator to finish {waiting} of job' in capsys.readouterr().err
	finally:
		daemon.release()
		thread.join(5)
	assert entered.is_set()


def test_pruning_and_backing_up_without_a_state_folder_proceed(job, tmp_path, monkeypatch):
	blocker = tmp_path / 'not-a-folder'
	blocker.write_text('x')
	monkeypatch.setenv('REVERB_STATE_DIR', str(blocker))
	_three_versions(job)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job)[0] >= 1


def _failing_history_open(monkeypatch, code=errno.EACCES, failing=None):
	real_open = os.open
	def fake_open(path, *args, **kwargs):
		if str(path).endswith('.history.lock') and (failing is None or failing[0]):
			raise OSError(code, os.strerror(code), path)
		return real_open(path, *args, **kwargs)
	monkeypatch.setattr(os, 'open', fake_open)


def _failing_history_flock(monkeypatch, failing=None):
	real_flock = fcntl.flock
	def fake_flock(fd, operation):
		if operation == fcntl.LOCK_EX | fcntl.LOCK_NB and os.readlink(f'/proc/self/fd/{fd}').endswith('.history.lock') and (failing is None or failing[0]):
			raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))
		return real_flock(fd, operation)
	monkeypatch.setattr(fcntl, 'flock', fake_flock)


@pytest.mark.parametrize('code', [errno.EMFILE, errno.EACCES])
def test_pruning_is_postponed_when_the_history_lock_cannot_be_opened(job, monkeypatch, code):
	_three_versions(job)
	_state()
	errors = _logged_errors(monkeypatch)
	_failing_history_open(monkeypatch, code)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	assert errors


def test_pruning_is_postponed_when_the_history_lock_cannot_be_taken(job, monkeypatch):
	_three_versions(job)
	_state()
	errors = _logged_errors(monkeypatch)
	_failing_history_flock(monkeypatch)
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	assert errors


def test_a_postponed_removal_is_logged_once_per_backup(job, monkeypatch):
	_three_versions(job)
	lines = _logged_lines(monkeypatch)
	with rv.JobLock('job'):
		# over the size limit, the inode limit and the version count: each retention loop tries to remove a version
		run_backup(job, _change(job, 3), keep_n_versions=3, backup_size_limit='1B,i1')
	assert _numbers(job) == [0, 1, 2, 3]
	assert len([line for line in lines if line.startswith('Postponing removal of the oldest version')]) == 1


def test_the_lock_files_are_never_opened_through_a_symlink(job, tmp_path, monkeypatch):
	_three_versions(job)
	_state()
	elsewhere = tmp_path / 'elsewhere'
	os.symlink(elsewhere, rv.job_lock_path('job', 'history'))
	# pruning is postponed, as for any lock that cannot be checked, and a command cannot take it
	run_backup(job, _change(job, 3), keep_n_versions=3)
	assert _numbers(job) == [0, 1, 2, 3]
	with pytest.raises(OSError) as raised:
		with rv.JobLock('job'):
			pass
	assert raised.value.errno == errno.ELOOP
	# a backup lock through a symlink postpones the backup
	os.remove(rv.job_lock_path('job', 'backup'))
	os.symlink(elsewhere, rv.job_lock_path('job', 'backup'))
	lines = _logged_lines(monkeypatch)
	locks = rv.BackupLocks('job')
	polls = iter(range(3))
	assert locks.take(lambda: next(polls, None) is not None) is False
	assert [line for line in lines if line.startswith('Backup postponed')] == [f'Backup postponed: cannot check the backup lock {rv.job_lock_path("job", "backup")}: {os.strerror(errno.ELOOP)}']
	assert not os.path.lexists(elsewhere)


@pytest.mark.parametrize('make_failing', [_failing_history_open, _failing_history_flock])
def test_a_history_lock_that_cannot_be_checked_raises_an_hourly_marker_after_the_grace(tmp_path, monkeypatch, capsys, make_failing):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 900)
	monkeypatch.setattr(rv, 'DISK_WAIT_REPEAT_SECONDS', 3600)
	_state()
	failing = [True]
	make_failing(monkeypatch, failing=failing)
	def prune_at(now, job_name='job'):
		capsys.readouterr()
		assert rv.prune_oldest(OrderedDict(), job_name, '/monitor', clock=lambda: now) == (0, 0)
		return alerting_lines(capsys.readouterr().out)
	assert prune_at(0) == [] and prune_at(899) == []
	markers = prune_at(900)
	lock_path = rv.job_lock_path('job', 'history')
	assert len(markers) == 1 and f'reverberator job job FAILED: cannot check the history lock {lock_path}: ' in markers[0]
	error = os.strerror(errno.EACCES if make_failing is _failing_history_open else errno.ENOLCK)
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


def test_command_lock_default_stream_is_the_stderr_of_the_moment(tmp_path, capsys):
	daemon = Held('history', fcntl.LOCK_EX)
	entered = threading.Event()
	def command():
		with rv.JobLock('job'):
			entered.set()
	thread = threading.Thread(target=command)
	thread.start()
	try:
		assert not entered.wait(0.3)
		assert 'Waiting for reverberator to finish removing an old version of job' in capsys.readouterr().err
	finally:
		daemon.release()
		thread.join(5)
	assert entered.is_set()


def test_pruning_holds_the_history_lock_while_the_oldest_version_is_removed(job, monkeypatch):
	_three_versions(job)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	_state()
	seen = []
	real = rv.prune_tree_version
	def stepping(vault_info_dict, *args, **kwargs):
		# what history or a restore starting now finds: the lock taken, so it waits for this removal
		seen.append('free' if _free('history') else 'held')
		return real(vault_info_dict, *args, **kwargs)
	monkeypatch.setattr(rv, 'prune_tree_version', stepping)
	assert rv.prune_oldest(info, 'job', job.monitor, on_tree=True) != (0, 0)
	assert seen == ['held'] and _numbers(job) == [1, 2]
	# and released afterwards
	with rv.JobLock('job'):
		pass


def test_a_batch_holds_the_backup_and_restore_locks_from_its_prunes_to_its_commit(job, monkeypatch):
	_three_versions(job)
	_state()
	seen = {}
	real_prune, real_commit = rv.prune_oldest, rv.place_change_list
	real_compare = rv.delta_generate_backup_entries
	def comparing(*args, **kwargs):
		seen['comparison'] = (_free('backup'), _free('restore'))
		return real_compare(*args, **kwargs)
	def pruning(*args, **kwargs):
		seen['prune'] = (_free('backup'), _free('restore'))
		return real_prune(*args, **kwargs)
	def committing(*args, **kwargs):
		seen['commit'] = (_free('backup'), _free('restore'))
		return real_commit(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', comparing)
	monkeypatch.setattr(rv, 'prune_oldest', pruning)
	monkeypatch.setattr(rv, 'place_change_list', committing)
	# the vault is known already, as it is to every batch after a job's start
	vault_info = rv.get_vault_info(job.job_vault)
	_change(job, 3)
	run_backup(job, keep_n_versions=3, vaultInfo=vault_info)
	assert seen == {'comparison': (True, True), 'prune': (False, False), 'commit': (False, False)}
	assert _free('backup') and _free('restore')


def test_a_batch_waits_while_a_restore_copies_and_runs_once_it_ends(job, monkeypatch):
	_three_versions(job)
	lines = _logged_lines(monkeypatch)
	restore = Held('restore')
	backup = Backup(job, _change(job, 3), keep_n_versions=3)
	try:
		wait_until(lambda: WAITING in lines, message='the batch never said it waits')
		time.sleep(0.3)
		assert backup.is_alive() and _numbers(job) == [0, 1, 2]
		# a waiting batch holds the backup lock, so restores starting now wait for it
		assert not _free('backup')
	finally:
		restore.release()
	backup.join(10)
	assert backup.error is None and backup.committed is True
	assert _numbers(job) == [1, 2, 3]
	assert lines.count(WAITING) == 1
	assert _free('backup') and _free('restore')


def test_a_batch_never_blocks_history(job, capsys):
	_state()
	locks = rv.BackupLocks('job')
	assert locks.take()
	try:
		entered = threading.Event()
		def history():
			with rv.JobLock('job', stream=sys.stderr):
				entered.set()
		thread = threading.Thread(target=history)
		thread.start()
		assert entered.wait(5)
		thread.join(5)
		assert 'Waiting' not in capsys.readouterr().err
	finally:
		locks.release()
	assert _free('backup') and _free('restore')


def test_a_stop_while_waiting_returns_at_once_and_keeps_the_batch_queued(job, monkeypatch, tmp_path):
	_three_versions(job)
	lines = _logged_lines(monkeypatch)
	restore = []
	real_do_backup = rv.do_backup
	def restore_starts_first(*args, **kwargs):
		# a restore takes its lock once the job's start has scanned the vault
		restore.append(Held('restore'))
		return real_do_backup(*args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', restore_starts_first)
	_change(job, 3)
	to_process = rv.ChangeEventQueue(job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	monitor_fs_flag = threading.Event()
	monitor_fs_flag.set()
	stopped = []
	def stop():
		wait_until(lambda: WAITING in lines, message='the batch never said it waits')
		stopped.append(time.monotonic())
		rv.GREEN_LIGHT.clear()
	stopper = threading.Thread(target=stop, daemon=True)
	stopper.start()
	try:
		rv.backuper('job', to_process, threading.Lock(), job.monitor, job.vault, 'N/A', threading.Event(), monitor_fs_flag, keep_n_versions=3)
		returned = time.monotonic()
	finally:
		rv.GREEN_LIGHT.set()
		for held in restore:
			held.release()
	stopper.join(5)
	assert stopped and returned - stopped[0] < 2
	assert _numbers(job) == [0, 1, 2]
	assert [event.path for event in to_process.take()] == [os.path.join(job.monitor, 'a.txt')]
	assert _free('backup') and _free('restore')


def test_a_job_start_scans_the_vault_under_the_locks(job, monkeypatch):
	_three_versions(job)
	_state()
	seen = []
	real_scan = rv.get_vault_info
	def scanning(*args, **kwargs):
		seen.append((_free('backup'), _free('restore')))
		return real_scan(*args, **kwargs)
	monkeypatch.setattr(rv, 'get_vault_info', scanning)
	monitor_fs_flag = threading.Event()
	monitor_fs_flag.set()
	# the start's scan is the batch's too: the stop comes as it compares, which scans nothing more
	real_compare = rv.delta_generate_backup_entries
	def comparing(*args, **kwargs):
		rv.GREEN_LIGHT.clear()
		return real_compare(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', comparing)
	to_process = rv.ChangeEventQueue(job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'full_scan', job.monitor, None))
	try:
		rv.backuper('job', to_process, threading.Lock(), job.monitor, job.vault, 'N/A', threading.Event(), monitor_fs_flag)
	finally:
		rv.GREEN_LIGHT.set()
	assert seen == [(False, False)]
	assert _free('backup') and _free('restore')


def test_a_restore_starting_while_a_batch_waits_waits_for_that_batch(job, monkeypatch):
	_three_versions(job)
	lines = _logged_lines(monkeypatch)
	copying = Held('restore')
	backup = Backup(job, _change(job, 3), keep_n_versions=3)
	entered = []
	def second_restore():
		with rv.command_restore_locks('job'):
			entered.append(_numbers(job))
	thread = threading.Thread(target=second_restore, daemon=True)
	try:
		wait_until(lambda: WAITING in lines, message='the batch never said it waits')
		thread.start()
		time.sleep(0.3)
		assert not entered and backup.is_alive()
	finally:
		copying.release()
	backup.join(10)
	thread.join(10)
	assert backup.committed is True
	# the second restore came in only after the batch committed and pruned
	assert entered == [[1, 2, 3]]
	assert _free('backup') and _free('restore')


@pytest.mark.parametrize('kind', ['backup', 'restore'])
def test_a_lock_that_cannot_be_checked_postpones_the_backup_with_an_hourly_marker(job, monkeypatch, capsys, kind):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 900)
	monkeypatch.setattr(rv, 'DISK_WAIT_REPEAT_SECONDS', 3600)
	_state()
	lock_path = rv.job_lock_path('job', kind)
	failing = [True]
	real_open = os.open
	def fake_open(path, *args, **kwargs):
		if path == lock_path and failing[0]:
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, *args, **kwargs)
	monkeypatch.setattr(os, 'open', fake_open)
	# one poll per step of the fake clock, until it runs out
	clock = [0]
	steps = []
	def running():
		if not steps:
			return False
		clock[0] = steps.pop(0)
		return True
	locks = rv.BackupLocks('job', clock=lambda: clock[0])
	def take_at(*times):
		capsys.readouterr()
		steps.extend(times)
		assert locks.take(running) is False
		return alerting_lines(capsys.readouterr().out)
	assert take_at(0, 600, 899) == []
	markers = take_at(900, 1000, 4499)
	assert len(markers) == 1 and f'reverberator job job FAILED: cannot check the {kind} lock {lock_path}: ' in markers[0]
	assert os.strerror(errno.EACCES) in markers[0] and markers[0].count('; backup postponed') == 1
	assert len(take_at(4500)) == 1 and take_at(5000) == []
	# checked again, it starts a new grace when it next fails
	failing[0] = False
	steps.append(6000)
	assert locks.take(running) is True
	locks.release()
	failing[0] = True
	assert take_at(6001, 6900) == [] and len(take_at(6901)) == 1
	# the batch itself: nothing is backed up while it cannot be checked, and it goes on once it can
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0)
	failing[0] = False
	seed_monitor(job, {'a.txt': 'data'})
	run_backup(job)
	failing[0] = True
	lines = _logged_lines(monkeypatch)
	backup = Backup(job, _change(job, 1))
	try:
		wait_until(lambda: any(line.startswith('Backup postponed') for line in lines), message='the batch never said it is postponed')
		time.sleep(0.3)
		assert backup.is_alive() and _numbers(job) == [0]
	finally:
		failing[0] = False
	backup.join(10)
	assert backup.committed is True and _numbers(job) == [0, 1]
	assert [line for line in lines if line.startswith('Backup postponed')] == [f'Backup postponed: cannot check the {kind} lock {lock_path}: {os.strerror(errno.EACCES)}']
	assert 'FAILED' in capsys.readouterr().out


def _restore(tmp_path, capsys, *argv):
	capsys.readouterr()
	code = rv.run_command(['restore', *argv, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', str(tmp_path / 'state')])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def test_a_restore_at_its_prompt_holds_only_the_history_lock(job, tmp_path, capsys, monkeypatch):
	_three_versions(job)
	write_rule(job)
	seen = []
	real_choose = rv.choose_version
	def choosing(*args, **kwargs):
		# a batch can run now; pruning cannot
		seen.append((_free('backup'), _free('restore'), _free('history')))
		return real_choose(*args, **kwargs)
	monkeypatch.setattr(rv, 'choose_version', choosing)
	real_restore = rv.restore_entry
	def copying(*args, **kwargs):
		seen.append((_free('backup'), _free('restore'), _free('history')))
		return real_restore(*args, **kwargs)
	monkeypatch.setattr(rv, 'restore_entry', copying)
	out = tmp_path / 'out'
	out.mkdir()
	code, _, err = _restore(tmp_path, capsys, f'{job.monitor}/a.txt', str(out), '--version', '1')
	assert (code, err) == (0, '')
	# at its copy it holds the restore lock, but not the backup lock, which a waiting batch takes
	assert seen == [(True, True, False), (True, False, False)]


def test_a_restore_reads_the_vault_again_once_it_holds_the_lock(job, tmp_path, capsys, monkeypatch):
	_three_versions(job)
	write_rule(job)
	real_locks = rv.command_restore_locks
	between = []
	def meanwhile(*args, **kwargs):
		# between the prompt and the lock
		between.pop(0)()
		return real_locks(*args, **kwargs)
	monkeypatch.setattr(rv, 'command_restore_locks', meanwhile)
	# a backup commits: the restore sees the version it made
	listed = []
	real_list = rv.list_versions
	def listing(job_vault):
		listed.append([v.number for v in real_list(job_vault)])
		return real_list(job_vault)
	monkeypatch.setattr(rv, 'list_versions', listing)
	between.append(lambda: run_backup(job, _change(job, 3)))
	out = tmp_path / 'out'
	out.mkdir()
	code, _, err = _restore(tmp_path, capsys, f'{job.monitor}/a.txt', str(out), '--version', '1')
	assert (code, err) == (0, '')
	assert listed == [[0, 1, 2], [0, 1, 2, 3]]
	with open(out / 'a.txt', encoding='utf-8') as f:
		assert f.read() == 'data 1'
	# the version picked goes: the restore says so and writes nothing
	v0 = rv.list_versions(job.job_vault)[0]
	def removed():
		shutil.rmtree(v0.path)
		os.remove(v0.change_list)
	between.append(removed)
	out = tmp_path / 'out0'
	out.mkdir()
	code, stdout, err = _restore(tmp_path, capsys, f'{job.monitor}/a.txt', str(out), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and stdout == ''
	assert f'V0 ({v0.name}) is no longer kept in the vault {job.job_vault}: run the restore again to pick another version' in err
	assert os.listdir(out) == []


def _status_job(tmp_path, job, capsys, *extra):
	capsys.readouterr()
	code = rv.run_command(['status', '--rule', job.rule_path, '--state_dir', str(tmp_path / 'state'), *extra])
	return code, capsys.readouterr().out


def _board(tmp_path, job):
	write_rule(job)
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), job.rule_path)
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	control.set_state('running')
	return control


def _record(tmp_path, job):
	import json
	with open(tmp_path / 'state' / f'job-{job.job_name}.json') as f:
		return json.load(f)


def test_a_batch_waiting_for_a_copying_restore_shows_waiting_in_status(job, tmp_path, capsys):
	import json
	control = _board(tmp_path, job)
	copying = Held('restore')
	locks = rv.BackupLocks('job', job=control)
	taken = []
	thread = threading.Thread(target=lambda: taken.append(locks.take()), daemon=True)
	thread.start()
	reason = 'a restore of job is copying'
	try:
		wait_until(lambda: _record(tmp_path, job)['state'] == 'waiting', message='status never showed the job waiting')
		assert _record(tmp_path, job)['detail'] == reason
		code, out = _status_job(tmp_path, job, capsys)
		assert code == 0 and 'waiting since' in out and reason in out
		code, out = _status_job(tmp_path, job, capsys, '--json')
		listed = json.loads(out)['jobs'][0]
		assert listed['state'] == 'waiting' and listed['detail'] == reason
	finally:
		copying.release()
	thread.join(10)
	assert taken == [True]
	locks.release()
	assert _record(tmp_path, job)['state'] == 'running'
	code, out = _status_job(tmp_path, job, capsys, '--json')
	assert json.loads(out)['jobs'][0]['state'] == 'running'


def test_a_lock_that_cannot_be_checked_shows_the_job_waiting_with_the_error(job, tmp_path, monkeypatch):
	control = _board(tmp_path, job)
	_state()
	lock_path = rv.job_lock_path('job', 'restore')
	failing = [True]
	real_open = os.open
	def fake_open(path, *args, **kwargs):
		if path == lock_path and failing[0]:
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, *args, **kwargs)
	monkeypatch.setattr(os, 'open', fake_open)
	locks = rv.BackupLocks('job', job=control)
	taken = []
	thread = threading.Thread(target=lambda: taken.append(locks.take()), daemon=True)
	thread.start()
	try:
		wait_until(lambda: _record(tmp_path, job)['state'] == 'waiting', message='status never showed the job waiting')
		detail = _record(tmp_path, job)['detail']
		assert detail == f'cannot check the restore lock {lock_path}: {os.strerror(errno.EACCES)}'
	finally:
		failing[0] = False
	thread.join(10)
	assert taken == [True]
	locks.release()
	assert _record(tmp_path, job)['state'] == 'running'


def test_a_job_that_stops_running_while_its_batch_waits_returns_at_once_with_the_batch_queued(job, tmp_path, monkeypatch):
	_three_versions(job)
	control = _board(tmp_path, job)
	lines = _logged_lines(monkeypatch)
	copying = Held('restore')
	# the daemon keeps running (GREEN_LIGHT): only the job's own watcher fails
	backup = Backup(job, _change(job, 3), keep_n_versions=3, control=control)
	try:
		wait_until(lambda: WAITING in lines and _record(tmp_path, job)['state'] == 'waiting', message='the batch never waited')
		control.fail('the watcher failed')
		backup.join(5)
		assert not backup.is_alive(), 'the wait went on past the job stopping'
	finally:
		copying.release()
	assert backup.error is None and backup.committed is False
	assert _numbers(job) == [0, 1, 2]
	assert _record(tmp_path, job)['state'] != 'waiting'
	assert _free('backup') and _free('restore')


@pytest.mark.parametrize('kind, purpose', [('backup', 'lets a backup that waits for a restore go first'),
		('history', 'keeps its versions from being pruned while they are read'), ('restore', 'keeps the vault unchanged while a restore copies')])
def test_a_command_that_cannot_take_a_lock_says_what_the_lock_is_for(tmp_path, monkeypatch, kind, purpose):
	_state()
	os.symlink(tmp_path / 'elsewhere', rv.job_lock_path('job', kind))
	with pytest.raises(rv.CommandError) as raised:
		with rv.command_lock('job', kind):
			pass
	assert str(raised.value).startswith(f'Cannot take the {kind} lock of job job, which {purpose}: ')
