import json
import os
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_rule, wait_for_committed_count, wait_until
from tests.test_jobs import _attempts


def _read(path):
	try:
		with open(path) as f:
			return json.load(f)
	except (OSError, ValueError):
		return None


@pytest.fixture
def board(tmp_path):
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), '/r.tsv')
	return rv.STATUS_BOARD


@pytest.fixture
def read_job(tmp_path):
	return lambda name: _read(tmp_path / 'state' / f'job-{name}.json')


def test_status_board_writes_the_daemon_record(tmp_path):
	rv.StatusBoard(str(tmp_path / 's'), '/etc/r.tsv')
	record = json.load(open(tmp_path / 's' / 'daemon.json'))
	assert record['pid'] == os.getpid() and record['start_ticks'] == rv.process_start_ticks(os.getpid())
	assert record['version'] == rv.__version__ and record['rule_path'] == '/etc/r.tsv'


def test_status_board_never_raises(tmp_path):
	(tmp_path / 'file').write_text('x')
	board = rv.StatusBoard(str(tmp_path / 'file'), '/r.tsv')
	board.write_job('j', {'state': 'running'})


def test_state_dir_path_prefers_override_then_environment(monkeypatch):
	monkeypatch.setenv('REVERB_STATE_DIR', '/env')
	assert rv.state_dir_path('/x') == '/x' and rv.state_dir_path() == '/env'
	monkeypatch.delenv('REVERB_STATE_DIR')
	assert rv.state_dir_path() == rv.DEFAULT_STATE_DIR


def test_process_start_ticks_is_none_for_a_missing_process():
	assert rv.process_start_ticks(2 ** 22 + 12345) is None


def test_waits_publish_waiting_until_the_last_ends(board, read_job):
	job = rv.JobControl('j')
	job.start_attempt()
	job.set_state('running')
	a = job.begin_wait('/v', 'vault filesystem not ready')
	b = job.begin_wait('/m', 'monitored filesystem not ready')
	assert read_job('j')['state'] == 'waiting' and read_job('j')['detail'] == '/v: vault filesystem not ready'
	job.end_wait(a)
	assert read_job('j')['state'] == 'waiting' and read_job('j')['detail'].startswith('/m')
	job.end_wait(b)
	assert read_job('j')['state'] == 'running'


def test_wait_for_path_reports_waiting(tmp_path, board, read_job, poll_fast):
	flag = threading.Event()
	flag.set()
	path = str(tmp_path / 'later')
	job = rv.JobControl('j')
	job.start_attempt()
	job.set_state('running')
	result = []
	thread = threading.Thread(target=lambda: result.append(rv.wait_for_path(job, flag, path, 'vault filesystem not ready')))
	thread.start()
	wait_until(lambda: (read_job('j') or {}).get('state') == 'waiting')
	assert read_job('j')['detail'] == f'{path}: vault filesystem not ready'
	os.makedirs(path)
	thread.join(5)
	assert result == [True] and read_job('j')['state'] == 'running'


def test_run_job_publishes_retrying_then_stopped(board, read_job, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.3)
	start_attempt, _ = _attempts([('fail', 'disk gone'), ('fail', 'bad pattern', True)])
	seen = []

	def retrying():
		# the time first: the record read after it was still the one waiting for its retry
		seen.append((time.time(), read_job('j')))
		return (seen[-1][1] or {}).get('state') == 'retrying'
	thread = threading.Thread(target=rv.run_job, args=(rv.JobControl('j'), start_attempt))
	thread.start()
	wait_until(retrying)
	read_at, record = seen[-1]
	assert record['detail'] == 'disk gone' and record['failures'] == 1 and record['retry_at'] > read_at
	thread.join(10)
	stopped = read_job('j')
	assert stopped['state'] == 'stopped' and stopped['detail'] == 'bad pattern'


def test_a_monitor_gate_wait_shows_what_it_waits_for_now(tmp_path, board, read_job, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 60)
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda path: [])
	path = str(tmp_path / 'late')
	gate = rv.MonitorGate(path, threading.Event(), 'auto')
	job = rv.JobControl('j')
	job.start_attempt()
	job.set_state('starting')
	result = []
	thread = threading.Thread(target=lambda: result.append(gate.resolve(job)), daemon=True)
	thread.start()
	try:
		wait_until(lambda: (read_job('j') or {}).get('detail') == f'{path}: monitored path not there yet')
		since = read_job('j')['since']
		os.makedirs(path)
		# the path is there, but its disk cannot be told yet
		wait_until(lambda: (read_job('j') or {}).get('detail') == f'{path}: monitored filesystem signature unknown')
		assert read_job('j')['state'] == 'waiting' and read_job('j')['since'] == since
	finally:
		job.fail('stop')
		thread.join(timeout=2)
	assert result == [False] and read_job('j')['state'] == 'starting'


def test_a_stalled_status_write_holds_up_no_other_job_thread(board, read_job):
	job = rv.JobControl('j')
	job.start_attempt()
	writing, release = threading.Event(), threading.Event()
	write_job = board.write_job
	def stalled(name, record):
		if record['state'] == 'running':
			writing.set()
			release.wait(5)
		write_job(name, record)
	board.write_job = stalled
	publisher = threading.Thread(target=job.set_state, args=('running',))
	publisher.start()
	later = threading.Thread(target=job.set_state, args=('stopped', 'bad pattern'))
	try:
		assert writing.wait(2)
		# fail() and should_run() take the job's lock, which no status write holds
		failed = threading.Thread(target=job.fail, args=('disk gone',), daemon=True)
		failed.start()
		failed.join(1)
		assert not failed.is_alive() and not job.should_run()
		later.start()
	finally:
		release.set()
		publisher.join(5)
		if later.ident is not None:
			later.join(5)
	# the records are written in the order they were taken
	assert read_job('j')['state'] == 'stopped'


def test_status_board_logs_one_error_for_writes_failing_together(tmp_path, capsys):
	main = threading.current_thread()
	class RacingBoard(rv.StatusBoard):
		# another job's write fails while this one has just found no error logged yet
		@property
		def _failed(self):
			failed = self.__dict__.get('failed', False)
			if not failed and threading.current_thread() is main and self.state_dir == str(blocker):
				other = threading.Thread(target=self.write_job, args=('k', {}))
				other.start()
				other.join(0.3)
				self.others.append(other)
			return failed
		@_failed.setter
		def _failed(self, value):
			self.__dict__['failed'] = value
	blocker = tmp_path / 'file'
	blocker.write_text('x')
	board = RacingBoard(str(tmp_path / 'state'), '/r.tsv')
	board.others = []
	board.state_dir = str(blocker)
	board.write_job('j', {})
	for other in board.others:
		other.join(5)
	assert capsys.readouterr().out.count('Cannot write status files') == 1


def test_mark_committed_records_last_success(board, read_job):
	job = rv.JobControl('j')
	job.set_state('running')
	assert read_job('j')['last_success'] is None
	before = time.time()
	job.mark_committed()
	assert read_job('j')['last_success'] >= before


@pytest.mark.process
def test_daemon_writes_status_files(job, run_reverberator, tmp_path):
	seed_monitor(job, {'a.txt': 'a'})
	write_rule(job)
	run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1)
	state = tmp_path / 'state'
	wait_until(lambda: (_read(state / 'job-job.json') or {}).get('last_success'))
	assert _read(state / 'daemon.json')['rule_path'] == os.path.abspath(job.rule_path)
	assert _read(state / 'job-job.json')['state'] == 'running'
