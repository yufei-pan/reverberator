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
	thread = threading.Thread(target=rv.run_job, args=(rv.JobControl('j'), start_attempt))
	thread.start()
	wait_until(lambda: seen.append(read_job('j')) or (seen[-1] or {}).get('state') == 'retrying')
	retrying = read_job('j')
	assert retrying['detail'] == 'disk gone' and retrying['failures'] == 1 and retrying['retry_at'] > time.time() - 0.01
	thread.join(10)
	stopped = read_job('j')
	assert stopped['state'] == 'stopped' and stopped['detail'] == 'bad pattern'


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
