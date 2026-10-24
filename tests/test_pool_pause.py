import json
import os
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import (committed_versions, latest_version, seed_monitor, wait_for_committed_count, wait_until,
	write_incomplete_version)

pytestmark = pytest.mark.unit


@pytest.fixture
def grace(monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)


@pytest.fixture
def board(tmp_path):
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), '/r.tsv')
	return rv.STATUS_BOARD


class Output:
	'''What capsys captured so far, kept across reads.'''
	def __init__(self, capsys):
		self.capsys = capsys
		self.text = ''

	def __call__(self) -> str:
		out = self.capsys.readouterr()
		self.text += out.out + out.err
		return self.text


@pytest.fixture
def output(capsys):
	return Output(capsys)


def _state(tmp_path, name='job'):
	try:
		with open(tmp_path / 'state' / f'job-{name}.json') as f:
			return json.load(f)
	except (OSError, ValueError):
		return {}


def _v0(job):
	_, manifest, _ = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()


def _run_backuper(job, control, to_process=None, to_process_lock=None, to_process_flag=None):
	to_process = rv.ChangeEventQueue(job.monitor) if to_process is None else to_process
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, to_process,
		threading.Lock() if to_process_lock is None else to_process_lock, job.monitor, job.vault, 'N/A',
		threading.Event() if to_process_flag is None else to_process_flag, flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	return thread


def _control(job):
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	return control


def _stop(control, *threads):
	control.fail('test done')
	for thread in threads:
		thread.join(timeout=5)
		assert not thread.is_alive()


def _marker(path, reason):
	return f'reverberator job job FAILED: waiting 0 min for {path}: {reason}'


def _goes_on(path):
	return f'reverberator job job goes on: {path} is ready again after 0 min'


def test_a_missing_vault_disk_pauses_the_job_with_the_waiting_marker(job, fake_pool, grace, board, output, tmp_path):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_incomplete_version(job, 1, {'a.txt': 'partial'})
	# a change since V0, so the comparison once the disk is back commits a version
	seed_monitor(job, {'b.txt': 'b'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		reason = f'disk {a} of pool {job.vault} is not mounted'
		wait_until(lambda: _marker(job.vault, reason) in output(), timeout=5, message='no waiting marker')
		assert os.path.isdir(orphan), 'the vault was scanned while a disk is out'
		assert len(committed_versions(job)) == 1
		assert _state(tmp_path)['state'] == 'waiting' and _state(tmp_path)['detail'] == f'{job.vault}: {reason}'
		fake_pool.mount(a)
		wait_until(lambda: not os.path.lexists(orphan), timeout=5, message='the orphan stayed')
		wait_for_committed_count(job, 2)
		wait_until(lambda: _goes_on(job.vault) in output(), timeout=5, message='no goes on line')
		assert output().count(_goes_on(job.vault)) == 1
	finally:
		_stop(control, thread)


def test_a_missing_monitored_disk_pauses_the_backup_but_not_the_vault_scan(job, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_incomplete_version(job, 1, {'a.txt': 'partial'})
	# a change since V0, so the comparison once the disk is back commits a version
	seed_monitor(job, {'b.txt': 'b'})
	m, _ = fake_pool.add(job.monitor, ['m1', 'm2'])
	fake_pool.drop(m)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: not os.path.lexists(orphan), timeout=5, message='the vault was not scanned')
		reason = f'disk {m} of pool {job.monitor} is not mounted'
		wait_until(lambda: _marker(job.monitor, reason) in output(), timeout=5, message='no waiting marker')
		assert len(committed_versions(job)) == 1
		fake_pool.mount(m)
		wait_for_committed_count(job, 2)
	finally:
		_stop(control, thread)


def test_the_watcher_keeps_queuing_while_the_vault_pool_is_out(job, fake_pool, grace, output, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	to_process_flag = threading.Event()
	control = _control(job)
	watched = []
	real_init = rv.initializeFolderWatchers
	def counting_init(inotify_obj, path, *args, **kwargs):
		result = real_init(inotify_obj, path, *args, **kwargs)
		if path == job.monitor:
			watched.append(result)
		return result
	monkeypatch.setattr(rv, 'initializeFolderWatchers', counting_init)
	monitor_flag = threading.Event()
	monitor_flag.set()
	watcher = threading.Thread(target=rv.watcher, args=(monitor_flag, job.monitor, to_process, lock, to_process_flag,
		rv.inotify_resource_manager(), 0, 60), kwargs=dict(job=control), daemon=True)
	watcher.start()
	backuper = _run_backuper(job, control, to_process, lock, to_process_flag)
	try:
		wait_until(lambda: watched, timeout=5, message='root not watched')
		wait_until(lambda: _marker(job.vault, f'disk {a} of pool {job.vault} is not mounted') in output(), timeout=5,
			message='no waiting marker')
		with open(os.path.join(job.monitor, 'new.txt'), 'w') as f:
			f.write('new')
		def queued():
			with lock:
				return any(event.path.endswith('new.txt') for event in list(to_process))
		wait_until(queued, timeout=5, message='the event was not queued')
		assert not committed_versions(job)
		fake_pool.mount(a)
		wait_for_committed_count(job, 1)
		assert os.path.isfile(os.path.join(latest_version(job).path, 'new.txt'))
	finally:
		_stop(control, watcher, backuper)


def test_a_disk_dropped_between_batches_pauses_the_next_one(job, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	to_process_flag = threading.Event()
	control = _control(job)
	thread = _run_backuper(job, control, to_process, lock, to_process_flag)
	try:
		wait_for_committed_count(job, 1)
		fake_pool.drop(a)
		seed_monitor(job, {'b.txt': 'b'})
		with lock:
			to_process.append(rv.ChangeEvent(time.monotonic(), False, 'create', os.path.join(job.monitor, 'b.txt'), None))
		to_process_flag.set()
		wait_until(lambda: _marker(job.vault, f'disk {a} of pool {job.vault} is not mounted') in output(), timeout=5,
			message='no waiting marker')
		assert len(committed_versions(job)) == 1
		fake_pool.mount(a)
		wait_for_committed_count(job, 2)
		assert os.path.isfile(os.path.join(latest_version(job).path, 'b.txt'))
	finally:
		_stop(control, thread)


def _wait_in_thread(control, flag, path, alert, results):
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, path,
		'monitored filesystem not ready', alert=alert)), daemon=True)
	thread.start()
	return thread


@pytest.mark.parametrize('first_alert', [True, False])
def test_a_lost_root_alerts_once_with_a_batch_pending(tmp_path, grace, output, first_alert):
	# the watcher's lost-root wait (alert=True), or its start-up wait (alert=False), and the batch loop's monitored wait
	path = str(tmp_path / 'root')
	control = rv.JobControl('job')
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	results = []
	first = _wait_in_thread(control, flag, path, first_alert, results)
	second = None
	try:
		wait_until(lambda: len(control._waits) == 1, timeout=5, message='first wait not begun')
		second = _wait_in_thread(control, flag, path, True, results)
		wait_until(lambda: len(control._waits) == 2, timeout=5, message='second wait not begun')
		first_token, second_token = (wait[0] for wait in control._waits)
		assert control.alerts(first_token) is first_alert and control.alerts(second_token) is not first_alert
		marker = _marker(path, 'monitored filesystem not ready')
		wait_until(lambda: marker in output(), timeout=5, message='no waiting marker')
		time.sleep(0.4)
		assert output().count(marker) == 1
		os.makedirs(path)
		first.join(timeout=5)
		second.join(timeout=5)
		assert results == [True, True]
		assert output().count(_goes_on(path)) == 1
	finally:
		_stop(control, *(thread for thread in (first, second) if thread is not None))


def test_a_job_off_the_pool_runs_while_the_pool_is_out(job, tmp_path, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	other = str(tmp_path / 'other_pool')
	a, _ = fake_pool.add(other, ['a', 'b'])
	fake_pool.drop(a)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_for_committed_count(job, 1)
		time.sleep(0.3)
		assert not [line for line in output().splitlines() if 'FAILED: waiting' in line and str(tmp_path) in line]
		assert fake_pool.reads == 0
	finally:
		_stop(control, thread)


def test_a_wait_that_never_alerted_ends_silently(job, fake_pool, poll_fast, monkeypatch, output):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 30)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	control = rv.JobControl('job')
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	results = []
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, job.vault,
		'vault filesystem not ready')), daemon=True)
	thread.start()
	time.sleep(0.3)
	assert thread.is_alive(), 'the wait ended with a disk out'
	fake_pool.mount(a)
	thread.join(timeout=5)
	assert results == [True]
	assert 'FAILED: waiting' not in output() and 'goes on' not in output()
