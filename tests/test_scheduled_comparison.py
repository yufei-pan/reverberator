import os
import shutil
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, latest_version, wait_until

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def recorded_backups(monkeypatch):
	'''(kind, start, end) of each do_backup() call, kind 'whole' or 'batch', times monotonic.'''
	calls = []
	real = rv.do_backup
	def recording(entries, *args, **kwargs):
		# judged before the call: a whole comparison fills entries with what it finds
		kind = 'batch' if entries or kwargs.get('touched') is not None else 'whole'
		start = time.monotonic()
		try:
			return real(entries, *args, **kwargs)
		finally:
			calls.append((kind, start, time.monotonic()))
	monkeypatch.setattr(rv, 'do_backup', recording)
	return calls


def start_backuper(job, interval):
	'''The job's backuper as the daemon runs it, with no watcher: (thread, queue, lock, flag).'''
	queue, lock, flag = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag),
		kwargs=dict(job=control, full_comparison_interval=interval), daemon=True)
	thread.start()
	return thread, queue, lock, flag


def stop_backuper(thread):
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=5)
	alive = thread.is_alive()
	rv.GREEN_LIGHT.set()
	assert not alive


def test_a_job_with_an_interval_compares_the_whole_tree_that_often(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, *_ = start_backuper(job, 0.3)
	try:
		wait_until(lambda: len(calls) >= 3, timeout=10, message='no scheduled full comparison')
	finally:
		stop_backuper(thread)
	assert [kind for kind, _, _ in calls[:3]] == ['whole'] * 3
	# counted from the end of the one before
	assert all(later[1] - earlier[2] >= 0.3 for earlier, later in zip(calls, calls[1:3]))


def test_a_job_without_an_interval_never_compares_on_its_own(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, *_ = start_backuper(job, 0)
	try:
		wait_until(lambda: len(calls) == 1, message='no start comparison')
		time.sleep(1)
	finally:
		stop_backuper(thread)
	assert [kind for kind, _, _ in calls] == ['whole']


@pytest.mark.parametrize('interval', [1e25])
def test_a_huge_interval_neither_raises_nor_compares_early(job, monkeypatch, interval):
	# a rule cell such as 99999999999999999999w reads as about 6e25 s, far above threading.TIMEOUT_MAX
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, *_ = start_backuper(job, interval)
	try:
		wait_until(lambda: len(calls) == 1, message='no start comparison')
		time.sleep(0.5)
		assert thread.is_alive()
	finally:
		stop_backuper(thread)
	assert [kind for kind, _, _ in calls] == ['whole']


def test_a_due_comparison_is_not_held_back_by_a_signalled_batch(job, monkeypatch):
	# a busy job: the watcher has signalled again by the time each batch ends, so the idle wait never waits
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, queue, lock, flag = start_backuper(job, 0.4)
	real = rv.do_backup
	def slow_batch(entries, *args, **kwargs):
		if entries:
			time.sleep(0.6)
			open(os.path.join(job.monitor, 'b.txt'), 'w').write('b2')
			with lock:
				queue.append(rv.ChangeEvent(time.monotonic(), False, 'modify', os.path.join(job.monitor, 'b.txt'), None))
			flag.set()
		return real(entries, *args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', slow_batch)
	try:
		wait_until(lambda: len(calls) == 1, message='no start comparison')
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('a2')
		with lock:
			queue.append(rv.ChangeEvent(time.monotonic(), False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
		flag.set()
		wait_until(lambda: len(calls) >= 3, timeout=10, message='no third backup')
	finally:
		stop_backuper(thread)
	# the take after the batch is the due comparison, which absorbs the event queued meanwhile
	assert [kind for kind, _, _ in calls[:3]] == ['whole', 'batch', 'whole']
	assert open(os.path.join(latest_version(job).path, 'b.txt')).read() == 'b2'


def test_a_huge_interval_is_never_passed_to_a_wait(job, monkeypatch):
	# every Event.wait timeout of the backuper's thread stays small: 6.048e25 s is what a cell of 99999999999999999999w reads as
	seen = []
	real_wait = threading.Event.wait
	def wait(self, timeout=None):
		if threading.current_thread().name == 'scheduled-backuper':
			seen.append(timeout)
		return real_wait(self, timeout)
	monkeypatch.setattr(threading.Event, 'wait', wait)
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, *_ = start_backuper(job, 6.048e25)
	thread.name = 'scheduled-backuper'
	try:
		wait_until(lambda: len(calls) == 1, message='no start comparison')
		time.sleep(0.5)
		assert thread.is_alive()
	finally:
		stop_backuper(thread)
	assert seen and max(t for t in seen if t is not None) <= 1, sorted(set(seen))[-5:]


def test_a_vault_not_ready_at_due_time_postpones_the_comparison(job, monkeypatch):
	vault_flag = threading.Event()
	vault_flag.set()
	real_register = rv.FS_SIGNATURE_MONITOR.register
	def register(path, signature):
		if os.path.abspath(path) == os.path.abspath(job.vault):
			return vault_flag
		return real_register(path, signature)
	monkeypatch.setattr(rv.FS_SIGNATURE_MONITOR, 'register', register)
	monkeypatch.setattr(rv.FS_SIGNATURE_MONITOR, 'unregister', lambda *args: None)
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	thread, *_ = start_backuper(job, 0.5)
	try:
		wait_until(lambda: len(calls) == 1, message='no start comparison')
		vault_flag.clear()
		time.sleep(1.5)
		assert len(calls) == 1, calls
		vault_flag.set()
		wait_until(lambda: len(calls) == 2, timeout=5, message='no postponed comparison')
		assert calls[1][0] == 'whole'
		# it ran when the vault came back, not a whole interval later
		assert calls[1][1] - calls[0][2] < 2.2
	finally:
		stop_backuper(thread)


def test_a_stop_while_a_due_comparison_waits_for_a_missing_vault_writes_nothing_under_the_vault(job, monkeypatch):
	vault_flag = threading.Event()
	vault_flag.set()
	real_register = rv.FS_SIGNATURE_MONITOR.register
	def register(path, signature):
		if os.path.abspath(path) == os.path.abspath(job.vault):
			return vault_flag
		return real_register(path, signature)
	monkeypatch.setattr(rv.FS_SIGNATURE_MONITOR, 'register', register)
	monkeypatch.setattr(rv.FS_SIGNATURE_MONITOR, 'unregister', lambda *args: None)
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	calls = recorded_backups(monkeypatch)
	away = job.vault + '.away'
	taken = threading.Event()
	real_take = rv.ChangeEventQueue.take
	def take(self, *args, **kwargs):
		batch = real_take(self, *args, **kwargs)
		if batch.full_scan_requested:
			# the vault goes between the due comparison's take and its run, as a disk dropping out does
			os.rename(job.vault, away)
			vault_flag.clear()
			taken.set()
		return batch
	monkeypatch.setattr(rv.ChangeEventQueue, 'take', take)
	thread, *_ = start_backuper(job, 0.3)
	try:
		wait_until(taken.is_set, message='no scheduled comparison taken')
		time.sleep(0.5)
		assert len(calls) == 1, calls
	finally:
		stop_backuper(thread)
		# the vault back as it was, for the fixture's teardown
		restored = os.path.isdir(job.vault)
		if restored:
			shutil.rmtree(job.vault)
		os.rename(away, job.vault)
	assert not restored, 'the stop created the job folder in the missing vault'
