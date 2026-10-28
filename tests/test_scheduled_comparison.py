import os
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
	rv.GREEN_LIGHT.set()


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


@pytest.mark.parametrize('interval', [1e25, 1e300])
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
