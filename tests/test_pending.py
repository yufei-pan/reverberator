import errno
import os
import threading
from collections import deque
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_fstab, write_pending

pytestmark = pytest.mark.unit


def test_persist_writes_rows_empty_deque_writes_nothing(job):
	os.makedirs(job.job_vault, exist_ok=True)
	rv.persist_pending_transactions(job.job_name, job.vault, rv.ChangeEventQueue())
	pending = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	assert not os.path.exists(pending)
	events = deque([rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	rv.persist_pending_transactions(job.job_name, job.vault, events)
	assert os.path.isfile(pending)


def test_load_resume_when_pending_newer_than_monitor(job):
	seed_monitor(job, {'a.txt': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	os.utime(job.monitor, (1000, 1000))
	os.utime(a, (1000, 1000))
	pending_path = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(pending_path, (2000, 2000))
	to_process = rv.ChangeEventQueue()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is True
	assert len(to_process) == 1
	assert list(to_process)[0].event == 'modify'
	assert not os.path.exists(pending_path)


def test_load_discard_when_monitor_not_older(job):
	seed_monitor(job, {'a.txt': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	pending_path = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	now = 5000
	os.utime(pending_path, (now, now))
	os.utime(job.monitor, (now, now))
	os.utime(a, (now, now))
	to_process = rv.ChangeEventQueue()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is False
	assert len(to_process) == 0
	assert not os.path.exists(pending_path)


def test_load_corrupt_pending_clears(job):
	seed_monitor(job, {'a.txt': 'x'})
	os.makedirs(job.job_vault, exist_ok=True)
	pending_path = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	open(pending_path, 'w', encoding='utf-8').write('not a valid nsv\x00\x00')
	os.utime(job.monitor, (1000, 1000))
	os.utime(os.path.join(job.monitor, 'a.txt'), (1000, 1000))
	os.utime(pending_path, (2000, 2000))
	to_process = rv.ChangeEventQueue()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is False
	assert len(to_process) == 0
	assert not os.path.exists(pending_path)


def _resumable(job, pending_path):
	# the monitored tree is older than the pending file, so loading resumes from it
	for path in (job.monitor, *(os.path.join(job.monitor, name) for name in os.listdir(job.monitor))):
		os.utime(path, (1000, 1000))
	os.utime(pending_path, (2000, 2000))


def test_events_sharing_a_time_survive_persist_and_load(job):
	# events from one inotify read share their time, and rows are keyed by it when read back
	seed_monitor(job, {'a.txt': 'x'})
	events = deque([
		rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'b.txt'), None),
		rv.ChangeEvent(5.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(6.0, True, 'delete', os.path.join(job.monitor, 'd') + '/', None),
	])
	os.makedirs(job.job_vault, exist_ok=True)
	rv.persist_pending_transactions(job.job_name, job.vault, events)
	_resumable(job, os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME))
	to_process = rv.ChangeEventQueue()
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process) is True
	assert [(e.event, e.path, e.is_dir) for e in to_process] == [(e.event, e.path, e.is_dir) for e in events]


def test_pending_rows_lost_on_read_request_a_full_scan(job):
	# a pending file with rows sharing a time, as written before they were spaced apart
	seed_monitor(job, {'a.txt': 'x'})
	pending_path = write_pending(job, [
		rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'b.txt'), None),
	])
	_resumable(job, pending_path)
	to_process = rv.ChangeEventQueue()
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process) is True
	assert [(e.event, e.path) for e in to_process] == [('full_scan', job.monitor)]


def test_pending_file_too_large_for_the_memory_available_requests_a_full_scan(job, monkeypatch):
	monkeypatch.setattr(rv, 'read_memory_state', lambda: (100, 16 << 30, 0.0))
	seed_monitor(job, {'a.txt': 'x'})
	pending_path = write_pending(job, [rv.ChangeEvent(float(i), False, 'modify', os.path.join(job.monitor, 'a.txt'), None) for i in range(3)])
	_resumable(job, pending_path)
	to_process = rv.ChangeEventQueue()
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process) is True
	assert [e.event for e in to_process] == ['full_scan']
	assert not os.path.exists(pending_path)


def test_queue_too_large_to_write_out_persists_a_full_scan(job, monkeypatch):
	# writing every row holds them all as Python objects while the service stops
	monkeypatch.setattr(rv, 'read_memory_state', lambda: (2 * rv.PENDING_ROW_BYTES, 16 << 30, 0.0))
	seed_monitor(job, {'a.txt': 'x'})
	queue = rv.ChangeEventQueue(job.monitor)
	for t in range(10):
		queue.append(rv.ChangeEvent(float(t), False, 'create', os.path.join(job.monitor, f'f{t}'), None))
	os.makedirs(job.job_vault, exist_ok=True)
	rv.persist_pending_transactions(job.job_name, job.vault, queue)
	monkeypatch.setattr(rv, 'read_memory_state', lambda: (16 << 30, 16 << 30, 0.0))
	_resumable(job, os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME))
	to_process = rv.ChangeEventQueue()
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process) is True
	assert [e.event for e in to_process] == ['full_scan']


@pytest.fixture
def lines(monkeypatch):
	said = []
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: said.append(message))
	return said


def _queue(job):
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	return queue


@pytest.mark.parametrize('kind', ['missing', 'a file'])
def test_a_stop_with_the_vault_path_not_a_folder_writes_nothing_and_says_so(job, lines, kind):
	vault = os.path.join(job.root, 'gone')
	if kind == 'a file':
		open(vault, 'w').write('x')
	rv.persist_pending_transactions(job.job_name, vault, _queue(job))
	assert (os.path.isfile(vault) if kind == 'a file' else not os.path.lexists(vault))
	assert [line for line in lines if line.startswith(f'Not saving 1 pending transactions: vault path {vault} is not a folder')]


def test_a_stop_with_the_vault_under_an_unmounted_fstab_mount_writes_no_pending_file(job, fake_pool, lines):
	write_fstab(job.vault)
	rv.persist_pending_transactions(job.job_name, job.vault, _queue(job))
	assert not os.path.lexists(job.job_vault) and any('is not ready: ' in line for line in lines)
	fake_pool.add_mount(job.vault)
	rv.persist_pending_transactions(job.job_name, job.vault, _queue(job))
	assert os.path.isfile(os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME))


def test_a_stop_with_a_disk_of_the_vault_pool_out_writes_no_pending_file(job, fake_pool, lines):
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	rv.persist_pending_transactions(job.job_name, job.vault, _queue(job))
	assert not os.path.lexists(job.job_vault)


def test_a_stop_with_the_vault_pool_dead_writes_no_pending_file(job, fake_pool, lines):
	fake_pool.add(job.vault, ['a', 'b'])
	write_fstab(job.vault)
	fake_pool.unreadable(job.vault, errno.ENOTCONN)
	rv.persist_pending_transactions(job.job_name, job.vault, _queue(job))
	assert not os.path.lexists(job.job_vault)
	assert [line for line in lines if 'is not ready: ' in line and 'Transport endpoint is not connected' in line]


def test_a_failed_jobs_queue_follows_the_same_rule(job, fake_pool, lines):
	# a bare vault folder under an unmounted fstab mount: a failed job's queue is a full scan request alone
	os.makedirs(job.vault, exist_ok=True)
	write_fstab(job.vault)
	rv.persist_failed_job_queue(job.job_name, job.monitor, job.vault, _queue(job), threading.Lock())
	assert not os.path.lexists(job.job_vault)
	assert [line for line in lines if line.startswith(f'Not saving a full comparison request: vault path {job.vault} is not ready: ')]
