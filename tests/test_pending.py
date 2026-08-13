import os
from collections import deque
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_pending

pytestmark = pytest.mark.unit


def test_persist_writes_rows_empty_deque_writes_nothing(job):
	os.makedirs(job.job_vault, exist_ok=True)
	rv.persist_pending_transactions(job.job_name, job.vault, deque())
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
	to_process = deque()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is True
	assert len(to_process) == 1
	assert to_process[0].event == 'modify'
	assert not os.path.exists(pending_path)


def test_load_discard_when_monitor_not_older(job):
	seed_monitor(job, {'a.txt': 'x'})
	a = os.path.join(job.monitor, 'a.txt')
	pending_path = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	now = 5000
	os.utime(pending_path, (now, now))
	os.utime(job.monitor, (now, now))
	os.utime(a, (now, now))
	to_process = deque()
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
	to_process = deque()
	ok = rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, to_process)
	assert ok is False
	assert len(to_process) == 0
	assert not os.path.exists(pending_path)
