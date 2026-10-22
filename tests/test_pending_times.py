import datetime
import os
import time
from collections import deque
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_pending

pytestmark = pytest.mark.unit


def resumable(job, pending_path, pending_mtime):
	'''Make the monitored tree older than the pending file, written at pending_mtime, so loading resumes from it.'''
	for path in (job.monitor, *(os.path.join(job.monitor, name) for name in os.listdir(job.monitor))):
		os.utime(path, (pending_mtime - 30, pending_mtime - 30))
	os.utime(pending_path, (pending_mtime, pending_mtime))


def test_times_from_an_earlier_boot_are_rebased(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	real_monotonic = time.monotonic
	# this boot began 30 s ago
	shift = real_monotonic() - 30.0
	monkeypatch.setattr(rv.time, 'monotonic', lambda: real_monotonic() - shift)
	# written four days into the boot before, 60 s ago
	start = time.monotonic() + 345600
	stored = [start, start + 0.5, start + 2.0]
	pending = write_pending(job, [rv.ChangeEvent(stored[0], False, 'modify', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(stored[1], False, 'modify', os.path.join(job.monitor, 'b.txt'), None),
		rv.ChangeEvent(stored[2], False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	resumable(job, pending, time.time() - 60)
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue) is True
	events = list(queue)
	assert [os.path.basename(event.path) for event in events] == ['a.txt', 'b.txt', 'a.txt']
	assert abs(events[-1].monotonic_time - (time.monotonic() - 60)) < 2
	assert [round(event.monotonic_time - events[0].monotonic_time, 6) for event in events] == [0.0, 0.5, 2.0]
	entries = rv.change_events_to_backup_entries(queue)
	assert max(datetime.datetime.fromisoformat(values.iso_time) for values in entries.values()) <= datetime.datetime.now()


def test_times_from_this_boot_are_kept(job):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	stored = [time.monotonic() - 10.25, time.monotonic() - 5.5]
	pending = write_pending(job, [rv.ChangeEvent(stored[0], False, 'modify', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(stored[1], False, 'modify', os.path.join(job.monitor, 'b.txt'), None)])
	resumable(job, pending, time.time() - 1)
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue) is True
	assert [event.monotonic_time for event in queue] == stored


def test_times_from_an_earlier_boot_in_a_file_dated_in_the_future_are_rebased(job):
	seed_monitor(job, {'a.txt': 'a'})
	start = time.monotonic() + 345600
	pending = write_pending(job, [rv.ChangeEvent(start, False, 'modify', os.path.join(job.monitor, 'a.txt'), None),
		rv.ChangeEvent(start + 1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	# the clock was set back after the file was written
	resumable(job, pending, time.time() + 3600)
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue) is True
	events = list(queue)
	assert events[-1].monotonic_time <= time.monotonic()
	assert round(events[1].monotonic_time - events[0].monotonic_time, 6) == 1.0
	entries = rv.change_events_to_backup_entries(queue)
	assert max(datetime.datetime.fromisoformat(values.iso_time) for values in entries.values()) <= datetime.datetime.now()


def test_scan_rows_alone_are_not_round_tripped(job):
	seed_monitor(job, {'disk/': None})
	pending = write_pending(job, [rv.ChangeEvent(time.monotonic(), True, 'scan', os.path.join(job.monitor, 'disk'), None)])
	resumable(job, pending, time.time() - 1)
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue) is True
	assert not queue.round_tripped
