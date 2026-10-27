import threading

import pytest
import reverberator as rv
from tests.harness import scripted_watch

pytestmark = pytest.mark.unit


def test_take_carries_the_read_time_and_keeps_it():
	queue = rv.ChangeEventQueue('/m')
	assert queue.read_wall_ns is None
	queue.read_wall_ns = 5
	queue.append(rv.ChangeEvent(1.0, False, 'modify', '/m/a', None))
	taken = queue.take()
	assert taken.read_wall_ns == 5 and queue.read_wall_ns == 5
	queue.append(rv.ChangeEvent(2.0, False, 'full_scan', '/m', None))
	assert queue.read_wall_ns == 5


class RecordingFlag(threading.Event):
	'''A flag that records the queue's read time at the moment the watcher signals.'''
	def __init__(self):
		super().__init__()
		self.queue, self.seen = None, []
	def set(self):
		self.seen.append(self.queue.read_wall_ns)
		super().set()


def test_a_max_delay_hand_over_carries_the_previous_reads_time(job, monkeypatch):
	flags = rv.inotify_simple.flags
	flag = RecordingFlag()
	monitor = job.monitor
	# reads[0]'s events are queued; reads[1] arrives while the tree is busy and the max delay has passed
	reads = [[(flags.CREATE, 'a', 0)], [(flags.CREATE, 'b', 0)]]
	flag.queue = rv.ChangeEventQueue(monitor)
	queue, _, returned = scripted_watch(monkeypatch, monitor, reads, flag=flag, queue=flag.queue,
		min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	# read 0 began before it returned; read 1's events were not all queued when it was handed over
	assert flag.seen and flag.seen[0] is not None and flag.seen[0] <= returned[0]


class RecordingQueue(rv.ChangeEventQueue):
	'''Records the read time a taker would see as each event is queued.'''
	def __init__(self, monitor):
		self.seen = []
		super().__init__(monitor)
	def append(self, event):
		self.seen.append((event.path.rsplit('/', 1)[-1], self.read_wall_ns))
		super().append(event)


def test_no_read_time_is_visible_before_all_its_events_are_queued(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE, 'a', 0), (flags.CREATE, 'b', 0)], [(flags.CREATE, 'c', 0), (flags.CREATE, 'd', 0)]]
	queue = RecordingQueue(job.monitor)
	_, _, returned = scripted_watch(monkeypatch, job.monitor, reads, queue=queue, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	seen = dict(queue.seen)
	# while read 0's events are queued no read is published; while read 1's are, only read 0's time, which began before it returned
	assert seen['a'] is None and seen['b'] is None
	assert seen['c'] is not None and seen['c'] <= returned[0] and seen['d'] <= returned[0]


def test_a_scripted_folder_create_does_not_re_root_later_events(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE | flags.ISDIR, 'd', 0)], [(flags.CREATE, 'x', 0)]]
	queue, _, _ = scripted_watch(monkeypatch, job.monitor, reads, min_snapshot_delay_seconds=3600)
	assert [(e.event, e.path) for e in queue] == [('create', job.monitor + '/d'), ('create', job.monitor + '/x')]
