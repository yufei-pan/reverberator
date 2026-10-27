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
	assert queue.read_wall_ns >= returned[0]
