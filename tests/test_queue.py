import datetime
import random
import time
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit


def _ev(t, event, path, is_dir=False, moved_from=None):
	return rv.ChangeEvent(float(t), is_dir, event, path, moved_from)


def test_queue_keeps_order_across_packed_blocks(monkeypatch):
	monkeypatch.setattr(rv, 'QUEUE_BLOCK_EVENTS', 3)
	events = [_ev(t, 'create', f'/m/f{t}') for t in range(10)]
	queue = rv.ChangeEventQueue('/m')
	for event in events:
		queue.append(event)
	assert len(queue) == 10 and list(queue) == events and list(reversed(queue)) == events[::-1]
	assert queue.nbytes() < 10 * rv.QUEUED_EVENT_BYTES
	taken = queue.take()
	assert (len(queue), list(taken)) == (0, events)
	queue.append(_ev(20, 'modify', '/m/late'))
	# a backup that did not commit hands its batch back in front of what arrived since
	queue.prepend(events[:4])
	assert list(queue) == events[:4] + [_ev(20, 'modify', '/m/late')]


def test_queue_compacts_as_it_grows(monkeypatch):
	monkeypatch.setattr(rv, 'QUEUE_BLOCK_EVENTS', 64)
	monkeypatch.setattr(rv, 'QUEUE_COMPACT_EVENTS', 100)
	queue = rv.ChangeEventQueue('/m')
	for t in range(1000):
		queue.append(_ev(t, 'modify', f'/m/log{t % 2}'))
	# each compaction leaves the last modify of each log, and the next waits for the queue to double
	assert len(queue) < 200
	queue.compact()
	assert [(e.monotonic_time, e.path) for e in queue] == [(998.0, '/m/log0'), (999.0, '/m/log1')]


def _converted(events):
	# entries made from the same event record the same time: compare that event's time, not when it was converted
	base = datetime.datetime.now() - datetime.timedelta(seconds=time.monotonic())
	return [(path, values.event, values.source_path, round((datetime.datetime.fromisoformat(values.iso_time) - base).total_seconds()))
			for path, values in rv.change_events_to_backup_entries(events).items()]


def test_compaction_never_changes_the_backup(monkeypatch):
	monkeypatch.setattr(rv, 'QUEUE_BLOCK_EVENTS', 5)
	rng = random.Random(3)
	paths = ['/m/a', '/m/b', '/m/c', '/m/d', '/m/e']
	compacted = 0
	for _ in range(3000):
		events = []
		for t in range(rng.randint(2, 30)):
			kind = rng.choice(['modify', 'modify', 'modify', 'attrib', 'attrib', 'create', 'delete', 'move', 'move'])
			path = rng.choice(paths)
			moved_from = rng.choice([p for p in paths if p != path]) if kind == 'move' and rng.random() < 0.85 else None
			events.append(_ev(1000 + t, kind, path, rng.random() < 0.15, moved_from))
		queue = rv.ChangeEventQueue('/m')
		for event in events:
			queue.append(event)
		queue.compact()
		compacted += len(events) - len(queue)
		assert _converted(queue) == _converted(events), events
	assert compacted > 1000


def _memory(monkeypatch, available, total, stall):
	monkeypatch.setattr(rv, 'read_memory_state', lambda: (available, total, stall))


@pytest.mark.parametrize('available,stall', [
	(8 << 30, 40.0),    # tasks stalled on memory 40% of the last minute
	(100 << 20, 0.0),   # under 5% of 16 GiB available
	(2 << 10, 0.0),     # more than a quarter of what is available would be the queue
])
def test_long_queue_becomes_one_full_scan_when_memory_is_short(monkeypatch, available, stall):
	monkeypatch.setattr(rv, 'QUEUE_KEEP_EVENTS', 20)
	monkeypatch.setattr(rv, 'MEMORY_CHECK_SECONDS', 0)
	_memory(monkeypatch, available, 16 << 30, stall)
	queue = rv.ChangeEventQueue('/m')
	for t in range(21):
		queue.append(_ev(t, 'create', f'/m/f{t}'))
	assert [(e.event, e.path) for e in queue] == [('full_scan', '/m')]


def test_queue_keeps_its_events_while_memory_lasts_or_below_the_floor(monkeypatch):
	monkeypatch.setattr(rv, 'QUEUE_KEEP_EVENTS', 20)
	monkeypatch.setattr(rv, 'MEMORY_CHECK_SECONDS', 0)
	_memory(monkeypatch, 8 << 30, 16 << 30, 0.0)
	queue = rv.ChangeEventQueue('/m')
	for t in range(100):
		queue.append(_ev(t, 'create', f'/m/f{t}'))
	assert len(queue) == 100
	# short of memory, but a queue this small costs too little to give up its events for
	_memory(monkeypatch, 8 << 30, 16 << 30, 90.0)
	small = rv.ChangeEventQueue('/m')
	for t in range(20):
		small.append(_ev(t, 'create', f'/m/f{t}'))
	assert len(small) == 20 and not small.full_scan_requested


def test_read_memory_state_takes_the_tightest_limit_and_worst_stall(tmp_path):
	proc = tmp_path / 'proc'
	(proc / 'pressure').mkdir(parents=True)
	(proc / 'self').mkdir()
	(proc / 'meminfo').write_text('MemTotal:       16777216 kB\nMemFree:  1 kB\nMemAvailable:    8388608 kB\n')
	(proc / 'pressure' / 'memory').write_text('some avg10=1.00 avg60=2.50 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n')
	(proc / 'self' / 'cgroup').write_text('0::/system.slice/job.service\n')
	cgroup = tmp_path / 'cgroup'
	service = cgroup / 'system.slice' / 'job.service'
	service.mkdir(parents=True)
	(service / 'memory.max').write_text('max\n')
	(service / 'memory.pressure').write_text('some avg10=0.00 avg60=12.00 avg300=0.00 total=1\n')
	# the slice's limit applies to the service inside it
	(cgroup / 'system.slice' / 'memory.max').write_text(f'{4 << 30}\n')
	(cgroup / 'system.slice' / 'memory.current').write_text(f'{3 << 30}\n')
	assert rv.read_memory_state(str(proc), str(cgroup)) == (1 << 30, 4 << 30, 12.0)
	assert rv.read_memory_state(str(tmp_path / 'missing'), str(tmp_path / 'missing')) == (None, None, None)
