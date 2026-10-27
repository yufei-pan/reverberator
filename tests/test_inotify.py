import contextlib
import errno
import os
import shutil
import threading
import time
import pytest
import reverberator as rv
from tests.harness import run_backup, seed_monitor, wait_until

pytestmark = pytest.mark.inotify


def _events(to_process, lock):
	with lock:
		return list(to_process)


def _wait_watch_ready(job, to_process, lock):
	probe = os.path.join(job.monitor, '.watch_ready')
	def ready():
		if os.path.exists(probe):
			os.remove(probe)
		open(probe, 'w').write('1')
		return any(e.event == 'create' and e.path.endswith('.watch_ready') for e in _events(to_process, lock))
	wait_until(ready, message='watcher not ready')


def _consume_batch(to_process, lock, to_process_flag):
	'''Drain to_process then clear the flag, same order as backuper.'''
	wait_until(to_process_flag.is_set, message='watcher did not signal process')
	with lock:
		to_process.take()
	to_process_flag.clear()


def _start_watch(job, to_process, to_process_flag, min_snapshot_delay_seconds=0, max_shapshot_delay_seconds=60):
	lock = threading.Lock()
	irm = rv.inotify_resource_manager()
	thread = threading.Thread(
		target=rv.watchFolder,
		kwargs=dict(
			monitor_path=job.monitor,
			to_process=to_process,
			to_process_lock=lock,
			to_process_flag=to_process_flag,
			irm=irm,
			min_snapshot_delay_seconds=min_snapshot_delay_seconds,
			max_shapshot_delay_seconds=max_shapshot_delay_seconds,
		),
		daemon=True,
	)
	thread.start()
	return thread, lock


def test_a_read_time_past_a_change_means_its_event_is_queued(job, poll_fast):
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		path = os.path.join(job.monitor, 'f.txt')
		open(path, 'w').write('a')
		done = time.time_ns()
		def published():
			with lock:
				return (to_process.read_wall_ns or 0) > done, [e for e in to_process if e.path == path and e.event == 'create']
		wait_until(lambda: published()[0], message='no read time past the change')
		assert published()[1]
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_file_create_modify_delete_attrib(job, poll_fast):
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		path = os.path.join(job.monitor, 'f.txt')
		open(path, 'w').write('a')
		wait_until(lambda: any(e.event == 'create' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no create')
		open(path, 'w').write('ab')
		wait_until(lambda: any(e.event == 'modify' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no modify')
		os.chmod(path, 0o600)
		wait_until(lambda: any(e.event == 'attrib' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no attrib')
		os.remove(path)
		wait_until(lambda: any(e.event == 'delete' and e.path.endswith('f.txt') for e in _events(to_process, lock)), message='no delete')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_file_rename_move_or_equivalent(job, poll_fast):
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('x')
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt'))
		def ok():
			evs = _events(to_process, lock)
			moves = [e for e in evs if e.event == 'move' and e.path.endswith('b.txt')]
			if moves and moves[0].moved_from and moves[0].moved_from.endswith('a.txt'):
				return True
			creates = [e for e in evs if e.event == 'create' and e.path.endswith('b.txt')]
			return bool(creates)
		wait_until(ok, message='rename produced neither move nor delete+create')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_mkdir_p_watches_child_create(job, poll_fast):
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(
			lambda: any(e.event == 'create' and e.path.rstrip('/') == dpath for e in _events(to_process, lock)),
			message='mkdir d not seen',
		)
		_consume_batch(to_process, lock, flag)
		epath = os.path.join(dpath, 'e')
		os.mkdir(epath)
		wait_until(
			lambda: any(e.event == 'create' and e.path.rstrip('/') == epath for e in _events(to_process, lock)),
			message='mkdir e not seen',
		)
		_consume_batch(to_process, lock, flag)
		child = os.path.join(epath, 'z.txt')
		open(child, 'w').write('z')
		wait_until(
			lambda: any(e.event == 'create' and e.path.endswith('z.txt') for e in _events(to_process, lock)),
			message='child create not seen under mkdir -p',
		)
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def _has_create(to_process, lock, path):
	return any(e.event == 'create' and e.path.rstrip('/') == path for e in _events(to_process, lock))


def test_new_dir_events_recorded_after_an_unsignalled_take(job, poll_fast):
	# the backuper's startup take sets no flag and clears none
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=86400)
	try:
		_wait_watch_ready(job, to_process, lock)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(lambda: _has_create(to_process, lock, dpath), message='mkdir d not seen')
		with lock:
			to_process.take()
		child = os.path.join(dpath, 'f.txt')
		open(child, 'w').write('f')
		wait_until(lambda: _has_create(to_process, lock, child), message='file in new dir lost after an unsignalled take')
		assert not flag.is_set()
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_a_watcher_started_with_the_flag_set_records_new_dir_events_after_the_next_take(job, poll_fast):
	# a restarted watcher finds its predecessor's signal still set: the batch is not taken yet
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	flag.set()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=0, max_shapshot_delay_seconds=0)
	try:
		_wait_watch_ready(job, to_process, lock)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(lambda: _has_create(to_process, lock, dpath), message='mkdir d not seen')
		before = os.path.join(dpath, 'a.txt')
		open(before, 'w').write('a')
		marker = os.path.join(job.monitor, 'marker.txt')
		open(marker, 'w').write('m')
		wait_until(lambda: _has_create(to_process, lock, marker), message='marker not seen')
		# the batch's recursive copy of d holds a.txt
		assert not _has_create(to_process, lock, before)
		with lock:
			to_process.take()
		after = os.path.join(dpath, 'b.txt')
		open(after, 'w').write('b')
		wait_until(lambda: _has_create(to_process, lock, after), message='file in new dir lost after the next take')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_subdir_created_inside_new_dir_before_batch_is_watched(job, poll_fast):
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(lambda: _has_create(to_process, lock, dpath), message='mkdir d not seen')
		# d's events are now discarded until its batch is taken: d's recursive copy will hold e
		epath = os.path.join(dpath, 'e')
		os.mkdir(epath)
		# events arrive in order, so once the probe shows up the create of e was handled
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		child = os.path.join(epath, 'z.txt')
		open(child, 'w').write('z')
		wait_until(lambda: _has_create(to_process, lock, child), message='file in a subdir made inside a new dir not seen')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_dir_moved_into_new_dir_before_batch_reports_new_paths(job, poll_fast):
	os.makedirs(os.path.join(job.monitor, 'old', 'sub'))
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(lambda: _has_create(to_process, lock, dpath), message='mkdir d not seen')
		moved = os.path.join(dpath, 'sub')
		os.rename(os.path.join(job.monitor, 'old', 'sub'), moved)
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		child = os.path.join(moved, 'y.txt')
		open(child, 'w').write('y')
		wait_until(
			lambda: any(e.event == 'create' and e.path.endswith('y.txt') for e in _events(to_process, lock)),
			message='file in a dir moved into a new dir not seen',
		)
		assert {e.path for e in _events(to_process, lock) if e.path.endswith('y.txt')} == {child}
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_new_dir_events_recorded_after_batch_taken_when_max_delay_rearms(job, poll_fast):
	# a busy tree never goes quiet for the min delay, so only the max delay signals the backuper
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	try:
		_wait_watch_ready(job, to_process, lock)
		dpath = os.path.join(job.monitor, 'd')
		os.mkdir(dpath)
		wait_until(lambda: _has_create(to_process, lock, dpath), message='mkdir d not seen')
		wait_until(flag.is_set, message='watcher did not signal process')
		# the backuper takes the batch holding d's recursive copy while the watcher is still
		# appending other events, so the watcher's next pass finds work queued and the flag clear
		with lock:
			to_process.take()
		busy = os.path.join(job.monitor, 'busy.txt')
		open(busy, 'w').write('b')
		wait_until(lambda: _has_create(to_process, lock, busy), message='busy create not seen')
		flag.clear()
		child = os.path.join(dpath, 'x.txt')
		open(child, 'w').write('x')
		wait_until(lambda: _has_create(to_process, lock, child), message='file in new dir lost after its batch was taken')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_queue_overflow_full_scan_or_skip(job, poll_fast):
	to_process = rv.ChangeEventQueue()
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag)
	try:
		_wait_watch_ready(job, to_process, lock)
		for i in range(20000):
			open(os.path.join(job.monitor, f'f{i}.txt'), 'w').write('x')
		try:
			wait_until(
				lambda: any(e.event == 'full_scan' for e in _events(to_process, lock)),
				timeout=2.0,
				message='no full_scan',
			)
		except AssertionError:
			pytest.skip('could not fill inotify queue on this kernel')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


def test_long_queue_becomes_one_full_scan_only_when_memory_is_short(job, poll_fast, monkeypatch):
	# on a machine with memory to spare, a busy job keeps every event however long it waits to back up
	monkeypatch.setattr(rv, 'QUEUE_KEEP_EVENTS', 50)
	monkeypatch.setattr(rv, 'MEMORY_CHECK_SECONDS', 0)
	memory = {'state': (8 << 30, 16 << 30, 0.0)}
	monkeypatch.setattr(rv, 'read_memory_state', lambda: memory['state'])
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=3600)
	try:
		_wait_watch_ready(job, to_process, lock)
		for i in range(200):
			open(os.path.join(job.monitor, f'f{i}.txt'), 'w').write('x')
		wait_until(lambda: sum(e.event == 'create' for e in _events(to_process, lock)) >= 200, message='creates not queued')
		memory['state'] = (8 << 30, 16 << 30, 40.0)
		open(os.path.join(job.monitor, 'stalled.txt'), 'w').write('x')
		wait_until(lambda: [e.event for e in _events(to_process, lock)] == ['full_scan'], message='no lone full_scan')
		open(os.path.join(job.monitor, 'later.txt'), 'w').write('x')
		# nothing to wait for when the event is dropped: give the watcher a few reads to pick it up
		time.sleep(0.5)
		assert [(e.event, e.path) for e in _events(to_process, lock)] == [('full_scan', job.monitor)]
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


def test_recreated_monitored_root_is_compared_with_the_vault(job, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 0.2)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('a')
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	flag = rv.FS_SIGNATURE_MONITOR.register(job.monitor, 'N/A')
	watched = []
	real_init = rv.initializeFolderWatchers
	def counting_init(inotify_obj, path, *args, **kwargs):
		result = real_init(inotify_obj, path, *args, **kwargs)
		if path == job.monitor:
			watched.append(result)
		return result
	monkeypatch.setattr(rv, 'initializeFolderWatchers', counting_init)
	thread = threading.Thread(target=rv.watcher, args=(flag, job.monitor, to_process, lock, threading.Event(),
		rv.inotify_resource_manager(), 0, 60), kwargs=dict(job=control, monitor_signature='N/A'), daemon=True)
	thread.start()
	try:
		wait_until(lambda: len(watched) == 1, message='root not watched')
		assert not to_process.full_scan_requested
		# the monitored root moves away and a new one takes its place: nothing tells what changed, so it is compared
		os.rename(job.monitor, job.monitor + '.old')
		os.makedirs(job.monitor)
		open(os.path.join(job.monitor, 'new.txt'), 'w').write('new')
		wait_until(lambda: len(watched) == 2, message='new root not watched')
		wait_until(lambda: to_process.full_scan_requested, timeout=2, message='new root never compared')
	finally:
		control.fail('test done')
		thread.join(timeout=3)
		rv.FS_SIGNATURE_MONITOR.unregister(job.monitor, 'N/A', flag)
	assert not thread.is_alive()


@contextlib.contextmanager
def _quiet_watch(job, max_shapshot_delay_seconds=60):
	'''A real watcher at a 1 s quiet hand-over and the default pair timeout, ready and with its first batch taken.'''
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=1, max_shapshot_delay_seconds=max_shapshot_delay_seconds)
	try:
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		yield to_process, lock, flag
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def taken(to_process, lock, flag):
	'''The batch the watcher signals, taken as the backuper takes it.'''
	wait_until(flag.is_set, timeout=5, message='watcher did not signal process')
	with lock:
		batch = to_process.take()
	flag.clear()
	return batch


def rels(job, events):
	return [(e.event, os.path.relpath(e.path, job.monitor)) for e in events]


def test_a_file_moved_into_a_new_folder_leaves_only_its_new_place(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	with _quiet_watch(job) as (to_process, lock, flag):
		os.mkdir(os.path.join(job.monitor, 'd'))
		os.rename(os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'd', 'a.txt'))
		batch = taken(to_process, lock, flag)
	assert ('delete', 'a.txt') in rels(job, batch)
	version = run_backup(job, rv.change_events_to_backup_entries(batch, job.monitor), touched=rv.touched_scopes(batch, job.monitor))[-1]
	assert not os.path.lexists(os.path.join(version, 'a.txt'))
	assert open(os.path.join(version, 'd', 'a.txt')).read() == 'a'


def test_a_move_out_that_is_the_last_event_lands_in_its_batch(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		got = rels(job, taken(to_process, lock, flag))
	assert [r for r in got if r[0] in ('create', 'delete')] == [('create', 'b.txt'), ('delete', 'a.txt')]


def test_a_move_out_alone_is_handed_over(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		assert rels(job, taken(to_process, lock, flag)) == [('delete', 'a.txt')]


def test_a_create_at_a_move_outs_source_keeps_the_order(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('new')
		got = rels(job, taken(to_process, lock, flag))
	assert [r for r in got if r[0] in ('create', 'delete')] == [('delete', 'a.txt'), ('create', 'a.txt')]


def test_a_folder_moved_out_before_a_quiet_hand_over_is_gone_and_unwatched(job, tmp_path, poll_fast):
	seed_monitor(job, {'d/sub/x': 'x', 'keep.txt': 'k'})
	run_backup(job)
	with _quiet_watch(job) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'd'), str(tmp_path / 'd'))
		batch = taken(to_process, lock, flag)
		assert rels(job, batch) == [('delete', 'd')]
		open(str(tmp_path / 'd' / 'sub' / 'y'), 'w').write('y')
		_wait_watch_ready(job, to_process, lock)
		assert not [e for e in _events(to_process, lock) if e.path.startswith(os.path.join(job.monitor, 'd') + '/')]
	version = run_backup(job, rv.change_events_to_backup_entries(batch, job.monitor), touched=rv.touched_scopes(batch, job.monitor))[-1]
	assert not os.path.lexists(os.path.join(version, 'd'))


def test_a_move_out_reaches_a_batch_signalled_before_it(job, tmp_path, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	with _quiet_watch(job) as (to_process, lock, flag):
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
		wait_until(flag.is_set, timeout=5)                 # signalled, not taken: the backuper is busy
		os.rename(os.path.join(job.monitor, 'a.txt'), str(tmp_path / 'a.txt'))
		wait_until(lambda: ('delete', 'a.txt') in rels(job, _events(to_process, lock)), timeout=5)



def busy_takes(job, to_process, lock, flag, after):
	'''
	Write a new file every 0.1 s, so the tree is never quiet, and take each batch the watcher signals, until two more
	after the first batch for which after(rels) holds: a move-out read before that batch's take then has a whole read
	behind it, so the last batch carries it if it is still held.
	'''
	batches = []
	more = None
	deadline = time.monotonic() + 10
	k = 0
	while time.monotonic() < deadline:
		open(os.path.join(job.monitor, f'busy_{k}.txt'), 'w').write('b')
		k += 1
		if flag.is_set():
			batches.append(taken(to_process, lock, flag))
			if more is not None:
				more -= 1
				if not more:
					return batches
			elif after(rels(job, batches[-1])):
				more = 2
		time.sleep(0.1)
	raise AssertionError('the watcher signalled no batch')


def back_up_each(job, batches):
	for batch in batches:
		version = run_backup(job, rv.change_events_to_backup_entries(batch, job.monitor), touched=rv.touched_scopes(batch, job.monitor))[-1]
	return version


def test_a_file_moved_into_a_new_folder_while_the_tree_is_busy_leaves_only_its_new_place(job, poll_fast):
	seed_monitor(job, {'f.txt': 'f', 'keep.txt': 'k'})
	run_backup(job)
	with _quiet_watch(job, max_shapshot_delay_seconds=0) as (to_process, lock, flag):
		os.mkdir(os.path.join(job.monitor, 'd'))
		os.rename(os.path.join(job.monitor, 'f.txt'), os.path.join(job.monitor, 'd', 'f.txt'))
		batches = busy_takes(job, to_process, lock, flag, lambda got: ('create', 'd') in got)
	# taken at max-delay hand-overs while the move-out is still held: none of them has its delete
	assert not [b for b in batches if ('delete', 'f.txt') in rels(job, b)]
	version = back_up_each(job, batches)
	assert not os.path.lexists(os.path.join(version, 'f.txt'))
	assert open(os.path.join(version, 'd', 'f.txt')).read() == 'f'


def test_a_folder_moved_out_while_the_tree_is_busy_is_gone_from_the_version(job, tmp_path, poll_fast):
	seed_monitor(job, {'d/sub/x': 'x', 'keep.txt': 'k'})
	run_backup(job)
	with _quiet_watch(job, max_shapshot_delay_seconds=0) as (to_process, lock, flag):
		os.rename(os.path.join(job.monitor, 'd'), str(tmp_path / 'd'))
		batches = busy_takes(job, to_process, lock, flag, lambda got: True)
	assert not [b for b in batches if ('delete', 'd') in rels(job, b)]
	version = back_up_each(job, batches)
	assert not os.path.lexists(os.path.join(version, 'd'))
	assert open(os.path.join(version, 'keep.txt')).read() == 'k'


def test_a_folder_made_while_the_walk_reads_its_parent_is_watched(job, poll_fast, monkeypatch):
	a = os.path.join(job.monitor, 'd', 'a')
	os.makedirs(a)
	b = os.path.join(a, 'b')
	real = os.scandir
	class Listing:
		# as cp -r or tar x goes on: b is made in a right after the walk has listed a
		def __init__(self, entries):
			self.entries = entries
		def __enter__(self):
			return self
		def __iter__(self):
			return iter(self.entries)
		def __exit__(self, *exc_info):
			self.entries.close()
			if not os.path.exists(b):
				os.mkdir(b)
	def scandir(path='.'):
		entries = real(path)
		return Listing(entries) if os.path.abspath(path) == a else entries
	monkeypatch.setattr(os, 'scandir', scandir)
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=0.2)
	try:
		_wait_watch_ready(job, to_process, lock)
		assert os.path.isdir(b)
		_consume_batch(to_process, lock, flag)
		x = os.path.join(b, 'x.txt')
		open(x, 'w').write('a later change in the folder made during the walk')
		wait_until(lambda: _has_create(to_process, lock, x), timeout=3, message='a change in the folder made during the walk is not queued')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def _kernel_watches(inotify_obj):
	with open(f'/proc/self/fdinfo/{inotify_obj.fileno()}', encoding='utf-8') as f:
		return sum(line.startswith('inotify wd:') for line in f)


def _fail_scandir(monkeypatch, folder, code=errno.EIO):
	real = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path) == folder:
			raise OSError(code, os.strerror(code), path)
		return real(path)
	monkeypatch.setattr(os, 'scandir', scandir)


WATCH_FLAGS = rv.inotify_simple.flags.CREATE | rv.inotify_simple.flags.MODIFY


def test_an_unreadable_folder_gives_its_watch_back_and_is_left_unwatched(tmp_path, monkeypatch):
	for rel in ('k/s', 'u/v'):
		os.makedirs(tmp_path / rel)
	root, k, u = str(tmp_path), str(tmp_path / 'k'), str(tmp_path / 'u')
	_fail_scandir(monkeypatch, u)
	irm = rv.inotify_resource_manager()
	wdDic, unwatched = rv.bidict(), set()
	with rv.inotify_simple.INotify() as inotify_obj:
		assert rv.initializeFolderWatchers(inotify_obj, root, wdDic, irm, WATCH_FLAGS, unwatched=unwatched) != -1
		# nothing can be told about what is in u: neither it nor v is watched
		assert sorted(path.rstrip('/') for path in wdDic.values()) == [root, k, os.path.join(k, 's')]
		assert irm.current_user_watches == len(wdDic) == _kernel_watches(inotify_obj)
	assert unwatched == {u}


@pytest.mark.parametrize('code, left_unwatched', [(errno.EACCES, True), (errno.ENOSPC, True), (errno.ENOENT, False), (errno.ENOTDIR, False)],
	ids=['EACCES', 'ENOSPC', 'ENOENT', 'ENOTDIR'])
def test_a_folder_whose_watch_fails_is_left_unwatched_unless_it_is_gone(tmp_path, code, left_unwatched):
	for rel in ('k/s', 'f/g'):
		os.makedirs(tmp_path / rel)
	root, f = str(tmp_path), str(tmp_path / 'f')
	class Failing:
		def __init__(self, inner):
			self.inner = inner
		def add_watch(self, path, mask):
			if path.rstrip('/') == f:
				raise OSError(code, os.strerror(code), path)
			return self.inner.add_watch(path, mask)
		def rm_watch(self, wd):
			return self.inner.rm_watch(wd)
	irm = rv.inotify_resource_manager()
	wdDic, unwatched = rv.bidict(), set()
	with rv.inotify_simple.INotify() as inotify_obj:
		rv.initializeFolderWatchers(Failing(inotify_obj), root, wdDic, irm, WATCH_FLAGS, unwatched=unwatched)
		assert f not in {path.rstrip('/') for path in wdDic.values()}
		assert irm.current_user_watches == len(wdDic) == _kernel_watches(inotify_obj)
	assert unwatched == ({f} if left_unwatched else set())


def test_a_folder_watched_twice_is_counted_once(tmp_path):
	os.makedirs(tmp_path / 'k' / 's')
	irm = rv.inotify_resource_manager()
	wdDic = rv.bidict()
	with rv.inotify_simple.INotify() as inotify_obj:
		rv.initializeFolderWatchers(inotify_obj, str(tmp_path), wdDic, irm, WATCH_FLAGS)
		# a folder made while its parent's walk ran is in the walk and raises its create, which watches it again
		rv.initializeFolderWatchers(inotify_obj, str(tmp_path / 'k'), wdDic, irm, WATCH_FLAGS)
		assert irm.current_user_watches == len(wdDic) == _kernel_watches(inotify_obj) == 3


def test_a_walk_tells_again_what_under_its_folder_is_unwatched(tmp_path, monkeypatch):
	for rel in ('u/v', 'u/w', 'k'):
		os.makedirs(tmp_path / rel)
	root, u, k = str(tmp_path), str(tmp_path / 'u'), str(tmp_path / 'k')
	real = os.scandir
	_fail_scandir(monkeypatch, u)
	irm = rv.inotify_resource_manager()
	wdDic, unwatched = rv.bidict(), set()
	with rv.inotify_simple.INotify() as inotify_obj:
		rv.initializeFolderWatchers(inotify_obj, root, wdDic, irm, WATCH_FLAGS, unwatched=unwatched)
		assert unwatched == {u}
		# u readable again, w not: a walk of u drops what it had and adds back what still fails; k is not walked
		unwatched.add(k)
		monkeypatch.setattr(os, 'scandir', real)
		_fail_scandir(monkeypatch, os.path.join(u, 'w'))
		rv.initializeFolderWatchers(inotify_obj, u, wdDic, irm, WATCH_FLAGS, unwatched=unwatched)
		assert unwatched == {os.path.join(u, 'w'), k}
		monkeypatch.setattr(os, 'scandir', real)
		rv.initializeFolderWatchers(inotify_obj, u, wdDic, irm, WATCH_FLAGS, unwatched=unwatched)
		assert unwatched == {k}


def test_read_times_publish_again_once_an_unreadable_folder_is_made_again_and_walked(job, poll_fast, monkeypatch):
	bad = os.path.join(job.monitor, 'bad')
	os.makedirs(os.path.join(bad, 'sub'))
	real = os.scandir
	_fail_scandir(monkeypatch, bad)
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=0.2)
	try:
		_wait_watch_ready(job, to_process, lock)
		with lock:
			assert to_process.read_wall_ns is None
		monkeypatch.setattr(os, 'scandir', real)
		shutil.rmtree(bad)
		os.makedirs(os.path.join(bad, 'sub'))
		wait_until(lambda: _has_create(to_process, lock, bad), message='no create of bad')
		_consume_batch(to_process, lock, flag)
		x = os.path.join(bad, 'sub', 'x.txt')
		open(x, 'w').write('x')
		wait_until(lambda: _has_create(to_process, lock, x), message='bad/sub not watched after it was made again')
		def published():
			with lock:
				return to_process.read_wall_ns is not None
		wait_until(published, timeout=3, message='no read time though nothing is unwatched')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def test_a_folder_moved_ahead_of_the_walk_keeps_its_watch_at_its_new_name(job, poll_fast, monkeypatch):
	m = job.monitor
	F = os.path.join(m, 'A', 'F')
	os.makedirs(os.path.join(F, 'sub'))
	for i in range(6):
		os.makedirs(os.path.join(m, f'X{i}'))
	real = rv.inotify_simple.INotify.add_watch
	watched_paths, moved = set(), []
	def add_watch(self, path, mask):
		wd = real(self, path, mask)
		watched_paths.add(os.path.abspath(path).rstrip('/'))
		if not moved and os.path.abspath(path).rstrip('/') == F:
			targets = [os.path.join(m, f'X{i}') for i in range(6) if os.path.join(m, f'X{i}') not in watched_paths]
			if targets:
				# mv A/F X/G after F's watch is added and before F is read, into a folder the walk has not reached: no
				# MOVED_TO comes, reading F fails with ENOENT, and the walk later finds G with F's watch
				G = os.path.join(targets[0], 'G')
				os.rename(F, G)
				moved.append(G)
		return wd
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	to_process = rv.ChangeEventQueue(m)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=0.2)
	try:
		_wait_watch_ready(job, to_process, lock)
		assert moved, 'the walk reached every X before A'
		_consume_batch(to_process, lock, flag)
		direct = os.path.join(moved[0], 'direct.txt')
		open(direct, 'w').write('d')
		wait_until(lambda: _has_create(to_process, lock, direct), timeout=3, message='the moved folder lost its watch')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def _in_one_read(monkeypatch, step):
	'''Run step while the watcher waits to read, so every change step makes comes in the same read.'''
	real_read = rv.inotify_simple.INotify.read
	waiting, go = threading.Event(), threading.Event()
	def read(self, *args, **kwargs):
		waiting.set()
		go.wait(5)
		return real_read(self, *args, **kwargs)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	try:
		assert waiting.wait(5), 'the watcher did not read'
		step()
	finally:
		monkeypatch.setattr(rv.inotify_simple.INotify, 'read', real_read)
		go.set()


@contextlib.contextmanager
def _ready_watch(job, **watch_kwargs):
	'''A real watcher at a 0.2 s quiet hand-over, ready and with its first batch taken.'''
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	lock = threading.Lock()
	thread = threading.Thread(target=rv.watchFolder, kwargs=dict(monitor_path=job.monitor, to_process=to_process, to_process_lock=lock,
		to_process_flag=flag, irm=rv.inotify_resource_manager(), min_snapshot_delay_seconds=0.2, **watch_kwargs), daemon=True)
	thread.start()
	try:
		_wait_watch_ready(job, to_process, lock)
		_consume_batch(to_process, lock, flag)
		yield to_process, lock, flag
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()


def _moved_to(to_process, lock, path):
	return any(e.event == 'move' and e.path.rstrip('/') == path for e in _events(to_process, lock))


def test_a_folder_made_and_renamed_at_once_is_watched_at_its_new_name(job, poll_fast, monkeypatch):
	d, e = os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 'e')
	with _ready_watch(job) as (to_process, lock, flag):
		# mkdir d; mv d e, as a tool that makes a folder under a temporary name does: d is gone when its create is handled
		_in_one_read(monkeypatch, lambda: (os.mkdir(d), os.rename(d, e)))
		wait_until(lambda: _moved_to(to_process, lock, e), message='no move')
		_consume_batch(to_process, lock, flag)
		late = os.path.join(e, 'late.txt')
		open(late, 'w').write('a later change in the renamed folder')
		wait_until(lambda: _has_create(to_process, lock, late), timeout=3, message='the renamed folder is not watched')


@pytest.mark.parametrize('made', ['in the same read', 'before'])
def test_a_subfolder_made_as_its_parent_moves_is_watched(job, poll_fast, monkeypatch, made):
	A, C = os.path.join(job.monitor, 'A'), os.path.join(job.monitor, 'C')
	if made == 'before':
		os.mkdir(A)
	with _ready_watch(job) as (to_process, lock, flag):
		# mkdir A; mkdir A/b; mv A C: b's create, if A had a watch to raise one, is handled at A/b, gone by then
		_in_one_read(monkeypatch, lambda: (os.makedirs(os.path.join(A, 'b')), os.rename(A, C)))
		wait_until(lambda: _moved_to(to_process, lock, C), message='no move')
		_consume_batch(to_process, lock, flag)
		late = os.path.join(C, 'b', 'late.txt')
		open(late, 'w').write('a later change in the subfolder')
		wait_until(lambda: _has_create(to_process, lock, late), timeout=3, message='the subfolder is not watched')


def test_a_folder_renamed_while_the_walk_is_inside_it_is_watched_in_full(job, poll_fast, monkeypatch):
	F, G = os.path.join(job.monitor, 'F'), os.path.join(job.monitor, 'G')
	for child in ('c1', 'c2', 'c3'):
		os.makedirs(os.path.join(F, child, 'deep'))
	real = os.scandir
	renamed = []
	def scandir(path='.'):
		entries = real(path)
		if not renamed and isinstance(path, str) and os.path.abspath(path).startswith(F + '/'):
			# mv F G while the walk reads one of F's subfolders: the ones it has not read yet are gone at their old path
			os.rename(F, G)
			renamed.append(path)
		return entries
	monkeypatch.setattr(os, 'scandir', scandir)
	with _ready_watch(job) as (to_process, lock, flag):
		monkeypatch.setattr(os, 'scandir', real)
		# the move went with the first batch, read before the watcher was ready
		assert renamed
		late = [os.path.join(G, child, 'deep', 'late.txt') for child in ('c1', 'c2', 'c3')]
		for path in late:
			open(path, 'w').write('a later change')
		wait_until(lambda: all(_has_create(to_process, lock, path) for path in late), timeout=3,
			message=f'not every subfolder is watched: {[path for path in late if not _has_create(to_process, lock, path)]}')


def _published(to_process, lock):
	with lock:
		return to_process.read_wall_ns is not None


@pytest.mark.parametrize('gone', ['deleted', 'moved out', 'moved to a skipped name', 'its parent moved'])
def test_read_times_publish_again_once_an_unwatched_folder_is_gone(job, tmp_path, poll_fast, monkeypatch, gone):
	P = os.path.join(job.monitor, 'P')
	bad = os.path.join(P, 'bad')
	os.makedirs(os.path.join(bad, 'sub'))
	real = os.scandir
	_fail_scandir(monkeypatch, bad)
	with _ready_watch(job, skip_list=rv.SkipList(job.monitor, ['old_*/'])) as (to_process, lock, flag):
		assert not _published(to_process, lock)
		monkeypatch.setattr(os, 'scandir', real)
		if gone == 'deleted':
			shutil.rmtree(bad)
		elif gone == 'moved out':
			os.rename(bad, str(tmp_path / 'bad'))
		elif gone == 'moved to a skipped name':
			os.rename(bad, os.path.join(P, 'old_bad'))
		else:
			os.rename(P, os.path.join(job.monitor, 'Q'))
		# nothing is left that the watcher should watch and does not
		wait_until(lambda: _published(to_process, lock), timeout=3, message='no read time though nothing is unwatched')
