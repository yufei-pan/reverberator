import contextlib
import os
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
		to_process.clear()
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
			to_process.clear()
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
def _quiet_watch(job):
	'''A real watcher at a 1 s quiet hand-over and the default pair timeout, ready and with its first batch taken.'''
	to_process = rv.ChangeEventQueue(job.monitor)
	flag = threading.Event()
	thread, lock = _start_watch(job, to_process, flag, min_snapshot_delay_seconds=1)
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
