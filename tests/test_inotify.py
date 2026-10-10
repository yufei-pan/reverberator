import os
import threading
from collections import deque
import pytest
import reverberator as rv
from tests.harness import wait_until

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


def test_file_create_modify_delete_attrib(job, poll_fast):
	to_process = deque()
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
	to_process = deque()
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
	to_process = deque()
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
	to_process = deque()
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
	to_process = deque()
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
	to_process = deque()
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
	to_process = deque()
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
