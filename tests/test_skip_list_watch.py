import os
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until

pytestmark = pytest.mark.inotify


# same probes as tests/test_inotify.py, copied so this module does not import another test module
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


def _start(job, patterns, to_process_flag=None):
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	thread = threading.Thread(target=rv.watchFolder, kwargs=dict(
		monitor_path=job.monitor, to_process=to_process, to_process_lock=lock,
		to_process_flag=threading.Event() if to_process_flag is None else to_process_flag,
		irm=rv.inotify_resource_manager(), min_snapshot_delay_seconds=0, max_shapshot_delay_seconds=60,
		skip_list=rv.SkipList(job.monitor, patterns)), daemon=True)
	thread.start()
	_wait_watch_ready(job, to_process, lock)
	return thread, to_process, lock


def _probe(job, to_process, lock, name='probe.txt'):
	path = os.path.join(job.monitor, name)
	open(path, 'a').write('p')
	wait_until(lambda: any(event.path == path for event in _events(to_process, lock)), message='probe not seen')


def _take_batch(to_process_flag):
	# as the backuper does: once it takes a batch, the watcher records events in the folders it saw created again
	wait_until(to_process_flag.is_set, message='watcher did not signal the backuper')
	to_process_flag.clear()
	# the watcher signals again only after it saw the flag cleared
	wait_until(to_process_flag.is_set, message='watcher did not signal the backuper again')


def _stop(thread):
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=2)
	rv.GREEN_LIGHT.set()


def _paths(to_process, lock, fragment):
	return [event for event in _events(to_process, lock) if fragment in event.path or fragment in (event.moved_from or '')]


def test_no_events_in_skipped_folder(job, poll_fast):
	seed_monitor(job, {'cache/sub/': None, 'src/': None})
	thread, to_process, lock = _start(job, ['cache/'])
	try:
		open(os.path.join(job.monitor, 'cache', 'sub', 'x'), 'w').write('x')
		open(os.path.join(job.monitor, 'cache', 'y'), 'w').write('y')
		_probe(job, to_process, lock)
		assert _paths(to_process, lock, '/cache') == []
	finally:
		_stop(thread)


def test_events_for_skipped_files_dropped(job, poll_fast):
	thread, to_process, lock = _start(job, ['*.tmp'])
	try:
		open(os.path.join(job.monitor, 'a.tmp'), 'w').write('t')
		_probe(job, to_process, lock)
		assert _paths(to_process, lock, 'a.tmp') == []
	finally:
		_stop(thread)


def test_created_folder_matching_pattern_gets_no_watch(job, poll_fast):
	seed_monitor(job, {'src/': None})
	thread, to_process, lock = _start(job, ['build/'])
	try:
		os.makedirs(os.path.join(job.monitor, 'src', 'build'))
		open(os.path.join(job.monitor, 'src', 'build', 'f'), 'w').write('f')
		_probe(job, to_process, lock)
		assert _paths(to_process, lock, '/src/build') == []
	finally:
		_stop(thread)


def test_move_into_skipped_name_is_delete(job, poll_fast):
	seed_monitor(job, {'keep.txt': 'k'})
	thread, to_process, lock = _start(job, ['*.tmp'])
	try:
		os.rename(os.path.join(job.monitor, 'keep.txt'), os.path.join(job.monitor, 'keep.tmp'))
		src = os.path.join(job.monitor, 'keep.txt')
		wait_until(lambda: any(e.event == 'delete' and e.path == src for e in _events(to_process, lock)), message='no delete')
		assert [e for e in _events(to_process, lock) if e.event == 'move'] == []
	finally:
		_stop(thread)


def test_move_out_of_skipped_name_is_create(job, poll_fast):
	seed_monitor(job, {'a.tmp': 't'})
	thread, to_process, lock = _start(job, ['*.tmp'])
	try:
		os.rename(os.path.join(job.monitor, 'a.tmp'), os.path.join(job.monitor, 'a.txt'))
		dst = os.path.join(job.monitor, 'a.txt')
		wait_until(lambda: any(e.event == 'create' and e.path == dst for e in _events(to_process, lock)), message='no create')
		assert [e for e in _events(to_process, lock) if e.event == 'move'] == []
	finally:
		_stop(thread)


def test_folder_moved_into_skipped_name_loses_watches(job, poll_fast):
	seed_monitor(job, {'d/sub/': None})
	thread, to_process, lock = _start(job, ['old_*/'])
	try:
		os.rename(os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 'old_d'))
		src = os.path.join(job.monitor, 'd')
		wait_until(lambda: any(e.event == 'delete' and e.path == src and e.is_dir for e in _events(to_process, lock)), message='no delete')
		open(os.path.join(job.monitor, 'old_d', 'sub', 'x'), 'w').write('x')
		_probe(job, to_process, lock)
		assert _paths(to_process, lock, 'old_d') == []
		assert [e for e in _events(to_process, lock) if e.path.startswith(os.path.join(job.monitor, 'd') + '/')] == []
	finally:
		_stop(thread)


def test_folder_moved_into_skipped_name_inside_new_folder_loses_watches(job, poll_fast):
	seed_monitor(job, {'d/sub/': None})
	thread, to_process, lock = _start(job, ['old_*/'])
	try:
		os.makedirs(os.path.join(job.monitor, 't'))
		_probe(job, to_process, lock, 'probe1.txt')
		os.rename(os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 't', 'old_d'))
		_probe(job, to_process, lock, 'probe2.txt')
		open(os.path.join(job.monitor, 't', 'old_d', 'sub', 'x'), 'w').write('x')
		_probe(job, to_process, lock, 'probe3.txt')
		assert [e for e in _events(to_process, lock) if e.path.startswith(os.path.join(job.monitor, 'd') + '/') or 'old_d' in e.path] == []
	finally:
		_stop(thread)


def test_location_dependent_move_rewatches_subtree(job, poll_fast):
	seed_monitor(job, {'projects/foo/build/': None, 'archive/bar/build/': None})
	thread, to_process, lock = _start(job, ['projects/*/build/'])
	try:
		os.rename(os.path.join(job.monitor, 'projects', 'foo'), os.path.join(job.monitor, 'archive', 'foo'))
		os.rename(os.path.join(job.monitor, 'archive', 'bar'), os.path.join(job.monitor, 'projects', 'bar'))
		wait_until(lambda: len([e for e in _events(to_process, lock) if e.event == 'move']) == 2, message='moves not seen')
		unskipped = os.path.join(job.monitor, 'archive', 'foo', 'build', 'x')
		open(unskipped, 'w').write('x')
		open(os.path.join(job.monitor, 'projects', 'bar', 'build', 'y'), 'w').write('y')
		wait_until(lambda: any(e.path == unskipped for e in _events(to_process, lock)), message='unskipped folder not watched')
		_probe(job, to_process, lock)
		assert _paths(to_process, lock, '/projects/bar/build') == []
	finally:
		_stop(thread)


def test_location_free_move_does_not_rewatch(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a/': None, 'b/': None})
	calls = []
	monkeypatch.setattr(rv, 'rewatch_moved_folder', lambda *args, **kwargs: calls.append(args))
	thread, to_process, lock = _start(job, ['*.tmp'])
	try:
		os.rename(os.path.join(job.monitor, 'a'), os.path.join(job.monitor, 'b', 'a'))
		wait_until(lambda: any(e.event == 'move' for e in _events(to_process, lock)), message='move not seen')
		# the probe is read after the move, so a re-walk of the moved folder would have happened by now
		_probe(job, to_process, lock)
		assert calls == []
	finally:
		_stop(thread)


def test_folder_moved_into_unwatched_skipped_folder_loses_watches(job, poll_fast, monkeypatch):
	# the skipped trash has no watch, so only MOVED_FROM arrives and the move expires into a delete
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	seed_monitor(job, {'data/sub/x': 'x', '.trash/': None})
	thread, to_process, lock = _start(job, ['.trash/'])
	try:
		data = os.path.join(job.monitor, 'data')
		os.rename(data, os.path.join(job.monitor, '.trash', 'data'))
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		mark = len(_events(to_process, lock))
		open(os.path.join(job.monitor, '.trash', 'data', 'sub', 'y'), 'w').write('y')
		_probe(job, to_process, lock)
		later = _events(to_process, lock)[mark:]
		assert [e for e in later if e.path.startswith(data + '/')] == []
		assert _paths(to_process, lock, '.trash') == []
	finally:
		_stop(thread)


def test_evicted_folder_move_loses_watches(job, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'COOKIE_DICT_MAX_SIZE', 1)
	seed_monitor(job, {'data/sub/x': 'x', 'f.txt': 'f', '.trash/': None})
	thread, to_process, lock = _start(job, ['.trash/'])
	try:
		data = os.path.join(job.monitor, 'data')
		os.rename(data, os.path.join(job.monitor, '.trash', 'data'))
		# a second unpaired move pushes the folder's move out of the cookie dictionary, long before it would expire
		os.rename(os.path.join(job.monitor, 'f.txt'), os.path.join(job.monitor, '.trash', 'f.txt'))
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		mark = len(_events(to_process, lock))
		open(os.path.join(job.monitor, '.trash', 'data', 'sub', 'y'), 'w').write('y')
		_probe(job, to_process, lock)
		assert [e for e in _events(to_process, lock)[mark:] if e.path.startswith(data + '/')] == []
	finally:
		_stop(thread)


def test_folder_recreated_at_moved_away_path_keeps_its_watches(job, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	seed_monitor(job, {'data/sub/x': 'x', '.trash/': None})
	flag = threading.Event()
	thread, to_process, lock = _start(job, ['.trash/'], flag)
	try:
		data = os.path.join(job.monitor, 'data')
		os.rename(data, os.path.join(job.monitor, '.trash', 'data'))
		# a new folder takes the old path before the move expires: its fresh watches stay
		os.makedirs(os.path.join(data, 'sub'))
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		_take_batch(flag)
		fresh = os.path.join(data, 'sub', 'z')
		open(fresh, 'w').write('z')
		wait_until(lambda: any(e.path == fresh for e in _events(to_process, lock)), message='recreated folder not watched')
	finally:
		_stop(thread)


def test_folder_moved_back_before_its_move_expires_keeps_its_watches(job, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	seed_monitor(job, {'data/sub/x': 'x', '.trash/': None})
	flag = threading.Event()
	thread, to_process, lock = _start(job, ['.trash/'], flag)
	try:
		data = os.path.join(job.monitor, 'data')
		os.rename(data, os.path.join(job.monitor, '.trash', 'data'))
		# restored from the trash: inotify hands back the watches the folder already had
		os.rename(os.path.join(job.monitor, '.trash', 'data'), data)
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		_take_batch(flag)
		restored = os.path.join(data, 'sub', 'y')
		open(restored, 'w').write('y')
		wait_until(lambda: any(e.path == restored for e in _events(to_process, lock)), message='restored folder not watched')
	finally:
		_stop(thread)


def test_folder_moved_away_and_back_is_not_deleted_later(job, tmp_path, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	outside = tmp_path / 'outside'
	outside.mkdir()
	seed_monitor(job, {'d/sub/': None})
	thread, to_process, lock = _start(job, [])
	try:
		os.rename(os.path.join(job.monitor, 'd'), str(outside / 'd'))
		os.rename(str(outside / 'd'), os.path.join(job.monitor, 'd'))
		d = os.path.join(job.monitor, 'd')
		wait_until(lambda: any(e.event == 'create' and e.path == d for e in _events(to_process, lock)), message='no create')
		time.sleep(1.0)
		_probe(job, to_process, lock, 'probe_after_expiry.txt')
		events = [(e.event, e.path) for e in _events(to_process, lock) if e.path == d]
		assert events == [('delete', d), ('create', d)]
	finally:
		_stop(thread)


def test_file_moved_over_a_moved_away_name_is_not_deleted_later(job, tmp_path, poll_fast, monkeypatch):
	# as Nextcloud does: the old file goes to a trash outside the tree, then the upload is renamed onto its name
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	outside = tmp_path / 'outside'
	outside.mkdir()
	seed_monitor(job, {'a.txt': 'old a', 'b.txt': 'new content'})
	thread, to_process, lock = _start(job, [])
	try:
		a = os.path.join(job.monitor, 'a.txt')
		b = os.path.join(job.monitor, 'b.txt')
		os.rename(a, str(outside / 'a.txt'))
		os.rename(b, a)
		wait_until(lambda: any(e.event == 'move' and e.path == a for e in _events(to_process, lock)), message='no move')
		time.sleep(1.0)
		_probe(job, to_process, lock, 'probe_after_expiry.txt')
		events = [(e.event, e.path, e.moved_from) for e in _events(to_process, lock) if a in (e.path, e.moved_from) or b in (e.path, e.moved_from)]
		assert events == [('delete', a, None), ('move', a, b)]
		entries = rv.change_events_to_backup_entries(_events(to_process, lock))
		assert entries[a].event == 'move' and entries[a].source_path == b
		assert b not in entries
	finally:
		_stop(thread)
