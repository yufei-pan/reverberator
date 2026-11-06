import os
import threading
import time
import pytest
import reverberator as rv
from tests.harness import latest_version, run_backup, seed_monitor, wait_until

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


def _take_batch(to_process, lock, to_process_flag):
	# as the backuper does: once it takes a batch, the watcher records events in the folders it saw created again
	wait_until(to_process_flag.is_set, message='watcher did not signal the backuper')
	with lock:
		to_process.take()
	to_process_flag.clear()


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


def test_a_location_free_move_skips_the_newly_skipped_watch_removal(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a/': None, 'b/': None})
	calls = []
	monkeypatch.setattr(rv, 'remove_newly_skipped_watches', lambda *args, **kwargs: calls.append(args))
	thread, to_process, lock = _start(job, ['*.tmp'])
	try:
		os.rename(os.path.join(job.monitor, 'a'), os.path.join(job.monitor, 'b', 'a'))
		wait_until(lambda: any(e.event == 'move' for e in _events(to_process, lock)), message='move not seen')
		# the probe is read after the move, so the removal would have run by now: a name-only list skips the same folders anywhere
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
		# read after both folders' creates, so the watcher has watched them before the take. the probes' own events can have
		# the flag set already, so without this the take can come first, and a file written then raises no event: its copy
		# holds it (test_a_file_written_before_the_watcher_reaches_a_new_folder_is_in_the_next_batch)
		_probe(job, to_process, lock)
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		_take_batch(to_process, lock, flag)
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
		# read after the move back, so its walk is done before the take, as in the test above
		_probe(job, to_process, lock)
		wait_until(lambda: any(e.event == 'delete' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no delete')
		_take_batch(to_process, lock, flag)
		restored = os.path.join(data, 'sub', 'y')
		open(restored, 'w').write('y')
		wait_until(lambda: any(e.path == restored for e in _events(to_process, lock)), message='restored folder not watched')
	finally:
		_stop(thread)


def _hold_reads(monkeypatch):
	'''Once hold is set, the watcher stops before its next read (held is set then) until go is set.'''
	real = rv.inotify_simple.INotify.read
	hold, held, go = threading.Event(), threading.Event(), threading.Event()
	def read(self, *args, **kwargs):
		if hold.is_set() and not go.is_set():
			held.set()
			go.wait(20)
		return real(self, *args, **kwargs)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	return hold, held, go


def _back_up_batch(job, to_process, lock, flag, skip_list):
	# as the backuper does with each batch the watcher signals
	wait_until(flag.is_set, message='watcher did not signal the backuper')
	with lock:
		batch = to_process.take()
	flag.clear()
	entries = rv.change_events_to_backup_entries(batch, job.monitor)
	scans = [event.path for event in batch if event.event == 'scan']
	scopes = rv.touched_scopes(batch, job.monitor)
	if scans:
		root_mount = rv.mount_fingerprint(rv.current_mount_table(), os.path.realpath(job.monitor))
		rv.compare_scanned_folders(entries, scans, job.job_name, job.monitor, job.vault, skip_list=skip_list, root_mount=root_mount)[1].close()
	run_backup(job, entries, skip_list=skip_list, touched=scopes if scopes.subtrees or scopes.paths else None, matched_since=batch.read_wall_ns)


@pytest.mark.parametrize('data_read_first', [False, True])
def test_a_file_written_before_the_watcher_reaches_a_new_folder_is_in_the_next_batch(job, poll_fast, monkeypatch, data_read_first):
	# a batch is taken and backed up while the creates of the folders that took the moved-away path are unread: a file
	# written then raises no event, as its folder has no watch yet. the create read after the take goes in the next
	# batch, and that batch's copy holds the file
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	seed_monitor(job, {'data/sub/x': 'x', '.trash/': None})
	skip_list = rv.SkipList(job.monitor, ['.trash/'])
	run_backup(job, skip_list=skip_list)
	hold, held, go = _hold_reads(monkeypatch)
	flag = threading.Event()
	thread, to_process, lock = _start(job, ['.trash/'], flag)
	def queued(event, path):
		return any(e.event == event and e.path.rstrip('/') == path for e in _events(to_process, lock))
	try:
		data = os.path.join(job.monitor, 'data')
		sub = os.path.join(data, 'sub')
		os.rename(data, os.path.join(job.monitor, '.trash', 'data'))
		wait_until(lambda: queued('delete', data), message='no delete')
		if data_read_first:
			os.mkdir(data)
			wait_until(lambda: queued('create', data), message='no create of the folder')
		hold.set()
		assert held.wait(10)
		os.makedirs(sub, exist_ok=True)
		_back_up_batch(job, to_process, lock, flag, skip_list)
		fresh = os.path.join(sub, 'z')
		open(fresh, 'w').write('z')
		go.set()
		wait_until(lambda: queued('create', sub if data_read_first else data), message='no create in the next batch')
		_probe(job, to_process, lock)
		assert [e for e in _events(to_process, lock) if e.path == fresh] == []
		_back_up_batch(job, to_process, lock, flag, skip_list)
		assert open(os.path.join(latest_version(job).path, 'data', 'sub', 'z')).read() == 'z'
	finally:
		go.set()
		_stop(thread)


def _hold_walk(monkeypatch, folder):
	'''The watcher stops before it walks folder (at is set then) until go is set.'''
	real = rv.initializeFolderWatchers
	at, go = threading.Event(), threading.Event()
	def walk(inotify_obj, path, *args, **kwargs):
		if path.rstrip('/') == folder:
			at.set()
			go.wait(20)
		return real(inotify_obj, path, *args, **kwargs)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', walk)
	return at, go


@pytest.mark.parametrize('how', ['made', 'moved_in'])
def test_a_file_written_before_the_watch_of_a_folder_read_before_the_take_is_in_the_next_batch(job, tmp_path, poll_fast, monkeypatch, how):
	# the read holding the folder's event came before the take, so the event is discarded as the copy's, but the watch comes
	# after the copy passed the folder: a file written between raises no event and is in no copy, so the next batch compares it
	seed_monitor(job, {'keep': 'k'})
	skip_list = rv.SkipList(job.monitor, [])
	run_backup(job, skip_list=skip_list)
	data = os.path.join(job.monitor, 'data')
	sub = os.path.join(data, 'sub')
	at, go = _hold_walk(monkeypatch, sub)
	flag = threading.Event()
	thread, to_process, lock = _start(job, [], flag)
	try:
		os.mkdir(data)
		wait_until(lambda: any(e.event == 'create' and e.path.rstrip('/') == data for e in _events(to_process, lock)), message='no create of the folder')
		wait_until(flag.is_set, message='watcher did not signal the backuper')
		if how == 'made':
			os.mkdir(sub)
		else:
			os.mkdir(tmp_path / 'outside')
			os.rename(tmp_path / 'outside', sub)
		assert at.wait(10)
		_back_up_batch(job, to_process, lock, flag, skip_list)
		open(os.path.join(sub, 'z'), 'w').write('z')
		go.set()
		wait_until(lambda: any(e.event == 'scan' and e.path.rstrip('/') == sub for e in _events(to_process, lock)), message='no scan of the folder')
		_back_up_batch(job, to_process, lock, flag, skip_list)
		assert open(os.path.join(latest_version(job).path, 'data', 'sub', 'z')).read() == 'z'
	finally:
		go.set()
		_stop(thread)


def test_a_take_waits_for_the_walk_of_a_folder_renamed_at_once(job, poll_fast, monkeypatch):
	# mkdir d; mv d e read together: e has no watch until the walk after its move, and a take during that walk would copy e
	# before it, so a file written then raises no event
	seed_monitor(job, {'keep': 'k'})
	skip_list = rv.SkipList(job.monitor, [])
	run_backup(job, skip_list=skip_list)
	made, moved = os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 'e')
	hold, held, read_go = _hold_reads(monkeypatch)
	at, walk_go = _hold_walk(monkeypatch, moved)
	flag = threading.Event()
	thread, to_process, lock = _start(job, [], flag)
	try:
		wait_until(flag.is_set, message='watcher did not signal the backuper')
		hold.set()
		assert held.wait(10)
		os.mkdir(made)
		os.rename(made, moved)
		read_go.set()
		assert at.wait(10)
		assert not lock.acquire(timeout=0.1)
		open(os.path.join(moved, 'z'), 'w').write('z')
		walk_go.set()
		_back_up_batch(job, to_process, lock, flag, skip_list)
		assert open(os.path.join(latest_version(job).path, 'e', 'z')).read() == 'z'
	finally:
		read_go.set()
		walk_go.set()
		_stop(thread)


def test_a_folders_changes_and_its_rename_stay_in_one_batch(job, poll_fast, monkeypatch):
	# a take during the walk after a rename would otherwise hold the change without the move, and its comparison would drop
	# the file as gone from the version
	seed_monitor(job, {'d/f': 'old'})
	skip_list = rv.SkipList(job.monitor, [])
	run_backup(job, skip_list=skip_list)
	source, moved = os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 'e')
	at, go = _hold_walk(monkeypatch, moved)
	flag = threading.Event()
	thread, to_process, lock = _start(job, [], flag)
	try:
		changed = os.path.join(source, 'f')
		open(changed, 'a').write(' new')
		wait_until(lambda: any(e.path == changed for e in _events(to_process, lock)), message='no modify')
		os.rename(source, moved)
		assert at.wait(10)
		assert not lock.acquire(timeout=0.1)
		go.set()
		_back_up_batch(job, to_process, lock, flag, skip_list)
		version = latest_version(job).path
		assert open(os.path.join(version, 'e', 'f')).read() == 'old new'
		assert not os.path.lexists(os.path.join(version, 'd'))
	finally:
		go.set()
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


def test_create_queues_every_pending_move_out_at_its_path_first(job, tmp_path, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 1.0)
	outside = tmp_path / 'outside'
	outside.mkdir()
	seed_monitor(job, {'p/a.txt': 'p', 'q/a.txt': 'q'})
	thread, to_process, lock = _start(job, [])
	try:
		a = os.path.join(job.monitor, 'p', 'a.txt')
		os.rename(a, str(outside / 'a1'))
		# folders renamed over each other bring another a.txt to the same path, which then moves away too
		os.rename(os.path.join(job.monitor, 'p'), os.path.join(job.monitor, 'p_old'))
		os.rename(os.path.join(job.monitor, 'q'), os.path.join(job.monitor, 'p'))
		os.rename(a, str(outside / 'a2'))
		open(a, 'w').write('new')
		wait_until(lambda: any(e.event == 'create' and e.path == a for e in _events(to_process, lock)), message='no create')
		time.sleep(1.5)
		_probe(job, to_process, lock, 'probe_after_expiry.txt')
		events = [e.event for e in _events(to_process, lock) if e.path == a]
		assert events[:3] == ['delete', 'delete', 'create'] and 'delete' not in events[3:]
	finally:
		_stop(thread)


def test_create_after_an_evicted_move_out_queues_no_second_delete(job, tmp_path, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'COOKIE_DICT_MAX_SIZE', 1)
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	outside = tmp_path / 'outside'
	outside.mkdir()
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	thread, to_process, lock = _start(job, [])
	try:
		a = os.path.join(job.monitor, 'a.txt')
		b = os.path.join(job.monitor, 'b.txt')
		os.rename(a, str(outside / 'a.txt'))
		# pushes a's move out of the cookie dictionary, which queues its delete
		os.rename(b, str(outside / 'b.txt'))
		open(a, 'w').write('new')
		wait_until(lambda: any(e.event == 'create' and e.path == a for e in _events(to_process, lock)), message='no create')
		time.sleep(1.0)
		_probe(job, to_process, lock, 'probe_after_expiry.txt')
		events = _events(to_process, lock)
		assert None not in events
		assert [e.event for e in events if e.path == a][:2] == ['delete', 'create']
		assert [e.event for e in events if e.path == a].count('delete') == 1
		assert [e.event for e in events if e.path == b] == ['delete']
	finally:
		_stop(thread)


def test_a_folder_made_while_a_moved_folders_walk_reads_its_parent_is_watched(job, poll_fast, monkeypatch):
	seed_monitor(job, {'projects/foo/build/': None, 'archive/': None})
	build = os.path.join(job.monitor, 'archive', 'foo', 'build')
	sub = os.path.join(build, 'sub')
	real = os.scandir
	class Listing:
		# as cp -r or tar x goes on in the moved folder: sub is made in build, newly wanted there, right after the walk lists it
		def __init__(self, entries):
			self.entries = entries
		def __enter__(self):
			return self
		def __iter__(self):
			return iter(self.entries)
		def __exit__(self, *exc_info):
			self.entries.close()
			if not os.path.exists(sub):
				os.mkdir(sub)
	def scandir(path='.'):
		entries = real(path)
		return Listing(entries) if isinstance(path, str) and os.path.abspath(path) == build else entries
	monkeypatch.setattr(os, 'scandir', scandir)
	flag = threading.Event()
	thread, to_process, lock = _start(job, ['projects/*/build/'], flag)
	try:
		os.rename(os.path.join(job.monitor, 'projects', 'foo'), os.path.join(job.monitor, 'archive', 'foo'))
		wait_until(lambda: os.path.isdir(sub), message='the moved folder was not walked')
		# build was watched before it was read, so sub's create is raised
		wait_until(lambda: any(e.event == 'create' and e.path.rstrip('/') == sub for e in _events(to_process, lock)), timeout=3,
			message='the folder made during the walk raised no create')
		_take_batch(to_process, lock, flag)
		x = os.path.join(sub, 'x.txt')
		open(x, 'w').write('x')
		wait_until(lambda: any(e.path == x for e in _events(to_process, lock)), timeout=3, message='the folder made during the walk is not watched')
	finally:
		_stop(thread)


def test_many_events_in_a_new_folder_log_one_discard_line(job, poll_fast, monkeypatch):
	# a busy new folder (a test run's traces) wrote one line per event; now one per folder until a take
	lines = []
	real = rv.watcherTeeLogToTl
	def capture(monitor_path, message, **kwargs):
		lines.append(message)
		return real(monitor_path, message, **kwargs)
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', capture)
	to_process_flag = threading.Event()
	thread, to_process, lock = _start(job, [], to_process_flag=to_process_flag)
	try:
		new = os.path.join(job.monitor, 'traces')
		os.makedirs(os.path.join(new, 'sub'))
		wait_until(lambda: _paths(to_process, lock, '/traces'), message='new folder not seen')
		for i in range(200):
			open(os.path.join(new, f'f{i}'), 'w').write('x')
			open(os.path.join(new, 'sub', f'g{i}'), 'w').write('x')
		_probe(job, to_process, lock)
		prefix = 'Discarding events for new recursive folder '
		discards = [line for line in lines if line.startswith(prefix)]
		assert all(line.endswith(' until its copy runs') for line in discards)
		# one line per folder (the watcher writes a walked folder's path with a slash)
		assert sorted(line[len(prefix):-len(' until its copy runs')].rstrip('/') for line in discards) == [new, f'{new}/sub']
		# nothing in it was recorded: the folder's copy holds it
		assert [event.path for event in _paths(to_process, lock, '/traces')] == [new]
	finally:
		_stop(thread)
