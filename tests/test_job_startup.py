import errno
import os
import shutil
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_pending, write_scan_leftover, write_incomplete_version, committed_versions, wait_for_committed_count, wait_until

pytestmark = pytest.mark.unit


def _skip_file(job, text):
	path = os.path.join(job.root, 'skip.txt')
	open(path, 'w').write(text)
	return path


def _v0(job, skip_list=None):
	_, manifest, _ = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', skip_list=skip_list)
	manifest.close()


def _run_backuper(job, startup, monitor_fs_flag=None):
	if monitor_fs_flag is None:
		monitor_fs_flag = threading.Event()
		monitor_fs_flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(),
		job.monitor, job.vault, 'N/A', threading.Event(), monitor_fs_flag), kwargs=dict(startup=startup), daemon=True)
	thread.start()
	return thread


def _stop(thread):
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=5)
	rv.GREEN_LIGHT.set()


def _age(job):
	for dirpath, dirnames, filenames in os.walk(job.monitor):
		for name in [dirpath] + [os.path.join(dirpath, n) for n in dirnames + filenames]:
			os.utime(name, (1000, 1000))


def _count_deltas(monkeypatch):
	'''The number of versions committed when each delta generation began.'''
	calls = []
	original = rv.delta_generate_backup_entries
	def counting(*args, **kwargs):
		latest = kwargs['latest_version_info'] if 'latest_version_info' in kwargs else args[1]
		calls.append(len(rv.list_versions(os.path.dirname(os.path.abspath(latest.path)))))
		return original(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', counting)
	return calls


def test_load_without_list_is_empty(job):
	startup = rv.JobStartup(job.job_name, job.monitor)
	assert startup.load(None) is True and startup.loaded.is_set() and not startup.failed
	assert not startup.skip_list


def test_load_missing_list_fails(job):
	startup = rv.JobStartup(job.job_name, job.monitor, os.path.join(job.root, 'missing'))
	assert startup.load(None) is False and startup.failed and startup.loaded.is_set()


def test_load_binary_list_fails(job):
	path = os.path.join(job.root, 'bin')
	open(path, 'wb').write(b'\xff\xfe\x00bad')
	assert rv.JobStartup(job.job_name, job.monitor, path).load(None) is False


def test_load_bad_pattern_fails(job):
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '[z-a]\n'))
	assert startup.load(None) is False and startup.failed


def test_load_refuses_losing_patterns_without_none(job):
	assert rv.JobStartup(job.job_name, job.monitor).load('recorded') is False
	assert rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '# nothing\n')).load('recorded') is False
	explicit = rv.JobStartup(job.job_name, job.monitor, explicit_none=True)
	assert explicit.load('recorded') is True and not explicit.skip_list


def test_backuper_loads_list_after_filesystem_ready(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'x.tmp': 't'})
	skip_path = os.path.join(job.root, 'skip.txt')
	startup = rv.JobStartup(job.job_name, job.monitor, skip_path)
	startup.watching.set()
	mounted = threading.Event()
	thread = _run_backuper(job, startup, mounted)
	try:
		time.sleep(0.3)
		assert not startup.loaded.is_set()
		open(skip_path, 'w').write('*.tmp\n')
		mounted.set()
		versions = wait_for_committed_count(job, 1)
		assert not startup.failed
		assert not os.path.lexists(os.path.join(versions[0], 'x.tmp'))
	finally:
		_stop(thread)


def test_backuper_with_missing_list_stops_only_its_job(job, poll_fast):
	startup = rv.JobStartup(job.job_name, job.monitor, os.path.join(job.root, 'missing'))
	thread = _run_backuper(job, startup)
	thread.join(timeout=5)
	assert not thread.is_alive() and startup.failed
	assert rv.GREEN_LIGHT.is_set() and committed_versions(job) == []


def test_backuper_with_bad_pattern_stops_only_its_job(job, poll_fast):
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '[z-a]\n'))
	thread = _run_backuper(job, startup)
	thread.join(timeout=5)
	assert not thread.is_alive() and startup.failed
	assert rv.GREEN_LIGHT.is_set() and committed_versions(job) == []


def _load_raises(monkeypatch):
	def load(cls, monitor_path, path):
		raise RuntimeError('unexpected')
	monkeypatch.setattr(rv.SkipList, 'load', classmethod(load))


def test_load_unexpected_error_fails(job, monkeypatch):
	_load_raises(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '*.tmp\n'))
	assert startup.load(None) is False and startup.failed and startup.loaded.is_set()


def test_backuper_with_unexpected_load_error_stops_only_its_job(job, poll_fast, monkeypatch):
	_load_raises(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '*.tmp\n'))
	thread = _run_backuper(job, startup)
	thread.join(timeout=5)
	assert not thread.is_alive() and startup.failed
	assert rv.GREEN_LIGHT.is_set() and committed_versions(job) == []


def test_watcher_exits_without_stopping_others_when_list_failed(job, poll_fast):
	startup = rv.JobStartup(job.job_name, job.monitor, os.path.join(job.root, 'missing'))
	startup.load(None)
	flag = threading.Event()
	flag.set()
	assert rv.watcher(flag, job.monitor, rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event(),
		rv.inotify_resource_manager(), startup=startup) is False
	assert rv.GREEN_LIGHT.is_set()


def test_a_changed_list_is_applied_by_the_starts_comparison(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'cache/x': 'x'})
	_v0(job)
	deltas = _count_deltas(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, 'cache/\n'))
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		versions = wait_for_committed_count(job, 2)
		assert deltas
		assert not os.path.lexists(os.path.join(versions[1], 'cache'))
	finally:
		_stop(thread)


def test_a_stop_before_the_watches_are_in_place_saves_nothing_and_makes_no_version(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	startup = rv.JobStartup(job.job_name, job.monitor)
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A',
		threading.Event(), flag), kwargs=dict(startup=startup), daemon=True)
	thread.start()
	wait_until(startup.loaded.is_set)
	# the watcher queued an event, then the daemon stopped before the backuper saw its watches were in place: the next start
	# compares the whole tree, so nothing is saved
	with lock:
		queue.append(rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'b.txt'), None))
	_stop(thread)
	assert not thread.is_alive() and not os.path.lexists(_pending(job))
	assert len(committed_versions(job)) == 1


def test_the_vault_scan_runs_while_the_job_waits_for_its_monitored_path(job, poll_fast):
	# a job restarted with its monitored path missing still has what a killed batch left taken away, by the scan, before
	# the path comes back; a pending file an older release left goes then too
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_scan_leftover(job)
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	shutil.rmtree(job.monitor)
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		wait_until(lambda: not os.path.lexists(orphan) and not os.path.lexists(pending))
		assert thread.is_alive() and not startup.loaded.is_set()
		assert len(committed_versions(job)) == 1
	finally:
		_stop(thread)


# ---- F3: every start is one full comparison, and the pending file goes. A stop saves nothing and a start resumes nothing:
# each start runs the one full comparison it ran anyway and makes one version. A pending file an older release left is
# removed at the start. The tree's mtimes are set back after each change (_age()), so 0.55.4's resume check passes and it
# replays what it saved.

class IdleFlag(threading.Event):
	'''A backuper's batch flag that says when the backuper first waits on it: idle, every batch it took before done.'''
	def __init__(self):
		super().__init__()
		self.idle = threading.Event()

	def wait(self, timeout=None):
		self.idle.set()
		return super().wait(timeout)


def _start(job, flag):
	'''A backuper as a start runs it, its watches in place, on a fresh queue, with flag as its batch flag: (thread, queue, lock).'''
	queue, lock = rv.ChangeEventQueue(job.monitor), threading.Lock()
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	ready = threading.Event()
	ready.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag, ready),
		kwargs=dict(startup=startup), daemon=True)
	thread.start()
	return thread, queue, lock


def _start_until_idle(job):
	'''A start run until its backuper is idle, then stopped.'''
	flag = IdleFlag()
	thread, _, _ = _start(job, flag)
	try:
		wait_until(flag.idle.is_set, message='the start never went idle')
	finally:
		_stop(thread)


def _logged(monkeypatch):
	'''(message, level) of each line the backuper logs, in the list returned.'''
	lines = []
	real = rv.backuperTeeLogToTl
	def spy(path, message, **kwargs):
		lines.append((message, next((level for level in ('error', 'warning', 'ok') if kwargs.get(level)), 'info')))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', spy)
	return lines


def _pending(job):
	return os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)


def _read(path):
	with open(path) as f:
		return f.read()


def test_a_stop_saves_nothing_and_the_start_makes_one_version(job, poll_fast):
	# fails on main: its stop writes the queued changes to the pending file; its start replays them as a version (the move a
	# rename), then compares the whole tree into a second one
	from tests.test_moves_then_changes import user_xattrs_or_skip
	user_xattrs_or_skip(job.monitor)
	seed_monitor(job, {'moved.txt': 'm', 'written.txt': 'w', 'chmod.txt': 'c', 'xattr.txt': 'x', 'removed.txt': 'r'})
	_age(job)
	_v0(job)
	moved_inode = os.lstat(os.path.join(committed_versions(job)[-1], 'moved.txt')).st_ino
	flag = IdleFlag()
	thread, queue, lock = _start(job, flag)
	try:
		wait_until(flag.idle.is_set, message='the start never went idle')
		assert len(committed_versions(job)) == 1
		# changes the watcher queued and the backuper has not taken, then the stop
		path = lambda rel: os.path.join(job.monitor, rel)
		os.rename(path('moved.txt'), path('moved-to.txt'))
		open(path('written.txt'), 'w').write('written before the stop')
		os.chmod(path('chmod.txt'), 0o600)
		os.setxattr(path('xattr.txt'), 'user.before_stop', b'1')
		with lock:
			for event in (rv.ChangeEvent(time.monotonic(), False, 'move', path('moved-to.txt'), path('moved.txt')),
					rv.ChangeEvent(time.monotonic(), False, 'modify', path('written.txt'), None),
					rv.ChangeEvent(time.monotonic(), False, 'attrib', path('chmod.txt'), None),
					rv.ChangeEvent(time.monotonic(), False, 'attrib', path('xattr.txt'), None)):
				queue.append(event)
	finally:
		_stop(thread)
	assert not os.path.lexists(_pending(job))
	# while the daemon is down
	open(path('new.txt'), 'w').write('new while down')
	os.remove(path('removed.txt'))
	_age(job)
	_start_until_idle(job)
	versions = committed_versions(job)
	assert len(versions) == 2
	newest = versions[-1]
	assert sorted(os.listdir(newest)) == ['chmod.txt', 'moved-to.txt', 'new.txt', 'written.txt', 'xattr.txt']
	assert _read(os.path.join(newest, 'written.txt')) == 'written before the stop' and _read(os.path.join(newest, 'new.txt')) == 'new while down'
	assert os.stat(os.path.join(newest, 'chmod.txt')).st_mode & 0o777 == 0o600
	assert os.getxattr(os.path.join(newest, 'xattr.txt'), 'user.before_stop') == b'1'
	# the move is copied, not renamed: the comparison finds a delete and a create
	assert _read(os.path.join(newest, 'moved-to.txt')) == 'm' and os.lstat(os.path.join(newest, 'moved-to.txt')).st_ino != moved_inode
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.matched[0] == os.path.basename(newest)
	finally:
		manifest.close()


def test_a_leftover_pending_file_is_removed_and_the_start_makes_one_version(job, poll_fast, monkeypatch):
	# fails on main: it replays the file as a version of its own, then compares the whole tree into a second one
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	_age(job)
	_v0(job)
	a, b = os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt')
	open(a, 'w').write('a changed before the stop')
	open(b, 'w').write('b changed while down')
	_age(job)
	# as 0.55.4 writes it at a stop, newer than every change of the tree
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(pending, (2000, 2000))
	lines = _logged(monkeypatch)
	_start_until_idle(job)
	assert [message for message, _ in lines if pending in message] == [f'Removed {pending}, a pending file of an older release: every start compares the whole tree']
	assert not os.path.lexists(pending)
	versions = committed_versions(job)
	assert len(versions) == 2
	assert _read(os.path.join(versions[-1], 'a.txt')) == 'a changed before the stop' and _read(os.path.join(versions[-1], 'b.txt')) == 'b changed while down'


def test_a_failed_attempt_is_followed_by_one_full_comparison(job, poll_fast, monkeypatch):
	# pin: the next attempt after a failed one compares the whole tree once, and makes one version
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	queue, lock = rv.ChangeEventQueue(job.monitor), threading.Lock()
	ready = threading.Event()
	ready.set()
	control = rv.JobControl(job.job_name)
	def attempt(flag):
		control.start_attempt()
		startup = rv.JobStartup(job.job_name, job.monitor)
		startup.watching.set()
		thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag, ready),
			kwargs=dict(startup=startup, job=control), daemon=True)
		thread.start()
		return thread
	real = rv.do_backup
	batches = []
	def do_backup(backup_entries, **kwargs):
		batches.append((len(backup_entries), kwargs.get('touched')))
		if fail:
			raise rv.JobFailure('the disk went')
		return real(backup_entries, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', do_backup)
	fail = False
	flag = IdleFlag()
	thread = attempt(flag)
	wait_until(flag.idle.is_set, message='the first attempt never went idle')
	# a batch of the first attempt fails
	fail = True
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed')
	with lock:
		queue.append(rv.ChangeEvent(time.monotonic(), False, 'modify', a, None))
	flag.set()
	thread.join(timeout=10)
	assert not thread.is_alive() and control.failure is not None and len(committed_versions(job)) == 1
	# the next attempt
	fail = False
	del batches[:]
	flag = IdleFlag()
	thread = attempt(flag)
	try:
		wait_until(flag.idle.is_set, message='the next attempt never went idle')
	finally:
		_stop(thread)
	# one batch, a full comparison (no entries, no touched scopes), and one version holding the change
	assert batches == [(0, None)]
	versions = committed_versions(job)
	assert len(versions) == 2 and _read(os.path.join(versions[-1], 'a.txt')) == 'changed'


def test_a_rewrite_keeping_size_mtime_and_tail_before_a_stop_is_not_in_the_starts_version(job, poll_fast):
	# fails on main: its start replays the rewrite's modify from the pending file and copies the file. A pin of the sentence
	# the rewrite entry gains: the start's full comparison cannot see such a rewrite, whose event the stop dropped
	tail = 64 * 1024
	seed_monitor(job, {'big.txt': 'h' * tail + 't' * tail})
	_age(job)
	_v0(job)
	flag = IdleFlag()
	thread, queue, lock = _start(job, flag)
	big = os.path.join(job.monitor, 'big.txt')
	try:
		wait_until(flag.idle.is_set, message='the start never went idle')
		# rewritten in place before its last 64 KiB, its size and mtime kept
		before = os.stat(big)
		with open(big, 'r+') as f:
			f.write('H' * 1024)
		os.utime(big, ns=(before.st_atime_ns, before.st_mtime_ns))
		with lock:
			queue.append(rv.ChangeEvent(time.monotonic(), False, 'modify', big, None))
	finally:
		_stop(thread)
	_age(job)
	_start_until_idle(job)
	assert _read(os.path.join(committed_versions(job)[-1], 'big.txt'))[:1024] == 'h' * 1024


def test_a_leftover_pending_file_that_cannot_be_removed_stops_nothing(job, poll_fast, monkeypatch):
	# review focus 5: one warning naming it, and the start's one full comparison and one version
	seed_monitor(job, {'a.txt': 'a'})
	_age(job)
	_v0(job)
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed while down')
	_age(job)
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(pending, (2000, 2000))
	real_remove = os.remove
	def remove(path, *args, **kwargs):
		if os.path.basename(os.fspath(path)) == rv.PENDING_TRANSACTIONS_FILE_NAME:
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_remove(path, *args, **kwargs)
	monkeypatch.setattr(os, 'remove', remove)
	lines = _logged(monkeypatch)
	flag = IdleFlag()
	thread, _, _ = _start(job, flag)
	try:
		wait_until(flag.idle.is_set, message='the start never went idle')
		assert thread.is_alive()
	finally:
		_stop(thread)
	assert [level for message, level in lines if pending in message] == ['warning']
	versions = committed_versions(job)
	assert len(versions) == 2 and _read(os.path.join(versions[-1], 'a.txt')) == 'changed while down'
