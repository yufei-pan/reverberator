import os
import shutil
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_pending, write_incomplete_version, committed_versions, wait_for_committed_count, wait_until

pytestmark = pytest.mark.unit


def _skip_file(job, text):
	path = os.path.join(job.root, 'skip.txt')
	open(path, 'w').write(text)
	return path


def _v0(job, skip_list=None):
	_, manifest, _ = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', skip_list=skip_list)
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


def _resumable_pending(job, path):
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', path, None)])
	for dirpath, dirnames, filenames in os.walk(job.monitor):
		for name in [dirpath] + [os.path.join(dirpath, n) for n in dirnames + filenames]:
			os.utime(name, (1000, 1000))
	os.utime(pending, (2000, 2000))
	return pending


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


def test_load_without_list_is_empty_and_unchanged(job):
	startup = rv.JobStartup(job.job_name, job.monitor)
	assert startup.load(None) is True and startup.loaded.is_set() and not startup.failed
	assert not startup.skip_list and startup.change == 'unchanged'


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
	assert explicit.load('recorded') is True and explicit.change == 'changed'


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


def test_changed_list_discards_pending_and_compares(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'cache/x': 'x'})
	_v0(job)
	pending = _resumable_pending(job, os.path.join(job.monitor, 'a.txt'))
	deltas = _count_deltas(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, 'cache/\n'))
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		versions = wait_for_committed_count(job, 2)
		assert not os.path.exists(pending) and deltas
		assert not os.path.lexists(os.path.join(versions[1], 'cache'))
	finally:
		_stop(thread)


def test_unchanged_list_resumes_pending(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job, rv.SkipList(job.monitor, ['*.tmp']))
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed')
	pending = _resumable_pending(job, a)
	deltas = _count_deltas(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor, _skip_file(job, '*.tmp\n'))
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		versions = wait_for_committed_count(job, 2)
		# the resumed batch is backed up as it is; only the full comparison that follows it compares the tree
		assert not os.path.exists(pending) and all(count >= 2 for count in deltas)
		assert open(os.path.join(versions[1], 'a.txt')).read() == 'changed'
	finally:
		_stop(thread)


def test_upgrade_without_skip_list_resumes_pending(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.conn.execute("DELETE FROM meta WHERE key = 'skip_fingerprint'")
	manifest.close()
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed')
	pending = _resumable_pending(job, a)
	deltas = _count_deltas(monkeypatch)
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		wait_for_committed_count(job, 2)
		# the resumed batch is backed up as it is; only the full comparison that follows it compares the tree
		assert not os.path.exists(pending) and all(count >= 2 for count in deltas)
	finally:
		_stop(thread)


def test_stop_before_watches_are_in_place_keeps_pending(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	pending = _resumable_pending(job, os.path.join(job.monitor, 'a.txt'))
	startup = rv.JobStartup(job.job_name, job.monitor)
	thread = _run_backuper(job, startup)
	wait_until(startup.loaded.is_set)
	_stop(thread)
	assert not thread.is_alive() and os.path.exists(pending)
	assert 'full_scan' not in open(pending).read()


def test_stop_before_deciding_saves_queued_events_as_full_scan(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	pending = _resumable_pending(job, os.path.join(job.monitor, 'a.txt'))
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	startup = rv.JobStartup(job.job_name, job.monitor)
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A',
		threading.Event(), flag), kwargs=dict(startup=startup), daemon=True)
	thread.start()
	wait_until(startup.loaded.is_set)
	# the watcher queued an event, then the daemon stopped before the backuper saw its watches were in place
	with lock:
		queue.append(rv.ChangeEvent(5.0, False, 'create', os.path.join(job.monitor, 'b.txt'), None))
	_stop(thread)
	assert not thread.is_alive() and 'full_scan' in open(pending).read()


def test_the_vault_scan_runs_while_the_job_waits_for_its_monitored_path(job, poll_fast):
	# a job restarted with its monitored path missing still has the orphan of a killed copy removed, by the scan, before
	# the path comes back
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_incomplete_version(job, 1, {'a.txt': 'partial'})
	shutil.rmtree(job.monitor)
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		wait_until(lambda: not os.path.lexists(orphan))
		assert thread.is_alive() and not startup.loaded.is_set()
		assert len(committed_versions(job)) == 1
	finally:
		_stop(thread)


def test_a_restart_with_only_scans_pending_compares_the_whole_tree(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'disk/x': 'x'})
	_age(job)                                               # every monitored entry at mtime 1000, before V0
	_v0(job)
	# while the daemon is down, outside the scanned folder
	os.chmod(os.path.join(job.monitor, 'a.txt'), 0o600)
	b = os.path.join(job.monitor, 'b.txt')
	open(b, 'w').write('changed while down')
	os.utime(b, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None)])
	os.utime(pending, (2000, 2000))
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		v1 = wait_for_committed_count(job, 2)[1]
	finally:
		_stop(thread)
	assert not os.path.exists(pending)
	assert open(os.path.join(v1, 'b.txt')).read() == 'changed while down'
	assert os.stat(os.path.join(v1, 'a.txt')).st_mode & 0o777 == 0o600


def test_a_resumed_scan_with_differences_is_followed_by_a_full_comparison(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'disk/x': 'x'})
	_age(job)
	_v0(job)
	b, x = os.path.join(job.monitor, 'b.txt'), os.path.join(job.monitor, 'disk', 'x')
	for path, text in ((b, 'changed while down'), (x, 'x changed while down')):
		open(path, 'w').write(text)
		os.utime(path, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None)])
	os.utime(pending, (2000, 2000))
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = _run_backuper(job, startup)
	try:
		v1, v2 = wait_for_committed_count(job, 3)[1:3]     # the resumed scan's version, then the follow-up's
	finally:
		_stop(thread)
	assert open(os.path.join(v1, 'disk', 'x')).read() == 'x changed while down'
	assert open(os.path.join(v2, 'b.txt')).read() == 'changed while down'
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.matched[0] == os.path.basename(v2)      # the follow-up advanced it; the resumed batch carried nothing
	manifest.close()
