import os
import subprocess
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, tracked_manifest, wait_until

def _privileged():
	return os.geteuid() == 0 or os.environ.get('REVERB_PRIVILEGED') == '1'

needs_root = pytest.mark.skipif(not _privileged(), reason='needs root to mount tmpfs')


@pytest.mark.unit
def test_change_events_skip_scan_events():
	entries = rv.change_events_to_backup_entries([rv.ChangeEvent(1.0, True, 'scan', '/tmp/reverb_doctest/m', None)])
	assert entries == {}


@pytest.mark.unit
def test_subscribe_calls_back_with_the_table(tmp_path, monkeypatch):
	table_file = tmp_path / 'mountinfo'
	table_file.write_bytes(b'22 1 8:1 / / rw - ext4 /dev/sda1 rw\n')
	monitor = rv.fs_signature_monitor(mountinfo_path=str(table_file))
	seen = []
	token = monitor.subscribe(seen.append)
	monitor.check_changed()
	monitor.unsubscribe(token)
	assert seen and [mount_point for mount_point, _ in seen[-1]] == ['/']


def _events(queue, lock):
	with lock:
		return list(queue)


def _start(job, irm=None, skip_list=None):
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	watching = threading.Event()
	thread = threading.Thread(target=rv.watchFolder, kwargs=dict(monitor_path=job.monitor, to_process=queue,
		to_process_lock=lock, to_process_flag=threading.Event(), irm=rv.inotify_resource_manager() if irm is None else irm,
		min_snapshot_delay_seconds=0, max_shapshot_delay_seconds=60, skip_list=skip_list, watching=watching), daemon=True)
	thread.start()
	# a mount change before the watcher has looked is not one it can see: wait until its watches are in place
	assert watching.wait(10), 'watcher did not start'
	return thread, queue, lock


@pytest.mark.privileged
@needs_root
def test_watcher_survives_inner_unmount_and_rewatches_on_remount(job, poll_fast):
	inner = os.path.join(job.monitor, 'disk')
	os.makedirs(inner)
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
	try:
		os.makedirs(os.path.join(inner, 'a', 'b'))
		thread, queue, lock = _start(job)
		wait_until(lambda: thread.is_alive(), timeout=2)
		subprocess.check_call(['umount', inner])
		wait_until(lambda: any(e.event == 'scan' and e.path.rstrip('/') == inner for e in _events(queue, lock)), timeout=10, message='no scan on unmount')
		assert thread.is_alive()
		subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
		wait_until(lambda: sum(e.event == 'scan' for e in _events(queue, lock)) >= 2, timeout=10, message='no scan on remount')
		target = os.path.join(inner, 'new.txt')
		open(target, 'w').write('x')
		wait_until(lambda: any(e.path == target for e in _events(queue, lock)), timeout=10, message='remounted disk not watched')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=3)
		rv.GREEN_LIGHT.set()
		subprocess.call(['umount', inner])


ROOT_LINE = '22 1 8:1 / / rw - ext4 /dev/sda1 rw\n'


def _mount_line(mount_id, path, source='tmpfs'):
	# mountinfo octal-escapes spaces and the like; the test paths have none
	return f'{mount_id} 22 0:{mount_id} / {path} rw - tmpfs {source} rw\n'


@pytest.fixture
def fake_mount_table(tmp_path, monkeypatch):
	'''A mount table file the watcher, current_mount_table and a fresh shared monitor all read; write() replaces it and
	has the monitor deliver it to its subscribers.'''
	path = str(tmp_path / 'fake_mountinfo')
	with open(path, 'w', encoding='utf-8') as f:
		f.write(ROOT_LINE)
	monitor = rv.fs_signature_monitor(mountinfo_path=path)
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', path)
	monkeypatch.setattr(rv, 'FS_SIGNATURE_MONITOR', monitor)

	class Table:
		def __init__(self):
			self.monitor = monitor

		def write(self, *lines):
			with open(path, 'w', encoding='utf-8') as f:
				f.write(ROOT_LINE + ''.join(lines))
			monitor.wake()
	return Table()


@pytest.mark.unit
def test_inner_mount_points_resolve_the_monitored_path(tmp_path):
	real = tmp_path / 'real'
	(real / 'disk').mkdir(parents=True)
	link = tmp_path / 'link'
	link.symlink_to(real)
	table = [('/', ('1',)), (str(real), ('2',)), (str(real / 'disk'), ('3',)), (str(real / 'disk'), ('4',)),
		(str(tmp_path / 'realx'), ('5',))]
	assert rv.inner_mount_points(table, str(link)) == [str(real / 'disk')]
	# the watcher works with paths under the monitored path as given, and sees the topmost of stacked mounts
	assert rv.watched_inner_mounts(table, str(link)) == {str(link / 'disk'): ('4',)}


@pytest.mark.unit
def test_watched_inner_mounts_leave_out_skipped_folders(tmp_path):
	monitor = str(tmp_path / 'm')
	table = [('/', ('1',)), (monitor + '/disk', ('2',)), (monitor + '/cache/disk', ('3',)), (monitor + '/keep', ('4',))]
	skip_list = rv.SkipList(monitor, ['disk/', 'cache/', '!cache/disk/'])
	assert rv.watched_inner_mounts(table, monitor, skip_list) == {monitor + '/keep': ('4',)}


@pytest.mark.unit
def test_current_mount_table_is_empty_when_unreadable(tmp_path, monkeypatch):
	monkeypatch.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'missing'))
	assert rv.current_mount_table() == []


@pytest.mark.unit
def test_subscriber_gets_no_table_after_unsubscribing(tmp_path):
	table_file = tmp_path / 'mountinfo'
	table_file.write_bytes(ROOT_LINE.encode())
	monitor = rv.fs_signature_monitor(mountinfo_path=str(table_file))
	monitor.start = lambda: None
	seen = []
	token = monitor.subscribe(seen.append)
	monitor.check_changed()
	monitor.unsubscribe(token)
	monitor.check_changed()
	assert len(seen) == 1
	# an unreadable table is no table: subscribers are not told every mount went away
	other = []
	monitor.subscribe(other.append)
	table_file.unlink()
	monitor.check_changed()
	assert other == []


@pytest.mark.inotify
def test_watcher_follows_inner_mounts_in_the_mount_table(job, poll_fast, fake_mount_table):
	inner = os.path.join(job.monitor, 'disk')
	seed_monitor(job, {'disk/sub/': None})
	thread, queue, lock = _start(job)
	try:
		# the table says a disk was mounted on the folder: its subtree is watched again and compared
		fake_mount_table.write(_mount_line(40, inner))
		wait_until(lambda: [e.path for e in _events(queue, lock) if e.event == 'scan'] == [inner], timeout=5, message='no scan on mount')
		target = os.path.join(inner, 'sub', 'new.txt')
		open(target, 'w').write('x')
		wait_until(lambda: any(e.path == target for e in _events(queue, lock)), timeout=5, message='mounted subtree not watched')
		# a table change elsewhere is no change of the inner mount
		fake_mount_table.write(_mount_line(40, inner), _mount_line(41, '/elsewhere'))
		time.sleep(0.3)
		assert sum(e.event == 'scan' for e in _events(queue, lock)) == 1
		# a disk mounted again (or on top) at the same point is a new disk
		fake_mount_table.write(_mount_line(42, inner))
		wait_until(lambda: sum(e.event == 'scan' for e in _events(queue, lock)) == 2, timeout=5, message='no scan on remount')
		fake_mount_table.write()
		wait_until(lambda: sum(e.event == 'scan' for e in _events(queue, lock)) == 3, timeout=5, message='no scan on unmount')
		target = os.path.join(inner, 'sub', 'after.txt')
		open(target, 'w').write('x')
		wait_until(lambda: any(e.path == target for e in _events(queue, lock)), timeout=5, message='mount point folder not watched')
		assert all(e.path == inner and e.is_dir for e in _events(queue, lock) if e.event == 'scan')
		assert thread.is_alive()
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=3)
		rv.GREEN_LIGHT.set()
	assert not thread.is_alive()
	assert not fake_mount_table.monitor.subscribers


def _inotify_fds():
	fds = set()
	for fd in os.listdir('/proc/self/fd'):
		try:
			if os.readlink(f'/proc/self/fd/{fd}') == 'anon_inode:inotify':
				fds.add(fd)
		except OSError:
			continue
	return fds


def _kernel_watches(fds):
	'''How many watches the kernel holds for these inotify instances.'''
	count = 0
	for fd in fds:
		with open(f'/proc/self/fdinfo/{fd}', encoding='utf-8') as f:
			count += sum(line.startswith('inotify wd:') for line in f)
	return count


@pytest.mark.inotify
def test_watcher_leaves_skipped_inner_mounts_alone(job, poll_fast, fake_mount_table):
	seed_monitor(job, {'disk/': None, 'keep/': None})
	irm = rv.inotify_resource_manager()
	before = _inotify_fds()
	thread, queue, lock = _start(job, irm=irm, skip_list=rv.SkipList(job.monitor, ['disk/']))
	try:
		watcher_fds = _inotify_fds() - before
		fake_mount_table.write(_mount_line(40, os.path.join(job.monitor, 'disk')), _mount_line(41, os.path.join(job.monitor, 'keep')))
		wait_until(lambda: any(e.event == 'scan' for e in _events(queue, lock)), timeout=5, message='no scan on mount')
		fake_mount_table.write()
		wait_until(lambda: sum(e.event == 'scan' for e in _events(queue, lock)) == 2, timeout=5, message='no scan on unmount')
		assert [e.path for e in _events(queue, lock) if e.event == 'scan'] == [os.path.join(job.monitor, 'keep')] * 2
		# re-watching counted what it took and gave back: the root and keep/, as the kernel holds them
		assert irm.current_user_watches == _kernel_watches(watcher_fds) == 2
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=3)
		rv.GREEN_LIGHT.set()
	assert irm.current_user_watches == 0


@pytest.mark.unit
def test_a_watch_that_cannot_be_added_is_not_counted(tmp_path):
	class Refusing:
		def add_watch(self, path, mask):
			raise OSError(13, 'Permission denied')
	irm = rv.inotify_resource_manager()
	assert rv.initializeFolderWatchers(Refusing(), str(tmp_path), rv.bidict(), irm, 0) == -1
	assert irm.current_user_watches == 0


from collections import OrderedDict
from tests.harness import committed_versions, content_file_path, wait_for_committed_count


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fake_mounts(monkeypatch, job, mounted):
	table = [('/', ('1',))] + [(os.path.join(job.monitor, rel.rstrip('/')), (rel,)) for rel in mounted]
	monkeypatch.setattr(rv, 'current_mount_table', lambda: table)


@pytest.mark.unit
def test_unmounted_inner_disk_is_paused_not_deleted(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f', 'disk/sub/g.txt': 'g'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	for name in ('f.txt', 'sub/g.txt'):
		os.remove(os.path.join(job.monitor, 'disk', name))
	os.rmdir(os.path.join(job.monitor, 'disk', 'sub'))   # the mount point now looks like an empty folder
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_, manifest, _ = _backup(job)
	assert manifest.inner_mounts == ['disk/']
	manifest.close()
	v1 = committed_versions(job)[1]
	assert os.path.lexists(os.path.join(v1, 'disk', 'f.txt')) and os.path.lexists(os.path.join(v1, 'disk', 'sub', 'g.txt'))


@pytest.mark.unit
def test_paused_mount_survives_restart(job, poll_fast, monkeypatch):
	seed_monitor(job, {'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	_backup(job)[1].close()          # a fresh manifest object, as after a restart
	assert os.path.lexists(os.path.join(committed_versions(job)[-1], 'disk', 'f.txt'))


@pytest.mark.unit
@pytest.mark.parametrize('retire', ['remove', 'repopulate'])
def test_retiring_the_mount_point_ends_the_pause(job, poll_fast, monkeypatch, retire):
	seed_monitor(job, {'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	if retire == 'remove':
		os.rmdir(os.path.join(job.monitor, 'disk'))
	else:
		open(os.path.join(job.monitor, 'disk', 'other.txt'), 'w').write('o')
	_backup(job)[1].close()
	latest = committed_versions(job)[-1]
	assert not os.path.lexists(os.path.join(latest, 'disk', 'f.txt'))


@pytest.mark.unit
def test_scoped_delta_compares_only_the_scope(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_, manifest, _ = _backup(job)
	latest = rv.get_vault_info(job.job_vault).vault_info_dict
	latest = latest[next(reversed(latest))]
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('outside change')
	open(os.path.join(job.monitor, 'disk', 'f.txt'), 'w').write('inside change')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest, job.monitor, manifest=manifest, scope_rel='disk/')
	manifest.close()
	assert list(entries) == [os.path.join(job.monitor, 'disk', 'f.txt')]


@pytest.mark.unit
def test_backuper_handles_scan_events(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('outside')
	open(os.path.join(job.monitor, 'disk', 'f.txt'), 'w').write('inside')
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
	queue.append(rv.ChangeEvent(2.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, threading.Lock(), job.monitor, job.vault, 'N/A',
		threading.Event(), flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
		v1 = wait_for_committed_count(job, 2)[1]
		assert open(os.path.join(v1, 'a.txt')).read() == 'outside'
		assert open(os.path.join(v1, 'disk', 'f.txt')).read() == 'inside'
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


@pytest.mark.privileged
@needs_root
def test_tmpfs_inner_disk_pause_and_remount(job, poll_fast):
	inner = os.path.join(job.monitor, 'disk')
	os.makedirs(inner)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('a')
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
	try:
		open(os.path.join(inner, 'f.txt'), 'w').write('f')
		_backup(job)[1].close()
		subprocess.check_call(['umount', inner])
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
		_backup(job)[1].close()
		assert os.path.lexists(os.path.join(committed_versions(job)[1], 'disk', 'f.txt'))
		subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
		open(os.path.join(inner, 'f.txt'), 'w').write('remounted')
		_, manifest, _ = _backup(job)
		manifest.close()
		assert open(os.path.join(committed_versions(job)[2], 'disk', 'f.txt')).read() == 'remounted'
	finally:
		subprocess.call(['umount', inner])


@pytest.mark.unit
def test_paused_inner_mounts_need_an_empty_unmounted_folder(tmp_path):
	monitor = str(tmp_path / 'm')
	for rel in ('empty/', 'full/', 'mounted/', 'outer/'):
		os.makedirs(os.path.join(monitor, rel))
	open(os.path.join(monitor, 'full', 'x'), 'w').close()
	open(os.path.join(monitor, 'file'), 'w').close()
	os.symlink('empty', os.path.join(monitor, 'link'))
	table = [('/', ('1',)), (os.path.join(monitor, 'mounted'), ('2',))]
	remembered = ['empty/', 'full/', 'mounted/', 'gone/', 'file/', 'link/', 'outer/', 'outer/inner/']
	# outer/inner/ is gone with its outer disk, which keeps it
	assert rv.paused_inner_mounts(monitor, remembered, table) == {'empty/', 'outer/'}


@pytest.mark.unit
def test_manifest_remembers_inner_mounts_and_lists_unseen_rows_of_a_folder(tmp_path):
	version = str(tmp_path / 'V0--2021-01-01_00-00-00_-0800')
	manifest = tracked_manifest(str(tmp_path), version, files=['a/x', 'a/y', 'ab', 'b/z'], folders=['a/', 'b/'])
	try:
		assert manifest.inner_mounts == []
		manifest.begin()
		manifest.set_inner_mounts(['a/', 'b/c/'])
		manifest.commit()
		manifest.clear_seen()
		manifest.mark_seen(['a/x', 'b/z'])
		assert manifest.unseen_under('a/') == ['a/', 'a/y']
		assert manifest.unseen() == ['a/', 'a/y', 'ab', 'b/']
	finally:
		manifest.close()
	reopened = rv.VaultManifest(str(tmp_path))
	try:
		assert reopened.inner_mounts == ['a/', 'b/c/']
	finally:
		reopened.close()


@pytest.mark.unit
def test_events_under_a_paused_mount_are_dropped(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f', 'disk/g.txt': 'g'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	for name in ('f.txt', 'g.txt'):
		os.remove(os.path.join(job.monitor, 'disk', name))
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	# what the disk saw before it went, taken after it went
	entries = rv.change_events_to_backup_entries([
		rv.ChangeEvent(1.0, False, 'delete', os.path.join(job.monitor, 'disk', 'f.txt'), None),
		rv.ChangeEvent(2.0, False, 'move', os.path.join(job.monitor, 'moved.txt'), os.path.join(job.monitor, 'disk', 'g.txt')),
		rv.ChangeEvent(3.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None)])
	open(os.path.join(job.monitor, 'moved.txt'), 'w').write('g')
	_backup(job, entries)[1].close()
	v1 = committed_versions(job)[1]
	assert os.path.lexists(os.path.join(v1, 'disk', 'f.txt')) and os.path.lexists(os.path.join(v1, 'disk', 'g.txt'))
	assert open(os.path.join(v1, 'moved.txt')).read() == 'g'
	assert open(os.path.join(v1, 'a.txt')).read() == 'changed'


def _run_backuper(job, queue, control, to_process_flag, lock=None):
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock or threading.Lock(), job.monitor, job.vault,
		'N/A', to_process_flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	return thread


@pytest.mark.unit
def test_scan_of_a_paused_mount_runs_no_backup(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	scopes = []
	delta = rv.delta_generate_backup_entries
	def recording_delta(*args, **kwargs):
		scopes.append(kwargs.get('scope_rel', ''))
		return delta(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', recording_delta)
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	queue.append(rv.ChangeEvent(1.0, False, 'delete', os.path.join(job.monitor, 'disk', 'f.txt'), None))
	queue.append(rv.ChangeEvent(2.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	to_process_flag = threading.Event()
	thread = _run_backuper(job, queue, control, to_process_flag, lock)
	try:
		wait_until(lambda: not queue, timeout=5, message='batch not taken')
		# a batch that needs no new version still counts as a clean backup
		assert control.committed.wait(5)
		# the next batch backs up as usual
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
		with lock:
			queue.append(rv.ChangeEvent(3.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
		to_process_flag.set()
		v1 = wait_for_committed_count(job, 2)[1]
		assert open(os.path.join(v1, 'a.txt')).read() == 'changed'
		assert os.path.lexists(os.path.join(v1, 'disk', 'f.txt'))
		# the paused scan neither compared the whole tree nor made a version of its own
		assert '' not in scopes
		assert len(committed_versions(job)) == 2
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


@pytest.mark.unit
@pytest.mark.parametrize('event', ['scan', 'full_scan'])
def test_a_changed_monitored_filesystem_fails_the_job_before_comparing(job, poll_fast, monkeypatch, event):
	seed_monitor(job, {'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	to_process_flag = threading.Event()
	thread = _run_backuper(job, queue, control, to_process_flag, lock)
	try:
		# the startup comparison finds nothing new
		assert control.committed.wait(5)
		# the monitored disk is lazily unmounted: its inner mount leaves the table, and the path shows another
		# filesystem, which has no disk folder
		monkeypatch.setattr(rv, 'current_mount_table', lambda: [('/', ('1',)), (job.monitor, ('other',))])
		import shutil
		shutil.rmtree(os.path.join(job.monitor, 'disk'))
		with lock:
			queue.append(rv.ChangeEvent(5.0, True, event, os.path.join(job.monitor, 'disk') if event == 'scan' else job.monitor, None))
		to_process_flag.set()
		thread.join(timeout=5)
		assert not thread.is_alive()
		assert control.failure is not None and not control.failure.permanent
		assert f'the monitored filesystem changed under {job.monitor}' in control.failure.reason
		# the batch waits for the job's next attempt, and nothing was recorded as deleted
		assert [e.event for e in queue] == [event]
		assert len(committed_versions(job)) == 1
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


@pytest.mark.unit
def test_scoped_delta_keeps_a_folder_it_cannot_look_at_and_drops_one_that_is_gone(job, poll_fast, monkeypatch):
	import errno
	import shutil
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_, manifest, _ = _backup(job)
	try:
		latest = rv.get_vault_info(job.job_vault).vault_info_dict
		latest = latest[next(reversed(latest))]
		disk = os.path.join(job.monitor, 'disk')
		real_lstat = os.lstat
		def failing_lstat(path, *args, **kwargs):
			if path == disk:
				raise OSError(errno.EIO, 'Input/output error', path)
			return real_lstat(path, *args, **kwargs)
		monkeypatch.setattr(rv.os, 'lstat', failing_lstat)
		entries = OrderedDict()
		rv.delta_generate_backup_entries(entries, latest, job.monitor, manifest=manifest, scope_rel='disk/')
		monkeypatch.setattr(rv.os, 'lstat', real_lstat)
		assert entries == {}
		shutil.rmtree(disk)
		rv.delta_generate_backup_entries(entries, latest, job.monitor, manifest=manifest, scope_rel='disk/')
		assert {path: values.event for path, values in entries.items()} == {disk + '/': 'delete', disk + '/f.txt': 'delete'}
	finally:
		manifest.close()


@pytest.mark.unit
def test_inner_disk_unmounted_during_a_full_comparison_is_not_deleted(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	state = {'table': [('/', ('1',)), (os.path.join(job.monitor, 'disk'), ('d',))], 'unmounted': False}
	monkeypatch.setattr(rv, 'current_mount_table', lambda: state['table'])
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	real = rv.paused_inner_mounts
	def deciding_then_unmounting(*args, **kwargs):
		result = real(*args, **kwargs)
		if not state['unmounted']:
			# the disk is unmounted right after do_backup decided what is paused, before the walk reaches it
			state['unmounted'] = True
			os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
			state['table'] = [('/', ('1',))]
		return result
	monkeypatch.setattr(rv, 'paused_inner_mounts', deciding_then_unmounting)
	_, manifest, _ = _backup(job)
	try:
		assert manifest.inner_mounts == ['disk/']
	finally:
		manifest.close()
	v1 = committed_versions(job)[1]
	assert os.path.lexists(os.path.join(v1, 'disk', 'f.txt'))
	assert open(os.path.join(v1, 'a.txt')).read() == 'changed'
	assert os.path.join(job.monitor, 'disk') not in open(content_file_path(v1)).read()


@pytest.mark.unit
def test_a_remembered_folder_that_cannot_be_inspected_stays_paused(job, poll_fast, monkeypatch):
	import errno
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	disk = os.path.join(job.monitor, 'disk')
	os.remove(os.path.join(disk, 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	real_lstat = os.lstat
	def failing_lstat(path, *args, **kwargs):
		if path == disk:
			raise OSError(errno.EIO, 'Input/output error', path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', failing_lstat)
	try:
		assert rv.paused_inner_mounts(job.monitor, ['disk/'], rv.current_mount_table()) == {'disk/'}
		_, manifest, _ = _backup(job)
	finally:
		monkeypatch.setattr(rv.os, 'lstat', real_lstat)
	try:
		assert manifest.inner_mounts == ['disk/']
	finally:
		manifest.close()
	assert os.path.lexists(os.path.join(committed_versions(job)[1], 'disk', 'f.txt'))


@pytest.mark.unit
def test_a_skipped_inner_mount_is_neither_paused_nor_remembered(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	os.makedirs(os.path.join(job.monitor, 'cache', 'usb'))
	_fake_mounts(monkeypatch, job, ['cache/usb/'])
	# the disk's folder is added to the skip list while it is unmounted, and a disk is mounted in a skipped folder
	skip_list = rv.SkipList(job.monitor, ['disk/', 'cache/'])
	assert rv.paused_inner_mounts(job.monitor, ['disk/'], rv.current_mount_table(), skip_list.skips) == set()
	_, manifest, _ = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', skip_list=skip_list)
	try:
		assert manifest.inner_mounts == []
	finally:
		manifest.close()
	assert not os.path.lexists(os.path.join(committed_versions(job)[-1], 'disk', 'f.txt'))


@pytest.mark.unit
def test_an_unreadable_folder_in_a_scanned_disk_is_reported_once(job, poll_fast, monkeypatch):
	import errno
	seed_monitor(job, {'a.txt': 'a', 'disk/': None})
	_fake_mounts(monkeypatch, job, [])
	_backup(job)[1].close()
	# a disk is mounted on the folder, holding a folder that cannot be read
	seed_monitor(job, {'disk/new.txt': 'n', 'disk/bad/x': 'x'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	bad = os.path.join(job.monitor, 'disk', 'bad')
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == bad:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)
	lines = []
	monkeypatch.setattr(rv, 'job_log', lambda job_name, text: lines.append(text) or text)
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = _run_backuper(job, queue, control, threading.Event())
	try:
		v1 = wait_for_committed_count(job, 2)[1]
		assert open(os.path.join(v1, 'disk', 'new.txt')).read() == 'n'
		assert sum(line.startswith(f'UNREADABLE: {bad}:') for line in lines) == 1
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()
