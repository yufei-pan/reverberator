import os
import subprocess
import threading
import time
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until

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
