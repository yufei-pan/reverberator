import errno
import os
import shutil
import subprocess
import threading
import time
import pytest
import reverberator as rv
from tests.harness import committed_versions, event_entry, on_folder_open, run_backup, seed_monitor, tracked_manifest, wait_until
from tests.test_restore_lock import _logged_lines as _lines

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



@pytest.mark.privileged
@needs_root
def test_a_walk_of_the_root_tells_again_what_is_unwatched_in_an_inner_mount(tmp_path, monkeypatch):
	root = str(tmp_path / 'm')
	inner = os.path.join(root, 'disk')
	os.makedirs(inner)
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
	try:
		u = os.path.join(inner, 'u')
		os.makedirs(os.path.join(u, 'v'))
		def fail():
			raise OSError(errno.EIO, os.strerror(errno.EIO), u)
		on_folder_open(monkeypatch, u, fail)
		irm = rv.inotify_resource_manager()
		wdDic, unwatched = {}, set()
		with rv.inotify_simple.INotify() as inotify_obj:
			rv.initializeFolderWatchers(inotify_obj, root, wdDic, irm, rv.inotify_simple.flags.CREATE, unwatched=unwatched)
			assert inner + '/' in wdDic.values() and unwatched == {u}
			# the walk goes into the inner mount, so a walk of the root, which drops what it held under the root, adds u back
			rv.initializeFolderWatchers(inotify_obj, root, wdDic, irm, rv.inotify_simple.flags.CREATE, unwatched=unwatched)
			assert unwatched == {u}
	finally:
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
	assert rv.initializeFolderWatchers(Refusing(), str(tmp_path), {}, irm, 0) == -1
	assert irm.current_user_watches == 0


from collections import OrderedDict
from tests.harness import change_list_of, committed_versions, wait_for_committed_count


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fake_disk(name):
	'''The fingerprint of a fake disk called name, the same at every read.'''
	return (name.encode(), b'0:0', b'/', b'fake:' + name.encode(), b'xfs')


def _real_table():
	with open(rv.MOUNTINFO_PATH, 'rb') as f:
		return rv.parse_mount_table(f.read())


def _fake_mounts(monkeypatch, job, mounted):
	'''The real mount table, with a fake disk mounted at each folder rel of mounted. At the source: a batch's waits read it, and current_mount_table() goes through it.'''
	table = _real_table() + [(os.path.join(job.monitor, rel.rstrip('/')), _fake_disk(rel)) for rel in mounted]
	monkeypatch.setattr(rv, 'read_mount_table', lambda: list(table))


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
	queue, lock, to_process_flag = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A',
		to_process_flag, flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
		# the start's full comparison first, then the changes and their batch: f.txt, with no event of its own, comes by the scan
		assert control.committed.wait(5)
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('outside')
		open(os.path.join(job.monitor, 'disk', 'f.txt'), 'w').write('inside')
		with lock:
			queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
			queue.append(rv.ChangeEvent(2.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
		to_process_flag.set()
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
		# never recorded: a reader takes the newest version's record instead (rv.remembered_inner_mounts())
		assert manifest.inner_mounts is None
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
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	to_process_flag = threading.Event()
	thread = _run_backuper(job, queue, control, to_process_flag, lock)
	try:
		# the start's full comparison, which keeps the paused disk's files, then what the disk saw before it went
		assert control.committed.wait(5)
		del scopes[:]
		control.committed.clear()
		with lock:
			queue.append(rv.ChangeEvent(1.0, False, 'delete', os.path.join(job.monitor, 'disk', 'f.txt'), None))
			queue.append(rv.ChangeEvent(2.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
		to_process_flag.set()
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
		other = _real_table() + [(job.monitor, _fake_disk('other'))]
		monkeypatch.setattr(rv, 'read_mount_table', lambda: list(other))
		import shutil
		shutil.rmtree(os.path.join(job.monitor, 'disk'))
		with lock:
			queue.append(rv.ChangeEvent(5.0, True, event, os.path.join(job.monitor, 'disk') if event == 'scan' else job.monitor, None))
		to_process_flag.set()
		thread.join(timeout=5)
		assert not thread.is_alive()
		assert control.failure is not None and not control.failure.permanent
		assert f'the monitored filesystem changed under {job.monitor}' in control.failure.reason
		# nothing is handed back, as the job's next attempt compares the whole tree first; nothing was recorded as deleted
		assert len(queue) == 0
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
	assert os.path.join(job.monitor, 'disk') not in open(change_list_of(v1)).read()


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
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', skip_list=skip_list)
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
	bad = os.path.join(job.monitor, 'disk', 'bad')
	def fail():
		raise OSError(errno.EIO, os.strerror(errno.EIO), bad)
	on_folder_open(monkeypatch, bad, fail)
	lines = []
	monkeypatch.setattr(rv, 'job_log', lambda job_name, text: lines.append(text) or text)
	queue, lock, to_process_flag = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = _run_backuper(job, queue, control, to_process_flag, lock)
	try:
		# the start's full comparison first; then a disk is mounted on the folder, holding a folder that cannot be read, and
		# its scan comes
		assert control.committed.wait(5)
		seed_monitor(job, {'disk/new.txt': 'n', 'disk/bad/x': 'x'})
		_fake_mounts(monkeypatch, job, ['disk/'])
		with lock:
			queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
		to_process_flag.set()
		v1 = wait_for_committed_count(job, 2)[1]
		assert open(os.path.join(v1, 'disk', 'new.txt')).read() == 'n'
		assert sum(line.startswith(f'UNREADABLE: {bad}:') for line in lines) == 1
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


@pytest.mark.unit
def test_an_inner_disk_unmounted_while_scanned_folders_are_walked_commits_nothing(job, poll_fast, monkeypatch):
	# pin, the re-check's run N3 (passes on main; fails with the waits' table handed to do_backup()): a batch of a scan of
	# disk/, an inner mount, which is unmounted while compare_scanned_folders() walks it. The walk finds the empty folder it
	# left, and the table read after the walk pauses it, so its deletes are dropped: no version, its files stay in the vault
	from tests.test_jobs import one_batch_through_the_backuper
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	disk = os.path.join(job.monitor, 'disk')
	real_table = rv.read_mount_table()
	mounted = real_table + [(os.path.realpath(disk), (b'9999', b'0:99', b'/', b'/dev/fakedisk', b'xfs'))]
	tables = {'now': mounted}
	monkeypatch.setattr(rv, 'read_mount_table', lambda: list(tables['now']))
	_backup(job)[1].close()
	versions = committed_versions(job)
	assert len(versions) == 1
	real = rv.delta_generate_backup_entries
	def walk(*args, **kwargs):
		if kwargs.get('scope_rel') == 'disk/' and tables['now'] is mounted:
			# unmounted: the mount point shows the empty folder under it
			os.remove(os.path.join(disk, 'f.txt'))
			tables['now'] = real_table
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', walk)
	one_batch_through_the_backuper(job, monkeypatch, lambda: [rv.ChangeEvent(time.monotonic(), True, 'scan', disk, None)])
	assert tables['now'] is real_table
	assert committed_versions(job) == versions
	assert os.path.isfile(os.path.join(versions[0], 'disk', 'f.txt'))


def _a_table_you_can_change(monkeypatch, table):
	'''A read_mount_table() that answers what tables['now'] holds, changed by the test as the batch runs.'''
	tables = {'now': table}
	monkeypatch.setattr(rv, 'read_mount_table', lambda: list(tables['now']))
	return tables


@pytest.mark.unit
def test_an_inner_disk_mounted_while_a_full_comparison_copies_is_remembered_by_its_commit(job, poll_fast, monkeypatch):
	# fails with the commit remembering inner mounts from the table read after the comparison's walk (R35): a full comparison
	# runs no verification, so no read follows its walk but the commit's. the disk is mounted during the copy phase, so what it
	# holds is in the version ( the copy of a.txt reads the mount point ), and unmounted before the next batch it would show
	# deleted in the newest version and be copied again on its return
	seed_monitor(job, {'a.txt': 'a', 'disk/': None})
	real_table = rv.read_mount_table()
	disk = os.path.join(job.monitor, 'disk')
	mounted = real_table + [(os.path.realpath(disk), (b'9999', b'0:99', b'/', b'/dev/fakedisk', b'xfs'))]
	tables = _a_table_you_can_change(monkeypatch, real_table)
	_backup(job)[1].close()
	assert tracked_inner_mounts(job) == []
	with open(os.path.join(job.monitor, 'a.txt'), 'w') as f:
		f.write('changed')
	real = rv.cp_af_copy_path
	copied = []
	def copy(source_path, dest_path, *args, **kwargs):
		copied.append(dest_path)
		tables['now'] = mounted
		return real(source_path, dest_path, *args, **kwargs)
	monkeypatch.setattr(rv, 'cp_af_copy_path', copy)
	_backup(job)[1].close()
	assert len(copied) == 1 and len(committed_versions(job)) == 2
	assert tracked_inner_mounts(job) == ['disk/']


def tracked_inner_mounts(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.inner_mounts
	finally:
		manifest.close()


@pytest.mark.unit
def test_a_monitored_mount_gone_while_a_first_version_waits_for_its_locks_commits_no_version(job, poll_fast, monkeypatch):
	# fails with the start check made on the table given before the first version's locks and vault scan (R37): the monitored
	# folder is a mount of its own, unmounted while the locks are taken, and shows the empty folder under it. the check looks
	# at a table read after them, finds another filesystem there, and the job fails, so no empty first version is committed
	seed_monitor(job, {'a.txt': 'a', 'd/b.txt': 'b'})
	real_table = rv.read_mount_table()
	monitor = os.path.realpath(job.monitor)
	mounted = real_table + [(monitor, (b'9999', b'0:99', b'/', b'/dev/fakedisk', b'xfs'))]
	tables = _a_table_you_can_change(monkeypatch, mounted)
	root_mount = rv.mount_fingerprint(mounted, monitor)
	real_take = rv.BackupLocks.take
	def take(self, *args, **kwargs):
		taken = real_take(self, *args, **kwargs)
		os.remove(os.path.join(job.monitor, 'a.txt'))
		shutil.rmtree(os.path.join(job.monitor, 'd'))
		tables['now'] = real_table
		return taken
	monkeypatch.setattr(rv.BackupLocks, 'take', take)
	with pytest.raises(rv.JobFailure, match='the monitored filesystem changed'):
		rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, only_sync_attributes=True,
			keep_n_versions=0, backup_size_limit='0', root_mount=root_mount, mount_table=mounted)
	assert committed_versions(job) == []


# ---- D8: a first version looks at the disks again after its walk ---------------------------------------------------------

# a fake disk's fingerprint in a table stood in for, as the tests above give one
FAKE_DISK = (b'9999', b'0:99', b'/', b'/dev/fakedisk', b'xfs')

FIRST_WALK_LINE = "Inner mounts unmounted during the first version's walk, which left out what it had not reached under them: disk/"


def _recorded(job):
	'''(matched, inner_mounts) the job vault's manifest records.'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.matched, manifest.inner_mounts
	finally:
		manifest.close()


def _read(path):
	with open(path, encoding='utf-8') as f:
		return f.read()


@pytest.mark.privileged
@needs_root
def test_a_first_version_walk_meeting_an_inner_disk_unmounted_midway_holds_the_matched_time(job, poll_fast, monkeypatch):
	# fails on main by its line (no line there); the matched time is held on main too in this variant, unlike the Docker one below (the Opus
	# review of Task 10 says so; it needs root, and was not run here): disk/ is an inner tmpfs (bound from one kept
	# aside, so it comes back with what it held), unmounted lazily by a hook in the first version's walk at disk/sub, a folder under it.
	# One line; the matched time is not recorded; the mount is remembered and paused at the next batch; once mounted again, the next
	# full comparison copies what the walk left out
	store, disk = os.path.join(job.root, 'store'), os.path.join(job.monitor, 'disk')
	os.makedirs(store)
	os.makedirs(disk)
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', store])
	try:
		seed_monitor(job, {'a.txt': 'a'})
		os.makedirs(os.path.join(store, 'sub'))
		for rel, text in (('f.txt', 'f'), ('sub/g.txt', 'g')):
			with open(os.path.join(store, rel), 'w', encoding='utf-8') as f:
				f.write(text)
		subprocess.check_call(['mount', '--bind', store, disk])
		lines = _lines(monkeypatch)
		gone = []
		def unmount():
			if not gone:
				gone.append(True)
				subprocess.check_call(['umount', '-l', disk])
		with monkeypatch.context() as walking:
			on_folder_open(walking, os.path.join(disk, 'sub'), unmount)
			run_backup(job, matched_since=time.time_ns())
		assert gone, 'the walk never opened disk/sub'
		assert lines.count(FIRST_WALK_LINE) == 1
		assert _recorded(job) == (None, ['disk/'])
		v0 = committed_versions(job)[0]
		assert not os.path.lexists(os.path.join(v0, 'disk', 'sub', 'g.txt'))
		# the next batch, the disk still away: paused, and the version keeps what the first one holds of it
		with open(os.path.join(job.monitor, 'a.txt'), 'w', encoding='utf-8') as f:
			f.write('changed')
		del lines[:]
		run_backup(job, matched_since=time.time_ns())
		assert 'Inner mounts not mounted, keeping their last backed-up contents: disk/' in lines
		assert _read(os.path.join(committed_versions(job)[1], 'a.txt')) == 'changed'
		# mounted again: the next full comparison copies what the first version's walk left out
		subprocess.check_call(['mount', '--bind', store, disk])
		run_backup(job, matched_since=time.time_ns())
		latest = committed_versions(job)[-1]
		assert _read(os.path.join(latest, 'disk', 'f.txt')) == 'f'
		assert _read(os.path.join(latest, 'disk', 'sub', 'g.txt')) == 'g'
	finally:
		subprocess.call(['umount', disk], stderr=subprocess.DEVNULL)
		subprocess.call(['umount', store])


@pytest.mark.unit
@pytest.mark.parametrize('left', ['a gone create', 'an untracked delete'])
def test_a_batch_the_look_after_the_locks_leaves_with_nothing_to_back_up_commits_no_version(job, poll_fast, monkeypatch, left):
	# R21 (the Task 10 review's M1 (a)): disk/, an inner mount, is unmounted while the batch waits for its locks; the batch holds a modify of
	# disk/f.txt, a change the check before the wait sees, and one more entry that changes nothing once it is alone: a create of a file that is
	# gone by then ("a gone create": entries_all_drop_out() drops it), or a move into disk/ whose source the vault never tracked
	# ("an untracked delete": the look drops the move, which leaves the delete of its source, drop_untracked_deletes() drops that). The look
	# drops the modify, and what is left was checked only before the wait, which it did not hold: a version that changes nothing, which
	# prunes the oldest under Keep N. Now the two checks run again under the locks. Fails on 652397a: a second version
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f', 'plain.txt': 'p'})
	disk = os.path.join(job.monitor, 'disk')
	real_table = rv.read_mount_table()
	mounted = real_table + [(os.path.realpath(disk), FAKE_DISK)]
	tables = _a_table_you_can_change(monkeypatch, mounted)
	_backup(job)[1].close()
	versions = committed_versions(job)
	assert len(versions) == 1 and tracked_inner_mounts(job) == ['disk/']
	with open(os.path.join(disk, 'f.txt'), 'w') as f:
		f.write('changed')
	entries = [event_entry(job, 'disk/f.txt', 'modify')]
	if left == 'a gone create':
		with open(os.path.join(job.monitor, 'new.txt'), 'w') as f:
			f.write('n')
		entries.append(event_entry(job, 'new.txt', 'create'))
	else:
		# a move of a file the vault does not track (never backed up) into disk/: the move is dropped with the disk's entries and leaves
		# the delete of its source, a path the vault has no row of
		with open(os.path.join(job.monitor, 'untracked.txt'), 'w') as f:
			f.write('u')
		os.rename(os.path.join(job.monitor, 'untracked.txt'), os.path.join(disk, 'moved.txt'))
		entries.append(event_entry(job, 'disk/moved.txt', 'move', 'untracked.txt'))
	lines = _lines(monkeypatch)
	real_take = rv.BackupLocks.take
	takes = []
	def take(self, *args, **kwargs):
		taken = real_take(self, *args, **kwargs)
		takes.append(True)
		if len(takes) > 1:
			# the wait for the locks after the comparison: the disk goes (the mount point shows an empty folder), and the create's file with it
			if tables['now'] is mounted:
				os.rename(disk, os.path.join(job.root, 'aside'))
				os.mkdir(disk)
				tables['now'] = real_table
			if left == 'a gone create':
				os.remove(os.path.join(job.monitor, 'new.txt'))
		return taken
	monkeypatch.setattr(rv.BackupLocks, 'take', take)
	vault_info, manifest, committed = _backup(job, OrderedDict(entries))
	manifest.close()
	assert tables['now'] is real_table, 'the batch never waited for its locks again'
	assert any(line.startswith('Inner mounts unmounted during the wait for the locks') for line in lines)
	assert committed is True and committed_versions(job) == versions
	assert os.path.isfile(os.path.join(versions[0], 'disk', 'f.txt')) and _read(os.path.join(versions[0], 'disk', 'f.txt')) == 'f'


@pytest.mark.unit
def test_a_first_version_walk_with_its_inner_mount_gone_from_the_table_pauses_it(job, poll_fast, monkeypatch):
	# fails on main (no line, the matched time recorded): the Docker variant of the test above, the mount table stood in for. disk/,
	# an inner mount, is unmounted as the first version's walk opens it: it leaves the table, and its folder is the empty mount point
	# (what it held moved aside). One line; the matched time is not recorded; the mount is remembered and paused at the next
	# batch; once mounted again, the next full comparison copies what the walk left out
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f', 'disk/sub/g.txt': 'g'})
	disk, aside = os.path.join(job.monitor, 'disk'), os.path.join(job.root, 'aside')
	real_table = rv.read_mount_table()
	mounted = real_table + [(os.path.realpath(disk), FAKE_DISK)]
	tables = _a_table_you_can_change(monkeypatch, mounted)
	def unmount():
		if tables['now'] is mounted:
			os.rename(disk, aside)
			os.mkdir(disk)
			tables['now'] = real_table
	lines = _lines(monkeypatch)
	with monkeypatch.context() as walking:
		on_folder_open(walking, disk, unmount)
		run_backup(job, matched_since=time.time_ns())
	assert tables['now'] is real_table, 'the walk never opened disk/'
	assert lines.count(FIRST_WALK_LINE) == 1
	assert _recorded(job) == (None, ['disk/'])
	v0 = committed_versions(job)[0]
	assert os.path.isdir(os.path.join(v0, 'disk')) and os.listdir(os.path.join(v0, 'disk')) == []
	# the next batch, the disk still away: paused
	with open(os.path.join(job.monitor, 'a.txt'), 'w', encoding='utf-8') as f:
		f.write('changed')
	del lines[:]
	run_backup(job, matched_since=time.time_ns())
	assert 'Inner mounts not mounted, keeping their last backed-up contents: disk/' in lines
	assert _read(os.path.join(committed_versions(job)[1], 'a.txt')) == 'changed'
	# mounted again: the next full comparison copies what the walk left out
	os.rmdir(disk)
	os.rename(aside, disk)
	tables['now'] = mounted
	run_backup(job, matched_since=time.time_ns())
	latest = committed_versions(job)[-1]
	assert _read(os.path.join(latest, 'disk', 'f.txt')) == 'f'
	assert _read(os.path.join(latest, 'disk', 'sub', 'g.txt')) == 'g'


# ---- D7: a batch that waited for its locks looks at the disks again --------------------------------------------------------

# each D7 test runs on a real mount in the test VM, and on the mount table stood in for in Docker
VENUES = [pytest.param('vm', marks=[pytest.mark.privileged, needs_root]), pytest.param('stand_in', marks=pytest.mark.unit)]


class _Disk:
	'''
	A disk mounted at folder: a real tmpfs in the test VM ('vm'), unmounted lazily; else ('stand_in') a fake disk in the table
	read_mount_table() answers, whose unmount takes it out of the table and moves what it held aside, leaving the empty folder.
	'''
	def __init__(self, monkeypatch, venue, folder, aside):
		self.venue, self.folder, self.aside = venue, folder, aside
		os.makedirs(folder, exist_ok=True)
		if venue == 'vm':
			subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', folder])
		else:
			self.real_table = rv.read_mount_table()
			self.tables = _a_table_you_can_change(monkeypatch, self.real_table + [(os.path.realpath(folder), FAKE_DISK)])

	def unmount(self):
		if self.venue == 'vm':
			subprocess.check_call(['umount', '-l', self.folder])
		else:
			os.rename(self.folder, self.aside)
			os.mkdir(self.folder)
			self.tables['now'] = self.real_table

	def close(self):
		if self.venue == 'vm':
			subprocess.call(['umount', self.folder], stderr=subprocess.DEVNULL)


def _a_batch_held_at_the_locks(job, monkeypatch, entries, meanwhile, **options):
	'''
	do_backup() of entries in a thread of its own while the test holds the job's restore lock, as a restore that copies holds it:
	once the batch says it waits for its locks, meanwhile() runs, and the lock is let go. (the batch's thread, once it ended: its
	committed and error; the lines logged from the start)
	'''
	from tests.test_restore_lock import WAITING, Backup, Held
	lines = _lines(monkeypatch)
	restore = Held('restore')
	try:
		# the vault known already, as it is to every batch after a job's start: one with none takes its locks first
		backup = Backup(job, entries, vaultInfo=rv.get_vault_info(job.job_vault), matched_since=time.time_ns(), **options)
		wait_until(lambda: WAITING in lines, message='the batch never waited for its locks')
		meanwhile()
	finally:
		restore.release()
	backup.join(10)
	assert not backup.is_alive(), 'the batch did not end'
	return backup, lines


@pytest.mark.parametrize('venue', VENUES)
def test_a_batch_whose_monitored_disk_goes_while_it_waits_for_its_locks_commits_nothing(job, poll_fast, monkeypatch, venue):
	# fails on main (a version without the file): the monitored path is a disk of its own, and a batch (a.txt changed, b.txt new)
	# waits for its locks behind a restore while the disk is unmounted. The look after the locks finds another filesystem at the
	# monitored path: the attempt fails, no version
	disk = _Disk(monkeypatch, venue, job.monitor, os.path.join(job.root, 'aside'))
	try:
		seed_monitor(job, {'a.txt': 'a'})
		root_mount = rv.mount_fingerprint(rv.read_mount_table(), os.path.realpath(job.monitor))
		versions = run_backup(job, root_mount=root_mount, matched_since=time.time_ns())
		seed_monitor(job, {'a.txt': 'changed', 'b.txt': 'b'})
		entries = OrderedDict([event_entry(job, 'a.txt', 'modify'), event_entry(job, 'b.txt', 'create')])
		backup, _ = _a_batch_held_at_the_locks(job, monkeypatch, entries, disk.unmount, root_mount=root_mount)
		assert isinstance(backup.error, rv.JobFailure), backup.error
		assert backup.error.reason == f'the monitored filesystem changed under {job.monitor}'
		assert committed_versions(job) == versions
	finally:
		disk.close()


def _a_monitored_tree_with_an_inner_disk(job, monkeypatch, venue, tree):
	'''disk/, a _Disk inside the monitored folder, and tree (rels under disk/ included) backed up by a first version: the _Disk.'''
	disk = _Disk(monkeypatch, venue, os.path.join(job.monitor, 'disk'), os.path.join(job.root, 'aside'))
	try:
		seed_monitor(job, tree)
		run_backup(job, matched_since=time.time_ns())
	except BaseException:
		disk.close()
		raise
	return disk


@pytest.mark.parametrize('venue', VENUES)
def test_an_inner_mount_gone_during_the_wait_for_the_locks_is_paused(job, poll_fast, monkeypatch, venue):
	# fails on main (no line, disk/old.txt deleted from the version, the matched time moved): a batch of a.txt changed and, on
	# disk/, an inner mount, f.txt changed and old.txt deleted, waits for its locks behind a restore while the disk is unmounted.
	# The look after the locks pauses it: one line; the version holds the new a.txt and keeps the disk's last copies, with no
	# row of its own under disk/; the matched time stays the first version's; the mount is remembered
	disk = _a_monitored_tree_with_an_inner_disk(job, monkeypatch, venue, {'a.txt': 'a', 'disk/f.txt': 'f', 'disk/old.txt': 'o'})
	try:
		(_, since), _ = _recorded(job)
		seed_monitor(job, {'a.txt': 'changed', 'disk/f.txt': 'changed'})
		os.remove(os.path.join(job.monitor, 'disk', 'old.txt'))
		entries = OrderedDict([event_entry(job, 'a.txt', 'modify'), event_entry(job, 'disk/f.txt', 'modify'), event_entry(job, 'disk/old.txt', 'delete')])
		backup, lines = _a_batch_held_at_the_locks(job, monkeypatch, entries, disk.unmount)
		assert backup.error is None and backup.committed is True
		assert [line for line in lines if line.startswith('Inner mounts unmounted during')] == \
			['Inner mounts unmounted during the wait for the locks, keeping their last backed-up contents: disk/; dropped 2 backup entries']
		v1 = committed_versions(job)[1]
		assert _read(os.path.join(v1, 'a.txt')) == 'changed'
		assert _read(os.path.join(v1, 'disk', 'f.txt')) == 'f' and _read(os.path.join(v1, 'disk', 'old.txt')) == 'o'
		assert os.path.join(job.monitor, 'disk') not in _read(change_list_of(v1))
		assert _recorded(job) == ((os.path.basename(v1), since), ['disk/'])
	finally:
		disk.close()


@pytest.mark.parametrize('venue', VENUES)
def test_a_batch_emptied_by_the_look_after_the_locks_makes_no_version_and_releases_them(job, poll_fast, monkeypatch, venue):
	# fails on main (a version that changes nothing): every entry of the batch is on disk/, an inner mount unmounted while the
	# batch waits for its locks behind a restore. The look after the locks drops them all: no version, the batch done as one that
	# found no differences, and a restore taking its lock right after the batch returned finds it free
	from tests.test_restore_lock import _free
	disk = _a_monitored_tree_with_an_inner_disk(job, monkeypatch, venue, {'a.txt': 'a', 'disk/f.txt': 'f'})
	try:
		versions = committed_versions(job)
		seed_monitor(job, {'disk/f.txt': 'changed'})
		backup, lines = _a_batch_held_at_the_locks(job, monkeypatch, OrderedDict([event_entry(job, 'disk/f.txt', 'modify')]), disk.unmount)
		assert backup.error is None and backup.committed is True
		assert committed_versions(job) == versions
		assert 'No differences after delta; skipping new version' in lines
		assert _free('restore') and _free('backup')
		assert _recorded(job)[1] == ['disk/']
	finally:
		disk.close()


# ---- D3, item 1: a lost manifest takes the inner mounts from the newest version's record --------------------------------------

def _lost_manifest_over_a_real_inner_tmpfs(job, monkeypatch, fail_first):
	'''
	disk/, an inner tmpfs (bound from one kept aside, so it comes back with what it held) holding f.txt and sub/g.txt, with real
	trusted.* records: V0, the vault database removed, disk/ unmounted and a.txt changed, then a start (with fail_first, after an
	attempt that fails at the estimate once its comparison committed the rebuilt manifest, which leaves the key absent). The
	new version keeps disk/'s files and "Inner mounts not mounted" is logged; mounted again, nothing is copied.
	'''
	from tests.test_restore_in_place import PAUSED_LINE, disk_inodes, holds_the_disk, remove_the_manifest
	store, disk = os.path.join(job.root, 'store'), os.path.join(job.monitor, 'disk')
	os.makedirs(store)
	os.makedirs(disk)
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', store])
	try:
		seed_monitor(job, {'a.txt': 'a'})
		os.makedirs(os.path.join(store, 'sub'))
		for rel, text in (('f.txt', 'f'), ('sub/g.txt', 'g')):
			with open(os.path.join(store, rel), 'w', encoding='utf-8') as f:
				f.write(text)
		subprocess.check_call(['mount', '--bind', store, disk])
		v0 = run_backup(job)[0]
		remove_the_manifest(job)
		subprocess.check_call(['umount', disk])
		with open(os.path.join(job.monitor, 'a.txt'), 'w', encoding='utf-8') as f:
			f.write('changed')
		lines = _lines(monkeypatch)
		if fail_first:
			def failing(*args, **kwargs):
				raise rv.JobFailure('the estimate stood in for fails')
			with monkeypatch.context() as estimating:
				estimating.setattr(rv, 'get_backup_size_inode', failing)
				with pytest.raises(rv.JobFailure, match='stood in for'):
					run_backup(job)
			manifest = rv.VaultManifest(job.job_vault)
			try:
				assert manifest.describes(v0)
				assert manifest.conn.execute("SELECT value FROM meta WHERE key = 'inner_mounts'").fetchone() is None
			finally:
				manifest.close()
			del lines[:]
		versions = run_backup(job)
		assert len(versions) == 2 and _read(os.path.join(versions[1], 'a.txt')) == 'changed'
		assert holds_the_disk(versions[1])
		assert PAUSED_LINE in lines
		inodes = disk_inodes(versions[1])
		subprocess.check_call(['mount', '--bind', store, disk])
		del lines[:]
		newest = run_backup(job)[-1]
		assert PAUSED_LINE not in lines
		assert holds_the_disk(newest) and disk_inodes(newest) == inodes
		# a real trusted.* attribute of the version's folder names the disk
		assert rv.load_root_meta(newest).inner_mounts == ['disk/']
	finally:
		subprocess.call(['umount', disk], stderr=subprocess.DEVNULL)
		subprocess.call(['umount', store])


@pytest.mark.privileged
@needs_root
def test_a_lost_manifest_still_pauses_a_real_inner_tmpfs(job, poll_fast, monkeypatch):
	# fails on main (commits the folder empty): the Docker variant is test_restore_in_place.py's
	# test_a_lost_manifest_still_pauses_an_inner_disk_unmounted_at_that_moment
	_lost_manifest_over_a_real_inner_tmpfs(job, monkeypatch, fail_first=False)


@pytest.mark.privileged
@needs_root
def test_a_lost_manifest_rebuilt_by_a_comparison_still_pauses_a_real_inner_tmpfs(job, poll_fast, monkeypatch):
	# fails on main (commits the folder empty): the Docker variant is test_restore_in_place.py's
	# test_a_rebuild_committed_by_a_comparison_leaves_the_key_absent
	_lost_manifest_over_a_real_inner_tmpfs(job, monkeypatch, fail_first=True)
