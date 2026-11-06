import errno
import json
import os
import sqlite3
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.harness import create_job, seed_monitor, tracked_manifest, run_backup, latest_version, event_entry, reads_the_file_before
from tests.test_names import contents, database, schema, schema_1_job

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def count_vault_reads(monkeypatch):
	reads = []
	read = rv.read_vault_record

	def counting(version_path, rel, *args):
		reads.append(rel)
		return read(version_path, rel, *args)
	monkeypatch.setattr(rv, 'read_vault_record', counting)
	return reads


def test_backup_records_what_the_new_version_holds(job):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	v0 = run_backup(job)[0]
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.describes(v0)
	assert (manifest.folders, manifest.files) == (['sub/'], ['a.txt', 'sub/b.txt'])
	record = manifest.lookup('a.txt')
	copy = os.lstat(os.path.join(v0, 'a.txt'))
	assert (record.kind, record.size, record.mtime_ns, record.hash) == ('f', 5, copy.st_mtime_ns, rv.hash_file(os.path.join(v0, 'a.txt'), 5))
	# read right after copying, so possibly from memory: the next start reads it back from the disk
	assert record.unchecked == 1
	manifest.close()


def test_cold_start_reads_each_copy_back_once_then_only_the_monitored_side(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	reads = count_vault_reads(monkeypatch)
	assert len(run_backup(job)) == 1
	assert sorted(reads) == ['a.txt', 'sub/b.txt']
	reads.clear()
	assert len(run_backup(job)) == 1
	assert reads == []


def test_mark_vouched_keeps_the_record_until_an_add(job):
	seed_monitor(job, {'a.txt': 'hello', 'd/b.txt': 'b'})
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		manifest.begin()
		record = manifest.lookup('a.txt')
		manifest.mark_vouched('a.txt')
		manifest.mark_vouched('untracked')
		assert manifest.take_dirty_records(10) == [('a.txt', record)]
		manifest.add('a.txt', dirty=True)
		assert manifest.take_dirty_records(10) == [('a.txt', None)]
	finally:
		manifest.rollback()
		manifest.close()


def recording_sync(monkeypatch, failing=False):
	'''
	rv.sync_vault_filesystems replaced by a recorder of the job vaults it is asked to sync, answering {} (no disk failed), and
	raising EIO when failing, as it does for a branch list it cannot read.
	'''
	calls = []
	def sync(job_vault, job_name):
		calls.append(job_vault)
		if failing:
			raise OSError(errno.EIO, os.strerror(errno.EIO), job_vault)
		return {}
	monkeypatch.setattr(rv, 'sync_vault_filesystems', sync)
	return calls


def disk_sync(monkeypatch, results):
	'''rv.sync_vault_filesystems answering results ({disk: None or an errno}) for any job vault, recording each failed disk as it does.'''
	def sync(job_vault, job_name):
		answer = {disk: None if code is None else OSError(code, os.strerror(code)) for disk, code in results.items()}
		for disk, error in answer.items():
			if error is not None:
				rv.record_failed_sync(disk, error, job_name)
		return answer
	monkeypatch.setattr(rv, 'sync_vault_filesystems', sync)


@pytest.fixture
def boot(tmp_path, monkeypatch):
	path = tmp_path / 'boot_id'
	path.write_text('boot-1\n')
	monkeypatch.setattr(rv, 'BOOT_ID_PATH', str(path))
	return path


def markers():
	state = rv.state_dir_path()
	return sorted(name for name in os.listdir(state) if name.startswith(rv.VAULT_SYNC_MARKER_PREFIX)) if os.path.isdir(state) else []


def test_a_disk_that_failed_a_sync_keeps_copies_unchecked_until_a_reboot(job, monkeypatch, boot, capsys):
	seed_monitor(job, {f'f{i}.txt': str(i) for i in range(4)})
	run_backup(job)
	disk_sync(monkeypatch, {'/mnt/d1': errno.EIO})
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1}
	assert capsys.readouterr().out.count('VAULT WRITE ERROR: disk /mnt/d1 failed a sync') == 1
	disk_sync(monkeypatch, {'/mnt/d1': None})              # the error was reported once: the next sync gets 0
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1} and 'VAULT WRITE ERROR' not in capsys.readouterr().out
	boot.write_text('boot-2\n')                            # the reboot
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0}


def test_a_second_disk_error_gets_its_own_marker_and_alert(job, monkeypatch, boot, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	disk_sync(monkeypatch, {'/mnt/d1': errno.EIO, '/mnt/d2': None})
	run_backup(job)
	disk_sync(monkeypatch, {'/mnt/d1': None, '/mnt/d2': errno.EIO})
	run_backup(job)
	assert rv.failed_sync_disks() == {'/mnt/d1', '/mnt/d2'} and len(markers()) == 2
	assert capsys.readouterr().out.count('VAULT WRITE ERROR') == 2


def test_a_marker_of_a_disk_not_holding_the_vault_holds_nothing(job, monkeypatch, boot):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	assert rv.mark_failed_sync('/mnt/other', OSError(errno.EIO, 'Input/output error')) is True
	disk_sync(monkeypatch, {'/mnt/d1': None})
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0}


def test_a_marker_from_a_previous_boot_is_ignored_and_removed(job, monkeypatch, boot):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	rv.mark_failed_sync('/mnt/d1', OSError(errno.EIO, 'Input/output error'))
	boot.write_text('boot-2\n')
	disk_sync(monkeypatch, {'/mnt/d1': None})
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0} and markers() == []


@pytest.mark.parametrize('trigger', ['state folder is a file', 'boot id unreadable', 'folder at the marker path'])
def test_a_marker_that_cannot_be_written_is_alerted_and_remembered_until_reverberator_stops(job, monkeypatch, boot, tmp_path, capsys, trigger):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	if trigger == 'state folder is a file':
		blocked = tmp_path / 'not_a_folder'
		blocked.write_text('')
		monkeypatch.setenv('REVERB_STATE_DIR', str(blocked))
	elif trigger == 'boot id unreadable':
		boot.unlink()
	else:
		os.makedirs(rv.vault_sync_marker_path('/mnt/d1'))
	disk_sync(monkeypatch, {'/mnt/d1': errno.EIO})
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1}
	out = capsys.readouterr().out
	assert 'VAULT WRITE ERROR: disk /mnt/d1 failed a sync' in out and 'its marker cannot be written' in out
	assert rv.UNRECORDED_FAILED_DISKS == {'/mnt/d1'}
	boot.write_text('boot-1\n')
	disk_sync(monkeypatch, {'/mnt/d1': None})              # the error was reported once: the next sync gets 0
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1} and 'VAULT WRITE ERROR' not in capsys.readouterr().out
	disk_sync(monkeypatch, {'/mnt/d2': None})              # a disk that never failed holds nothing
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0}


def test_a_disk_remembered_in_memory_leaves_memory_once_its_marker_is_written(job, monkeypatch, boot, tmp_path):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	os.makedirs(rv.vault_sync_marker_path('/mnt/d1'))      # a folder at the marker path: the marker cannot be written
	disk_sync(monkeypatch, {'/mnt/d1': errno.EIO})
	run_backup(job)
	assert rv.UNRECORDED_FAILED_DISKS == {'/mnt/d1'}
	os.rmdir(rv.vault_sync_marker_path('/mnt/d1'))         # the state folder is fixed, and the disk fails again
	lines = warning_lines(monkeypatch)
	run_backup(job)
	assert rv.UNRECORDED_FAILED_DISKS == set() and rv.failed_sync_disks() == {'/mnt/d1'}
	warnings = [message for message, warning in lines if warning and 'sync of the vault failed' in message]
	assert warnings and not any('remembered only until reverberator stops' in message for message in warnings)
	assert set(unchecked_flags(job).values()) == {1}


def test_an_unreadable_boot_id_keeps_the_copies_unchecked_with_one_warning(job, monkeypatch, boot, capsys):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	boot.unlink()
	disk_sync(monkeypatch, {'/mnt/d1': None})
	lines = warning_lines(monkeypatch)
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1}
	assert len([message for message, warning in lines if warning and 'sync of the vault failed' in message]) == 1
	boot.write_text('boot-1\n')
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0}


def test_a_sync_that_raises_leaves_no_marker(job, monkeypatch, boot):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	recording_sync(monkeypatch, failing=True)
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1} and markers() == [] and rv.UNRECORDED_FAILED_DISKS == set()


def test_a_disk_path_too_long_for_a_marker_name_is_remembered_in_memory_with_its_alert(job, monkeypatch, boot, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	long_disk = '/' + 'x' * 300
	with pytest.raises(OSError):
		rv.mark_failed_sync(long_disk, OSError(errno.EIO, 'Input/output error'))
	assert markers() == []
	# the longest name that still fits is the readable one
	assert os.path.basename(rv.vault_sync_marker_path('/' + 'x' * 180)) == rv.VAULT_SYNC_MARKER_PREFIX + '%2F' + 'x' * 180
	disk_sync(monkeypatch, {long_disk: errno.EIO})
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1}
	out = capsys.readouterr().out
	assert 'VAULT WRITE ERROR' in out and 'its marker cannot be written' in out
	assert markers() == [] and rv.UNRECORDED_FAILED_DISKS == {long_disk}
	disk_sync(monkeypatch, {long_disk: None})              # the error was reported once: the next sync gets 0
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1} and 'VAULT WRITE ERROR' not in capsys.readouterr().out


def test_a_second_job_syncing_the_disk_after_the_failed_sync_waits_for_its_marker(tmp_path, monkeypatch, boot):
	# job a's sync of disk X meets the kernel's one error and it syncs Y slowly; job b's sync of X then gets 0, as the kernel
	# reports an error once, and b must not record its copies checked before a has marked X
	a = create_job(str(tmp_path / 'ra'), 'job_a')
	b = create_job(str(tmp_path / 'rb'), 'job_b')
	seed_monitor(a, {'a.txt': 'a'})
	seed_monitor(b, {'b.txt': 'b'})
	run_backup(a)
	run_backup(b)
	monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
	monkeypatch.setattr(rv, 'vault_disks', lambda path: (True, [('/fake/X', 'X:' + path), ('/fake/Y', 'Y:' + path)]))
	unseen = [True]
	a_hit = threading.Event()
	release_a = threading.Event()
	def syncfs(folder):
		if folder[0] == 'X':
			if unseen:
				unseen.pop()
				a_hit.set()
				raise OSError(errno.EIO, os.strerror(errno.EIO), folder)
			return
		if threading.current_thread().name == 'A':
			release_a.wait(10)
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	thread_a = threading.Thread(target=run_backup, args=(a,), name='A')
	thread_b = threading.Thread(target=run_backup, args=(b,), name='B')
	thread_a.start()
	assert a_hit.wait(10)
	thread_b.start()
	thread_b.join(1)                   # without the lock b is done by now, with its copies checked
	release_a.set()
	thread_a.join(10)
	thread_b.join(10)
	assert not thread_a.is_alive() and not thread_b.is_alive()
	assert set(unchecked_flags(a).values()) == {1} and set(unchecked_flags(b).values()) == {1}
	assert rv.failed_sync_disks() == {'/fake/X'}


def test_a_pool_job_and_an_off_pool_job_on_one_filesystem_share_the_marker(tmp_path, fake_pool, monkeypatch, boot, capsys):
	# the kernel reports the filesystem's error once: the pool's job meets it, the other job's sync gets 0 and must still find the marker
	b = create_job(str(tmp_path / 'rb'), 'job_b')
	seed_monitor(b, {'b.txt': 'b'})
	run_backup(b)
	pool = str(tmp_path / 'pool')
	os.makedirs(pool)
	fake_pool.add(pool, ['d'])
	branch = str(tmp_path / 'plain' / 'x')           # a folder of the root filesystem, where job b's vault is too
	os.makedirs(os.path.join(branch, 'job_a'))
	monkeypatch.setattr(rv, 'read_pool_branches', lambda mount_point: [branch])
	os.makedirs(os.path.join(pool, 'job_a'))
	monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
	unseen = [True]
	def syncfs(folder):
		if unseen:
			unseen.pop()
			raise OSError(errno.EIO, os.strerror(errno.EIO), folder)
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	assert rv.check_vault_sync(os.path.join(pool, 'job_a'), 'job_a') == ['/']
	assert rv.failed_sync_disks() == {'/'} and capsys.readouterr().out.count('VAULT WRITE ERROR') == 1
	run_backup(b)
	assert set(unchecked_flags(b).values()) == {1}


def fake_disks(monkeypatch, vaults, syncfs):
	'''The real sync over fake disks: vaults is {job vault: its disks}, and the folder of a vault on a disk is 'disk:vault'.'''
	monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
	monkeypatch.setattr(rv, 'vault_disks', lambda path: (len(vaults[path]) > 1, [(disk, f'{disk}:{path}') for disk in vaults[path]]))
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)


def in_thread(target, *args):
	thread = threading.Thread(target=target, args=args, daemon=True)
	thread.start()
	return thread


@pytest.mark.parametrize('sync', ['check_vault_sync', 'flush_vault_disks'])
def test_a_sync_of_one_disk_does_not_wait_for_a_slow_sync_of_another(monkeypatch, boot, sync):
	in_slow = threading.Event()
	release = threading.Event()
	def syncfs(folder):
		if folder.startswith('/fake/slow'):
			in_slow.set()
			assert release.wait(20)
	fake_disks(monkeypatch, {'slow_vault': ['/fake/slow'], 'fast_vault': ['/fake/fast']}, syncfs)
	slow = in_thread(getattr(rv, sync), 'slow_vault', 'slow_job')
	assert in_slow.wait(10)
	fast = in_thread(getattr(rv, sync), 'fast_vault', 'fast_job')
	fast.join(5)
	waited = fast.is_alive()
	release.set()
	slow.join(10)
	fast.join(10)
	assert not waited


def test_two_syncs_of_a_disk_go_one_at_a_time_and_the_first_ones_error_is_marked_before_the_second_gets_its_0(monkeypatch, boot):
	steps = []
	in_first = threading.Event()
	release = threading.Event()
	def syncfs(folder):
		if steps:
			steps.append('second sync')
			return
		steps.append('first sync')
		in_first.set()
		assert release.wait(20)
		steps.append('first sync failed')
		raise OSError(errno.EIO, os.strerror(errno.EIO), folder)
	real_mark = rv.mark_failed_sync
	def mark(disk, error):
		time.sleep(0.2)            # a second sync not held out runs in this gap
		steps.append('marked')
		return real_mark(disk, error)
	monkeypatch.setattr(rv, 'mark_failed_sync', mark)
	fake_disks(monkeypatch, {'vault_a': ['/fake/X'], 'vault_b': ['/fake/X']}, syncfs)
	second_answer = []
	first = in_thread(rv.check_vault_sync, 'vault_a', 'job_a')
	assert in_first.wait(10)
	second = in_thread(lambda: second_answer.append(rv.check_vault_sync('vault_b', 'job_b')))
	second.join(0.2)
	release.set()
	first.join(10)
	second.join(10)
	assert steps == ['first sync', 'first sync failed', 'marked', 'second sync']
	assert second_answer == [['/fake/X']]


def test_a_vault_on_two_disks_takes_each_disks_lock_on_its_own(monkeypatch, boot):
	in_slow = threading.Event()
	release = threading.Event()
	two_disks_b = threading.Event()
	def syncfs(folder):
		if folder == '/fake/A:slow_vault':
			in_slow.set()
			assert release.wait(20)
		elif folder == '/fake/B:two_disks':
			two_disks_b.set()
	fake_disks(monkeypatch, {'slow_vault': ['/fake/A'], 'two_disks': ['/fake/A', '/fake/B'], 'b_only': ['/fake/B']}, syncfs)
	slow = in_thread(rv.flush_vault_disks, 'slow_vault', 'slow_job')
	assert in_slow.wait(10)
	two = in_thread(rv.flush_vault_disks, 'two_disks', 'two_job')
	# held out of A, it syncs B all the same, and waits for A with B's lock free
	synced_b = two_disks_b.wait(5)
	b_only = in_thread(rv.flush_vault_disks, 'b_only', 'b_job')
	b_only.join(5)
	b_waited = b_only.is_alive()
	two_waits_for_a = two.is_alive()
	release.set()
	for thread in (slow, two, b_only):
		thread.join(10)
		assert not thread.is_alive()
	assert synced_b and not b_waited and two_waits_for_a


def test_reading_the_markers_leaves_the_one_another_disks_failed_sync_rewrites(monkeypatch, boot):
	# a job on disk Y reads the markers while a job on disk X fails its sync: X's marker of another boot, which the reader
	# removes, must not take the new one with it
	error = OSError(errno.EIO, os.strerror(errno.EIO))
	assert rv.mark_failed_sync('/fake/X', error) is True
	boot.write_text('boot-2\n')
	def syncfs(folder):
		if folder.startswith('/fake/X'):
			raise OSError(errno.EIO, os.strerror(errno.EIO), folder)
	fake_disks(monkeypatch, {'vault_x': ['/fake/X'], 'vault_y': ['/fake/Y']}, syncfs)
	real_read = rv.read_vault_sync_marker
	failing = []
	def read(path):
		marker = real_read(path)
		if not failing:
			failing.append(in_thread(rv.check_vault_sync, 'vault_x', 'job_x'))
			failing[0].join(0.3)
		return marker
	monkeypatch.setattr(rv, 'read_vault_sync_marker', read)
	assert rv.check_vault_sync('vault_y', 'job_y') == []
	failing[0].join(10)
	assert not failing[0].is_alive() and rv.failed_sync_disks() == {'/fake/X'}


def test_a_marker_is_written_once_per_boot(boot):
	error = OSError(errno.EIO, 'Input/output error')
	assert rv.mark_failed_sync('/mnt/d1', error) is True
	assert rv.mark_failed_sync('/mnt/d1', error) is False
	boot.write_text('boot-2\n')
	assert rv.failed_sync_disks() == set()
	assert rv.mark_failed_sync('/mnt/d1', error) is True and rv.failed_sync_disks() == {'/mnt/d1'}


def warning_lines(monkeypatch):
	'''The backuper log's messages from now on: (message, whether a warning).'''
	lines = []
	real = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kw: lines.append((message, bool(kw.get('warning')))) or real(path, message, **kw))
	return lines


def unchecked_flags(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return {rel: manifest.lookup(rel).unchecked for rel in manifest.files}
	finally:
		manifest.close()


@pytest.mark.parametrize('loss', ['truncated', 'zeroed'])
def test_a_copy_lost_after_a_batch_read_it_back_is_copied_again(job, monkeypatch, loss):
	# the power-loss test: a later batch's check reads the copy back while the vault sync fails, so the copy stays
	# unchecked (0.45 recorded it checked from the page cache); then a failed writeback leaves it short or zeroed, and the
	# restart's full comparison must still catch it
	seed_monitor(job, {'a.txt': 'hello world'})
	copy = os.path.join(run_backup(job)[0], 'a.txt')
	recording_sync(monkeypatch, failing=True)
	run_backup(job, OrderedDict(), touched=rv.TouchedScopes(['a.txt/'], ['a.txt'], None, None))
	assert unchecked_flags(job) == {'a.txt': 1}
	st = os.lstat(copy)
	if loss == 'truncated':
		os.truncate(copy, 3)
	else:
		with open(copy, 'r+b') as f:
			f.write(b'\0' * st.st_size)
		os.utime(copy, ns=(st.st_atime_ns, st.st_mtime_ns))
	recording_sync(monkeypatch)
	lines = warning_lines(monkeypatch)
	versions = run_backup(job)
	assert any('does not match its record, copying again' in message for message, _ in lines)
	assert open(os.path.join(versions[-1], 'a.txt')).read() == 'hello world'


def test_a_comparison_syncs_once_however_many_copies_it_checks(job, monkeypatch):
	seed_monitor(job, {**{f'f{i}.txt': str(i) for i in range(6)}, 'sub/g.txt': 'g'})
	calls = recording_sync(monkeypatch)
	run_backup(job)
	# the commit's flush, of the copies it placed: no comparison ran
	assert calls == [job.job_vault] and set(unchecked_flags(job).values()) == {1}
	calls.clear()
	run_backup(job)                                   # the next start reads all seven back
	assert calls == [job.job_vault]
	assert set(unchecked_flags(job).values()) == {0}


def test_a_failed_sync_keeps_the_copies_unchecked_with_one_warning_and_the_next_comparison_checks_them(job, monkeypatch):
	seed_monitor(job, {f'f{i}.txt': str(i) for i in range(4)})
	run_backup(job)
	calls = recording_sync(monkeypatch, failing=True)
	lines = warning_lines(monkeypatch)
	run_backup(job)
	assert calls == [job.job_vault]
	assert set(unchecked_flags(job).values()) == {1}
	failures = [message for message, warning in lines if warning and 'sync' in message]
	assert len(failures) == 1
	calls = recording_sync(monkeypatch)
	run_backup(job)
	assert calls == [job.job_vault]
	assert set(unchecked_flags(job).values()) == {0}


def test_a_comparison_storing_no_checked_file_record_makes_no_sync(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	run_backup(job)
	calls = recording_sync(monkeypatch)
	run_backup(job)                                   # every row is checked: nothing is read back
	assert calls == []
	# a batch's own new copy is read back fresh, so it is recorded unchecked
	seed_monitor(job, {'b.txt': 'b'})
	run_backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]), touched=rv.TouchedScopes(['b.txt/'], ['b.txt'], None, None))
	# the commit's flush alone
	assert calls == [job.job_vault]
	assert unchecked_flags(job)['b.txt'] == 1


def test_the_real_sync_succeeds_on_the_test_filesystem(job):
	os.makedirs(job.job_vault, exist_ok=True)
	REAL_SYNC_VAULT_FILESYSTEMS(job.job_vault, 'job')
	with pytest.raises(OSError):
		rv.syncfs_folder(os.path.join(job.job_vault, 'not there'))


def test_copies_a_backup_wrote_stay_unchecked_without_any_patch(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = run_backup(job)[0]
	assert rv.read_copied_record(v0, 'a.txt').unchecked == 1
	# read back from a committed version, a copy is checked, as the vault sync of the comparison stands behind it
	assert rv.read_vault_record(v0, 'a.txt').unchecked == 0


def test_unchecked_copy_missing_its_bytes_is_copied_again(job):
	# a crash mid copy can leave the size and mtime in place over space whose bytes never reached the disk
	seed_monitor(job, {'a.txt': 'hello'})
	copy = os.path.join(run_backup(job)[0], 'a.txt')
	st = os.lstat(copy)
	with open(copy, 'r+b') as f:
		f.write(b'\0' * st.st_size)
	os.utime(copy, ns=(st.st_atime_ns, st.st_mtime_ns))
	versions = run_backup(job)
	assert len(versions) == 2
	assert open(os.path.join(versions[1], 'a.txt')).read() == 'hello'


def test_content_rewritten_keeping_size_and_mtime_is_modify_without_reading_the_vault(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	run_backup(job)
	source = os.path.join(job.monitor, 'a.txt')
	st = os.lstat(source)
	open(source, 'w').write('jello')
	os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))
	reads = count_vault_reads(monkeypatch)
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries[source].event == 'modify'
	assert reads == []


def test_relative_symlink_is_not_copied_again_at_each_start(job):
	seed_monitor(job, {'lib/x.txt': 'x'})
	os.symlink('lib', os.path.join(job.monitor, 'lib64'))
	run_backup(job)
	assert len(run_backup(job)) == 1


def test_attribute_change_is_attrib(job):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	source = os.path.join(job.monitor, 'a.txt')
	os.chmod(source, 0o600)
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == OrderedDict([(source, entries[source])]) and entries[source].event == 'attrib'


def test_moved_folder_is_read_from_the_vault_again(job, monkeypatch):
	seed_monitor(job, {'sub/x.txt': 'x'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	run_backup(job, OrderedDict([
		(os.path.join(job.monitor, 'moved') + '/', rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')),
	]))
	reads = count_vault_reads(monkeypatch)
	assert len(run_backup(job)) == 2
	assert sorted(reads) == ['moved/', 'moved/x.txt']


def test_folder_moved_to_another_depth_needs_no_copy(job):
	# a folder moved to another depth keeps its files, whatever the depth, as the older version gets them by hard links
	seed_monitor(job, {'sub/x.txt': 'x', 'deep/er/p.txt': 'p'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'deep', 'er', 'sub'))
	run_backup(job, OrderedDict([event_entry(job, 'deep/er/sub/', 'move', 'sub/')]))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == {}
	copy = os.path.join(latest_version(job).path, 'deep', 'er', 'sub', 'x.txt')
	assert reads_the_file_before(latest_version(job).path, 'deep/er/sub/x.txt', 'sub/x.txt') and open(copy).read() == 'x'


def test_manifest_for_another_version_is_listed_again_from_the_vault(job):
	# a version whose content file was never written is removed at startup, but the manifest committed before it
	seed_monitor(job, {'a.txt': 'hello', 'new.txt': 'n'})
	v0 = os.path.join(job.job_vault, 'V0--2021-01-01_00-00-00_-0800')
	os.makedirs(v0)
	rv.cp_af_copy_path(os.path.join(job.monitor, 'a.txt'), os.path.join(v0, 'a.txt'))
	tracked_manifest(job.job_vault, os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800'), ['gone.txt']).close()
	entries = OrderedDict()
	manifest = rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert {path: values.event for path, values in entries.items()} == {os.path.join(job.monitor, 'new.txt'): 'create'}
	assert manifest.describes(v0) and manifest.lookup('a.txt').kind == 'f'
	manifest.close()


def test_interrupted_backup_leaves_the_manifest_on_the_previous_version(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = run_backup(job)[0]
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('hello again')
	real = rv.record_dirty_entries

	def stop_then_record(*args):
		rv.GREEN_LIGHT.clear()
		real(*args)
	monkeypatch.setattr(rv, 'record_dirty_entries', stop_then_record)
	_, manifest, committed = rv.do_backup(
		OrderedDict([(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None))]),
		job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0',
	)
	manifest.close()
	assert committed is False
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.describes(v0) and reopened.lookup('a.txt').size == len('hello')
	reopened.close()


def test_unreadable_manifest_is_started_over(job):
	os.makedirs(job.job_vault)
	with open(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), 'wb') as f:
		f.write(b'not a database' * 100)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.files == [] and not manifest.describes(os.path.join(job.job_vault, 'V0--x'))
	manifest.close()


def test_a_malformed_manifest_is_started_over(job):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	path = os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)
	size = os.path.getsize(path)
	with open(path, 'r+b') as f:
		# the pages after the first, where the rows are, are not a database's
		f.seek(4096)
		f.write(os.urandom(size - 4096))
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.files == [] and not manifest.describes(latest_version(job).path)
	manifest.close()


def test_a_lock_held_past_the_timeout_keeps_the_manifest(job, monkeypatch):
	# the manifest of a cut batch holds the only copy of version n's folder times: a lock, a failing disk or a full table of
	# file handles says nothing of the file, and it stays as it is
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world'})
	run_backup(job)
	before = contents(job)
	inode = os.stat(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)).st_ino
	holder = database(job)
	holder.execute('BEGIN EXCLUSIVE')
	connect = sqlite3.connect
	monkeypatch.setattr(rv.sqlite3, 'connect', lambda *args, **kwargs: connect(*args, **{**kwargs, 'timeout': 0}))
	with pytest.raises(rv.JobFailure, match='database is locked.*remove that file'):
		rv.VaultManifest(job.job_vault)
	holder.rollback()
	holder.close()
	assert contents(job) == before and os.stat(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)).st_ino == inode
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.describes(latest_version(job).path) and reopened.files == ['a.txt', 'sub/b.txt']
	reopened.close()


@pytest.mark.parametrize('message', ['disk I/O error', 'unable to open database file', 'database or disk is full'])
def test_an_error_of_the_operation_keeps_the_manifest(job, monkeypatch, message):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	before = contents(job)
	connect = sqlite3.connect
	failures = []
	def failing(*args, **kwargs):
		if not failures:
			failures.append(message)
			raise sqlite3.OperationalError(message)
		return connect(*args, **kwargs)
	monkeypatch.setattr(rv.sqlite3, 'connect', failing)
	with pytest.raises(rv.JobFailure, match=message):
		rv.VaultManifest(job.job_vault)
	assert contents(job) == before
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.files == ['a.txt']
	reopened.close()


def test_a_vault_whose_manifest_cannot_be_opened_says_so_first_and_what_fixes_it(job, monkeypatch):
	# every open fails: the scan stops at the layout, before any open of the manifest of the backup itself, so the reason is the scan's
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	connect = sqlite3.connect
	def failing(*args, **kwargs):
		if rv.MANIFEST_FILE_NAME in str(args[0]):
			raise sqlite3.OperationalError('unable to open database file')
		return connect(*args, **kwargs)
	monkeypatch.setattr(rv.sqlite3, 'connect', failing)
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(), job.monitor, job.vault, 'N/A', threading.Event()),
		kwargs=dict(job=control), daemon=True)
	thread.start()
	thread.join(20)
	assert not thread.is_alive() and control.failure is not None and not control.failure.permanent
	reason = control.failure.reason
	# the error first: a status card cuts the reason at 40 characters
	assert reason[:40] == 'unable to open database file: cannot tel'
	assert os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME) in reason and 'if it stays, remove' in reason


def test_an_attempt_that_cannot_open_the_manifest_fails_and_the_next_one_commits(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	seed_monitor(job, {'b.txt': 'second'})
	before = contents(job)
	connect = sqlite3.connect
	failures = []
	def failing(*args, **kwargs):
		if not failures:
			failures.append(1)
			raise sqlite3.OperationalError('disk I/O error')
		return connect(*args, **kwargs)
	monkeypatch.setattr(rv.sqlite3, 'connect', failing)
	with pytest.raises(rv.JobFailure):
		run_backup(job)
	assert contents(job) == before
	run_backup(job)
	reopened = rv.VaultManifest(job.job_vault)
	assert reopened.files == ['a.txt', 'b.txt'] and reopened.describes(latest_version(job).path)
	reopened.close()


# --- schema 3: an in-place upgrade, and the keys design R reads ---

def as_schema_2(job):
	'''The job's manifest with the schema value 0.54 wrote: schema 3 changed only that value.'''
	conn = database(job)
	conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema'")
	conn.close()


def without_schema(meta):
	return [pair for pair in meta if pair[0] != 'schema']


def test_schema_2_upgrades_in_place_keeping_rows(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello', 'sub/b.txt': 'world', 'sub/c/d.txt': 'deep'})
	run_backup(job)
	# the second backup reads the copies back once, so every row is recorded and checked
	run_backup(job)
	as_schema_2(job)
	rows, meta = contents(job)
	assert len(rows) == 5 and all(row[1] is not None for row in rows) and dict(meta)['schema'] == '2'
	inode = os.stat(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)).st_ino
	rv.VaultManifest(job.job_vault).close()
	after_rows, after_meta = contents(job)
	assert after_rows == rows and without_schema(after_meta) == without_schema(meta)
	assert schema(job) == '3' == rv.VaultManifest.SCHEMA
	assert os.stat(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)).st_ino == inode
	# the whole point: no live job reads its tree again
	reads = []
	read = rv.read_vault_record
	monkeypatch.setattr(rv, 'read_vault_record', lambda *args: reads.append(args) or read(*args))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == OrderedDict() and reads == []


def test_schema_1_upgrades_to_3(job):
	schema_1_job(job)
	rows, meta = contents(job)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.layout() is None
	manifest.close()
	after_rows, after_meta = contents(job)
	assert schema(job) == '3' and len(after_rows) == len(rows) and {key for key, _ in after_meta} == {key for key, _ in meta}
	assert dict(after_meta)['skip_fingerprint'] == 'abc' and dict(after_meta)['version'] == dict(meta)['version']


def test_schema_2_without_its_entries_table_upgrades(job):
	# _open commits a new database's schema and its entries table one after the other: a crash between them left this
	os.makedirs(job.job_vault)
	conn = database(job)
	conn.execute('CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID')
	conn.execute("INSERT INTO meta VALUES ('schema', '2')")
	conn.close()
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.counts() == (0, 0)
	manifest.close()
	assert schema(job) == '3'


def test_a_schema_2_the_upgrade_cannot_write_stays_for_the_next_attempt(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	as_schema_2(job)
	before = contents(job)
	holder = database(job)
	holder.execute('BEGIN IMMEDIATE')
	connect = sqlite3.connect
	monkeypatch.setattr(rv.sqlite3, 'connect', lambda *args, **kwargs: connect(*args, **{**kwargs, 'timeout': 0}))
	with pytest.raises(rv.JobFailure, match='cannot upgrade'):
		rv.VaultManifest(job.job_vault)
	holder.rollback()
	holder.close()
	assert contents(job) == before
	rv.VaultManifest(job.job_vault).close()
	assert contents(job)[0] == before[0] and schema(job) == '3'


def test_the_journal_name_is_flushed_before_an_upgrade_writes(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'hello'})
	run_backup(job)
	# the plain connection of as_schema_2 removes the journal when it ends, as a kill can leave a vault with none
	as_schema_2(job)
	journal = os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME + '-journal')
	assert not os.path.exists(journal)
	calls = []
	flush = rv.fsync_vault_folder
	begin = rv.VaultManifest.begin

	def flushing(path):
		calls.append(('flush', os.path.exists(journal)))
		return flush(path)

	def beginning(manifest):
		calls.append(('begin',))
		return begin(manifest)
	monkeypatch.setattr(rv, 'fsync_vault_folder', flushing)
	monkeypatch.setattr(rv.VaultManifest, 'begin', beginning)
	rv.VaultManifest(job.job_vault).close()
	assert calls[:2] == [('flush', True), ('begin',)]


def test_the_new_keys_roll_back_with_the_transaction(job):
	os.makedirs(job.job_vault)
	manifest = rv.VaultManifest(job.job_vault)
	nothing = (None, None, set())
	keys = lambda: (manifest.layout(), manifest.previous_list(), manifest.migrated())
	assert keys() == nothing
	manifest.begin()
	manifest.set_layout('r')
	manifest.set_previous_list('old.list', 'new.list')
	manifest.add_migrated('V1--a')
	whole = ('r', {'from': 'old.list', 'to': 'new.list'}, {'V1--a'})
	assert keys() == whole
	manifest.rollback()
	assert keys() == nothing
	manifest.begin()
	manifest.set_layout('r')
	manifest.set_previous_list('old.list', 'new.list')
	manifest.add_migrated('V1--a')
	manifest.add_migrated('V2--\udcff')
	# redoing a version names it once
	manifest.add_migrated('V1--a')
	manifest.commit()
	manifest.close()
	manifest = rv.VaultManifest(job.job_vault)
	assert keys() == ('r', {'from': 'old.list', 'to': 'new.list'}, {'V1--a', 'V2--\udcff'})
	manifest.close()
	conn = database(job)
	assert json.loads(dict(conn.execute('SELECT * FROM meta'))['previous_list']) == {'from': 'old.list', 'to': 'new.list'}
	conn.close()


def manifest_of_rows(job, rows):
	'''A manifest holding rows {path: record}, a path ending with / being a folder, a record of None unverified.'''
	os.makedirs(job.job_vault, exist_ok=True)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	for rel in rows:
		manifest.add(rel)
	manifest.set_records(rows.items())
	manifest.commit()
	return manifest


def file_row(size):
	return rv.ManifestRecord('f', size, 1, 0o100644, 0, 0, 'h', None, 0)


LINK_ROW = rv.ManifestRecord('l', None, None, 0o120777, 0, 0, None, 'to', 0)
FOLDER_ROW = rv.ManifestRecord('d', None, 1, 0o40755, 0, 0, None, None, 0)
FOLDER_BYTES = 4096


def test_totals_counts_files_and_folders(job):
	manifest = manifest_of_rows(job, {'a.txt': file_row(5), 'd/': FOLDER_ROW, 'd/b.txt': file_row(7), 'd/l': LINK_ROW, 'd/e/': FOLDER_ROW})
	# a link has no bytes and one inode, as sizes_by_newest_holder counts it
	assert manifest.totals() == (5 + 7 + 2 * FOLDER_BYTES, 5)
	big = 3 << 60
	manifest.begin()
	manifest.set_records([('a.txt', file_row(big))])
	manifest.commit()
	# exact, where a float sum would round
	assert manifest.totals() == (big + 7 + 2 * FOLDER_BYTES, 5)
	manifest.close()


def test_totals_of_no_rows_is_zero_and_an_unverified_row_is_an_inode_of_no_bytes(job):
	manifest = manifest_of_rows(job, {})
	assert manifest.totals() == (0, 0)
	assert manifest.size_under('d/') == (0, 0)
	manifest.begin()
	manifest.add('a.txt')
	manifest.commit()
	assert manifest.totals() == (0, 1)
	manifest.close()


def test_size_under_counts_only_below_the_folder(job):
	escape = rv.NAME_ESCAPE
	manifest = manifest_of_rows(job, {
		# a name sorting between d and d/, one beside it sharing its prefix, and one above it
		'd-': file_row(1000), 'de/': FOLDER_ROW, 'de/x': file_row(2000), 'top': file_row(4000), 'c/': FOLDER_ROW,
		'd/': FOLDER_ROW, 'd/a': file_row(3), 'd/s/': FOLDER_ROW, 'd/s/b': file_row(4), 'd/l': LINK_ROW,
		'd/' + escape + '\udcff': file_row(8),
	})
	assert manifest.size_under('d/') == (3 + 4 + 8 + FOLDER_BYTES, 5)
	assert manifest.size_under('d') == manifest.size_under('d/')
	assert manifest.size_under('d/s/') == (4, 1)
	assert manifest.size_under('none/') == (0, 0)
	manifest.close()


def test_size_under_finds_a_name_that_is_not_utf8(job):
	manifest = manifest_of_rows(job, {'b\udcff/': FOLDER_ROW, 'b\udcff/x': file_row(6)})
	assert manifest.size_under('b\udcff/') == (6, 1)
	manifest.close()


def test_synchronous_stays_full(job):
	# the manifest's commit is the commit point of a version
	os.makedirs(job.job_vault)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.conn.execute('PRAGMA synchronous').fetchone()[0] >= 2
	manifest.close()


def test_a_read_only_open_of_schema_2_reads_no_layout(job, v054):
	v054.build(job, [lambda monitor: seed_monitor(job, {'a.txt': 'hello'})])
	before = contents(job)
	# what a command does: it reads the file as it is, and only a job upgrades it
	manifest = rv.VaultManifest.__new__(rv.VaultManifest)
	manifest.conn = sqlite3.connect(f'file:{os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)}?mode=ro', uri=True)
	assert (manifest.layout(), manifest.previous_list(), manifest.migrated()) == (None, None, set())
	manifest.conn.close()
	assert rv.read_recorded_monitor_paths(job.job_vault)[0] == [(0, job.monitor)]
	assert contents(job) == before and schema(job) == '2'
