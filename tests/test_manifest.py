import errno
import os
import threading
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.harness import create_job, seed_monitor, tracked_manifest, run_backup, latest_version, event_entry

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def count_vault_reads(monkeypatch):
	reads = []
	read = rv.read_vault_record

	def counting(version_path, rel, monitor_path, *args):
		reads.append(rel)
		return read(version_path, rel, monitor_path, *args)
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


def recording_sync(monkeypatch, failing=False):
	'''
	rv.sync_vault_filesystems replaced by a recorder of the job vaults it is asked to sync, answering {} (no disk failed), and
	raising EIO when failing, as it does for a branch list it cannot read.
	'''
	calls = []
	def sync(job_vault):
		calls.append(job_vault)
		if failing:
			raise OSError(errno.EIO, os.strerror(errno.EIO), job_vault)
		return {}
	monkeypatch.setattr(rv, 'sync_vault_filesystems', sync)
	return calls


def disk_sync(monkeypatch, results):
	'''rv.sync_vault_filesystems answering results ({disk: None or an errno}) for any job vault.'''
	monkeypatch.setattr(rv, 'sync_vault_filesystems', lambda job_vault: {disk: None if code is None else OSError(code, os.strerror(code))
		for disk, code in results.items()})


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
	assert 'VAULT WRITE ERROR: disk /mnt/d1 failed a sync' in out and 'cannot record it until a reboot' in out
	assert rv.UNRECORDED_FAILED_DISKS == {'/mnt/d1'}
	boot.write_text('boot-1\n')
	disk_sync(monkeypatch, {'/mnt/d1': None})              # the error was reported once: the next sync gets 0
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {1} and 'VAULT WRITE ERROR' not in capsys.readouterr().out
	disk_sync(monkeypatch, {'/mnt/d2': None})              # a disk that never failed holds nothing
	run_backup(job)
	assert set(unchecked_flags(job).values()) == {0}


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
	assert 'VAULT WRITE ERROR' in out and 'cannot record it until a reboot' in out
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
	assert calls == [] and set(unchecked_flags(job).values()) == {1}
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
	assert calls == []
	assert unchecked_flags(job)['b.txt'] == 1


def test_the_real_sync_succeeds_on_the_test_filesystem(job):
	os.makedirs(job.job_vault, exist_ok=True)
	REAL_SYNC_VAULT_FILESYSTEMS(job.job_vault)
	with pytest.raises(OSError):
		rv.syncfs_folder(os.path.join(job.job_vault, 'not there'))


def test_copies_a_backup_wrote_stay_unchecked_without_any_patch(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = run_backup(job)[0]
	assert rv.read_copied_record(v0, 'a.txt', job.monitor).unchecked == 1
	assert rv.read_version_record(v0, 'a.txt', job.monitor, True).unchecked == 1
	# read back from a committed version, a copy is checked, as the vault sync of the comparison stands behind it
	assert rv.read_vault_record(v0, 'a.txt', job.monitor).unchecked == 0


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
	# the links inside a folder moved to another depth are re-targeted, so they still reach the version holding the copies
	seed_monitor(job, {'sub/x.txt': 'x', 'deep/er/p.txt': 'p'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'deep', 'er', 'sub'))
	run_backup(job, OrderedDict([event_entry(job, 'deep/er/sub/', 'move', 'sub/')]))
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest_version(job), job.monitor).close()
	assert entries == {}
	copy = os.path.join(latest_version(job).path, 'deep', 'er', 'sub', 'x.txt')
	assert os.path.islink(copy) and open(copy).read() == 'x'


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
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0',
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
