import errno
import os
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fail_scandir(monkeypatch, failing_path, err):
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == os.path.abspath(failing_path).rstrip('/'):
			raise OSError(err, os.strerror(err), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)


def test_unreadable_folder_keeps_entries_and_logs_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', **{f'big/f{i}.txt': str(i) for i in range(500)}})
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'big'), errno.EIO)
	capsys.readouterr()
	_backup(job)[1].close()
	v1 = committed_versions(job)[1]
	assert len(os.listdir(os.path.join(v1, 'big'))) == 500
	out = capsys.readouterr()
	assert (out.out + out.err).count(f'reverberator job {job.job_name} UNREADABLE: {os.path.join(job.monitor, "big")}') == 1


def test_unreadable_root_fails_the_job_without_deletions(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	_fail_scandir(monkeypatch, job.monitor, errno.ENOTCONN)
	with pytest.raises(rv.JobFailure):
		_backup(job)
	assert len(committed_versions(job)) == 1


def test_unreadable_folder_in_first_backup_is_reported(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', 'locked/b.txt': 'b'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'locked'), errno.EACCES)
	_backup(job)[1].close()
	out = capsys.readouterr()
	assert 'UNREADABLE: ' + os.path.join(job.monitor, 'locked') in out.out + out.err


def test_resume_check_refuses_after_a_read_error(job, monkeypatch):
	seed_monitor(job, {'d/a.txt': 'a'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'd'), errno.EIO)
	assert rv.get_monitor_path_most_recent_change_time(job.monitor) == float('inf')


def test_new_unreadable_folder_is_logged_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	seed_monitor(job, {'new/x': 'x'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'new'), errno.EIO)
	capsys.readouterr()
	_backup(job)[1].close()
	out = capsys.readouterr()
	assert (out.out + out.err).count(f'reverberator job {job.job_name} UNREADABLE: {os.path.join(job.monitor, "new")}') == 1


class FakeTask:
	def __init__(self, returncode, stderr=()):
		self.returncode = returncode
		self.stderr = list(stderr)


def _tracked(job, version, rel):
	os.makedirs(job.job_vault, exist_ok=True)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.add(rel, dirty=True)
	return manifest


def test_unreadable_source_keeps_the_previous_entry(job, capsys, monkeypatch):
	src = os.path.join(job.monitor, 'locked.txt')
	open(src, 'w').write('locked')
	monkeypatch.setattr(rv, 'source_readable', lambda path: False)
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	os.symlink('../V0--x/a.txt', dest)
	temp = os.path.join(version, '.a.txt.reverberator-partial')
	open(temp, 'w').write('partial')
	manifest = _tracked(job, version, 'a.txt')
	rv.finish_copies([rv.PendingCopy(FakeTask(1, ['Input/output error']), src, temp, dest)],
		manifest, version, job.job_name)
	assert os.readlink(dest) == '../V0--x/a.txt' and not os.path.exists(temp)
	assert 'UNREADABLE: ' in ''.join(capsys.readouterr())
	manifest.rollback(); manifest.close()


def test_new_entry_with_unreadable_source_is_untracked(job):
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	manifest = _tracked(job, version, 'new.txt')
	rv.finish_copies([rv.PendingCopy(FakeTask(1), os.path.join(job.monitor, 'gone.txt'),
		os.path.join(version, '.new.txt.reverberator-partial'), os.path.join(version, 'new.txt'))], manifest, version, job.job_name)
	assert manifest.lookup('new.txt') is None
	manifest.rollback(); manifest.close()


def test_readable_source_with_failed_copy_fails_the_job(job):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('a')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	manifest = _tracked(job, version, 'a.txt')
	with pytest.raises(rv.JobFailure) as exc:
		rv.finish_copies([rv.PendingCopy(FakeTask(1, ['No space left on device']), src,
			os.path.join(version, '.a.txt.reverberator-partial'), os.path.join(version, 'a.txt'))], manifest, version, job.job_name)
	assert 'No space left on device' in exc.value.reason and not exc.value.permanent
	manifest.rollback(); manifest.close()


def test_failed_vault_copy_commits_nothing_and_next_attempt_cleans_up(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	v0 = committed_versions(job)[0]
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	def vault_full(*args, **kwargs):
		raise rv.JobFailure('copying b.txt into the vault failed: No space left on device')
	monkeypatch.setattr(rv, 'finish_copies', vault_full)
	with pytest.raises(rv.JobFailure):
		_backup(job, OrderedDict({os.path.join(job.monitor, 'b.txt'): rv.BackupEntryValues('t', 'create', None)}))
	monkeypatch.undo()
	assert committed_versions(job) == [v0]
	_backup(job)[1].close()   # the next attempt compares the whole tree
	versions = committed_versions(job)
	assert len(versions) == 2 and os.path.isfile(os.path.join(versions[1], 'b.txt'))
	assert sorted(name for name in os.listdir(job.job_vault) if name.startswith('V') and rv.CONTENT_FILE_EXTENSION_NAME not in name) == [os.path.basename(v) for v in versions]


def test_successful_async_copy_replaces_the_link(job):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('new')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	os.symlink('../V0--x/a.txt', dest)
	pending = []
	mcae = rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True)
	rv.cp_af_copy_path(src, dest, mcae, pending)
	assert os.path.islink(dest)   # untouched until finished
	while mcae.runningThreads:
		mcae.wait(timeout=0.1)
	manifest = _tracked(job, version, 'a.txt')
	rv.finish_copies(pending, manifest, version, job.job_name)
	assert not os.path.islink(dest) and open(dest).read() == 'new'
	manifest.rollback(); manifest.close()


def _partial_files(root):
	return [os.path.join(folder, name) for folder, dirs, files in os.walk(root) for name in dirs + files if name.endswith('.reverberator-partial')]


def test_failed_synchronous_copy_keeps_the_destination(job, monkeypatch):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('new')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	os.symlink('../V0--x/a.txt', dest)
	def cp_fails_midway(command, **kwargs):
		open(command[-1], 'w').write('part')
		return 1
	monkeypatch.setattr(rv.multiCMD, 'run_command', cp_fails_midway)
	assert rv.cp_af_copy_path(src, dest) == 1
	assert os.readlink(dest) == '../V0--x/a.txt' and not _partial_files(job.vault)


def _sleep_running():
	'''Whether this process has a running `sleep 30` child.'''
	me = os.getpid()
	for entry in os.listdir('/proc'):
		if not entry.isdigit():
			continue
		try:
			with open(f'/proc/{entry}/stat') as stat:
				ppid = int(stat.read().rsplit(')', 1)[1].split()[1])
			with open(f'/proc/{entry}/cmdline', 'rb') as cmdline:
				argv = cmdline.read().split(b'\0')[:2]
		except (OSError, ValueError, IndexError):
			continue
		if ppid == me and argv == [b'sleep', b'30']:
			return True
	return False


@pytest.mark.parametrize('first_backup', [True, False])
def test_failed_backup_leaves_no_copy_running(job, poll_fast, monkeypatch, first_backup):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	semaphore = threading.Semaphore(4)
	monkeypatch.setattr(rv, 'BACKUP_SEMAPHORE', semaphore)
	entries = None
	if not first_backup:
		_backup(job)[1].close()
		entries = OrderedDict((os.path.join(job.monitor, name), rv.BackupEntryValues('t', 'modify', None)) for name in ('a.txt', 'b.txt'))
	executors = []
	class RecordingExecutor(rv.multiCMD.AsyncExecutor):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)
			executors.append(self)
	monkeypatch.setattr(rv.multiCMD, 'AsyncExecutor', RecordingExecutor)
	tasks = []
	started = []
	def slow_copy(source_path, dest_path, mcae=..., pending=None):
		# the first copy is still running when the second one fails to reach the vault
		if tasks:
			deadline = time.monotonic() + 10
			# multiCMD 1.51 and 1.54 differ in what a Task shows of a started command (1.54 sets thread before the
			# process exists and clears it afterwards), so wait for the sleep process itself
			while not _sleep_running() and time.monotonic() < deadline:
				time.sleep(0.01)
			started.append(_sleep_running())
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), dest_path)
		temp = rv.partial_copy_path(dest_path)
		open(temp, 'w').write('partial')
		tasks.append(mcae.run_command(['sleep', '30']))
		if pending is not None:
			pending.append(rv.PendingCopy(tasks[-1], source_path, temp, dest_path))
		return tasks[-1]
	monkeypatch.setattr(rv, 'cp_af_copy_path', slow_copy)
	with pytest.raises(OSError):
		_backup(job, entries)
	assert executors and not executors[-1].runningThreads
	assert started == [True] and tasks[0].returncode is not None and not tasks[0].is_alive()   # killed and reaped
	assert semaphore._value == 4   # every permit is back
	if first_backup:
		# the uncommitted V0 keeps them until it is removed whole, as the next attempt does
		rv.get_vault_info(job.job_vault)
	assert not _partial_files(job.vault)


def test_two_copies_to_one_destination_both_finish(job):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('new')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	copies = []
	for content in ('first', 'second'):
		temp = rv.partial_copy_path(dest)
		open(temp, 'w').write(content)
		copies.append(rv.PendingCopy(FakeTask(0), src, temp, dest))
	manifest = _tracked(job, version, 'a.txt')
	rv.finish_copies(copies, manifest, version, job.job_name)
	assert open(dest).read() == 'second' and not _partial_files(job.vault)
	manifest.rollback(); manifest.close()


def _finish_one(job, src, stderr, temp_content=None, returncode=1, rel='a.txt', unsynced=None):
	'''Finish one failed copy of src over the version entry rel, linked to the previous version; returns its path.'''
	version = os.path.join(job.job_vault, 'V1--x')
	dest = os.path.join(version, rel)
	os.makedirs(os.path.dirname(dest), exist_ok=True)
	os.symlink(os.path.relpath(os.path.join(job.job_vault, 'V0--x', rel), os.path.dirname(dest)), dest)
	temp = rv.partial_copy_path(dest)
	if temp_content is not None:
		open(temp, 'w').write(temp_content)
	manifest = _tracked(job, version, rel)
	try:
		rv.finish_copies([rv.PendingCopy(FakeTask(returncode, [line.format(src=src, temp=temp) for line in stderr]), src, temp, dest)],
			manifest, version, job.job_name, unsynced=unsynced)
	finally:
		manifest.rollback(); manifest.close()
	return dest


@pytest.mark.parametrize('recreated', [False, True])
def test_vanished_source_keeps_the_previous_entry_quietly(job, capsys, recreated):
	src = os.path.join(job.monitor, 'gone.txt')
	if recreated:
		# gone while cp ran, back by the time the copy is looked at
		open(src, 'w').write('back')
	dest = _finish_one(job, src, ["cp: cannot stat '{src}': No such file or directory"], temp_content='partial')
	assert os.readlink(dest) == '../V0--x/a.txt' and not _partial_files(job.vault)
	assert 'UNREADABLE' not in ''.join(capsys.readouterr())


def test_source_read_error_named_by_cp_keeps_the_previous_entry(job, capsys):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('a')   # opens fine, yet a read failed
	dest = _finish_one(job, src, ["cp: error reading '{src}': Input/output error"], temp_content='part')
	assert os.readlink(dest) == '../V0--x/a.txt' and not _partial_files(job.vault)
	assert f'reverberator job {job.job_name} UNREADABLE: {src}: ' in ''.join(capsys.readouterr())


def test_vault_error_named_by_cp_fails_the_job_whatever_the_source(job, monkeypatch):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('a')
	monkeypatch.setattr(rv, 'source_readable', lambda path: False)
	with pytest.raises(rv.JobFailure) as exc:
		# the vault folder vanished: an ENOENT on the destination is not a vanished source
		_finish_one(job, src, ["cp: cannot create regular file '{temp}': No such file or directory"])
	assert 'cannot create regular file' in exc.value.reason and not _partial_files(job.vault)


# 'a': the source grew after cp copied it, as an actively written file does
@pytest.mark.parametrize('temp_content', ['abc', 'a', None])
def test_metadata_only_failure_accepts_the_copy(job, capsys, temp_content):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('abc')
	stderr = ["cp: failed to preserve ownership for '{temp}': Operation not permitted", "cp: preserving times for '{temp}': Operation not permitted"]
	if temp_content is not None:
		unsynced = []
		dest = _finish_one(job, src, stderr, temp_content=temp_content, unsynced=unsynced)
		assert not os.path.islink(dest) and open(dest).read() == temp_content
		out = ''.join(capsys.readouterr())
		assert 'without all of its metadata' in out and src in out and 'UNREADABLE' not in out
		# its extended attributes may be missing: the backup does not record that the vault matched the tree
		assert unsynced == [src]
	else:
		# no partial file: nothing arrived to accept
		with pytest.raises(rv.JobFailure):
			_finish_one(job, src, stderr)
	assert not _partial_files(job.vault)


def test_copies_run_cp_with_the_c_locale(job, monkeypatch):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('a')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	pending = []
	mcae = rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True)
	task = rv.cp_af_copy_path(src, os.path.join(version, 'a.txt'), mcae, pending)
	while mcae.runningThreads:
		mcae.wait(timeout=0.1)
	rv.discard_copies(pending)
	commands = []
	def run_command(command, **kwargs):
		commands.append(command)
		return 1
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	rv.cp_af_copy_path(src, os.path.join(version, 'b.txt'))
	for command in (task.command, commands[0]):
		assert command[:3] == ['env', 'LC_ALL=C', 'cp'] and command[3:6] == ['-af', '--reflink=auto', '--sparse=always']


def test_file_name_cannot_make_a_content_failure_look_metadata_only(job):
	# the partial file sits in the folder mirroring the source's, whose name is cp's metadata phrase
	src = os.path.join(job.monitor, 'failed to preserve ownership for', 'a.txt')
	os.makedirs(os.path.dirname(src))
	open(src, 'w').write('abc')
	with pytest.raises(rv.JobFailure):
		# full size, as when writing failed only once all of it was sent, so the size tells nothing either
		_finish_one(job, src, ["cp: error writing '{temp}': No space left on device"], temp_content='abc', rel='failed to preserve ownership for/a.txt')
	assert not _partial_files(job.vault)


def test_file_name_with_the_partial_suffix_cannot_make_a_read_error_the_vaults(job, capsys):
	src = os.path.join(job.monitor, 'x.reverberator-partial')
	open(src, 'w').write('x')
	dest = _finish_one(job, src, ["cp: error reading '{src}': Input/output error"], temp_content='part')
	assert os.readlink(dest) == '../V0--x/a.txt'
	assert f'UNREADABLE: {src}: ' in ''.join(capsys.readouterr())


def test_file_name_cannot_make_a_read_error_look_vanished(job, capsys):
	src = os.path.join(job.monitor, 'No such file or directory')
	open(src, 'w').write('x')
	dest = _finish_one(job, src, ["cp: error reading '{src}': Input/output error"], temp_content='part')
	assert os.readlink(dest) == '../V0--x/a.txt'
	assert f'UNREADABLE: {src}: ' in ''.join(capsys.readouterr())


def test_stuck_copy_bounds_the_wait(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	monkeypatch.setattr(rv, 'COPY_STOP_WAIT_SECONDS', 0.5)
	original = rv.multiCMD.AsyncExecutor
	executors = []
	class StubbornExecutor(original):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)
			executors.append(self)
		def stop(self, timeout=None):
			# its commands ignore being stopped
			return self.tasks
	monkeypatch.setattr(rv.multiCMD, 'AsyncExecutor', StubbornExecutor)
	tasks = []
	def slow_copy(source_path, dest_path, mcae=..., pending=None):
		if tasks:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), dest_path)
		tasks.append(mcae.run_command(['sleep', '30']))
		pending.append(rv.PendingCopy(tasks[-1], source_path, rv.partial_copy_path(dest_path), dest_path))
		return tasks[-1]
	monkeypatch.setattr(rv, 'cp_af_copy_path', slow_copy)
	start = time.monotonic()
	try:
		with pytest.raises(OSError):
			_backup(job)
		assert time.monotonic() - start < 10
		out = capsys.readouterr()
		assert 'stopped commands still running' in out.out + out.err and 'sleep 30' in out.out + out.err
	finally:
		original.stop(executors[0], timeout=10)


def test_entry_named_like_a_partial_copy_is_backed_up_as_itself(job, poll_fast):
	seed_monitor(job, {'foo': 'foo', '.foo.reverberator-partial': 'not a partial copy'})
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'foo'), 'w').write('foo changed')
	_backup(job, OrderedDict({os.path.join(job.monitor, 'foo'): rv.BackupEntryValues('t', 'modify', None)}))[1].close()
	versions = committed_versions(job)
	assert len(versions) == 2
	for version, foo in zip(versions, ('foo', 'foo changed')):
		assert open(os.path.join(version, 'foo')).read() == foo
		assert open(os.path.join(version, '.foo.reverberator-partial')).read() == 'not a partial copy'


@pytest.mark.parametrize('flags', [{'warning': True}, {'debug': True}, {}])
@pytest.mark.parametrize('debug_mode', [True, False])
def test_backuper_log_needs_only_old_tee_logger_methods(monkeypatch, flags, debug_mode):
	# Tee_Logger 6.40 has no teewarning, teedebug or debug
	lines = []
	class OldLogger:
		def info(self, message, callerStackDepth=None):
			lines.append(message)
		teeprint = teeerror = teeok = teelog = info
	monkeypatch.setattr(rv, 'tl', OldLogger())
	monkeypatch.setattr(rv, 'DEBUG', debug_mode)
	rv.backuperTeeLogToTl('p', 'm', **flags)
	assert len(lines) == 1 and lines[0].endswith('m')


class _DoneTask:
	returncode = 0
	stderr = ()
	command = ['cp']
	def is_alive(self):
		return False


def test_interrupted_complete_v0_leaves_its_partial_files_to_the_sweep(job, poll_fast, monkeypatch):
	# unlinking each partial file of a large first backup would only hold up the stop: the uncommitted version goes whole
	seed_monitor(job, {f'f{i}.txt': str(i) for i in range(20)})
	def copy(source_path, dest_path, mcae=..., pending=None):
		temp = rv.partial_copy_path(dest_path)
		open(temp, 'w').write('part')
		pending.append(rv.PendingCopy(_DoneTask(), source_path, temp, dest_path))
		rv.GREEN_LIGHT.clear()
	monkeypatch.setattr(rv, 'cp_af_copy_path', copy)
	removed = []
	real_remove = rv.remove_entry
	monkeypatch.setattr(rv, 'remove_entry', lambda path: removed.append(path) or real_remove(path))
	try:
		_, manifest, committed = _backup(job)
		manifest.close()
	finally:
		rv.GREEN_LIGHT.set()
	assert committed is False and committed_versions(job) == []
	assert removed == []
	assert _partial_files(job.vault)
	rv.get_vault_info(job.job_vault)
	assert not _partial_files(job.vault)


def test_stopped_copies_lose_their_partial_files_by_default(job):
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	temp = os.path.join(version, '.a.txt.reverberator-partial')
	open(temp, 'w').write('part')
	pending = [rv.PendingCopy(_DoneTask(), os.path.join(job.monitor, 'a.txt'), temp, os.path.join(version, 'a.txt'))]
	mcae = rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True)
	rv.stop_copies(mcae, pending, version)
	assert pending == [] and not os.path.lexists(temp)
