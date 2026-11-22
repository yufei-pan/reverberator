import errno
import os
import shutil
import socket
import stat
import sys
import threading
import time
from collections import OrderedDict, deque
import pytest
import reverberator as rv
from tests.harness import on_folder_open, seed_monitor, committed_versions
from tests.vault_oracle import landing, rows_match_vault, version_number

pytestmark = pytest.mark.unit


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fail_open(monkeypatch, failing_path, err):
	'''Every open of the folder at failing_path for a listing fails with err (on_folder_open()).'''
	def fail():
		raise OSError(err, os.strerror(err), failing_path)
	on_folder_open(monkeypatch, failing_path, fail)


def _fail_lstat(monkeypatch, failing_path, err):
	original = os.lstat
	def lstat(path, *args, **kwargs):
		if isinstance(path, (str, bytes)) and os.path.abspath(os.fsdecode(path)).rstrip('/') == os.path.abspath(failing_path).rstrip('/'):
			raise OSError(err, os.strerror(err), path)
		return original(path, *args, **kwargs)
	monkeypatch.setattr(os, 'lstat', lstat)


def test_unreadable_folder_keeps_entries_and_logs_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', **{f'big/f{i}.txt': str(i) for i in range(500)}})
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_fail_open(monkeypatch, os.path.join(job.monitor, 'big'), errno.EIO)
	capsys.readouterr()
	_backup(job)[1].close()
	v1 = committed_versions(job)[1]
	assert len(os.listdir(os.path.join(v1, 'big'))) == 500
	out = capsys.readouterr()
	assert (out.out + out.err).count(f'reverberator job {job.job_name} UNREADABLE: {os.path.join(job.monitor, "big")}') == 1


def test_unreadable_root_fails_the_job_without_deletions(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	_fail_open(monkeypatch, job.monitor, errno.ENOTCONN)
	with pytest.raises(rv.JobFailure):
		_backup(job)
	assert len(committed_versions(job)) == 1


def test_unreadable_folder_in_first_backup_is_reported(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', 'locked/b.txt': 'b'})
	_fail_open(monkeypatch, os.path.join(job.monitor, 'locked'), errno.EACCES)
	_backup(job)[1].close()
	out = capsys.readouterr()
	assert 'UNREADABLE: ' + os.path.join(job.monitor, 'locked') in out.out + out.err


def test_new_unreadable_folder_is_logged_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	seed_monitor(job, {'new/x': 'x'})
	_fail_open(monkeypatch, os.path.join(job.monitor, 'new'), errno.EIO)
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


def _failing_rm(monkeypatch, job, rel, remove=False):
	'''
	The rm of the version's rel runs a stand-in that fails as rm does (after removing the entry, with remove). A record without keep
	takes an entry out of the tree with no rm to fail, so here it keeps it, as a record earlier in the batch does.
	'''
	real = rv.multiCMD.AsyncExecutor.run_command
	real_record = rv.TreeWriter.record
	def record(self, recorded, keep, *args, **kwargs):
		real_record(self, recorded, keep or recorded.rstrip('/') == rel, *args, **kwargs)
	monkeypatch.setattr(rv.TreeWriter, 'record', record)
	script = ('rm -rf -- "$1"; ' if remove else '') + 'echo "rm: cannot remove \'$1\': Operation not permitted" >&2; exit 1'
	def run_command(self, command, *args, **kwargs):
		if list(command[:1]) == ['rm'] and command[-1].startswith(job.job_vault + '/') and command[-1].endswith('/' + rel):
			command = ['sh', '-c', script, 'sh', command[-1]]
		return real(self, command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD.AsyncExecutor, 'run_command', run_command)


@pytest.mark.parametrize('rel, tree', [('b.txt', {'b.txt': 'b'}), ('d', {'d/x': 'x'})])
def test_a_delete_whose_rm_fails_fails_the_batch_and_commits_nothing(job, poll_fast, monkeypatch, rel, tree):
	seed_monitor(job, {'a.txt': 'a', **tree})
	_backup(job)[1].close()
	v0 = committed_versions(job)[0]
	path = os.path.join(job.monitor, rel)
	shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
	_failing_rm(monkeypatch, job, rel)
	entry = path + ('/' if rel == 'd' else '')
	with pytest.raises(rv.JobFailure) as exc:
		_backup(job, OrderedDict({entry: rv.BackupEntryValues('t', 'delete', None)}))
	assert 'Operation not permitted' in exc.value.reason and rel in exc.value.reason and not exc.value.permanent
	assert committed_versions(job) == [v0]
	monkeypatch.undo()
	_backup(job)[1].close()                    # the next attempt compares the whole tree
	assert not os.path.lexists(os.path.join(committed_versions(job)[-1], rel))


def test_a_failed_rm_whose_entry_went_is_no_failure(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'b.txt'))
	_failing_rm(monkeypatch, job, 'b.txt', remove=True)
	_, manifest, committed = _backup(job, OrderedDict({os.path.join(job.monitor, 'b.txt'): rv.BackupEntryValues('t', 'delete', None)}))
	manifest.close()
	assert committed and not os.path.lexists(os.path.join(committed_versions(job)[-1], 'b.txt'))


def test_failed_removal_reads_each_rm_task(tmp_path):
	there = str(tmp_path / 'there')
	open(there, 'w').write('x')
	gone = str(tmp_path / 'gone')
	assert rv.failed_removal([(FakeTask(0), there), (FakeTask(1, ['rm: x']), gone)]) is None
	removals = [(FakeTask(1, ['  ', "rm: cannot remove 'there': Device or resource busy"]), there)]
	assert rv.failed_removal(removals) == f"removing {there} from the version failed: rm: cannot remove 'there': Device or resource busy"
	assert removals == []
	assert rv.failed_removal([(FakeTask(-1), there)]) == f'removing {there} from the version failed: rm exited with -1'
	assert rv.failed_removal([(FakeTask(None), there)]) == f'removing {there} from the version failed: rm did not run'


def test_failed_removal_shows_the_first_line_and_counts_the_rest():
	there = '/'
	lines = [f"rm: cannot remove 'f{i}': Operation not permitted" for i in range(1000)]
	assert rv.failed_removal([(FakeTask(1, lines), there)]) == f"removing {there} from the version failed: {lines[0]} (and 999 more)"


# ---- F4: a batch whose every entry drops out (an unreadable file, a path gone, a link the vault refuses) is compared as one
# with none, and commits nothing when that finds nothing else. As uid 65534 a mode-000 file is unreadable; as root it reads,
# so the VM gate deselects these by name

needs_unreadable = pytest.mark.skipif(os.geteuid() == 0, reason='as root a mode-000 file reads: Docker runs this as uid 65534')
KEPT = dict(only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _settled(job):
	'''V0 of the tree, and a full comparison that finds nothing: a vault whose next comparison writes nothing.'''
	from tests.harness import run_backup
	run_backup(job)
	run_backup(job)
	return committed_versions(job)


def _full(job):
	'''A full comparison, as a start or the interval runs it: whether it committed.'''
	_, manifest, committed = _backup(job)
	manifest.close()
	return committed


def _events(job, events, **options):
	'''A batch of raw events (is_dir, event, rel, moved_from rel), collapsed and verified by what they touched.'''
	from tests.crash_batches import backup_events
	backup_events(job, events, **{**KEPT, **options})


def _lines(capsys, kind, path):
	out = capsys.readouterr()
	return (out.out + out.err).count(f'{kind}: {path}: ')


@needs_unreadable
@pytest.mark.parametrize('changed', [True, False], ids=['size_changed', 'unchanged'])
def test_a_full_comparison_meeting_only_an_unreadable_file_makes_no_version(job, poll_fast, capsys, changed):
	# fails on main: the comparison calls it a modify (its size changed, or its hash cannot be read), its copy keeps the last
	# copy with an UNREADABLE line, and the batch commits a version that changes nothing
	from tests.harness import header_counter
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	if changed:
		stat = os.stat(path)
		open(path, 'w').write('b, longer')
		os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	os.chmod(path, 0)
	counter = header_counter(job.job_vault)
	capsys.readouterr()
	assert _full(job) is True
	assert committed_versions(job) == before
	# with nothing to write, the manifest is not written either
	assert header_counter(job.job_vault) == counter
	assert _lines(capsys, 'UNREADABLE', path) == 1


@needs_unreadable
def test_an_attrib_of_an_unreadable_file_under_only_sync_attributes_makes_no_version(job, poll_fast, capsys):
	# fails on main: its record cannot vouch for the copy, as its tail cannot be read, so the replay copies it, the copy keeps the
	# last copy, and the batch commits a version that changes nothing
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	os.chmod(path, 0)
	capsys.readouterr()
	_events(job, [(False, 'attrib', 'b.txt', None)], only_sync_attributes=True)
	assert committed_versions(job) == before
	assert _lines(capsys, 'UNREADABLE', path) == 1


def test_a_create_of_a_file_gone_since_still_commits_the_removal_it_hid(job, poll_fast):
	# pin (the design review's probe H): create tmp; mv tmp f; rm f, with f in the vault, beside the create of a file gone since.
	# Every entry drops out, and the comparison of the places the batch touched still finds f deleted
	seed_monitor(job, {'a.txt': 'a', 'f': 'f'})
	before = _settled(job)
	os.remove(os.path.join(job.monitor, 'f'))
	_events(job, [(False, 'create', 'gone.txt', None), (False, 'create', 'tmp', None), (False, 'move', 'f', 'tmp'), (False, 'delete', 'f', None)])
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	assert not os.path.lexists(os.path.join(versions[-1], 'f')) and os.path.lexists(os.path.join(before[-1], 'f'))


@needs_unreadable
def test_a_scanned_folder_meeting_only_an_unreadable_file_makes_no_version_and_one_comparison(job, poll_fast, monkeypatch, capsys):
	# fails on main: the folder's comparison finds the file, and the batch commits a version that changes nothing
	from tests.harness import wait_until
	seed_monitor(job, {'a.txt': 'a', 'disk/b.txt': 'b'})
	before = _settled(job)
	compared = []
	real = rv.compare_scopes
	def compare_scopes(found, manifest, version_path, monitor_path, scopes, *args, **kwargs):
		compared.append((list(scopes.subtrees), list(scopes.paths)))
		return real(found, manifest, version_path, monitor_path, scopes, *args, **kwargs)
	monkeypatch.setattr(rv, 'compare_scopes', compare_scopes)
	queue, lock, flag = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag),
		kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
		# the start's full comparison first, then the change and its batch, the scan of disk/
		wait_until(lambda: control.committed.is_set(), message='the start did not end')
		path = os.path.join(job.monitor, 'disk', 'b.txt')
		open(path, 'w').write('b, longer')
		os.chmod(path, 0)
		del compared[:]
		capsys.readouterr()
		control.committed.clear()
		with lock:
			queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
		flag.set()
		wait_until(lambda: control.committed.is_set(), message='the batch did not end')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=10)
		rv.GREEN_LIGHT.set()
	assert committed_versions(job) == before
	# the folder's own comparison, and no comparison of the batch again
	assert compared == [(['disk/'], [])]
	assert _lines(capsys, 'UNREADABLE', path) == 1


def test_a_move_into_a_paused_inner_mount_from_an_untracked_path_makes_no_version(job, poll_fast, monkeypatch):
	# fails on main: the paused drop makes the move a delete of its source, which the vault does not track, after the drop of
	# such deletes ran, and the batch commits a version that changes nothing
	from tests.test_inner_mounts import _fake_mounts
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	before = _settled(job)
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	# a file the vault never held, moved into the disk before it went
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'disk/new.txt', 'move', 'new.txt')]))
	manifest.close()
	assert committed is True and committed_versions(job) == before


def test_a_create_of_a_folder_removed_before_the_check_makes_no_version(job, poll_fast):
	# fails on main: its replay finds nothing to copy, and the batch commits a version that changes nothing
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a'})
	before = _settled(job)
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'made-and-gone/', 'create')]))
	manifest.close()
	assert committed is True and committed_versions(job) == before


def test_a_file_gone_between_the_check_and_its_open_is_gone_not_unreadable(job, poll_fast, monkeypatch, capsys):
	# fails at 15b3108: the open's FileNotFoundError is taken for an unreadable file, and the batch logs a false UNREADABLE line,
	# which alerts. The file is looked at, then gone at the open (faked once: the entry is not there at that moment)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	_settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	open(path, 'w').write('b, longer')
	real_open = os.open
	gone = []
	def opening(target, flags, *args, **kwargs):
		if not gone and os.fspath(target) == path and flags & os.O_NONBLOCK:
			gone.append(True)
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), target)
		return real_open(target, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)
	capsys.readouterr()
	_events(job, [(False, 'modify', 'b.txt', None)])
	out = capsys.readouterr()
	assert gone and 'UNREADABLE' not in out.out + out.err
	# the replay's own line for a path gone, as the lstat's ENOENT gets
	assert (out.out + out.err).count('Not tracking b.txt: source no longer exists') == 1


@needs_unreadable
def test_an_unreadable_file_beside_a_real_change_commits(job, poll_fast, capsys):
	# pin: the check stops at the readable change; the unreadable file keeps its last copy, with its line
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	open(path, 'w').write('b, longer')
	os.chmod(path, 0)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('a changed')
	capsys.readouterr()
	_events(job, [(False, 'modify', 'b.txt', None), (False, 'modify', 'a.txt', None)])
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	assert open(os.path.join(versions[-1], 'a.txt')).read() == 'a changed' and open(os.path.join(versions[-1], 'b.txt')).read() == 'b'
	assert _lines(capsys, 'UNREADABLE', path) == 1


def test_a_one_file_batch_checks_its_file_once_and_probes_nothing(job, poll_fast, monkeypatch):
	# fails on main, which makes no check: one lstat, one open and one close of the file before the estimate, and no probe
	seed_monitor(job, {'a.txt': 'a'})
	_settled(job)
	path = os.path.join(job.monitor, 'a.txt')
	open(path, 'w').write('a changed')
	calls, fds = [], set()
	estimating = []
	real_lstat, real_open, real_close, real_symlink = os.lstat, os.open, os.close, os.symlink
	def lstat(target, *args, **kwargs):
		if not estimating and os.fspath(target) == path:
			calls.append('lstat')
		return real_lstat(target, *args, **kwargs)
	def opening(target, flags, *args, **kwargs):
		fd = real_open(target, flags, *args, **kwargs)
		if not estimating and os.fspath(target) == path:
			calls.append('open')
			fds.add(fd)
		return fd
	def closing(fd):
		if not estimating and fd in fds:
			fds.discard(fd)
			calls.append('close')
		return real_close(fd)
	def symlink(text, target, *args, **kwargs):
		if os.path.basename(os.fspath(target)).startswith('.link-probe-'):
			calls.append('probe')
		return real_symlink(text, target, *args, **kwargs)
	real_estimate = rv.get_backup_size_inode
	def estimate(*args, **kwargs):
		estimating.append(True)
		return real_estimate(*args, **kwargs)
	monkeypatch.setattr(os, 'lstat', lstat)
	monkeypatch.setattr(os, 'open', opening)
	monkeypatch.setattr(os, 'close', closing)
	monkeypatch.setattr(os, 'symlink', symlink)
	monkeypatch.setattr(rv, 'get_backup_size_inode', estimate)
	_events(job, [(False, 'modify', 'a.txt', None)])
	assert estimating and calls == ['lstat', 'open', 'close']


@needs_unreadable
def test_an_unreadable_file_written_again_and_again_makes_no_version(job, poll_fast, capsys):
	# review focus 2 (fails on main, one version a batch): another user's file, written again and again, as three event batches
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	for round in range(3):
		os.chmod(path, 0o600)
		open(path, 'w').write('b' * (round + 2))
		os.chmod(path, 0)
		capsys.readouterr()
		_events(job, [(False, 'modify', 'b.txt', None)])
		assert committed_versions(job) == before
		assert _lines(capsys, 'UNREADABLE', path) == 1


@pytest.mark.parametrize('kind', ['fifo', 'socket'])
def test_a_batch_of_only_a_fifo_or_a_socket_commits_it(job, poll_fast, monkeypatch, kind):
	# pin (review focus 3): the check counts another kind as a change, and the version holds it, as cp -a copies it as itself
	import socket
	import stat as stats
	seed_monitor(job, {'a.txt': 'a'})
	before = _settled(job)
	if kind == 'fifo':
		os.mkfifo(os.path.join(job.monitor, 'entry'))
	else:
		# a socket's path must fit in sun_path's 108 bytes: bound by its name, from the monitored folder
		monkeypatch.chdir(job.monitor)
		bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		bound.bind('entry')
		bound.close()
	_events(job, [(False, 'create', 'entry', None)])
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	mode = os.lstat(os.path.join(versions[-1], 'entry')).st_mode
	assert (stats.S_ISFIFO if kind == 'fifo' else stats.S_ISSOCK)(mode)


# ---- L10: a folder gone when a walk reaches it is no error

def _removed_at_its_listing(monkeypatch, folder):
	'''folder is removed when it is opened for a listing, just before the kernel's open: a folder made and removed while a walk passed.'''
	def remove():
		if os.path.isdir(folder):
			shutil.rmtree(folder)
	on_folder_open(monkeypatch, folder, remove)


def _walk_lines(monkeypatch):
	'''The walk's log lines from now on (iter_tree_entries() logs as the watcher), as (message, whether an error line).'''
	lines = []
	real = rv.watcherTeeLogToTl
	def record(monitor_path, message, error=False, ok=False):
		lines.append((message, error))
		return real(monitor_path, message, error=error, ok=ok)
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', record)
	return lines


def _gone_lines(lines, folder):
	return [message for message, error in lines if message.startswith(f'{folder} was gone when the walk reached it: ') and not error]


def _scan_errors(lines):
	return [message for message, error in lines if error and message.startswith('Error scanning')]


def _row(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel)
	finally:
		manifest.close()


def test_a_folder_removed_between_its_parents_listing_and_its_own_is_one_info_line(job, poll_fast, monkeypatch, capsys):
	# a full comparison meets a folder its parent listed and that went before its own listing opened (git's objects/xx, a build's
	# scratch): one info line, no ERROR line, no UNREADABLE alert, and its rows kept for its delete event or the next comparison.
	# Fails on 82732dd: "Error scanning <path>: [Errno 2] ..." at ERROR, and an UNREADABLE line
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x', 'd/sub/y.txt': 'y'})
	_settled(job)
	folder = os.path.join(job.monitor, 'd')
	_removed_at_its_listing(monkeypatch, folder)
	lines = _walk_lines(monkeypatch)
	capsys.readouterr()
	_full(job)
	assert len(_gone_lines(lines, folder)) == 1
	assert _scan_errors(lines) == []
	assert _lines(capsys, 'UNREADABLE', folder) == 0
	assert _row(job, 'd/x.txt') is not None and _row(job, 'd/sub/y.txt') is not None


def test_a_touched_folder_removed_after_its_lstat_is_one_info_line(job, poll_fast, monkeypatch, capsys):
	# a batch's comparison of a folder its events touched: the folder looked at (iter_scope_entries()'s lstat), then gone before its
	# listing opened. Fails on 82732dd: "Error scanning <path>: [Errno 2] ..." at ERROR, and an UNREADABLE line
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x'})
	_settled(job)
	seed_monitor(job, {'d/new/n.txt': 'n'})
	folder = os.path.join(job.monitor, 'd', 'new')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		# the walk of the scope, right after its lstat
		if sys._getframe(1).f_code.co_name == 'iter_scope_entries' and os.path.abspath(path).rstrip('/') == folder and os.path.isdir(folder):
			shutil.rmtree(folder)
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	lines = _walk_lines(monkeypatch)
	capsys.readouterr()
	_events(job, [(True, 'create', 'd/new', None), (False, 'create', 'd/new/n.txt', None)])
	assert len(_gone_lines(lines, folder)) == 1
	assert _scan_errors(lines) == []
	assert _lines(capsys, 'UNREADABLE', folder) == 0


def test_a_mode_000_folder_still_logs_its_error_and_unreadable_lines(job, poll_fast, monkeypatch, capsys):
	# pin: a folder the walk cannot open while it is there (EACCES, what a folder of mode 000 is to a user other than root, given by a
	# stand-in so root sees it too) keeps its ERROR line and its UNREADABLE alert, and its rows
	seed_monitor(job, {'a.txt': 'a', 'locked/b.txt': 'b'})
	_settled(job)
	folder = os.path.join(job.monitor, 'locked')
	_fail_open(monkeypatch, folder, errno.EACCES)
	lines = _walk_lines(monkeypatch)
	capsys.readouterr()
	_full(job)
	assert len(_scan_errors(lines)) == 1 and _gone_lines(lines, folder) == []
	assert _lines(capsys, 'UNREADABLE', folder) == 1
	assert _row(job, 'locked/b.txt') is not None


@pytest.mark.parametrize('lookup', ['lstat_finds_it', 'lstat_fails_too'])
def test_a_folder_listed_but_never_opened_keeps_its_error_and_unreadable_lines(job, poll_fast, monkeypatch, capsys, lookup):
	# pin, R32 and R44: a folder its parent lists and the kernel cannot open, every time (name trouble on a FUSE, CIFS or NTFS mount):
	# its contents are not backed up, so it keeps its ERROR line and UNREADABLE alert at every walk, and its rows stay. An lstat of it
	# may find it, or fail with ENOENT as well, since a name the kernel cannot look up fails both: only the parent's listing says
	# whether it is gone. Fails on 850ecf5 with the lstat failing too: one INFO line, no ERROR line, no UNREADABLE alert
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x'})
	_settled(job)
	folder = os.path.join(job.monitor, 'd')
	_fail_open(monkeypatch, folder, errno.ENOENT)
	if lookup == 'lstat_fails_too':
		_fail_lstat(monkeypatch, folder, errno.ENOENT)
	for _ in range(2):
		lines = _walk_lines(monkeypatch)
		capsys.readouterr()
		_full(job)
		assert len(_scan_errors(lines)) == 1 and _gone_lines(lines, folder) == []
		assert _lines(capsys, 'UNREADABLE', folder) == 1
	assert _row(job, 'd/x.txt') is not None


def test_a_monitored_root_gone_at_the_walk_still_fails_the_attempt(job, poll_fast, monkeypatch):
	# pin: the monitored root gone when the comparison's walk opens it fails the attempt, before anything is recorded as deleted
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x'})
	before = _settled(job)
	_removed_at_its_listing(monkeypatch, job.monitor.rstrip('/'))
	with pytest.raises(rv.JobFailure):
		_backup(job)
	assert committed_versions(job) == before


# ---- P11: a folder is opened without following a link at its name (spec section 2, items 2 and 6)

def _outside(tmp_path):
	'''A folder beside the monitored tree, holding secret.txt and a subfolder: what a link swapped in for a folder points to.'''
	outside = tmp_path / 'outside'
	os.makedirs(outside / 'sub')
	(outside / 'secret.txt').write_text('not in the tree')
	(outside / 'sub' / 'deeper.txt').write_text('not in the tree either')
	return str(outside)


def _swap(folder, aside, replaced_by, target=None):
	'''What mv folder aside; ln -s target folder does (or puts a file at folder's place), once: an action for on_folder_open().'''
	def swap():
		if os.path.isdir(folder) and not os.path.islink(folder):
			os.rename(folder, aside)
			if replaced_by == 'link':
				os.symlink(target, folder)
			else:
				with open(folder, 'w') as f:
					f.write('a file now')
	return swap


def _holding(job, name):
	'''The paths in every committed version of job that end with name (links not followed).'''
	return [os.path.join(base, found) for version in committed_versions(job) for base, dirs, files in os.walk(version)
		for found in dirs + files if found == name]


@pytest.mark.parametrize('replaced_by', ['link', 'file'])
def test_a_folder_replaced_at_its_open_is_gone_with_one_info_line(tmp_path, monkeypatch, replaced_by):
	# spec section 2, test 4: d, listed by its parent, is replaced before the walk opens it by a link to a folder outside the tree
	# (mv d d.old; ln -s /srv/other d) or by a file: no entry of the outside folder, one INFO line, no ERROR line, a FolderGone.
	# Fails on ed959e0: the walk lists the outside folder through the link; for the file, "Error scanning" at ERROR
	from tests.harness import write_tree
	root = str(tmp_path / 'm')
	write_tree(root, {'a.txt': 'a', 'd/x.txt': 'x', 'e/y.txt': 'y'})
	folder = os.path.join(root, 'd')
	on_folder_open(monkeypatch, folder, _swap(folder, str(tmp_path / 'd.old'), replaced_by, _outside(tmp_path)))
	lines = _walk_lines(monkeypatch)
	errors = []
	walked = sorted((rel, is_dir) for _, rel, is_dir in rv.iter_tree_entries(root, errors=errors))
	assert walked == [('a.txt', False), ('d/', True), ('e/', True), ('e/y.txt', False)]
	assert [(rel, type(error)) for rel, error in errors] == [('d/', rv.FolderGone)]
	assert len(_gone_lines(lines, folder)) == 1 and _scan_errors(lines) == []


def test_a_full_comparison_meeting_a_link_swapped_in_mid_walk_commits_nothing_from_outside(job, tmp_path, poll_fast, monkeypatch):
	# spec section 2, test 4: the same swap while a full comparison walks the tree. Fails on ed959e0: the walk lists the outside
	# folder through the link, and the version holds its files under d, with their rows
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x'})
	_settled(job)
	folder = os.path.join(job.monitor, 'd')
	on_folder_open(monkeypatch, folder, _swap(folder, str(tmp_path / 'd.old'), 'link', _outside(tmp_path)))
	_full(job)
	assert os.path.islink(folder)
	assert _holding(job, 'secret.txt') == [] and _holding(job, 'deeper.txt') == []
	assert _row(job, 'd/secret.txt') is None and _row(job, 'd/sub/') is None


def test_a_new_folder_replaced_by_a_link_before_its_copy_walk_is_not_followed(job, tmp_path, poll_fast, monkeypatch):
	# review focus 2 (beyond the spec): a batch's create of a folder copies it with a walk from that folder, which is not a
	# configured path: n is replaced by a link to a folder outside the tree before that walk opens it, and nothing of the outside
	# folder is copied. Fails on ed959e0: the copy walk opens its root following the link, and the version holds the outside
	# folder's files under n
	from tests.harness import event_entry, run_backup
	seed_monitor(job, {'a.txt': 'a'})
	_settled(job)
	seed_monitor(job, {'n/inner.txt': 'i'})
	folder = os.path.join(job.monitor, 'n')
	on_folder_open(monkeypatch, folder, _swap(folder, str(tmp_path / 'n.old'), 'link', _outside(tmp_path)))
	run_backup(job, OrderedDict([event_entry(job, 'n/', 'create')]))
	assert os.path.islink(folder)
	assert _holding(job, 'secret.txt') == [] and _holding(job, 'deeper.txt') == []
	assert _row(job, 'n/secret.txt') is None


@pytest.mark.parametrize('skip', ['no_skip_list', 'skip_list'])
def test_the_size_estimate_of_a_new_folder_replaced_by_a_link_charges_nothing_of_the_links_target(job, tmp_path, monkeypatch, skip):
	# review of Task 6, I1: the size estimate walks each folder entry of a batch from that folder, which is not a configured path: n
	# is replaced by a link to a folder outside the tree after the estimate's lstat found it and before its walk opens it. The
	# copy walk copies none of the outside folder, so the estimate must charge none of it either (a limit would otherwise prune the
	# oldest versions for good to make room for bytes never written). Fails on 3869779: the walk opens n following the link and
	# charges the outside folder's file and subfolder
	seed_monitor(job, {'n/inner.txt': 'i' * 5000})
	folder = os.path.join(job.monitor, 'n')
	os.makedirs(job.job_vault, exist_ok=True)
	outside = _outside(tmp_path)
	with open(os.path.join(outside, 'big.bin'), 'wb') as f:
		f.write(b'o' * (1 << 20))
	# n itself, which the lstat found before the swap
	own_blocks = os.lstat(folder).st_blocks * 512
	on_folder_open(monkeypatch, folder, _swap(folder, str(tmp_path / 'n.old'), 'link', outside))
	entries = OrderedDict([(folder + '/', rv.BackupEntryValues('t', 'create', None))])
	skip_list = rv.SkipList(job.monitor, ['*.tmp']) if skip == 'skip_list' else None
	size, inodes = rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, skip_list, version_bytes=0)
	assert os.path.islink(folder)
	assert (size, inodes) == (own_blocks, 1)


def test_a_root_with_a_trailing_slash_yields_the_same_paths(tmp_path):
	# pin: review focus 3: a listing of a handle names its entries only, so the walk joins each path itself, where DirEntry.path
	# joined it. A root given with a trailing / (a rule path may end with one) yields the same paths as without, none with //, and
	# the walk of / itself yields paths with one / at their start (only its own names kept, the walk stopped early)
	import itertools
	from tests.harness import write_tree
	root = str(tmp_path / 'm')
	write_tree(root, {'a.txt': 'a', 'd/e/f.txt': 'f', 'd/g.txt': 'g', 'h/': None})
	plain = list(rv.iter_tree_entries(root))
	assert list(rv.iter_tree_entries(root + '/')) == plain
	assert sorted(rel for _, rel, _ in plain) == ['a.txt', 'd/', 'd/e/', 'd/e/f.txt', 'd/g.txt', 'h/']
	assert all(path == os.path.join(root, rel) and '//' not in path for path, rel, _ in plain)
	walk = rv.iter_tree_entries('/', skip=lambda rel: '/' in rel.rstrip('/'))
	first = list(itertools.islice(walk, 5))
	walk.close()
	assert first and all(path == '/' + rel and not path.startswith('//') for path, rel, _ in first)


def test_a_folder_whose_path_passes_4095_bytes_keeps_its_error_and_unreadable_lines(job, poll_fast, monkeypatch, capsys):
	# pin: spec section 2, test 9: the kernel refuses a path of 4,096 bytes and more (ENAMETOOLONG), which no swap explains: the
	# folder whose path passes it keeps its ERROR line and its UNREADABLE alert. The monitored folder is itself deep, so its
	# files' places in the vault, which is not, stay short
	# 3,900 bytes of the monitored folder's path, made of names of 200 bytes and one shorter
	monitor = os.path.join(job.root, 'm')
	while len(os.fsencode(monitor)) < 3690:
		monitor = os.path.join(monitor, 'x' * 200)
	monitor = os.path.join(monitor, 'y' * (3900 - len(os.fsencode(monitor)) - 1))
	job = job._replace(monitor=monitor)
	seed_monitor(job, {'a.txt': 'a'})
	_settled(job)
	name = 'f' * 200
	folder = os.path.join(monitor, name)
	assert len(os.fsencode(folder)) >= 4096 > len(os.fsencode(monitor)) + len('/a.txt')
	monkeypatch.chdir(monitor)
	os.mkdir(name)
	lines = _walk_lines(monkeypatch)
	capsys.readouterr()
	_full(job)
	assert [message for message in _scan_errors(lines) if message.startswith(f'Error scanning {folder}: [Errno {errno.ENAMETOOLONG}]')] == _scan_errors(lines)
	assert len(_scan_errors(lines)) >= 1 and _gone_lines(lines, folder) == []
	assert _lines(capsys, 'UNREADABLE', folder) == 1


# ---- D14 and P12: a listing kept per parent, and only the reads' OSError caught (spec section 2, items 4 and 5)

def _listings_of(monkeypatch, folder):
	'''The listings of folder (an absolute path) from now on, each by its path or by a handle of it, as a list that grows as os.scandir() is called.'''
	folder_id = (os.stat(folder).st_dev, os.stat(folder).st_ino)
	listings = []
	real_scandir = os.scandir
	def scandir(name='.'):
		if isinstance(name, int):
			st = os.fstat(name)
			if (st.st_dev, st.st_ino) == folder_id:
				listings.append(name)
		elif os.path.abspath(os.fsdecode(name)).rstrip('/') == folder:
			listings.append(name)
		return real_scandir(name)
	monkeypatch.setattr(os, 'scandir', scandir)
	return listings


def test_a_mass_deletion_while_the_walk_passes_lists_the_parent_at_most_twice(tmp_path, monkeypatch):
	# spec section 2, test 6 (D14): 200 sibling folders, all removed as the walk opens the first of them (an rm -rf of a build's
	# output while a full comparison passes): one listing of their parent, kept, tells the rest gone, rather than a listing a
	# folder. Each is still a FolderGone with its INFO line. Fails on 249ee52: the parent is listed 201 times (its own listing,
	# then once for each folder gone)
	root = str(tmp_path / 'm')
	parent = os.path.join(root, 'p')
	names = [f'd{i:03}' for i in range(200)]
	for name in names:
		os.makedirs(os.path.join(parent, name, 'sub'))
	# the first the walk opens: an unchanged folder is listed in the same order every time
	with os.scandir(parent) as listing:
		first = next(entry.name for entry in listing)
	def remove_all():
		for name in names:
			shutil.rmtree(os.path.join(parent, name), ignore_errors=True)
	on_folder_open(monkeypatch, os.path.join(parent, first), remove_all)
	listings = _listings_of(monkeypatch, parent)
	lines = _walk_lines(monkeypatch)
	errors = []
	walked = [rel for _, rel, _ in rv.iter_tree_entries(root, errors=errors)]
	assert walked[0] == 'p/' and sorted(walked[1:]) == [f'p/{name}/' for name in names]
	assert len(listings) <= 2, listings
	assert sorted((rel, type(error)) for rel, error in errors) == [(f'p/{name}/', rv.FolderGone) for name in names]
	assert all(len(_gone_lines(lines, os.path.join(parent, name))) == 1 for name in names) and _scan_errors(lines) == []


def test_a_folder_the_kept_listing_still_names_is_asked_again_by_a_new_listing(tmp_path, monkeypatch):
	# the Opus review of Task 7, Minor 1 (D14): p/a and p/b are each removed just before their own open. Whichever the walk opens
	# first is gone by a listing of p, kept; that listing still names the other, which is removed after it, so the kept names cannot
	# tell it gone, and a new listing does. Both are a FolderGone with their INFO line and no ERROR line, and p is listed three
	# times: by its own handle, then once for each folder gone. Fails on a walk that answers from the kept names: the second is
	# taken for an unreadable folder (an ERROR line), and p is listed twice
	root = str(tmp_path / 'm')
	parent = os.path.join(root, 'p')
	for name in ('a', 'b'):
		os.makedirs(os.path.join(parent, name, 'sub'))
		_removed_at_its_listing(monkeypatch, os.path.join(parent, name))
	listings = _listings_of(monkeypatch, parent)
	lines = _walk_lines(monkeypatch)
	errors = []
	walked = sorted(rel for _, rel, _ in rv.iter_tree_entries(root, errors=errors))
	assert walked == ['p/', 'p/a/', 'p/b/']
	assert sorted((rel, type(error)) for rel, error in errors) == [('p/a/', rv.FolderGone), ('p/b/', rv.FolderGone)]
	assert [len(_gone_lines(lines, os.path.join(parent, name))) for name in ('a', 'b')] == [1, 1] and _scan_errors(lines) == []
	assert len(listings) == 3, listings


def test_a_parent_that_cannot_be_listed_leaves_the_folders_error_and_unreadable_lines(job, poll_fast, monkeypatch, capsys):
	# pin: the Opus and Haiku B reviews of Task 7: p/d cannot be opened (ENOENT, as name trouble on a FUSE mount gives it), and the
	# listing of p by its path, which tells whether d is gone, fails with EIO. Nothing tells d gone, so it keeps its ERROR line and its
	# UNREADABLE alert, and its rows stay: a rule that took any failed listing for "gone" would drop its rows from the next version
	# and say nothing. Fails on a walk that answers gone for any error of that listing
	seed_monitor(job, {'a.txt': 'a', 'p/d/x.txt': 'x', 'p/e.txt': 'e'})
	_settled(job)
	parent, folder = os.path.join(job.monitor, 'p'), os.path.join(job.monitor, 'p', 'd')
	_fail_open(monkeypatch, folder, errno.ENOENT)
	real_scandir = os.scandir
	def scandir(name='.'):
		if not isinstance(name, int) and os.path.abspath(os.fsdecode(name)).rstrip('/') == parent:
			raise OSError(errno.EIO, os.strerror(errno.EIO), name)
		return real_scandir(name)
	monkeypatch.setattr(os, 'scandir', scandir)
	lines = _walk_lines(monkeypatch)
	capsys.readouterr()
	_full(job)
	scan_errors = _scan_errors(lines)
	assert len(scan_errors) == 1 and scan_errors[0].startswith(f'Error scanning {folder}: [Errno {errno.ENOENT}] ') and _gone_lines(lines, folder) == []
	assert _lines(capsys, 'UNREADABLE', folder) == 1
	assert _row(job, 'p/d/x.txt') is not None


def test_a_walk_raises_what_its_skip_raises(tmp_path):
	# spec section 2, test 8 (P12): a bug in what the walk calls between its reads (here its skip, at the bottom of a deep tree) is
	# raised to the caller with its traceback, not taken for an unreadable folder. And with that exception and its traceback still
	# held, every listing the walk had open is closed: the traceback keeps the walk's frame, so only the walk's own finally closes
	# them (a walk stopped early by a break or a close() is freed with its listings anyway). Fails on 249ee52: the ValueError is
	# swallowed as an unreadable folder (the one whose listing called the skip), with an "Error scanning" line, and the walk goes on
	from tests.harness import deep_tree
	from tests.test_deep_trees import open_fds
	root = str(tmp_path / 't')
	depth = 20
	deep_tree(root, depth)
	bottom = 'd/' * depth
	def skip(rel):
		if rel == bottom:
			raise ValueError(f'a bug at {rel}')
		return False
	before = open_fds()
	with pytest.raises(ValueError) as excinfo:
		list(rv.iter_tree_entries(root, skip=skip))
	assert open_fds() == before
	assert str(excinfo.value) == f'a bug at {bottom}' and excinfo.traceback[-1].name == 'skip'


@pytest.mark.parametrize('raised_by', ['skip', 'consumer'])
def test_a_walk_raises_an_oserror_of_its_skip_or_its_consumer_as_it_is(tmp_path, monkeypatch, raised_by):
	# ruling R17 (the walk's loop shape), a pin of P12 for what is an OSError: the walk catches an OSError of its own reads only, so
	# one that the skip raises (a bug in it that reads a file, say) or one thrown into the walk at a yield (the caller's own) is no
	# unreadable folder either: it leaves the walk as it is, with no ERROR line and no errors entry, and, with it and its traceback
	# held, every listing the walk had open is closed. Fails on a walk whose catch cannot tell its reads from its body: the OSError
	# is taken as the folder's error (an ERROR line, an errors entry) and the walk goes on
	from tests.harness import deep_tree
	from tests.test_deep_trees import open_fds
	root = str(tmp_path / 't')
	depth = 20
	deep_tree(root, depth)
	bottom = 'd/' * depth
	def skip(rel):
		if raised_by == 'skip' and rel == bottom:
			raise OSError(errno.EIO, 'a bug in the skip', rel)
		return False
	lines = _walk_lines(monkeypatch)
	errors = []
	before = open_fds()
	with pytest.raises(OSError) as excinfo:
		walk = rv.iter_tree_entries(root, skip=skip, errors=errors)
		for _, rel, _ in walk:
			if raised_by == 'consumer' and rel == bottom:
				walk.throw(OSError(errno.EIO, 'thrown in by the caller', rel))
	assert open_fds() == before
	assert excinfo.value.errno == errno.EIO and excinfo.value.strerror == ('a bug in the skip' if raised_by == 'skip' else 'thrown in by the caller')
	assert errors == [] and _scan_errors(lines) == []


class _FailingListing:
	'''
	A listing of a folder by handle, as os.scandir(fd) gives one, whose entries come sorted by name and which fails with EIO as a folder
	on a dying disk does: its next entry after `served` entries (fail_at 'next'), or the is_dir() of the entry with the name `name`
	(fail_at 'is_dir', the way a DirEntry whose type the filesystem does not give stats through the handle).
	'''
	def __init__(self, listing, fail_at, served=1, name=None):
		self._listing, self._fail_at, self._name = listing, fail_at, name
		self._entries = iter(sorted(listing, key=lambda entry: entry.name))
		self._served = served

	def __iter__(self):
		return self

	def __next__(self):
		if self._fail_at == 'next' and not self._served:
			raise OSError(errno.EIO, os.strerror(errno.EIO))
		self._served -= 1
		entry = next(self._entries)
		return _FailingEntry(entry) if self._fail_at == 'is_dir' and entry.name == self._name else entry

	def close(self):
		self._listing.close()


class _FailingEntry:
	def __init__(self, entry):
		self.name = entry.name

	def is_dir(self, *, follow_symlinks=True):
		raise OSError(errno.EIO, os.strerror(errno.EIO), self.name)


@pytest.mark.parametrize('fail_at', ['next', 'is_dir'])
def test_an_oserror_of_a_listings_next_entry_or_an_entrys_type_is_the_folders_error(tmp_path, monkeypatch, fail_at):
	# pin: ruling R17, the reads the walk catches (P12): d is listed and its entries x then y come, the next entry after x, or the
	# type of y, failing with EIO. That is d's error and no other's: the entry before it is yielded, d gets its ERROR line and its
	# errors entry (no FolderGone), and the walk goes on with the next folder and its files. It passes on 249ee52 too, whose broad
	# catch took these errors as well: it keeps what the narrower catch must not lose, and fails on a walk with no catch of its
	# reads (the OSError leaves the walk)
	from tests.harness import listed_folder, write_tree
	from tests.test_deep_trees import open_fds
	root = str(tmp_path / 'm')
	write_tree(root, {'a.txt': 'a', 'd/x.txt': 'x', 'd/y.txt': 'y', 'e/z.txt': 'z'})
	folder = os.path.join(root, 'd')
	real_scandir = os.scandir
	def scandir(name='.'):
		listing = real_scandir(name)
		if isinstance(name, int) and listed_folder(name) == folder:
			return _FailingListing(listing, fail_at, name='y.txt')
		return listing
	monkeypatch.setattr(os, 'scandir', scandir)
	lines = _walk_lines(monkeypatch)
	errors = []
	before = open_fds()
	walked = [rel for _, rel, _ in rv.iter_tree_entries(root, errors=errors)]
	assert open_fds() == before
	assert sorted(walked) == ['a.txt', 'd/', 'd/x.txt', 'e/', 'e/z.txt']
	assert [(rel, type(error), error.errno) for rel, error in errors] == [('d/', OSError, errno.EIO)]
	scan_errors = _scan_errors(lines)
	assert len(scan_errors) == 1 and scan_errors[0].startswith(f'Error scanning {folder}: [Errno {errno.EIO}] ')


@pytest.mark.parametrize('version', ['none', 'in_place'], ids=['first_version', 'full_comparison'])
def test_a_start_whose_skip_raises_fails_the_attempt(job, poll_fast, monkeypatch, version):
	# spec section 2, test 8 (P12), the backuper's half: the job's skip list raises a ValueError at d/ (a bug in it), and the
	# start's walk raises it: the attempt fails with it, and nothing is committed. With no version the walk is the first version's
	# (do_backup()'s, with first_skip); with one in place it is the full comparison's (compare_scopes()): the two walks a start makes.
	# Fails on 249ee52: the walk swallows it as an unreadable folder, the one whose listing called the skip (here the monitored
	# folder), so the attempt fails as "cannot read <the monitored folder>: a bug in the skip list", and with the skip at a deeper
	# folder it would commit V0 without that one
	from tests.harness import wait_until
	seed_monitor(job, {'a.txt': 'a', 'd/x.txt': 'x'})
	before = _settled(job) if version == 'in_place' else []
	real = rv.SkipList.skips
	def skips(self, rel):
		if rel == 'd/':
			raise ValueError('a bug in the skip list')
		return real(self, rel)
	monkeypatch.setattr(rv.SkipList, 'skips', skips)
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	# the backuper as a start runs it, its watches in place
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	queue, lock, flag, ready = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event(), threading.Event()
	ready.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag, ready),
		kwargs=dict(startup=startup, job=control), daemon=True)
	thread.start()
	try:
		wait_until(lambda: control.failure is not None or len(committed_versions(job)) > len(before), message='the attempt neither failed nor committed')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()
	assert committed_versions(job) == before
	assert control.failure is not None and control.failure.reason == 'ValueError: a bug in the skip list'


# ---- F4's check meets two cases the copy answers otherwise (the final review's measurement, F-fix): a file another process
# holds a write lease on, and an entry under a folder the version has no row of

# a holder of a write lease, as knfsd (a write delegation), Samba (kernel oplocks) or any F_SETLEASE caller is: it lets the
# lease go some time after the break begins, as a client returns a delegation. A blocking open waits for that; one with
# O_NONBLOCK fails at once with EWOULDBLOCK, though the break still begins (fcntl(2)). 1.5 s is longer than the check's
# comparison after the drop takes (milliseconds), so the comparison's own check meets the lease too
LEASE_HOLDER = '''
import fcntl, os, signal, sys, time
fd = os.open(sys.argv[1], os.O_RDWR)
try:
	fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_WRLCK)
except OSError as e:
	print('refused', e.errno, flush=True)
	sys.exit(0)
def broken(*_):
	time.sleep(1.5)
	fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
signal.signal(signal.SIGIO, broken)
print('held', flush=True)
sys.stdin.read()
'''


def test_a_file_under_another_processs_write_lease_is_backed_up_as_on_main(job, poll_fast, capsys):
	# fails on 260f399: the check's open (O_NONBLOCK) fails at once with EWOULDBLOCK, the file is classed unreadable, and the batch
	# is dropped with an UNREADABLE line and no copy, where main's blocking cp waits for the lease to break and backs it up. A real
	# lease, taken by a helper process (it needs the file's owner and no other open of it)
	import subprocess
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	with open(path, 'w') as f:
		f.write('b, longer')
	holder = subprocess.Popen([sys.executable, '-c', LEASE_HOLDER, path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
	try:
		said = holder.stdout.readline().strip()
		if said.startswith('refused'):
			pytest.skip(f'this filesystem takes no write lease ({said})')
		# a helper that died before saying anything is a failure of the test, not of the filesystem
		assert said == 'held', f'the lease helper said {said!r} and exited {holder.poll()}'
		capsys.readouterr()
		_events(job, [(False, 'modify', 'b.txt', None)])
	finally:
		holder.stdin.close()
		holder.wait(timeout=30)
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	with open(os.path.join(versions[-1], 'b.txt')) as f:
		assert f.read() == 'b, longer'
	assert _lines(capsys, 'UNREADABLE', path) == 0


# ---- spec section 3 (D2, D1): a comparison waits for a leased file as cp does, and the check reads the last 64 KiB of the file it
# opens, so a file whose tail cannot be read drops out there

def _matched(job):
	'''The vault's matched time (VaultManifest.matched).'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.matched
	finally:
		manifest.close()


def test_a_full_comparison_waits_for_a_leased_file_and_finds_it_unchanged(job, poll_fast, capsys):
	# fails on main ("Error comparing <path>: [Errno 11] Resource temporarily unavailable, treating as modify", and a version that
	# changes nothing): b.txt matches its record by size and mtime, and the helper holds a write lease on it through a full
	# comparison, letting go 1.5 s after the break begins. The comparison's tail read waits for that, as cp's open does
	import subprocess
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	holder = subprocess.Popen([sys.executable, '-c', LEASE_HOLDER, path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
	try:
		said = holder.stdout.readline().strip()
		if said.startswith('refused'):
			pytest.skip(f'this filesystem takes no write lease ({said})')
		assert said == 'held', f'the lease helper said {said!r} and exited {holder.poll()}'
		capsys.readouterr()
		began = time.monotonic()
		assert _full(job) is True
		took = time.monotonic() - began
	finally:
		holder.stdin.close()
		holder.wait(timeout=30)
	out = capsys.readouterr()
	assert 'Error comparing' not in out.out + out.err
	assert committed_versions(job) == before
	assert took >= 1


def test_a_fifo_swapped_in_after_the_ewouldblock_does_not_hold_the_comparison(tmp_path, monkeypatch):
	# fails on main at once, never by blocking: main raises the EWOULDBLOCK itself. A stand-in on os.open answers the non-blocking
	# open of f with EWOULDBLOCK, as a lease does, after putting a FIFO with no writer at f's place, so the reopen meets the FIFO:
	# its O_PATH handle cannot block, and its fstat refuses it as "Not a regular file", where a blocking open would wait for ever
	path = str(tmp_path / 'f')
	with open(path, 'w') as f:
		f.write('f')
	real_open = os.open
	swapped = []
	def opening(target, flags, *args, **kwargs):
		if not swapped and os.fspath(target) == path and flags & os.O_NONBLOCK:
			swapped.append(True)
			os.remove(path)
			os.mkfifo(path)
			raise BlockingIOError(errno.EWOULDBLOCK, os.strerror(errno.EWOULDBLOCK), target)
		return real_open(target, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)
	outcome = []
	def hash_it():
		try:
			outcome.append(rv.hash_file(path, 1))
		except OSError as e:
			outcome.append(e)
	worker = threading.Thread(target=hash_it, daemon=True)
	worker.start()
	worker.join(timeout=5)
	if worker.is_alive():
		# a writer's open lets a blocked reader's open return, so the thread does not outlive the test
		os.close(real_open(path, os.O_WRONLY | os.O_NONBLOCK))
	assert not worker.is_alive(), 'hash_file blocked on the FIFO'
	assert swapped and isinstance(outcome[0], OSError)
	assert (outcome[0].errno, outcome[0].strerror) == (errno.EINVAL, 'Not a regular file'), outcome[0]


@pytest.mark.parametrize('stopping', [True, False], ids=['stopping', 'running'])
def test_a_stopping_daemon_does_not_wait_for_a_lease_to_break(tmp_path, monkeypatch, stopping):
	# fails on b73897c with GREEN_LIGHT clear: the opener meets EWOULDBLOCK (a stand-in on the non-blocking open, as a lease answers it)
	# and reopens the file through its O_PATH handle and a blocking open, which waits for the lease to break (the lease-break time, 45 s
	# by default), and every comparison still queued on the pool would wait again. A stopping daemon raises the BlockingIOError at once
	# and opens nothing more; a running one (the pin) reopens, as cp's open waits, and hashes the file
	path = str(tmp_path / 'f')
	with open(path, 'w') as f:
		f.write('f')
	real_open = os.open
	reopened = []
	def opening(target, flags, *args, **kwargs):
		if os.fspath(target) == path and flags & os.O_NONBLOCK:
			raise BlockingIOError(errno.EWOULDBLOCK, os.strerror(errno.EWOULDBLOCK), target)
		if flags & os.O_PATH or os.fspath(target).startswith('/proc/self/fd/'):
			reopened.append(os.fspath(target))
		return real_open(target, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)
	try:
		if stopping:
			rv.GREEN_LIGHT.clear()
			with pytest.raises(BlockingIOError):
				rv.hash_file(path, 1)
			assert reopened == []
		else:
			assert rv.hash_file(path, 1) == rv.xxhash.xxh64(b'f').hexdigest()
			assert len(reopened) == 2
	finally:
		rv.GREEN_LIGHT.set()


@pytest.mark.parametrize('changed', [True, False], ids=['changed', 'unchanged'])
def test_a_file_whose_tail_cannot_be_read_makes_no_version(job, poll_fast, monkeypatch, capsys, changed):
	# fails on main (a version that changes nothing): b.txt opens and its read fails with EIO (a bad sector under its tail), at the
	# check's read (os.pread of a handle of its inode). Changed, it was rewritten and its modify is a batch's only entry; unchanged, a
	# full comparison meets it, its tail failing there too (rv.hash_file), which logs "Error comparing ..., treating as modify". The
	# check drops it with one UNREADABLE line, and the matched time stays
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	if changed:
		with open(path, 'w') as f:
			f.write('b, longer')
	st = os.lstat(path)
	real_pread = os.pread
	def pread(fd, length, offset):
		held = os.fstat(fd)
		if (held.st_dev, held.st_ino) == (st.st_dev, st.st_ino):
			raise OSError(errno.EIO, os.strerror(errno.EIO))
		return real_pread(fd, length, offset)
	monkeypatch.setattr(os, 'pread', pread)
	if not changed:
		real_hash = rv.hash_file
		def hash_file(target, *args, **kwargs):
			if os.path.abspath(target) == path:
				raise OSError(errno.EIO, os.strerror(errno.EIO), target)
			return real_hash(target, *args, **kwargs)
		monkeypatch.setattr(rv, 'hash_file', hash_file)
	matched = _matched(job)
	capsys.readouterr()
	if changed:
		_events(job, [(False, 'modify', 'b.txt', None)])
	else:
		assert _full(job) is True
	out = capsys.readouterr()
	assert committed_versions(job) == before
	assert (out.out + out.err).count(f'UNREADABLE: {path}: ') == 1
	# the file has a last copy: the line says it stays
	assert [line for line in (out.out + out.err).splitlines() if f'UNREADABLE: {path}: ' in line][0].endswith('; keeping its last backed-up copy')
	assert changed or f'Error comparing {path}: ' in out.out + out.err
	assert _matched(job) == matched


def test_a_fifo_swapped_in_after_the_checks_lstat_counts_as_a_change(job, poll_fast, monkeypatch, capsys):
	# pin (review focus 4): the check's lstat sees a regular file f, then a FIFO is put at f's place, which its open takes without
	# blocking (O_NONBLOCK). An entry of another kind changes the version, as the lstat pass counts one, and the tail read of a FIFO,
	# which fails (ESPIPE), must not make it an unreadable file
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a', 'f': 'f'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'f')
	real_lstat = os.lstat
	swapped = []
	def lstat(target, *args, **kwargs):
		got = real_lstat(target, *args, **kwargs)
		if not swapped and os.fspath(target) == path:
			swapped.append(True)
			os.remove(path)
			os.mkfifo(path)
		return got
	capsys.readouterr()
	with monkeypatch.context() as patch:
		patch.setattr(os, 'lstat', lstat)
		manifest = rv.VaultManifest(job.job_vault)
		try:
			dropped = rv.entries_all_drop_out(OrderedDict([event_entry(job, 'f', 'modify')]), job.monitor, before[-1], job.job_vault, None, job.job_name, set(), manifest, True)
		finally:
			manifest.close()
	assert swapped and dropped is False
	assert _lines(capsys, 'UNREADABLE', path) == 0


def test_a_socket_swapped_in_after_the_checks_lstat_counts_as_a_change(job, poll_fast, monkeypatch, capsys):
	# fails on b73897c: the check's lstat sees a regular file f, then a socket is put at f's place, which no open takes (ENXIO): the
	# check read it as an unreadable file and dropped the batch with a false UNREADABLE line. An entry of another kind changes the
	# version (cp -a copies it as itself), as the FIFO's case above, which opens. The socket is bound at a short relative name (a
	# socket's path holds 107 bytes) and renamed into place
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a', 'f': 'f'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'f')
	real_lstat = os.lstat
	swapped = []
	sockets = []
	def lstat(target, *args, **kwargs):
		got = real_lstat(target, *args, **kwargs)
		if not swapped and os.fspath(target) == path:
			swapped.append(True)
			bound = socket.socket(socket.AF_UNIX)
			sockets.append(bound)
			with monkeypatch.context() as inside:
				inside.chdir(job.monitor)
				bound.bind('f.sock')
			os.replace(os.path.join(job.monitor, 'f.sock'), path)
		return got
	capsys.readouterr()
	try:
		with monkeypatch.context() as patch:
			patch.setattr(os, 'lstat', lstat)
			manifest = rv.VaultManifest(job.job_vault)
			try:
				dropped = rv.entries_all_drop_out(OrderedDict([event_entry(job, 'f', 'modify')]), job.monitor, before[-1], job.job_vault, None, job.job_name, set(), manifest, True)
			finally:
				manifest.close()
	finally:
		for bound in sockets:
			bound.close()
	assert swapped and stat.S_ISSOCK(os.lstat(path).st_mode)
	assert dropped is False
	assert _lines(capsys, 'UNREADABLE', path) == 0


def test_a_link_swapped_in_after_the_checks_lstat_counts_as_a_change_and_is_not_followed(job, poll_fast, monkeypatch, capsys):
	# fails before the fix wave's FW3 (the final review's s13 (3)): the check's lstat sees a regular file f, then a link is put at f's
	# place, which the check's open followed: here to a path that is not there, so the check took f for gone ("Not tracking f: source
	# no longer exists") and dropped the batch, which the replay would have given the link (cp -a copies it as itself); to a file
	# elsewhere it read that file's last 64 KiB. The open takes no link now (ELOOP): an entry of another kind changes the version, as
	# the FIFO's and the socket's above
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a', 'f': 'f'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'f')
	real_lstat = os.lstat
	swapped = []
	def lstat(target, *args, **kwargs):
		got = real_lstat(target, *args, **kwargs)
		if not swapped and os.fspath(target) == path:
			swapped.append(True)
			os.remove(path)
			os.symlink(os.path.join(job.root, 'nowhere'), path)
		return got
	capsys.readouterr()
	with monkeypatch.context() as patch:
		patch.setattr(os, 'lstat', lstat)
		manifest = rv.VaultManifest(job.job_vault)
		try:
			dropped = rv.entries_all_drop_out(OrderedDict([event_entry(job, 'f', 'modify')]), job.monitor, before[-1], job.job_vault, None, job.job_name, set(), manifest, True)
		finally:
			manifest.close()
	assert swapped and os.path.islink(path)
	out = capsys.readouterr()
	assert dropped is False
	assert 'source no longer exists' not in out.out + out.err and f'UNREADABLE: {path}: ' not in out.out + out.err


@pytest.mark.parametrize('failing', ['this_version', 'the_version_before'])
def test_the_unreadable_lines_end_says_when_a_place_cannot_be_looked_at(tmp_path, monkeypatch, failing):
	# fails before the fix wave's FW6 (the final review's s04): unreadable_end() read an lstat that fails (EIO, EACCES) as nothing there
	# (os.path.lexists()), so the UNREADABLE line said 'left out of this version' of a copy that may still be in it, or 'which may be
	# damaged' of a last backed-up copy. Only ENOENT and ENOTDIR are nothing there: any other error is said as what it is
	dest, previous = str(tmp_path / 'this'), str(tmp_path / 'before')
	for path in (dest, previous):
		open(path, 'w').close()
	_fail_lstat(monkeypatch, dest if failing == 'this_version' else previous, errno.EIO)
	if failing == 'this_version':
		assert rv.unreadable_end(dest, previous) == 'what this version holds for it cannot be looked at (Input/output error)'
	else:
		assert rv.unreadable_end(dest, previous) == 'keeping the copy this version holds, which may be one a cut backup made, and damaged: the version before cannot be looked at (Input/output error)'


def test_the_unreadable_lines_end_says_when_the_version_before_cannot_be_looked_at_for_a_file_left_out(tmp_path, monkeypatch):
	# fails before the residual round's W2 (the fix wave's second-opinion finding on FW6): with nothing at this version's place the ending was
	# 'left out of this version' before the version before's place was looked at, so an I/O error there went unnamed, where the README says
	# the ending names it. The ending stays as it was where that place is not there, or is
	dest, previous = str(tmp_path / 'this'), str(tmp_path / 'before')
	assert rv.unreadable_end(dest, None) == 'left out of this version'
	assert rv.unreadable_end(dest, previous) == 'left out of this version'
	open(previous, 'w').close()
	assert rv.unreadable_end(dest, previous) == 'left out of this version'
	_fail_lstat(monkeypatch, previous, errno.EIO)
	assert rv.unreadable_end(dest, previous) == 'left out of this version; the version before cannot be looked at (Input/output error)'


def test_an_unchanged_readable_file_compares_as_unchanged(job, poll_fast, capsys):
	# pin: a full comparison reads each file's tail through its non-blocking open, which a file no lease is on takes at once
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b' * (rv.HASH_SIZE + 10)})
	before = _settled(job)
	capsys.readouterr()
	assert _full(job) is True
	out = capsys.readouterr()
	assert committed_versions(job) == before
	assert 'Error comparing' not in out.out + out.err and 'UNREADABLE' not in out.out + out.err


@pytest.mark.parametrize('where', ['comparison', 'check'])
def test_a_file_deleted_between_its_lstat_and_its_tail_read_is_handled_as_on_main(job, poll_fast, monkeypatch, capsys, where):
	# pin: b.txt goes after its lstat. At a full comparison it goes at the tail read's open: the comparison's error line, then the
	# check's lstat finds it gone ("Not tracking"), and no version. At the check of a batch, it goes just after the check's open, and
	# its tail is read through the handle: a change, as main's open counted it, and the version drops it. Neither is unreadable
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	if where == 'check':
		with open(path, 'w') as f:
			f.write('b, longer')
	real_open = os.open
	gone = []
	def opening(target, flags, *args, **kwargs):
		if gone or os.fspath(target) != path or not flags & os.O_NONBLOCK:
			return real_open(target, flags, *args, **kwargs)
		gone.append(True)
		if where == 'comparison':
			os.remove(path)
			return real_open(target, flags, *args, **kwargs)
		fd = real_open(target, flags, *args, **kwargs)
		os.remove(path)
		return fd
	monkeypatch.setattr(os, 'open', opening)
	capsys.readouterr()
	if where == 'comparison':
		assert _full(job) is True
	else:
		_events(job, [(False, 'modify', 'b.txt', None)])
	out = capsys.readouterr()
	text = out.out + out.err
	assert gone and 'UNREADABLE' not in text
	versions = committed_versions(job)
	if where == 'comparison':
		assert f'Error comparing {path}: [Errno {errno.ENOENT}] ' in text and text.count('Not tracking b.txt: source no longer exists') == 1
		assert versions == before
	else:
		assert len(versions) == len(before) + 1 and not os.path.lexists(os.path.join(versions[-1], 'b.txt'))


def test_a_new_file_whose_tail_cannot_be_read_is_left_out_and_its_line_says_so(job, poll_fast, monkeypatch, capsys):
	# the check drops a new file it cannot read (as the test above drops a changed one), and its UNREADABLE line says it is left out of the
	# version: there is no last copy to keep. The line ended "keeping its last backed-up copy" on 0.55.5
	seed_monitor(job, {'a.txt': 'a'})
	before = _settled(job)
	seed_monitor(job, {'new.txt': 'n'})
	path = os.path.join(job.monitor, 'new.txt')
	st = os.lstat(path)
	real_pread = os.pread
	def pread(fd, length, offset):
		held = os.fstat(fd)
		if (held.st_dev, held.st_ino) == (st.st_dev, st.st_ino):
			raise OSError(errno.EIO, os.strerror(errno.EIO))
		return real_pread(fd, length, offset)
	monkeypatch.setattr(os, 'pread', pread)
	capsys.readouterr()
	_events(job, [(False, 'create', 'new.txt', None)])
	out = capsys.readouterr()
	assert committed_versions(job) == before
	lines = [line for line in (out.out + out.err).splitlines() if f'UNREADABLE: {path}: ' in line]
	assert len(lines) == 1 and lines[0].endswith('; left out of this version'), lines


def test_a_readable_change_beside_a_file_whose_tail_cannot_be_read_commits(job, poll_fast, monkeypatch, capsys):
	# pin: the check's read of b.txt fails (EIO at os.pread), and it goes on to a.txt, a readable change, so the batch commits; b.txt's
	# copy fails as cp fails on a read error, and it keeps its last copy with its UNREADABLE line, once. b.txt leads the batch (checked:
	# the batch is [b.txt, a.txt] for these events), and the stand-in records each read, so the test asserts the check met the
	# unreadable file first and then read the readable one: it fails when the check stops at an unreadable entry (the batch is then
	# dropped to a comparison, which finds a.txt's change: the same version, a second walk), or never reads b.txt
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'b.txt')
	with open(path, 'w') as f:
		f.write('b, longer')
	with open(os.path.join(job.monitor, 'a.txt'), 'w') as f:
		f.write('a changed')
	st = os.lstat(path)
	other = os.lstat(os.path.join(job.monitor, 'a.txt'))
	real_pread = os.pread
	read = []
	def pread(fd, length, offset):
		held = os.fstat(fd)
		if (held.st_dev, held.st_ino) == (st.st_dev, st.st_ino):
			read.append('b.txt')
			raise OSError(errno.EIO, os.strerror(errno.EIO))
		if (held.st_dev, held.st_ino) == (other.st_dev, other.st_ino):
			read.append('a.txt')
		return real_pread(fd, length, offset)
	monkeypatch.setattr(os, 'pread', pread)
	real_check = rv.entries_all_drop_out
	checks = []
	def check(*args, **kwargs):
		checks.append(True)
		return real_check(*args, **kwargs)
	monkeypatch.setattr(rv, 'entries_all_drop_out', check)
	real_command = rv.copy_command
	def copy_command(source_path, dest_path):
		if source_path == path:
			return ['sh', '-c', 'printf "%s\\n" "$1" >&2; exit 1', 'sh', f"cp: error reading '{source_path}': Input/output error", dest_path]
		return real_command(source_path, dest_path)
	monkeypatch.setattr(rv, 'copy_command', copy_command)
	capsys.readouterr()
	_events(job, [(False, 'modify', 'b.txt', None), (False, 'modify', 'a.txt', None)])
	# the check read the unreadable file first, failed it, and went on to the readable one, whose read it stopped at: once, the batch
	# not dropped to a comparison (a check that stops at an unreadable entry says the batch drops out, and do_backup() compares as
	# one with none: the same version, a second walk)
	assert read == ['b.txt', 'a.txt'] and len(checks) == 1
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	with open(os.path.join(versions[-1], 'a.txt')) as f:
		assert f.read() == 'a changed'
	with open(os.path.join(versions[-1], 'b.txt')) as f:
		assert f.read() == 'b'
	seen = capsys.readouterr()
	lines = [line for line in (seen.out + seen.err).splitlines() if f'UNREADABLE: {path}: ' in line]
	assert len(lines) == 1 and lines[0].endswith('; keeping its last backed-up copy'), lines


def _a_version_lacking_the_folder_with_the_files(job, monkeypatch):
	'''
	The state a folder with no row comes from: a batch's copy walk of p/ could not list p/s (EIO), so the newest version holds p/s
	and not p/s/t, whose files are in the monitored tree. Returns the versions before the next batch.
	'''
	from tests.harness import commit_with_a_subfolder_unlisted
	seed_monitor(job, {'a.txt': 'a'})
	_settled(job)
	seed_monitor(job, {'p/s/t/r.txt': 'r', 'p/s/t/u.txt': 'u'})
	versions = commit_with_a_subfolder_unlisted(job, monkeypatch, 'p/', 'p/s')
	assert os.path.isdir(os.path.join(versions[-1], 'p', 's')) and not os.path.lexists(os.path.join(versions[-1], 'p', 's', 't'))
	return versions


@needs_unreadable
def test_an_unreadable_file_under_a_folder_the_version_has_no_row_of_commits_the_folder(job, poll_fast, monkeypatch, capsys):
	# fails on 260f399: a folder's copy walk that could not list p/s (EIO) left p/s/t out of the version, with no row. copy_path() copies
	# it whole for an entry below it, as main does for every batch: the check never asked, dropped a batch of only an unreadable file
	# under it, and the folder's readable file stayed out of the newest version until a readable event under it or the next full
	# comparison
	from tests.harness import event_entry
	before = _a_version_lacking_the_folder_with_the_files(job, monkeypatch)
	path = os.path.join(job.monitor, 'p', 's', 't', 'u.txt')
	os.chmod(path, 0)
	capsys.readouterr()
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'p/s/t/u.txt', 'modify')]))
	manifest.close()
	assert committed is True
	versions = committed_versions(job)
	assert len(versions) == len(before) + 1
	with open(os.path.join(versions[-1], 'p', 's', 't', 'r.txt')) as f:
		assert f.read() == 'r'
	assert _lines(capsys, 'UNREADABLE', path) == 1


@pytest.mark.parametrize('event, copies_the_folder', [('attrib', True), ('modify', False)], ids=['attrib', 'modify'])
def test_a_path_gone_under_a_folder_the_version_has_no_row_of_commits_the_folder_for_an_attrib_only(job, poll_fast, monkeypatch, capsys, event, copies_the_folder):
	# the replay's attrib branch copies an untracked folder whole before it looks at the entry, so an attrib entry whose path is gone,
	# under a folder the newest version lacks, is a change; a create or a modify of a gone path returns at copy_path()'s lexists check,
	# before the folder, and drops out. fails on ea4f8a3 for the attrib (the check looked at the entry first: gone, dropped)
	from tests.harness import event_entry
	before = _a_version_lacking_the_folder_with_the_files(job, monkeypatch)
	os.remove(os.path.join(job.monitor, 'p', 's', 't', 'u.txt'))
	capsys.readouterr()
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'p/s/t/u.txt', event)]))
	manifest.close()
	assert committed is True
	versions = committed_versions(job)
	if copies_the_folder:
		assert len(versions) == len(before) + 1
		with open(os.path.join(versions[-1], 'p', 's', 't', 'r.txt')) as f:
			assert f.read() == 'r'
	else:
		assert versions == before


@needs_unreadable
def test_an_unreadable_file_under_a_folder_the_version_has_a_row_of_still_makes_no_version(job, poll_fast, capsys):
	# pin: the folder is a real folder in the newest version (it has its row), so the check's one lstat of it says so and the entry drops out as before
	from tests.harness import event_entry
	seed_monitor(job, {'a.txt': 'a', 'd/r.txt': 'r', 'd/u.txt': 'u'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'd', 'u.txt')
	with open(path, 'w') as f:
		f.write('u, longer')
	os.chmod(path, 0)
	capsys.readouterr()
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'd/u.txt', 'modify')]))
	manifest.close()
	assert committed is True and committed_versions(job) == before
	assert _lines(capsys, 'UNREADABLE', path) == 1


@needs_unreadable
def test_an_unreadable_file_under_a_folder_over_a_lost_manifest_still_makes_no_version(job, poll_fast, capsys):
	# pin: the attempt's first batch over a lost manifest, the full comparison, lists the tree into the manifest from the newest version
	# (the rows the replay and the check ask), finds u.txt changed and cannot read it: the check drops it, as it does with a manifest that
	# describes the version, so the batch makes no version, with one UNREADABLE line. (Before round 0.55.6 this sent a batch with entries over
	# the lost manifest, a state the daemon never reaches: a batch with entries comes after the attempt's first batch.)
	from tests.test_vault_units import lose_the_manifest
	seed_monitor(job, {'a.txt': 'a', 'd/r.txt': 'r', 'd/u.txt': 'u'})
	before = _settled(job)
	path = os.path.join(job.monitor, 'd', 'u.txt')
	with open(path, 'w') as f:
		f.write('u, longer')
	os.chmod(path, 0)
	lose_the_manifest(job)
	capsys.readouterr()
	_, manifest, committed = _backup(job)
	manifest.close()
	assert committed is True and committed_versions(job) == before
	assert _lines(capsys, 'UNREADABLE', path) == 1


# the folder-metadata healing check (spec section 16, step 1; the user's pick 2026-11-03, "Not an issue, check healing
# (Recommended)"): a folder's own metadata copy fails once, and later versions are read for whether they heal it

# the kernel's POSIX ACL as an extended attribute: version 2, then (tag, permissions, id) per entry. A minimal default ACL,
# user::rwx group::r-x other::r-x, which a folder made in its folder inherits as its own default ACL (and no access ACL)
ACL_DEFAULT = 'system.posix_acl_default'
DEFAULT_ACL = (2).to_bytes(4, 'little') + b''.join(tag.to_bytes(2, 'little') + perm.to_bytes(2, 'little') + (0xFFFFFFFF).to_bytes(4, 'little')
	for tag, perm in ((0x01, 7), (0x04, 5), (0x20, 5)))
# copy_file_meta()'s steps after the owner, in its order: drop_xattrs_missing_from(), then copystat()'s times, extended attributes and
# mode (Python 3.13's order). A step named here is the one the stand-in fails at: everything before it is done
FOLDER_COPY_STEPS = ('drop_missing', 'copy_xattrs', 'before_chmod')


def fail_folder_copy_once(monkeypatch, vault_rel:str, step:str, every:bool = False) -> list:
	'''
	rv.copy_new_folder_meta() and rv.copy_file_meta() replaced so that the first copy onto any version's folder at vault_rel
	(<job vault>/V<n>--<time>/<vault_rel>; never one into staging, on its way into the previous version) runs the real
	copy_file_meta() with its steps after the owner done for real up to step, one of FOLDER_COPY_STEPS, where an EIO stops it:
	copy_file_meta()'s own except then writes its ERROR line and traceback, appends the source to failed and returns False.
	Every later call is the real one; with every, each such copy fails so, a failure that hits every time. Both are replaced, as
	copy_new_folder_meta()'s fast path falls back to copy_file_meta(), which would mend a single failed request at once. Returns
	the list of the destinations it failed, empty until then.
	'''
	assert step in FOLDER_COPY_STEPS
	parts = vault_rel.strip('/').split('/')
	real_new_folder_meta, real_file_meta, real_drop, real_copystat = rv.copy_new_folder_meta, rv.copy_file_meta, rv.drop_xattrs_missing_from, rv.copystat
	failed_at = []

	def first_at_place(dest:str) -> bool:
		held = os.path.normpath(dest).split(os.sep)
		if (failed_at and not every) or len(held) <= len(parts) or held[-len(parts):] != parts or version_number(held[-len(parts) - 1]) is None:
			return False
		failed_at.append(dest)
		return True

	def fail_at(here:str, path:str):
		if here == step:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)

	def drop(source:str, dest:str):
		fail_at('drop_missing', dest)
		real_drop(source, dest)

	def copystat(src:str, dst:str):
		# shutil.copystat() of 3.13 on a folder, step by step, as copy_file_meta() calls it
		st = os.stat(src)
		os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))
		fail_at('copy_xattrs', dst)
		shutil._copyxattr(src, dst)
		fail_at('before_chmod', dst)
		os.chmod(dst, stat.S_IMODE(st.st_mode))

	def failing_copy(source:str, dest:str, failed:list):
		rv.drop_xattrs_missing_from, rv.copystat = drop, copystat
		try:
			return real_file_meta(source, dest, failed)
		finally:
			rv.drop_xattrs_missing_from, rv.copystat = real_drop, real_copystat

	def copy_new_folder_meta(source_folder, backup_folder_path, st, failed=None):
		if first_at_place(backup_folder_path):
			return failing_copy(source_folder, backup_folder_path, failed)
		return real_new_folder_meta(source_folder, backup_folder_path, st, failed)

	def copy_file_meta(source_file, backup_file_path, failed=None):
		if first_at_place(backup_file_path):
			return failing_copy(source_file, backup_file_path, failed)
		return real_file_meta(source_file, backup_file_path, failed)

	monkeypatch.setattr(rv, 'copy_new_folder_meta', copy_new_folder_meta)
	monkeypatch.setattr(rv, 'copy_file_meta', copy_file_meta)
	return failed_at


def _give(path:str, case:str):
	'''The monitored folder at path gets what case names: setgid, the default ACL, or user.note. Skips where the filesystem keeps no such attribute.'''
	try:
		if case == 'setgid':
			os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_ISGID)
		elif case == 'default_acl':
			os.setxattr(path, ACL_DEFAULT, DEFAULT_ACL)
		else:
			os.setxattr(path, 'user.note', b'x')
	except OSError as e:
		if e.errno != errno.ENOTSUP:
			raise
		pytest.skip(f'the basetemp\'s filesystem keeps no {ACL_DEFAULT if case == "default_acl" else "user.*"} attribute: {e}')


def _case_reading(path:str, case:str):
	'''What case reads of the folder at path: whether it has setgid, its default ACL, or its user.note (None for none).'''
	if case == 'setgid':
		return bool(os.lstat(path).st_mode & stat.S_ISGID)
	try:
		return os.getxattr(path, ACL_DEFAULT if case == 'default_acl' else 'user.note', follow_symlinks=False)
	except OSError as e:
		if e.errno != errno.ENODATA:
			raise
		return None


def healed_at(job, versions:list, steps:list, case:str, monitored:str, rel:str):
	'''
	The step in steps (one name per version in versions, the failing version first) of the first version from which the folder at
	rel, read through its daemon links, reads as the monitored folder does what case reads, and every later version reads so too:
	'failing' when the failing version already does (its failure left nothing to heal), None when the last one does not. Also
	returns each version's reading.
	'''
	want = _case_reading(monitored, case)
	reads = [_case_reading(os.path.join(job.job_vault, *landing(job.job_vault, os.path.basename(version), rel)), case) for version in versions]
	return next((step for i, step in enumerate(steps) if all(read == want for read in reads[i:])), None), reads


CASES = {
	# P setgid, C without (uid 65534 sets both on its own folders); the copy fails before its chmod. At settle C keeps the bit it
	# inherited from the vault's P (at first_version it inherits none, and at attrib the bit is the one the test's _give() gave the
	# monitored C before the batch that reports its attrib, which the vault's C lacks). Kept only when two attempts fail: a folder with no extended attributes on either side is copied
	# first by copy_new_folder_meta()'s fast path (a request each for the owner, mode and times), and one failed request there falls
	# back to copy_file_meta(), which mends it in the same batch with no ERROR line. fail_folder_copy_once() fails both on purpose, as
	# a chmod that keeps failing does. (V0's walk copies each folder with copy_file_meta() itself: no fast path at first_version)
	'setgid': 'before_chmod',
	# P with a default ACL (system.posix_acl_default, an ACL blob written by os.setxattr), C without; the removal step fails. The
	# single-failure case: at settle the vault's C holds the inherited ACL and at attrib the monitored C has one, so
	# copy_new_folder_meta() sends the copy straight to copy_file_meta(), which has no fallback (V0's walk calls it itself). The
	# removal is real only at settle: at first_version and attrib the vault's C has no extended attributes at that step, so the real
	# drop_xattrs_missing_from() lists the destination's attributes (xattr_names(dest), a listxattr) and returns before any removal.
	# The stand-in fails before that listing. An EIO from the listing is a real failure at this step at first_version and attrib, and
	# leaves the state the stand-in does (the pins stand with more reason): no times, no extended attributes and no mode copied, as a
	# real failure at the next step, the first of copystat(), leaves it too
	'default_acl': 'drop_missing',
	# C with user.note = b'x'; copystat()'s attribute step fails, after the times. The single-failure case: the monitored C has an
	# attribute, so copy_new_folder_meta() sends the copy straight to copy_file_meta(), which has no fallback (V0's walk calls it
	# itself). Its chmod is not done either, so a C that is new keeps the mode mkdir gave it in the vault (0755 under umask 022, which
	# umask_022 sets), and its row records that mode: the monitored C, made under the same umask, has the same one, which the test
	# asserts
	'own_xattr': 'copy_xattrs',
	# the same with the monitored C at mode 0775, which differs from the vault's new C and from its row: the next full comparison
	# finds that by the mode, wherever it comes. At attrib, V0 copied the mode (C was right), so this case is as own_xattr there
	'own_xattr_0775': 'copy_xattrs',
}
# step 1's three places: V0's walk, and settle() of a folder a batch made (mkdir C), where the vault's C is new; at V0 it inherits
# nothing from P, whatever P has (V0's walk makes every folder with os.makedirs() before it copies any folder's metadata, so the
# vault's P has nothing to give yet), and at settle() it inherits what the vault's P has (V0 copied P's metadata); and a batch's attrib
# of C, where C is right in the vault and the test gives the monitored C what the case names (_give(): chmod g+s, a default ACL,
# user.note) before the batch that reports it, which settle() copies too
PLACES = ['first_version', 'settle', 'attrib']
# What comes between the failing version and the full comparison, and whether the full comparison's attribute check reaches C. That
# check compares the extended attributes of the entries whose ctime is not before the matched time less VERIFY_CTIME_MARGIN_SECONDS
# (10 s: full_comparison_since(), ctime_bound()). A commit records a matched time when no inner mount was paused, nothing was logged
# unreadable, every metadata copy synced (so the failing version never does) and there is a time to record (the read time of a
# batch, which is none while a folder is unwatched, or the start of a full comparison). Any other commit leaves the older time, and with none recorded the bound starts at a version's folder time, which holds
# whole seconds. So the commits between decide, never how late the full comparison itself runs. The test differs from the daemon in
# where a matched time comes from: its _full() and _backup() pass no matched_since, so a full comparison records none (record_matched()
# writes nothing with no time and none to carry over), and a batch of backup_events() is stamped with the time of the call
# no_batch: the full comparison is the commit right after the failing version, which no batch comes between. Nothing is matched in
# the test, so its bound comes from full_comparison_since()'s fallback, V0's folder time: V0's start in whole seconds. At settle and
# attrib that is the same instant as the daemon's matched time (the start of V0's full comparison, which the failing version's commit
# carries over) to within a second; at the first version V0 is the failing version, which records none, so the daemon's bound comes
# from the same fallback. At settle and attrib C's last change came after V0's start, so the bound reaches C however late the full
# comparison runs; at the first version V0 is the failing version, and its folder time is within a second of C's last change (it can
# fall just before it)
# no_batch_old_folder: the same at the first version, with C's last change more than the margin before V0's folder time (a folder that
# was there long before the first backup). The margin is -1 for the full comparison, which puts the bound after C's ctime (0 would
# leave a C made in the same whole second as the folder's name after it). Not at settle or attrib: C changed after V0's start there,
# so no time passing puts it before the bound
# next_commit: a batch elsewhere, then a batch that writes into C (the file moves C's ctime and mtime), then the full comparison as
# the next commit. backup_events() stamps the batch into C with the time of the call, milliseconds after C's last change, so the
# bound reaches C. In the daemon a batch's matched time is its watcher read time, and next_commit holds only where that is within the
# margin of C's last change: a minimum interval under about 10 s (blank or none is 0), a take at the maximum interval of a tree
# never quiet that long, or a late take by a busy backuper (the watcher goes on restamping while the batch waits). At the sample
# rule's 60 s (auto is 60 too) it does not occur for a batch taken at the quiet signal: the watcher signals a batch after the
# minimum interval of quiet and restamps its read time at every empty read, so such a batch into C carries a read time about 57 s
# or more after C's last change (the interval less the watcher's read wait, 3 s by default), and the bound misses C: the
# next_commit cells are then after_another_batch's. From about 13 s up (the margin and the read wait) the minimum interval alone
# cannot produce next_commit
# after_another_batch: next_commit's sequence with the margin 0 for the full comparison, which puts the bound at the matched time of
# the batch into C, past C's ctime. The margin 0 stands for a batch whose read time is more than the margin after C's last change: in
# the daemon at 60 s any batch taken at the quiet signal, the batch into C included (see next_commit). A real 11 s wait and
# one more batch after the one into C, with the margin left at 10, gave the same cells
TIMINGS = {'no_batch': (False, None), 'no_batch_old_folder': (False, -1), 'next_commit': (True, None), 'after_another_batch': (True, 0)}
PLACE_TIMINGS = [(place, timing) for place in PLACES for timing in ('no_batch', 'next_commit', 'after_another_batch')] + [('first_version', 'no_batch_old_folder')]
# the cells main 0.55.5 left wrong (None there): its full comparison found no difference in C. Since step 2 (spec section 16; the
# user's answer to Q7, 2026-11-17, "Build the retry (Recommended)") C's row holds a mark from the failing version's commit on
# (META_RETRY_MODE), which the batches between keep (the batch into C gives C its times only), so they heal at the full comparison
# (HEALS), and at the next batch that compares C (test_a_folder_whose_copy_failed_heals_at_the_next_batch_comparing_it)
LEFT_WRONG_ON_MAIN = [('default_acl', 'settle', 'after_another_batch'), ('default_acl', 'attrib', 'after_another_batch'),
	('own_xattr', 'first_version', 'no_batch_old_folder'), ('own_xattr', 'first_version', 'after_another_batch'),
	('own_xattr', 'settle', 'after_another_batch'), ('own_xattr', 'attrib', 'after_another_batch'), ('own_xattr_0775', 'attrib', 'after_another_batch')]
# (case, place, timing): the step of the first version that holds C as the monitored C is, from which every later one does:
# 'failing' when the failing version already does, 'elsewhere' (after a batch that does not touch C), 'into_c' (after a batch that
# touches C), 'full' (after the full comparison), None when the last one does not
HEALS = {
	# main 0.55.5: nothing to heal, at any timing: V0's walk makes every folder before it copies any folder's metadata, so the vault's C
	# inherits nothing from P and reads as the monitored C does
	('setgid', 'first_version', 'no_batch'): 'failing',
	('setgid', 'first_version', 'no_batch_old_folder'): 'failing',
	('setgid', 'first_version', 'next_commit'): 'failing',
	('setgid', 'first_version', 'after_another_batch'): 'failing',
	# main 0.55.5: heals at the full comparison, at any timing, by C's mode against its record (the failed copy stopped before its
	# chmod, both attempts of it: see CASES)
	('setgid', 'settle', 'no_batch'): 'full',
	('setgid', 'settle', 'next_commit'): 'full',
	('setgid', 'settle', 'after_another_batch'): 'full',
	('setgid', 'attrib', 'no_batch'): 'full',
	('setgid', 'attrib', 'next_commit'): 'full',
	('setgid', 'attrib', 'after_another_batch'): 'full',
	# main 0.55.5: nothing to heal, at any timing, as for setgid
	('default_acl', 'first_version', 'no_batch'): 'failing',
	('default_acl', 'first_version', 'no_batch_old_folder'): 'failing',
	('default_acl', 'first_version', 'next_commit'): 'failing',
	('default_acl', 'first_version', 'after_another_batch'): 'failing',
	# main 0.55.5: heals at the full comparison, by C's mtime against its record while no batch has written into C (the failed
	# removal stopped the times too: the vault's C has its mkdir time), and by the attribute check while it reaches C
	('default_acl', 'settle', 'no_batch'): 'full',
	('default_acl', 'settle', 'next_commit'): 'full',
	# main 0.55.5: None, it did not heal after another batch: the batch that wrote into C gave it its times and recorded them, so C's
	# record no longer differed, and the attribute check no longer reached C. It healed by C's mode where that was not the 0755 the ACL
	# gave the vault's C (probed with 0700, 0750, 0775 and 0777, not pinned). Since step 2: at the full comparison, by the mark
	('default_acl', 'settle', 'after_another_batch'): 'full',
	# main 0.55.5: heals at the full comparison by the attribute check, which reaches C (its record never differed: an extended
	# attribute moves no mtime, and the failed copy stopped before it changed anything of C)
	('default_acl', 'attrib', 'no_batch'): 'full',
	('default_acl', 'attrib', 'next_commit'): 'full',
	# main 0.55.5: None, it did not heal after another batch: the attribute check no longer reached C, and its record never differed.
	# Since step 2: at the full comparison, by the mark
	('default_acl', 'attrib', 'after_another_batch'): 'full',
	# main 0.55.5: heals at the full comparison by the attribute check, which reaches C: the bound (the first version's folder time, or
	# the matched time of the batch into C, less the margin) is not after C's last change here. This is the only way it heals, with the
	# monitored C at the mode mkdir gave the vault's C (0755): see own_xattr_0775
	('own_xattr', 'first_version', 'no_batch'): 'full',
	('own_xattr', 'first_version', 'next_commit'): 'full',
	# main 0.55.5: None, it did not heal where the attribute check did not reach C (C last changed more than the margin before the first
	# version's folder time, or the matched time of a batch more than the margin after C's last change: the margin 0): C's record
	# matched the monitored C's, as the times were copied before the failing step and the mode is the 0755 mkdir gave both (at another
	# mode it healed, by the mode: own_xattr_0775). Since step 2: at the full comparison, by the mark
	('own_xattr', 'first_version', 'no_batch_old_folder'): 'full',
	('own_xattr', 'first_version', 'after_another_batch'): 'full',
	# main 0.55.5: heals at the full comparison by the attribute check, which reaches C: C changed after V0's start, so after the bound
	# of no_batch (V0's folder time less the margin), and the matched time of the batch that wrote into C (next_commit) is within the
	# margin of its ctime. The mode condition is as at the first version
	('own_xattr', 'settle', 'no_batch'): 'full',
	('own_xattr', 'settle', 'next_commit'): 'full',
	# main 0.55.5: None, it did not heal after another batch: C's record matched the monitored C's, as at the first version. Since
	# step 2: at the full comparison, by the mark
	('own_xattr', 'settle', 'after_another_batch'): 'full',
	# main 0.55.5: heals at the full comparison by the attribute check, which reaches C (the monitored C's attribute changed after V0's
	# start, so after the bound of no_batch, V0's folder time less the margin; for next_commit, the matched time of the batch into C is
	# within the margin of C's ctime)
	('own_xattr', 'attrib', 'no_batch'): 'full',
	('own_xattr', 'attrib', 'next_commit'): 'full',
	# main 0.55.5: None, it did not heal after another batch: C's record matched the monitored C's (V0 copied the mode and the times).
	# Since step 2: at the full comparison, by the mark
	('own_xattr', 'attrib', 'after_another_batch'): 'full',
	# main 0.55.5: heals at the full comparison, at any timing, by C's mode against its record: the failed copy stopped before its
	# chmod, so the vault's C (new here) keeps the 0755 mkdir gave it, and the monitored C is 0775
	('own_xattr_0775', 'first_version', 'no_batch'): 'full',
	('own_xattr_0775', 'first_version', 'no_batch_old_folder'): 'full',
	('own_xattr_0775', 'first_version', 'next_commit'): 'full',
	('own_xattr_0775', 'first_version', 'after_another_batch'): 'full',
	('own_xattr_0775', 'settle', 'no_batch'): 'full',
	('own_xattr_0775', 'settle', 'next_commit'): 'full',
	('own_xattr_0775', 'settle', 'after_another_batch'): 'full',
	# main 0.55.5: as own_xattr at attrib: V0 copied the 0775 (C was right), so the full comparison healed it only by the attribute
	# check, and after another batch not at all (None). Since step 2 that cell heals at the full comparison too, by the mark
	('own_xattr_0775', 'attrib', 'no_batch'): 'full',
	('own_xattr_0775', 'attrib', 'next_commit'): 'full',
	('own_xattr_0775', 'attrib', 'after_another_batch'): 'full',
}


@pytest.fixture
def umask_022():
	'''
	The process's umask 022 for the test, the old one back after it. Listed before job, so it holds when anything is made: the
	monitored C and the daemon's vault C (made in this process, by do_backup) then get the same mode from mkdir whoever runs the test.
	'''
	old = os.umask(0o022)
	try:
		yield
	finally:
		os.umask(old)


def _failing_version(job, monkeypatch, case:str, place:str, every:bool = False) -> tuple:
	'''
	The healing check's failing version: the monitored P and P/C as case (CASES) names them, and C's own metadata copy failing at
	place (PLACES) through fail_folder_copy_once() (every: at each copy onto C in a version, not only the first). Returns (P, C, the
	stand-in's list of the destinations it failed, the failing version's index in committed_versions()).
	'''
	own = case.startswith('own_xattr')
	parent, folder = os.path.join(job.monitor, 'P'), os.path.join(job.monitor, 'P', 'C')
	seed_monitor(job, {'a.txt': 'a'})
	os.mkdir(parent)
	if not own:
		_give(parent, case)
		# the kernel keeps setgid only for a chmod by the folder's group: P must have what the case names
		assert _case_reading(parent, case)

	def make_folder():
		# made in P, so it inherits what P has; then without it, as the case's C is
		os.mkdir(folder)
		if not own:
			assert _case_reading(folder, case), 'C did not inherit from P what the case names'
		if case == 'setgid':
			os.chmod(folder, stat.S_IMODE(os.lstat(folder).st_mode) & ~stat.S_ISGID)
		elif case == 'default_acl':
			os.removexattr(folder, ACL_DEFAULT)
		elif case == 'own_xattr_0775':
			os.chmod(folder, 0o775)
		assert _case_reading(folder, case) in (False, None)
		if own:
			# the mode mkdir gives a folder under the umask the fixture sets (022), the same in the vault, unless the case sets another
			assert stat.S_IMODE(os.lstat(folder).st_mode) == (0o775 if case == 'own_xattr_0775' else 0o755)
			if place != 'attrib':
				_give(folder, case)

	if place == 'first_version':
		make_folder()
		failed_at = fail_folder_copy_once(monkeypatch, 'P/C', CASES[case], every)
		assert _full(job) is True
	elif place == 'settle':
		assert _full(job) is True
		make_folder()
		failed_at = fail_folder_copy_once(monkeypatch, 'P/C', CASES[case], every)
		_events(job, [(True, 'create', 'P/C', None)])
	else:
		make_folder()
		assert _full(job) is True
		_give(folder, case)
		failed_at = fail_folder_copy_once(monkeypatch, 'P/C', CASES[case], every)
		_events(job, [(True, 'attrib', 'P/C', None)])
	failing = len(committed_versions(job)) - 1
	# the stand-in failed C's copy in the failing version, once
	assert [os.path.dirname(os.path.dirname(os.path.normpath(dest))) for dest in failed_at] == [committed_versions(job)[failing]]
	return parent, folder, failed_at, failing


def _read_in(job, version:str, rel:str, case:str):
	'''What case reads of the folder at rel in the committed version folder version, through its daemon links.'''
	return _case_reading(os.path.join(job.job_vault, *landing(job.job_vault, os.path.basename(version), rel)), case)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('place, timing', PLACE_TIMINGS)
def test_a_folder_metadata_copy_that_failed_once(umask_022, job, poll_fast, monkeypatch, capsys, case, place, timing):
	# fails on main for the seven cells of LEFT_WRONG_ON_MAIN, which main 0.55.5 left wrong and step 2's mark heals at the full
	# comparison; every other cell pins main's answer to the healing check (spec section 16, step 1). The failing version, then (by
	# timing) a batch that does not touch C (a file elsewhere) and a batch that touches C (a file in it), and a full comparison (with a
	# file changed elsewhere, so it commits a version whatever it finds of C): C's setgid bit, its system.posix_acl_default, or its
	# user.note, read in each version through its daemon links
	batches, margin = TIMINGS[timing]
	parent, folder, failed_at, failing = _failing_version(job, monkeypatch, case, place)
	steps = ['failing']
	if batches:
		steps += ['elsewhere', 'into_c']
		seed_monitor(job, {'elsewhere.txt': 'e'})
		_events(job, [(False, 'create', 'elsewhere.txt', None)])
		seed_monitor(job, {'P/C/f.txt': 'f'})
		_events(job, [(False, 'create', 'P/C/f.txt', None)])
	steps.append('full')
	seed_monitor(job, {'a.txt': 'a, changed'})
	if margin is not None:
		monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', margin)
	assert _full(job) is True
	versions = committed_versions(job)[failing:]
	assert len(versions) == len(steps)
	out = capsys.readouterr()
	assert (out.out + out.err).count('Failed to copy metadata ') == 1
	heals, reads = healed_at(job, versions, steps, case, folder, 'P/C')
	assert heals == HEALS[(case, place, timing)], f'{case} at {place}, {timing}: heals at {heals}; the versions read {reads}, the monitored C {_case_reading(folder, case)!r}'


@pytest.mark.parametrize('case, place', sorted({(case, place) for case, place, _ in LEFT_WRONG_ON_MAIN}))
def test_a_folder_whose_copy_failed_heals_at_the_next_batch_comparing_it(umask_022, job, poll_fast, monkeypatch, capsys, case, place):
	# fails on main, at the mark assert first (`assert [] == ['P/C/']`: main marks no row), and without it at the assert on Q/C's
	# reading (the batch left C as the failing version held it): the batch that renames P to Q compares the tree under Q (its
	# verification, compare_scopes()), C's record there matches the monitored C's, and the attribute check does not reach C, so the
	# newest version keeps C as the failing one left it. Since step 2 C's row holds the mark (it moved with C:
	# VaultManifest.move_tree()), and the batch copies C's metadata again. The batch is stamped now, as the watcher stamps one
	# (backup_events() stamps its events at a monotonic 1.0 s, near the boot, which would put every ctime in the window), and
	# VERIFY_CTIME_MARGIN_SECONDS is 0, as for after_another_batch: C's last change came more than the margin before the batch
	parent, folder, failed_at, failing = _failing_version(job, monkeypatch, case, place)
	failed = _read_in(job, committed_versions(job)[failing], 'P/C', case)
	assert failed != _case_reading(folder, case), 'the failing version holds C right: nothing to heal'
	assert _marked_rows(job) == ['P/C/']
	moved = os.path.join(job.monitor, 'Q')
	os.rename(parent, moved)
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', 0)
	raw = deque([rv.ChangeEvent(time.monotonic(), True, 'move', moved, parent)])
	_, manifest, committed = rv.do_backup(rv.change_events_to_backup_entries(deque(raw), job.monitor), job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, touched=rv.touched_scopes(raw, job.monitor), matched_since=time.time_ns(), **KEPT)
	manifest.close()
	assert committed is True and len(committed_versions(job)) == failing + 2
	want = _case_reading(os.path.join(moved, 'C'), case)
	assert _read_in(job, committed_versions(job)[-1], 'Q/C', case) == want, f'{case} at {place}: the batch comparing C left it {failed!r}, the monitored C {want!r}'
	out = capsys.readouterr()
	assert (out.out + out.err).count('Failed to copy metadata ') == 1


def _marked_rows(job) -> list:
	'''The rels of the manifest rows whose mode is no entry's (below 0): the mark of a folder whose metadata is to be copied again.'''
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return [rv.stored_name(path) for (path,) in manifest.conn.execute('SELECT path FROM entries WHERE mode < 0 ORDER BY path')]
	finally:
		manifest.close()


@pytest.mark.parametrize('place', PLACES)
def test_a_folder_copy_that_fails_every_time_is_tried_once_more_and_then_left(umask_022, job, poll_fast, monkeypatch, capsys, place):
	# fails on main, at the mark assert first (`assert [] == ['P/C/']`: main marks no row), and would fail at the count of versions
	# without it: no comparison meets C again (its record matches the monitored C's, and the attribute check misses it), so its
	# copy is never tried again: no version follows the failing one. Since step 2 the full comparison after the failing version finds
	# C by its mark and tries the copy once more, which fails again: one more version, which changes nothing of C, its row recorded from
	# that version with no mark; the next full comparison finds nothing. The stand-in fails every copy onto C, at copystat()'s attribute
	# step (own_xattr), with its ERROR line and traceback each time. VERIFY_CTIME_MARGIN_SECONDS at -3600 puts each full comparison's
	# bound an hour past the version it starts from, so the attribute check reaches no entry, as for a folder last changed more than
	# the margin before the matched time (after_another_batch, no_batch_old_folder): only the mark can find C
	parent, folder, failed_at, failing = _failing_version(job, monkeypatch, 'own_xattr', place, every=True)
	# the failing version's commit marked C's row, which the row oracle passes over (its mode alone)
	assert _marked_rows(job) == ['P/C/']
	assert rows_match_vault(job.job_vault) == []
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', -3600)
	assert _full(job) is True
	versions = committed_versions(job)
	assert len(versions) == failing + 2, 'the full comparison after the failing version made no version: C was not tried again'
	assert [os.path.dirname(os.path.dirname(os.path.normpath(dest))) for dest in failed_at] == versions[failing:]
	assert _marked_rows(job) == []
	assert _full(job) is True
	assert committed_versions(job) == versions, 'a failure every time was tried more than once more'
	assert len(failed_at) == 2
	assert _read_in(job, versions[-1], 'P/C', 'own_xattr') is None
	out = capsys.readouterr()
	text = out.out + out.err
	assert text.count('Failed to copy metadata ') == 2
	assert text.count('Traceback (most recent call last)') == 2


def test_a_folder_whose_copy_works_keeps_its_record(job, poll_fast):
	# pin: no row holds the mark after normal batches: a first version, a batch that makes a folder, changes another's mode and
	# renames a third, and a full comparison, all of whose copies work. Every row's record describes the version (rows_match_vault()),
	# and the full comparison finds nothing to back up
	seed_monitor(job, {'a.txt': 'a', 'P/C/f.txt': 'f', 'P/D/g.txt': 'g', 'P/E/h.txt': 'h'})
	_give(os.path.join(job.monitor, 'P', 'C'), 'own_xattr')
	assert _full(job) is True
	os.mkdir(os.path.join(job.monitor, 'N'))
	os.chmod(os.path.join(job.monitor, 'P', 'D'), 0o750)
	os.rename(os.path.join(job.monitor, 'P', 'E'), os.path.join(job.monitor, 'F'))
	_events(job, [(True, 'create', 'N', None), (True, 'attrib', 'P/D', None), (True, 'move', 'F', 'P/E')])
	versions = committed_versions(job)
	assert len(versions) == 2
	assert _full(job) is True
	assert committed_versions(job) == versions
	assert _marked_rows(job) == []
	assert rows_match_vault(job.job_vault) == []


def test_a_roll_forward_keeps_a_folders_mark(tmp_path):
	# the rows of a cut batch's tree (read_rows_from_tree(), a roll-forward) keep a folder row's mark, so the roll-forward's comparison
	# copies the folder's metadata again: its mtime, owner and group are read from the tree as any folder's, its mode stays the mark. A
	# marked folder the tree holds a file in place of loses its record, as any row of another kind; a row with no record is not marked
	tree, vault = str(tmp_path / 'tree'), str(tmp_path / 'vault')
	for rel in ('C', 'G', 'U'):
		os.makedirs(os.path.join(tree, rel))
	os.makedirs(vault)
	manifest = rv.VaultManifest(vault)
	try:
		manifest.begin()
		for rel in ('C/', 'G/'):
			manifest.add(rel, dirty=True)
		manifest.add('U/')
		rv.record_dirty_entries(manifest, tree)
		manifest.mark_meta_retry(['C/', 'G/', 'U/', 'X/'])
		assert [manifest.lookup(rel).mode for rel in ('C/', 'G/')] == [rv.META_RETRY_MODE] * 2
		assert manifest.lookup('U/').kind is None and manifest.lookup('U/').mode is None and manifest.lookup('X/') is None
		st = os.lstat(os.path.join(tree, 'C'))
		os.utime(os.path.join(tree, 'C'), ns=(st.st_atime_ns, st.st_mtime_ns - 10 ** 9))
		os.rmdir(os.path.join(tree, 'G'))
		open(os.path.join(tree, 'G'), 'w').close()
		rv.read_rows_from_tree(manifest, tree)
		assert manifest.lookup('C/') == rv.ManifestRecord('d', None, st.st_mtime_ns - 10 ** 9, rv.META_RETRY_MODE, st.st_uid, st.st_gid, None, None, 0)
		assert manifest.lookup('G/').kind is None
	finally:
		manifest.close()


@pytest.mark.parametrize('place', ['file', 'link'])
def test_a_folder_attrib_refused_where_the_version_holds_no_folder_is_not_marked(job, poll_fast, monkeypatch, capsys, place):
	# fails before the fix wave's FW1 (the final review's s09 (1), a regression of Task 18): the replay refuses a folder's attrib where the
	# version holds a file or a link at the folder's place (an outside change to the vault), copying nothing, and the commit marked the
	# folder's row for a retry all the same (META_RETRY_MODE): every full comparison after it found an attrib there, refused it again with
	# its ERROR line and committed a version that changed nothing (Keep N then pushes a real version out). Only a folder whose own metadata
	# copy was tried and failed is marked now. The attrib is the monitored C's user.note alone, which moves no mode, owner or mtime, so
	# its record still matches the monitored C; VERIFY_CTIME_MARGIN_SECONDS at -3600 keeps the full comparison's attribute check off every
	# entry, as for a folder last changed more than the margin before the matched time: only a mark can find C there
	seed_monitor(job, {'a.txt': 'a', 'P/C/f.txt': 'f'})
	assert _full(job) is True
	folder = os.path.join(job.monitor, 'P', 'C')
	held = os.path.join(committed_versions(job)[-1], 'P', 'C')
	shutil.rmtree(held)
	if place == 'file':
		open(held, 'w').close()
	else:
		os.symlink('nowhere', held)
	_give(folder, 'own_xattr')
	capsys.readouterr()
	_events(job, [(True, 'attrib', 'P/C', None)])
	out = capsys.readouterr()
	assert f'Not syncing the attributes of {folder}/ onto ' in out.out + out.err
	versions = committed_versions(job)
	assert _marked_rows(job) == []
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', -3600)
	_full(job)
	assert committed_versions(job) == versions, 'the full comparison found the refused folder again and made a version that changes nothing'
	# the change lists name the sizes of what the rows hold, C/f.txt among them, which the outside change took out of the vault: the
	# version view oracle's lines on that (and only those) are this test's own, looked at and taken out
	from tests import version_view_ground_truth as view_truth
	assert all('its list should be' in line for line in view_truth.WRONG), view_truth.WRONG
	view_truth.WRONG.clear()
