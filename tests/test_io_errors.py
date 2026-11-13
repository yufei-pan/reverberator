import errno
import os
import shutil
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


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
	path = os.path.join(job.monitor, 'disk', 'b.txt')
	open(path, 'w').write('b, longer')
	os.chmod(path, 0)
	compared = []
	real = rv.compare_scopes
	def compare_scopes(found, manifest, version_path, monitor_path, scopes, *args, **kwargs):
		compared.append((list(scopes.subtrees), list(scopes.paths)))
		return real(found, manifest, version_path, monitor_path, scopes, *args, **kwargs)
	monkeypatch.setattr(rv, 'compare_scopes', compare_scopes)
	queue, lock = rv.ChangeEventQueue(job.monitor), threading.Lock()
	queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	capsys.readouterr()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', threading.Event()),
		kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
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


def test_an_untracked_delete_over_a_lost_manifest_makes_no_version(job, poll_fast):
	# fails on main: the drop of deletes the vault does not track needs a manifest that describes the newest version, and the
	# batch commits a version that changes nothing
	from tests.harness import event_entry
	from tests.test_vault_units import lose_the_manifest
	seed_monitor(job, {'a.txt': 'a'})
	before = _settled(job)
	lose_the_manifest(job)
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'never-backed-up.txt', 'delete')]))
	manifest.close()
	assert committed is True and committed_versions(job) == before


def test_a_tracked_delete_over_a_lost_manifest_is_still_removed(job, poll_fast):
	# pin: with the manifest lost the drop of deletes asks the newest version, which holds the file, so the delete is a change
	from tests.harness import event_entry
	from tests.test_vault_units import lose_the_manifest
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	before = _settled(job)
	lose_the_manifest(job)
	os.remove(os.path.join(job.monitor, 'b.txt'))
	_, manifest, committed = _backup(job, OrderedDict([event_entry(job, 'b.txt', 'delete')]))
	manifest.close()
	versions = committed_versions(job)
	assert committed is True and len(versions) == len(before) + 1
	assert not os.path.lexists(os.path.join(versions[-1], 'b.txt')) and os.path.lexists(os.path.join(before[-1], 'b.txt'))


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
