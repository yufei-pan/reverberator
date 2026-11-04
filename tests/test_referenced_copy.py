'''
do_referenced_copy() looks at the previous version, and makes the folders and links, on a few threads (round 14). Its results stay those of the per-entry version it replaced, kept here as the oracle: the same
links and folders, the same rows dropped with the same lines in the same order, unsynced filled the same way, and a
stop or a dropped disk still stops it.
'''
import errno
import os
import re
import shutil
import stat
import threading
import pytest
import reverberator as rv
from tests.harness import write_committed_version, tracked_manifest

pytestmark = pytest.mark.unit

V1 = 'V1--2021-01-02_00-00-00_-0800'


def oracle_referenced_copy(source_path, backup_folder, manifest, relative=False, pool_guard=None, unsynced=None):
	'''do_referenced_copy() as 0781f67 had it, one lstat and one call per entry, on the calling thread.'''
	def source_entry(path, kind, rel):
		try:
			return os.lstat(path)
		except (FileNotFoundError, NotADirectoryError):
			return None
		except OSError as e:
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Cannot look at tracked {kind} {rel} in {source_path}, keeping it: {e}')
			return False
	rv.backuperTeeLogToTl(path=source_path,message=f'Creating a referenced copy of {source_path} to {backup_folder}')
	missing = []
	for folder in manifest.iter_folders():
		source_folder = os.path.join(source_path,folder)
		backup_folder_path = os.path.join(backup_folder,folder)
		if not rv.is_entry_rel(folder):
			rv.backuperTeeLogToTl(path=source_path,warning=True,message=f'Dropping a tracked row that names no folder below the version: {folder!r}')
			missing.append(folder)
			continue
		st = source_entry(source_folder.rstrip('/'), 'folder', folder)
		if st is None:
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked folder missing from {source_path}: {folder}')
			missing.append(folder)
			continue
		if st and not stat.S_ISDIR(st.st_mode):
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked folder {folder}: {source_folder.rstrip("/")} is no folder')
			missing.append(folder)
			continue
		os.makedirs(backup_folder_path,exist_ok=True)
		rv.copy_file_meta(source_folder,backup_folder_path,unsynced)
		if pool_guard is not None:
			pool_guard.poll()
		if not rv.GREEN_LIGHT.is_set():
			rv.backuperTeeLogToTl(path=source_path,error=True,message='Backup process interrupted, stopping')
			return False
	for file in manifest.iter_files():
		source_file_real = os.path.join(source_path,file)
		backup_file_path = os.path.join(backup_folder,file)
		if not rv.is_entry_rel(file):
			rv.backuperTeeLogToTl(path=source_path,warning=True,message=f'Dropping a tracked row that names no file below the version: {file!r}')
			missing.append(file)
			continue
		st = source_entry(source_file_real, 'file', file)
		if st is None:
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked file missing from {source_path}: {file}')
			missing.append(file)
			continue
		if st and stat.S_ISDIR(st.st_mode):
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked file {file}: it is a folder in {source_path}')
			missing.append(file)
			continue
		if relative:
			source_file = os.path.relpath(source_file_real,os.path.dirname(backup_file_path))
		else:
			source_file = os.path.abspath(source_file_real)
		try:
			os.symlink(source_file, backup_file_path)
		except FileExistsError:
			rv.backuperTeeLogToTl(path=source_path,error=True,message=f'Dropping tracked file {file}: {backup_file_path} is taken in the new version')
			missing.append(file)
			continue
		except FileNotFoundError:
			parent = os.path.dirname(backup_file_path)
			if not os.path.lexists(parent):
				rv.backuperTeeLogToTl(path=source_path,warning=True,message=f'Making {parent}, which no row tracks, for the tracked {file}')
			os.makedirs(parent, exist_ok=True)
			os.symlink(source_file, backup_file_path)
		if pool_guard is not None:
			pool_guard.poll()
		if not rv.GREEN_LIGHT.is_set():
			rv.backuperTeeLogToTl(path=source_path,error=True,message='Backup process interrupted, stopping')
			return False
	manifest.discard_many(missing)
	return True


@pytest.fixture
def small_chunks(monkeypatch):
	# many chunks, and a short window, on a small tree
	monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', 3)
	monkeypatch.setattr(rv, 'REFERENCED_COPY_WINDOW', 2)


@pytest.fixture
def logged(monkeypatch):
	'''Every line the backuper logs, as (kind, message).'''
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		kind = 'error' if kwargs.get('error') else 'warning' if kwargs.get('warning') else 'info'
		lines.append((kind, str(message)))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def tree_of(root):
	'''{rel: 'folder' | ('link', text) | 'file'} of everything under root.'''
	found = {}
	for folder, folders, files in os.walk(root):
		for name in folders + files:
			path = os.path.join(folder, name)
			rel = os.path.relpath(path, root)
			if os.path.islink(path):
				found[rel] = ('link', os.readlink(path))
			elif os.path.isdir(path):
				found[rel] = 'folder'
			else:
				found[rel] = 'file'
	return found


# file rows a test adds to edge_version()'s
extra = []


@pytest.fixture(autouse=True)
def no_extra():
	yield
	del extra[:]


def edge_version(job):
	'''A V0 with rows for every case the copy tells apart: (v0, folder rows, file rows).'''
	tree = {f'many/{i:03d}': str(i) for i in range(60)}
	tree.update({
		'd/x': 'x', 'd/inner': 'i', 'd/sub/y': 'y', 'f_is_file': 'f', 'dir_is_folder/z': 'z', 'bare/sub/w': 'w',
		'top.txt': 't', 'bad\udcff/n\udcfe': 'b', 'deep/a/b/c/e': 'e',
	})
	v0 = write_committed_version(job, 0, tree)
	os.symlink('d', os.path.join(v0, 'lnk'))
	folders = ['d/', 'd/sub/', 'many/', 'gone/', 'gone/deeper/', 'f_is_file/', 'lnk/', 'dir_is_folder/', 'bad\udcff/',
		'deep/', 'deep/a/', 'deep/a/b/', 'deep/a/b/c/']
	files = [f'many/{i:03d}' for i in range(60)] + [f'many/{i:03d}x' for i in range(0, 60, 7)] + [
		'd/x', 'd/inner', 'd/sub/y', 'ghost', 'gone/deeper/q', 'f_is_file', 'dir_is_folder', 'dir_is_folder/z', 'lnk',
		'lnk/inner', 'bare/sub/w', 'top.txt', 'bad\udcff/n\udcfe', 'deep/a/b/c/e', 'deep/a/b/c'] + extra
	return v0, folders, files


def run_both(job, monkeypatch, logged, prepare=None):
	'''The oracle's and the new copy's (result, tree, rows, lines, unsynced) of edge_version(), each into its own V1.'''
	v0, folders, files = edge_version(job)
	outcomes = []
	for copy in (oracle_referenced_copy, rv.do_referenced_copy):
		v1 = os.path.join(job.job_vault, V1)
		if os.path.lexists(v1):
			shutil.rmtree(v1)
		os.makedirs(v1)
		manifest = tracked_manifest(job.job_vault, v0, files, folders)
		# rows naming no entry, as daemons before 0.43 wrote them: add() no longer takes them
		manifest.begin()
		manifest.conn.executemany('INSERT INTO entries (path) VALUES (?)', [('./',), ('a/../b',)])
		manifest.commit()
		if prepare is not None:
			prepare(v0)
		del logged[:]
		unsynced = []
		rv.GREEN_LIGHT.set()
		result = copy(v0, v1, manifest, relative=True, unsynced=unsynced)
		# the time line is the new copy's alone
		lines = [line for line in logged if not line[1].startswith('Made the referenced copy of ')]
		outcomes.append((result, tree_of(v1), (manifest.folders, manifest.files), lines, unsynced))
		manifest.close()
	return v0, outcomes


def test_every_case_comes_out_as_the_per_entry_copy_had_it(job, monkeypatch, logged, small_chunks):
	v0, (old, new) = run_both(job, monkeypatch, logged)
	assert new == old
	result, tree, (folders, files), lines, unsynced = new
	assert result is True
	# the cases are all there: missing rows of both kinds, a kind that differs either way, a link above a file, a folder
	# no row tracks, rows that name no entry
	messages = [message for _, message in lines]
	assert f'Dropping tracked folder missing from {v0}: gone/' in messages
	assert f'Dropping tracked file missing from {v0}: ghost' in messages
	assert f'Dropping tracked folder f_is_file/: {v0}/f_is_file is no folder' in messages
	assert f'Dropping tracked folder lnk/: {v0}/lnk is no folder' in messages
	assert f'Dropping tracked file dir_is_folder: it is a folder in {v0}' in messages
	assert f'Dropping tracked file lnk/inner: {job.job_vault}/{V1}/lnk/inner is taken in the new version' in messages
	assert ('warning', f'Making {job.job_vault}/{V1}/bare/sub, which no row tracks, for the tracked bare/sub/w') in lines
	assert ('warning', "Dropping a tracked row that names no folder below the version: './'") in lines
	assert ('warning', "Dropping a tracked row that names no file below the version: 'a/../b'") in lines
	assert tree['f_is_file'] == ('link', f'../V0--2021-01-01_00-00-00_-0800/f_is_file')
	assert tree['bad\udcff/n\udcfe'] == ('link', '../../V0--2021-01-01_00-00-00_-0800/bad\udcff/n\udcfe')
	assert tree['dir_is_folder'] == 'folder' and 'dir_is_folder' not in files and 'dir_is_folder/' in folders
	assert f'Dropping tracked file missing from {v0}: many/007x' in messages
	assert 'many/000x' not in files and 'many/059' in files and unsynced == []


def test_unsynced_comes_in_row_order(job, monkeypatch, logged, small_chunks):
	real = rv.copy_file_meta
	def failing(source, dest, failed=None):
		if source.rstrip('/').endswith(('d', 'sub', 'b', 'c')):
			failed.append(source)
			return False
		return real(source, dest, failed)
	monkeypatch.setattr(rv, 'copy_file_meta', failing)
	# the folders the copy makes go to copy_new_folder_meta(), which fails them the same way
	real_new = rv.copy_new_folder_meta
	def failing_new(source, dest, st, failed=None):
		if source.rstrip('/').endswith(('d', 'sub', 'b', 'c')):
			failed.append(source)
			return False
		return real_new(source, dest, st, failed)
	monkeypatch.setattr(rv, 'copy_new_folder_meta', failing_new)
	_, (old, new) = run_both(job, monkeypatch, logged)
	assert new == old
	assert [os.path.basename(path.rstrip('/')) for path in new[4]] == ['d', 'sub', 'b', 'c']


def eio(path):
	return OSError(errno.EIO, os.strerror(errno.EIO), path)


@pytest.mark.parametrize('what', ['folder', 'file'])
def test_an_entry_that_cannot_be_looked_at_is_kept_with_its_line(job, monkeypatch, logged, small_chunks, what):
	# its lstat fails: it stays tracked and is made or linked as ever. for the folder, a file row of its name too: linked
	# as ever, it finds the folder made, and is dropped with a line a thread reports, which comes before the lines of the
	# rows after it
	failing_entry = 'd/sub' if what == 'folder' else 'd/x'
	monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', 8)
	extra.extend(['d/sub', 'd/subx', 'd/x2'] if what == 'folder' else ['d/x2'])
	real_lstat = os.lstat
	failing = {}
	def lstat(path, *args, **kwargs):
		if os.fspath(path).rstrip('/') == failing.get('entry'):
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	def prepare(v0):
		failing['entry'] = os.path.join(v0, failing_entry)
	monkeypatch.setattr(os, 'lstat', lstat)
	v0, (old, new) = run_both(job, monkeypatch, logged, prepare)
	failing.clear()
	assert new == old
	result, tree, (folders, files), lines, _ = new
	shown = failing_entry + ('/' if what == 'folder' else '')
	assert ('error', f'Cannot look at tracked {what} {shown} in {v0}, keeping it: {eio(os.path.join(v0, failing_entry))}') in lines
	assert (shown in folders) if what == 'folder' else (shown in files)
	assert failing_entry in tree
	if what == 'folder':
		messages = [message for _, message in lines]
		taken = messages.index(f'Dropping tracked file d/sub: {job.job_vault}/{V1}/d/sub is taken in the new version')
		assert messages.index(f'Cannot look at tracked file d/sub in {v0}, keeping it: {eio(os.path.join(v0, "d/sub"))}') < taken
		assert taken < messages.index(f'Dropping tracked file missing from {v0}: d/subx')


def links_counted(monkeypatch, after, action):
	'''The links do_referenced_copy() makes, counted; action() runs once the after-th is made.'''
	made = []
	real = os.symlink
	lock = threading.Lock()
	def symlink(*args, **kwargs):
		real(*args, **kwargs)
		with lock:
			made.append(args[1])
			if len(made) == after:
				action()
	monkeypatch.setattr(os, 'symlink', symlink)
	return made


def big_version(job, count=400):
	tree = {f'f/{i // 50:02d}/{i:04d}': '' for i in range(count)}
	v0 = write_committed_version(job, 0, tree)
	folders = ['f/'] + [f'f/{i:02d}/' for i in range(count // 50)]
	return v0, tracked_manifest(job.job_vault, v0, list(tree), folders)


def test_a_stop_mid_copy_returns_false_and_drops_no_row(job, monkeypatch, logged):
	v0, manifest = big_version(job)
	v1 = os.path.join(job.job_vault, V1)
	made = links_counted(monkeypatch, 50, rv.GREEN_LIGHT.clear)
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True) is False
	finally:
		rv.GREEN_LIGHT.set()
	monkeypatch.undo()
	assert ('error', 'Backup process interrupted, stopping') in logged
	# each other thread finishes the link it is making at most
	assert 50 <= len(made) <= 50 + rv.REFERENCED_COPY_THREADS
	assert len(manifest.files) == 400
	manifest.close()


def test_a_stop_while_the_folders_are_made_makes_no_link(job, monkeypatch, logged):
	v0, manifest = big_version(job)
	v1 = os.path.join(job.job_vault, V1)
	made = []
	real = rv.copy_file_meta
	def meta(*args, **kwargs):
		made.append(args[1])
		if len(made) == 2:
			rv.GREEN_LIGHT.clear()
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'copy_file_meta', meta)
	real_new = rv.copy_new_folder_meta
	def new_meta(*args, **kwargs):
		made.append(args[1])
		if len(made) == 2:
			rv.GREEN_LIGHT.clear()
		return real_new(*args, **kwargs)
	monkeypatch.setattr(rv, 'copy_new_folder_meta', new_meta)
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True) is False
	finally:
		rv.GREEN_LIGHT.set()
	assert ('error', 'Backup process interrupted, stopping') in logged
	assert not [rel for rel, kind in tree_of(v1).items() if kind != 'folder']
	manifest.close()


class DroppingGuard:
	'''A pool guard whose disk drops once armed: every poll from then raises PoolNotReady.'''
	def __init__(self):
		self.dropped = False
		self.polls = 0
		self.lock = threading.Lock()
	def poll(self):
		with self.lock:
			self.polls += 1
		if self.dropped:
			raise rv.PoolNotReady('disk /b1 of pool /pool is not mounted')


def test_a_disk_dropping_mid_copy_raises_promptly(job, monkeypatch, logged):
	v0, manifest = big_version(job)
	v1 = os.path.join(job.job_vault, V1)
	guard = DroppingGuard()
	def drop():
		guard.dropped = True
	made = links_counted(monkeypatch, 30, drop)
	with pytest.raises(rv.PoolNotReady):
		rv.do_referenced_copy(v0, v1, manifest, relative=True, pool_guard=guard)
	monkeypatch.undo()
	assert 30 <= len(made) <= 30 + rv.REFERENCED_COPY_THREADS
	assert len(manifest.files) == 400
	# every entry made was polled for, on whichever thread made it
	assert guard.polls >= len(made)
	manifest.close()


def test_an_absolute_copy_links_each_file_to_its_source(job):
	# the first backup's referenced copy (relative False): links straight to the monitored files
	v0, manifest = big_version(job, 120)
	v1 = os.path.join(job.job_vault, V1)
	assert rv.do_referenced_copy(v0, v1, manifest) is True
	tree = tree_of(v1)
	assert tree['f/01/0060'] == ('link', os.path.join(v0, 'f/01/0060'))
	assert sum(1 for kind in tree.values() if kind == 'folder') == 4
	manifest.close()


@pytest.mark.parametrize('exc', [PermissionError(errno.EACCES, 'EACCES'), OSError(errno.ENOSPC, 'ENOSPC')])
@pytest.mark.parametrize('where', ['symlink', 'mkdir'])
def test_what_a_thread_raises_comes_out_and_no_thread_is_left(job, monkeypatch, logged, exc, where):
	v0, manifest = big_version(job)
	v1 = os.path.join(job.job_vault, V1)
	calls = []
	lock = threading.Lock()
	real = getattr(os, where)
	# the fifth entry fails each time it is tried: a mkdir that fails is tried again by os.makedirs()
	failing_path = []
	def failing(*args, **kwargs):
		with lock:
			calls.append(args)
			if len(calls) == 5:
				failing_path.append(os.fspath(args[-1] if where == 'symlink' else args[0]).rstrip('/'))
			hit = bool(failing_path) and os.fspath(args[-1] if where == 'symlink' else args[0]).rstrip('/') == failing_path[0]
		if hit:
			raise exc
		return real(*args, **kwargs)
	monkeypatch.setattr(os, where, failing)
	before = threading.active_count()
	with pytest.raises(type(exc)):
		rv.do_referenced_copy(v0, v1, manifest, relative=True)
	assert threading.active_count() == before
	# no row dropped for it
	assert len(manifest.files) == 400
	manifest.close()


def test_one_line_tells_how_long_the_copy_took(job, logged):
	v0, manifest = big_version(job, 120)
	v1 = os.path.join(job.job_vault, V1)
	assert rv.do_referenced_copy(v0, v1, manifest, relative=True) is True
	line = [(kind, message) for kind, message in logged if message.startswith('Made the referenced copy of ')]
	assert len(line) == 1 and line[0][0] == 'info'
	line = [message for _, message in line]
	assert re.fullmatch(re.escape(f'Made the referenced copy of {v0} in ') + rf'\d+\.\d s: 120 files, 3 folders, {rv.REFERENCED_COPY_THREADS} threads', line[0])
	manifest.close()


def test_a_stopped_copy_says_it_stopped(job, monkeypatch, logged):
	v0, manifest = big_version(job)
	v1 = os.path.join(job.job_vault, V1)
	links_counted(monkeypatch, 50, rv.GREEN_LIGHT.clear)
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True) is False
	finally:
		rv.GREEN_LIGHT.set()
	line = [message for kind, message in logged if message.startswith('Stopped making the referenced copy of ')]
	assert len(line) == 1 and line[0].endswith(f' threads') and not any(message.startswith('Made the referenced copy of ') for _, message in logged)
	manifest.close()


@pytest.mark.parametrize('code', [errno.ENOTSUP, errno.ENOSYS])
def test_a_filesystem_without_attributes_takes_the_fast_path(tmp_path, monkeypatch, logged, code):
	# a mergerfs pool switched to xattr=nosys lists no attributes, as xattr_names() has it: no folder goes to copy_file_meta()
	source, by_meta, by_fast = (str(tmp_path / name) for name in ('s', 'm', 'f'))
	for folder in (source, by_meta, by_fast):
		os.mkdir(folder)
	os.chmod(source, 0o705)
	os.utime(source, ns=(1_000_000_000_123, 2_000_000_000_456))
	def listxattr(path, *args, **kwargs):
		raise OSError(code, os.strerror(code), path)
	monkeypatch.setattr(os, 'listxattr', listxattr)
	monkeypatch.setattr(rv, 'copy_file_meta', lambda *args, **kwargs: pytest.fail('the folder went to copy_file_meta()'))
	assert rv.copy_new_folder_meta(source, by_fast, os.lstat(source)) is True
	st = os.lstat(by_fast)
	assert (stat.S_IMODE(st.st_mode), st.st_atime_ns, st.st_mtime_ns) == (0o705, 1_000_000_000_123, 2_000_000_000_456)
	assert not [line for line in logged if line[0] == 'error']


def test_a_filesystem_without_attributes_ends_as_copy_file_meta_has_it(tmp_path, monkeypatch, logged):
	source, by_meta, by_fast = (str(tmp_path / name) for name in ('s', 'm', 'f'))
	for folder in (source, by_meta, by_fast):
		os.mkdir(folder)
	os.chmod(source, 0o750)
	os.utime(source, ns=(1_000_000_000_123, 2_000_000_000_456))
	def listxattr(path, *args, **kwargs):
		raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP), path)
	monkeypatch.setattr(os, 'listxattr', listxattr)
	failed = []
	assert rv.copy_file_meta(source, by_meta, failed) is True
	assert rv.copy_new_folder_meta(source, by_fast, os.lstat(source)) is True
	look = lambda path: (lambda st: (st.st_mode, st.st_uid, st.st_gid, st.st_atime_ns, st.st_mtime_ns))(os.lstat(path))
	assert look(by_fast) == look(by_meta)
	assert not failed and not [line for line in logged if line[0] == 'error']
