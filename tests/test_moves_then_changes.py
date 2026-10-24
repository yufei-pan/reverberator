import errno
import os
from collections import deque

import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup

pytestmark = pytest.mark.unit

root_only = pytest.mark.skipif(os.geteuid() != 0, reason='chown needs root')
BAD_LINES = ('IsADirectoryError', 'Failed to move', 'Doing delete & copy instead')


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


@pytest.fixture
def logged(monkeypatch):
	'''Every line the backuper logs from now on.'''
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		lines.append(str(message))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def batch(job, *events):
	'''The backup entries of events (is_dir, event, rel, moved_from rel or None), as the watcher queues them in one batch.'''
	m = job.monitor
	return rv.change_events_to_backup_entries(deque(rv.ChangeEvent(float(i), is_dir, event, f'{m}/{rel}', None if source is None else f'{m}/{source}')
		for i, (is_dir, event, rel, source) in enumerate(events, 1)), m)


def resolved(job, version, rel):
	got = rv.resolve_version_entry(job.job_vault, version, rel, job.monitor)
	assert got.kind in ('file', 'symlink'), got
	return got.path


def assert_moved_cleanly(lines):
	bad = [line for line in lines if any(word in line for word in BAD_LINES)]
	assert not bad, bad


def mode(path):
	return os.lstat(path).st_mode & 0o7777


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_mv_then_chmod_of_the_moved_file(job, logged, only_sync_attributes):
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	v0 = run_backup(job, only_sync_attributes=only_sync_attributes)[0]
	shared = os.path.join(v0, 'x')
	before = mode(shared)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	os.chmod(f'{m}/d/x', 0o600)
	v1 = run_backup(job, batch(job, (False, 'move', 'd/x', 'x'), (False, 'attrib', 'd/x', None)), only_sync_attributes=only_sync_attributes)[-1]
	end = resolved(job, v1, 'd/x')
	assert mode(end) == 0o600 and open(end).read() == 'x'
	if only_sync_attributes:
		# the shared copy at the chain's end carries the newest metadata
		assert end == shared
	else:
		assert end == os.path.join(v1, 'd/x') and not os.path.islink(end)
		assert mode(shared) == before
	assert_moved_cleanly(logged)


@root_only
def test_mv_then_chown_of_the_moved_file(job, logged):
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	os.chown(f'{m}/d/x', 1234, 1234)
	v1 = run_backup(job, batch(job, (False, 'move', 'd/x', 'x'), (False, 'attrib', 'd/x', None)))[-1]
	st = os.lstat(resolved(job, v1, 'd/x'))
	assert (st.st_uid, st.st_gid) == (1234, 1234)
	assert_moved_cleanly(logged)


def test_mv_then_an_xattr_of_the_moved_file(job, logged):
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	try:
		os.setxattr(f'{job.monitor}/d/keep', 'user.probe', b'1')
	except OSError as e:
		if e.errno in (errno.ENOTSUP, errno.EPERM):
			pytest.skip('user xattrs are unsupported here')
		raise
	os.removexattr(f'{job.monitor}/d/keep', 'user.probe')
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	os.setxattr(f'{m}/d/x', 'user.k', b'v')
	v1 = run_backup(job, batch(job, (False, 'move', 'd/x', 'x'), (False, 'attrib', 'd/x', None)))[-1]
	assert os.getxattr(resolved(job, v1, 'd/x'), 'user.k') == b'v'
	assert_moved_cleanly(logged)


@root_only
def test_a_moved_user_link_then_lchown(job, logged):
	seed_monitor(job, {'target': 't', 'd/keep': 'k'})
	m = job.monitor
	os.symlink('../target', f'{m}/u')
	run_backup(job)
	os.rename(f'{m}/u', f'{m}/d/u')
	os.lchown(f'{m}/d/u', 1234, 1234)
	v1 = run_backup(job, batch(job, (False, 'move', 'd/u', 'u'), (False, 'attrib', 'd/u', None)))[-1]
	got = rv.resolve_version_entry(job.job_vault, v1, 'd/u', job.monitor)
	assert got.kind == 'symlink'
	st = os.lstat(got.path)
	assert (st.st_uid, st.st_gid) == (1234, 1234)
	assert os.readlink(got.path) == '../target'
	assert_moved_cleanly(logged)


def assert_left_alone(v1, rel):
	# a file of the moved folder nothing changed is still linked, not copied again
	assert os.path.islink(os.path.join(v1, rel)), rel


def test_mv_folder_deep_then_chmod_inside(job, logged):
	seed_monitor(job, {'F/y': 'y', 'F/z': 'z', 'p/q/keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/F', f'{m}/p/q/F')
	os.chmod(f'{m}/p/q/F/y', 0o600)
	v1 = run_backup(job, batch(job, (True, 'move', 'p/q/F', 'F'), (False, 'attrib', 'p/q/F/y', None)))[-1]
	end = resolved(job, v1, 'p/q/F/y')
	assert mode(end) == 0o600 and open(end).read() == 'y'
	assert_left_alone(v1, 'p/q/F/z')
	assert not os.path.lexists(os.path.join(v1, 'F'))
	assert_moved_cleanly(logged)


@root_only
def test_mv_folder_then_chown_inside(job, logged):
	seed_monitor(job, {'d/y': 'y', 'd/z': 'z'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/e')
	os.chown(f'{m}/e/y', 1234, 1234)
	v1 = run_backup(job, batch(job, (True, 'move', 'e', 'd'), (False, 'attrib', 'e/y', None)))[-1]
	st = os.lstat(resolved(job, v1, 'e/y'))
	assert (st.st_uid, st.st_gid) == (1234, 1234)
	assert_left_alone(v1, 'e/z')
	assert_moved_cleanly(logged)


def test_mv_folder_then_create_inside(job, logged):
	seed_monitor(job, {'d/old': 'old', 'd/old2': 'old2'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/e')
	with open(f'{m}/e/new', 'w') as f:
		f.write('new')
	v1 = run_backup(job, batch(job, (True, 'move', 'e', 'd'), (False, 'create', 'e/new', None), (False, 'modify', 'e/new', None)))[-1]
	assert open(resolved(job, v1, 'e/new')).read() == 'new'
	assert open(resolved(job, v1, 'e/old')).read() == 'old'
	assert_left_alone(v1, 'e/old')
	assert_left_alone(v1, 'e/old2')
	assert not os.path.lexists(os.path.join(v1, 'd'))
	assert_moved_cleanly(logged)


def test_mv_folder_then_modify_inside(job, logged):
	seed_monitor(job, {'d/old': 'old', 'd/old2': 'old2'})
	v0 = run_backup(job)[0]
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/e')
	with open(f'{m}/e/old', 'w') as f:
		f.write('changed')
	v1 = run_backup(job, batch(job, (True, 'move', 'e', 'd'), (False, 'modify', 'e/old', None)))[-1]
	assert open(resolved(job, v1, 'e/old')).read() == 'changed'
	assert open(os.path.join(v0, 'd/old')).read() == 'old'
	assert_left_alone(v1, 'e/old2')
	assert_moved_cleanly(logged)


def test_a_plain_move_leaves_the_shared_copy_alone(job, logged, monkeypatch):
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	v0 = run_backup(job)[0]
	shared = os.path.join(v0, 'x')
	before = rv.entry_metadata(shared)
	calls = []
	real = rv.copy_file_meta
	def spy(source_file, backup_file_path):
		calls.append(os.path.abspath(backup_file_path))
		return real(source_file, backup_file_path)
	monkeypatch.setattr(rv, 'copy_file_meta', spy)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	v1 = run_backup(job, batch(job, (False, 'move', 'd/x', 'x')))[-1]
	assert os.path.islink(os.path.join(v1, 'd/x'))
	assert rv.entry_metadata(shared) == before
	assert os.path.abspath(shared) not in calls
	assert_moved_cleanly(logged)


def test_a_swap_gives_no_older_version_another_files_metadata(job, logged):
	# mv a a.tmp; mv b a; mv a.tmp b collapses to moves the replay cannot apply as made: a moved link can end at the
	# other file's copy, which must not take its mode, even with the same size and times
	seed_monitor(job, {'a': 'A', 'b': 'B'})
	m = job.monitor
	os.chmod(f'{m}/a', 0o600)
	os.utime(f'{m}/a', ns=(10 ** 18, 10 ** 18))
	os.utime(f'{m}/b', ns=(10 ** 18, 10 ** 18))
	v0 = run_backup(job)[0]
	before = {name: rv.entry_metadata(os.path.join(v0, name)) for name in ('a', 'b')}
	os.rename(f'{m}/a', f'{m}/a.tmp')
	os.rename(f'{m}/b', f'{m}/a')
	os.rename(f'{m}/a.tmp', f'{m}/b')
	events = deque(rv.ChangeEvent(float(i), False, 'move', f'{m}/{rel}', f'{m}/{source}')
		for i, (rel, source) in enumerate([('a.tmp', 'a'), ('a', 'b'), ('b', 'a.tmp')], 1))
	v1 = run_backup(job, rv.change_events_to_backup_entries(deque(events), m), touched=rv.touched_scopes(events, m))[-1]
	assert {name: rv.entry_metadata(os.path.join(v0, name)) for name in ('a', 'b')} == before
	for name, content, want in (('a', 'B', 0o644), ('b', 'A', 0o600)):
		end = resolved(job, v1, name)
		assert open(end).read() == content and mode(end) == want
