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
	'''Every line the backuper logs from now on, an error line starting with "ERROR ".'''
	lines = []
	real = rv.backuperTeeLogToTl
	def record(path, message, **kwargs):
		lines.append(('ERROR ' if kwargs.get('error') else '') + str(message))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return lines


def raw(job, *events):
	'''The watcher's ChangeEvents of events (is_dir, event, rel, moved_from rel or None), in this order.'''
	m = job.monitor
	return deque(rv.ChangeEvent(float(i), is_dir, event, f'{m}/{rel}', None if source is None else f'{m}/{source}')
		for i, (is_dir, event, rel, source) in enumerate(events, 1))


def batch(job, *events):
	'''The backup entries of events (is_dir, event, rel, moved_from rel or None), as the watcher queues them in one batch.'''
	return rv.change_events_to_backup_entries(raw(job, *events), job.monitor)


def verified(job, *events, **kwargs):
	'''A backup of events in one batch with its verification, as the daemon runs one; returns the new version.'''
	evs = raw(job, *events)
	return run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), touched=rv.touched_scopes(evs, job.monitor), **kwargs)[-1]


def resolved(job, version, rel):
	got = rv.resolve_version_entry(job.job_vault, version, rel, job.monitor)
	assert got.kind in ('file', 'symlink'), got
	return got.path


def assert_moved_cleanly(lines):
	# a first backup's own error line says the vault is new
	bad = [line for line in lines if (line.startswith('ERROR ') and 'treating the vault as new' not in line) or any(word in line for word in BAD_LINES)]
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


# ---- changes carried by a later move in the same batch ------------------------------------------------------------

def test_the_collapse_carries_a_change_through_a_later_folder_move(job):
	m = job.monitor
	entries = batch(job, (False, 'move', 'd/x', 'x'), (False, 'attrib', 'd/x', None), (True, 'move', 'e', 'd'))
	assert [(path[len(m):], values.event, values.source_path and values.source_path[len(m):]) for path, values in entries.items()] == [
		('/d/x', 'move', '/x'), ('/e/', 'move', '/d/'), ('/e/x', 'attrib', None)]


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_mv_into_a_folder_chmod_then_mv_the_folder(job, logged, only_sync_attributes):
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	run_backup(job, only_sync_attributes=only_sync_attributes)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	os.chmod(f'{m}/d/x', 0o600)
	os.rename(f'{m}/d', f'{m}/e')
	v1 = run_backup(job, batch(job, (False, 'move', 'd/x', 'x'), (False, 'attrib', 'd/x', None), (True, 'move', 'e', 'd')),
		only_sync_attributes=only_sync_attributes)[-1]
	end = resolved(job, v1, 'e/x')
	assert mode(end) == 0o600 and open(end).read() == 'x'
	assert_left_alone(v1, 'e/keep')
	assert not os.path.lexists(os.path.join(v1, 'd')) and not os.path.lexists(os.path.join(v1, 'x'))
	assert_moved_cleanly(logged)


def test_mv_a_folder_chmod_inside_then_mv_it_again(job, logged):
	seed_monitor(job, {'d/y': 'y', 'd/z': 'z'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/e')
	os.chmod(f'{m}/e/y', 0o600)
	os.rename(f'{m}/e', f'{m}/f')
	v1 = run_backup(job, batch(job, (True, 'move', 'e', 'd'), (False, 'attrib', 'e/y', None), (True, 'move', 'f', 'e')))[-1]
	assert mode(resolved(job, v1, 'f/y')) == 0o600
	assert_left_alone(v1, 'f/z')
	assert sorted(os.listdir(v1)) == ['f']
	assert_moved_cleanly(logged)


def tracked(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel) is not None
	finally:
		manifest.close()


def test_mv_a_folder_mkdir_inside_then_mv_it_again(job, logged):
	seed_monitor(job, {'d/y': 'y'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/e')
	os.mkdir(f'{m}/e/x')
	os.rename(f'{m}/e', f'{m}/f')
	v1 = run_backup(job, batch(job, (True, 'move', 'e', 'd'), (True, 'create', 'e/x', None), (True, 'move', 'f', 'e')))[-1]
	assert os.path.isdir(os.path.join(v1, 'f/x')) and not os.path.islink(os.path.join(v1, 'f/x'))
	assert tracked(job, 'f/x/')
	assert_left_alone(v1, 'f/y')
	assert sorted(os.listdir(v1)) == ['f']
	assert_moved_cleanly(logged)


def test_changes_before_a_folder_move_reach_its_new_place(job, logged):
	# fuzz seed 40: mkdir d/sub; modify d/c; mv d m1
	seed_monitor(job, {'d/c': 'c', 'd/z': 'z'})
	run_backup(job)
	m = job.monitor
	os.mkdir(f'{m}/d/sub')
	with open(f'{m}/d/c', 'w') as f:
		f.write('changed')
	os.rename(f'{m}/d', f'{m}/m1')
	v1 = run_backup(job, batch(job, (True, 'create', 'd/sub', None), (False, 'modify', 'd/c', None), (True, 'move', 'm1', 'd')))[-1]
	assert os.path.isdir(os.path.join(v1, 'm1/sub')) and tracked(job, 'm1/sub/')
	assert open(resolved(job, v1, 'm1/c')).read() == 'changed'
	assert_left_alone(v1, 'm1/z')
	assert_moved_cleanly(logged)


def test_a_folder_made_before_its_parent_moved_is_kept_for_the_next_backups(job, logged):
	# fuzz seed 147: the folder lost, a later create under it, then the next referenced copy failed
	seed_monitor(job, {'a/d992/keep': 'k', 'a/n': 'n'})
	run_backup(job)
	m = job.monitor
	os.makedirs(f'{m}/a/d992/d247')
	for name in ('c0', 'c1'):
		with open(f'{m}/a/d992/d247/{name}', 'w') as f:
			f.write(name)
	os.rename(f'{m}/a/d992', f'{m}/a/y')
	with open(f'{m}/a/y/n407', 'w') as f:
		f.write('n407')
	run_backup(job, batch(job, (True, 'create', 'a/d992/d247', None), (False, 'create', 'a/d992/d247/c0', None),
		(False, 'modify', 'a/d992/d247/c0', None), (False, 'create', 'a/d992/d247/c1', None), (False, 'modify', 'a/d992/d247/c1', None),
		(True, 'move', 'a/y', 'a/d992'), (False, 'create', 'a/y/n407', None), (False, 'modify', 'a/y/n407', None)))
	with open(f'{m}/a/y/d247/n247', 'w') as f:
		f.write('n247')
	run_backup(job, batch(job, (False, 'create', 'a/y/d247/n247', None), (False, 'modify', 'a/y/d247/n247', None)))
	with open(f'{m}/a/n', 'w') as f:
		f.write('n2')
	v3 = run_backup(job, batch(job, (False, 'modify', 'a/n', None)))[-1]
	for rel, content in (('a/y/d247/c0', 'c0'), ('a/y/d247/c1', 'c1'), ('a/y/d247/n247', 'n247'), ('a/y/n407', 'n407'), ('a/y/keep', 'k')):
		assert open(resolved(job, v3, rel)).read() == content, rel
	assert_moved_cleanly(logged)


@root_only
def test_a_user_link_chowned_then_its_folder_moved(job, logged):
	# fuzz seed 17: chown -h d/l; mv d m2
	seed_monitor(job, {'d/t': 't'})
	m = job.monitor
	os.symlink('t', f'{m}/d/l')
	run_backup(job)
	os.lchown(f'{m}/d/l', 1000, 1000)
	os.rename(f'{m}/d', f'{m}/m2')
	v1 = run_backup(job, batch(job, (False, 'attrib', 'd/l', None), (True, 'move', 'm2', 'd')))[-1]
	got = rv.resolve_version_entry(job.job_vault, v1, 'm2/l', job.monitor)
	assert got.kind == 'symlink' and os.readlink(got.path) == 't'
	st = os.lstat(got.path)
	assert (st.st_uid, st.st_gid) == (1000, 1000)
	assert_moved_cleanly(logged)


def test_a_delete_inside_a_moved_folder_is_fixed_by_the_verification(job, logged):
	# fuzz seed 150: mv d15 z; rm z/d612/l652; create z/d612/n19. The delete replays before the move, and the
	# verification removes what the move carried
	seed_monitor(job, {'d15/d612/n822': 'n'})
	m = job.monitor
	os.symlink('t1', f'{m}/d15/d612/l652')
	run_backup(job)
	os.rename(f'{m}/d15', f'{m}/z')
	os.remove(f'{m}/z/d612/l652')
	with open(f'{m}/z/d612/n19', 'w') as f:
		f.write('n19')
	v1 = verified(job, (True, 'move', 'z', 'd15'), (False, 'delete', 'z/d612/l652', None), (False, 'create', 'z/d612/n19', None),
		(False, 'modify', 'z/d612/n19', None))
	assert not os.path.lexists(os.path.join(v1, 'z/d612/l652')) and not tracked(job, 'z/d612/l652')
	assert open(resolved(job, v1, 'z/d612/n19')).read() == 'n19'
	assert_left_alone(v1, 'z/d612/n822')
	assert_moved_cleanly(logged)


def test_a_file_renamed_then_its_folder_moved_logs_no_error(job, logged):
	seed_monitor(job, {'d/a': 'a', 'd/z': 'z'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d/a', f'{m}/d/b')
	os.rename(f'{m}/d', f'{m}/e')
	v1 = run_backup(job, batch(job, (False, 'move', 'd/b', 'd/a'), (True, 'move', 'e', 'd')))[-1]
	assert open(resolved(job, v1, 'e/b')).read() == 'a'
	assert_left_alone(v1, 'e/b')
	assert_left_alone(v1, 'e/z')
	assert_moved_cleanly(logged)


def copies_made(monkeypatch):
	'''The destination of each copy the backuper queues from now on.'''
	copies = []
	real = rv.cp_af_copy_path
	def spy(source_path, dest_path, *args, **kwargs):
		copies.append(dest_path)
		return real(source_path, dest_path, *args, **kwargs)
	monkeypatch.setattr(rv, 'cp_af_copy_path', spy)
	return copies


def test_a_save_through_a_backup_name_copies_the_new_file_once(job, logged, monkeypatch):
	# an editor's save: mv f f~; echo new > f
	seed_monitor(job, {'f': 'old', 'k': 'k'})
	v0 = run_backup(job)[0]
	m = job.monitor
	os.rename(f'{m}/f', f'{m}/f~')
	with open(f'{m}/f', 'w') as fh:
		fh.write('new')
	copies = copies_made(monkeypatch)
	v1 = run_backup(job, batch(job, (False, 'move', 'f~', 'f'), (False, 'create', 'f', None), (False, 'modify', 'f', None)))[-1]
	assert open(resolved(job, v1, 'f')).read() == 'new'
	assert resolved(job, v1, 'f~') == os.path.join(v0, 'f') and open(os.path.join(v0, 'f')).read() == 'old'
	assert copies == [os.path.join(v1, 'f')]
	assert_moved_cleanly(logged)


@pytest.mark.parametrize('emptied', ['deleted', 'empty'])
def test_a_folder_moved_onto_a_removed_or_empty_folder_is_renamed(job, logged, emptied):
	seed_monitor(job, {'d/y': 'y', 'd/z': 'z', 'e/': None} if emptied == 'empty' else {'d/y': 'y', 'd/z': 'z', 'e/q': 'q'})
	run_backup(job)
	m = job.monitor
	if emptied == 'deleted':
		os.remove(f'{m}/e/q')
	os.rmdir(f'{m}/e')
	os.rename(f'{m}/d', f'{m}/e')
	events = [(False, 'delete', 'e/q', None)] if emptied == 'deleted' else []
	v1 = run_backup(job, batch(job, *events, (True, 'delete', 'e', None), (True, 'move', 'e', 'd')))[-1]
	assert_left_alone(v1, 'e/y')
	assert_left_alone(v1, 'e/z')
	assert sorted(os.listdir(os.path.join(v1, 'e'))) == ['y', 'z']
	assert not os.path.lexists(os.path.join(v1, 'd'))
	assert_moved_cleanly(logged)


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_chmod_then_mv_links_the_moved_file(job, logged, monkeypatch, only_sync_attributes):
	seed_monitor(job, {'x': 'x', 'k': 'k'})
	v0 = run_backup(job, only_sync_attributes=only_sync_attributes)[0]
	m = job.monitor
	os.chmod(f'{m}/x', 0o600)
	os.rename(f'{m}/x', f'{m}/y')
	copies = copies_made(monkeypatch)
	v1 = run_backup(job, batch(job, (False, 'attrib', 'x', None), (False, 'move', 'y', 'x')), only_sync_attributes=only_sync_attributes)[-1]
	end = resolved(job, v1, 'y')
	assert mode(end) == 0o600 and open(end).read() == 'x'
	if only_sync_attributes:
		# the shared copy takes the newest metadata, and nothing is copied
		assert end == os.path.join(v0, 'x') and copies == []
	else:
		assert copies == [os.path.join(v1, 'y')]
	assert_moved_cleanly(logged)


# ---- fix round 2 --------------------------------------------------------------------------------------------------

def test_many_atomic_saves_in_one_batch_collapse_quickly(job, monkeypatch):
	# write state.tmp, rename it over state.json, 20k times: each path's later events are looked up, not scanned
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda *args, **kwargs: None)
	m = job.monitor
	events = deque()
	for k in range(20000):
		events.extend((rv.ChangeEvent(3.0 * k, False, 'create', f'{m}/app/state.tmp', None),
			rv.ChangeEvent(3.0 * k + 1, False, 'modify', f'{m}/app/state.tmp', None),
			rv.ChangeEvent(3.0 * k + 2, False, 'move', f'{m}/app/state.json', f'{m}/app/state.tmp')))
	import time
	started = time.monotonic()
	entries = rv.change_events_to_backup_entries(events, m)
	assert time.monotonic() - started < 3
	assert f'{m}/app/state.json' in entries


def test_a_file_changed_moved_into_a_folder_then_the_folder_moved(job, logged):
	# echo new > a; mv a d/a; mv d e: the modify the move became lands where the live file is
	seed_monitor(job, {'a': 'a', 'd/keep': 'k'})
	run_backup(job)
	m = job.monitor
	with open(f'{m}/a', 'w') as f:
		f.write('new')
	os.rename(f'{m}/a', f'{m}/d/a')
	os.rename(f'{m}/d', f'{m}/e')
	v1 = run_backup(job, batch(job, (False, 'modify', 'a', None), (False, 'move', 'd/a', 'a'), (True, 'move', 'e', 'd')))[-1]
	assert open(resolved(job, v1, 'e/a')).read() == 'new'
	assert_left_alone(v1, 'e/keep')
	assert sorted(os.listdir(v1)) == ['e']
	assert_moved_cleanly(logged)


def test_a_new_folder_moved_into_a_folder_then_the_folder_moved(job, logged):
	# mkdir n; mv n d/n; echo x > d/n/x; mv d e
	seed_monitor(job, {'d/keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.mkdir(f'{m}/n')
	os.rename(f'{m}/n', f'{m}/d/n')
	with open(f'{m}/d/n/x', 'w') as f:
		f.write('x')
	os.rename(f'{m}/d', f'{m}/e')
	v1 = run_backup(job, batch(job, (True, 'create', 'n', None), (True, 'move', 'd/n', 'n'), (False, 'create', 'd/n/x', None),
		(False, 'modify', 'd/n/x', None), (True, 'move', 'e', 'd')))[-1]
	assert open(resolved(job, v1, 'e/n/x')).read() == 'x' and tracked(job, 'e/n/')
	assert sorted(os.listdir(v1)) == ['e']
	with open(f'{m}/keep2', 'w') as f:
		f.write('k2')
	v2 = run_backup(job, batch(job, (False, 'create', 'keep2', None)))[-1]
	assert open(resolved(job, v2, 'e/n/x')).read() == 'x'
	assert_moved_cleanly(logged)


def test_a_folder_made_then_a_folder_moved_into_it_copies_nothing(job, logged, monkeypatch):
	# mkdir n; mv d n/d: d arrives by its move, so the new n is copied without it, and not counted for it
	seed_monitor(job, {f'd/f{i}': str(i) * 100000 for i in range(5)})
	run_backup(job)
	m = job.monitor
	os.mkdir(f'{m}/n')
	os.rename(f'{m}/d', f'{m}/n/d')
	entries = batch(job, (True, 'create', 'n', None), (True, 'move', 'n/d', 'd'))
	size, inodes = rv.get_backup_size_inode(entries, True, rv.list_versions(job.job_vault)[-1].path, m)
	assert size < 100000 and inodes == 1
	copies = copies_made(monkeypatch)
	v1 = run_backup(job, entries)[-1]
	assert copies == []
	for i in range(5):
		assert_left_alone(v1, f'n/d/f{i}')
	assert tracked(job, 'n/') and tracked(job, 'n/d/')
	assert_moved_cleanly(logged)


def test_a_folder_left_without_a_row_is_copied_by_the_next_change_under_it(job, logged, monkeypatch):
	# the version could not make n ( ENOSPC, say ): n/b's create later copies the whole of n, rows and all, and the
	# backups after it run
	seed_monitor(job, {'keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.mkdir(f'{m}/n')
	with open(f'{m}/n/a', 'w') as f:
		f.write('a')
	real = rv.make_real_folder
	def failing(path):
		if path.rstrip('/').endswith('/n'):
			return False
		return real(path)
	monkeypatch.setattr(rv, 'make_real_folder', failing)
	run_backup(job, batch(job, (True, 'create', 'n', None), (False, 'create', 'n/a', None)))
	monkeypatch.setattr(rv, 'make_real_folder', real)
	assert not tracked(job, 'n/')
	with open(f'{m}/n/b', 'w') as f:
		f.write('b')
	run_backup(job, batch(job, (False, 'create', 'n/b', None), (False, 'modify', 'n/b', None)))
	assert tracked(job, 'n/') and tracked(job, 'n/a') and tracked(job, 'n/b')
	for attempt in range(2):
		with open(f'{m}/keep', 'w') as f:
			f.write(f'k{attempt}')
		version = run_backup(job, batch(job, (False, 'modify', 'keep', None)))[-1]
	assert open(resolved(job, version, 'n/a')).read() == 'a' and open(resolved(job, version, 'n/b')).read() == 'b'


def test_a_vault_with_a_file_row_under_a_folder_without_one_heals(job, logged):
	# a vault left so by an earlier daemon: the referenced copy makes the folder, and the backup runs
	seed_monitor(job, {'keep': 'k', 'n/a': 'a'})
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.discard('n/')
	manifest.commit()
	manifest.close()
	m = job.monitor
	with open(f'{m}/keep', 'w') as f:
		f.write('k2')
	version = run_backup(job, batch(job, (False, 'modify', 'keep', None)))[-1]
	assert open(resolved(job, version, 'n/a')).read() == 'a'
	with open(f'{m}/n/b', 'w') as f:
		f.write('b')
	version = run_backup(job, batch(job, (False, 'create', 'n/b', None), (False, 'modify', 'n/b', None)))[-1]
	assert tracked(job, 'n/') and open(resolved(job, version, 'n/b')).read() == 'b'


def test_an_attrib_on_a_link_left_at_another_files_copy_copies_the_file(job, logged):
	# a swap the replay cannot apply as made leaves b linked to V0's copy of b while the live b is the old a: a chmod
	# of b then copies it, and V0's b keeps its own metadata
	seed_monitor(job, {'a': 'aaa', 'b': 'bbbb'})
	m = job.monitor
	os.utime(f'{m}/a', ns=(10 ** 18, 10 ** 18))
	os.utime(f'{m}/b', ns=(2 * 10 ** 18, 2 * 10 ** 18))
	v0 = run_backup(job)[0]
	os.rename(f'{m}/a', f'{m}/t')
	os.rename(f'{m}/b', f'{m}/a')
	os.rename(f'{m}/t', f'{m}/b')
	run_backup(job, batch(job, (False, 'move', 't', 'a'), (False, 'move', 'a', 'b'), (False, 'move', 'b', 't')))
	before = rv.entry_metadata(os.path.join(v0, 'b'))
	os.chmod(f'{m}/b', 0o600)
	v2 = run_backup(job, batch(job, (False, 'attrib', 'b', None)))[-1]
	assert rv.entry_metadata(os.path.join(v0, 'b')) == before
	end = resolved(job, v2, 'b')
	assert open(end).read() == 'aaa' and mode(end) == 0o600


# ---- fix round 3 --------------------------------------------------------------------------------------------------

def assert_version_is_the_tree(job, version):
	'''Every entry of the monitored tree is in version, of its kind and with its bytes or link text, and nothing else.'''
	def walk(root):
		found = set()
		for folder, dirs, files in os.walk(root):
			rel_folder = os.path.relpath(folder, root)
			for name in dirs + files:
				rel = name if rel_folder == '.' else f'{rel_folder}/{name}'
				if not rel.startswith('.'):
					found.add(rel)
		return found
	live = walk(job.monitor)
	for rel in sorted(live):
		path = os.path.join(job.monitor, rel)
		got = rv.resolve_version_entry(job.job_vault, version, rel, job.monitor)
		if os.path.islink(path):
			assert got.kind == 'symlink' and os.readlink(got.path) == os.readlink(path), (rel, got)
		elif os.path.isdir(path):
			assert got.kind == 'folder', (rel, got)
		else:
			assert got.kind == 'file' and open(got.path, 'rb').read() == open(path, 'rb').read(), (rel, got)
	extra = walk(version) - live
	assert not extra, extra


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_a_file_moved_in_a_folder_swapped_in_the_batch_reaches_the_version(job, logged, only_sync_attributes):
	# fuzz seed 614: swap the folder d459 and the file b ( via t136 ), then rotate b/c1 to b/c1.1 and write a new b/c1
	seed_monitor(job, {'d459/c1': 'c1', 'd459/x/c0': 'c0', 'b': 'b', 'keep': 'k'})
	run_backup(job, only_sync_attributes=only_sync_attributes)
	m = job.monitor
	os.chmod(f'{m}/d459/x/c0', 0o600)
	os.rename(f'{m}/d459', f'{m}/t136')
	os.rename(f'{m}/b', f'{m}/d459')
	os.rename(f'{m}/t136', f'{m}/b')
	os.rename(f'{m}/b/c1', f'{m}/b/c1.1')
	with open(f'{m}/b/c1', 'w') as f:
		f.write('new')
	v1 = verified(job, (False, 'attrib', 'd459/x/c0', None), (True, 'move', 't136', 'd459'), (False, 'move', 'd459', 'b'),
		(True, 'move', 'b', 't136'), (False, 'move', 'b/c1.1', 'b/c1'), (False, 'create', 'b/c1', None), (False, 'modify', 'b/c1', None),
		only_sync_attributes=only_sync_attributes)
	assert_version_is_the_tree(job, v1)


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_a_link_swapped_into_a_folder_swapped_in_the_batch_reaches_the_version(job, logged, only_sync_attributes):
	# fuzz seed 483: swap the folder z/d609 and the file n929 ( via z/t188 ), then swap d41/d922/n499 with n929/l741
	seed_monitor(job, {'z/d609/k': 'k', 'n929': 'n', 'd41/d922/n499': 'nn', 'n28/': None})
	m = job.monitor
	os.symlink('nowhere', f'{m}/z/d609/l741')
	run_backup(job, only_sync_attributes=only_sync_attributes)
	os.chmod(f'{m}/d41/d922/n499', 0o600)
	os.chmod(f'{m}/n28', 0o700)
	os.rename(f'{m}/z/d609', f'{m}/z/t188')
	os.rename(f'{m}/n929', f'{m}/z/d609')
	os.rename(f'{m}/z/t188', f'{m}/n929')
	os.rename(f'{m}/d41/d922/n499', f'{m}/d41/d922/t281')
	os.rename(f'{m}/n929/l741', f'{m}/d41/d922/n499')
	os.rename(f'{m}/d41/d922/t281', f'{m}/n929/l741')
	v1 = verified(job, (False, 'attrib', 'd41/d922/n499', None), (True, 'attrib', 'n28', None), (True, 'move', 'z/t188', 'z/d609'),
		(False, 'move', 'z/d609', 'n929'), (True, 'move', 'n929', 'z/t188'), (False, 'move', 'd41/d922/t281', 'd41/d922/n499'),
		(False, 'move', 'd41/d922/n499', 'n929/l741'), (False, 'move', 'n929/l741', 'd41/d922/t281'), only_sync_attributes=only_sync_attributes)
	assert_version_is_the_tree(job, v1)


@pytest.mark.parametrize('verify', [False, True])
def test_a_folder_moved_into_a_new_folder_where_one_moved_away(job, logged, verify):
	# mv n n.old; mkdir n; mv d n/d: the move falls back to a copy, which must not leave n/d out as a move target
	seed_monitor(job, {'n/x': 'x', **{f'd/f{i}': str(i) for i in range(3)}})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/n', f'{m}/n.old')
	os.mkdir(f'{m}/n')
	os.rename(f'{m}/d', f'{m}/n/d')
	events = ((True, 'move', 'n.old', 'n'), (True, 'create', 'n', None), (True, 'move', 'n/d', 'd'))
	v1 = verified(job, *events) if verify else run_backup(job, batch(job, *events))[-1]
	assert_version_is_the_tree(job, v1)
	assert not [line for line in logged if 'treating as create' in line]


@pytest.mark.parametrize('verify', [False, True])
def test_a_changed_file_moved_into_a_folder_moved_then_removed(job, logged, verify):
	# echo new > a; mv a d/a; mv d e; rm -r e: the modify the move became is carried to e/a, which is gone
	seed_monitor(job, {'a': 'a', 'd/keep': 'k', 'z': 'z'})
	run_backup(job)
	m = job.monitor
	with open(f'{m}/a', 'w') as f:
		f.write('new')
	os.rename(f'{m}/a', f'{m}/d/a')
	os.rename(f'{m}/d', f'{m}/e')
	os.remove(f'{m}/e/a')
	os.remove(f'{m}/e/keep')
	os.rmdir(f'{m}/e')
	events = ((False, 'modify', 'a', None), (False, 'move', 'd/a', 'a'), (True, 'move', 'e', 'd'),
		(False, 'delete', 'e/a', None), (False, 'delete', 'e/keep', None), (True, 'delete', 'e', None))
	v1 = verified(job, *events) if verify else run_backup(job, batch(job, *events))[-1]
	assert_version_is_the_tree(job, v1)
	assert_moved_cleanly(logged)


class NothingSkipped:
	'''A skip list with a pattern that skips nothing, so the size estimate walks folders instead of running du.'''
	def __init__(self, monitor):
		self.monitor = monitor
	def __bool__(self):
		return True
	def skips(self, rel):
		return False
	def folder_rel(self, path):
		rel = os.path.relpath(path, self.monitor)
		return '' if rel == '.' else rel.rstrip('/') + '/'


def test_the_estimate_leaves_a_move_inside_another_out_once(job):
	# mkdir n; echo > n/own; mv d n/d; mv y n/d/y: both moves land in the new n, the second inside the first
	seed_monitor(job, {'d/f': 'd' * 200000, 'y': 'y' * 300000, 'keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.mkdir(f'{m}/n')
	with open(f'{m}/n/own', 'w') as f:
		f.write('o' * 100000)
	os.rename(f'{m}/d', f'{m}/n/d')
	os.rename(f'{m}/y', f'{m}/n/d/y')
	entries = batch(job, (True, 'create', 'n', None), (False, 'create', 'n/own', None), (True, 'move', 'n/d', 'd'), (False, 'move', 'n/d/y', 'y'))
	size, inodes = rv.get_backup_size_inode(entries, True, rv.list_versions(job.job_vault)[-1].path, m, NothingSkipped(m))
	assert (size, inodes) == (os.lstat(f'{m}/n/own').st_blocks * 512 + os.lstat(f'{m}/n').st_blocks * 512, 2)


def test_touching_a_file_syncs_its_times_onto_the_copy(job, logged, monkeypatch):
	# touch -m, three times: the row's record vouches for the copy's contents, so nothing is copied
	seed_monitor(job, {'big': 'x' * 300000, 'keep': 'k'})
	v0 = run_backup(job)[0]
	run_backup(job)
	m = job.monitor
	copies = copies_made(monkeypatch)
	for n in range(1, 4):
		os.utime(f'{m}/big', ns=(n * 10 ** 18, n * 10 ** 18))
		version = verified(job, (False, 'attrib', 'big', None))
		end = resolved(job, version, 'big')
		assert copies == [] and end == os.path.join(v0, 'big') and os.lstat(end).st_mtime_ns == n * 10 ** 18
	assert_moved_cleanly(logged)


def test_an_attrib_that_copies_is_counted_by_the_estimate(job, logged):
	# the swap's stale link of E: the chmod of b copies it, and the estimate counts that copy
	seed_monitor(job, {'a': 'a' * 200000, 'b': 'b' * 300000})
	m = job.monitor
	os.utime(f'{m}/a', ns=(10 ** 18, 10 ** 18))
	os.utime(f'{m}/b', ns=(2 * 10 ** 18, 2 * 10 ** 18))
	run_backup(job)
	os.rename(f'{m}/a', f'{m}/t')
	os.rename(f'{m}/b', f'{m}/a')
	os.rename(f'{m}/t', f'{m}/b')
	run_backup(job, batch(job, (False, 'move', 't', 'a'), (False, 'move', 'a', 'b'), (False, 'move', 'b', 't')))
	os.chmod(f'{m}/b', 0o600)
	entries = batch(job, (False, 'attrib', 'b', None))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		latest = rv.list_versions(job.job_vault)[-1].path
		copied = rv.attribs_to_copy(entries, manifest, m, job.job_vault, latest)
		size, _ = rv.get_backup_size_inode(entries, True, latest, m, copied=copied)
		assert copied == {f'{m}/b'} and size >= 200000
		assert rv.batch_rewrites(entries, m, True, ['b'], copied)[0] == {'b'}
	finally:
		manifest.close()
