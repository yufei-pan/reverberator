import errno
import mmap
import threading
import os
import shutil
import sqlite3
import stat
import struct
import sys
import time
from collections import deque

import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, wait_for_committed_count, latest_version, committed_versions

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
	def spy(source_file, backup_file_path, *args):
		calls.append(os.path.abspath(backup_file_path))
		return real(source_file, backup_file_path, *args)
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
	# b/c1 → b/c1.1 renames what the fallback copy of b put at b/c1; the verification compares the moved row in full
	assert not [line for line in logged if 'Failed to move' in line]


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


def test_touching_a_file_copies_it(job, logged, monkeypatch):
	# touch -m, three times: the mtime moved, as an mmap write moves it, so the file is copied each time, and the older
	# versions keep their copy's mtime
	seed_monitor(job, {'big': 'x' * 300000, 'keep': 'k'})
	v0 = run_backup(job)[0]
	run_backup(job)
	m = job.monitor
	kept = os.lstat(os.path.join(v0, 'big')).st_mtime_ns
	copies = copies_made(monkeypatch)
	for n in range(1, 4):
		os.utime(f'{m}/big', ns=(n * 10 ** 18, n * 10 ** 18))
		version = verified(job, (False, 'attrib', 'big', None))
		entry = os.path.join(version, 'big')
		assert len(copies) == n and not os.path.islink(entry) and os.lstat(entry).st_mtime_ns == n * 10 ** 18
	assert os.lstat(os.path.join(v0, 'big')).st_mtime_ns == kept
	assert_moved_cleanly(logged)


def test_bytes_written_through_mmap_then_a_chmod_reach_the_version(job, logged):
	seed_monitor(job, {'mm': 'a' * 200000, 'keep': 'k'})          # bigger than the hashed tail, so the head's bytes are unseen by it
	m = job.monitor
	os.utime(f'{m}/mm', ns=(10 ** 18, 10 ** 18))
	run_backup(job)
	run_backup(job)
	with open(f'{m}/mm', 'r+b') as f, mmap.mmap(f.fileno(), 0) as mapped:
		mapped[:4] = b'MMAP'
		mapped.flush()
	assert os.lstat(f'{m}/mm').st_mtime_ns != 10 ** 18          # an mmap store moves the mtime, and raises no event
	os.chmod(f'{m}/mm', 0o600)
	version = verified(job, (False, 'attrib', 'mm', None))
	end = resolved(job, version, 'mm')
	assert open(end).read(4) == 'MMAP' and mode(end) == 0o600
	count = len(committed_versions(job))
	assert len(run_backup(job)) == count                          # the next full comparison finds nothing more


def test_a_recopied_file_written_through_mmap_then_moved_reaches_the_version(job, logged, monkeypatch):
	# the chain-length rule re-copies mm into this version as a real file holding the old bytes and mtime: the move step
	# must not put the moved mtime on them, as the verification would then find them matching from then on
	monkeypatch.setattr(rv, 'DEFAULT_CHAIN_LENGTH', 3)
	seed_monitor(job, {'mm': 'a' * 200000, 'keep': 'k'})
	m = job.monitor
	os.utime(f'{m}/mm', ns=(10 ** 18, 10 ** 18))
	v0 = run_backup(job)[0]
	run_backup(job)
	with open(f'{m}/keep', 'w') as f:
		f.write('k2')
	verified(job, (False, 'modify', 'keep', None))
	with open(f'{m}/mm', 'r+b') as f, mmap.mmap(f.fileno(), 0) as mapped:
		mapped[:4] = b'MMAP'
		mapped.flush()
	os.rename(f'{m}/mm', f'{m}/mm2')
	version = verified(job, (False, 'move', 'mm2', 'mm'))
	assert any('Copied 1 of 1 files again from the vault' in line for line in logged)
	assert open(resolved(job, version, 'mm2')).read(4) == 'MMAP'
	count = len(committed_versions(job))
	run_backup(job)
	assert len(committed_versions(job)) == count                  # a full comparison finds nothing more
	assert open(resolved(job, committed_versions(job)[-1], 'mm2')).read(4) == 'MMAP'
	assert open(os.path.join(v0, 'mm')).read(4) == 'aaaa'


def test_a_record_vouches_only_while_the_mtime_is_the_recorded_one(job):
	seed_monitor(job, {'x': 'x' * 1000})
	v0 = run_backup(job)[0]
	run_backup(job)
	m = job.monitor
	manifest = rv.VaultManifest(job.job_vault)
	try:
		record = manifest.lookup('x')
		os.chmod(f'{m}/x', 0o600)
		assert rv.record_vouches(record, f'{m}/x') and rv.record_vouches(record, f'{m}/x', os.path.join(v0, 'x'))
		os.utime(f'{m}/x', ns=(10 ** 18, 10 ** 18))
		assert not rv.record_vouches(record, f'{m}/x') and not rv.record_vouches(record, f'{m}/x', os.path.join(v0, 'x'))
	finally:
		manifest.close()


def test_a_touch_is_counted_by_the_estimate(job):
	seed_monitor(job, {'big': 'b' * 300000, 'keep': 'k'})
	run_backup(job)
	run_backup(job)
	m = job.monitor
	os.utime(f'{m}/big', ns=(10 ** 18, 10 ** 18))
	entries = batch(job, (False, 'attrib', 'big', None))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		latest = rv.list_versions(job.job_vault)[-1].path
		copied = rv.attribs_to_copy(entries, manifest, m, job.job_vault, latest)
		size, _ = rv.get_backup_size_inode(entries, True, latest, m, copied=copied)
	finally:
		manifest.close()
	assert copied == {f'{m}/big'} and size >= 300000
	assert rv.batch_rewrites(entries, m, True, ['big'], copied)[0] == {'big'}


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


# ---- fix round 4 --------------------------------------------------------------------------------------------------

def test_an_attrib_after_chained_moves_is_counted_by_the_estimate(job):
	# mv d x; mv x/m a; touch -m a/big: the latest version has a/big at d/m/big, two moves back, and its chain end there
	# holds another mtime, so the attribute change copies it
	seed_monitor(job, {'d/m/big': 'b' * 300000, 'd/keep': 'k', 'keep': 'k'})
	run_backup(job)
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/d', f'{m}/x')
	os.rename(f'{m}/x/m', f'{m}/a')
	os.utime(f'{m}/a/big', ns=(10 ** 18, 10 ** 18))
	entries = batch(job, (True, 'move', 'x', 'd'), (True, 'move', 'a', 'x/m'), (False, 'attrib', 'a/big', None))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		latest = rv.list_versions(job.job_vault)[-1].path
		copied = rv.attribs_to_copy(entries, manifest, m, job.job_vault, latest)
		size, _ = rv.get_backup_size_inode(entries, True, latest, m, copied=copied)
	finally:
		manifest.close()
	assert copied == {f'{m}/a/big'} and size >= 300000


def user_xattrs_or_skip(path):
	try:
		os.setxattr(path, 'user.probe', b'1')
	except OSError as e:
		if e.errno in (errno.ENOTSUP, errno.EPERM):
			pytest.skip('user xattrs are unsupported here')
		raise
	os.removexattr(path, 'user.probe')


@pytest.mark.parametrize('rel', ['x', 'd/'])
def test_a_removed_xattr_is_gone_from_the_newest_version(job, logged, rel):
	# setfattr -x user.k: the sync leaves the copy, or the version's folder, with the monitored entry's xattrs only
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	m = job.monitor
	path = os.path.join(m, rel.rstrip('/'))
	user_xattrs_or_skip(path)
	os.setxattr(path, 'user.k', b'v')
	os.setxattr(path, 'user.stays', b's')
	run_backup(job)
	os.removexattr(path, 'user.k')
	version = verified(job, (rel.endswith('/'), 'attrib', rel.rstrip('/'), None))
	got = rv.resolve_version_entry(job.job_vault, version, rel.rstrip('/'), m)
	assert got.kind in ('file', 'folder') and os.listxattr(got.path) == ['user.stays']
	assert_moved_cleanly(logged)


def test_a_removed_xattr_then_a_move_is_gone_from_the_newest_version(job, logged):
	# setfattr -x user.k x; mv x d/x ( fuzz seed 10 ): the move step syncs the moved file's metadata, the removal too
	seed_monitor(job, {'x': 'x', 'd/keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/x')
	os.setxattr(f'{m}/x', 'user.k', b'v')
	run_backup(job)
	os.removexattr(f'{m}/x', 'user.k')
	os.rename(f'{m}/x', f'{m}/d/x')
	version = verified(job, (False, 'attrib', 'x', None), (False, 'move', 'd/x', 'x'))
	assert os.listxattr(resolved(job, version, 'd/x')) == []
	assert_moved_cleanly(logged)


def access_acl(uid):
	# a POSIX access ACL as the kernel stores it in system.posix_acl_access: version 2, then (tag, perm, id) entries for
	# the owner, a named user, the group, the mask and others
	undefined = 0xffffffff
	entries = ((0x01, 6, undefined), (0x02, 6, uid), (0x04, 4, undefined), (0x10, 6, undefined), (0x20, 4, undefined))
	return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)


def test_a_removed_acl_is_gone_from_the_newest_version(job, logged):
	# setfacl -b x: an ACL is an extended attribute, which the sync removes from the shared copy too, so a restore does
	# not give the ACL back
	seed_monitor(job, {'x': 'x', 'keep': 'k'})
	m = job.monitor
	try:
		os.setxattr(f'{m}/x', 'system.posix_acl_access', access_acl(1234))
	except OSError as e:
		if e.errno in (errno.ENOTSUP, errno.EPERM):
			pytest.skip('POSIX ACLs are unsupported here')
		raise
	v0 = run_backup(job)[0]
	assert 'system.posix_acl_access' in os.listxattr(os.path.join(v0, 'x'))
	os.removexattr(f'{m}/x', 'system.posix_acl_access')
	version = verified(job, (False, 'attrib', 'x', None))
	assert 'system.posix_acl_access' not in os.listxattr(resolved(job, version, 'x'))
	assert_moved_cleanly(logged)


def test_a_file_row_where_a_folder_row_was_made_is_dropped(job, logged):
	# a vault whose rows hold both a file and a folder of one name ( fuzz seed 858 at 36b48f6 ): the referenced copy
	# makes the folder, drops the file's row with an error line, and the backup runs
	seed_monitor(job, {'keep': 'k', 'n/a': 'a'})
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.add('n')
	manifest.commit()
	manifest.close()
	m = job.monitor
	with open(f'{m}/keep', 'w') as f:
		f.write('k2')
	version = run_backup(job, batch(job, (False, 'modify', 'keep', None)))[-1]
	assert open(resolved(job, version, 'n/a')).read() == 'a'
	assert tracked(job, 'n/') and not tracked(job, 'n')
	assert [line for line in logged if line.startswith('ERROR Dropping tracked file n') and 'is a folder' in line]


# ---- fix round 5 --------------------------------------------------------------------------------------------------

def plant_rows(job, discard=(), add=()):
	'''Change the rows of the latest version, as an earlier daemon or a swap the collapse could not order left them.'''
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	for rel in discard:
		manifest.discard(rel)
	for rel in add:
		manifest.add(rel)
	manifest.commit()
	manifest.close()


@pytest.mark.parametrize('change', ['xattr', 'chmod'])
def test_a_change_carried_into_a_folder_made_in_the_batch_reaches_the_version(job, logged, change):
	# setfattr -n user.k0 d890/n356; mkdir n460; mv d890 n460/d890 ( fuzz seed 726 ), replayed alone: the create of n460
	# leaves n460/d890 to its move, so the carried change is replayed there
	seed_monitor(job, {'d890/n356': 'n', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/d890/n356')
	run_backup(job)
	if change == 'xattr':
		os.setxattr(f'{m}/d890/n356', 'user.k0', b'v')
	else:
		os.chmod(f'{m}/d890/n356', 0o600)
	os.mkdir(f'{m}/n460')
	os.rename(f'{m}/d890', f'{m}/n460/d890')
	v1 = run_backup(job, batch(job, (False, 'attrib', 'd890/n356', None), (True, 'create', 'n460', None), (True, 'move', 'n460/d890', 'd890')))[-1]
	end = resolved(job, v1, 'n460/d890/n356')
	if change == 'xattr':
		assert os.listxattr(end) == ['user.k0']
	else:
		assert mode(end) == 0o600
	assert_left_alone(v1, 'n460/d890/n356')
	assert_moved_cleanly(logged)


def test_a_change_after_a_move_into_a_folder_made_in_the_batch_reaches_the_version(job, logged):
	# mkdir n308; mv d433 n308/d433; setfattr -n user.k2 n308/d433/d902/c0 ( fuzz seed 991, batch 2 )
	seed_monitor(job, {'d433/d902/c0': 'c', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/d433/d902/c0')
	run_backup(job)
	os.mkdir(f'{m}/n308')
	os.rename(f'{m}/d433', f'{m}/n308/d433')
	os.setxattr(f'{m}/n308/d433/d902/c0', 'user.k2', b'v')
	v1 = run_backup(job, batch(job, (True, 'create', 'n308', None), (True, 'move', 'n308/d433', 'd433'), (False, 'attrib', 'n308/d433/d902/c0', None)))[-1]
	assert os.listxattr(resolved(job, v1, 'n308/d433/d902/c0')) == ['user.k2']
	assert_left_alone(v1, 'n308/d433/d902/c0')
	assert_moved_cleanly(logged)


def test_a_folder_made_inside_a_folder_moved_into_a_new_one_is_copied_once(job, logged, monkeypatch):
	# mkdir n; mv d n/d; mkdir n/d/s; echo f > n/d/s/f: the create of n/d/s copies n/d/s/f, and its own entry goes
	seed_monitor(job, {'d/keep': 'k', 'top': 't'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/d/keep')
	run_backup(job)
	os.setxattr(f'{m}/d/keep', 'user.k', b'v')
	os.mkdir(f'{m}/n')
	os.rename(f'{m}/d', f'{m}/n/d')
	os.mkdir(f'{m}/n/d/s')
	with open(f'{m}/n/d/s/f', 'w') as fh:
		fh.write('f')
	copies = copies_made(monkeypatch)
	v1 = run_backup(job, batch(job, (False, 'attrib', 'd/keep', None), (True, 'create', 'n', None), (True, 'move', 'n/d', 'd'),
		(True, 'create', 'n/d/s', None), (False, 'create', 'n/d/s/f', None), (False, 'modify', 'n/d/s/f', None)))[-1]
	assert open(resolved(job, v1, 'n/d/s/f')).read() == 'f'
	assert os.listxattr(resolved(job, v1, 'n/d/keep')) == ['user.k']
	assert copies == [os.path.join(v1, 'n/d/s/f')]
	assert_left_alone(v1, 'n/d/keep')
	assert_moved_cleanly(logged)


def test_a_file_row_over_a_folder_of_the_previous_version_is_dropped(job, logged):
	# rows hold the file n and the file n/a, and no folder n/, while V0 holds the folder n: n's row goes, so n is never
	# linked to V0's folder, and nothing is removed or linked through it into V0
	seed_monitor(job, {'keep': 'k', 'n/a': 'a'})
	v0 = run_backup(job)[0]
	plant_rows(job, discard=['n/'], add=['n'])
	before = os.lstat(os.path.join(v0, 'n/a'))
	with open(f'{job.monitor}/keep', 'w') as f:
		f.write('k2')
	version = run_backup(job, batch(job, (False, 'modify', 'keep', None)))[-1]
	after = os.lstat(os.path.join(v0, 'n/a'))
	assert stat.S_ISREG(after.st_mode) and after.st_ino == before.st_ino
	assert open(os.path.join(v0, 'n/a')).read() == 'a'
	assert open(resolved(job, version, 'n/a')).read() == 'a'
	assert not os.path.islink(os.path.join(version, 'n'))
	assert not tracked(job, 'n') and tracked(job, 'n/a')
	assert [line for line in logged if line.startswith('ERROR Dropping tracked file n') and 'is a folder' in line]


def test_a_folder_row_over_a_users_link_to_a_folder_is_dropped(job, logged):
	# a stale row of the folder L, where the version holds the user's link L to a folder: the link stays, as the tree has it
	seed_monitor(job, {'keep': 'k', 'sub/a': 'a'})
	m = job.monitor
	os.symlink('sub', f'{m}/L')
	run_backup(job)
	plant_rows(job, add=['L/'])
	with open(f'{m}/keep', 'w') as f:
		f.write('k2')
	version = run_backup(job, batch(job, (False, 'modify', 'keep', None)))[-1]
	got = rv.resolve_version_entry(job.job_vault, version, 'L', m)
	assert got.kind == 'symlink' and os.readlink(got.path) == 'sub'
	assert tracked(job, 'L') and not tracked(job, 'L/')
	assert [line for line in logged if line.startswith('ERROR Dropping tracked folder') and 'L/' in line]


def test_the_referenced_copy_looks_nothing_up_in_the_new_version_for_a_file(job, monkeypatch):
	# a vault on mergerfs keeps no negative lookups ( cache.negative_entry=0 ): one per tracked file is seconds a backup
	seed_monitor(job, {f'd/f{i}': str(i) for i in range(50)})
	v0 = run_backup(job)[0]
	inside = []
	real_copy = rv.do_referenced_copy
	def copying(*args, **kwargs):
		inside.append(True)
		try:
			return real_copy(*args, **kwargs)
		finally:
			inside.pop()
	monkeypatch.setattr(rv, 'do_referenced_copy', copying)
	looked = []
	def by_the_daemon():
		# called from reverberator.py, or from os.path called from it: not the chain ground truth's own lstat of each link
		frame = sys._getframe(2)
		if frame.f_globals.get('__name__') in ('genericpath', 'posixpath'):
			frame = frame.f_back
		return frame.f_code.co_filename == rv.__file__
	def spy(real):
		def look(path, *args, **kwargs):
			name = os.fsdecode(path) if isinstance(path, (str, bytes)) else ''
			if inside and name.startswith(job.job_vault) and not name.startswith(v0) and by_the_daemon():
				looked.append(name)
			return real(path, *args, **kwargs)
		return look
	monkeypatch.setattr(os, 'stat', spy(os.stat))
	monkeypatch.setattr(os, 'lstat', spy(os.lstat))
	with open(f'{job.monitor}/d/f0', 'w') as f:
		f.write('changed')
	run_backup(job, batch(job, (False, 'modify', 'd/f0', None)))
	assert len(looked) < 10, looked


def test_a_monitored_filesystem_without_xattrs_strips_none_from_the_vault(job, logged, monkeypatch):
	# listxattr answers ENOTSUP for the monitored tree ( a mergerfs pool switched to xattr=nosys ): the vault's copy,
	# V0's too, keeps its xattrs ( Samba's user.DOSATTRIB, say ), as copystat leaves them
	seed_monitor(job, {'x': 'x', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/x')
	os.setxattr(f'{m}/x', 'user.k', b'v')
	v0 = run_backup(job)[0]
	real = os.listxattr
	def unsupported(path, *args, **kwargs):
		if os.fsdecode(path).startswith(m):
			raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP), path)
		return real(path, *args, **kwargs)
	monkeypatch.setattr(os, 'listxattr', unsupported)
	os.chmod(f'{m}/x', 0o600)
	version = verified(job, (False, 'attrib', 'x', None))
	assert real(os.path.join(v0, 'x')) == ['user.k']
	assert mode(resolved(job, version, 'x')) == 0o600
	assert_moved_cleanly(logged)


def test_an_xattr_set_before_its_folder_moved_onto_an_emptied_folder_reaches_the_version(job, logged):
	# setfattr -n user.k1 d816/d399/c0; rm d781/d324/*; mv d816/d399 d781/d324 ( fuzz seed 996 ), replayed alone: the
	# deletes came before the move, so they end nothing it carried to d781/d324/c0
	seed_monitor(job, {'d816/d399/c0': 'new', 'd781/d324/c0': 'old', 'd781/d324/c1': 'c1', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/d816/d399/c0')
	run_backup(job)
	os.setxattr(f'{m}/d816/d399/c0', 'user.k1', b'v')
	os.remove(f'{m}/d781/d324/c0')
	os.remove(f'{m}/d781/d324/c1')
	os.rename(f'{m}/d816/d399', f'{m}/d781/d324')
	entries = batch(job, (False, 'attrib', 'd816/d399/c0', None), (False, 'delete', 'd781/d324/c0', None),
		(False, 'delete', 'd781/d324/c1', None), (True, 'move', 'd781/d324', 'd816/d399'))
	assert entries[f'{m}/d781/d324/c0'].event == 'attrib'
	v1 = run_backup(job, entries)[-1]
	end = resolved(job, v1, 'd781/d324/c0')
	assert open(end).read() == 'new' and os.listxattr(end) == ['user.k1']
	assert sorted(os.listdir(os.path.join(v1, 'd781/d324'))) == ['c0']
	assert_left_alone(v1, 'd781/d324/c0')
	assert_moved_cleanly(logged)


def test_a_change_carried_where_a_move_before_it_landed_is_fixed_by_the_verification(job, logged):
	# chmod D/c0; mv q F/c0; mv F G; mv D F: the move into F/c0 came before the move that carried the chmod there, and
	# the replay still needs it ( G/c0 is q ), so the carried attrib yields to it, and the verification syncs the mode
	seed_monitor(job, {'D/c0': 'd', 'q': 'q', 'F/': None, 'keep': 'k'})
	m = job.monitor
	run_backup(job)
	os.chmod(f'{m}/D/c0', 0o600)
	os.rename(f'{m}/q', f'{m}/F/c0')
	os.rename(f'{m}/F', f'{m}/G')
	os.rename(f'{m}/D', f'{m}/F')
	version = verified(job, (False, 'attrib', 'D/c0', None), (False, 'move', 'F/c0', 'q'), (True, 'move', 'G', 'F'), (True, 'move', 'F', 'D'))
	assert_version_is_the_tree(job, version)
	assert mode(resolved(job, version, 'F/c0')) == 0o600
	assert open(resolved(job, version, 'G/c0')).read() == 'q'


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_the_verification_syncs_xattrs_the_replay_missed(job, logged, only_sync_attributes):
	# the batch lost the setfattr events ( a race ): the verification compares the xattrs of what the batch changed, and
	# syncs them as an attrib's replay does, a removed one too
	seed_monitor(job, {'D/a': 'a', 'D/b': 'b', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/D/a')
	os.setxattr(f'{m}/D/a', 'user.gone', b'g')
	run_backup(job, only_sync_attributes=only_sync_attributes)
	os.rename(f'{m}/D', f'{m}/D2')
	os.setxattr(f'{m}/D2/a', 'user.new', b'n')
	os.removexattr(f'{m}/D2/a', 'user.gone')
	version = verified(job, (True, 'move', 'D2', 'D'), only_sync_attributes=only_sync_attributes)
	end = resolved(job, version, 'D2/a')
	assert os.listxattr(end) == ['user.new'] and open(end).read() == 'a'
	assert os.path.islink(os.path.join(version, 'D2/a')) == only_sync_attributes
	assert_left_alone(version, 'D2/b')
	assert_moved_cleanly(logged)


def test_the_verification_reads_the_xattrs_of_entries_the_batch_changed_only(job, logged, monkeypatch):
	# a folder moved: its files keep their ctimes, so only the folder's own xattrs are compared, not one pair per file
	seed_monitor(job, {f'D/f{i}': str(i) for i in range(20)})
	m = job.monitor
	run_backup(job)
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', 0.25)
	time.sleep(0.5)
	taken = time.monotonic()
	os.rename(f'{m}/D', f'{m}/E')
	compared = []
	real = rv.xattrs_differ
	def spy(monitor_entry, vault_entry):
		compared.append(monitor_entry)
		return real(monitor_entry, vault_entry)
	monkeypatch.setattr(rv, 'xattrs_differ', spy)
	events = deque([rv.ChangeEvent(taken, True, 'move', f'{m}/E', f'{m}/D')])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), m), touched=rv.touched_scopes(events, m))
	assert compared == [f'{m}/E/']
	assert_moved_cleanly(logged)


# --- the final fix wave of round 9 ---

def listing_enodata(monkeypatch, root, name='security.capability'):
	'''os.listxattr also lists name for every entry under root, whose os.getxattr answers ENODATA, as mergerfs with
	security_capability=false does for security.capability.'''
	real_list, real_get = os.listxattr, os.getxattr
	def under(path):
		path = os.fsdecode(path)
		return path == root or path.startswith(root + '/')
	def listing(path, *args, **kwargs):
		names = real_list(path, *args, **kwargs)
		return names + [name] if under(path) else names
	def getting(path, attribute, *args, **kwargs):
		if attribute == name and under(path):
			raise OSError(errno.ENODATA, os.strerror(errno.ENODATA), path)
		return real_get(path, attribute, *args, **kwargs)
	monkeypatch.setattr(os, 'listxattr', listing)
	monkeypatch.setattr(os, 'getxattr', getting)


def test_xattrs_differ_skips_a_listed_name_that_has_no_value(job, monkeypatch):
	seed_monitor(job, {'x': 'x'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/x')
	os.setxattr(f'{m}/x', 'user.k', b'v')
	v0 = run_backup(job)[0]
	listing_enodata(monkeypatch, m)
	assert rv.xattrs_differ(f'{m}/x', os.path.join(v0, 'x')) is False
	os.setxattr(f'{m}/x', 'user.k', b'w')
	assert rv.xattrs_differ(f'{m}/x', os.path.join(v0, 'x')) is True


def test_a_listed_xattr_without_a_value_copies_no_moved_folder(job, logged, monkeypatch):
	# a folder moved on a mergerfs pool that lists security.capability and answers ENODATA for it: its xattrs compare
	# equal, so its tree is not copied again
	seed_monitor(job, {'D/a': 'a', 'D/b': 'b', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/D/a')
	run_backup(job)
	listing_enodata(monkeypatch, m)
	copies = copies_made(monkeypatch)
	os.rename(f'{m}/D', f'{m}/E')
	version = verified(job, (True, 'move', 'E', 'D'))
	assert copies == []
	assert not [line for line in logged if 'treating as modify' in line]
	assert_left_alone(version, 'E/a')
	assert_left_alone(version, 'E/b')


class SteppedClock:
	'''The time module, with a wall clock step seconds ahead of the real one.'''
	def __init__(self, step):
		self.step = step
	def __getattr__(self, name):
		return getattr(time, name)
	def time_ns(self):
		return time.time_ns() + int(self.step * 10 ** 9)
	def time(self):
		return time.time() + self.step


def test_an_xattr_changed_5_s_before_its_batchs_first_event_is_compared(job, logged):
	# chrony steps the clock forward by a second or two right after boot: an entry the batch changed can have a ctime up
	# to VERIFY_CTIME_MARGIN_SECONDS (10 s) before its batch's first event, and its xattrs are still compared
	seed_monitor(job, {'D/a': 'a', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/D/a')
	run_backup(job)
	os.rename(f'{m}/D', f'{m}/D2')
	os.setxattr(f'{m}/D2/a', 'user.new', b'n')
	events = deque([rv.ChangeEvent(time.monotonic() + 5, True, 'move', f'{m}/D2', f'{m}/D')])
	version = run_backup(job, rv.change_events_to_backup_entries(deque(events), m), touched=rv.touched_scopes(events, m))[-1]
	assert os.listxattr(resolved(job, version, 'D2/a')) == ['user.new']
	assert_moved_cleanly(logged)


def test_the_queue_stamps_the_wall_clock_time_of_a_batchs_first_event():
	queue = rv.ChangeEventQueue('/m')
	assert queue.first_wall_ns is None
	before = time.time_ns()
	queue.append(rv.ChangeEvent(1.0, False, 'modify', '/m/a', None))
	stamp = queue.first_wall_ns
	assert before <= stamp <= time.time_ns()
	queue.append(rv.ChangeEvent(2.0, False, 'modify', '/m/b', None))
	assert queue.first_wall_ns == stamp
	taken = queue.take()
	assert taken.first_wall_ns == stamp and queue.first_wall_ns is None
	assert rv.touched_scopes(taken, '/m').changed_since_wall == stamp


def test_the_ctime_bound_is_the_earlier_of_the_two_clocks(monkeypatch):
	margin = rv.VERIFY_CTIME_MARGIN_SECONDS * 10 ** 9
	now = time.time_ns()
	# a wall clock that stepped forward a minute after the first event: the first event's wall time is the earlier
	monkeypatch.setattr(rv, 'time', SteppedClock(60))
	assert abs(rv.ctime_bound(time.monotonic(), now) - (now - margin)) < 10 ** 8
	# one that stepped back a minute: now less the time since the first event is the earlier
	monkeypatch.setattr(rv, 'time', SteppedClock(-60))
	assert abs(rv.ctime_bound(time.monotonic(), now) - (now - 60 * 10 ** 9 - margin)) < 10 ** 8
	# a full comparison's bound is a wall time alone
	assert rv.ctime_bound(None, now) == now - margin
	assert rv.ctime_bound(float('-inf'), now) == 0 and rv.ctime_bound(None) is None


def test_an_xattr_changed_before_a_forward_clock_step_is_compared(job, logged, monkeypatch):
	# the wall clock steps forward a minute between the batch's first event and its verification: the bound is the first
	# event's wall time, so the xattr the batch lost is still synced
	seed_monitor(job, {'D/a': 'a', 'keep': 'k'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/D/a')
	run_backup(job)
	os.rename(f'{m}/D', f'{m}/D2')
	os.setxattr(f'{m}/D2/a', 'user.new', b'n')
	queue = rv.ChangeEventQueue(m)
	queue.append(rv.ChangeEvent(time.monotonic(), True, 'move', f'{m}/D2', f'{m}/D'))
	taken = queue.take()
	monkeypatch.setattr(rv, 'time', SteppedClock(60))
	version = run_backup(job, rv.change_events_to_backup_entries(taken, m), touched=rv.touched_scopes(taken, m))[-1]
	assert os.listxattr(resolved(job, version, 'D2/a')) == ['user.new']
	assert_moved_cleanly(logged)


@pytest.mark.parametrize('only_sync_attributes', [True, False])
def test_a_full_comparison_syncs_an_xattr_set_while_nothing_watched(job, logged, only_sync_attributes):
	# setfattr right after the daemon starts, before its watches are in place ( race_xattr.py ): the comparison at the
	# start reads the xattrs of the entries changed since the version before the latest, by their ctime
	seed_monitor(job, {'x': 'x', 'y': 'y'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/x')
	run_backup(job, only_sync_attributes=only_sync_attributes)
	os.setxattr(f'{m}/x', 'user.race', b'r')
	versions = run_backup(job, only_sync_attributes=only_sync_attributes)
	assert len(versions) == 2
	end = resolved(job, versions[-1], 'x')
	assert os.listxattr(end) == ['user.race'] and open(end).read() == 'x'
	assert_left_alone(versions[-1], 'y')
	assert_moved_cleanly(logged)


class Killed(BaseException):
	pass


def test_a_killed_commit_then_a_restart_drops_an_xattr_the_user_removed(job, logged, monkeypatch):
	# setfattr -x user.gone x; the backup of its attrib is killed before its replay; at the restart the whole tree is
	# compared ( extra_xattr.py ): the xattr is gone from the new version
	seed_monitor(job, {'x': 'x', 'y': 'y'})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/x')
	os.setxattr(f'{m}/x', 'user.gone', b'g')
	run_backup(job)
	os.removexattr(f'{m}/x', 'user.gone')
	def killed(*args, **kwargs):
		raise Killed()
	with monkeypatch.context() as patched:
		patched.setattr(rv, 'do_reverb_backup', killed)
		with pytest.raises(Killed):
			rv.do_backup(batch(job, (False, 'attrib', 'x', None)), job_name=job.job_name, monitor_path=m, vault_path=job.vault,
				keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	rv.VERSION_MOVES.clear()
	rv.REAL_VAULT_FOLDERS.clear()
	versions = run_backup(job)
	assert len(versions) == 2
	assert os.listxattr(resolved(job, versions[-1], 'x')) == []


def test_a_full_comparison_reads_the_xattrs_of_recently_changed_entries_only(job, monkeypatch):
	# entries whose ctime is before the bound cost one compare of numbers each, and no xattr read
	seed_monitor(job, {f'f{i}': str(i) for i in range(20)})
	m = job.monitor
	user_xattrs_or_skip(f'{m}/f0')
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', 0.25)
	time.sleep(1.5)
	run_backup(job)
	os.setxattr(f'{m}/f3', 'user.k', b'v')
	compared = []
	real = rv.xattrs_differ
	def spy(monitor_entry, vault_entry):
		compared.append(monitor_entry)
		return real(monitor_entry, vault_entry)
	monkeypatch.setattr(rv, 'xattrs_differ', spy)
	versions = run_backup(job)
	assert compared == [f'{m}/f3']
	assert os.listxattr(resolved(job, versions[-1], 'f3')) == ['user.k']


def nested_swap(job):
	'''
	Fuzz seed 1358, batch 4: two folders swapped, P and x/Q, then a file inside the one now at x/Q swapped with the one now
	at P ( P/s/f is a file, and it ends at P; what was x/Q ends at x/Q/s/f ). Returns the watcher's events.
	'''
	m = job.monitor
	os.rename(f'{m}/P', f'{m}/t')
	os.rename(f'{m}/x/Q', f'{m}/P')
	os.rename(f'{m}/t', f'{m}/x/Q')
	os.rename(f'{m}/x/Q/s/f', f'{m}/x/Q/s/t2')
	os.rename(f'{m}/P', f'{m}/x/Q/s/f')
	os.rename(f'{m}/x/Q/s/t2', f'{m}/P')
	return ((True, 'move', 't', 'P'), (True, 'move', 'P', 'x/Q'), (True, 'move', 'x/Q', 't'),
		(False, 'move', 'x/Q/s/t2', 'x/Q/s/f'), (True, 'move', 'x/Q/s/f', 'P'), (False, 'move', 'P', 'x/Q/s/t2'))


NESTED_TREE = {'P/s/f': 'F', 'P/pk': 'pk', 'x/Q/qk': 'qk', 'keep': 'k'}


@pytest.mark.parametrize('verify', [False, True])
def test_a_folder_moved_into_a_folder_moved_onto_its_place_commits_its_batch(job, logged, verify):
	# the collapse moves P onto x/Q first, so the move of what was x/Q to x/Q/s/f finds a folder to be moved into itself,
	# and falls back to delete & copy: the delete of x/Q goes first, then the copy, which is not removed under it
	seed_monitor(job, NESTED_TREE)
	run_backup(job)
	events = nested_swap(job)
	if verify:
		version = verified(job, *events)
		assert_version_is_the_tree(job, version)
	else:
		version = run_backup(job, batch(job, *events))[-1]
	assert open(resolved(job, version, 'P')).read() == 'F'
	assert open(resolved(job, version, 'x/Q/s/f/qk')).read() == 'qk'


def test_a_failed_batch_is_followed_by_a_full_comparison_in_the_job_loop(job, monkeypatch, capsys):
	# fuzz seed 1358 in the daemon's own retry loop: the batch's attempt fails ( a copy into the vault failing once, as
	# the delete & copy of its nested move did at c4b0e30 ), the job is retried, and its next attempt compares the
	# whole tree instead of replaying the batch it handed back, which commits a version that is the tree
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	seed_monitor(job, NESTED_TREE)
	run_backup(job)
	m = job.monitor
	attempts = []
	def watcher(monitor_fs_flag, monitor_path, to_process, to_process_lock, to_process_flag, irm, low, high, startup, control, signature):
		# the watcher's part of a start: its watches are in place once the skip list is loaded; on the first attempt the
		# batch comes once the comparison at the start has committed
		attempts.append(control)
		while control.should_run() and not startup.loaded.is_set():
			time.sleep(0.01)
		startup.watching.set()
		if len(attempts) == 1:
			while control.should_run() and not control.committed.is_set():
				time.sleep(0.01)
			events = nested_swap(job)
			with to_process_lock:
				for is_dir, event, rel, source in events:
					to_process.append(rv.ChangeEvent(time.monotonic(), is_dir, event, f'{m}/{rel}', None if source is None else f'{m}/{source}'))
			to_process_flag.set()
		while control.should_run():
			time.sleep(0.01)
	monkeypatch.setattr(rv, 'watcher', watcher)
	backups = []
	real_backup = rv.do_backup
	def backup(entries, **kwargs):
		# a whole comparison is a backup of no entries for no touched places
		backups.append('batch' if entries or kwargs.get('touched') is not None else 'whole')
		return real_backup(entries, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', backup)
	real_replay = rv.do_reverb_backup
	def replay(*args, **kwargs):
		if backups.count('batch') == 1 and not replay.failed:
			replay.failed = True
			raise rv.JobFailure(f'copying {m}/P into the vault failed: cp: No such file or directory')
		return real_replay(*args, **kwargs)
	replay.failed = False
	monkeypatch.setattr(rv, 'do_reverb_backup', replay)
	to_process, lock, flag, ready = rv.ChangeEventQueue(m), threading.Lock(), threading.Event(), threading.Event()
	ready.set()
	start_attempt = rv.job_attempt_starter(job.job_name, (job.job_name, m), (ready, m, to_process, lock, flag, None, 1, 1),
		(job.job_name, to_process, lock, m, job.vault, 'N/A', flag, ready, True, True, 0, '0', False))
	control = rv.JobControl(job.job_name)
	supervisor = threading.Thread(target=lambda: rv.run_job(control, start_attempt), daemon=True)
	supervisor.start()
	try:
		wait_for_committed_count(job, 2, timeout=30)
	finally:
		rv.GREEN_LIGHT.clear()
		supervisor.join(timeout=10)
		rv.GREEN_LIGHT.set()
	assert not supervisor.is_alive()
	text = capsys.readouterr().out
	assert f'reverberator job {job.job_name} FAILED: ' in text and 'RECOVERED after 1 failed attempts' in text
	# each start compares the whole tree: the batch handed back is not replayed again
	assert backups == ['whole', 'batch', 'whole']
	assert len(attempts) == 2 and len(committed_versions(job)) == 2
	assert_version_is_the_tree(job, latest_version(job).path)


def test_an_attrib_whose_record_vouches_reads_no_vault_copy(job, logged, monkeypatch):
	# chown -R over many files: each file's record vouches for its copy, so only the live file is read, never the
	# vault copy's tail
	seed_monitor(job, {'x': 'x' * 100000, 'keep': 'k'})
	m = job.monitor
	run_backup(job)
	os.chmod(f'{m}/x', 0o600)
	read = []
	real = rv.same_contents
	def spy(source_path, path):
		read.append(path)
		return real(source_path, path)
	monkeypatch.setattr(rv, 'same_contents', spy)
	version = run_backup(job, batch(job, (False, 'attrib', 'x', None)))[-1]
	assert read == []
	assert mode(resolved(job, version, 'x')) == 0o600 and os.path.islink(os.path.join(version, 'x'))
	assert_moved_cleanly(logged)


def test_a_batch_of_deletes_the_vault_does_not_track_makes_no_version(job, logged):
	# the carried move-out: its delete names a path no version holds
	seed_monitor(job, {'a.txt': 'a'})
	count = len(run_backup(job))
	verified(job, (False, 'delete', 'gone.txt', None), (True, 'delete', 'never', None))
	assert len(committed_versions(job)) == count
	assert any('Dropped 2 delete entries' in line for line in logged) and any('No differences' in line for line in logged)


def test_untracked_deletes_beside_a_change_leave_only_the_change(job, logged):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	seed_monitor(job, {'a.txt': 'a2'})
	version = verified(job, (False, 'delete', 'gone.txt', None), (False, 'modify', 'a.txt', None))
	rows = [(os.path.relpath(row.path, job.monitor), row.event) for row in rv.iter_change_list(rv.list_versions(job.job_vault)[-1].change_list)]
	assert rows == [('a.txt', 'modify')] and open(os.path.join(version, 'a.txt')).read() == 'a2'


def test_a_delete_of_a_folder_tracked_only_by_its_children_is_kept(job, logged):
	seed_monitor(job, {'d/x': 'x', 'keep': 'k'})
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.discard('d/')
	manifest.commit()
	manifest.close()
	shutil.rmtree(os.path.join(job.monitor, 'd'))
	version = verified(job, (True, 'delete', 'd', None))
	assert not os.path.lexists(os.path.join(version, 'd/x'))


def test_a_stale_manifest_keeps_untracked_deletes(job):
	seed_monitor(job, {'a.txt': 'a'})
	count = len(run_backup(job))
	conn = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None)
	try:
		conn.execute("UPDATE meta SET value = 'V99--stale' WHERE key = 'version'")
	finally:
		conn.close()
	verified(job, (False, 'delete', 'gone.txt', None))
	assert len(committed_versions(job)) == count + 1


def test_a_delete_of_a_tracked_symlink_is_kept(job, logged):
	seed_monitor(job, {'a.txt': 'a'})
	os.symlink('a.txt', os.path.join(job.monitor, 'ln'))
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.lookup('ln').kind == 'l'
	manifest.close()
	os.unlink(os.path.join(job.monitor, 'ln'))
	version = verified(job, (False, 'delete', 'ln', None))
	assert not os.path.lexists(os.path.join(version, 'ln')) and not any('Dropped' in line for line in logged)


def test_a_file_made_and_deleted_in_one_batch_makes_no_version(job, logged):
	# the collapse leaves a delete of the made file, or nothing: either way the vault holds no path of it
	seed_monitor(job, {'a.txt': 'a'})
	count = len(run_backup(job))
	verified(job, (False, 'create', 'tmp', None), (False, 'modify', 'tmp', None), (False, 'delete', 'tmp', None))
	assert len(committed_versions(job)) == count
