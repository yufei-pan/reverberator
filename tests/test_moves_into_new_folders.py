'''
A folder or file moved into a folder made in the same batch is a move, not a copy, driven through the real watchFolder on real
inotify: hand-built events are why 0.55 and before copied each such folder whole with nobody seeing it.
Each batch runs as the backuper runs it: collapsed, replayed, compared with what it touched.
'''
import contextlib
import errno
import os
import shutil
import threading
import time

import pytest

import reverberator as rv
from tests.harness import committed_versions, latest_version, run_backup, seed_monitor, wait_until
from tests.vault_oracle import read_view, snapshot_tree

pytestmark = pytest.mark.inotify

SEED = {'big/a': 'a' * 5000, 'big/sub/b': 'b' * 5000, 'f.txt': 'f' * 5000, 'g.txt': 'g' * 5000, 'other/': None}
# how the steps of a batch meet the watcher. apart: each read and handled on its own. at_once: as fast as Python goes.
# unread: all done before the watcher reads any, so a new folder has no watch yet and a move into it raises no MOVED_TO
TIMINGS = ('apart', 'at_once', 'unread')


class Session:
	'''A real watcher on job's monitor, with the batches it signals backed up.'''
	def __init__(self, job, monkeypatch, patterns=(), only_sync_attributes=True, **options):
		self.job, self.monkeypatch = job, monkeypatch
		self.skip_list = rv.SkipList(job.monitor, list(patterns))
		self.options = dict(only_sync_attributes=only_sync_attributes, skip_list=self.skip_list, **options)
		self.queue = rv.ChangeEventQueue(job.monitor)
		self.lock = threading.Lock()
		self.flag = threading.Event()
		self.thread = None

	def start(self):
		watching = threading.Event()
		self.thread = threading.Thread(target=rv.watchFolder, kwargs=dict(monitor_path=self.job.monitor, to_process=self.queue,
			to_process_lock=self.lock, to_process_flag=self.flag, irm=rv.inotify_resource_manager(), min_snapshot_delay_seconds=0.15,
			max_shapshot_delay_seconds=60, skip_list=self.skip_list, watching=watching), daemon=True)
		self.thread.start()
		assert watching.wait(10), 'the watcher did not start'
		self.take()

	def stop(self):
		rv.GREEN_LIGHT.clear()
		self.thread.join(timeout=5)
		rv.GREEN_LIGHT.set()

	def events(self):
		with self.lock:
			return list(self.queue)

	def settle(self):
		'''The watcher has read, and handled, everything done so far: a probe's event says so. The probe stays, as an entry of every version.'''
		probe = os.path.join(self.job.monitor, f'.probe_{time.monotonic_ns()}')
		open(probe, 'w').close()
		wait_until(lambda: any(e.event == 'create' and e.path == probe for e in self.events()), message='watcher not ready')

	def take(self):
		'''
		The batch of everything done so far, as the backuper takes it once the watcher signals: a probe's event says all before it
		is read, and a signal after it that the tree went quiet, each move-out held by then expired. The probe stays, as an
		entry of every version (content_view() leaves it out).
		'''
		self.settle()
		self.flag.clear()
		wait_until(self.flag.is_set, message='watcher did not signal the backuper')
		with self.lock:
			batch = self.queue.take()
		self.flag.clear()
		return batch

	def back_up(self, batch):
		'''Run batch as the backuper does.'''
		entries = rv.change_events_to_backup_entries(batch, self.job.monitor)
		scans = [event.path for event in batch if event.event == 'scan']
		scopes = rv.touched_scopes(batch, self.job.monitor)
		if scans:
			root_mount = rv.mount_fingerprint(rv.current_mount_table(), os.path.realpath(self.job.monitor))
			rv.compare_scanned_folders(entries, scans, self.job.job_name, self.job.monitor, self.job.vault, skip_list=self.skip_list, root_mount=root_mount)[1].close()
		return run_backup(self.job, entries, touched=scopes if scopes.subtrees or scopes.paths else None, matched_since=batch.read_wall_ns, **self.options)

	def back_up_next(self):
		return self.back_up(self.take())

	@contextlib.contextmanager
	def unread(self):
		'''What runs in the block is done before the watcher reads any of it, all of it in one read.'''
		real_read = rv.inotify_simple.INotify.read
		waiting, go = threading.Event(), threading.Event()
		def read(inotify, *args, **kwargs):
			waiting.set()
			go.wait(10)
			return real_read(inotify, *args, **kwargs)
		self.monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
		try:
			assert waiting.wait(10), 'the watcher did not read'
			yield
		finally:
			self.monkeypatch.setattr(rv.inotify_simple.INotify, 'read', real_read)
			go.set()

	def run(self, steps, timing):
		if timing == 'unread':
			with self.unread():
				for step in steps:
					self.apply(step)
			return
		for step in steps:
			self.apply(step)
			if timing == 'apart':
				time.sleep(0.03)

	def apply(self, step):
		verb, *args = step
		at = lambda rel: rel if rel.startswith('/') else os.path.join(self.job.monitor, rel)
		if verb == 'mkdir':
			os.makedirs(at(args[0]))
		elif verb == 'mv':
			os.rename(at(args[0]), at(args[1]))
		elif verb == 'write':
			with open(at(args[0]), 'w') as f:
				f.write(args[1])
		elif verb == 'append':
			with open(at(args[0]), 'a') as f:
				f.write(args[1])
		elif verb == 'rm':
			os.remove(at(args[0]))
		elif verb == 'rmtree':
			shutil.rmtree(at(args[0]))
		elif verb == 'chmod':
			os.chmod(at(args[0]), args[1])
		else:
			raise AssertionError(verb)


@pytest.fixture
def session(job, poll_fast, monkeypatch):
	sessions = []
	def start(tree=SEED, **kwargs):
		seed_monitor(job, tree)
		one = Session(job, monkeypatch, **kwargs)
		one.options.setdefault('keep_n_versions', 0)
		one.options.setdefault('backup_size_limit', '0')
		run_backup(job, **one.options)
		one.start()
		sessions.append(one)
		return one
	yield start
	for one in sessions:
		one.stop()


def content_view(views: dict) -> dict:
	'''What a version must hold: each entry's kind, contents and metadata, a folder's times among them.'''
	return {rel: (view.kind, view.data, view.mode, view.uid, view.gid, view.mtime_ns if view.kind == 'd' else None, view.xattrs) for rel, view in views.items() if rel and not rel.startswith('.probe')}


def live_view(job) -> dict:
	return content_view(snapshot_tree(job.monitor))


def version_view(job, version: str = None, inodes: dict = None) -> dict:
	return content_view(read_view(job.job_vault, os.path.basename(version or latest_version(job).path), inodes))


def inodes_of(job) -> dict:
	found = {}
	version_view(job, inodes=found)
	return found


def assert_held_as_the_tree(job, before: dict, previous: str) -> None:
	'''The newest version is the tree, and the version before it holds what it held: under Only Sync Attributes a chmod reaches a file's shared inode there.'''
	assert version_view(job) == live_view(job)
	assert {rel: view[:2] for rel, view in version_view(job, previous).items()} == {rel: view[:2] for rel, view in before.items()}


def vault_bytes(job) -> int:
	return rv.get_path_size(job.job_vault)


@pytest.mark.parametrize('gap', [0, 0.2])
@pytest.mark.parametrize('steps,rels', [
	([('mv', 'big', 'other/big')], {'big/a': 'other/big/a', 'big/sub/b': 'other/big/sub/b'}),
	([('mkdir', 'new'), ('mv', 'big', 'new/big')], {'big/a': 'new/big/a', 'big/sub/b': 'new/big/sub/b'}),
	([('mkdir', 'p/q'), ('mv', 'big', 'p/q/big')], {'big/a': 'p/q/big/a', 'big/sub/b': 'p/q/big/sub/b'}),
], ids=['existing', 'new', 'nested'])
def test_a_folder_moved_keeps_its_inodes_and_the_vault_grows_by_no_copy(session, job, steps, rels, gap):
	tree = {f'big/f{i}': f'{i}' * 100000 for i in range(4)}
	one = session({**SEED, **tree})
	rels = {**rels, **{rel: rels['big/a'].replace('/a', rel[3:]) for rel in tree}}
	before = version_view(job)
	previous = latest_version(job).path
	inodes = inodes_of(job)
	size = vault_bytes(job)
	for step in steps:
		one.apply(step)
		time.sleep(gap)
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	after = inodes_of(job)
	assert {new: after[new] for new in rels.values()} == {new: inodes[old] for old, new in rels.items()}
	# 400 KB would be a copy; what a batch itself adds is a few folders, links and lists
	assert vault_bytes(job) - size < 200000


# name, steps, what keeps its inode (old rel -> new rel), and whether that holds with the moves done as fast as they go or before
# the watcher reads: a file moved in then has no watch to tell it by and a second rename may have no event either, so the entry
# is copied (a folder has its watch, which says where it went)
SHAPES = [
	('folder', [('mkdir', 'n'), ('mv', 'big', 'n/big')], {'big/a': 'n/big/a', 'big/sub/b': 'n/big/sub/b'}, True),
	('file', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt')], {'f.txt': 'n/f.txt'}, False),
	('file_renamed', [('mkdir', 'n'), ('mv', 'f.txt', 'n/renamed')], {'f.txt': 'n/renamed'}, False),
	('nested', [('mkdir', 'p/q/r'), ('mv', 'big', 'p/q/r/big')], {'big/a': 'p/q/r/big/a'}, True),
	('folder_written_in', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('write', 'n/big/z', 'z'), ('append', 'n/big/a', 'more')], {'big/sub/b': 'n/big/sub/b'}, True),
	('folder_chmod_in', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('chmod', 'n/big', 0o700), ('chmod', 'n/big/a', 0o600)], {'big/sub/b': 'n/big/sub/b'}, True),
	('folder_removed_from', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('rm', 'n/big/a')], {'big/sub/b': 'n/big/sub/b'}, True),
	('changed_before', [('append', 'big/a', 'more'), ('mkdir', 'n'), ('mv', 'big', 'n/big')], {'big/sub/b': 'n/big/sub/b'}, True),
	('changed_between', [('mkdir', 'n'), ('append', 'big/a', 'more'), ('mv', 'big', 'n/big')], {'big/sub/b': 'n/big/sub/b'}, True),
	('file_written_after', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('append', 'n/f.txt', 'more')], {}, True),
	('file_chmod_after', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('chmod', 'n/f.txt', 0o600)], {}, True),
	('file_replaced', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('rm', 'n/f.txt'), ('write', 'n/f.txt', 'new')], {}, True),
	('out_to_a_folder', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'other/big')], {'big/a': 'other/big/a'}, False),
	('out_of_the_tree', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', '{outside}/big')], {}, True),
	('file_out_again', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('mv', 'n/f.txt', 'other/f.txt')], {'f.txt': 'other/f.txt'}, False),
	('chain', [('mkdir', 'n'), ('mkdir', 'n2'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n2/big')], {'big/a': 'n2/big/a'}, False),
	('file_chain', [('mkdir', 'n'), ('mkdir', 'n2'), ('mv', 'f.txt', 'n/f.txt'), ('mv', 'n/f.txt', 'n2/f.txt')], {'f.txt': 'n2/f.txt'}, False),
	('renamed_inside', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n/big2')], {'big/a': 'n/big2/a'}, False),
	('swap', [('mkdir', 'n'), ('mv', 'f.txt', 'n/t'), ('mv', 'g.txt', 'f.txt'), ('mv', 'n/t', 'g.txt')], {}, True),
	('folder_swap', [('mkdir', 'n'), ('mv', 'big', 'n/t'), ('mv', 'other', 'big'), ('mv', 'n/t', 'other')], {}, True),
	('new_folder_renamed', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n', 'm')], {}, True),
	('new_folder_removed', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('rmtree', 'n')], {}, True),
	('new_folder_moved_on', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n', 'other/n')], {}, True),
	('folder_made_inside', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'n/big/s'), ('write', 'n/big/s/f', 'f')], {'big/a': 'n/big/a'}, True),
	('beside_new_files', [('mkdir', 'n'), ('write', 'n/own', 'own'), ('mv', 'big', 'n/big'), ('write', 'n/own2', 'own2')], {'big/a': 'n/big/a'}, True),
	('from_outside', [('mkdir', 'n'), ('mv', '{outside}/kept', 'n/kept')], {}, True),
	('onto_a_moved_in_file', [('mkdir', 'n'), ('mv', 'f.txt', 'n/x'), ('mv', 'g.txt', 'n/x')], {'g.txt': 'n/x'}, False),
	('a_file_made_in_the_batch', [('write', 'made', 'made'), ('mkdir', 'n'), ('mv', 'made', 'n/made')], {}, True),
	('a_folder_made_in_the_batch', [('mkdir', 'd'), ('write', 'd/f', 'f'), ('mkdir', 'n'), ('mv', 'd', 'n/d')], {}, True),
	('moved_inside_a_new_folder', [('mkdir', 'n'), ('write', 'n/a', 'a'), ('mv', 'n/a', 'n/b')], {}, True),
	('moved_out_of_a_new_folder', [('mkdir', 'n'), ('write', 'n/a', 'a'), ('mv', 'n/a', 'other/a')], {}, True),
	('its_own_old_place', [('mv', 'big', 'x'), ('mkdir', 'big'), ('mv', 'x', 'big/big')], {}, True),
]


@pytest.mark.parametrize('only_sync_attributes', [True, False], ids=['osa', 'no_osa'])
@pytest.mark.parametrize('timing', TIMINGS)
@pytest.mark.parametrize('name,steps,kept,kept_unread', SHAPES, ids=[shape[0] for shape in SHAPES])
def test_a_batch_of_moves_into_new_folders_ends_as_the_tree(session, job, tmp_path, name, steps, kept, kept_unread, timing, only_sync_attributes):
	outside = tmp_path / 'outside'
	os.makedirs(outside / 'kept')
	(outside / 'kept' / 'x').write_text('x')
	steps = [tuple(arg.replace('{outside}', str(outside)) if isinstance(arg, str) else arg for arg in step) for step in steps]
	one = session(only_sync_attributes=only_sync_attributes)
	before = version_view(job)
	previous = latest_version(job).path
	inodes = inodes_of(job)
	one.run(steps, timing)
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	# a change the batch left for later would show here
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	assert version_view(job) == live_view(job)
	if timing == 'apart' or kept_unread:
		after = inodes_of(job)
		assert {new: after[new] for new in kept.values()} == {new: inodes[old] for old, new in kept.items()}


@pytest.mark.parametrize('timing', TIMINGS)
@pytest.mark.parametrize('moved', ['folder', 'file'])
def test_a_file_written_in_a_moved_in_folder_right_after_the_move_is_in_a_version(session, job, timing, moved):
	one = session()
	source = 'big' if moved == 'folder' else 'f.txt'
	one.run([('mkdir', 'n'), ('mv', source, 'n/in')], timing)
	# the watcher has nothing to tell it this one but the watches it has by now, or the walk that comes after
	if moved == 'folder':
		one.apply(('write', 'n/in/z', 'z'))
		one.apply(('mkdir', 'n/in/s'))
		one.apply(('write', 'n/in/s/y', 'y'))
	else:
		one.apply(('append', 'n/in', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


def test_a_move_in_that_the_walk_saw_and_whose_event_comes_is_one_move(session, job, monkeypatch):
	# the new folder has its watch and the walk has not listed it when the move comes: the walk finds it and its MOVED_TO comes too
	one = session()
	new, big = os.path.join(job.monitor, 'n'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == new and os.path.lexists(big):
			os.rename(big, os.path.join(new, 'big'))
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	inodes = inodes_of(job)
	before = version_view(job)
	previous = latest_version(job).path
	os.mkdir(new)
	batch = one.take()
	assert [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch if e.event != 'attrib' and '.probe' not in e.path] == [('create', 'n'), ('move', 'n/big')]
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	assert inodes_of(job)['n/big/a'] == inodes['big/a']


TAIL = 'T' * 70000


@pytest.mark.parametrize('only_sync_attributes', [True, False], ids=['osa', 'no_osa'])
def test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name(session, job, tmp_path, only_sync_attributes):
	# same name, size, mtime and last 64 KiB, other bytes before: no comparison tells them apart, so the version must get the new file's
	# bytes from a copy, not from the old file by a guess of the name ( mkdir stage; cp -p fw.img stage; mv fw.img /archive )
	one = session({**SEED, 'f.bin': 'A' * 4096 + TAIL}, only_sync_attributes=only_sync_attributes)
	before = version_view(job)
	previous = latest_version(job).path
	old = os.path.join(job.monitor, 'f.bin')
	stat = os.lstat(old)
	with one.unread():
		os.rename(old, tmp_path / 'f.bin')
		os.mkdir(os.path.join(job.monitor, 'n'))
		new = os.path.join(job.monitor, 'n', 'f.bin')
		with open(new, 'w') as f:
			f.write('B' * 4096 + TAIL)
		os.utime(new, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)


@pytest.mark.parametrize('where', ['file_moved_in_at_gap_0', 'folder_moved_in_at_gap_0'])
def test_a_write_with_its_mtime_set_back_in_a_moved_in_file_is_in_a_version(session, job, where):
	# nothing tells a comparison of this write but the event, so what holds the file must be a copy made after it
	one = session({**SEED, 'f.bin': 'A' * 4096 + TAIL, 'd/f.bin': 'A' * 4096 + TAIL})
	rel = 'n/f.bin' if where == 'file_moved_in_at_gap_0' else 'n/d/f.bin'
	with one.unread():
		os.mkdir(os.path.join(job.monitor, 'n'))
		os.rename(os.path.join(job.monitor, 'f.bin' if where == 'file_moved_in_at_gap_0' else 'd'), os.path.join(job.monitor, rel if where == 'file_moved_in_at_gap_0' else 'n/d'))
	path = os.path.join(job.monitor, rel)
	stat = os.lstat(path)
	with open(path, 'r+b') as f:
		f.seek(100)
		f.write(b'WRITTEN')
	os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	one.back_up_next()
	assert version_view(job)[rel][1] == live_view(job)[rel][1]


def test_events_in_a_folder_the_walk_found_moved_in_are_recorded(session, job):
	# nothing copies it: its move does, and what changes in it is recorded as in any moved folder
	one = session()
	with one.unread():
		one.apply(('mkdir', 'n'))
		one.apply(('mv', 'big', 'n/big'))
	z = os.path.join(job.monitor, 'n', 'big', 'sub', 'z')
	wait_until(lambda: any(e.event == 'move' for e in one.events()), message='no move')
	one.apply(('write', 'n/big/sub/z', 'z'))
	wait_until(lambda: any(e.event == 'create' and e.path == z for e in one.events()), message='no create of the file')


def test_what_a_walk_found_ends_with_the_take(session, job, tmp_path):
	# a found subfolder has no move-out of its own here: left over, it would take a later move-out at that path
	one = session()
	with one.unread():
		one.apply(('mkdir', 'n'))
		one.apply(('write', 'n/g.txt', 'another g'))
		one.apply(('mv', 'big', 'n/big'))
	one.back_up_next()
	one.apply(('mkdir', 'big/sub'))
	one.back_up_next()
	one.apply(('mkdir', 'other/x'))
	one.back_up_next()
	os.rename(os.path.join(job.monitor, 'big', 'sub'), tmp_path / 'sub')
	os.rename(os.path.join(job.monitor, 'g.txt'), tmp_path / 'g.txt')
	batch = one.take()
	assert sorted((e.event, os.path.relpath(e.path, job.monitor)) for e in batch if e.event in ('move', 'delete')) == [('delete', 'big/sub'), ('delete', 'g.txt')]
	one.back_up(batch)
	assert version_view(job) == live_view(job)


def written_after(one, job, rel):
	'''A write in a folder, as a later batch holds it: the folder must still be watched, or no event comes and the version never gets it.'''
	one.apply(('write', rel, 'after'))
	one.back_up_next()
	assert version_view(job) == live_view(job)
	assert rel in version_view(job)


def test_a_folder_moved_out_after_another_took_its_place_is_not_the_one_the_walk_found(session, job):
	# blue-green: the old release is archived in a new folder, the new one renamed into place, and its subfolder moved out. the walk
	# of the new folder, before any of it is handled, found the old release and its sub under the watches of 'big' and 'big/sub',
	# and the sub of the release now at 'big' is another folder that must not be taken for it
	one = session({**SEED, 'next/sub/c': 'c', 'next/keep': 'k'})
	before = version_view(job)
	previous = latest_version(job).path
	with one.unread():
		one.run([('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'next', 'big'), ('mv', 'big/sub', 'other/sub')], 'at_once')
	batch = one.take()
	assert ('move', 'other/sub') in [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch]
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'other/sub/y')


def test_a_folder_renamed_onto_the_place_of_one_moved_in_from_it_and_moved_on_is_not_that_one(session, job, tmp_path):
	# the move-out of big is read before the walk that finds it in n/big: its watches stay under 'big' until its delete expires.
	# another folder renamed onto big and moved on is not the one the walk found
	one = session({**SEED, 'next/sub/c': 'c', 'next/keep': 'k'})
	before = version_view(job)
	previous = latest_version(job).path
	os.rename(os.path.join(job.monitor, 'big'), tmp_path / 'big')
	one.settle()
	with one.unread():
		os.mkdir(os.path.join(job.monitor, 'n'))
		os.rename(tmp_path / 'big', os.path.join(job.monitor, 'n', 'big'))
		one.run([('mv', 'next', 'big'), ('mv', 'big', 'x')], 'at_once')
	batch = one.take()
	assert ('move', 'x') in [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch]
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'x/sub/y')


def test_a_folder_found_moved_in_is_not_a_new_folder_when_its_parent_is_walked_again(session, job, monkeypatch):
	# a/b is made and big moved into it while a is walked: that walk finds big under its old watch, and a's next read, the create of
	# a/b, walks a/b again. big is carried by its move and nothing copies it, so a write in it, made so that only its event can
	# show it (inside the file, its mtime set back), must still be recorded
	one = session({**SEED, 'big/a': 'A' * 4096 + TAIL})
	new, big = os.path.join(job.monitor, 'a'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == new and os.path.lexists(big):
			os.mkdir(os.path.join(new, 'b'))
			os.rename(big, os.path.join(new, 'b', 'big'))
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	inodes = inodes_of(job)
	before = version_view(job)
	previous = latest_version(job).path
	os.mkdir(new)
	one.settle()
	moved = os.path.join(new, 'b', 'big', 'a')
	stat = os.lstat(moved)
	with open(moved, 'r+b') as f:
		f.seek(100)
		f.write(b'WRITTEN')
	os.utime(moved, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	batch = one.take()
	assert ('move', 'a/b/big') in [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch]
	assert ('modify', 'a/b/big/a') in [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch]
	one.back_up(batch)
	assert version_view(job) == live_view(job)
	assert inodes_of(job)['a/b/big/sub/b'] == inodes['big/sub/b']


def hold_walk(monkeypatch, folder):
	'''The watcher stops before it walks folder (at is set then) until go is set.'''
	real = rv.initializeFolderWatchers
	at, go = threading.Event(), threading.Event()
	def walk(inotify_obj, path, *args, **kwargs):
		if path.rstrip('/') == folder:
			at.set()
			go.wait(20)
		return real(inotify_obj, path, *args, **kwargs)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', walk)
	return at, go


def take_at_append(one, monkeypatch, wanted):
	'''A take right after the watcher queues the first event wanted() says yes to: inside its read, between it and what comes next.'''
	real = rv.ChangeEventQueue.append
	taken = []
	def append(queue, event):
		real(queue, event)
		if queue is one.queue and not taken and wanted(event):
			taken.append(queue.take())
	monkeypatch.setattr(rv.ChangeEventQueue, 'append', append)
	return taken


def test_a_take_between_the_mkdir_and_the_mv(session, job):
	one = session()
	inodes = inodes_of(job)
	one.apply(('mkdir', 'n'))
	one.back_up_next()
	before = version_view(job)
	previous = latest_version(job).path
	one.apply(('mv', 'big', 'n/big'))
	one.apply(('write', 'n/big/z', 'z'))
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	assert inodes_of(job)['n/big/a'] == inodes['big/a']


def test_a_take_before_the_watcher_reads_the_mkdir(session, job):
	one = session()
	inodes = inodes_of(job)
	with one.unread():
		one.apply(('mkdir', 'n'))
		one.apply(('mv', 'big', 'n/big'))
		with one.lock:
			one.queue.take()
	one.apply(('write', 'n/big/z', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)
	assert inodes_of(job)['n/big/a'] == inodes['big/a']


def test_a_take_and_its_copy_between_the_mv_and_its_read(session, job):
	# the copy holds the folder, and the take's read says so: the move replaces what the copy put there
	one = session()
	one.apply(('mkdir', 'n'))
	wait_until(lambda: any(e.event == 'create' for e in one.events()), message='no create')
	inodes = inodes_of(job)
	with one.unread():
		one.apply(('mv', 'big', 'n/big'))
		with one.lock:
			batch = one.queue.take()
		one.flag.clear()
		one.back_up(batch)
	one.apply(('write', 'n/big/z', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)
	assert inodes_of(job)['n/big/sub/b'] == inodes['big/sub/b']


@pytest.mark.parametrize('moved', ['folder', 'file'])
def test_a_take_between_the_mvs_read_and_its_handling(session, job, monkeypatch, moved):
	one = session()
	one.apply(('mkdir', 'n'))
	wait_until(lambda: any(e.event == 'create' for e in one.events()), message='no create')
	marker = os.path.join(job.monitor, 'marker')
	taken = take_at_append(one, monkeypatch, lambda event: event.path == marker)
	source = 'big' if moved == 'folder' else 'f.txt'
	with one.unread():
		one.apply(('write', 'marker', 'm'))
		one.apply(('mv', source, 'n/in'))
	wait_until(lambda: taken, message='no take')
	one.back_up(taken[0])
	if moved == 'folder':
		one.apply(('write', 'n/in/z', 'z'))
	else:
		one.apply(('append', 'n/in', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


def test_a_take_between_the_walk_that_found_the_folder_and_its_move_out(session, job, monkeypatch):
	# the create is queued and taken inside the read that holds the move-out, as a take can land there
	one = session()
	new = os.path.join(job.monitor, 'n')
	taken = take_at_append(one, monkeypatch, lambda event: event.path.rstrip('/') == new)
	with one.unread():
		one.apply(('mkdir', 'n'))
		one.apply(('mv', 'big', 'n/big'))
	wait_until(lambda: taken, message='no take')
	one.back_up(taken[0])
	one.apply(('write', 'n/big/z', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


def test_a_take_waits_for_the_walk_of_a_folder_moved_into_a_new_folder(session, job, monkeypatch):
	one = session()
	new = os.path.join(job.monitor, 'n')
	moved = os.path.join(new, 'big')
	one.apply(('mkdir', 'n'))
	wait_until(lambda: any(e.event == 'create' for e in one.events()), message='no create')
	at, go = hold_walk(monkeypatch, moved)
	inodes = inodes_of(job)
	try:
		one.apply(('mv', 'big', 'n/big'))
		assert at.wait(10)
		assert not one.lock.acquire(timeout=0.1)
		one.apply(('write', 'n/big/z', 'z'))
	finally:
		go.set()
	one.back_up_next()
	assert version_view(job) == live_view(job)
	assert inodes_of(job)['n/big/a'] == inodes['big/a']


@pytest.mark.parametrize('timing', TIMINGS)
def test_a_move_into_a_new_folder_prunes_no_version(session, job, timing):
	big = {f'big/f{i}': f'{i}' * 200000 for i in range(5)}
	one = session(big, keep_n_versions=9, backup_size_limit='0')
	for i in range(5):
		one.apply(('write', f'v{i}', f'{i}'))
		one.back_up_next()
	versions = committed_versions(job)
	assert len(versions) == 6
	# room for this batch and more, but not for a copy of big
	one.options['backup_size_limit'] = str(rv.get_vault_info(job.job_vault).vault_size + 500000)
	one.run([('mkdir', 'new'), ('mv', 'big', 'new/big')], timing)
	one.back_up_next()
	assert committed_versions(job)[:-1] == versions
	assert version_view(job) == live_view(job)


def test_a_batch_handed_back_replays_its_move_once(session, job):
	one = session()
	inodes = inodes_of(job)
	before = version_view(job)
	previous = latest_version(job).path
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big'), ('write', 'n/big/z', 'z')], 'apart')
	batch = one.take()
	first = rv.change_events_to_backup_entries(batch, job.monitor)
	# as a backup that did not commit hands its batch back, with what came meanwhile behind it
	one.apply(('append', 'n/big/z', 'more'))
	wait_until(lambda: one.events(), message='nothing queued')
	with one.lock:
		one.queue.prepend(rv.backup_entries_to_change_events(first))
	again = one.take()
	assert again.round_tripped
	entries = rv.change_events_to_backup_entries(again, job.monitor)
	assert [(rel.rstrip('/'), values.event) for rel, values in entries.items() if values.event == 'move'] == [(os.path.join(job.monitor, 'n/big'), 'move')]
	one.back_up(again)
	assert_held_as_the_tree(job, before, previous)
	assert inodes_of(job)['n/big/a'] == inodes['big/a']


def test_a_batch_read_before_the_first_version_is_right(job, poll_fast, monkeypatch):
	# nothing is in the vault yet: the batch becomes V0, whatever its moves say
	seed_monitor(job, SEED)
	one = Session(job, monkeypatch, keep_n_versions=0, backup_size_limit='0')
	one.start()
	try:
		one.run([('mkdir', 'n'), ('mv', 'big', 'n/big')], 'at_once')
		batch = one.take()
		entries = rv.change_events_to_backup_entries(batch, job.monitor)
		run_backup(job, entries, **one.options)
		assert version_view(job) == live_view(job)
	finally:
		one.stop()


@pytest.mark.parametrize('timing', TIMINGS)
def test_on_a_filesystem_with_no_exchange(session, job, monkeypatch, timing):
	tried = []
	def no_exchange(*args):
		tried.append(args)
		raise OSError(errno.EINVAL, 'no exchange')
	monkeypatch.setattr(rv, 'rename_exchange', no_exchange)
	one = session()
	before = version_view(job)
	previous = latest_version(job).path
	inodes = inodes_of(job)
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'f.txt', 'n/f.txt'), ('write', 'n/big/z', 'z')], timing)
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	after = inodes_of(job)
	assert after['n/big/a'] == inodes['big/a']
	# a file moved in before the watcher reached the folder is copied
	if timing == 'apart':
		assert after['n/f.txt'] == inodes['f.txt']
	assert tried


@pytest.mark.parametrize('timing', TIMINGS)
def test_a_move_in_from_a_skipped_path_is_copied(session, job, timing):
	one = session({**SEED, 'cache/kept/x': 'x'}, patterns=['cache/'])
	one.run([('mkdir', 'n'), ('mv', 'cache/kept', 'n/kept')], timing)
	one.back_up_next()
	assert version_view(job)['n/kept/x'] == live_view(job)['n/kept/x']


@pytest.mark.parametrize('timing', TIMINGS)
def test_a_move_in_to_a_skipped_path_is_gone_from_the_version(session, job, timing):
	one = session(patterns=['cache/'])
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/cache')], timing)
	one.back_up_next()
	view = version_view(job)
	assert 'big' not in view and 'n/cache' not in view and 'n' in view
	# and no watch of it is left to report what changes there
	one.apply(('write', 'n/cache/x', 'x'))
	one.apply(('write', 'other/marker', 'm'))
	assert not [e for e in one.take() if 'n/cache' in e.path or e.path.startswith(os.path.join(job.monitor, 'big'))]


@pytest.mark.parametrize('timing', TIMINGS)
def test_a_moved_in_folder_a_location_pattern_now_leaves_out_part_of(session, job, timing):
	one = session({**SEED, 'big/logs/x': 'x'}, patterns=['/n/big/logs/'])
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big')], timing)
	one.back_up_next()
	view = version_view(job)
	assert 'n/big/a' in view and 'n/big/logs' not in view and 'big' not in view
	one.apply(('write', 'n/big/logs/y', 'y'))
	one.apply(('write', 'other/marker', 'm'))
	assert not [e for e in one.take() if '/logs' in e.path]
