'''
A folder or file moved into a folder made in the same batch is copied once with that folder, as on 0.55, and every batch of such
moves ends as the tree, driven through the real watchFolder on real inotify: hand-built events are why 0.55 and before went wrong
here with nobody seeing it. (0.55.1 tried to record such a move as a move and gave it up: each way of pairing it found another
order of events that kept wrong bytes; the move into a new folder waits for its own design.)
Each batch runs as the backuper runs it: collapsed, replayed, compared with what it touched.
'''
import contextlib
import errno
import itertools
import os
import shutil
import sys
import threading
import time

import pytest

import reverberator as rv
from tests.harness import get_path_size, committed_versions, latest_version, run_backup, seed_monitor, wait_until
from tests.vault_oracle import read_view, snapshot_tree

pytestmark = pytest.mark.inotify

SEED = {'big/a': 'a' * 5000, 'big/sub/b': 'b' * 5000, 'f.txt': 'f' * 5000, 'g.txt': 'g' * 5000, 'other/': None}
# how the steps of a batch meet the watcher. apart: each read and handled on its own. unread: all done before the watcher reads any,
# so a new folder has no watch yet and a move into it raises no MOVED_TO. at_once, as fast as Python goes, is a race between those two
# and has a stress test of its own
TIMINGS = ('apart', 'unread')


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
		elif verb == 'poke':
			# a write inside the file with its size and mtime kept: only its event can show it
			stat = os.lstat(at(args[0]))
			with open(at(args[0]), 'r+b') as f:
				f.write(b'POKED')
			os.utime(at(args[0]), ns=(stat.st_atime_ns, stat.st_mtime_ns))
		elif verb == 'cpp':
			# cp -p of a same-size file over it: other bytes, the same size and mtime
			stat = os.lstat(at(args[0]))
			with open(at(args[0]), 'r+b') as f:
				data = f.read()
				f.seek(0)
				f.write(b'N' * 100 + data[100:])
			os.utime(at(args[0]), ns=(stat.st_atime_ns, stat.st_mtime_ns))
		elif verb == 'touch':
			# a new mtime, as touch gives: the file is copied under either Only Sync Attributes setting
			stat = os.lstat(at(args[0]))
			os.utime(at(args[0]), ns=(stat.st_atime_ns, stat.st_mtime_ns + 5 * 10**9))
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
	return get_path_size(job.job_vault)


EXISTING = [('mv', 'big', 'other/big')]


@pytest.mark.parametrize('gap', [0, 0.2])
@pytest.mark.parametrize('steps,rels', [
	(EXISTING, {'big/a': 'other/big/a', 'big/sub/b': 'other/big/sub/b'}),
	([('mkdir', 'new'), ('mv', 'big', 'new/big')], {'big/a': 'new/big/a', 'big/sub/b': 'new/big/sub/b'}),
	([('mkdir', 'p/q'), ('mv', 'big', 'p/q/big')], {'big/a': 'p/q/big/a', 'big/sub/b': 'p/q/big/sub/b'}),
], ids=['existing', 'new', 'nested'])
def test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy(session, job, steps, rels, gap):
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
	if steps == EXISTING:
		assert {new: after[new] for new in rels.values()} == {new: inodes[old] for old, new in rels.items()}
		# 400 KB would be a copy; what a batch itself adds is a few folders, links and lists
		assert vault_bytes(job) - size < 200000
	else:
		# a folder moved into a folder made in the same batch is copied with it, whatever the gap, as on 0.55
		assert not {after[new] for new in rels.values()} & {inodes[old] for old in rels}
		assert vault_bytes(job) - size >= 400000


# name and steps of a batch with moves into new folders: whatever the watcher read of it, the version must end as the tree
SHAPES = [
	('folder', [('mkdir', 'n'), ('mv', 'big', 'n/big')]),
	('file', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt')]),
	('file_renamed', [('mkdir', 'n'), ('mv', 'f.txt', 'n/renamed')]),
	('nested', [('mkdir', 'p/q/r'), ('mv', 'big', 'p/q/r/big')]),
	('folder_written_in', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('write', 'n/big/z', 'z'), ('append', 'n/big/a', 'more')]),
	('folder_chmod_in', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('chmod', 'n/big', 0o700), ('chmod', 'n/big/a', 0o600)]),
	('folder_removed_from', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('rm', 'n/big/a')]),
	('changed_before', [('append', 'big/a', 'more'), ('mkdir', 'n'), ('mv', 'big', 'n/big')]),
	# a same-size write with its mtime kept: only its event shows it, and the copy of the folder must be made after it
	('changed_between', [('mkdir', 'n'), ('poke', 'big/a'), ('mv', 'big', 'n/big')]),
	('file_written_after', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('append', 'n/f.txt', 'more')]),
	('file_chmod_after', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('chmod', 'n/f.txt', 0o600)]),
	('file_replaced', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('rm', 'n/f.txt'), ('write', 'n/f.txt', 'new')]),
	('out_to_a_folder', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'other/big')]),
	('out_of_the_tree', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', '{outside}/big')]),
	('file_out_again', [('mkdir', 'n'), ('mv', 'f.txt', 'n/f.txt'), ('mv', 'n/f.txt', 'other/f.txt')]),
	('chain', [('mkdir', 'n'), ('mkdir', 'n2'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n2/big')]),
	('file_chain', [('mkdir', 'n'), ('mkdir', 'n2'), ('mv', 'f.txt', 'n/f.txt'), ('mv', 'n/f.txt', 'n2/f.txt')]),
	('renamed_inside', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n/big2')]),
	('swap', [('mkdir', 'n'), ('mv', 'f.txt', 'n/t'), ('mv', 'g.txt', 'f.txt'), ('mv', 'n/t', 'g.txt')]),
	('folder_swap', [('mkdir', 'n'), ('mv', 'big', 'n/t'), ('mv', 'other', 'big'), ('mv', 'n/t', 'other')]),
	('new_folder_renamed', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n', 'm')]),
	('new_folder_removed', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('rmtree', 'n')]),
	('new_folder_moved_on', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'n', 'other/n')]),
	('folder_made_inside', [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'n/big/s'), ('write', 'n/big/s/f', 'f')]),
	('beside_new_files', [('mkdir', 'n'), ('write', 'n/own', 'own'), ('mv', 'big', 'n/big'), ('write', 'n/own2', 'own2')]),
	('from_outside', [('mkdir', 'n'), ('mv', '{outside}/kept', 'n/kept')]),
	('onto_a_moved_in_file', [('mkdir', 'n'), ('mv', 'f.txt', 'n/x'), ('mv', 'g.txt', 'n/x')]),
	('a_file_made_in_the_batch', [('write', 'made', 'made'), ('mkdir', 'n'), ('mv', 'made', 'n/made')]),
	('a_folder_made_in_the_batch', [('mkdir', 'd'), ('write', 'd/f', 'f'), ('mkdir', 'n'), ('mv', 'd', 'n/d')]),
	('moved_inside_a_new_folder', [('mkdir', 'n'), ('write', 'n/a', 'a'), ('mv', 'n/a', 'n/b')]),
	('moved_out_of_a_new_folder', [('mkdir', 'n'), ('write', 'n/a', 'a'), ('mv', 'n/a', 'other/a')]),
	('its_own_old_place', [('mv', 'big', 'x'), ('mkdir', 'big'), ('mv', 'x', 'big/big')]),
]


# the shapes that no change of the watcher made fail while the review's mutants were run over the whole matrix: what the old code got
# right too, kept as cover, at one timing. Only Sync Attributes is the backuper's, and matters where a chmod comes: both ways there
NEVER_FAILED = {'file_written_after', 'file_chmod_after', 'file_replaced', 'out_of_the_tree', 'new_folder_removed', 'new_folder_moved_on', 'from_outside',
	'a_file_made_in_the_batch', 'a_folder_made_in_the_batch', 'moved_inside_a_new_folder', 'moved_out_of_a_new_folder', 'its_own_old_place'}
MATRIX = [pytest.param(*shape, timing, osa, id=f'{shape[0]}-{timing}-{"osa" if osa else "no_osa"}')
	for shape in SHAPES for timing in (TIMINGS[:1] if shape[0] in NEVER_FAILED else TIMINGS)
	for osa in ((True, False) if any(step[0] == 'chmod' for step in shape[1]) else (True,))]


@pytest.mark.parametrize('name,steps,timing,only_sync_attributes', MATRIX)
def test_a_batch_of_moves_into_new_folders_ends_as_the_tree(session, job, tmp_path, name, steps, timing, only_sync_attributes):
	outside = tmp_path / 'outside'
	os.makedirs(outside / 'kept')
	(outside / 'kept' / 'x').write_text('x')
	steps = [tuple(arg.replace('{outside}', str(outside)) if isinstance(arg, str) else arg for arg in step) for step in steps]
	one = session(only_sync_attributes=only_sync_attributes)
	before = version_view(job)
	previous = latest_version(job).path
	one.run(steps, timing)
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	# a change the batch left for later would show here
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


def test_moves_into_new_folders_as_fast_as_they_go_end_as_the_tree(session, job):
	# at_once is a race between the two paths: a new folder is watched in time for the move into it or it is not. sixty of each shape in one
	# batch, in the order of one tool, and whatever the race gave must end as the tree, and in a watch for what changes after
	count = 60
	one = session({**SEED, **{f'src{i}/a': 'a' * 3000 for i in range(count)}, **{f'f{i}': 'f' * 3000 for i in range(count)}})
	steps = []
	for i in range(count):
		steps += [('mkdir', f'n{i}'), ('mv', f'src{i}', f'n{i}/src{i}'), ('mv', f'f{i}', f'n{i}/f{i}'), ('write', f'n{i}/src{i}/z', 'z'), ('mkdir', f'm{i}'),
			('mv', f'n{i}/src{i}', f'm{i}/src{i}'), ('append', f'n{i}/f{i}', 'more')]
	one.run(steps, 'at_once')
	one.back_up_next()
	assert version_view(job) == live_view(job)
	for i in range(count):
		one.apply(('write', f'm{i}/src{i}/after', 'after'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


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


def test_a_move_in_that_the_walk_saw_and_whose_event_comes_is_a_copy(session, job, monkeypatch):
	# the new folder has its watch and the walk has not listed it when the move comes: the walk finds it and re-points its watches, and
	# its MOVED_TO comes too. the walk got there first, so the copy of the new folder holds it, as on 0.55: the event is discarded
	one = session()
	new, big = os.path.join(job.monitor, 'n'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == new and os.path.lexists(big):
			os.rename(big, os.path.join(new, 'big'))
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	before = version_view(job)
	previous = latest_version(job).path
	os.mkdir(new)
	batch = one.take()
	assert [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch if e.event != 'attrib' and '.probe' not in e.path and e.event != 'delete'] == [('create', 'n')]
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'n/big/after')


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


# a folder with no watch yet at the old path of one a walk found: made or renamed there and moved on before its create's walk added
# a watch, so no watch tells it from the found folder. each, all unread so the walk of n comes first, must leave the folder moved out
# in the version and watched
UNWATCHED_AT_THE_OLD_PATH = {
	'made_at_a_subfolder': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'next', 'big'), ('mkdir', 'big/sub'), ('write', 'big/sub/x', 'x'),
		('mv', 'big/sub', 'other/sub')],
	'made_before_its_parent_was_renamed_there': [('mkdir', 'next/sub'), ('write', 'next/sub/x', 'x'), ('mkdir', 'n'), ('mv', 'big', 'n/big'),
		('mv', 'next', 'big'), ('mv', 'big/sub', 'other/sub')],
	'made_after_the_walk': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'next/sub'), ('write', 'next/sub/x', 'x'), ('mv', 'next', 'big'),
		('mv', 'big/sub', 'other/sub')],
	'made_at_a_top_path_read_out_first': [('mv', 'big', '{outside}/big'), ('mkdir', 'n'), ('mv', '{outside}/big', 'n/big'), ('mkdir', 'big'),
		('write', 'big/x', 'x'), ('mv', 'big', 'other/sub')],
	# the found folder's own rename was read before the walk that found it (its new folder moved on into another), and a folder made
	# at its old path leaves right before it moves again
	'found_after_its_move_was_read': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'q'), ('mv', 'n', 'q/n'), ('mkdir', 'big'), ('write', 'big/x', 'x'),
		('mv', 'big', '{outside}/e'), ('mv', 'q/n/big', 'other/sub')],
}


@pytest.mark.parametrize('steps', UNWATCHED_AT_THE_OLD_PATH.values(), ids=UNWATCHED_AT_THE_OLD_PATH)
def test_a_folder_with_no_watch_yet_at_a_found_folders_old_path_is_not_that_folder(session, job, tmp_path, steps):
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	one = session({**SEED, 'big/sub/deep/x': 'x' * 100, 'next/z': 'z' * 100})
	before = version_view(job)
	previous = latest_version(job).path
	one.run([tuple(arg.replace('{outside}', str(outside)) for arg in step) for step in steps], 'unread')
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'other/sub/after')


@pytest.mark.parametrize('timing', TIMINGS)
def test_the_order_of_fuzz_seed_2854(session, job, tmp_path, timing):
	# keep/s/n2 leaves the tree and keep is renamed before that move-out expires, which kept the watch of the folder outside mapped at
	# c/keep2/s/n2. the folder comes back, a new folder is made at that path, and a chain moves it on: the version must end as the tree
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	one = session({'keep/s/n2/b/h': 'h' * 100, 'x/n1/y': 'y', 'x/z': 'z', 'c/b/f': 'f', 'c/s/g': 'g', 'other/o': 'o'})
	with one.unread():
		os.rename(os.path.join(job.monitor, 'keep/s/n2'), outside / 'x16')
		one.apply(('mv', 'keep', 'c/keep2'))
	one.back_up_next()
	one.back_up_next()
	at, chain = 'c/keep2/s/n2', 'c/b/n1'
	one.run([('mv', str(outside / 'x16'), 'c/b/n2'), ('mkdir', at), ('mv', 'x', at + '/n2'), ('mkdir', chain), ('mv', at, chain + '/n2')], timing)
	one.back_up_next()
	one.back_up_next()
	for base, folders, _ in os.walk(job.monitor):
		for folder in folders:
			open(os.path.join(base, folder, 'mark'), 'w').close()
	one.back_up_next()
	assert version_view(job) == live_view(job)


def kernel_merges(first, second):
	'''Every order of two renames' events another CPU can give: each rename's own events stay in their order.'''
	for at in itertools.combinations(range(len(first) + len(second)), len(second)):
		a, b = iter(first), iter(second)
		yield [next(b) if i in at else next(a) for i in range(len(first) + len(second))]


class StagedReads:
	'''The watcher reads once per stage, and stands before its next read in between: a stage runs its steps while the watcher waits to read, lets it read and handle everything, and returns when it waits again.'''
	def __init__(self, monkeypatch):
		self.real = rv.inotify_simple.INotify.read
		self.waiting, self.permit, self.open = threading.Event(), threading.Semaphore(0), False
		def read(inotify, *args, **kwargs):
			if not self.open:
				self.waiting.set()
				assert self.permit.acquire(timeout=20), 'the stage did not come'
			return self.real(inotify, *args, **kwargs)
		monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)

	def stage(self, one, steps):
		assert self.waiting.wait(20), 'the watcher did not come back to read'
		for step in steps:
			one.apply(step)
		self.waiting.clear()
		self.permit.release()
		assert self.waiting.wait(20), 'the watcher did not come back to read'

	def end(self):
		self.open = True
		self.permit.release()


def test_a_subfolder_taken_back_from_a_folder_moved_out_keeps_its_watch_when_the_move_out_expires(session, job, tmp_path, monkeypatch):
	# X leaves the tree and takes its watches along, and one of them, X/sub, is moved back (the stale watch of X reports it as a move
	# from X/sub), which re-points that watch to sub. the read that holds the rename sub -> sub2 and a same-size write in it also finds
	# the move-out of X past the pair timeout of a tree that is never quiet: the watch is a live folder's, though its path has no folder
	# yet to the watcher, and removing it loses the write, which only its event shows
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 1.0)
	one = session({'X/g': 'g' * 100, 'X/sub/f': 'f' * 200000, 'X/sub/deep/h': 'h' * 100, 'other/o': 'o'})
	reads = StagedReads(monkeypatch)
	reads.stage(one, [('mv', 'X', str(tmp_path / 'out'))])
	reads.stage(one, [('mv', str(tmp_path / 'out' / 'sub'), 'sub')])
	time.sleep(1.1)
	reads.stage(one, [('mv', 'sub', 'sub2'), ('poke', 'sub2/f')])
	reads.end()
	one.back_up_next()
	assert version_view(job) == live_view(job)


TWICE_TREE = {'big/a': 'p' * 200000, 'big/sub/b': 'p' * 200000, 'keep/k': 'k', 'other/o': 'o'}
TWICE_SHAPES = {
	# a change only its event shows (a poke keeps the size and mtime, cp -p of a same-size file does too), then the folder moved into
	# a new folder (or into a folder moved there first) and renamed again, all before the watcher reads any of it
	'twice': [('mkdir', 'n'), ('mv', 'keep', 'n/keep'), ('poke', 'big/a'), ('mv', 'big', 'n/keep/app.tmp'), ('mv', 'n/keep/app.tmp', 'n/keep/app')],
	'twice_cpp': [('mkdir', 'n'), ('mv', 'keep', 'n/keep'), ('cpp', 'big/sub/b'), ('mv', 'big', 'n/keep/app.tmp'), ('mv', 'n/keep/app.tmp', 'n/keep/app')],
	'once': [('mkdir', 'n'), ('mv', 'keep', 'n/keep'), ('poke', 'big/a'), ('mv', 'big', 'n/keep/app')],
	'twice_poke_first': [('poke', 'big/a'), ('mkdir', 'n'), ('mv', 'keep', 'n/keep'), ('mv', 'big', 'n/keep/app.tmp'), ('mv', 'n/keep/app.tmp', 'n/keep/app')],
	'twice_in_old': [('mv', 'keep', 'other/keep'), ('poke', 'big/a'), ('mv', 'big', 'other/keep/app.tmp'), ('mv', 'other/keep/app.tmp', 'other/keep/app')],
}


@pytest.mark.parametrize('name', TWICE_SHAPES)
def test_a_folder_renamed_twice_in_a_new_folder_before_the_walk_lists_it_keeps_its_changed_bytes(session, job, name):
	# the walk of the new folder lists the folder at its last name and re-points its own watch there, so the change's event is
	# discarded with the new folder's and the copy holds it: the first move, read after that walk, is no move to keep, whatever name
	# the folder had when it landed
	one = session(TWICE_TREE)
	with one.unread():
		for step in TWICE_SHAPES[name]:
			one.apply(step)
	batch = one.take()
	one.back_up(batch)
	assert version_view(job) == live_view(job), [(e.event, os.path.relpath(e.path, job.monitor)) for e in batch if '.probe' not in e.path]


def test_a_folder_moved_into_a_new_folder_from_the_place_a_folder_once_left_the_tree_from_keeps_its_changed_bytes(session, job, tmp_path, monkeypatch):
	# mkdir n; mkdir n/x; mv n/x /outside/x: the watch of the folder outside stays mapped at n/x. a folder made at n/x later, changed
	# so that only its event shows it (a same-size write), is moved into a new folder M with the rename landing right after the
	# watch of M and before its listing: the walk of M finds the folder, re-points its watch and discards the write, and the stale
	# watch at n/x must not make its move-out read as the folder's own, which would keep the move and leave the old bytes
	one = session({'other/o': 'o'})
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	one.run([('mkdir', 'n'), ('mkdir', 'n/x'), ('write', 'n/x/y', 'y')], 'apart')
	one.run([('mv', 'n/x', str(outside / 'x'))], 'apart')
	one.back_up_next()
	one.run([('mkdir', 'n/x'), ('write', 'n/x/f', 'p' * 200000)], 'apart')
	one.back_up_next()
	real_add = rv.inotify_simple.INotify.add_watch
	state = {'moved': False}
	def add_watch(inotify, path, mask):
		wd = real_add(inotify, path, mask)
		if path.rstrip('/') == os.path.join(job.monitor, 'M') and not state['moved']:
			state['moved'] = True
			one.apply(('mv', 'n/x', 'M/x2'))
		return wd
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	with one.unread():
		one.apply(('mkdir', 'M'))
		one.apply(('poke', 'n/x/f'))
	one.back_up_next()
	assert state['moved']
	assert version_view(job) == live_view(job)


@pytest.mark.parametrize('order', range(6))
def test_another_folders_move_out_among_a_folders_rename_events_is_never_its_move(session, job, tmp_path, monkeypatch, order):
	# mkdir n; mv big n/big before the watcher reads n, and on another CPU mv other/y outside/y, which takes no lock of the two folders
	# big's rename holds: its MOVED_FROM and MOVE_SELF can land anywhere among big's. nothing pairs big with a move-out by its
	# MOVE_SELF: in every order the move-out of big is a delete and n is copied, never a move from other/y
	one = session({**SEED, 'other/y/z': 'z' * 100})
	before = version_view(job)
	previous = latest_version(job).path
	real_read, flags = rv.inotify_simple.INotify.read, rv.inotify_simple.flags
	waiting, go = threading.Event(), threading.Event()
	def read(inotify, *args, **kwargs):
		waiting.set()
		go.wait(10)
		events = real_read(inotify, *args, **kwargs)
		monkeypatch.setattr(rv.inotify_simple.INotify, 'read', real_read)
		# one process: create n, then each rename's MOVED_FROM and its folder's MOVE_SELF, as read
		assert [(event.mask & ~flags.ISDIR, event.name) for event in events[:5]] == [(flags.CREATE, 'n'), (flags.MOVED_FROM, 'big'), (flags.MOVE_SELF, ''),
			(flags.MOVED_FROM, 'y'), (flags.MOVE_SELF, '')]
		return events[:1] + list(kernel_merges(events[1:3], events[3:5]))[order] + events[5:]
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	assert waiting.wait(10)
	os.mkdir(os.path.join(job.monitor, 'n'))
	os.rename(os.path.join(job.monitor, 'big'), os.path.join(job.monitor, 'n', 'big'))
	os.rename(os.path.join(job.monitor, 'other', 'y'), tmp_path / 'y')
	go.set()
	batch = one.take()
	moves = [(os.path.relpath(e.path, job.monitor), os.path.relpath(e.moved_from, job.monitor)) for e in batch if e.event == 'move']
	assert moves == []
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'n/big/after')


def test_a_write_kept_at_its_size_and_mtime_in_a_folder_the_walk_found_moved_in_is_in_a_version(session, job, monkeypatch):
	# a/b is made and big moved into it while a is walked: that walk finds big under its old watch, and a's next read, the create of
	# a/b, walks a/b again. a's copy holds big, and a write in it, made so that only its event can show it (inside the file, its mtime
	# set back), is in that copy: its events are discarded until the copy runs
	one = session({**SEED, 'big/a': 'A' * 4096 + TAIL})
	new, big = os.path.join(job.monitor, 'a'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == new and os.path.lexists(big):
			os.mkdir(os.path.join(new, 'b'))
			os.rename(big, os.path.join(new, 'b', 'big'))
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	os.mkdir(new)
	one.settle()
	moved = os.path.join(new, 'b', 'big', 'a')
	stat = os.lstat(moved)
	with open(moved, 'r+b') as f:
		f.seek(100)
		f.write(b'WRITTEN')
	os.utime(moved, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	batch = one.take()
	assert not [e for e in batch if e.event == 'move']
	one.back_up(batch)
	assert version_view(job) == live_view(job)


@pytest.mark.parametrize('into', ['m/big', 'm/s/big'])
def test_a_folder_moved_into_a_folder_from_outside_while_it_is_walked_is_copied(session, job, tmp_path, monkeypatch, into):
	# mv /out/d m; mv big m/big, the second after the watch of m (or m/s) and before m is listed: the walk of a move-in with no known
	# source finds big under its old watch, and the move's own MOVED_TO is discarded, as the walk got there first. m's copy holds big,
	# and a write in it made so that only its event can show it (inside the file, its mtime set back) is in that copy
	one = session({**SEED, 'big/a': 'A' * 4096 + TAIL})
	outside = tmp_path / 'd'
	os.makedirs(outside / 's')
	(outside / 'x').write_text('x')
	m, big = os.path.join(job.monitor, 'm'), os.path.join(job.monitor, 'big')
	landing = os.path.dirname(os.path.join(job.monitor, into))
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == m and os.path.lexists(big):
			if landing == m:
				os.rename(big, os.path.join(job.monitor, into))
				return real(path, *args, **kwargs)
			return rename_at(landing, real(path, *args, **kwargs))
		return real(path, *args, **kwargs)
	def rename_at(folder, entries):
		# the watch of m/s is added as the walk reaches it, and the rename lands right after, before m/s is listed
		for entry in entries:
			yield entry
			if entry[0].rstrip('/') == folder and os.path.lexists(big):
				os.rename(big, os.path.join(job.monitor, into))
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	os.rename(outside, m)
	one.settle()
	monkeypatch.setattr(rv, 'iter_tree_entries', real)
	moved = os.path.join(job.monitor, into, 'a')
	stat = os.lstat(moved)
	with open(moved, 'r+b') as f:
		f.seek(100)
		f.write(b'WRITTEN')
	os.utime(moved, ns=(stat.st_atime_ns, stat.st_mtime_ns))
	batch = one.take()
	assert not [e for e in batch if e.event == 'move']
	one.back_up(batch)
	assert version_view(job) == live_view(job)


def test_a_folder_moved_into_a_new_folder_made_after_its_parents_walk_listed_it_is_copied(session, job, monkeypatch):
	# mkdir -p p/q; mv big p/q/big, with p walked before q exists: q's create is read after that walk, and q's own walk, in the
	# discard of a folder p's copy holds, is the one that finds big under its old watch. no MOVED_TO comes, as q had no watch: p's copy
	# holds big, as on 0.55
	one = session({**SEED, **{f'big/f{i}': f'{i}' * 100000 for i in range(4)}})
	new, big = os.path.join(job.monitor, 'p'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		listed = list(real(path, *args, **kwargs))
		if path.rstrip('/') == new and os.path.lexists(big):
			os.makedirs(os.path.join(new, 'q'))
			os.rename(big, os.path.join(new, 'q', 'big'))
		return iter(listed)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	before = version_view(job)
	previous = latest_version(job).path
	os.mkdir(new)
	batch = one.take()
	assert not [e for e in batch if e.event == 'move']
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'p/q/big/after')


def test_a_folder_the_walk_found_moved_in_and_moved_on_in_a_later_read_ends_as_the_tree(session, job, monkeypatch):
	# the walk of n finds big under its old watch, and it is moved on later, out of the new folder n whose copy holds it
	one = session()
	new, big = os.path.join(job.monitor, 'n'), os.path.join(job.monitor, 'big')
	one.apply(('mkdir', 'n2'))
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		if path.rstrip('/') == new and os.path.lexists(big):
			os.rename(big, os.path.join(new, 'big'))
		return real(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	before = version_view(job)
	previous = latest_version(job).path
	os.mkdir(new)
	one.settle()
	one.apply(('mv', 'n/big', 'n2/big'))
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
	written_after(one, job, 'n2/big/after')


def test_a_folder_moved_into_a_folder_from_outside_before_its_subfolder_is_listed_is_copied(session, job, tmp_path, monkeypatch):
	# mv /out/d m; mv big m/s/big, the second after m is listed and before m/s is watched: the walk of a move-in with no known source finds
	# big under its old watch and records nothing, so big is copied with m, as on 0.55, and its move-out is its delete
	one = session()
	outside = tmp_path / 'd'
	os.makedirs(outside / 's')
	m, big = os.path.join(job.monitor, 'm'), os.path.join(job.monitor, 'big')
	real = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		for entry in real(path, *args, **kwargs):
			if path.rstrip('/') == m and entry[0].rstrip('/') == os.path.join(m, 's') and os.path.lexists(big):
				os.rename(big, os.path.join(m, 's', 'big'))
			yield entry
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	os.rename(outside, m)
	batch = one.take()
	assert not [e for e in batch if e.event == 'move']
	one.back_up(batch)
	assert version_view(job) == live_view(job)
	written_after(one, job, 'm/s/big/after')


def test_a_move_out_waiting_at_the_place_a_folder_is_moved_to_is_its_delete_first(session, job, tmp_path):
	# n/big leaves the tree and n is renamed away, a new n is made and big moved into it, before the watcher reads any: the move-out
	# of the old n/big waits for a pair, and its delete, expiring after the folder landed on that name, must not remove the copied one
	one = session({**SEED, 'n/big/old': 'old'})
	before = version_view(job)
	previous = latest_version(job).path
	with one.unread():
		os.rename(os.path.join(job.monitor, 'n', 'big'), tmp_path / 'oldbig')
		one.run([('mv', 'n', 'n_old'), ('mkdir', 'n'), ('mv', 'big', 'n/big')], 'at_once')
	batch = one.take()
	one.back_up(batch)
	assert_held_as_the_tree(job, before, previous)


def test_a_folder_found_moved_in_takes_its_unwatched_subfolder_off_the_old_path(session, job, monkeypatch):
	# big/sub could not be read when it was watched, so the watcher claims no read time while that stands; moved to n/big, where it is read
	# and watched, it is not unwatched at the old path any more
	state = {'fail': True}
	bad = os.path.join(job.monitor, 'big', 'sub')
	real = os.scandir
	def scandir(path='.'):
		if state['fail'] and os.path.abspath(path) == bad and threading.current_thread() is not threading.main_thread():
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real(path)
	monkeypatch.setattr(os, 'scandir', scandir)
	one = session()
	state['fail'] = False
	with one.unread():
		one.run([('mkdir', 'n'), ('mv', 'big', 'n/big')], 'at_once')
	assert one.take().read_wall_ns is not None


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
	with one.unread():
		one.apply(('mkdir', 'n'))
		one.apply(('mv', 'big', 'n/big'))
		with one.lock:
			one.queue.take()
	one.apply(('write', 'n/big/z', 'z'))
	one.back_up_next()
	assert version_view(job) == live_view(job)


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


def test_a_take_waits_for_the_walk_of_a_folder_moved_into_an_existing_folder(session, job, monkeypatch):
	one = session()
	moved = os.path.join(job.monitor, 'other', 'big')
	at, go = hold_walk(monkeypatch, moved)
	inodes = inodes_of(job)
	try:
		one.apply(('mv', 'big', 'other/big'))
		assert at.wait(10)
		assert not one.lock.acquire(timeout=0.1)
		one.apply(('write', 'other/big/z', 'z'))
	finally:
		go.set()
	one.back_up_next()
	assert version_view(job) == live_view(job)
	assert inodes_of(job)['other/big/a'] == inodes['big/a']


def test_a_batch_handed_back_replays_its_move_once(session, job):
	one = session()
	inodes = inodes_of(job)
	before = version_view(job)
	previous = latest_version(job).path
	one.run([('mv', 'big', 'other/big'), ('write', 'other/big/z', 'z')], 'apart')
	batch = one.take()
	first = rv.change_events_to_backup_entries(batch, job.monitor)
	# as a backup that did not commit hands its batch back, with what came meanwhile behind it
	one.apply(('append', 'other/big/z', 'more'))
	wait_until(lambda: one.events(), message='nothing queued')
	with one.lock:
		one.queue.prepend(rv.backup_entries_to_change_events(first))
	again = one.take()
	assert again.round_tripped
	entries = rv.change_events_to_backup_entries(again, job.monitor)
	assert [(rel.rstrip('/'), values.event) for rel, values in entries.items() if values.event == 'move'] == [(os.path.join(job.monitor, 'other/big'), 'move')]
	one.back_up(again)
	assert_held_as_the_tree(job, before, previous)
	assert inodes_of(job)['other/big/a'] == inodes['big/a']


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
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'f.txt', 'n/f.txt'), ('write', 'n/big/z', 'z')], timing)
	one.back_up_next()
	assert_held_as_the_tree(job, before, previous)
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


# the rows of the review: what a batch writes under a folder moved into a new one, its bytes and the inodes it makes (the new
# folder, what is made, and the probe file of the session)
ESTIMATE_ROWS = [
	('one file rewritten', [('write', 'n/big/a', 'x' * (5 << 20))], 5 << 20, 2),
	('three new files', [('write', f'n/big/{name}', name * (5 << 20)) for name in 'pqr'], 15 << 20, 5),
	('a new folder of two files', [('mkdir', 'n/big/new'), ('write', 'n/big/new/p', 'p' * (5 << 20)), ('write', 'n/big/new/q', 'q' * (5 << 20))], 10 << 20, 5),
]


@pytest.mark.parametrize('patterns', [(), ('no_such_folder/',)], ids=['no_skip_list', 'skip_list'])
@pytest.mark.parametrize('row,writes,written,made', ESTIMATE_ROWS, ids=[row[0] for row in ESTIMATE_ROWS])
def test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one(session, job, monkeypatch, patterns, row, writes, written, made):
	# the folder is taken out of the new folder's size, with what is written in it: that is copied, and a limit would make no room
	one = session(patterns=patterns)
	estimates = []
	real = rv.get_backup_size_inode
	def spy(*args, **kwargs):
		estimates.append(real(*args, **kwargs))
		return estimates[-1]
	monkeypatch.setattr(rv, 'get_backup_size_inode', spy)
	size = vault_bytes(job)
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big')] + writes, 'apart')
	one.back_up_next()
	assert len(estimates) == 1
	grew = vault_bytes(job) - size
	assert written <= estimates[0][0] <= grew
	assert estimates[0][1] == made


ATTRIB_ROWS = [
	('three files touched', [('touch', f'n/big/{name}') for name in ('h1', 'h2', 'h3')], (True, False)),
	('three files chmodded', [('chmod', f'n/big/{name}', 0o600) for name in ('h1', 'h2', 'h3')], (False,)),
]


@pytest.mark.parametrize('patterns', [(), ('no_such_folder/',)], ids=['no_skip_list', 'skip_list'])
@pytest.mark.parametrize('row,changes,only_sync_attributes', [(row, changes, osa) for row, changes, settings in ATTRIB_ROWS for osa in settings],
	ids=[f'{row}-{"osa" if osa else "no_osa"}' for row, _, settings in ATTRIB_ROWS for osa in settings])
def test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one(session, job, monkeypatch, patterns, row, changes, only_sync_attributes):
	# an attrib that copies the file (a new mtime, or any change without Only Sync Attributes) is counted as the same change in an
	# existing folder is: a limit makes room for the 15 MiB
	one = session({**SEED, **{f'big/{name}': name * (5 << 19) for name in ('h1', 'h2', 'h3')}}, patterns=patterns, only_sync_attributes=only_sync_attributes)
	estimates = []
	real = rv.get_backup_size_inode
	def spy(*args, **kwargs):
		estimates.append(real(*args, **kwargs))
		return estimates[-1]
	monkeypatch.setattr(rv, 'get_backup_size_inode', spy)
	size = vault_bytes(job)
	one.run([('mkdir', 'n'), ('mv', 'big', 'n/big')] + changes, 'apart')
	one.back_up_next()
	assert len(estimates) == 1
	grew = vault_bytes(job) - size
	assert 15 << 20 <= estimates[0][0] <= grew
	assert estimates[0][1] == 2
