'''
The watch map of round 22's step back, in process through the real watchFolder on real inotify: a walk never moves a watch the
events hold, what needs the tree's view waits for an empty event queue (settle()), a move reported through a watch that is not
settled is a delete and a create, and an event queue overflow restarts the watch. Each order here kept wrong bytes, lost a
change or left a watch on another folder's path on 0.55.1, or tests a part that 0.55.1 lacks.
'''
import errno
import os
import shutil
import sys
import threading
import time

import pytest

import reverberator as rv
from tests.harness import run_backup, wait_until, watch_map_errors
from tests.test_moves_into_new_folders import live_view, session, version_view  # noqa: F401 (session is the fixture)

pytestmark = pytest.mark.inotify

# more than the 64 KiB the check after a batch compares: two files alike in it, in size and in mtime differ only by an event
TAIL = b't' * (70 << 10)
STAMP = 1_700_000_000_000_000_000


def same_but_head(path, head, tails='same'):
	with open(path, 'wb') as f:
		f.write(head * 1000 + TAIL)
	if tails == 'differ':
		with open(path, 'r+b') as f:
			f.seek(-10, os.SEEK_END)
			f.write(b'0123456789')
	os.utime(path, ns=(STAMP, STAMP))


def wrong(job) -> list:
	version, tree = version_view(job), live_view(job)
	return sorted(rel for rel in set(version) | set(tree) if version.get(rel) != tree.get(rel))


def relative(batch, monitor) -> list:
	return [(e.event, os.path.relpath(e.path, monitor), e.moved_from and os.path.relpath(e.moved_from, monitor)) for e in batch if '.probe' not in e.path]


def latest_map(monkeypatch) -> list:
	'''(inotify, wdDic) of each watch the test starts, newest last: an overflow starts a new one.'''
	maps = []
	real_init = rv.initializeFolderWatchers
	def init(inotify_obj, path, wdDic, *args, **kwargs):
		if not maps or maps[-1][1] is not wdDic:
			maps.append((inotify_obj, wdDic))
		return real_init(inotify_obj, path, wdDic, *args, **kwargs)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', init)
	return maps


def captured_notes(monkeypatch) -> list:
	'''The WatchNotes of each watch the test starts, newest last.'''
	notes = []
	class Captured(rv.WatchNotes):
		__slots__ = ()
		def __init__(self, *args):
			super().__init__(*args)
			notes.append(self)
	monkeypatch.setattr(rv, 'WatchNotes', Captured)
	return notes


def blinded_probes(monkeypatch) -> set:
	'''The paths whose probe (an add_watch with IN_ONLYDIR, as settle() makes them) fails with EIO while in the set.'''
	blind = set()
	real_add = rv.inotify_simple.INotify.add_watch
	def add_watch(inotify, path, mask):
		if mask & rv.inotify_simple.flags.ONLYDIR and path.rstrip('/') in blind:
			raise OSError(errno.EIO, 'a probe that cannot look')
		return real_add(inotify, path, mask)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	return blind


def watch_of(wd_dic, path) -> int:
	return next(wd for wd, held in list(wd_dic.items()) if held.rstrip('/') == path)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('tails', ['same', 'differ'])
def test_a_rename_outside_the_tree_does_not_land_on_the_folder_now_at_the_old_path(session, job, tmp_path, run, tails):
	'''
	Review 5's F1: a folder made in a new folder leaves the tree from it, so its move-out is discarded and its watch stays at
	n/x; another folder made at n/x holds two files alike in size, mtime and last 64 KiB. A rename in the folder outside then
	came as a rename at n/x, the version renamed the other folder's file onto the other name, and the check after the batch
	could not tell (wrong bytes for good, 3 of 3 on 0.55.1 with alike tails).
	'''
	one = session({'other/o': 'o'})
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	m = job.monitor
	one.run([('mkdir', 'n'), ('mkdir', 'n/x'), ('write', 'n/x/g', 'outside g')], 'apart')
	one.run([('mv', 'n/x', str(outside / 'x'))], 'apart')
	one.back_up_next()
	os.mkdir(f'{m}/n/x')
	same_but_head(f'{m}/n/x/g', b'G')
	same_but_head(f'{m}/n/x/h', b'H', tails)
	one.back_up_next()
	assert not wrong(job)
	os.rename(outside / 'x' / 'g', outside / 'x' / 'h')
	batch = one.take()
	one.back_up(batch)
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	bad = wrong(job)
	one.stop()
	# and a restart's whole-tree comparison, which cannot see such a rename either
	run_backup(job, **one.options)
	assert not bad and not wrong(job), (relative(batch, m), bad)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('tails', ['same', 'differ'])
def test_a_nested_move_out_stays_guarded_through_its_parents_rename(session, job, tmp_path, run, tails):
	'''
	The step-back review's finding 1, F1 through an ancestor: keep/s/n2 leaves the tree, keep is renamed while that move-out
	is pending (its pairing moves n2's watch to c/keep2/s/n2), and live lands there. A rename in n2 outside the tree came on
	n2's watch as c/keep2/s/n2/g -> h, and the version renamed live's g onto h. A watch stays guarded while any pending
	move-out holds it, so that rename is a delete and a create (wrong bytes 3 of 3 on 0.55.1 with alike tails).
	'''
	one = session({'keep/s/n2/g': 'n' * 5000, 'live/g': 'x', 'live/h': 'x', 'c/': None, 'other/o': 'o'})
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	m = job.monitor
	same_but_head(f'{m}/live/g', b'G')
	same_but_head(f'{m}/live/h', b'H', tails)
	one.back_up_next()
	assert not wrong(job)
	# one batch, each step read on its own, no quiet read between them: the pair timeout has not passed
	one.run([('mv', 'keep/s/n2', str(outside / 'n2')), ('mv', 'keep', 'c/keep2'), ('mv', 'live', 'c/keep2/s/n2')], 'apart')
	os.rename(outside / 'n2' / 'g', outside / 'n2' / 'h')
	batch = one.take()
	one.back_up(batch)
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	bad = wrong(job)
	one.stop()
	run_backup(job, **one.options)
	assert not bad and not wrong(job), (relative(batch, m), bad)


def lose(monkeypatch, names):
	'''The next read that holds an event named in names loses every such event, and ends with a Q_OVERFLOW.'''
	real_read = rv.inotify_simple.INotify.read
	state = {'done': False}
	def read(inotify, *args, **kwargs):
		events = real_read(inotify, *args, **kwargs)
		if state['done'] or not any(e.name in names for e in events):
			return events
		state['done'] = True
		kept = [e for e in events if e.name not in names]
		return kept + [rv.inotify_simple.Event(-1, rv.inotify_simple.flags.Q_OVERFLOW, 0, '')]
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	return state


def back_up_batch(one, job, batch):
	if batch.full_scan_requested:
		return run_backup(job, **one.options)
	return one.back_up(batch)


def poke(path):
	stat = os.lstat(path)
	with open(path, 'r+b') as f:
		f.write(b'POKED')
	os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('case', ['lost_create', 'lost_move_out', 'lost_rename'])
def test_an_overflow_leaves_the_watches_on_the_tree(session, job, tmp_path, monkeypatch, case, run):
	'''
	An event queue overflow, made by hand (lowering max_queued_events needs root): the read that holds the chosen events loses
	them, and a Q_OVERFLOW takes their place, as a full queue does. lost_create: n's create lost, so 0.55.1 never watched it;
	lost_move_out: big's move-out lost, so its watches stayed in the tree; lost_rename: big renamed to b2 unseen, then changed
	so that only its event shows it. The watch starts again on the tree as it is (0.55.1: 9 of 9 wrong).
	'''
	maps = latest_map(monkeypatch)
	one = session({'big/a': 'p' * 200000, 'big/sub/b': 'b' * 100, 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	if case == 'lost_create':
		lose(monkeypatch, {'n'})
		with one.unread():
			os.makedirs(f'{m}/n/s')
			open(f'{m}/n/f', 'w').write('f')
	elif case == 'lost_move_out':
		lose(monkeypatch, {'big'})
		with one.unread():
			os.rename(f'{m}/big', outside / 'big')
	else:
		lose(monkeypatch, {'big', 'b2'})
		with one.unread():
			os.rename(f'{m}/big', f'{m}/b2')
	# a full scan takes every later event in (the queue keeps none), so the batch is taken once it is there and signalled
	wait_until(lambda: one.queue.full_scan_requested, message='no overflow handled')
	one.flag.clear()
	wait_until(one.flag.is_set, message='watcher did not signal the backuper')
	with one.lock:
		batch = one.queue.take()
	one.flag.clear()
	one.settle()
	assert batch.full_scan_requested
	back_up_batch(one, job, batch)
	if case == 'lost_create':
		open(f'{m}/n/g', 'w').write('g')
		open(f'{m}/n/s/h', 'w').write('h')
	elif case == 'lost_move_out':
		os.makedirs(f'{m}/big/sub')
		open(f'{m}/big/sub/new', 'w').write('n')
		os.remove(outside / 'big' / 'sub' / 'b')
	else:
		poke(f'{m}/b2/a')
	back_up_batch(one, job, one.take())
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not wrong(job) and not stale and not missing, (wrong(job), stale, missing)


def test_a_big_move_out_is_unwatched_in_parts_that_fit_the_queue(session, job, tmp_path, monkeypatch):
	'''
	Each removed watch queues an IN_IGNORED, which counts against the queue limit the kernel read when the instance was made:
	the watches of a folder of 300 folders moved out of the tree go at most half that limit at a time, with no overflow,
	all of them within a few settles. The limit is 64 here as the watch reads it; the kernel's stays as it is.
	'''
	class SmallQueue(rv.inotify_resource_manager):
		def __init__(self):
			super().__init__()
			self.max_queued_events = 64
	monkeypatch.setattr(rv, 'inotify_resource_manager', SmallQueue)
	removed = []
	real_remove = rv.remove_watches
	def remove(inotify_obj, wd_dic, irm, wds, *args, **kwargs):
		wds = list(wds)
		removed.append(len([wd for wd in wds if wd in wd_dic]))
		return real_remove(inotify_obj, wd_dic, irm, wds, *args, **kwargs)
	monkeypatch.setattr(rv, 'remove_watches', remove)
	watches = []
	real_watch = rv.watchFolder
	def watch(**kwargs):
		watches.append(1)
		return real_watch(**kwargs)
	monkeypatch.setattr(rv, 'watchFolder', watch)
	maps = latest_map(monkeypatch)
	one = session({**{f'big/d{i}/f': 'x' for i in range(300)}, 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	gone = [wd for wd, path in list(maps[-1][1].items()) if path.startswith(f'{m}/big')]
	assert len(gone) == 301
	os.rename(f'{m}/big', outside / 'big')
	one.back_up_next()
	wait_until(lambda: not set(gone) & set(maps[-1][1]), message='the watches of the folder that left are still held')
	assert sum(removed) == 301 and max(removed) <= 32, removed
	assert len(watches) == 1, 'the watch started again'
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not wrong(job) and not stale and not missing, (wrong(job), stale, missing)


QUEUE_LIMIT = '/proc/sys/fs/inotify/max_queued_events'


@pytest.mark.privileged
@pytest.mark.skipif(os.geteuid() != 0 or 'PYTEST_XDIST_WORKER' in os.environ,
	reason='sets the host-wide fs.inotify.max_queued_events: as root, alone (no xdist), in the test VM')
def test_a_big_move_out_fits_a_real_queue_of_64(session, job, tmp_path, monkeypatch):
	'''The same with the kernel's limit really 64 while the watch's instance is made: 301 removals at once overflowed it.'''
	with open(QUEUE_LIMIT) as f:
		before = f.read().strip()
	overflows = []
	real_read = rv.inotify_simple.INotify.read
	def read(inotify, *args, **kwargs):
		events = real_read(inotify, *args, **kwargs)
		overflows.extend(e for e in events if e.mask & rv.inotify_simple.flags.Q_OVERFLOW)
		return events
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	maps = latest_map(monkeypatch)
	try:
		with open(QUEUE_LIMIT, 'w') as f:
			f.write('64')
		one = session({**{f'big/d{i}/f': 'x' for i in range(300)}, 'other/o': 'o'})
	finally:
		# the kernel read it when the watch's instance was made
		with open(QUEUE_LIMIT, 'w') as f:
			f.write(before)
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	gone = [wd for wd, path in list(maps[-1][1].items()) if path.startswith(f'{m}/big')]
	os.rename(f'{m}/big', outside / 'big')
	one.back_up_next()
	wait_until(lambda: not set(gone) & set(maps[-1][1]), message='the watches of the folder that left are still held')
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not overflows and len(maps) == 1
	assert not wrong(job) and not stale and not missing, (wrong(job), stale, missing)


def test_the_maximum_delay_counts_on_across_overflows(job, monkeypatch, poll_fast):
	'''
	While events never pause only the maximum delay takes a batch: a watch started again after an overflow counts it from the
	old watch's last take, so overflows that keep coming (a sysctl that cannot be raised) never put the batch off for ever.
	'''
	monitor = job.monitor
	os.makedirs(os.path.join(monitor, 'd'), exist_ok=True)
	real_read = rv.inotify_simple.INotify.read
	state = {'next': time.monotonic() + 0.3, 'overflows': 0}
	def read(inotify, *args, **kwargs):
		events = real_read(inotify, *args, **kwargs)
		if time.monotonic() < state['next']:
			return events
		state['next'] = time.monotonic() + 0.3
		state['overflows'] += 1
		return list(events) + [rv.inotify_simple.Event(-1, rv.inotify_simple.flags.Q_OVERFLOW, 0, '')]
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	queue, lock, flag = rv.ChangeEventQueue(monitor), threading.Lock(), threading.Event()
	ready, stop = threading.Event(), threading.Event()
	ready.set()
	def write():
		i = 0
		while not stop.is_set():
			with open(os.path.join(monitor, 'd', f'f{i % 20}'), 'w') as f:
				f.write('x')
			i += 1
			time.sleep(0.02)
	# a minimum delay never reached while the writes go on, and a maximum delay of 1 s
	watching = threading.Thread(target=rv.watcher, args=(ready, monitor, queue, lock, flag, rv.inotify_resource_manager(), 30, 1), daemon=True)
	writer = threading.Thread(target=write, daemon=True)
	writer.start()
	watching.start()
	try:
		assert flag.wait(6), f'no batch signalled in 6 s, with the maximum delay at 1 s and {state["overflows"]} overflows'
		assert state['overflows'] >= 2
	finally:
		stop.set()
		rv.GREEN_LIGHT.clear()
		watching.join(10)
		writer.join(5)
		rv.GREEN_LIGHT.set()


def test_removing_a_watch_already_gone_does_nothing():
	class FakeINotify:
		def __init__(self):
			self.removed = []
		def rm_watch(self, wd):
			self.removed.append(wd)
	class FakeIrm:
		decreased = 0
		def decreaseUserWatches(self, count=1):
			self.decreased += count
	inotify_obj, irm, wd_dic, forgotten = FakeINotify(), FakeIrm(), {1: '/m/a/', 2: '/m/b/'}, []
	assert rv.remove_watches(inotify_obj, wd_dic, irm, [1, 3, 1], forgotten.append) == 1
	assert inotify_obj.removed == [1] and irm.decreased == 1 and wd_dic == {2: '/m/b/'} and forgotten == [1]


@pytest.mark.parametrize('kind', ['found', 'leaving', 'doubtful'])
def test_a_folder_deleted_while_its_watch_is_flagged_leaves_every_set(session, job, tmp_path, monkeypatch, kind):
	'''A watch that leaves the watch map leaves found, leaving, doubtful and outgoing with it.'''
	notes = captured_notes(monkeypatch)
	maps = latest_map(monkeypatch)
	blind = blinded_probes(monkeypatch)
	one = session({'big/a': 'a', 'big/sub/b': 'b', 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	wd = watch_of(maps[-1][1], f'{m}/big')
	flagged = lambda: getattr(notes[-1], kind)
	if kind == 'found':
		# back from outside under a new name in one read: the move-in's walk notes big's watch at big2
		blind.add(f'{m}/big2')
		with one.unread():
			os.rename(f'{m}/big', outside / 'big')
			os.rename(outside / 'big', f'{m}/big2')
		wait_until(lambda: wd in flagged(), message='not found')
		shutil.rmtree(f'{m}/big2')
	elif kind == 'leaving':
		# out of the tree: its move-out expires at the quiet read
		blind.add(f'{m}/big')
		os.rename(f'{m}/big', outside / 'big')
		wait_until(lambda: wd in flagged(), message='not leaving')
		shutil.rmtree(outside / 'big')
	else:
		# swapped by one rename: both watches were taken from one path
		blind.update({f'{m}/big', f'{m}/other'})
		one.apply(('exchange', 'big', 'other'))
		wait_until(lambda: wd in flagged(), message='not doubtful')
		shutil.rmtree(f'{m}/other')
	wait_until(lambda: wd not in maps[-1][1], message='the deleted folder is still watched')
	left = notes[-1]
	assert not [name for name in ('found', 'found_takes', 'leaving', 'doubtful', 'outgoing') if wd in getattr(left, name)]


def test_a_probe_that_cannot_look_leaves_the_watch_flagged(session, job, tmp_path, monkeypatch):
	'''A probe that fails (EIO, a dead mergerfs) is never taken for an absence: the watch stays leaving until one answers.'''
	notes = captured_notes(monkeypatch)
	maps = latest_map(monkeypatch)
	blind = blinded_probes(monkeypatch)
	one = session({'big/a': 'a', 'big/sub/b': 'b', 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	wd = watch_of(maps[-1][1], f'{m}/big')
	blind.add(f'{m}/big')
	os.rename(f'{m}/big', outside / 'big')
	one.back_up_next()
	wait_until(lambda: wd in notes[-1].leaving, message='not leaving')
	# the watcher reads every 0.05 s here, each read a settle that probes it again
	time.sleep(0.3)
	assert wd in maps[-1][1] and wd in notes[-1].leaving
	blind.clear()
	one.apply(('write', 'other/marker', 'm'))
	wait_until(lambda: wd not in maps[-1][1], message='the watch of the folder that left is still held')
	assert wd not in notes[-1].leaving
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not wrong(job) and not stale and not missing, (wrong(job), stale, missing)


def test_the_kernel_tells_a_renamed_folder_its_move(tmp_path):
	'''
	What the watcher's MOVE_SELF rule rests on: a rename of a folder with a watch of its own is reported to that watch
	(IN_MOVE_SELF) after the rename's MOVED_FROM and MOVED_TO, out of the watched tree too; a folder with no watch of its own,
	or a watched subfolder of the moved one, gets none.
	'''
	flags = rv.inotify_simple.flags
	mask = flags.MOVED_FROM | flags.MOVED_TO | flags.MOVE_SELF | flags.CREATE
	tree, outside = tmp_path / 'tree', tmp_path / 'outside'
	outside.mkdir()
	def renamed(watched, to):
		shutil.rmtree(tree, ignore_errors=True)
		os.makedirs(tree / 'd' / 's')
		with rv.inotify_simple.INotify() as inotify:
			names = {inotify.add_watch(str(tree), mask): 'tree'}
			for rel in watched:
				names[inotify.add_watch(str(tree / rel), mask)] = rel
			os.rename(tree / 'd', to)
			shutil.rmtree(to)
			kinds = {flags.MOVED_FROM: 'from', flags.MOVED_TO: 'to', flags.MOVE_SELF: 'self'}
			return [(names[event.wd], next(name for flag, name in kinds.items() if event.mask & flag)) for event in inotify.read(timeout=1000) if event.mask & (flags.MOVED_FROM | flags.MOVED_TO | flags.MOVE_SELF)]
	assert renamed(['d', 'd/s'], tree / 'e') == [('tree', 'from'), ('tree', 'to'), ('d', 'self')]
	assert renamed(['d'], outside / 'e') == [('tree', 'from'), ('d', 'self')]
	assert renamed([], tree / 'e') == [('tree', 'from'), ('tree', 'to')]
	assert renamed(['d/s'], tree / 'e') == [('tree', 'from'), ('tree', 'to')]


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('watched', [True, False], ids=['watched', 'never_watched'])
def test_a_folder_renamed_twice_out_of_a_new_folder_leaves_no_watch(session, job, tmp_path, monkeypatch, watched, run):
	'''
	A folder made in a new folder, renamed in it and then out of the tree in one read, and another made at its first name: the
	discarded move-out keeps no cookie, and the move-in's walk finds the folder gone, so only its IN_MOVE_SELF tells the watch
	that left with it (a folder that never had one, its create read with its renames, tells nothing and needs nothing).
	'''
	maps = latest_map(monkeypatch)
	one = session({'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	one.run([('mkdir', 'n')], 'apart')
	if watched:
		one.run([('mkdir', 'n/d/s')], 'apart')
		one.settle()
		assert any(held.rstrip('/') == f'{m}/n/d/s' for held in maps[-1][1].values())
	with one.unread():
		if not watched:
			os.makedirs(f'{m}/n/d/s')
		os.rename(f'{m}/n/d', f'{m}/n/e')
		os.rename(f'{m}/n/e', outside / 'e')
		os.makedirs(f'{m}/n/d/s')
	one.back_up_next()
	open(outside / 'e' / 's' / 'w', 'w').write('w')
	one.apply(('write', 'n/d/s/f', 'f'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not wrong(job) and not stale and not missing, (wrong(job), stale, missing)


def test_the_kernel_queues_a_folders_move_self_within_its_rename(tmp_path):
	'''
	What the MOVE_SELF rule's take window rests on: once rename() returns, the queue holds the folder's IN_MOVE_SELF with
	the rename's MOVED_FROM or MOVED_TO, yet a read can end between the two (a reader that took only part of the queue),
	which leaves the IN_MOVE_SELF to a later read.
	'''
	flags = rv.inotify_simple.flags
	mask = flags.MOVED_FROM | flags.MOVED_TO | flags.MOVE_SELF
	tree, outside = tmp_path / 'tree', tmp_path / 'outside'
	os.makedirs(tree / 'd')
	outside.mkdir()
	kinds = lambda events: [(e.wd, e.mask & ~flags.ISDIR) for e in events]
	with rv.inotify_simple.INotify() as inotify:
		top = inotify.add_watch(str(tree), mask)
		moved = inotify.add_watch(str(tree / 'd'), mask)
		# no wait: what each rename() queued before it returned
		os.rename(tree / 'd', outside / 'd')
		assert kinds(inotify.read(timeout=0)) == [(top, flags.MOVED_FROM), (moved, flags.MOVE_SELF)]
		os.rename(outside / 'd', tree / 'd')
		assert kinds(inotify.read(timeout=0)) == [(top, flags.MOVED_TO), (moved, flags.MOVE_SELF)]
		os.rename(tree / 'd', outside / 'd')
		# a read whose buffer holds the first event alone (16 bytes, and the name d padded to 16), then the next read
		first = rv.inotify_simple.parse_events(os.read(inotify.fileno(), 32))
		rest = inotify.read(timeout=0)
	assert kinds(first) == [(top, flags.MOVED_FROM)] and kinds(rest) == [(moved, flags.MOVE_SELF)]


def split_move_self(one, monkeypatch, name, lag):
	'''
	The read that holds the move-out of the folder name ends right after its MOVED_FROM, and a batch is taken before the next
	read (held for back_up_next()). The folder's IN_MOVE_SELF comes in that next read, or, with lag 'read_after', in the
	read after it, the next one holding a write of other/w alone. state['stage'] is 3 once the IN_MOVE_SELF was read. It
	returns once the watcher reads through it (a read begun before it was set is over).
	'''
	real_read, flags = rv.inotify_simple.INotify.read, rv.inotify_simple.flags
	state = {'rest': None, 'stage': 0}
	reading = threading.Event()
	def read(inotify, *args, **kwargs):
		reading.set()
		if state['stage'] == 0:
			events = real_read(inotify, *args, **kwargs)
			at = next((i for i, e in enumerate(events) if e.mask & flags.MOVED_FROM and e.name == name), None)
			if at is None:
				return events
			state['rest'] = events[at + 1:]
			assert any(e.mask & flags.MOVE_SELF for e in state['rest']), events
			state['stage'] = 1
			return events[:at + 1]
		if state['stage'] == 1:
			with one.lock:
				one.held.append(one.queue.take())
			if lag == 'read_after':
				state['stage'] = 2
				one.apply(('write', 'other/w', 'w'))
				return real_read(inotify, *args, **kwargs)
		if state['stage'] in (1, 2):
			state['stage'] = 3
			return state['rest']
		return real_read(inotify, *args, **kwargs)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	assert reading.wait(10), 'the watcher did not read'
	return state


@pytest.mark.parametrize('run', range(2))
@pytest.mark.parametrize('lag', ['next_read', 'read_after'])
def test_a_move_out_of_a_new_folder_whose_move_self_comes_after_a_take_leaves_no_watch(session, job, tmp_path, monkeypatch, lag, run):
	'''
	The MOVE_SELF rule's take window: a folder made in a new folder leaves the tree from it (no cookie), the read ends between
	its MOVED_FROM and its IN_MOVE_SELF, and a batch is taken before the IN_MOVE_SELF is read, which clears newDirWDs. The
	watch must still leave: else it stays at n/x, and review 5's F1 follows (another folder made at n/x with two files alike
	in size, mtime and last 64 KiB; a rename in the folder outside came as a rename at n/x, onto the other file's bytes).
	'''
	maps = latest_map(monkeypatch)
	one = session({'other/o': 'o'})
	outside = tmp_path / 'outside'
	os.makedirs(outside)
	m = job.monitor
	one.run([('mkdir', 'n'), ('mkdir', 'n/x'), ('write', 'n/x/g', 'outside g')], 'apart')
	one.settle()
	state = split_move_self(one, monkeypatch, 'x', lag)
	one.apply(('mv', 'n/x', str(outside / 'x')))
	wait_until(lambda: state['stage'] == 3, message='the IN_MOVE_SELF was not read')
	one.back_up_next()
	os.mkdir(f'{m}/n/x')
	same_but_head(f'{m}/n/x/g', b'G')
	same_but_head(f'{m}/n/x/h', b'H')
	one.back_up_next()
	assert not wrong(job)
	os.rename(outside / 'x' / 'g', outside / 'x' / 'h')
	batch = one.take()
	one.back_up(batch)
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	bad = wrong(job)
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert not bad and not stale and not missing, (relative(batch, m), bad, stale, missing)


def watch_of_or_none(wd_dic, path):
	return next((wd for wd, held in list(wd_dic.items()) if held.rstrip('/') == path), None)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('blinded', [True, False], ids=['blind', 'control'])
def test_a_doubtful_watch_whose_place_cannot_be_probed_is_not_removed(session, job, tmp_path, monkeypatch, blinded, run):
	'''
	Review 1: big/sub and next2/sub swapped by one rename (both watches, at big/sub, doubtful with next2/sub before), then big
	moved out of the tree in the same read, so its move-out holds big/sub's watches and makes them leaving at its expiry.
	The probe of next2/sub, where big's old sub lives on, cannot look (EIO): settle() step 2 keeps that watch doubtful for
	the next settle, and step 3 must leave it too, not probe it at big/sub, find nothing and remove it (next2/sub then had
	no watch, and a later change in it no event).
	'''
	maps = latest_map(monkeypatch)
	blind = blinded_probes(monkeypatch)
	one = session({'big/a': 'a' * 100, 'big/sub/b': 'b' * 100, 'next2/sub/z': 'z' * 100, 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	sub = watch_of(maps[-1][1], f'{m}/big/sub')
	if blinded:
		blind.add(f'{m}/next2/sub')
	with one.unread():
		one.apply(('exchange', 'big/sub', 'next2/sub'))
		os.rename(f'{m}/big', outside / 'big')
	# big's move-out expires at the quiet read, and that read's settle runs its leaving watches
	wait_until(lambda: watch_of_or_none(maps[-1][1], f'{m}/big') is None, message='big still watched')
	time.sleep(0.5)
	held_during = sub in maps[-1][1]
	blind.clear()
	time.sleep(0.5)
	one.apply(('write', 'next2/sub/new', 'n'))
	one.back_up_next()
	# a change in a later batch, which no comparison of the swap covers
	one.apply(('write', 'next2/sub/later', 'l'))
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert held_during and not wrong(job) and not stale and not missing, (held_during, wrong(job), stale, missing)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('during', [True, False], ids=['moved_during_settle', 'moved_after_settle'])
def test_a_placed_watch_whose_folder_leaves_before_the_settles_walk(session, job, tmp_path, monkeypatch, during, run):
	'''
	Review 1: settle() puts a found watch in place in a new folder (step 1); step 5's walk of that place would put it into
	newDirWDs (rule 2). If the folder leaves the tree from the new folder between the placement and that walk, the walk
	fails: the watch must be in newDirWDs from its placement, or its IN_MOVE_SELF is skipped, the watch stays at its old
	place, and review 5's F1 follows. The control moves the folder once the settle's walk of it is done.
	'''
	maps = latest_map(monkeypatch)
	one = session({'big/a': 'a' * 100, 'big/sub/b': 'b' * 100, 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	state = {'moved': False, 'walked': False}
	real_init = rv.initializeFolderWatchers
	def init(inotify_obj, path, *args, **kwargs):
		by_settle = sys._getframe(1).f_code.co_name == 'settle' and path.rstrip('/') == f'{m}/n/big'
		if by_settle and during and not state['moved']:
			# the folder put in place leaves the tree from the new folder before the settle's walk of it
			state['moved'] = True
			os.rename(f'{m}/n/big', outside / 'b2')
		result = real_init(inotify_obj, path, *args, **kwargs)
		if by_settle:
			state['walked'] = True
		return result
	monkeypatch.setattr(rv, 'initializeFolderWatchers', init)
	# in one read: n made, big out of the tree and back into n (a create: its move-out's cookie is not the move-in's), and a
	# folder made at big's old place, which expires big's move-out (its watches leaving, let go)
	with one.unread():
		os.mkdir(f'{m}/n')
		os.rename(f'{m}/big', outside / 'big')
		os.rename(outside / 'big', f'{m}/n/big')
		os.mkdir(f'{m}/big')
	wait_until(lambda: state['walked'], message='the settle did not walk n/big')
	if not during:
		os.rename(f'{m}/n/big', outside / 'b2')
	one.back_up_next()
	stale_after_move, _ = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	# review 5's F1 from here: a folder made at n/big with two files alike in size, mtime and last 64 KiB
	os.mkdir(f'{m}/n/big')
	same_but_head(f'{m}/n/big/a', b'G')
	same_but_head(f'{m}/n/big/h', b'H')
	one.back_up_next()
	assert not wrong(job)
	os.rename(outside / 'b2' / 'a', outside / 'b2' / 'h')
	batch = one.take()
	one.back_up(batch)
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	bad = wrong(job)
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert state['moved'] or not during
	assert not stale_after_move and not bad and not stale and not missing, (relative(batch, m), stale_after_move, bad, stale, missing)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('when', ['before_the_create_is_read', 'after'])
def test_a_folder_made_during_the_first_walk_whose_subfolder_leaves(session, job, tmp_path, monkeypatch, when, run):
	'''
	The final review's finding 1, through the first walk: a folder made while the first walk runs, in a folder the walk has
	watched and not listed yet, so its create is queued and the walk watches it and its subfolder, neither as new. The
	subfolder leaves the tree before the create is read: the create's walk then makes the folder new, the subfolder's
	move-out is read on it and discarded (no cookie), and only the subfolder's IN_MOVE_SELF tells the move. With the
	MOVE_SELF rule's old set condition the watch, in no set, was skipped and stayed at a/n/w (3 of 3). The control moves
	the subfolder out once its parent's create is read.
	'''
	maps = latest_map(monkeypatch)
	outside = tmp_path / 'outside'
	outside.mkdir()
	m = job.monitor
	flags = rv.inotify_simple.flags
	real_add, real_read = rv.inotify_simple.INotify.add_watch, rv.inotify_simple.INotify.read
	state = {'made': False, 'moved': False}
	def add_watch(inotify, path, mask):
		wd = real_add(inotify, path, mask)
		if not state['made'] and path.rstrip('/') == f'{m}/a' and not mask & flags.ONLYDIR:
			# a is watched and not listed yet
			state['made'] = True
			os.makedirs(f'{m}/a/n/w')
		return wd
	def read(inotify, *args, **kwargs):
		if when == 'before_the_create_is_read' and state['made'] and not state['moved']:
			state['moved'] = True
			os.rename(f'{m}/a/n/w', outside / 'w')
		return real_read(inotify, *args, **kwargs)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	one = session({'a/x': 'x', 'other/o': 'o'})
	assert state['made']
	held = sorted(os.path.relpath(path, m) for path in maps[-1][1].values())
	if when == 'after':
		one.settle()
		os.rename(f'{m}/a/n/w', outside / 'w')
	one.back_up_next()
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list, add_watch=real_add)
	# the watch map alone: the session drops the batch it takes at its start, which holds the create made during the walk
	assert not stale and not missing, (held, stale, missing)


@pytest.mark.parametrize('run', range(3))
@pytest.mark.parametrize('order', ['interleaved', 'as_made'])
def test_a_move_self_between_an_ancestors_move_out_and_its_pair(session, job, tmp_path, monkeypatch, order, run):
	'''
	The final review's finding 2: a subfolder of a folder made in the batch leaves the tree (its move-out read on the new
	folder's watch, so no cookie), while a folder above them is renamed inside the tree by another thread, the kernel
	queueing the subfolder's MOVED_FROM and IN_MOVE_SELF between the ancestor rename's MOVED_FROM and MOVED_TO. The
	ancestor's move-out holds the subfolder's watch when its IN_MOVE_SELF is read, and its pair then takes the watch to
	y/n/w: with the old rule, which skipped any watch a move-out held, it stayed there (3 of 3). The order is forced on the
	read: the two renames are made one after the other, unread, and their events handed over as two threads can queue
	them. The control hands them over as made (the subfolder's first).
	'''
	maps = latest_map(monkeypatch)
	one = session({'x/keep': 'k', 'other/o': 'o'})
	m = job.monitor
	outside = tmp_path / 'outside'
	outside.mkdir()
	one.run([('mkdir', 'x/n'), ('mkdir', 'x/n/w')], 'apart')
	one.settle()
	w = watch_of(maps[-1][1], f'{m}/x/n/w')
	flags = rv.inotify_simple.flags
	real_read = rv.inotify_simple.INotify.read
	state = {'done': False, 'seen': None}
	def read(inotify, *args, **kwargs):
		events = real_read(inotify, *args, **kwargs)
		if state['done'] or not any(e.mask & flags.MOVED_TO and e.name == 'y' for e in events):
			return events
		state['done'] = True
		sub = [e for e in events if (e.mask & flags.MOVED_FROM and e.name == 'w') or (e.mask & flags.MOVE_SELF and e.wd == w)]
		first = [e for e in events if e.mask & flags.MOVED_FROM and e.name == 'x']
		rest = [e for e in events if e not in sub and e not in first]
		assert len(sub) == 2 and len(first) == 1, events
		state['seen'] = [(e.wd, str(flags.from_mask(e.mask)), e.name) for e in (first + sub + rest if order == 'interleaved' else events)]
		return first + sub + rest if order == 'interleaved' else events
	# before unread(), which puts back the read it found
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	with one.unread():
		os.rename(f'{m}/x/n/w', outside / 'w')
		os.rename(f'{m}/x', f'{m}/y')
	one.back_up_next()
	one.apply(('write', 'other/marker', 'm'))
	one.back_up_next()
	stale, missing = watch_map_errors(*maps[-1], m, skip_list=one.skip_list)
	assert state['done'] and not wrong(job) and not stale and not missing, (state['seen'], wrong(job), stale, missing)
