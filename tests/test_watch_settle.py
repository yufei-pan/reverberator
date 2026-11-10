'''
The watch map of round 22's step back, in process through the real watchFolder on real inotify: a walk never moves a watch the
events hold, what needs the tree's view waits for an empty event queue (settle()), a move reported through a watch that is not
settled is a delete and a create, and an event queue overflow restarts the watch. Each order here kept wrong bytes, lost a
change or left a watch on another folder's path on 0.55.1, or tests a part that 0.55.1 lacks.
'''
import os

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
