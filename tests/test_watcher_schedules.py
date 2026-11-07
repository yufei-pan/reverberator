'''
Bounded schedule enumeration through the real watcher on real inotify. A shape's steps run inside the watcher's own thread, step
i at the t_i-th visit of a hook (before a read, before each event is handled, before and after each add_watch, at each entry of a
walk), for vectors t of visits that never go down. That reaches orders free scheduling almost never gives: a rename landing
between a new folder's watch and its listing, or between a walk and the read of what it raced. The fuzz and the take points never
found the two that a second review found this way in two minutes.

After the steps, everything settles, a marker goes into every folder, and the newest version must equal the tree: a folder that
left every version, a change a discard threw away, or a folder with no working watch shows.

The first step runs at the first visit. The suite runs every vector up to H visits of a short shape, and a deterministic sample
of SAMPLE out of them for a longer one. REVERB_WATCH_SCHED_H, REVERB_WATCH_SCHED_SAMPLE (0 for all) and REVERB_WATCH_SCHED_SHAPES (names, by commas) widen it.
'''
import itertools
import os
import random
import shutil
import time

import pytest

import reverberator as rv
from tests.harness import wait_until
from tests.test_moves_into_new_folders import live_view, session, version_view  # session is the fixture

pytestmark = pytest.mark.inotify

# the visits a shape's steps may land at: all of them for a short shape, where the window is a visit or two wide
H = {'moved_into_a_folder_from_outside': 12, 'poke_between': 12, 'cpp_between': 12, 'in_then_poke_mv': 12, 'twice_in_new': 12, 'twice_in_new_sub': 12}
H_DEFAULT = 16
SAMPLE = int(os.environ.get('REVERB_WATCH_SCHED_SAMPLE', '100'))
BIG = 'p' * 200000
TREE = {'big/a': BIG, 'big/sub/b': BIG, 'big/sub/deep/x': 'x' * 100, 'next/z': 'z' * 100, 'f.txt': 'f' * 300, 'other/o': 'o', 'keep/k': 'k'}
SHAPES = {
	# a folder made at the old path of the folder the walk of n found, and moved on before its own walk (R1)
	'made_at_a_found_folders_old_path': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mv', 'next', 'big'), ('mkdir', 'big/new'), ('mv', 'big/new', 'big/sub'),
		('mv', 'big/sub', 'other/sub')],
	# the same at a top path whose move-out was read before the walk (R1)
	'made_at_an_old_path_read_out_first': [('mv', 'big', '{outside}/big'), ('mkdir', 'n'), ('mv', '{outside}/big', 'n/big'), ('mkdir', 'big'),
		('mv', 'big', 'other/e')],
	# a folder moved into one that came in from outside, while that one is walked, then changed so that only its event shows it (R2)
	'moved_into_a_folder_from_outside': [('mv', '{outside}/d', 'm'), ('mv', 'big', 'm/big'), ('poke', 'm/big/a')],
	# a chain through a new folder made at a found folder's place, as fuzz seed 2854 had it
	'chain_through_a_new_folder': [('mkdir', 'A'), ('mv', 'big', 'A/n2'), ('mkdir', 'M'), ('mv', 'A', 'M/n2'), ('poke', 'M/n2/n2/a')],
	# a change that only its event shows, made between mkdir n and the rename that carries the folder into it: the rename can land
	# right after the new folder's watch, before the walk lists it, and then the walk got there first (the third review's F3)
	'poke_between': [('mkdir', 'n'), ('poke', 'big/a'), ('mv', 'big', 'n/big')],
	# the same as cp -p of a same-size release file does it: other bytes, the same size and mtime
	'cpp_between': [('mkdir', 'n'), ('cpp', 'big/sub/b'), ('mv', 'big', 'n/big')],
	# the same into a folder that came in from outside
	'in_then_poke_mv': [('mv', '{outside}/d', 'm'), ('poke', 'big/a'), ('mv', 'big', 'm/big')],
	# moved on into another new folder, a folder made at its old place, and a change that only its event shows
	'found_twice': [('mkdir', 'n'), ('mv', 'big', 'n/big'), ('mkdir', 'm'), ('mv', 'n/big', 'm/big'), ('mv', 'next', 'big'), ('poke', 'm/big/sub/b')],
	# renamed again inside the new folder: the walk can list the folder at its last name and re-point its own watch there before
	# the first rename's events are read, so the change's event is discarded and the first move must not be kept (the fourth review's F1)
	'twice_in_new': [('mkdir', 'n'), ('poke', 'big/a'), ('mv', 'big', 'n/big'), ('mv', 'n/big', 'n/c')],
	# the same in a subfolder of the new folder
	'twice_in_new_sub': [('mkdir', 'n'), ('mkdir', 'n/s'), ('poke', 'big/a'), ('mv', 'big', 'n/s/big'), ('mv', 'n/s/big', 'n/s/c')],
}
NAMES = [name for name in os.environ.get('REVERB_WATCH_SCHED_SHAPES', ','.join(SHAPES)).split(',') if name]


def vectors(name):
	# the first step at the first visit: before it the watcher only reads an idle tree, so a later start is the same schedule
	steps = len(SHAPES[name])
	bound = int(os.environ.get('REVERB_WATCH_SCHED_H', H.get(name, H_DEFAULT)))
	every = [(0, *rest) for rest in itertools.combinations_with_replacement(range(bound), steps - 1)]
	return every if not SAMPLE or len(every) <= SAMPLE else sorted(random.Random(name).sample(every, SAMPLE))


CASES = [(name, vector) for name in NAMES for vector in vectors(name)]


def folders_of(root):
	return [os.path.relpath(os.path.join(base, name), root) for base, names, _ in os.walk(root) for name in names]


@pytest.fixture
def folders_removed(tmp_path):
	'''Asked for before session, so torn down after its watcher stopped: thousands of schedules would leave millions of inodes.'''
	yield
	shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.mark.parametrize('name,vector', CASES, ids=[f'{name}-{"_".join(map(str, vector))}' for name, vector in CASES])
def test_a_schedule_ends_as_the_tree(folders_removed, session, job, tmp_path, monkeypatch, name, vector):
	outside = tmp_path / 'outside'
	os.makedirs(outside / 'd' / 's')
	(outside / 'd' / 'x').write_text('x')
	(outside / 'd' / 's' / 'y').write_text('y')
	steps = [tuple(arg.replace('{outside}', str(outside)) for arg in step) for step in SHAPES[name]]
	one = session(TREE)
	state = {'visits': 0, 'done': 0, 'armed': False, 'inside': False}
	log = []
	def visit(where):
		if not state['armed'] or state['inside']:
			return
		state['inside'] = True
		try:
			at = state['visits']
			state['visits'] += 1
			while state['done'] < len(steps) and vector[state['done']] <= at:
				step = steps[state['done']]
				state['done'] += 1
				log.append(('step', at, where, step))
				try:
					one.apply(step)
				except OSError as e:
					log.append(('failed', os.strerror(e.errno)))
		finally:
			state['inside'] = False
	class Events(list):
		def __iter__(self):
			for i in range(len(self)):
				visit('event')
				yield self[i]
	real_read, real_add, real_walk = rv.inotify_simple.INotify.read, rv.inotify_simple.INotify.add_watch, rv.iter_tree_entries
	def read(inotify, *args, **kwargs):
		visit('read')
		return Events(real_read(inotify, *args, **kwargs))
	def add_watch(inotify, path, mask):
		visit('add_watch')
		wd = real_add(inotify, path, mask)
		visit('added')
		return wd
	def walk(*args, **kwargs):
		for item in real_walk(*args, **kwargs):
			visit('walk')
			yield item
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)
	real_back_up = one.back_up
	def back_up(batch):
		log.append(('batch', [(e.event, os.path.relpath(e.path, job.monitor), e.moved_from and os.path.relpath(e.moved_from, job.monitor))
			for e in batch if '.probe' not in e.path and e.event != 'attrib']))
		return real_back_up(batch)
	one.back_up = back_up
	state['armed'] = True
	wait_until(lambda: state['done'] == len(steps), timeout=20, message='steps not run')
	state['armed'] = False
	one.back_up_next()
	time.sleep(0.01)
	one.back_up_next()
	for folder in ['.'] + folders_of(job.monitor):
		open(os.path.join(job.monitor, folder, 'mark'), 'w').write('m')
	one.back_up_next()
	version, tree = version_view(job), live_view(job)
	if version != tree:
		detail = {rel: ('MISSING' if rel not in version else 'present', 'MISSING' if rel not in tree else 'present', version.get(rel, [None, None])[1] == tree.get(rel, [None, None])[1])
			for rel in sorted(set(version) | set(tree)) if version.get(rel) != tree.get(rel)}
		pytest.fail(f'{name} {vector}: {detail}\nto run it alone: REVERB_WATCH_SCHED_SHAPES={name} -k "{name}-{"_".join(map(str, vector))}"\nsteps and batches:\n'
			+ '\n'.join(map(str, log)), pytrace=False)
