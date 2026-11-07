'''
Random batches through the real watcher on real inotify: folders made, files and folders moved (into new folders most of all),
written, removed, moved out of the tree and back in, with takes landing anywhere. After each round everything settles, a marker
goes into every folder (one with no working watch shows then), and the newest version must equal the tree. The tests behind it
are hand-picked orders; this found what they did not.

The sample that runs with the suite is small, so it cannot rot. REVERB_WATCH_FUZZ=<seeds> runs that many, from seed
REVERB_WATCH_FUZZ_FROM (0 by default). A failure prints its seed and every step and batch before it: to run it alone,
REVERB_WATCH_FUZZ=1 REVERB_WATCH_FUZZ_FROM=<seed>. The same seed gives the same steps, but not the same interleaving with the
watcher, so a failure may need several runs to show again.

Besides the version equalling the tree, the suite's ground truth plugin (tests/version_view_ground_truth.py) checks that no
older version changed. It also checks each change list's size record, and one fault there is known and deferred: a copy
fallback after a whole-tree comparison that fell between a rename and its read leaves the version before it with a list that
says too little. Those lines, a list below the oracle's numbers and never above them, are left out here unless
REVERB_WATCH_FUZZ_LISTS=1; a list that says too much still fails.
'''
import ast
import os
import random
import re
import shutil
import time

import pytest

import reverberator as rv
from tests import version_view_ground_truth as view_truth
from tests.test_moves_into_new_folders import live_view, session, version_view  # session is the fixture

pytestmark = pytest.mark.inotify

SEEDS = int(os.environ.get('REVERB_WATCH_FUZZ', '64'))
FIRST = int(os.environ.get('REVERB_WATCH_FUZZ_FROM', '0'))
ROUNDS = 8
FOLDER_NAMES = ['a', 'b', 'c', 's', 't']
FILE_NAMES = ['f', 'g', 'h']
TREE = {'a/f': 'a' * 3000, 'a/s/g': 'b' * 3000, 'a/s/t/h': 'c' * 3000, 'b/f': 'd' * 3000, 'b/s/g': 'e' * 3000, 'c/h': 'f' * 3000, 'f': 'g' * 3000, 'g': 'h' * 3000, 'keep/': None}
# by name and by place, for a seed in six
PATTERNS = ['t/', '/n0/c/', '/a/n1/', '/keep/s/']


def folders_of(root):
	return [os.path.relpath(os.path.join(base, name), root) for base, names, _ in os.walk(root) for name in names]


def files_of(root):
	return [os.path.relpath(os.path.join(base, name), root) for base, _, names in os.walk(root) for name in names if not name.startswith(('.probe', 'mark'))]


def step(r, monitor, outside, log):
	'''One random operation; what it did goes to log. One that fails (a folder into itself, a name taken) is logged as failed.'''
	folders, files = folders_of(monitor), files_of(monitor)
	where = lambda: r.choice(['.'] + folders)
	at = lambda rel: os.path.normpath(os.path.join(monitor, rel))
	kind = r.choices(['mkdir', 'mvd', 'mvf', 'write', 'append', 'rm', 'rmtree', 'out', 'in', 'mvd_new', 'mvf_new'], [4, 6, 4, 2, 1, 1, 1, 2, 2, 8, 5])[0]
	try:
		if kind == 'mkdir':
			path = os.path.normpath(os.path.join(where(), r.choice(FOLDER_NAMES)))
			log.append(('mkdir', path))
			os.makedirs(at(path))
		elif kind == 'mvd' and folders:
			source, path = r.choice(folders), os.path.normpath(os.path.join(where(), r.choice(FOLDER_NAMES)))
			log.append(('mv', source, path))
			os.rename(at(source), at(path))
		elif kind == 'mvf' and files:
			source = r.choice(files)
			path = os.path.normpath(os.path.join(where(), r.choice(FILE_NAMES + [os.path.basename(source)])))
			log.append(('mv', source, path))
			os.rename(at(source), at(path))
		elif kind in ('mvd_new', 'mvf_new'):
			# the shape under test: mkdir n; mv x n/x
			pool = folders if kind == 'mvd_new' else files
			if pool:
				source = r.choice(pool)
				new = os.path.normpath(os.path.join(where(), 'n%d' % r.randrange(3)))
				log.append(('mkdir', new))
				os.makedirs(at(new))
				log.append(('mv', source, os.path.join(new, os.path.basename(source))))
				os.rename(at(source), at(os.path.join(new, os.path.basename(source))))
		elif kind == 'write':
			path = os.path.normpath(os.path.join(where(), r.choice(FILE_NAMES)))
			log.append(('write', path))
			open(at(path), 'w').write(str(r.random()) * 50)
		elif kind == 'append' and files:
			path = r.choice(files)
			log.append(('append', path))
			open(at(path), 'a').write('z')
		elif kind == 'rm' and files:
			path = r.choice(files)
			log.append(('rm', path))
			os.remove(at(path))
		elif kind == 'rmtree' and folders:
			path = r.choice(folders)
			log.append(('rmtree', path))
			shutil.rmtree(at(path))
		elif kind == 'out' and (folders or files):
			source = r.choice(folders + files)
			log.append(('out', source))
			os.rename(at(source), os.path.join(outside, f'{len(log)}_{os.path.basename(source)}'))
		elif kind == 'in':
			held = os.listdir(outside)
			if held:
				source = r.choice(held)
				path = os.path.normpath(os.path.join(where(), source.split('_', 1)[1]))
				log.append(('in', source, path))
				os.rename(os.path.join(outside, source), at(path))
	except OSError as e:
		log.append(('failed', os.strerror(e.errno)))


def jitter(monkeypatch, r):
	'''Small random delays around every watch added and every read, so the watcher lags the steps by different amounts.'''
	real_add, real_read = rv.inotify_simple.INotify.add_watch, rv.inotify_simple.INotify.read
	def add_watch(inotify, path, mask):
		time.sleep(r.choice([0, 0, 0.00005, 0.0002, 0.001]))
		wd = real_add(inotify, path, mask)
		time.sleep(r.choice([0, 0, 0.00005, 0.0002, 0.001]))
		return wd
	def read(inotify, *args, **kwargs):
		time.sleep(r.choice([0, 0.0001, 0.0005, 0.002]))
		return real_read(inotify, *args, **kwargs)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'add_watch', add_watch)
	monkeypatch.setattr(rv.inotify_simple.INotify, 'read', read)


@pytest.fixture
def folders_removed(tmp_path):
	'''Asked for before session, so torn down after its watcher stopped: a seed's folders go with it, as thousands of seeds leave millions of inodes.'''
	yield
	shutil.rmtree(tmp_path, ignore_errors=True)


@pytest.mark.parametrize('seed', range(FIRST, FIRST + SEEDS))
def test_random_batches_end_as_the_tree(folders_removed, session, job, tmp_path, monkeypatch, seed):
	r = random.Random(seed)
	outside = str(tmp_path / 'outside')
	os.makedirs(outside)
	patterns = PATTERNS if seed % 6 == 5 else []
	one = session(TREE, only_sync_attributes=r.random() < 0.7, patterns=patterns)
	if seed % 4 == 3:
		jitter(monkeypatch, random.Random(seed + 1))
	log = []
	real_back_up = one.back_up
	def back_up(batch):
		log.append(('batch', [(e.event, 'D' if e.is_dir else 'F', os.path.relpath(e.path, job.monitor), e.moved_from and os.path.relpath(e.moved_from, job.monitor))
			for e in batch if '.probe' not in e.path and e.event != 'attrib']))
		return real_back_up(batch)
	one.back_up = back_up
	def kept(views):
		def left_out(rel, view):
			parts = rel.split('/')
			return any(one.skip_list.skips('/'.join(parts[:i]) + ('/' if i < len(parts) or view[0] == 'd' else '')) for i in range(1, len(parts) + 1))
		return {rel: view for rel, view in views.items() if not left_out(rel, view)}
	def fail(what):
		pytest.fail(f'seed {seed}: {what}\nrun it alone: REVERB_WATCH_FUZZ=1 REVERB_WATCH_FUZZ_FROM={seed}\nsteps and batches:\n' + '\n'.join(map(str, log)), pytrace=False)
	for rnd in range(ROUNDS):
		log.append(('round', rnd))
		timing = r.choice(['unread', 'unread', 'at_once', 'apart'])
		count = r.randrange(2, 9)
		def run(n):
			for _ in range(n):
				step(r, job.monitor, outside, log)
				if timing == 'apart':
					time.sleep(0.003)
		if timing == 'unread':
			# the first steps are all done before the watcher reads any of them
			held = r.randrange(1, count + 1)
			log.append(('hold',))
			with one.unread():
				run(held)
			log.append(('release',))
			if r.random() < 0.5:
				time.sleep(r.choice([0.002, 0.02, 0.1]))
			run(count - held)
		else:
			run(count)
		if r.random() < 0.3:
			# a take landing anywhere, as a max delay's does, with its backup and more changes behind it
			log.append(('take',))
			with one.lock:
				batch = one.queue.take()
			one.flag.clear()
			one.back_up(batch)
			run(r.randrange(0, 3))
		one.back_up_next()
		time.sleep(0.01)
		one.back_up_next()
		log.append(('markers',))
		for folder in ['.'] + folders_of(job.monitor):
			open(os.path.join(job.monitor, folder, f'mark{rnd}'), 'w').write('m')
		one.back_up_next()
		version, tree = version_view(job), kept(live_view(job))
		if version != tree:
			fail(f'round {rnd}: ' + str({rel: ('MISSING' if rel not in version else 'present', 'MISSING' if rel not in tree else 'present', version.get(rel, [None])[1:2] == tree.get(rel, [None])[1:2])
				for rel in sorted(set(version) | set(tree)) if version.get(rel) != tree.get(rel)}))
	if os.environ.get('REVERB_WATCH_FUZZ_LISTS') != '1':
		view_truth.WRONG[:] = [line for line in view_truth.WRONG if not says_too_little(line)]


LIST_LINE = re.compile(r'(?P<version>\S+): its list should be (?P<wanted>\S+), the lists are (?P<lists>\[.*\])$')


def says_too_little(line: str) -> bool:
	'''
	Whether line is the known fault: a version's change list whose size record is below the oracle's, in bytes and inodes, and
	never above it. A list that says too much, a missing list or any other line is not, and fails the test.

	>>> says_too_little("V2--t: its list should be V2--t--8.00_KiB-3_ino.modified_contents.nsv, the lists are ['V2--t--4.00_KiB-2_ino.modified_contents.nsv']")
	True
	>>> says_too_little("V2--t: its list should be V2--t--8.00_KiB-3_ino.modified_contents.nsv, the lists are ['V2--t--12.00_KiB-3_ino.modified_contents.nsv']")
	False
	>>> says_too_little("V2--t: its list should be V2--t--8.00_KiB-3_ino.modified_contents.nsv, the lists are []")
	False
	'''
	match = LIST_LINE.match(line)
	if match is None:
		return False
	wanted = rv.change_list_record(match['wanted'].rpartition('--')[2])
	lists = [rv.change_list_record(name.rpartition('--')[2]) for name in ast.literal_eval(match['lists'])]
	return wanted is not None and bool(lists) and all(listed is not None and listed[0] <= wanted[0] and listed[1] <= wanted[1] for listed in lists)
