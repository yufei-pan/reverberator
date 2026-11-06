'''
The pool's repairs after a cut, and the pool cut test (spec section 5), the release gate of 0.55.

Each disk of a mergerfs pool comes back from a power cut at its own last checkpoint. So each branch here is its own f2fs image, with the
live features and options, under mergerfs. A run is (K, c_1..c_d): a child runs the batch, counting each change of the job vault and each
flush as a step; after step c_i disk i is synced by itself, directly on the branch; after step K every disk stops with no checkpoint
(f2fs_io shutdown 2) and the child dies. With f the last flush before K, each c_i lies in [f, K], as a flush took every disk there. Then the
pool comes back, a fresh daemon-side call scans and retries, the oracle reads every kept version, and the commands read one file of each.

Each worker is a process in a mount namespace of its own, which keeps thousands of mounts out of the host's table, and lets every worker
mount its pool at the paths the template was built on. The monitored tree is off the pool, on the scratch folder, and only read.

REVERB_POOL_CUT=full runs every run the spec names; by default a sample. Needs REVERB_SCRATCH, root, /dev/fuse, mergerfs and mkfs.f2fs. The
seed and every run go in a JSONL under REVERB_SCRATCH; a failed run keeps its images beside it, one set of them.
'''
import contextlib
import errno
import json
import os
import pickle
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback

import pytest

import reverberator as rv
from tests import chain_ground_truth, version_view_ground_truth as view_truth
from tests.crash_batches import after_retries, apply_batch3, batch3_of, build_base, expected_of, UNREADABLE
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.crash_child import in_child, KillPoints, retry, run_do_backup
from tests.harness import create_job, run_backup, seed_monitor, write_rule
from tests.scratch_images import flush_scratch, LoopImage, SCRATCH, shut_down_scratch
from tests.test_migration import cli_differences, expected as views_by_number, folders_of, migrate, plain_links, SMALL
from tests.test_pool_writer import MERGERFS_OPTIONS, needs_mergerfs, pool_writer
from tests.test_tree_writer import a_vault as a_vault_of_two_names
from tests.vault_oracle import check_vault, read_view, recorded_design_r, sha256_of, snapshot_tree, version_number

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

FULL = os.environ.get('REVERB_POOL_CUT') == 'full'
IMAGE_MIB = 256
SEED = 20261106
SAMPLED = {2: 2000, 3: 2000}
# by default, over all the shapes
SAMPLE_RUNS = 30
SCRATCH_BYTES = 2 << 30
# a control may need another template to show
CONTROL_TEMPLATES = 12
# the shapes this session built a template of
BUILT = set()


# --- the steps of a batch ---

class CutPoints(KillPoints):
	'''
	The steps of a run: each mutating call under the job vault (KillPoints), each flush of every disk (flush()), and the end of the work
	(finished()), so a cut can come after the last of them. After step c of cuts {c: [disks]} those disks are synced, by themselves. After step
	kill every disk stops and the child dies. What each step did goes in trace: [kind, its paths].
	'''
	def __init__(self, job_vault: str, disks: list, kill: int = None, cuts: dict = None):
		super().__init__(job_vault)
		self.disks = disks
		self.kill = kill
		self.cuts = cuts or {}
		self.trace = []
		self.call = threading.local()

	def hook(self, event: str, args: tuple) -> None:
		self.call.args = args
		super().hook(event, args)

	def step(self, kind: str) -> None:
		with self.lock:
			# the steps done, this one not yet
			done = next(self.steps) - 1
			for disk in self.cuts.get(done, ()):
				flush_scratch(disk)
			if done == self.kill:
				for disk in self.disks:
					shut_down_scratch(disk)
				os.killpg(0, signal.SIGKILL)
			self.counts[kind] += 1
			args = getattr(self.call, 'args', ())
			self.trace.append([kind] + [os.fsdecode(arg)[len(self.prefix):] for arg in args[:2] if isinstance(arg, (str, bytes)) and os.fsdecode(arg).startswith(self.prefix)])

	def finished(self) -> None:
		self.step('end')


def real_flushes(points: CutPoints = None):
	"""
	A crash child's fault: a flush of the vault is the real helper (sync_vault_filesystems(): the disks of the pool, a thread and a lock for each, the record of
	a failed sync), with the system call under it a syncfs of that folder's image (flush_scratch()), and one step of points for the whole flush. The step is
	taken outside the helper's threads. What the helper takes as arguments is its own: nothing here repeats its signature.
	"""
	def fault(module):
		def syncfs(folder):
			if not os.path.isdir(folder):
				raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), folder)
			flush_scratch(folder)
		def sync(*args, **kwargs):
			if points is not None:
				points.step('flush')
			return REAL_SYNC_VAULT_FILESYSTEMS(*args, **kwargs)
		module.syncfs_folder = syncfs
		module.sync_vault_filesystems = sync
	return fault


def flushes_of(trace: list) -> list:
	'''The positions a flush left every disk at: the start, then after each flush step.'''
	return [0] + [number for number, step in enumerate(trace, 1) if step[0] == 'flush']


def at_the_top(path: str) -> bool:
	return '/' not in path.removeprefix(rv.STAGING_NAME + '/')


def boundaries(trace: list) -> set:
	'''
	The positions at a phase's edge: both sides of every flush, which are also the first and last step of each apply phase; both sides of each rename
	of a whole version (a hand-over's, a conversion's, the prune's); and every step of the commit, from its change list on.
	'''
	wanted = {0, len(trace) - 1}
	for number, step in enumerate(trace, 1):
		if step[0] == 'flush':
			wanted |= {number - 1, number}
		elif step[0] == 'rename' and len(step) == 3 and all(map(at_the_top, step[1:])) and any(version_number(os.path.basename(path).removeprefix(rv.SKELETON_PREFIX)) is not None or os.path.basename(path) in (rv.CONVERTED_NAME, rv.REPLACED_NAME, rv.READY_NAME) for path in step[1:]):
			wanted |= {number - 1, number}
	listed = next((number for number, step in enumerate(trace, 1) if step[0] == 'mkdir' and step[1].startswith(rv.CHANGE_LIST_FOLDER_PREFIX)), None)
	if listed is not None:
		wanted |= set(range(listed - 1, len(trace)))
	return {position for position in wanted if position < len(trace)}


def planned_runs(trace: list, disks: int) -> list:
	'''
	Every (K, c_1..c_d) the spec names, for a batch of these steps. In each flush interval [f, g], K being g: every pair with at least one at a
	boundary; every triple with one at a boundary and the others at the interval's ends. Then the sampled ones, K anywhere, seeded.
	'''
	edges = boundaries(trace)
	flushes = flushes_of(trace)
	last = len(trace) - 1
	runs = set()
	# a flush that is step g has not run at g - 1, and g starts the next interval
	for f, end in zip(flushes, [flush - 1 for flush in flushes[1:]] + [last]):
		for edge in sorted(position for position in edges if f <= position <= end):
			if disks == 2:
				for other in range(f, end + 1):
					runs |= {(end, edge, other), (end, other, edge)}
			else:
				for first in (f, end):
					for second in (f, end):
						runs |= {(end, edge, first, second), (end, first, edge, second), (end, first, second, edge)}
	sampler = random.Random(SEED + disks)
	sampled = []
	for _ in range(SAMPLED[disks]):
		kill = sampler.randrange(1, last + 1)
		f = max(position for position in flushes if position <= kill)
		sampled.append((kill, *(sampler.randint(f, kill) for _ in range(disks))))
	# one run may repeat another: the pool places each new entry on a disk at random, so it is another run
	return sorted(runs) + sampled


# --- the repairs, by hand ---

V1, V2 = 'V1--2026-01-01_00-00-00_-0800', 'V2--2026-01-02_00-00-00_-0800'


def a_vault(root: str, entries: dict) -> tuple:
	"""(job vault, the newest version's folder) of tests/test_tree_writer.py, under a version name the rules of a link go by."""
	job_vault, newest = a_vault_of_two_names(root, entries)
	named = os.path.join(job_vault, V1)
	os.rename(newest, named)
	return job_vault, named


@pytest.fixture
def split_vault(tmp_path, fake_pool):
	"""A vault shown at job_vault over two disks, as the repairs read them: (job_vault, the version, disk a's job vault, disk b's)."""
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	a, b = fake_pool.add(job_vault, ['a', 'b'])
	return job_vault, newest, a, b


def on_disk(disk: str, rel: str, text: str = 'held') -> str:
	path = os.path.join(disk, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w') as f:
		f.write(text)
	return path


def link_on_disk(disk: str, rel: str) -> str:
	"""The forward link at rel of version V1, on disk."""
	path = os.path.join(disk, V1, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	os.symlink(rv.forward_text(rel, V2), path)
	return path


def test_a_name_both_link_and_real_loses_its_link(split_vault):
	job_vault, newest, a, b = split_vault
	file_link, folder_link, deep_link, alone = (link_on_disk(a, rel) for rel in ('g', 'd', 'e/f', 'h'))
	on_disk(b, f'{V1}/g')
	on_disk(b, f'{V1}/d/held')
	on_disk(b, f'{V1}/e/f')
	rv.remove_shadowed_links(newest)
	assert not os.path.lexists(file_link) and not os.path.lexists(folder_link) and not os.path.lexists(deep_link)
	assert os.path.isfile(os.path.join(b, V1, 'g')) and os.path.isfile(os.path.join(b, V1, 'd/held'))
	# a link with nothing against it stands
	assert os.path.islink(alone)


def test_a_vault_off_a_pool_has_no_links_to_look_for(tmp_path, monkeypatch):
	job_vault, newest = a_vault(str(tmp_path), {'g': 'y'})
	monkeypatch.setattr(rv, 'entries_on_disks', lambda disks, folder: pytest.fail('a walk off a pool'))
	rv.remove_shadowed_links(newest)
	rv.remove_mixed_names(newest, newest)


def test_a_missing_row_under_a_real_folder_gets_its_link_back(tmp_path, fake_pool):
	job = create_job(str(tmp_path))
	write_rule(job)
	seed_monitor(job, {'d/f': 'x', 'd/e/g': 'y', 'h': 'z'})
	run_backup(job)
	newest = max(rv.list_versions(job.job_vault), key=lambda version: version.number)
	fake_pool.add(job.vault, ['a', 'b'])
	manifest = rv.VaultManifest(job.job_vault)
	try:
		tree = os.path.join(job.job_vault, newest.name.replace('V0--', 'V1--'))
		writer = rv.hand_over(job.job_vault, newest.path, tree, manifest)
		assert writer.ensure_real('d')
		before = read_view(job.job_vault, newest.name)
		# the record of d/e and the link of h, cut between their two renames: nothing stands there, and the tree holds the entries
		os.unlink(os.path.join(newest.path, 'd/e'))
		os.unlink(os.path.join(newest.path, 'h'))
		# no row of this version, and no entry of the tree: nothing to put back
		with open(os.path.join(tree, 'new'), 'w') as f:
			f.write('new')
		rv.put_back_forward_links(newest.path, tree, manifest)
		rv.give_back_folder_times(newest.path, manifest)
	finally:
		manifest.close()
	name = os.path.basename(tree)
	assert os.readlink(os.path.join(newest.path, 'd/e')) == rv.forward_text('d/e', name)
	assert os.readlink(os.path.join(newest.path, 'h')) == rv.forward_text('h', name)
	assert not os.path.lexists(os.path.join(newest.path, 'new'))
	assert read_view(job.job_vault, newest.name) == before


def test_a_name_of_two_kinds_in_the_tree_goes_on_every_disk(split_vault):
	job_vault, newest, a, b = split_vault
	tree = os.path.join(job_vault, V2)
	on_disk(a, f'{V2}/r')
	on_disk(b, f'{V2}/r/in')
	# one kind on each disk stands, and so does a folder on both
	on_disk(a, f'{V2}/same/x')
	on_disk(b, f'{V2}/same/y')
	on_disk(a, f'{V2}/same/deep')
	on_disk(b, f'{V2}/same/deep/in')
	rv.remove_mixed_names(newest, tree)
	assert not os.path.lexists(os.path.join(a, V2, 'r')) and not os.path.lexists(os.path.join(b, V2, 'r'))
	assert os.path.isfile(os.path.join(a, V2, 'same/x')) and os.path.isfile(os.path.join(b, V2, 'same/y'))
	assert not os.path.lexists(os.path.join(a, V2, 'same/deep')) and not os.path.lexists(os.path.join(b, V2, 'same/deep'))


def test_a_name_the_previous_version_forwards_to_is_left_alone(tmp_path, fake_pool):
	# it never changed in this batch, so what it holds is the only copy of it: whatever a disk shows, nothing goes on inference
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x'})
	a, b = fake_pool.add(job_vault, ['a', 'b'])
	tree = os.path.join(job_vault, V2)
	shutil.rmtree(os.path.join(newest, 'd'))
	os.symlink(rv.forward_text('d', V2), os.path.join(newest, 'd'))
	on_disk(a, f'{V2}/d')
	on_disk(b, f'{V2}/d/in')
	rv.remove_mixed_names(newest, tree)
	assert os.path.isfile(os.path.join(a, V2, 'd')) and os.path.isfile(os.path.join(b, V2, 'd/in'))


@pytest.fixture
def flushes(monkeypatch):
	seen = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: seen.append(1) or [])
	return seen


def test_a_skeleton_in_staging_is_finished(tmp_path, fake_pool, flushes):
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	fake_pool.add(job_vault, ['a', 'b'])
	before = read_view(job_vault, V1)
	rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	# cut between the two renames: the tree under its new name, the skeleton not in
	skeleton = os.path.join(job_vault, rv.STAGING_NAME, rv.SKELETON_PREFIX + V1)
	os.rename(newest, skeleton)
	del flushes[:]
	manifest = rv.VaultManifest(job_vault)
	try:
		rv.repair_pool_vault(job_vault, manifest)
		assert not os.path.lexists(skeleton)
		assert read_view(job_vault, V1) == before
		assert flushes == [1]
		# run again it changes nothing
		rv.repair_pool_vault(job_vault, manifest)
		assert flushes == [1]
	finally:
		manifest.close()


def test_a_tree_renamed_on_one_disk_only_gets_its_name_on_the_other(split_vault, flushes):
	job_vault, newest, a, b = split_vault
	os.mkdir(os.path.join(job_vault, V2))
	os.makedirs(os.path.join(job_vault, rv.STAGING_NAME, rv.SKELETON_PREFIX + V1))
	on_disk(a, f'{V2}/here')
	on_disk(b, f'{V1}/there/x')
	manifest = rv.VaultManifest(job_vault)
	try:
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V2, 'here')) and os.path.isfile(os.path.join(b, V2, 'there/x'))
	assert not os.path.lexists(os.path.join(b, V1))
	assert flushes


def test_a_skeleton_on_its_way_in_is_no_tree(split_vault, flushes):
	# past the flush between the renames every disk has the tree under its new name: a disk's folder under the old one is the skeleton's
	job_vault, newest, a, b = split_vault
	os.mkdir(os.path.join(job_vault, V2))
	os.makedirs(os.path.join(job_vault, rv.STAGING_NAME, rv.SKELETON_PREFIX + V1))
	link = link_on_disk(a, 'g')
	assert rv.finish_tree_rename(job_vault, V1) is False
	assert os.path.islink(link)


def test_no_new_folder_means_no_tree_to_rename(split_vault):
	job_vault, newest, a, b = split_vault
	on_disk(b, f'{V1}/there/x')
	assert rv.finish_tree_rename(job_vault, V1) is False
	assert os.path.isfile(os.path.join(b, V1, 'there/x'))


@pytest.mark.parametrize('second', ['full', 'empty', 'none'])
def test_a_skeleton_left_beside_a_committed_version_is_no_tree_to_rename(tmp_path, fake_pool, flushes, second):
	# the rm of a hand-over's skeleton failed, and V2 committed since: its list is there. disk b's folder of V1 holds the only copy of what V1
	# changed, and is not the tree of a hand-over, whatever V2 holds on that disk
	job_vault, newest = a_vault(str(tmp_path), {'g': 'y'})
	a, b = fake_pool.add(job_vault, ['a', 'b'])
	os.mkdir(os.path.join(job_vault, V2))
	os.makedirs(os.path.join(job_vault, rv.STAGING_NAME, rv.SKELETON_PREFIX + V1))
	on_disk(b, f'{V1}/old-record', 'the only copy')
	on_disk(a, f'{V2}/tree-a')
	if second == 'full':
		on_disk(b, f'{V2}/tree-b')
	elif second == 'empty':
		os.makedirs(os.path.join(b, V2))
	with open(rv.change_list_path(os.path.join(job_vault, V2), 1024, 1), 'w'):
		pass
	manifest = rv.VaultManifest(job_vault)
	try:
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(b, V1, 'old-record'))
	assert not os.path.lexists(os.path.join(b, V2, 'old-record'))
	assert flushes == []


def conversion_in_staging(job_vault: str, names: dict) -> None:
	"""Staging holding each of names, {name: one file's rel in it}, in the job vault shown."""
	for name, rel in names.items():
		on_disk(os.path.join(job_vault, rv.STAGING_NAME, name), rel)


def a_cut_conversion(tmp_path, fake_pool):
	"""A version of a vault under conversion, shown over two disks, and its manifest, which says it began."""
	job_vault, newest = a_vault(str(tmp_path), {'g': 'y'})
	a, b = fake_pool.add(job_vault, ['a', 'b'])
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.begin_migration({V1: [1, 2]})
	manifest.commit()
	return job_vault, newest, a, b, manifest


def test_a_cut_migration_is_renamed_into_place(tmp_path, flushes):
	# a filesystem with no RENAME_EXCHANGE, the job vault its one disk: the version gone, its tree ready
	job_vault, newest = a_vault(str(tmp_path), {'g': 'y'})
	staging = os.path.join(job_vault, rv.STAGING_NAME)
	os.makedirs(staging)
	os.rename(newest, os.path.join(staging, rv.READY_NAME))
	manifest = rv.VaultManifest(job_vault)
	try:
		manifest.begin()
		manifest.begin_migration({V1: [1, 2]})
		manifest.commit()
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(newest, 'g'))
	assert flushes == [1]


def test_a_ready_tree_goes_in_on_each_disk(tmp_path, fake_pool, flushes):
	# in on one disk and on its way on the other: the version's folder shows, and the half still in staging joins it
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		conversion_in_staging(job_vault, {rv.READY_NAME: 'x', rv.REPLACED_NAME: 'x'})
		on_disk(a, f'{V1}/landed')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.READY_NAME}/waiting')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.REPLACED_NAME}/old')
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V1, 'landed')) and os.path.isfile(os.path.join(b, V1, 'waiting'))
	assert os.path.isfile(os.path.join(b, rv.STAGING_NAME, rv.REPLACED_NAME, 'old'))


def test_an_old_tree_out_on_one_disk_only_comes_back(tmp_path, fake_pool, flushes):
	# the tree built is still under its first name, so no flush said the old one is out of every disk: the version is converted again
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		conversion_in_staging(job_vault, {rv.CONVERTED_NAME: 'x', rv.REPLACED_NAME: 'x'})
		on_disk(a, f'{V1}/stayed')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.REPLACED_NAME}/left')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.CONVERTED_NAME}/built')
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V1, 'stayed')) and os.path.isfile(os.path.join(b, V1, 'left'))
	assert not os.path.lexists(os.path.join(b, V1, 'built'))


def test_a_conversion_whose_tree_is_in_leaves_the_old_one_to_staging(tmp_path, fake_pool, flushes):
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		conversion_in_staging(job_vault, {rv.REPLACED_NAME: 'x'})
		on_disk(b, f'{rv.STAGING_NAME}/{rv.REPLACED_NAME}/old')
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert flushes == []
	assert os.path.isfile(os.path.join(b, rv.STAGING_NAME, rv.REPLACED_NAME, 'old'))


def test_a_conversion_on_two_renames_flushes_before_the_version_moves(tmp_path, fake_pool, monkeypatch):
	# the tree built in staging must be on every disk before the version goes to old: then old on a disk means m or n shows somewhere,
	# and old with the version showing means the tree is in. without the flush a disk may come back with old and the other with no m
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	fake_pool.add(job_vault, ['a', 'b'])
	os.makedirs(os.path.join(job_vault, rv.STAGING_NAME))
	steps = []
	real_rename = os.rename
	def rename(source, target, *args, **kwargs):
		steps.append(('rename', os.path.basename(source), os.path.basename(target)))
		return real_rename(source, target, *args, **kwargs)
	monkeypatch.setattr(os, 'rename', rename)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: steps.append(('flush',)) or [])
	assert rv.materialize_version(job_vault, V1) is True
	moves = [step for step in steps if step[0] == 'rename' and step[2] in (rv.REPLACED_NAME, rv.READY_NAME, V1)]
	assert moves == [('rename', V1, rv.REPLACED_NAME), ('rename', rv.CONVERTED_NAME, rv.READY_NAME), ('rename', rv.READY_NAME, V1)]
	# a flush before the first of them, and one after each
	first = steps.index(moves[0])
	assert first > 0 and steps[first - 1] == ('flush',)
	for move in moves:
		assert steps[steps.index(move) + 1] == ('flush',)


def test_a_conversion_on_one_swap_has_no_flush_of_its_own(tmp_path, flushes):
	# a swap in one call (RENAME_EXCHANGE) is one step on one disk
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	os.makedirs(os.path.join(job_vault, rv.STAGING_NAME))
	assert rv.materialize_version(job_vault, V1) is True
	assert flushes == []


def test_a_conversion_split_in_the_middle_goes_back(tmp_path, fake_pool, flushes):
	# m on one disk, n on the other, old on both: the middle rename reached one disk only, and the version is converted again
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		conversion_in_staging(job_vault, {rv.CONVERTED_NAME: 'x', rv.READY_NAME: 'x', rv.REPLACED_NAME: 'x'})
		on_disk(a, f'{rv.STAGING_NAME}/{rv.CONVERTED_NAME}/built')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.READY_NAME}/built')
		on_disk(a, f'{rv.STAGING_NAME}/{rv.REPLACED_NAME}/left-a')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.REPLACED_NAME}/left-b')
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V1, 'left-a')) and os.path.isfile(os.path.join(b, V1, 'left-b'))
	assert flushes


def test_a_lone_ready_tree_beside_the_version_is_a_leftover(tmp_path, fake_pool, flushes):
	# a repair put old back and the removal of staging stopped after m: n is half of a tree already given up, and the version shows
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		conversion_in_staging(job_vault, {rv.READY_NAME: 'x'})
		on_disk(a, f'{V1}/whole')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.READY_NAME}/half')
		rv.repair_pool_vault(job_vault, manifest)
		assert rv.finish_conversion_renames(job_vault, manifest, [rv.READY_NAME]) is False
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V1, 'whole')) and os.path.isfile(os.path.join(b, rv.STAGING_NAME, rv.READY_NAME, 'half'))
	assert not os.path.lexists(os.path.join(b, V1, 'half'))
	assert flushes == []


def test_a_lone_ready_tree_with_the_version_gone_goes_in(tmp_path, fake_pool, flushes):
	job_vault, newest, a, b, manifest = a_cut_conversion(tmp_path, fake_pool)
	try:
		# the version's folder is out of every disk
		shutil.rmtree(newest)
		conversion_in_staging(job_vault, {rv.READY_NAME: 'x'})
		on_disk(a, f'{rv.STAGING_NAME}/{rv.READY_NAME}/here')
		on_disk(b, f'{rv.STAGING_NAME}/{rv.READY_NAME}/there')
		rv.repair_pool_vault(job_vault, manifest)
	finally:
		manifest.close()
	assert os.path.isfile(os.path.join(a, V1, 'here')) and os.path.isfile(os.path.join(b, V1, 'there'))
	assert flushes == [1]


def test_the_version_being_converted_is_the_newest_not_done(tmp_path):
	job_vault, newest = a_vault(str(tmp_path), {'g': 'y'})
	manifest = rv.VaultManifest(job_vault)
	try:
		manifest.begin()
		manifest.begin_migration({V1: [1, 2], V2: [1, 2]})
		manifest.commit()
		assert rv.version_being_converted(job_vault, manifest) == V2
		manifest.begin()
		manifest.add_migrated(V2)
		manifest.commit()
		assert rv.version_being_converted(job_vault, manifest) == V1
	finally:
		manifest.close()


def test_a_walk_does_not_read_a_folder_an_rm_is_removing(tmp_path, fake_pool, monkeypatch):
	# through mergerfs a lstat of a folder an rm -rf is at can answer EBADF, and the attempt would fail on it
	job_vault, newest = a_vault(str(tmp_path), {'d/e/f': 'x', 'd/g': 'y'})
	fake_pool.add(job_vault, ['a', 'b'])
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	writer.record('d/e', False)
	writer.removing.add('d/e')
	busy = writer.path('d/e')
	real = rv.kind_at
	monkeypatch.setattr(rv, 'kind_at', lambda path: pytest.fail(f'{path} read during its removal') if path == busy else real(path))
	writer.record('d', False)


def test_a_folder_queued_for_removal_is_known_to_the_writer(tmp_path, fake_pool):
	job_vault, newest = a_vault(str(tmp_path), {'d/e/f': 'x', 'g': 'y'})
	fake_pool.add(job_vault, ['a', 'b'])
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	class Queue:
		def run_command(self, command):
			return command
	removals = []
	writer.remove_queued('d/e/', True, Queue(), removals)
	writer.remove_queued('g', False, Queue(), removals)
	assert writer.removing == {'d/e'}
	assert len(removals) == 2


def test_the_plan_of_a_batch():
	# flushes at 2 and 5, the change list at 4: an interval is cut before its next flush
	trace = [['mkdir', 'x'], ['flush'], ['rename', 'V1--a', 'V2--a'], ['mkdir', f'{rv.CHANGE_LIST_FOLDER_PREFIX}x'], ['flush'], ['commit'], ['end']]
	assert flushes_of(trace) == [0, 2, 5]
	assert boundaries(trace) == {0, 1, 2, 3, 4, 5, 6}
	runs = planned_runs(trace, 2)[:-SAMPLED[2]]
	assert (1, 0, 1) in runs and (4, 2, 4) in runs and (6, 5, 6) in runs
	for kill, *cuts in planned_runs(trace, 2) + planned_runs(trace, 3):
		f = max(position for position in flushes_of(trace) if position <= kill)
		assert all(f <= cut <= kill for cut in cuts)


# --- a pool of images ---

def private_mounts() -> None:
	'''This process's mounts are its own from here on: none reaches the host's table, or another worker's, and all go when it ends.'''
	os.unshare(os.CLONE_NEWNS)
	subprocess.run(['mount', '--make-rprivate', '/'], check=True)


class Pool:
	'''A mergerfs at root/vault over one image per disk, mounted at root/d<i>: new ones, or copies of those in template. Every path is the same in each worker.'''
	def __init__(self, root: str, work: str, disks: int, template: str = None, options: str = MERGERFS_OPTIONS):
		self.options = options
		self.root = root
		self.work = work
		self.vault = os.path.join(root, 'vault')
		self.branches = [os.path.join(root, f'd{disk}') for disk in range(disks)]
		self.template = template
		self.images = []
		self.mergerfs = None

	def start(self) -> None:
		self.mergerfs = subprocess.Popen(['mergerfs', '-f', ':'.join(self.branches), self.vault, '-o', self.options], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		deadline = time.monotonic() + 30
		while not os.path.ismount(self.vault):
			assert self.mergerfs.poll() is None and time.monotonic() < deadline, 'mergerfs did not start'
			time.sleep(0.002)

	def stop(self) -> None:
		subprocess.run(['umount', '-l', self.vault], check=True)
		self.mergerfs.wait(30)

	def power_back(self) -> None:
		'''After the shutdown of every disk: the pool lazily unmounted, each image mounted again, which recovers it, and the pool mounted.'''
		self.stop()
		for image in self.images:
			image.remount()
		self.start()

	def keep_images(self, folder: str) -> None:
		os.makedirs(folder, exist_ok=True)
		for number, image in enumerate(self.images):
			image.keep = os.path.join(folder, f'd{number}.image')

	def __enter__(self) -> 'Pool':
		self.stack = contextlib.ExitStack()
		try:
			os.makedirs(self.vault, exist_ok=True)
			for number, branch in enumerate(self.branches):
				source = None if self.template is None else os.path.join(self.template, f'd{number}.image')
				self.images.append(self.stack.enter_context(LoopImage(os.path.join(self.work, f'd{number}'), IMAGE_MIB, source, branch)))
			self.start()
		except BaseException:
			self.stack.close()
			raise
		return self

	def __exit__(self, *_) -> None:
		try:
			self.stop()
		finally:
			self.stack.close()


# --- the two batches ---

class Shape:
	'''A batch on a pool of so many disks: its template, built once, what a run does and what it must find. Its paths are the same in each worker.'''
	# how the pool places a new entry; a shape may force it
	mergerfs_options = MERGERFS_OPTIONS

	def __init__(self, disks: int, options: dict = None):
		self.disks = disks
		self.options = options or {}
		self.name = f'{self.batch}-{disks}' + ('-only-sync-attributes' if self.options else '')
		self.base = os.path.join(SCRATCH, 'pool-cut')
		self.root = os.path.join(self.base, self.name)
		self.template = os.path.join(self.root, 'template')
		self.wanted = None

	def job_paths(self):
		return create_job(self.root)

	def keep_failed(self) -> bool:
		'''True once: one failed run's images are kept.'''
		try:
			os.mkdir(os.path.join(self.base, 'failed'))
			return True
		except FileExistsError:
			return False

	def load(self) -> None:
		with open(os.path.join(self.template, 'wanted.pickle'), 'rb') as f:
			self.wanted = pickle.load(f)

	def build_template(self, fixture) -> None:
		'''Build it, in a mount namespace of its own, unless this session did: a template of older code proves nothing.'''
		if self.name not in BUILT:
			if not BUILT:
				shutil.rmtree(os.path.join(self.base, 'failed'), ignore_errors=True)
			BUILT.add(self.name)
			shutil.rmtree(self.root, ignore_errors=True)
			os.makedirs(self.template)
			def build():
				job = self.job_paths()
				write_rule(job)
				with Pool(self.root, os.path.join(self.root, 'building'), self.disks, options=self.mergerfs_options) as pool:
					wanted = self.build(job, fixture)
					pool.keep_images(self.template)
				with open(os.path.join(self.template, 'wanted.pickle'), 'wb') as f:
					pickle.dump(wanted, f)
			[failure] = in_workers([build])
			assert failure is None, failure
		self.load()

	def read_through_the_commands(self, job, wanted: dict, work: str, rng) -> list:
		'''One file of each kept version, restored by the command: what came out wrong, as lines.'''
		lines = []
		out = os.path.join(work, 'restored')
		def read():
			for number, view in sorted(wanted.items()):
				files = sorted(rel for rel, entry in view.items() if entry.kind == 'f' and not rel.endswith(UNREADABLE))
				if not files:
					continue
				rel = rng.choice(files)
				shutil.rmtree(out, ignore_errors=True)
				os.makedirs(out)
				code = rv.run_command(['restore', os.path.join(job.monitor, rel), out, '--version', str(number), '--rule', job.rule_path])
				restored = os.path.join(out, os.path.basename(rel))
				if code != 0 or not os.path.exists(restored):
					lines.append(f'V{number}:{rel!r}: the restore answered {code}')
				elif sha256_of(restored) != view[rel].data:
					lines.append(f'V{number}:{rel!r}: the restore gave other contents')
			with open(os.path.join(work, 'read.json'), 'w') as f:
				json.dump(lines, f, ensure_ascii=True)
			return True
		outcome = in_child(job, None, read)
		if outcome.error is not None:
			return [f'the read through the commands: {outcome.error}']
		with open(os.path.join(work, 'read.json')) as f:
			return json.load(f)


class MixedBatch(Shape):
	'''The mixed batch of spec section 9, with its prune.'''
	batch = 'mixed'

	def build(self, job, fixture) -> dict:
		base = build_base(job, **self.options)
		apply_batch3(job)
		return {1: base[1], 2: base[2], 3: expected_of(snapshot_tree(job.monitor), base[2])}

	def work(self, job, points: CutPoints) -> bool:
		entries, touched = batch3_of(job)
		committed = run_do_backup(job, entries, self.options, touched=touched, matched_since=time.time_ns())
		points.finished()
		return committed

	def again(self, job, fault):
		return retry(job, fault=fault, options=self.options)

	def wrong(self, job) -> tuple:
		'''(what is wrong, as lines; {version number: view} of the versions kept.)'''
		job_vault = job.job_vault
		wanted = after_retries(job_vault, self.wanted)
		lines = check_vault(job_vault, wanted, set(), free_file_meta=bool(self.options.get('only_sync_attributes'))) + view_truth.wrong_lists(job_vault)
		return lines, wanted


class Conversion(Shape):
	'''A small vault of 0.54 made a plain one, version by version.'''
	batch = 'conversion'

	def build(self, job, fixture) -> dict:
		fixture.build(job, SMALL, keep_n_versions=9)
		return {'views': views_by_number(job), 'times': self.times(job)}

	def times(self, job) -> dict:
		return {name: os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns for name in folders_of(job).values()}

	def work(self, job, points: CutPoints) -> bool:
		done = migrate(job)
		points.finished()
		return done

	def again(self, job, fault, points=None):
		return in_child(job, None, lambda: migrate(job), fault, points=points)

	def wrong(self, job) -> tuple:
		wanted = self.wanted['views']
		lines = check_vault(job.job_vault, wanted, set()) + cli_differences(job.job_vault, wanted) + view_truth.wrong_lists(job.job_vault)
		if not recorded_design_r(job.job_vault):
			lines.append('no layout')
		if any(plain_links(job).values()):
			lines.append('a chain link is left')
		if self.times(job) != self.wanted['times']:
			lines.append('a version folder has another mtime')
		return lines, wanted


class ForcedConversion(Conversion):
	"""The conversion on a pool that puts every new entry on its first disk, for the one state placement decides (see the test of it)."""
	batch = 'forced-conversion'
	mergerfs_options = MERGERFS_OPTIONS.replace('category.create=pfrd', 'category.create=ff')


def run_uncut(shape: Shape, work: str, cut_fault=None) -> tuple:
	'''(the steps of the batch with nothing cut, the bytes its images hold at the end).'''
	job = shape.job_paths()
	with Pool(shape.root, work, shape.disks, shape.template, shape.mergerfs_options) as pool:
		points = CutPoints(job.job_vault, pool.branches)
		def batch():
			done = shape.work(job, points)
			with open(os.path.join(work, 'trace.json'), 'w') as f:
				json.dump(points.trace, f)
			return done
		def fault(module):
			real_flushes(points)(module)
			if cut_fault is not None:
				cut_fault(module)
		outcome = in_child(job, None, batch, fault, points=points)
		assert outcome.error is None and outcome.committed is True, outcome.error
		held = sum(os.stat(image.image).st_blocks * 512 for image in pool.images)
		lines, _ = shape.wrong(job)
		assert lines == [], lines[:8]
	with open(os.path.join(work, 'trace.json')) as f:
		return json.load(f), held


def judged(shape: Shape, job, work: str, seed: str) -> list:
	'''
	What is wrong in the vault after a run, as lines: the oracle's, and a file of each version read through the commands. Reading the vault is the
	run's result: a vault wrong enough that a read of it fails (a link that shows a file and opens none) is a wrong run, never a failure of the rig.
	'''
	try:
		wrong, wanted = shape.wrong(job)
		return wrong or shape.read_through_the_commands(job, wanted, work, random.Random(seed))
	except OSError as e:
		return [f'the vault cannot be read: {type(e).__name__}: {e}']


def one_run(shape: Shape, work: str, kill: int, cuts: tuple, cut_fault=None, retry_fault=None) -> list:
	'''What is wrong after the run (kill, cuts), as lines. Empty means it passed.'''
	job = shape.job_paths()
	lines = []
	with Pool(shape.root, work, shape.disks, shape.template, shape.mergerfs_options) as pool:
		at = {}
		for disk, position in zip(pool.branches, cuts):
			at.setdefault(position, []).append(disk)
		points = CutPoints(job.job_vault, pool.branches, kill, at)
		def fault(module):
			real_flushes(points)(module)
			if cut_fault is not None:
				cut_fault(module)
		cut = in_child(job, None, lambda: shape.work(job, points), fault, points=points)
		if not cut.killed:
			lines.append(f'the cut run: {cut.error or "it was not cut"}')
		pool.power_back()
		flushing = real_flushes()
		def fault_after(module):
			flushing(module)
			if retry_fault is not None:
				retry_fault(module)
		again = shape.again(job, fault_after)
		if again.error is not None or again.committed is not True:
			lines.append(f'the retry: {again.error or again}')
		else:
			lines += judged(shape, job, work, f'{kill} {cuts}')
		if lines and shape.keep_failed():
			pool.keep_images(os.path.join(shape.base, 'failed', f'{shape.name}-{kill}-{"-".join(map(str, cuts))}'))
	return lines


# --- side by side ---

def in_workers(jobs: list) -> list:
	'''Each of jobs in a forked process with mounts of its own, side by side; what each failed with, None for one that ended well.'''
	sys.stdout.flush()
	sys.stderr.flush()
	children = []
	for job in jobs:
		reader, writer = os.pipe()
		pid = os.fork()
		if pid == 0:
			os.close(reader)
			failure = b''
			try:
				private_mounts()
				# the plugins read every version before the batch, through the pool, which no daemon does before its scan: what they find is not reported from a child
				rv.do_backup = chain_ground_truth._real_do_backup
				job()
			except BaseException:
				failure = traceback.format_exc().encode()
			try:
				os.write(writer, failure)
			finally:
				os._exit(0)
		os.close(writer)
		children.append((pid, reader))
	failures = []
	for pid, reader in children:
		with os.fdopen(reader, 'rb') as f:
			failure = f.read()
		_, status = os.waitpid(pid, 0)
		failures.append(failure.decode() if failure else (f'worker ended with status {status:#x}' if status else None))
	return failures


def in_worker_result(call):
	'''call() in a worker: what it returned.'''
	answer = []
	reader, writer = os.pipe()
	def job():
		with os.fdopen(writer, 'wb') as f:
			pickle.dump(call(), f)
	with os.fdopen(reader, 'rb') as f:
		def collect():
			answer.append(pickle.load(f))
		collector = threading.Thread(target=collect)
		collector.start()
		failures = in_workers([job])
		os.close(writer)
		collector.join()
	assert failures == [None], failures
	return answer[0]


def worker_count(bytes_each: int) -> int:
	'''One per core, as far as the scratch folder's limit goes, and fewer while memory is under pressure.'''
	count = max(1, min(os.cpu_count(), SCRATCH_BYTES // max(1, bytes_each)))
	with open('/proc/pressure/memory') as f:
		full = next(line for line in f if line.startswith('full'))
	if float(full.split()[2].partition('=')[2]) > 5:
		count = max(1, count // 2)
	return count


def run_all(shape: Shape, runs: list, held: int, tag: str = '', cut_fault=None, retry_fault=None, runner=None) -> list:
	'''runs side by side, each by runner (one_run()); the JSONL lines of those that failed. Every line goes in <base>/<shape><tag>.jsonl.'''
	runner = runner or one_run
	count = min(len(runs), worker_count(2 * held))
	results = os.path.join(shape.base, f'{shape.name}{tag}.jsonl')
	if tag:
		with contextlib.suppress(FileNotFoundError):
			os.remove(results)
	def worker(number):
		def job():
			work = os.path.join(shape.base, 'work', f'{shape.name}-{number}')
			os.environ['REVERB_STATE_DIR'] = os.path.join(work, 'state')
			with open(f'{results}.{number}', 'w') as f:
				for kill, *cuts in runs[number::count]:
					started = time.monotonic()
					rig = None
					try:
						lines = runner(shape, work, kill, tuple(cuts), cut_fault, retry_fault)
					except Exception:
						# the rig failed (a mount, an image), which is the test's own and no run gone wrong: kept apart from the wrong ones
						lines, rig = [], traceback.format_exc()
					f.write(json.dumps({'shape': shape.name, 'kill': kill, 'cuts': cuts, 'wrong': lines[:8], 'rig': rig, 'seconds': round(time.monotonic() - started, 3)}) + '\n')
					f.flush()
		return job
	failures = in_workers([worker(number) for number in range(count)])
	assert not any(failures), [failure for failure in failures if failure][:2]
	wrong = []
	rigs = []
	with open(results, 'a') as whole:
		for number in range(count):
			with open(f'{results}.{number}') as f:
				for text in f:
					whole.write(text)
					row = json.loads(text)
					if row['wrong']:
						wrong.append(row)
					if row['rig']:
						rigs.append(row)
			os.remove(f'{results}.{number}')
	shutil.rmtree(os.path.join(shape.base, 'work'), ignore_errors=True)
	assert not rigs, (f'the rig failed (a mount or an image, before any reading of the vault) in {len(rigs)} of {len(runs)} runs; '
		f'the first, run {rigs[0]["kill"]} {rigs[0]["cuts"]}, ended with {rigs[0]["rig"].strip().splitlines()[-1]}:\n{rigs[0]["rig"]}')
	return wrong


# the two batches on two and on three disks; the live jobs run with Only Sync Attributes, section 9's batch without
SHAPES = {'mixed-2': (MixedBatch, 2), 'mixed-3': (MixedBatch, 3), 'mixed-2-only-sync-attributes': (MixedBatch, 2, {'only_sync_attributes': True}),
	'mixed-3-only-sync-attributes': (MixedBatch, 3, {'only_sync_attributes': True}), 'conversion-2': (Conversion, 2), 'conversion-3': (Conversion, 3)}


# the shape of the test of one state, not swept
FORCED = {'forced-conversion-2': (ForcedConversion, 2)}


def built_shape(name: str, request) -> Shape:
	kind, *arguments = {**SHAPES, **FORCED}[name]
	made = kind(*arguments)
	os.makedirs(made.base, exist_ok=True)
	made.build_template(request.getfixturevalue('v054') if issubclass(kind, Conversion) else None)
	return made


def steps_of(shape: Shape, cut_fault=None) -> tuple:
	return in_worker_result(lambda: run_uncut(shape, os.path.join(shape.base, 'work', f'{shape.name}-uncut'), cut_fault))


@needs_mergerfs
@pytest.mark.parametrize('name', list(SHAPES))
def test_a_cut_at_any_step_of_each_disk_leaves_every_version_exact(name, request):
	shape = built_shape(name, request)
	started = time.monotonic()
	trace, held = steps_of(shape)
	runs = planned_runs(trace, shape.disks)
	total = len(runs)
	if not FULL:
		runs = random.Random(SEED).sample(runs, -(-SAMPLE_RUNS // len(SHAPES)))
	with open(os.path.join(shape.base, f'{shape.name}.jsonl'), 'w') as f:
		f.write(json.dumps({'shape': shape.name, 'seed': SEED, 'steps': len(trace), 'flushes': flushes_of(trace), 'boundaries': sorted(boundaries(trace)), 'planned': total, 'running': len(runs)}) + '\n')
	wrong = run_all(shape, runs, held)
	print(f'{shape.name}: {len(runs)} of {total} runs on {len(trace)} steps in {time.monotonic() - started:.0f} s; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {len(runs)} runs wrong: {wrong[:3]}'


# --- the controls: the test must see what it claims to ---

def control_runs(trace: list, disks: int) -> list:
	"""Every planned run of the short intervals, the renames of a whole version among them, and a seeded share of the others."""
	flushes = flushes_of(trace)
	short = {kill for f, g in zip(flushes, flushes[1:]) if g - f <= 5 for kill in range(f, g)}
	runs = planned_runs(trace, disks)
	near = sorted({run for run in runs if run[0] in short})
	return near + random.Random(SEED).sample(runs, 256)


def apply_runs(trace: list, disks: int) -> list:
	'''Every planned run from the last pass of records on: a name left of two kinds needs a change of kind cut half way.'''
	return sorted({run for run in planned_runs(trace, disks) if run[0] >= flushes_of(trace)[-3]})


def no_pre_record_flush(module):
	real = module.TreeWriter.pre_record
	def pre_record(self, ops, poll=None):
		self.flush_if_needed = lambda: None
		real(self, ops, poll)
		del self.flush_if_needed
		# what flush() does besides the sync: the fault takes the flush away and nothing else
		for folder, times in self.saved.items():
			os.utime(self.kept_path(folder), ns=times, follow_symlinks=False)
		self.needs_flush = False
	module.TreeWriter.pre_record = pre_record


def caught(name: str, request, plan, tag: str, cut_fault=None, retry_fault=None) -> bool:
	"""
	Whether a run of plan(trace, disks) goes wrong with these faults, on a template or a later one: where a pool put a file decides whether some windows show
	at all, as the comparison copies again all but a file that cannot be read.
	"""
	for attempt in range(CONTROL_TEMPLATES):
		BUILT.discard(name)
		shape = built_shape(name, request)
		trace, held = steps_of(shape, cut_fault)
		runs = plan(trace, shape.disks)
		wrong = run_all(shape, runs, held, tag, cut_fault, retry_fault)
		print(f'{tag}, template {attempt + 1}: {len(wrong)} of {len(runs)} runs wrong')
		if wrong:
			return True
	return False


def test_the_pre_record_fault_takes_away_the_flush_and_nothing_else(tmp_path, fake_pool, monkeypatch):
	# flush() also gives a real folder its times back: without that, a folder a pool made on a disk keeps the time of the record in a run with no cut at all (Review 3b's N6)
	writer, job_vault, newest = pool_writer(tmp_path, fake_pool, {'d/f': 'x', 'd/e/g': 'y'})
	flushes = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: flushes.append(1) or [])
	monkeypatch.setattr(rv.TreeWriter, 'pre_record', rv.TreeWriter.pre_record)
	real_ensure_real = rv.TreeWriter.ensure_real
	def ensure_real(self, *args, **kwargs):
		made = real_ensure_real(self, *args, **kwargs)
		# as a pool does on a disk that had no such folder: the next one made there moves this one's time
		for folder in self.saved:
			os.utime(self.kept_path(folder))
		return made
	monkeypatch.setattr(rv.TreeWriter, 'ensure_real', ensure_real)
	no_pre_record_flush(rv)
	wanted = os.lstat(os.path.join(writer.tree, 'd')).st_mtime_ns
	writer.pre_record([(rv.FOLDER_OP, 'd')])
	assert flushes == [] and not writer.needs_flush
	assert not os.path.islink(os.path.join(newest, 'd'))
	assert os.lstat(os.path.join(newest, 'd')).st_mtime_ns == wanted


@needs_mergerfs
def test_a_skipped_pre_record_flush_is_caught(request):
	assert caught('mixed-2', request, control_runs, '-control-pre-record', cut_fault=no_pre_record_flush)


def syncing_one_disk(module):
	"""A flush that reaches the first disk of the pool only, as a regression in the real helper's choice of disks would make it."""
	real = module.syncfs_folder
	def syncfs(folder):
		if os.sep + 'd1' + os.sep not in folder:
			real(folder)
	module.syncfs_folder = syncfs


def last_disk_unsynced(trace: list, disks: int) -> list:
	"""control_runs() with the last disk coming back from its template, which a flush that skipped it leaves it at: its own sync is the first step."""
	return sorted({(kill, *cuts[:-1], 0) for kill, *cuts in control_runs(trace, disks)})


@needs_mergerfs
def test_a_flush_of_one_disk_of_two_is_caught(request):
	# the plan puts a disk's own sync at or after the last flush, as a flush takes every disk: so it takes runs where that sync comes first
	assert caught('mixed-2', request, last_disk_unsynced, '-control-one-disk', cut_fault=syncing_one_disk)


def skipping(name: str):
	def fault(module):
		setattr(module, name, lambda *args: False)
	return fault


@needs_mergerfs
@pytest.mark.parametrize('name, repair', [('mixed-2', 'finish_tree_rename'), ('mixed-2', 'remove_shadowed_links'), ('mixed-2', 'put_back_forward_links'), ('mixed-2', 'remove_mixed_names'),
	('conversion-2', 'finish_conversion_renames')])
def test_a_skipped_repair_is_caught(name, repair, request):
	assert caught(name, request, apply_runs if repair == 'remove_mixed_names' else control_runs, f'-control-{repair}', retry_fault=skipping(repair))


# --- the one state placement decides ---

FORCED_TRIES = 12


def one_forced_try(shape: Shape, rename: int, flushed: int) -> dict:
	"""
	A conversion cut right after the version's rename to old, on a pool where every entry of the version's tree built sits on the first disk
	(d0) and the version's links are on the second (d1): d0 comes back from the flush before the rename, d1 from the flush after it. Gives what was
	found: the version's names before and after, what the oracle says, and whether the retry committed.
	"""
	job = shape.job_paths()
	work = os.path.join(shape.base, 'work', 'forced')
	shutil.rmtree(work, ignore_errors=True)
	os.makedirs(work)
	found = {}
	with Pool(shape.root, work, shape.disks, shape.template, shape.mergerfs_options) as pool:
		d0, d1 = pool.branches
		rel = os.path.relpath(job.job_vault, pool.vault)
		pool.stop()
		name = next(entry for entry in sorted(os.listdir(os.path.join(d0, rel))) if entry.startswith('V2--') and os.path.isdir(os.path.join(d0, rel, entry)))
		os.makedirs(os.path.join(d1, rel, name, 'd'))
		for moved in ('a.txt', 'b.txt', 'lnk'):
			shutil.move(os.path.join(d0, rel, name, moved), os.path.join(d1, rel, name, moved))
		pool.start()
		for branch in pool.branches:
			# moving the entries changed the folders' times
			os.utime(os.path.join(branch, rel, name), ns=(shape.wanted['times'][name],) * 2)
			flush_scratch(branch)
		version = os.path.join(job.job_vault, name)
		found['before'] = sorted(os.listdir(version))
		points = CutPoints(job.job_vault, pool.branches, rename, {max(flushed, 2): [d0], rename: [d1]})
		cut = in_child(job, None, lambda: shape.work(job, points), real_flushes(points), points=points)
		found['cut'] = cut.killed
		pool.power_back()
		again = shape.again(job, real_flushes())
		found['retry'] = (again.committed, again.error)
		found['after'] = sorted(os.listdir(version)) if os.path.isdir(version) else None
		found['wrong'] = [line[:110] for line in shape.wrong(job)[0]][:8]
	return found


@needs_mergerfs
def test_a_conversion_cut_after_the_version_moved_keeps_every_name(request):
	# old on one disk and the version's other part in place on the other must never read as "the tree is in": that depends on where the pool put
	# the tree built, which the random placement of the other shapes leaves to chance, so it is forced here (spec section 7). Tries are
	# repeated, as a disk may come back further on than asked, from a checkpoint of its own
	shape = built_shape('forced-conversion-2', request)
	trace, _ = steps_of(shape)
	rename = next(number for number, step in enumerate(trace, 1) if step[0] == 'rename' and len(step) == 3 and step[2].endswith('/' + rv.REPLACED_NAME))
	flushed = max(position for position in flushes_of(trace) if position < rename)
	# the flush right before the rename is what the test is about: without it d0 comes back from the one before the tree was built
	bad = []
	for number in range(FORCED_TRIES):
		found = in_worker_result(lambda: one_forced_try(shape, rename, flushed))
		print(f'forced try {number + 1}: {found}')
		if found['cut'] is not True or found['retry'] != (True, None) or found['after'] != found['before'] or found['wrong']:
			bad.append(found)
	print(f'forced-conversion-2: {len(bad)} of {FORCED_TRIES} tries wrong')
	assert not bad, f'{len(bad)} of {FORCED_TRIES} tries wrong: {bad[:2]}'


# --- the retry cut too (a second cut, in the conversion's repair or its go-on) ---

DOUBLE_RUNS = 400
DOUBLE_SAMPLE = 8


def double_run(shape: Shape, work: str, kill: int, cuts: tuple, cut_fault=None, retry_fault=None) -> list:
	"""
	One run of (K, c_1..c_d, K2, c2_1..c2_d): the first cut as one_run() makes it, then the retry (the scan, its repairs and the go-on of the conversion) cut at its
	step K2 with each disk at its own c2_i, then a third run, the oracle, and one file of each version read through the commands. What is wrong, as lines.
	A retry that finishes before K2 is not cut, and is the single-cut run.
	"""
	first, second = cuts[:shape.disks], cuts[shape.disks:]
	kill2, cuts2 = second[0], second[1:]
	job = shape.job_paths()
	lines = []
	with Pool(shape.root, work, shape.disks, shape.template, shape.mergerfs_options) as pool:
		at = {}
		for disk, position in zip(pool.branches, first):
			at.setdefault(position, []).append(disk)
		points = CutPoints(job.job_vault, pool.branches, kill, at)
		cut = in_child(job, None, lambda: shape.work(job, points), real_flushes(points), points=points)
		if not cut.killed:
			return [f'the first run: {cut.error or "it was not cut"}']
		pool.power_back()
		at2 = {}
		for disk, position in zip(pool.branches, cuts2):
			at2.setdefault(position, []).append(disk)
		points2 = CutPoints(job.job_vault, pool.branches, kill2, at2)
		second_run = shape.again(job, real_flushes(points2), points2)
		if second_run.killed:
			pool.power_back()
		third = shape.again(job, real_flushes())
		if third.error is not None or third.committed is not True:
			lines.append(f'the third run: {third.error or third}')
		else:
			lines += judged(shape, job, work, f'{kill} {cuts}')
		if lines and shape.keep_failed():
			pool.keep_images(os.path.join(shape.base, 'failed', f'{shape.name}-double-{kill}-{"-".join(map(str, cuts))}'))
	return lines


def double_runs(trace: list, disks: int) -> list:
	"""
	Seeded: first cuts from the planned ones with a retry cut anywhere in its first steps or later, and the first cut at the middle rename of the conversion
	(some disks have it, some do not) with the retry cut at each early step of the repair.
	"""
	rng = random.Random(f'double {disks}')
	planned = planned_runs(trace, disks)
	runs = []
	for _ in range(DOUBLE_RUNS):
		kill2 = rng.randint(1, 40) if rng.random() < 0.6 else rng.randint(41, 120)
		runs.append((*rng.choice(planned), kill2, *(rng.randint(max(0, kill2 - 25), kill2) for _ in range(disks))))
	flushes = flushes_of(trace)
	for number, step in enumerate(trace, 1):
		if step[0] == 'rename' and len(step) == 3 and step[1].endswith('/' + rv.CONVERTED_NAME) and step[2].endswith('/' + rv.READY_NAME):
			f = max(position for position in flushes if position < number)
			for kill2 in range(1, 41):
				for gap in (0, 1, 2, 3):
					c2 = max(0, kill2 - gap)
					runs.append((number, number, f, kill2, kill2, c2) if disks == 2 else (number, number, f, f, kill2, kill2, c2, c2))
					runs.append((number, f, number, kill2, c2, kill2) if disks == 2 else (number, f, number, number, kill2, c2, kill2, kill2))
	return runs


@needs_mergerfs
@pytest.mark.parametrize('name', ['conversion-2', 'conversion-3'])
def test_a_second_cut_in_the_retry_leaves_every_version_exact(name, request):
	# the single cut passes what a second one finds: a repair that is not run again to the same state (Review 3's F2 and F5)
	shape = built_shape(name, request)
	started = time.monotonic()
	trace, held = steps_of(shape)
	runs = double_runs(trace, shape.disks)
	total = len(runs)
	if not FULL:
		runs = random.Random(SEED).sample(runs, DOUBLE_SAMPLE)
	wrong = run_all(shape, runs, held, '-double', runner=double_run)
	print(f'{shape.name} with the retry cut too: {len(runs)} of {total} runs in {time.monotonic() - started:.0f} s; {len(wrong)} wrong')
	assert not wrong, f'{len(wrong)} of {len(runs)} runs wrong: {wrong[:3]}'


@needs_mergerfs
@pytest.mark.parametrize('name, runner, plan', [('mixed-2', one_run, planned_runs), ('conversion-2', double_run, double_runs)], ids=['single', 'double'])
def test_a_vault_the_oracle_cannot_read_is_a_wrong_run_and_no_failure_of_the_rig(name, runner, plan, request):
	# a link that shows a file and opens none, as a cut can leave, makes the oracle's read raise: that is what a run looks for (Review 3b's N7)
	shape = built_shape(name, request)
	trace, held = steps_of(shape)
	def unreadable(job):
		raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), os.path.join(job.job_vault, 'V2', 'b', 'y.txt'))
	shape.wrong = unreadable
	wrong = run_all(shape, plan(trace, shape.disks)[:2], held, '-unreadable', runner=runner)
	assert len(wrong) == 2 and all('FileNotFoundError' in row['wrong'][0] and 'y.txt' in row['wrong'][0] for row in wrong), wrong


@needs_mergerfs
def test_a_failure_to_mount_or_make_an_image_stays_a_rig_row_that_says_what_failed(request):
	shape = built_shape('mixed-2', request)
	def no_mount(shape, work, kill, cuts, cut_fault, retry_fault):
		raise OSError(errno.EBUSY, 'the mount point is busy', work)
	with pytest.raises(AssertionError, match=r'the rig failed \(a mount or an image.*in 1 of 1 runs.*OSError: \[Errno 16\] the mount point is busy'):
		run_all(shape, [(1, 0, 0)], 1 << 20, '-rig', runner=no_mount)
