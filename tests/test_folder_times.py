'''
Round 18: every version's folders keep the monitored folders' own times, mode, owner and extended attributes as of
that version's batch, set after the last write into them: the referenced copy sets them once its links are made, the
complete copy once its copies are in place, the replay and its verification once they are done (each folder they wrote
into gets the monitored folder's times, each they made or synced all of its metadata), and a prune gives each folder of
the next version it wrote into its times back. A restore then gives each folder its own times.

The oracle runs random batches (creates, deletes, renames, folder moves, chmod, chown, touch and xattrs of folders) as
the watcher reports them, with their verification as the daemon runs a batch, and full comparisons, keeping a few versions so prunes
run: after each backup every kept version's folders are as the monitored ones were at its batch.
'''
import errno
import os
import random
import shutil
import stat
import time
from collections import deque, OrderedDict
import pytest
import reverberator as rv
from tests.harness import create_job, run_backup, seed_monitor, write_rule, committed_versions, event_entry
from tests.test_restore import restore, destination

pytestmark = pytest.mark.unit

SEEDS = int(os.environ.get('FOLDER_TIMES_SEEDS', 40))
BATCHES = int(os.environ.get('FOLDER_TIMES_BATCHES', 12))
OLD = 1_000_000_000 * 10 ** 9


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def meta(path):
	'''What a version's folder must have of the monitored one's: (mtime, mode, owner, extended attributes).'''
	st = os.lstat(path)
	xattrs = tuple(sorted((name, os.getxattr(path, name, follow_symlinks=False)) for name in os.listxattr(path, follow_symlinks=False)))
	return (st.st_mtime_ns, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, xattrs)


def folders_of(root):
	'''{rel: meta()} of every real folder below root, no link followed.'''
	found = {}
	for path, rel, is_dir in rv.iter_tree_entries(root):
		if is_dir:
			found[rel.rstrip('/')] = meta(path)
	return found


def entries(root):
	files, folders = [], ['']
	for path, rel, is_dir in rv.iter_tree_entries(root):
		(folders if is_dir else files).append(rel.rstrip('/'))
	return files, folders


def random_ops(rng, monitor, full):
	'''Random changes made in monitor, and the watcher's events of them as (is_dir, event, rel, source rel or None).'''
	events = []
	def new_name(folder):
		while True:
			name = rng.choice('abcdefgh') + str(rng.randint(0, 99))
			rel = f'{folder}/{name}' if folder else name
			if not os.path.lexists(os.path.join(monitor, rel)):
				return rel
	kinds = ['write', 'write', 'modify', 'delete', 'mkdir', 'rmtree', 'mv_file', 'mv_folder', 'chmod', 'chown', 'xattr']
	# a full comparison stands for events that were lost, and finds only what differs from the vault: a folder whose times
	# alone changed is not one it finds, nor one an entry was made in and taken out of again. so with full, the entries
	# made or moved in the batch stay where they are
	fresh = set()
	if not full:
		kinds.append('touch')
	for _ in range(rng.randint(1, 8)):
		files, folders = entries(monitor)
		kind = rng.choice(kinds)
		path = lambda rel: os.path.join(monitor, rel)
		subfolders = [rel for rel in folders if rel]
		movable_files = [rel for rel in files if rel not in fresh]
		movable_folders = [rel for rel in subfolders if rel not in fresh]
		if kind == 'write':
			rel = new_name(rng.choice(folders))
			with open(path(rel), 'w') as f:
				f.write('new')
			fresh.add(rel)
			events += [(False, 'create', rel, None), (False, 'modify', rel, None)]
		elif kind == 'modify' and files:
			rel = rng.choice(files)
			with open(path(rel), 'a') as f:
				f.write('more')
			events.append((False, 'modify', rel, None))
		elif kind == 'delete' and movable_files:
			rel = rng.choice(movable_files)
			os.remove(path(rel))
			events.append((False, 'delete', rel, None))
		elif kind == 'mkdir':
			rel = new_name(rng.choice(folders))
			os.mkdir(path(rel))
			fresh.add(rel)
			events.append((True, 'create', rel, None))
			if rng.random() < 0.5:
				inner = new_name(rel)
				with open(path(inner), 'w') as f:
					f.write('in')
				events += [(False, 'create', inner, None), (False, 'modify', inner, None)]
		elif kind == 'rmtree' and movable_folders:
			rel = rng.choice(movable_folders)
			gone = [(is_dir, f'{rel}/{sub.rstrip("/")}') for _, sub, is_dir in rv.iter_tree_entries(path(rel))]
			shutil.rmtree(path(rel))
			# inotify reports the entries of a folder before the folder
			for is_dir, sub in sorted(gone, key=lambda entry: -entry[1].count('/')):
				events.append((is_dir, 'delete', sub, None))
			events.append((True, 'delete', rel, None))
		elif kind == 'mv_file' and movable_files:
			rel = rng.choice(movable_files)
			dest = new_name(rng.choice(folders))
			if rng.random() < 0.2 and len(files) > 1:
				# over another file
				dest = rng.choice([other for other in files if other != rel])
			os.rename(path(rel), path(dest))
			fresh.add(dest)
			events.append((False, 'move', dest, rel))
		elif kind == 'mv_folder' and movable_folders:
			rel = rng.choice(movable_folders)
			into = [folder for folder in folders if folder != rel and not folder.startswith(rel + '/')]
			dest = new_name(rng.choice(into))
			os.rename(path(rel), path(dest))
			fresh.add(dest)
			events.append((True, 'move', dest, rel))
		elif kind in ('chmod', 'chown', 'xattr', 'touch') and subfolders:
			rel = rng.choice(subfolders)
			if kind == 'chmod':
				os.chmod(path(rel), rng.choice([0o755, 0o700, 0o2775, 0o750, 0o1777]))
			elif kind == 'chown':
				os.chown(path(rel), rng.randint(0, 3), rng.randint(0, 3))
			elif kind == 'xattr':
				names = os.listxattr(path(rel))
				if names and rng.random() < 0.3:
					os.removexattr(path(rel), rng.choice(names))
				else:
					os.setxattr(path(rel), 'user.k' + str(rng.randint(0, 2)), os.urandom(rng.randint(0, 5)))
			else:
				os.utime(path(rel), ns=(OLD + rng.randint(0, 10 ** 12), OLD + rng.randint(0, 10 ** 12)))
			events.append((True, 'attrib', rel, None))
	return events


def raw(monitor, events):
	return deque(rv.ChangeEvent(float(i), is_dir, event, os.path.join(monitor, rel), None if source is None else os.path.join(monitor, source))
		for i, (is_dir, event, rel, source) in enumerate(events, 1))


def seed_tree(rng, job):
	tree = {}
	for i in range(rng.randint(3, 12)):
		depth = rng.randint(0, 3)
		folder = '/'.join(rng.choice('pqrs') for _ in range(depth))
		tree[(folder + '/' if folder else '') + f'f{i}'] = 'x'
	seed_monitor(job, tree)
	for path, rel, is_dir in rv.iter_tree_entries(job.monitor):
		if is_dir:
			os.utime(path, ns=(OLD + rng.randint(0, 10 ** 12), OLD + rng.randint(0, 10 ** 12)))


def check(job, expected, why=''):
	'''Every kept version's folders are the monitored ones of its batch (expected: version path -> folders_of()).'''
	for version in committed_versions(job):
		assert folders_of(version) == expected[version], (os.path.basename(version), why)


@pytest.mark.parametrize('complete', [True, False])
def test_every_version_keeps_the_folders_of_its_batch(tmp_path, complete):
	cases = {'verified': 0, 'full': 0, 'pruned': 0}
	for seed in range(SEEDS):
		rng = random.Random(seed * 2 + complete)
		job = create_job(str(tmp_path / f's{seed}'))
		seed_tree(rng, job)
		keep = rng.choice([0, 3, 4])
		run_backup(job, keep_one_complete_backup=complete, keep_n_versions=keep)
		expected = {committed_versions(job)[-1]: folders_of(job.monitor)}
		check(job, expected)
		for _ in range(BATCHES):
			mode = rng.choices(['verified', 'full'], [7, 3])[0]
			events = random_ops(rng, job.monitor, mode == 'full')
			# so a write into a version's folder cannot land on the monitored folder's own tick
			time.sleep(0.005)
			before = len(committed_versions(job))
			if mode == 'full':
				run_backup(job, keep_one_complete_backup=complete, keep_n_versions=keep)
			else:
				evs = raw(job.monitor, events)
				run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), keep_one_complete_backup=complete, keep_n_versions=keep,
					touched=rv.touched_scopes(evs, job.monitor))
			versions = committed_versions(job)
			if versions[-1] not in expected:
				cases[mode] += 1
				expected[versions[-1]] = folders_of(job.monitor)
			cases['pruned'] += len(versions) <= before
			check(job, expected, (seed, mode, events))
		if not complete:
			# a referenced backup's files are the live ones, which a restore does not copy out
			shutil.rmtree(str(tmp_path / f's{seed}'))
			continue
		# a restore of the whole tree from the oldest kept version gives each folder its own times
		write_rule(job)
		oldest = committed_versions(job)[0]
		out = destination(tmp_path / f's{seed}')
		code = rv.run_command(['restore', job.monitor + '/', out, '--version', str(rv.vault_version_number(os.path.basename(oldest))),
			'--rule', job.rule_path, '--state_dir', str(tmp_path / 'state')])
		assert code == 0, seed
		restored = folders_of(os.path.join(out, os.path.basename(job.monitor)))
		assert restored == expected[oldest], seed
		shutil.rmtree(str(tmp_path / f's{seed}'))
	assert min(cases.values()) >= 10, cases


def test_a_restored_folder_gets_its_own_times_back(tmp_path, capsys):
	# the round 16 probe: a folder holding entries came back with the time its version's entries were written
	job = create_job(str(tmp_path))
	seed_monitor(job, {'d/f': 'x', 'd/e/g': 'y', 'top': 'z'})
	for rel in ('d/e', 'd'):
		os.utime(os.path.join(job.monitor, rel), ns=(OLD, OLD))
	run_backup(job)
	with open(os.path.join(job.monitor, 'top'), 'w') as f:
		f.write('changed')
	versions = run_backup(job, OrderedDict([event_entry(job, 'top', 'modify')]))
	for version in versions:
		assert [os.lstat(os.path.join(version, rel)).st_mtime_ns for rel in ('d', 'd/e')] == [OLD, OLD]
	write_rule(job)
	out = destination(tmp_path)
	code, _, err = restore(tmp_path, capsys, f'{job.monitor}/d', out, '--version', '1')
	assert (code, err) == (0, '')
	assert [os.lstat(os.path.join(out, 'd', rel)).st_mtime_ns for rel in ('', 'e')] == [OLD, OLD]


def three_versions(tmp_path):
	'''V0 to V2 with folders at old times, V1 and V2 each changing keep: V1's other files are chain links into V0.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a': 'a', 'D/b': 'b', 'D/E/c': 'c', 'F/d': 'd', 'keep': 'k'})
	for rel in ('D/E', 'D', 'F'):
		os.utime(os.path.join(job.monitor, rel), ns=(OLD, OLD + 7))
	run_backup(job)
	for i in (1, 2):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'v{i}')
		run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	return job


def test_a_prune_leaves_the_next_versions_folder_times(tmp_path):
	job = three_versions(tmp_path)
	v1 = committed_versions(job)[1]
	before = folders_of(v1)
	assert before['D'][0] == OLD + 7
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert list(info) == [1, 2]
	assert not os.path.islink(os.path.join(v1, 'D/E/c'))
	assert folders_of(v1) == before


def test_a_prune_that_moves_its_copies_leaves_the_folder_times(tmp_path, monkeypatch):
	# a filesystem without hard links: each copy is moved in place of its link
	job = three_versions(tmp_path)
	v1 = committed_versions(job)[1]
	before = folders_of(v1)
	def no_link(*args, **kwargs):
		raise OSError(errno.EXDEV, 'no hard links')
	monkeypatch.setattr(os, 'link', no_link)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert list(info) == [1, 2]
	assert not os.path.islink(os.path.join(v1, 'D/E/c'))
	assert folders_of(v1) == before


def test_the_cut_repair_leaves_the_next_versions_folder_times(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	monkeypatch.setattr(rv.PoolGuard, 'covers', lambda self, path: True)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: [])
	v0, v1 = committed_versions(job)[:2]
	before = folders_of(v1)
	# the cut: the marker names V0, and V1 lost its links D/b and D/E/c on a disk that came back without them; the
	# folders' times as they were
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	for rel in ('D/b', 'D/E/c'):
		os.remove(os.path.join(v1, rel))
	for rel, held in before.items():
		os.utime(os.path.join(v1, rel), ns=(held[0], held[0]))
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert list(info) == [1, 2]
	assert open(os.path.join(v1, 'D/E/c')).read() == 'c'
	assert folders_of(v1) == before


def test_a_folder_whose_metadata_the_copy_could_not_take_gets_the_monitored_ones(tmp_path, monkeypatch):
	# the healing check: the referenced copy fails to copy D's metadata from V0; the batch's end copies the monitored D's
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/b': 'b', 'keep': 'k'})
	os.chmod(os.path.join(job.monitor, 'D'), 0o750)
	os.utime(os.path.join(job.monitor, 'D'), ns=(OLD, OLD))
	run_backup(job)
	real = rv.copy_new_folder_meta
	def failing(source, dest, st, failed=None):
		if '/V0--' in source and source.rstrip('/').endswith('/D'):
			failed.append(source)
			return False
		return real(source, dest, st, failed)
	monkeypatch.setattr(rv, 'copy_new_folder_meta', failing)
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('v1')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]), matched_since=time.time_ns())[-1]
	assert meta(os.path.join(v1, 'D')) == meta(os.path.join(job.monitor, 'D'))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		# taken from the tree, so the vault matches it again
		assert manifest.matched is not None and manifest.matched[0] == os.path.basename(v1)
	finally:
		manifest.close()


def test_written_folders_follow_the_folder_moves():
	folders = rv.WrittenFolders()
	for rel in ('a/b', 'a/b/c', 'a/bc', 'a/b!', 'x'):
		folders.wrote_in(rel + '/f')
	folders.add('a/b/new', whole=True)
	folders.moved('a/b/', 'x/y')
	assert sorted(folders.whole.items()) == [('a/b!', False), ('a/bc', False), ('x', False), ('x/y', False), ('x/y/c', False), ('x/y/new', True)]
	assert folders.rels == sorted(folders.whole)
	folders.moved('x', 'z')
	assert folders.rels == ['a/b!', 'a/bc', 'z', 'z/y', 'z/y/c', 'z/y/new']
