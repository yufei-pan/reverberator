'''
Round 18: every version's folders keep the monitored folders' own times, mode, owner and extended attributes as of
that version's batch, set after the last write into them: the referenced copy sets them once its links are made, the
complete copy once its copies are in place, the replay and its verification once they are done (each folder they wrote
into gets the monitored folder's times, each they made or synced all of its metadata), and a prune gives each folder of
the next version it wrote into its times back. A restore then gives each folder its own times.

The oracle runs random batches (creates, deletes, renames, folder moves, chmod, chown, touch and xattrs of folders) as
the watcher reports them, with their verification as the daemon runs a batch, and full comparisons (which compare
folders' mtimes, so they find a folder whose times alone moved), keeping a few versions so prunes run: after each backup
every kept version's folders, its own top folder among them, are as the monitored ones were at its batch.
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
from tests.vault_oracle import read_view

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
	'''{rel: meta()} of root ('') and every real folder below it, no link followed.'''
	found = {'': meta(root)}
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
	kinds = ['write', 'write', 'modify', 'delete', 'mkdir', 'rmtree', 'mv_file', 'mv_folder', 'chmod', 'chown', 'xattr', 'touch']
	# a full comparison stands for events that were lost: it compares folders' mtimes too, so it finds a folder whose
	# times alone changed (touch), and one an entry was made in and taken out of again. full, the ops pick freely; a
	# batch's verification compares no folder times, so there the entries made or moved in it stay where they are
	fresh = set()
	if full:
		kinds += ['touch', 'churn']
	for _ in range(rng.randint(1, 8)):
		files, folders = entries(monitor)
		kind = rng.choice(kinds)
		path = lambda rel: os.path.join(monitor, rel)
		subfolders = [rel for rel in folders if rel]
		movable_files = [rel for rel in files if full or rel not in fresh]
		movable_folders = [rel for rel in subfolders if full or rel not in fresh]
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
		elif kind == 'churn':
			# a file made and removed: its folder's times alone moved, the root's too
			rel = new_name(rng.choice(folders))
			with open(path(rel), 'w') as f:
				f.write('t')
			os.remove(path(rel))
			events += [(False, 'create', rel, None), (False, 'delete', rel, None)]
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


def version_folders_of(version):
	'''
	folders_of() a version, its top folder's being the monitored root's it keeps (rv.load_root_meta()): the version folder
	itself stays the daemon's, root's 0755 folder.
	'''
	if os.geteuid() != 0:
		pytest.skip('trusted.* extended attributes need root')
	job_vault, name = os.path.split(version)
	found = {rel: (entry.mtime_ns, entry.mode, entry.uid, entry.gid, entry.xattrs) for rel, entry in read_view(job_vault, name).items() if entry.kind == 'd'}
	st = os.lstat(version)
	assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o755, os.geteuid(), os.getegid())
	assert [name for name in os.listxattr(version) if name.startswith('trusted.reverberator.')] == [rv.ROOT_META_XATTR]
	root = rv.load_root_meta(version)
	found[''] = (root.mtime_ns, root.mode, root.uid, root.gid, tuple(sorted(root.xattrs.items())))
	return found


def check(job, expected, why=''):
	'''Every kept version's folders are the monitored ones of its batch (expected: version path -> folders_of()).'''
	for version in committed_versions(job):
		assert version_folders_of(version) == expected[version], (os.path.basename(version), why)


def test_every_version_keeps_the_folders_of_its_batch(tmp_path, monkeypatch):
	cases = {'verified': 0, 'full': 0, 'pruned': 0}
	# the scope of each delta generation: a full mode's is the whole tree
	compared = []
	real = rv.delta_generate_backup_entries
	def delta(*args, **kwargs):
		compared.append(kwargs.get('scope_rel', ''))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', delta)
	for seed in range(SEEDS):
		rng = random.Random(seed * 2 + 1)
		job = create_job(str(tmp_path / f's{seed}'))
		seed_tree(rng, job)
		keep = rng.choice([0, 3, 4])
		run_backup(job, keep_n_versions=keep)
		expected = {committed_versions(job)[-1]: folders_of(job.monitor)}
		check(job, expected)
		for _ in range(BATCHES):
			mode = rng.choices(['verified', 'full'], [7, 3])[0]
			events = random_ops(rng, job.monitor, mode == 'full')
			# so a write into a version's folder cannot land on the monitored folder's own tick
			time.sleep(0.005)
			before = len(committed_versions(job))
			if mode == 'full':
				# no entries: the whole tree is compared with the latest version, and what differs makes a version
				compared.clear()
				run_backup(job, keep_n_versions=keep)
				assert compared == [''], compared
			else:
				evs = raw(job.monitor, events)
				run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), keep_n_versions=keep,
					touched=rv.touched_scopes(evs, job.monitor))
			versions = committed_versions(job)
			if versions[-1] not in expected:
				cases[mode] += 1
				expected[versions[-1]] = folders_of(job.monitor)
			cases['pruned'] += len(versions) <= before
			check(job, expected, (seed, mode, events))
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
		view = read_view(*os.path.split(version))
		assert [view[rel].mtime_ns for rel in ('d', 'd/e')] == [OLD, OLD]
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


@pytest.mark.on_054
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


@pytest.mark.on_054
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


@pytest.mark.on_054
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


# --- the round 18 fix pass ---

def test_a_move_to_the_top_never_names_the_version_folder_a_written_folder(tmp_path, monkeypatch):
	# a file moved to the top lands in the version folder, named '.', which is no written folder ( the version folder
	# keeps the monitored root's by its own step )
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a/f': '1', 'keep': 'k'})
	run_backup(job)
	m = lambda rel: os.path.join(job.monitor, rel)
	run_backup(job, rv.change_events_to_backup_entries(deque([rv.ChangeEvent(1.0, False, 'modify', m('keep'), None)]), job.monitor))
	os.rename(m('a/f'), m('f'))
	seen = []
	real = rv.WrittenFolders.settle
	def spy(self, *args, **kwargs):
		seen.append(list(self.rels))
		return real(self, *args, **kwargs)
	monkeypatch.setattr(rv.WrittenFolders, 'settle', spy)
	evs = deque([rv.ChangeEvent(2.0, False, 'move', m('f'), m('a/f'))])
	v = run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), touched=rv.touched_scopes(evs, job.monitor))[-1]
	assert seen and '.' not in seen[0] and '' not in seen[0]
	assert version_folders_of(v)[''] == meta(job.monitor)


def test_settle_leaves_paused_inner_mounts_and_polls_each_folder(tmp_path):
	version, monitor = tmp_path / 'v', tmp_path / 'm'
	for root in (version, monitor):
		for rel in ('mnt/in', 'd'):
			(root / rel).mkdir(parents=True)
	for rel in ('mnt', 'mnt/in', 'd'):
		os.utime(monitor / rel, ns=(OLD, OLD))
	folders = rv.WrittenFolders()
	for rel in ('mnt', 'mnt/in', 'd'):
		folders.add(rel)
	polls = []
	assert folders.settle(str(version), str(monitor), [], paused={'mnt/'}, poll=lambda: polls.append(1)) == []
	assert len(polls) == 3
	assert os.lstat(version / 'd').st_mtime_ns == OLD
	assert os.lstat(version / 'mnt').st_mtime_ns != OLD and os.lstat(version / 'mnt/in').st_mtime_ns != OLD


def test_settle_stops_when_the_pool_guard_says_a_disk_dropped(tmp_path):
	version, monitor = tmp_path / 'v', tmp_path / 'm'
	for root in (version, monitor):
		(root / 'd').mkdir(parents=True)
	folders = rv.WrittenFolders()
	folders.add('d')
	def dropped():
		raise rv.PoolNotReady('a disk dropped')
	with pytest.raises(rv.PoolNotReady):
		folders.settle(str(version), str(monitor), [], poll=dropped)


def test_copy_new_folder_meta_never_follows_a_link_in_the_folders_place(tmp_path):
	source, target, link = tmp_path / 's', tmp_path / 't', tmp_path / 'l'
	source.mkdir(mode=0o700)
	target.mkdir(mode=0o755)
	os.chmod(source, 0o700)
	os.utime(source, ns=(OLD, OLD))
	os.symlink(target, link)
	rv.copy_new_folder_meta(str(source), str(link), os.lstat(source), [])
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o755 and os.lstat(target).st_mtime_ns != OLD


@pytest.mark.on_054
def test_a_prune_that_fails_mid_walk_gives_the_folder_times_back(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	v1 = committed_versions(job)[1]
	before = folders_of(v1)
	real = rv.in_row_order
	def walk_then_fail(pool, rows, work, handled, stop, check=None, alone=None):
		real(pool, rows, work, handled, stop, check, alone)
		raise RuntimeError('cut')
	monkeypatch.setattr(rv, 'in_row_order', walk_then_fail)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	with pytest.raises(RuntimeError):
		rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert not os.path.islink(os.path.join(v1, 'D/E/c'))
	assert folders_of(v1) == before


def test_a_full_comparison_gives_a_folder_whose_mtime_alone_moved_its_times(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/a': 'a', 'D/E/b': 'b', 'keep': 'k'})
	run_backup(job)
	# a file made and removed in D, whose events were lost: only D's mtime moved
	with open(os.path.join(job.monitor, 'D/tmp'), 'w') as f:
		f.write('t')
	os.remove(os.path.join(job.monitor, 'D/tmp'))
	os.utime(os.path.join(job.monitor, 'D'), ns=(OLD, OLD + 9))
	settled = []
	real = rv.WrittenFolders.settle
	def spy(self, *args, **kwargs):
		settled.append(dict(self.whole))
		return real(self, *args, **kwargs)
	monkeypatch.setattr(rv.WrittenFolders, 'settle', spy)
	sized = []
	real_size = rv.get_unskipped_size_inodes
	monkeypatch.setattr(rv, 'get_unskipped_size_inodes', lambda path, *args: sized.append(path) or real_size(path, *args))
	versions = run_backup(job)
	assert len(versions) == 2
	# its times only, and nothing sized or copied for it
	assert settled == [{'D': False}] and sized == []
	assert version_folders_of(versions[-1]) == folders_of(job.monitor)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.lookup('D/').mtime_ns == OLD + 9
	finally:
		manifest.close()
	# the next full comparison finds nothing
	assert run_backup(job) == versions


def test_the_first_full_comparison_repairs_folders_whose_records_hold_no_mtime(tmp_path):
	# records of a daemon before 0.54 hold no folder mtime, and the versions' folders the times their entries were
	# written: the first full comparison gives every folder the monitored one's times, once
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/a': 'a', 'D/E/b': 'b', 'F/c': 'c'})
	for rel in ('D/E', 'D', 'F'):
		os.utime(os.path.join(job.monitor, rel), ns=(OLD, OLD + 1))
	v0 = run_backup(job)[-1]
	for rel in ('D/E', 'D', 'F'):
		os.utime(os.path.join(v0, rel))
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.conn.execute("UPDATE entries SET mtime_ns = NULL WHERE kind = 'd'")
	manifest.commit()
	manifest.close()
	versions = run_backup(job)
	assert len(versions) == 2 and version_folders_of(versions[-1]) == folders_of(job.monitor)
	assert run_backup(job) == versions


def test_a_batch_that_collapses_to_nothing_makes_no_version_for_its_folders_times(tmp_path):
	# a file made and removed, as editors and lock files do all day: the batch's comparison compares no folder times
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/a': 'a'})
	versions = run_backup(job)
	m = lambda rel: os.path.join(job.monitor, rel)
	with open(m('D/lock'), 'w') as f:
		f.write('l')
	os.remove(m('D/lock'))
	evs = deque([rv.ChangeEvent(1.0, False, 'create', m('D/lock'), None), rv.ChangeEvent(2.0, False, 'delete', m('D/lock'), None)])
	assert run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), touched=rv.touched_scopes(evs, job.monitor)) == versions


def test_a_folder_moved_to_another_parent_and_on_again_gets_its_times_at_its_final_place(tmp_path, monkeypatch):
	# f2fs bumps the mtime of a folder renamed into another parent (ext4 does not). the replay's rename does so to the
	# version's folder; its attribute sync is skipped when the batch moves it on again, so it is timed as written. the
	# folders are empty, so no link is re-targeted and no other step times them
	job = create_job(str(tmp_path))
	seed_monitor(job, {'q/s/': None, 'r/z/': None, 'w/': None, 'keep': 'k'})
	for path, rel, is_dir in rv.iter_tree_entries(job.monitor):
		if is_dir:
			os.utime(path, ns=(OLD, OLD + 5))
	run_backup(job)
	real = os.rename
	def f2fs_rename(source, dest, *args, **kwargs):
		real(source, dest, *args, **kwargs)
		if os.path.isdir(dest) and not os.path.islink(dest) and os.path.dirname(os.path.abspath(source)) != os.path.dirname(os.path.abspath(dest)):
			os.utime(dest, ns=(OLD, time.time_ns()), follow_symlinks=False)
	monkeypatch.setattr(os, 'rename', f2fs_rename)
	m = lambda rel: os.path.join(job.monitor, rel)
	os.rename(m('q/s'), m('r/t'))
	os.rename(m('r'), m('w/r2'))
	evs = deque([rv.ChangeEvent(1.0, True, 'move', m('r/t'), m('q/s')), rv.ChangeEvent(2.0, True, 'move', m('w/r2'), m('r'))])
	v1 = run_backup(job, rv.change_events_to_backup_entries(deque(evs), job.monitor), touched=rv.touched_scopes(evs, job.monitor))[-1]
	assert version_folders_of(v1) == folders_of(job.monitor)


@pytest.mark.skipif(os.geteuid() != 0, reason='trusted.* extended attributes need root')
def test_a_symlinked_monitored_root_keeps_the_folders_own_metadata_on_the_version(tmp_path):
	real = tmp_path / 'real'
	real.mkdir()
	os.chmod(real, 0o750)
	os.utime(real, ns=(OLD, OLD + 9))
	os.setxattr(real, 'user.k', b'v')
	link = tmp_path / 'link'
	os.symlink(real, link)
	version = tmp_path / 'V1'
	version.mkdir(0o755)
	before = os.lstat(version)
	assert rv.record_root_meta(str(link), str(version))
	assert rv.load_root_meta(str(version)) == rv.RootMeta(os.geteuid(), os.getegid(), 0o750, OLD, OLD + 9, {'user.k': b'v'})
	after = os.lstat(version)
	# the version folder keeps its own
	assert (after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns) == (before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns)
	assert os.listxattr(version) == [rv.ROOT_META_XATTR]
