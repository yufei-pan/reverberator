import os
import shutil
import stat
from collections import deque, OrderedDict
import pytest
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, latest_version, write_tree as write_plain_tree
from tests.test_long_chains import name_with_threshold, fast_forward_to_32

pytestmark = pytest.mark.unit

BASE = {'keep.txt': 'keep', 'D/old.txt': 'old', 'D/sub/deep.txt': 'deep'}
BAD = 'bad\udcff.txt'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def write_tree(root, tree):
	'''seed_monitor() for a tree whose values can also be ('link', text): a symlink holding text.'''
	for rel, content in tree.items():
		dest = os.path.join(root, rel.rstrip('/'))
		if isinstance(content, tuple):
			os.makedirs(os.path.dirname(dest), exist_ok=True)
			os.symlink(content[1], dest)
		else:
			write_plain_tree(root, {rel: content})


def make_tree(job, before, after):
	'''
	Make the monitored tree hold after (folders are keys ending in /, symlinks ('link', text) values) in place of before.
	A file whose contents some file of before held is copied from it with its times, as a rename keeps them; the others
	are written anew.
	'''
	snapshot = os.path.join(job.root, 'before')
	shutil.copytree(job.monitor, snapshot, symlinks=True)
	for name in os.listdir(job.monitor):
		rv.remove_entry(os.path.join(job.monitor, name))
	for rel, content in sorted(after.items()):
		dest = os.path.join(job.monitor, rel.rstrip('/'))
		if rel.endswith('/') or content is None:
			os.makedirs(dest, exist_ok=True)
			continue
		os.makedirs(os.path.dirname(dest), exist_ok=True)
		if isinstance(content, tuple):
			os.symlink(content[1], dest)
			continue
		same = [rel] if before.get(rel) == content else [old for old, held in before.items() if held == content]
		if same:
			shutil.copy2(os.path.join(snapshot, same[0]), dest)
		else:
			with open(dest, 'w') as f:
				f.write(content)
	shutil.rmtree(snapshot)


def raw_events(job, events_spec):
	'''The watcher's ChangeEvents for (event, rel, source rel or None, is_dir) specs, its paths without a trailing /.'''
	path = lambda rel: job.monitor if rel == '' else os.path.join(job.monitor, rel)
	return [rv.ChangeEvent(float(i), is_dir, event, path(rel), None if source is None else path(source))
		for i, (event, rel, source, is_dir) in enumerate(events_spec)]


def replay_sequence(tmp_path, before:dict, after:dict, events_spec:list, between=None, **kwargs):
	'''
	V0 of before, then one batch of events_spec run as the backuper runs it, over the monitored tree made into after
	(or after(job), once between has run). between(job), when given, runs once V0 is taken. Returns (job, the batch's
	version).
	'''
	job = create_job(str(tmp_path))
	write_tree(job.monitor, before)
	run_backup(job)
	if between is not None:
		between(job)
	if callable(after):
		after = after(job)
	make_tree(job, before, after)
	events = raw_events(job, events_spec)
	entries = rv.change_events_to_backup_entries(deque(events), job.monitor)
	run_backup(job, entries, touched=rv.touched_scopes(events, job.monitor), **kwargs)
	return job, rv.list_versions(job.job_vault)[-1]


def read_tree(root, links=None):
	'''
	{rel: bytes, None for a folder (rel ending with /), or ('link', text) for a symlink} under root. With links (the
	monitored tree's {rel: text}), root is a version: a symlink holding the same text at the same rel is a backed up
	symlink, and any other is followed, only to read a file's bytes.
	'''
	found = {}
	for folder, dirs, files in os.walk(root):
		rel_folder = os.path.relpath(folder, root)
		prefix = '' if rel_folder == '.' else rel_folder + '/'
		for name in dirs + files:
			path = os.path.join(folder, name)
			rel = prefix + name
			if os.path.islink(path) and (links is None or links.get(rel) == os.readlink(path)):
				found[rel] = ('link', os.readlink(path))
			elif name in dirs:
				found[rel + '/'] = None
			else:
				with open(path, 'rb') as f:
					found[rel] = f.read()
	return found


def manifest_rows(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return set(manifest.iter_folders()) | set(manifest.iter_files())
	finally:
		manifest.close()


def assert_version_matches_tree(job, version):
	'''The version folder and the manifest's rows hold what the monitored tree holds: names, kinds and file bytes.'''
	tree = read_tree(job.monitor)
	assert read_tree(version.path, {rel: held[1] for rel, held in tree.items() if isinstance(held, tuple)}) == tree
	assert manifest_rows(job) == set(tree)


def changes(job, version):
	'''(rel, event) of each row of version's change list, a folder's rel ending with /.'''
	return [(row.path[len(job.monitor) + 1:], row.event) for row in rv.iter_change_list(version.change_list)]


# name: (before, after, raw events, the verification's fixes)
SEQUENCES = {
	'a': ({**BASE, 'D/lnk': ('link', 'old.txt')}, {'keep.txt': 'keep', 'D/new.txt': 'new', 'D/lnk': ('link', 'new.txt')},
		[('delete', 'D', None, True), ('create', 'D', None, True)],
		{('D/old.txt', 'delete'), ('D/sub/', 'delete'), ('D/sub/deep.txt', 'delete')}),
	'c': ({**BASE, 'E/e.txt': 'e'}, {'keep.txt': 'keep', 'D/e.txt': 'e'},
		[('delete', 'D', None, True), ('move', 'D', 'E', True)],
		{('D/old.txt', 'delete'), ('D/sub/', 'delete')}),
	'd4': (BASE, {'keep.txt': 'keep', 'D/x.txt': 'moved in'},
		[('delete', 'D', None, True), ('create', 'D', None, True)],
		{('D/old.txt', 'delete'), ('D/sub/', 'delete'), ('D/sub/deep.txt', 'delete')}),
	'd6': (BASE, {'keep.txt': 'keep', 'D/old.txt': 'old', 'D/sub/other.txt': 'other'},
		[('delete', 'D/sub', None, True), ('create', 'D/sub', None, True)],
		{('D/sub/deep.txt', 'delete')}),
	'd7': (BASE, {'keep.txt': 'keep', 'D/sub/other.txt': 'other'},
		[('delete', 'D', None, True), ('create', 'D', None, True)],
		{('D/old.txt', 'delete'), ('D/sub/deep.txt', 'delete')}),
	'f1': (BASE, {'keep.txt': 'keep', 'D2/sub/deep.txt': 'deep'},
		[('move', 'D2', 'D', True), ('delete', 'D2/old.txt', None, False)],
		{('D2/old.txt', 'delete')}),
	'e1': ({'f': 'old', 'keep.txt': 'k'}, {'f~': 'old', 'f': 'new', 'keep.txt': 'k'},
		[('move', 'f~', 'f', False), ('create', 'f', None, False), ('modify', 'f', None, False)],
		{('f~', 'modify'), ('f', 'create')}),
	'e2': ({'f': 'old', 'keep.txt': 'k'}, {'f': 'new', 'keep.txt': 'k'},
		[('move', 'f~', 'f', False), ('create', 'f', None, False), ('modify', 'f', None, False), ('delete', 'f~', None, False)],
		{('f', 'create')}),
	'e3': ({'D/old.txt': 'old', 'keep.txt': 'k'}, {'D/new.txt': 'new', 'keep.txt': 'k'},
		[('move', 'D2', 'D', True), ('create', 'D', None, True), ('delete', 'D2/old.txt', None, False), ('delete', 'D2', None, True)],
		{('D/', 'create'), ('D/new.txt', 'create')}),
	'e4': ({'D/old.txt': 'old', 'D.new/new.txt': 'new', 'keep.txt': 'k'}, {'D/new.txt': 'new', 'keep.txt': 'k'},
		[('move', 'D.old', 'D', True), ('move', 'D', 'D.new', True), ('delete', 'D.old/old.txt', None, False), ('delete', 'D.old', None, True)],
		{('D/', 'create'), ('D/new.txt', 'create'), ('D.new/', 'delete'), ('D.new/new.txt', 'delete')}),
	'd5': (BASE, {'keep.txt': 'keep', 'D2/old.txt': 'old', 'D2/sub/deep.txt': 'deep', 'D/new.txt': 'new'},
		[('move', 'D2', 'D', True), ('create', 'D', None, True)],
		{('D/', 'create'), ('D/new.txt', 'create'), ('D2/new.txt', 'delete')}),
	'f3': (BASE, {'keep.txt': 'keep', 'D2/old.txt': 'old', 'D2/sub/deep.txt': 'deep', 'D2/new.txt': 'x'},
		[('create', 'D/new.txt', None, False), ('modify', 'D/new.txt', None, False), ('move', 'D2', 'D', True)],
		{('D2/new.txt', 'create')}),
	'f5': (BASE, {'keep.txt': 'keep', 'D2/old.txt': 'changed', 'D2/sub/deep.txt': 'deep'},
		[('modify', 'D/old.txt', None, False), ('modify', 'D/old.txt', None, False), ('move', 'D2', 'D', True)],
		{('D2/old.txt', 'modify')}),
	# git branch -D: the ref's new contents written to X.lock, renamed over X, then X deleted; the batch's collapsed
	# entries do not name X at all
	'git': ({'keep.txt': 'keep', 'refs/X': 'old ref'}, {'keep.txt': 'changed', 'refs/': None},
		[('create', 'refs/X.lock', None, False), ('modify', 'refs/X.lock', None, False), ('move', 'refs/X', 'refs/X.lock', False),
		 ('delete', 'refs/X', None, False), ('modify', 'keep.txt', None, False), ('modify', 'keep.txt', None, False)],
		{('refs/X', 'delete')}),
	'swap': ({'a': 'A', 'b': 'B'}, {'a': 'B', 'b': 'A'},
		[('move', 'a.tmp', 'a', False), ('move', 'a', 'b', False), ('move', 'b', 'a.tmp', False)],
		{('a', 'create'), ('b', 'modify')}),
	'chain': ({'a': 'A'}, {'c': 'A more'},
		[('move', 'b', 'a', False), ('modify', 'b', None, False), ('move', 'c', 'b', False)],
		{('a', 'delete')}),
	# mv D/old.txt <outside>; mv D D2: the watcher holds the move out of the tree until it expires, so its delete is
	# queued after the batch holding D's rename was taken
	'late_delete': (BASE, {'keep.txt': 'keep', 'D2/sub/deep.txt': 'deep'},
		[('move', 'D2', 'D', True)],
		{('D2/old.txt', 'delete')}),
}


def check_sequence(tmp_path, name):
	before, after, events_spec, fixes = SEQUENCES[name]
	job, version = replay_sequence(tmp_path, before, after, events_spec)
	assert version.number == 1
	assert_version_matches_tree(job, version)
	assert fixes <= set(changes(job, version))
	return job, version


def test_sequence_a(tmp_path):
	check_sequence(tmp_path, 'a')


def test_sequence_c(tmp_path):
	check_sequence(tmp_path, 'c')


def test_sequence_d4(tmp_path):
	check_sequence(tmp_path, 'd4')


def test_sequence_d6(tmp_path):
	check_sequence(tmp_path, 'd6')


def test_sequence_d7(tmp_path):
	check_sequence(tmp_path, 'd7')


def test_sequence_f1(tmp_path):
	check_sequence(tmp_path, 'f1')


def test_sequence_e1(tmp_path):
	check_sequence(tmp_path, 'e1')


def test_sequence_e2(tmp_path):
	job, version = check_sequence(tmp_path, 'e2')
	# the batch's own row says f was deleted; the verification's row after it says what the version holds
	rows = changes(job, version)
	assert rows.index(('f', 'create')) > rows.index(('f', 'delete'))


def test_sequence_e3(tmp_path):
	check_sequence(tmp_path, 'e3')


def test_sequence_e4(tmp_path):
	check_sequence(tmp_path, 'e4')


def test_sequence_d5(tmp_path):
	check_sequence(tmp_path, 'd5')


def test_sequence_f3(tmp_path):
	check_sequence(tmp_path, 'f3')


def test_sequence_f5(tmp_path):
	check_sequence(tmp_path, 'f5')


def test_sequence_git(tmp_path):
	job, version = check_sequence(tmp_path, 'git')
	assert not os.path.lexists(os.path.join(version.path, 'refs/X'))


def test_sequence_swap(tmp_path):
	check_sequence(tmp_path, 'swap')


def test_sequence_chain(tmp_path):
	check_sequence(tmp_path, 'chain')


def test_sequence_late_delete(tmp_path):
	check_sequence(tmp_path, 'late_delete')


def test_sequence_loop(tmp_path):
	job, version = replay_sequence(tmp_path, BASE, BASE, [('move', 'D2', 'D', True), ('move', 'D', 'D2', True)])
	assert_version_matches_tree(job, version)


def spy_on_compare_scopes(monkeypatch):
	'''The scopes of each compare_scopes() call.'''
	calls = []
	real = rv.compare_scopes

	def spy(*args, **kwargs):
		calls.append(args[4] if len(args) > 4 else kwargs['scopes'])
		compared = real(*args, **kwargs)
		calls.append(compared)
		return compared
	monkeypatch.setattr(rv, 'compare_scopes', spy)
	return calls


def test_a_single_modify_compares_one_path(tmp_path, monkeypatch):
	calls = []
	job, version = replay_sequence(tmp_path, {'a.txt': 'a', 'D/b.txt': 'b'}, {'a.txt': 'changed', 'D/b.txt': 'b'},
		[('modify', 'a.txt', None, False)], between=lambda job: calls.append(spy_on_compare_scopes(monkeypatch)))
	# a.txt as a file, and as a folder that would hold the rows of the folder it replaced
	assert calls[0][:2] == [rv.TouchedScopes(['a.txt/'], ['a.txt']), 1]
	assert changes(job, version) == [('a.txt', 'modify')]


def test_folder_attrib_compares_the_folder_only(tmp_path, monkeypatch):
	calls = []
	job, version = replay_sequence(tmp_path, {'D/x.txt': 'x', 'D/E/y.txt': 'y'}, {'D/x.txt': 'x', 'D/E/y.txt': 'y'},
		[('attrib', 'D', None, True), ('attrib', '', None, True)], between=lambda job: calls.append(spy_on_compare_scopes(monkeypatch)))
	assert calls[0][:2] == [rv.TouchedScopes([], ['D', 'D/']), 1]
	assert_version_matches_tree(job, version)


def test_touched_scopes(job):
	events = raw_events(job, [
		('create', 'N', None, True), ('modify', 'N/f.txt', None, False), ('move', 'M', 'S', True),
		('attrib', 'A', None, True), ('modify', 'A/g.txt', None, False), ('move', 'b.txt', 'a.txt', False),
		('delete', 'N/sub', None, True), ('scan', 'Q', None, True), ('attrib', '', None, True), ('modify', 'M', None, False)])
	events += [rv.ChangeEvent(20.0, True, 'move', os.path.join(job.monitor, 'in'), os.path.join(job.root, 'outside')),
		rv.ChangeEvent(21.0, False, 'modify', os.path.join(job.root, 'outside.txt'), None),
		rv.ChangeEvent(22.0, True, 'full_scan', job.monitor, None), rv.ChangeEvent(23.0, True, 'self_destruct', job.monitor, None)]
	# each touched name in both its forms, as a file and as a folder
	assert rv.touched_scopes(events, job.monitor) == rv.TouchedScopes(['A/g.txt/', 'M/', 'N/', 'S/', 'a.txt/', 'b.txt/', 'in/'],
		['A', 'A/', 'A/g.txt', 'M', 'N', 'S', 'a.txt', 'b.txt', 'in'])
	assert rv.touched_scopes([], job.monitor) == rv.TouchedScopes([], [])
	# a job monitoring the root of the filesystem
	assert rv.touched_scopes([rv.ChangeEvent(1.0, False, 'modify', '/etc/x', None), rv.ChangeEvent(2.0, True, 'create', '/srv', None),
		rv.ChangeEvent(3.0, True, 'attrib', '/', None)], '/') == rv.TouchedScopes(['etc/x/', 'srv/'], ['etc/x', 'srv'])


def test_verification_respects_skip_list_and_paused_mounts(tmp_path, monkeypatch):
	def mounts(job, mounted):
		table = [('/', ('1',))] + [(os.path.join(job.monitor, rel.rstrip('/')), (rel,)) for rel in mounted]
		monkeypatch.setattr(rv, 'current_mount_table', lambda: table)
	skip_list = rv.SkipList(str(tmp_path / 'monitor'), ['*.tmp'])
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/a.txt': 'a', 'D/disk/f.txt': 'f'})
	mounts(job, ['D/disk/'])
	run_backup(job, skip_list=skip_list)
	# the disk is unmounted, leaving its empty mount point, and D is replaced by a folder holding it and a skipped file
	mounts(job, [])
	make_tree(job, {'D/a.txt': 'a'}, {'D/a.txt': 'a', 'D/disk/': None, 'D/x.tmp': 'skipped'})
	events = raw_events(job, [('delete', 'D', None, True), ('create', 'D', None, True)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events)), touched=rv.touched_scopes(events, job.monitor), skip_list=skip_list)
	version = rv.list_versions(job.job_vault)[-1]
	assert os.path.lexists(os.path.join(version.path, 'D/disk/f.txt'))
	assert not os.path.lexists(os.path.join(version.path, 'D/x.tmp'))
	assert manifest_rows(job) == {'D/', 'D/a.txt', 'D/disk/', 'D/disk/f.txt'}
	assert ('D/disk/f.txt', 'delete') not in changes(job, version)


def test_verification_handles_non_utf8_names(tmp_path):
	before, after, events_spec, fixes = SEQUENCES['a']
	job, version = replay_sequence(tmp_path, {**before, f'D/{BAD}': 'bad'}, after, events_spec)
	assert_version_matches_tree(job, version)
	assert fixes | {(f'D/{BAD}', 'delete')} <= set(changes(job, version))


def test_fresh_copies_keep_unchecked(tmp_path):
	before, after, events_spec, _ = SEQUENCES['a']
	job, version = replay_sequence(tmp_path, before, after, events_spec)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.lookup('D/new.txt').unchecked == 1
	finally:
		manifest.close()


def test_attribute_only_differences_are_not_replayed(tmp_path):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/a.txt': 'a', 'D/b.txt': 'b'})
	run_backup(job)
	v0 = latest_version(job).path
	v0_mode = stat.S_IMODE(os.lstat(os.path.join(v0, 'D/a.txt')).st_mode)
	os.rename(os.path.join(job.monitor, 'D'), os.path.join(job.monitor, 'D2'))
	os.chmod(os.path.join(job.monitor, 'D2/a.txt'), 0o600)
	assert v0_mode != 0o600
	events = raw_events(job, [('move', 'D2', 'D', True)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events)), touched=rv.touched_scopes(events, job.monitor))
	version = rv.list_versions(job.job_vault)[-1]
	assert changes(job, version) == [('D2/', 'move')]
	assert stat.S_IMODE(os.lstat(os.path.join(v0, 'D/a.txt')).st_mode) == v0_mode
	assert os.path.islink(os.path.join(version.path, 'D2/a.txt'))


def older_versions(job, synced=()):
	'''
	(rel, kind, link target, mode, uid, gid, mtime_ns, ctime_ns, inode, size, hash of the bytes, extended attributes) of
	everything in every version, by lstat: a link is never followed. The rels of synced (job vault rels) are the chain
	ends an attribute sync may write: only their kind, link target, inode, size and bytes are listed.
	'''
	import hashlib
	listing = []
	for version in rv.list_versions(job.job_vault):
		for folder, dirs, files in os.walk(version.path):
			for name in sorted(dirs + files):
				path = os.path.join(folder, name)
				rel = os.path.relpath(path, job.job_vault)
				st = os.lstat(path)
				digest = None
				if stat.S_ISREG(st.st_mode):
					with open(path, 'rb') as f:
						digest = hashlib.sha256(f.read()).hexdigest()
				try:
					xattrs = sorted((attr, os.getxattr(path, attr, follow_symlinks=False)) for attr in os.listxattr(path, follow_symlinks=False))
				except OSError as e:
					xattrs = type(e).__name__
				meta = (st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns, st.st_ctime_ns, xattrs)
				if rel in synced:
					meta = (None,) * len(meta)
				listing.append((rel, stat.S_IFMT(st.st_mode), os.readlink(path) if stat.S_ISLNK(st.st_mode) else None,
					*meta[:5], st.st_ino, st.st_size, digest, meta[5]))
	return sorted(listing, key=lambda row: row[0])


def second_version(job):
	'''
	V1 of the tree with the times of keep.txt (or of its first file) changed, so that the version a batch then writes
	chains through V1 to V0.
	'''
	keep = os.path.join(job.monitor, 'keep.txt')
	if not os.path.lexists(keep):
		keep = os.path.join(job.monitor, sorted(name for name in os.listdir(job.monitor) if os.path.isfile(os.path.join(job.monitor, name)))[0])
	os.utime(keep, ns=(os.lstat(keep).st_atime_ns, os.lstat(keep).st_mtime_ns - 10 ** 9))
	run_backup(job)
	assert rv.list_versions(job.job_vault)[-1].number == 1


def link_into_v0(job, rel):
	'''The absolute path of rel in V0, for a user's link into the vault.'''
	return os.path.join(rv.list_versions(job.job_vault)[0].path, rel)


def with_users_link(job):
	'''second_version(), with D/lnk made a user's link to sub/deep.txt first, so that V1 holds it.'''
	os.symlink('sub/deep.txt', os.path.join(job.monitor, 'D/lnk'))
	second_version(job)


def attrib_after(job):
	os.chmod(os.path.join(job.monitor, 'D/old.txt'), 0o600)
	os.setxattr(os.path.join(job.monitor, 'D/old.txt'), 'user.guard', b'1')
	os.chmod(os.path.join(job.monitor, 'D'), 0o700)
	os.utime(os.path.join(job.monitor, 'D/lnk'), ns=(10 ** 18, 10 ** 18), follow_symlinks=False)


# name: (before, between(job) making V1, after (or after(job)), raw events, after_tree(job) run on the made tree, the
# job vault rels whose attributes the batch syncs onto chain ends)
GUARD_SEQUENCES = {
	# D, D/old.txt and D/lnk given other attributes: they are synced onto the end of each chain, V0's copy of D/old.txt
	# and V1's user link D/lnk, never what the link leads to
	'attrib': (BASE, with_users_link, {**BASE, 'D/lnk': ('link', 'sub/deep.txt')},
		[('attrib', 'D/old.txt', None, False), ('attrib', 'D', None, True), ('attrib', 'D/lnk', None, False)], attrib_after,
		lambda job: {os.path.relpath(link_into_v0(job, 'D/old.txt'), job.job_vault),
			os.path.join(rv.list_versions(job.job_vault)[1].name, 'D/lnk')}),
	# the folder D replaced by a user's link to V0's D, with an event of its old child after it: nothing of the version is
	# written or removed through the link
	'users_link_into_the_vault': (BASE, second_version, lambda job: {'keep.txt': 'keep', 'D': ('link', link_into_v0(job, 'D'))},
		[('delete', 'D/sub/deep.txt', None, False), ('create', 'D', None, False), ('modify', 'D/old.txt', None, False)], None,
		lambda job: set()),
}


@pytest.mark.parametrize('name', sorted(SEQUENCES) + sorted(GUARD_SEQUENCES))
def test_older_versions_are_untouched(tmp_path, name):
	if name in GUARD_SEQUENCES:
		before, between, after, events_spec, after_tree, synced = GUARD_SEQUENCES[name]
	else:
		# V1 of the same tree first, so that the older versions hold chain links too
		before, after, events_spec, _ = SEQUENCES[name]
		between, after_tree, synced = second_version, None, lambda job: set()
	job = create_job(str(tmp_path))
	write_tree(job.monitor, before)
	run_backup(job)
	between(job)
	synced = synced(job)
	older = older_versions(job, synced)
	make_tree(job, before, after(job) if callable(after) else after)
	if after_tree is not None:
		after_tree(job)
	events = raw_events(job, events_spec)
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	version = rv.list_versions(job.job_vault)[-1]
	assert version.number == 2
	assert [row for row in older_versions(job, synced) if not row[0].startswith(version.name + '/')] == older
	if name == 'attrib':
		# the syncs were made, onto the ends of the chains
		assert stat.S_IMODE(os.lstat(link_into_v0(job, 'D/old.txt')).st_mode) == 0o600
		assert os.getxattr(link_into_v0(job, 'D/old.txt'), 'user.guard') == b'1'
		assert os.lstat(os.path.join(rv.list_versions(job.job_vault)[1].path, 'D/lnk')).st_mtime_ns == 10 ** 18
	else:
		# attrib's D/lnk is a chain link to V1's, which assert_version_matches_tree() would follow
		assert_version_matches_tree(job, version)


@pytest.mark.parametrize('name', ['a', 'c'])
def test_interrupted_verification_commits_nothing(tmp_path, monkeypatch, name):
	before, after, events_spec, _ = SEQUENCES[name]
	job = create_job(str(tmp_path))
	write_tree(job.monitor, before)
	run_backup(job)
	manifest = rv.VaultManifest(job.job_vault)
	rows_before = list(manifest.conn.execute('SELECT * FROM entries ORDER BY path'))
	manifest.close()
	make_tree(job, before, after)

	real_sweep = rv.sweep_version_folder
	swept = []

	def interrupted(*args, **kwargs):
		# the comparison's fixes are replayed and the sweep has removed what no row tracks, all in the open transaction
		swept.append(real_sweep(*args, **kwargs))
		rv.GREEN_LIGHT.clear()
		return swept[-1]
	monkeypatch.setattr(rv, 'sweep_version_folder', interrupted)
	events = raw_events(job, events_spec)
	try:
		_, manifest, committed = rv.do_backup(rv.change_events_to_backup_entries(deque(events)), job_name=job.job_name, monitor_path=job.monitor,
			vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0',
			touched=rv.touched_scopes(events, job.monitor))
		manifest.close()
	finally:
		rv.GREEN_LIGHT.set()
	assert committed is False
	if name == 'c':
		assert swept[0][0] == ['D/old.txt', 'D/sub/']
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert list(manifest.conn.execute('SELECT * FROM entries ORDER BY path')) == rows_before
	finally:
		manifest.close()
	incomplete = [name for name in os.listdir(job.job_vault) if name.startswith('V1--')]
	assert incomplete
	rv.remove_incomplete_vault_versions(job.job_vault)
	assert not [name for name in os.listdir(job.job_vault) if name.startswith('V1--')]
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]


@pytest.mark.parametrize('pattern', ['recreated_folder', 'git', 'git_alone'])
def test_recopy_row_dropped_for_a_verified_delete(tmp_path, pattern):
	job = create_job(str(tmp_path))
	if pattern == 'git_alone':
		# a due file replaced and deleted, and nothing else: the batch collapses to no entry, and goes through the backuper
		due = name_with_threshold(32, 'g')
		fast_forward_to_32(job, {due: 'x' * 1024})
		backuper = RunningBackuper(job)
		try:
			lock = os.path.join(job.monitor, due + '.lock')
			with open(lock, 'w') as f:
				f.write('new')
			os.rename(lock, os.path.join(job.monitor, due))
			os.remove(os.path.join(job.monitor, due))
			assert backuper.back_up(raw_events(job, [('create', due + '.lock', None, False), ('move', due, due + '.lock', False),
				('delete', due, None, False)]))[0::2] == (0, True)
		finally:
			backuper.stop()
	elif pattern == 'recreated_folder':
		# a stale child of a folder moved out of the tree and made again, due to be copied again from the vault
		due = name_with_threshold(32, 'e/f')
		fast_forward_to_32(job, {due: 'x' * 1024})
		shutil.rmtree(os.path.join(job.monitor, 'e'))
		seed_monitor(job, {'e/new.txt': 'new'})
		events = raw_events(job, [('delete', 'e', None, True), ('create', 'e', None, True)])
	else:
		# a due file the batch's collapsed entries do not name
		due = name_with_threshold(32, 'g')
		fast_forward_to_32(job, {due: 'x' * 1024})
		os.remove(os.path.join(job.monitor, due))
		seed_monitor(job, {'c.txt': 'c changed'})
		events = raw_events(job, [('create', due + '.lock', None, False), ('move', due, due + '.lock', False), ('delete', due, None, False),
			('modify', 'c.txt', None, False)])
	if pattern != 'git_alone':
		run_backup(job, rv.change_events_to_backup_entries(deque(events)), touched=rv.touched_scopes(events, job.monitor))
	version = rv.list_versions(job.job_vault)[-1]
	assert version.number == 33
	assert not os.path.lexists(os.path.join(version.path, due))
	rows = changes(job, version)
	assert (due, 'delete') in rows and (due, 'recopy') not in rows
	assert_version_matches_tree(job, version)


def test_backuper_passes_what_each_batch_touched(job, monkeypatch):
	import threading
	from tests.harness import wait_for_committed_count
	seed_monitor(job, {'a.txt': 'a', 'D/b.txt': 'b'})
	run_backup(job)
	passed = []
	real = rv.do_backup

	def recording(*args, **kwargs):
		passed.append(kwargs.get('touched'))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', recording)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	flag = threading.Event()
	# the batch queued at startup
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag),
		kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
		wait_for_committed_count(job, 2)
		# then a folder created, and a full comparison
		seed_monitor(job, {'N/c.txt': 'c'})
		with lock:
			queue.append(rv.ChangeEvent(2.0, True, 'create', os.path.join(job.monitor, 'N'), None))
		flag.set()
		wait_for_committed_count(job, 3)
		open(os.path.join(job.monitor, 'D/b.txt'), 'w').write('changed')
		with lock:
			queue.append(rv.ChangeEvent(3.0, False, 'full_scan', job.monitor, None))
		flag.set()
		wait_for_committed_count(job, 4)
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()
	assert passed == [rv.TouchedScopes(['a.txt/'], ['a.txt']), rv.TouchedScopes(['N/'], ['N']), None]


def test_the_sweep_never_follows_links(job):
	seed_monitor(job, {'D/a.txt': 'a', 'E/b.txt': 'b', 'keep.txt': 'k'})
	run_backup(job)
	v0 = latest_version(job).path
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True)
		before = older_versions(job)
		# untracked: a link to an older version's folder, a real folder holding a link, and a link where a parent folder is
		os.symlink(os.path.join(v0, 'E'), os.path.join(v1, 'D/to_e'))
		os.makedirs(os.path.join(v1, 'D/stale'))
		os.symlink(os.path.join(v0, 'E/b.txt'), os.path.join(v1, 'D/stale/b.txt'))
		os.symlink(os.path.join(v0, 'E'), os.path.join(v1, 'L'))
		os.symlink(os.path.join(v0, 'E/b.txt'), os.path.join(v1, 'D', BAD))
		removed, missing = rv.sweep_version_folder(manifest, v1, rv.TouchedScopes(['D/', 'L/x/', 'E/'], []))
		assert sorted(removed) == sorted([f'D/{BAD}', 'D/stale/', 'D/to_e']) and missing == []
		# L is not a folder of the version, so nothing under it is looked at
		assert os.path.islink(os.path.join(v1, 'L'))
		os.remove(os.path.join(v1, 'L'))
		assert [row for row in older_versions(job) if not row[0].startswith('V1--')] == [row for row in before if not row[0].startswith('V1--')]
		assert read_tree(os.path.join(v0, 'E')) == {'b.txt': b'b'}
		# a tracked entry gone from the version is missing; the version itself is never removed
		os.remove(os.path.join(v1, 'D/a.txt'))
		assert rv.sweep_version_folder(manifest, v1, rv.TouchedScopes(['D/'], [])) == ([], ['D/a.txt'])
		manifest.discard_many(['D/', 'D/a.txt', 'E/', 'E/b.txt', 'keep.txt'])
		assert rv.sweep_version_folder(manifest, v1, rv.TouchedScopes([''], [])) == (['D/', 'E/', 'keep.txt'], [])
		assert os.path.isdir(v1)
	finally:
		manifest.rollback()
		manifest.close()


@pytest.mark.parametrize('kind', ['absolute', 'relative', 'into_tree', 'into_version'])
def test_links_in_the_version_are_never_followed(tmp_path, kind):
	"""
	mv P <outside>/P_old; mkdir P; ln -s <a folder> P/A: the folder create copies the link to <version>/P/A, while the
	rows of the old real folder P/A/ stay until the verification deletes them. Nothing may be removed or written
	through the link: not outside the vault, not in the monitored tree, not elsewhere in the version.
	"""
	job = create_job(str(tmp_path))
	outside = os.path.join(job.root, 'data')
	os.makedirs(outside)
	write_tree(job.monitor, {'P/A/B/X': 'precious', 'P/A/y': 'y2', 'keep': 'k', 'Q/A/B/X': 'q precious', 'Q/A/y': 'qy'})
	run_backup(job)
	older = older_versions(job)
	shutil.move(os.path.join(job.monitor, 'P'), os.path.join(outside, 'P_old'))
	os.makedirs(os.path.join(job.monitor, 'P'))
	target = {'absolute': os.path.join(outside, 'P_old/A'), 'relative': os.path.relpath(os.path.join(outside, 'P_old/A'), os.path.join(job.monitor, 'P')),
		'into_tree': os.path.join(job.monitor, 'Q/A'), 'into_version': '../Q/A'}[kind]
	os.symlink(target, os.path.join(job.monitor, 'P/A'))
	targets = {path: read_tree(path) for path in (os.path.join(outside, 'P_old/A'), os.path.join(job.monitor, 'Q/A'))}
	events = raw_events(job, [('delete', 'P', None, True), ('create', 'P', None, True), ('create', 'P/A', None, False)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events)), touched=rv.touched_scopes(events, job.monitor))
	version = rv.list_versions(job.job_vault)[-1]
	assert {path: read_tree(path) for path in targets} == targets
	assert os.readlink(os.path.join(version.path, 'P/A')) == target
	assert_version_matches_tree(job, version)
	assert not [row for row in manifest_rows(job) if row.startswith('P/A/')]
	assert [row for row in older_versions(job) if not row[0].startswith(version.name)] == older


def test_the_sweep_never_writes_through_links(job):
	seed_monitor(job, {'D/a.txt': 'a', 'keep': 'k'})
	run_backup(job)
	v0 = latest_version(job).path
	outside = os.path.join(job.root, 'outside')
	os.makedirs(os.path.join(outside, 'B'))
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True)
		# the version holds links at D/L and at L, while stale rows still name folders under them
		os.symlink(outside, os.path.join(v1, 'D/L'))
		os.symlink(outside, os.path.join(v1, 'L'))
		for rel in ('D/L', 'D/L/', 'D/L/B/', 'D/L/B/x', 'L', 'L/', 'L/x/', 'L/x/y'):
			manifest.add(rel)
		removed, missing = rv.sweep_version_folder(manifest, v1, rv.TouchedScopes(['D/', 'L/x/'], []))
		# a version cannot hold them there: their rows go, and nothing is copied through the links
		assert missing == []
		assert sorted(removed) == ['D/L/', 'D/L/B/', 'D/L/B/x', 'L/x/', 'L/x/y']
		assert [rel for rel in ('D/L', 'D/L/', 'D/L/B/', 'D/L/B/x', 'L', 'L/', 'L/x/', 'L/x/y') if manifest.lookup(rel) is not None] == ['D/L', 'L', 'L/']
		assert read_tree(outside) == {'B/': None}
	finally:
		manifest.rollback()
		manifest.close()


def test_an_inner_mount_unmounted_during_the_verification_keeps_its_rows(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	table = [('/', ('1',)), (os.path.join(job.monitor, 'D/disk'), ('disk',))]
	monkeypatch.setattr(rv, 'current_mount_table', lambda: list(table))
	seed_monitor(job, {'D/a.txt': 'a', 'D/disk/f.txt': 'f', 'keep': 'k'})
	run_backup(job)
	seed_monitor(job, {'D/sub/n.txt': 'n'})
	real = rv.compare_scopes

	def unmounting(*args, **kwargs):
		# the disk goes away while the verification walks, leaving its empty mount point
		table[:] = [('/', ('1',))]
		shutil.move(os.path.join(job.monitor, 'D/disk/f.txt'), os.path.join(job.root, 'f.txt'))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'compare_scopes', unmounting)
	events = raw_events(job, [('delete', 'D', None, True), ('create', 'D', None, True)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events)), touched=rv.touched_scopes(events, job.monitor))
	version = rv.list_versions(job.job_vault)[-1]
	assert version.number == 1
	assert os.path.lexists(os.path.join(version.path, 'D/disk/f.txt'))
	assert 'D/disk/f.txt' in manifest_rows(job)
	assert not [row for row in changes(job, version) if row[0].startswith('D/disk/') and row[1] == 'delete']


def test_the_root_mount_changed_during_the_verification_fails_the_job(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	table = [('/', ('1',))]
	monkeypatch.setattr(rv, 'current_mount_table', lambda: list(table))
	seed_monitor(job, {'D/a.txt': 'a', 'keep': 'k'})
	run_backup(job, root_mount=rv.mount_fingerprint(table, os.path.realpath(job.monitor)))
	root_mount = rv.mount_fingerprint(table, os.path.realpath(job.monitor))
	seed_monitor(job, {'D/sub/n.txt': 'n'})
	real = rv.compare_scopes

	def remounting(*args, **kwargs):
		# another filesystem now shows at the monitored path
		table[:] = [('/', ('1',)), (job.monitor, ('other',))]
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'compare_scopes', remounting)
	events = raw_events(job, [('delete', 'D', None, True), ('create', 'D', None, True)])
	with pytest.raises(rv.JobFailure):
		rv.do_backup(rv.change_events_to_backup_entries(deque(events)), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
			keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', root_mount=root_mount,
			touched=rv.touched_scopes(events, job.monitor))
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]


@pytest.mark.parametrize('how', ['moved', 'covered'])
def test_recopies_keep_their_crash_check(tmp_path, how):
	job = create_job(str(tmp_path))
	due = name_with_threshold(32, 'D/f')
	fast_forward_to_32(job, {due: 'x' * 1024})
	if how == 'moved':
		# the re-copy is renamed with its folder, so its row is unverified and read back from this version
		os.rename(os.path.join(job.monitor, 'D'), os.path.join(job.monitor, 'D2'))
		events = raw_events(job, [('move', 'D2', 'D', True)])
		entries, touched, rel = rv.change_events_to_backup_entries(deque(events)), rv.touched_scopes(events, job.monitor), 'D2/' + due[2:]
	else:
		# a touched subtree over the re-copy that the batch's replay leaves alone
		seed_monitor(job, {'c.txt': 'changed again'})
		entries = OrderedDict([(os.path.join(job.monitor, 'c.txt'), rv.BackupEntryValues('t', 'modify', None))])
		touched, rel = rv.TouchedScopes(['D/'], ['c.txt']), due
	run_backup(job, entries, touched=touched)
	version = rv.list_versions(job.job_vault)[-1]
	assert version.number == 33 and not os.path.islink(os.path.join(version.path, rel))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		record = manifest.lookup(rel)
		assert record.kind == 'f' and record.unchecked == 1
	finally:
		manifest.close()


def test_fixes_the_replay_could_not_apply_are_not_recorded(tmp_path, monkeypatch):
	before, after, events_spec, _ = SEQUENCES['e2']
	real_compare, real_sweep = rv.compare_scopes, rv.sweep_version_folder

	def vanishing(entries, manifest, version_path, monitor_path, *args, **kwargs):
		compared = real_compare(entries, manifest, version_path, monitor_path, *args, **kwargs)
		# f, which the comparison found missing from the version, is gone again before its copy
		os.remove(os.path.join(monitor_path, 'f'))
		return compared

	def ghost(*args, **kwargs):
		removed, missing = real_sweep(*args, **kwargs)
		# a tracked rel missing from the version whose monitored source is gone
		return removed, missing + ['ghost.txt']
	monkeypatch.setattr(rv, 'compare_scopes', vanishing)
	monkeypatch.setattr(rv, 'sweep_version_folder', ghost)
	job, version = replay_sequence(tmp_path, before, after, events_spec)
	rows = changes(job, version)
	assert ('f', 'create') not in rows and ('ghost.txt', 'create') not in rows
	assert_version_matches_tree(job, version)


def test_self_move_is_dropped(job):
	folder = os.path.join(job.monitor, 'D')
	assert rv.change_events_to_backup_entries(deque([rv.ChangeEvent(1.0, True, 'move', folder, folder)])) == OrderedDict()


def start_backuper(job, queue):
	'''The job's backuper on queue, as the daemon runs it, with no watcher: (thread, to_process_lock, to_process_flag).'''
	import threading
	lock = threading.Lock()
	flag = threading.Event()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag),
		kwargs=dict(job=control), daemon=True)
	thread.start()
	return thread, lock, flag


def stop_backuper(thread):
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=5)
	rv.GREEN_LIGHT.set()


def queued_full_scan(queue, lock):
	with lock:
		return queue.full_scan_requested


def record_backups(monkeypatch):
	'''(entries, touched) of each do_backup() call; a full comparison is (0, None).'''
	calls = []
	real = rv.do_backup

	def recording(entries, *args, **kwargs):
		calls.append((len(entries), kwargs.get('touched')))
		return real(entries, *args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', recording)
	return calls


def test_a_resumed_batch_is_followed_by_a_full_comparison(job, monkeypatch):
	from tests.harness import write_pending, wait_until, wait_for_committed_count
	import time
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	a = os.path.join(job.monitor, 'a.txt')
	with open(a, 'w') as f:
		f.write('changed')
	pending = write_pending(job, [rv.ChangeEvent(time.monotonic(), False, 'modify', a, None)])
	for path in (job.monitor, a, os.path.join(job.monitor, 'b.txt')):
		os.utime(path, (time.time() - 30, time.time() - 30))
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue) is True
	assert queue.round_tripped
	calls = record_backups(monkeypatch)
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		# with no watcher to signal the backuper again
		wait_until(lambda: (0, None) in calls, message='no full comparison after the resumed batch')
		assert calls[0][0] == 1
		# the comparison is the batch's own, not a flag left for later batches
		assert not queue.round_tripped
	finally:
		stop_backuper(thread)


def test_a_requeued_batch_is_followed_by_a_full_comparison(job, monkeypatch):
	from tests.harness import wait_until, wait_for_committed_count
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	a = os.path.join(job.monitor, 'a.txt')
	with open(a, 'w') as f:
		f.write('changed')
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'b.txt'), None))
	assert not queue.round_tripped
	# the batch a backup that did not commit hands back
	queue.prepend(rv.backup_entries_to_change_events(OrderedDict([(a, rv.BackupEntryValues('t', 'modify', None))])))
	assert queue.round_tripped
	calls = record_backups(monkeypatch)
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		wait_until(lambda: (0, None) in calls, message='no full comparison after the requeued batch')
	finally:
		stop_backuper(thread)


def test_an_ordinary_batch_is_not_followed_by_a_full_comparison(job, monkeypatch):
	from tests.harness import wait_for_committed_count
	import time
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	with open(os.path.join(job.monitor, 'a.txt'), 'w') as f:
		f.write('changed')
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	calls = record_backups(monkeypatch)
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		time.sleep(0.5)
		assert calls == [(1, rv.TouchedScopes(['a.txt/'], ['a.txt']))]
		assert not queued_full_scan(queue, lock)
	finally:
		stop_backuper(thread)


class RunningBackuper:
	'''
	The job's backuper as the daemon runs it, past its startup comparison: each batch is queued and signalled as the
	watcher does, and waited for until the do_backup() it leads to returns. calls holds (entries, touched, committed) of
	each do_backup() call, the startup comparison's first.
	'''

	def __init__(self, job):
		from tests.harness import wait_until
		self.calls = []
		real = rv.do_backup

		def recording(entries, *args, **kwargs):
			count = len(entries)
			result = real(entries, *args, **kwargs)
			self.calls.append((count, kwargs.get('touched'), result[2]))
			return result
		self.patch = pytest.MonkeyPatch()
		self.patch.setattr(rv, 'do_backup', recording)
		self.queue = rv.ChangeEventQueue(job.monitor)
		self.thread, self.lock, self.flag = start_backuper(job, self.queue)
		wait_until(lambda: len(self.calls) == 1, message='no startup comparison')

	def back_up(self, events, timeout=10.0):
		'''Hand the backuper events as one batch. Returns its do_backup() call; it fails when there is none.'''
		from tests.harness import wait_until
		count = len(self.calls)
		with self.lock:
			for event in events:
				self.queue.append(event)
		self.flag.set()
		wait_until(lambda: len(self.calls) > count, timeout=timeout, message='the backuper did not back up the batch')
		return self.calls[count]

	def stop(self):
		try:
			stop_backuper(self.thread)
		finally:
			self.patch.undo()


def replace_then_delete(job):
	'''git's ref written to X.lock, renamed over the existing X, then X deleted: the raw events, made in the tree.'''
	ref = lambda name: os.path.join(job.monitor, 'refs', name)
	with open(ref('X.lock'), 'w') as f:
		f.write('new ref')
	os.rename(ref('X.lock'), ref('X'))
	os.remove(ref('X'))
	return [rv.ChangeEvent(1.0, False, 'create', ref('X.lock'), None), rv.ChangeEvent(2.0, False, 'modify', ref('X.lock'), None),
		rv.ChangeEvent(3.0, False, 'move', ref('X'), ref('X.lock')), rv.ChangeEvent(4.0, False, 'delete', ref('X'), None)]


def test_a_lone_replace_then_delete_is_verified(job):
	seed_monitor(job, {'refs/X': 'old ref', 'keep.txt': 'k'})
	run_backup(job)
	backuper = RunningBackuper(job)
	try:
		events = replace_then_delete(job)
		assert rv.change_events_to_backup_entries(deque(events), job.monitor) == OrderedDict()
		assert backuper.back_up(events) == (0, rv.touched_scopes(events, job.monitor), True)
	finally:
		backuper.stop()
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [0, 1]
	assert not os.path.lexists(os.path.join(versions[-1].path, 'refs/X'))
	assert ('refs/X', 'delete') in changes(job, versions[-1])
	assert_version_matches_tree(job, versions[-1])


def test_a_swap_back_over_an_existing_file_is_verified(job):
	seed_monitor(job, {'a': 'A', 'b': 'B'})
	run_backup(job)
	backuper = RunningBackuper(job)
	try:
		m = lambda name: os.path.join(job.monitor, name)
		os.rename(m('a'), m('b'))
		os.rename(m('b'), m('a'))
		events = [rv.ChangeEvent(1.0, False, 'move', m('b'), m('a')), rv.ChangeEvent(2.0, False, 'move', m('a'), m('b'))]
		assert backuper.back_up(events)[0::2] == (0, True)
	finally:
		backuper.stop()
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [0, 1]
	# the old b went with the first move
	assert sorted(os.listdir(versions[-1].path)) == ['a']
	with open(os.path.join(versions[-1].path, 'a')) as f:
		assert f.read() == 'A'
	assert_version_matches_tree(job, versions[-1])


def test_an_empty_batch_whose_touched_places_match_the_vault_makes_no_version(job):
	seed_monitor(job, {'X': 'x', 'keep.txt': 'k'})
	run_backup(job)
	rows = manifest_rows(job)
	backuper = RunningBackuper(job)
	try:
		lock = os.path.join(job.monitor, 'X.lock')
		with open(lock, 'w') as f:
			f.write('tmp')
		os.remove(lock)
		events = [rv.ChangeEvent(1.0, False, 'create', lock, None), rv.ChangeEvent(2.0, False, 'modify', lock, None),
			rv.ChangeEvent(3.0, False, 'delete', lock, None)]
		assert backuper.back_up(events) == (0, rv.touched_scopes(events, job.monitor), True)
	finally:
		backuper.stop()
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]
	assert manifest_rows(job) == rows


def test_scans_with_an_empty_collapse_compare_the_touched_places_too(job):
	seed_monitor(job, {'refs/X': 'old ref', 'S/s.txt': 's'})
	run_backup(job)
	backuper = RunningBackuper(job)
	try:
		events = [rv.ChangeEvent(0.5, True, 'scan', os.path.join(job.monitor, 'S'), None)] + replace_then_delete(job)
		assert backuper.back_up(events)[0::2] == (0, True)
	finally:
		backuper.stop()
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [0, 1]
	assert not os.path.lexists(os.path.join(versions[-1].path, 'refs/X'))
	assert_version_matches_tree(job, versions[-1])


def test_an_empty_collapse_that_does_not_commit_asks_for_a_full_comparison(job, monkeypatch):
	from tests.harness import wait_until
	seed_monitor(job, {'refs/X': 'old ref'})
	run_backup(job)
	real = rv.do_backup
	calls = []

	def failing(entries, *args, **kwargs):
		calls.append(kwargs.get('touched'))
		if len(calls) == 1:
			return real(entries, *args, **kwargs)
		# the batch's backup did not commit
		return None, None, False
	monkeypatch.setattr(rv, 'do_backup', failing)
	queue = rv.ChangeEventQueue(job.monitor)
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_until(lambda: len(calls) == 1, message='no startup comparison')
		with lock:
			for event in replace_then_delete(job):
				queue.append(event)
		flag.set()
		# its events are gone from the queue, and nothing names what they touched but a full comparison
		thread.join(timeout=10)
		assert not thread.is_alive() and len(calls) == 2 and calls[1] is not None
		assert queued_full_scan(queue, lock)
	finally:
		stop_backuper(thread)


def test_git_pattern_round_tripped_ends_clean(tmp_path):
	from tests.harness import wait_until, wait_for_committed_count
	before, after, events_spec, _ = SEQUENCES['git']
	job = create_job(str(tmp_path))
	write_tree(job.monitor, before)
	run_backup(job)
	make_tree(job, before, after)
	entries = rv.change_events_to_backup_entries(deque(raw_events(job, events_spec)), job.monitor)
	# the pending round trip keeps only the collapsed entries, which do not name X
	queue = rv.ChangeEventQueue(job.monitor)
	queue.prepend(rv.backup_entries_to_change_events(entries))
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		assert os.path.lexists(os.path.join(rv.list_versions(job.job_vault)[1].path, 'refs/X'))
		# the full comparison follows by itself
		wait_for_committed_count(job, 3)
	finally:
		stop_backuper(thread)
	latest = rv.list_versions(job.job_vault)[-1]
	assert not os.path.lexists(os.path.join(latest.path, 'refs/X'))
	assert_version_matches_tree(job, latest)


def test_an_event_on_the_root_gives_no_entry_and_no_row(tmp_path):
	job = create_job(str(tmp_path))
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, True, 'attrib', job.monitor, None))
	queue.append(rv.ChangeEvent(2.0, True, 'modify', job.monitor + '/', None))
	assert rv.change_events_to_backup_entries(deque(queue), job.monitor) == OrderedDict()
	# the queue knows its monitored path
	assert rv.change_events_to_backup_entries(queue) == OrderedDict()
	job, version = replay_sequence(tmp_path / 'replayed', {'a.txt': 'a'}, {'a.txt': 'changed'},
		[('attrib', '', None, True), ('modify', 'a.txt', None, False)])
	assert version.number == 1
	assert changes(job, version) == [('a.txt', 'modify')]
	assert_version_matches_tree(job, version)


def test_the_manifest_and_the_referenced_copy_reject_the_root(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	v0 = latest_version(job).path
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		for rel in ('', '.', './', '/', 'a/../b', 'a/./b', '/etc/x'):
			manifest.add(rel)
		assert manifest_rows_of(manifest) == {'a.txt'}
		# a row a daemon before 0.43 wrote for the root's own attrib event
		manifest.conn.execute("INSERT INTO entries(path) VALUES ('./'), ('')")
		v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
		os.makedirs(v1)
		lines = spy_on_log(monkeypatch)
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True)
		assert manifest_rows_of(manifest) == {'a.txt'}
		assert sorted(os.listdir(v1)) == ['a.txt']
		# the one-time cleanup of such rows is a warning
		dropped = [(error, warning) for message, error, warning in lines if 'names no' in message]
		assert dropped == [(False, True), (False, True)]
	finally:
		manifest.rollback()
		manifest.close()


def manifest_rows_of(manifest):
	return set(manifest.iter_folders()) | set(manifest.iter_files())


def xattrs_supported(path):
	probe = os.path.join(path, 'xattr-probe')
	with open(probe, 'w') as f:
		f.write('x')
	try:
		os.setxattr(probe, 'user.probe', b'1')
		return True
	except OSError:
		return False
	finally:
		os.remove(probe)


def entry_meta(path, xattrs):
	st = os.stat(path)
	held = {name: os.getxattr(path, name) for name in os.listxattr(path)} if xattrs else None
	return stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns, held


def set_meta(path, mode, owner, mtime_ns, note, xattrs):
	os.chmod(path, mode)
	os.chown(path, owner, owner)
	os.utime(path, ns=(mtime_ns, mtime_ns))
	if xattrs:
		os.setxattr(path, 'user.note', note)


@pytest.mark.parametrize('kind', ['outside', 'into_vault'])
def test_attrib_never_syncs_through_a_users_symlink(tmp_path, kind):
	'''
	A user's symlink L is backed up as a link, so the version's L leads, by its chain link, to it in V0 and then to
	where its text points: an outside file, or for a relative link, another file of the vault. An attrib batch on L
	syncs the link's own owner and times only, and nothing it points to changes.
	'''
	job = create_job(str(tmp_path))
	xattrs = xattrs_supported(job.root)
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	for name in ('A', 'B'):
		with open(os.path.join(outside, name), 'w') as f:
			f.write(name)
	if kind == 'outside':
		write_tree(job.monitor, {'keep.txt': 'k', 'L': ('link', os.path.join(outside, 'A'))})
	else:
		write_tree(job.monitor, {'keep.txt': 'k', 'target': 'in the vault', 'L': ('link', 'target')})
	run_backup(job)
	v0 = latest_version(job).path
	assert os.path.islink(os.path.join(v0, 'L'))
	victim = os.path.join(outside, 'A') if kind == 'outside' else os.path.join(v0, 'target')
	set_meta(victim, 0o640, 1234, 1_600_000_000_000_000_000, b'victim', xattrs)
	held = entry_meta(victim, xattrs)
	# what the monitored link leads to now has other attributes: another outside file, or the monitored target
	if kind == 'outside':
		os.remove(os.path.join(job.monitor, 'L'))
		os.symlink(os.path.join(outside, 'B'), os.path.join(job.monitor, 'L'))
		led_to = os.path.join(outside, 'B')
	else:
		led_to = os.path.join(job.monitor, 'target')
	set_meta(led_to, 0o600, 4321, 1_500_000_000_000_000_000, b'source', xattrs)
	link = os.path.join(job.monitor, 'L')
	os.lchown(link, 1111, 1111)
	os.utime(link, ns=(1_400_000_000_000_000_000, 1_400_000_000_000_000_000), follow_symlinks=False)
	events = raw_events(job, [('attrib', 'L', None, False)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	assert entry_meta(victim, xattrs) == held
	version = rv.list_versions(job.job_vault)[-1]
	assert version.number == 1
	# the version's L chains to the backed up link, which took the link's own owner and times
	end = rv.chain_end(job.job_vault, version.path, 'L')
	assert end.path == os.path.join(v0, 'L') and stat.S_ISLNK(end.st.st_mode)
	assert (end.st.st_uid, end.st.st_mtime_ns) == (1111, 1_400_000_000_000_000_000)


def test_copy_file_meta_gives_a_link_only_its_own_owner_and_times(tmp_path):
	xattrs = xattrs_supported(str(tmp_path))
	source, target, link = (os.path.join(str(tmp_path), name) for name in ('source', 'target', 'link'))
	for path in (source, target):
		with open(path, 'w') as f:
			f.write(path)
	set_meta(target, 0o640, 1234, 1_600_000_000_000_000_000, b'target', xattrs)
	set_meta(source, 0o600, 4321, 1_500_000_000_000_000_000, b'source', xattrs)
	held = entry_meta(target, xattrs)
	os.symlink(target, link)
	assert rv.copy_file_meta(source, link)
	assert entry_meta(target, xattrs) == held
	st = os.lstat(link)
	assert (st.st_uid, st.st_gid, st.st_mtime_ns) == (4321, 4321, 1_500_000_000_000_000_000)


def test_the_sweep_checks_the_folders_above_what_it_removes(job):
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	with open(os.path.join(outside, 'x'), 'w') as f:
		f.write('precious')
	v1 = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(v1)
	os.symlink(outside, os.path.join(v1, 'L'))
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		removed = []
		assert rv.sweep_entry(manifest, v1, os.path.join(v1, 'L/x'), 'L/x', False, set(), removed) == []
		assert removed == [] and os.path.isfile(os.path.join(outside, 'x'))
	finally:
		manifest.rollback()
		manifest.close()


@pytest.mark.parametrize('parent', ['file', 'link'])
def test_a_refused_copy_leaves_its_partial_file_alone(job, parent):
	from tests.test_io_errors import FakeTask
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	src = os.path.join(job.monitor, 'a.txt')
	with open(src, 'w') as f:
		f.write('a')
	version = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(version)
	# the copy's folder D was replaced, after the copy was made in it, by a file or a link
	if parent == 'file':
		with open(os.path.join(version, 'D'), 'w') as f:
			f.write('now a file')
	else:
		os.symlink(outside, os.path.join(version, 'D'))
		with open(os.path.join(outside, '.partial'), 'w') as f:
			f.write('not the copy')
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		manifest.add('D/a.txt', dirty=True)
		assert rv.finish_copies([rv.PendingCopy(FakeTask(0), src, os.path.join(version, 'D/.partial'), os.path.join(version, 'D/a.txt'))],
			manifest, version, job.job_name) == []
		assert manifest.lookup('D/a.txt') is None
	finally:
		manifest.rollback()
		manifest.close()
	if parent == 'link':
		assert sorted(os.listdir(outside)) == ['.partial']


@pytest.mark.parametrize('how', ['failed', 'discarded'])
def test_partial_files_behind_a_link_are_never_removed(job, how):
	from tests.test_io_errors import FakeTask
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	with open(os.path.join(outside, '.partial'), 'w') as f:
		f.write('not the copy')
	version = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(version)
	# the copy's folder D was replaced by a link after the copy was made in it
	os.symlink(outside, os.path.join(version, 'D'))
	copy = rv.PendingCopy(FakeTask(1, ['No such file or directory']), os.path.join(job.monitor, 'gone.txt'), os.path.join(version, 'D/.partial'),
		os.path.join(version, 'D/a.txt'))
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		if how == 'failed':
			rv.finish_copies([copy], manifest, version, job.job_name)
		else:
			rv.stop_copies(rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True), [copy], version)
	finally:
		manifest.rollback()
		manifest.close()
	assert sorted(os.listdir(outside)) == ['.partial']


def test_a_version_being_written_is_never_trusted_for_its_folders(tmp_path):
	'''
	An attrib on D/f, then D replaced by a link out of the tree in the same batch. Then a link of chain form naming that
	version's D/g, and a touch -h on it: nothing about the version written first may be taken as known, or the attribute
	sync reaches through D to the outside file.
	'''
	rv.REAL_VAULT_FOLDERS.clear()
	job = create_job(str(tmp_path))
	xattrs = xattrs_supported(job.root)
	outside = os.path.join(job.root, 'outside_dir')
	os.makedirs(outside)
	victim = os.path.join(outside, 'g')
	with open(victim, 'w') as f:
		f.write('root owned')
	set_meta(victim, 0o600, 0, 1_600_000_000_000_000_000, b'victim', xattrs)
	held = entry_meta(victim, xattrs)
	before = {'D/f': 'x', 'keep': 'k'}
	write_tree(job.monitor, before)
	run_backup(job)
	make_tree(job, before, {'D': ('link', outside), 'keep': 'k'})
	events = raw_events(job, [('attrib', 'D/f', None, False), ('create', 'D', None, False)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	v1 = rv.list_versions(job.job_vault)[-1]
	assert os.path.islink(os.path.join(v1.path, 'D'))
	cached = [key for key in rv.REAL_VAULT_FOLDERS if key[0] == os.path.abspath(v1.path)]
	os.makedirs(os.path.join(job.monitor, 'a'))
	os.symlink(f'../{v1.name}/D/g', os.path.join(job.monitor, 'a', 'U'))
	decoy = os.path.join(job.monitor, v1.name, 'D', 'g')
	os.makedirs(os.path.dirname(decoy))
	with open(decoy, 'w') as f:
		f.write('decoy')
	set_meta(decoy, 0o666, 4242, 1_500_000_000_000_000_000, b'decoy', xattrs)
	events = raw_events(job, [('create', 'a', None, True), ('create', v1.name, None, True)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	os.lchown(os.path.join(job.monitor, 'a', 'U'), 4243, 4243)
	events = raw_events(job, [('attrib', 'a/U', None, False)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	assert rv.list_versions(job.job_vault)[-1].number == 3
	assert entry_meta(victim, xattrs) == held
	assert cached == []


def test_copy_file_meta_never_follows_a_link_named_with_a_trailing_slash(tmp_path):
	source, target, link = (os.path.join(str(tmp_path), name) for name in ('source', 'target', 'link'))
	for path in (source, target):
		os.makedirs(path)
	os.chmod(target, 0o700)
	os.utime(target, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
	os.chmod(source, 0o755)
	os.utime(source, ns=(1_500_000_000_000_000_000, 1_500_000_000_000_000_000))
	held = os.stat(target)
	os.symlink(target, link)
	assert rv.copy_file_meta(source, link + '/')
	st = os.stat(target)
	assert (st.st_mode, st.st_uid, st.st_mtime_ns) == (held.st_mode, held.st_uid, held.st_mtime_ns)
	assert os.lstat(link).st_mtime_ns == 1_500_000_000_000_000_000


def spy_on_log(monkeypatch):
	'''(message, error, warning) of each backuper log line.'''
	lines = []
	real = rv.backuperTeeLogToTl

	def spy(path, message, error=False, ok=False, warning=False, debug=False):
		lines.append((message, error, warning))
		return real(path, message, error=error, ok=ok, warning=warning, debug=debug)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', spy)
	return lines


def test_a_folder_replaced_by_a_file_logs_one_line(tmp_path, monkeypatch):
	lines = []
	before = {'big/' + f'sub{i}/f{j}.txt': 'x' for i in range(3) for j in range(5)}
	job, version = replay_sequence(tmp_path, {**before, 'keep.txt': 'k'}, {'big': 'now a file', 'keep.txt': 'k'},
		[('create', 'big', None, False)], between=lambda job: lines.append(spy_on_log(monkeypatch)))
	assert_version_matches_tree(job, version)
	logged = [message for message, error, _ in lines[0] if 'big' in message and (error or 'in its place' in message)]
	assert len(logged) == 1 and 'in its place' in logged[0], logged


def test_scans_handed_back_alone_are_not_round_tripped(job):
	queue = rv.ChangeEventQueue(job.monitor)
	queue.prepend(rv.scan_events([os.path.join(job.monitor, 'disk')]))
	assert not queue.round_tripped
	queue.prepend(rv.backup_entries_to_change_events(OrderedDict([(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues('t', 'modify', None))])))
	assert queue.round_tripped


@pytest.mark.parametrize('name', ['file_over_folder', 'gone_folder_named_as_a_folder'])
def test_the_other_kind_of_a_touched_name_is_compared(tmp_path, name):
	if name == 'file_over_folder':
		# rm -rf L; echo > L, its events reduced to the create of the file
		before, after, events_spec = {'L/x.txt': 'x', 'L/sub/y.txt': 'y', 'keep.txt': 'k'}, {'L': 'now a file', 'keep.txt': 'k'}, [('create', 'L', None, False)]
	else:
		# a folder's event for a name the version holds as a file, now gone
		before, after, events_spec = {'L': 'a file', 'keep.txt': 'k'}, {'keep.txt': 'k', 'M/': None}, [('attrib', 'L', None, True), ('create', 'M', None, True)]
	job, version = replay_sequence(tmp_path, before, after, events_spec)
	assert_version_matches_tree(job, version)
	# and the next batch backs up as any other
	seed_monitor(job, {'keep.txt': 'changed'})
	events = raw_events(job, [('modify', 'keep.txt', None, False)])
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	latest = rv.list_versions(job.job_vault)[-1]
	assert latest.number == 2
	assert_version_matches_tree(job, latest)


def versions_meta(job, xattrs, but=None):
	"""older_versions() of every version (but the one named but), with each regular file's extended attributes."""
	rows = []
	for row in older_versions(job):
		if but is not None and row[0].startswith(but + '/'):
			continue
		path = os.path.join(job.job_vault, row[0])
		held = None
		if xattrs and stat.S_ISREG(row[1]):
			held = {name: os.getxattr(path, name) for name in os.listxattr(path)}
		rows.append((*row, held))
	return rows


def run_batch(job, spec):
	events = raw_events(job, spec)
	run_backup(job, rv.change_events_to_backup_entries(deque(events), job.monitor), touched=rv.touched_scopes(events, job.monitor))
	return rv.list_versions(job.job_vault)[-1]


@pytest.mark.parametrize('depth', [1, 2])
def test_a_users_link_of_chain_form_never_redirects_an_attribute_sync(tmp_path, monkeypatch, depth):
	"""
	A user's link whose text has a chain link's form, naming a file of the version before the one holding it, and a
	decoy file it reaches in the monitored tree (depth 2), or beside it (depth 1). The chain rule takes the stored link
	for a chain link to that file's copy: an attribute sync of the link, a symlink in the tree, must not land there.
	"""
	rv.REAL_VAULT_FOLDERS.clear()
	job = create_job(str(tmp_path))
	xattrs = xattrs_supported(job.root)
	write_tree(job.monitor, {'D/secret': 'secret', 'keep': 'k'})
	set_meta(os.path.join(job.monitor, 'D/secret'), 0o600, 0, 1_600_000_000_000_000_000, b'secret', xattrs)
	run_backup(job)
	v0 = rv.list_versions(job.job_vault)[-1]
	if depth == 2:
		os.makedirs(os.path.join(job.monitor, 'a'))
		link = os.path.join(job.monitor, 'a', 'U')
		decoy = os.path.join(job.monitor, v0.name, 'D', 'secret')
		spec = [('create', 'a', None, True), ('create', v0.name, None, True)]
	else:
		link = os.path.join(job.monitor, 'U')
		decoy = os.path.join(job.root, v0.name, 'D', 'secret')
		spec = [('create', 'U', None, False)]
	os.symlink(f'../{v0.name}/D/secret', link)
	os.makedirs(os.path.dirname(decoy))
	with open(decoy, 'w') as f:
		f.write('decoy')
	set_meta(decoy, 0o666, 4242, 1_500_000_000_000_000_000, b'decoy', xattrs)
	run_batch(job, spec)
	os.lchown(link, 4243, 4243)
	held = versions_meta(job, xattrs)
	lines = spy_on_log(monkeypatch)
	version = run_batch(job, [('attrib', os.path.relpath(link, job.monitor), None, False)])
	assert version.number == 2
	assert versions_meta(job, xattrs, but=version.name) == held
	assert [message for message, error, _ in lines if error and 'Not syncing the attributes' in message]


def test_an_attribute_sync_whose_chain_ends_at_a_folder_is_refused(tmp_path, monkeypatch):
	rv.REAL_VAULT_FOLDERS.clear()
	job = create_job(str(tmp_path))
	write_tree(job.monitor, {'D/g': 'g', 'keep': 'k'})
	run_backup(job)
	v0 = rv.list_versions(job.job_vault)[-1]
	folder = os.path.join(v0.path, 'D')
	os.chmod(folder, 0o750)
	held = os.stat(folder)
	# what the monitored link reaches: a decoy folder beside the monitored tree
	decoy = os.path.join(job.root, v0.name, 'D')
	os.makedirs(decoy)
	os.chmod(decoy, 0o777)
	os.chown(decoy, 4242, 4242)
	os.symlink(f'../{v0.name}/D', os.path.join(job.monitor, 'U'))
	run_batch(job, [('create', 'U', None, False)])
	os.lchown(os.path.join(job.monitor, 'U'), 4243, 4243)
	lines = spy_on_log(monkeypatch)
	run_batch(job, [('attrib', 'U', None, False)])
	st = os.stat(folder)
	assert (st.st_mode, st.st_uid, st.st_mtime_ns) == (held.st_mode, held.st_uid, held.st_mtime_ns)
	assert [message for message, error, _ in lines if error and 'ends at the folder' in message]


def test_a_partial_file_that_cannot_be_removed_fails_the_copy(job, monkeypatch):
	from tests.test_io_errors import FakeTask
	version = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(os.path.join(version, 'D'))
	temp = os.path.join(version, 'D/.partial')
	with open(temp, 'w') as f:
		f.write('partial')

	def stuck(path):
		raise PermissionError(13, 'Permission denied', path)
	monkeypatch.setattr(rv, 'remove_entry', stuck)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		# the copy's folder is a real folder of the version: a partial file left there would be committed with it
		with pytest.raises(PermissionError):
			rv.finish_copies([rv.PendingCopy(FakeTask(1, ['No such file or directory']), os.path.join(job.monitor, 'gone.txt'), temp,
				os.path.join(version, 'D/a.txt'))], manifest, version, job.job_name)
	finally:
		manifest.rollback()
		manifest.close()


def test_a_partial_file_behind_a_link_is_logged_and_left(job, monkeypatch):
	from tests.test_io_errors import FakeTask
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	with open(os.path.join(outside, '.partial'), 'w') as f:
		f.write('not the copy')
	version = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(version)
	os.symlink(outside, os.path.join(version, 'D'))
	lines = spy_on_log(monkeypatch)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	try:
		rv.finish_copies([rv.PendingCopy(FakeTask(1, ['No such file or directory']), os.path.join(job.monitor, 'gone.txt'),
			os.path.join(version, 'D/.partial'), os.path.join(version, 'D/a.txt'))], manifest, version, job.job_name)
	finally:
		manifest.rollback()
		manifest.close()
	assert sorted(os.listdir(outside)) == ['.partial']
	assert [message for message, _, _ in lines if 'Leaving the partial copy' in message]


def test_version_folders_stay_the_daemons_whatever_the_monitored_root(job):
	# the user chose to keep each version folder the daemon's: the monitored root's owner (www-data for a Nextcloud
	# folder) must not be able to change the top level of committed versions
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	with open(os.path.join(job.monitor, 'a.txt'), 'w') as f:
		f.write('changed')
	os.chmod(job.monitor, 0o777)
	os.chown(job.monitor, 1234, 5678)
	# the root's own events give no entry
	version = run_batch(job, [('attrib', '', None, True), ('modify', 'a.txt', None, False)])
	assert version.number == 1
	for path in (version.path, rv.list_versions(job.job_vault)[0].path):
		st = os.lstat(path)
		assert (st.st_uid, st.st_gid) == (os.geteuid(), os.getegid())
		assert stat.S_IMODE(st.st_mode) != 0o777


@pytest.mark.parametrize('kind', ['file', 'folder'])
def test_copy_file_meta_never_takes_a_links_target_onto_an_entry_that_is_not_one(tmp_path, monkeypatch, kind):
	# the monitored entry is a symlink now, while the version still holds a real copy of it
	target = os.path.join(str(tmp_path), 'target')
	dest = os.path.join(str(tmp_path), 'dest')
	if kind == 'file':
		write_plain_tree(str(tmp_path), {'target': 'elsewhere', 'dest': 'copy'})
	else:
		os.makedirs(target)
		os.makedirs(dest)
	os.chmod(target, 0o600)
	os.chown(target, 1234, 5678)
	os.setxattr(target, 'user.target', b'1')
	link = os.path.join(str(tmp_path), 'link')
	os.symlink(target, link)
	before = os.lstat(dest)
	lines = spy_on_log(monkeypatch)
	assert rv.copy_file_meta(link + ('/' if kind == 'folder' else ''), dest) is False
	after = os.lstat(dest)
	assert (after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns, after.st_ctime_ns) == (before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns, before.st_ctime_ns)
	assert os.listxattr(dest) == []
	assert len([message for message, error, _ in lines if error]) == 1


@pytest.mark.parametrize('how', ['returns', 'raises'])
def test_a_version_being_written_is_forgotten_on_every_exit(job, monkeypatch, how):
	seed_monitor(job, {'D/a.txt': 'a'})
	run_backup(job)
	latest = latest_version(job)
	backup_folder = os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800')
	os.makedirs(backup_folder)
	# what a walk of the version being written learned before the referenced copy stopped
	key = (os.path.abspath(backup_folder), os.path.join(os.path.abspath(backup_folder), 'D'))
	rv.REAL_VAULT_FOLDERS[key] = True

	def stopped(*args, **kwargs):
		if how == 'raises':
			raise OSError('the disk went')
		return False
	monkeypatch.setattr(rv, 'do_referenced_copy', stopped)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		if how == 'raises':
			with pytest.raises(OSError):
				rv.do_reverb_backup(OrderedDict(), backup_folder, latest, True, manifest, job.monitor)
		else:
			rv.do_reverb_backup(OrderedDict(), backup_folder, latest, True, manifest, job.monitor)
	finally:
		manifest.rollback()
		manifest.close()
	assert key not in rv.REAL_VAULT_FOLDERS


@pytest.mark.parametrize('first', [True, False])
@pytest.mark.parametrize('kind', ['link', 'folder'])
def test_a_version_folder_already_there_fails_the_attempt(job, monkeypatch, first, kind):
	'''A leftover of the new version's exact name, a link out of the vault or a folder holding one, is never written into.'''
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	seed_monitor(job, {'D/a.txt': 'a', 'keep.txt': 'k'})
	if not first:
		run_backup(job)
	stamp = '2021-01-03_00-00-00_-0800'
	real_format = rv.VAULT_TIMESTAMP_FORMAT
	os.makedirs(job.job_vault, exist_ok=True)
	leftover = os.path.join(job.job_vault, f'V{0 if first else 1}--{stamp}')
	real_info = rv.get_vault_info

	def info_then_leftover(*args, **kwargs):
		# listing the vault removes the incomplete versions it finds: the leftover appears after that, and the new version
		# is named as it is ( strftime() gives back a format without directives as it is )
		info = real_info(*args, **kwargs)
		monkeypatch.setattr(rv, 'VAULT_TIMESTAMP_FORMAT', stamp)
		if kind == 'link':
			os.symlink(outside, leftover)
		else:
			os.makedirs(leftover)
			os.symlink(outside, os.path.join(leftover, 'D'))
			os.symlink(os.path.join(outside, 'k'), os.path.join(leftover, 'keep.txt'))
		return info
	monkeypatch.setattr(rv, 'get_vault_info', info_then_leftover)
	older = older_versions(job)
	with open(os.path.join(job.monitor, 'D/a.txt'), 'w') as f:
		f.write('changed')
	lines = spy_on_log(monkeypatch)
	entries = OrderedDict() if first else OrderedDict([event_entry_for(job, 'D/a.txt', 'modify')])
	_, manifest, committed = rv.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert os.listdir(outside) == []
	assert committed is False
	monkeypatch.setattr(rv, 'get_vault_info', real_info)
	monkeypatch.setattr(rv, 'VAULT_TIMESTAMP_FORMAT', real_format)
	assert older_versions(job) == older
	assert [message for message, error, _ in lines if error and leftover in message]
	assert [version.number for version in rv.list_versions(job.job_vault)] == ([] if first else [0])


def event_entry_for(job, rel, event):
	from tests.harness import event_entry
	return event_entry(job, rel, event)
