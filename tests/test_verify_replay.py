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
	V0 of before, then one batch of events_spec run as the backuper runs it, over the monitored tree made into after.
	between(job), when given, runs once V0 is taken. Returns (job, the batch's version).
	'''
	job = create_job(str(tmp_path))
	write_tree(job.monitor, before)
	run_backup(job)
	if between is not None:
		between(job)
	make_tree(job, before, after)
	events = raw_events(job, events_spec)
	entries = rv.change_events_to_backup_entries(deque(events))
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


@pytest.mark.xfail(strict=True, reason='a move onto itself is dropped in the collapse in Task 3')
def test_sequence_loop(tmp_path):
	job, version = replay_sequence(tmp_path, BASE, BASE, [('move', 'D2', 'D', True), ('move', 'D', 'D2', True)])
	assert_version_matches_tree(job, version)


def spy_on_compare_scopes(monkeypatch):
	'''The scopes of each compare_scopes() call.'''
	calls = []
	real = rv.compare_scopes

	def spy(*args, **kwargs):
		calls.append(args[4] if len(args) > 4 else kwargs['scopes'])
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'compare_scopes', spy)
	return calls


def test_a_single_modify_compares_one_path(tmp_path, monkeypatch):
	calls = []
	job, version = replay_sequence(tmp_path, {'a.txt': 'a', 'D/b.txt': 'b'}, {'a.txt': 'changed', 'D/b.txt': 'b'},
		[('modify', 'a.txt', None, False)], between=lambda job: calls.append(spy_on_compare_scopes(monkeypatch)))
	assert calls[0] == [rv.TouchedScopes([], ['a.txt'])]
	assert changes(job, version) == [('a.txt', 'modify')]


def test_folder_attrib_compares_the_folder_only(tmp_path, monkeypatch):
	calls = []
	job, version = replay_sequence(tmp_path, {'D/x.txt': 'x', 'D/E/y.txt': 'y'}, {'D/x.txt': 'x', 'D/E/y.txt': 'y'},
		[('attrib', 'D', None, True), ('attrib', '', None, True)], between=lambda job: calls.append(spy_on_compare_scopes(monkeypatch)))
	assert calls[0] == [rv.TouchedScopes([], ['D/'])]
	# the rows are left out: the batch's own attrib entry for the root replays as a row './' (not the verification's)
	assert read_tree(version.path, {}) == read_tree(job.monitor)


def test_touched_scopes(job):
	events = raw_events(job, [
		('create', 'N', None, True), ('modify', 'N/f.txt', None, False), ('move', 'M', 'S', True),
		('attrib', 'A', None, True), ('modify', 'A/g.txt', None, False), ('move', 'b.txt', 'a.txt', False),
		('delete', 'N/sub', None, True), ('scan', 'Q', None, True), ('attrib', '', None, True), ('modify', 'M', None, False)])
	events += [rv.ChangeEvent(20.0, True, 'move', os.path.join(job.monitor, 'in'), os.path.join(job.root, 'outside')),
		rv.ChangeEvent(21.0, False, 'modify', os.path.join(job.root, 'outside.txt'), None),
		rv.ChangeEvent(22.0, True, 'full_scan', job.monitor, None), rv.ChangeEvent(23.0, True, 'self_destruct', job.monitor, None)]
	assert rv.touched_scopes(events, job.monitor) == rv.TouchedScopes(['M/', 'N/', 'S/', 'in/'], ['A/', 'A/g.txt', 'a.txt', 'b.txt'])
	assert rv.touched_scopes([], job.monitor) == rv.TouchedScopes([], [])
	# a job monitoring the root of the filesystem
	assert rv.touched_scopes([rv.ChangeEvent(1.0, False, 'modify', '/etc/x', None), rv.ChangeEvent(2.0, True, 'create', '/srv', None),
		rv.ChangeEvent(3.0, True, 'attrib', '/', None)], '/') == rv.TouchedScopes(['srv/'], ['etc/x'])


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


def older_versions(job):
	'''(rel, kind, link target, mode, uid, gid, mtime_ns) of everything in every version but the newest.'''
	listing = []
	for version in rv.list_versions(job.job_vault):
		for folder, dirs, files in os.walk(version.path):
			for name in sorted(dirs + files):
				path = os.path.join(folder, name)
				st = os.lstat(path)
				listing.append((os.path.relpath(path, job.job_vault), stat.S_IFMT(st.st_mode), os.readlink(path) if stat.S_ISLNK(st.st_mode) else None,
					st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns))
	return sorted(listing)


@pytest.mark.parametrize('name', sorted(SEQUENCES))
def test_older_versions_are_untouched(tmp_path, name):
	before, after, events_spec, _ = SEQUENCES[name]
	snapshots = []
	job, version = replay_sequence(tmp_path, before, after, events_spec, between=lambda job: snapshots.append(older_versions(job)))
	assert version.number == 1
	assert snapshots[0] and [row for row in older_versions(job) if not row[0].startswith(version.name)] == snapshots[0]


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


@pytest.mark.parametrize('pattern', ['recreated_folder', 'git'])
def test_recopy_row_dropped_for_a_verified_delete(tmp_path, pattern):
	job = create_job(str(tmp_path))
	if pattern == 'recreated_folder':
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
	assert passed == [rv.TouchedScopes([], ['a.txt']), rv.TouchedScopes(['N/'], []), None]


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
