'''
Users' symlinks whose text has the form of the vault's own chain links (round 8): pruning, the re-copy, history and
restore tell them from chain links by their version's moves (vault_chain_hop()), so the link stays a link, and no
other file's copy moves, changes or disappears in any kept version. Most tests invert one of the investigation's
repros, each of which passed while its bug was there.
'''
import errno
import os
import shutil
import sqlite3
import stat
from collections import deque, OrderedDict
import pytest
import TSVZ
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, event_entry, write_rule, write_committed_version
from tests.test_log_text import alerting_lines

pytestmark = pytest.mark.unit

T0 = '2021-01-01_00-00-00_-0800'
T1 = '2021-01-02_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fresh_folders():
	rv.REAL_VAULT_FOLDERS.clear()


def fresh_job(tmp_path, tree=None):
	'''A job whose V0 holds tree: by default a private D/secret and keep.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'} if tree is None else tree)
	if os.path.exists(os.path.join(job.monitor, 'D/secret')):
		os.chmod(os.path.join(job.monitor, 'D/secret'), 0o600)
	run_backup(job)
	return job


def latest(job):
	return rv.list_versions(job.job_vault)[-1]


def add_user_link(job, rel, text, **kwargs):
	'''The monitored symlink rel -> text (its folder made too), backed up as the watcher queues it: a create.'''
	folder = os.path.dirname(rel)
	entries = OrderedDict()
	if folder and not os.path.isdir(os.path.join(job.monitor, folder)):
		os.makedirs(os.path.join(job.monitor, folder))
		entries.update([event_entry(job, folder + '/', 'create')])
	os.symlink(text, os.path.join(job.monitor, rel))
	if not entries:
		entries.update([event_entry(job, rel, 'create')])
	run_backup(job, entries, **kwargs)
	return latest(job)


def bump(job, n, **kwargs):
	'''n more versions, each modifying keep.'''
	for i in range(n):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'{i}-{len(rv.list_versions(job.job_vault))}')
		run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]), **kwargs)


def chain_text(version_name, rel):
	'''The text the referenced copy writes for rel, linking it to the version named version_name.'''
	return '../' * (rel.count('/') + 1) + f'{version_name}/{rel}'


def holds_user_link(job, version, rel, text):
	'''Whether version holds the user's link rel -> text: the link itself, or the daemon's chain links down to it.'''
	below = {kept.number: kept for kept in rv.list_versions(job.job_vault)}
	while True:
		path = os.path.join(version.path, rel)
		if not os.path.islink(path):
			return False
		found = os.readlink(path)
		if found == text:
			return True
		version = below.get(version.number - 1)
		if version is None or found != chain_text(version.name, rel):
			return False


def snapshot(job, versions, links):
	'''
	What each of versions holds, as the kernel reads it through the chain links: every rel, each file's bytes, mode,
	owner and mtime, each folder's mode and owner; a rel of links (rel -> the user's text) as whether it is that link.
	'''
	seen = {}
	for version in versions:
		held = {}
		for path, rel, is_dir in rv.iter_tree_entries(version.path):
			if rel in links:
				held[rel] = ('user link', holds_user_link(job, version, rel, links[rel]))
			elif is_dir:
				st = os.lstat(path)
				held[rel] = ('folder', st.st_mode, st.st_uid, st.st_gid)
			elif not os.path.exists(path):
				held[rel] = ('broken', os.readlink(path))
			else:
				st = os.stat(path)
				with open(path, 'rb') as f:
					held[rel] = ('file', f.read(), st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns)
		seen[version.number] = held
	return seen


@pytest.fixture
def pruning_keeps(monkeypatch):
	'''
	watch(job, links) checks every removal of the oldest version from then on: each kept version holds what it held
	before, as snapshot() reads it. Returns the list of what each removal returned.
	'''
	removals = []
	def watch(job, links):
		real = rv.decrement_stepper
		def checked(vault_info_dict, *args, **kwargs):
			kept = rv.list_versions(job.job_vault)[1:]
			before = snapshot(job, kept, links)
			removed = real(vault_info_dict, *args, **kwargs)
			after = snapshot(job, [version for version in rv.list_versions(job.job_vault) if version.number in before], links)
			assert after == before
			removals.append(removed)
			return removed
		monkeypatch.setattr(rv, 'decrement_stepper', checked)
		return removals
	return watch


def command(tmp_path, capsys, *argv):
	capsys.readouterr()
	code = rv.run_command([*argv, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', str(tmp_path / 'state')])
	out = capsys.readouterr()
	return code, out.out, out.err


def warnings_logged(monkeypatch):
	warnings = []
	real_log = rv.backuperTeeLogToTl
	def record(path, message, error=False, ok=False, warning=False, debug=False):
		if warning:
			warnings.append(message)
		return real_log(path, message, error=error, ok=ok, warning=warning, debug=debug)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', record)
	return warnings


# --- pruning ---

@pytest.mark.parametrize('folder', ['a', 'zz'])
@pytest.mark.parametrize('form', ['one_up', 'right_depth'])
def test_pruning_keeps_a_user_link_naming_another_file(tmp_path, pruning_keeps, folder, form):
	# repro test_r8_prune: the named file's copy was moved onto the link, or the link removed, in every kept version
	job = fresh_job(tmp_path)
	v0 = latest(job)
	rel = f'{folder}/U'
	text = {'one_up': f'../{v0.name}/D/secret', 'right_depth': chain_text(v0.name, 'D/secret')}[form]
	add_user_link(job, rel, text)
	removals = pruning_keeps(job, {rel: text})
	bump(job, 3, keep_n_versions=2)
	assert removals and all(removed != (0, 0) for removed in removals)
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [3, 4]
	for version in versions:
		assert holds_user_link(job, version, rel, text)
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'
		assert stat.S_IMODE(os.stat(os.path.join(version.path, 'D/secret')).st_mode) == 0o600
	assert os.path.islink(os.path.join(job.monitor, rel))


def test_pruning_keeps_a_user_link_naming_a_missing_file(tmp_path, pruning_keeps):
	# repro test_r8_prune: removed as a dangling chain link
	job = fresh_job(tmp_path)
	text = f'../../{latest(job).name}/no/such/file'
	add_user_link(job, 'a/U', text)
	pruning_keeps(job, {'a/U': text})
	bump(job, 3, keep_n_versions=2)
	assert all(holds_user_link(job, version, 'a/U', text) for version in rv.list_versions(job.job_vault))


def test_a_user_link_naming_a_folder_never_wedges_pruning(tmp_path, pruning_keeps, monkeypatch):
	# repro test_r8_folder_target: the folder's rename onto the link failed at every prune, so retention stopped for good
	job = fresh_job(tmp_path)
	text = f'../../{latest(job).name}/D'
	add_user_link(job, 'a/U', text)
	renamed = []
	real_rename = os.rename
	def recording_rename(source, dest, *args, **kwargs):
		if os.path.isdir(source) and not os.path.islink(source):
			renamed.append((os.fspath(source), os.fspath(dest)))
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', recording_rename)
	pruning_keeps(job, {'a/U': text})
	bump(job, 6, keep_n_versions=2)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [6, 7]
	# the user's link copy itself is moved on as the versions go, but never a folder onto it
	assert not [pair for pair in renamed if pair[1].endswith('/a/U')]
	assert all(holds_user_link(job, version, 'a/U', text) for version in rv.list_versions(job.job_vault))


def wedged_job(tmp_path, monkeypatch):
	'''A job whose V1 links its unchanged a to V0's copy, which cannot be moved while failing[0] holds.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a': 'a', 'b': 'b'})
	run_backup(job)
	with open(os.path.join(job.monitor, 'b'), 'w') as f:
		f.write('b1')
	run_backup(job, OrderedDict([event_entry(job, 'b', 'modify')]))
	v0 = rv.list_versions(job.job_vault)[0].path
	failing = [True]
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if failing[0] and os.fspath(source).startswith(v0 + '/'):
			raise OSError(errno.EIO, os.strerror(errno.EIO), source)
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	return job, v0, failing


def test_a_wedged_prune_logs_one_failed_marker(tmp_path, monkeypatch, capsys):
	monkeypatch.setattr(rv, 'DISK_WAIT_REPEAT_SECONDS', 3600)
	monkeypatch.setattr(rv, 'PRUNE_ABORTED', {})
	job, v0, failing = wedged_job(tmp_path, monkeypatch)
	def prune_at(now):
		capsys.readouterr()
		removed = rv.prune_oldest(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor, clock=lambda: now)
		return removed, alerting_lines(capsys.readouterr().out)
	removed, markers = prune_at(0)
	assert removed == (0, 0) and len(markers) == 1
	assert f'reverberator job {job.job_name} FAILED: cannot remove {v0}' in markers[0]
	assert os.path.isdir(v0)
	# while it lasts: again only on the timer
	assert prune_at(10)[1] == [] and prune_at(3599)[1] == []
	assert len(prune_at(3600)[1]) == 1 and prune_at(7199)[1] == [] and len(prune_at(7200)[1]) == 1
	failing[0] = False
	removed, markers = prune_at(7300)
	assert removed != (0, 0) and markers == [] and not os.path.exists(v0)
	assert job.job_name not in rv.PRUNE_ABORTED


def test_a_link_that_cannot_be_looked_at_still_aborts_the_prune(tmp_path, monkeypatch, capsys):
	# an I/O error tells nothing: the link may be the version's only way to its copy
	monkeypatch.setattr(rv, 'PRUNE_ABORTED', {})
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a': 'a', 'b': 'b'})
	run_backup(job)
	with open(os.path.join(job.monitor, 'b'), 'w') as f:
		f.write('b1')
	run_backup(job, OrderedDict([event_entry(job, 'b', 'modify')]))
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault))
	real_hop = rv.vault_chain_hop
	def hop(job_vault, link_path, link_text, moves):
		if link_path == os.path.join(v1, 'a'):
			raise rv.UncheckedVaultLink(OSError(errno.EIO, os.strerror(errno.EIO)))
		return real_hop(job_vault, link_path, link_text, moves)
	monkeypatch.setattr(rv, 'vault_chain_hop', hop)
	capsys.readouterr()
	assert rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor) == (0, 0)
	assert len(alerting_lines(capsys.readouterr().out)) == 1
	assert os.path.isfile(os.path.join(v0, 'a')) and os.path.islink(os.path.join(v1, 'a'))


def moved_job(tmp_path):
	'''A job whose V1 moved a/x to deep/er/x: its chain link there names V0's a/x, which only V1's rows explain.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a/x': 'x', 'deep/er/keep': 'k', 'keep': 'k'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'a/x'), os.path.join(job.monitor, 'deep/er/x'))
	run_backup(job, OrderedDict([event_entry(job, 'deep/er/x', 'move', 'a/x')]))
	v0, v1 = rv.list_versions(job.job_vault)
	assert os.readlink(os.path.join(v1.path, 'deep/er/x')) == f'../../../{v0.name}/a/x'
	return job, v0, v1


def rewrite_text(version, change):
	'''Write version's change list again, its text changed by change().'''
	with open(version.change_list) as f:
		text = f.read()
	with open(version.change_list, 'w') as f:
		f.write(change(text))


def forget_record(job):
	manifest = rv.VaultManifest(job.job_vault)
	manifest.conn.execute("DELETE FROM meta WHERE key = 'monitor_paths'")
	manifest.close()


@pytest.mark.parametrize('why', ['empty', 'old_monitored_path'])
def test_pruning_keeps_moved_copies_when_rows_cannot_be_used(tmp_path, pruning_keeps, monkeypatch, why):
	job, v0, v1 = moved_job(tmp_path)
	if why == 'empty':
		# a crash right after the commit, before 0.44 wrote change lists whole
		rewrite_text(v1, lambda text: text.partition('\n')[0] + '\n')
	else:
		# the monitored path changed since, with no record of the old one, as before 0.44
		rewrite_text(v1, lambda text: text.replace(job.monitor, '/old/monitor'))
		forget_record(job)
	warnings = warnings_logged(monkeypatch)
	pruning_keeps(job, {})
	bump(job, 1, keep_n_versions=2)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [1, 2]
	held = os.path.join(v1.path, 'deep/er/x')
	assert not os.path.islink(held) and open(held).read() == 'x'
	assert len([warning for warning in warnings if v1.name in warning and 'text alone' in warning]) == 1


def test_away_and_back_with_a_failed_retarget_survives_pruning(tmp_path, monkeypatch):
	# mv x d/x; mv d e; mv e/x x, the last retarget failing: x sits at its own path with another depth's text, which
	# the kernel cannot follow (so pruning_keeps() would see it change), while the vault's rule still names V0's x
	job = create_job(str(tmp_path))
	seed_monitor(job, {'x': 'x', 'd/keep': 'k', 'keep': 'k'})
	run_backup(job)
	m = job.monitor
	os.rename(f'{m}/x', f'{m}/d/x')
	os.rename(f'{m}/d', f'{m}/e')
	os.rename(f'{m}/e/x', f'{m}/x')
	E = rv.ChangeEvent
	entries = rv.change_events_to_backup_entries(deque([E(1, False, 'move', f'{m}/d/x', f'{m}/x'), E(2, True, 'move', f'{m}/e', f'{m}/d'),
		E(3, False, 'move', f'{m}/x', f'{m}/e/x')]), m)
	real = rv.retarget_chain_link
	calls = []
	def flaky(job_vault, link_path, *args, **kwargs):
		calls.append(link_path)
		if link_path.endswith('/x') and len([c for c in calls if c.endswith('/x')]) == 2:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return real(job_vault, link_path, *args, **kwargs)
	monkeypatch.setattr(rv, 'retarget_chain_link', flaky)
	run_backup(job, entries)
	monkeypatch.setattr(rv, 'retarget_chain_link', real)
	v0, v1 = rv.list_versions(job.job_vault)
	assert os.readlink(os.path.join(v1.path, 'x')) == f'../../{v0.name}/x'
	bump(job, 1, keep_n_versions=2)
	held = os.path.join(v1.path, 'x')
	assert not os.path.exists(v0.path) and not os.path.islink(held) and open(held).read() == 'x'
	assert open(os.path.join(v1.path, 'e/keep')).read() == 'k' and open(os.path.join(v1.path, 'keep')).read() == 'k'


def test_pruning_forgets_the_moves_of_the_version_it_removes(tmp_path):
	job, v0, v1 = moved_job(tmp_path)
	bump(job, 1)
	rv.VERSION_MOVES.clear()
	versions = rv.list_versions(job.job_vault)
	for version in versions[1:]:
		moves = rv.VersionMoves.of_committed(job.job_vault, version.path, job.monitor)
		assert moves.usable
	assert {key[0] for key in rv.VERSION_MOVES} == {v1.path, versions[2].path}
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	# V1, now the oldest, was read for its links into V0; V0 was never read, and nothing of it is kept
	assert all(key[0] != v0.path for table in (rv.VERSION_MOVES, rv.VERSION_MOVES_WARNED) for key in table)
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert all(key[0] != v1.path for table in (rv.VERSION_MOVES, rv.VERSION_MOVES_WARNED) for key in table)


# --- the re-copy ---

def test_the_recopy_keeps_a_user_link_a_link(tmp_path, monkeypatch):
	# repro test_r8_recopy: the re-copy followed the link on to D/secret and copied its bytes in the link's place
	monkeypatch.setattr(rv, 'RECOPY_MIN_HOPS', 1)
	monkeypatch.setattr(rv, 'RECOPY_MAX_HOPS', 1)
	job = fresh_job(tmp_path)
	text = chain_text(latest(job).name, 'D/secret')
	add_user_link(job, 'a/U', text)
	bump(job, 2)
	v3 = latest(job)
	held = os.path.join(v3.path, 'a/U')
	assert os.path.islink(held) and os.readlink(held) == text
	assert rv.resolve_version_entry(job.job_vault, v3.path, 'a/U', job.monitor).kind == 'symlink'
	assert open(os.path.join(v3.path, 'D/secret')).read() == 'secret'
	assert os.path.islink(os.path.join(job.monitor, 'a/U'))


def test_chain_end_stops_at_a_user_link(tmp_path):
	job = fresh_job(tmp_path)
	text = chain_text(latest(job).name, 'D/secret')
	v1 = add_user_link(job, 'a/U', text)
	bump(job, 1)
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	end = rv.chain_end(job.job_vault, latest(job).path, 'a/U', moves)
	assert end.number == 1 and end.path == os.path.join(v1.path, 'a/U') and stat.S_ISLNK(end.st.st_mode)
	assert rv.learn_copy_version(job.job_vault, latest(job).path, 'a/U', moves) == 1
	record = rv.read_vault_record(latest(job).path, 'a/U', job.monitor)
	assert (record.kind, record.link) == ('l', text)


# --- history and restore ---

@pytest.mark.parametrize('form', ['one_up', 'right_depth'])
def test_history_and_restore_show_a_user_link_as_a_symlink(tmp_path, capsys, form):
	# repro test_r8_history_restore: history said "moved from D/secret", and restore gave its bytes
	job = fresh_job(tmp_path)
	v0 = latest(job)
	text = {'one_up': f'../{v0.name}/D/secret', 'right_depth': chain_text(v0.name, 'D/secret')}[form]
	add_user_link(job, 'a/U', text)
	bump(job, 1)
	write_rule(job)
	versions = rv.list_versions(job.job_vault)
	assert [rv.resolve_version_entry(job.job_vault, version.path, 'a/U', job.monitor).kind for version in versions[1:]] == ['symlink', 'symlink']
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'a/U'))
	assert (code, err) == (0, '')
	assert 'moved' not in out and 'D/secret' not in out and 'created' in out
	assert [(row.version.number, row.event) for row in rv.file_history(job.job_vault, versions, job.monitor, 'a/U')] == [(1, 'create')]
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'a/U'), str(dest), '--version', '2')
	assert code == 0, err
	assert os.path.islink(dest / 'U') and os.readlink(dest / 'U') == text
	dest2 = tmp_path / 'out2'
	dest2.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'a'), str(dest2), '--version', '2')
	assert code == 0, err
	assert os.path.islink(dest2 / 'a/U') and os.readlink(dest2 / 'a/U') == text


def test_restore_gives_a_user_link_naming_a_folder_as_the_link(tmp_path, capsys):
	# repro test_r8_folder_target: restore made a private folder in the link's place and failed each file in it
	job = fresh_job(tmp_path)
	text = f'../../{latest(job).name}/D'
	add_user_link(job, 'a/U', text)
	bump(job, 1)
	write_rule(job)
	versions = rv.list_versions(job.job_vault)
	assert rv.path_kind(job.job_vault, versions, job.monitor, 'a/U') == 'file'
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'a/U'))
	assert code == 0 and 'moved' not in out
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'a/U'), str(dest), '--version', '2')
	assert code == 0, err
	assert os.path.islink(dest / 'U') and os.readlink(dest / 'U') == text


def test_an_absolute_link_into_a_pruned_version_restores_as_the_link(tmp_path, capsys):
	# repro test_r8_history_restore: called dangling, and refused
	job = fresh_job(tmp_path)
	v0 = latest(job)
	bump(job, 2)
	text = os.path.join(job.job_vault, v0.name, 'D/secret')
	add_user_link(job, 'a/U', text, keep_n_versions=5)
	bump(job, 3, keep_n_versions=3)
	write_rule(job)
	newest = latest(job)
	assert rv.resolve_version_entry(job.job_vault, newest.path, 'a/U', job.monitor).kind == 'symlink'
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'a/U'), str(dest), '--version', str(newest.number))
	assert code == 0, err
	assert os.readlink(dest / 'U') == text


def test_a_copied_vault_in_the_tree_restores_as_links(tmp_path, capsys):
	# repro test_r8_history_restore: a copy of another vault, whose V2 links x to its V1, a name with this job's V1
	# number: called dangling, and refused
	job = fresh_job(tmp_path)
	bump(job, 1)
	foreign = os.path.join(job.monitor, 'old')
	os.makedirs(os.path.join(foreign, 'V1--2020-01-02_00-00-00_-0800'))
	os.makedirs(os.path.join(foreign, 'V2--2020-01-03_00-00-00_-0800'))
	with open(os.path.join(foreign, 'V1--2020-01-02_00-00-00_-0800', 'x'), 'w') as f:
		f.write('x')
	text = '../V1--2020-01-02_00-00-00_-0800/x'
	os.symlink(text, os.path.join(foreign, 'V2--2020-01-03_00-00-00_-0800', 'x'))
	run_backup(job, OrderedDict([event_entry(job, 'old/', 'create')]))
	bump(job, 1)
	write_rule(job)
	rel = 'old/V2--2020-01-03_00-00-00_-0800/x'
	for version in rv.list_versions(job.job_vault)[2:]:
		assert rv.resolve_version_entry(job.job_vault, version.path, rel, job.monitor).kind == 'symlink'
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'old'), str(dest), '--version', str(latest(job).number))
	assert code == 0, err
	assert os.readlink(dest / rel) == text


def test_a_chain_link_into_a_missing_version_is_dangling_only_by_the_rule(job):
	# a link whose named version is gone: dangling when the rule takes it for a chain link of its place, else a symlink
	write_committed_version(job, 0, {'keep': 'k'}, timestamp=T0, current=False)
	v2 = write_committed_version(job, 2, {'a/': None, 'b/': None, 'deep/er/': None}, timestamp=T1, rows=[('a/', 'create', None),
		('deep/er/x', 'move', 'b/x')])
	gone = 'V1--2021-01-01_12-00-00_-0800'
	os.symlink(f'../../{gone}/a/own', os.path.join(v2, 'a/own'))
	os.symlink(f'../../{gone}/D/secret', os.path.join(v2, 'a/U'))
	os.symlink(f'../{gone}/a/short', os.path.join(v2, 'a/short'))
	os.symlink(f'../../../{gone}/b/x', os.path.join(v2, 'deep/er/x'))
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	kinds = {rel: rv.resolve_version_entry(job.job_vault, v2, rel, job.monitor, moves).kind for rel in ('a/own', 'a/U', 'a/short', 'deep/er/x')}
	assert kinds == {'a/own': 'dangling', 'a/U': 'symlink', 'a/short': 'symlink', 'deep/er/x': 'dangling'}
	# with rows that cannot be used, only the text of the link's own place
	rv.VERSION_MOVES.clear()
	with open(rv.list_versions(job.job_vault)[-1].change_list, 'w') as f:
		f.write('path\tiso_time\tevent\tsource_path\n')
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	assert [rv.resolve_version_entry(job.job_vault, v2, rel, job.monitor, moves).kind for rel in ('a/own', 'deep/er/x')] == ['dangling', 'symlink']


def test_reading_follows_a_link_the_rows_cannot_tell_as_a_chain_link(job):
	# no row of V1 lands on deep/x: it may be a chain link under rows of another monitored path
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T0, current=False)
	v1 = write_committed_version(job, 1, {'deep/': None}, timestamp=T1, rows=[('other', 'modify', None)])
	os.symlink(f'../../V0--{T0}/a/x', os.path.join(v1, 'deep/x'))
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	resolved = rv.resolve_version_entry(job.job_vault, v1, 'deep/x', job.monitor, moves)
	assert (resolved.kind, resolved.path) == ('file', os.path.join(v0, 'a/x'))
	assert rv.chain_end(job.job_vault, v1, 'deep/x', moves).path == os.path.join(v0, 'a/x')
	assert rv.read_vault_record(v1, 'deep/x', job.monitor, moves).kind == 'f'
	_, hop_rel = rv.history_entry(job.job_vault, rv.list_versions(job.job_vault)[1], job.monitor, 'deep/x', moves)
	assert hop_rel == 'a/x'


# --- carried from Task 1's reviews ---

def record_pairs(job, pairs):
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	for number, path in pairs:
		manifest.note_monitor_path(number, path)
	manifest.commit()
	manifest.close()


def shifted_job(job):
	'''
	V1 written under M/proj, the job now at M, recorded: read under M, V1's rows land on its moved chain link
	(proj/b/x), so it would be refused; read under M/proj, its move takes proj/y there.
	'''
	old_monitor = os.path.join(job.monitor, 'proj')
	v0 = write_committed_version(job, 0, {'proj/y': 'y'}, timestamp=T0, current=False, rows=[], monitor=old_monitor)
	v1 = write_committed_version(job, 1, {'proj/b/': None}, timestamp=T1, rows=[('b/', 'attrib', None), ('proj/b/x', 'move', 'proj/y')], monitor=old_monitor)
	link = os.path.join(v1, 'proj/b/x')
	os.symlink(f'../../../V0--{T0}/proj/y', link)
	return old_monitor, v0, v1, link


def test_rows_count_as_unusable_when_the_record_cannot_be_read(job, monkeypatch):
	old_monitor, v0, v1, link = shifted_job(job)
	record_pairs(job, [(0, old_monitor), (2, job.monitor)])
	# never read under the current path, whose rows would refuse the link
	monkeypatch.setattr(rv, 'recorded_monitor_paths', lambda job_vault: None)
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert not moves.usable and 'record' in moves.why
	assert rv.vault_chain_hop(job.job_vault, link, os.readlink(link), moves) == os.path.join(v0, 'proj/y')
	assert rv.VaultMoves(job.job_vault, job.monitor).follow(link, os.readlink(link)) == os.path.join(v0, 'proj/y')


def test_a_locked_manifest_is_a_record_that_cannot_be_read(job):
	old_monitor, v0, v1, link = shifted_job(job)
	record_pairs(job, [(0, old_monitor), (2, job.monitor)])
	locker = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None)
	try:
		locker.execute('PRAGMA locking_mode = EXCLUSIVE')
		locker.execute('BEGIN EXCLUSIVE')
		locker.execute("UPDATE meta SET value = value WHERE key = 'schema'")
		assert rv.recorded_monitor_paths(job.job_vault) is None
		moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
		assert rv.vault_chain_hop(job.job_vault, link, os.readlink(link), moves) == os.path.join(v0, 'proj/y')
	finally:
		locker.close()


def test_the_daemon_reads_the_record_from_its_own_manifest(tmp_path, monkeypatch, pruning_keeps):
	# a read of its own may find the manifest locked by the daemon's own write: the record comes from its connection
	job, v0, v1 = moved_job(tmp_path)
	read = []
	monkeypatch.setattr(rv, 'recorded_monitor_paths', lambda job_vault: read.append(job_vault))
	rows_read = []
	real = rv.read_change_list_moves
	def counting(path, monitor):
		rows_read.append((os.path.basename(path).partition('--')[0], monitor))
		return real(path, monitor)
	monkeypatch.setattr(rv, 'read_change_list_moves', counting)
	rv.VERSION_MOVES.clear()
	monkeypatch.setattr(rv, 'RECOPY_MIN_HOPS', 1)
	monkeypatch.setattr(rv, 'RECOPY_MAX_HOPS', 1)
	pruning_keeps(job, {})
	bump(job, 2, keep_n_versions=2)
	assert read == []
	# pruning V0 read the rows of V1, whose moved link names V0's a/x, under the recorded path
	assert ('V1', job.monitor) in rows_read
	assert open(os.path.join(rv.list_versions(job.job_vault)[0].path, 'deep/er/x')).read() == 'x'


def test_a_version_below_the_first_recorded_path_is_read_under_it(job):
	# probe review3/pre044_then_change: V1 from before 0.44, then the path widened from M/proj to M
	old_monitor, v0, v1, link = shifted_job(job)
	record_pairs(job, [(2, old_monitor), (3, job.monitor)])
	assert rv.written_under(rv.recorded_monitor_paths(job.job_vault), 1, job.monitor) == old_monitor
	moves = rv.VersionMoves.of_committed(job.job_vault, v1, job.monitor)
	assert moves.moves == [('proj/y', 'proj/b/x', False)]
	assert rv.vault_chain_hop(job.job_vault, link, os.readlink(link), moves) == os.path.join(v0, 'proj/y')


def test_a_vault_started_over_drops_the_pairs_of_its_old_versions(tmp_path):
	# probe review3/record_restart: every version gone by hand, the manifest kept
	base = create_job(str(tmp_path))
	a, b = (base._replace(monitor=os.path.join(base.monitor, name)) for name in ('a', 'b'))
	seed_monitor(base, {'a/x': 'x', 'b/y': 'y'})
	run_backup(a)
	run_backup(b)
	assert rv.recorded_monitor_paths(base.job_vault) == [(0, a.monitor), (1, b.monitor)]
	for name in os.listdir(base.job_vault):
		if name.startswith('V'):
			path = os.path.join(base.job_vault, name)
			shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
	run_backup(b)
	assert rv.recorded_monitor_paths(base.job_vault) == [(0, b.monitor)]
	manifest = rv.VaultManifest(base.job_vault)
	try:
		manifest.begin()
		manifest.note_monitor_path(3, a.monitor)
		manifest.note_monitor_path(2, b.monitor)
		manifest.commit()
		assert manifest.monitor_paths == [(0, b.monitor)]
	finally:
		manifest.close()


def test_the_record_is_read_from_a_vault_path_that_is_not_utf8(tmp_path):
	job = create_job(str(tmp_path / 'v\udcff'))
	os.makedirs(job.job_vault)
	record_pairs(job, [(0, job.monitor)])
	assert rv.recorded_monitor_paths(job.job_vault) == [(0, job.monitor)]


def test_the_moves_kept_are_keyed_on_the_path_their_rows_were_read_under(job):
	# probe haiku3/t_cache: V1 written under A, the job now at B
	monitor_a, monitor_b = '/mon/a', '/mon/b'
	write_committed_version(job, 0, {}, timestamp=T0, current=False, rows=[], monitor=monitor_a)
	v1 = write_committed_version(job, 1, {}, timestamp=T1, rows=[('x', 'create', None), ('y', 'move', 'z')], monitor=monitor_a)
	first = rv.VersionMoves.of_committed(job.job_vault, v1, monitor_b, monitor_paths=[])
	assert not first.usable
	second = rv.VersionMoves.of_committed(job.job_vault, v1, monitor_b, monitor_paths=[(0, monitor_a)])
	assert second is not first and second.usable and second.moves == [('z', 'y', False)]
	assert rv.VersionMoves.of_committed(job.job_vault, v1, monitor_b, monitor_paths=[(0, monitor_a)]) is second


def test_a_change_list_is_written_in_a_private_folder(job, monkeypatch):
	# probe haiku3/t_race: a name planted in the job vault, before or while the list is written, never takes the rows
	seed_monitor(job, {'a': 'a'})
	run_backup(job)
	victim = os.path.join(job.root, 'victim')
	with open(victim, 'w') as f:
		f.write('ORIGINAL\n')
	written = []
	real_append = TSVZ.appendLinesTabularFile
	def planting_append(path, *args, **kwargs):
		folder = os.path.dirname(path)
		st = os.lstat(folder)
		written.append((folder, stat.S_ISDIR(st.st_mode), stat.S_IMODE(st.st_mode)))
		# the list's own name behind a dot in the job vault, planted as the rows go in
		planted = os.path.join(job.job_vault, '.' + os.path.basename(path).lstrip('.'))
		if not os.path.lexists(planted):
			os.symlink(victim, planted)
		return real_append(path, *args, **kwargs)
	monkeypatch.setattr(TSVZ, 'appendLinesTabularFile', planting_append)
	with open(os.path.join(job.monitor, 'a'), 'w') as f:
		f.write('a1')
	run_backup(job, OrderedDict([event_entry(job, 'a', 'modify')]))
	monkeypatch.undo()
	assert open(victim).read() == 'ORIGINAL\n'
	folder, is_dir, mode = written[-1]
	assert os.path.dirname(folder) == job.job_vault and os.path.basename(folder).startswith(rv.CHANGE_LIST_FOLDER_PREFIX)
	assert is_dir and mode == 0o700 and not os.path.lexists(folder)
	change_list = rv.list_versions(job.job_vault)[-1].change_list
	assert stat.S_ISREG(os.lstat(change_list).st_mode)
	assert [row.path for row in rv.iter_change_list(change_list)] == [os.path.join(job.monitor, 'a')]


def test_startup_removes_a_private_change_list_folder_a_crash_left(job):
	seed_monitor(job, {'a': 'a'})
	run_backup(job)
	left = os.path.join(job.job_vault, rv.CHANGE_LIST_FOLDER_PREFIX + 'abc123')
	os.makedirs(left)
	with open(os.path.join(left, f'V1--{T1}--8.00_KiB-2_ino{rv.CONTENT_FILE_EXTENSION_NAME}'), 'w') as f:
		f.write('path')
	# only a folder of this exact prefix, never through a link, nor another hidden name
	others = [os.path.join(job.job_vault, name) for name in ('.reverberator-change-lis', '.other')]
	for other in others:
		os.makedirs(other)
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	with open(os.path.join(outside, 'kept'), 'w') as f:
		f.write('k')
	linked = os.path.join(job.job_vault, rv.CHANGE_LIST_FOLDER_PREFIX + 'link')
	os.symlink(outside, linked)
	rv.remove_incomplete_vault_versions(job.job_vault)
	assert not os.path.lexists(left)
	assert all(os.path.isdir(other) for other in others)
	assert os.path.islink(linked) and os.path.exists(os.path.join(outside, 'kept'))
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0]


def test_a_pass_reads_each_change_list_once(job, monkeypatch):
	# probe review3/cache_thrash: two versions too big to be kept together, asked in turn
	monkeypatch.setattr(rv, 'VERSION_MOVES_ROWS_KEPT', 5)
	versions = []
	for n in (1, 2):
		rows = [(f'd{n}/f{i}', 'move' if i % 3 == 0 else 'modify', f'old{n}/f{i}' if i % 3 == 0 else None) for i in range(12)]
		versions.append(write_committed_version(job, n, {'x/': None}, timestamp=f'2021-01-0{n + 1}_00-00-00_-0800', rows=rows))
	reads = []
	real = rv.read_change_list_moves
	def counting(path, monitor):
		reads.append(os.path.basename(path)[:2])
		return real(path, monitor)
	monkeypatch.setattr(rv, 'read_change_list_moves', counting)
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	for step in range(6):
		moves.of(versions[step % 2]).takes('old/f', 'd/f')
	assert sorted(reads) == ['V1', 'V2']


@pytest.mark.parametrize('which', ['history', 'restore'])
def test_the_history_and_restore_commands_read_each_change_list_once(tmp_path, capsys, monkeypatch, which):
	# probe review3/cache_thrash, through the commands: two versions whose moved links are read for their rows, with
	# room kept for one version's rows at a time
	job, v0, v1 = moved_job(tmp_path)
	os.makedirs(os.path.join(job.monitor, 'b'))
	os.rename(os.path.join(job.monitor, 'deep/er/x'), os.path.join(job.monitor, 'b/x'))
	run_backup(job, OrderedDict([event_entry(job, 'b/', 'create'), event_entry(job, 'b/x', 'move', 'deep/er/x')]))
	bump(job, 1)
	write_rule(job)
	versions = rv.list_versions(job.job_vault)
	assert os.readlink(os.path.join(versions[2].path, 'b/x')) == f'../../{v1.name}/deep/er/x'
	monkeypatch.setattr(rv, 'VERSION_MOVES_ROWS_KEPT', 0)
	rv.VERSION_MOVES.clear()
	reads = []
	real = rv.read_change_list_moves
	def counting(path, monitor):
		reads.append(os.path.basename(path).partition('--')[0])
		return real(path, monitor)
	monkeypatch.setattr(rv, 'read_change_list_moves', counting)
	if which == 'history':
		code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'b/x'))
		assert 'moved' in out
	else:
		dest = tmp_path / 'out'
		dest.mkdir()
		code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'b/x'), str(dest), '--version', '3')
		assert open(dest / 'x').read() == 'x'
	assert code == 0, err
	assert sorted(reads) == ['V1', 'V2']
