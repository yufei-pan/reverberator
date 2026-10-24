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
import signal
import stat
import sys
import threading
import time
from collections import deque, OrderedDict
import pytest
import TSVZ
import xxhash
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, event_entry, write_rule, write_committed_version
from tests.test_log_text import alerting_lines
from tests import chain_ground_truth

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


def vault_salt(job):
	'''The vault's secret for the names pruning links copies under, made now when it has none, as the daemon's first prune makes it.'''
	return rv.vault_prune_salt(job.job_vault, job.job_name)


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


@pytest.mark.chain_ground_truth_allows('blind_spot', reason="a/U's text is exactly its own path's chain text: the documented blind spot")
def test_a_user_link_with_its_own_paths_chain_text_is_the_documented_blind_spot(tmp_path):
	# the one form no rows can tell: a link at a/U whose text is what the referenced copy writes for a/U itself. Its damage
	# stays on that path: pruning gives a/U its own older copy, and every other copy is kept
	job = fresh_job(tmp_path, {'a/U': 'old', 'D/secret': 'secret', 'keep': 'k'})
	v0 = latest(job)
	text = chain_text(v0.name, 'a/U')
	os.remove(os.path.join(job.monitor, 'a/U'))
	os.symlink(text, os.path.join(job.monitor, 'a/U'))
	run_backup(job, OrderedDict([event_entry(job, 'a/U', 'create')]))
	v1 = latest(job)
	held = os.path.join(v1.path, 'a/U')
	assert os.readlink(held) == text
	bump(job, 1, keep_n_versions=2)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [1, 2]
	assert not os.path.islink(held) and open(held).read() == 'old'
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret'
	assert os.readlink(os.path.join(job.monitor, 'a/U')) == text
	if chain_ground_truth.ENABLED:
		# the ground truth found it at the prune, and lets it pass by this test's marker alone
		assert ('prune', 'blind_spot', held, 'a/U', text) in chain_ground_truth.FOUND


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
	'''A job whose V1 links its unchanged a to V0's copy, which cannot be linked while failing[0] holds.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a': 'a', 'b': 'b'})
	run_backup(job)
	with open(os.path.join(job.monitor, 'b'), 'w') as f:
		f.write('b1')
	run_backup(job, OrderedDict([event_entry(job, 'b', 'modify')]))
	v0 = rv.list_versions(job.job_vault)[0].path
	failing = [True]
	real_link = os.link
	def link(source, dest, *args, **kwargs):
		if failing[0] and os.fspath(source).startswith(v0 + '/'):
			raise OSError(errno.EIO, os.strerror(errno.EIO), source)
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
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


@pytest.mark.parametrize('why', ['empty', 'old_monitored_path', 'unreadable', 'missing'])
def test_pruning_keeps_moved_copies_when_rows_cannot_be_used(tmp_path, pruning_keeps, monkeypatch, why):
	job, v0, v1 = moved_job(tmp_path)
	if why == 'empty':
		# a crash right after the commit, before 0.44 wrote change lists whole
		rewrite_text(v1, lambda text: text.partition('\n')[0] + '\n')
	elif why == 'old_monitored_path':
		# the monitored path changed since, with no record of the old one, as before 0.44
		rewrite_text(v1, lambda text: text.replace(job.monitor, '/old/monitor'))
		forget_record(job)
	elif why == 'unreadable':
		real_ended = rv.change_list_rows_ended
		def failing(change_list):
			if os.path.basename(change_list).startswith(v1.name):
				raise OSError(errno.EIO, os.strerror(errno.EIO), change_list)
			return real_ended(change_list)
		monkeypatch.setattr(rv, 'change_list_rows_ended', failing)
	warnings = warnings_logged(monkeypatch)
	if why == 'missing':
		# gone between the listing of the versions and the removal: Task 2b, it may be only out of the listing (a
		# mergerfs branch out), so the prune stops, keeping V0 whole, and makes none (a second once the first is back)
		info = rv.get_vault_info(job.job_vault).vault_info_dict
		os.remove(v1.change_list)
		assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
		assert os.path.isdir(v0.path) and list(info)[0] == 0
		assert not [name for name in os.listdir(job.job_vault) if name.startswith(v1.name + '--')]
		assert open(os.path.join(v1.path, 'deep/er/x')).read() == 'x'
		return
	else:
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
	# every kept version holds the link, and D/secret as it was
	for version in rv.list_versions(job.job_vault):
		if version.number:
			assert holds_user_link(job, version, 'a/U', text)
			assert rv.resolve_version_entry(job.job_vault, version.path, 'a/U', job.monitor).kind == 'symlink'
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'
		assert stat.S_IMODE(os.stat(os.path.join(version.path, 'D/secret')).st_mode) == 0o600
	assert os.path.islink(os.path.join(job.monitor, 'a/U'))


def test_chain_end_stops_at_a_user_link(tmp_path):
	job = fresh_job(tmp_path)
	text = chain_text(latest(job).name, 'D/secret')
	v1 = add_user_link(job, 'a/U', text)
	bump(job, 1)
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	end = rv.chain_end(job.job_vault, latest(job).path, 'a/U', moves)
	assert end.number == 1 and end.path == os.path.join(v1.path, 'a/U') and stat.S_ISLNK(end.st.st_mode)
	# a link of the chain form that the rows refuse is not learned from: the manifest's word would be the rows', and a
	# re-copy would copy the link where no rule follows it, were it a chain link the rows cannot account for
	assert rv.learn_copy_version(job.job_vault, latest(job).path, 'a/U', moves) is None
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
	# started over while the daemon was stopped: one that saw the versions would refuse an emptied vault (Task 2b)
	rv.VAULTS_WITH_VERSIONS.clear()
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


# --- pruning keeps the oldest version when the next one cannot be looked at in full ---

def during_prune(monkeypatch):
	'''A list whose first item is True while decrement_stepper() runs.'''
	inside = [False]
	real = rv.decrement_stepper
	def stepping(*args, **kwargs):
		inside[0] = True
		try:
			return real(*args, **kwargs)
		finally:
			inside[0] = False
	monkeypatch.setattr(rv, 'decrement_stepper', stepping)
	return inside


@pytest.mark.parametrize('fails', ['listing', 'lstat'])
def test_a_next_version_that_cannot_be_looked_at_keeps_the_oldest(tmp_path, monkeypatch, capsys, fails):
	# probe haiku4/probe_a2: a folder of V1 that cannot be listed while V0 was pruned lost the copies V1 linked under it
	monkeypatch.setattr(rv, 'PRUNE_ABORTED', {})
	job = fresh_job(tmp_path, {'D/secret': 'secret', 'sub/f1': 'payload', 'keep': 'k'})
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	assert os.path.islink(os.path.join(v1.path, 'sub/f1'))
	inside = during_prune(monkeypatch)
	real_scandir, real_lstat = os.scandir, os.lstat
	failing = os.path.join(v1.path, 'sub')
	def scandir(path, *args, **kwargs):
		if inside[0] and fails == 'listing' and os.fspath(path) == failing:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_scandir(path, *args, **kwargs)
	def lstat(path, *args, **kwargs):
		if inside[0] and fails == 'lstat' and os.fspath(path) == os.path.join(failing, 'f1'):
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'scandir', scandir)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	before = snapshot(job, [v1], {})
	capsys.readouterr()
	bump(job, 1, keep_n_versions=2)
	assert len([line for line in alerting_lines(capsys.readouterr().out) if 'cannot remove' in line]) == 1
	monkeypatch.undo()
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [0, 1, 2] and os.path.isdir(v0.path)
	assert snapshot(job, [v1], {}) == before
	assert open(os.path.join(versions[2].path, 'sub/f1')).read() == 'payload'


def test_a_copy_that_cannot_be_looked_at_after_a_failed_move_keeps_the_oldest(tmp_path, monkeypatch):
	# probe haiku4/probe_f_lexists: a failed rename whose lstat failed too was taken for a copy already gone, and the
	# chain link removed, the copy going with V0
	monkeypatch.setattr(rv, 'PRUNE_ABORTED', {})
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	target = os.path.join(v0.path, 'D/secret')
	inside = during_prune(monkeypatch)
	# a filesystem that cannot hard link: the copy is moved
	no_hard_links(monkeypatch, inside)
	failed = [False]
	real_rename, real_lstat = os.rename, os.lstat
	def rename(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == target and not failed[0]:
			failed[0] = True
			raise OSError(errno.EIO, os.strerror(errno.EIO), source)
		return real_rename(source, dest, *args, **kwargs)
	def lstat(path, *args, **kwargs):
		if inside[0] and failed[0] and os.fspath(path) == target:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert failed[0] and os.path.isfile(target)
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'
	assert os.readlink(os.path.join(v1.path, 'D/secret')) == chain_text(v0.name, 'D/secret')


def no_hard_links(monkeypatch, inside):
	'''os.link() failing with EXDEV while inside[0] holds, as between two branches that cannot hard link.'''
	real_link = os.link
	def link(source, dest, *args, **kwargs):
		if inside[0]:
			raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), source)
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)


def test_a_vault_path_with_glob_characters_removes_only_its_own_version(tmp_path):
	# probe haiku4/probe_g_glob: the removal globbed the version's path as typed, matching a sibling's folder
	root = tmp_path / 'r[x]*'
	job = fresh_job(root)
	bump(job, 1)
	v0 = rv.list_versions(job.job_vault)[0]
	# a sibling the pattern matches: [x] for x, then * for anything
	decoy_vault = os.path.join(tmp_path, 'rx-decoy', 'vault', 'job')
	decoy = os.path.join(decoy_vault, v0.name)
	shutil.copytree(v0.path, decoy, symlinks=True)
	shutil.copy(v0.change_list, decoy_vault)
	held = sorted(os.listdir(decoy_vault))
	bump(job, 1, keep_n_versions=2)
	assert not os.path.exists(v0.path)
	assert sorted(os.listdir(decoy_vault)) == held and open(os.path.join(decoy, 'D/secret')).read() == 'secret'


# --- the commands read the record of monitored paths once, waiting while the daemon writes the manifest ---

def lock_manifest(job):
	'''An exclusive lock on the job's manifest, as a big backup's spilled write holds it; close() releases it.'''
	locker = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None, check_same_thread=False)
	locker.execute('PRAGMA locking_mode = EXCLUSIVE')
	locker.execute('BEGIN EXCLUSIVE')
	locker.execute("UPDATE meta SET value = value WHERE key = 'schema'")
	return locker


@pytest.mark.parametrize('which', ['history', 'restore'])
def test_a_command_waits_for_the_manifest_and_then_judges_by_the_rows(tmp_path, capsys, which):
	# review4 probe_locked_commands: each version waited 1 s, then the link was judged by its text, silently
	job = fresh_job(tmp_path)
	text = chain_text(latest(job).name, 'D/secret')
	add_user_link(job, 'a/U', text)
	bump(job, 4)
	write_rule(job)
	locker = lock_manifest(job)
	releaser = threading.Timer(1.0, locker.close)
	releaser.start()
	try:
		start = time.monotonic()
		if which == 'history':
			code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'a/U'))
			assert 'moved' not in out and 'D/secret' not in out
		else:
			dest = tmp_path / 'out'
			dest.mkdir()
			code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'a/U'), str(dest), '--version', str(latest(job).number))
			assert os.readlink(dest / 'U') == text
		elapsed = time.monotonic() - start
	finally:
		releaser.join()
	assert code == 0, err
	assert err.count('Waiting for reverberator to finish writing') == 1 and 'cannot be read' not in err
	assert 1.0 <= elapsed < 3.0


def test_a_command_reads_the_record_once_and_only_when_rows_are_needed(tmp_path, capsys, monkeypatch):
	job = fresh_job(tmp_path)
	text = chain_text(latest(job).name, 'D/secret')
	add_user_link(job, 'a/U', text)
	bump(job, 4)
	write_rule(job)
	reads = []
	real = rv.read_recorded_monitor_paths
	monkeypatch.setattr(rv, 'read_recorded_monitor_paths', lambda *args, **kwargs: reads.append(args) or real(*args, **kwargs))
	# keep is copied in each version, D/secret linked at its own path: no rows needed
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'D/secret'))
	assert code == 0 and reads == []
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'a/U'))
	assert code == 0 and len(reads) == 1 and 'moved' not in out and err == ''


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the record of monitored paths is broken on purpose, so a/U goes by its text')
def test_a_command_says_once_when_the_record_cannot_be_read(tmp_path, capsys):
	job = fresh_job(tmp_path)
	add_user_link(job, 'a/U', chain_text(latest(job).name, 'D/secret'))
	bump(job, 2)
	write_rule(job)
	manifest = sqlite3.connect(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), isolation_level=None)
	manifest.execute("UPDATE meta SET value = 'not a record' WHERE key = 'monitor_paths'")
	manifest.close()
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'a/U'))
	assert code == 0
	assert err.count("the vault's record of monitored paths cannot be read; links are judged by their text") == 1
	assert 'Waiting' not in err


def test_a_history_pass_lets_go_of_the_versions_it_has_passed(tmp_path):
	job, v0, v1 = moved_job(tmp_path)
	bump(job, 3)
	versions = rv.list_versions(job.job_vault)
	moves = rv.VaultMoves(job.job_vault, job.monitor)
	rows = list(rv.path_history(job.job_vault, versions, job.monitor, 'deep/er/x', folder=False, moves=moves))
	assert [(row.version.number, row.event) for row in rows][-1:] == [(1, 'move')]
	# the walk is done with every version above the last two it resolved
	assert set(moves._held) <= {v0.path, v1.path}


@pytest.mark.parametrize('sig', [signal.SIGINT, signal.SIGTERM], ids=['SIGINT', 'SIGTERM'])
def test_a_folder_restore_waiting_for_the_manifest_stops_on_a_signal(tmp_path, capsys, monkeypatch, sig):
	# review5 probe_sigint_wait: the restore's handlers only set RESTORE_STOP, which the wait never looked at
	job, v0, v1 = moved_job(tmp_path)
	write_rule(job)
	handlers = {each: signal.getsignal(each) for each in rv.RESTORE_STOP_SIGNALS}
	real = rv.read_recorded_monitor_paths
	tries, signalled = [], []
	def read(job_vault, timeout=1):
		tries.append(timeout)
		if len(tries) == 3:
			signalled.append(time.monotonic())
			os.kill(os.getpid(), sig)
		assert len(tries) < 40, 'still waiting long after the signal'
		return real(job_vault, timeout=min(timeout, 0.2))
	monkeypatch.setattr(rv, 'read_recorded_monitor_paths', read)
	dest = tmp_path / 'out'
	dest.mkdir()
	locker = lock_manifest(job)
	try:
		code, out, err = command(tmp_path, capsys, 'restore', os.path.join(job.monitor, 'deep'), str(dest), '--version', '1')
	finally:
		locker.close()
	assert code == rv.EXIT_COMMAND_FAILED and 'Interrupted' in err, err
	assert signalled and time.monotonic() - signalled[0] < 2
	# each try waits a short while, so a stop is met soon
	assert all(timeout <= rv.RESTORE_WAIT_SECONDS for timeout in tries)
	assert {each: signal.getsignal(each) for each in handlers} == handlers


@pytest.mark.parametrize('how', ['link', 'move'])
def test_a_move_that_lands_then_reports_an_error_keeps_the_copy(tmp_path, monkeypatch, how):
	# haiku5 h1: the rename moved the copy, then raised; the copy, now where the link was, was removed as a dangling link
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	target = os.path.join(v0.path, 'D/secret')
	inside = during_prune(monkeypatch)
	if how == 'move':
		no_hard_links(monkeypatch, inside)
	# the rename of the hard link over the chain link, or of the copy itself
	source_of = {'link': rv.prune_link_path(os.path.join(v1.path, 'D/secret'), os.lstat(target), vault_salt(job)), 'move': target}[how]
	real_rename = os.rename
	fired = []
	def rename(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == source_of and not fired:
			real_rename(source, dest, *args, **kwargs)
			fired.append(dest)
			raise OSError(errno.EIO, os.strerror(errno.EIO), source)
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert fired and not os.path.exists(v0.path)
	assert not os.path.lexists(source_of)
	held = os.path.join(v1.path, 'D/secret')
	assert not os.path.islink(held) and open(held).read() == 'secret'
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'


def order_walk(monkeypatch, inside, v1, first):
	'''The walk of v1 while inside[0] holds, with the entries under first before the others.'''
	real_walk = rv.iter_tree_entries
	def walk(path, *args, **kwargs):
		entries = list(real_walk(path, *args, **kwargs))
		if inside[0] and os.path.abspath(path) == os.path.abspath(v1.path):
			entries.sort(key=lambda entry: not entry[1].startswith(first))
		yield from entries
	monkeypatch.setattr(rv, 'iter_tree_entries', walk)


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
@pytest.mark.parametrize('how', ['link', 'move'])
@pytest.mark.parametrize('first', ['D/', 'a/'])
def test_two_links_naming_one_copy_both_keep_its_bytes(tmp_path, monkeypatch, capsys, first, how):
	# haiku5 h7: by the text alone, a user's link and the chain link both name V0's D/secret; the first walked took the
	# copy, and the second, its target gone, was removed as dangling: V1 lost D/secret when the user's link came first
	job = fresh_job(tmp_path)
	v0 = latest(job)
	v1 = add_user_link(job, 'a/U', chain_text(v0.name, 'D/secret'))
	# rows that cannot be used: the user's link goes by its text
	rewrite_text(v1, lambda text: text.partition('\n')[0] + '\n')
	inside = during_prune(monkeypatch)
	if how == 'move':
		no_hard_links(monkeypatch, inside)
	order_walk(monkeypatch, inside, v1, first)
	capsys.readouterr()
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert not os.path.exists(v0.path)
	held = os.path.join(v1.path, 'D/secret')
	assert not os.path.islink(held) and open(held).read() == 'secret'
	assert stat.S_IMODE(os.lstat(held).st_mode) == 0o600
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'
	# the user's link gets the copy's bytes too: the ruled damage of the fallback, with no file lost
	assert open(os.path.join(v1.path, 'a/U')).read() == 'secret'
	# the move path knows it moved the copy for the other link; the link path cannot tell, as st_nlink can be stale
	assert ("a user's link that cannot be told from a chain link" in capsys.readouterr().out) == (how == 'move')


def test_a_link_that_cannot_be_read_aborts_the_prune_and_the_backup_goes_on(tmp_path, monkeypatch, capsys):
	# haiku5 h3: an OSError from readlink escaped decrement_stepper, after earlier renames, with no marker
	job = fresh_job(tmp_path, {'D/secret': 'secret', 'b/x': 'x', 'keep': 'k'})
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = during_prune(monkeypatch)
	real_readlink = os.readlink
	def readlink(path, *args, **kwargs):
		if inside[0] and os.fspath(path) == os.path.join(v1.path, 'D/secret'):
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_readlink(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'readlink', readlink)
	capsys.readouterr()
	bump(job, 1, keep_n_versions=2)
	assert len([line for line in alerting_lines(capsys.readouterr().out) if 'cannot remove' in line]) == 1
	monkeypatch.undo()
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2]
	assert os.readlink(os.path.join(v1.path, 'D/secret')) == chain_text(v0.name, 'D/secret')
	# a clean run prunes as ever
	bump(job, 1, keep_n_versions=2)
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [2, 3]
	for version in versions:
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret' and open(os.path.join(version.path, 'b/x')).read() == 'x'


@pytest.mark.parametrize('fails', ['listing', 'rm'])
def test_a_removal_that_does_not_happen_is_not_reported_done(tmp_path, monkeypatch, capsys, fails):
	# haiku5 h8: glob() passes over a listing error and rm's code was ignored, so the version was reported removed. Task
	# 2b: the job vault is listed for the version's own paths, and a listing error keeps it
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	if fails == 'listing':
		real_listdir = os.listdir
		def listdir(path='.'):
			if os.path.abspath(os.fspath(path)) == job.job_vault:
				raise eio(path)
			return real_listdir(path)
		monkeypatch.setattr(rv.os, 'listdir', listdir)
	else:
		real_run = rv.multiCMD.run_command
		monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: 1 if command[0] == 'rm' else real_run(command, *args, **kwargs))
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	capsys.readouterr()
	# V0 stays, but V1's link was replaced by V0's copy: the records went down by that link, as the vault did
	assert prune_dropping(info, job)[1] == 1
	assert len([line for line in alerting_lines(capsys.readouterr().out) if f'cannot remove {v0.path}' in line]) == 1
	assert list(info) == [0, 1] and os.path.isdir(v0.path) and job.job_name in rv.PRUNE_ABORTED
	monkeypatch.undo()
	# V1's links were made copies: nothing depends on V0 now, and the next removal goes through
	assert rv.decrement_stepper(info, job.job_name, job.monitor) != (0, 0)
	assert not os.path.exists(v0.path) and job.job_name not in rv.PRUNE_ABORTED
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret'


# --- materialised by hard link: the oldest version stays whole until it is removed ---

class Killed(BaseException):
	'''The daemon killed in the middle of a prune.'''


def two_links_job(tmp_path):
	'''V1 holding the chain link D/secret and a user's link a/U naming the same copy in V0, its rows unusable.'''
	job = fresh_job(tmp_path)
	v0 = latest(job)
	v1 = add_user_link(job, 'a/U', chain_text(v0.name, 'D/secret'))
	rewrite_text(v1, lambda text: text.partition('\n')[0] + '\n')
	return job, v0, v1


def holds_secret_everywhere(job, v1):
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret', version.name
		assert open(os.path.join(version.path, 'keep')).read() is not None
	assert open(os.path.join(v1.path, 'a/U')).read() == 'secret'


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
@pytest.mark.parametrize('fault', ['enospc', 'kill'])
@pytest.mark.parametrize('first', ['D/', 'a/'])
def test_a_failed_link_or_a_kill_between_two_links_loses_nothing(tmp_path, monkeypatch, first, fault):
	# haiku6 p1/p2, review6: the share worked within one run only; after a failed one, or a kill between the two links,
	# the next run found the copy gone from V0 and removed the second link as dangling
	job, v0, v1 = two_links_job(tmp_path)
	inside = during_prune(monkeypatch)
	order_walk(monkeypatch, inside, v1, first)
	target = os.path.join(v0.path, 'D/secret')
	real_link = os.link
	calls = []
	def link(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == target:
			calls.append(dest)
			if len(calls) == 2:
				if fault == 'kill':
					raise Killed()
				raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), dest)
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
	if fault == 'kill':
		with pytest.raises(Killed):
			bump(job, 1, keep_n_versions=2)
	else:
		bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert len(calls) == 2
	# V0 whole: its copy is still there, whatever was linked from it
	assert open(target).read() == 'secret'
	rv.VERSION_MOVES.clear()
	# a clean run, removing V0 alone
	bump(job, 1, keep_n_versions=len(rv.list_versions(job.job_vault)))
	assert not os.path.exists(v0.path) and os.path.isdir(v1.path)
	holds_secret_everywhere(job, v1)


@pytest.mark.parametrize('how', ['link', 'move'])
def test_a_stored_symlink_whose_rename_lands_then_fails_is_kept(tmp_path, monkeypatch, how):
	# haiku6 p5: the moved copy is a user's symlink kept in V1, so a landed rename was told by its type, and the link removed
	job = fresh_job(tmp_path)
	os.remove(os.path.join(job.monitor, 'D/secret'))
	os.symlink('elsewhere-target', os.path.join(job.monitor, 'D/secret'))
	run_backup(job, OrderedDict([event_entry(job, 'D/secret', 'modify')]))
	bump(job, 1)
	v0, v1, v2 = rv.list_versions(job.job_vault)
	assert os.readlink(os.path.join(v1.path, 'D/secret')) == 'elsewhere-target'
	assert os.readlink(os.path.join(v2.path, 'D/secret')) == chain_text(v1.name, 'D/secret')
	inside = during_prune(monkeypatch)
	if how == 'move':
		no_hard_links(monkeypatch, inside)
	sources = {rv.prune_link_path(os.path.join(v2.path, 'D/secret'), os.lstat(os.path.join(v1.path, 'D/secret')), vault_salt(job)), os.path.join(v1.path, 'D/secret')}
	real_rename = os.rename
	fired = []
	def rename(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) in sources and not fired:
			real_rename(source, dest, *args, **kwargs)
			fired.append(source)
			raise OSError(errno.EIO, os.strerror(errno.EIO), source)
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	versions = rv.list_versions(job.job_vault)
	assert fired and [version.number for version in versions] == [2, 3]
	held = os.path.join(v2.path, 'D/secret')
	assert os.path.islink(held) and os.readlink(held) == 'elsewhere-target'
	assert holds_user_link(job, versions[1], 'D/secret', 'elsewhere-target')


@pytest.mark.parametrize('first', ['D/secret', 'D/.'], ids=['link_first', 'temp_first'])
def test_a_temp_link_a_cut_off_run_left_is_reused(tmp_path, monkeypatch, first):
	# listed with the link first, the temp, once renamed over the link, was looked at as a link of its own, and gone
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	link = os.path.join(v1.path, 'D/secret')
	temp = rv.prune_link_path(link, os.lstat(os.path.join(v0.path, 'D/secret')), vault_salt(job))
	inside = during_prune(monkeypatch)
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == temp:
			raise Killed()
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	with pytest.raises(Killed):
		bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	# killed between the link and the rename: the temp is the copy's, V0 whole
	assert os.lstat(temp).st_ino == os.lstat(os.path.join(v0.path, 'D/secret')).st_ino and os.path.islink(link)
	# the links made: the one tried at the temp's name finds it there (review7 M6: tried first, looked at only then)
	linked = []
	real_link = os.link
	def linking(source, dest, *args, **kwargs):
		real_link(source, dest, *args, **kwargs)
		linked.append(dest)
	monkeypatch.setattr(rv.os, 'link', linking)
	order_walk(monkeypatch, during_prune(monkeypatch), v1, first)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert temp not in linked and not os.path.lexists(temp) and not os.path.exists(v0.path)
	assert not os.path.islink(link) and open(link).read() == 'secret'
	holds = [open(os.path.join(version.path, 'D/secret')).read() for version in rv.list_versions(job.job_vault)]
	assert holds == ['secret', 'secret']


def test_something_else_at_the_temp_name_keeps_the_oldest_and_is_left(tmp_path, capsys):
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	link = os.path.join(v1.path, 'D/secret')
	temp = rv.prune_link_path(link, os.lstat(os.path.join(v0.path, 'D/secret')), vault_salt(job))
	with open(temp, 'w') as f:
		f.write('not the copy')
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=vault_salt(job)) == (0, 0)
	assert len([line for line in alerting_lines(capsys.readouterr().out) if 'cannot remove' in line]) == 1
	assert open(temp).read() == 'not the copy' and os.path.islink(link) and open(os.path.join(v0.path, 'D/secret')).read() == 'secret'
	assert list(info) == [0, 1]


def v1_change_lists(job):
	return [name for name in os.listdir(job.job_vault) if name.startswith('V1--') and name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]


def test_an_abort_at_the_removal_makes_no_second_change_list(tmp_path, monkeypatch, capsys):
	# review6: the next version's list was renamed for its new size before the removal failed; the retry found no list
	# by the old name, and made another
	job = fresh_job(tmp_path, {'D/secret': 'secret' * 3000, 'keep': 'k'})
	bump(job, 1)
	real_run = rv.multiCMD.run_command
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: 1 if command[0] == 'rm' else real_run(command, *args, **kwargs))
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	prune_dropping(info, job)
	monkeypatch.undo()
	assert len(v1_change_lists(job)) == 1
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) != (0, 0)
	assert 'does not exist, creating a new one' not in capsys.readouterr().out
	assert len(v1_change_lists(job)) == 1 and list(info) == [1]


def test_a_removal_cut_short_is_finished_by_the_next_prune(tmp_path, monkeypatch):
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	real_run = rv.multiCMD.run_command
	def run(command, *args, **kwargs):
		if command[0] == 'rm':
			# the folder went, its change list did not
			shutil.rmtree(v0.path)
			return 1
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	prune_dropping(info, job)
	monkeypatch.undo()
	left = [os.path.join(job.job_vault, name) for name in os.listdir(job.job_vault) if name.startswith(v0.name)]
	assert list(info) == [0, 1] and not os.path.exists(v0.path) and len(left) == 1
	# the folder went, and with it all V0's record counted, which the records went down by at once
	assert (info[0].size, info[0].inode) == (0, 0)
	# the next prune removes what is left, freeing what V0's record still holds: nothing
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	assert not [name for name in os.listdir(job.job_vault) if name.startswith(v0.name)]
	assert list(info) == [1] and job.job_name not in rv.PRUNE_ABORTED
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret'


# --- fix round 4: an error never takes the oldest version for gone, and the books say what the versions take ---

def eio(path):
	return OSError(errno.EIO, os.strerror(errno.EIO), path)


def markers(capsys, v0):
	return [line for line in alerting_lines(capsys.readouterr().out) if f'cannot remove {v0.path}' in line]


def test_an_oldest_version_that_cannot_be_looked_at_is_kept(tmp_path, monkeypatch, capsys):
	# review7 P1: os.path.lexists() is False on any error, so one EIO looking at V0 took it for a removal cut short, and
	# all of it went with no link of V1 materialised
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = during_prune(monkeypatch)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if inside[0] and os.path.abspath(os.fspath(path)) == v0.path:
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	monkeypatch.undo()
	assert len(markers(capsys, v0)) == 1
	assert list(info) == [0, 1] and os.path.isdir(v0.path)
	assert os.path.islink(os.path.join(v1.path, 'D/secret')) and open(os.path.join(v1.path, 'D/secret')).read() == 'secret'


def test_an_error_from_statvfs_never_escapes_the_prune(tmp_path, monkeypatch):
	# review7: the statvfs() of V0 for its block size raised out of decrement_stepper, with V0 popped from the dict; the
	# books now go by st_blocks alone, so nothing asks for the block size
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = during_prune(monkeypatch)
	real_statvfs = os.statvfs
	def statvfs(path, *args, **kwargs):
		if inside[0]:
			raise eio(path)
		return real_statvfs(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'statvfs', statvfs)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor)
	monkeypatch.undo()
	assert list(info) == [1] and not os.path.exists(v0.path)
	held = os.path.join(v1.path, 'D/secret')
	assert not os.path.islink(held) and open(held).read() == 'secret'


def test_a_link_that_cannot_be_looked_at_before_its_copy_is_moved_keeps_the_oldest(tmp_path, monkeypatch, capsys):
	# review7 M3: the move's own look at the link, on a filesystem that cannot hard link, raised out of
	# decrement_stepper with no marker and V0 popped from the dict
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	link = os.path.join(v1.path, 'D/secret')
	inside = during_prune(monkeypatch)
	no_hard_links(monkeypatch, inside)
	real_lstat = os.lstat
	looks = []
	def lstat(path, *args, **kwargs):
		# the walk's look passes, the move's own fails
		if inside[0] and os.fspath(path) == link and sys._getframe(1).f_code.co_name == 'move_copy':
			looks.append(path)
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	monkeypatch.undo()
	assert looks and len(markers(capsys, v0)) == 1
	assert list(info) == [0, 1] and open(os.path.join(v0.path, 'D/secret')).read() == 'secret'
	assert os.readlink(link) == chain_text(v0.name, 'D/secret')


def test_a_change_list_that_cannot_be_looked_at_keeps_the_oldest(tmp_path, monkeypatch, capsys):
	# the next version's change list was looked for with os.path.lexists(): an error took it for missing, and a second
	# list was made beside it, which a restart counts too
	job = fresh_job(tmp_path, {'D/secret': 'secret' * 3000, 'keep': 'k'})
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = during_prune(monkeypatch)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if inside[0] and os.path.basename(os.fspath(path)) == os.path.basename(v1.change_list):
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	monkeypatch.undo()
	assert len(markers(capsys, v0)) == 1 and list(info) == [0, 1] and os.path.isdir(v0.path)
	assert v1_change_lists(job) == [os.path.basename(v1.change_list)]
	assert os.path.islink(os.path.join(v1.path, 'D/secret'))


def unsalted_prune_link_name(name):
	'''The name 1aa5f7b hard linked a copy under beside the link name, worked out from the name alone.'''
	return '.' + xxhash.xxh128(os.fsencode(name)).hexdigest() + rv.PARTIAL_COPY_SUFFIX


def names_from_the_copy(kind, copy_st):
	'''A name for the temp beside D/secret that someone who can see the copy's inode could work out.'''
	if kind == 'unsalted':
		return unsalted_prune_link_name('secret')
	if kind == 'device_and_inode':
		# 8b08fa8's
		return '.' + xxhash.xxh128(b'secret' + f'\0{copy_st.st_dev}:{copy_st.st_ino}'.encode()).hexdigest() + rv.PARTIAL_COPY_SUFFIX
	# what pruning falls back to without the vault's secret
	return os.path.basename(rv.prune_link_path('/v/V1--x/D/secret', copy_st, None))


@pytest.mark.parametrize('kind', ['unsalted', 'device_and_inode', 'inode_only'])
def test_a_monitored_file_at_a_name_worked_out_from_the_copy_never_stops_pruning(tmp_path, monkeypatch, capsys, kind):
	# review7 P3: any monitored user could stop pruning for good with a file of that name beside one of theirs; review8:
	# on mergerfs the inode alone has only the branch inode's entropy, and st_dev is another mount's number after a remount
	job = fresh_job(tmp_path)
	v0 = latest(job)
	user_file = 'D/' + names_from_the_copy(kind, os.lstat(os.path.join(v0.path, 'D/secret')))
	with open(os.path.join(job.monitor, user_file), 'w') as f:
		f.write('a user file')
	run_backup(job, OrderedDict([event_entry(job, user_file, 'create')]))
	v1 = latest(job)
	assert os.path.islink(os.path.join(v1.path, 'D/secret')) and not os.path.islink(os.path.join(v1.path, user_file))
	capsys.readouterr()
	bump(job, 1, keep_n_versions=2)
	assert not markers(capsys, v0)
	versions = rv.list_versions(job.job_vault)
	assert [version.number for version in versions] == [1, 2]
	held = os.path.join(v1.path, 'D/secret')
	assert not os.path.islink(held) and open(held).read() == 'secret'
	for version in versions:
		assert open(os.path.join(version.path, user_file)).read() == 'a user file'
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'


def test_the_temp_name_is_the_copys_own(tmp_path):
	link = os.path.join(str(tmp_path), 'V1--x', 'D', 'secret')
	first, second, other_device = (os.stat_result((stat.S_IFREG | 0o600, ino, dev, 1, 0, 0, 6, 0, 0, 0)) for ino, dev in ((11, 7), (12, 7), (11, 8)))
	salt, other_salt = bytes(range(16)), bytes(range(1, 17))
	path = rv.prune_link_path(link, first, salt)
	assert os.path.dirname(path) == os.path.dirname(link) and rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(path))
	assert path == rv.prune_link_path(link, first, salt) and path != rv.prune_link_path(link, second, salt)
	# the vault's own secret is in it, and no device number, which a FUSE mount gets anew at each mount
	assert path != rv.prune_link_path(link, first, other_salt) and path != rv.prune_link_path(link, first, None)
	assert path == rv.prune_link_path(link, other_device, salt)
	assert os.path.basename(path) not in {names_from_the_copy(kind, first) for kind in ('unsalted', 'device_and_inode', 'inode_only')}


def salt_file(job):
	return os.path.join(job.job_vault, rv.PRUNE_SALT_FILE_NAME)


def stored_row(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.conn.execute("SELECT value FROM meta WHERE key = 'prune_salt'").fetchone()
	finally:
		manifest.close()


def test_the_vaults_secret_is_made_once_and_kept(tmp_path):
	# review8: kept so a restart, or a remount, names a cut off run's temp the same; Task 2b: in a file of its own that
	# only root can read, as the manifest is 0644 and every user who can see a copy's inode could read the secret there
	job = fresh_job(tmp_path)
	bump(job, 1)
	assert not os.path.lexists(salt_file(job))
	bump(job, 1, keep_n_versions=2)
	st = os.lstat(salt_file(job))
	assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.geteuid() and st.st_size == 16
	secret = open(salt_file(job), 'rb').read()
	assert stored_row(job) is None
	bump(job, 1, keep_n_versions=2)
	assert vault_salt(job) == secret and open(salt_file(job), 'rb').read() == secret


def test_the_secret_file_is_0600_whatever_the_umask_and_synced_with_the_vault(tmp_path, monkeypatch):
	job = fresh_job(tmp_path)
	synced = []
	real_fsync_path = rv.fsync_path
	monkeypatch.setattr(rv, 'fsync_path', lambda path, folder=False: synced.append((path, folder)) or real_fsync_path(path, folder))
	old = os.umask(0o077 ^ 0o777)
	try:
		secret = vault_salt(job)
	finally:
		os.umask(old)
	assert len(secret) == 16 and stat.S_IMODE(os.lstat(salt_file(job)).st_mode) == 0o600
	assert (job.job_vault, True) in synced


def test_a_secret_an_older_daemon_kept_in_the_manifest_moves_to_the_file(tmp_path):
	job = fresh_job(tmp_path)
	bump(job, 1)
	old = bytes(range(16))
	manifest = rv.VaultManifest(job.job_vault)
	try:
		manifest.conn.execute("INSERT OR REPLACE INTO meta VALUES ('prune_salt', ?)", (old.hex(),))
	finally:
		manifest.close()
	# the temp a run cut off under that secret had made keeps its name
	v0, v1 = rv.list_versions(job.job_vault)
	copy_st = os.lstat(os.path.join(v0.path, 'D/secret'))
	temp = rv.prune_link_path(os.path.join(v1.path, 'D/secret'), copy_st, old)
	os.link(os.path.join(v0.path, 'D/secret'), temp)
	bump(job, 1, keep_n_versions=2)
	assert open(salt_file(job), 'rb').read() == old and stored_row(job) is None
	# zeroed where it was, not left on a freed page of the manifest, which every user can read
	assert old.hex().encode() not in open(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME), 'rb').read()
	assert numbers(job) == [1, 2] and not os.path.lexists(temp)
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret' and not os.path.islink(os.path.join(v1.path, 'D/secret'))


def bad_secret_files():
	def symlink(path):
		other = path + '.elsewhere'
		with open(other, 'wb') as f:
			f.write(bytes(16))
		os.chmod(other, 0o600)
		os.symlink(other, path)
	def mode(path):
		with open(path, 'wb') as f:
			f.write(bytes(16))
		os.chmod(path, 0o644)
	def short(path):
		with open(path, 'wb') as f:
			f.write(bytes(15))
		os.chmod(path, 0o600)
	def long(path):
		with open(path, 'wb') as f:
			f.write(bytes(17))
		os.chmod(path, 0o600)
	def owner(path):
		with open(path, 'wb') as f:
			f.write(bytes(16))
		os.chmod(path, 0o600)
		os.chown(path, 65534, 65534)
	def folder(path):
		os.mkdir(path, 0o600)
	def fifo(path):
		os.mkfifo(path, 0o600)
	return {'symlink': symlink, 'mode_0644': mode, 'short': short, 'long': long, 'owner': owner, 'folder': folder, 'fifo': fifo}


def held_as(path):
	st = os.lstat(path)
	content = open(path, 'rb').read() if stat.S_ISREG(st.st_mode) else os.readlink(path) if stat.S_ISLNK(st.st_mode) else None
	return st.st_ino, st.st_mode, st.st_uid, content


@pytest.mark.parametrize('kind', list(bad_secret_files()))
def test_a_secret_file_that_fails_the_checks_is_left_and_pruning_names_by_the_inode(tmp_path, monkeypatch, kind):
	if kind == 'owner' and os.geteuid() != 0:
		pytest.skip('needs root to give the file another owner')
	job = fresh_job(tmp_path)
	bump(job, 1)
	bad_secret_files()[kind](salt_file(job))
	before = held_as(salt_file(job))
	warnings = warnings_logged(monkeypatch)
	v0, v1 = rv.list_versions(job.job_vault)
	copy_st = os.lstat(os.path.join(v0.path, 'D/secret'))
	linked = []
	real_link = os.link
	def link(source, dest, *args, **kwargs):
		linked.append(os.fspath(dest))
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert held_as(salt_file(job)) == before
	assert [warning for warning in warnings if rv.PRUNE_SALT_FILE_NAME in warning]
	assert rv.prune_link_path(os.path.join(v1.path, 'D/secret'), copy_st, None) in linked
	assert numbers(job) == [1, 2] and open(os.path.join(v1.path, 'D/secret')).read() == 'secret'


def test_a_secret_file_another_made_first_is_the_one_read(tmp_path, monkeypatch):
	job = fresh_job(tmp_path)
	theirs = bytes(range(100, 116))
	real_open = os.open
	def racing_open(path, flags, *args, **kwargs):
		if os.fspath(path) == salt_file(job) and flags & os.O_EXCL:
			fd = real_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
			os.write(fd, theirs)
			os.close(fd)
		return real_open(path, flags, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'open', racing_open)
	assert vault_salt(job) == theirs
	monkeypatch.undo()
	assert open(salt_file(job), 'rb').read() == theirs


def test_a_secret_file_that_cannot_be_written_is_not_left_half_made(tmp_path, monkeypatch, capsys):
	job = fresh_job(tmp_path)
	real_write = os.write
	def write(fd, data):
		if os.path.realpath(f'/proc/self/fd/{fd}') == salt_file(job):
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return real_write(fd, data)
	monkeypatch.setattr(rv.os, 'write', write)
	assert vault_salt(job) is None
	monkeypatch.undo()
	assert not os.path.lexists(salt_file(job))
	assert len(vault_salt(job)) == 16


def test_pruning_without_the_vaults_secret_names_by_the_inode_and_says_so_once(tmp_path, monkeypatch):
	job = fresh_job(tmp_path)
	bump(job, 3)
	warnings = warnings_logged(monkeypatch)
	for _ in range(2):
		info = rv.get_vault_info(job.job_vault).vault_info_dict
		rv.decrement_stepper(info, job.job_name, job.monitor)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [2, 3]
	assert len([warning for warning in warnings if 'secret' in warning]) == 1
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'


def test_a_filesystem_that_gives_enosys_for_a_hard_link_moves_the_copy(tmp_path, monkeypatch):
	# sshfs without its hard link extension, and rclone, answer link() with ENOSYS
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = during_prune(monkeypatch)
	real_link, real_rename = os.link, os.rename
	moved = []
	def link(source, dest, *args, **kwargs):
		if inside[0]:
			raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS), source)
		return real_link(source, dest, *args, **kwargs)
	def rename(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == os.path.join(v0.path, 'D/secret'):
			moved.append(dest)
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
	monkeypatch.setattr(rv.os, 'rename', rename)
	bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	assert moved == [os.path.join(v1.path, 'D/secret')] and not os.path.exists(v0.path)
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret'


# a rel whose chain link is too long to sit in its inode, so the link takes a block of its own
LONG = 'a_folder_with_a_long_enough_name/and_a_file_name_long_enough_too.txt'


def books_job(tmp_path, tree=None):
	'''
	V0, V1 and V2 of a job whose V1 links keep, D/secret (a link short enough to sit in its inode), LONG and b/x to
	V0's copies, and copies b/y, which it modified.
	'''
	job = fresh_job(tmp_path, {'D/secret': 'secret' * 3000, 'b/x': 'x' * 20000, 'b/y': 'y', LONG: 'z' * 5000, 'keep': 'k'} if tree is None else tree)
	with open(os.path.join(job.monitor, 'b/y'), 'w') as f:
		f.write('y' * 50000)
	run_backup(job, OrderedDict([event_entry(job, 'b/y', 'modify')]))
	bump(job, 1)
	return job


def du_versions(job):
	'''What the job's version folders take, (bytes, inodes), each inode once: du of them all in one call.'''
	paths = [version.path for version in rv.list_versions(job.job_vault)]
	return rv.get_path_size(*paths), rv.get_path_inodes(*paths)


def recorded(job):
	'''What the change lists' names record, (bytes, inodes), as a restart sums them.'''
	versions = rv.list_versions(job.job_vault)
	return sum(version.size for version in versions), sum(version.inodes for version in versions)


def held(info):
	return sum(entry.size for entry in info.values()), sum(entry.inode for entry in info.values())


def prune_dropping(info, job):
	'''decrement_stepper() of info, which returns how far the sums of info's records went down, whatever came of it.'''
	before = held(info)
	removed = rv.decrement_stepper(info, job.job_name, job.monitor)
	after = held(info)
	assert removed == (before[0] - after[0], before[1] - after[1])
	return removed


def assert_books(job, info, caller):
	'''
	The change lists' names, the dict of the versions and the caller's sums each say what the version folders take, and
	each version folder has one change list: none went missing, none was made twice.
	'''
	names = os.listdir(job.job_vault)
	for folder in names:
		if rv.is_version_folder_name(folder) and os.path.isdir(os.path.join(job.job_vault, folder)):
			assert len([name for name in names if (rv.parse_change_list_name(name) or (None, None))[1] == folder]) == 1, folder
	real = du_versions(job)
	assert recorded(job) == real
	assert held(info) == real
	assert tuple(caller) == real


def reads_right(job):
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'secret' * 3000, version.name
		assert open(os.path.join(version.path, 'b/x')).read() == 'x' * 20000, version.name
		assert open(os.path.join(version.path, LONG)).read() == 'z' * 5000, version.name
		# modified in V1
		assert open(os.path.join(version.path, 'b/y')).read() == ('y' if version.number == 0 else 'y' * 50000), version.name


class StaleLinkCount:
	'''An lstat() result with st_nlink 1, as mergerfs's attribute cache (cache.attr=1) shows for a second after a link.'''
	st_nlink = 1

	def __init__(self, st):
		self._st = st

	def __getattr__(self, name):
		return getattr(self._st, name)


@pytest.mark.parametrize('case', ['clean', 'stale_link_count', 'abort', 'kill', 'cut_short'])
def test_the_books_say_what_the_versions_take(tmp_path, monkeypatch, case):
	# review7 P2, P4, P7, M4, M5, haiku7 p6: the sizes the change lists record, which a restart sums, and the caller's
	# vault_size went by st_nlink, counted the removed version's change list, booked a link as a whole block, were
	# measured again by du after an abort, each version counting the copies they then share, and were never written
	# when a removal was cut short
	job = books_job(tmp_path)
	v0, v1, v2 = rv.list_versions(job.job_vault)
	assert os.lstat(os.path.join(v1.path, LONG)).st_blocks and not os.lstat(os.path.join(v1.path, 'D/secret')).st_blocks
	info = rv.get_vault_info(job.job_vault)
	caller = [info.vault_size, info.vault_inodes]
	assert_books(job, info.vault_info_dict, caller)
	def prune():
		freed = rv.decrement_stepper(info.vault_info_dict, job.job_name, job.monitor)
		caller[0] -= freed[0]
		caller[1] -= freed[1]
	inside = during_prune(monkeypatch)
	if case in ('clean', 'stale_link_count'):
		if case == 'stale_link_count':
			real_lstat = os.lstat
			monkeypatch.setattr(rv.os, 'lstat', lambda path, *args, **kwargs: StaleLinkCount(real_lstat(path, *args, **kwargs)) if inside[0] else real_lstat(path, *args, **kwargs))
		prune()
		monkeypatch.undo()
	elif case == 'abort':
		# every other link is materialised, then V0 kept
		real_link = os.link
		def link(source, dest, *args, **kwargs):
			if inside[0] and os.fspath(source) == os.path.join(v0.path, 'b/x'):
				raise eio(source)
			return real_link(source, dest, *args, **kwargs)
		monkeypatch.setattr(rv.os, 'link', link)
		prune()
		monkeypatch.undo()
		assert list(info.vault_info_dict) == [0, 1, 2] and os.path.isdir(v0.path)
		assert os.lstat(os.path.join(v1.path, LONG)).st_ino == os.lstat(os.path.join(v0.path, LONG)).st_ino
		assert_books(job, info.vault_info_dict, caller)
		reads_right(job)
		prune()
	elif case == 'kill':
		real_run = rv.multiCMD.run_command
		def run(command, *args, **kwargs):
			if command[0] == 'rm':
				raise Killed()
			return real_run(command, *args, **kwargs)
		monkeypatch.setattr(rv.multiCMD, 'run_command', run)
		with pytest.raises(Killed):
			prune()
		monkeypatch.undo()
		# a restart reads the names the books were written to before the removal
		info = rv.get_vault_info(job.job_vault)
		caller = [info.vault_size, info.vault_inodes]
		assert list(info.vault_info_dict) == [0, 1, 2]
		assert_books(job, info.vault_info_dict, caller)
		reads_right(job)
		prune()
	else:
		real_run = rv.multiCMD.run_command
		def run(command, *args, **kwargs):
			if command[0] == 'rm':
				# the folder went, its change list did not
				shutil.rmtree(v0.path)
				return 1
			return real_run(command, *args, **kwargs)
		monkeypatch.setattr(rv.multiCMD, 'run_command', run)
		prune()
		monkeypatch.undo()
		assert list(info.vault_info_dict) == [0, 1, 2] and not os.path.exists(v0.path)
		assert_books(job, info.vault_info_dict, caller)
		prune()
		assert not [name for name in os.listdir(job.job_vault) if name.startswith(v0.name)]
	assert list(info.vault_info_dict) == [1, 2] and not os.path.exists(v0.path)
	assert_books(job, info.vault_info_dict, caller)
	reads_right(job)


@pytest.mark.parametrize('restart', [True, False], ids=['restart', 'carried'])
def test_after_an_aborted_prune_the_next_backup_removes_no_version_the_limit_keeps(tmp_path, monkeypatch, restart):
	# review7 P2: the abort measured V0 and V1 again by du, each counting the copies they then shared, so a restart
	# summed those twice, and removed versions 0 to 2 although the vault fit its limit
	job = fresh_job(tmp_path, {'big': 'B' * 900_000, LONG: 'z', 'keep': 'k'})
	bump(job, 3)
	v0, v1 = rv.list_versions(job.job_vault)[:2]
	inside = during_prune(monkeypatch)
	real_link = os.link
	def link(source, dest, *args, **kwargs):
		if inside[0] and os.fspath(source) == os.path.join(v0.path, LONG):
			raise eio(source)
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
	def backup(text, **kwargs):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(text)
		options = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
		options.update(kwargs)
		info, manifest, committed = rv.do_backup(OrderedDict([event_entry(job, 'keep', 'modify')]), job_name=job.job_name,
			monitor_path=job.monitor, vault_path=job.vault, **options)
		manifest.close()
		assert committed
		return info
	# the prune aborts inside a backup, as the daemon runs it, and the backup goes on
	carried = backup('aborted', keep_n_versions=4)
	monkeypatch.undo()
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2, 3, 4]
	assert os.lstat(os.path.join(v1.path, 'big')).st_ino == os.lstat(os.path.join(v0.path, 'big')).st_ino
	real, books = du_versions(job), (recorded(job), (carried.vault_size, carried.vault_inodes))
	# the next backup, under a limit the vault fits with room to spare
	after = backup('next', backup_size_limit=str(real[0] + 300_000), **({} if restart else {'vaultInfo': carried}))
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2, 3, 4, 5]
	assert books == (real, real)
	assert (after.vault_size, after.vault_inodes) == du_versions(job) == recorded(job)


# --- fix round 5 ---

def numbers(job):
	return [version.number for version in rv.list_versions(job.job_vault)]


def keep_backup(job, text, **kwargs):
	'''One do_backup() of keep set to text, as the daemon runs it: (the VaultInfo it returns, which a next one carries).'''
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write(text)
	options = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	options.update(kwargs)
	info, manifest, committed = rv.do_backup(OrderedDict([event_entry(job, 'keep', 'modify')]), job_name=job.job_name,
		monitor_path=job.monitor, vault_path=job.vault, **options)
	manifest.close()
	assert committed
	return info


@pytest.mark.parametrize('carried', [True, False], ids=['carried', 'restart'])
def test_after_finishing_a_removal_cut_short_the_next_backup_keeps_n_versions(tmp_path, monkeypatch, carried):
	# review8 NB1: finishing frees what V0's record still holds, nothing once its folder went, and the loop took that
	# for no progress: with the vault info carried, as the daemon carries it, the next backup kept 5 of keep 3
	job = fresh_job(tmp_path)
	bump(job, 3)
	v0 = rv.list_versions(job.job_vault)[0]
	real_run = rv.multiCMD.run_command
	cut = []
	def run(command, *args, **kwargs):
		if command[0] == 'rm' and not cut:
			# the folder went, its change list did not
			cut.append(command)
			shutil.rmtree(v0.path)
			return 1
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	first = keep_backup(job, 'A', keep_n_versions=3)
	monkeypatch.undo()
	assert cut and numbers(job) == [1, 2, 3, 4] and list(first.vault_info_dict) == [0, 1, 2, 3, 4]
	after = keep_backup(job, 'B', keep_n_versions=3, **({'vaultInfo': first} if carried else {}))
	assert numbers(job) == [3, 4, 5] and list(after.vault_info_dict) == [3, 4, 5]
	assert (after.vault_size, after.vault_inodes) == du_versions(job) == recorded(job)


def big_two_links_job(tmp_path):
	'''two_links_job() with a copy of five blocks, and V2 after it, so a removal of V0 alone fits a limit V1's would not.'''
	job = fresh_job(tmp_path, {'D/secret': 'S' * 20000, 'keep': 'k'})
	v0 = latest(job)
	v1 = add_user_link(job, 'a/U', chain_text(v0.name, 'D/secret'))
	rewrite_text(v1, lambda text: text.partition('\n')[0] + '\n')
	bump(job, 1)
	return job, v0, v1


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
def test_two_links_naming_one_copy_book_it_once(tmp_path):
	# review8 NB2, haiku8 p1: both links took the copy into V1's record, so the prune returned less than nothing
	job, v0, v1 = big_two_links_job(tmp_path)
	info = rv.get_vault_info(job.job_vault)
	caller = [info.vault_size, info.vault_inodes]
	freed = prune_dropping(info.vault_info_dict, job)
	caller = [caller[0] - freed[0], caller[1] - freed[1]]
	assert freed[0] >= 0 and freed[1] >= 0
	assert os.lstat(os.path.join(v1.path, 'D/secret')).st_ino == os.lstat(os.path.join(v1.path, 'a/U')).st_ino
	assert_books(job, info.vault_info_dict, caller)


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
def test_two_links_naming_one_copy_remove_no_version_the_limit_keeps(tmp_path):
	# haiku8 p1: the prune's return took vault_size up by the copy, and the loop removed V1 too although the vault fit
	job, v0, v1 = big_two_links_job(tmp_path)
	v2 = latest(job)
	# what the vault takes without V0: V1 and V2, V1's links into V0 replaced by the copies they name, one of them twice
	links = sum(os.lstat(os.path.join(v1.path, rel)).st_blocks * 512 for rel in ('D/secret', 'a/U', 'keep'))
	copies = sum(os.lstat(os.path.join(v0.path, rel)).st_blocks * 512 for rel in ('D/secret', 'keep'))
	without_v0 = rv.get_path_size(v1.path, v2.path) - links + copies
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('next')
	entries = OrderedDict([event_entry(job, 'keep', 'modify')])
	estimate = rv.get_backup_size_inode(backup_entries=entries, only_sync_attributes=True, last_vault_version_path=latest(job).path,
		monitor_path=job.monitor, skip_list=None)[0]
	info, manifest, committed = rv.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit=str(without_v0 + estimate))
	manifest.close()
	assert committed and numbers(job) == [1, 2, 3]
	assert (info.vault_size, info.vault_inodes) == du_versions(job) == recorded(job)


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
def test_a_prune_never_gives_back_less_than_nothing(tmp_path, monkeypatch):
	# across runs a copy two links name can still be booked twice (an abort, then the rerun's link): what the prune
	# returns stays at nothing or more, so vault_size never rises from a prune
	job, v0, v1 = big_two_links_job(tmp_path)
	inside = during_prune(monkeypatch)
	order_walk(monkeypatch, inside, v1, 'D/')
	real_link = os.link
	def link(source, dest, *args, **kwargs):
		if inside[0] and os.path.dirname(os.fspath(dest)) == os.path.join(v1.path, 'a'):
			raise eio(dest)
		return real_link(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'link', link)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	first = rv.decrement_stepper(info, job.job_name, job.monitor)
	monkeypatch.undo()
	assert list(info) == [0, 1, 2]
	second = rv.decrement_stepper(info, job.job_name, job.monitor)
	assert list(info) == [1, 2]
	assert min(first + second) >= 0
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'D/secret')).read() == 'S' * 20000, version.name
	assert open(os.path.join(v1.path, 'a/U')).read() == 'S' * 20000


def test_the_root_is_never_removed_and_stays_the_oldest(tmp_path):
	# with progress told by the oldest version changing, a skipped root must stay where it was
	info = OrderedDict([(0, rv.VaultEntry(0, '/', 0, 1, 1)), (1, rv.VaultEntry(1, str(tmp_path), 0, 1, 1))])
	assert rv.decrement_stepper(info, 'job', '/m') == (0, 0)
	assert list(info) == [0, 1]


def test_a_cut_off_runs_temp_is_reused_after_a_restart(tmp_path, monkeypatch):
	# review8: the secret the run cut off made is the one the restarted daemon reads, so the temp's name is the same
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	link = os.path.join(v1.path, 'D/secret')
	inside = during_prune(monkeypatch)
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if inside[0] and rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(os.fspath(source))):
			raise Killed()
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	with pytest.raises(Killed):
		bump(job, 1, keep_n_versions=2)
	monkeypatch.undo()
	# a restart: nothing kept in memory, the manifest opened again
	rv.VERSION_MOVES.clear()
	rv.REAL_VAULT_FOLDERS.clear()
	temp = rv.prune_link_path(link, os.lstat(os.path.join(v0.path, 'D/secret')), vault_salt(job))
	assert os.lstat(temp).st_ino == os.lstat(os.path.join(v0.path, 'D/secret')).st_ino
	bump(job, 1, keep_n_versions=2)
	assert not os.path.exists(v0.path) and not os.path.lexists(temp)
	assert not [name for name in os.listdir(os.path.join(v1.path, 'D')) if rv.PARTIAL_COPY_NAME.fullmatch(name)]
	assert not os.path.islink(link) and open(link).read() == 'secret'


def test_a_version_folder_that_cannot_be_looked_at_is_kept_by_the_scan(tmp_path, monkeypatch, capsys):
	# review8, also 0.43: os.path.exists() is False on any error, so one EIO looking at V0 when the vault was read
	# deleted its change list, and its folder went as an orphan, with every copy V1's links name
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	inside = [False]
	real_scan = rv.get_vault_info
	def scan(*args, **kwargs):
		inside[0] = True
		try:
			return real_scan(*args, **kwargs)
		finally:
			inside[0] = False
	monkeypatch.setattr(rv, 'get_vault_info', scan)
	real_stat, real_lstat = os.stat, os.lstat
	def failing(real):
		def look(path, *args, **kwargs):
			if inside[0] and os.path.abspath(os.fspath(path)) == v0.path:
				raise eio(path)
			return real(path, *args, **kwargs)
		return look
	monkeypatch.setattr(rv.os, 'stat', failing(real_stat))
	monkeypatch.setattr(rv.os, 'lstat', failing(real_lstat))
	capsys.readouterr()
	info = rv.get_vault_info(job.job_vault)
	monkeypatch.undo()
	# Task 2b: a folder listed with its change list is the list's, and is not looked at again; an error looking at an
	# entry of the listing fails the scan (tests/test_vault_scan.py)
	assert os.path.isdir(v0.path) and os.path.isfile(v0.change_list)
	assert list(info.vault_info_dict) == [0, 1] and info.vault_info_dict[0].size == v0.size
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret'


def during(monkeypatch, name):
	'''A list whose first item is True while rv.<name>() runs.'''
	inside = [False]
	real = getattr(rv, name)
	def running(*args, **kwargs):
		inside[0] = True
		try:
			return real(*args, **kwargs)
		finally:
			inside[0] = False
	monkeypatch.setattr(rv, name, running)
	return inside


@pytest.mark.parametrize('what', ['D', 'D/secret'], ids=['folder', 'file'])
def test_a_tracked_entry_that_cannot_be_looked_at_stays_tracked(tmp_path, monkeypatch, what):
	# review8: the referenced copy took a tracked folder (or file) that could not be looked at for missing, and dropped
	# its row: the new version lacked it
	job = fresh_job(tmp_path)
	v0 = latest(job)
	inside = during(monkeypatch, 'do_referenced_copy')
	real_lstat = os.lstat
	failing = os.path.join(v0.path, what)
	def lstat(path, *args, **kwargs):
		if inside[0] and os.fspath(path).rstrip('/') == failing:
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	bump(job, 1)
	monkeypatch.undo()
	v1 = latest(job)
	assert v1.number == 1 and os.path.isdir(os.path.join(v1.path, 'D'))
	assert os.readlink(os.path.join(v1.path, 'D/secret')) == chain_text(v0.name, 'D/secret')
	assert open(os.path.join(v1.path, 'D/secret')).read() == 'secret'
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert 'D/' in manifest.folders and 'D/secret' in manifest.files
	finally:
		manifest.close()


def test_a_prune_makes_no_change_list_for_the_next_version(tmp_path, monkeypatch):
	# review8 had the list made for a next version without one written whole; Task 2b: none is made, as the next
	# version's list may be only out of the listing, and the prune stops
	job = fresh_job(tmp_path)
	bump(job, 1)
	v0, v1 = rv.list_versions(job.job_vault)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	os.remove(v1.change_list)
	written = []
	real_write = rv.write_change_list
	monkeypatch.setattr(rv, 'write_change_list', lambda name, rows: written.append((name, list(rows))) or real_write(name, rows))
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	assert written == [] and v1_change_lists(job) == [] and os.path.isdir(v0.path)


# --- Task 2b ---

def rows_out_of_step(tmp_path, rows):
	'''V0 holding a file a and c, its rows tracking rows (a/b under a, which V0 holds as a file), and an empty V1.'''
	vault = os.path.join(str(tmp_path), 'job')
	v0 = os.path.join(vault, f'V0--{T0}')
	v1 = os.path.join(vault, f'V1--{T1}')
	os.makedirs(v0)
	os.makedirs(v1)
	for name, text in (('a', 'a file where the rows say a folder'), ('c', 'c')):
		with open(os.path.join(v0, name), 'w') as f:
			f.write(text)
	manifest = rv.VaultManifest(vault)
	manifest.begin()
	for rel in rows:
		manifest.add(rel)
	manifest.commit(v0)
	return vault, v0, v1, manifest


@pytest.mark.parametrize('rows', [('a/b', 'c'), ('a/', 'a/b', 'c')], ids=['file_row', 'folder_and_file_rows'])
def test_a_row_below_a_file_is_missing_from_the_source(tmp_path, rows):
	# review9 p5, p6: lstat of a/b, below V0's file a, gives ENOTDIR, which counted as "cannot be looked at": the row was
	# kept, and the referenced copy either raised FileNotFoundError making its link (every backup failed), or left V1 a
	# dangling a/b
	vault, v0, v1, manifest = rows_out_of_step(tmp_path, rows)
	try:
		assert rv.do_referenced_copy(v0, v1, manifest, relative=True)
		assert 'a/b' not in manifest.files and 'c' in manifest.files
	finally:
		manifest.close()
	assert not os.path.lexists(os.path.join(v1, 'a', 'b'))
	assert open(os.path.join(v1, 'c')).read() == 'c'


def test_a_link_whose_target_lies_below_a_file_is_dropped_as_dangling(tmp_path, capsys):
	# review9 p6: V1's a/b links to V0's a/b, below V0's file a: the walk's lstat gave ENOTDIR and every prune of V0 aborted
	vault, v0, v1, manifest = rows_out_of_step(tmp_path, ('a/', 'a/b', 'c'))
	manifest.close()
	os.makedirs(os.path.join(v1, 'a'))
	os.symlink(chain_text(os.path.basename(v0), 'a/b'), os.path.join(v1, 'a', 'b'))
	os.symlink(chain_text(os.path.basename(v0), 'c'), os.path.join(v1, 'c'))
	for version in (v0, v1):
		rv.write_change_list(rv.change_list_path(version, 4096, 3), [])
	info = rv.get_vault_info(vault).vault_info_dict
	capsys.readouterr()
	rv.decrement_stepper(info, 'job', os.path.join(str(tmp_path), 'm'))
	assert alerting_lines(capsys.readouterr().out) == []
	assert list(info) == [1] and not os.path.exists(v0)
	assert not os.path.lexists(os.path.join(v1, 'a', 'b'))
	assert not os.path.islink(os.path.join(v1, 'c')) and open(os.path.join(v1, 'c')).read() == 'c'


def books_after_prune(job, info):
	'''decrement_stepper() of info as a backup's loop runs it: (what it freed, the caller's sums after it, and before).'''
	before = (info.vault_size, info.vault_inodes)
	freed = rv.decrement_stepper(info.vault_info_dict, job.job_name, job.monitor)
	return freed, (before[0] - freed[0], before[1] - freed[1]), before


@pytest.mark.chain_ground_truth_allows('unusable_rows', reason='the rows of V1 are cut to the header on purpose, so a/U goes by its text')
@pytest.mark.parametrize('first', ['D/', 'a/'])
@pytest.mark.parametrize('how', ['move', 'link_then_emlink'])
def test_two_links_naming_one_copy_keep_the_books_on_the_move_path_and_the_mixed_one(tmp_path, monkeypatch, how, first):
	# review9 p3: the records, the dict and du of the version folders agree, and the caller's sums do within the clamp,
	# which keeps a prune from raising them: on the move path the second link's own copy is new space, so the prune frees
	# nothing of the bytes there, and the caller's sum stays below what the vault takes by that copy until a restart
	job, v0, v1 = big_two_links_job(tmp_path)
	inside = during_prune(monkeypatch)
	order_walk(monkeypatch, inside, v1, first)
	target = os.path.join(v0.path, 'D/secret')
	if how == 'move':
		no_hard_links(monkeypatch, inside)
	else:
		real_link = os.link
		calls = []
		def link(source, dest, *args, **kwargs):
			if inside[0] and os.fspath(source) == target:
				calls.append(dest)
				if len(calls) == 2:
					raise OSError(errno.EMLINK, os.strerror(errno.EMLINK), dest)
			return real_link(source, dest, *args, **kwargs)
		monkeypatch.setattr(rv.os, 'link', link)
	info = rv.get_vault_info(job.job_vault)
	freed, caller, before = books_after_prune(job, info)
	monkeypatch.undo()
	assert list(info.vault_info_dict) == [1, 2]
	real = du_versions(job)
	assert recorded(job) == real and held(info.vault_info_dict) == real
	assert freed == (max(0, before[0] - real[0]), max(0, before[1] - real[1]))
	assert caller == (min(before[0], real[0]), min(before[1], real[1]))
	if how == 'link_then_emlink':
		assert caller == real
	for rel in ('D/secret', 'a/U'):
		assert open(os.path.join(v1.path, rel)).read() == 'S' * 20000
		assert not os.path.islink(os.path.join(v1.path, rel))


def test_a_secret_made_whole_is_used_when_only_the_vaults_sync_fails(tmp_path, monkeypatch):
	# review10: the file was made and synced, but a failed fsync of the job vault was reported as "cannot be made"
	job = fresh_job(tmp_path)
	real_fsync_path = rv.fsync_path
	def fsync_path(path, folder=False):
		if folder and os.path.abspath(path) == job.job_vault:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_fsync_path(path, folder)
	monkeypatch.setattr(rv, 'fsync_path', fsync_path)
	warnings = warnings_logged(monkeypatch)
	secret = vault_salt(job)
	monkeypatch.undo()
	assert secret is not None and len(secret) == 16 and open(salt_file(job), 'rb').read() == secret
	assert [warning for warning in warnings if os.strerror(errno.EIO) in warning]
	assert vault_salt(job) == secret


# --- the version being written: the replay's applied moves, and copy_version for the latest version ---

def record_of(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel)
	finally:
		manifest.close()


def full_comparisons_make_no_version(job, times=3):
	'''Whether times full comparisons, one after another, all find the tree as the vault holds it.'''
	for _ in range(times):
		before = latest(job).number
		run_backup(job)
		if latest(job).number != before:
			return False
	return True


def backup_with_events(job, events):
	'''A batch of the watcher's raw events, collapsed and verified as the backuper runs it; returns what the verification fixed.'''
	verified = []
	real = rv.do_reverb_backup
	def keeping(*args, **kwargs):
		kwargs['verified'] = verified
		return real(*args, **kwargs)
	rv.do_reverb_backup = keeping
	try:
		_, manifest, committed = rv.do_backup(rv.change_events_to_backup_entries(deque(events), job.monitor), job_name=job.job_name,
			monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True,
			keep_n_versions=0, backup_size_limit='0', touched=rv.touched_scopes(deque(events), job.monitor))
		manifest.close()
	finally:
		rv.do_reverb_backup = real
	assert committed is True
	return verified


def test_links_moved_in_this_batch_are_chain_links_for_its_readers(tmp_path):
	# a file and a folder moved to other depths in one batch, verified: the retarget, the move's metadata check and the
	# verification read the links the batch renamed by its own moves, the one whose retarget is running included, so each
	# reaches its copy by the kernel, nothing is copied again, and the next batch's attribute changes reach the copies
	job = fresh_job(tmp_path, {'x': 'payload', 'F/y': 'why', 'deep/er/keep': 'k', 'p/q/keep': 'k', 'keep': 'k'})
	v0 = latest(job)
	copies = {rel: os.lstat(os.path.join(v0.path, rel)) for rel in ('x', 'F/y')}
	m = job.monitor
	os.rename(os.path.join(m, 'x'), os.path.join(m, 'deep/er/x'))
	os.rename(os.path.join(m, 'F'), os.path.join(m, 'p/q/F'))
	fixed = backup_with_events(job, [rv.ChangeEvent(1.0, False, 'move', os.path.join(m, 'deep/er/x'), os.path.join(m, 'x')),
		rv.ChangeEvent(2.0, True, 'move', os.path.join(m, 'p/q/F'), os.path.join(m, 'F'))])
	v1 = latest(job)
	assert v1.number == 1 and fixed == []
	assert [(os.path.relpath(row.path, m), row.event) for row in rv.iter_change_list(v1.change_list)] == [('deep/er/x', 'move'), ('p/q/F', 'move')]
	for rel, text, payload in (('deep/er/x', f'../../../{v0.name}/x', 'payload'), ('p/q/F/y', f'../../../../{v0.name}/F/y', 'why')):
		held = os.path.join(v1.path, rel)
		# re-targeted: the kernel follows it to the copy, which stayed where it was
		assert os.readlink(held) == text and open(held).read() == payload
		record = record_of(job, rel)
		assert (record.kind, record.link) == ('f', None) and record.hash == rv.hash_file(held, len(payload))
	assert {rel: os.lstat(os.path.join(v0.path, rel)) for rel in copies} == copies
	# the next batch's attribute changes go down the moved links to the copies, as the attribute sync has it
	for rel in ('deep/er/x', 'p/q/F/y'):
		os.chmod(os.path.join(m, rel), 0o640)
	run_backup(job, OrderedDict([event_entry(job, 'deep/er/x', 'attrib'), event_entry(job, 'p/q/F/y', 'attrib')]))
	for rel in ('x', 'F/y'):
		st = os.lstat(os.path.join(v0.path, rel))
		assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_ino == copies[rel].st_ino
	assert full_comparisons_make_no_version(job)


@pytest.mark.parametrize('end', ['user_link', 'referenced'])
def test_an_attribute_sync_of_a_users_link_lands_on_its_own_copy_and_records_the_link(tmp_path, end):
	# repro test_r8_sync_attributes: the sync wrote the link's owner and times onto the entry its text names, in an older
	# version; and the backup recorded the link as that entry, so the next comparison copied it again
	if end == 'user_link':
		job = fresh_job(tmp_path)
		os.symlink('elsewhere', os.path.join(job.monitor, 'D/L'))
		run_backup(job, OrderedDict([event_entry(job, 'D/L', 'create')]))
		target_rel = 'D/L'
	else:
		job = create_job(str(tmp_path))
		seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
		run_backup(job, keep_one_complete_backup=False)
		target_rel = 'D/secret'
	before = latest(job)
	target = os.path.join(before.path, target_rel)
	target_before = os.lstat(target)
	text = f'../../{before.name}/{target_rel}'
	v_link = add_user_link(job, 'a/U', text)
	record = record_of(job, 'a/U')
	assert (record.kind, record.link) == ('l', text)
	own = os.path.join(v_link.path, 'a/U')
	monitored = os.path.join(job.monitor, 'a/U')
	os.lchown(monitored, 4242, 4242)
	os.utime(monitored, ns=(1_000_000_000, 1_000_000_000), follow_symlinks=False)
	run_backup(job, OrderedDict([event_entry(job, 'a/U', 'attrib')]))
	st = os.lstat(target)
	assert (st.st_uid, st.st_mtime_ns, os.readlink(target)) == (target_before.st_uid, target_before.st_mtime_ns, os.readlink(target))
	assert (os.lstat(own).st_uid, os.lstat(own).st_mtime_ns, os.readlink(own)) == (4242, 1_000_000_000, text)
	record = record_of(job, 'a/U')
	assert (record.kind, record.link, record.uid) == ('l', text, 4242)
	assert full_comparisons_make_no_version(job)


@pytest.mark.parametrize('form', ['one_up', 'right_depth', 'absolute'])
def test_a_users_link_is_recorded_as_a_link_and_not_copied_again(tmp_path, form):
	# repro test_r8_manifest: the backup recorded the link as the file its text names, so a comparison copied it again
	# (once for a relative link, every time for an absolute one)
	job = fresh_job(tmp_path)
	v0 = latest(job)
	text = {'one_up': f'../{v0.name}/D/secret', 'right_depth': f'../../{v0.name}/D/secret',
		'absolute': os.path.join(job.job_vault, v0.name, 'D/secret')}[form]
	add_user_link(job, 'a/U', text)
	record = record_of(job, 'a/U')
	assert (record.kind, record.link, record.size, record.hash) == ('l', text, None, None)
	assert full_comparisons_make_no_version(job, 4)
	assert (record_of(job, 'a/U').kind, record_of(job, 'a/U').link) == ('l', text)


def test_a_users_link_a_move_carries_keeps_its_text(tmp_path):
	# repro test_r8_retarget (crafted entries): the replay copied the user's link, then a move to another depth carried
	# the copy along, and the retarget rewrote its text as a chain link's
	job = fresh_job(tmp_path, {'D/secret': 'secret', 'keep': 'k', 'a/old': 'o', 'p/x': 'x'})
	v0 = latest(job)
	text = f'../../{v0.name}/D/secret'
	os.symlink(text, os.path.join(job.monitor, 'a/U'))
	run_backup(job, OrderedDict([event_entry(job, 'a/U', 'create'), event_entry(job, 'p/q/', 'move', 'a/')]))
	v1 = latest(job)
	assert os.readlink(os.path.join(v1.path, 'p/q/U')) == text
	# the chain link the move carried is re-targeted all the same
	assert open(os.path.join(v1.path, 'p/q/old')).read() == 'o'


def test_a_users_link_made_where_a_folder_moved_from_is_never_retargeted(tmp_path, monkeypatch):
	# repro test_r8_retarget: mv a p/q; mkdir a; ln -s TEXT a/U. The replay copies a/ with U, then moves a/ to p/q/,
	# carrying the fresh copy, whose text the retarget rewrote before the verification removed it
	job = fresh_job(tmp_path, {'D/secret': 'secret', 'keep': 'k', 'a/old': 'o', 'p/x': 'x'})
	v0 = latest(job)
	m = job.monitor
	os.rename(os.path.join(m, 'a'), os.path.join(m, 'p/q'))
	os.mkdir(os.path.join(m, 'a'))
	text = f'../../{v0.name}/D/secret'
	os.symlink(text, os.path.join(m, 'a/U'))
	real = rv.retarget_moved_links
	seen = []
	def spy(job_vault, moved_path, *args, **kwargs):
		before = {p: os.readlink(p) for p in [os.path.join(moved_path, 'U')] if os.path.islink(p)}
		count = real(job_vault, moved_path, *args, **kwargs)
		seen.append((before, {p: os.readlink(p) for p in before if os.path.islink(p)}))
		return count
	monkeypatch.setattr(rv, 'retarget_moved_links', spy)
	backup_with_events(job, [rv.ChangeEvent(1.0, True, 'move', os.path.join(m, 'p/q'), os.path.join(m, 'a')),
		rv.ChangeEvent(2.0, True, 'create', os.path.join(m, 'a'), None), rv.ChangeEvent(3.0, False, 'create', os.path.join(m, 'a/U'), None)])
	monkeypatch.undo()
	v1 = latest(job)
	assert seen and seen[0][0] and seen[0][1] == seen[0][0]
	assert os.readlink(os.path.join(v1.path, 'a/U')) == text and not os.path.lexists(os.path.join(v1.path, 'p/q/U'))
	assert open(os.path.join(v1.path, 'p/q/old')).read() == 'o'


def refused_move_job(tmp_path):
	'''
	A job whose V1 moved D/secret to E/secret, with V1's rows changed so they refuse the chain link the move made: its
	row is a create carrying the source, which renamed nothing. The manifest still says V0 holds the copy.
	'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'E/keep': 'k', 'keep': 'k'})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'D/secret'), os.path.join(job.monitor, 'E/secret'))
	run_backup(job, OrderedDict([event_entry(job, 'E/secret', 'move', 'D/secret')]))
	v0, v1 = rv.list_versions(job.job_vault)
	rewrite_text(v1, lambda text: text.replace('\0move\0', '\0create\0'))
	rv.VERSION_MOVES.clear()
	link = os.path.join(v1.path, 'E/secret')
	assert os.readlink(link) == f'../../{v0.name}/D/secret'
	assert rv.vault_chain_hop(job.job_vault, link, os.readlink(link), rv.VersionMoves.of_committed(job.job_vault, v1.path, job.monitor)) is None
	return job, v0, v1


def copy_version_of(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.copy_version(rel)
	finally:
		manifest.close()


@pytest.mark.chain_ground_truth_allows('refused_by_rows', rels=['E/secret'], reason='the rows of V1 are forged to refuse E/secret, which copy_version overrules')
@pytest.mark.parametrize('reader', ['comparison', 'sync', 'recopy', 'learned'])
def test_copy_version_is_authoritative_for_the_latest_version(tmp_path, monkeypatch, reader):
	# a row whose copy_version names an older version is followed down to it, by the links' text, whatever the rows of
	# the versions on the way say; a version learned from a chain is never one the rows refused a link on the way to
	job, v0, v1 = refused_move_job(tmp_path)
	copy = os.path.join(v0.path, 'D/secret')
	copy_st = os.lstat(copy)
	if reader == 'comparison':
		# read from the vault as the copy it is, so nothing is copied again
		assert full_comparisons_make_no_version(job)
		record = record_of(job, 'E/secret')
		assert (record.kind, record.hash) == ('f', rv.hash_file(copy, 6))
	elif reader == 'sync':
		os.chown(os.path.join(job.monitor, 'E/secret'), 4242, 4242)
		run_backup(job, OrderedDict([event_entry(job, 'E/secret', 'attrib')]))
		assert os.lstat(copy).st_uid == 4242 and os.lstat(copy).st_ino == copy_st.st_ino
		assert os.readlink(os.path.join(v1.path, 'E/secret')) == f'../../{v0.name}/D/secret'
	else:
		monkeypatch.setattr(rv, 'RECOPY_MIN_HOPS', 1)
		monkeypatch.setattr(rv, 'RECOPY_MAX_HOPS', 1)
		if reader == 'learned':
			manifest = rv.VaultManifest(job.job_vault)
			manifest.begin()
			manifest.set_copy_version(['E/secret'], None)
			manifest.commit()
			manifest.close()
		if reader == 'recopy':
			# V2 is the first version whose chain from V0 passes the limit of one link
			bump(job, 1)
			held = os.path.join(latest(job).path, 'E/secret')
			# the copy's bytes, never the link the rows refuse, which no rule would follow from V2
			assert not os.path.islink(held) and open(held).read() == 'secret'
			assert copy_version_of(job, 'E/secret') == 2
		else:
			# V3 would be the first to copy again a file whose copy V2 learned is in V1
			bump(job, 2)
			below, v3 = rv.list_versions(job.job_vault)[-2:]
			held = os.path.join(v3.path, 'E/secret')
			# not learned, so linked as ever: the chain still leads to the copy
			assert os.readlink(held) == chain_text(below.name, 'E/secret') and open(held).read() == 'secret'
			assert copy_version_of(job, 'E/secret') is None
	for version in rv.list_versions(job.job_vault):
		assert open(os.path.join(version.path, 'E/secret' if version.number else 'D/secret')).read() == 'secret'


def test_a_setuid_file_keeps_its_bits_through_an_attribute_sync(tmp_path):
	# chown after copystat cleared S_ISUID and S_ISGID, even for root: 0o6755 was stored as 0o755
	job = create_job(str(tmp_path))
	seed_monitor(job, {'bin/tool': 'x', 'keep': 'k'})
	tool = os.path.join(job.monitor, 'bin/tool')
	os.chmod(tool, 0o6755)
	run_backup(job)
	v0 = latest(job)
	assert stat.S_IMODE(os.lstat(os.path.join(v0.path, 'bin/tool')).st_mode) == 0o6755
	os.chown(tool, 4242, 4242)
	os.chmod(tool, 0o6755)
	run_backup(job, OrderedDict([event_entry(job, 'bin/tool', 'attrib')]))
	st = os.lstat(os.path.join(v0.path, 'bin/tool'))
	assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o6755, 4242, 4242)
	assert full_comparisons_make_no_version(job, 1)


def test_a_fresh_copy_of_a_setuid_file_keeps_its_bits(tmp_path, monkeypatch):
	# the re-copy makes a copy of its own, which the batch then moves: the move syncs the file's attributes onto it
	monkeypatch.setattr(rv, 'RECOPY_MIN_HOPS', 1)
	monkeypatch.setattr(rv, 'RECOPY_MAX_HOPS', 1)
	job = create_job(str(tmp_path))
	seed_monitor(job, {'bin/tool': 'x', 'keep': 'k'})
	tool = os.path.join(job.monitor, 'bin/tool')
	os.chmod(tool, 0o6755)
	run_backup(job)
	bump(job, 1)
	os.rename(tool, os.path.join(job.monitor, 'tool'))
	run_backup(job, OrderedDict([event_entry(job, 'tool', 'move', 'bin/tool')]))
	held = os.path.join(latest(job).path, 'tool')
	assert not os.path.islink(held) and stat.S_IMODE(os.lstat(held).st_mode) == 0o6755
	# and copy_file_meta() onto any copy
	plain = os.path.join(str(tmp_path), 'plain')
	shutil.copyfile(os.path.join(job.monitor, 'tool'), plain)
	assert rv.copy_file_meta(os.path.join(job.monitor, 'tool'), plain)
	assert stat.S_IMODE(os.lstat(plain).st_mode) == 0o6755
