'''
Round 20: history, restore, the picker and --accept on the walk (spec sections 4.2 and 4.4, plan S8). A version is told from the
one above it by the two walks landing on one inode and by the change list's rows, never by which way a link points. A restore
walks forward into what a folder forwards to. The vaults come from real batches through r_layout, but for the read edge cases no
batch makes (tests/vaults.py).

REVERB_CRASH_FULL=1 runs the cut test at every kill point; by default a stride of them.
'''
import contextlib
import fcntl
import io
import os
import shutil
import tempfile
import threading
import types
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import build_base, prepare, restore as restore_vault
from tests.crash_child import kill_run
from tests.harness import create_job, event_entry, run_backup, seed_monitor, write_committed_version, write_rule
from tests.vault_oracle import entry_view, read_view, snapshot_tree
from tests.vaults import FORWARD, Link, forward_chain, record_layout, version_name, write_version

T0 = '2021-01-01_00-00-00_-0800'
T1 = '2021-01-02_00-00-00_-0800'
T2 = '2021-01-03_00-00-00_-0800'
DEFAULT_KILL_POINTS = 16
PREPARED = {}
needs_root = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


@pytest.fixture
def r_job(tmp_path):
	job = create_job(str(tmp_path))
	write_rule(job)
	return job


@pytest.fixture
def vault(tmp_path):
	path = str(tmp_path / 'job')
	os.mkdir(path)
	return path


def write(job, rel, content):
	path = os.path.join(job.monitor, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w', encoding='utf-8') as f:
		f.write(content)


def backup(job, *entries, **kwargs):
	'''One backup of the entries, each (rel, event) or (rel, 'move', source rel).'''
	return run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries), **kwargs)


def change(job, rel, content, event='modify'):
	write(job, rel, content)
	backup(job, (rel, event))


def versions(job):
	return rv.list_versions(job.job_vault)


def hist(job, rel):
	return rv.file_history(job.job_vault, versions(job), job.monitor, rel)


def folder_hist(job, rel, **kwargs):
	return rv.folder_history(job.job_vault, versions(job), job.monitor, rel, **kwargs)


def events(rows):
	return [(row.version.number, row.event) for row in rows]


def command(job, *args):
	return rv.run_command([*args, '--rule', job.rule_path])


def restored_to(job, tmp_path, name, path, *extra):
	'''The exit code of a restore of path into a new folder called name, and that folder.'''
	out = tmp_path / name
	out.mkdir()
	return command(job, 'restore', path, str(out), *extra), str(out)


def lock_backup(job_name='job', state_dir=None):
	'''The job's backup lock held as a batch holds it: the fd.'''
	os.makedirs(state_dir or rv.state_dir_path(), exist_ok=True)
	fd = rv.open_job_lock(rv.job_lock_path(job_name, 'backup', state_dir))
	fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	return fd


def stacked_job(job):
	'''
	V0 to V3 of a tree with a folder inside a folder: d/x changes in V1, so V0's d is real and its d/sub forwards; top.txt changes in
	V2 and d/sub/deep/f in V3. What each version must hold, by the oracle's snapshot.
	'''
	seed_monitor(job, {'top.txt': 't0', 'other.txt': 'o', 'd/x': 'x0', 'd/sub/deep/f': 'f0', 'd/sub/g': 'g', 'empty/': None})
	os.chmod(os.path.join(job.monitor, 'd/sub'), 0o750)
	os.symlink('../g', os.path.join(job.monitor, 'd/sub/deep/up'))
	os.symlink('nowhere', os.path.join(job.monitor, 'lnk'))
	expected = {0: snapshot_tree(job.monitor)}
	run_backup(job)
	for number, rel, text in ((1, 'd/x', 'x1'), (2, 'top.txt', 't2'), (3, 'd/sub/deep/f', 'f3')):
		change(job, rel, text)
		expected[number] = snapshot_tree(job.monitor)
	return expected


# --- history ---

def test_history_lists_a_version_only_where_the_path_changed(r_job):
	stacked_job(r_job)
	assert events(hist(r_job, 'top.txt')) == [(2, 'modify'), (0, 'oldest')]
	assert events(hist(r_job, 'other.txt')) == [(0, 'oldest')]
	assert events(hist(r_job, 'd/sub/deep/f')) == [(3, 'modify'), (0, 'oldest')]
	assert events(hist(r_job, 'lnk')) == [(0, 'oldest')]
	assert [(row.version.number, row.size) for row in hist(r_job, 'top.txt')] == [(2, 2), (0, 2)]
	assert [row.version.number for row in folder_hist(r_job, 'd')] == [3, 1, 0]
	assert [row.version.number for row in folder_hist(r_job, 'd/sub')] == [3, 0]
	assert [row.version.number for row in folder_hist(r_job, 'empty')] == [0]
	assert [row.version.number for row in folder_hist(r_job, '')] == [3, 2, 1, 0]


def test_a_path_gone_and_made_again_shows_each_step(r_job):
	seed_monitor(r_job, {'a.txt': 'a', 'keep.txt': 'k'})
	run_backup(r_job)
	os.remove(os.path.join(r_job.monitor, 'a.txt'))
	backup(r_job, ('a.txt', 'delete'))
	change(r_job, 'keep.txt', 'k2')
	change(r_job, 'a.txt', 'b', 'create')
	change(r_job, 'keep.txt', 'k3')
	assert events(hist(r_job, 'a.txt')) == [(3, 'create'), (1, 'delete'), (0, 'oldest')]


def plain_vault_sharing_inodes(job):
	'''A migrated vault: V0 to V2 plain trees, a.txt one inode through all three, b.txt another copy in V2, no change rows for either.'''
	tops = [write_committed_version(job, number, {'a.txt': 'a', 'b.txt': 'b', 'd/in': 'i', 'other': str(number)}, timestamp=stamp, rows=[('other', 'modify', None)], current=number == 2)
		for number, stamp in enumerate((T0, T1, T2))]
	for top in tops[1:]:
		for rel in ('a.txt', 'd/in'):
			os.remove(os.path.join(top, rel))
			os.link(os.path.join(tops[0], rel), os.path.join(top, rel))
	os.remove(os.path.join(tops[1], 'b.txt'))
	os.link(os.path.join(tops[0], 'b.txt'), os.path.join(tops[1], 'b.txt'))
	record_layout(job.job_vault, 'r')


def test_history_after_a_migration_sees_shared_inodes_as_unchanged(r_job):
	plain_vault_sharing_inodes(r_job)
	assert events(hist(r_job, 'a.txt')) == [(0, 'oldest')]
	assert events(hist(r_job, 'd/in')) == [(0, 'oldest')]
	# two copies of one text are two inodes, and no row says why: it changed
	assert events(hist(r_job, 'b.txt')) == [(2, 'changed'), (0, 'oldest')]
	assert events(hist(r_job, 'other')) == [(2, 'modify'), (1, 'modify'), (0, 'oldest')]


def test_history_shows_moves_from_the_change_lists(r_job):
	seed_monitor(r_job, {'a.txt': 'a', 'd/in': 'i', 'keep.txt': 'k'})
	run_backup(r_job)
	os.rename(os.path.join(r_job.monitor, 'a.txt'), os.path.join(r_job.monitor, 'b.txt'))
	os.rename(os.path.join(r_job.monitor, 'd'), os.path.join(r_job.monitor, 'e'))
	backup(r_job, ('b.txt', 'move', 'a.txt'), ('e/', 'move', 'd/'))
	change(r_job, 'keep.txt', 'k2')
	rows = [(row.version.number, row.event, row.source) for row in hist(r_job, 'b.txt')]
	assert rows == [(1, 'move', os.path.join(r_job.monitor, 'a.txt'))]
	rows = [(row.version.number, row.event, row.source) for row in hist(r_job, 'a.txt')]
	assert rows == [(1, 'moved_away', os.path.join(r_job.monitor, 'b.txt')), (0, 'oldest', None)]
	rows = [(row.version.number, row.event, row.source) for row in hist(r_job, 'e/in')]
	assert rows == [(1, 'move', os.path.join(r_job.monitor, 'd/in'))]
	rows = [(row.version.number, row.event, row.source) for row in hist(r_job, 'd/in')]
	assert rows == [(1, 'moved_away', os.path.join(r_job.monitor, 'e/in')), (0, 'oldest', None)]


def test_a_change_list_renamed_mid_read_is_listed_again(r_job):
	stacked_job(r_job)
	listed = versions(r_job)
	want = events(rv.file_history(r_job.job_vault, listed, r_job.monitor, 'top.txt'))
	# a commit renames the previous version's list, as its size is known only then
	old = listed[2].change_list
	moved = os.path.join(os.path.dirname(old), f'{listed[2].name}--1.00_KiB-3_ino.modified_contents.nsv')
	assert rv.parse_change_list_name(os.path.basename(moved)) is not None
	os.rename(old, moved)
	assert events(rv.file_history(r_job.job_vault, listed, r_job.monitor, 'top.txt')) == want


def test_a_change_list_gone_for_good_is_an_error(r_job):
	stacked_job(r_job)
	listed = versions(r_job)
	os.remove(listed[2].change_list)
	with pytest.raises(FileNotFoundError):
		rv.file_history(r_job.job_vault, listed, r_job.monitor, 'top.txt')


def test_a_folder_history_counts_an_attribute_change_below_a_forwarded_folder(r_job):
	# under Only Sync Attributes a file's attributes are set on the shared inode with no record: the folder stays forwarded in the
	# version below, and only the change list tells
	seed_monitor(r_job, {'d/f': 'f', 'keep.txt': 'k'})
	run_backup(r_job)
	os.chmod(os.path.join(r_job.monitor, 'd/f'), 0o600)
	backup(r_job, ('d/f', 'attrib'))
	assert os.path.islink(os.path.join(versions(r_job)[0].path, 'd'))
	rows = folder_hist(r_job, 'd')
	assert events(rows) == [(1, 'changed'), (0, 'oldest')]
	assert rows[0].counts['attrib'] == 1
	assert events(hist(r_job, 'd/f')) == [(1, 'attrib'), (0, 'oldest')]


def test_the_history_command_on_a_vault_of_forward_links(r_job, capsys):
	stacked_job(r_job)
	capsys.readouterr()
	assert command(r_job, 'history', os.path.join(r_job.monitor, 'd/sub/deep/f')) == 0
	lines = capsys.readouterr().out.splitlines()
	assert [line.split()[0] for line in lines[1:]] == ['V3', 'V0']


# --- restore ---

@needs_root
def test_restore_a_file_from_every_version_gives_the_oracle_bytes_and_meta(tmp_path):
	job = create_job(str(tmp_path))
	expected = build_base(job)
	write_rule(job)
	restored = 0
	for number, want in expected.items():
		for index, (rel, view) in enumerate(sorted(want.items())):
			if view.kind in ('d', 'root'):
				continue
			code, out = restored_to(job, tmp_path, f'out{number}-{index}', os.path.join(job.monitor, rel), '--version', str(number))
			assert code == 0, rel
			assert entry_view(os.path.join(out, os.path.basename(rel))) == view, (number, rel)
			restored += 1
	assert restored > 50


def test_restore_a_folder_that_forwards_gives_a_real_tree(r_job, tmp_path):
	expected = stacked_job(r_job)
	top = versions(r_job)[0].path
	assert not os.path.islink(os.path.join(top, 'd')) and os.path.islink(os.path.join(top, 'd/sub'))
	for number in range(4):
		code, out = restored_to(r_job, tmp_path, f'out{number}', os.path.join(r_job.monitor, 'd'), '--version', str(number))
		assert code == 0
		got = snapshot_tree(os.path.join(out, 'd'))
		want = {rel[2:]: view for rel, view in expected[number].items() if rel.startswith('d/')}
		assert {rel: view for rel, view in got.items() if rel} == want, number
		assert got[''][2:] == expected[number]['d'][2:], number
		assert not any(view.kind == 'l' and view.data.startswith('../') and 'V' in view.data for view in got.values() if view.data != '../g')


@needs_root
def test_restore_whole_job_from_every_version_equals_its_view(tmp_path):
	job = create_job(str(tmp_path))
	expected = build_base(job)
	write_rule(job)
	for version in versions(job):
		code, out = restored_to(job, tmp_path, f'out{version.number}', job.monitor, '--version', str(version.number))
		assert code == 0
		got = snapshot_tree(os.path.join(out, os.path.basename(job.monitor)))
		assert got == expected[version.number], version.number
		assert got == read_view(job.job_vault, version.name), version.number


def test_restore_gives_a_users_link_as_a_link_at_any_age(r_job, tmp_path):
	stacked_job(r_job)
	for number in range(4):
		code, out = restored_to(r_job, tmp_path, f'one{number}', os.path.join(r_job.monitor, 'lnk'), '--version', str(number))
		assert code == 0
		assert os.readlink(os.path.join(out, 'lnk')) == 'nowhere'
		code, out = restored_to(r_job, tmp_path, f'whole{number}', os.path.join(r_job.monitor, 'd'), '--version', str(number))
		assert code == 0
		assert os.readlink(os.path.join(out, 'd/sub/deep/up')) == '../g'


def test_the_picker_lists_only_versions_that_differ(r_job):
	stacked_job(r_job)
	kept = versions(r_job)
	picks = lambda rel, kind: [row.version.number for row in rv.restore_candidates(r_job.job_vault, kept, r_job.monitor, rel, kind)]
	assert picks('top.txt', 'file') == [2, 0]
	assert picks('other.txt', 'file') == [0]
	assert picks('d/sub', 'folder') == [3, 0]
	assert picks('', 'folder') == [3, 2, 1, 0]
	shown = io.StringIO()
	class Terminal(io.StringIO):
		def isatty(self):
			return True
	candidates = rv.restore_candidates(r_job.job_vault, kept, r_job.monitor, 'other.txt', 'file')
	assert rv.choose_version(candidates, kept, lambda version: True, stdin=Terminal(''), stderr=shown).number == 0


def test_accept_reads_the_walk(r_job, tmp_path):
	expected = stacked_job(r_job)
	version = versions(r_job)[0]
	out = tmp_path / 'out'
	out.mkdir()
	target = str(out / 'd')
	# what a stopped restore leaves: its folders private, its marker at the top
	for rel in ('', 'sub', 'sub/deep'):
		os.makedirs(os.path.join(target, rel), mode=0o700, exist_ok=True)
	rv.write_restore_marker(target, 'job', 'd', version)
	assert command(r_job, 'restore', os.path.join(r_job.monitor, 'd'), str(out), '--version', '0', '--accept') == 0
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	got = snapshot_tree(target)
	for rel in ('sub', 'sub/deep'):
		assert got[rel] == expected[0][f'd/{rel}'], rel
	assert got[''][2:] == expected[0]['d'][2:]


def size_of(number, size):
	return rv.KeptVersion(number, f'/v/V{number}', f'V{number}', 0.0, size, 1, f'/v/V{number}.nsv')


@pytest.mark.parametrize('backward, free, chosen, outcome', [
	(False, 999, 1, 'refused'), (False, 1000, 3, 'quiet'), (False, 1149, 1, 'warned'), (False, 1150, 1, 'quiet'), (False, 1049, 2, 'warned'), (False, 1050, 2, 'quiet'),
	# a vault not yet migrated: its oldest version holds the whole tree, and a file's copy is at or below the version
	(True, 99, 1, 'refused'), (True, 149, 2, 'warned'), (True, 150, 2, 'quiet'),
])
def test_whole_job_refuses_below_the_newest_size_and_warns_below_the_sum(tmp_path, monkeypatch, backward, free, chosen, outcome):
	kept = [size_of(1, 100), size_of(2, 50), size_of(3, 1000)]
	monkeypatch.setattr(os, 'statvfs', lambda path: types.SimpleNamespace(f_bavail=free, f_frsize=1))
	status = types.SimpleNamespace(alive=False, jobs={})
	stderr = io.StringIO()
	confirm = lambda: rv.confirm_whole_job_in_place('job', kept[chosen - 1], kept, str(tmp_path), status, True, False, None, stderr, backward)
	if outcome == 'refused':
		with pytest.raises(rv.CommandError) as refused:
			confirm()
		assert f'V{1 if backward else 3}' in refused.value.message
		return
	confirm()
	assert ('may not fit' in stderr.getvalue()) == (outcome == 'warned')


def test_restore_passes_over_no_file_of_a_temporary_name_on_design_r(r_job, tmp_path):
	# a prune's temporary is 0.54's: on design R a name of that form beside a hard link of it is the user's
	stacked_job(r_job)
	name = '.' + '0' * 32 + rv.PARTIAL_COPY_SUFFIX
	newest = versions(r_job)[-1]
	os.link(os.path.join(newest.path, 'top.txt'), os.path.join(newest.path, name))
	code, out = restored_to(r_job, tmp_path, 'out', r_job.monitor, '--version', '3')
	assert code == 0
	assert name in os.listdir(os.path.join(out, os.path.basename(r_job.monitor)))


# --- the walk of a folder ---

def test_iter_version_entries_goes_forward_parents_first(vault):
	write_version(vault, 1, {'a/': None, 'a/x': 'x1', 'a/sub': FORWARD, 'f': FORWARD, 'u': Link('elsewhere')})
	write_version(vault, 2, {'a/sub/': None, 'a/sub/in': FORWARD, 'a/sub/deep': FORWARD, 'f': 'f2'})
	write_version(vault, 3, {'a/sub/in': 'i3', 'a/sub/deep/z': 'z3'})
	found = list(rv.iter_version_entries(vault, 1, '', False))
	assert [rel for rel, _ in found][0] == ''
	order = [rel for rel, _ in found]
	assert sorted(order) == ['', 'a', 'a/sub', 'a/sub/deep', 'a/sub/deep/z', 'a/sub/in', 'a/x', 'f', 'u']
	for rel in order:
		parent = os.path.dirname(rel)
		if rel:
			assert order.index(parent) < order.index(rel), rel
	walked = dict(found)
	at = lambda number, rel: os.path.join(vault, version_name(number), rel)
	assert {rel: (entry.kind, entry.path) for rel, entry in walked.items() if rel} == {
		'a': ('folder', at(1, 'a')), 'a/x': ('file', at(1, 'a/x')), 'a/sub': ('folder', at(2, 'a/sub')),
		'a/sub/in': ('file', at(3, 'a/sub/in')), 'a/sub/deep': ('folder', at(3, 'a/sub/deep')), 'a/sub/deep/z': ('file', at(3, 'a/sub/deep/z')),
		'f': ('file', at(2, 'f')), 'u': ('symlink', at(1, 'u'))}


def test_iter_version_entries_starts_at_any_path(vault):
	forward_chain(vault, 1, 4, {'d/e/f': 'held'})
	assert [rel for rel, _ in rv.iter_version_entries(vault, 1, 'd/e', False)] == ['d/e', 'd/e/f']
	assert [(rel, walked.kind) for rel, walked in rv.iter_version_entries(vault, 1, 'd/e/f', False)] == [('d/e/f', 'file')]
	assert [(rel, walked.kind) for rel, walked in rv.iter_version_entries(vault, 1, 'nothing', False)] == [('nothing', 'missing')]


def test_iter_version_entries_goes_past_the_kernels_limit_of_links(vault):
	forward_chain(vault, 1, 60, {'d/f': 'held'})
	assert [(rel, walked.path) for rel, walked in rv.iter_version_entries(vault, 1, 'd', False)][1:] == [('d/f', os.path.join(vault, version_name(60), 'd/f'))]


def test_a_folder_refused_as_it_is_met_is_not_gone_into(vault):
	forward_chain(vault, 1, 2, {'d/f': 'held', 'e/g': 'held'})
	refused = {'d'}
	assert sorted(rel for rel, _ in rv.iter_version_entries(vault, 1, '', False, refused)) == ['', 'd', 'e', 'e/g']


def test_a_folder_that_cannot_be_listed_is_told(vault, monkeypatch):
	write_version(vault, 1, {'d/f': 'held'})
	real = os.scandir
	def refusing(path):
		if os.fspath(path).endswith('/d'):
			raise PermissionError(13, 'Permission denied', path)
		return real(path)
	monkeypatch.setattr(os, 'scandir', refusing)
	errors = []
	assert [rel for rel, _ in rv.iter_version_entries(vault, 1, '', False, errors=errors)] == ['', 'd']
	assert [rel for rel, _ in errors] == ['d']


# --- while a batch runs ---

def read_kind(walked):
	return walked.kind


def waits_of(monkeypatch):
	'''The waits read_checked asks for, none of them held: the batch is one the test keeps running.'''
	asked = []
	monkeypatch.setattr(rv, 'wait_for_backup', lambda job, state_dir=None: asked.append(job) or False)
	return asked


def test_a_path_missing_from_an_old_version_does_not_wait_for_a_batch(vault, monkeypatch):
	forward_chain(vault, 1, 4, {'a': 'held'})
	asked = waits_of(monkeypatch)
	fd = lock_backup()
	try:
		for number in (1, 2):
			assert rv.read_checked(vault, number, 'nothing', read_kind, job='job', backward=False) == 'missing'
		assert asked == []
		# V4, the newest, and V3 below it are what a batch changes
		for number in (3, 4):
			assert rv.read_checked(vault, number, 'nothing', read_kind, job='job', backward=False) == 'missing'
		assert asked == ['job', 'job']
	finally:
		os.close(fd)


def test_the_version_a_walk_ended_in_decides_the_wait_not_where_it_began(vault, monkeypatch):
	# from V1 the walk goes forward to V4, whose path is gone: a pool's two renames can show that for a moment
	write_version(vault, 1, {'a': FORWARD})
	write_version(vault, 2, {'a': FORWARD})
	write_version(vault, 3, {'a': FORWARD})
	write_version(vault, 4, {'other': 'held'})
	asked = waits_of(monkeypatch)
	fd = lock_backup()
	try:
		assert rv.read_checked(vault, 1, 'a', read_kind, job='job', backward=False) == 'missing'
		assert asked == ['job']
	finally:
		os.close(fd)


def test_a_vault_not_yet_migrated_waits_at_every_version(vault, monkeypatch):
	forward_chain(vault, 1, 4, {'a': 'held'})
	asked = waits_of(monkeypatch)
	fd = lock_backup()
	try:
		assert rv.read_checked(vault, 1, 'nothing', read_kind, job='job', backward=True) == 'missing'
		assert asked == ['job']
	finally:
		os.close(fd)


def test_no_batch_running_means_no_wait(vault, monkeypatch):
	forward_chain(vault, 1, 2, {'a': 'held'})
	asked = waits_of(monkeypatch)
	assert rv.read_checked(vault, 2, 'nothing', read_kind, job='job', backward=False) == 'missing'
	assert asked == []


def test_a_read_finding_its_entry_gone_waits_in_any_version(vault, monkeypatch):
	forward_chain(vault, 1, 4, {'a': 'held'})
	asked = waits_of(monkeypatch)
	calls = []
	def read(walked):
		calls.append(walked.path)
		if len(calls) == 1:
			raise FileNotFoundError(2, 'gone', walked.path)
		return walked.kind
	fd = lock_backup()
	try:
		assert rv.read_checked(vault, 1, 'a', read, job='job', backward=False) == 'file'
		assert asked == ['job']
	finally:
		os.close(fd)


def test_history_of_a_path_older_versions_never_held_stalls_on_no_batch(r_job, monkeypatch):
	seed_monitor(r_job, {'keep.txt': 'k'})
	run_backup(r_job)
	change(r_job, 'keep.txt', 'k1')
	change(r_job, 'keep.txt', 'k2')
	change(r_job, 'new.txt', 'n', 'create')
	reading = rv.vault_reading(r_job.job_vault, 'job')
	asked = waits_of(monkeypatch)
	fd = lock_backup()
	try:
		rows = rv.file_history(r_job.job_vault, versions(r_job), r_job.monitor, 'new.txt', reading)
	finally:
		os.close(fd)
	assert events(rows) == [(3, 'create')]
	# only V2 is one of the two newest and lacks it
	assert asked == ['job']


def test_a_restore_waits_for_a_running_batch_and_rereads(r_job, tmp_path, monkeypatch):
	stacked_job(r_job)
	# with no state folder a batch has no locks to take
	os.makedirs(rv.state_dir_path(), exist_ok=True)
	at_the_lock = threading.Event()
	steps = []
	real_locks = rv.command_restore_locks
	@contextlib.contextmanager
	def locks(job_name, state_dir=None):
		at_the_lock.set()
		with real_locks(job_name, state_dir):
			steps.append('restore holds the lock')
			yield
	monkeypatch.setattr(rv, 'command_restore_locks', locks)
	out = tmp_path / 'out'
	out.mkdir()
	result = []
	restore = threading.Thread(target=lambda: result.append(command(r_job, 'restore', os.path.join(r_job.monitor, 'd/sub/deep/f'), str(out), '--version', '3')))
	real_commit = rv.VaultManifest.commit
	def commit(self, *args, **kwargs):
		# the commit naming the version: the batch holds its locks and has changed the tree, so the restore starts now and comes to the lock.
		# a commit before that one comes before the batch takes them
		if args and not restore.ident:
			assert rv.backup_is_running('job')
			restore.start()
			assert at_the_lock.wait(30)
			steps.append('the batch commits')
		return real_commit(self, *args, **kwargs)
	write(r_job, 'd/sub/deep/f', 'f4')
	with monkeypatch.context() as patched:
		patched.setattr(rv.VaultManifest, 'commit', commit)
		backup(r_job, ('d/sub/deep/f', 'modify'))
	restore.join(30)
	assert not restore.is_alive()
	assert result == [0]
	assert steps == ['the batch commits', 'restore holds the lock']
	# V3's copy, recorded by the batch and read after it: not the file the walk found before
	with open(out / 'f') as f:
		assert f.read() == 'f3'


def test_a_restore_under_its_lock_meeting_a_missing_path_with_a_batch_waiting_does_not_hang(r_job, tmp_path, monkeypatch):
	stacked_job(r_job)
	# a forward link whose entry was removed by hand reads as missing
	newest = versions(r_job)[-1]
	os.remove(os.path.join(newest.path, 'other.txt'))
	assert os.path.islink(os.path.join(versions(r_job)[-2].path, 'other.txt'))
	real_restore = rv.restore_entry
	held = []
	def with_a_batch_waiting(*args, **kwargs):
		# what a batch that comes while the restore copies holds, waiting for the restore lock
		held.append(lock_backup())
		return real_restore(*args, **kwargs)
	def never(job, state_dir=None):
		raise AssertionError('a restore under its lock waited for the batch waiting for that lock')
	monkeypatch.setattr(rv, 'restore_entry', with_a_batch_waiting)
	monkeypatch.setattr(rv, 'wait_for_backup', never)
	try:
		code, out = restored_to(r_job, tmp_path, 'out', r_job.monitor, '--version', '2')
	finally:
		for fd in held:
			os.close(fd)
	assert held and code == rv.EXIT_COMMAND_FAILED
	assert not os.path.lexists(os.path.join(out, os.path.basename(r_job.monitor), 'other.txt'))
	assert os.path.exists(os.path.join(out, os.path.basename(r_job.monitor), 'top.txt'))


# --- a cut batch, with the monitored disk gone ---

@pytest.fixture
def crash_vault(tmp_path_factory):
	'''The crash vault on design R, as batch 2 left it. Outside tmp_path, whose vaults the ground truth plugins read: they see no fork's links.'''
	if 'vault' not in PREPARED:
		place = os.environ.get('REVERB_CRASH_ROOT')
		root = tempfile.mkdtemp(prefix='reverb-readers-', dir=place) if place else str(tmp_path_factory.mktemp('readers'))
		PREPARED['vault'] = prepare(root, only_sync_attributes=False)
		PREPARED['root'] = root
	restore_vault(PREPARED['vault'])
	return PREPARED['vault']


@pytest.fixture(scope='module', autouse=True)
def remove_the_root():
	yield
	if os.environ.get('REVERB_CRASH_ROOT') and 'root' in PREPARED:
		shutil.rmtree(PREPARED['root'])
	PREPARED.clear()


@needs_root
def test_restore_works_while_the_monitored_disk_is_gone_after_a_cut(crash_vault, tmp_path):
	job = crash_vault.job
	write_rule(job)
	want = {**crash_vault.base, 3: crash_vault.expected[3]}
	total = kill_run(job).steps
	assert total > 100
	points = range(1, total + 1) if os.environ.get('REVERB_CRASH_FULL') else range(1, total + 1, max(1, total // DEFAULT_KILL_POINTS))
	gone = job.monitor + '.gone'
	wrong = {}
	cut_trees = 0
	for point in points:
		restore_vault(crash_vault)
		kill_run(job, point)
		# the start's scan, then the wait for the monitored path, which never comes
		manifest = rv.VaultManifest(job.job_vault)
		info = rv.get_vault_info(job.job_vault, manifest=manifest)
		manifest.close()
		cut_trees += info.tree is not None
		os.rename(job.monitor, gone)
		try:
			for version in versions(job):
				out = tmp_path / f'{point}-{version.number}'
				out.mkdir()
				code = command(job, 'restore', job.monitor, str(out), '--version', str(version.number))
				got = snapshot_tree(os.path.join(out, os.path.basename(job.monitor))) if code == 0 else None
				if got != want[version.number]:
					rels = None if got is None else [rel for rel in set(got) | set(want[version.number]) if got.get(rel) != want[version.number].get(rel)]
					wrong[(point, version.number)] = (code, rels)
				shutil.rmtree(out)
				if command(job, 'history', os.path.join(job.monitor, 'b/y.txt')) != 0:
					wrong[(point, version.number, 'history')] = 'history failed'
		finally:
			os.rename(gone, job.monitor)
	assert not wrong, (len(wrong), next(iter(wrong.items())))
	# the kill points that matter were met
	assert cut_trees > 0
