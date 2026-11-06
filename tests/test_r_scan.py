'''
Round 20: the scan of a vault on design R and the rule for which layout a vault gets (plan S1, S2, S3, spec section 3). On R a
version folder with no change list can be the only real tree of a cut batch, so the scan never deletes on inference, and a
lost manifest must never bring the 0.54 rules down on it.
'''
import fcntl
import os
import shutil
import sqlite3
import threading
import time
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import backup_events, build_base, put_text
from tests.harness import create_job, write_committed_version, write_incomplete_version
from tests.vault_oracle import check_vault, compared, read_view, snapshot_tree, version_number

STAMP = '2030-01-01_00-00-00_+0000'
MANIFEST = rv.MANIFEST_FILE_NAME
KEPT = {'keep_n_versions': 0}


class Cut(BaseException):
	'''A kill at this point of a batch: nothing after it runs.'''


@pytest.fixture
def r_job(tmp_path):
	return create_job(str(tmp_path))


def folder_of(job, number):
	'''The path of the version folder numbered number.'''
	names = [name for name in os.listdir(job.job_vault) if version_number(name) == number and os.path.isdir(os.path.join(job.job_vault, name))]
	assert len(names) == 1, names
	return os.path.join(job.job_vault, names[0])


def list_of(job, number):
	'''The name of the change list of the version numbered number, None with none.'''
	folder = os.path.basename(folder_of(job, number))
	names = [name for name in os.listdir(job.job_vault) if name.startswith(folder + '--')]
	assert len(names) < 2, names
	return names[0] if names else None


def kept_versions_wrong(job, expected):
	'''What differs from expected in the committed versions read with the oracle, with a cut batch's tree still unnamed beside them.'''
	wrong = []
	for number, want in expected.items():
		view = read_view(job.job_vault, os.path.basename(folder_of(job, number)))
		wrong += [(number, rel) for rel in set(view) | set(want) if compared(view.get(rel), True, False) != compared(want.get(rel), True, False)]
	return wrong


def privates(job):
	return [name for name in os.listdir(job.job_vault) if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX)]


def lose_manifest(job, how='removed'):
	path = os.path.join(job.job_vault, MANIFEST)
	if how == 'removed':
		os.remove(path)
		if os.path.exists(path + '-journal'):
			os.remove(path + '-journal')
	else:
		with open(path, 'wb') as f:
			f.write(b'this is no database' * 200)


def opened_manifest(job):
	return rv.VaultManifest(job.job_vault)


def new_folder(job, number=3):
	return os.path.join(job.job_vault, f'V{number}--{STAMP}')


def handed_over(job):
	'''The newest version handed over to V3, a batch's first step, and the writer of that batch, whose manifest is open.'''
	manifest = opened_manifest(job)
	return rv.hand_over(job.job_vault, folder_of(job, 2), new_folder(job), manifest), manifest


def cut_batch(job):
	'''A batch cut with its tree handed over and one file recorded and replaced: the only real tree is an orphan.'''
	writer, manifest = handed_over(job)
	writer.record('a/x.txt', True)
	os.remove(os.path.join(writer.tree, 'a/x.txt'))
	with open(os.path.join(writer.tree, 'a/x.txt'), 'w') as f:
		f.write('being written')
	manifest.close()
	return writer.tree


def commit_cut_at(job, monkeypatch, name):
	'''The version after the base committed by the manifest, then a kill as rv.<name> is called. What it must hold.'''
	put_text(job.monitor, 'a/x.txt', 'the new contents')
	expected = snapshot_tree(job.monitor)
	real = getattr(rv, name)
	def cut(*args, **kwargs):
		raise Cut()
	monkeypatch.setattr(rv, name, cut)
	with pytest.raises(Cut):
		backup_events(job, [(False, 'modify', 'a/x.txt', None)], **KEPT)
	monkeypatch.setattr(rv, name, real)
	return expected


# ---- S3: a commit cut after the manifest

@pytest.mark.parametrize('cut_at', ['swap_current_version', 'place_change_list'], ids=['old name', 'new name'])
def test_a_commit_cut_after_the_manifest_is_finished(r_job, monkeypatch, cut_at):
	expected = build_base(r_job, **KEPT)
	old_list = list_of(r_job, 2)
	expected[3] = commit_cut_at(r_job, monkeypatch, cut_at)
	assert privates(r_job)
	assert (list_of(r_job, 2) == old_list) == (cut_at == 'swap_current_version')
	info = rv.get_vault_info(r_job.job_vault)
	assert list(info.vault_info_dict) == [0, 1, 2, 3] and info.tree is None
	assert not privates(r_job)
	assert os.readlink(os.path.join(r_job.job_vault, 'current_version')) == os.path.basename(folder_of(r_job, 3))
	assert list_of(r_job, 2) != old_list
	manifest = opened_manifest(r_job)
	assert manifest.previous_list() == {'from': old_list, 'to': list_of(r_job, 2)}
	manifest.close()
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_placed_list_over_the_previous_list_under_its_old_name_is_finished(r_job):
	# a power loss can keep the placement and lose the rename, as the commit syncs nothing between them
	expected = build_base(r_job, **KEPT)
	old_list = list_of(r_job, 2)
	put_text(r_job.monitor, 'a/x.txt', 'the new contents')
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'modify', 'a/x.txt', None)], **KEPT)
	new_list = list_of(r_job, 2)
	assert new_list != old_list
	os.rename(os.path.join(r_job.job_vault, new_list), os.path.join(r_job.job_vault, old_list))
	info = rv.get_vault_info(r_job.job_vault)
	assert list_of(r_job, 2) == new_list
	size, inodes = rv.change_list_record(new_list[len(os.path.basename(folder_of(r_job, 2))) + 2:])
	assert (info.vault_info_dict[2].size, info.vault_info_dict[2].inode) == (size, inodes)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_the_scan_leaves_a_finished_rename_alone(r_job):
	build_base(r_job, **KEPT)
	names = sorted(os.listdir(r_job.job_vault))
	rv.get_vault_info(r_job.job_vault)
	assert sorted(os.listdir(r_job.job_vault)) == names


def test_a_named_version_with_no_list_is_refused(r_job, monkeypatch):
	expected = build_base(r_job, **KEPT)
	commit_cut_at(r_job, monkeypatch, 'place_change_list')
	for private in privates(r_job):
		shutil.rmtree(os.path.join(r_job.job_vault, private))
	tree = folder_of(r_job, 3)
	with pytest.raises(rv.JobFailure, match='records .*as committed'):
		rv.get_vault_info(r_job.job_vault)
	assert os.path.isdir(os.path.join(tree, 'a'))
	assert kept_versions_wrong(r_job, expected) == []


def test_a_named_version_whose_folder_is_gone_is_refused(r_job, monkeypatch):
	build_base(r_job, **KEPT)
	commit_cut_at(r_job, monkeypatch, 'place_change_list')
	moved = str(folder_of(r_job, 3)) + '.moved'
	os.rename(folder_of(r_job, 3), moved)
	names = sorted(os.listdir(r_job.job_vault))
	with pytest.raises(rv.JobFailure, match='records .*as committed'):
		rv.get_vault_info(r_job.job_vault)
	assert sorted(os.listdir(r_job.job_vault)) == names


def test_the_refusal_says_a_lost_manifest_finishes_it(r_job, monkeypatch):
	# what the refusal tells the operator to do works: the tree is kept for the next attempt
	build_base(r_job, **KEPT)
	commit_cut_at(r_job, monkeypatch, 'place_change_list')
	for private in privates(r_job):
		shutil.rmtree(os.path.join(r_job.job_vault, private))
	tree = folder_of(r_job, 3)
	with pytest.raises(rv.JobFailure, match=MANIFEST):
		rv.get_vault_info(r_job.job_vault)
	lose_manifest(r_job)
	assert rv.get_vault_info(r_job.job_vault).tree == tree


# ---- S3: the orphan at the number after the newest

@pytest.mark.parametrize('links', [False, True], ids=['empty', 'links naming themselves'])
def test_a_skeleton_is_removed(r_job, monkeypatch, links):
	expected = build_base(r_job, **KEPT)
	if links:
		def cut(*args):
			raise Cut()
		monkeypatch.setattr(rv, 'rename_exchange', cut)
		with pytest.raises(Cut):
			handed_over(r_job)
		monkeypatch.undo()
		assert os.listdir(new_folder(r_job))
	else:
		os.mkdir(new_folder(r_job))
	info = rv.get_vault_info(r_job.job_vault)
	assert not os.path.lexists(new_folder(r_job))
	assert info.tree is None and list(info.vault_info_dict) == [0, 1, 2]
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_tree_is_kept_for_the_next_attempt(r_job):
	expected = build_base(r_job, **KEPT)
	tree = cut_batch(r_job)
	info = rv.get_vault_info(r_job.job_vault)
	assert info.tree == tree
	assert list(info.vault_info_dict) == [0, 1, 2]
	assert os.path.isdir(os.path.join(tree, 'a'))
	# the tree's own contents, and the cut batch's record reaches version 2
	with open(os.path.join(tree, 'a/x.txt')) as f:
		assert f.read() == 'being written'
	assert kept_versions_wrong(r_job, expected) == []


def test_a_tree_holding_a_self_named_link_beside_real_entries_is_kept(r_job):
	# what exchange_in() leaves in the tree when cut: the rest of the tree is still real
	build_base(r_job, **KEPT)
	writer, manifest = handed_over(r_job)
	manifest.close()
	shutil.rmtree(os.path.join(writer.tree, 'd'))
	os.symlink(rv.forward_text('d', os.path.basename(writer.tree)), os.path.join(writer.tree, 'd'))
	assert rv.get_vault_info(r_job.job_vault).tree == writer.tree


@pytest.mark.parametrize('leave', ['empty', 'self named'])
def test_a_cut_after_emptying_the_tree_keeps_version_n_exact(r_job, leave):
	expected = build_base(r_job, **KEPT)
	writer, manifest = handed_over(r_job)
	tree_name = os.path.basename(writer.tree)
	for name in sorted(os.listdir(writer.tree)):
		writer.record(name, False)
	assert os.listdir(writer.tree) == []
	if leave == 'self named':
		for name in ('a', 'b'):
			os.symlink(rv.forward_text(name, tree_name), os.path.join(writer.tree, name))
	manifest.close()
	# the cut fell in the one call between a change in that folder and giving its times back
	touched = os.path.join(folder_of(r_job, 2), 'a')
	st = os.lstat(touched)
	os.utime(touched, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000), follow_symlinks=False)
	assert kept_versions_wrong(r_job, expected) != []
	info = rv.get_vault_info(r_job.job_vault)
	assert info.tree is None and not os.path.lexists(writer.tree)
	assert check_vault(r_job.job_vault, expected, set()) == []
	# and the job goes on from it
	put_text(r_job.monitor, 'after.txt', 'after')
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'create', 'after.txt', None)], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_cut_while_giving_times_back_leaves_the_skeleton_for_the_next_scan(r_job, monkeypatch):
	# the times go first: with the skeleton gone first, nothing would tell the next scan to give them back
	expected = build_base(r_job, **KEPT)
	writer, manifest = handed_over(r_job)
	for name in sorted(os.listdir(writer.tree)):
		writer.record(name, False)
	manifest.close()
	touched = os.path.join(folder_of(r_job, 2), 'a')
	st = os.lstat(touched)
	os.utime(touched, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000), follow_symlinks=False)
	def cut(*args):
		raise Cut()
	monkeypatch.setattr(rv, 'give_back_folder_times', cut)
	with pytest.raises(Cut):
		rv.get_vault_info(r_job.job_vault)
	monkeypatch.undo()
	assert os.path.isdir(writer.tree)
	rv.get_vault_info(r_job.job_vault)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_lone_v0_orphan_is_removed(r_job):
	os.makedirs(r_job.job_vault)
	os.mkdir(os.path.join(r_job.job_vault, rv.STAGING_NAME))
	v0 = os.path.join(r_job.job_vault, f'V0--{STAMP}')
	os.mkdir(v0)
	with open(os.path.join(v0, 'file'), 'w') as f:
		f.write('a first copy cut short')
	info = rv.get_vault_info(r_job.job_vault)
	assert info.vault_info_dict == {} and info.tree is None
	assert not os.path.lexists(v0)


@pytest.mark.parametrize('numbers', [[5], [4], [3, 4]], ids=['far ahead', 'one too far', 'two orphans'])
def test_any_other_orphan_is_an_error(r_job, numbers):
	expected = build_base(r_job, **KEPT)
	folders = [new_folder(r_job, number) for number in numbers]
	for folder in folders:
		os.mkdir(folder)
	staged = os.path.join(r_job.job_vault, rv.STAGING_NAME, 'left')
	open(staged, 'w').close()
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(r_job.job_vault)
	assert all(os.path.isdir(folder) for folder in folders)
	# before anything is removed
	assert os.path.exists(staged)
	os.remove(staged)
	for folder in folders:
		os.rmdir(folder)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_an_orphan_below_the_newest_is_an_error(r_job):
	build_base(r_job, **KEPT)
	os.remove(os.path.join(r_job.job_vault, list_of(r_job, 1)))
	folder = folder_of(r_job, 1)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(r_job.job_vault)
	assert os.path.isdir(folder)


# ---- the rest of the scan

def test_staging_is_emptied(r_job):
	expected = build_base(r_job, **KEPT)
	staging = os.path.join(r_job.job_vault, rv.STAGING_NAME)
	os.makedirs(os.path.join(staging, 'V0--old', 'deep', 'er'))
	open(os.path.join(staging, 'V0--old', 'deep', 'er', 'file'), 'w').close()
	open(os.path.join(staging, 'file'), 'w').close()
	os.symlink('../../V9--x/gone', os.path.join(staging, 'link'))
	info = rv.get_vault_info(r_job.job_vault)
	assert os.listdir(staging) == [] and info.tree is None
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_stale_list_below_the_oldest_is_removed(r_job):
	# a prune cut between its rename into staging and the removal of the list
	expected = build_base(r_job, **KEPT)
	stale = list_of(r_job, 0)
	folder = folder_of(r_job, 0)
	os.rename(folder, os.path.join(r_job.job_vault, rv.STAGING_NAME, os.path.basename(folder)))
	del expected[0]
	info = rv.get_vault_info(r_job.job_vault)
	assert list(info.vault_info_dict) == [1, 2]
	assert not os.path.lexists(os.path.join(r_job.job_vault, stale))
	assert os.listdir(os.path.join(r_job.job_vault, rv.STAGING_NAME)) == []
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_current_version_moves_forward(r_job):
	build_base(r_job, **KEPT)
	rv.swap_current_version(r_job.job_vault, os.path.basename(folder_of(r_job, 1)))
	rv.get_vault_info(r_job.job_vault)
	assert os.readlink(os.path.join(r_job.job_vault, 'current_version')) == os.path.basename(folder_of(r_job, 2))


@pytest.mark.parametrize('kind', ['file', 'folder'])
def test_a_current_version_that_is_no_link_fails_the_scan_and_is_left_as_it_is(r_job, kind):
	# something there that is no link, which the move forward would replace (a file) or fail on (a folder)
	build_base(r_job, **KEPT)
	link = os.path.join(r_job.job_vault, 'current_version')
	os.remove(link)
	if kind == 'file':
		with open(link, 'w') as f:
			f.write('mine')
	else:
		os.mkdir(link)
		open(os.path.join(link, 'inside'), 'w').close()
	# a skeleton the scan would remove, and a stale list: nothing is touched before the refusal
	os.mkdir(new_folder(r_job))
	before = sorted(os.listdir(r_job.job_vault))
	with pytest.raises(rv.VaultScanError, match='current_version is no link'):
		rv.get_vault_info(r_job.job_vault)
	assert sorted(os.listdir(r_job.job_vault)) == before
	if kind == 'file':
		assert open(link).read() == 'mine'
	else:
		assert os.listdir(link) == ['inside']


def test_the_private_list_of_an_uncommitted_attempt_goes(r_job):
	build_base(r_job, **KEPT)
	tree = cut_batch(r_job)
	private = rv.prepare_change_list(rv.change_list_path(tree, 1, 1), [])
	assert rv.get_vault_info(r_job.job_vault).tree == tree
	assert not os.path.lexists(os.path.dirname(private))


def test_the_sizes_are_the_lists(r_job):
	build_base(r_job, **KEPT)
	info = rv.get_vault_info(r_job.job_vault)
	assert info.vault_size == sum(entry.size for entry in info.vault_info_dict.values())
	assert info.vault_inodes == sum(entry.inode for entry in info.vault_info_dict.values())


# ---- S1: which rules a vault gets

@pytest.mark.parametrize('how', ['removed', 'unreadable'])
def test_an_r_vault_with_a_lost_manifest_keeps_its_tree(r_job, how):
	expected = build_base(r_job, **KEPT)
	tree = cut_batch(r_job)
	private = rv.prepare_change_list(rv.change_list_path(tree, 1, 1), [])
	lose_manifest(r_job, how)
	info = rv.get_vault_info(r_job.job_vault)
	assert info.tree == tree
	assert os.path.isdir(os.path.join(tree, 'a'))
	assert not os.path.lexists(os.path.dirname(private))
	assert kept_versions_wrong(r_job, expected) == []


def test_a_lost_manifest_with_a_skeleton_removes_it(r_job):
	expected = build_base(r_job, **KEPT)
	os.mkdir(new_folder(r_job))
	lose_manifest(r_job)
	assert rv.get_vault_info(r_job.job_vault).tree is None
	assert not os.path.lexists(new_folder(r_job))
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_recorded_layout_with_staging_gone_keeps_its_tree(r_job):
	# the manifest alone says it: the 0.54 rules must not see this tree
	build_base(r_job, **KEPT)
	tree = cut_batch(r_job)
	os.rmdir(os.path.join(r_job.job_vault, rv.STAGING_NAME))
	assert rv.get_vault_info(r_job.job_vault).tree == tree


def test_a_vault_with_no_staging_and_no_layout_gets_the_054_rules(job, monkeypatch):
	write_committed_version(job, 0, {'f': 'x'})
	orphan = write_incomplete_version(job, 1, {'f': 'y'})
	def never(*args):
		raise AssertionError('the R scan ran')
	monkeypatch.setattr(rv, 'read_job_vault_r', never)
	info = rv.get_vault_info(job.job_vault)
	assert list(info.vault_info_dict) == [0]
	assert not os.path.lexists(orphan)
	# nothing is created to find that out
	assert not os.path.lexists(os.path.join(job.job_vault, MANIFEST))
	assert not os.path.lexists(os.path.join(job.job_vault, rv.STAGING_NAME))


def test_an_unreadable_manifest_with_no_staging_gets_the_054_rules(job):
	write_committed_version(job, 0, {'f': 'x'})
	orphan = write_incomplete_version(job, 1, {'f': 'y'})
	with open(os.path.join(job.job_vault, MANIFEST), 'wb') as f:
		f.write(b'this is no database' * 200)
	rv.get_vault_info(job.job_vault)
	assert not os.path.lexists(orphan)


def test_a_manifest_that_cannot_be_asked_removes_nothing(job):
	# no answer is not "no layout"
	write_committed_version(job, 0, {'f': 'x'})
	orphan = write_incomplete_version(job, 1, {'f': 'y'})
	conn = sqlite3.connect(os.path.join(job.job_vault, MANIFEST), isolation_level=None)
	try:
		conn.execute('CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)')
		conn.execute('BEGIN EXCLUSIVE')
		with pytest.raises(rv.VaultScanError):
			rv.get_vault_info(job.job_vault)
	finally:
		conn.close()
	assert os.path.isdir(orphan)


def test_a_look_at_staging_that_fails_removes_nothing(job, monkeypatch):
	write_committed_version(job, 0, {'f': 'x'})
	orphan = write_incomplete_version(job, 1, {'f': 'y'})
	real_lstat = os.lstat
	def failing(path, *args, **kwargs):
		if os.fspath(path).endswith(rv.STAGING_NAME):
			raise PermissionError(13, 'no', path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', failing)
	with pytest.raises(rv.VaultScanError):
		rv.get_vault_info(job.job_vault)
	monkeypatch.undo()
	assert os.path.isdir(orphan)


def test_a_job_vault_that_is_not_there_is_an_empty_one(r_job):
	info = rv.get_vault_info(r_job.job_vault)
	assert info.vault_info_dict == {} and info.tree is None
	assert not os.path.lexists(r_job.job_vault)


def test_a_new_vault_scan_on_r_finds_nothing(r_job):
	os.makedirs(r_job.job_vault)
	info = rv.get_vault_info(r_job.job_vault)
	assert info.vault_info_dict == {}


def test_a_shown_empty_r_vault_is_no_new_vault(r_job):
	build_base(r_job, **KEPT)
	rv.get_vault_info(r_job.job_vault)
	for number in (0, 1, 2):
		name = list_of(r_job, number)
		folder = folder_of(r_job, number)
		os.remove(os.path.join(r_job.job_vault, name))
		shutil.rmtree(folder)
	with pytest.raises(rv.VaultScanError):
		rv.get_vault_info(r_job.job_vault)


def test_a_batch_on_a_vault_with_no_layout_leaves_it_to_the_migration(r_job):
	# S1: the layout is set only once the migration's sizes pass; a batch sets none but V0's
	expected = build_base(r_job, **KEPT)
	lose_manifest(r_job)
	put_text(r_job.monitor, 'a/x.txt', 'the new contents')
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'modify', 'a/x.txt', None)], **KEPT)
	manifest = opened_manifest(r_job)
	assert manifest.layout() is None and rv.vault_layout(r_job.job_vault, manifest) == 'converting'
	manifest.close()
	assert check_vault(r_job.job_vault, expected, set()) == []


# ---- the pieces

def test_is_skeleton(tmp_path):
	path = tmp_path / f'V3--{STAMP}'
	path.mkdir()
	assert rv.is_skeleton(str(path))
	os.symlink(rv.forward_text('a', path.name), path / 'a')
	assert rv.is_skeleton(str(path)) and rv.is_skeleton(f'{path}/')
	os.symlink(rv.forward_text('b', 'V4--other'), path / 'b')
	assert not rv.is_skeleton(str(path))
	os.remove(path / 'b')
	(path / 'real').mkdir()
	assert not rv.is_skeleton(str(path))
	(path / 'real').rmdir()
	(path / 'file').write_text('x')
	assert not rv.is_skeleton(str(path))


def test_give_back_folder_times_returns_the_recorded_paths_and_writes_only_what_differs(r_job, monkeypatch):
	build_base(r_job, **KEPT)
	writer, manifest = handed_over(r_job)
	writer.record('a/x.txt', True)
	previous = folder_of(r_job, 2)
	st = os.lstat(os.path.join(previous, 'a'))
	row_mtime = manifest.lookup('a/').mtime_ns
	assert row_mtime is not None
	os.utime(os.path.join(previous, 'a'), ns=(st.st_atime_ns, row_mtime + 5_000_000_000), follow_symlinks=False)
	before = os.lstat(os.path.join(previous, 'a'))
	calls = []
	real_utime = os.utime
	def utime(path, *args, **kwargs):
		calls.append(path)
		# a rename never moves the atime
		assert kwargs['ns'] == (before.st_atime_ns, row_mtime)
		return real_utime(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'utime', utime)
	recorded = rv.give_back_folder_times(previous, manifest)
	again = rv.give_back_folder_times(previous, manifest)
	monkeypatch.undo()
	manifest.close()
	assert recorded == again
	assert 'a/' in recorded and 'a/x.txt' in recorded
	# forward links are no records
	assert 'b' not in recorded and 'a/sub' not in recorded and 'top.txt' not in recorded
	assert [path.rstrip('/') for path in calls] == [os.path.join(previous, 'a')]
	assert os.lstat(os.path.join(previous, 'a')).st_mtime_ns == row_mtime


def test_give_back_folder_times_leaves_a_folder_with_no_row(r_job):
	build_base(r_job, **KEPT)
	writer, manifest = handed_over(r_job)
	writer.record('a/x.txt', True)
	manifest.close()
	lose_manifest(r_job)
	manifest = opened_manifest(r_job)
	previous = folder_of(r_job, 2)
	before = os.lstat(os.path.join(previous, 'a')).st_mtime_ns
	assert 'a/' in rv.give_back_folder_times(previous, manifest)
	manifest.close()
	assert os.lstat(os.path.join(previous, 'a')).st_mtime_ns == before


# ---- S2: the locks

def lock_free(job, kind):
	'''Whether the job's lock of kind can be taken exclusive right now.'''
	fd = os.open(rv.job_lock_path(job.job_name, kind), os.O_RDWR | os.O_CREAT, 0o600)
	try:
		fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
		return True
	except BlockingIOError:
		return False
	finally:
		os.close(fd)


@pytest.fixture
def scans(monkeypatch):
	'''What each R scan found the locks as: (backup free, restore free).'''
	found = []
	real = rv.read_job_vault_r
	def scan(job_vault, manifest, job_name):
		job = scan.job
		found.append((lock_free(job, 'backup'), lock_free(job, 'restore')))
		return real(job_vault, manifest, job_name)
	monkeypatch.setattr(rv, 'read_job_vault_r', scan)
	os.makedirs(rv.state_dir_path(), exist_ok=True)
	found_with = lambda job: (setattr(scan, 'job', job), found)[1]
	return found_with


def test_every_scan_that_can_write_holds_the_locks(r_job, scans, monkeypatch):
	found = scans(r_job)
	build_base(r_job, **KEPT)
	# do_backup's own, which the two batches of the base after V0 ran: V0 starts with no staging
	assert len(found) == 2 and set(found) == {(False, False)}
	assert lock_free(r_job, 'backup') and lock_free(r_job, 'restore')
	# compare_scanned_folders' own
	found.clear()
	entries = OrderedDict()
	info, manifest, full = rv.compare_scanned_folders(entries, [os.path.join(r_job.monitor, 'a')], r_job.job_name, r_job.monitor, r_job.vault)
	if manifest is not None:
		manifest.close()
	assert list(info.vault_info_dict) == [0, 1, 2] and full is False
	assert found == [(False, False)]
	assert lock_free(r_job, 'backup') and lock_free(r_job, 'restore')
	# the job start's
	found.clear()
	monitor_fs_flag = threading.Event()
	monitor_fs_flag.set()
	real_compare = rv.delta_generate_backup_entries
	def comparing(*args, **kwargs):
		rv.GREEN_LIGHT.clear()
		return real_compare(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', comparing)
	to_process = rv.ChangeEventQueue(r_job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'full_scan', r_job.monitor, None))
	try:
		rv.backuper(r_job.job_name, to_process, threading.Lock(), r_job.monitor, r_job.vault, 'N/A', threading.Event(), monitor_fs_flag)
	finally:
		rv.GREEN_LIGHT.set()
	assert found == [(False, False)]
	assert lock_free(r_job, 'backup') and lock_free(r_job, 'restore')


def test_a_stop_while_a_comparison_waits_for_the_locks_scans_nothing(r_job, scans):
	found = scans(r_job)
	build_base(r_job, **KEPT)
	found.clear()
	fd = os.open(rv.job_lock_path(r_job.job_name, 'restore'), os.O_RDWR | os.O_CREAT, 0o600)
	fcntl.flock(fd, fcntl.LOCK_SH)
	rv.GREEN_LIGHT.clear()
	try:
		info, manifest, full = rv.compare_scanned_folders(OrderedDict(), [os.path.join(r_job.monitor, 'a')], r_job.job_name, r_job.monitor, r_job.vault)
	finally:
		rv.GREEN_LIGHT.set()
		os.close(fd)
	assert (info, manifest, full) == (None, None, False)
	assert found == []
