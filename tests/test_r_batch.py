'''
Round 20: a real backup batch on design R, end to end through do_backup: every item of spec section 9's batch run alone, and
the batch whole, each version read by the independent oracle (tests/vault_oracle.py) afterwards.
'''
import os
import shutil
import stat
from collections import OrderedDict
import pytest

import reverberator as rv
from tests import version_view_ground_truth as view_truth
from tests.crash_batches import (BAD_NAME, NEWLINE_NAME, OPTIONS, UNREADABLE, apply_batch3, backup_events, batch3_of, build_base, expected_of, put_text)
from tests.crash_child import failing_copy_command
from tests.harness import create_job, event_entry, run_backup
from tests.vault_oracle import check_vault, forward_text, linked_place, read_view, snapshot_tree, version_number

# every version stays to be read; tests/test_r_sizes.py runs each item through a real keep-N
KEPT = dict(keep_n_versions=0)


def at(monitor, rel):
	return os.path.join(monitor, rel)


# each item takes the monitored path, changes it as spec section 9's batch does, and gives the raw events
def item_create(m):
	put_text(m, 'n1.txt', 'n1')
	put_text(m, 'newf/a.txt', 'na')
	put_text(m, 'newf/sub/b.txt', 'nb')
	return [(False, 'create', 'n1.txt', None), (True, 'create', 'newf', None)]

def item_modify(m):
	put_text(m, 'a/x.txt', 'ax3')
	return [(False, 'modify', 'a/x.txt', None)]

def item_modify_twice(m):
	put_text(m, 'b/y.txt', 'y3a')
	put_text(m, 'b/y.txt', 'y3b')
	return [(False, 'modify', 'b/y.txt', None), (False, 'modify', 'b/y.txt', None)]

def item_three_levels_deep(m):
	put_text(m, 'g/h/i/j.txt', 'j3')
	os.remove(at(m, 'g/h/i/gone.txt'))
	put_text(m, 'g/h/i/new.txt', 'gn')
	return [(False, 'modify', 'g/h/i/j.txt', None), (False, 'delete', 'g/h/i/gone.txt', None), (False, 'create', 'g/h/i/new.txt', None)]

def item_delete(m):
	os.remove(at(m, 'c/z.txt'))
	return [(False, 'delete', 'c/z.txt', None)]

def item_folder_delete(m):
	shutil.rmtree(at(m, 'big'))
	return [(True, 'delete', 'big', None)]

def item_move_out_then_delete(m):
	os.rename(at(m, 'd/g'), at(m, 'y'))
	shutil.rmtree(at(m, 'd'))
	return [(False, 'move', 'y', 'd/g'), (True, 'delete', 'd', None)]

def item_move_then_changes(m):
	os.rename(at(m, 'a/sub'), at(m, 'e'))
	put_text(m, 'e/m.txt', 'new')
	put_text(m, 'e/new.txt', 'n')
	put_text(m, 'e/deep/k.txt', 'k3')
	return [(True, 'move', 'e', 'a/sub'), (False, 'modify', 'e/m.txt', None), (False, 'create', 'e/new.txt', None), (False, 'modify', 'e/deep/k.txt', None)]

def item_folder_swap(m):
	os.rename(at(m, 's1'), at(m, 'tmp'))
	os.rename(at(m, 's2'), at(m, 's1'))
	os.rename(at(m, 'tmp'), at(m, 's2'))
	return [(True, 'move', 'tmp', 's1'), (True, 'move', 's1', 's2'), (True, 'move', 's2', 'tmp')]

def item_file_swap(m):
	os.rename(at(m, 'f1.txt'), at(m, 't'))
	os.rename(at(m, 'f2.txt'), at(m, 'f1.txt'))
	os.rename(at(m, 't'), at(m, 'f2.txt'))
	return [(False, 'move', 't', 'f1.txt'), (False, 'move', 'f1.txt', 'f2.txt'), (False, 'move', 'f2.txt', 't')]

def item_chained_moves(m):
	os.rename(at(m, 'chain1.txt'), at(m, 'chain2.txt'))
	os.rename(at(m, 'chain2.txt'), at(m, 'chain3.txt'))
	return [(False, 'move', 'chain2.txt', 'chain1.txt'), (False, 'move', 'chain3.txt', 'chain2.txt')]

def item_modify_then_delete(m):
	put_text(m, 'q.txt', 'q3')
	os.remove(at(m, 'q.txt'))
	return [(False, 'modify', 'q.txt', None), (False, 'delete', 'q.txt', None)]

def item_folder_chmod(m):
	os.chmod(at(m, 'b'), 0o700)
	return [(True, 'attrib', 'b', None)]

def item_file_to_folder(m):
	os.remove(at(m, 'r.txt'))
	os.mkdir(at(m, 'r.txt'))
	put_text(m, 'r.txt/in.txt', 'rin')
	return [(False, 'delete', 'r.txt', None), (True, 'create', 'r.txt', None)]

def item_folder_to_file(m):
	shutil.rmtree(at(m, 'rr'))
	put_text(m, 'rr', 'rr is a file')
	return [(True, 'delete', 'rr', None), (False, 'create', 'rr', None)]

def item_link_retarget(m):
	os.remove(at(m, 'lnk'))
	os.symlink('b/y.txt', at(m, 'lnk'))
	return [(False, 'delete', 'lnk', None), (False, 'create', 'lnk', None)]

def item_attrib(m):
	os.chmod(at(m, 'top.txt'), 0o600)
	return [(False, 'attrib', 'top.txt', None)]

def item_folder_over_folder(m):
	os.remove(at(m, 'w/old.txt'))
	put_text(m, f'w/x{UNREADABLE}', 'b3')
	put_text(m, f'w/fresh{UNREADABLE}', 'f3')
	put_text(m, 'w/sub/s.txt', 's3')
	put_text(m, 'w/new.txt', 'wn')
	return [(True, 'create', 'w', None)]

def item_odd_names(m):
	put_text(m, BAD_NAME, 'bad name')
	put_text(m, NEWLINE_NAME, 'newline name')
	return [(False, 'create', BAD_NAME, None), (False, 'create', NEWLINE_NAME, None)]


ITEMS = {function.__name__[len('item_'):]: function for function in (item_create, item_modify, item_modify_twice, item_three_levels_deep, item_delete,
	item_folder_delete, item_move_out_then_delete, item_move_then_changes, item_folder_swap, item_file_swap, item_chained_moves, item_modify_then_delete,
	item_folder_chmod, item_file_to_folder, item_folder_to_file, item_link_retarget, item_attrib, item_folder_over_folder, item_odd_names)}
each_item = pytest.mark.parametrize('item', ITEMS)


@pytest.fixture
def r_job(tmp_path):
	return create_job(str(tmp_path))


@pytest.fixture
def copies_fail(monkeypatch):
	'''Call it once the base is built: a copy of a name ending UNREADABLE fails from then on, as cp fails on a file it may not read (root reads any file).'''
	return lambda: monkeypatch.setattr(rv, 'copy_command', failing_copy_command(rv.copy_command))


@pytest.fixture
def run_item(r_job, copies_fail):
	def run(item, **options):
		'''The vault's three versions, then the item alone as version 3; {version number: what it must hold}.'''
		expected = build_base(r_job, **KEPT, **options)
		copies_fail()
		events = ITEMS[item](r_job.monitor)
		expected[3] = expected_of(snapshot_tree(r_job.monitor), expected[2])
		backup_events(r_job, events, **KEPT, **options)
		return expected
	return run


def folder_of(job, number):
	return next(name for name in os.listdir(job.job_vault) if version_number(name) == number)


def take_wrong():
	'''What the view plugin found, taken out, for a test that broke a version on purpose.'''
	wrong = list(view_truth.WRONG)
	view_truth.WRONG.clear()
	return wrong


# --- the layout ---

def test_a_new_vault_is_r(tmp_path):
	job = create_job(str(tmp_path))
	put_text(job.monitor, 'a', 'a')
	run_backup(job)
	put_text(job.monitor, 'a', 'b')
	run_backup(job)
	assert os.path.isdir(os.path.join(job.job_vault, rv.STAGING_NAME))
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.layout() == 'r' and rv.vault_layout(job.job_vault, manifest) == 'r'
	manifest.close()
	assert os.path.islink(os.path.join(job.job_vault, folder_of(job, 1), 'a')) is False
	assert view_truth.TOTALS is not None


def test_vault_layout_answers(tmp_path):
	job_vault = tmp_path / 'job'
	job_vault.mkdir()
	manifest = rv.VaultManifest(str(job_vault))
	assert rv.vault_layout(str(job_vault), manifest) == rv.NEW_VAULT_LAYOUT == 'r'
	(job_vault / 'V0--2021-01-01_00-00-00_-0800').mkdir()
	assert rv.vault_layout(str(job_vault), manifest) == '0.54'
	(job_vault / rv.STAGING_NAME).mkdir()
	assert rv.vault_layout(str(job_vault), manifest) == 'converting'
	manifest.begin()
	manifest.set_layout('r')
	manifest.commit()
	assert rv.vault_layout(str(job_vault), manifest) == 'r'
	manifest.close()


def test_v0_makes_staging_and_records_the_layout_in_its_commit(r_job):
	put_text(r_job.monitor, 'a/b', 'x')
	run_backup(r_job)
	assert os.path.isdir(os.path.join(r_job.job_vault, rv.STAGING_NAME))
	manifest = rv.VaultManifest(r_job.job_vault)
	assert manifest.layout() == 'r'
	manifest.close()
	assert check_vault(r_job.job_vault, {0: snapshot_tree(r_job.monitor)}, set()) == []


def test_v0_on_r_is_a_complete_copy_whatever_the_rule_says(r_job):
	put_text(r_job.monitor, 'a/b', 'x')
	run_backup(r_job, keep_one_complete_backup=False)
	assert check_vault(r_job.job_vault, {0: snapshot_tree(r_job.monitor)}, set()) == []
	assert not os.path.islink(os.path.join(r_job.job_vault, folder_of(r_job, 0), 'a', 'b'))


def test_a_lost_manifest_on_r_lists_the_tree_before_the_hand_over(r_job):
	expected = build_base(r_job, **KEPT)
	os.remove(os.path.join(r_job.job_vault, '.reverberator_manifest.sqlite'))
	events = item_modify(r_job.monitor)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, events, **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []
	manifest = rv.VaultManifest(r_job.job_vault)
	# the layout comes back through the migration's sizes pass (plan S1), never a batch
	assert manifest.layout() is None and manifest.lookup('b/y.txt') is not None
	manifest.close()


def test_an_attempt_in_the_same_second_changes_nothing(r_job, monkeypatch):
	expected = build_base(r_job, **KEPT)
	item_modify(r_job.monitor)
	taken = []
	real = rv.hand_over
	def taken_folder(job_vault, newest, new, *rest):
		os.mkdir(new)
		taken.append(new)
		return real(job_vault, newest, new, *rest)
	monkeypatch.setattr(rv, 'hand_over', taken_folder)
	_, manifest, committed = rv.do_backup(rv.OrderedDict(), job_name=r_job.job_name, monitor_path=r_job.monitor, vault_path=r_job.vault, **{**OPTIONS, **KEPT})
	assert committed is False and taken
	assert not manifest.in_transaction
	manifest.close()
	os.rmdir(taken[0])
	assert check_vault(r_job.job_vault, expected, set()) == []


# --- every item alone ---

@each_item
def test_an_item_leaves_every_version_exact(r_job, run_item, item):
	expected = run_item(item)
	assert check_vault(r_job.job_vault, expected, set()) == []


@each_item
def test_the_newest_version_holds_no_daemon_link(r_job, run_item, item):
	run_item(item)
	name = folder_of(r_job, 3)
	top = os.path.join(r_job.job_vault, name)
	found = []
	for folder, folders, files in os.walk(top):
		for entry in folders + files:
			path = os.path.join(folder, entry)
			if os.path.islink(path) and linked_place(name, os.path.relpath(path, top), os.readlink(path)) is not None:
				found.append(path)
	assert found == []


@each_item
def test_an_older_version_holds_forward_links_where_nothing_changed(r_job, run_item, item):
	expected = run_item(item)
	older, newer = folder_of(r_job, 2), folder_of(r_job, 3)
	for name in sorted(n for n in os.listdir(os.path.join(r_job.job_vault, older))):
		entries = lambda view: sorted((rel, entry) for rel, entry in view.items() if rel == name or rel.startswith(name + '/'))
		if entries(expected[2]) == entries(expected[3]):
			path = os.path.join(r_job.job_vault, older, name)
			assert os.readlink(path) == forward_text(name, newer), name


def test_a_folder_changed_deep_is_unfolded_only_on_the_way_there(r_job, run_item):
	run_item('three_levels_deep')
	older, newer = folder_of(r_job, 2), folder_of(r_job, 3)
	top = os.path.join(r_job.job_vault, older)
	for rel in ('g', 'g/h', 'g/h/i'):
		assert not os.path.islink(os.path.join(top, rel)) and os.path.isdir(os.path.join(top, rel))
	for rel in ('g/top.txt', 'g/up', 'g/h/other.txt'):
		assert os.readlink(os.path.join(top, rel)) == forward_text(rel, newer), rel
	with open(os.path.join(top, 'g/h/i/j.txt')) as f:
		assert f.read() == 'j0'
	with open(os.path.join(top, 'g/h/i/gone.txt')) as f:
		assert f.read() == 'gone0'


def test_a_failed_copy_keeps_the_last_copy_in_both_versions(r_job, run_item):
	expected = run_item('folder_over_folder')
	assert check_vault(r_job.job_vault, expected, set()) == []
	rel = f'w/x{UNREADABLE}'
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), rel))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), rel))
	assert (older.st_dev, older.st_ino) == (newer.st_dev, newer.st_ino) and not os.path.islink(os.path.join(r_job.job_vault, folder_of(r_job, 2), rel))
	with open(os.path.join(r_job.job_vault, folder_of(r_job, 3), rel)) as f:
		assert f.read() == 'b0'
	# one never copied is in no version
	assert not os.path.lexists(os.path.join(r_job.job_vault, folder_of(r_job, 3), f'w/fresh{UNREADABLE}'))


def test_a_non_osa_attrib_records_then_copies(r_job, run_item):
	expected = run_item('attrib')
	assert check_vault(r_job.job_vault, expected, set()) == []
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'top.txt'))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'top.txt'))
	assert older.st_ino != newer.st_ino
	assert (older.st_mode & 0o777, newer.st_mode & 0o777) == (expected[2]['top.txt'].mode, 0o600)


def test_an_osa_attrib_changes_the_shared_inode_in_place(r_job):
	build_base(r_job, **KEPT, only_sync_attributes=True)
	inode = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'top.txt')).st_ino
	events = item_attrib(r_job.monitor)
	backup_events(r_job, events, **KEPT, only_sync_attributes=True)
	older, newer = folder_of(r_job, 2), folder_of(r_job, 3)
	assert os.lstat(os.path.join(r_job.job_vault, newer, 'top.txt')).st_ino == inode
	assert os.readlink(os.path.join(r_job.job_vault, older, 'top.txt')) == forward_text('top.txt', newer)
	assert read_view(r_job.job_vault, older)['top.txt'].mode == 0o600


def test_a_folder_attrib_makes_the_folder_real(r_job, run_item):
	expected = run_item('folder_chmod')
	older, newer = folder_of(r_job, 2), folder_of(r_job, 3)
	path = os.path.join(r_job.job_vault, older, 'b')
	assert not os.path.islink(path) and os.lstat(path).st_mode & 0o777 == expected[2]['b'].mode != 0o700
	assert os.lstat(os.path.join(r_job.job_vault, newer, 'b')).st_mode & 0o777 == 0o700
	assert os.readlink(os.path.join(path, 'y.txt')) == forward_text('b/y.txt', newer)


@pytest.mark.parametrize('only_sync_attributes', [True, False], ids=['osa', 'no_osa'])
def test_the_whole_mixed_batch_is_exact(r_job, copies_fail, only_sync_attributes):
	options = dict(KEPT, only_sync_attributes=only_sync_attributes)
	expected = build_base(r_job, **options)
	copies_fail()
	apply_batch3(r_job)
	expected[3] = expected_of(snapshot_tree(r_job.monitor), expected[2])
	entries, touched = batch3_of(r_job)
	_, manifest, committed = rv.do_backup(entries, job_name=r_job.job_name, monitor_path=r_job.monitor, vault_path=r_job.vault, touched=touched,
		matched_since=rv.time.time_ns(), **{**OPTIONS, **options})
	manifest.close()
	assert committed is True
	# spec section 2.4: under Only Sync Attributes the versions sharing a file show its new attributes
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=only_sync_attributes) == []
	# the newest version is the monitored tree, whatever else
	view = read_view(r_job.job_vault, folder_of(r_job, 3))
	assert sorted(rel for rel in view if view[rel] != expected[3].get(rel)) == []


# --- the two rules the prototype left open ---

def test_a_file_removed_by_hand_then_copied_again_reads_missing_in_the_older_versions(r_job):
	build_base(r_job, **KEPT)
	newest = os.path.join(r_job.job_vault, folder_of(r_job, 2))
	# one at the top, whose forward link stands in an older version, and one in a folder an older version forwards
	os.remove(os.path.join(newest, 'top.txt'))
	os.remove(os.path.join(newest, 'c/z.txt'))
	before = {number: read_view(r_job.job_vault, folder_of(r_job, number)) for number in (0, 1, 2)}
	put_text(r_job.monitor, 'top.txt', 'again')
	put_text(r_job.monitor, 'c/z.txt', 'again')
	backup_events(r_job, [(False, 'modify', 'top.txt', None), (False, 'modify', 'c/z.txt', None)], **KEPT)
	for number in (1, 2):
		view = read_view(r_job.job_vault, folder_of(r_job, number))
		for rel in ('top.txt', 'c/z.txt'):
			assert rel not in view or view[rel].kind == 'dangling', (number, rel)
		assert {rel: entry for rel, entry in view.items() if entry.kind != 'dangling'} == {rel: entry for rel, entry in before[number].items() if entry.kind != 'dangling'}
	assert read_view(r_job.job_vault, folder_of(r_job, 0))['top.txt'].kind == 'f'
	with open(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'top.txt')) as f:
		assert f.read() == 'again'


def removed_after_the_hand_over(monkeypatch, *rels):
	'''A hand removes rels from the tree just after the hand-over, so the previous version's links to them lead nowhere.'''
	real = rv.hand_over
	def removing(job_vault, newest, new, *rest):
		writer = real(job_vault, newest, new, *rest)
		for rel in rels:
			path = os.path.join(new, rel)
			shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
		return writer
	monkeypatch.setattr(rv, 'hand_over', removing)


def test_a_forward_link_whose_entry_is_gone_goes_with_a_warning_and_the_job_goes_on(r_job, monkeypatch, capsys):
	build_base(r_job, **KEPT)
	removed_after_the_hand_over(monkeypatch, 'top.txt', 'c')
	put_text(r_job.monitor, 'top.txt', 'again')
	put_text(r_job.monitor, 'c/z.txt', 'again')
	backup_events(r_job, [(False, 'modify', 'top.txt', None), (True, 'create', 'c', None)], **KEPT)
	# the plugin sees the hand's removal as what it is: version 2 lost those paths, and only those
	wrong = take_wrong()
	assert wrong and all("'top.txt'" in line or "'c" in line for line in wrong)
	view = read_view(r_job.job_vault, folder_of(r_job, 2))
	assert 'top.txt' not in view and 'c' not in view
	# never the new copy, in any older version
	for number in (0, 1):
		older = read_view(r_job.job_vault, folder_of(r_job, number))
		assert older.get('top.txt') is None or older['top.txt'].data != snapshot_tree(r_job.monitor)['top.txt'].data
		assert older.get('c/z.txt') is None or older['c/z.txt'].data != snapshot_tree(r_job.monitor)['c/z.txt'].data
	newest = read_view(r_job.job_vault, folder_of(r_job, 3))
	assert sorted(rel for rel, entry in snapshot_tree(r_job.monitor).items() if rel and newest.get(rel) != entry) == []
	assert os.path.join(folder_of(r_job, 2), 'top.txt') in capsys.readouterr().out


def test_a_forward_link_whose_entry_is_gone_fails_the_attempt_on_a_pool(r_job, monkeypatch):
	build_base(r_job, **KEPT)
	real = rv.hand_over
	def removing(job_vault, newest, new, *rest):
		writer = real(job_vault, newest, new, *rest)
		os.remove(os.path.join(new, 'top.txt'))
		monkeypatch.setattr(rv, 'pool_state', lambda *args, **kwargs: object())
		return writer
	monkeypatch.setattr(rv, 'hand_over', removing)
	put_text(r_job.monitor, 'top.txt', 'again')
	with pytest.raises(rv.JobFailure, match='top.txt'):
		backup_events(r_job, [(False, 'modify', 'top.txt', None)], **KEPT)
	take_wrong()


def test_a_moved_file_with_new_attributes_keeps_version_n_without_osa(r_job):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'q.txt'), at(r_job.monitor, 'b/q.txt'))
	os.chmod(at(r_job.monitor, 'b/q.txt'), 0o600)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/q.txt', 'q.txt'), (False, 'attrib', 'b/q.txt', None)], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'q.txt'))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'b/q.txt'))
	assert older.st_mode & 0o777 == expected[2]['q.txt'].mode != 0o600
	assert older.st_ino != newer.st_ino and newer.st_mode & 0o777 == 0o600


@pytest.mark.parametrize('only_sync_attributes', [True, False], ids=['osa', 'no_osa'])
def test_a_move_takes_its_attributes_with_no_verification_to_find_them(r_job, only_sync_attributes):
	# a do_backup with no touched scopes: the replay's own step is all there is
	options = dict(KEPT, only_sync_attributes=only_sync_attributes)
	expected = build_base(r_job, **options)
	os.rename(at(r_job.monitor, 'q.txt'), at(r_job.monitor, 'b/q.txt'))
	os.chmod(at(r_job.monitor, 'b/q.txt'), 0o600)
	expected[3] = snapshot_tree(r_job.monitor)
	entries = rv.OrderedDict([event_entry(r_job, 'b/q.txt', 'move', 'q.txt')])
	run_backup(r_job, entries, **{**OPTIONS, **options})
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=only_sync_attributes) == []
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'q.txt'))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'b/q.txt'))
	assert newer.st_mode & 0o777 == 0o600 and (older.st_ino == newer.st_ino) == only_sync_attributes


def test_a_moved_file_with_a_new_xattr_keeps_version_n_without_osa(r_job):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'q.txt'), at(r_job.monitor, 'b/q.txt'))
	os.setxattr(at(r_job.monitor, 'b/q.txt'), 'user.tag', b'new')
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/q.txt', 'q.txt')], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_moved_file_with_new_attributes_stays_shared_under_osa(r_job):
	options = dict(KEPT, only_sync_attributes=True)
	expected = build_base(r_job, **options)
	os.rename(at(r_job.monitor, 'q.txt'), at(r_job.monitor, 'b/q.txt'))
	os.chmod(at(r_job.monitor, 'b/q.txt'), 0o600)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/q.txt', 'q.txt'), (False, 'attrib', 'b/q.txt', None)], **options)
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=True) == []
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'q.txt'))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'b/q.txt'))
	assert older.st_ino == newer.st_ino and newer.st_mode & 0o777 == 0o600


def test_a_moved_file_with_the_same_attributes_stays_shared_without_osa(r_job):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'q.txt'), at(r_job.monitor, 'b/q.txt'))
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/q.txt', 'q.txt')], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []
	older = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'q.txt'))
	newer = os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'b/q.txt'))
	# no second copy of the bytes for a move
	assert older.st_ino == newer.st_ino


@pytest.mark.parametrize('with_attrib_event', [True, False], ids=['event', 'found_by_verification'])
def test_a_moved_folders_file_with_new_attributes_keeps_version_n_without_osa(r_job, with_attrib_event):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'd'), at(r_job.monitor, 'e'))
	os.chmod(at(r_job.monitor, 'e/g'), 0o600)
	expected[3] = snapshot_tree(r_job.monitor)
	events = [(True, 'move', 'e', 'd')] + ([(False, 'attrib', 'e/g', None)] if with_attrib_event else [])
	backup_events(r_job, events, **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []
	assert expected[2]['d/g'].mode != 0o600
	assert os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'd/g')).st_mode & 0o777 == expected[2]['d/g'].mode


def test_a_moved_folders_xattr_change_keeps_version_n_without_osa(r_job):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'd'), at(r_job.monitor, 'e'))
	os.setxattr(at(r_job.monitor, 'e/g'), 'user.tag', b'new')
	os.setxattr(at(r_job.monitor, 'e'), 'user.folder', b'new')
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(True, 'move', 'e', 'd')], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_moved_user_link_with_a_new_owner_keeps_version_n_without_osa(r_job):
	expected = build_base(r_job, **KEPT)
	os.rename(at(r_job.monitor, 'lnk'), at(r_job.monitor, 'b/lnk'))
	os.lchown(at(r_job.monitor, 'b/lnk'), 1234, 1235)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/lnk', 'lnk')], **KEPT)
	assert check_vault(r_job.job_vault, expected, set()) == []


def test_a_moved_user_link_with_a_new_owner_stays_shared_under_osa(r_job):
	options = dict(KEPT, only_sync_attributes=True)
	expected = build_base(r_job, **options)
	os.rename(at(r_job.monitor, 'lnk'), at(r_job.monitor, 'b/lnk'))
	os.lchown(at(r_job.monitor, 'b/lnk'), 1234, 1235)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'move', 'b/lnk', 'lnk')], **options)
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=True) == []
	assert os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'b/lnk')).st_uid == 1234


def test_an_osa_attrib_on_a_user_link_changes_it_in_place(r_job):
	options = dict(KEPT, only_sync_attributes=True)
	expected = build_base(r_job, **options)
	os.lchown(at(r_job.monitor, 'lnk'), 1234, 1235)
	expected[3] = snapshot_tree(r_job.monitor)
	backup_events(r_job, [(False, 'attrib', 'lnk', None)], **options)
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=True) == []
	assert os.lstat(os.path.join(r_job.job_vault, folder_of(r_job, 3), 'lnk')).st_uid == 1234
	assert os.path.islink(os.path.join(r_job.job_vault, folder_of(r_job, 2), 'lnk'))


def test_a_users_link_in_the_tree_is_read_as_a_link_whatever_its_text_says(tmp_path):
	# the same shape as a 0.54 chain link, whose version is there: on R nothing in the tree is the daemon's
	stamp = '2021-01-01_00-00-00_-0800'
	job_vault = tmp_path / 'job'
	tree = job_vault / f'V2--{stamp}'
	(job_vault / f'V1--{stamp}').mkdir(parents=True)
	tree.mkdir()
	(job_vault / f'V1--{stamp}' / 'a').write_text('old')
	os.symlink(f'../V1--{stamp}/a', tree / 'a')
	record = rv.read_vault_record(str(tree), 'a', str(tmp_path / 'monitor'), rv.TREE_LINKS, copy_version=0)
	assert (record.kind, record.link) == ('l', f'../V1--{stamp}/a')


def test_a_batch_on_r_makes_no_referenced_copy_and_retargets_no_link(r_job, monkeypatch):
	build_base(r_job, **KEPT)
	called = []
	monkeypatch.setattr(rv, 'do_referenced_copy', lambda *args, **kwargs: called.append('copy'))
	monkeypatch.setattr(rv, 'retarget_moved_links', lambda *args, **kwargs: called.append('retarget'))
	# to another folder depth, which is what asks for a re-target on 0.54
	backup_events(r_job, item_move_then_changes(r_job.monitor), **KEPT)
	assert called == []


def test_a_verification_reads_the_tree_with_no_daemon_link(r_job):
	# compare_scopes() and record_dirty_entries() take the layout from the manifest, in the batch's own transaction
	build_base(r_job, **KEPT)
	put_text(r_job.monitor, 'top.txt', 't3')
	backup_events(r_job, [(False, 'modify', 'top.txt', None)], **KEPT)
	manifest = rv.VaultManifest(r_job.job_vault)
	record = manifest.lookup('top.txt')
	link = manifest.lookup('lnk')
	manifest.close()
	assert record.kind == 'f' and (link.kind, link.link) == ('l', 'a/x.txt')


# --- the oracle catches what it must ---

def test_the_old_whole_folder_swap_fails_the_oracle(r_job, run_item, monkeypatch):
	# spec section 2.2's old rule: a folder created over a folder swapped the whole folder into the previous version
	def whole_swap(self, rel):
		if self.previous is not None:
			self.record(rel, False)
		return rv.make_real_folder(self.path(rel))
	monkeypatch.setattr(rv.TreeWriter, 'make_folder', whole_swap)
	expected = run_item('folder_over_folder')
	assert check_vault(r_job.job_vault, expected, set()) != []


def test_a_missing_deep_unfold_fails_the_oracle(r_job, run_item, monkeypatch):
	real = rv.TreeWriter.ensure_real
	# only the first level is unfolded, so a record two levels down finds nothing to do
	monkeypatch.setattr(rv.TreeWriter, 'ensure_real', lambda self, folder: real(self, folder) if folder.count('/') < 1 else False)
	expected = run_item('three_levels_deep')
	assert check_vault(r_job.job_vault, expected, set()) != []
	# and the plugin reads the same version as broken, in the same batch
	assert any('g/h/i/j.txt' in line for line in take_wrong())


# --- the entries a backup leaves alone, and the attributes of a user's link ---

def without(view, *prefixes):
	'''view without the entries at or under the rels (folders without their /).'''
	return {rel: entry for rel, entry in view.items() if not any(rel == prefix or rel.startswith(prefix + '/') for prefix in prefixes)}


def test_a_skip_list_leaves_its_entries_out_of_the_newest_version_and_in_the_older(r_job):
	for rel, text in (('a.txt', 'a0'), ('cache/x.bin', 'x'), ('cache/deep/y.bin', 'y'), ('noise.log', 'n'), ('sub/b.txt', 'b0'), ('sub/keep.log', 'k')):
		put_text(r_job.monitor, rel, text)
	first = snapshot_tree(r_job.monitor)
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	# a list the vault has not met: a full comparison finds what it holds of the list's paths, and the next version leaves them out
	put_text(r_job.monitor, 'a.txt', 'a1')
	put_text(r_job.monitor, 'noise2.log', 'n2')
	skip_list = rv.SkipList(r_job.monitor, ['cache/', '*.log', '!sub/keep.log'])
	run_backup(r_job, only_sync_attributes=False, skip_list=skip_list, **KEPT)
	second = without(snapshot_tree(r_job.monitor), 'cache', 'noise.log', 'noise2.log')
	assert 'cache' not in second and 'sub/keep.log' in second
	assert check_vault(r_job.job_vault, {0: first, 1: second}, set()) == []
	# and the list holds from then on: a file it skips is not copied, the others are
	put_text(r_job.monitor, 'cache/more.bin', 'm')
	put_text(r_job.monitor, 'sub/b.txt', 'b1')
	run_backup(r_job, only_sync_attributes=False, skip_list=skip_list, **KEPT)
	third = without(snapshot_tree(r_job.monitor), 'cache', 'noise.log', 'noise2.log')
	assert check_vault(r_job.job_vault, {0: first, 1: second, 2: third}, set()) == []


def test_a_paused_inner_mount_keeps_its_last_backed_up_contents_in_the_newest_version(r_job, monkeypatch):
	for rel, text in (('a.txt', 'a0'), ('disk/f.txt', 'f'), ('disk/sub/g.txt', 'g')):
		put_text(r_job.monitor, rel, text)
	def mounted(*rels):
		table = [('/', ('1',))] + [(os.path.join(r_job.monitor, rel.rstrip('/')), (rel,)) for rel in rels]
		monkeypatch.setattr(rv, 'current_mount_table', lambda: table)
	mounted('disk/')
	before = snapshot_tree(r_job.monitor)
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	# the disk goes: its mount point looks like an empty folder, and the vault keeps what it held of it
	shutil.rmtree(at(r_job.monitor, 'disk'))
	os.mkdir(at(r_job.monitor, 'disk'))
	mounted()
	put_text(r_job.monitor, 'a.txt', 'a1')
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=r_job.job_name, monitor_path=r_job.monitor, vault_path=r_job.vault,
		keep_one_complete_backup=True, only_sync_attributes=False, keep_n_versions=0, backup_size_limit='0')
	try:
		assert committed is True and manifest.inner_mounts == ['disk/']
	finally:
		manifest.close()
	paused = {rel: entry for rel, entry in before.items() if rel == 'disk' or rel.startswith('disk/')}
	after = {**without(snapshot_tree(r_job.monitor), 'disk'), **paused}
	assert check_vault(r_job.job_vault, {0: before, 1: after}, set()) == []
	# the disk is back, with another file: the next version holds what it holds
	put_text(r_job.monitor, 'disk/h.txt', 'h')
	mounted('disk/')
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	third = snapshot_tree(r_job.monitor)
	assert check_vault(r_job.job_vault, {0: before, 1: after, 2: third}, set(), folder_times=False) == []


@pytest.mark.chain_ground_truth_allows('blind_spot', reason='the user link is made with the text of a chain link to the version before on purpose')
def test_the_attributes_of_a_users_link_go_on_the_link_itself_in_the_tree(r_job, monkeypatch):
	# Only Sync Attributes: a file's attributes go on the end of its chain, and in the tree of design R there is no chain: a link is a user's,
	# also one whose text has the form of 0.54's chain link to the version before the one being made (../<that version>/<its own path>). To have
	# the name of a version before it is made, every version folder gets the same time in its name; the plugin reads that link as a daemon
	# link to nowhere, and no oracle can tell them apart, so the vault is looked at by hand
	monkeypatch.setattr(rv, 'VAULT_TIMESTAMP_FORMAT', '2030-01-01_00-00-00_-0800')
	rv.is_version_folder_name.cache_clear()
	rv.is_previous_version_name.cache_clear()
	try:
		build_base(r_job, only_sync_attributes=True, **KEPT)
		link = at(r_job.monitor, 'ulink')
		text = '../V3--2030-01-01_00-00-00_-0800/ulink'
		os.symlink(text, link)
		backup_events(r_job, [(False, 'create', 'ulink', None)], only_sync_attributes=True, **KEPT)
		os.chown(link, 1234, 1235, follow_symlinks=False)
		os.utime(link, ns=(5 * 10 ** 18, 5 * 10 ** 18), follow_symlinks=False)
		# no chain is followed from a link of the tree
		followed = []
		real = rv.vault_chain_hop
		monkeypatch.setattr(rv, 'vault_chain_hop', lambda job_vault, link_path, *args: followed.append(link_path) or real(job_vault, link_path, *args))
		backup_events(r_job, [(False, 'attrib', 'ulink', None)], only_sync_attributes=True, **KEPT)
		assert [path for path in followed if path.endswith('/ulink')] == []
		path = os.path.join(r_job.job_vault, folder_of(r_job, 4), 'ulink')
		st = os.lstat(path)
		assert (stat.S_ISLNK(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns, os.readlink(path)) == (True, 1234, 1235, 5 * 10 ** 18, text)
	finally:
		take_wrong()
		rv.is_version_folder_name.cache_clear()
		rv.is_previous_version_name.cache_clear()


def test_a_users_link_with_the_text_of_a_daemon_link_is_no_daemon_link_in_the_newest_version(r_job):
	# the oracle reads such a link as a daemon link to nowhere, but what it flags as a daemon link in the newest version of an R vault is
	# a link the monitored tree does not hold with that text
	put_text(r_job.monitor, 'a', 'a')
	os.symlink('../V1--2030-01-01_00-00-00_-0800/ulink', at(r_job.monitor, 'ulink'))
	expected = {0: snapshot_tree(r_job.monitor)}
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	def flagged(want):
		return [line for line in check_vault(r_job.job_vault, want, set()) if 'daemon link' in line]
	assert flagged(expected) == []
	assert len(flagged({0: without(expected[0], 'ulink')})) == 1
	assert len(flagged({0: {**expected[0], 'ulink': expected[0]['ulink']._replace(data='elsewhere')}})) == 1


# --- the plugin ---

@pytest.mark.old_writer
def test_the_plugin_reads_nothing_of_a_054_vault(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	put_text(job.monitor, 'a', 'a')
	read = []
	monkeypatch.setattr(view_truth, 'read_view', lambda *args: read.append(args))
	run_backup(job)
	put_text(job.monitor, 'a', 'b')
	run_backup(job)
	assert read == []


def test_the_plugin_reads_the_versions_of_an_r_vault(r_job, monkeypatch):
	build_base(r_job, **KEPT)
	read = []
	real = view_truth.read_view
	monkeypatch.setattr(view_truth, 'read_view', lambda job_vault, name: read.append(name) or real(job_vault, name))
	backup_events(r_job, item_modify(r_job.monitor), **KEPT)
	# each of the three, before the batch and after it
	assert sorted(read) == sorted(2 * [folder_of(r_job, number) for number in (0, 1, 2)])


def test_the_plugin_lets_a_dangling_link_go_and_nothing_else(tmp_path):
	job_vault = tmp_path / 'job'
	job_vault.mkdir()
	name = 'V0--x'
	(job_vault / name).mkdir()
	(job_vault / name / 'kept').write_text('a')
	os.symlink('../V1--y/gone', job_vault / name / 'gone')
	before = {name: read_view(str(job_vault), name)}
	assert before[name]['gone'].kind == 'dangling'
	os.remove(job_vault / name / 'gone')
	assert view_truth.differences(str(job_vault), before, False) == []
	(job_vault / name / 'kept').write_text('b')
	assert view_truth.differences(str(job_vault), before, False) != []
