'''
Round 20: sizes under design R. The size in a change list's name is what that version alone holds (spec section 6), and the
retention loops rely on it, so each number here is held against the independent oracle's (tests/vault_oracle.py) or against
what the disk really gives back. Also the commit's rename of the previous version's list, the R prune and the inode estimate.
'''
import errno
import fcntl
import os
import shutil
import stat
import time
from collections import OrderedDict, deque

import pytest

import reverberator as rv
from tests.crash_batches import OPTIONS, UNREADABLE, apply_batch1, apply_batch2, apply_batch3, batch3_of, build_base, expected_of, put_text, raw_events, seed_base
from tests.crash_child import failing_copy_command
from tests.harness import copy_now, create_job
from tests.test_r_batch import ITEMS, each_item, take_wrong
from tests.test_tree_writer import V2, deep_vault, source_file
from tests.vault_oracle import check_vault, sizes_by_newest_holder, snapshot_tree, version_number

ONE_MIB = 1 << 20


class Run:
	'''A job's batches as the backuper runs them: its vaultInfo and manifest handed from one to the next.'''
	def __init__(self, job, **options):
		self.job = job
		self.options = {**OPTIONS, **options}
		self.info = None
		self.manifest = None

	def backup(self, entries=None, touched=None, **options):
		self.info, self.manifest, committed = rv.do_backup(OrderedDict() if entries is None else entries, job_name=self.job.job_name, monitor_path=self.job.monitor,
			vault_path=self.job.vault, vaultInfo=self.info, manifest=self.manifest, touched=touched, matched_since=time.time_ns(), **{**self.options, **options})
		assert committed is True

	def events(self, events, **options):
		raw = raw_events(self.job.monitor, events)
		self.backup(rv.change_events_to_backup_entries(deque(raw), self.job.monitor), rv.touched_scopes(raw, self.job.monitor), **options)

	def base(self):
		'''Batches 0-2 of the crash vault, the lists right after each.'''
		os.makedirs(self.job.job_vault, exist_ok=True)
		seed_base(self.job.monitor)
		self.backup()
		assert_sizes(self)
		for apply_batch in (apply_batch1, apply_batch2):
			self.events(apply_batch(self.job.monitor))
			assert_sizes(self)

	def close(self):
		if self.manifest is not None:
			self.manifest.close()
			self.manifest = None


@pytest.fixture
def r_job(tmp_path):
	return create_job(str(tmp_path))


@pytest.fixture
def run(r_job):
	runs = []
	def make(**options):
		runs.append(Run(r_job, **options))
		return runs[-1]
	yield make
	for one in runs:
		one.close()


def folders_of(job):
	return {version_number(name): name for name in os.listdir(job.job_vault) if version_number(name) is not None}


def lists_of(job):
	return {name for name in os.listdir(job.job_vault) if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)}


def assert_sizes(run_):
	'''
	Each kept version's list names what the oracle counts, and what the batch returned says it to the byte for the two
	versions it just wrote, as a name rounds.
	'''
	job = run_.job
	truth = sizes_by_newest_holder(job.job_vault)
	folders = folders_of(job)
	assert set(truth) == set(folders)
	wanted = {os.path.basename(rv.change_list_path(os.path.join(job.job_vault, folders[number]), *truth[number])) for number in truth}
	assert lists_of(job) == wanted, truth
	for number in sorted(truth)[-2:]:
		entry = run_.info.vault_info_dict[number]
		assert (entry.size, entry.inode) == truth[number], number
	assert run_.info.vault_size == sum(entry.size for entry in run_.info.vault_info_dict.values())
	assert run_.info.vault_inodes == sum(entry.inode for entry in run_.info.vault_info_dict.values())


def really_held(job) -> tuple:
	'''(bytes, inodes) every version folder holds on the disk, each inode once: files by size, folders at 4 KiB, links no bytes; no version's root.'''
	seen = set()
	size = 0
	for name in folders_of(job).values():
		pending = [os.path.join(job.job_vault, name)]
		while pending:
			with os.scandir(pending.pop()) as entries:
				for entry in entries:
					st = entry.stat(follow_symlinks=False)
					if (st.st_dev, st.st_ino) in seen:
						continue
					seen.add((st.st_dev, st.st_ino))
					if stat.S_ISDIR(st.st_mode):
						size += 4096
						pending.append(entry.path)
					elif stat.S_ISREG(st.st_mode):
						size += st.st_size
	return size, len(seen)


# --- what each list names ---

def test_each_list_names_what_its_version_alone_holds(r_job, run, monkeypatch):
	one = run()
	one.base()
	monkeypatch.setattr(rv, 'copy_command', failing_copy_command(rv.copy_command))
	# spec section 9's mixed batch, then more over what it left
	apply_batch3(r_job)
	entries, touched = batch3_of(r_job)
	one.backup(entries, touched)
	assert_sizes(one)
	put_text(r_job.monitor, 'y', 'y4 is longer')
	os.rename(os.path.join(r_job.monitor, 'e'), os.path.join(r_job.monitor, 'e2'))
	shutil.rmtree(os.path.join(r_job.monitor, 's1'))
	one.events([(False, 'modify', 'y', None), (True, 'move', 'e2', 'e'), (True, 'delete', 's1', None)])
	assert_sizes(one)
	put_text(r_job.monitor, 'e2/m.txt', 'again')
	os.remove(os.path.join(r_job.monitor, 'y'))
	one.events([(False, 'modify', 'e2/m.txt', None), (False, 'delete', 'y', None)])
	assert_sizes(one)
	# a full comparison finds nothing left to do
	one.backup()
	assert_sizes(one)


@each_item
@pytest.mark.parametrize('only_sync_attributes', [False, True])
def test_each_item_alone_keeps_every_list_right_through_a_real_prune(r_job, run, item, only_sync_attributes, monkeypatch):
	one = run(only_sync_attributes=only_sync_attributes)
	expected = build_base(r_job, only_sync_attributes=only_sync_attributes)
	monkeypatch.setattr(rv, 'copy_command', failing_copy_command(rv.copy_command))
	events = ITEMS[item](r_job.monitor)
	expected[3] = expected_of(snapshot_tree(r_job.monitor), expected[2])
	one.events(events)
	assert_sizes(one)
	# keep-N 3: version 0 went, and nothing that stays changed
	del expected[0]
	assert sorted(folders_of(r_job)) == [1, 2, 3]
	assert check_vault(r_job.job_vault, expected, set(), free_file_meta=only_sync_attributes) == []


def test_the_first_version_names_the_tree(r_job, run):
	put_text(r_job.monitor, 'a/x', '12345')
	os.symlink('a/x', os.path.join(r_job.monitor, 'lnk'))
	one = run()
	one.backup()
	assert_sizes(one)
	# the folder and the file and the link: no version's root is counted
	assert sizes_by_newest_holder(r_job.job_vault)[0] == (4096 + 5, 3)


def test_a_lost_manifest_still_names_the_tree_by_what_it_holds(r_job, run):
	# rows listed again from the tree hold no record, and a size of no bytes would leave the tree out of the size limit
	one = run()
	one.base()
	one.close()
	one.info = None
	os.remove(os.path.join(r_job.job_vault, '.reverberator_manifest.sqlite'))
	put_text(r_job.monitor, 'top.txt', 'after the loss')
	shutil.rmtree(os.path.join(r_job.monitor, 'big'))
	one.events([(False, 'modify', 'top.txt', None), (True, 'delete', 'big', None)])
	assert_sizes(one)


# --- removing ---

def test_removing_the_oldest_frees_its_size(r_job, run):
	one = run()
	one.base()
	for i in range(3):
		put_text(r_job.monitor, 'top.txt', f'top {i} ' * 100)
		shutil.rmtree(os.path.join(r_job.monitor, 'big/inner'), ignore_errors=True)
		os.rename(os.path.join(r_job.monitor, 'a/x.txt' if i == 0 else f'moved{i - 1}.txt'), os.path.join(r_job.monitor, f'moved{i}.txt'))
		one.events([(False, 'modify', 'top.txt', None), (True, 'delete', 'big/inner', None), (False, 'move', f'moved{i}.txt', 'a/x.txt' if i == 0 else f'moved{i - 1}.txt')], keep_n_versions=0)
		assert_sizes(one)
	while len(one.info.vault_info_dict) > 1:
		before = really_held(r_job)
		oldest = next(iter(one.info.vault_info_dict))
		truth = sizes_by_newest_holder(r_job.job_vault)[oldest]
		named = one.info.vault_info_dict[oldest]
		assert rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True) == (named.size, named.inode) == truth
		after = really_held(r_job)
		assert (before[0] - after[0], before[1] - after[1]) == truth, oldest


def test_a_folder_removed_counts_all_it_held(r_job, run):
	# an exchanged folder is counted from its rows, in one query
	one = run()
	one.base()
	big = sum(os.lstat(os.path.join(root, name)).st_size for root, _, names in os.walk(os.path.join(r_job.monitor, 'big')) for name in names)
	shutil.rmtree(os.path.join(r_job.monitor, 'big'))
	one.events([(True, 'delete', 'big', None)], keep_n_versions=0)
	assert_sizes(one)
	assert sizes_by_newest_holder(r_job.job_vault)[2][0] == 2 * 4096 + big


def test_a_failed_copy_counts_nothing_into_the_previous_version(r_job, run, monkeypatch):
	name = f'f{UNREADABLE}'
	put_text(r_job.monitor, name, 'held in both')
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	monkeypatch.setattr(rv, 'copy_command', failing_copy_command(rv.copy_command))
	put_text(r_job.monitor, name, 'cannot be read')
	one.events([(False, 'modify', name, None)])
	assert_sizes(one)
	# the tree holds it, so version 0 holds no byte alone; and its one link there, for the other top entry
	assert sizes_by_newest_holder(r_job.job_vault)[0] == (0, 1)
	assert one.info.vault_info_dict[0].size == 0


def test_a_placed_copy_counts_the_old_file_into_the_previous_version(r_job, run):
	put_text(r_job.monitor, 'f', 'old old old')
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	put_text(r_job.monitor, 'f', 'new')
	one.events([(False, 'modify', 'f', None)])
	assert_sizes(one)
	assert one.info.vault_info_dict[0][3:] == (len('old old old'), 2)


def test_a_moved_entry_counts_nothing_into_the_previous_version(r_job, run):
	put_text(r_job.monitor, 'd/inner/one', '1' * 100)
	put_text(r_job.monitor, 'd/two', '2' * 200)
	os.symlink('two', os.path.join(r_job.monitor, 'd/lnk'))
	put_text(r_job.monitor, 'f', 'f' * 300)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	os.rename(os.path.join(r_job.monitor, 'd'), os.path.join(r_job.monitor, 'e'))
	os.rename(os.path.join(r_job.monitor, 'f'), os.path.join(r_job.monitor, 'g'))
	one.events([(True, 'move', 'e', 'd'), (False, 'move', 'g', 'f')])
	assert_sizes(one)
	# only the folders made anew: d and d/inner, the link there and the top link of other. the files are the tree's
	assert one.info.vault_info_dict[0][3:] == (2 * 4096, 4)


@pytest.mark.parametrize('case', ['move_then_replace', 'move_then_delete', 'folder_move_then_delete', 'folder_move_then_replace', 'move_then_new_at_the_source'])
def test_a_drop_of_a_moved_inode_in_its_own_batch_counts_in_it(r_job, run, case, monkeypatch):
	# the entry's new path has no record to make, as the previous version never held it there, yet the previous version alone holds the inode now
	put_text(r_job.monitor, 'f', 'f' * 300)
	put_text(r_job.monitor, 'd/x', 'x' * 400)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	m = r_job.monitor
	writer_rel = {'move_then_replace': ('f', 'g'), 'move_then_delete': ('f', 'g'), 'folder_move_then_delete': ('d', 'e'), 'folder_move_then_replace': ('d', 'e'), 'move_then_new_at_the_source': ('f', 'g')}[case]
	real_rename = rv.TreeWriter.rename
	def rename_then_change(self, src, dst):
		done = real_rename(self, src, dst)
		# the tree changes right after the move, by the verbs a later entry of the batch uses
		if case == 'move_then_replace':
			temp = self.path('g') + '.new'
			with open(temp, 'w') as f:
				f.write('new')
			self.record('g', True)
			self.place(temp, 'g')
			self.manifest.add('g', dirty=True)
		elif case == 'move_then_delete':
			self.remove_now('g')
			self.manifest.discard('g')
		elif case == 'folder_move_then_delete':
			self.remove_now('e')
			self.manifest.remove_tree('e/')
		elif case == 'folder_move_then_replace':
			temp = self.path('e/x') + '.new'
			with open(temp, 'w') as f:
				f.write('new')
			self.record('e/x', True)
			self.place(temp, 'e/x')
			self.manifest.add('e/x', dirty=True)
		elif case == 'move_then_new_at_the_source':
			temp = self.path('f') + '.new'
			with open(temp, 'w') as f:
				f.write('new')
			self.record('f', True)
			self.place(temp, 'f')
			self.manifest.add('f', dirty=True)
		return done
	monkeypatch.setattr(rv.TreeWriter, 'rename', rename_then_change)
	try:
		os.rename(os.path.join(m, writer_rel[0]), os.path.join(m, writer_rel[1]))
		one.backup(rv.change_events_to_backup_entries(deque(raw_events(m, [(writer_rel[0] == 'd', 'move', writer_rel[1], writer_rel[0])])), m))
	finally:
		monkeypatch.undo()
	assert_sizes(one)
	entry = one.info.vault_info_dict[0]
	if case == 'move_then_new_at_the_source':
		# the tree still holds the moved file at g: nothing goes to version 0
		assert entry.size == 0
	elif case in ('move_then_replace', 'move_then_delete'):
		assert entry.size == 300
	else:
		assert entry.size == 4096 + 400


def test_a_later_drop_of_a_shared_inode_counts_in_the_batch_that_drops_it(r_job, run):
	put_text(r_job.monitor, 'f', 'f' * 300)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	os.rename(os.path.join(r_job.monitor, 'f'), os.path.join(r_job.monitor, 'g'))
	one.events([(False, 'move', 'g', 'f')])
	assert_sizes(one)
	assert one.info.vault_info_dict[0].size == 0
	os.remove(os.path.join(r_job.monitor, 'g'))
	one.events([(False, 'delete', 'g', None)])
	assert_sizes(one)
	# version 1 is the newest that holds it now; version 0 shares it and still counts nothing
	assert one.info.vault_info_dict[1].size == 300
	assert sizes_by_newest_holder(r_job.job_vault)[0][0] == 0
	# so version 1 frees it only once version 0 has gone first
	before = really_held(r_job)
	rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True)
	assert before[0] == really_held(r_job)[0]
	rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True)
	assert before[0] - 300 == really_held(r_job)[0]


def test_a_failed_copy_that_a_later_batch_replaces_counts_in_that_batch(r_job, run, monkeypatch):
	name = f'f{UNREADABLE}'
	put_text(r_job.monitor, name, 'held in both')
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	failing = failing_copy_command(rv.copy_command)
	working = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', failing)
	put_text(r_job.monitor, name, 'cannot be read')
	one.events([(False, 'modify', name, None)])
	assert_sizes(one)
	monkeypatch.setattr(rv, 'copy_command', working)
	put_text(r_job.monitor, name, 'can be read now')
	one.events([(False, 'modify', name, None)])
	assert_sizes(one)
	assert one.info.vault_info_dict[1].size == len('held in both')


def test_a_refused_hard_link_counts_the_copy_it_makes(r_job, run, monkeypatch):
	put_text(r_job.monitor, 'f', 'f' * 300)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	def refused(*args, **kwargs):
		raise OSError(errno.EMLINK, 'too many links')
	monkeypatch.setattr(rv.os, 'link', refused)
	os.rename(os.path.join(r_job.monitor, 'f'), os.path.join(r_job.monitor, 'g'))
	one.events([(False, 'move', 'g', 'f')])
	assert_sizes(one)
	assert one.info.vault_info_dict[0][3:] == (300, 2)


def test_a_forward_link_removed_with_its_entry_counts_no_inode(r_job, run, monkeypatch):
	put_text(r_job.monitor, 'f', 'f' * 300)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	# removed from the tree by hand once the batch has handed it over
	real_hand_over = rv.hand_over
	def then_by_hand(*args, **kwargs):
		writer = real_hand_over(*args, **kwargs)
		os.remove(writer.path('f'))
		return writer
	monkeypatch.setattr(rv, 'hand_over', then_by_hand)
	try:
		os.remove(os.path.join(r_job.monitor, 'f'))
		one.events([(False, 'delete', 'f', None)])
	finally:
		monkeypatch.undo()
	# version 0 read as holding it until the hand did that, as the view plugin saw
	assert any("'f'" in line for line in take_wrong())
	assert sizes_by_newest_holder(r_job.job_vault)[0] == (0, 1)
	assert one.info.vault_info_dict[0][3:] == (0, 1)


def test_a_forward_text_too_long_counts_what_is_held_real(tmp_path):
	# links cannot hold this deep a path, so the record holds the entries real: folders, hard links of files, hard links of links
	levels = 1500
	job_vault, newest = deep_vault(str(tmp_path), levels)
	deepest = '/'.join(['d'] * levels)
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert copy_now(writer, source_file(str(tmp_path)), deepest + '/f') == 0
	assert writer.sizes.result() == sizes_by_newest_holder(job_vault)[1]


def test_a_moved_folder_whose_files_the_tree_lets_go_later_counts_them(tmp_path):
	job_vault, newest = deep_vault(str(tmp_path), 3)
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert writer.rename('d', 'moved')
	assert writer.sizes.result() == sizes_by_newest_holder(job_vault)[1]
	writer.remove_now('moved/d')
	assert writer.sizes.result() == sizes_by_newest_holder(job_vault)[1]
	writer.remove_now('moved')
	assert writer.sizes.result() == sizes_by_newest_holder(job_vault)[1]


def test_a_move_over_a_folder_counts_the_folder_it_replaces(r_job, run):
	# the rows of the target are the source's by the time it is recorded
	put_text(r_job.monitor, 'src/one', '1' * 100)
	put_text(r_job.monitor, 'dst/old', '2' * 2000)
	put_text(r_job.monitor, 'dst/deep/older', '3' * 3000)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	shutil.rmtree(os.path.join(r_job.monitor, 'dst'))
	os.rename(os.path.join(r_job.monitor, 'src'), os.path.join(r_job.monitor, 'dst'))
	one.backup(OrderedDict([rv_entry(r_job, 'dst/', 'src/')]), touched=None)
	assert_sizes(one)
	assert one.info.vault_info_dict[0].size == 2 * 4096 + 5000 + 4096


def test_a_move_of_a_folder_with_no_files_over_a_folder_counts_the_folder_it_replaces(r_job, run):
	# moved rows of files hold no record, which would send the count to a walk anyway; a moved folder of folders has none of those
	os.makedirs(os.path.join(r_job.monitor, 'src/empty'))
	put_text(r_job.monitor, 'dst/old', '2' * 2000)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	shutil.rmtree(os.path.join(r_job.monitor, 'dst'))
	os.rename(os.path.join(r_job.monitor, 'src'), os.path.join(r_job.monitor, 'dst'))
	one.backup(OrderedDict([rv_entry(r_job, 'dst/', 'src/')]), touched=None)
	assert_sizes(one)
	# dst and its file, src and its folder made anew by hard links
	assert one.info.vault_info_dict[0].size == 4096 + 2000 + 2 * 4096


def test_the_tree_counts_a_moved_file_whose_row_has_no_record(r_job, run):
	# a move with no verification after it leaves its rows unverified until the next comparison, and a sum of rows alone would count them as no bytes
	put_text(r_job.monitor, 'f', 'f' * 5000)
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	os.rename(os.path.join(r_job.monitor, 'f'), os.path.join(r_job.monitor, 'g'))
	one.backup(OrderedDict([rv_entry(r_job, 'g', 'f')]), touched=None)
	assert one.manifest.lookup('g').kind is None
	assert one.info.vault_info_dict[1].size == 5005


def rv_entry(job, rel, source):
	return os.path.join(job.monitor, rel), rv.BackupEntryValues('2026-11-05T00:00:00', 'move', os.path.join(job.monitor, source))


# --- the commit ---

def test_the_commit_renames_the_previous_list_and_names_it_first(r_job, run, monkeypatch):
	put_text(r_job.monitor, 'f', 'old')
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	old_list = next(iter(lists_of(r_job)))
	order = []
	real_commit = rv.VaultManifest.commit
	def commit(self, version_path=None):
		order.append(('commit', self.previous_list(), set(lists_of(r_job)) == {old_list}))
		return real_commit(self, version_path)
	real_swap, real_rename, real_place = rv.swap_current_version, os.rename, rv.place_change_list
	def swap(*args):
		order.append('swap')
		return real_swap(*args)
	def rename(src, dst, **kwargs):
		if os.path.basename(src) == old_list:
			order.append(('rename', os.path.basename(dst)))
		return real_rename(src, dst, **kwargs)
	def place(*args):
		order.append('place')
		return real_place(*args)
	monkeypatch.setattr(rv.VaultManifest, 'commit', commit)
	monkeypatch.setattr(rv, 'swap_current_version', swap)
	monkeypatch.setattr(rv.os, 'rename', rename)
	monkeypatch.setattr(rv, 'place_change_list', place)
	put_text(r_job.monitor, 'f', 'new')
	one.events([(False, 'modify', 'f', None)])
	monkeypatch.undo()
	assert_sizes(one)
	new_name = os.path.basename(rv.change_list_path(os.path.join(r_job.job_vault, folders_of(r_job)[0]), *sizes_by_newest_holder(r_job.job_vault)[0]))
	assert new_name != old_list
	assert order == [('commit', {'from': old_list, 'to': new_name}, True), 'swap', ('rename', new_name), 'place']


def test_the_commit_syncs_nothing_between_the_previous_list_and_the_new_one(r_job, run, monkeypatch):
	# the scan renames the previous list whenever its old name is still there, so a power loss may keep the placement and lose the rename (tests/test_r_scan.py)
	put_text(r_job.monitor, 'f', 'old')
	put_text(r_job.monitor, 'other', 'other')
	one = run(keep_n_versions=0)
	one.backup()
	old_list = next(iter(lists_of(r_job)))
	order = []
	real_rename, real_sync, real_place = os.rename, rv.fsync_vault_folder, rv.place_change_list
	def rename(src, dst, **kwargs):
		if os.path.basename(src) == old_list:
			order.append('rename')
		return real_rename(src, dst, **kwargs)
	def sync(path):
		order.append('sync')
		return real_sync(path)
	def place(*args):
		order.append('place')
		return real_place(*args)
	monkeypatch.setattr(rv.os, 'rename', rename)
	monkeypatch.setattr(rv, 'fsync_vault_folder', sync)
	monkeypatch.setattr(rv, 'place_change_list', place)
	put_text(r_job.monitor, 'f', 'new')
	one.events([(False, 'modify', 'f', None)])
	monkeypatch.undo()
	at = order.index('rename')
	assert order[at:at + 2] == ['rename', 'place']


def test_a_previous_list_that_is_gone_fails_the_attempt_before_the_commit(r_job, run):
	put_text(r_job.monitor, 'f', 'old')
	one = run(keep_n_versions=0)
	one.backup()
	committed_as = one.manifest.conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
	os.remove(os.path.join(r_job.job_vault, next(iter(lists_of(r_job)))))
	put_text(r_job.monitor, 'f', 'new')
	with pytest.raises(rv.JobFailure):
		one.events([(False, 'modify', 'f', None)])
	assert one.manifest.conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone() == committed_as


def normalized(info) -> dict:
	'''{number: the list name it makes}: a scan reads sizes off names, which a commit's numbers round to.'''
	return {number: (entry.path, os.path.basename(rv.change_list_path(entry.path, entry.size, entry.inode))) for number, entry in info.vault_info_dict.items()}


def test_vault_info_after_a_commit_equals_a_fresh_scan(r_job, run):
	one = run()
	one.base()
	for i in range(4):
		put_text(r_job.monitor, 'top.txt', f'top {i} ' * 1000)
		put_text(r_job.monitor, f'n{i}', 'x' * 5000)
		one.events([(False, 'modify', 'top.txt', None), (False, 'create', f'n{i}', None)])
		assert_sizes(one)
		scanned = rv.get_vault_info(r_job.job_vault)
		assert normalized(one.info) == normalized(scanned)
		# and the sums, each from the numbers it holds
		assert one.info.vault_inodes == sum(entry.inode for entry in one.info.vault_info_dict.values())
		assert scanned.vault_inodes == sum(entry.inode for entry in scanned.vault_info_dict.values())
		assert abs(one.info.vault_size - scanned.vault_size) <= 0.01 * one.info.vault_size


# --- the retention loops ---

def nested_tree(monitor):
	# few entries in each folder, so a version of links costs little. 660 rows
	for i in range(10):
		for j in range(65):
			put_text(monitor, f'd{i}/f{j}', 'x')


def test_an_inode_limit_counts_the_batch_not_the_tree(r_job, run):
	# a tree at 66% of the limit: counted twice it would pass it, and every version it may lose would go
	nested_tree(r_job.monitor)
	one = run(keep_n_versions=0, backup_size_limit='i1000')
	one.backup()
	for i in range(3):
		put_text(r_job.monitor, 'd0/f0', f'change {i}')
		one.events([(False, 'modify', 'd0/f0', None)])
		assert_sizes(one)
	assert sorted(folders_of(r_job)) == [0, 1, 2, 3]
	assert one.info.vault_inodes < 1000


def test_an_inode_limit_still_prunes_a_batch_that_would_pass_it(r_job, run):
	nested_tree(r_job.monitor)
	one = run(keep_n_versions=0, backup_size_limit='i1000')
	one.backup()
	put_text(r_job.monitor, 'd0/f0', 'change')
	one.events([(False, 'modify', 'd0/f0', None)])
	assert sorted(folders_of(r_job)) == [0, 1]
	for i in range(400):
		put_text(r_job.monitor, f'new/{i}', 'x')
	# 660 and the links of the one older version, and 401 more: past the limit, until the older version goes
	one.events([(True, 'create', 'new', None)])
	assert sorted(folders_of(r_job)) == [1, 2]
	assert_sizes(one)


def test_a_flat_tree_pays_its_links_against_the_limit(r_job, run):
	# one link per top entry per version: these are real inodes, and a limit that counts them prunes for them
	for i in range(600):
		put_text(r_job.monitor, f'f{i}', 'x')
	one = run(keep_n_versions=0, backup_size_limit='i1000')
	one.backup()
	for i in range(3):
		put_text(r_job.monitor, 'f0', f'change {i}')
		one.events([(False, 'modify', 'f0', None)])
		assert_sizes(one)
	assert len(folders_of(r_job)) == 2


def test_a_batch_that_removes_inodes_leaves_no_room_by_them(r_job, run):
	# they stay in the previous version, so the vault is no smaller: the estimate is floored at 0, and a vault over its limit still prunes
	for i in range(100):
		put_text(r_job.monitor, f'd/f{i}', 'x')
	put_text(r_job.monitor, 'top', 'x')
	one = run(keep_n_versions=0)
	one.backup()
	put_text(r_job.monitor, 'top', 'y')
	one.events([(False, 'modify', 'top', None)])
	assert sorted(folders_of(r_job)) == [0, 1]
	one.options['backup_size_limit'] = f'i{one.info.vault_inodes - 1}'
	shutil.rmtree(os.path.join(r_job.monitor, 'd'))
	one.events([(True, 'delete', 'd', None)])
	assert sorted(folders_of(r_job)) == [1, 2]
	assert_sizes(one)


def test_the_size_limit_loop_prunes_by_the_new_sizes(r_job, run):
	# a version counts what it alone holds, so a limit a little over three files' size keeps three versions of one changing file, and no fewer
	put_text(r_job.monitor, 'f', 'a' * ONE_MIB)
	one = run(keep_n_versions=0, backup_size_limit='3500000')
	one.backup()
	seen = []
	for i in range(1, 7):
		put_text(r_job.monitor, 'f', chr(ord('a') + i) * ONE_MIB)
		one.events([(False, 'modify', 'f', None)])
		assert_sizes(one)
		seen.append(sorted(folders_of(r_job)))
	assert seen == [[0, 1], [0, 1, 2], [1, 2, 3], [2, 3, 4], [3, 4, 5], [4, 5, 6]]
	assert one.info.vault_size == sum(sizes_by_newest_holder(r_job.job_vault)[n][0] for n in folders_of(r_job))


# --- the prune ---

def test_a_prune_stops_being_a_version_in_one_call(r_job, run, monkeypatch):
	one = run()
	one.base()
	folder = folders_of(r_job)[0]
	staged = os.path.join(r_job.job_vault, rv.STAGING_NAME, folder)
	seen = []
	real_rename = os.rename
	def rename(src, dst, **kwargs):
		done = real_rename(src, dst, **kwargs)
		if dst == staged:
			# in that one call the version is gone from the vault, whole, and the listing no longer has it
			listing = rv.read_job_vault(r_job.job_vault)
			seen.append((src, os.path.isdir(staged), os.path.lexists(src), sorted(listing.versions)))
		return done
	monkeypatch.setattr(rv.os, 'rename', rename)
	oldest = one.info.vault_info_dict[0]
	removed = rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True)
	monkeypatch.undo()
	assert seen == [(os.path.join(r_job.job_vault, folder), True, False, [1, 2])]
	assert sorted(folders_of(r_job)) == [1, 2]
	assert not any(name.startswith(folder) for name in os.listdir(r_job.job_vault))
	assert os.listdir(os.path.join(r_job.job_vault, rv.STAGING_NAME)) == []
	assert removed == (oldest.size, oldest.inode)
	assert 0 not in one.info.vault_info_dict


def test_a_prune_whose_removal_fails_still_stops_being_a_version(r_job, run, monkeypatch):
	one = run()
	one.base()
	size = one.info.vault_info_dict[0]
	class Failed:
		returncode = 1
		stderr = ['rm: cannot remove: I/O error']
		stdout = []
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda *args, **kwargs: Failed())
	removed = rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True)
	monkeypatch.undo()
	assert removed == (size.size, size.inode)
	assert sorted(folders_of(r_job)) == [1, 2]
	assert os.path.isdir(os.path.join(r_job.job_vault, rv.STAGING_NAME, os.path.basename(size.path)))


def test_a_prune_whose_rename_fails_keeps_the_version(r_job, run, monkeypatch):
	one = run()
	one.base()
	def refused(src, dst, **kwargs):
		raise OSError(errno.EIO, 'disk says no')
	monkeypatch.setattr(rv.os, 'rename', refused)
	removed = rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True)
	monkeypatch.undo()
	assert removed == (0, 0)
	assert sorted(one.info.vault_info_dict) == [0, 1, 2]
	assert sorted(folders_of(r_job)) == [0, 1, 2]
	assert_sizes(one)


def test_the_last_version_is_never_pruned(r_job, run):
	put_text(r_job.monitor, 'f', 'f')
	one = run()
	one.backup()
	assert rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True) == (0, 0)
	assert sorted(folders_of(r_job)) == [0]
	# nor does a batch's keep-N of one, or a limit no version can meet
	put_text(r_job.monitor, 'f', 'g')
	one.events([(False, 'modify', 'f', None)], keep_n_versions=1, backup_size_limit='1')
	assert sorted(folders_of(r_job)) == [0, 1]


def test_a_prune_waits_for_a_history_command(r_job, run, monkeypatch, tmp_path):
	one = run()
	one.base()
	state = tmp_path / 'state'
	state.mkdir()
	monkeypatch.setattr(rv, 'job_lock_path', lambda job_name, name: str(state / f'{job_name}.{name}.lock'))
	fd = os.open(str(state / f'{r_job.job_name}.history.lock'), os.O_CREAT | os.O_RDWR)
	fcntl.flock(fd, fcntl.LOCK_SH)
	try:
		assert rv.prune_oldest(one.info.vault_info_dict, r_job.job_name, r_job.monitor, on_tree=True) == (0, 0)
	finally:
		os.close(fd)
	assert sorted(folders_of(r_job)) == [0, 1, 2]


def test_a_prune_on_r_needs_no_secret(r_job, run):
	# the 0.54 prune's secret for its temps: design R has no temps, and the migration removes the file
	one = run()
	one.base()
	put_text(r_job.monitor, 'top.txt', 'again')
	one.events([(False, 'modify', 'top.txt', None)])
	assert sorted(folders_of(r_job)) == [1, 2, 3]
	assert not os.path.lexists(os.path.join(r_job.job_vault, rv.PRUNE_SALT_FILE_NAME))
