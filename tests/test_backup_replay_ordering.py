import os
import tempfile
import unittest
from collections import OrderedDict, deque

import reverberator as rv
import pytest
from tests.harness import tracked_manifest

pytestmark = pytest.mark.unit


class TestCpAfCreatesParentDirs(unittest.TestCase):
	def test_cp_creates_missing_parent_directories(self):
		with tempfile.TemporaryDirectory() as root:
			src = os.path.join(root, 'src.txt')
			with open(src, 'w') as f:
				f.write('hello')
			dst = os.path.join(root, 'missing', 'nested', 'dst.txt')
			self.assertFalse(os.path.isdir(os.path.dirname(dst)))
			ok = rv.cp_af_copy_path(src, dst)
			self.assertEqual(ok, 0)
			self.assertTrue(os.path.isfile(dst))
			with open(dst) as f:
				self.assertEqual(f.read(), 'hello')


class TestPruneEntriesUnderDirCreates(unittest.TestCase):
	def test_child_creates_and_modifies_under_dir_create_are_pruned(self):
		entries = OrderedDict([
			('/mon/a/b/c.txt', rv.BackupEntryValues('t1', 'create', None)),
			('/mon/a/b/d.txt', rv.BackupEntryValues('t2', 'modify', None)),
			('/mon/a/b/', rv.BackupEntryValues('t3', 'create', None)),
			('/mon/a/other.txt', rv.BackupEntryValues('t4', 'create', None)),
			('/mon/a/b/gone.txt', rv.BackupEntryValues('t5', 'delete', None)),
		])
		pruned = rv.prune_entries_covered_by_dir_creates(entries)
		self.assertNotIn('/mon/a/b/c.txt', pruned)
		self.assertNotIn('/mon/a/b/d.txt', pruned)
		self.assertIn('/mon/a/b/', pruned)
		self.assertIn('/mon/a/other.txt', pruned)
		# deletes under a created dir are kept (may still matter chronologically)
		self.assertIn('/mon/a/b/gone.txt', pruned)

	def test_nested_dir_creates_under_ancestor_create_are_pruned(self):
		entries = OrderedDict([
			('/mon/venv/lib/', rv.BackupEntryValues('t1', 'create', None)),
			('/mon/venv/', rv.BackupEntryValues('t2', 'create', None)),
			('/mon/venv/lib/x.py', rv.BackupEntryValues('t3', 'create', None)),
		])
		pruned = rv.prune_entries_covered_by_dir_creates(entries)
		self.assertEqual(list(pruned.keys()), ['/mon/venv/'])

	def test_entries_the_walk_of_a_create_skips_for_a_move_are_kept(self):
		# mkdir n; mv d n/d; chmod n/d/y; mkdir n/d/s; echo > n/d/s/f: the create of n/ leaves n/d to its move, so the
		# chmod and the create of n/d/s stay, and n/d/s/f is left to the create of n/d/s
		entries = OrderedDict([
			('/mon/n/', rv.BackupEntryValues('t1', 'create', None)),
			('/mon/n/d/', rv.BackupEntryValues('t2', 'move', '/mon/d/')),
			('/mon/n/d/y', rv.BackupEntryValues('t3', 'attrib', None)),
			('/mon/n/d/s/', rv.BackupEntryValues('t4', 'create', None)),
			('/mon/n/d/s/f', rv.BackupEntryValues('t5', 'create', None)),
			('/mon/n/x', rv.BackupEntryValues('t6', 'modify', None)),
			('/mon/n/dx', rv.BackupEntryValues('t7', 'modify', None)),
		])
		pruned = rv.prune_entries_covered_by_dir_creates(entries)
		self.assertEqual(list(pruned.keys()), ['/mon/n/', '/mon/n/d/', '/mon/n/d/y', '/mon/n/d/s/'])


class TestOrderBackupEntriesForReplay(unittest.TestCase):
	def test_dir_creates_come_before_descendant_file_creates(self):
		entries = OrderedDict([
			('/mon/venv/lib/x.py', rv.BackupEntryValues('t1', 'create', None)),
			('/mon/venv/', rv.BackupEntryValues('t2', 'create', None)),
		])
		ordered = rv.order_backup_entries_for_replay(entries)
		keys = list(ordered.keys())
		self.assertLess(keys.index('/mon/venv/'), keys.index('/mon/venv/lib/x.py'))

	def test_deletes_come_before_creates_on_overlapping_trees(self):
		entries = OrderedDict([
			('/mon/venv/a.py', rv.BackupEntryValues('t1', 'create', None)),
			('/mon/old/', rv.BackupEntryValues('t2', 'delete', None)),
		])
		ordered = rv.order_backup_entries_for_replay(entries)
		keys = list(ordered.keys())
		self.assertLess(keys.index('/mon/old/'), keys.index('/mon/venv/a.py'))

	def test_deeper_deletes_before_shallower_deletes(self):
		entries = OrderedDict([
			('/mon/a/', rv.BackupEntryValues('t1', 'delete', None)),
			('/mon/a/b.txt', rv.BackupEntryValues('t2', 'delete', None)),
		])
		ordered = rv.order_backup_entries_for_replay(entries)
		keys = list(ordered.keys())
		self.assertLess(keys.index('/mon/a/b.txt'), keys.index('/mon/a/'))

	def test_changes_at_or_under_a_move_destination_after_the_move_come_after_the_moves(self):
		entries = OrderedDict([
			('/m/e/', rv.BackupEntryValues('t1', 'move', '/m/d/')),
			('/m/e/y', rv.BackupEntryValues('t2', 'attrib', None)),
			('/m/e/new', rv.BackupEntryValues('t3', 'create', None)),
			('/m/x', rv.BackupEntryValues('t4', 'modify', None)),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/x', '/m/e/', '/m/e/y', '/m/e/new'])

	def test_changes_before_a_move_stay_before_it(self):
		entries = OrderedDict([
			('/m/d/y', rv.BackupEntryValues('t1', 'attrib', None)),
			('/m/e/', rv.BackupEntryValues('t2', 'move', '/m/d/')),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/d/y', '/m/e/'])

	def test_a_change_at_a_move_source_after_the_move_comes_after_it(self):
		entries = OrderedDict([
			('/m/f~', rv.BackupEntryValues('t1', 'move', '/m/f')),
			('/m/f', rv.BackupEntryValues('t2', 'create', None)),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/f~', '/m/f'])

	def test_a_delete_holding_a_move_source_comes_right_after_the_last_move_out_of_it(self):
		# mv d/g y; mv d/s z; rm -r d; echo > d; mv q e: the delete of d/ after the moves out of it, the file in its place
		# after the delete, and the move that came later after them both; the other deletes stay at the front
		entries = OrderedDict([
			('/m/y', rv.BackupEntryValues('t1', 'move', '/m/d/g')),
			('/m/z/', rv.BackupEntryValues('t2', 'move', '/m/d/s/')),
			('/m/d/k', rv.BackupEntryValues('t3', 'delete', None)),
			('/m/d/', rv.BackupEntryValues('t4', 'delete', None)),
			('/m/d', rv.BackupEntryValues('t5', 'create', None)),
			('/m/e', rv.BackupEntryValues('t6', 'move', '/m/q')),
			('/m/x/', rv.BackupEntryValues('t7', 'delete', None)),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()),
			['/m/d/k', '/m/x/', '/m/y', '/m/z/', '/m/d/', '/m/d', '/m/e'])

	def test_nested_deletes_holding_move_sources_come_deepest_first_after_their_moves(self):
		entries = OrderedDict([
			('/m/y', rv.BackupEntryValues('t1', 'move', '/m/d/e/g')),
			('/m/d/e/', rv.BackupEntryValues('t2', 'delete', None)),
			('/m/d/', rv.BackupEntryValues('t3', 'delete', None)),
			('/m/w', rv.BackupEntryValues('t4', 'move', '/m/v')),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/y', '/m/d/e/', '/m/d/', '/m/w'])

	def test_a_delete_with_a_later_move_into_it_before_the_last_move_out_stays_at_the_front(self):
		# rm -r d; mv q d/q; mv d/q y, as the collapse can keep them: the move into d/ has to come after the delete and
		# the move out of it after that, so no order replays both and the delete stays where it was
		entries = OrderedDict([
			('/m/d/', rv.BackupEntryValues('t1', 'delete', None)),
			('/m/d/q', rv.BackupEntryValues('t2', 'move', '/m/q')),
			('/m/y', rv.BackupEntryValues('t3', 'move', '/m/d/q')),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/d/', '/m/d/q', '/m/y'])

	def test_a_move_into_it_before_the_delete_goes_before_it_too(self):
		# mv e d/s/b; mv d/s z; rm -r d: the delete after both moves
		entries = OrderedDict([
			('/m/d/s/b/', rv.BackupEntryValues('t1', 'move', '/m/e/')),
			('/m/z/', rv.BackupEntryValues('t2', 'move', '/m/d/s/')),
			('/m/d/', rv.BackupEntryValues('t3', 'delete', None)),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/d/s/b/', '/m/z/', '/m/d/'])

	def test_a_delete_with_a_later_move_onto_or_out_of_a_folder_above_it_stays_at_the_front(self):
		# rm -r d/s; mv d D; mv x d; mv d/s/g y: after the moves of d, d/s names x's folder, not the removed one
		entries = OrderedDict([
			('/m/d/s/', rv.BackupEntryValues('t1', 'delete', None)),
			('/m/D/', rv.BackupEntryValues('t2', 'move', '/m/d/')),
			('/m/d/', rv.BackupEntryValues('t3', 'move', '/m/x/')),
			('/m/y', rv.BackupEntryValues('t4', 'move', '/m/d/s/g')),
		])
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/d/s/', '/m/D/', '/m/d/', '/m/y'])
		# and only out of it ( mv d D, then a move out of the D/s the version still holds as d/s, as the collapse gives it )
		del entries['/m/d/']
		self.assertEqual(list(rv.order_backup_entries_for_replay(entries).keys()), ['/m/d/s/', '/m/D/', '/m/y'])


class TestReverbBackupNewTreeFileBeforeParent(unittest.TestCase):
	def test_new_tree_succeeds_when_entries_list_files_before_dirs(self):
		"""Regression: V27-style file-before-parent create lists must not ENOENT."""
		with tempfile.TemporaryDirectory() as root:
			monitor = os.path.join(root, 'mon')
			vault = os.path.join(root, 'vault')
			job_vault = os.path.join(vault, 'job')
			v0 = os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800')
			v1 = os.path.join(job_vault, 'V1--2021-01-02_00-00-00_-0800')
			os.makedirs(v0)
			os.makedirs(monitor)
			os.makedirs(v1)
			# Prior version has no pkg/ tree
			with open(os.path.join(monitor, 'keep.txt'), 'w') as f:
				f.write('k')
			with open(os.path.join(v0, 'keep.txt'), 'w') as f:
				f.write('k')
			pkg = os.path.join(monitor, 'pkg', 'sub')
			os.makedirs(pkg)
			with open(os.path.join(pkg, 'a.py'), 'w') as f:
				f.write('print(1)')
			tracking = tracked_manifest(job_vault, v0, ['keep.txt'])
			# Deliberately list file create before parent dir creates (buggy delta order)
			entries = OrderedDict([
				(os.path.join(pkg, 'a.py'), rv.BackupEntryValues('t1', 'create', None)),
				(os.path.join(monitor, 'pkg') + '/', rv.BackupEntryValues('t2', 'create', None)),
				(os.path.join(monitor, 'pkg', 'sub') + '/', rv.BackupEntryValues('t3', 'create', None)),
			])
			rv.GREEN_LIGHT.set()
			latest = rv.VaultEntry(0, v0, 0, 1, 1)
			result = rv.do_reverb_backup(entries, v1, latest, True, tracking, monitor)
			dst = os.path.join(v1, 'pkg', 'sub', 'a.py')
			self.assertTrue(os.path.isfile(dst), f'missing {dst}')
			with open(dst) as f:
				self.assertEqual(f.read(), 'print(1)')
			self.assertIn('pkg/sub/a.py', result.files)
			self.assertIn('pkg/', result.folders)


class TestChangeEventsParentOrdering(unittest.TestCase):
	def test_mkdir_then_file_is_covered_by_dir_create_after_prepare(self):
		events = deque([
			rv.ChangeEvent(1.0, True, 'create', '/tmp/reverb_order/d', None),
			rv.ChangeEvent(2.0, False, 'create', '/tmp/reverb_order/d/f.txt', None),
		])
		entries = rv.change_events_to_backup_entries(events)
		prepared = rv.prepare_backup_entries_for_replay(entries)
		self.assertIn('/tmp/reverb_order/d/', prepared)
		self.assertNotIn('/tmp/reverb_order/d/f.txt', prepared)
		self.assertEqual(prepared['/tmp/reverb_order/d/'].event, 'create')


if __name__ == '__main__':
	unittest.main()
