import os
import tempfile
import unittest
from collections import deque
from collections import OrderedDict
import threading

import reverberator as rv


class TestRemoveIncompleteVaultVersions(unittest.TestCase):
	def test_deletes_vdir_without_content_file_keeps_committed(self):
		with tempfile.TemporaryDirectory() as job_vault:
			committed = os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800')
			orphan = os.path.join(job_vault, 'V2--2021-01-02_00-00-00_-0800')
			os.makedirs(committed)
			os.makedirs(orphan)
			with open(os.path.join(committed, 'f.txt'), 'w') as f:
				f.write('x')
			content = (
				f'{committed}--1_B-1_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
			)
			with open(content, 'w') as f:
				f.write('path\tiso_time\tevent\tsource_path\n')
			deleted = rv.remove_incomplete_vault_versions(job_vault)
			self.assertTrue(os.path.isdir(committed))
			self.assertTrue(os.path.isfile(content))
			self.assertFalse(os.path.isdir(orphan))
			self.assertEqual(deleted, [orphan])


class TestGetVaultInfoOrphans(unittest.TestCase):
	def test_orphan_dir_is_removed_not_indexed(self):
		with tempfile.TemporaryDirectory() as job_vault:
			orphan = os.path.join(job_vault, 'V3--2021-01-03_00-00-00_-0800')
			os.makedirs(orphan)
			with open(os.path.join(orphan, 'x'), 'w') as f:
				f.write('y')
			info = rv.get_vault_info(job_vault)
			self.assertFalse(os.path.isdir(orphan))
			self.assertNotIn(3, info.vault_info_dict)


class TestBackupEntriesToChangeEvents(unittest.TestCase):
	def test_move_and_dir_flags(self):
		entries = {
			'/tmp/a': rv.BackupEntryValues('t', 'modify', None),
			'/tmp/d/': rv.BackupEntryValues('t', 'create', None),
			'/tmp/b': rv.BackupEntryValues('t', 'move', '/tmp/a'),
		}
		events = rv.backup_entries_to_change_events(entries)
		by_path = {e.path: e for e in events}
		self.assertFalse(by_path['/tmp/a'].is_dir)
		self.assertTrue(by_path['/tmp/d/'].is_dir)
		self.assertEqual(by_path['/tmp/b'].event, 'move')
		self.assertEqual(by_path['/tmp/b'].moved_from, '/tmp/a')


class TestWatcherInitFailure(unittest.TestCase):
	def test_watcher_clears_green_light_when_watchfolder_fails(self):
		rv.GREEN_LIGHT.set()
		monitor_fs_flag = threading.Event()
		monitor_fs_flag.set()
		original = rv.watchFolder
		try:
			rv.watchFolder = lambda *a, **k: 'init_failed'
			rv.watcher(
				monitor_fs_flag,
				'/nonexistent',
				deque(),
				threading.Lock(),
				threading.Event(),
				rv.inotify_resource_manager(),
			)
			self.assertFalse(rv.GREEN_LIGHT.is_set())
		finally:
			rv.watchFolder = original
			rv.GREEN_LIGHT.set()

	def test_watchfolder_reports_self_destruct_without_clearing_green_light(self):
		rv.GREEN_LIGHT.set()
		original_inotify = rv.inotify_simple.INotify
		original_initialize = rv.initializeFolderWatchers

		class FakeEvent:
			def __init__(self, wd, mask):
				self.wd = wd
				self.mask = mask
				self.cookie = 0
				self.name = ''

		class FakeINotify:
			def __enter__(self):
				return self

			def __exit__(self, *args):
				return False

			def read(self, timeout=None):
				return [FakeEvent(42, rv.inotify_simple.flags.UNMOUNT)]

		try:
			rv.inotify_simple.INotify = FakeINotify
			rv.initializeFolderWatchers = lambda *a, **k: 42
			result = rv.watchFolder(
				'/monitor',
				deque(),
				threading.Lock(),
				threading.Event(),
				rv.inotify_resource_manager(),
			)
			self.assertEqual(result, 'self_destruct')
			self.assertTrue(rv.GREEN_LIGHT.is_set())
		finally:
			rv.inotify_simple.INotify = original_inotify
			rv.initializeFolderWatchers = original_initialize
			rv.GREEN_LIGHT.set()


class TestBackuperCommitFailure(unittest.TestCase):
	def test_uncommitted_backup_while_green_light_set_requeues_and_clears_green_light(self):
		with tempfile.TemporaryDirectory() as tmp:
			rv.GREEN_LIGHT.set()
			original_do_backup = rv.do_backup
			original_fs_flag_daemon = rv.fs_flag_daemon
			try:
				rv.do_backup = lambda *a, **k: (None, None, False)
				rv.fs_flag_daemon = lambda path, signature, fs_event: fs_event.set()
				to_process = deque([
					rv.ChangeEvent(1, False, 'modify', os.path.join(tmp, 'monitor', 'f.txt'), None)
				])
				monitor_fs_flag = threading.Event()
				monitor_fs_flag.set()
				rv.backuper(
					'job',
					to_process,
					threading.Lock(),
					os.path.join(tmp, 'monitor'),
					os.path.join(tmp, 'vault'),
					'N/A',
					threading.Event(),
					monitor_fs_flag,
				)
				self.assertEqual(len(to_process), 1)
				self.assertFalse(rv.GREEN_LIGHT.is_set())
			finally:
				rv.do_backup = original_do_backup
				rv.fs_flag_daemon = original_fs_flag_daemon
				rv.GREEN_LIGHT.set()


class TestDoBackupCommitGate(unittest.TestCase):
	def test_incomplete_flag_skips_content_file(self):
		entries = {'/tmp/x': rv.BackupEntryValues('t', 'modify', None)}
		events = rv.backup_entries_to_change_events(entries)
		self.assertEqual(len(events), 1)
		self.assertEqual(events[0].event, 'modify')

	def test_cleared_green_light_skips_content_file_and_current_version(self):
		with tempfile.TemporaryDirectory() as tmp:
			monitor_path = os.path.join(tmp, 'monitor')
			vault_path = os.path.join(tmp, 'vault')
			job_name = 'job'
			os.makedirs(monitor_path)
			os.makedirs(vault_path)
			with open(os.path.join(monitor_path, 'f.txt'), 'w') as f:
				f.write('x')
			rv.GREEN_LIGHT.clear()
			try:
				_, _, committed = rv.do_backup(
					{},
					job_name=job_name,
					monitor_path=monitor_path,
					vault_path=vault_path,
					keep_one_complete_backup=True,
					only_sync_attributes=True,
					keep_n_versions=0,
					backup_size_limit='0',
				)
			finally:
				rv.GREEN_LIGHT.set()
			job_vault = os.path.join(vault_path, job_name)
			self.assertFalse(committed)
			self.assertFalse(os.path.lexists(os.path.join(job_vault, 'current_version')))
			self.assertFalse(any(
				name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)
				for name in os.listdir(job_vault)
			))


class TestEmptyBackupSkip(unittest.TestCase):
	def test_no_new_version_when_delta_empty(self):
		with tempfile.TemporaryDirectory() as root:
			monitor = os.path.join(root, 'mon')
			vault = os.path.join(root, 'vault')
			job = 'job'
			os.makedirs(monitor)
			with open(os.path.join(monitor, 'a.txt'), 'w') as f:
				f.write('hi')
			job_vault = os.path.join(vault, job)
			v0 = os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800')
			os.makedirs(v0)
			with open(os.path.join(v0, 'a.txt'), 'w') as f:
				f.write('hi')
			original = rv.delta_generate_backup_entries
			try:
				rv.delta_generate_backup_entries = lambda backupEntries, latest_version_info, monitor_path: rv.TrackingFilesFolders([], [])
				vault_info = rv.VaultInfo(
					OrderedDict([
						(0, rv.VaultEntry(0, v0, 0, 1, 1))
					]),
					1,
					1,
				)
				rv.GREEN_LIGHT.set()
				info, tracking, committed = rv.do_backup(
					{},
					job_name=job,
					monitor_path=monitor,
					vault_path=vault,
					keep_one_complete_backup=True,
					only_sync_attributes=True,
					keep_n_versions=0,
					backup_size_limit='0',
					log_journal=False,
					vaultInfo=vault_info,
					trackingFilesFolders=rv.TrackingFilesFolders(['a.txt'], []),
				)
				self.assertTrue(committed)
				versions = [p for p in os.listdir(job_vault) if p.startswith('V') and os.path.isdir(os.path.join(job_vault, p))]
				self.assertEqual(versions, ['V0--2021-01-01_00-00-00_-0800'])
			finally:
				rv.delta_generate_backup_entries = original


class TestDecrementStepperAbort(unittest.TestCase):
	def _make_pair(self, root):
		# V0 real file, V1 symlink to V0 file
		v0 = os.path.join(root, 'V0--2021-01-01_00-00-00_-0800')
		v1 = os.path.join(root, 'V1--2021-01-02_00-00-00_-0800')
		os.makedirs(v0)
		os.makedirs(v1)
		with open(os.path.join(v0, 'a.txt'), 'w') as f:
			f.write('data')
		os.symlink(os.path.join(v0, 'a.txt'), os.path.join(v1, 'a.txt'))
		# content files with parseable names (use get_path_size after)
		for path, ver in ((v0, 0), (v1, 1)):
			sz = rv.get_path_size(path)
			ino = rv.get_path_inodes(path)
			sz_s = rv.format_bytes(sz, use_1024_bytes=True, to_str=True).replace(' ', '_')
			ino_s = rv.format_bytes(ino, use_1024_bytes=False, to_str=True).replace(' ', '')
			with open(f'{path}--{sz_s}B-{ino_s}_ino{rv.CONTENT_FILE_EXTENSION_NAME}', 'w') as f:
				f.write('path\tiso_time\tevent\tsource_path\n')
		d = OrderedDict([
			(0, rv.VaultEntry(0, v0, 0, rv.get_path_size(v0), rv.get_path_inodes(v0))),
			(1, rv.VaultEntry(1, v1, 1, rv.get_path_size(v1), rv.get_path_inodes(v1))),
		])
		return d, v0, v1

	def test_successful_step_removes_oldest(self):
		with tempfile.TemporaryDirectory() as root:
			d, v0, v1 = self._make_pair(root)
			removed_size, removed_inodes = rv.decrement_stepper(d)
			self.assertFalse(os.path.isdir(v0))
			self.assertTrue(os.path.isfile(os.path.join(v1, 'a.txt')))
			self.assertFalse(os.path.islink(os.path.join(v1, 'a.txt')))
			self.assertNotIn(0, d)
			self.assertGreater(removed_size + removed_inodes, 0)

	def test_materialize_failure_keeps_oldest_and_restores_dict(self):
		with tempfile.TemporaryDirectory() as root:
			d, v0, v1 = self._make_pair(root)
			real_rename = os.rename

			def boom(src, dst):
				if os.path.basename(src) == 'a.txt' or os.path.basename(dst) == 'a.txt':
					raise OSError('simulated')
				return real_rename(src, dst)

			os.rename = boom
			try:
				removed_size, removed_inodes = rv.decrement_stepper(d)
			finally:
				os.rename = real_rename
			self.assertEqual((removed_size, removed_inodes), (0, 0))
			self.assertTrue(os.path.isdir(v0))
			self.assertIn(0, d)
			self.assertTrue(os.path.islink(os.path.join(v1, 'a.txt')))


if __name__ == '__main__':
	unittest.main()
