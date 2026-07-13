import os
import tempfile
import unittest
from collections import OrderedDict

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
			open(os.path.join(monitor, 'a.txt'), 'w').write('hi')
			job_vault = os.path.join(vault, job)
			v0 = os.path.join(job_vault, 'V0--2021-01-01_00-00-00_-0800')
			os.makedirs(v0)
			open(os.path.join(v0, 'a.txt'), 'w').write('hi')
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


if __name__ == '__main__':
	unittest.main()
