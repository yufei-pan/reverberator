import os
import tempfile
import unittest
import reverberator as rv


class TestRemoveIncompleteVaultVersions(unittest.TestCase):
	def test_deletes_vdir_without_content_file_keeps_committed(self):
		with tempfile.TemporaryDirectory() as job_vault:
			committed = os.path.join(job_vault, 'V1--2021-01-01_00-00-00_-0800')
			orphan = os.path.join(job_vault, 'V2--2021-01-02_00-00-00_-0800')
			os.makedirs(committed)
			os.makedirs(orphan)
			open(os.path.join(committed, 'f.txt'), 'w').write('x')
			content = (
				f'{committed}--1_B-1_ino{rv.CONTENT_FILE_EXTENSION_NAME}'
			)
			open(content, 'w').write('path\tiso_time\tevent\tsource_path\n')
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
			open(os.path.join(orphan, 'x'), 'w').write('y')
			info = rv.get_vault_info(job_vault)
			self.assertFalse(os.path.isdir(orphan))
			self.assertNotIn(3, info.vault_info_dict)


if __name__ == '__main__':
	unittest.main()
