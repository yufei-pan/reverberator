import os
import pytest
import reverberator as rv
from tests.harness import write_committed_version, write_incomplete_version, content_file_path

pytestmark = pytest.mark.unit


def test_get_vault_info_indexes_committed_only(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'x'})
	write_incomplete_version(job, 1, {'a.txt': 'y'})
	info = rv.get_vault_info(job.job_vault)
	assert os.path.isdir(v0)
	assert 0 in info.vault_info_dict
	assert 1 not in info.vault_info_dict
	assert info.vault_info_dict[0].path == v0
	assert not os.path.isdir(os.path.join(job.job_vault, 'V1--2021-01-02_00-00-00_-0800'))


def test_get_vault_info_keeps_committed_when_content_file_listed_first(job, monkeypatch):
	# Reverting the post-scan orphan discard must fail: scandir can yield the
	# content file before V0, so the in-loop discard misses the later dir add.
	v0 = write_committed_version(job, 0, {'a.txt': 'x'})
	v1 = write_incomplete_version(job, 1, {'a.txt': 'y'})
	real_scandir = os.scandir

	def content_files_before_dirs(path):
		entries = list(real_scandir(path))
		entries.sort(key=lambda e: (
			0 if e.is_file() and rv.CONTENT_FILE_EXTENSION_NAME in e.name else 1,
			e.name,
		))
		return iter(entries)

	monkeypatch.setattr(rv.os, 'scandir', content_files_before_dirs)
	info = rv.get_vault_info(job.job_vault)
	assert os.path.isdir(v0)
	assert 0 in info.vault_info_dict
	assert not os.path.isdir(v1)


def test_content_file_path_matches_production_formula(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	expected = content_file_path(v0)
	assert os.path.isfile(expected)


def test_get_vault_info_recalculate_refreshes_size(job):
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	info = rv.get_vault_info(job.job_vault, recalculate=True)
	assert 0 in info.vault_info_dict
	assert info.vault_info_dict[0].size == rv.get_path_size(v0)
	assert info.vault_info_dict[0].inode == rv.get_path_inodes(v0)
