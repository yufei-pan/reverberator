import os
import pytest
import reverberator as rv
from tests.harness import change_list_of, event_entry, run_backup, seed_monitor
from tests.vault_oracle import sizes_by_newest_holder
from tests.vaults import version_name, write_version

pytestmark = pytest.mark.unit


def two_versions(job):
	'''V0 and V1 of a real vault, and the tree of a cut batch, which has no list: its path.'''
	seed_monitor(job, {'a.txt': 'x', 'b.txt': 'b'})
	run_backup(job)
	seed_monitor(job, {'a.txt': 'y'})
	run_backup(job, dict([event_entry(job, 'a.txt', 'modify')]))
	return write_version(job.job_vault, 2, {'a.txt': 'partial'})


def test_get_vault_info_indexes_committed_only(job):
	tree = two_versions(job)
	info = rv.get_vault_info(job.job_vault)
	assert list(info.vault_info_dict) == [0, 1]
	# what is not committed is a cut batch's tree, the only real one the next batch finishes
	assert info.tree == tree and os.path.isdir(tree)


class Listing(list):
	'''What os.scandir() hands back, in an order the test sets: the daemon iterates it bare and in a with.'''
	def __enter__(self):
		return self

	def __exit__(self, *_):
		return False


def test_get_vault_info_keeps_committed_when_content_file_listed_first(job, monkeypatch):
	# Reverting the post-scan orphan discard must fail: scandir can yield the
	# content file before V0, so the in-loop discard misses the later dir add.
	tree = two_versions(job)
	real_scandir = os.scandir

	def content_files_before_dirs(path):
		with real_scandir(path) as listing:
			entries = list(listing)
		entries.sort(key=lambda e: (
			0 if e.is_file() and rv.CONTENT_FILE_EXTENSION_NAME in e.name else 1,
			e.name,
		))
		return Listing(entries)

	monkeypatch.setattr(rv.os, 'scandir', content_files_before_dirs)
	info = rv.get_vault_info(job.job_vault)
	assert list(info.vault_info_dict) == [0, 1] and info.tree == tree


def test_change_list_path_matches_production_formula(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = run_backup(job)[0]
	assert change_list_of(v0) == rv.change_list_path(v0, *sizes_by_newest_holder(job.job_vault)[0])


def test_get_vault_info_reads_the_sizes_a_list_names(job):
	# what the newest holder counts: no du of the folder, which a forward link would take for nothing or for everything
	two_versions(job)
	os.rename(os.path.join(job.job_vault, version_name(2)), os.path.join(job.root, 'out'))
	sizes = sizes_by_newest_holder(job.job_vault)
	for recalculate in (False, True):
		info = rv.get_vault_info(job.job_vault, recalculate=recalculate)
		assert {number: (entry.size, entry.inode) for number, entry in info.vault_info_dict.items()} == sizes
