import os
import stat
import sys
import types
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None, keep_one_complete_backup=True):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=keep_one_complete_backup, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0')


def _assert_matches_du(job, manifest, version):
	assert rv.measure_version_usage(manifest, version) == (rv.get_path_size(version), rv.get_path_inodes(version))


@pytest.mark.parametrize('complete', [True, False])
def test_v0_usage_matches_du(job, poll_fast, complete):
	seed_monitor(job, {'a.txt': 'a' * 10000, 'd/e/f.bin': 'x' * 300000, 'empty/': None})
	os.symlink('a.txt', os.path.join(job.monitor, 'short'))
	os.symlink('d/' + 'n' * 200, os.path.join(job.monitor, 'long'))
	_, manifest, _ = _backup(job, keep_one_complete_backup=complete)
	_assert_matches_du(job, manifest, committed_versions(job)[0])
	manifest.close()


def test_replay_version_usage_matches_du(job, poll_fast):
	seed_monitor(job, {'keep.txt': 'k', 'old.txt': 'o' * 5000, 'sub/x.txt': 'x', 'deep/a/b/c.txt': 'c'})
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'old.txt'))
	open(os.path.join(job.monitor, 'new.bin'), 'w').write('n' * 70000)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	entries = OrderedDict()
	entries[os.path.join(job.monitor, 'old.txt')] = rv.BackupEntryValues('t', 'delete', None)
	entries[os.path.join(job.monitor, 'new.bin')] = rv.BackupEntryValues('t', 'create', None)
	entries[os.path.join(job.monitor, 'moved') + '/'] = rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')
	_, manifest, _ = _backup(job, entries)
	_assert_matches_du(job, manifest, committed_versions(job)[1])
	manifest.close()


def test_backup_no_longer_runs_du_on_the_new_version(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	measured = []
	original = rv.get_path_size
	monkeypatch.setattr(rv, 'get_path_size', lambda *paths: measured.extend(paths) or original(*paths))
	_backup(job)[1].close()
	assert not any(os.path.basename(path).startswith('V0--') for path in measured)


def test_the_manifest_notes_each_path_changed_once_with_whether_a_row_was_there(job):
	os.makedirs(job.job_vault)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	for rel in ('d/', 'd/keep', 'u', 'target', 'gone'):
		manifest.add(rel)
	assert manifest.changes() is None
	manifest.track_changes()
	# a path noted as about to be written, with the folders above it as files' rels
	manifest.note_changed('n/w')
	# moved over a path noted first, then added again: INSERT OR REPLACE keeps the first note
	manifest.move_file('u', 'n/w')
	manifest.add('n/w', dirty=True)
	manifest.add('d/keep', dirty=True)
	manifest.discard('gone')
	manifest.move_tree('d/', 'e/')
	assert sorted(manifest.changes()) == [('d/', True), ('d/keep', True), ('e/', False), ('e/keep', False), ('gone', True),
		('n', False), ('n/w', False), ('u', True)]
	assert sorted(manifest.changed_files()) == ['e/keep', 'n/w']
	# a rollback takes the notes back, and ends them
	manifest.rollback()
	assert manifest.changes() is None
	manifest.begin()
	manifest.track_changes()
	manifest.add('x')
	manifest.commit()
	assert manifest.changes() is None
	manifest.close()


def test_links_of_one_length_that_take_different_bytes_are_measured_row_by_row(job, poll_fast, monkeypatch):
	# disks of a pool of different filesystems: what a link takes is not told by the length of its text
	seed_monitor(job, {'a': 'a', 'b': 'b', 'd/c': 'c'})
	_backup(job)[1].close()
	copies = []
	real_copy, real_lstat = rv.do_referenced_copy, os.lstat
	def lstat(path, *args, **kwargs):
		st = real_lstat(path, *args, **kwargs)
		if os.fspath(path).endswith('/b') and stat.S_ISLNK(st.st_mode) and sys._getframe(1).f_code.co_name == 'referenced_link':
			# the link b, of a's length, said to take a block more than a
			return types.SimpleNamespace(st_blocks=st.st_blocks + 8, st_mode=st.st_mode)
		return st
	def copying(*args, **kwargs):
		copies.append(kwargs['sizes'])
		with monkeypatch.context() as patched:
			patched.setattr(os, 'lstat', lstat)
			return real_copy(*args, **kwargs)
	monkeypatch.setattr(rv, 'do_referenced_copy', copying)
	with open(os.path.join(job.monitor, 'd/c'), 'w') as f:
		f.write('changed')
	_, manifest, _ = _backup(job, OrderedDict([(os.path.join(job.monitor, 'd/c'), rv.BackupEntryValues('t', 'modify', None))]))
	assert copies[0].usable is False and copies[0].linked == 3
	_assert_matches_du(job, manifest, committed_versions(job)[1])
	manifest.close()
