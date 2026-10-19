import os
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
