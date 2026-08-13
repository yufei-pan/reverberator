import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_committed_version

pytestmark = pytest.mark.unit


def test_delta_unchanged_file_not_added(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	os.utime(os.path.join(job.monitor, 'a.txt'), ns=(os.lstat(os.path.join(v0, 'a.txt')).st_atime_ns, os.lstat(os.path.join(v0, 'a.txt')).st_mtime_ns))
	entries = OrderedDict()
	latest = rv.VaultEntry(0, v0, 0, 1, 1)
	rv.delta_generate_backup_entries(entries, latest, job.monitor)
	assert os.path.join(job.monitor, 'a.txt') not in entries


def test_delta_changed_content_is_modify(job):
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('world')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'a.txt')].event == 'modify'


def test_delta_new_and_deleted(job):
	seed_monitor(job, {'keep.txt': 'k'})
	v0 = write_committed_version(job, 0, {'keep.txt': 'k', 'gone.txt': 'g'})
	open(os.path.join(job.monitor, 'new.txt'), 'w').write('n')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, rv.VaultEntry(0, v0, 0, 1, 1), job.monitor)
	assert entries[os.path.join(job.monitor, 'new.txt')].event == 'create'
	assert entries[os.path.join(job.monitor, 'gone.txt')].event == 'delete'
