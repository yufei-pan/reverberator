import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, write_committed_version, run_backup, event_entry

pytestmark = pytest.mark.unit

T = '2021-01-01_00-00-00_-0800'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def assert_links_to(path, copy, content):
	assert os.path.islink(path) and open(path).read() == content
	assert os.path.realpath(path) == os.path.realpath(copy)


def test_file_moved_deeper_keeps_its_link(job):
	seed_monitor(job, {'a/x.txt': 'x', 'deep/er/keep.txt': 'k'})
	v0 = run_backup(job)[0]
	os.rename(f'{job.monitor}/a/x.txt', f'{job.monitor}/deep/er/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/x.txt', 'move', 'a/x.txt')]))[-1]
	assert_links_to(os.path.join(v1, 'deep/er/x.txt'), os.path.join(v0, 'a/x.txt'), 'x')


def test_file_moved_shallower_keeps_its_link(job):
	seed_monitor(job, {'deep/er/x.txt': 'x'})
	v0 = run_backup(job)[0]
	os.rename(f'{job.monitor}/deep/er/x.txt', f'{job.monitor}/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'x.txt', 'move', 'deep/er/x.txt')]))[-1]
	assert_links_to(os.path.join(v1, 'x.txt'), os.path.join(v0, 'deep/er/x.txt'), 'x')


def test_folder_moved_to_another_depth_keeps_every_link(job):
	# moved deeper, then shallower, with no full comparison in between to copy anything again
	seed_monitor(job, {'sub/x.txt': 'x', 'sub/inner/y.txt': 'y', 'deep/er/keep.txt': 'k'})
	v0 = run_backup(job)[0]
	os.rename(f'{job.monitor}/sub', f'{job.monitor}/deep/er/sub')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/sub/', 'move', 'sub/')]))[-1]
	os.rename(f'{job.monitor}/deep/er/sub', f'{job.monitor}/top')
	v2 = run_backup(job, OrderedDict([event_entry(job, 'top/', 'move', 'deep/er/sub/')]))[-1]
	for version, folder in ((v1, 'deep/er/sub'), (v2, 'top')):
		for rel, content in (('x.txt', 'x'), ('inner/y.txt', 'y')):
			assert_links_to(os.path.join(version, folder, rel), os.path.join(v0, 'sub', rel), content)


def test_retarget_moved_links_keeps_user_symlinks(tmp_path):
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V0--{T}', {'a/x': 'x'})
	moved = f'{job_vault}/V1--{T}/deep/er/sub'
	os.makedirs(moved)
	# a chain link moved here from V1's top level, and a user's symlink backed up as one
	os.symlink(f'../../V0--{T}/a/x', f'{moved}/x')
	os.symlink('x', f'{moved}/u')
	assert rv.retarget_moved_links(job_vault, moved) == 1
	assert os.readlink(f'{moved}/u') == 'x'
	assert open(f'{moved}/x').read() == 'x'
	assert sorted(os.listdir(moved)) == ['u', 'x']


def test_retarget_moved_links_leaves_a_moved_copy_alone(tmp_path, capsys):
	# a file this backup copied, then moved
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V1--{T}', {'deep/er/x': 'x'})
	assert rv.retarget_moved_links(job_vault, f'{job_vault}/V1--{T}/deep/er/x') == 0
	assert 'ERROR' not in capsys.readouterr().out


def test_same_depth_move_leaves_the_link_text_alone(job, monkeypatch):
	seed_monitor(job, {'a/x.txt': 'x', 'b/keep.txt': 'k'})
	v0 = run_backup(job)[0]
	retargeted = []
	retarget = rv.retarget_moved_links

	def recording(job_vault, moved_path):
		retargeted.append(moved_path)
		return retarget(job_vault, moved_path)
	monkeypatch.setattr(rv, 'retarget_moved_links', recording)
	os.rename(f'{job.monitor}/a/x.txt', f'{job.monitor}/b/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'b/x.txt', 'move', 'a/x.txt')]))[-1]
	# the text the referenced copy gave a/x.txt in the new version, before the move renamed it
	assert os.readlink(os.path.join(v1, 'b/x.txt')) == os.path.relpath(os.path.join(v0, 'a/x.txt'), os.path.join(v1, 'a'))
	assert retargeted == []


def test_read_vault_record_reads_a_link_broken_by_an_old_move(job):
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v1 = os.path.join(job.job_vault, f'V1--{T}')
	os.makedirs(f'{v1}/deep/er')
	os.symlink(f'../../V0--{T}/a/x', f'{v1}/deep/er/x')
	record = rv.read_vault_record(v1, 'deep/er/x', job.monitor)
	assert (record.kind, record.size) == ('f', os.path.getsize(os.path.join(v0, 'a/x')))


def test_pruning_materialises_a_link_broken_by_an_old_move(job):
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'deep/er/': None}, timestamp=T)
	os.symlink(f'../../V0--{T}/a/x', f'{v1}/deep/er/x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/deep/er/x') and open(f'{v1}/deep/er/x').read() == 'x'
