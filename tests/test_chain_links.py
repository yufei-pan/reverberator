import errno
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, write_committed_version, run_backup, latest_version, event_entry

pytestmark = pytest.mark.unit

T = '2021-01-01_00-00-00_-0800'
# the timestamp of a vault the user keeps in the monitored tree, which the job's vault does not have
INNER_T = '2020-01-01_00-00-00_-0800'
INNER_LINK_TEXT = f'../../V0--{INNER_T}/a/x'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def seed_vault_shaped_tree(job, folder):
	'''A vault of the user's own under folder: V1's a/x links to V0's like the daemon's links do.'''
	seed_monitor(job, {f'{folder}/job/V0--{INNER_T}/a/x': 'x'})
	os.makedirs(f'{job.monitor}/{folder}/job/V1--{INNER_T}/a')
	os.symlink(INNER_LINK_TEXT, f'{job.monitor}/{folder}/job/V1--{INNER_T}/a/x')


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
	# a user's symlink shaped like a chain link, naming a version folder the job vault does not have
	os.symlink(INNER_LINK_TEXT, f'{moved}/v')
	assert rv.retarget_moved_links(job_vault, moved) == 1
	assert os.readlink(f'{moved}/u') == 'x'
	assert os.readlink(f'{moved}/v') == INNER_LINK_TEXT
	assert open(f'{moved}/x').read() == 'x'
	assert sorted(os.listdir(moved)) == ['u', 'v', 'x']


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


def test_vault_shaped_user_links_are_backed_up_as_links(job, capsys):
	seed_vault_shaped_tree(job, 'inner')
	assert len(run_backup(job)) == 1
	# nothing changed, so the comparisons read the user's links back as links and commit nothing
	assert len(run_backup(job)) == 1
	assert len(run_backup(job)) == 1
	assert 'Cannot read' not in capsys.readouterr().out
	assert os.readlink(os.path.join(latest_version(job).path, f'inner/job/V1--{INNER_T}/a/x')) == INNER_LINK_TEXT


def test_vault_shaped_folder_moved_to_another_depth_keeps_its_user_links(job):
	seed_monitor(job, {'deep/er/keep.txt': 'k'})
	seed_vault_shaped_tree(job, 'inner')
	run_backup(job)
	os.rename(f'{job.monitor}/inner', f'{job.monitor}/deep/er/inner')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/inner/', 'move', 'inner/')]))[-1]
	record = rv.read_vault_record(v1, f'deep/er/inner/job/V1--{INNER_T}/a/x', job.monitor)
	assert (record.kind, record.link) == ('l', INNER_LINK_TEXT)
	assert len(run_backup(job)) == 2


def test_link_naming_an_older_version_is_not_followed_or_pruned_onto(job):
	# V1 gone (as by a hand removal) leaves V2 next to V0; the daemon links a version only to the one just before it
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v2 = write_committed_version(job, 2, {}, timestamp=T)
	os.symlink(f'../V0--{T}/a/x', f'{v2}/u')
	record = rv.read_vault_record(v2, 'u', job.monitor)
	assert (record.kind, record.link) == ('l', f'../V0--{T}/a/x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert os.readlink(f'{v2}/u') == f'../V0--{T}/a/x'


def test_link_naming_another_folder_for_the_previous_version_is_not_a_chain_link(tmp_path):
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V0--{T}', {'a/x': 'x'})
	write_tree(f'{job_vault}/V0--notatime', {'a/x': 'x'})
	link_path = f'{job_vault}/V1--{T}/y'
	assert rv.chain_link_target(job_vault, f'../V0--{T}/a/x', link_path) == f'{job_vault}/V0--{T}/a/x'
	# another timestamp than the previous version's folder has, and a folder whose name holds no timestamp
	assert rv.chain_link_target(job_vault, f'../V0--{INNER_T}/a/x', link_path) is None
	assert rv.chain_link_target(job_vault, '../V0--notatime/a/x', link_path) is None


@pytest.mark.parametrize('absolute', [False, True])
def test_link_through_a_backed_up_folder_symlink_is_not_followed_or_pruned_onto(job, absolute):
	outside = os.path.join(job.root, 'outside')
	write_tree(outside, {'x': 'not the vault\'s'})
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	# a user's symlink to a folder, backed up as one
	os.symlink(outside, f'{v0}/a')
	v1 = write_committed_version(job, 1, {'deep/': None}, timestamp=T)
	# shaped like a chain link an older daemon moved deeper, or like an older daemon's absolute one
	text = f'{v0}/a/x' if absolute else f'../V0--{T}/a/x'
	os.symlink(text, f'{v1}/deep/u')
	record = rv.read_vault_record(v1, 'deep/u', job.monitor)
	assert (record.kind, record.link) == ('l', text)
	assert rv.retarget_moved_links(job.job_vault, f'{v1}/deep') == 0
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert open(os.path.join(outside, 'x')).read() == 'not the vault\'s'
	assert os.readlink(f'{v1}/deep/u') == text


def test_pruning_drops_a_chain_link_whose_folder_is_gone(job):
	# nothing to materialise: as for a link whose file is gone, keeping it would hand the broken reference on
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'sub/': None}, timestamp=T)
	os.symlink(f'../../V0--{T}/sub/x', f'{v1}/sub/x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert not os.path.lexists(f'{v1}/sub/x')


DEEP = 'a/' * 1000


@pytest.mark.parametrize('absolute', [False, True])
def test_a_link_a_thousand_folders_deep_stops_neither_a_backup_nor_a_prune(job, absolute):
	seed_monitor(job, {'keep.txt': 'k'})
	v0 = run_backup(job)[0]
	# a user's symlink shaped like a chain link into a V0 folder the vault does not have, a thousand folders down
	text = (f'{job.job_vault}/V0--{T}/' if absolute else f'../V0--{T}/') + DEEP + 'x'
	os.symlink(text, f'{job.monitor}/u')
	# copied into V1, then read back to record it
	v1 = run_backup(job, OrderedDict([event_entry(job, 'u', 'create')]))[-1]
	record = rv.read_vault_record(v1, 'u', job.monitor)
	assert (record.kind, record.link) == ('l', text)
	open(f'{job.monitor}/keep.txt', 'w').write('k2')
	run_backup(job, OrderedDict([event_entry(job, 'keep.txt', 'modify')]), keep_n_versions=2)
	assert not os.path.exists(v0) and latest_version(job).version_number == 2
	assert not os.path.islink(f'{v1}/keep.txt') and open(f'{v1}/keep.txt').read() == 'k'
	assert os.readlink(f'{v1}/u') == text


def test_a_chain_a_thousand_folders_deep_resolves_and_prunes(job):
	v0 = write_committed_version(job, 0, {}, timestamp=T, current=False)
	# one folder at a time, as os.makedirs recurses once a folder
	folder = v0
	for _ in range(DEEP.count('/')):
		folder = os.path.join(folder, 'a')
		os.mkdir(folder)
	write_tree(folder, {'x': 'x'})
	v1 = write_committed_version(job, 1, {}, timestamp=T)
	# as an older daemon left it after moving the file to the top
	os.symlink(f'../V0--{T}/{DEEP}x', f'{v1}/x')
	assert rv.read_vault_record(v1, 'x', job.monitor).kind == 'f'
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/x') and open(f'{v1}/x').read() == 'x'


def test_a_link_naming_too_long_a_folder_does_not_stop_a_prune(job):
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'other': 'o'}, timestamp=T)
	# no folder can have a name this long
	text = f'../V0--{T}/' + 'a' * 300 + '/x'
	os.symlink(text, f'{v1}/u')
	assert rv.read_vault_record(v1, 'u', job.monitor).kind == 'l'
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert os.readlink(f'{v1}/u') == text


@pytest.mark.parametrize('absolute', [False, True])
def test_a_chain_link_whose_folders_cannot_be_looked_at_keeps_the_version_being_pruned(job, monkeypatch, capsys, absolute):
	v0 = write_committed_version(job, 0, {'a/b/x': 'x'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'a/b/': None}, timestamp=T)
	# as the daemon writes it, or as an older daemon did
	text = f'{v0}/a/b/x' if absolute else f'../../../V0--{T}/a/b/x'
	os.symlink(text, f'{v1}/a/b/x')
	lstat = os.lstat
	def lstat_failing_on_a(path, *args, **kwargs):
		if path == f'{v0}/a':
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return lstat(path, *args, **kwargs)
	with monkeypatch.context() as patch:
		patch.setattr(rv.os, 'lstat', lstat_failing_on_a)
		# the link may be V1's only way to x, so V0 stays
		assert rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict) == (0, 0)
		assert open(f'{v0}/a/b/x').read() == 'x'
		assert os.readlink(f'{v1}/a/b/x') == text
		out = capsys.readouterr().out
		assert f'{v1}/a/b/x' in out and os.strerror(errno.EIO) in out
		# unreadable, never a user's symlink
		assert rv.read_vault_record(v1, 'a/b/x', job.monitor) is None
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/a/b/x') and open(f'{v1}/a/b/x').read() == 'x'


def test_a_refused_or_missing_folder_is_looked_at_again(tmp_path):
	job_vault = str(tmp_path / 'job')
	v0 = f'{job_vault}/V0--{T}'
	link_path = f'{job_vault}/V1--{T}/u'
	texts = (f'{v0}/a/x', f'../V0--{T}/a/x')
	# V0 is not there yet
	assert [rv.chain_hop(job_vault, link_path, text) for text in texts] == [None, None]
	os.makedirs(v0)
	# V0/a is not there yet, so nothing goes through it
	assert [rv.chain_hop(job_vault, link_path, text) for text in texts] == [f'{v0}/a/x'] * 2
	os.symlink(str(tmp_path), f'{v0}/a')
	assert [rv.chain_hop(job_vault, link_path, text) for text in texts] == [None, None]


def test_an_absolute_link_into_a_later_version_is_not_a_chain_link(tmp_path):
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V2--{T}', {'a/x': 'x'})
	target = f'{job_vault}/V2--{T}/a/x'
	assert rv.chain_hop(job_vault, f'{job_vault}/V1--{T}/u', target) is None
	assert rv.chain_hop(job_vault, f'{job_vault}/V3--{T}/u', target) == target
