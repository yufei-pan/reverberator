'''
The links of a 0.54 vault as the code a 0.54 vault still needs reads them: vault_chain_hop() and the prune tell a chain link from a user's
link. tests/legacy054.py writes the vaults, as the product's writer is gone.
'''
import contextlib
import errno
import os
import sys
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, write_committed_version, run_backup, latest_version, event_entry, link_text_limit

pytestmark = pytest.mark.unit

T = '2021-01-01_00-00-00_-0800'
# the timestamp of a vault the user keeps in the monitored tree, which the job's vault does not have
INNER_T = '2020-01-01_00-00-00_-0800'
INNER_LINK_TEXT = f'../../V0--{INNER_T}/a/x'


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def assert_links_to(path, copy, content):
	assert os.path.islink(path) and open(path).read() == content
	assert os.path.realpath(path) == os.path.realpath(copy)


def test_pruning_materialises_a_link_broken_by_an_old_move(job):
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'deep/er/': None}, timestamp=T)
	os.symlink(f'../../V0--{T}/a/x', f'{v1}/deep/er/x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/deep/er/x') and open(f'{v1}/deep/er/x').read() == 'x'


def test_link_naming_an_older_version_is_not_followed_or_pruned_onto(job):
	# V1 gone (as by a hand removal) leaves V2 next to V0; the daemon links a version only to the one just before it
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v2 = write_committed_version(job, 2, {}, timestamp=T)
	os.symlink(f'../V0--{T}/a/x', f'{v2}/u')
	# Task 2b: the scan fails on the gap, so no backup prunes past it; pruning given V0 and V2 still follows no such link
	with pytest.raises(rv.VaultScanError):
		rv.get_vault_info(job.job_vault)
	info = OrderedDict((kept.number, rv.VaultEntry(kept.number, kept.path, kept.timestamp, kept.size, kept.inodes)) for kept in rv.list_versions(job.job_vault))
	rv.decrement_stepper(info, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert os.readlink(f'{v2}/u') == f'../V0--{T}/a/x'


def test_link_naming_another_folder_for_the_previous_version_is_not_a_chain_link(tmp_path):
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V0--{T}', {'a/x': 'x'})
	write_tree(f'{job_vault}/V0--notatime', {'a/x': 'x'})
	link_path = f'{job_vault}/V1--{T}/y'
	# judged by the text alone (BY_THE_TEXT): the folder name is what this tells, not the rows
	assert rv.vault_chain_hop(job_vault, link_path, f'../V0--{T}/a/x', rv.BY_THE_TEXT) == f'{job_vault}/V0--{T}/a/x'
	# another timestamp than the previous version's folder has, and a folder whose name holds no timestamp
	assert rv.vault_chain_hop(job_vault, link_path, f'../V0--{INNER_T}/a/x', rv.BY_THE_TEXT) is None
	assert rv.vault_chain_hop(job_vault, link_path, '../V0--notatime/a/x', rv.BY_THE_TEXT) is None


@pytest.mark.parametrize('absolute', [False, True])
def test_link_through_a_backed_up_folder_symlink_is_not_followed_or_pruned_onto(job, absolute):
	outside = os.path.join(job.root, 'outside')
	write_tree(outside, {'x': 'not the vault\'s'})
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	# a user's symlink to a folder, backed up as one
	os.symlink(outside, f'{v0}/a')
	v1 = write_committed_version(job, 1, {'deep/': None}, timestamp=T)
	# shaped like a chain link an older daemon moved deeper, or an absolute link of that shape (no chain link since
	# 0.44, wherever it leads)
	text = f'{v0}/a/x' if absolute else f'../V0--{T}/a/x'
	os.symlink(text, f'{v1}/deep/u')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert open(os.path.join(outside, 'x')).read() == 'not the vault\'s'
	assert os.readlink(f'{v1}/deep/u') == text


def test_pruning_leaves_a_chain_link_whose_folder_is_gone(job):
	# nothing to materialise: as for a link whose file is gone, it is left as it is, and reads as missing either way
	# (final fix g), and the removal is not held back by it
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'sub/': None}, timestamp=T)
	os.symlink(f'../../V0--{T}/sub/x', f'{v1}/sub/x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert os.readlink(f'{v1}/sub/x') == f'../../V0--{T}/sub/x'


# a thousand folders deep, which was past Python's default limit of 1000 frames for a check that went down a folder at a time. A link that deep needs a
# text of 2,000 bytes and more, which ext4 and f2fs take (4,095) and XFS does not (1,023): there the link is as deep as its filesystem lets it be
DEEP_FOLDERS = 1000
# the frames the daemon's own calls under these tests need above the test's: the three tests below pass with 16 and fail with 14 (measured by lowering the limit)
DAEMON_FRAMES = 16


def folders_deep(prefix, *folders):
	'''How many folders deep a link at prefix + 'a/' * n + 'x' can go in folders: a thousand, or as many as the longest text their filesystems take allows.'''
	depth = min(DEEP_FOLDERS, (link_text_limit(*folders) - len(prefix) - len('x')) // 2)
	# the stack limit leaves depth // 2 frames to the daemon, which needs about DAEMON_FRAMES: twice that is the least depth that
	# does not starve it
	assert depth // 2 >= 2 * DAEMON_FRAMES, depth
	return depth


@contextlib.contextmanager
def stack_for_half_the_folders(depth):
	'''
	A limit on the stack that gives the code under it half as many frames as the link has folders: a check that went down a folder at a time,
	a frame for each, would fail on it, whatever depth its filesystem lets a link be.
	'''
	limit = sys.getrecursionlimit()
	frames, frame = 0, sys._getframe()
	while frame is not None:
		frames, frame = frames + 1, frame.f_back
	sys.setrecursionlimit(frames + depth // 2)
	try:
		yield
	finally:
		sys.setrecursionlimit(limit)


@pytest.mark.parametrize('absolute', [False, True])
def test_a_link_a_thousand_folders_deep_stops_neither_a_backup_nor_a_prune(job, absolute):
	seed_monitor(job, {'keep.txt': 'k'})
	v0 = run_backup(job)[0]
	# a user's symlink shaped like a chain link into a V0 folder the vault does not have, a thousand folders down (as far as the filesystems take a text)
	prefix = f'{job.job_vault}/V0--{T}/' if absolute else f'../V0--{T}/'
	depth = folders_deep(prefix, job.monitor, job.vault)
	text = prefix + 'a/' * depth + 'x'
	os.symlink(text, f'{job.monitor}/u')
	# copied into V1, then read back to record it
	v1 = run_backup(job, OrderedDict([event_entry(job, 'u', 'create')]))[-1]
	assert os.readlink(f'{v1}/u') == text
	open(f'{job.monitor}/keep.txt', 'w').write('k2')
	with stack_for_half_the_folders(depth):
		run_backup(job, OrderedDict([event_entry(job, 'keep.txt', 'modify')]), keep_n_versions=2)
	assert not os.path.exists(v0) and latest_version(job).version_number == 2
	assert not os.path.islink(f'{v1}/keep.txt') and open(f'{v1}/keep.txt').read() == 'k'
	assert os.readlink(f'{v1}/u') == text


def test_a_chain_a_thousand_folders_deep_resolves_and_prunes(job):
	v0 = write_committed_version(job, 0, {}, timestamp=T, current=False)
	depth = folders_deep(f'../V0--{T}/', job.vault)
	# one folder at a time, as os.makedirs recurses once a folder
	folder = v0
	for _ in range(depth):
		folder = os.path.join(folder, 'a')
		os.mkdir(folder)
	write_tree(folder, {'x': 'x'})
	v1 = write_committed_version(job, 1, {}, timestamp=T)
	# as an older daemon left it after moving the file to the top
	os.symlink(f'../V0--{T}/' + 'a/' * depth + 'x', f'{v1}/x')
	with stack_for_half_the_folders(depth):
		rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/x') and open(f'{v1}/x').read() == 'x'


def test_a_link_naming_too_long_a_folder_does_not_stop_a_prune(job):
	v0 = write_committed_version(job, 0, {'keep': 'k'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'other': 'o'}, timestamp=T)
	# no folder can have a name this long
	text = f'../V0--{T}/' + 'a' * 300 + '/x'
	os.symlink(text, f'{v1}/u')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert os.readlink(f'{v1}/u') == text


@pytest.mark.parametrize('absolute', [False, True])
def test_a_chain_link_whose_folders_cannot_be_looked_at_keeps_the_version_being_pruned(job, monkeypatch, capsys, absolute):
	v0 = write_committed_version(job, 0, {'a/b/x': 'x'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'a/b/': None}, timestamp=T)
	# as the daemon writes it, or an absolute link of that shape
	text = f'{v0}/a/b/x' if absolute else f'../../../V0--{T}/a/b/x'
	os.symlink(text, f'{v1}/a/b/x')
	lstat = os.lstat
	def lstat_failing_on_a(path, *args, **kwargs):
		if path == f'{v0}/a':
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return lstat(path, *args, **kwargs)
	if absolute:
		# since 0.44 an absolute link is a user's symlink, told without looking at a folder: pruning goes on and leaves it
		info = rv.get_vault_info(job.job_vault).vault_info_dict
		with monkeypatch.context() as patch:
			patch.setattr(rv.os, 'lstat', lstat_failing_on_a)
			assert rv.decrement_stepper(info, job.job_name, job.monitor) != (0, 0)
			assert os.strerror(errno.EIO) not in capsys.readouterr().out
		assert not os.path.exists(v0) and os.readlink(f'{v1}/a/b/x') == text
		return
	with monkeypatch.context() as patch:
		patch.setattr(rv.os, 'lstat', lstat_failing_on_a)
		# the link may be V1's only way to x, so V0 stays
		assert rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor) == (0, 0)
		assert open(f'{v0}/a/b/x').read() == 'x'
		assert os.readlink(f'{v1}/a/b/x') == text
		out = capsys.readouterr().out
		assert f'{v1}/a/b/x' in out and os.strerror(errno.EIO) in out
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/a/b/x') and open(f'{v1}/a/b/x').read() == 'x'


def test_a_refused_or_missing_folder_is_looked_at_again(tmp_path):
	job_vault = str(tmp_path / 'job')
	v0 = f'{job_vault}/V0--{T}'
	link_path = f'{job_vault}/V1--{T}/u'
	# relative only: since 0.44 an absolute link is never a chain link, so no folder of it is looked at
	text = f'../V0--{T}/a/x'
	# V0 is not there yet (judged by the text alone, BY_THE_TEXT: the folders are what this tells, not the rows)
	assert rv.vault_chain_hop(job_vault, link_path, text, rv.BY_THE_TEXT) is None
	os.makedirs(v0)
	# V0/a is not there yet, so nothing goes through it
	assert rv.vault_chain_hop(job_vault, link_path, text, rv.BY_THE_TEXT) == f'{v0}/a/x'
	os.symlink(str(tmp_path), f'{v0}/a')
	assert rv.vault_chain_hop(job_vault, link_path, text, rv.BY_THE_TEXT) is None


def test_an_absolute_link_into_any_version_is_not_a_chain_link(tmp_path):
	job_vault = str(tmp_path / 'job')
	write_tree(f'{job_vault}/V2--{T}', {'a/x': 'x'})
	target = f'{job_vault}/V2--{T}/a/x'
	# not even by the text alone
	assert rv.vault_chain_hop(job_vault, f'{job_vault}/V1--{T}/u', target, rv.BY_THE_TEXT) is None
	# an older one too: no released daemon wrote absolute chain links, and since 0.44 that form is a user's symlink to a
	# backed-up copy
	assert rv.vault_chain_hop(job_vault, f'{job_vault}/V3--{T}/u', target, rv.BY_THE_TEXT) is None



def test_pruning_forgets_the_real_folders_of_the_version_it_removes(job):
	v0 = write_committed_version(job, 0, {'a/x': 'x'}, timestamp=T, current=False)
	v1 = write_committed_version(job, 1, {'a/': None}, timestamp=T)
	os.symlink(f'../../V0--{T}/a/x', f'{v1}/a/x')
	# through V0's folders, which are found real
	assert rv.vault_chain_hop(job.job_vault, f'{v1}/a/x', f'../../V0--{T}/a/x', rv.BY_THE_TEXT) == f'{v0}/a/x'
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	# a user's symlink naming the version just removed is not a chain link: it is no version of the vault now
	text = f'../V0--{T}/a/x'
	os.symlink(text, f'{v1}/u')
	assert rv.vault_chain_hop(job.job_vault, f'{v1}/u', text, rv.BY_THE_TEXT) is None


def test_pruning_the_oldest_version_after_a_retargeted_move_leaves_a_real_copy(job):
	seed_monitor(job, {'a/x.txt': 'x', 'deep/er/keep.txt': 'k'})
	v0 = run_backup(job)[0]
	os.rename(f'{job.monitor}/a/x.txt', f'{job.monitor}/deep/er/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/x.txt', 'move', 'a/x.txt')]))[-1]
	assert_links_to(os.path.join(v1, 'deep/er/x.txt'), os.path.join(v0, 'a/x.txt'), 'x')
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0)
	assert not os.path.islink(os.path.join(v1, 'deep/er/x.txt')) and open(os.path.join(v1, 'deep/er/x.txt')).read() == 'x'


def test_a_referenced_link_after_a_move_still_leads_to_the_live_file(job):
	seed_monitor(job, {'a/x.txt': 'x', 'deep/er/keep.txt': 'k'})
	v0 = run_backup(job, keep_one_complete_backup=False)[0]
	assert os.path.islink(os.path.join(v0, 'a/x.txt'))
	os.rename(f'{job.monitor}/a/x.txt', f'{job.monitor}/deep/er/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/x.txt', 'move', 'a/x.txt')]))[-1]
	moved = os.path.join(v1, 'deep/er/x.txt')
	# the link was retargeted like any other, and still leads through V0's link to the file the first version referenced
	assert os.readlink(moved) == os.path.relpath(os.path.join(v0, 'a/x.txt'), os.path.join(v1, 'deep/er'))
	got = rv.resolve_version_entry(job.job_vault, v1, 'deep/er/x.txt', job.monitor)
	assert got.kind == 'referenced' and got.detail == os.path.join(job.monitor, 'a/x.txt')
