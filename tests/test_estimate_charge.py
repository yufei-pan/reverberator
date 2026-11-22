'''
0.55.2: the size estimate charges a regular file what its copy takes in the vault, the smaller of its blocks on the
source (holes stay holes) and its size rounded up to the vault's block: XFS's speculative preallocation shows a file just
appended to at about 2.6 times its size in blocks for minutes, and the copy gets none of it.
'''
import ctypes
import errno
import os
from collections import OrderedDict

import pytest

import reverberator as rv

pytestmark = pytest.mark.unit

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
FALLOC_FL_KEEP_SIZE = 1


def preallocated(path, size, extra):
	'''A file of size bytes holding extra bytes of blocks past its end, as a speculative preallocation leaves one.'''
	with open(path, 'wb') as f:
		f.write(b'p' * size)
		f.flush()
		if LIBC.fallocate(f.fileno(), FALLOC_FL_KEEP_SIZE, 0, size + extra) != 0:
			code = ctypes.get_errno()
			if code in (errno.EOPNOTSUPP, errno.ENOSYS):
				pytest.skip(f'the filesystem under the test cannot preallocate past a file\'s end: {os.strerror(code)}')
			raise OSError(code, os.strerror(code), path)


def estimate(job, *rels, event='create'):
	entries = OrderedDict((os.path.join(job.monitor, rel), rv.BackupEntryValues('t', event, None)) for rel in rels)
	os.makedirs(job.job_vault, exist_ok=True)
	return rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, version_bytes=0)


def block_of(job):
	os.makedirs(job.job_vault, exist_ok=True)
	return os.statvfs(job.job_vault).f_frsize


@pytest.mark.parametrize('event', ['create', 'modify', 'attrib'])
def test_the_estimate_charges_a_preallocated_file_its_size_rounded_up(job, event):
	block = block_of(job)
	path = os.path.join(job.monitor, 'appended')
	os.makedirs(job.monitor, exist_ok=True)
	preallocated(path, 5000, 4 << 20)
	# the source's blocks run well past its size
	assert os.lstat(path).st_blocks * 512 >= 4 << 20
	size, _ = estimate(job, 'appended', event=event)
	assert size == -(-5000 // block) * block


def test_the_estimate_walk_charges_a_preallocated_file_its_size_rounded_up(job):
	# the same through a folder's walk, with a skip list and without
	block = block_of(job)
	folder = os.path.join(job.monitor, 'n')
	os.makedirs(folder)
	preallocated(os.path.join(folder, 'appended'), 5000, 4 << 20)
	entries = OrderedDict({folder + '/': rv.BackupEntryValues('t', 'create', None)})
	expected = os.lstat(folder).st_blocks * 512 + -(-5000 // block) * block, 2
	assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, version_bytes=0) == expected
	assert rv.get_backup_size_inode(entries, False, job.job_vault, job.monitor, rv.SkipList(job.monitor, ['*.tmp']), version_bytes=0) == expected


def test_the_estimate_charges_a_sparse_file_its_blocks(job):
	block = block_of(job)
	path = os.path.join(job.monitor, 'sparse')
	os.makedirs(job.monitor, exist_ok=True)
	with open(path, 'wb') as f:
		f.truncate(64 << 20)
		f.seek((64 << 20) - 1)
		f.write(b'x')
	blocks = os.lstat(path).st_blocks * 512
	assert blocks < 1 << 20
	size, _ = estimate(job, 'sparse')
	# the hole stays a hole in the copy: its blocks, not its size
	assert size == blocks and size <= -(-(64 << 20) // block) * block


def test_the_estimate_charges_a_file_smaller_than_a_block_one_block_at_most(job):
	block = block_of(job)
	path = os.path.join(job.monitor, 'small')
	os.makedirs(job.monitor, exist_ok=True)
	with open(path, 'w') as f:
		f.write('tiny')
	size, _ = estimate(job, 'small')
	assert size == min(os.lstat(path).st_blocks * 512, block)
	assert size <= block


def test_the_estimate_charges_a_folder_and_a_link_their_blocks(job):
	os.makedirs(os.path.join(job.monitor, 'd'))
	os.symlink('t' * 900, os.path.join(job.monitor, 'l'))
	assert estimate(job, 'd/')[0] == os.lstat(os.path.join(job.monitor, 'd')).st_blocks * 512
	assert estimate(job, 'l')[0] == os.lstat(os.path.join(job.monitor, 'l')).st_blocks * 512


def test_a_folder_entry_replaced_by_a_link_is_charged_as_the_link(job):
	# fails before the fix wave's FW4 (the final review's s15 (1)): the estimate's lstat of a batch folder's path with its trailing slash
	# followed a link put at the folder's name and charged the folder it leads to its blocks, where the replay makes an empty folder (its
	# copy walk does not follow the link): under a size limit, versions could be pruned that need not be. The folder the link leads to
	# holds 2,000 names of 104 bytes, about 230 KB of entries, which take blocks of their own on a disk's filesystem
	elsewhere = os.path.join(job.root, 'elsewhere')
	os.makedirs(elsewhere)
	for i in range(2000):
		open(os.path.join(elsewhere, f'{i:04}' + 'n' * 100), 'w').close()
	if os.lstat(elsewhere).st_blocks == 0:
		pytest.skip('the filesystem under the test gives a folder no blocks (tmpfs): a folder and a link would be charged alike')
	os.makedirs(job.monitor, exist_ok=True)
	link = os.path.join(job.monitor, 'd')
	os.symlink(elsewhere, link)
	assert estimate(job, 'd/') == (os.lstat(link).st_blocks * 512, 1)


@pytest.mark.parametrize('kind', ['file', 'fifo', 'dangling link', 'link to a file'])
@pytest.mark.parametrize('event', ['create', 'modify'])
def test_a_folder_entry_that_something_else_took_the_name_of_is_charged_nothing(job, kind, event):
	# fails before the residual round's R1 (the fix wave's second-opinion finding on FW4): the estimate's lstat of the folder's name, which
	# no longer fails when a file stands there, charged the file's bytes and an inode, where the replay finds no folder at the path with its /
	# (copy_path(): it does not exist) and copies nothing: under a size limit, versions could be pruned that need not be. The file holds
	# 20 KB, so a charge shows
	os.makedirs(job.monitor, exist_ok=True)
	place = os.path.join(job.monitor, 'd')
	if kind == 'file':
		with open(place, 'wb') as f:
			f.write(b'f' * 20000)
	elif kind == 'fifo':
		os.mkfifo(place)
	elif kind == 'dangling link':
		os.symlink(os.path.join(job.root, 'nowhere'), place)
	else:
		with open(os.path.join(job.root, 'a file'), 'wb') as f:
			f.write(b'f' * 20000)
		os.symlink(os.path.join(job.root, 'a file'), place)
	assert estimate(job, 'd/', event=event) == (0, 0)


def test_the_estimate_runs_no_du(job, monkeypatch):
	os.makedirs(os.path.join(job.monitor, 'd'))
	with open(os.path.join(job.monitor, 'd', 'f'), 'w') as f:
		f.write('f')
	run_command = rv.multiCMD.run_command
	ran = []
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: ran.append(command) or run_command(command, *args, **kwargs))
	assert estimate(job, 'd/', 'd/f', 'd/f', event='create')[1] == 2
	# a folder's modify is walked, and copies what it holds: its inodes count as its bytes do
	assert estimate(job, 'd/', event='modify')[1] == 2
	assert ran == []
