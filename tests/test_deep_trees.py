'''
Trees deeper than Python's limit of 1,000 frames (spec section 2, P10): the walks keep a stack of the folders they are in, not a call a
level, so the deepest folders are watched, backed up, listed and restored, and a walk stopped early leaves no listing open.
'''
import os
import resource
import subprocess
import sys
import pytest
import reverberator as rv
from tests.harness import deep_tree, reverberator_script, stack_for_half_the_folders, wait_for_committed_count, write_rule

# past the 1,000 frames a walk that called itself a level at a time had; 2,400 bytes of path below the basetemp, so every path of the
# tree, in the vault and restored too, stays under the kernel's 4,096
DEPTH = 1200
T = '2021-01-01_00-00-00_-0800'
OLD = 1_000_000_000 * 10 ** 9


def soft_limit_1024():
	'''A process's soft limit of open files set to the 1,024 a login shell starts with, so only its own raise lets a walk hold a handle a level past it.'''
	resource.setrlimit(resource.RLIMIT_NOFILE, (1024, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))


def deep_rels(depth: int) -> list:
	'''The rels of deep_tree(root, depth) below root, in walk order: each folder with its trailing /, then the file at the bottom.'''
	return ['d/' * level for level in range(1, depth + 1)] + ['d/' * depth + 'f']


@pytest.mark.process
def test_a_tree_1200_levels_deep_is_backed_up_listed_and_restored(job, tmp_path, run_reverberator, process_env):
	# the daemon and the commands, each started with a soft limit of 1,024 open files, as from a login shell: each raises its own,
	# as a walk holds a listing a level. Fails on 1a4eeae: the walk stops some 990 levels down at Python's recursion limit, taken
	# for an unreadable folder, so the bottom file is never backed up
	bottom = deep_tree(job.monitor, DEPTH)
	rel = 'd/' * DEPTH + 'f'
	write_rule(job)
	run_reverberator(job.rule_path, preexec_fn=soft_limit_1024)
	first = wait_for_committed_count(job, 1, timeout=60)[0]
	assert os.path.isfile(os.path.join(first, rel))
	with open(os.path.join(bottom, 'f'), 'w') as f:
		f.write('two')
	newest = wait_for_committed_count(job, 2, timeout=60)[-1]
	assert open(os.path.join(newest, rel)).read() == 'two'
	script, state = [sys.executable, reverberator_script()], str(tmp_path / 'state')
	def command(*argv):
		return subprocess.run([*script, *argv, '--rule', job.rule_path, '--state_dir', state], env=process_env, stdin=subprocess.DEVNULL,
			capture_output=True, text=True, timeout=300, preexec_fn=soft_limit_1024)
	ran = command('history', os.path.join(bottom, 'f'))
	assert (ran.returncode, ran.stderr) == (0, '')
	lines = ran.stdout.split('\n')
	assert [line.split('  ')[0] for line in lines[1:]] == ['V1', 'V0', ''], ran.stdout
	out = tmp_path / 'out'
	out.mkdir()
	ran = command('restore', job.monitor, str(out), '--version', '1')
	assert (ran.returncode, ran.stderr) == (0, ''), ran.stdout
	assert open(os.path.join(out, os.path.basename(job.monitor), rel)).read() == 'two'


@pytest.mark.unit
@pytest.mark.parametrize('walk', ['iter_tree_entries', 'iter_folder_entries', 'settle'])
def test_a_walk_needs_no_frame_a_level(tmp_path, walk):
	# with the stack limited to the frames in use and half the tree's depth, a walk that took a frame a level stops half way down.
	# Fails on 1a4eeae: iter_tree_entries() and iter_folder_entries() take the RecursionError for an unreadable folder, ending the
	# walk there with an error, and settle()'s is_real() raises it
	if walk == 'iter_tree_entries':
		root = str(tmp_path / 't')
		deep_tree(root, DEPTH)
		errors = []
		with stack_for_half_the_folders(DEPTH):
			walked = [(path, rel, is_dir) for path, rel, is_dir in rv.iter_tree_entries(root, errors=errors)]
		assert errors == []
		assert walked == [(os.path.join(root, rel), rel, rel.endswith('/')) for rel in deep_rels(DEPTH)]
	elif walk == 'iter_folder_entries':
		# what V1 holds below its top folder is listed in V2, which its forward link leads to
		vault = tmp_path / 'vault'
		V1, V2 = f'V1--{T}', f'V2--{T}'
		deep_tree(str(vault / V2), DEPTH)
		os.mkdir(vault / V1)
		os.symlink(rv.forward_text('d', V2), vault / V1 / 'd')
		errors = []
		with stack_for_half_the_folders(DEPTH):
			walked = [(rel, entry.kind, entry.path) for rel, entry in rv.iter_version_entries(str(vault), 1, '', False, errors=errors)]
		assert errors == []
		assert walked[0] == ('', 'folder', str(vault / V1))
		assert walked[1:] == [(rel.rstrip('/'), 'folder' if rel.endswith('/') else 'file', os.path.join(vault, V2, rel.rstrip('/'))) for rel in deep_rels(DEPTH)]
	else:
		version, monitor = str(tmp_path / 'v'), str(tmp_path / 'm')
		bottom = deep_tree(version, DEPTH)[len(version) + 1:]
		deep_tree(monitor, DEPTH)
		os.utime(os.path.join(monitor, bottom), ns=(OLD, OLD))
		folders = rv.WrittenFolders()
		folders.add(bottom)
		with stack_for_half_the_folders(DEPTH):
			assert folders.settle(version, monitor, []) == []
		assert os.lstat(os.path.join(version, bottom)).st_mtime_ns == OLD
		assert folders.settled == [(OLD, bottom + '/')]


def open_fds() -> int:
	'''How many files the process holds open: /proc/self/fd's listing, which holds one more for itself every time.'''
	return len(os.listdir('/proc/self/fd'))


@pytest.mark.unit
@pytest.mark.parametrize('walk', ['iter_tree_entries', 'iter_folder_entries'])
def test_a_walk_stopped_early_closes_every_listing(tmp_path, walk):
	# review focus 1: a consumer stops a walk early (a JobFailure from the pool guard, a PoolNotReady in a comparison, a break), and
	# the daemon, which runs for months, keeps no listing of it. pin: a with block a level closes them today
	depth = 50
	if walk == 'iter_tree_entries':
		root = str(tmp_path / 't')
		deep_tree(root, depth)
		start, rel_of = lambda: rv.iter_tree_entries(root), lambda entry: entry[1]
	else:
		vault = tmp_path / 'vault'
		deep_tree(str(vault / f'V1--{T}'), depth)
		start, rel_of = lambda: rv.iter_version_entries(str(vault), 1, '', False), lambda entry: entry[0]
	bottom = 'd/' * depth + 'f'
	before = open_fds()
	def at_the_bottom(entry) -> bool:
		if rel_of(entry) != bottom:
			return False
		# a listing a level is open, the walk root's too
		assert open_fds() >= before + depth + 1
		return True
	for entry in start():
		if at_the_bottom(entry):
			break
	assert open_fds() == before
	walking = start()
	assert any(at_the_bottom(entry) for entry in walking)
	walking.close()
	assert open_fds() == before
	with pytest.raises(ValueError):
		for entry in start():
			if at_the_bottom(entry):
				raise ValueError('stopped')
	assert open_fds() == before
	# and a walk left to its end
	assert bottom in [rel_of(entry) for entry in start()]
	assert open_fds() == before
