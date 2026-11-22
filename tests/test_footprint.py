'''
The footprint gate (spec section 6, the user's pick of 2026-11-13, "Trim, shrink, 2 arenas (Recommended)"): the daemon, run as a
process of its own over a small tree, gives back what glibc's allocators freed once it starts and once each backup commits
(malloc_trim(0), with sqlite's shrink_memory), under MALLOC_ARENA_MAX=2 as its unit sets. The compile of the 17,000-line script at
every start is about 29 MB of garbage whatever the tree's size, so a small tree catches a daemon that keeps it. That gate measures
after a restart's backup, which leaves about 2 MB for the trim after each commit to give back: it passes without that trim. The
second (round 0.55.6's spec section 11, D15) measures after a burst of batches, and its run with that trim stubbed out shows it
fails when the trim goes.
'''
import json
import os
import signal
import time

import pytest

import reverberator as rv
from tests.harness import create_job, wait_until, write_rule

HERE = os.path.dirname(os.path.abspath(__file__))

# the footprint report's gate (section 6): one job of 3,000 folders and 19,843 files, a restart, then idle. Plain 0.55.4: [heap]
# 34.0 MB and RssAnon + VmSwap 57 to 60 MB; trimmed: 5.8 and 25 to 29 MB, 10.3 MB of [heap] with MALLOC_ARENA_MAX=2. The bounds
# sit 11 MB above the highest fixed figure and 17 below the lowest plain one
HEAP_LIMIT_KB = 15 * 1024
ANON_LIMIT_KB = 40 * 1024
FOLDERS = 3000
FILES = 20000
# a start over this tree: the full comparison of 20,000 files, about 10 s in the report's container; generous for a loaded host
START_SECONDS = 300
# the report's idle point after the commit
IDLE_SECONDS = 5
# the gate after a burst: 2,000 of the tree's files rewritten in 20 waves of 100, each wave written once the one before committed,
# so each is a batch of its own (spec section 11; in its measurement every run made 21 versions, V0 and one a wave)
BURST_WAVES = 20
WAVE_FILES = 100
# a wave's batch: the 1 s snapshot delay and the backup of 100 files, 1.11 s on a quiet host and up to 1.52 s at a load of 85 in
# the measurement's container; generous for a loaded host
WAVE_SECONDS = 60
# its bound, measured on round 0.55.6 (Task 16, Docker, uid 65534, six runs each way, at loads of 5 to 85): after the burst and
# IDLE_SECONDS, RssAnon + VmSwap 34,912 to 37,928 kB with the trim after each commit, 49,180 to 52,128 kB with it stubbed out.
# 42.5 MB sits halfway, 5.5 MB from each. [heap] cannot tell them apart and is left out: 5,556 to 5,960 kB trimmed, 15,704 to
# 18,628 stubbed in five runs of six, but 6,440 in the sixth, whose freed memory sat outside [heap] (its anon was the others')
BURST_ANON_LIMIT_KB = 43520


def make_tree(root):
	'''FOLDERS folders, 50 at the top each holding the rest in turn, and FILES small files spread over them; the files' paths.'''
	folders, files = [], []
	for top in range(50):
		folders.append(os.path.join(root, f'top{top:02d}'))
		for sub in range(FOLDERS // 50 - 1):
			folders.append(os.path.join(root, f'top{top:02d}', f'sub{sub:02d}'))
	for folder in folders:
		os.makedirs(folder)
	for i in range(FILES):
		files.append(os.path.join(folders[i % len(folders)], f'f{i:05d}.txt'))
		with open(files[-1], 'w') as f:
			f.write(f'{i}\n' * 20)
	return files


def last_success(state_dir, job_name):
	try:
		with open(os.path.join(state_dir, f'job-{job_name}.json'), encoding='utf-8') as f:
			return json.load(f).get('last_success')
	except (OSError, ValueError):
		return None


def daemon_env(tmp_path, env):
	'''The child's environment as the unit's: MALLOC_ARENA_MAX=2, and reverberator.py compiled at its start.'''
	env['MALLOC_ARENA_MAX'] = '2'
	# the unit starts reverberator.py as a script, compiled at every start: about 29 MB of garbage to give back. The tests' daemon
	# imports it (daemon_without_syncfs.py, footprint_child.py), and an import reads a cached .pyc when a valid one stands beside it
	# (any import of reverberator by a pytest run, or by hand, writes one): no compile, no garbage, and the gate passes with no trim at
	# all. So the child looks for its cache in a folder of its own, empty, and no start writes one
	env['PYTHONPYCACHEPREFIX'] = str(tmp_path / 'pycache')
	env['PYTHONDONTWRITEBYTECODE'] = '1'


def heap_kb(pid):
	'''Rss + Swap of the process's [heap] mapping (glibc's main arena), in kB.'''
	total, in_heap = 0, False
	with open(f'/proc/{pid}/smaps', encoding='utf-8') as f:
		for line in f:
			if not line[0].isupper():
				# a mapping's own line, its address range first; its fields follow, each a capitalised name
				in_heap = line.rstrip().endswith('[heap]')
			elif in_heap and line.split()[0] in ('Rss:', 'Swap:'):
				total += int(line.split()[1])
	return total


def anon_kb(pid):
	'''RssAnon + VmSwap of the process, in kB: what it holds of its own whether the host swapped it out or not.'''
	fields = {}
	with open(f'/proc/{pid}/status', encoding='utf-8') as f:
		for line in f:
			name, _, value = line.partition(':')
			fields[name] = value.split()
	return int(fields['RssAnon'][0]) + int(fields['VmSwap'][0])


@pytest.mark.unit
def test_the_trim_is_there():
	# the gate below would pass on a libc without malloc_trim for the wrong reason
	assert rv.LIBC_MALLOC_TRIM is not None


@pytest.mark.process
def test_an_idle_daemon_gives_back_what_its_start_and_its_backup_freed(tmp_path, run_reverberator, process_env):
	# fails on 2c47969 ([heap] about 34 MB): nothing gave back the compile's garbage or the comparison's
	job = create_job(str(tmp_path))
	make_tree(job.monitor)
	rule = write_rule(job, min_snapshot='1')
	state_dir = process_env['REVERB_STATE_DIR']
	daemon_env(tmp_path, process_env)
	# the first start makes V0; the measured one is a restart, as the report's: the scan and the full comparison of the whole tree
	first = run_reverberator(rule)
	wait_until(lambda: last_success(state_dir, job.job_name) is not None, timeout=START_SECONDS, message='the first start committed no backup')
	first.send_signal(signal.SIGTERM)
	first.wait(timeout=60)
	started = time.time()
	daemon = run_reverberator(rule)
	wait_until(lambda: (last_success(state_dir, job.job_name) or 0) >= started, timeout=START_SECONDS, message='the restart committed no backup')
	time.sleep(IDLE_SECONDS)
	assert daemon.poll() is None
	heap, anon = heap_kb(daemon.pid), anon_kb(daemon.pid)
	measured = f'[heap] {heap} kB, RssAnon + VmSwap {anon} kB'
	assert heap <= HEAP_LIMIT_KB, measured
	assert anon <= ANON_LIMIT_KB, measured


@pytest.mark.process
@pytest.mark.parametrize('trim', ['after_each_commit', 'stubbed'])
def test_an_idle_daemon_after_a_burst_gives_back_what_its_commits_freed(tmp_path, run_reverberator, process_env, trim):
	# 'stubbed' must break the bound, so the gate can tell a missing trim: footprint_child.py makes release_idle_memory() a no-op. The
	# daemon whose release_idle_memory() loses its trim_heap() fails 'after_each_commit' (RssAnon + VmSwap 52,244 kB) and passes the
	# start gate; one that loses sqlite's shrink alone passes (about 2 MB, inside the runs' 3 MB spread)
	job = create_job(str(tmp_path))
	files = make_tree(job.monitor)
	rule = write_rule(job, min_snapshot='1')
	state_dir = process_env['REVERB_STATE_DIR']
	daemon_env(tmp_path, process_env)
	if trim == 'stubbed':
		process_env['REVERB_FOOTPRINT_NO_COMMIT_TRIM'] = '1'
	daemon = run_reverberator(rule, script=os.path.join(HERE, 'footprint_child.py'))
	wait_until(lambda: last_success(state_dir, job.job_name) is not None, timeout=START_SECONDS, message='the start committed no backup')
	for wave in range(BURST_WAVES):
		done = last_success(state_dir, job.job_name)
		for i in range(wave * WAVE_FILES, (wave + 1) * WAVE_FILES):
			with open(files[i], 'w') as f:
				f.write(f'{i} {wave}\n' * 30)
		wait_until(lambda: (last_success(state_dir, job.job_name) or 0) > done, timeout=WAVE_SECONDS, message=f'wave {wave} committed no backup')
	time.sleep(IDLE_SECONDS)
	assert daemon.poll() is None
	heap, anon = heap_kb(daemon.pid), anon_kb(daemon.pid)
	measured = f'trim {trim}: [heap] {heap} kB, RssAnon + VmSwap {anon} kB'
	assert (anon <= BURST_ANON_LIMIT_KB) == (trim == 'after_each_commit'), measured
