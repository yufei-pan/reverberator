'''
The footprint gate (spec section 6, the user's pick of 2026-11-13, "Trim, shrink, 2 arenas (Recommended)"): the daemon, run as a
process of its own over a small tree, gives back what glibc's allocators freed once it starts and once each backup commits
(malloc_trim(0), with sqlite's shrink_memory), under MALLOC_ARENA_MAX=2 as its unit sets. The compile of the 17,000-line script at
every start is about 29 MB of garbage whatever the tree's size, so a small tree catches a daemon that keeps it. That gate measures
after a restart's backup, which leaves about 2 MB for the trim after each commit to give back: it passes without that trim. The
second (round 0.55.6's spec section 11, D15) measures after a burst of batches, and its run with that trim stubbed out shows it
fails when the trim goes through the start's commit (V0), in the measured process: the 14 MB or so that commit leaves is what tells.
It bounds the growth of each later batch only coarsely (more than about 280 kB a batch, 5.5 MB over its 20), and cannot tell a trim
lost only after the later commits: the burst's batches (100 files) free about 2 MB each, and what one freed the next reuses, so a
daemon that keeps its trim after V0 and loses it after every later commit ends inside the trimmed runs' 3 MB spread. A unit pin
counts the calls instead: test_every_commit_of_a_job_gives_back_what_it_freed.
'''
import json
import os
import shutil
import signal
import threading
import time

import pytest

import reverberator as rv
from tests.harness import committed_versions, create_job, seed_monitor, wait_until, write_rule
from tests.test_jobs import IdleFlag, a_changed_file

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
# 42.5 MB sits halfway, 5.5 MB from each. [heap] is left out: 5,556 to 5,960 kB trimmed, 15,704 to 18,628 stubbed in five runs of six,
# but 6,440 in the sixth, whose freed memory sat outside [heap] (its anon was the others'). The figures are disjoint, by 480 kB, but a
# bound in that gap has about 240 kB of margin each side, under the 404 kB the trimmed runs alone spread
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


def stop_and_clear(daemon, job):
	'''A passed gate's end: the daemon stopped, then the job's tree and vault removed; a failed gate keeps them. The burst leaves 21
	versions of a 23,000 entry tree, and pytest keeps its last three basetemps.'''
	daemon.send_signal(signal.SIGTERM)
	daemon.wait(timeout=60)
	shutil.rmtree(job.monitor)
	shutil.rmtree(job.vault)


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


@pytest.mark.unit
def test_every_commit_of_a_job_gives_back_what_it_freed(job, poll_fast, monkeypatch):
	# pin: counts the calls of release_idle_memory() the backuper makes, one for each commit of a job (V0, and two batches that each
	# change a file) and one for a batch that commits no version (a scan of a folder that matches the vault: no batch of the burst
	# gate takes that path). The burst gate below cannot tell a trim lost only after the later commits (a probe that kept the first
	# call's ended inside the trimmed runs' range)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b', 'd/c.txt': 'c'})
	calls = []
	monkeypatch.setattr(rv, 'release_idle_memory', lambda manifest: calls.append(manifest))
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	flag = IdleFlag()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag),
		kwargs=dict(job=control), daemon=True)
	thread.start()

	def back_to_waiting(expected_calls, expected_versions, what):
		# the backuper waits for a batch again: what follows the commit is done too, so a second call would be counted
		wait_until(lambda: len(calls) >= expected_calls, message=f'{what}: no call of release_idle_memory() after its commit')
		flag.idle.clear()
		wait_until(flag.idle.is_set, message=f'{what}: the backuper never waited for the next batch')
		assert control.failure is None, control.failure
		assert (len(calls), len(committed_versions(job))) == (expected_calls, expected_versions), what

	def batch(events):
		with lock:
			queue.read_wall_ns = time.time_ns()
			for event in events:
				queue.append(event)
		flag.set()

	try:
		back_to_waiting(1, 1, 'the first version')
		batch([a_changed_file(job, 'a.txt')])
		back_to_waiting(2, 2, 'a first batch')
		batch([a_changed_file(job, 'b.txt')])
		back_to_waiting(3, 3, 'a second batch')
		batch([rv.ChangeEvent(time.monotonic(), True, 'scan', os.path.join(job.monitor, 'd'), None)])
		back_to_waiting(4, 3, 'a batch that makes no version')
	finally:
		control.fail('test done')
		thread.join(timeout=5)
		assert not thread.is_alive()


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
	stop_and_clear(daemon, job)


@pytest.mark.process
@pytest.mark.parametrize('trim', ['after_each_commit', 'stubbed'])
def test_an_idle_daemon_after_a_burst_gives_back_what_its_commits_freed(tmp_path, run_reverberator, process_env, trim):
	# 'stubbed' must break the bound, so the gate can tell a missing trim: footprint_child.py makes release_idle_memory() a no-op.
	# What it tells: a trim lost through the start's commit (V0), in the measured process. The daemon whose release_idle_memory() loses
	# its trim_heap() fails 'after_each_commit' (RssAnon + VmSwap 52,244 kB) and passes the start gate. What it cannot tell: a trim lost
	# only after the later commits (a probe that kept the first call's, ended at 37,052 kB, inside the trimmed range), or sqlite's
	# shrink alone (about 2 MB, inside the runs' 3 MB spread); test_every_commit_of_a_job_gives_back_what_it_freed counts the calls
	job = create_job(str(tmp_path))
	files = make_tree(job.monitor)
	rule = write_rule(job, min_snapshot='1')
	state_dir = process_env['REVERB_STATE_DIR']
	daemon_env(tmp_path, process_env)
	if trim == 'stubbed':
		process_env['REVERB_FOOTPRINT_NO_COMMIT_TRIM'] = '1'
	else:
		# a shell that exported the switch must not stub the trimmed case
		process_env.pop('REVERB_FOOTPRINT_NO_COMMIT_TRIM', None)
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
	if trim == 'stubbed':
		assert anon > BURST_ANON_LIMIT_KB, f'the stubbed daemon no longer breaks the bound: the gate cannot tell a lost trim; measure again (spec section 11). {measured}'
	else:
		assert anon <= BURST_ANON_LIMIT_KB, measured
	stop_and_clear(daemon, job)
