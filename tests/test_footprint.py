'''
The footprint gate (spec section 6, the user's pick of 2026-11-13, "Trim, shrink, 2 arenas (Recommended)"): the daemon, run as a
process of its own over a small tree, gives back what glibc's allocators freed once it starts and once each backup commits
(malloc_trim(0), with sqlite's shrink_memory), under MALLOC_ARENA_MAX=2 as its unit sets. The compile of the 17,000-line script at
every start is about 29 MB of garbage whatever the tree's size, so a small tree catches a daemon that keeps it.
'''
import json
import os
import signal
import time

import pytest

import reverberator as rv
from tests.harness import create_job, wait_until, write_rule

pytestmark = pytest.mark.unit

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


def make_tree(root):
	'''FOLDERS folders, 50 at the top each holding the rest in turn, and FILES small files spread over them.'''
	folders = []
	for top in range(50):
		folders.append(os.path.join(root, f'top{top:02d}'))
		for sub in range(FOLDERS // 50 - 1):
			folders.append(os.path.join(root, f'top{top:02d}', f'sub{sub:02d}'))
	for folder in folders:
		os.makedirs(folder)
	for i in range(FILES):
		with open(os.path.join(folders[i % len(folders)], f'f{i:05d}.txt'), 'w') as f:
			f.write(f'{i}\n' * 20)


def last_success(state_dir, job_name):
	try:
		with open(os.path.join(state_dir, f'job-{job_name}.json'), encoding='utf-8') as f:
			return json.load(f).get('last_success')
	except (OSError, ValueError):
		return None


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


def test_the_trim_is_there():
	# the gate below would pass on a libc without malloc_trim for the wrong reason
	assert rv.LIBC_MALLOC_TRIM is not None


def test_an_idle_daemon_gives_back_what_its_start_and_its_backup_freed(tmp_path, run_reverberator, process_env):
	# fails on 2c47969 ([heap] about 34 MB): nothing gave back the compile's garbage or the comparison's
	job = create_job(str(tmp_path))
	make_tree(job.monitor)
	rule = write_rule(job, min_snapshot='1')
	state_dir = process_env['REVERB_STATE_DIR']
	process_env['MALLOC_ARENA_MAX'] = '2'
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
