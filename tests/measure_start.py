'''
M1, the start measurement of round 0.55.5 (spec section 3, plan Task 15): what a start costs on 0.55.4 against the branch, on a
vault of the larger live job's shape. Each run, on a fresh copy of one vault image:

1. the daemon starts and its start's full comparison finds nothing (the vault's one version holds the tree);
2. one file is written, and the daemon is stopped before its batch is taken (Min Snapshot Time an hour): 0.55.4 writes its
   pending file, the branch nothing;
3. while it is down another file's mode changes (its mtime stays, so 0.55.4's resume check passes and it replays);
4. the measured start: from the launch until the daemon is idle again, every version it makes committed. 0.55.4 walks the tree
   for its resume check, replays the pending batch as a version and compares the whole tree into a second one; the branch
   compares the whole tree into one.

It reports, per run: the wall time of the start, and on the vault's f2fs (/sys/fs/f2fs/<loop device>/) the start's
lifetime_write_kbytes and cp_foreground_calls, read when the daemon is idle and again after a syncfs of the image (the writes
left dirty then are the start's too), cp_background_calls, the versions it made, and what the stop before it wrote. The
releases alternate, main first, and a metric where the branch's best run is worse than main's worst is flagged.

Run it as root in the test VM, with REVERB_SCRATCH set, under the python that runs the tests (the daemon is run with it):

	REVERB_SCRATCH=<scratch> python3 tests/measure_start.py --main <0.55.4's reverberator.py> --branch <the branch's reverberator.py>

Options: --runs N (3), --folders N (19000), --files N (123000), --out DIR (results.tsv and each start's output; a folder under
REVERB_SCRATCH by default), --plain (a plain folder for the vault, no image and no counters: a check of the steps alone, as
any user). It needs fs.inotify.max_user_watches above the folder count, and removes what it made under REVERB_SCRATCH.
'''
import argparse
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

# the live job's shape (spec section 3)
FOLDERS = 19000
FILES = 123000
RUNS = 3
# an image of a 1 GiB order of use (the tree's 142,000 inodes of 4 KiB, its manifest), with room for f2fs's lfs mode
IMAGE_MIB = 8192
# the daemon is idle once its process used no more than this much CPU (clock ticks, 10 ms) in each SAMPLE_SECONDS for
# QUIET_SECONDS: a comparison of the tree keeps a core busy, and an idle daemon wakes for a few microseconds a poll
SAMPLE_SECONDS = 0.2
QUIET_TICKS = 1
QUIET_SECONDS = 3.0
# a start of the live job's shape takes about a minute; one that has not gone idle in this long is stuck
START_TIMEOUT_SECONDS = 1800
# the watcher queues a write's event within one read; the resume check of 0.55.4 wants the tree a second older than its file
QUEUED_SECONDS = 2.0
JOB = 'm1'
COUNTERS = ('lifetime_write_kbytes', 'cp_foreground_calls', 'cp_background_calls')


def make_tree(root:str, folders:int, files:int) -> tuple:
	'''A tree of folders and files of 100 to 3,999 bytes, the same every time: (the file written in step 2, the file chmodded in step 3).'''
	paths = ['']
	index = 0
	while len(paths) < folders + 1:
		parent = paths[index // 40] if index >= 40 else ''
		paths.append(os.path.join(parent, f'd{index:05d}'))
		index += 1
	for rel in paths[1:]:
		os.makedirs(os.path.join(root, rel), exist_ok=True)
	written = []
	for number in range(files):
		rel = os.path.join(paths[number % len(paths)], f'f{number:06d}.txt')
		size = 100 + (number * 37) % 3900
		with open(os.path.join(root, rel), 'wb') as f:
			f.write((f'{number:06d}' * (size // 6 + 1)).encode()[:size])
		written.append(rel)
	return written[len(written) // 3], written[2 * len(written) // 3]


def ticks(pid:int) -> int:
	'''The CPU the process and its waited children used, in clock ticks (utime, stime, cutime, cstime of /proc/<pid>/stat).'''
	with open(f'/proc/{pid}/stat') as f:
		text = f.read()
	return sum(int(field) for field in text[text.rindex(')') + 2:].split()[11:15])


def versions(job_vault:str) -> int:
	return sum(1 for name in os.listdir(job_vault) if name.startswith('V') and '--' in name and os.path.isdir(os.path.join(job_vault, name))) if os.path.isdir(job_vault) else 0


def status(state:str) -> dict:
	try:
		with open(os.path.join(state, f'job-{JOB}.json'), encoding='utf-8') as f:
			return json.load(f)
	except (OSError, ValueError):
		return {}


def until_idle(proc, job_vault:str, state:str, launched_wall:float, launched:float) -> float:
	'''
	Wait until the daemon is idle, once it has marked a batch done since its launch: the seconds from launched (monotonic) to
	its last activity, a sample with CPU used, a version folder made, or its status written.
	'''
	last_ticks, last_versions = ticks(proc.pid), versions(job_vault)
	active = time.monotonic()
	while True:
		if proc.poll() is not None:
			raise RuntimeError(f'the daemon exited with {proc.returncode}')
		if time.monotonic() - launched > START_TIMEOUT_SECONDS:
			raise RuntimeError(f'the daemon did not go idle in {START_TIMEOUT_SECONDS} s')
		time.sleep(SAMPLE_SECONDS)
		now_ticks, now_versions = ticks(proc.pid), versions(job_vault)
		if now_ticks - last_ticks > QUIET_TICKS or now_versions != last_versions:
			active = time.monotonic()
		last_ticks, last_versions = now_ticks, now_versions
		record = status(state)
		done = (record.get('last_success') or 0) >= launched_wall
		if done and time.monotonic() - active >= QUIET_SECONDS:
			written = (record.get('updated') or launched_wall) - launched_wall
			return max(active - launched, written)


def counters(device:str) -> dict:
	if device is None:
		return {name: None for name in COUNTERS}
	found = {}
	for name in COUNTERS:
		with open(f'/sys/fs/f2fs/{os.path.basename(device)}/{name}') as f:
			found[name] = int(f.read().split()[0])
	return found


def delta(after:dict, before:dict) -> dict:
	return {name: None if after[name] is None else after[name] - before[name] for name in after}


class Run:
	'''One daemon process of a release, its output in log.'''
	def __init__(self, script:str, rule:str, state:str, log:str):
		env = dict(os.environ, REVERB_STATE_DIR=state, PYTHONUNBUFFERED='1')
		self.out = open(log, 'w', encoding='utf-8', errors='surrogateescape')
		self.launched_wall, self.launched = time.time(), time.monotonic()
		self.proc = subprocess.Popen([sys.executable, script, '--no_log', '-ld', os.path.dirname(log), rule], env=env, stdout=self.out,
			stderr=subprocess.STDOUT, start_new_session=True)

	def stop(self) -> None:
		self.proc.send_signal(signal.SIGTERM)
		try:
			self.proc.wait(timeout=600)
		finally:
			if self.proc.poll() is None:
				self.proc.kill()
				self.proc.wait()
			self.out.close()


def spread_verdicts(rows:list) -> list:
	'''For each number, main's and the branch's runs, and whether the branch's best is worse than main's worst.'''
	lines = []
	for key in ('wall_s', 'write_kb_idle', 'write_kb_flushed', 'cp_fg_idle', 'cp_fg_flushed', 'cp_bg_flushed'):
		main = [row[key] for row in rows if row['release'] == 'main' and row[key] is not None]
		branch = [row[key] for row in rows if row['release'] == 'branch' and row[key] is not None]
		if not main or not branch:
			continue
		worse = min(branch) > max(main)
		lines.append(f'{key}: main {sorted(main)} (median {statistics.median(main):g}), branch {sorted(branch)} (median {statistics.median(branch):g})'
			+ (': THE BRANCH COSTS MORE BEYOND THE SPREAD' if worse else ''))
	return lines


def main(argv=None) -> int:
	parser = argparse.ArgumentParser(description='M1: the cost of a start, 0.55.4 against the branch (tests/measure_start.py).')
	parser.add_argument('--main', required=True, help="0.55.4's reverberator.py")
	parser.add_argument('--branch', required=True, help="the branch's reverberator.py")
	parser.add_argument('--runs', type=int, default=RUNS)
	parser.add_argument('--folders', type=int, default=FOLDERS)
	parser.add_argument('--files', type=int, default=FILES)
	parser.add_argument('--out', default=None)
	parser.add_argument('--plain', action='store_true', help='a plain folder for the vault: the steps alone, no counters')
	args = parser.parse_args(argv)
	sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
	from tests.harness import create_job, write_rule
	scratch = os.environ.get('REVERB_SCRATCH')
	if not scratch:
		parser.error('REVERB_SCRATCH is not set')
	if not args.plain:
		from tests.scratch_images import LoopImage, flush_scratch
		if os.geteuid() != 0:
			parser.error('the image needs root (or --plain)')
	with open('/proc/sys/fs/inotify/max_user_watches') as f:
		watches = int(f.read())
	if watches < args.folders + 1000:
		parser.error(f'fs.inotify.max_user_watches is {watches}: the daemon watches {args.folders + 1} folders; raise it above that first')
	scripts = {'main': os.path.abspath(args.main), 'branch': os.path.abspath(args.branch)}
	work = tempfile.mkdtemp(prefix='m1-', dir=scratch)
	out = args.out or os.path.join(work, 'out')
	os.makedirs(out, exist_ok=True)
	rows = []
	try:
		job = create_job(os.path.join(work, 'job'), JOB)
		vault = job.vault
		# made at each run, a mount point or a folder
		os.rmdir(vault)
		print(f'making a tree of {args.folders} folders and {args.files} files', flush=True)
		written, chmodded = (os.path.join(job.monitor, rel) for rel in make_tree(job.monitor, args.folders, args.files))
		original = {path: (open(path, 'rb').read(), os.stat(path)) for path in (written, chmodded)}

		def reset_tree():
			for path, (data, st) in original.items():
				with open(path, 'wb') as f:
					f.write(data)
				os.chmod(path, st.st_mode & 0o7777)
				os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))

		def run_until_idle(release, state, log):
			run = Run(scripts[release], job.rule_path, state, log)
			try:
				run.seconds = until_idle(run.proc, job.job_vault, state, run.launched_wall, run.launched)
			except BaseException:
				run.stop()
				raise
			return run

		def mounted_vault(source):
			if args.plain:
				if source is not None:
					subprocess.run(['cp', '-a', source, vault], check=True)
				else:
					os.makedirs(vault)
				return None
			image = LoopImage(os.path.join(work, 'images'), IMAGE_MIB, source=source, mount_point=vault)
			image.__enter__()
			return image

		def unmount(image, keep=None):
			if args.plain:
				if keep is not None:
					os.replace(vault, keep)
				else:
					shutil.rmtree(vault)
				return
			image.keep = keep
			image.__exit__()

		write_rule(job, min_snapshot='3600', max_snapshot='86400')
		# the vault every run starts from: its one version, made by 0.55.4, as a live vault was
		print('making the vault both releases start from', flush=True)
		template = os.path.join(work, 'template')
		image = mounted_vault(None)
		try:
			run_until_idle('main', os.path.join(work, 'state-template'), os.path.join(out, 'template.log')).stop()
		finally:
			unmount(image, keep=template)
		order = [release for _ in range(args.runs) for release in ('main', 'branch')]
		for number, release in enumerate(order, 1):
			reset_tree()
			write_rule(job, min_snapshot='3600', max_snapshot='86400')
			image = mounted_vault(template)
			device = None if image is None else image.device
			try:
				state = os.path.join(work, f'state-{number}')
				# 1. a start that finds nothing; 2. a write queued, and the stop
				first = run_until_idle(release, state, os.path.join(out, f'{number}-{release}-first.log'))
				with open(written, 'ab') as f:
					f.write(b' written before the stop')
				time.sleep(QUEUED_SECONDS)
				if not args.plain:
					flush_scratch(vault)
				before_stop = counters(device)
				first.stop()
				if not args.plain:
					flush_scratch(vault)
				stop_kb = delta(counters(device), before_stop)['lifetime_write_kbytes']
				pending = os.path.lexists(os.path.join(job.job_vault, '.reverberator_pending_transactions.nsv'))
				# 3. while down, a mode change that keeps the mtime
				os.chmod(chmodded, 0o600)
				before = counters(device)
				made_before = versions(job.job_vault)
				# 4. the start
				start = run_until_idle(release, state, os.path.join(out, f'{number}-{release}-start.log'))
				idle = delta(counters(device), before)
				if not args.plain:
					flush_scratch(vault)
				flushed = delta(counters(device), before)
				made = versions(job.job_vault) - made_before
				start.stop()
				with open(os.path.join(out, f'{number}-{release}-start.log'), encoding='utf-8', errors='replace') as f:
					created = f.read().count('Created new backup at ')
				row = {'run': number, 'release': release, 'wall_s': round(start.seconds, 2),
					'write_kb_idle': idle['lifetime_write_kbytes'], 'write_kb_flushed': flushed['lifetime_write_kbytes'],
					'cp_fg_idle': idle['cp_foreground_calls'], 'cp_fg_flushed': flushed['cp_foreground_calls'],
					'cp_bg_flushed': flushed['cp_background_calls'], 'versions': made, 'created_lines': created,
					'pending_file_at_stop': pending, 'stop_write_kb': stop_kb}
				rows.append(row)
				print('\t'.join(f'{key}={value}' for key, value in row.items()), flush=True)
			finally:
				unmount(image)
		with open(os.path.join(out, 'results.tsv'), 'w', encoding='utf-8') as f:
			f.write('\t'.join(rows[0]) + '\n')
			for row in rows:
				f.write('\t'.join(str(value) for value in row.values()) + '\n')
		verdicts = spread_verdicts(rows)
		for line in verdicts:
			print(line)
		print(f'results: {os.path.join(out, "results.tsv")}')
		return 1 if any('BEYOND THE SPREAD' in line for line in verdicts) else 0
	finally:
		# the out folder stays when it was named; the rest of what this made goes
		for name in os.listdir(work):
			path = os.path.join(work, name)
			if os.path.realpath(path) == os.path.realpath(out):
				continue
			shutil.rmtree(path) if os.path.isdir(path) and not os.path.islink(path) else os.remove(path)
		if args.out is not None:
			shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
	sys.exit(main())
