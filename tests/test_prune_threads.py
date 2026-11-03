'''
decrement_stepper() replaces the next version's chain links on a few threads (round 15). Its results stay those of the
walk on one thread it replaced, kept as the oracle (tests/prune_oracle.py): on random vaults, both versions' trees, both
change lists and their names, the return value, the dict, the FAILED marker and every line with its level and in its
order, whether links are hard linked or moved, with errors at random entries, links two of which name one copy,
dangling links, user's links, links the rows cannot tell, what a cut off run leaves, and a disk that drops.
'''
import errno
import os
import random
import re
import shutil
import stat
import threading
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import create_job, write_change_list
from tests.prune_oracle import oracle_decrement_stepper

pytestmark = pytest.mark.unit

V0 = 'V0--2021-01-01_00-00-00_-0800'
V1 = 'V1--2021-01-02_00-00-00_-0800'
SALT = b's' * 16
SEEDS = 500
real_lstat = os.lstat
# a temp a prune links a copy under is named by the copy's inode, which each build of a vault gives anew
TEMP = re.compile(r'\.[0-9a-f]{32}' + re.escape(rv.PARTIAL_COPY_SUFFIX))
# the one line of a helper a thread runs: logged as it is met, so its place among the others is the thread's
HELPER_LINE = 'Telling the moved links of '


@pytest.fixture
def small_chunks(monkeypatch):
	# many chunks, and a short window, on a small tree: the threads interleave
	monkeypatch.setattr(rv, 'REFERENCED_COPY_CHUNK', 3)
	monkeypatch.setattr(rv, 'REFERENCED_COPY_WINDOW', 2)


def chain_text(rel, named=None):
	'''The text of the chain link at rel of V1 naming named (rel itself by default) in V0.'''
	return '../' * (rel.count('/') + 1) + V0 + '/' + (rel if named is None else named)


def build(root, seed):
	'''
	A job vault of V0 and V1 under root, made the same from seed every time, and what to run the prune with: (job,
	vault_info_dict, the failures to inject as {path: kind}, how: a dict of the run's other choices).
	'''
	rng = random.Random(seed)
	job = create_job(root)
	v0, v1 = os.path.join(job.job_vault, V0), os.path.join(job.job_vault, V1)
	how = {
		'hard_links': rng.random() < 0.7, 'no_link_errno': rng.choice([errno.EXDEV, errno.EPERM]),
		'salt': rng.choice([SALT, None]), 'pool_drop': rng.choice([None] * 6 + [1, 2]),
		'rm_fails': rng.random() < 0.05, 'gone': rng.random() < 0.03,
	}
	folders = ['']
	for i in range(rng.randint(1, 5)):
		parent = rng.choice(folders)
		folders.append(f'{parent}d{i}/')
	files = []
	for i in range(rng.randint(5, 40)):
		files.append(f'{rng.choice(folders)}f{i}')
	for folder in folders:
		os.makedirs(os.path.join(v0, folder), exist_ok=True)
		os.makedirs(os.path.join(v1, folder), exist_ok=True)
	for rel in files:
		with open(os.path.join(v0, rel), 'w') as f:
			f.write(rel * rng.choice([0, 1, 50, 500]))
	# a user's symlink V0 stored, which V1 chain links to
	stored_links = []
	for i in range(rng.randint(0, 3)):
		rel = f'{rng.choice(folders)}s{i}'
		os.symlink(rng.choice(['/etc/hostname', 'nowhere', '../x']), os.path.join(v0, rel))
		stored_links.append(rel)
	rows = []
	failures = {}
	chain = []
	for rel in files + stored_links:
		at = os.path.join(v1, rel)
		roll = rng.random()
		if roll < 0.08:
			# changed in V1
			with open(at, 'w') as f:
				f.write('new')
			rows.append((rel, 'create', None))
		elif roll < 0.12:
			# deleted in V1
			continue
		elif roll < 0.16:
			# a cut off run replaced it already
			os.link(os.path.join(v0, rel), at, follow_symlinks=False)
		else:
			os.symlink(chain_text(rel), at)
			chain.append(rel)
	for i in range(rng.randint(0, 4)):
		# dangling chain links: their copies are gone
		rel = f'{rng.choice(folders)}g{i}'
		os.symlink(chain_text(rel), os.path.join(v1, rel))
	for i in range(rng.randint(0, 4)):
		# user's links: one of chain form whose create row lands on it, one of no chain form
		rel = f'{rng.choice(folders)}u{i}'
		if rng.random() < 0.5:
			os.symlink(chain_text(rel, rng.choice(files)), os.path.join(v1, rel))
			rows.append((rel, 'create', None))
		else:
			os.symlink(rng.choice(['/etc/hostname', os.path.join(v0, rng.choice(files)), 'f0']), os.path.join(v1, rel))
	for i in range(rng.randint(0, 4)):
		# links to another path's copy: moved there (a row says so), or the rows cannot tell, which makes two links naming
		# one copy when that copy's own link is there too
		rel = f'{rng.choice(folders)}m{i}'
		named = rng.choice(files + stored_links)
		os.symlink(chain_text(rel, named), os.path.join(v1, rel))
		if rng.random() < 0.5:
			rows.append((rel, 'move', named))
	if rng.random() < 0.2:
		# a link naming a folder of V0
		os.symlink(chain_text('to_folder', folders[-1].rstrip('/') or 'd0'), os.path.join(v1, 'to_folder'))
	for rel in rng.sample(chain, min(len(chain), rng.randint(0, 3))):
		# temps a cut off run left: its own copy linked, or something else under that name
		target = os.path.join(v0, rel)
		temp = rv.prune_link_path(os.path.join(v1, rel), real_lstat(target), how['salt'])
		if rng.random() < 0.9:
			os.link(target, temp, follow_symlinks=False)
		else:
			with open(temp, 'w') as f:
				f.write('not its copy')
	# errors at random entries, in a third of the vaults
	errors = rng.random() < 0.35
	for rel in rng.sample(chain, min(len(chain), rng.randint(1, 4) * errors)):
		failures[os.path.join(v1, rel)] = rng.choice(['lstat', 'readlink', 'rename', 'rename_late'])
	for rel in rng.sample(files, min(len(files), rng.randint(0, 2) * errors)):
		failures[os.path.join(v0, rel)] = rng.choice(['lstat', 'link'])
	sizes = {}
	for version in (v0, v1):
		sizes[version] = (rng.randint(0, 10 ** 6), rng.randint(0, 200))
		write_change_list(rv.change_list_path(version, *sizes[version]), job.monitor, rows if version == v1 else [])
	if how['gone']:
		shutil.rmtree(v0)
	info = OrderedDict((number, rv.VaultEntry(number, version, 0, *sizes[version])) for number, version in enumerate((v0, v1)))
	return job, info, failures, how


class Killed(BaseException):
	'''The daemon killed in the middle of a prune.'''


def inject(monkeypatch, failures, how):
	'''The failures of build() and how's filesystem and pools, in place for one prune.'''
	def eio(path):
		return OSError(errno.EIO, os.strerror(errno.EIO), path)
	def lstat(path, *args, **kwargs):
		if failures.get(os.fspath(path)) == 'lstat':
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	real_readlink, real_link, real_rename = os.readlink, os.link, os.rename
	def readlink(path, *args, **kwargs):
		if failures.get(os.fspath(path)) == 'readlink':
			raise eio(path)
		return real_readlink(path, *args, **kwargs)
	def link(source, dest, *args, **kwargs):
		if not how['hard_links']:
			raise OSError(how['no_link_errno'], os.strerror(how['no_link_errno']), source)
		if failures.get(os.fspath(source)) == 'link':
			raise eio(source)
		return real_link(source, dest, *args, **kwargs)
	def rename(source, dest, *args, **kwargs):
		kind = failures.get(os.fspath(dest))
		if kind == 'rename':
			raise eio(dest)
		if kind == 'kill' and TEMP.search(os.path.basename(os.fspath(source))):
			raise Killed()
		real_rename(source, dest, *args, **kwargs)
		if kind == 'rename_late':
			raise eio(dest)
	monkeypatch.setattr(os, 'lstat', lstat)
	monkeypatch.setattr(os, 'readlink', readlink)
	monkeypatch.setattr(os, 'link', link)
	monkeypatch.setattr(os, 'rename', rename)
	problems = [0]
	def problem(self):
		problems[0] += 1
		return 'disk /b1 of pool /pool is not mounted' if problems[0] == how['pool_drop'] else None
	monkeypatch.setattr(rv.PoolGuard, 'problem', problem)
	if how['rm_fails']:
		real_run = rv.multiCMD.run_command
		monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: 1 if command[0] == 'rm' else real_run(command, *args, **kwargs))


def snapshot(root):
	'''{rel: what it is} of everything under root, a temp by its folder alone, with the rels that share each inode.'''
	def shown(rel):
		return TEMP.sub('<temp>', rel)
	found, by_inode = {}, {}
	for folder, folders, files in os.walk(root):
		for name in sorted(folders + files):
			path = os.path.join(folder, name)
			rel = shown(os.path.relpath(path, root))
			st = real_lstat(path)
			if stat.S_ISLNK(st.st_mode):
				what = ('link', os.readlink(path))
			elif stat.S_ISDIR(st.st_mode):
				what = ('folder',)
			else:
				with open(path, 'rb') as f:
					held = f.read()
				if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME):
					# each build writes its rows at its own time
					held = b'\n'.join(b'\0'.join(field for at, field in enumerate(line.split(b'\0')) if at != 1) for line in held.split(b'\n'))
				what = ('file', held, stat.S_IMODE(st.st_mode))
			if not stat.S_ISDIR(st.st_mode):
				by_inode.setdefault((st.st_dev, st.st_ino), []).append(rel)
			found.setdefault(rel, []).append(what)
	for rels in by_inode.values():
		for rel in rels:
			found[rel].append(tuple(sorted(rels)))
	return {rel: sorted(map(repr, whats)) for rel, whats in found.items()}


def run(stepper, root, seed, monkeypatch):
	'''What stepper does with build(root, seed): (result or the exception's type, the dict, the vault, lines, FAILED).'''
	if os.path.exists(root):
		shutil.rmtree(root)
	for table in (rv.VERSION_MOVES, rv.VERSION_MOVES_WARNED, rv.PRUNE_ABORTED, rv.REAL_VAULT_FOLDERS):
		table.clear()
	rv.PRUNE_SALT_MISSING.clear()
	job, info, failures, how = build(root, seed)
	lines, failed = [], []
	with monkeypatch.context() as patch:
		patch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, error=False, warning=False, **kwargs:
			lines.append(('error' if error else 'warning' if warning else 'info', TEMP.sub('<temp>', str(message)))))
		patch.setattr(rv, 'job_log', lambda job_name, text: failed.append(text))
		inject(patch, failures, how)
		try:
			result = stepper(info, job.job_name, job.monitor, prune_salt=how['salt'])
		except rv.PoolNotReady as e:
			result = type(e)
	# the time line is the new prune's alone, and a helper's line on a thread comes where the thread met it
	timed = [line for line in lines if line[1].startswith(('Pruned ', 'Kept '))]
	helper = sorted(line for line in lines if line[1].startswith(HELPER_LINE))
	lines = [line for line in lines if line not in timed and not line[1].startswith(HELPER_LINE)]
	return (result, list(info.items()), snapshot(job.job_vault), lines, helper, failed), timed, how


def test_the_prune_on_threads_comes_out_as_the_walk_on_one_had_it(tmp_path, monkeypatch, small_chunks):
	root = str(tmp_path / 'vaults')
	seen = {'moved': 0, 'hard linked': 0, 'two links': 0, 'aborted': 0, 'pool': 0, 'removed': 0, 'dangling': 0, 'again': 0}
	for seed in range(SEEDS):
		old, _, how = run(oracle_decrement_stepper, root, seed, monkeypatch)
		new, timed, _ = run(rv.decrement_stepper, root, seed, monkeypatch)
		if new != old:
			parts = ('result', 'dict', 'vault', 'lines', 'helper lines', 'FAILED')
			differ = {parts[at]: (o, n) for at, (o, n) in enumerate(zip(old, new)) if o != n}
			if 'lines' in differ:
				o, n = differ['lines']
				first = next(at for at in range(max(len(o), len(n))) if o[at:at + 1] != n[at:at + 1])
				differ['lines'] = (o[first:first + 5], n[first:first + 5])
			if 'vault' in differ:
				o, n = differ['vault']
				differ['vault'] = {rel: (o.get(rel), n.get(rel)) for rel in sorted(set(o) | set(n)) if o.get(rel) != n.get(rel)}
			pytest.fail(f'seed {seed}, {how}: the oracle and the new prune differ in (old, new) {differ}')
		result, _, _, lines, _, failed = new
		assert len(timed) == 1 and timed[0][0] == 'info', f'seed {seed}'
		messages = ' '.join(message for _, message in lines)
		seen['moved'] += any(message.startswith('Moving ') for _, message in lines) or 'Not moving ' in messages
		seen['hard linked'] += how['hard_links'] and not failed
		seen['two links'] += 'both link to' in messages
		seen['aborted'] += bool(failed)
		seen['pool'] += result is rv.PoolNotReady
		seen['removed'] += not failed and result is not rv.PoolNotReady
		seen['dangling'] += 'Leaving the dangling link' in messages
		seen['again'] += 'which an earlier run left' in messages
	# every case came up
	assert all(seen.values()), seen


def simple_vault(root, count=60):
	'''A V0 of count files in 3 folders and a V1 of their chain links, with change lists: (job, vault_info_dict, rels).'''
	job = create_job(root)
	v0, v1 = os.path.join(job.job_vault, V0), os.path.join(job.job_vault, V1)
	rels = [f'd{i % 3}/f{i:03d}' for i in range(count)]
	for rel in rels:
		os.makedirs(os.path.dirname(os.path.join(v0, rel)), exist_ok=True)
		os.makedirs(os.path.dirname(os.path.join(v1, rel)), exist_ok=True)
		with open(os.path.join(v0, rel), 'w') as f:
			f.write(rel)
		os.symlink(chain_text(rel), os.path.join(v1, rel))
	for version in (v0, v1):
		write_change_list(rv.change_list_path(version, 4096 * count, count), job.monitor, [])
	return job, OrderedDict((number, rv.VaultEntry(number, version, 0, 4096 * count, count)) for number, version in enumerate((v0, v1))), rels


def test_a_kill_on_a_thread_is_raised_once_the_rows_before_it_are_handled_and_leaves_no_thread(tmp_path, monkeypatch, small_chunks):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	v0, v1 = (entry.path for entry in info.values())
	walked = []
	real_walk = rv.iter_tree_entries
	def walk(*args, **kwargs):
		for entry in real_walk(*args, **kwargs):
			walked.append(entry[0])
			yield entry
	killed = os.path.join(v1, rels[len(rels) // 2])
	lines = []
	with monkeypatch.context() as patch:
		patch.setattr(rv, 'iter_tree_entries', walk)
		patch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: lines.append(str(message)))
		inject(patch, {killed: 'kill'}, dict(hard_links=True, pool_drop=None, rm_fails=False))
		before = threading.active_count()
		with pytest.raises(Killed):
			rv.decrement_stepper(OrderedDict(info), job.job_name, job.monitor, prune_salt=SALT)
		assert threading.active_count() == before
	# it was not replaced, and each other entry is its link or its copy, as a chunk before it may stop too; V0 stays
	# whole, and so do the records
	files = [path for path in walked if not path.endswith('/')]
	assert files.index(killed) > 0
	for path in files:
		rel = os.path.relpath(path, v1)
		assert (os.readlink(path) == chain_text(rel)) if os.path.islink(path) else open(path).read() == rel
	assert os.path.islink(killed) and all(os.path.isfile(os.path.join(v0, rel)) for rel in rels)
	assert not any(line.startswith('Renaming ') for line in lines)
	# a rerun finishes it
	assert rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT) != (0, 0)
	assert not os.path.exists(v0)
	for rel in rels:
		assert not os.path.islink(os.path.join(v1, rel)) and open(os.path.join(v1, rel)).read() == rel


@pytest.mark.parametrize('exc', [ValueError('bad'), MemoryError()])
def test_what_a_thread_raises_comes_out_and_no_thread_is_left(tmp_path, monkeypatch, small_chunks, exc):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	v0 = info[0].path
	calls = []
	lock = threading.Lock()
	real_readlink = os.readlink
	def readlink(path, *args, **kwargs):
		with lock:
			calls.append(path)
			hit = len(calls) == 5
		if hit:
			raise exc
		return real_readlink(path, *args, **kwargs)
	monkeypatch.setattr(os, 'readlink', readlink)
	before = threading.active_count()
	with pytest.raises(type(exc)):
		rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT)
	assert threading.active_count() == before
	# a stop, not a removal
	assert all(os.path.isfile(os.path.join(v0, rel)) for rel in rels)


def test_one_line_tells_how_long_the_prune_took(tmp_path, monkeypatch):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	v0 = info[0].path
	lines = []
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, error=False, warning=False, **kwargs:
		lines.append(('error' if error else 'warning' if warning else 'info', str(message))))
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT)
	timed = [line for line in lines if line[1].startswith(('Pruned ', 'Kept '))]
	assert len(timed) == 1 and timed[0][0] == 'info'
	assert re.fullmatch(re.escape(f'Pruned {v0} in ') + r'\d+\.\d s: 60 links replaced in \d+\.\d s, removed in \d+\.\d s, '
		+ f'{rv.REFERENCED_COPY_THREADS} threads', timed[0][1]), timed


def test_a_kept_prune_says_so_in_its_time_line(tmp_path, monkeypatch):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	v0 = info[0].path
	lines = []
	real_run = rv.multiCMD.run_command
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: 1 if command[0] == 'rm' else real_run(command, *args, **kwargs))
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda path, message, **kwargs: lines.append(str(message)))
	monkeypatch.setattr(rv, 'job_log', lambda job_name, text: None)
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT)
	timed = [line for line in lines if line.startswith(('Pruned ', 'Kept '))]
	assert len(timed) == 1
	assert re.fullmatch(re.escape(f'Kept {v0}, as its prune stopped after ') + r'\d+\.\d s: 60 links replaced in \d+\.\d s, removal tried in \d+\.\d s, '
		+ f'{rv.REFERENCED_COPY_THREADS} threads', timed[0]), timed


def test_the_links_are_replaced_on_several_threads(tmp_path, monkeypatch, small_chunks):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	threads = set()
	real_readlink = os.readlink
	def readlink(path, *args, **kwargs):
		threads.add(threading.get_ident())
		# long enough for the other threads to take chunks meanwhile
		threading.Event().wait(0.002)
		return real_readlink(path, *args, **kwargs)
	monkeypatch.setattr(os, 'readlink', readlink)
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT)
	assert threading.get_ident() not in threads and len(threads) > 1
	for rel in rels:
		assert open(os.path.join(job.job_vault, V1, rel)).read() == rel


@pytest.mark.parametrize('top_fails', [False, True])
def test_the_folders_at_the_top_are_removed_on_threads_then_the_whole_one_decides(tmp_path, monkeypatch, top_fails):
	job, info, rels = simple_vault(str(tmp_path / 'vault'))
	v0 = info[0].path
	commands = []
	lock = threading.Lock()
	real_run = rv.multiCMD.run_command
	def run(command, *args, **kwargs):
		if command[0] != 'rm':
			return real_run(command, *args, **kwargs)
		with lock:
			commands.append((threading.get_ident(), command))
		if top_fails and command[-1] != v0:
			# one that fails leaves the folder to the last
			return 1
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	assert rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=SALT) != (0, 0)
	assert not os.path.exists(v0) and not [name for name in os.listdir(job.job_vault) if name.startswith(V0)]
	assert sorted(command for _, command in commands[:-1]) == [['rm', '-rf', os.path.join(v0, f'd{i}')] for i in range(3)]
	assert commands[-1] == (threading.get_ident(), ['rm', '-rf', v0])
	assert all(thread != threading.get_ident() for thread, _ in commands[:-1])
