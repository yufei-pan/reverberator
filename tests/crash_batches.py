'''
The vault of the crash runs: batches 0-2 kept to 3 versions, and a mixed batch 3 (spec section 9) to kill. What each version
must hold is read from the monitored tree with the oracle's own snapshot, before the daemon sees the batch.
'''
import os
import pickle
import shutil
import subprocess
import time
from collections import deque, namedtuple, OrderedDict

import reverberator as rv
from tests.harness import create_job
from tests.vault_oracle import snapshot_tree, version_number

KEEP = 3
# every batch of a crash run, as a rule row gives them. no Only Sync Attributes, so batch 3's chmod of a file is copied (spec
# section 9's non-OSA attrib): nothing changes a shared inode, and every version's file metadata stays exact
OPTIONS = dict(keep_one_complete_backup=True, only_sync_attributes=False, keep_n_versions=KEEP, backup_size_limit='0')
# a name ending so reads as not readable in the crash child (crash_child.failing_copy_command)
UNREADABLE = '.unreadable'
BATCH3_FILE = 'crash_batch3.pickle'
T0 = 1700000000_000000000
BAD_NAME = os.fsdecode(b'bad\xff.txt')
NEWLINE_NAME = 'new\nline.txt'


def put_text(monitor: str, rel: str, text: str, mtime: int = None) -> None:
	path = os.path.join(monitor, rel)
	os.makedirs(os.path.dirname(path), exist_ok=True)
	with open(path, 'w') as f:
		f.write(text)
	stamp = time.time_ns() if mtime is None else mtime
	os.utime(path, ns=(stamp, stamp))


def raw_events(monitor: str, events: list) -> deque:
	'''The watcher's ChangeEvents of events, each (is_dir, event, rel, moved_from rel or None), in this order.'''
	return deque(rv.ChangeEvent(float(i), is_dir, event, os.path.join(monitor, rel), None if source is None else os.path.join(monitor, source))
		for i, (is_dir, event, rel, source) in enumerate(events, 1))


def backup_events(job, events: list, **kwargs) -> None:
	'''One batch of raw events, as the backuper runs a fresh one: collapsed, then verified by what they touched.'''
	raw = raw_events(job.monitor, events)
	_, manifest, committed = rv.do_backup(rv.change_events_to_backup_entries(deque(raw), job.monitor), job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, touched=rv.touched_scopes(raw, job.monitor), matched_since=time.time_ns(), **{**OPTIONS, **kwargs})
	manifest.close()
	assert committed is True


def seed_base(monitor: str) -> None:
	files = {'a/x.txt': 'ax0', 'a/sub/m.txt': 'm0', 'a/sub/deep/k.txt': 'k0', 'b/y.txt': 'y0', 'b/w.txt': 'w0', 'c/z.txt': 'z0',
		'c/keep.txt': 'keep0', 'd/g': 'g0', 'd/h': 'h0', 's1/one.txt': 's1', 's2/two.txt': 's2', 'f1.txt': 'F1',
		'f2.txt': 'F2', 'q.txt': 'q0', 'r.txt': 'r0', 'rr/inside.txt': 'rr0', 'chain1.txt': 'c0', 'top.txt': 't0',
		'g/h/i/j.txt': 'j0', 'g/h/i/gone.txt': 'gone0', 'g/h/other.txt': 'o0', 'g/top.txt': 'gt0',
		'w/old.txt': 'o0', f'w/x{UNREADABLE}': 'b0', 'w/sub/s.txt': 's0', 'attrs.txt': 'attrs0', 'owned.txt': 'owned0'}
	for i in range(6):
		files[f'big/f{i}.txt'] = f'big{i}'
	files['big/inner/f.txt'] = 'bi'
	for i, (rel, text) in enumerate(sorted(files.items())):
		put_text(monitor, rel, text, T0 + i * 1000000000)
	os.symlink('a/x.txt', os.path.join(monitor, 'lnk'))
	os.symlink('/etc/hostname', os.path.join(monitor, 'abs'))
	# a user's relative link leading up, the same shape as a daemon link until its version name
	os.symlink('../a/x.txt', os.path.join(monitor, 'g', 'up'))
	# what else a version must keep: a file's and a folder's attributes, an owner, a folder's mode
	os.setxattr(os.path.join(monitor, 'attrs.txt'), 'user.tag', b'file')
	os.setxattr(os.path.join(monitor, 'a'), 'user.tag', b'folder')
	os.chown(os.path.join(monitor, 'owned.txt'), 1234, 1235)
	os.chmod(os.path.join(monitor, 'c'), 0o750)
	# folder times as a settled tree has them
	for root, _, _ in os.walk(monitor, topdown=False):
		os.utime(root, ns=(T0, T0 + 500))


def apply_batch1(monitor: str) -> list:
	put_text(monitor, 'top.txt', 't1')
	put_text(monitor, 'a/new1.txt', 'n1')
	os.remove(os.path.join(monitor, 'c/keep.txt'))
	return [(False, 'modify', 'top.txt', None), (False, 'create', 'a/new1.txt', None), (False, 'delete', 'c/keep.txt', None)]


def apply_batch2(monitor: str) -> list:
	put_text(monitor, 'a/x.txt', 'ax2')
	put_text(monitor, 'b/w.txt', 'w2')
	put_text(monitor, 'e0.txt', 'e0')
	return [(False, 'modify', 'a/x.txt', None), (False, 'modify', 'b/w.txt', None), (False, 'create', 'e0.txt', None)]


def expected_of(now: dict, prev: dict) -> dict:
	'''
	What a version holds of the monitored tree now, its last version holding prev: a file that cannot be read keeps its
	last copy, and one with no last copy is not there.
	'''
	out = dict(now)
	for rel in now:
		if rel.endswith(UNREADABLE):
			if prev.get(rel) is not None and prev[rel].kind == 'f':
				out[rel] = prev[rel]
			else:
				del out[rel]
	return out


def build_base(job, **options) -> dict:
	'''Batches 0-2 of the crash vault, options over OPTIONS; {version number: what it must hold}.'''
	os.makedirs(job.job_vault, exist_ok=True)
	seed_base(job.monitor)
	expected = {0: snapshot_tree(job.monitor)}
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, matched_since=time.time_ns(), **{**OPTIONS, **options})
	manifest.close()
	assert committed is True
	for number, apply_batch in ((1, apply_batch1), (2, apply_batch2)):
		events = apply_batch(job.monitor)
		expected[number] = snapshot_tree(job.monitor)
		backup_events(job, events, **options)
	return expected


def change_batch3(monitor: str) -> list:
	'''Change the monitored tree as batch 3 does; its events, as (is_dir, event, rel, moved_from rel or None).'''
	def at(rel):
		return os.path.join(monitor, rel)
	put_text(monitor, 'n1.txt', 'n1')
	put_text(monitor, 'newf/a.txt', 'na')
	put_text(monitor, 'newf/sub/b.txt', 'nb')
	put_text(monitor, 'a/x.txt', 'ax3')
	put_text(monitor, 'b/y.txt', 'y3a')
	put_text(monitor, 'b/y.txt', 'y3b')
	os.remove(at('c/z.txt'))
	shutil.rmtree(at('big'))
	os.rename(at('d/g'), at('y'))
	shutil.rmtree(at('d'))
	os.rename(at('a/sub'), at('e'))
	put_text(monitor, 'e/m.txt', 'new')
	put_text(monitor, 'e/new.txt', 'n')
	put_text(monitor, 'e/deep/k.txt', 'k3')
	os.rename(at('s1'), at('tmp'))
	os.rename(at('s2'), at('s1'))
	os.rename(at('tmp'), at('s2'))
	os.rename(at('f1.txt'), at('t'))
	os.rename(at('f2.txt'), at('f1.txt'))
	os.rename(at('t'), at('f2.txt'))
	put_text(monitor, 'q.txt', 'q3')
	os.remove(at('q.txt'))
	os.rename(at('chain1.txt'), at('chain2.txt'))
	os.rename(at('chain2.txt'), at('chain3.txt'))
	os.chmod(at('b'), 0o700)
	os.remove(at('r.txt'))
	os.mkdir(at('r.txt'))
	put_text(monitor, 'r.txt/in.txt', 'rin')
	shutil.rmtree(at('rr'))
	put_text(monitor, 'rr', 'rr is a file')
	os.remove(at('lnk'))
	os.symlink('b/y.txt', at('lnk'))
	os.chmod(at('top.txt'), 0o600)
	put_text(monitor, 'g/h/i/j.txt', 'j3')
	os.remove(at('g/h/i/gone.txt'))
	put_text(monitor, 'g/h/i/new.txt', 'gn')
	# a folder copied over the folder already there, the collapse leaving one create: a file that cannot be read keeps its
	# last copy, and one never copied is not there
	os.remove(at('w/old.txt'))
	put_text(monitor, f'w/x{UNREADABLE}', 'b3')
	put_text(monitor, f'w/fresh{UNREADABLE}', 'f3')
	put_text(monitor, 'w/sub/s.txt', 's3')
	put_text(monitor, 'w/new.txt', 'wn')
	put_text(monitor, BAD_NAME, 'bad name')
	put_text(monitor, NEWLINE_NAME, 'newline name')
	return [(True, 'create', 'w', None),
		(False, 'modify', 'g/h/i/j.txt', None), (False, 'delete', 'g/h/i/gone.txt', None), (False, 'create', 'g/h/i/new.txt', None),
		(False, 'delete', 'c/z.txt', None), (True, 'delete', 'big', None),
		(False, 'move', 'y', 'd/g'), (True, 'delete', 'd', None),
		(True, 'move', 'e', 'a/sub'), (False, 'modify', 'e/m.txt', None), (False, 'create', 'e/new.txt', None), (False, 'modify', 'e/deep/k.txt', None),
		(True, 'move', 'tmp', 's1'), (True, 'move', 's1', 's2'), (True, 'move', 's2', 'tmp'),
		(False, 'move', 't', 'f1.txt'), (False, 'move', 'f1.txt', 'f2.txt'), (False, 'move', 'f2.txt', 't'),
		(False, 'modify', 'q.txt', None), (False, 'delete', 'q.txt', None),
		(False, 'move', 'chain2.txt', 'chain1.txt'), (False, 'move', 'chain3.txt', 'chain2.txt'),
		(True, 'attrib', 'b', None),
		(False, 'delete', 'r.txt', None), (True, 'create', 'r.txt', None),
		(True, 'delete', 'rr', None), (False, 'create', 'rr', None),
		(False, 'create', 'n1.txt', None), (True, 'create', 'newf', None), (False, 'modify', 'a/x.txt', None), (False, 'modify', 'b/y.txt', None), (False, 'modify', 'b/y.txt', None),
		(False, 'delete', 'lnk', None), (False, 'create', 'lnk', None), (False, 'attrib', 'top.txt', None),
		(False, 'create', BAD_NAME, None), (False, 'create', NEWLINE_NAME, None)]


def apply_batch3(job) -> OrderedDict:
	'''
	Change the monitored tree as batch 3 does; its backup entries. Its raw events are kept beside the job, for the crash child.
	'''
	monitor = job.monitor
	raw = raw_events(monitor, change_batch3(monitor))
	with open(os.path.join(job.root, BATCH3_FILE), 'wb') as f:
		pickle.dump(list(raw), f)
	return rv.change_events_to_backup_entries(deque(raw), monitor)


def batch3_of(job) -> tuple:
	'''(backup entries, touched scopes) of the batch apply_batch3() kept beside job, for a backup of it.'''
	with open(os.path.join(job.root, BATCH3_FILE), 'rb') as f:
		raw = deque(pickle.load(f))
	return rv.change_events_to_backup_entries(deque(raw), job.monitor), rv.touched_scopes(raw, job.monitor)


def after_retries(job_vault: str, expected: dict) -> dict:
	'''
	expected (versions 1 to 3) as the vault's newest version asks: a retry after the commit compares again, finds the file
	that cannot be read still differing and makes one more version holding what version 3 holds, which keep-N pays for. So
	the kept versions are the KEEP up to the newest, from version 3 on holding what it holds.
	'''
	numbers = [number for number in map(version_number, os.listdir(job_vault)) if number is not None]
	newest = max(numbers, default=3)
	if newest <= 3:
		return expected
	return {number: expected[min(number, 3)] for number in range(newest - KEEP + 1, newest + 1)}


# options: what every batch of this vault runs with, over OPTIONS
CrashVault = namedtuple('CrashVault', ['job', 'template', 'base', 'expected', 'options'], defaults=[{}])


def prepare(root: str, **options) -> CrashVault:
	'''
	The crash vault under root (on a mount of REVERB_CRASH_ROOT's, when the caller chose it): built by the real daemon, in
	this process, under isolated_runtime(), so call it from a test, not from a fixture wider than a test's. base is what
	each version must hold before batch 3 ({0, 1, 2}), expected after it ({1, 2, 3}). The monitored tree stays as batch 3
	left it: restore() puts back only the vault, so what a retry compares has the ctimes a real restart would see.
	'''
	job = create_job(root)
	base = build_base(job, **options)
	template = os.path.join(root, 'template')
	subprocess.run(['cp', '-a', job.vault, template], check=True)
	apply_batch3(job)
	subprocess.run(['cp', '-a', job.monitor, monitor_template(job)], check=True)
	after = expected_of(snapshot_tree(job.monitor), base[2])
	return CrashVault(job, template, base, {1: base[1], 2: base[2], 3: after}, options)


def monitor_template(job) -> str:
	return os.path.join(job.root, 'monitor_template')


def restore(vault: CrashVault) -> None:
	'''The vault back as batch 2 left it.'''
	shutil.rmtree(vault.job.vault)
	subprocess.run(['cp', '-a', vault.template, vault.job.vault], check=True)


def restore_monitor(vault: CrashVault) -> None:
	'''The monitored tree back as batch 3 left it, for a test that changed it: its names, contents, modes and times, though not its ctimes.'''
	shutil.rmtree(vault.job.monitor)
	subprocess.run(['cp', '-a', monitor_template(vault.job), vault.job.monitor], check=True)
