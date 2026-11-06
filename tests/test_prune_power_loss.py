'''
Round 17: a prune on a mergerfs pool loses nothing on a power loss. One mergerfs request can change two disks (a rename
lands on one and unlinks on another), and each disk comes back at its own last checkpoint, so the prune makes a marker
naming the oldest version durable before its walk, flushes every disk before anything of the oldest version goes and
again before its change lists go, and a prune that finds the marker naming its oldest version (cut off before its first
flush) links back from the oldest version what the next one lost. A single filesystem keeps its own order and gets none
of it.

The cut-state test at the end runs a real mergerfs over three folders, with each folder put back at a snapshot of its
own: it needs root, /dev/fuse and mergerfs, and REVERB_SCRATCH naming a folder to mount in (it is skipped otherwise).
'''
import datetime
import errno
import itertools
import json
import os
import shutil
import subprocess
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.conftest import REAL_SYNC_VAULT_FILESYSTEMS
from tests.harness import create_job, daemon, event_entry, run_backup, seed_monitor

pytestmark = pytest.mark.unit

V = ['V0--2021-01-01_00-00-00_-0800', 'V1--2021-01-02_00-00-00_-0800', 'V2--2021-01-03_00-00-00_-0800']


def as_pool(monkeypatch, flushes=None, failing=()):
	'''
	Every job vault taken for one on a pool (PoolGuard.covers()), with flush_vault_disks() recorded in flushes and
	failing the disks in failing: the prune's pool path on plain folders.
	'''
	monkeypatch.setattr(rv.PoolGuard, 'covers', lambda self, path: True)
	calls = [] if flushes is None else flushes
	def flush(job_vault, job_name):
		calls.append(job_vault)
		return sorted(failing)
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	return calls


def marker_path(job):
	return os.path.join(job.job_vault, rv.PRUNE_MARKER_FILE_NAME)


def marker(job):
	with open(marker_path(job)) as f:
		return f.read()


def logged(monkeypatch):
	lines = []
	real = rv.backuperTeeLogToTl
	def log(path='', message='', **kwargs):
		lines.append((str(message), kwargs))
		return real(path, message, **kwargs)
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', log)
	return lines


def three_versions(tmp_path):
	'''V0 holding a, D/b and keep, then V1 and V2, each modifying keep: V1's a and D/b are chain links into V0.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a': 'a', 'D/b': 'b', 'keep': 'k'})
	run_backup(job)
	for i in (1, 2):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'v{i}')
		run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	return job


def prune(job):
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	return info, rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)


# --- the marker ---

def test_the_marker_is_one_json_line_written_in_place(tmp_path):
	job_vault = str(tmp_path)
	assert rv.read_prune_marker(job_vault) is None
	rv.write_prune_marker(job_vault, V[0])
	path = os.path.join(job_vault, rv.PRUNE_MARKER_FILE_NAME)
	inode = os.stat(path).st_ino
	assert open(path).read() == json.dumps({'walking': V[0]}) + '\n' and rv.read_prune_marker(job_vault) == V[0]
	rv.write_prune_marker(job_vault, None)
	assert open(path).read() == '{"walking": null}\n' and rv.read_prune_marker(job_vault) is None
	# made once and kept: the same file each time
	assert os.stat(path).st_ino == inode


@pytest.mark.parametrize('content', [b'', b'{"walking": "V0--x"}\n{"walk', b'{"walking": 3}\n', b'[]\n', b'\xff\n'],
	ids=['empty', 'torn', 'not_a_name', 'not_an_object', 'not_utf8'])
def test_a_marker_that_holds_anything_else_cannot_be_read(tmp_path, content):
	with open(os.path.join(tmp_path, rv.PRUNE_MARKER_FILE_NAME), 'wb') as f:
		f.write(content)
	with pytest.raises(rv.UnreadablePruneMarker):
		rv.read_prune_marker(str(tmp_path))


def test_a_marker_made_whose_folder_cannot_be_flushed_is_removed_again(tmp_path, monkeypatch):
	def fail(path):
		raise OSError(errno.EIO, 'EIO', path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', fail)
	with pytest.raises(OSError):
		rv.write_prune_marker(str(tmp_path), V[0])
	assert not os.path.lexists(os.path.join(tmp_path, rv.PRUNE_MARKER_FILE_NAME))


# --- the prune's order on a pool, and none of it on a single filesystem ---

def test_a_prune_on_a_single_filesystem_makes_no_marker_and_no_flush(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	flushes = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda *args: flushes.append(args) or [])
	info, _ = prune(job)
	assert list(info) == [1, 2] and flushes == []
	assert not os.path.lexists(marker_path(job))


def test_a_prune_on_a_pool_names_its_walk_flushes_twice_and_clears_the_marker(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	events = []
	monkeypatch.setattr(rv.PoolGuard, 'covers', lambda self, path: True)
	real_write = rv.write_prune_marker
	monkeypatch.setattr(rv, 'write_prune_marker', lambda job_vault, walking: events.append(('marker', walking)) or real_write(job_vault, walking))
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: events.append(('flush',
		any(name.startswith('V0--') and os.path.isdir(os.path.join(job_vault, name)) for name in os.listdir(job_vault)))) or [])
	real_remove = os.remove
	def remove(path, *args, **kwargs):
		if os.path.basename(str(path)).startswith('V0--'):
			events.append(('list removed',))
		return real_remove(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'remove', remove)
	lines = logged(monkeypatch)
	v0 = os.path.basename(rv.list_versions(job.job_vault)[0].path)
	info, _ = prune(job)
	assert list(info) == [1, 2]
	# the marker before the walk, a flush with V0 there, the marker cleared, a flush once V0 is gone, then its list
	assert events == [('marker', v0), ('flush', True), ('marker', None), ('flush', False), ('list removed',)]
	assert marker(job) == '{"walking": null}\n'
	pruned = [message for message, _ in lines if message.startswith('Pruned ')]
	assert len(pruned) == 1 and ', disks flushed in ' in pruned[0]


@pytest.mark.parametrize('when', ['first', 'second'])
def test_a_disk_that_fails_its_flush_keeps_the_oldest_version(tmp_path, monkeypatch, when):
	job = three_versions(tmp_path)
	monkeypatch.setattr(rv.PoolGuard, 'covers', lambda self, path: True)
	calls = []
	def flush(job_vault, job_name):
		calls.append(job_vault)
		return ['/mnt/disk_a'] if len(calls) == (1 if when == 'first' else 2) else []
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	failed = []
	monkeypatch.setattr(rv, 'job_log', lambda job_name, text: failed.append(text))
	info, _ = prune(job)
	assert next(iter(info)) == 0
	assert failed and 'disk /mnt/disk_a of ' in failed[0] and 'failed a sync' in failed[0]
	if when == 'first':
		# kept whole, and the marker still names it: the next prune checks the next version against it
		assert os.path.isdir(rv.list_versions(job.job_vault)[0].path)
		assert json.loads(marker(job))['walking'] == os.path.basename(info[0].path)
	else:
		# the folder went, its list stays for the next prune or scan, which flushes again first
		assert not os.path.exists(info[0].path)
		info2 = rv.get_vault_info(job.job_vault).vault_info_dict
		assert list(info2) == [1, 2]


def test_a_marker_that_cannot_be_written_keeps_the_oldest_version(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	os.mkdir(marker_path(job))
	failed = []
	monkeypatch.setattr(rv, 'job_log', lambda job_name, text: failed.append(text))
	info, _ = prune(job)
	assert next(iter(info)) == 0 and os.path.isdir(info[0].path)
	assert len(failed) == 1 and 'its prune marker' in failed[0] and 'cannot be written' in failed[0]
	# nothing was walked: V1's links are as they were
	assert os.path.islink(os.path.join(info[1].path, 'a'))


class Killed(Exception):
	pass


def cut_after_the_removal(job, monkeypatch):
	'''A prune of V0 on a pool killed at its second flush: its folder gone, its list there. The vault as the scan had it before.'''
	calls = as_pool(monkeypatch)
	def killed_at_the_second(job_vault, job_name):
		calls.append(job_vault)
		if len(calls) == 2:
			raise Killed()
		return []
	monkeypatch.setattr(rv, 'flush_vault_disks', killed_at_the_second)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	before = OrderedDict(info)
	with pytest.raises(Killed):
		rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert not os.path.exists(before[0].path)
	assert [name for name in os.listdir(job.job_vault) if name.startswith(os.path.basename(before[0].path) + '--')]
	return before


def test_the_already_gone_path_flushes_before_the_lists_go(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	before = cut_after_the_removal(job, monkeypatch)
	flushes = as_pool(monkeypatch)
	rv.decrement_stepper(before, job.job_name, job.monitor, prune_salt=b's' * 16)
	assert list(before) == [1, 2] and flushes == [job.job_vault]
	assert not [name for name in os.listdir(job.job_vault) if name.startswith('V0--')]


# --- after a cut before the first flush ---

def test_a_prune_after_a_cut_links_back_what_the_next_version_lost(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	copies = {rel: os.lstat(os.path.join(v0, rel)).st_ino for rel in ('a', 'D/b')}
	# the cut: the marker names V0, V1's link a was unlinked on its disk and its rename never landed on the copy's
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	os.remove(os.path.join(v1, 'a'))
	lines = logged(monkeypatch)
	info, _ = prune(job)
	assert list(info) == [1, 2]
	for rel, inode in copies.items():
		assert os.lstat(os.path.join(v1, rel)).st_ino == inode and not os.path.islink(os.path.join(v1, rel))
	assert open(os.path.join(v1, 'a')).read() == 'a'
	assert any(message.startswith('A prune of ') and 'was cut off before its flush' in message for message, _ in lines)
	assert any(message.startswith('Linked 1 copies of ') for message, _ in lines)
	assert any('1 copies linked back from it' in message for message, _ in lines if message.startswith('Pruned '))
	assert marker(job) == '{"walking": null}\n'


def test_an_unreadable_marker_is_taken_for_a_cut(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	with open(marker_path(job), 'w') as f:
		f.write('{"walking": "V0--')
	os.remove(os.path.join(v1, 'a'))
	prune(job)
	assert open(os.path.join(v1, 'a')).read() == 'a'


def test_a_marker_naming_another_version_is_no_cut(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v1 = rv.list_versions(job.job_vault)[1].path
	rv.write_prune_marker(job.job_vault, V[2])
	os.remove(os.path.join(v1, 'a'))
	prune(job)
	# not checked: a file V1 dropped stays dropped when no cut is known
	assert not os.path.lexists(os.path.join(v1, 'a'))


def test_unusable_rows_link_back_at_the_files_own_path_with_an_error_line(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	os.remove(os.path.join(v1, 'a'))
	monkeypatch.setattr(rv, 'rows_dropping', lambda *args: (_ for _ in ()).throw(ValueError('a row outside /elsewhere')))
	lines = logged(monkeypatch)
	prune(job)
	assert open(os.path.join(v1, 'a')).read() == 'a'
	assert any(kwargs.get('error') and 'cannot be used (a row outside /elsewhere)' in message for message, kwargs in lines)


def test_a_stray_temp_beside_its_copy_goes_after_a_cut(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	salt = b's' * 16
	# the cut: a's rename landed (the copy in the link's place) and its temp stayed on another disk
	link = os.path.join(v1, 'a')
	copy_st = os.lstat(os.path.join(v0, 'a'))
	temp = rv.prune_link_path(link, copy_st, salt)
	os.link(os.path.join(v0, 'a'), temp)
	os.replace(temp, link)
	os.link(os.path.join(v0, 'a'), temp)
	# a restore before the rerun passes it over too
	assert rv.is_prune_temp(job.job_vault, v1, os.path.basename(temp), job.monitor)
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	prune(job)
	assert not os.path.lexists(temp) and open(link).read() == 'a'


def test_a_temp_whose_rename_does_nothing_is_removed_after_a_cut(tmp_path, monkeypatch):
	# on a pool, the link's name can show as the link while the disk the rename lands on holds the copy there already:
	# rename(temp, name) of one inode does nothing. stood in for by a rename that leaves the temp
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(source)):
			os.remove(dest)
			os.link(source, dest)
			return None
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	prune(job)
	monkeypatch.undo()
	assert sorted(os.listdir(v1)) == ['D', 'a', 'keep']
	assert sorted(os.listdir(os.path.join(v1, 'D'))) == ['b']


def test_no_temp_is_looked_at_beside_a_copy_without_a_cut(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	link = os.path.join(v1, 'a')
	temp = rv.prune_link_path(link, os.lstat(os.path.join(v0, 'a')), b's' * 16)
	os.link(os.path.join(v0, 'a'), temp)
	os.replace(temp, link)
	os.link(os.path.join(v0, 'a'), temp)
	prune(job)
	assert os.path.lexists(temp)


# --- the backup finishes a cut prune first; the scan flushes before deleting a stale list ---

def test_a_backup_finishes_a_cut_prune_before_its_comparison(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	os.remove(os.path.join(v1, 'a'))
	compared = []
	real_delta = rv.delta_generate_backup_entries
	def delta(*args, **kwargs):
		compared.append(os.path.isdir(v0))
		return real_delta(*args, **kwargs)
	monkeypatch.setattr(rv, 'delta_generate_backup_entries', delta)
	# no limit asks for a prune (keep 0, no size limit)
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert compared == [False] and committed
	assert [version.number for version in rv.list_versions(job.job_vault)] == [1, 2]
	assert open(os.path.join(v1, 'a')).read() == 'a'


def test_a_backup_leaves_the_oldest_version_when_the_marker_names_none(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	rv.write_prune_marker(job.job_vault, None)
	run_backup(job)
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2]


@pytest.mark.parametrize('flush', ['ok', 'failing'])
def test_the_scan_flushes_a_pool_before_it_deletes_a_stale_list(tmp_path, monkeypatch, flush):
	job = three_versions(tmp_path)
	v0 = cut_after_the_removal(job, monkeypatch)[0]
	stale = [name for name in os.listdir(job.job_vault) if name.startswith(os.path.basename(v0.path) + '--')]
	assert len(stale) == 1
	flushes = as_pool(monkeypatch, failing=['/mnt/disk_a'] if flush == 'failing' else ())
	lines = logged(monkeypatch)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	assert list(info) == [1, 2] and flushes == [job.job_vault]
	assert os.path.exists(os.path.join(job.job_vault, stale[0])) == (flush == 'failing')
	if flush == 'failing':
		assert any(message.startswith('Keeping ') and 'cannot all be flushed (/mnt/disk_a)' in message for message, _ in lines)


def test_the_scan_of_a_single_filesystem_flushes_nothing(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	v0 = cut_after_the_removal(job, monkeypatch)[0]
	monkeypatch.undo()
	flushes = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda *args: flushes.append(args) or [])
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2]
	assert flushes == [] and not [name for name in os.listdir(job.job_vault) if name.startswith(os.path.basename(v0.path))]


def test_the_disks_of_a_vault_sync_side_by_side(tmp_path, monkeypatch):
	# each disk once, through its first folder holding the vault, on threads of their own
	import threading
	folders = [str(tmp_path / name) for name in 'abcd']
	for folder in folders[1:]:
		os.makedirs(folder)
	monkeypatch.setattr(rv, 'vault_disks', lambda path: (True, [('d1', folders[0]), ('d1', folders[1]), ('d2', folders[2]), ('d3', folders[3])]))
	barrier = threading.Barrier(2, timeout=5)
	synced = []
	def syncfs(path):
		if not os.path.isdir(path):
			raise FileNotFoundError(errno.ENOENT, 'ENOENT', path)
		synced.append(path)
		if path != folders[3]:
			# d1 and d2 wait for each other: run one after the other, this would time out
			barrier.wait()
		else:
			raise OSError(errno.EIO, 'EIO', path)
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	results = REAL_SYNC_VAULT_FILESYSTEMS(str(tmp_path))
	assert list(results) == ['d1', 'd2', 'd3'] and results['d1'] is None and results['d2'] is None
	assert results['d3'].errno == errno.EIO and sorted(synced) == sorted(folders[1:])


# --- the rule, against the real replay: every chain link of V1 into V0 removed ---

PATTERNS = {
	'p1': 'mv p1/d/g p1/y; rm -r p1/d',
	'p2': 'rm p2/d/g; mv p2/d p2/e',
	'p3': 'mv p3/S p3/R (over R)',
	'p4': 'chmod p4/d',
	'p5': 'modify p5/d/x',
	'p6': 'mv p6/d p6/e; create p6/e/new',
	'p7': 'rm -r p7/f; mkdir p7/f; create p7/f/a (one create of p7/f/)',
	'p8': 'rm p8/x; mkdir p8/x (file to folder)',
	'p9': 'chmod p9/d/y',
	'p10': 'mv p10/d/g p10/d/h; mv p10/d p10/e',
	'p11': 'rm p11/d/g (file delete)',
}


def two_versions_of_tricky_batches(base):
	'''
	V0 backed up from a tree of the 11 patterns' folders, then one batch of them replayed into V1 by do_reverb_backup(),
	both committed with their change lists: (job vault, V0, V1, monitored path).
	'''
	mon, job_vault = os.path.join(base, 'mon'), os.path.join(base, 'vault', 'job')
	os.makedirs(job_vault)
	v0, v1 = (os.path.join(job_vault, name) for name in V[:2])
	def mk(rel, data=None):
		path = os.path.join(mon, rel)
		os.makedirs(os.path.dirname(path), exist_ok=True)
		with open(path, 'wb') as f:
			f.write((data or rel).encode() * 20)
	for p in PATTERNS:
		for rel in ('d/g', 'd/h', 'd/x', 'd/y', 'R', 'S', 'f/a', 'f/b', 'x', 'keep'):
			mk(f'{p}/{rel}')
	manifest = rv.VaultManifest(job_vault)
	t = datetime.datetime.now().isoformat()
	def commit(number, rows):
		path = os.path.join(job_vault, V[number])
		size, inodes = rv.measure_version_usage(manifest, path)
		name = rv.change_list_path(path, size, inodes)
		manifest.note_monitor_path(number, mon)
		prepared = rv.prepare_change_list(name, rows)
		manifest.commit(path)
		rv.swap_current_version(job_vault, V[number])
		rv.place_change_list(name, prepared)
	os.mkdir(v0)
	manifest.begin()
	for root, dirs, files in os.walk(mon):
		rel_root = os.path.relpath(root, mon)
		for name in sorted(dirs):
			rel = os.path.normpath(os.path.join(rel_root, name))
			os.mkdir(os.path.join(v0, rel))
			manifest.add(rel + '/')
		for name in sorted(files):
			rel = os.path.normpath(os.path.join(rel_root, name))
			shutil.copy2(os.path.join(mon, rel), os.path.join(v0, rel))
			manifest.add(rel)
	commit(0, [rv.entry_row(os.path.join(mon, p) + '/', rv.BackupEntryValues(t, 'create', None)) for p in PATTERNS])
	entries = OrderedDict()
	events = []
	def ev(rel, event, src=None):
		entries[os.path.join(mon, rel)] = rv.BackupEntryValues(t, event, None if src is None else os.path.join(mon, src))
		events.append(rv.ChangeEvent(1.0 + len(events), rel.endswith('/'), event, os.path.join(mon, rel), None if src is None else os.path.join(mon, src)))
	J = lambda *parts: os.path.join(mon, *parts)
	os.rename(J('p1/d/g'), J('p1/y')); shutil.rmtree(J('p1/d')); ev('p1/y', 'move', 'p1/d/g'); ev('p1/d/', 'delete')
	os.remove(J('p2/d/g')); os.rename(J('p2/d'), J('p2/e')); ev('p2/d/g', 'delete'); ev('p2/e/', 'move', 'p2/d/')
	os.replace(J('p3/S'), J('p3/R')); ev('p3/R', 'move', 'p3/S')
	os.chmod(J('p4/d'), 0o700); ev('p4/d/', 'attrib')
	mk('p5/d/x', 'changed'); ev('p5/d/x', 'modify')
	os.rename(J('p6/d'), J('p6/e')); mk('p6/e/new'); ev('p6/e/', 'move', 'p6/d/'); ev('p6/e/new', 'create')
	shutil.rmtree(J('p7/f')); mk('p7/f/a', 'new a'); ev('p7/f/', 'create')
	os.remove(J('p8/x')); os.mkdir(J('p8/x')); ev('p8/x', 'delete'); ev('p8/x/', 'create')
	os.chmod(J('p9/d/y'), 0o600); ev('p9/d/y', 'attrib')
	os.rename(J('p10/d/g'), J('p10/d/h')); os.rename(J('p10/d'), J('p10/e')); ev('p10/d/h', 'move', 'p10/d/g'); ev('p10/e/', 'move', 'p10/d/')
	os.remove(J('p11/d/g')); ev('p11/d/g', 'delete')
	manifest.begin()
	# with touched scopes, as a daemon's batch has them: the verification after the replay writes its rows too
	verified = []
	rv.do_reverb_backup(OrderedDict(entries), v1, rv.VaultEntry(0, v0, 0, 0, 0), False, manifest, mon, job_name='job',
		touched=rv.touched_scopes(events, mon), verified=verified)
	commit(1, [rv.entry_row(path, values) for path, values in entries.items()] + [rv.entry_row(path, values) for path, values in verified])
	manifest.close()
	return job_vault, v0, v1, mon


def test_after_the_worst_cut_every_lost_copy_is_linked_back_and_nothing_else(tmp_path, monkeypatch):
	job_vault, v0, v1, mon = two_versions_of_tricky_batches(str(tmp_path))
	as_pool(monkeypatch)
	moves = rv.VaultMoves(job_vault, mon, None).of(v1)
	held, links = set(), {}
	for path, rel, is_dir in rv.iter_tree_entries(v1):
		if is_dir:
			continue
		held.add(rel)
		if os.path.islink(path):
			target = rv.vault_chain_hop(job_vault, path, os.readlink(path), moves)
			if target is not None and target.startswith(v0 + '/'):
				links[rel] = os.lstat(target).st_ino
	# the worst a cut walk and a power loss can do: every chain link of V1 into V0 gone, the marker naming V0
	for rel in links:
		os.unlink(os.path.join(v1, rel))
	rv.write_prune_marker(job_vault, V[0])
	rv.VERSION_MOVES.clear()
	info = rv.get_vault_info(job_vault).vault_info_dict
	rv.decrement_stepper(info, 'job', mon, prune_salt=b's' * 16)
	assert list(info) == [1] and not os.path.exists(v0)
	after = {rel for path, rel, is_dir in rv.iter_tree_entries(v1) if not is_dir}
	assert len(links) == 98          # 99 before the verification deleted p7/f/b, which the folder create left
	assert sorted(set(links) - after) == []          # none missed
	assert sorted(after - held) == []                # nothing V1 had dropped shown again
	assert [rel for rel, inode in links.items() if os.lstat(os.path.join(v1, rel)).st_ino != inode] == []


# --- the rule on replays of batches whose verification and moves interact (from the round 17 review) ---

def change(job, t, is_dir, event, rel, src=None):
	return rv.ChangeEvent(t, is_dir, event, os.path.join(job.monitor, rel), None if src is None else os.path.join(job.monitor, src))


def replay(job, events, before_verification=None, monkeypatch=None):
	'''A batch of raw events replayed and verified as the daemon does it; before_verification runs between the two.'''
	entries = rv.change_events_to_backup_entries(events, job.monitor)
	if before_verification is not None:
		real = rv.compare_scopes
		def compare(*args, **kwargs):
			before_verification()
			return real(*args, **kwargs)
		monkeypatch.setattr(rv, 'compare_scopes', compare)
	run_backup(job, entries, touched=rv.touched_scopes(events, job.monitor))
	if before_verification is not None:
		monkeypatch.setattr(rv, 'compare_scopes', real)


def worst_cut_prune(job, monkeypatch):
	'''
	The worst cut: every chain link of V1 into V0 removed, the marker naming V0, then the prune. (what V1 held, the links
	it had into V0 as rel -> V0's inode, V1's files after the prune as rel -> inode)
	'''
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	moves = rv.VaultMoves(job.job_vault, job.monitor, None).of(v1)
	held, links = set(), {}
	for path, rel, is_dir in rv.iter_tree_entries(v1):
		if is_dir:
			continue
		held.add(rel)
		if os.path.islink(path):
			target = rv.vault_chain_hop(job.job_vault, path, os.readlink(path), moves)
			if target is not None and target.startswith(v0 + '/'):
				links[rel] = os.lstat(target).st_ino
	for rel in links:
		os.unlink(os.path.join(v1, rel))
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	rv.VERSION_MOVES.clear()
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=b's' * 16)
	after = {rel: os.lstat(path).st_ino for path, rel, is_dir in rv.iter_tree_entries(v1) if not is_dir}
	return held, links, after


@pytest.mark.parametrize('order', ['g_first', 'h_first'])
def test_a_move_over_a_file_then_a_folder_move_links_back_the_moved_file_whatever_the_walk_order(tmp_path, monkeypatch, order):
	# mv d/g d/h (over d/h); mv d e: V0's d/h and d/g both place at e/h, and only d/g's copy belongs there
	job = create_job(str(tmp_path))
	seed_monitor(job, {'d/g': 'G' * 50, 'd/h': 'H' * 50, 'keep': 'k' * 50})
	run_backup(job)
	os.replace(os.path.join(job.monitor, 'd/g'), os.path.join(job.monitor, 'd/h'))
	os.rename(os.path.join(job.monitor, 'd'), os.path.join(job.monitor, 'e'))
	replay(job, [change(job, 1.0, False, 'move', 'd/h', 'd/g'), change(job, 2.0, True, 'move', 'e', 'd')])
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	g_inode = os.lstat(os.path.join(v0, 'd/g')).st_ino
	real = rv.iter_tree_entries
	def ordered(path, *args, **kwargs):
		items = list(real(path, *args, **kwargs))
		if os.path.abspath(path) == os.path.abspath(v0):
			files = sorted((i for i in items if not i[2]), key=lambda i: i[1], reverse=(order == 'h_first'))
			items = [i for i in items if i[2]] + files
		return iter(items)
	monkeypatch.setattr(rv, 'iter_tree_entries', ordered)
	held, links, after = worst_cut_prune(job, monkeypatch)
	monkeypatch.undo()
	assert sorted(links) == ['e/h', 'keep'] and links['e/h'] == g_inode
	assert after == links and open(os.path.join(v1, 'e/h')).read() == 'G' * 50


def test_the_moves_of_a_version_tell_a_file_moved_over_from_one_moved_on():
	moves = rv.VersionMoves.applied([('d/g', 'd/h', False), ('d/', 'e/', True), ('c', 'e/h', False), ('e/k', 'k', False)])
	# d/h is overwritten by the first move; d/g is moved on to e/h, which c's move then overwrites; c is the one left there;
	# e/k is under the folder the second move lands on
	assert [moves.place(rel) for rel in ('d/h', 'd/g', 'c', 'd/k', 'e/k', 'a')] == [
		(None, True), (None, True), ('e/h', True), ('k', True), (None, True), ('a', False)]


def test_a_new_file_at_a_moved_folders_old_path_that_is_gone_before_the_verification_loses_no_copy(tmp_path, monkeypatch):
	# mv D E; mkdir D; echo > D/x; D/x removed between the replay and its verification, whose delete row of D/x names the new
	# file, not V0's D/x that went to E/x
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/x': 'x' * 50, 'D/z': 'z' * 50, 'keep': 'k' * 50})
	run_backup(job)
	os.rename(os.path.join(job.monitor, 'D'), os.path.join(job.monitor, 'E'))
	os.mkdir(os.path.join(job.monitor, 'D'))
	with open(os.path.join(job.monitor, 'D/x'), 'w') as f:
		f.write('new x')
	gone = lambda: os.path.lexists(os.path.join(job.monitor, 'D/x')) and os.remove(os.path.join(job.monitor, 'D/x'))
	replay(job, [change(job, 1.0, True, 'move', 'E', 'D'), change(job, 2.0, True, 'create', 'D'), change(job, 3.0, False, 'create', 'D/x')],
		before_verification=gone, monkeypatch=monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	x_inode = os.lstat(os.path.join(v0, 'D/x')).st_ino
	held, links, after = worst_cut_prune(job, monkeypatch)
	assert 'E/x' in links and after['E/x'] == x_inode
	assert sorted(set(links) - set(after)) == [] and sorted(set(after) - held) == []


def test_a_delete_before_a_folder_move_still_drops_what_it_names(tmp_path, monkeypatch):
	# rm D/x; mv D E: the delete runs before the move and names V0's D/x, so its copy is not linked back
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/x': 'x' * 50, 'D/z': 'z' * 50, 'keep': 'k' * 50})
	run_backup(job)
	os.remove(os.path.join(job.monitor, 'D/x'))
	os.rename(os.path.join(job.monitor, 'D'), os.path.join(job.monitor, 'E'))
	replay(job, [change(job, 1.0, False, 'delete', 'D/x'), change(job, 2.0, True, 'move', 'E', 'D')])
	v1 = rv.list_versions(job.job_vault)[1].path
	assert not os.path.lexists(os.path.join(v1, 'E/x'))
	held, links, after = worst_cut_prune(job, monkeypatch)
	assert sorted(links) == ['E/z', 'keep'] and sorted(after) == ['E/z', 'keep']


def test_a_place_in_a_users_symlinked_folder_is_not_linked_into_after_a_cut(tmp_path, monkeypatch):
	# V1 holds a user's symlink in the place of V0's folder d; rows that cannot be used link back at the file's own path,
	# which must not follow that symlink out of the vault
	job = create_job(str(tmp_path))
	seed_monitor(job, {'d/f': 'f' * 50, 'keep': 'k' * 50})
	run_backup(job)
	outside = str(tmp_path / 'outside')
	os.makedirs(outside)
	shutil.rmtree(os.path.join(job.monitor, 'd'))
	os.symlink(outside, os.path.join(job.monitor, 'd'))
	replay(job, [change(job, 1.0, True, 'delete', 'd'), change(job, 2.0, False, 'create', 'd')])
	assert os.path.islink(os.path.join(rv.list_versions(job.job_vault)[1].path, 'd'))
	monkeypatch.setattr(rv, 'rows_dropping', lambda *args: (_ for _ in ()).throw(ValueError('a row outside /elsewhere')))
	worst_cut_prune(job, monkeypatch)
	assert os.listdir(outside) == []


def test_a_temp_whose_link_was_unlinked_on_one_disk_and_not_renamed_on_the_other_goes_with_the_relink(tmp_path, monkeypatch):
	# the copy's disk has the temp's link but not its rename, the link's disk has the link's unlink: link_back() links the
	# copy in the link's place, and the temp is the one name left of it
	job = three_versions(tmp_path)
	as_pool(monkeypatch)
	v0, v1 = (version.path for version in rv.list_versions(job.job_vault)[:2])
	salt = b's' * 16
	link = os.path.join(v1, 'a')
	copy_st = os.lstat(os.path.join(v0, 'a'))
	temp = rv.prune_link_path(link, copy_st, salt)
	os.link(os.path.join(v0, 'a'), temp)
	os.unlink(link)
	rv.write_prune_marker(job.job_vault, os.path.basename(v0))
	prune(job)
	assert open(link).read() == 'a' and os.lstat(link).st_ino == copy_st.st_ino
	assert not os.path.lexists(temp)


# --- every cut state on a real mergerfs pool of three folders ---

SCRATCH = os.environ.get('REVERB_SCRATCH')
MERGERFS_OPTIONS = ('allow_other,fsname=reverb_r17_test,read-thread-count=-1,func.readdir=cor,passthrough.io=rw,readahead=2048,'
	'security_capability=false,category.create=pfrd,lazy-umount-mountpoint=true')
needs_mergerfs = pytest.mark.skipif(not SCRATCH or os.geteuid() != 0 or not shutil.which('mergerfs') or not os.path.exists('/dev/fuse'),
	reason='needs REVERB_SCRATCH, root, /dev/fuse and mergerfs')


class ScratchPool:
	'''A mergerfs at base/mnt over base/br/b1..b3, mounted and unmounted (fusermount3 -u) at will.'''
	def __init__(self, base):
		self.base = base
		self.mnt, self.br = os.path.join(base, 'mnt'), os.path.join(base, 'br')
		self.branches = [os.path.join(self.br, f'b{i}') for i in (1, 2, 3)]

	def mount(self):
		os.makedirs(self.mnt, exist_ok=True)
		subprocess.run(['mergerfs', ':'.join(self.branches), self.mnt, '-o', MERGERFS_OPTIONS], check=True)

	def umount(self):
		if os.path.ismount(self.mnt):
			subprocess.run(['fusermount3', '-u', self.mnt], check=True)

	def snapshot(self, name):
		dest = os.path.join(self.base, 'snap', name)
		shutil.rmtree(dest, ignore_errors=True)
		os.makedirs(os.path.dirname(dest), exist_ok=True)
		subprocess.run(['cp', '-a', self.br, dest], check=True)

	def put_back(self, mix):
		# each branch at the snapshot its letter names
		self.umount()
		shutil.rmtree(self.br)
		os.makedirs(self.br)
		for branch, name in zip(self.branches, mix):
			subprocess.run(['cp', '-a', os.path.join(self.base, 'snap', name, os.path.basename(branch)), branch], check=True)
		self.mount()


def build_three_versions(job):
	'''V0 of 10 folders of 30 files, V1 modifying, deleting and moving one each, V2 creating one: each version's files.'''
	for i in range(10):
		for j in range(30):
			seed_monitor(job, {f'f{i}/x{j}': f'f{i}/x{j} v0 ' * 50})
	run_backup(job)
	with open(os.path.join(job.monitor, 'f0', 'x0'), 'w') as f:
		f.write('f0/x0 v1 ' * 50)
	os.remove(os.path.join(job.monitor, 'f1', 'x1'))
	os.rename(os.path.join(job.monitor, 'f2', 'x2'), os.path.join(job.monitor, 'f3', 'moved'))
	run_backup(job, OrderedDict([event_entry(job, 'f0/x0', 'modify'), event_entry(job, 'f1/x1', 'delete'),
		event_entry(job, 'f3/moved', 'move', 'f2/x2')]))
	expect = {1: tree_contents(job.monitor)}
	with open(os.path.join(job.monitor, 'f4', 'new'), 'w') as f:
		f.write('f4/new v2 ' * 50)
	run_backup(job, OrderedDict([event_entry(job, 'f4/new', 'create')]))
	expect[2] = tree_contents(job.monitor)
	return expect


def tree_contents(root):
	return {rel: open(path, 'rb').read() for path, rel, is_dir in rv.iter_tree_entries(root) if not is_dir}


def survey(job, pool, expect):
	'''What versions 1 and 2 give of each file they should hold: lost (absent or dangling), hidden (shadowed on a branch).'''
	lost, hidden = [], []
	for version in rv.list_versions(job.job_vault):
		if version.number not in expect:
			continue
		for rel, data in expect[version.number].items():
			path = os.path.join(version.path, rel)
			try:
				if open(path, 'rb').read() == data:
					continue
			except OSError:
				pass
			on_branches = [os.path.join(branch, os.path.relpath(path, pool.mnt)) for branch in pool.branches]
			(hidden if any(os.path.isfile(p) and not os.path.islink(p) and open(p, 'rb').read() == data for p in on_branches) else lost).append((version.number, rel))
	strays = [rel for version in rv.list_versions(job.job_vault) if version.number in expect
		for path, rel, is_dir in rv.iter_tree_entries(version.path) if not is_dir and rel not in expect[version.number]]
	return lost, hidden, strays


@needs_mergerfs
@pytest.mark.chain_ground_truth_allows('blind_spot', reason='the branches are put back by cp -a, which makes every chain link anew, so no frame recorded them and the plugin takes them for user links')
def test_every_cut_state_on_a_pool_loses_nothing_after_the_rerun(monkeypatch):
	base = os.path.join(SCRATCH, 'cut_states')
	shutil.rmtree(base, ignore_errors=True)
	pool = ScratchPool(base)
	for branch in pool.branches:
		os.makedirs(branch)
	monkeypatch.setattr(rv, 'sync_vault_filesystems', REAL_SYNC_VAULT_FILESYSTEMS)
	# the scratch folders are folders of one filesystem: each is its own disk to the prune, as a pool's SSDs are
	monkeypatch.setattr(rv, 'mount_holding', lambda table, path: None)
	# and folders, not mounts: the pool's check would take them for disks not mounted, in the daemon that builds the vault too
	for module in (rv, daemon()):
		monkeypatch.setattr(module.PoolGuard, 'problem', lambda self: None)
	pool.mount()
	try:
		# the monitored tree off the pool, the vault on it
		job = create_job(base)._replace(vault=os.path.join(pool.mnt, 'vault'), job_vault=os.path.join(pool.mnt, 'vault', 'job'))
		os.makedirs(job.vault)
		expect = build_three_versions(job)
		pool.umount()
		pool.mount()
		# S0 once the marker names V0 (it is fsynced before the walk), S1 before the first flush, S3 once V0's folder
		# is gone, S2 once the prune is done; S1' is the state at the removal, after the first flush
		real_write, real_flush = rv.write_prune_marker, rv.flush_vault_disks
		flushes = []
		def write(job_vault, walking):
			real_write(job_vault, walking)
			if walking is not None:
				pool.snapshot('S0')
		def flush(job_vault, job_name):
			pool.snapshot('S1' if not flushes else 'S3')
			flushes.append(job_vault)
			return real_flush(job_vault, job_name)
		real_run = rv.multiCMD.run_command
		import threading
		first_rm = threading.Lock()
		def run_command(command, *args, **kwargs):
			# the removal's rm -rf runs on threads: every one waits for the snapshot before the first
			if command[0] == 'rm':
				with first_rm:
					if not os.path.exists(os.path.join(base, 'snap', 'S1b')):
						pool.snapshot('S1b')
			return real_run(command, *args, **kwargs)
		monkeypatch.setattr(rv, 'write_prune_marker', write)
		monkeypatch.setattr(rv, 'flush_vault_disks', flush)
		monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
		info, _ = prune(job)
		assert list(info) == [1, 2] and len(flushes) == 2
		pool.snapshot('S2')
		monkeypatch.setattr(rv, 'write_prune_marker', real_write)
		monkeypatch.setattr(rv, 'flush_vault_disks', real_flush)
		monkeypatch.setattr(rv.multiCMD, 'run_command', real_run)
		results, before = {}, {}
		# a cut before the first flush: each branch at S0 or S1; between the flushes: S1b or S3; after: S3 or S2
		for pair in (('S0', 'S1'), ('S1b', 'S3'), ('S3', 'S2')):
			for mix in itertools.product(pair, repeat=3):
				pool.put_back(mix)
				rv.VERSION_MOVES.clear()
				rv.VAULTS_WITH_VERSIONS.clear()
				rv.forget_real_vault_folders(job.job_vault)
				scanned = rv.get_vault_info(job.job_vault).vault_info_dict
				before[mix] = survey(job, pool, expect)
				if 0 in scanned:
					rv.decrement_stepper(scanned, job.job_name, job.monitor, prune_salt=b's' * 16)
				assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2], mix
				results[mix] = survey(job, pool, expect)
		bad = {mix: result for mix, result in results.items() if any(result)}
		assert bad == {}
		assert len(results) == 23
		# the cuts before the first flush did lose copies, until the rerun linked them back
		lost_by_cuts = {mix: len(lost) for mix, (lost, _, _) in before.items() if lost}
		assert lost_by_cuts and all(set(mix) == {'S0', 'S1'} for mix in lost_by_cuts), lost_by_cuts
		print('lost before the rerun, by mix:', lost_by_cuts)
	finally:
		pool.umount()
		shutil.rmtree(base, ignore_errors=True)
