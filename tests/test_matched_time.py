import errno
import os
import threading
import time
from collections import OrderedDict

import pytest
import reverberator as rv
from tests.harness import (scripted_watch, seed_monitor, run_backup, event_entry, latest_version, wait_until,
	wait_for_committed_count, write_pending)
from tests.test_inner_mounts import _fake_mounts
from tests.test_moves_then_changes import user_xattrs_or_skip
from tests.test_verify_replay import start_backuper, stop_backuper

pytestmark = pytest.mark.unit


def test_take_carries_the_read_time_and_keeps_it():
	queue = rv.ChangeEventQueue('/m')
	assert queue.read_wall_ns is None
	queue.read_wall_ns = 5
	queue.append(rv.ChangeEvent(1.0, False, 'modify', '/m/a', None))
	taken = queue.take()
	assert taken.read_wall_ns == 5 and queue.read_wall_ns == 5
	queue.append(rv.ChangeEvent(2.0, False, 'full_scan', '/m', None))
	assert queue.read_wall_ns == 5


class RecordingFlag(threading.Event):
	'''A flag that records the queue's read time at the moment the watcher signals.'''
	def __init__(self):
		super().__init__()
		self.queue, self.seen = None, []
	def set(self):
		self.seen.append(self.queue.read_wall_ns)
		super().set()


def test_a_max_delay_hand_over_carries_the_previous_reads_time(job, monkeypatch):
	flags = rv.inotify_simple.flags
	flag = RecordingFlag()
	monitor = job.monitor
	# reads[0]'s events are queued; reads[1] arrives while the tree is busy and the max delay has passed
	reads = [[(flags.CREATE, 'a', 0)], [(flags.CREATE, 'b', 0)]]
	flag.queue = rv.ChangeEventQueue(monitor)
	queue, _, returned = scripted_watch(monkeypatch, monitor, reads, flag=flag, queue=flag.queue,
		min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	# read 0 began before it returned; read 1's events were not all queued when it was handed over
	assert flag.seen and flag.seen[0] is not None and flag.seen[0] <= returned[0]


class RecordingQueue(rv.ChangeEventQueue):
	'''Records the read time a taker would see as each event is queued.'''
	def __init__(self, monitor):
		self.seen = []
		super().__init__(monitor)
	def append(self, event):
		self.seen.append((event.path.rsplit('/', 1)[-1], self.read_wall_ns))
		super().append(event)


def test_no_read_time_is_visible_before_all_its_events_are_queued(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE, 'a', 0), (flags.CREATE, 'b', 0)], [(flags.CREATE, 'c', 0), (flags.CREATE, 'd', 0)]]
	queue = RecordingQueue(job.monitor)
	_, _, returned = scripted_watch(monkeypatch, job.monitor, reads, queue=queue, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	seen = dict(queue.seen)
	# while read 0's events are queued no read is published; while read 1's are, only read 0's time, which began before it returned
	assert seen['a'] is None and seen['b'] is None
	assert seen['c'] is not None and seen['c'] <= returned[0] and seen['d'] <= returned[0]


def test_a_scripted_folder_create_does_not_re_root_later_events(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE | flags.ISDIR, 'd', 0)], [(flags.CREATE, 'x', 0)]]
	queue, _, _ = scripted_watch(monkeypatch, job.monitor, reads, min_snapshot_delay_seconds=3600)
	assert [(e.event, e.path) for e in queue] == [('create', job.monitor + '/d'), ('create', job.monitor + '/x')]


def matched(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.matched
	finally:
		manifest.close()


def name(path):
	return os.path.basename(path)


def modify(job, rel, text):
	with open(os.path.join(job.monitor, rel), 'w') as f:
		f.write(text)
	return OrderedDict([event_entry(job, rel, 'modify')])


def record_matched_since(monkeypatch):
	'''The matched_since of each do_backup() call.'''
	calls = []
	real = rv.do_backup

	def recording(entries, *args, **kwargs):
		calls.append(kwargs.get('matched_since'))
		return real(entries, *args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', recording)
	return calls


def test_full_comparison_since_uses_a_key_naming_the_newest_version():
	infos = OrderedDict([(4, rv.VaultEntry(4, '/v/V4--a', 100.0, 0, 0)), (5, rv.VaultEntry(5, '/v/V5--b', 200.0, 0, 0))])
	assert rv.full_comparison_since(infos, ('V5--b', 150 * 10 ** 9)) == 150 * 10 ** 9
	assert rv.full_comparison_since(infos, ('V4--a', 150 * 10 ** 9)) == 100 * 10 ** 9
	assert rv.full_comparison_since(infos, None) == 100 * 10 ** 9


def test_each_final_commit_advances_or_carries_the_key(job):
	seed_monitor(job, {'a.txt': 'a'})
	v0 = run_backup(job, matched_since=100)[-1]
	assert matched(job) == (name(v0), 100)
	v1 = run_backup(job, modify(job, 'a.txt', 'b'), matched_since=200)[-1]
	assert matched(job) == (name(v1), 200)
	run_backup(job, matched_since=300)                      # "No differences"
	assert matched(job) == (name(v1), 300)
	v2 = run_backup(job, modify(job, 'a.txt', 'c'))[-1]     # round-tripped: carried forward
	assert matched(job) == (name(v2), 300)


def test_no_key_is_carried_from_a_vault_without_one(job):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	run_backup(job, modify(job, 'a.txt', 'b'))
	assert matched(job) is None


def test_a_paused_inner_mount_carries_the_time_forward(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	run_backup(job, matched_since=100)
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	v1 = run_backup(job, modify(job, 'a.txt', 'b'), matched_since=200)[-1]
	assert matched(job) == (name(v1), 100)


def test_an_attempt_that_met_an_unreadable_folder_carries_the_time_forward(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'bad/x': 'x'})
	run_backup(job, matched_since=100)
	bad = os.path.join(job.monitor, 'bad')
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == bad:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)
	v0 = rv.list_versions(job.job_vault)[-1].path
	run_backup(job, matched_since=200)                      # a full comparison that could not read bad/
	assert matched(job) == (name(v0), 100)


def test_a_failed_metadata_copy_carries_the_time_forward(job, monkeypatch):
	user_xattrs_or_skip(job.monitor)
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job, matched_since=100)
	a = os.path.join(job.monitor, 'a.txt')
	os.setxattr(a, 'user.x', b'1')
	real = rv.copystat
	def copystat(src, dst, *args, **kwargs):
		if os.fspath(src) == a:
			raise OSError(errno.EIO, os.strerror(errno.EIO), dst)
		return real(src, dst, *args, **kwargs)
	monkeypatch.setattr(rv, 'copystat', copystat)
	# the attrib's copy of a's metadata onto the vault's copy fails, and its verification's again: the batch commits without it
	v1 = run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'attrib')]), matched_since=time.time_ns())[-1]
	assert matched(job) == (name(v1), 100)
	monkeypatch.setattr(rv, 'copystat', real)
	v2 = run_backup(job, matched_since=time.time_ns())[-1]  # a later full comparison still reads a's xattrs
	assert v2 != v1 and os.getxattr(os.path.join(v2, 'a.txt'), 'user.x') == b'1'


def test_a_refused_attribute_sync_carries_the_time_forward(job, monkeypatch):
	user_xattrs_or_skip(job.monitor)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job, matched_since=100)
	v1 = run_backup(job, modify(job, 'b.txt', 'bb'), matched_since=200)[-1]
	assert os.path.islink(os.path.join(v1, 'a.txt'))
	os.setxattr(os.path.join(job.monitor, 'a.txt'), 'user.x', b'1')
	real = rv.chain_end
	def chain_end(vault, version_path, rel, *args, **kwargs):
		return None if rel.rstrip('/') == 'a.txt' else real(vault, version_path, rel, *args, **kwargs)
	monkeypatch.setattr(rv, 'chain_end', chain_end)
	# a's link chain cannot be followed: its attributes are not synced. the batch was read well after the change
	v2 = run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'attrib')]), matched_since=time.time_ns() + 20 * 10 ** 9)[-1]
	assert matched(job) == (name(v2), 200)
	monkeypatch.setattr(rv, 'chain_end', real)
	v3 = run_backup(job, matched_since=time.time_ns())[-1]  # a later full comparison still reads a's xattrs
	assert v3 != v2 and os.getxattr(os.path.join(v3, 'a.txt'), 'user.x') == b'1'


def test_delta_generation_writes_no_key(job):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	rv.delta_generate_backup_entries(OrderedDict(), latest_version(job), job.monitor).close()
	assert matched(job) is None


def test_a_full_comparison_reads_xattrs_only_of_entries_changed_since_the_matched_time(job, monkeypatch):
	monkeypatch.setattr(rv, 'VERIFY_CTIME_MARGIN_SECONDS', 0)
	files = [os.path.join(job.monitor, f'f{i}.txt') for i in range(5)]
	seed_monitor(job, {os.path.basename(path): 'x' for path in files})
	run_backup(job)
	for path in files:                                      # a version that changed every entry
		os.chmod(path, 0o600)
	time.sleep(0.02)
	since = time.time_ns()
	time.sleep(0.02)
	run_backup(job, OrderedDict(event_entry(job, os.path.basename(path), 'attrib') for path in files), matched_since=since)
	os.chmod(files[2], 0o600)                               # a new ctime, nothing else
	calls = []
	real = os.listxattr
	monkeypatch.setattr(os, 'listxattr', lambda path, *a, **kw: calls.append(path) or real(path, *a, **kw))
	run_backup(job)
	assert [path for path in calls if path.startswith(job.monitor)] == [files[2]]


def test_the_backuper_passes_each_batch_its_matched_time(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	calls = record_matched_since(monkeypatch)
	queue = rv.ChangeEventQueue(job.monitor)
	queue.read_wall_ns = 111
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	thread, lock, flag = start_backuper(job, queue)
	try:
		wait_for_committed_count(job, 2)
		open(os.path.join(job.monitor, 'b.txt'), 'w').write('changed')
		before = time.time_ns()
		with lock:
			queue.prepend(rv.backup_entries_to_change_events(OrderedDict([event_entry(job, 'b.txt', 'modify')])))
			queue.read_wall_ns = 222
		flag.set()
		wait_until(lambda: len(calls) == 3, message='no follow-up full comparison')
	finally:
		stop_backuper(thread)
	assert calls[:2] == [111, None] and before <= calls[2] <= time.time_ns()


def test_a_restarts_full_comparison_records_a_key(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	v0 = run_backup(job)[-1]
	assert matched(job) is None
	before = time.time_ns()
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(),
		job.monitor, job.vault, 'N/A', threading.Event()), kwargs=dict(startup=startup), daemon=True)
	thread.start()
	try:
		wait_until(lambda: matched(job) is not None, message='the restart wrote no key')
	finally:
		stop_backuper(thread)
	assert matched(job)[0] == name(v0) and before <= matched(job)[1] <= time.time_ns()


def test_an_xattr_set_while_down_reaches_the_follow_up_version(job, monkeypatch):
	user_xattrs_or_skip(job.monitor)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	for path in (job.monitor, os.path.join(job.monitor, 'a.txt'), os.path.join(job.monitor, 'b.txt')):
		os.utime(path, (1000, 1000))
	run_backup(job, matched_since=time.time_ns())
	# while the daemon is down: an xattr of b, and a write to a its pending batch holds
	os.setxattr(os.path.join(job.monitor, 'b.txt'), 'user.down', b'1')
	a = os.path.join(job.monitor, 'a.txt')
	open(a, 'w').write('changed')
	os.utime(a, (1000, 1000))
	pending = write_pending(job, [rv.ChangeEvent(time.monotonic(), False, 'modify', a, None)])
	os.utime(pending, (2000, 2000))
	queue = rv.ChangeEventQueue(job.monitor)
	assert rv.load_pending_transactions_for_resume(job.job_name, job.monitor, job.vault, queue)
	queue.read_wall_ns = time.time_ns() + 3600 * 10 ** 9   # a resumed batch's stamp is never used
	thread, lock, flag = start_backuper(job, queue)
	try:
		v2 = wait_for_committed_count(job, 3)[2]
	finally:
		stop_backuper(thread)
	assert os.getxattr(os.path.join(v2, 'b.txt'), 'user.down') == b'1'


def test_a_move_out_pending_at_a_max_delay_hand_over_still_pairs(job, monkeypatch):
	flags = rv.inotify_simple.flags
	reads = [[(flags.CREATE, 'f', 0)], [(flags.MOVED_FROM, 'a', 7)], [(flags.MOVED_TO, 'b', 7)]]
	queue, flag, _ = scripted_watch(monkeypatch, job.monitor, reads, min_snapshot_delay_seconds=3600, max_shapshot_delay_seconds=0)
	assert flag.is_set()
	m = job.monitor
	assert [(e.event, e.path, e.moved_from) for e in queue] == [('create', f'{m}/f', None), ('move', f'{m}/b', f'{m}/a')]
