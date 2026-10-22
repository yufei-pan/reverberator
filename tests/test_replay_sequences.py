import os
import shutil
import threading
import time
import pytest
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, write_tree as write_plain_tree, wait_until
from tests.test_verify_replay import BASE, assert_version_matches_tree

pytestmark = pytest.mark.inotify

# a move out of the tree expires into its delete after this long (30 s in the daemon)
MOVE_EXPIRY_SECONDS = 1.0


@pytest.fixture(autouse=True)
def _fast(poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', MOVE_EXPIRY_SECONDS)
	return poll_fast


class Watch:
	'''The real watchFolder on the monitored tree, its queue taken batch by batch as the backuper takes it.'''

	def __init__(self, job):
		self.job = job
		self.queue = rv.ChangeEventQueue(job.monitor)
		self.lock = threading.Lock()
		self.flag = threading.Event()
		self.thread = threading.Thread(target=rv.watchFolder, kwargs=dict(monitor_path=job.monitor, to_process=self.queue,
			to_process_lock=self.lock, to_process_flag=self.flag, irm=rv.inotify_resource_manager(), min_snapshot_delay_seconds=0,
			max_shapshot_delay_seconds=60), daemon=True)
		self.thread.start()
		probe = os.path.join(job.monitor, '.watch_ready')

		def ready():
			if os.path.exists(probe):
				os.remove(probe)
			with open(probe, 'w') as f:
				f.write('1')
			return any(e.event == 'create' and e.path.endswith('.watch_ready') for e in self.events())
		wait_until(ready, message='watcher not ready')
		os.remove(probe)
		wait_until(lambda: any(e.event == 'delete' and e.path.endswith('.watch_ready') for e in self.events()), message='no probe delete')
		self.take()

	def events(self):
		with self.lock:
			return list(self.queue)

	def take(self, until=None, settle=0.4):
		'''Wait for until(events), when given, and for the tree to settle, then take the batch as the backuper does.'''
		if until is not None:
			wait_until(lambda: until(self.events()), message='expected events not seen')
		time.sleep(settle)
		with self.lock:
			batch = self.queue.take()
		# the backuper clears the flag after taking: the watcher then records events in new folders again
		self.flag.clear()
		return batch

	def stop(self):
		rv.GREEN_LIGHT.clear()
		self.thread.join(timeout=3)
		rv.GREEN_LIGHT.set()


def has(kind, rel):
	'''A wait predicate: the watcher has queued a kind event for rel.'''
	return lambda events: any(e.event == kind and e.path.rstrip('/').endswith('/monitor/' + rel) for e in events)


def all_of(*predicates):
	return lambda events: all(predicate(events) for predicate in predicates)


def backup_batch(job, batch):
	'''One taken batch as the backuper backs it up: collapsed, its raw events' scopes to verify. Returns the new version.'''
	entries = rv.change_events_to_backup_entries(batch, job.monitor)
	run_backup(job, entries, touched=rv.touched_scopes(batch, job.monitor))
	return rv.list_versions(job.job_vault)[-1]


def start(tmp_path, before):
	'''V0 of before, and the real watcher on the monitored tree. Returns (job, the folder outside it, the watcher).'''
	job = create_job(str(tmp_path))
	outside = os.path.join(job.root, 'outside')
	os.makedirs(outside)
	seed_monitor(job, before)
	run_backup(job)
	return job, outside, Watch(job)


def mon(job, rel):
	return os.path.join(job.monitor, rel)


def put(job, rel, text):
	write_plain_tree(job.monitor, {rel: text})


def run_sequence(tmp_path, before, ops, until, number=1):
	'''
	V0 of before, then ops(job, outside) in one batch, backed up. The latest version, number number, holds what the
	monitored tree holds.
	'''
	job, outside, watch = start(tmp_path, before)
	try:
		ops(job, outside)
		batch = watch.take(until=until)
	finally:
		watch.stop()
	version = backup_batch(job, batch)
	assert version.number == number
	assert_version_matches_tree(job, version)
	return job, version


def read(path):
	with open(path) as f:
		return f.read()


# name: (before, operations, wait predicate for the last of the events)
def mv_dir_out_then_mkdir(job, outside):
	os.rename(mon(job, 'D'), os.path.join(outside, 'D'))
	os.mkdir(mon(job, 'D'))
	put(job, 'D/new.txt', 'new')
	os.symlink('new.txt', mon(job, 'D/lnk'))


def mv_dir_out_then_move_in(job, outside):
	write_plain_tree(outside, {'X/x.txt': 'moved in'})
	os.rename(mon(job, 'D'), os.path.join(outside, 'D'))
	os.rename(os.path.join(outside, 'X'), mon(job, 'D'))


def mv_subdir_out_then_mkdir(job, outside):
	os.rename(mon(job, 'D/sub'), os.path.join(outside, 'sub'))
	os.mkdir(mon(job, 'D/sub'))
	put(job, 'D/sub/other.txt', 'other')


def mv_dir_out_then_mkdir_p(job, outside):
	os.rename(mon(job, 'D'), os.path.join(outside, 'D'))
	os.makedirs(mon(job, 'D/sub'))
	put(job, 'D/sub/other.txt', 'other')


def mv_dir_out_then_mv_dir_over(job, outside):
	os.rename(mon(job, 'D'), os.path.join(outside, 'D'))
	os.rename(mon(job, 'E'), mon(job, 'D'))


def mv_dir_then_rm_child(job, outside):
	os.rename(mon(job, 'D'), mon(job, 'D2'))
	os.remove(mon(job, 'D2/old.txt'))


def rename_save(job, outside):
	os.rename(mon(job, 'f'), mon(job, 'f~'))
	put(job, 'f', 'new')


def vim_save(job, outside):
	os.rename(mon(job, 'f'), mon(job, 'f~'))
	put(job, 'f', 'new')
	os.remove(mon(job, 'f~'))


def mv_dir_mkdir_rm_old(job, outside):
	os.rename(mon(job, 'D'), mon(job, 'D2'))
	os.mkdir(mon(job, 'D'))
	put(job, 'D/new.txt', 'new')
	shutil.rmtree(mon(job, 'D2'))


def atomic_swap(job, outside):
	os.rename(mon(job, 'D'), mon(job, 'D.old'))
	os.rename(mon(job, 'D.new'), mon(job, 'D'))
	shutil.rmtree(mon(job, 'D.old'))


def mv_dir_then_mkdir(job, outside):
	os.rename(mon(job, 'D'), mon(job, 'D2'))
	os.mkdir(mon(job, 'D'))
	put(job, 'D/new.txt', 'new')


def create_in_dir_then_mv_dir(job, outside):
	put(job, 'D/new.txt', 'x')
	os.rename(mon(job, 'D'), mon(job, 'D2'))


def modify_in_dir_then_mv_dir(job, outside):
	put(job, 'D/old.txt', 'changed')
	os.rename(mon(job, 'D'), mon(job, 'D2'))


def git_branch_delete(job, outside):
	# the ref's new contents written to X.lock, renamed over X, then X deleted
	put(job, 'refs/X.lock', 'new ref')
	os.rename(mon(job, 'refs/X.lock'), mon(job, 'refs/X'))
	os.remove(mon(job, 'refs/X'))
	put(job, 'keep.txt', 'changed')


def swap_names(job, outside):
	os.rename(mon(job, 'a'), mon(job, 'a.tmp'))
	os.rename(mon(job, 'b'), mon(job, 'a'))
	os.rename(mon(job, 'a.tmp'), mon(job, 'b'))


def chain_of_renames(job, outside):
	os.rename(mon(job, 'a'), mon(job, 'b'))
	with open(mon(job, 'b'), 'a') as f:
		f.write(' more')
	os.rename(mon(job, 'b'), mon(job, 'c'))


def mv_dir_there_and_back(job, outside):
	os.rename(mon(job, 'D'), mon(job, 'D2'))
	os.rename(mon(job, 'D2'), mon(job, 'D'))


SEQUENCES = {
	'a': ({**BASE, 'D/lnk': 'old.txt'}, mv_dir_out_then_mkdir, has('create', 'D')),
	'd4': (BASE, mv_dir_out_then_move_in, has('create', 'D')),
	'd6': (BASE, mv_subdir_out_then_mkdir, has('create', 'D/sub')),
	'd7': (BASE, mv_dir_out_then_mkdir_p, has('create', 'D')),
	'c': ({**BASE, 'E/e.txt': 'e'}, mv_dir_out_then_mv_dir_over, has('move', 'D')),
	'f1': (BASE, mv_dir_then_rm_child, has('delete', 'D2/old.txt')),
	'e1': ({'f': 'old', 'keep.txt': 'k'}, rename_save, has('modify', 'f')),
	'e2': ({'f': 'old', 'keep.txt': 'k'}, vim_save, has('delete', 'f~')),
	'e3': ({'D/old.txt': 'old', 'keep.txt': 'k'}, mv_dir_mkdir_rm_old, has('delete', 'D2')),
	'e4': ({'D/old.txt': 'old', 'D.new/new.txt': 'new', 'keep.txt': 'k'}, atomic_swap, has('delete', 'D.old')),
	'd5': (BASE, mv_dir_then_mkdir, has('create', 'D')),
	'f3': (BASE, create_in_dir_then_mv_dir, has('move', 'D2')),
	'f5': (BASE, modify_in_dir_then_mv_dir, has('move', 'D2')),
	'git': ({'keep.txt': 'keep', 'refs/X': 'old ref'}, git_branch_delete, all_of(has('delete', 'refs/X'), has('modify', 'keep.txt'))),
	'swap': ({'a': 'A', 'b': 'B'}, swap_names, has('move', 'b')),
	'chain': ({'a': 'A'}, chain_of_renames, has('move', 'c')),
	'loop': (BASE, mv_dir_there_and_back, all_of(has('move', 'D'), has('move', 'D2'))),
}


@pytest.mark.parametrize('name', SEQUENCES)
def test_sequence(tmp_path, name):
	before, ops, until = SEQUENCES[name]
	# a folder moved away and back leaves the tree as it was: the batch makes no new version, and does not fail
	run_sequence(tmp_path, before, ops, until, number=0 if name == 'loop' else 1)


def test_sequence_content_is_what_the_tree_holds(tmp_path):
	# the cases whose old bytes stayed in the wrong place: a rename-save, a swap and a modify under a moved folder
	job, version = run_sequence(tmp_path, {'f': 'old', 'keep.txt': 'k'}, rename_save, has('modify', 'f'))
	assert (read(os.path.join(version.path, 'f')), read(os.path.join(version.path, 'f~'))) == ('new', 'old')
	job, version = run_sequence(tmp_path / 'swap', {'a': 'A', 'b': 'B'}, swap_names, has('move', 'b'))
	assert (read(os.path.join(version.path, 'a')), read(os.path.join(version.path, 'b'))) == ('B', 'A')
	job, version = run_sequence(tmp_path / 'f5', BASE, modify_in_dir_then_mv_dir, has('move', 'D2'))
	assert read(os.path.join(version.path, 'D2/old.txt')) == 'changed'


def test_sequence_git_pattern_removes_the_ref(tmp_path):
	job, version = run_sequence(tmp_path, SEQUENCES['git'][0], git_branch_delete, SEQUENCES['git'][2])
	assert not os.path.lexists(os.path.join(version.path, 'refs/X'))
	assert read(os.path.join(version.path, 'keep.txt')) == 'changed'


def test_sequence_late_delete(tmp_path):
	# mv D/old.txt <outside>; mv D D2: the watcher holds the move out of the tree until it expires, so its delete reaches
	# a later batch than D's rename
	job, outside, watch = start(tmp_path, BASE)
	try:
		os.rename(mon(job, 'D/old.txt'), os.path.join(outside, 'old.txt'))
		os.rename(mon(job, 'D'), mon(job, 'D2'))
		first = watch.take(until=has('move', 'D2'), settle=0.1)
		assert not has('delete', 'D/old.txt')(list(first))
		wait_until(lambda: has('delete', 'D/old.txt')(watch.events()), message='the move out did not expire')
		second = watch.take()
	finally:
		watch.stop()
	version = backup_batch(job, first)
	assert version.number == 1
	assert_version_matches_tree(job, version)
	version = backup_batch(job, second)
	assert version.number == 2
	assert_version_matches_tree(job, version)
