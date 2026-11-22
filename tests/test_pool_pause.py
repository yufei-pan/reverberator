import errno
import json
import os
import shutil
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import (write_scan_leftover, change_list_of, committed_versions, latest_version, run_backup, seed_monitor, wait_for_committed_count, wait_until,
	write_fstab, write_incomplete_version)


@pytest.fixture
def grace(monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)


@pytest.fixture
def board(tmp_path):
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), '/r.tsv')
	return rv.STATUS_BOARD


class Output:
	'''What capsys captured so far, kept across reads.'''
	def __init__(self, capsys):
		self.capsys = capsys
		self.text = ''

	def __call__(self) -> str:
		out = self.capsys.readouterr()
		self.text += out.out + out.err
		return self.text


@pytest.fixture
def output(capsys):
	return Output(capsys)


def _state(tmp_path, name='job'):
	try:
		with open(tmp_path / 'state' / f'job-{name}.json') as f:
			return json.load(f)
	except (OSError, ValueError):
		return {}


def _v0(job):
	_, manifest, _ = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
	manifest.close()


def _run_backuper(job, control, to_process=None, to_process_lock=None, to_process_flag=None, monitor_flag=None):
	to_process = rv.ChangeEventQueue(job.monitor) if to_process is None else to_process
	flag = monitor_flag
	if flag is None:
		flag = threading.Event()
		flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, to_process,
		threading.Lock() if to_process_lock is None else to_process_lock, job.monitor, job.vault, 'N/A',
		threading.Event() if to_process_flag is None else to_process_flag, flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	return thread


def _control(job):
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	return control


def _stop(control, *threads):
	control.fail('test done')
	for thread in threads:
		thread.join(timeout=5)
		assert not thread.is_alive()


def _marker(path, reason):
	return f'reverberator job job FAILED: waiting 0 min for {path}: {reason}'


def _goes_on(path):
	return f'reverberator job job goes on: {path} is ready again after 0 min'


@pytest.mark.unit
def test_a_missing_vault_disk_pauses_the_job_with_the_waiting_marker(job, fake_pool, grace, board, output, tmp_path):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_scan_leftover(job)
	# a change since V0, so the comparison once the disk is back commits a version
	seed_monitor(job, {'b.txt': 'b'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		reason = f'disk {a} of pool {job.vault} is not mounted'
		wait_until(lambda: _marker(job.vault, reason) in output(), timeout=5, message='no waiting marker')
		assert os.path.lexists(orphan), 'the vault was scanned while a disk is out'
		assert len(committed_versions(job)) == 1
		assert _state(tmp_path)['state'] == 'waiting' and _state(tmp_path)['detail'] == f'{job.vault}: {reason}'
		fake_pool.mount(a)
		wait_until(lambda: not os.path.lexists(orphan), timeout=5, message='the orphan stayed')
		wait_for_committed_count(job, 2)
		wait_until(lambda: _goes_on(job.vault) in output(), timeout=5, message='no goes on line')
		assert output().count(_goes_on(job.vault)) == 1
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_missing_monitored_disk_pauses_the_backup_but_not_the_vault_scan(job, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_scan_leftover(job)
	# a change since V0, so the comparison once the disk is back commits a version
	seed_monitor(job, {'b.txt': 'b'})
	m, _ = fake_pool.add(job.monitor, ['m1', 'm2'])
	fake_pool.drop(m)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: not os.path.lexists(orphan), timeout=5, message='the vault was not scanned')
		reason = f'disk {m} of pool {job.monitor} is not mounted'
		wait_until(lambda: _marker(job.monitor, reason) in output(), timeout=5, message='no waiting marker')
		assert len(committed_versions(job)) == 1
		fake_pool.mount(m)
		wait_for_committed_count(job, 2)
	finally:
		_stop(control, thread)


@pytest.mark.inotify
def test_the_watcher_keeps_queuing_while_the_vault_pool_is_out(job, fake_pool, grace, output, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	to_process_flag = threading.Event()
	control = _control(job)
	watched = []
	real_init = rv.initializeFolderWatchers
	def counting_init(inotify_obj, path, *args, **kwargs):
		result = real_init(inotify_obj, path, *args, **kwargs)
		if path == job.monitor:
			watched.append(result)
		return result
	monkeypatch.setattr(rv, 'initializeFolderWatchers', counting_init)
	monitor_flag = threading.Event()
	monitor_flag.set()
	watcher = threading.Thread(target=rv.watcher, args=(monitor_flag, job.monitor, to_process, lock, to_process_flag,
		rv.inotify_resource_manager(), 0, 60), kwargs=dict(job=control), daemon=True)
	watcher.start()
	backuper = _run_backuper(job, control, to_process, lock, to_process_flag)
	try:
		wait_until(lambda: watched, timeout=5, message='root not watched')
		wait_until(lambda: _marker(job.vault, f'disk {a} of pool {job.vault} is not mounted') in output(), timeout=5,
			message='no waiting marker')
		with open(os.path.join(job.monitor, 'new.txt'), 'w') as f:
			f.write('new')
		def queued():
			with lock:
				return any(event.path.endswith('new.txt') for event in list(to_process))
		wait_until(queued, timeout=5, message='the event was not queued')
		assert not committed_versions(job)
		fake_pool.mount(a)
		wait_for_committed_count(job, 1)
		assert os.path.isfile(os.path.join(latest_version(job).path, 'new.txt'))
	finally:
		_stop(control, watcher, backuper)


@pytest.mark.unit
@pytest.mark.parametrize('side', ['vault', 'monitor'])
def test_a_disk_dropped_between_batches_pauses_the_next_one(job, fake_pool, grace, output, side):
	seed_monitor(job, {'a.txt': 'a'})
	pool = job.vault if side == 'vault' else job.monitor
	disk, _ = fake_pool.add(pool, ['d1', 'd2'])
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	to_process_flag = threading.Event()
	control = _control(job)
	thread = _run_backuper(job, control, to_process, lock, to_process_flag)
	try:
		wait_for_committed_count(job, 1)
		fake_pool.drop(disk)
		seed_monitor(job, {'b.txt': 'b'})
		with lock:
			to_process.append(rv.ChangeEvent(time.monotonic(), False, 'create', os.path.join(job.monitor, 'b.txt'), None))
		to_process_flag.set()
		wait_until(lambda: _marker(pool, f'disk {disk} of pool {pool} is not mounted') in output(), timeout=5,
			message='no waiting marker')
		assert len(committed_versions(job)) == 1
		fake_pool.mount(disk)
		wait_for_committed_count(job, 2)
		assert os.path.isfile(os.path.join(latest_version(job).path, 'b.txt'))
	finally:
		_stop(control, thread)


@pytest.mark.unit
@pytest.mark.parametrize('side', ['vault', 'monitor'])
def test_an_idle_job_reports_a_missing_pool_disk(job, fake_pool, grace, output, side):
	# a job with nothing to back up waits for its next batch: a disk of its pool that drops meanwhile is reported
	seed_monitor(job, {'a.txt': 'a'})
	pool = job.vault if side == 'vault' else job.monitor
	a, _ = fake_pool.add(pool, ['a', 'b'])
	to_process = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	to_process_flag = threading.Event()
	control = _control(job)
	# the monitor's flag for the monitored path, which clears on a pool problem, as the daemon hands the backuper
	monitor_flag = rv.FS_SIGNATURE_MONITOR.register(job.monitor, 'N/A') if side == 'monitor' else None
	thread = _run_backuper(job, control, to_process, lock, to_process_flag, monitor_flag)
	try:
		wait_for_committed_count(job, 1)
		fake_pool.drop(a)
		wait_until(lambda: _marker(pool, f'disk {a} of pool {pool} is not mounted') in output(), timeout=5,
			message='no waiting marker')
		fake_pool.mount(a)
		wait_until(lambda: _goes_on(pool) in output(), timeout=5, message='no goes on line')
		seed_monitor(job, {'b.txt': 'b'})
		with lock:
			to_process.append(rv.ChangeEvent(time.monotonic(), False, 'create', os.path.join(job.monitor, 'b.txt'), None))
		to_process_flag.set()
		wait_for_committed_count(job, 2)
		assert os.path.isfile(os.path.join(latest_version(job).path, 'b.txt'))
		assert output().count(_goes_on(pool)) == 1
	finally:
		_stop(control, thread)


def _left_reason(pool, branch):
	return (f'disk {branch} left pool {pool} during the last attempt: waiting for it to be listed again '
		'(restart reverberator if it was taken out for good)')


def _attempt_that_loses_a_disk(job, fake_pool, monkeypatch, pool):
	"""
	A job with a change since its V0 and a pool of two disks at pool (the vault's or the monitored path's), whose first attempt has one
	taken out of the pool's list, still mounted, as the first batch's copies are flushed: the JobControl once that attempt failed, and
	the disk.
	"""
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	seed_monitor(job, {'b.txt': 'b'})
	_, b = fake_pool.add(pool, ['a', 'b'])
	real, left = rv.flush_copies, []
	def flushing(*args, **kwargs):
		if not left:
			fake_pool.leave(pool, b)
			left.append(True)
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'flush_copies', flushing)
	control = _control(job)
	thread = _run_backuper(job, control)
	thread.join(timeout=10)
	try:
		assert left and not thread.is_alive()
		assert control.failure.reason == f'disk {b} left pool {pool} during this step'
	except BaseException:
		# a regression must not leave a backuper thread running behind the failed test
		_stop(control, thread)
		raise
	return control, b


@pytest.mark.unit
@pytest.mark.parametrize('side', ['vault', 'monitor'])
def test_the_attempt_after_a_disk_was_taken_out_of_the_pool_waits_for_it_to_be_listed_again(job, fake_pool, grace, board, output, monkeypatch, tmp_path, side):
	# fails on 0392dcc (goes on): the retry of a step that failed for a disk taken out of its pool's list (mergerfs's control file) finds the
	# pool whole as it is then, as no wait sees a disk that is mounted still. Its scan then acts on a view that hides what that disk holds,
	# such as a version's real entry on it, over which the scan writes a forward link to the cut batch's new copy: once the roll-forward
	# commits, version n shows the new bytes. The retry waits for the disk to be listed again instead, before it does anything with the
	# vault (the vault scan, or for the monitored pool's disk the walk of the monitored tree)
	pool = job.vault if side == 'vault' else job.monitor
	control, b = _attempt_that_loses_a_disk(job, fake_pool, monkeypatch, pool)
	orphan = write_scan_leftover(job)
	control.start_attempt()
	thread = _run_backuper(job, control)
	try:
		reason = _left_reason(pool, b)
		wait_until(lambda: _marker(pool, reason) in output(), timeout=5, message='no waiting marker')
		scanned = 'the vault was scanned while a disk of its pool is out' if side == 'vault' else 'the vault was not scanned, though only the monitored path\'s pool lost a disk'
		assert (os.path.lexists(orphan) if side == 'vault' else not os.path.lexists(orphan)), scanned
		assert len(committed_versions(job)) == 1
		assert _state(tmp_path)['state'] == 'waiting' and _state(tmp_path)['detail'] == f'{pool}: {reason}'
		fake_pool.come_back(pool, b)
		wait_for_committed_count(job, 2)
		wait_until(lambda: _goes_on(pool) in output(), timeout=5, message='no goes on line')
		assert not os.path.lexists(orphan) and not control.left
		assert os.path.isfile(os.path.join(latest_version(job).path, 'b.txt'))
	finally:
		_stop(control, thread)


@pytest.mark.unit
@pytest.mark.parametrize('unreadable', ['the branch list', 'the mount table'])
def test_a_wait_for_a_disk_that_left_the_pool_goes_on_while_the_pool_cannot_be_read(job, tmp_path, fake_pool, monkeypatch, unreadable):
	# review of Task 13 (Haiku c1 (3)), fails on b565fd2 (the wait ends: left_reason() answered None): the pool's branch list, or the mount
	# table, cannot be read at the moment the wait looks for the disk the failed attempt saw leave. It is the wait's reason, as the pool's
	# own is (pool_state()), not an end to the wait with the disk possibly still out
	_, b = fake_pool.add(job.vault, ['a', 'b'])
	pool = os.path.realpath(job.vault)
	control = rv.JobControl('job')
	control.left.add((pool, b))
	fake_pool.leave(job.vault, b)
	assert control.left_reason(job.vault) == _left_reason(pool, b)
	if unreadable == 'the branch list':
		fake_pool.unreadable(job.vault, errno.ENOTCONN)
		assert control.left_reason(job.vault) == f'the disks of pool {pool} cannot be listed: {os.strerror(errno.ENOTCONN)}'
		fake_pool.unreadable_pools.pop(pool)
	else:
		with monkeypatch.context() as unread:
			unread.setattr(rv, 'MOUNTINFO_PATH', str(tmp_path / 'no-mountinfo'))
			assert control.left_reason(job.vault).startswith('the mount table cannot be read: ')
	# nothing is forgotten by it: listed again, the wait ends
	fake_pool.come_back(job.vault, b)
	assert control.left_reason(job.vault) is None and not control.left


@pytest.mark.unit
def test_the_attempt_after_a_disk_taken_out_and_listed_again_goes_on_at_once(job, fake_pool, grace, board, output, monkeypatch):
	# pin: the disk is listed again before the retry looks, so nothing waits and the memory of it is gone
	control, b = _attempt_that_loses_a_disk(job, fake_pool, monkeypatch, job.vault)
	fake_pool.come_back(job.vault, b)
	control.start_attempt()
	thread = _run_backuper(job, control)
	try:
		wait_for_committed_count(job, 2)
		assert 'FAILED: waiting' not in output()
		assert not control.left
	finally:
		_stop(control, thread)


def _wait_in_thread(control, flag, path, results):
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, path,
		'monitored filesystem not ready')), daemon=True)
	thread.start()
	return thread


@pytest.mark.unit
@pytest.mark.parametrize('phase', [0, 1 / 3, 2 / 3])
def test_a_lost_root_alerts_once_with_a_batch_pending(tmp_path, grace, output, phase):
	# the watcher's lost-root wait and the batch loop's monitored wait, half a poll apart, both past the grace when the
	# root comes back at phase of a poll period
	path = str(tmp_path / 'root')
	control = rv.JobControl('job')
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	results = []
	first = _wait_in_thread(control, flag, path, results)
	second = None
	try:
		wait_until(lambda: len(control._waits) == 1, timeout=5, message='first wait not begun')
		time.sleep(rv.POLL_WAIT_SECONDS / 2)
		second = _wait_in_thread(control, flag, path, results)
		wait_until(lambda: len(control._waits) == 2, timeout=5, message='second wait not begun')
		first_token, second_token = (wait[0] for wait in control._waits)
		assert control.alerts(first_token) and not control.alerts(second_token)
		marker = _marker(path, 'monitored filesystem not ready')
		wait_until(lambda: marker in output(), timeout=5, message='no waiting marker')
		time.sleep(0.4 + phase * rv.POLL_WAIT_SECONDS)
		assert output().count(marker) == 1
		os.makedirs(path)
		first.join(timeout=5)
		second.join(timeout=5)
		assert results == [True, True]
		assert output().count(marker) == 1 and output().count(_goes_on(path)) == 1
	finally:
		_stop(control, *(thread for thread in (first, second) if thread is not None))


@pytest.mark.unit
def test_a_job_off_the_pool_runs_while_the_pool_is_out(job, tmp_path, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	other = str(tmp_path / 'other_pool')
	a, _ = fake_pool.add(other, ['a', 'b'])
	fake_pool.drop(a)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_for_committed_count(job, 1)
		time.sleep(0.3)
		assert not [line for line in output().splitlines() if 'FAILED: waiting' in line and str(tmp_path) in line]
		assert fake_pool.reads == 0
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_wait_that_never_alerted_ends_silently(job, fake_pool, poll_fast, monkeypatch, output):
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 30)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	control = rv.JobControl('job')
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	results = []
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, job.vault,
		'vault filesystem not ready')), daemon=True)
	thread.start()
	time.sleep(0.3)
	assert thread.is_alive(), 'the wait ended with a disk out'
	fake_pool.mount(a)
	thread.join(timeout=5)
	assert results == [True]
	assert 'FAILED: waiting' not in output() and 'goes on' not in output()


def _not_mounted(mount_point):
	return f'{mount_point} is not mounted ({rv.FSTAB_PATH} names it)'


@pytest.mark.unit
def test_a_vault_wait_waits_for_its_fstab_mount_with_the_marker(job, fake_pool, grace, output):
	write_fstab(job.vault)
	control = _control(job)
	flag = threading.Event()
	flag.set()
	results = []
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, job.vault,
		'vault filesystem not ready')), daemon=True)
	thread.start()
	try:
		wait_until(lambda: _marker(job.vault, _not_mounted(job.vault)) in output(), timeout=5, message='no waiting marker')
		assert thread.is_alive()
		fake_pool.add_mount(job.vault)
		thread.join(timeout=5)
		assert results == [True] and _goes_on(job.vault) in output()
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_monitored_path_wait_waits_for_its_fstab_mount_with_the_marker(job, fake_pool, grace, output):
	# 0.47 and the first 0.48 build pinned the opposite: a monitored wait read no fstab
	write_fstab(job.monitor)
	control = _control(job)
	flag = threading.Event()
	flag.set()
	results = []
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, job.monitor,
		'monitored filesystem not ready')), daemon=True)
	thread.start()
	try:
		wait_until(lambda: _marker(job.monitor, _not_mounted(job.monitor)) in output(), timeout=5, message='no waiting marker')
		assert thread.is_alive()
		fake_pool.add_mount(job.monitor)
		thread.join(timeout=5)
		assert results == [True] and _goes_on(job.monitor) in output()
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_file_at_the_waited_path_is_named_in_the_marker(job, fake_pool, grace, output):
	path = os.path.join(job.root, 'a_file')
	open(path, 'w').write('x')
	control = _control(job)
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.wait_for_path, args=(control, flag, path, 'vault filesystem not ready'), daemon=True)
	thread.start()
	try:
		wait_until(lambda: _marker(path, f'{path} is not a folder') in output(), timeout=5, message='no waiting marker')
	finally:
		_stop(control, thread)
	assert open(path).read() == 'x'


@pytest.mark.unit
def test_a_monitored_path_under_an_unmounted_fstab_mount_commits_nothing_until_mounted(job, fake_pool, grace, output):
	# the unmounted disk's bare folder is empty: backing it up would commit every file deleted
	write_fstab(job.monitor)
	seed_monitor(job, {'a.txt': 'a'})
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(job.monitor, _not_mounted(job.monitor)) in output(), timeout=5, message='no waiting marker')
		time.sleep(0.3)
		assert committed_versions(job) == []
		fake_pool.add_mount(job.monitor)
		wait_for_committed_count(job, 1)
		assert os.path.exists(os.path.join(latest_version(job).path, 'a.txt'))
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_bare_vault_folder_hidden_by_its_mount_is_replaced_by_one_made_on_the_disk(job, tmp_path, fake_pool, grace, output):
	# a 0.47 leftover (or mkdir -p before mounting) shows the vault path, while the disk mounted over it has no such folder
	vaults = str(tmp_path / 'vaults')
	vault = os.path.join(vaults, 'reverbs')
	os.makedirs(vault)
	job = job._replace(vault=vault, job_vault=os.path.join(vault, job.job_name))
	write_fstab(vaults)
	seed_monitor(job, {'a.txt': 'a'})
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(vault, _not_mounted(vaults)) in output(), timeout=5, message='no waiting marker')
		# the mount hides the bare folder; the disk holds no reverbs
		shutil.rmtree(vault)
		fake_pool.add_mount(vaults)
		wait_for_committed_count(job, 1, timeout=10)
		assert os.path.isdir(vault)
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_the_start_makes_a_missing_vault_path_once_its_fstab_mount_is_mounted(job, tmp_path, fake_pool, grace, output, monkeypatch):
	vaults = str(tmp_path / 'vaults')
	os.makedirs(vaults)
	job = job._replace(vault=os.path.join(vaults, 'reverbs'), job_vault=os.path.join(vaults, 'reverbs', job.job_name))
	write_fstab(vaults)
	seed_monitor(job, {'a.txt': 'a'})
	# the signature passes only on the folder made, and a pair that failed is not checked again for an hour: the
	# backup comes at once only when the monitor learns of the new folder at once
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: os.path.isdir(path))
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 3600)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(job.vault, _not_mounted(vaults)) in output(), timeout=5, message='no waiting marker')
		assert not os.path.lexists(job.vault)
		fake_pool.add_mount(vaults)
		wait_for_committed_count(job, 1, timeout=10)
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_bare_vault_folder_under_an_unmounted_fstab_mount_is_never_backed_up_into(job, fake_pool, grace, output):
	# 0.47 left such folders on the root disk
	write_fstab(job.vault)
	seed_monitor(job, {'a.txt': 'a'})
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(job.vault, _not_mounted(job.vault)) in output(), timeout=5, message='no waiting marker')
		time.sleep(0.3)
		assert committed_versions(job) == [] and not os.path.lexists(job.job_vault)
		fake_pool.add_mount(job.vault)
		wait_for_committed_count(job, 1)
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_vault_disk_unmounted_mid_run_holds_the_next_batch(job, fake_pool, grace, output):
	write_fstab(job.vault)
	fake_pool.add_mount(job.vault)
	seed_monitor(job, {'a.txt': 'a'})
	control = _control(job)
	to_process, lock, to_process_flag = rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event()
	thread = _run_backuper(job, control, to_process, lock, to_process_flag)
	try:
		wait_for_committed_count(job, 1)
		fake_pool.drop(job.vault)
		seed_monitor(job, {'b.txt': 'b'})
		with lock:
			to_process.append(rv.ChangeEvent(time.monotonic(), False, 'create', os.path.join(job.monitor, 'b.txt'), None))
		to_process_flag.set()
		wait_until(lambda: _marker(job.vault, _not_mounted(job.vault)) in output(), timeout=5, message='no waiting marker')
		time.sleep(0.3)
		assert len(committed_versions(job)) == 1
		fake_pool.mount(job.vault)
		wait_for_committed_count(job, 2)
	finally:
		_stop(control, thread)


@pytest.mark.unit
def test_a_vault_path_that_cannot_be_made_fails_the_attempt(job, fake_pool, poll_fast):
	blocker = os.path.join(job.root, 'blocker')
	open(blocker, 'w').write('x')
	job = job._replace(vault=os.path.join(blocker, 'vault'), job_vault=os.path.join(blocker, 'vault', job.job_name))
	control = _control(job)
	thread = _run_backuper(job, control)
	thread.join(timeout=5)
	assert not thread.is_alive() and 'does not exist and cannot be created' in control.failure.reason


@pytest.mark.unit
@pytest.mark.parametrize('spelled', ['//', '/', '/./'])
def test_the_guard_of_a_batch_answers_for_the_job_folder_however_the_vault_path_is_spelled(job, fake_pool, poll_fast, monkeypatch, spelled):
	# the rule's vault path is not normalised: the guard is built on the job's folder as spelled and asked with the normal spelling (the prune), or the other way
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	seed_monitor(job, {'b.txt': 'b'})
	fake_pool.add(job.vault, ['a', 'b'])
	control = _control(job)
	guards = []
	def do_backup(*args, **kwargs):
		guards.append((kwargs['pool_guard'], kwargs['vault_path']))
		control.fail('test done')
		return kwargs['vaultInfo'], kwargs['manifest'], True
	monkeypatch.setattr(rv, 'do_backup', do_backup)
	job = job._replace(vault=job.vault + spelled)
	thread = _run_backuper(job, control)
	thread.join(timeout=5)
	assert not thread.is_alive() and len(guards) == 1
	guard, vault_path = guards[0]
	assert vault_path == job.vault
	plain = os.path.join(os.path.normpath(job.vault), job.job_name)
	for asked in (plain, os.path.join(job.vault, job.job_name), plain + '/'):
		assert guard.covers(asked), asked
	assert not guard.covers(os.path.join(plain, 'other'))


# ---- D10: a disk mounted under a pool's disk at the monitored path's place -------------------------------------------------

def _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool):
	'''
	The pool at <tmp>/pool of one disk, disk1, the monitored path <tmp>/pool/data, and a disk mounted at <disk1>/data/sub, which the
	pool shows at <tmp>/pool/data/sub (the fake pool's folder stands for what the pool shows): (the monitored path, the disk's mount
	point).
	'''
	pool = os.path.realpath(tmp_path / 'pool')
	disk1, = fake_pool.add(pool, ['disk1'])
	monitor = os.path.join(pool, 'data')
	os.makedirs(os.path.join(monitor, 'sub'))
	return monitor, fake_pool.add_mount(os.path.join(disk1, 'data', 'sub'))


@pytest.mark.unit
def test_a_mount_under_a_branch_at_the_paths_place_is_an_inner_mount(tmp_path, fake_pool):
	# fails on main (no pool parameter; the mount table shows the disk under disk1, not under the monitored path): the disk at
	# <disk1>/data/sub is an inner mount of <tmp>/pool/data, as the pool shows it. One at the place itself (<disk1>/data) is the
	# fstab wait's, not an inner mount
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	table = rv.read_mount_table()
	state = rv.pool_state(monitor, table)
	assert rv.inner_mount_rels(table, monitor, pool=state) == {'sub/'}
	assert rv.pool_inner_mounts(table, monitor, state) == {os.path.join(monitor, 'sub'): disk}
	fake_pool.add_mount(os.path.dirname(disk))
	table = rv.read_mount_table()
	assert rv.inner_mount_rels(table, monitor, pool=rv.pool_state(monitor, table)) == {'sub/'}


@pytest.mark.unit
def test_a_full_comparison_with_it_unmounted_keeps_its_rows(job, tmp_path, fake_pool, monkeypatch, poll_fast):
	# fails on main (its rows deleted): a first version with the disk mounted holds its files; the disk unmounted (out of the table,
	# its folder empty through the pool) and a.txt changed, the full comparison pauses it: "Inner mounts not mounted" logged, the new
	# version keeps the disk's last copies, the matched time is the first version's carried forward, and the mount is remembered
	from tests.test_inner_mounts import _lines, _read, _recorded
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	job = job._replace(monitor=monitor)
	seed_monitor(job, {'a.txt': 'a', 'sub/f.txt': 'f', 'sub/g/h.txt': 'h'})
	run_backup(job, matched_since=time.time_ns())
	(_, since), _ = _recorded(job)
	fake_pool.drop(disk)
	shutil.rmtree(os.path.join(monitor, 'sub'))
	os.mkdir(os.path.join(monitor, 'sub'))
	seed_monitor(job, {'a.txt': 'changed'})
	lines = _lines(monkeypatch)
	run_backup(job, matched_since=time.time_ns())
	v1 = committed_versions(job)[1]
	assert _read(os.path.join(v1, 'sub', 'f.txt')) == 'f' and _read(os.path.join(v1, 'sub', 'g', 'h.txt')) == 'h'
	assert _read(os.path.join(v1, 'a.txt')) == 'changed'
	assert 'Inner mounts not mounted, keeping their last backed-up contents: sub/' in lines
	assert os.path.join(monitor, 'sub') not in _read(change_list_of(v1))
	assert _recorded(job) == ((os.path.basename(v1), since), ['sub/'])


@pytest.mark.unit
def test_its_files_deleted_while_it_is_mounted_are_deleted(job, tmp_path, fake_pool, poll_fast):
	# pin: the disk mounted and emptied is not paused, as the batch's pool is passed to every look at it: the backuper's comparison of
	# a scanned folder (the watcher's scan of it) finds its file deleted, and so does a full comparison, whose version lacks it
	monitor, _ = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	job = job._replace(monitor=monitor)
	seed_monitor(job, {'a.txt': 'a', 'sub/f.txt': 'f'})
	run_backup(job)
	os.remove(os.path.join(monitor, 'sub', 'f.txt'))
	table = rv.read_mount_table()
	entries = OrderedDict()
	_, manifest, full = rv.compare_scanned_folders(entries, [os.path.join(monitor, 'sub')], job.job_name, monitor, job.vault,
		vaultInfo=rv.get_vault_info(job.job_vault), pool_guard=rv.PoolGuard([job.job_vault, monitor], mount_table=table), mount_table=table)
	manifest.close()
	assert not full and entries[os.path.join(monitor, 'sub', 'f.txt')].event == 'delete'
	run_backup(job)
	assert not os.path.lexists(os.path.join(committed_versions(job)[1], 'sub', 'f.txt'))


@pytest.mark.unit
def test_its_fingerprint_is_the_disks_own(tmp_path, fake_pool):
	# fails on main (no pool parameter): the watcher's fingerprint of the inner mount at <tmp>/pool/data/sub is the one of the disk
	# mounted at <disk1>/data/sub, not the pool's, which a disk under a branch never changes
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	table = rv.read_mount_table()
	watched = rv.watched_inner_mounts(table, monitor, pool=rv.pool_state(monitor, table))
	assert watched == {os.path.join(monitor, 'sub'): rv.mount_fingerprint(table, disk)}
	assert watched[os.path.join(monitor, 'sub')] != rv.mount_fingerprint(table, os.path.join(monitor, 'sub'))


@pytest.mark.unit
def test_the_watcher_compares_it_when_it_is_mounted_again(tmp_path, fake_pool):
	# fails on main (nothing queued): the watcher follows the disk under the branch as an inner mount, each change of it (mounted,
	# unmounted, mounted again) a scan of its folder through the pool
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	queue = rv.ChangeEventQueue(monitor)
	class FakeINotify:
		def rm_watch(self, wd):
			pass
		def add_watch(self, path, mask):
			return 1
	inner = {}
	seen = [None]
	def follow():
		return rv.follow_inner_mounts(FakeINotify(), monitor, rv.read_mount_table(), inner, seen, {}, rv.inotify_resource_manager(), 0, queue, threading.Lock())
	assert follow() == 1
	fake_pool.drop(disk)
	assert follow() == 1 and inner == {}
	fake_pool.mount(disk)
	assert follow() == 1 and list(inner) == [os.path.join(monitor, 'sub')]
	assert [(event.event, event.path) for event in queue] == [('scan', os.path.join(monitor, 'sub'))] * 3


@pytest.mark.unit
def test_the_watcher_reads_the_branch_list_alone_and_keeps_the_last_one_when_a_read_fails(tmp_path, fake_pool, monkeypatch):
	# review of Task 12, M2 (fails on 8212548, which read the whole pool_state() at each table: fstab, a statx of the pool and each branch, so its
	# read of the branch list failing gave no disks, the disk under the branch read as unmounted, its watches went and a scan was queued, and
	# the next table mounted it again: a large inner disk compared twice for a read that failed). The watcher takes the pool's mount point and
	# the branch list from the control file alone, and keeps the last list when a read fails
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	pool = os.path.dirname(monitor)
	queue = rv.ChangeEventQueue(monitor)
	class FakeINotify:
		def rm_watch(self, wd):
			pass
		def add_watch(self, path, mask):
			return 1
	reads = []
	for name in ('fstab_mount_points', 'statx_mount'):
		real = getattr(rv, name)
		monkeypatch.setattr(rv, name, lambda *args, _real=real, _name=name, **kwargs: reads.append(_name) or _real(*args, **kwargs))
	inner = {}
	seen = [rv.watched_pool(monitor, rv.read_mount_table(), None)]
	assert [branch for branch, _ in seen[0].ids] == [os.path.realpath(os.path.join(tmp_path, 'disks', 'disk1'))]
	def follow():
		return rv.follow_inner_mounts(FakeINotify(), monitor, rv.read_mount_table(), inner, seen, {}, rv.inotify_resource_manager(), 0, queue, threading.Lock())
	assert follow() == 1 and list(inner) == [os.path.join(monitor, 'sub')]
	assert reads == []
	fake_pool.unreadable(pool, errno.ENOTCONN)
	# the read fails: the last list stays, the disk is still the pool's inner mount, nothing is queued
	assert follow() == 0 and list(inner) == [os.path.join(monitor, 'sub')]
	assert len(list(queue)) == 1 and reads == []


@pytest.mark.unit
def test_a_pool_the_watcher_never_read_has_no_disks_until_a_table_reads_them(tmp_path, fake_pool):
	# a start whose branch list cannot be read has no list to keep: no inner mount under a branch is followed until a read answers
	monitor, disk = _a_pool_with_a_disk_under_its_branch(tmp_path, fake_pool)
	fake_pool.unreadable(os.path.dirname(monitor), errno.ENOTCONN)
	table = rv.read_mount_table()
	first = rv.watched_pool(monitor, table, None)
	assert first.pool == os.path.dirname(monitor) and first.ids == () and rv.watched_inner_mounts(table, monitor, pool=first) == {}
	fake_pool.unreadable_pools.pop(os.path.dirname(monitor))
	assert list(rv.watched_inner_mounts(table, monitor, pool=rv.watched_pool(monitor, table, first))) == [os.path.join(monitor, 'sub')]


@pytest.mark.unit
def test_off_a_pool_inner_mounts_are_as_today(tmp_path):
	# pin: off a pool, an inner mount is a mount point under the monitored path, and a disk mounted at a folder of the same name
	# elsewhere is none: pool_state() is None there, so no caller passes a pool
	root = os.path.realpath(tmp_path)
	monitor = os.path.join(root, 'm')
	for folder in ('m/disk', 'disk1/m/sub'):
		os.makedirs(os.path.join(root, folder))
	disk = (b'2', b'8:17', b'/', b'/dev/sdb1', b'xfs')
	table = [('/', (b'1', b'8:1', b'/', b'/dev/sda1', b'ext4')), (os.path.join(monitor, 'disk'), disk),
		(os.path.join(root, 'disk1'), (b'3', b'8:33', b'/', b'/dev/sdc1', b'xfs')), (os.path.join(root, 'disk1', 'm', 'sub'), (b'4', b'8:49', b'/', b'/dev/sdd1', b'xfs'))]
	assert rv.pool_state(monitor, table) is None
	assert rv.inner_mount_rels(table, monitor, pool=None) == {'disk/'}
	assert rv.watched_inner_mounts(table, monitor, pool=None) == {os.path.join(monitor, 'disk'): disk}
	assert rv.paused_inner_mounts(monitor, ['disk/', 'gone/'], table, pool=None) == set()
