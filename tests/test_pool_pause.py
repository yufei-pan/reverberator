import json
import os
import shutil
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import (committed_versions, latest_version, seed_monitor, wait_for_committed_count, wait_until,
	write_fstab, write_incomplete_version)

pytestmark = pytest.mark.unit


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
		keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')
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


def test_a_missing_vault_disk_pauses_the_job_with_the_waiting_marker(job, fake_pool, grace, board, output, tmp_path):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_incomplete_version(job, 1, {'a.txt': 'partial'})
	# a change since V0, so the comparison once the disk is back commits a version
	seed_monitor(job, {'b.txt': 'b'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		reason = f'disk {a} of pool {job.vault} is not mounted'
		wait_until(lambda: _marker(job.vault, reason) in output(), timeout=5, message='no waiting marker')
		assert os.path.isdir(orphan), 'the vault was scanned while a disk is out'
		assert len(committed_versions(job)) == 1
		assert _state(tmp_path)['state'] == 'waiting' and _state(tmp_path)['detail'] == f'{job.vault}: {reason}'
		fake_pool.mount(a)
		wait_until(lambda: not os.path.lexists(orphan), timeout=5, message='the orphan stayed')
		wait_for_committed_count(job, 2)
		wait_until(lambda: _goes_on(job.vault) in output(), timeout=5, message='no goes on line')
		assert output().count(_goes_on(job.vault)) == 1
	finally:
		_stop(control, thread)


def test_a_missing_monitored_disk_pauses_the_backup_but_not_the_vault_scan(job, fake_pool, grace, output):
	seed_monitor(job, {'a.txt': 'a'})
	_v0(job)
	orphan = write_incomplete_version(job, 1, {'a.txt': 'partial'})
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


def _wait_in_thread(control, flag, path, results):
	thread = threading.Thread(target=lambda: results.append(rv.wait_for_path(control, flag, path,
		'monitored filesystem not ready')), daemon=True)
	thread.start()
	return thread


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


def test_a_bare_vault_folder_hidden_by_its_mount_is_replaced_by_one_made_on_the_disk(job, tmp_path, fake_pool, grace, output):
	# a 0.47 leftover (or mkdir -p before mounting) shows the vault path, while the disk mounted over it has no such folder
	jank = str(tmp_path / 'jank')
	vault = os.path.join(jank, 'reverbs')
	os.makedirs(vault)
	job = job._replace(vault=vault, job_vault=os.path.join(vault, job.job_name))
	write_fstab(jank)
	seed_monitor(job, {'a.txt': 'a'})
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(vault, _not_mounted(jank)) in output(), timeout=5, message='no waiting marker')
		# the mount hides the bare folder; the disk holds no reverbs
		shutil.rmtree(vault)
		fake_pool.add_mount(jank)
		wait_for_committed_count(job, 1, timeout=10)
		assert os.path.isdir(vault)
	finally:
		_stop(control, thread)


def test_the_start_makes_a_missing_vault_path_once_its_fstab_mount_is_mounted(job, tmp_path, fake_pool, grace, output, monkeypatch):
	jank = str(tmp_path / 'jank')
	os.makedirs(jank)
	job = job._replace(vault=os.path.join(jank, 'reverbs'), job_vault=os.path.join(jank, 'reverbs', job.job_name))
	write_fstab(jank)
	seed_monitor(job, {'a.txt': 'a'})
	# the signature passes only on the folder made, and a pair that failed is not checked again for an hour: the
	# backup comes at once only when the monitor learns of the new folder at once
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: os.path.isdir(path))
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 3600)
	control = _control(job)
	thread = _run_backuper(job, control)
	try:
		wait_until(lambda: _marker(job.vault, _not_mounted(jank)) in output(), timeout=5, message='no waiting marker')
		assert not os.path.lexists(job.vault)
		fake_pool.add_mount(jank)
		wait_for_committed_count(job, 1, timeout=10)
	finally:
		_stop(control, thread)


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


def test_a_vault_path_that_cannot_be_made_fails_the_attempt(job, fake_pool, poll_fast):
	blocker = os.path.join(job.root, 'blocker')
	open(blocker, 'w').write('x')
	job = job._replace(vault=os.path.join(blocker, 'vault'), job_vault=os.path.join(blocker, 'vault', job.job_name))
	control = _control(job)
	thread = _run_backuper(job, control)
	thread.join(timeout=5)
	assert not thread.is_alive() and 'does not exist and cannot be created' in control.failure.reason
