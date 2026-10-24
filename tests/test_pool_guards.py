'''
Round 9, Task 3: a disk of the vault pool or the monitored pool that drops (or drops and is mounted again) while a step
runs fails that step before it deletes or commits anything, and a batch's copies stop within POOL_CHECK_SECONDS (0
here), so nothing more is written into the version. The folders are real, so "nothing lands on the root disk" is shown
by nothing being copied, linked or committed after the drop.
'''
import os
import sys
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import (committed_versions, event_entry, latest_version, seed_monitor, wait_for_committed_count,
	wait_until, write_committed_version, write_incomplete_version)

pytestmark = pytest.mark.unit

OPTIONS = dict(keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def backup(job, entries=None, **options):
	'''do_backup() of entries (a whole comparison, or a complete V0, without), its manifest closed: whether it committed.'''
	_, manifest, committed = rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name,
		monitor_path=job.monitor, vault_path=job.vault, **{**OPTIONS, **options})
	manifest.close()
	return committed


def counting_copies(monkeypatch, fake_pool, disk, at=3):
	'''rv.cp_af_copy_path counted, with disk dropped once the at-th copy is queued: the calls, and how many came before the drop.'''
	real = rv.cp_af_copy_path
	calls = []
	dropped = []
	def copying(*args, **kwargs):
		calls.append(args[0] if args else kwargs.get('source_path'))
		result = real(*args, **kwargs)
		if len(calls) == at and not dropped:
			fake_pool.drop(disk)
			dropped.append(len(calls))
		return result
	monkeypatch.setattr(rv, 'cp_af_copy_path', copying)
	return calls, dropped


def version_folder(job, number):
	found = [name for name in os.listdir(job.job_vault) if name.startswith(f'V{number}--') and rv.CONTENT_FILE_EXTENSION_NAME not in name]
	assert len(found) == 1, found
	return os.path.join(job.job_vault, found[0])


def partials(folder):
	return [os.path.join(top, name) for top, _, names in os.walk(folder) for name in names if rv.PARTIAL_COPY_NAME.fullmatch(name)]


def files(count):
	return {f'f{i:02}.txt': f'file {i}' for i in range(count)}


def test_the_scan_removes_nothing_when_a_disk_drops_during_it(job, fake_pool, monkeypatch, capsys):
	# V1 is the oldest committed version, so a list named for a V0 is a stale one the scan would delete
	write_committed_version(job, 1, {'a.txt': 'a'})
	stale = rv.change_list_path(os.path.join(job.job_vault, 'V0--2020-01-01_00-00-00_-0800'), 4096, 1)
	open(stale, 'w').close()
	orphan = write_incomplete_version(job, 2, {'a.txt': 'partial'})
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	real = rv.read_job_vault
	def reading(*args, **kwargs):
		listing = real(*args, **kwargs)
		fake_pool.drop(a)
		return listing
	monkeypatch.setattr(rv, 'read_job_vault', reading)
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.get_vault_info(job.job_vault)
	reason = f'disk {a} of pool {job.vault} is not mounted'
	assert failure.value.reason == reason
	assert os.path.isdir(orphan) and os.path.isfile(stale)
	out = capsys.readouterr()
	assert f'Cannot scan the vault, nothing in it is removed: {reason}' in out.out + out.err


def test_a_disk_mounted_again_during_a_prune_walk_keeps_the_oldest_version(job, fake_pool, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	seed_monitor(job, {'b.txt': 'b'})
	assert backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]))
	v0 = version_folder(job, 0)
	assert os.path.islink(os.path.join(version_folder(job, 1), 'a.txt'))
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real = rv.vault_chain_hop
	hops = []
	def hop(*args, **kwargs):
		if not hops:
			fake_pool.drop(a)
			fake_pool.mount(a)
		hops.append(args[1])
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'vault_chain_hop', hop)
	with pytest.raises(rv.PoolNotReady):
		rv.decrement_stepper(info, 'job', job.monitor)
	assert hops
	# its change list renamed for the copies the walk hard linked into V1, as an aborted removal leaves it
	assert os.path.isdir(v0) and [name for name in os.listdir(job.job_vault)
		if name.startswith(os.path.basename(v0) + '--') and name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]
	assert open(os.path.join(v0, 'a.txt')).read() == 'a'
	assert list(info) == [0, 1]
	out = capsys.readouterr()
	assert (f'reverberator job job FAILED: cannot remove {v0}, as disk {a} of pool {job.vault} was mounted again during '
		'this step') in out.out + out.err


def test_the_commit_is_refused_when_a_disk_drops_after_the_list_is_written(job, fake_pool, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	v0 = version_folder(job, 0)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {'b.txt': 'b'})
	real = rv.prepare_change_list
	def preparing(*args, **kwargs):
		prepared = real(*args, **kwargs)
		fake_pool.drop(a)
		return prepared
	monkeypatch.setattr(rv, 'prepare_change_list', preparing)
	with pytest.raises(rv.PoolNotReady):
		backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]))
	assert committed_versions(job) == [v0]
	assert os.readlink(os.path.join(job.job_vault, 'current_version')) == os.path.basename(v0)
	assert not [name for name in os.listdir(job.job_vault) if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX)]
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.describes(v0)
	finally:
		manifest.close()


def commits_after_the_drop(monkeypatch, fake_pool, disk, function):
	'''rv.<function> wrapped to drop disk once it returns: the manifest commits made after that.'''
	real = getattr(rv, function)
	dropped = []
	def dropping(*args, **kwargs):
		result = real(*args, **kwargs)
		fake_pool.drop(disk)
		dropped.append(True)
		return result
	monkeypatch.setattr(rv, function, dropping)
	commits = []
	real_commit = rv.VaultManifest.commit
	def commit(self, *args, **kwargs):
		if dropped:
			commits.append(args)
		return real_commit(self, *args, **kwargs)
	monkeypatch.setattr(rv.VaultManifest, 'commit', commit)
	return commits


@pytest.mark.parametrize('function', ['compare_scopes', 'delta_generate_backup_entries'])
def test_a_comparison_records_nothing_when_a_disk_drops_during_it(job, fake_pool, monkeypatch, function):
	# what the comparison read of the vault (compare_scopes), or that the tree matches it (no differences), is not kept
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	commits = commits_after_the_drop(monkeypatch, fake_pool, a, function)
	with pytest.raises(rv.PoolNotReady):
		backup(job)
	assert commits == []


def test_copies_stop_while_the_replay_is_still_queuing(job, fake_pool, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	v0 = version_folder(job, 0)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, files(50))
	calls, dropped = counting_copies(monkeypatch, fake_pool, a)
	with pytest.raises(rv.PoolNotReady):
		backup(job, OrderedDict(event_entry(job, name, 'create') for name in files(50)))
	assert dropped and len(calls) - dropped[0] <= 1, f'{len(calls)} copies, the disk dropped at {dropped}'
	assert committed_versions(job) == [v0]
	assert partials(version_folder(job, 1)) == []


def test_copies_stop_inside_a_folder_create(job, fake_pool, monkeypatch):
	# one entry, a folder create, copies every file below it
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	v0 = version_folder(job, 0)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {f'D/{name}': text for name, text in files(50).items()})
	calls, dropped = counting_copies(monkeypatch, fake_pool, a)
	with pytest.raises(rv.PoolNotReady):
		backup(job, OrderedDict([event_entry(job, 'D/', 'create')]))
	assert dropped and len(calls) - dropped[0] <= 1, f'{len(calls)} copies, the disk dropped at {dropped}'
	assert committed_versions(job) == [v0]
	assert partials(version_folder(job, 1)) == []


def test_the_referenced_copy_stops_when_a_vault_disk_drops(job, fake_pool, monkeypatch):
	seed_monitor(job, files(50))
	assert backup(job)
	v0 = version_folder(job, 0)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {'new.txt': 'new'})
	# the ground truth's recorder, so both see the calls
	current = os.symlink
	links = []
	dropped = []
	def linking(*args, **kwargs):
		in_referenced_copy = sys._getframe(1).f_code.co_name == 'do_referenced_copy'
		current(*args, **kwargs)
		if in_referenced_copy:
			links.append(args[1])
			if len(links) == 3:
				fake_pool.drop(a)
				dropped.append(len(links))
	monkeypatch.setattr(os, 'symlink', linking)
	with pytest.raises(rv.PoolNotReady):
		backup(job, OrderedDict([event_entry(job, 'new.txt', 'create')]))
	assert dropped and len(links) - dropped[0] <= 1, f'{len(links)} links, the disk dropped at {dropped}'
	assert committed_versions(job) == [v0]


def test_a_first_backup_stops_its_copies_when_a_vault_disk_drops(job, fake_pool, monkeypatch):
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, files(50))
	calls, dropped = counting_copies(monkeypatch, fake_pool, a)
	with pytest.raises(rv.PoolNotReady):
		backup(job)
	assert dropped and len(calls) - dropped[0] <= 1, f'{len(calls)} copies, the disk dropped at {dropped}'
	assert committed_versions(job) == []
	assert not os.path.lexists(os.path.join(job.job_vault, 'current_version'))


def test_a_monitored_disk_lost_mid_batch_commits_nothing(job, fake_pool, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	v0 = version_folder(job, 0)
	m, _ = fake_pool.add(job.monitor, ['m1', 'm2'])
	seed_monitor(job, files(5))
	calls, dropped = counting_copies(monkeypatch, fake_pool, m, at=1)
	with pytest.raises(rv.PoolNotReady) as failure:
		backup(job, OrderedDict(event_entry(job, name, 'create') for name in files(5)))
	assert failure.value.reason == f'disk {m} of pool {job.monitor} is not mounted'
	assert dropped and len(calls) - dropped[0] <= 1, f'{len(calls)} copies, the disk dropped at {dropped}'
	assert committed_versions(job) == [v0]


def test_a_failed_attempt_waits_then_compares_the_whole_tree(job, fake_pool, monkeypatch, poll_fast, capsys):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {'b.txt': 'b'})
	calls, dropped = counting_copies(monkeypatch, fake_pool, a, at=1)
	to_process = rv.ChangeEventQueue(job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'create', os.path.join(job.monitor, 'b.txt'), None))
	lock, flag = threading.Lock(), threading.Event()
	def start_attempt(control, attempt):
		thread = threading.Thread(target=rv.backuper, args=(job.job_name, to_process, lock, job.monitor, job.vault, 'N/A', flag),
			kwargs=dict(keep_n_versions=0, job=control), name=f'{job.job_name} backuper', daemon=True)
		thread.start()
		return [thread]
	control = rv.JobControl(job.job_name)
	supervisor = threading.Thread(target=lambda: rv.run_job(control, start_attempt), daemon=True)
	supervisor.start()
	text = ''
	def logged(line):
		nonlocal text
		out = capsys.readouterr()
		text += out.out + out.err
		return line in text
	reason = f'disk {a} of pool {job.vault} is not mounted'
	retrying = f'reverberator job job FAILED: {reason}; retrying in 0s'
	waiting = f'reverberator job job FAILED: waiting 0 min for {job.vault}: {reason}'
	try:
		wait_until(lambda: logged(waiting), timeout=10, message='no waiting marker')
		assert logged(retrying) and text.index(retrying) < text.index(waiting)
		assert len(committed_versions(job)) == 1
		fake_pool.mount(a)
		wait_for_committed_count(job, 2)
		assert open(os.path.join(latest_version(job).path, 'b.txt')).read() == 'b'
	finally:
		rv.GREEN_LIGHT.clear()
		supervisor.join(timeout=10)
		rv.GREEN_LIGHT.set()
	assert not supervisor.is_alive()


# --- fix round 1 ---

def two_versions(job):
	'''V0 holding a.txt and D/x.txt, then V1 creating b.txt, its a.txt and D/x.txt links into V0: their folders.'''
	seed_monitor(job, {'a.txt': 'a', 'D/x.txt': 'x'})
	assert backup(job)
	seed_monitor(job, {'b.txt': 'b'})
	assert backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]))
	v0, v1 = version_folder(job, 0), version_folder(job, 1)
	assert os.path.islink(os.path.join(v1, 'a.txt'))
	return v0, v1


def lists_of(job, folder):
	name = os.path.basename(folder)
	return [entry for entry in os.listdir(job.job_vault) if entry.startswith(name + '--') and entry.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]


def prune_finishes(job, v0, v1):
	'''A prune with every disk there removes V0 whole, its copies now V1's.'''
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1]
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, 'job', job.monitor)
	assert not os.path.lexists(v0) and lists_of(job, v0) == []
	assert open(os.path.join(v1, 'a.txt')).read() == 'a' and not os.path.islink(os.path.join(v1, 'a.txt'))
	assert open(os.path.join(v1, 'D/x.txt')).read() == 'x'


def test_a_prune_never_finishes_an_oldest_version_a_missing_disk_hides(job, fake_pool, tmp_path):
	# V0's folder lived on disk a alone: with it out, V0 reads as a removal cut short, though V1's links were never
	# materialised
	v0, v1 = two_versions(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	fake_pool.drop(a)
	hidden = str(tmp_path / 'hidden_v0')
	os.rename(v0, hidden)
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.decrement_stepper(info, 'job', job.monitor)
	assert failure.value.reason == f'disk {a} of pool {job.vault} is not mounted'
	assert lists_of(job, v0) and list(info) == [0, 1]
	os.rename(hidden, v0)
	fake_pool.mount(a)
	prune_finishes(job, v0, v1)


def test_a_disk_dropping_during_the_removal_keeps_the_oldest_versions_lists(job, fake_pool, tmp_path, monkeypatch):
	# the part of V0 on disk a goes out of sight while rm -rf runs, and is back with the disk
	v0, v1 = two_versions(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real = rv.multiCMD.run_command
	hidden = str(tmp_path / 'hidden_part')
	def running(command, *args, **kwargs):
		if command[:2] == ['rm', '-rf']:
			fake_pool.drop(a)
			os.makedirs(hidden)
			os.rename(os.path.join(v0, 'D'), os.path.join(hidden, 'D'))
		return real(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', running)
	with pytest.raises(rv.PoolNotReady):
		rv.decrement_stepper(info, 'job', job.monitor)
	monkeypatch.setattr(rv.multiCMD, 'run_command', real)
	assert lists_of(job, v0) and list(info) == [0, 1]
	os.makedirs(v0)
	os.rename(os.path.join(hidden, 'D'), os.path.join(v0, 'D'))
	fake_pool.mount(a)
	prune_finishes(job, v0, v1)


def test_the_scan_names_the_disk_when_a_drop_hid_a_change_list(job, fake_pool, tmp_path, monkeypatch, capsys):
	two_versions(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	v0_list = lists_of(job, version_folder(job, 0))[0]
	real = rv.read_job_vault
	def reading(*args, **kwargs):
		fake_pool.drop(a)
		os.rename(os.path.join(job.job_vault, v0_list), str(tmp_path / 'hidden_list'))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'read_job_vault', reading)
	reason = f'disk {a} of pool {job.vault} is not mounted'
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.get_vault_info(job.job_vault)
	assert failure.value.reason == reason and isinstance(failure.value.__cause__, rv.VaultScanError)
	out = capsys.readouterr()
	assert f'Cannot scan the vault, nothing in it is removed: {reason}' in out.out + out.err


@pytest.mark.parametrize('first', [True, False], ids=['complete_v0', 'replay'])
def test_copies_stop_while_they_are_waited_for(job, fake_pool, monkeypatch, poll_fast, tmp_path, first):
	# slow copies, one at a time: the drop comes at the first wait for them, with every copy queued
	if not first:
		seed_monitor(job, {'a.txt': 'a'})
		assert backup(job)
	log = str(tmp_path / 'started.log')
	real_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, target: ['sh', '-c', 'echo x >> "$0"; sleep 0.3; exec "$@"', log]
		+ real_command(source, target))
	monkeypatch.setattr(rv, 'BACKUP_SEMAPHORE', threading.Semaphore(1))
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, files(20))
	real_wait = rv.multiCMD.AsyncExecutor.wait
	started_at_drop = []
	def waiting(self, *args, **kwargs):
		if not started_at_drop:
			fake_pool.drop(a)
			started_at_drop.append(len(open(log).read().split()) if os.path.exists(log) else 0)
		return real_wait(self, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD.AsyncExecutor, 'wait', waiting)
	with pytest.raises(rv.PoolNotReady):
		backup(job) if first else backup(job, OrderedDict(event_entry(job, name, 'create') for name in files(20)))
	started = len(open(log).read().split()) if os.path.exists(log) else 0
	assert started_at_drop and started - started_at_drop[0] <= 2, f'{started} of 20 copies started, {started_at_drop} at the drop'
	assert len(committed_versions(job)) == (0 if first else 1)


def test_the_change_list_is_not_placed_when_a_disk_drops_after_the_commit_check(job, fake_pool, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	assert backup(job)
	v0 = version_folder(job, 0)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	seed_monitor(job, {'b.txt': 'b'})
	real = rv.swap_current_version
	def swapping(*args, **kwargs):
		result = real(*args, **kwargs)
		fake_pool.drop(a)
		return result
	monkeypatch.setattr(rv, 'swap_current_version', swapping)
	with pytest.raises(rv.PoolNotReady):
		backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]))
	assert committed_versions(job) == [v0]
	assert lists_of(job, version_folder(job, 1)) == []
	assert os.readlink(os.path.join(job.job_vault, 'current_version')) == os.path.basename(v0)
	assert not [name for name in os.listdir(job.job_vault) if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX)]
