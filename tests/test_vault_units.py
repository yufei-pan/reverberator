'''
The flush round: every vault sync of the daemon goes through handles a unit of its work (a batch, a scan, a conversion) opened
before its first write (VaultUnit), so a write error that another program's sync, a restore's or another job's met first is still
heard; a sync that fails commits nothing and fails the attempt, whose next attempt copies again what the cut batch wrote; the
comparison no longer syncs; and no failed-sync marker is written. The kernel's rule stands in at the syncfs binding
(tests/errseq.py): one model per filesystem, sampled at each open.
'''
import datetime
import errno
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import sys
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import backup_events, put_text
from tests.errseq import open_folders
from tests.harness import committed_versions, create_job, mark_unchecked_by_hand, run_backup, vault_unit, wait_for_committed_count, wait_until, write_fstab, write_rule
from tests.scratch_images import needs_mount, ScratchTmpfs
from tests import version_view_ground_truth as view_truth
from tests.vault_oracle import check_vault, rows_match_vault, snapshot_tree, version_number

pytestmark = pytest.mark.unit

KEPT = {'keep_n_versions': 0}
# past f2fs's inline size and past the 64 KiB tail a comparison reads back: a loss before the tail is what no read-back sees
BIG = 256 * 1024
TAIL = 64 * 1024


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


@pytest.fixture
def r_job(tmp_path):
	return create_job(str(tmp_path))


def disk_of(path):
	'''The disk an alert names for path: the mount point holding it.'''
	held = rv.mount_holding(rv.read_mount_table(), os.path.realpath(path))
	return held[0] if held else path


def markers():
	'''The failed-sync markers 0.55.2 wrote in the state folder: none, from this round on.'''
	state = rv.state_dir_path()
	return sorted(name for name in os.listdir(state) if name.startswith('vault-sync-failed-')) if os.path.isdir(state) else []


def manifest_version(job):
	'''The version the manifest's meta names, read only.'''
	connection = sqlite3.connect(f'file:{os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)}?mode=ro', uri=True)
	try:
		row = connection.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
	finally:
		connection.close()
	return None if row is None else row[0]


def lists_of(job):
	return sorted(name for name in os.listdir(job.job_vault) if '--' in name and not os.path.isdir(os.path.join(job.job_vault, name)))


def at_the_commit_flush(monkeypatch, then):
	'''then() runs once, between a batch's copies and its commit flush (flush_copies()).'''
	real = rv.flush_copies
	ran = []
	def flush(*args, **kwargs):
		if not ran:
			ran.append(True)
			then()
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'flush_copies', flush)
	return ran


def big_text(tag):
	return ''.join(f'{tag}{i:07d}\n' for i in range(BIG // 12))


def base(job):
	'''V0 of a job: a big file, a small one, a file in a folder.'''
	put_text(job.monitor, 'big.txt', big_text('b0'))
	put_text(job.monitor, 'small.txt', 's0')
	put_text(job.monitor, 'd/inner.txt', 'i0')
	run_backup(job, **KEPT)


def modify_big(job):
	put_text(job.monitor, 'big.txt', big_text('b1'))
	return [(False, 'modify', 'big.txt', None)]


def vault_write_errors(out):
	return [line for line in out.splitlines() if 'VAULT WRITE ERROR' in line]


# ---- 1. the commit flush hears an error another program's sync saw first

def test_the_commit_flush_hears_a_write_error_another_sync_saw_first(r_job, errseq, monkeypatch, capsys):
	base(r_job)
	before, lists = committed_versions(r_job), lists_of(r_job)
	ran = at_the_commit_flush(monkeypatch, lambda: (errseq.fail(r_job.job_vault), errseq.seen_elsewhere(r_job.job_vault)))
	capsys.readouterr()
	with pytest.raises(rv.JobFailure) as failed:
		backup_events(r_job, modify_big(r_job), **KEPT)
	out = capsys.readouterr().out
	assert ran
	disk = disk_of(r_job.job_vault)
	alerts = vault_write_errors(out)
	assert len(alerts) == 1 and f'VAULT WRITE ERROR: disk {disk} failed a sync (' in alerts[0]
	assert disk in failed.value.reason and 'no version of this job is' in failed.value.reason
	assert markers() == []
	# nothing commits: the manifest names the version before, no list is placed, and current_version stays
	assert manifest_version(r_job) == os.path.basename(before[-1]) and lists_of(r_job) == lists and committed_versions(r_job) == before
	assert not [name for name in os.listdir(r_job.job_vault) if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX)]
	# and no handle of the unit is left open
	assert open_folders(r_job.job_vault) == []


# ---- 2. the comparison no longer syncs

def test_a_comparison_that_reads_copies_back_makes_no_sync(r_job, errseq):
	base(r_job)
	# copies an older release left unchecked
	mark_unchecked_by_hand(r_job)
	unchecked = rows(r_job)
	assert {rel for rel, record in unchecked.items() if record.kind == 'f' and record.unchecked} == {'big.txt', 'small.txt', 'd/inner.txt'}
	errseq.events.clear()
	# the start's full comparison reads every unchecked copy back, finds nothing, and commits no version
	run_backup(r_job, **KEPT)
	assert {rel for rel, record in rows(r_job).items() if record.kind == 'f' and record.unchecked} == set()
	assert errseq.synced() == []


def test_a_batch_that_placed_a_copy_flushes_even_after_a_read_back_after_its_last_copy(r_job, errseq, monkeypatch):
	for rel in ('a/x.txt', 'a/sub/m.txt', 'a/sub/deep/k.txt'):
		put_text(r_job.monitor, rel, rel)
	run_backup(r_job, **KEPT)
	flushed = []
	real_flush = rv.flush_copies
	def flush(*args, **kwargs):
		flushed.append(len(errseq.synced()))
		return real_flush(*args, **kwargs)
	monkeypatch.setattr(rv, 'flush_copies', flush)
	errseq.events.clear()
	# the moved row carries its record, and the verification compares it after every copy of the batch is in place, with no sync
	os.rename(os.path.join(r_job.monitor, 'a/sub'), os.path.join(r_job.monitor, 'e'))
	put_text(r_job.monitor, 'e/m.txt', 'new')
	backup_events(r_job, [(True, 'move', 'e', 'a/sub'), (False, 'modify', 'e/m.txt', None)], **KEPT)
	# the commit flush ran, with no sync before it, and made the one sync of the batch
	assert flushed == [0] and [code for _, code in errseq.synced()] == [0]


def rows(job):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return {rel: manifest.lookup(rel) for rel in list(manifest.files) + list(manifest.folders)}
	finally:
		manifest.close()


# ---- 3. whoever saw the error first, the unit hears it itself

def test_a_write_error_a_restores_sync_saw_first_is_heard_by_the_batch(r_job, errseq, monkeypatch, capsys, tmp_path):
	base(r_job)
	before = committed_versions(r_job)
	folder = str(tmp_path / 'restored')
	os.makedirs(folder)
	assert os.stat(folder).st_dev == os.stat(r_job.job_vault).st_dev
	restored = []
	def restore_syncs_first():
		errseq.fail(r_job.job_vault)
		# a restore on the vault's disk, its handles opened at its claim: its own sync takes the error first
		fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
		try:
			report = rv.RestoreReport()
			disks = rv.open_restore_disks(folder, fd, report, 'x')
			restored.append(rv.sync_restore(disks, folder, report, 'x'))
			rv.close_restore_disks(disks, fd)
		finally:
			os.close(fd)
	at_the_commit_flush(monkeypatch, restore_syncs_first)
	capsys.readouterr()
	with pytest.raises(rv.JobFailure):
		backup_events(r_job, modify_big(r_job), **KEPT)
	out = capsys.readouterr().out
	# the restore failed on it, and the batch heard it too: one alert, the batch's, and nothing committed
	assert restored == [False]
	assert len(vault_write_errors(out)) == 1 and f'reverberator job {r_job.job_name} VAULT WRITE ERROR' in out
	assert committed_versions(r_job) == before and markers() == []
	assert 'for the daemon' not in out


def test_a_write_error_another_jobs_batch_saw_first_is_heard_by_each(r_job, errseq, monkeypatch, capsys, tmp_path):
	base(r_job)
	other = create_job(str(tmp_path / 'other'), 'other')
	base(other)
	assert os.stat(other.job_vault).st_dev == os.stat(r_job.job_vault).st_dev
	before, other_before = committed_versions(r_job), committed_versions(other)
	failures = []
	def other_job_first():
		errseq.fail(r_job.job_vault)
		# another job's batch on the same disk, in the same process, on a thread of its own as each job's backuper runs
		def batch():
			try:
				backup_events(other, modify_big(other), **KEPT)
			except rv.JobFailure as e:
				failures.append(e)
		thread = threading.Thread(target=batch)
		thread.start()
		thread.join()
	at_the_commit_flush(monkeypatch, other_job_first)
	capsys.readouterr()
	with pytest.raises(rv.JobFailure):
		backup_events(r_job, modify_big(r_job), **KEPT)
	out = capsys.readouterr().out
	# each unit that heard it alerts once, and neither commits
	alerts = vault_write_errors(out)
	assert len(failures) == 1 and len(alerts) == 2
	assert sum(f'reverberator job {r_job.job_name} VAULT WRITE ERROR' in line for line in alerts) == 1
	assert sum('reverberator job other VAULT WRITE ERROR' in line for line in alerts) == 1
	assert committed_versions(r_job) == before and committed_versions(other) == other_before and markers() == []


# ---- 4. every sync site hears it

class FirstSync(list):
	'''
	Once armed, the next vault sync meets a write error on its job vault's disk that another program's sync saw first, after the
	step's unit opened and wrote: the list of the job vaults it was met on.
	'''
	armed = False

	def arm(self):
		self.armed = True


@pytest.fixture
def heard_at_the_first_sync(errseq, monkeypatch):
	real = rv.sync_vault_filesystems
	met = FirstSync()
	def sync(job_vault, job_name):
		if met.armed and not met:
			met.append(job_vault)
			errseq.fail(job_vault)
			errseq.seen_elsewhere(job_vault)
		return real(job_vault, job_name)
	monkeypatch.setattr(rv, 'sync_vault_filesystems', sync)
	return met


def no_exchange(monkeypatch):
	'''A vault filesystem with no RENAME_EXCHANGE.'''
	def refused(a, b):
		raise OSError(errno.EINVAL, os.strerror(errno.EINVAL), a, None, b)
	monkeypatch.setattr(rv, 'rename_exchange', refused)


def test_the_hand_over_on_a_vault_with_no_exchange_hears_it(r_job, heard_at_the_first_sync, monkeypatch, capsys):
	base(r_job)
	before = committed_versions(r_job)
	no_exchange(monkeypatch)
	heard_at_the_first_sync.arm()
	with pytest.raises(rv.JobFailure) as failed:
		backup_events(r_job, modify_big(r_job), **KEPT)
	# the hand-over's first flush, before its first rename
	assert heard_at_the_first_sync == [r_job.job_vault]
	assert 'failed a sync' in failed.value.reason and 'stops here; the next attempt goes on with it' in failed.value.reason
	assert len(vault_write_errors(capsys.readouterr().out)) == 1
	assert committed_versions(r_job) == before


def test_the_scans_repair_of_a_cut_between_two_renames_hears_it(r_job, errseq, monkeypatch, capsys):
	base(r_job)
	no_exchange(monkeypatch)
	# a hand-over cut between its two renames: its second flush fails, with the tree under the new name and the skeleton in staging
	flushes = []
	def second_fails(job_vault, job_name):
		flushes.append(job_vault)
		return {'/dev/fake': OSError(errno.EIO, 'input/output error')} if len(flushes) == 2 else {}
	with monkeypatch.context() as cut:
		cut.setattr(rv, 'sync_vault_filesystems', second_fails)
		with pytest.raises(rv.JobFailure):
			backup_events(r_job, modify_big(r_job), **KEPT)
	assert len(flushes) == 2
	assert [name for name in os.listdir(rv.staging_path(r_job.job_vault)) if name.startswith(rv.SKELETON_PREFIX)]
	real = rv.sync_vault_filesystems
	met = []
	def sync(job_vault, job_name):
		met.append(job_vault)
		errseq.fail(job_vault)
		errseq.seen_elsewhere(job_vault)
		return real(job_vault, job_name)
	monkeypatch.setattr(rv, 'sync_vault_filesystems', sync)
	capsys.readouterr()
	with pytest.raises(rv.JobFailure) as failed:
		rv.get_vault_info(r_job.job_vault)
	assert met == [r_job.job_vault] and 'the scan of' in failed.value.reason and 'stops here' in failed.value.reason
	assert len(vault_write_errors(capsys.readouterr().out)) == 1


@pytest.mark.parametrize('exchange', [False, True], ids=['materialize_with_no_exchange', 'per_version_flush'])
def test_the_conversion_hears_it(tmp_path, v054, heard_at_the_first_sync, monkeypatch, capsys, exchange):
	from tests.test_migration import SMALL
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_n_versions=9)
	if not exchange:
		no_exchange(monkeypatch)
	info = rv.get_vault_info(job.job_vault)
	capsys.readouterr()
	heard_at_the_first_sync.arm()
	with pytest.raises(rv.JobFailure) as failed:
		rv.convert_at_start(job.job_vault, info, job.job_name, job.monitor, lambda: True)
	assert heard_at_the_first_sync == [job.job_vault]
	if exchange:
		# the version's flush before the manifest says it is done
		assert f'the conversion of {job.job_vault} stops' in failed.value.reason
	else:
		# the first of the four flushes around the two renames
		assert 'the conversion of V2--' in failed.value.reason and 'stops here' in failed.value.reason
	assert len(vault_write_errors(capsys.readouterr().out)) == 1
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.layout() != 'r' and manifest.migrated() == set()
	finally:
		manifest.close()


def pool_vault(job, fake_pool):
	'''The vault of job on a fake pool of branches a and b, each holding the job vault: the branches.'''
	branches = fake_pool.add(job.vault, ['a', 'b'])
	for branch in branches:
		os.makedirs(os.path.join(branch, job.job_name), exist_ok=True)
	return branches


def test_a_prunes_flush_on_a_pool_hears_it(r_job, fake_pool, heard_at_the_first_sync, capsys):
	base(r_job)
	put_text(r_job.monitor, 'small.txt', 's1')
	run_backup(r_job, **KEPT)
	pool_vault(r_job, fake_pool)
	before = committed_versions(r_job)
	capsys.readouterr()
	heard_at_the_first_sync.arm()
	with pytest.raises(rv.JobFailure) as failed:
		backup_events(r_job, modify_big(r_job), keep_n_versions=2)
	# the prune is the batch's first step that syncs: its rename into staging is not on every disk
	assert heard_at_the_first_sync == [r_job.job_vault]
	assert f'{before[0]} is not removed yet; the next scan does it' in failed.value.reason
	assert len(vault_write_errors(capsys.readouterr().out)) == 1
	assert committed_versions(r_job) == before[1:]


def test_the_scans_removal_of_a_stale_list_on_a_pool_hears_it_and_keeps_the_list(r_job, fake_pool, heard_at_the_first_sync, capsys):
	base(r_job)
	put_text(r_job.monitor, 'small.txt', 's1')
	run_backup(r_job, **KEPT)
	pool_vault(r_job, fake_pool)
	oldest = committed_versions(r_job)[0]
	stale = [name for name in lists_of(r_job) if name.startswith(os.path.basename(oldest) + '--')]
	# a prune cut after its folder went, before its list did
	shutil.rmtree(oldest)
	capsys.readouterr()
	heard_at_the_first_sync.arm()
	with pytest.raises(rv.JobFailure) as failed:
		rv.get_vault_info(r_job.job_vault)
	assert heard_at_the_first_sync == [r_job.job_vault]
	assert 'whose folders are gone, stay for now' in failed.value.reason
	assert len(vault_write_errors(capsys.readouterr().out)) == 1
	assert all(os.path.lexists(os.path.join(r_job.job_vault, name)) for name in stale) and stale


def test_a_054_prunes_flush_on_a_pool_hears_it(tmp_path, v054, fake_pool, heard_at_the_first_sync, capsys):
	from tests.test_migration import SMALL
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_n_versions=9)
	pool_vault(job, fake_pool)
	versions = committed_versions(job)
	# a pool's prune of V0 cut before its flush
	rv.write_prune_marker(job.job_vault, os.path.basename(versions[0]))
	info = rv.get_vault_info(job.job_vault)
	capsys.readouterr()
	heard_at_the_first_sync.arm()
	with pytest.raises(rv.JobFailure) as failed:
		rv.convert_at_start(job.job_vault, info, job.job_name, job.monitor, lambda: True)
	assert heard_at_the_first_sync == [job.job_vault]
	assert 'cut off before its flush has not finished' in failed.value.reason
	out = capsys.readouterr().out
	assert len(vault_write_errors(out)) == 1
	assert os.path.isdir(versions[0])


# ---- 5. a disk that joins a pool

def test_a_disk_that_joins_the_pool_holding_the_job_vault_fails_the_sync(r_job, fake_pool, errseq, monkeypatch, capsys, other_filesystem, tmp_path):
	pool_vault(r_job, fake_pool)
	base(r_job)
	pool = os.path.realpath(r_job.vault)
	joined = []
	def a_disk_joins():
		# a disk of another filesystem, holding the job vault
		branch = fake_pool.join(r_job.vault, os.path.join(other_filesystem, 'e'), 'e')
		os.makedirs(os.path.join(branch, r_job.job_name))
		joined.append((branch, len(errseq.events)))
	ran = at_the_commit_flush(monkeypatch, a_disk_joins)
	capsys.readouterr()
	with pytest.raises(rv.JobFailure) as failed:
		backup_events(r_job, modify_big(r_job), **KEPT)
	assert ran
	# the sync itself refuses it, naming it, and alerts nothing: it is no write error
	branch, at = joined[0]
	assert f'{os.path.join(branch, r_job.job_name)} is not on a filesystem this step opened' in failed.value.reason
	assert vault_write_errors(capsys.readouterr().out) == []
	assert [event for event in errseq.events[at:] if event[0] == 'syncfs'] == []
	# it leaves the pool. at the next attempt, which rolls the cut batch's tree forward, a disk of another filesystem joins
	# without the job vault, and a folder of the first disks' filesystem joins holding it
	fake_pool.pools[pool].remove(branch)
	fake_pool.write()
	marks = []
	def two_join():
		fake_pool.join(r_job.vault, os.path.join(other_filesystem, 'f'), 'f')
		other = fake_pool.join(r_job.vault, str(tmp_path / 'disks' / 'g'), 'g')
		os.makedirs(os.path.join(other, r_job.job_name))
		marks.append(len(errseq.events))
	at_the_commit_flush(monkeypatch, two_join)
	errseq.events.clear()
	with pytest.raises(rv.PoolNotReady):
		backup_events(r_job, [], **KEPT)
	# the flush synced the one filesystem holding the job vault once, through a handle the unit opened at the job vault's folder
	# on a branch before the batch wrote, and passed the disk without it over; then the pool's guard fails the batch, as disks
	# joined
	synced = [event for event in errseq.events[marks[0]:] if event[0] == 'syncfs']
	assert len(synced) == 1 and synced[0][4] == 0
	places = {os.path.join(os.path.realpath(path), r_job.job_name) for path in fake_pool.pools[pool][:2]}
	assert [path for kind, path, fd in (event for event in errseq.events[:marks[0]] if event[0] == 'open') if fd == synced[0][1] and path in places]


# ---- F2: a pool vault's handles open where the job vault is, so a job vault on a filesystem of its own on a branch (a mount
# nested under the branch, a btrfs subvolume) is synced through a handle of that filesystem. A symlink to a folder on /dev/shm
# stands in for the nested mount, as os.open() and os.stat() follow it to another st_dev

def synced_through(events):
	'''The real path each syncfs of events went through, as its fd was opened, in order.'''
	opened, paths = {}, []
	for event in events:
		if event[0] == 'open':
			opened[event[2]] = os.path.join(os.path.realpath(os.path.dirname(event[1])), os.path.basename(event[1]))
		elif event[0] == 'syncfs':
			paths.append(opened.get(event[1]))
	return paths


def own_filesystem_on_a_branch(job, fake_pool, other_filesystem):
	'''
	The vault of job on a fake pool of branches a and b, each holding the job vault, its folder on a a filesystem of its own:
	that folder.
	'''
	branches = fake_pool.add(job.vault, ['a', 'b'])
	own = fake_pool.add_mount(os.path.join(other_filesystem, 'own'))
	os.symlink(own, os.path.join(branches[0], job.job_name))
	os.makedirs(os.path.join(branches[1], job.job_name))
	return own


def test_a_job_vault_on_a_filesystem_of_its_own_on_a_branch_commits(r_job, fake_pool, errseq, other_filesystem):
	# fails on main: every sync raises "is not on a filesystem this step opened", as the handle is the branch root's
	own = own_filesystem_on_a_branch(r_job, fake_pool, other_filesystem)
	base(r_job)
	before = committed_versions(r_job)
	errseq.events.clear()
	backup_events(r_job, modify_big(r_job), **KEPT)
	assert len(committed_versions(r_job)) == len(before) + 1
	# the commit flush synced both filesystems once each, the one of its own through the handle the unit opened at the job
	# vault's folder on a
	synced = [event for event in errseq.events if event[0] == 'syncfs']
	assert {event[3] for event in synced} == {os.stat(own).st_dev, os.stat(r_job.monitor).st_dev}
	assert all(event[4] == 0 for event in synced)
	assert os.path.join(fake_pool.branch_path('a'), r_job.job_name) in synced_through(errseq.events)
	assert open_folders(own) == []


def test_a_write_error_on_a_branchs_own_filesystem_fails_the_batch(r_job, fake_pool, errseq, monkeypatch, capsys, other_filesystem):
	# fails on main: its sync raises "is not on a filesystem this step opened" (no write error is heard, no alert)
	own = own_filesystem_on_a_branch(r_job, fake_pool, other_filesystem)
	base(r_job)
	before = committed_versions(r_job)
	ran = at_the_commit_flush(monkeypatch, lambda: (errseq.fail(own), errseq.seen_elsewhere(own)))
	capsys.readouterr()
	with pytest.raises(rv.JobFailure) as failed:
		backup_events(r_job, modify_big(r_job), **KEPT)
	assert ran
	# heard through the handle of that filesystem, opened before the batch wrote: one alert, naming the disk that failed (the
	# nested mount, not the healthy disk of the branch holding it; fails at 15b3108), and nothing commits
	lines = vault_write_errors(capsys.readouterr().out)
	assert len(lines) == 1 and f'disk {own} failed a sync' in lines[0], lines
	assert 'is not on a filesystem this step opened' not in failed.value.reason
	assert committed_versions(r_job) == before


def unmount_nested_disk(fake_pool, own, place):
	'''The disk of its own at place leaves the mount table, and the branch's folder at its place is the bare mount point.'''
	os.remove(place)
	os.mkdir(place)
	fake_pool.drop(own)


def mount_nested_disk(fake_pool, own, place):
	os.rmdir(place)
	os.symlink(own, place)
	fake_pool.mount(own)


def test_a_batch_on_a_nested_vault_disk_fstab_names_that_is_not_mounted_fails_with_the_disk_named(r_job, fake_pool, errseq, other_filesystem):
	# pin: the guard of a scan and a batch, for a disk that drops while a batch runs; it held before the waits below. What a batch
	# writes into the bare mount point is hidden when the disk is mounted again, so the guard fails it whatever the waits did
	own = own_filesystem_on_a_branch(r_job, fake_pool, other_filesystem)
	place = os.path.join(fake_pool.branch_path('a'), r_job.job_name)
	write_fstab(place)
	base(r_job)
	pool = os.path.realpath(r_job.vault)
	# mounted: nothing is missing
	assert rv.vault_disk_problem(r_job.job_vault) is None
	before = committed_versions(r_job)
	unmount_nested_disk(fake_pool, own, place)
	assert rv.vault_disk_problem(r_job.job_vault) == f'disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'
	with pytest.raises(rv.PoolNotReady) as failed:
		backup_events(r_job, modify_big(r_job), **KEPT)
	assert failed.value.args[0] == f'disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'
	assert committed_versions(r_job) == before
	# it is mounted again: the job goes on
	mount_nested_disk(fake_pool, own, place)
	assert rv.vault_disk_problem(r_job.job_vault) is None
	backup_events(r_job, modify_big(r_job), **KEPT)
	assert len(committed_versions(r_job)) == len(before) + 1


def start_attempt(job, flag):
	'''A backuper as a start runs it, its watches in place, on a fresh queue and its own JobControl: (control, thread, queue, lock).'''
	queue, lock = rv.ChangeEventQueue(job.monitor), threading.Lock()
	ready = threading.Event()
	ready.set()
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	startup = rv.JobStartup(job.job_name, job.monitor)
	startup.watching.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, lock, job.monitor, job.vault, 'N/A', flag, ready),
		kwargs=dict(startup=startup, job=control, keep_n_versions=0), daemon=True)
	thread.start()
	return control, thread, queue, lock


def printed(capsys):
	out = capsys.readouterr()
	return out.out + out.err


def waits_for_the_job_vault(control, job, reason):
	'''Whether the job's one wait now is for its job vault, with reason.'''
	return [wait[1:3] for wait in control._waits] == [[job.job_vault, reason]]


def test_an_attempt_waits_for_a_nested_vault_disk_fstab_names_that_is_not_mounted(r_job, fake_pool, errseq, other_filesystem, capsys):
	# fails at 5bfa874: the waits ask about the rule's Vault Path, whose place on each branch lies above the disk's mount point, so
	# none holds the job: the start's scan raises PoolNotReady, the attempt fails, and run_job() retries after its delay (60 s,
	# doubling to an hour) with a FAILED alert each time, the job down for what is left of the delay once the disk is back
	own = own_filesystem_on_a_branch(r_job, fake_pool, other_filesystem)
	place = os.path.join(fake_pool.branch_path('a'), r_job.job_name)
	write_fstab(place)
	base(r_job)
	pool = os.path.realpath(r_job.vault)
	before = committed_versions(r_job)
	# a change the start's full comparison backs up once the disk is back
	modify_big(r_job)
	unmount_nested_disk(fake_pool, own, place)
	capsys.readouterr()
	control, thread, queue, lock = start_attempt(r_job, threading.Event())
	reason = f'disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'
	try:
		# the job waits for the job vault, with the disk's reason, and stays in the wait: it does not fail, log a FAILED line or commit
		wait_until(lambda: waits_for_the_job_vault(control, r_job, reason) or control.failure is not None, timeout=10,
			message='the attempt never waited for the job vault')
		assert control.failure is None, f'the attempt failed instead of waiting: {control.failure.reason}'
		time.sleep(0.5)
		assert thread.is_alive() and control.failure is None and waits_for_the_job_vault(control, r_job, reason)
		text = printed(capsys)
		assert 'FAILED' not in text and 'Job failed' not in text and 'Cannot scan the vault' not in text
		assert committed_versions(r_job) == before
		# it is mounted again: the wait ends and the start backs up the change
		mount_nested_disk(fake_pool, own, place)
		wait_for_committed_count(r_job, len(before) + 1)
		assert control.failure is None and control._waits == []
		text = printed(capsys)
		assert 'FAILED' not in text and 'Job failed' not in text
	finally:
		control.fail('stop')
		thread.join(timeout=10)
	assert not thread.is_alive()


def test_a_batch_waits_for_a_nested_vault_disk_fstab_names_that_goes_out_while_the_job_idles(r_job, fake_pool, errseq, other_filesystem, capsys):
	# fails at 5bfa874: the batch's waits, which share one read of the mount table, ask about the Vault Path alone, so the batch
	# begins, and its guard, which sees the disk, fails the attempt with PoolNotReady instead of the batch waiting
	own = own_filesystem_on_a_branch(r_job, fake_pool, other_filesystem)
	place = os.path.join(fake_pool.branch_path('a'), r_job.job_name)
	write_fstab(place)
	base(r_job)
	pool = os.path.realpath(r_job.vault)
	modify_big(r_job)
	flag = threading.Event()
	control, thread, queue, lock = start_attempt(r_job, flag)
	reason = f'disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'
	try:
		# the start's full comparison backs up the change; the job idles
		wait_until(control.committed.is_set, timeout=10, message='the start never committed')
		before = committed_versions(r_job)
		assert len(before) == 2
		# the disk goes out, then a change comes
		unmount_nested_disk(fake_pool, own, place)
		capsys.readouterr()
		put_text(r_job.monitor, 'small.txt', 's1')
		with lock:
			queue.append(rv.ChangeEvent(time.monotonic(), False, 'modify', os.path.join(r_job.monitor, 'small.txt'), None))
		flag.set()
		wait_until(lambda: waits_for_the_job_vault(control, r_job, reason) or control.failure is not None, timeout=10,
			message='the batch never waited for the job vault')
		assert control.failure is None, f'the batch failed instead of waiting: {control.failure.reason}'
		time.sleep(0.5)
		assert thread.is_alive() and control.failure is None and waits_for_the_job_vault(control, r_job, reason)
		text = printed(capsys)
		assert 'FAILED' not in text and 'Job failed' not in text
		assert committed_versions(r_job) == before
		# it is mounted again: the batch goes on
		mount_nested_disk(fake_pool, own, place)
		wait_for_committed_count(r_job, 3)
		assert control.failure is None and control._waits == []
	finally:
		control.fail('stop')
		thread.join(timeout=10)
	assert not thread.is_alive()


def test_a_nested_disk_fstab_names_says_so_beside_a_branch_that_is_out(r_job, fake_pool):
	# the nested disk's text carries "(/etc/fstab names it)", as the reason of a disk off a pool does; a branch that is out has none
	a, b = fake_pool.add(r_job.vault, ['a', 'b'])
	place = os.path.join(b, r_job.job_name)
	os.makedirs(place)
	write_fstab(place)
	pool = os.path.realpath(r_job.vault)
	assert rv.vault_disk_problem(r_job.job_vault) == f'disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'
	fake_pool.drop(a)
	assert rv.vault_disk_problem(r_job.job_vault) == f'disk {a} of pool {pool} is not mounted; disk {place} of pool {pool} is not mounted ({rv.FSTAB_PATH} names it)'


def test_a_job_vault_made_later_under_a_nested_mount_is_synced_through_its_parents_handle(tmp_path, fake_pool, errseq, monkeypatch, other_filesystem):
	# fails on main: its handle is the branch root's, on another filesystem, so the sync raises "is not on a filesystem this step
	# opened"
	root = str(tmp_path / 'r')
	job = create_job(root)
	# the vault a folder of a pool; on branch a the folder above the job vault, mnt, is a filesystem of its own, without the job
	# vault when the unit opens; on b the job vault is there
	branches = fake_pool.add(str(tmp_path / 'pool'), ['a', 'b'])
	vault = str(tmp_path / 'pool' / 'mnt')
	job = job._replace(vault=vault, job_vault=os.path.join(vault, job.job_name))
	os.makedirs(job.vault)
	nested = os.path.join(other_filesystem, 'mnt')
	os.makedirs(nested)
	os.symlink(nested, os.path.join(branches[0], 'mnt'))
	os.makedirs(os.path.join(branches[1], 'mnt', job.job_name))
	base(job)
	before = committed_versions(job)
	# a copy lands on a, where the job vault was not yet: its folder is made on the nested filesystem
	ran = at_the_commit_flush(monkeypatch, lambda: os.makedirs(os.path.join(nested, job.job_name)))
	errseq.events.clear()
	backup_events(job, modify_big(job), **KEPT)
	assert ran and len(committed_versions(job)) == len(before) + 1
	# synced through the handle opened at a/mnt, no error
	assert all(event[4] == 0 for event in errseq.events if event[0] == 'syncfs')
	assert os.path.join(branches[0], 'mnt') in synced_through(errseq.events)


def test_the_nearest_existing_folder_stops_at_the_branch(tmp_path):
	branch = str(tmp_path / 'branch')
	os.makedirs(os.path.join(branch, 'x'))
	put_text(branch, 'x/file', 'f')
	# nothing of rel there: the branch itself
	assert rv.nearest_existing_folder(branch, 'vault/job') == branch
	# a file at rel's place: its parent
	assert rv.nearest_existing_folder(branch, 'x/file') == os.path.join(branch, 'x')
	assert rv.nearest_existing_folder(branch, 'x/file/below') == os.path.join(branch, 'x')
	# the folder itself when it is there
	assert rv.nearest_existing_folder(branch, 'x') == os.path.join(branch, 'x')
	# never above the branch, even when the branch itself is not there
	gone = str(tmp_path / 'gone')
	assert rv.nearest_existing_folder(gone, 'vault/job') == gone


# ---- 5, in the VM: a disk swapped at its mount point, off a pool and on one (root, to mount a tmpfs)

def swapped_sync_fails(job, disk, folder, capsys):
	'''A unit opened, a sync through it, the disk at folder swapped and the job vault made again there: the next sync raises, naming it.'''
	with vault_unit(job.job_vault):
		assert rv.sync_vault_filesystems(job.job_vault, job.job_name) == {}
		capsys.readouterr()
		disk.swap()
		os.makedirs(folder)
		with pytest.raises(OSError) as failed:
			rv.sync_vault_filesystems(job.job_vault, job.job_name)
	assert f'{folder} is not on a filesystem this step opened' in str(failed.value)
	# no write error, so no alert
	assert vault_write_errors(capsys.readouterr().out) == []


@needs_mount
def test_a_disk_swapped_at_the_vaults_mount_point_fails_the_sync(tmp_path, errseq, capsys):
	with ScratchTmpfs(str(tmp_path / 'disk')) as disk:
		job = create_job(disk.folder)
		os.makedirs(job.job_vault)
		swapped_sync_fails(job, disk, job.job_vault, capsys)


@needs_mount
def test_a_disk_swapped_at_a_branchs_mount_point_fails_the_sync(r_job, fake_pool, errseq, capsys):
	branches = fake_pool.add(r_job.vault, ['a', 'b'])
	with ScratchTmpfs(branches[0]) as disk:
		for branch in branches:
			os.makedirs(os.path.join(branch, r_job.job_name), exist_ok=True)
		swapped_sync_fails(r_job, disk, os.path.join(branches[0], r_job.job_name), capsys)


# ---- 6. a one-file batch off a pool

def test_a_one_file_batch_opens_one_handle_before_its_copy_and_syncs_once(r_job, errseq, monkeypatch):
	base(r_job)
	stacks = []
	real_table = rv.read_mount_table
	def table(*args, **kwargs):
		frame, names = sys._getframe(1), []
		while frame is not None:
			names.append(frame.f_code.co_qualname)
			frame = frame.f_back
		stacks.append(names)
		return real_table(*args, **kwargs)
	monkeypatch.setattr(rv, 'read_mount_table', table)
	real_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: errseq.events.append(('copy', source)) or real_command(source, dest))
	errseq.events.clear()
	backup_events(r_job, modify_big(r_job), **KEPT)
	events = errseq.events
	synced = [event for event in events if event[0] == 'syncfs']
	assert len(synced) == 1 and synced[0][4] == 0
	handle = synced[0][1]
	opened = [index for index, event in enumerate(events) if event[0] == 'open' and event[2] == handle and os.path.realpath(event[1]) == os.path.realpath(r_job.job_vault)]
	first_copy = next(index for index, event in enumerate(events) if event[0] == 'copy')
	sync_at = events.index(synced[0])
	# the handle was opened before the first copy and not closed until the sync was done
	assert opened and opened[-1] < first_copy
	assert ('close', handle) not in events[opened[-1]:sync_at]
	assert ('close', handle) in events[sync_at:]
	# no mount table read for the unit or its sync
	assert stacks and not [stack for stack in stacks if any(name.startswith(('VaultUnit.', 'sync_vault_filesystems', 'flush_vault_disks')) for name in stack)]
	assert open_folders(r_job.job_vault) == []
	# and closed when the batch raises
	def cut(*args, **kwargs):
		raise rv.JobFailure('cut')
	monkeypatch.setattr(rv, 'prepare_change_list', cut)
	put_text(r_job.monitor, 'small.txt', 's2')
	with pytest.raises(rv.JobFailure):
		backup_events(r_job, [(False, 'modify', 'small.txt', None)], **KEPT)
	assert open_folders(r_job.job_vault) == []


# ---- 7, 8, 10. the roll-forward copies again what the cut batch wrote

class Cut(BaseException):
	'''A kill at this point of a batch: nothing after it runs.'''


def cut_before_the_commit(job, events, monkeypatch, **options):
	'''
	A batch of events cut once its copies are placed and its replay done, as its change list is about to be written, before its
	commit point: what its tree holds stays for the roll-forward. (A kill before the commit flush, or a failed one, leaves the
	same tree; 0.55.2 skips that flush where a comparison synced after the last copy, and reaches this point either way.)
	'''
	def cut(*args, **kwargs):
		raise Cut()
	with monkeypatch.context() as patched:
		patched.setattr(rv, 'prepare_change_list', cut)
		with pytest.raises(Cut):
			backup_events(job, events, **KEPT, **options)


def tree_of(job):
	'''The folder of the cut batch's tree: the version folder with no list, past the newest.'''
	names = [name for name in os.listdir(job.job_vault) if version_number(name) is not None and os.path.isdir(os.path.join(job.job_vault, name))]
	newest = max(names, key=version_number)
	assert os.path.join(job.job_vault, newest) not in committed_versions(job)
	return os.path.join(job.job_vault, newest)


def overwrite_middle(path):
	'''Its middle overwritten, keeping its size, mtime and last 64 KiB: what a lost write shows no read-back of the tail.'''
	st = os.lstat(path)
	assert st.st_size > 2 * TAIL
	with open(path, 'r+b') as f:
		f.seek(TAIL // 2)
		f.write(b'X' * (st.st_size - TAIL - TAIL // 2))
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def all_nul(path):
	'''All NUL at its size and mtime: what a checkpoint that kept a new file's size and not its data leaves.'''
	st = os.lstat(path)
	with open(path, 'r+b') as f:
		f.write(bytes(st.st_size))
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def recording_reads_and_copies(monkeypatch):
	'''
	(the rels read back from the vault to be recorded checked, the sources copied), from now on. The record a commit makes of its
	own new copy reads it too (record_dirty_entries()), and is no read-back.
	'''
	reads, copies = [], []
	real_read, real_command = rv.read_vault_record, rv.copy_command
	def read(version_path, rel, known=None):
		if not sys._getframe(1).f_code.co_qualname.startswith('record_dirty_entries.'):
			reads.append(rel)
		return real_read(version_path, rel, known)
	monkeypatch.setattr(rv, 'read_vault_record', read)
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: copies.append(source) or real_command(source, dest))
	return reads, copies


def roll_forward(job, **options):
	'''The next attempt: the scan finds the cut batch's tree, and its first batch, the start's full comparison, rolls it forward.'''
	_, manifest, committed = rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, matched_since=time.time_ns(),
		only_sync_attributes=options.get('only_sync_attributes', False), keep_n_versions=0, backup_size_limit='0')
	manifest.close()
	assert committed is True


def read_bytes(path):
	with open(path, 'rb') as f:
		return f.read()


def test_the_roll_forward_copies_again_what_the_cut_batch_wrote_over(r_job, monkeypatch):
	base(r_job)
	cut_before_the_commit(r_job, modify_big(r_job), monkeypatch)
	tree = tree_of(r_job)
	overwrite_middle(os.path.join(tree, 'big.txt'))
	reads, copies = recording_reads_and_copies(monkeypatch)
	roll_forward(r_job)
	assert 'big.txt' not in reads
	assert os.path.join(r_job.monitor, 'big.txt') in copies
	assert read_bytes(os.path.join(committed_versions(r_job)[-1], 'big.txt')) == read_bytes(os.path.join(r_job.monitor, 'big.txt'))


def test_the_roll_forward_copies_again_a_file_an_attribute_change_copied(r_job, monkeypatch):
	# Only Sync Attributes off: a chmod copies the file, which the cut batch records before its copy
	data = b''.join(f'z{i:07d}\n'.encode() for i in range(8192)) + bytes(128 * 1024)
	path = os.path.join(r_job.monitor, 'zeros.bin')
	with open(path, 'wb') as f:
		f.write(data)
	put_text(r_job.monitor, 'small.txt', 's0')
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	os.chmod(path, 0o600)
	cut_before_the_commit(r_job, [(False, 'attrib', 'zeros.bin', None)], monkeypatch, only_sync_attributes=False)
	tree = tree_of(r_job)
	all_nul(os.path.join(tree, 'zeros.bin'))
	reads, copies = recording_reads_and_copies(monkeypatch)
	roll_forward(r_job, only_sync_attributes=False)
	assert 'zeros.bin' not in reads and path in copies
	assert read_bytes(os.path.join(committed_versions(r_job)[-1], 'zeros.bin')) == data


def test_the_roll_forward_over_a_rebuilt_manifest_copies_again_what_the_cut_batch_made(r_job, monkeypatch):
	base(r_job)
	put_text(r_job.monitor, 'new.txt', big_text('n1'))
	os.rename(os.path.join(r_job.monitor, 'small.txt'), os.path.join(r_job.monitor, 'moved.txt'))
	cut_before_the_commit(r_job, [(False, 'create', 'new.txt', None), (False, 'move', 'moved.txt', 'small.txt')], monkeypatch)
	tree = tree_of(r_job)
	assert os.path.isfile(os.path.join(tree, 'moved.txt')) and not os.path.lexists(os.path.join(tree, 'small.txt'))
	overwrite_middle(os.path.join(tree, 'new.txt'))
	# the manifest is lost before the retry
	for name in (rv.MANIFEST_FILE_NAME, rv.MANIFEST_FILE_NAME + '-journal'):
		if os.path.lexists(os.path.join(r_job.job_vault, name)):
			os.remove(os.path.join(r_job.job_vault, name))
	reads, copies = recording_reads_and_copies(monkeypatch)
	rebuilt = []
	real_rebuild = rv.VaultManifest.rebuild
	monkeypatch.setattr(rv.VaultManifest, 'rebuild', lambda self, *args, **kwargs: rebuilt.append(kwargs.get('tree_path')) or real_rebuild(self, *args, **kwargs))
	roll_forward(r_job)
	assert tree in rebuilt
	assert 'new.txt' not in reads and 'moved.txt' not in reads
	assert {os.path.join(r_job.monitor, rel) for rel in ('new.txt', 'moved.txt')} <= set(copies)
	newest = committed_versions(r_job)[-1]
	for rel in ('new.txt', 'moved.txt'):
		assert read_bytes(os.path.join(newest, rel)) == read_bytes(os.path.join(r_job.monitor, rel)), rel


# a file that took the place of an entry of another kind: what the cut batch recorded there is a link, a folder, or (for what is
# new under a folder that took a file's place) nothing, and the comparison must not read the file back for any of them. Each
# shape is cut, its file's middle overwritten, and rolled forward with the manifest standing and with it lost.
# On 5b93a71: link_to_file fails in both manifest states, and folder_to_file, file_to_folder and dirlink_to_folder fail with the
# manifest lost (the roll-forward kept only recorded regular files, and new_in_tree() skipped a name both folders list); those three
# with the manifest standing pass there, and pin that the comparison finds a create where a row of another kind stands.
# dirlink_to_folder is the one that needs new_in_tree() to tell a user's link to a folder from a real folder (kind_at(twin) == 'd',
# not isdir()): a twin that is a link to a folder must still be new, and with isdir() its lost-manifest case reads y/f back.
KIND_SHAPES = {
	# a user's link replaced by a file: the file is the new tree's x
	'link_to_file': dict(file='x', events=[(False, 'delete', 'x', None), (False, 'create', 'x', None)]),
	# a folder (with a file in it) replaced by a file
	'folder_to_file': dict(file='d', events=[(False, 'delete', 'd/inner.txt', None), (True, 'delete', 'd', None), (False, 'create', 'd', None)]),
	# a file replaced by a folder holding a new file
	'file_to_folder': dict(file='small.txt/a', events=[(False, 'delete', 'small.txt', None), (True, 'create', 'small.txt', None), (False, 'create', 'small.txt/a', None)]),
	# a user's link to a folder (y -> d) replaced by a folder holding a new file
	'dirlink_to_folder': dict(file='y/f', events=[(False, 'delete', 'y', None), (True, 'create', 'y', None), (False, 'create', 'y/f', None)]),
}


def change_kind(job, shape):
	base_files = {'big.txt': big_text('b0'), 'small.txt': 's0', 'd/inner.txt': 'i0'}
	for rel, text in base_files.items():
		put_text(job.monitor, rel, text)
	os.symlink('small.txt', os.path.join(job.monitor, 'x'))
	os.symlink('d', os.path.join(job.monitor, 'y'))
	run_backup(job, **KEPT)
	if shape == 'folder_to_file':
		shutil.rmtree(os.path.join(job.monitor, 'd'))
	elif shape == 'file_to_folder':
		os.remove(os.path.join(job.monitor, 'small.txt'))
	else:
		# a link of either kind goes
		os.remove(os.path.join(job.monitor, 'x' if shape == 'link_to_file' else 'y'))
	put_text(job.monitor, KIND_SHAPES[shape]['file'], big_text('n1'))
	return KIND_SHAPES[shape]['events']


def lose_the_manifest(job):
	for name in (rv.MANIFEST_FILE_NAME, rv.MANIFEST_FILE_NAME + '-journal'):
		if os.path.lexists(os.path.join(job.job_vault, name)):
			os.remove(os.path.join(job.job_vault, name))


def recording_rebuilds(monkeypatch):
	'''The tree_path of each rebuild of the manifest from now on: a roll-forward over a lost manifest rebuilds it from the cut batch's tree.'''
	rebuilt = []
	real = rv.VaultManifest.rebuild
	monkeypatch.setattr(rv.VaultManifest, 'rebuild', lambda self, version_path, tree_path=None: rebuilt.append(tree_path) or real(self, version_path, tree_path))
	return rebuilt


def contents_of(root):
	'''What a tree holds, nothing followed: {rel: ('l', text) | ('d',) | ('f', bytes)}, the daemon's own files left out.'''
	found = {}
	for folder, folders, files in os.walk(root):
		for name in folders + files:
			path = os.path.join(folder, name)
			rel = os.path.relpath(path, root)
			if rel.startswith('.reverberator'):
				continue
			found[rel] = ('l', os.readlink(path)) if os.path.islink(path) else ('d',) if os.path.isdir(path) else ('f', read_bytes(path))
	return found


@pytest.mark.parametrize('manifest', ['standing', 'lost'])
@pytest.mark.parametrize('shape', sorted(KIND_SHAPES))
def test_the_roll_forward_copies_again_a_file_that_took_the_place_of_another_kind(r_job, monkeypatch, shape, manifest):
	events = change_kind(r_job, shape)
	cut_before_the_commit(r_job, events, monkeypatch)
	tree = tree_of(r_job)
	rel = KIND_SHAPES[shape]['file']
	assert os.path.isfile(os.path.join(tree, rel)) and not os.path.islink(os.path.join(tree, rel))
	overwrite_middle(os.path.join(tree, rel))
	if manifest == 'lost':
		lose_the_manifest(r_job)
	rebuilt = recording_rebuilds(monkeypatch)
	reads, copies = recording_reads_and_copies(monkeypatch)
	roll_forward(r_job)
	# a lost manifest is rebuilt from the tree (test 10's case), and a standing one is not
	assert bool([tree_path for tree_path in rebuilt if tree_path]) == (manifest == 'lost')
	source = os.path.join(r_job.monitor, rel)
	assert rel not in reads
	assert source in copies
	newest = committed_versions(r_job)[-1]
	assert os.path.isfile(os.path.join(newest, rel)) and not os.path.islink(os.path.join(newest, rel))
	assert read_bytes(os.path.join(newest, rel)) == read_bytes(source)


# ---- the roll-forward over a lost manifest reaches through no link
# On c661652 both fail with the manifest lost and pass with it standing (pins): new_in_tree() listed what a link of the tree led to, as a
# link stood where a recorded real folder was (a: ELOOP, for a link naming its own place), and the roll-forward took each recorded
# name under a link of the monitored tree for a regular file of that tree and replayed it as a modify (b: d/inner.txt copied).

@pytest.mark.parametrize('manifest', ['standing', 'lost'])
def test_the_roll_forward_commits_over_the_link_a_cut_exchange_left_in_a_folders_place(r_job, monkeypatch, manifest):
	# a folder deleted is recorded by swapping it with the previous version's forward link, which is then unlinked: a cut between leaves
	# the tree holding at the folder's name a link whose text names its own place (TreeWriter.exchange_in()'s docstring; test_r_scan.py
	# builds the same state). With the manifest lost, new_in_tree() listed it (ELOOP) and no attempt could commit; standing, it is a pin.
	# The folder holds a subfolder too, so d/ and d/sub/ are both recorded: without new_in_tree()'s real_folders_to() half of its guard,
	# kind_at(tree/d/sub) follows the link (ELOOP) even if the folder's own kind were checked
	put_text(r_job.monitor, 'd/sub/k.txt', 'k0')
	base(r_job)
	shutil.rmtree(os.path.join(r_job.monitor, 'd'))
	cut_before_the_commit(r_job, [(False, 'delete', 'd/inner.txt', None), (False, 'delete', 'd/sub/k.txt', None), (True, 'delete', 'd/sub', None), (True, 'delete', 'd', None)], monkeypatch)
	tree = tree_of(r_job)
	# the batch recorded the folder in the previous version, and the tree holds nothing at its name until the link goes there
	previous = committed_versions(r_job)[-1]
	assert not os.path.lexists(os.path.join(tree, 'd')) and os.path.isfile(os.path.join(previous, 'd', 'inner.txt'))
	assert os.path.isdir(os.path.join(previous, 'd', 'sub')) and not os.path.islink(os.path.join(previous, 'd', 'sub'))
	os.symlink(rv.forward_text('d', os.path.basename(tree)), os.path.join(tree, 'd'))
	if manifest == 'lost':
		lose_the_manifest(r_job)
	rebuilt = recording_rebuilds(monkeypatch)
	roll_forward(r_job)
	assert bool([tree_path for tree_path in rebuilt if tree_path]) == (manifest == 'lost')
	assert contents_of(committed_versions(r_job)[-1]) == contents_of(r_job.monitor)
	assert 'd' not in contents_of(committed_versions(r_job)[-1])


@pytest.mark.parametrize('manifest', ['standing', 'lost'])
def test_the_roll_forward_copies_nothing_a_link_of_the_monitored_tree_leads_to(r_job, monkeypatch, manifest, tmp_path, capsys):
	# a folder moved out and an absolute link put in its place: the monitored d/inner.txt is a regular file through the link, and is
	# no entry of the monitored tree. Nothing of what the link leads to is copied, whatever its size. With the manifest standing, the
	# replay of the delete of each row under the link finds the version holds nothing there but through the link: the rows go, and no
	# error line is logged (before, one "Not removing ..." per row, though the version came out right)
	base(r_job)
	outside = tmp_path / 'outside'
	outside.mkdir()
	shutil.move(os.path.join(r_job.monitor, 'd'), str(outside / 'd'))
	put_text(str(outside), 'd/extra.txt', big_text('x0'))
	os.symlink(str(outside / 'd'), os.path.join(r_job.monitor, 'd'))
	cut_before_the_commit(r_job, [(True, 'delete', 'd', None), (False, 'create', 'd', None)], monkeypatch)
	if manifest == 'lost':
		lose_the_manifest(r_job)
	reads, copies = recording_reads_and_copies(monkeypatch)
	capsys.readouterr()
	roll_forward(r_job)
	assert [line for line in capsys.readouterr().out.splitlines() if line.startswith('[ERROR]')] == []
	assert [source for source in copies if source.startswith(os.path.join(r_job.monitor, 'd') + os.sep)] == []
	newest = committed_versions(r_job)[-1]
	assert contents_of(newest) == contents_of(r_job.monitor)
	assert contents_of(newest)['d'] == ('l', str(outside / 'd'))


# ---- F1: the scan makes a cut batch's tree version n's again (put_back_recorded()), before anything reads its rows

class InnerDisk:
	'''
	The monitored folder disk as an inner mount of a fake mount table. Unmounted, its folder is the empty one it leaves, and what it
	held waits at aside.
	'''
	def __init__(self, job, monkeypatch, aside):
		self.job, self.monkeypatch, self.aside = job, monkeypatch, aside
		self.folder = os.path.join(job.monitor, 'disk')
		os.makedirs(self.folder, exist_ok=True)
		self.table('disk/')

	def table(self, *rels):
		table = [('/', ('1',))] + [(os.path.join(self.job.monitor, rel.rstrip('/')), (rel,)) for rel in rels]
		self.monkeypatch.setattr(rv, 'current_mount_table', lambda: table)

	def unmount(self):
		os.rename(self.folder, self.aside)
		os.mkdir(self.folder)
		self.table()

	def mount(self):
		os.rmdir(self.folder)
		os.rename(self.aside, self.folder)
		self.table('disk/')


def an_attribute_copy_cut(job, monkeypatch, tmp_path):
	'''
	A file on the inner disk, backed up and read back checked (as after any restart of the daemon, the full comparison reads the copies
	back); then a chmod, which with Only Sync Attributes off copies the file, in a batch cut after the copy, whose bytes did not reach
	the disk (NUL at its size and mtime, as after an f2fs checkpoint). (the InnerDisk, the monitored file, its bytes, version n's
	folder, the file's row in version n)
	'''
	data = b''.join(f'z{i:07d}\n'.encode() for i in range(40000))
	disk = InnerDisk(job, monkeypatch, os.path.join(str(tmp_path), 'aside'))
	path = os.path.join(disk.folder, 'file.bin')
	with open(path, 'wb') as f:
		f.write(data)
	put_text(job.monitor, 'a.txt', 'a0')
	run_backup(job, only_sync_attributes=False, **KEPT)
	run_backup(job, only_sync_attributes=False, **KEPT)
	assert len(committed_versions(job)) == 1
	row = rows(job)['disk/file.bin']
	assert row.unchecked == 0
	os.chmod(path, 0o600)
	cut_before_the_commit(job, [(False, 'attrib', 'disk/file.bin', None)], monkeypatch, only_sync_attributes=False)
	copy = os.path.join(tree_of(job), 'disk', 'file.bin')
	assert os.lstat(copy).st_nlink == 1, 'the cut batch placed its own copy'
	all_nul(copy)
	return disk, path, data, committed_versions(job)[-1], row


def unreadable_below(monkeypatch, folder):
	'''
	Every look into folder fails with EACCES (its listing, and an lstat of anything in it), as a folder of mode 000 does for a user
	other than root, while the folder itself can still be looked at. A real mode 000 would not do: root reads it, and a daemon run as
	uid 65534 gives its own copy of the folder that mode and then cannot measure its own version.
	'''
	real_scandir, real_lstat = os.scandir, os.lstat
	inside = folder + os.sep
	def denied(path):
		raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
	def scandir(path='.'):
		if isinstance(path, str) and (path.rstrip(os.sep) == folder or path.startswith(inside)):
			denied(path)
		return real_scandir(path)
	def lstat(path, *args, **kwargs):
		if isinstance(path, str) and path.startswith(inside):
			denied(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'scandir', scandir)
	monkeypatch.setattr(rv.os, 'lstat', lstat)


@pytest.mark.parametrize('mount', ['stays', 'paused_at_the_retry', 'goes_during_the_walk', 'unreadable_folder'])
def test_a_cut_batchs_file_the_roll_forward_cannot_copy_again_holds_version_ns_entry(r_job, monkeypatch, tmp_path, mount):
	# At the retry the roll-forward cannot copy the cut batch's file again: its inner mount is not mounted yet, it goes during the
	# roll-forward's walk (drop_unmounted_entries() drops the forced modify), or its monitored folder cannot be read
	# (unreadable_below(): what a folder of mode 000 is to a user other than root). The scan put version n's entry back at the
	# name, so the newest version holds version n's inode under version n's row, and the next full comparison, the mount back, reads
	# nothing back and copies the file. 'stays' is a pin: the roll-forward copies the file again. The other three fail on 82732dd:
	# the newest version holds the cut copy, all NUL, under a row marked unchecked
	disk, path, data, previous, row = an_attribute_copy_cut(r_job, monkeypatch, tmp_path)
	if mount == 'paused_at_the_retry':
		disk.unmount()
	elif mount == 'goes_during_the_walk':
		real = rv.roll_forward_entries
		def walked(*args, **kwargs):
			found = real(*args, **kwargs)
			# what drop_unmounted_entries() reads next: the disk was unmounted while the comparison ran
			disk.unmount()
			return found
		monkeypatch.setattr(rv, 'roll_forward_entries', walked)
	if mount == 'unreadable_folder':
		with monkeypatch.context() as denied:
			unreadable_below(denied, disk.folder)
			roll_forward(r_job, only_sync_attributes=False)
	else:
		roll_forward(r_job, only_sync_attributes=False)
	held = os.path.join(committed_versions(r_job)[-1], 'disk', 'file.bin')
	if mount != 'stays':
		assert os.lstat(held).st_ino == os.lstat(os.path.join(previous, 'disk', 'file.bin')).st_ino, 'the newest version holds a copy, not version n\'s entry'
		assert read_bytes(held) == data
		assert rows(r_job)['disk/file.bin'] == row
		if mount != 'unreadable_folder':
			disk.mount()
	reads, copies = recording_reads_and_copies(monkeypatch)
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	held = os.path.join(committed_versions(r_job)[-1], 'disk', 'file.bin')
	if mount != 'stays':
		assert 'disk/file.bin' not in reads and path in copies
	assert read_bytes(held) == data, 'the newest version holds the file ' + ('all NUL' if not any(read_bytes(held)) else 'wrong')


# a name of another kind on the inner disk, the cut batch's change there, and the file it wrote
OTHER_KINDS = {
	# a user's link replaced by a file
	'link_to_file': dict(file='disk/x', events=[(False, 'delete', 'disk/x', None), (False, 'create', 'disk/x', None)]),
	# a folder (with a file in it) replaced by a file
	'folder_to_file': dict(file='disk/d', events=[(False, 'delete', 'disk/d/inner.txt', None), (True, 'delete', 'disk/d', None), (False, 'create', 'disk/d', None)]),
	# a file replaced by a folder holding a new file
	'file_to_folder': dict(file='disk/small.txt/a', events=[(False, 'delete', 'disk/small.txt', None), (True, 'create', 'disk/small.txt', None),
		(False, 'create', 'disk/small.txt/a', None)]),
}


@pytest.mark.parametrize('shape', sorted(OTHER_KINDS))
def test_a_paused_mounts_name_of_another_kind_gets_version_ns_entry_back(r_job, monkeypatch, tmp_path, shape):
	# the cut batch changed a name's kind on the inner disk, which is not mounted at the retry: the roll-forward passes over it, and
	# the newest version holds there what version n held, a folder with its mode and times, until the next full comparison with
	# the disk back. Fails on 82732dd: the newest version holds the cut batch's entry (the file, or the folder and its new file)
	disk = InnerDisk(r_job, monkeypatch, os.path.join(str(tmp_path), 'aside'))
	put_text(r_job.monitor, 'disk/small.txt', 's0')
	put_text(r_job.monitor, 'disk/d/inner.txt', 'i0')
	os.symlink('small.txt', os.path.join(disk.folder, 'x'))
	put_text(r_job.monitor, 'top.txt', 't0')
	run_backup(r_job, **KEPT)
	held_before = contents_of(os.path.join(committed_versions(r_job)[-1], 'disk'))
	folder_before = os.lstat(os.path.join(committed_versions(r_job)[-1], 'disk', 'd'))
	if shape == 'folder_to_file':
		shutil.rmtree(os.path.join(disk.folder, 'd'))
	else:
		os.remove(os.path.join(disk.folder, 'x' if shape == 'link_to_file' else 'small.txt'))
	put_text(r_job.monitor, OTHER_KINDS[shape]['file'], big_text('n1'))
	put_text(r_job.monitor, 'top.txt', 't1')
	cut_before_the_commit(r_job, OTHER_KINDS[shape]['events'] + [(False, 'modify', 'top.txt', None)], monkeypatch)
	assert os.path.isfile(os.path.join(tree_of(r_job), OTHER_KINDS[shape]['file']))
	disk.unmount()
	roll_forward(r_job)
	newest = committed_versions(r_job)[-1]
	assert contents_of(os.path.join(newest, 'disk')) == held_before
	folder = os.lstat(os.path.join(newest, 'disk', 'd'))
	assert (folder.st_mode, folder.st_mtime_ns) == (folder_before.st_mode, folder_before.st_mtime_ns)
	assert read_bytes(os.path.join(newest, 'top.txt')) == b't1'
	disk.mount()
	run_backup(r_job, **KEPT)
	assert contents_of(committed_versions(r_job)[-1]) == contents_of(r_job.monitor)


def test_a_folder_moved_under_a_paused_mount_and_cut_comes_back_where_it_was(r_job, monkeypatch, tmp_path):
	# the design review's probe B: mv disk/a disk/b on the inner disk, the batch cut before its commit, retried with the disk not
	# mounted. The newest version holds disk/a as version n held it and no disk/b, under rows that name disk/a, and every list
	# names what the oracle counts. Fails on 82732dd: the newest version holds disk/b, its rows name disk/a
	disk = InnerDisk(r_job, monkeypatch, os.path.join(str(tmp_path), 'aside'))
	put_text(r_job.monitor, 'disk/a/x.txt', 'x0')
	put_text(r_job.monitor, 'disk/a/y.txt', big_text('y0'))
	put_text(r_job.monitor, 'top.txt', 't0')
	run_backup(r_job, **KEPT)
	held_before = contents_of(committed_versions(r_job)[-1])
	os.rename(os.path.join(disk.folder, 'a'), os.path.join(disk.folder, 'b'))
	cut_before_the_commit(r_job, [(True, 'move', 'disk/b', 'disk/a')], monkeypatch)
	assert os.path.isdir(os.path.join(tree_of(r_job), 'disk', 'b'))
	disk.unmount()
	roll_forward(r_job)
	assert contents_of(committed_versions(r_job)[-1]) == held_before
	named = sorted(rel for rel in rows(r_job) if rel.startswith('disk/'))
	assert named == ['disk/', 'disk/a/', 'disk/a/x.txt', 'disk/a/y.txt']
	assert rows_match_vault(r_job.job_vault) == []
	assert view_truth.wrong_lists(r_job.job_vault) == []


def test_a_cut_create_unreadable_at_the_retry_is_left_out_with_its_line(r_job, monkeypatch, capsys):
	# the design re-check's run N4, the manifest standing: a file the cut batch made, its copy's middle lost (a stand-in writes it
	# damaged), and its source mode 000 at the retry (uid 65534 only, as root reads it; the VM gate deselects it by name). The scan
	# removes what the batch made, so the newest version holds nothing there, with one UNREADABLE line, and once the file can be read
	# the next full comparison copies it. Fails on 82732dd: the newest version keeps the damaged copy, through both comparisons
	base(r_job)
	path = os.path.join(r_job.monitor, 'new.bin')
	put_text(r_job.monitor, 'new.bin', big_text('n1'))
	put_text(r_job.monitor, 'small.txt', 's1')
	cut_before_the_commit(r_job, [(False, 'create', 'new.bin', None), (False, 'modify', 'small.txt', None)], monkeypatch)
	overwrite_middle(os.path.join(tree_of(r_job), 'new.bin'))
	os.chmod(path, 0)
	try:
		capsys.readouterr()
		roll_forward(r_job)
		out = capsys.readouterr().out
	finally:
		os.chmod(path, 0o644)
	newest = committed_versions(r_job)[-1]
	assert not os.path.lexists(os.path.join(newest, 'new.bin'))
	assert read_bytes(os.path.join(newest, 'small.txt')) == b's1'
	assert len([line for line in out.splitlines() if 'UNREADABLE' in line and path in line]) == 1, out
	run_backup(r_job, **KEPT)
	assert read_bytes(os.path.join(committed_versions(r_job)[-1], 'new.bin')) == read_bytes(path)


def test_a_put_back_where_hard_links_are_refused_copies_and_flushes_once(r_job, monkeypatch, tmp_path):
	# a vault that refuses hard links at the retry (EMLINK; a FUSE or network filesystem, or a pool answering EXDEV between its disks):
	# the put-back copies version n's entry, and the scan flushes the vault's disks once, through its own unit, before the attempt
	# goes on. The disk is not mounted at the retry, so the newest version keeps that copy. Fails on 82732dd: no put-back, no flush
	disk, path, data, previous, row = an_attribute_copy_cut(r_job, monkeypatch, tmp_path)
	disk.unmount()
	callers = []
	real_flush = rv.flush_or_fail
	def flush(*args, **kwargs):
		callers.append(sys._getframe(1).f_code.co_name)
		return real_flush(*args, **kwargs)
	def refused(source, dest, *args, **kwargs):
		raise OSError(errno.EMLINK, os.strerror(errno.EMLINK), source, None, dest)
	with monkeypatch.context() as patched:
		patched.setattr(rv, 'flush_or_fail', flush)
		patched.setattr(rv.os, 'link', refused)
		roll_forward(r_job, only_sync_attributes=False)
	assert callers.count('prepare_roll_forward') == 1, callers
	held = os.path.join(committed_versions(r_job)[-1], 'disk', 'file.bin')
	assert os.lstat(held).st_ino != os.lstat(os.path.join(previous, 'disk', 'file.bin')).st_ino
	assert read_bytes(held) == data


def test_a_pool_cut_after_the_put_back_links_every_recorded_entry_again(r_job, fake_pool, monkeypatch):
	# on a pool there is no same-inode shortcut: mergerfs makes up the inode number it shows, and after a cut each disk comes back at
	# its own point. A scan cut after its put-back (nothing after it ran) leaves the tree as version n's; the next scan unlinks and
	# links every recorded file and link again, and ends by dropping the pool's cache. Fails on 82732dd: no put-back
	pool_vault(r_job, fake_pool)
	put_text(r_job.monitor, 'big.txt', big_text('b0'))
	put_text(r_job.monitor, 'd/inner.txt', 'i0')
	os.symlink('big.txt', os.path.join(r_job.monitor, 'ln'))
	run_backup(r_job, **KEPT)
	put_text(r_job.monitor, 'big.txt', big_text('b1'))
	put_text(r_job.monitor, 'd/inner.txt', 'i1')
	os.remove(os.path.join(r_job.monitor, 'ln'))
	os.symlink('d/inner.txt', os.path.join(r_job.monitor, 'ln'))
	cut_before_the_commit(r_job, [(False, 'modify', 'big.txt', None), (False, 'modify', 'd/inner.txt', None), (False, 'delete', 'ln', None),
		(False, 'create', 'ln', None)], monkeypatch)
	tree = tree_of(r_job)
	rv.get_vault_info(r_job.job_vault)
	linked, forgotten = [], []
	real_link, real_forget = rv.link_or_copy, rv.forget_pool_cache
	def link(source, dest):
		if dest.startswith(tree + os.sep):
			linked.append(os.path.relpath(dest, tree))
		return real_link(source, dest)
	def forget(path):
		forgotten.append(path)
		return real_forget(path)
	with monkeypatch.context() as recording:
		recording.setattr(rv, 'link_or_copy', link)
		recording.setattr(rv, 'forget_pool_cache', forget)
		rv.get_vault_info(r_job.job_vault)
	assert sorted(linked) == ['big.txt', 'd/inner.txt', 'ln']
	assert forgotten and forgotten[-1] == tree
	roll_forward(r_job)
	assert contents_of(committed_versions(r_job)[-1]) == contents_of(r_job.monitor)


def test_a_pool_branch_gone_while_the_put_back_lists_a_folder_fails_the_scan_and_removes_nothing(r_job, fake_pool, monkeypatch):
	# on a pool a branch that goes after the scan read the vault and before the put-back lists a recorded folder of version n hides what that
	# branch holds: here the forward link of an unchanged name, whose entry in the tree is the only copy (R45). The listing then lacks the
	# name and pass 2 takes it for one the batch made. The put-back checks the pool after each folder's listing and before its removals, as
	# the removal of a stale list does: PoolNotReady, with every entry of the tree as it was. Fails on 850ecf5: the entry is deleted
	branches = pool_vault(r_job, fake_pool)
	put_text(r_job.monitor, 'd/other.txt', 'o0')
	base(r_job)
	put_text(r_job.monitor, 'd/inner.txt', 'i1')
	cut_before_the_commit(r_job, [(False, 'modify', 'd/inner.txt', None)], monkeypatch)
	tree = tree_of(r_job)
	previous = committed_versions(r_job)[-1]
	assert os.path.islink(os.path.join(previous, 'd', 'other.txt')), 'version n holds a forward link to the unchanged name'
	held = os.path.join(tree, 'd', 'other.txt')
	assert read_bytes(held) == b'o0'
	hidden = os.path.join(previous, 'd')
	real_listdir, dropped = os.listdir, []
	def listdir(path='.'):
		names = real_listdir(path)
		if isinstance(path, str) and path.rstrip(os.sep) == hidden and not dropped:
			# the branch holding the link goes while it is listed
			dropped.append(path)
			fake_pool.drop(branches[1])
			return [name for name in names if name != 'other.txt']
		return names
	monkeypatch.setattr(rv.os, 'listdir', listdir)
	with pytest.raises(rv.PoolNotReady):
		rv.get_vault_info(r_job.job_vault)
	assert dropped
	assert read_bytes(held) == b'o0'


@pytest.mark.parametrize('unreadable', ['file', 'folder'])
def test_a_lost_manifest_keeps_what_a_cut_exchange_left_in_staging(r_job, monkeypatch, unreadable):
	# pin, the design re-check's run N5: on a vault with no RENAME_EXCHANGE a folder goes into the previous version by two renames,
	# its forward link to staging first; a cut between them leaves version n's folder in the tree only. With the manifest lost no
	# row gives the link back, and the source cannot be read at the retry: a file in the folder (mode 000), or a folder in it with
	# files (unreadable_below()). The newest version keeps them, as the put-back removes what the batch made only over a standing
	# manifest. It fails on a put-back that removes over a lost manifest; 0.55.4 kept them too
	put_text(r_job.monitor, 'd/x.bin', big_text('x0'))
	put_text(r_job.monitor, 'd/sub/s.txt', 's0')
	put_text(r_job.monitor, 'd/sub/t.txt', 't0')
	put_text(r_job.monitor, 'top.txt', 't0')
	run_backup(r_job, **KEPT)
	held_before = contents_of(committed_versions(r_job)[-1])
	no_exchange(monkeypatch)
	def cut_between(self, rel, st, holder):
		# the first of the two renames, then the cut
		self.two_renames = True
		os.rename(self.kept_path(rel), self.staged())
		raise Cut()
	with monkeypatch.context() as cut:
		cut.setattr(rv.TreeWriter, 'exchange_in', cut_between)
		with pytest.raises(Cut):
			backup_events(r_job, [(True, 'delete', 'd', None)], **KEPT)
	previous = committed_versions(r_job)[-1]
	assert not os.path.lexists(os.path.join(previous, 'd')) and os.path.isdir(os.path.join(tree_of(r_job), 'd'))
	lose_the_manifest(r_job)
	with monkeypatch.context() as denied:
		if unreadable == 'file':
			os.chmod(os.path.join(r_job.monitor, 'd/x.bin'), 0)
		else:
			unreadable_below(denied, os.path.join(r_job.monitor, 'd/sub'))
		try:
			roll_forward(r_job)
		finally:
			os.chmod(os.path.join(r_job.monitor, 'd/x.bin'), 0o644)
	held = contents_of(committed_versions(r_job)[-1])
	assert {rel: held.get(rel) for rel in held_before} == held_before
	# the version before keeps nothing at d: the link the cut left in staging goes with staging, and over a lost manifest no row
	# gives it back, as on 0.55.4 (a pool's case is the entry "A manifest lost in the same cut as a split on a pool"). The ground
	# truth's lines for it are looked at and taken out; any other line still fails the test
	lost = [line for line in view_truth.WRONG if line.startswith(f"{os.path.basename(previous)}:'d")]
	assert lost and all(line.endswith('None after it') for line in lost), lost
	view_truth.WRONG[:] = [line for line in view_truth.WRONG if line not in lost]


def test_a_recorded_folders_failed_metadata_copy_fails_the_attempt(r_job, monkeypatch):
	# the put-back gives each recorded folder of the tree its metadata in version n; a copy of it that fails fails the scan, and
	# with it the attempt, and the next attempt puts back again and commits right. Fails on 82732dd: no put-back, nothing fails
	base(r_job)
	put_text(r_job.monitor, 'd/inner.txt', 'i1')
	cut_before_the_commit(r_job, [(False, 'modify', 'd/inner.txt', None)], monkeypatch)
	tree = tree_of(r_job)
	def fails(source, dest, failed=None):
		if failed is not None:
			failed.append(source)
		return False
	with monkeypatch.context() as failing:
		failing.setattr(rv, 'copy_file_meta', fails)
		with pytest.raises(rv.JobFailure):
			rv.get_vault_info(r_job.job_vault)
	assert tree_of(r_job) == tree
	roll_forward(r_job)
	assert contents_of(committed_versions(r_job)[-1]) == contents_of(r_job.monitor)


# ---- 9. no markers

def test_neither_the_daemon_nor_a_restore_writes_a_marker(r_job, errseq, monkeypatch, capsys, tmp_path):
	base(r_job)
	write_rule(r_job)
	# a restore whose sync fails on the vault's disk: no marker, and no word of the daemon
	def failing(fd, path=None):
		raise OSError(errno.EIO, os.strerror(errno.EIO))
	out = tmp_path / 'out'
	out.mkdir()
	with monkeypatch.context() as patched:
		patched.setattr(rv, 'syncfs_fd', failing)
		capsys.readouterr()
		code = rv.run_command(['restore', os.path.join(r_job.monitor, 'd'), str(out), '--version', '0', '--rule', r_job.rule_path])
		said = capsys.readouterr()
	assert code == rv.EXIT_COMMAND_FAILED
	assert markers() == [] and 'for the daemon' not in said.out + said.err and 'record the write error' not in said.out + said.err
	assert not [line for line in said.out.splitlines() if line.startswith('WARNING')]
	# the daemon's failed flush: one alert line, and no marker
	at_the_commit_flush(monkeypatch, lambda: errseq.fail(r_job.job_vault))
	capsys.readouterr()
	with pytest.raises(rv.JobFailure):
		backup_events(r_job, modify_big(r_job), **KEPT)
	out = capsys.readouterr().out
	alerts = vault_write_errors(out)
	assert len(alerts) == 1 and 'nothing is committed past it, and the next attempt copies again what this one changed' in alerts[0]
	assert markers() == []


# ---- L2: no folder fsyncs off a pool after the commit point ----------------------------------------------------------

def after_the_commit_point(monkeypatch):
	'''
	The fsync_vault_folder() calls (their paths) and the read_mount_table() calls made once VaultManifest.commit() was called
	with a version, the commit point, until the test disarms it.
	'''
	seen = {'armed': False, 'fsyncs': [], 'reads': 0}
	real_commit, real_fsync, real_read = rv.VaultManifest.commit, rv.fsync_vault_folder, rv.read_mount_table
	def commit(self, version_path=None):
		if version_path is not None:
			seen['armed'] = True
		return real_commit(self, version_path)
	def fsync(path, *args, **kwargs):
		if seen['armed']:
			seen['fsyncs'].append(path)
		return real_fsync(path, *args, **kwargs)
	def read():
		if seen['armed']:
			seen['reads'] += 1
		return real_read()
	monkeypatch.setattr(rv.VaultManifest, 'commit', commit)
	monkeypatch.setattr(rv, 'fsync_vault_folder', fsync)
	monkeypatch.setattr(rv, 'read_mount_table', read)
	return seen


def first_version_and_a_one_file_batch(job, seen):
	'''After the commit point of V0, then of a one-file batch: (fsyncs, reads) of each.'''
	put_text(job.monitor, 'a.txt', 'a')
	put_text(job.monitor, 'k.txt', 'k')
	found = []
	for entries in (None, OrderedDict([(os.path.join(job.monitor, 'a.txt'), rv.BackupEntryValues(datetime.datetime.now().isoformat(), 'modify', None))])):
		if entries is not None:
			put_text(job.monitor, 'a.txt', 'changed')
		seen.update(armed=False, fsyncs=[], reads=0)
		run_backup(job, entries)
		found.append((seen['fsyncs'], seen['reads']))
	return found


def test_an_off_pool_batch_makes_no_folder_fsync_after_its_commit(r_job, monkeypatch):
	# fails on main: both the first version and a one-file batch fsync the job vault twice after the commit, after
	# swap_current_version() and in place_change_list(), each reading the mount table
	seen = after_the_commit_point(monkeypatch)
	assert first_version_and_a_one_file_batch(r_job, seen) == [([], 0), ([], 0)]


def test_a_pool_batch_fsyncs_both_after_its_commit(r_job, fake_pool, monkeypatch):
	# pin: on a pool each disk keeps its own order, so both fsyncs stay, a first version's included
	pool_vault(r_job, fake_pool)
	seen = after_the_commit_point(monkeypatch)
	assert [fsyncs for fsyncs, _ in first_version_and_a_one_file_batch(r_job, seen)] == [[r_job.job_vault] * 2] * 2


class Cut(Exception):
	pass


@pytest.mark.parametrize('pooled', [False, True], ids=['off_pool', 'pool'])
def test_finishing_a_cut_commit_fsyncs_both_off_a_pool_too(r_job, fake_pool, monkeypatch, pooled):
	# pin: the scan's finish of a commit cut before its list was placed, which runs once after a crash, fsyncs the job vault
	# after the swap and after the placement, on every filesystem
	if pooled:
		pool_vault(r_job, fake_pool)
	put_text(r_job.monitor, 'a.txt', 'a')
	run_backup(r_job)
	put_text(r_job.monitor, 'a.txt', 'changed')
	real_place = rv.place_change_list
	def cut(*args, **kwargs):
		raise Cut()
	monkeypatch.setattr(rv, 'place_change_list', cut)
	with pytest.raises(Cut):
		run_backup(r_job, OrderedDict([(os.path.join(r_job.monitor, 'a.txt'), rv.BackupEntryValues(datetime.datetime.now().isoformat(), 'modify', None))]))
	monkeypatch.setattr(rv, 'place_change_list', real_place)
	assert len(committed_versions(r_job)) == 1
	fsyncs = []
	real_fsync = rv.fsync_vault_folder
	def fsync(path, *args, **kwargs):
		frame = sys._getframe(1)
		while frame is not None and frame.f_code.co_name != 'finish_r_commit':
			frame = frame.f_back
		if frame is not None:
			fsyncs.append(path)
		return real_fsync(path, *args, **kwargs)
	monkeypatch.setattr(rv, 'fsync_vault_folder', fsync)
	assert list(rv.get_vault_info(r_job.job_vault).vault_info_dict) == [0, 1]
	assert fsyncs == [r_job.job_vault] * 2 and len(committed_versions(r_job)) == 2
