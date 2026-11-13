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
from tests.harness import committed_versions, create_job, run_backup, vault_unit, write_rule
from tests.scratch_images import needs_mount, ScratchTmpfs
from tests.vault_oracle import check_vault, snapshot_tree, version_number

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
	own new copy reads it too, as unchecked (read_copied_record()), and is no read-back.
	'''
	reads, copies = [], []
	real_read, real_command = rv.read_vault_record, rv.copy_command
	def read(version_path, rel, known=None, unchecked=0):
		if not unchecked:
			reads.append(rel)
		return real_read(version_path, rel, known, unchecked)
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


# ---- what the roll-forward does not copy again keeps its unchecked row, and a saved event is replayed through no link

@pytest.mark.parametrize('mount', ['stays', 'paused_at_the_retry', 'goes_during_the_walk'])
def test_a_cut_batchs_copy_under_an_inner_mount_paused_at_the_roll_forward_is_read_at_the_next_full_comparison(r_job, monkeypatch, tmp_path, mount):
	# An attribute change with Only Sync Attributes off copies its file; the batch is cut after the copy, whose bytes did not reach the
	# disk (NUL at its size and mtime, as after an f2fs checkpoint). At the retry the file's inner mount is not mounted yet: the
	# roll-forward cannot copy it again, and its row, checked until now, must be unchecked, or no comparison reads the copy back and the
	# newest version holds the file all NUL until it next changes. The mount going during the roll-forward's walk is the same: the
	# forced modify is dropped (drop_unmounted_entries()). 'stays' is a pin (the roll-forward copies the file again).
	# Without prepare_roll_forward()'s mark, the other two fail on 436b9c3 with the newest version all NUL.
	data = b''.join(f'z{i:07d}\n'.encode() for i in range(40000))
	path = os.path.join(r_job.monitor, 'disk', 'file.bin')
	os.makedirs(os.path.dirname(path))
	with open(path, 'wb') as f:
		f.write(data)
	put_text(r_job.monitor, 'a.txt', 'a0')
	def mounted(*rels):
		table = [('/', ('1',))] + [(os.path.join(r_job.monitor, rel.rstrip('/')), (rel,)) for rel in rels]
		monkeypatch.setattr(rv, 'current_mount_table', lambda: table)
	mounted('disk/')
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	# as after any restart of the daemon: a full comparison reads the copies back and records them checked
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	assert len(committed_versions(r_job)) == 1
	os.chmod(path, 0o600)
	cut_before_the_commit(r_job, [(False, 'attrib', 'disk/file.bin', None)], monkeypatch, only_sync_attributes=False)
	copy = os.path.join(tree_of(r_job), 'disk', 'file.bin')
	st = os.lstat(copy)
	assert st.st_nlink == 1, 'the cut batch placed its own copy'
	all_nul(copy)
	aside = os.path.join(str(tmp_path), 'aside')
	def unmount():
		# the inner disk is not mounted: its folder is the empty one it leaves
		os.rename(os.path.join(r_job.monitor, 'disk'), aside)
		os.mkdir(os.path.join(r_job.monitor, 'disk'))
		mounted()
	if mount == 'paused_at_the_retry':
		# not mounted yet when the daemon comes back
		unmount()
	elif mount == 'goes_during_the_walk':
		real = rv.roll_forward_entries
		def walked(*args, **kwargs):
			found = real(*args, **kwargs)
			# what drop_unmounted_entries() reads next: the disk was unmounted while the comparison ran
			unmount()
			return found
		monkeypatch.setattr(rv, 'roll_forward_entries', walked)
	roll_forward(r_job, only_sync_attributes=False)
	if mount != 'stays':
		os.rmdir(os.path.join(r_job.monitor, 'disk'))
		os.rename(aside, os.path.join(r_job.monitor, 'disk'))
	mounted('disk/')
	# the next full comparison, with the disk there
	run_backup(r_job, only_sync_attributes=False, **KEPT)
	held = read_bytes(os.path.join(committed_versions(r_job)[-1], 'disk', 'file.bin'))
	assert held == data, 'the newest version holds the file ' + ('all NUL' if not any(held) else 'wrong')


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
