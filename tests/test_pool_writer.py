'''
The writer on a mergerfs pool, and on a filesystem with no RENAME_EXCHANGE (spec section 5, plan S11): the hand-over, each folder record
and a conversion go by two renames, the tree keeps every entry until its apply phase, and every disk is flushed before a change
that needs what came before it. Most of it runs with fake_pool. The kill sweep on a real mergerfs of two f2fs images needs
REVERB_SCRATCH, root, /dev/fuse and mergerfs. A process kill loses nothing written, so every kill must pass; what a power cut does to
each disk is tests/test_pool_cut.py's.

REVERB_CRASH_FULL=1 runs every kill point; by default a stride of them.
'''
import contextlib
import errno
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict

import pytest

import reverberator as rv
from tests import version_view_ground_truth as view_truth
from tests.crash_batches import after_retries, batch3_of, OPTIONS, prepare, restore
from tests.crash_child import in_child, kill_run, retry
from tests.harness import create_job, event_entry, run_backup, seed_monitor, write_rule
from tests.scratch_images import LoopImage, needs_f2fs, SCRATCH
from tests.test_migration import cli_differences, expected, folders_of, migrate, plain_links, SMALL
from tests.test_tree_writer import a_vault, V1, V2
from tests.vault_oracle import check_vault, read_view, recorded_design_r, snapshot_tree, version_number

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

DEFAULT_KILL_POINTS = 40
MERGERFS_OPTIONS = ('allow_other,fsname=reverb_pool_writer_test,read-thread-count=-1,func.readdir=cor,passthrough.io=rw,readahead=2048,'
	# test_prune_power_loss.py's, but for the free space, as an image is smaller than the 4 GiB a branch must have free by default
	'security_capability=false,category.create=pfrd,lazy-umount-mountpoint=true,minfreespace=1M')
needs_mergerfs = pytest.mark.skipif(not SCRATCH or os.geteuid() != 0 or not shutil.which('mergerfs') or not shutil.which('mkfs.f2fs') or not os.path.exists('/dev/fuse'),
	reason='needs REVERB_SCRATCH, root, /dev/fuse, mergerfs and mkfs.f2fs')
PREPARED = {}
ROOTS = []


def no_exchange(module, code=errno.EINVAL):
	'''A filesystem with no RENAME_EXCHANGE, in the module given (a crash child's fault, or the test's own).'''
	def refused(a, b):
		raise OSError(code, os.strerror(code), a, None, b)
	module.rename_exchange = refused


def kill_points(total, default=DEFAULT_KILL_POINTS):
	every = list(range(1, total + 3))
	if os.environ.get('REVERB_CRASH_FULL'):
		return every
	return sorted({*every[::max(1, total // default)], *every[-5:]})


def prepared(key, tmp_path_factory, **options):
	if key not in PREPARED:
		root = str(tmp_path_factory.mktemp('pool_writer'))
		ROOTS.append(root)
		PREPARED[key] = prepare(root, **options)
	restore(PREPARED[key])
	return PREPARED[key]


@pytest.fixture(params=[False, True], ids=['attributes_copied', 'only_sync_attributes'])
def crash_vault(request, tmp_path_factory):
	return prepared(request.param, tmp_path_factory, only_sync_attributes=request.param)


@pytest.fixture
def plain_vault(tmp_path_factory):
	return prepared(False, tmp_path_factory, only_sync_attributes=False)


@pytest.fixture(scope='module', autouse=True)
def forget_the_vaults():
	yield
	PREPARED.clear()


def wrong_after_retry(vault):
	'''What is wrong with the vault once a batch or a retry ended: every version read by the oracle, and each list against what the oracle counts.'''
	job_vault = vault.job.job_vault
	return check_vault(job_vault, after_retries(job_vault, vault.expected), {3}, free_file_meta=bool(vault.options.get('only_sync_attributes'))) + view_truth.wrong_lists(job_vault)


def sweep(vault, fault=None, default=DEFAULT_KILL_POINTS):
	'''Batch 3 killed at each kill point and retried: what went wrong, and how many points ran.'''
	options = vault.options
	uncut = kill_run(vault.job, fault=fault, options=options)
	assert uncut.error is None and uncut.committed is True, uncut.error
	assert wrong_after_retry(vault) == []
	wrong = []
	points = kill_points(uncut.steps, default)
	for point in points:
		restore(vault)
		cut = kill_run(vault.job, point, fault=fault, options=options)
		if cut.error is not None or (point <= uncut.steps and not cut.killed):
			wrong.append((point, 'the cut run', cut))
			continue
		again = retry(vault.job, fault=fault, options=options)
		if again.error is not None or again.committed is not True:
			wrong.append((point, 'the retry', again))
			continue
		problems = wrong_after_retry(vault)
		if problems:
			wrong.append((point, problems[:8]))
	print(f'{len(points)} of {uncut.steps} kill points run; {len(wrong)} wrong')
	return wrong


# --- no RENAME_EXCHANGE ---

def test_a_filesystem_without_exchange_uses_two_renames(crash_vault):
	wrong = sweep(crash_vault, no_exchange)
	assert not wrong, f'{len(wrong)} kill points wrong: {wrong[:4]}'


@pytest.mark.parametrize('code', [errno.EINVAL, errno.ENOSYS, errno.ENOTSUP])
def test_each_answer_of_no_exchange_turns_to_two_renames(tmp_path, monkeypatch, code):
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	before = read_view(job_vault, V1)
	with monkeypatch.context() as patched:
		patched.setattr(rv, 'rename_exchange', lambda a, b: no_exchange(rv, code) or rv.rename_exchange(a, b))
		writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
		assert writer.two_renames
		writer.remove_now('d')
	assert read_view(job_vault, V1) == before


def test_another_error_of_the_exchange_stops_the_hand_over(tmp_path, monkeypatch):
	job_vault, newest = a_vault(str(tmp_path), {'f': 'x'})
	monkeypatch.setattr(rv, 'rename_exchange', lambda a, b: no_exchange(rv, errno.EIO) or rv.rename_exchange(a, b))
	with pytest.raises(OSError) as failure:
		rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert failure.value.errno == errno.EIO
	assert os.path.isfile(os.path.join(newest, 'f'))


def test_a_roll_forward_finds_out_at_its_first_exchange(plain_vault):
	# it makes no hand-over to find out by, so its writer starts on exchanges, and the first record of a folder turns it to two renames
	job = plain_vault.job
	cut = kill_run(job, 60, options=plain_vault.options)
	assert cut.killed
	assert retry(job, fault=no_exchange, options=plain_vault.options).committed is True
	assert wrong_after_retry(plain_vault) == []


def conversion_steps(job, fault):
	outcome = in_child(job, None, lambda: migrate(job), fault)
	assert outcome.error is None and outcome.committed is True, outcome.error
	return outcome


def test_a_conversion_without_exchange_uses_two_renames(tmp_path, tmp_path_factory, v054):
	job = create_job(str(tmp_path / 'job'))
	v054.build(job, SMALL, keep_n_versions=9)
	# out of tmp_path: a link of this copy can get the inode of one the chain plugin saw made, and it would judge the copy as a vault of its links
	template = str(tmp_path_factory.mktemp('template') / 'vault')
	subprocess.run(['cp', '-a', job.vault, template], check=True)
	before = expected(job)
	times = {name: os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns for name in folders_of(job).values()}

	def back():
		shutil.rmtree(job.vault)
		subprocess.run(['cp', '-a', template, job.vault], check=True)

	def wrong(point):
		lines = check_vault(job.job_vault, before, set()) + cli_differences(job.job_vault, before) + view_truth.wrong_lists(job.job_vault)
		if not recorded_design_r(job.job_vault):
			lines.append('no layout')
		if any(plain_links(job).values()):
			lines.append('a chain link is left')
		if {name: os.lstat(os.path.join(job.job_vault, name)).st_mtime_ns for name in folders_of(job).values()} != times:
			lines.append('a version folder has another mtime')
		return [f'kill at {point}: {line}' for line in lines]

	total = conversion_steps(job, no_exchange).steps
	assert wrong('none') == []
	between = 0
	found = []
	for point in range(1, total + 2):
		back()
		cut = in_child(job, point, lambda: migrate(job), no_exchange)
		assert cut.error is None and (cut.killed or point > total), cut.error
		# the kill between the two renames: a version with a list and no folder, its tree in staging
		staged = os.listdir(os.path.join(job.job_vault, rv.STAGING_NAME)) if os.path.isdir(os.path.join(job.job_vault, rv.STAGING_NAME)) else []
		if rv.REPLACED_NAME in staged and rv.CONVERTED_NAME in staged:
			between += 1
		conversion_steps(job, no_exchange)
		found += wrong(point)
	assert found == []
	# one for each version with chain links
	assert between == 2


def test_a_one_version_vault_cut_between_the_two_renames_resumes(tmp_path, v054):
	# every version folder gone between them: the vault reads as started over, had the repair not come first
	job = create_job(str(tmp_path / 'job'))
	v054.build(job, SMALL[:1], keep_n_versions=9)
	name = next(iter(folders_of(job).values()))
	before = expected(job)
	os.makedirs(os.path.join(job.job_vault, rv.STAGING_NAME))
	os.rename(os.path.join(job.job_vault, name), os.path.join(job.job_vault, rv.STAGING_NAME, rv.REPLACED_NAME))
	assert migrate(job) is True
	assert check_vault(job.job_vault, before, set()) == []


# --- a batch on a pool ---

@pytest.fixture
def steps(monkeypatch):
	'''Each flush of a disk and each rename under a vault, in order: ('flush',) or ('rename', source, dest).'''
	seen = []
	real_rename = os.rename
	def rename(source, dest, **kwargs):
		seen.append(('rename', os.path.basename(source), os.path.basename(dest)))
		return real_rename(source, dest, **kwargs)
	monkeypatch.setattr(os, 'rename', rename)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: seen.append(('flush',)) or [])
	return seen


def test_hand_over_flushes_between_its_renames(tmp_path, fake_pool, steps):
	job_vault, newest = a_vault(str(tmp_path), {'d/f': 'x', 'g': 'y'})
	fake_pool.add(job_vault, ['a', 'b'])
	before = read_view(job_vault, V1)
	writer = rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert steps == [('flush',), ('rename', V1, V2), ('flush',), ('rename', f'skel-{V1}', V1), ('flush',)]
	assert writer.two_renames and not writer.needs_flush
	assert read_view(job_vault, V1) == before
	assert read_view(job_vault, V2) == before
	assert os.listdir(os.path.join(job_vault, rv.STAGING_NAME)) == []
	assert os.readlink(os.path.join(newest, 'g')) == rv.forward_text('g', V2)


def test_a_hand_over_keeps_its_folders_times_and_record_across_the_renames(tmp_path, fake_pool, monkeypatch):
	job_vault, newest = a_vault(str(tmp_path), {'f': 'x'})
	fake_pool.add(job_vault, ['a', 'b'])
	st, record = os.lstat(newest), os.getxattr(newest, rv.ROOT_META_XATTR)
	real = os.rename
	def rename(source, dest, **kwargs):
		real(source, dest, **kwargs)
		# as f2fs does to a folder moved into another parent
		if os.path.basename(source).startswith(rv.SKELETON_PREFIX):
			os.utime(dest)
	monkeypatch.setattr(os, 'rename', rename)
	rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert os.lstat(newest).st_mtime_ns == st.st_mtime_ns
	assert os.getxattr(newest, rv.ROOT_META_XATTR) == record


def test_a_hand_over_on_a_pool_refuses_a_taken_name_with_nothing_changed(tmp_path, fake_pool):
	job_vault, newest = a_vault(str(tmp_path), {'f': 'x'})
	fake_pool.add(job_vault, ['a', 'b'])
	os.mkdir(os.path.join(job_vault, V2))
	with pytest.raises(FileExistsError):
		rv.hand_over(job_vault, newest, os.path.join(job_vault, V2))
	assert os.path.isfile(os.path.join(newest, 'f'))


@pytest.mark.parametrize('failing_flush', [1, 2, 3, 4])
def test_a_failed_flush_in_the_hand_over_is_a_cut_the_scan_finishes(plain_vault, fake_pool, failing_flush):
	job = plain_vault.job
	fake_pool.add(job.vault, ['a', 'b'])
	flushes = []
	def failing(module):
		def flush(job_vault, job_name):
			flushes.append(1)
			return ['/dev/fake'] if len(flushes) == failing_flush else []
		module.flush_vault_disks = flush
	failed = kill_run(job, fault=failing, options=plain_vault.options)
	assert 'failed a sync' in failed.error
	assert retry(job, options=plain_vault.options).committed is True
	assert wrong_after_retry(plain_vault) == []


def test_the_tree_keeps_every_entry_until_its_apply_phase(plain_vault, fake_pool, monkeypatch):
	job = plain_vault.job
	fake_pool.add(job.vault, ['a', 'b'])
	newest = max(rv.list_versions(job.job_vault), key=lambda version: version.number)
	before = read_view(job.job_vault, newest.name)
	views = []
	def flush(job_vault, job_name):
		folders = [name for name in os.listdir(job_vault) if version_number(name) == newest.number + 1]
		# past the first rename the tree has the new name; between the two its old name reads as nothing
		views.append((read_view(job_vault, folders[0]) if folders else None, read_view(job_vault, newest.name) if os.path.lexists(newest.path) else None))
		return []
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	entries, touched = batch3_of(job)
	_, manifest, committed = rv.do_backup(entries, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, touched=touched, matched_since=time.time_ns(), **OPTIONS)
	manifest.close()
	assert committed is True
	# the prune's first, then the hand-over's three, the replay's pass, and at least the commit
	window = next(index for index, (_, previous) in enumerate(views) if previous is None)
	assert len(views) >= window + 4
	assert views[window - 1] == (None, before)
	assert views[window] == (before, None)
	assert views[window + 1] == (before, before)
	# the moment that counts: every record of the replay is made, and the tree has not changed
	assert views[window + 2] == (before, before)
	assert views[-1][1] == before
	assert read_view(job.job_vault, newest.name) == before


def pool_writer(tmp_path, fake_pool, entries):
	job_vault, newest = a_vault(str(tmp_path), entries)
	fake_pool.add(job_vault, ['a', 'b'])
	return rv.hand_over(job_vault, newest, os.path.join(job_vault, V2)), job_vault, newest


def test_inline_records_are_noops_after_the_pass(tmp_path, fake_pool, steps):
	writer, job_vault, newest = pool_writer(tmp_path, fake_pool, {'d/f': 'x', 'd/e/g': 'y', 'h': 'z', 'keep/i': 'k'})
	del steps[:]
	writer.pre_record([(rv.ENTRY_OP, 'd/f'), (rv.ENTRY_OP, 'h'), (rv.ENTRY_OP, 'd/e'), (rv.FOLDER_OP, 'keep')])
	assert steps.count(('flush',)) == 1
	assert not writer.needs_flush
	for rel in ('d/f', 'h', 'd/e/g'):
		assert not os.path.islink(os.path.join(newest, rel))
		assert os.path.exists(os.path.join(writer.tree, rel))
	before = snapshot_tree(newest)
	del steps[:]
	writer.record('d/f', False)
	writer.hl_record('h')
	writer.ensure_real('keep')
	assert not writer.needs_flush
	writer.remove_now('d/f')
	writer.remove_now('d/e')
	writer.rename('h', 'keep/h')
	assert steps.count(('flush',)) == 0
	assert snapshot_tree(newest) == before


def test_a_pass_with_nothing_to_record_flushes_nothing(tmp_path, fake_pool, steps):
	writer, _, _ = pool_writer(tmp_path, fake_pool, {'f': 'x'})
	del steps[:]
	writer.pre_record([(rv.ENTRY_OP, 'new/where/never')])
	writer.pre_record([])
	assert steps == []


def test_an_inline_record_after_a_change_flushes_first(tmp_path, fake_pool, monkeypatch):
	writer, job_vault, newest = pool_writer(tmp_path, fake_pool, {'d/f': 'x', 'g': 'y'})
	seen = []
	def flush(job_vault, job_name):
		# the record is made, the tree not changed yet
		seen.append((os.path.islink(os.path.join(newest, 'g')), os.path.exists(os.path.join(writer.tree, 'g'))))
		return []
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	writer.remove_now('g')
	assert seen == [(False, True)]
	assert not os.path.lexists(os.path.join(writer.tree, 'g'))
	with open(os.path.join(newest, 'g')) as f:
		assert f.read() == 'y'


def test_each_verb_flushes_a_record_before_its_change(tmp_path, fake_pool, monkeypatch):
	writer, job_vault, newest = pool_writer(tmp_path, fake_pool, {'a/f': '1', 'b/f': '2', 'c/f': '3', 'd/f': '4', 'e/f': '5'})
	flushes = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: flushes.append(1) or [])
	made = []
	assert writer.make_folders('a/new/deep', made)
	assert len(flushes) == 1
	assert writer.make_folder('b')
	assert len(flushes) == 2
	st = os.lstat(writer.path('c'))
	writer.folder_times('c', st)
	assert len(flushes) == 3
	assert writer.folder_meta(writer.path('d'), 'd', st, [])
	assert len(flushes) == 4
	assert writer.rename('e/f', 'moved')
	assert len(flushes) == 5
	assert not writer.needs_flush


def test_a_record_on_a_pool_leaves_the_tree_as_it_was(tmp_path, fake_pool):
	writer, job_vault, newest = pool_writer(tmp_path, fake_pool, {'d/e/f': 'x', 'g': 'y'})
	tree = snapshot_tree(writer.tree)
	before = read_view(job_vault, V1)
	writer.record('d', False)
	writer.record('g', False)
	assert snapshot_tree(writer.tree) == tree
	assert read_view(job_vault, V1) == before
	assert not os.path.islink(os.path.join(newest, 'd/e'))
	assert os.lstat(os.path.join(newest, 'g')).st_ino == os.lstat(writer.path('g')).st_ino


def test_a_batch_with_nothing_copied_flushes_on_a_pool_before_it_commits(tmp_path, fake_pool, monkeypatch):
	job = create_job(str(tmp_path))
	write_rule(job)
	seed_monitor(job, {'a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	seed_monitor(job, {'c.txt': 'c'})
	run_backup(job, OrderedDict([event_entry(job, 'c.txt', 'create')]))
	fake_pool.add(job.vault, ['x', 'y'])
	seen = []
	real_commit = rv.VaultManifest.commit
	def commit(self, *args, **kwargs):
		if args:
			seen.append('commit')
		return real_commit(self, *args, **kwargs)
	monkeypatch.setattr(rv.VaultManifest, 'commit', commit)
	real_flush_copies = rv.flush_copies
	# the commit's own flush, as the end of the batch's settling can flush just before it
	monkeypatch.setattr(rv, 'flush_copies', lambda *args: seen.append('commit flush') or real_flush_copies(*args))
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: seen.append('flush') or [])
	os.remove(os.path.join(job.monitor, 'a.txt'))
	run_backup(job, OrderedDict([event_entry(job, 'a.txt', 'delete')]))
	assert seen[-3:] == ['commit flush', 'flush', 'commit']


def test_a_batch_on_a_pool_flushes_by_the_phase_not_by_the_entry(tmp_path, fake_pool, monkeypatch):
	# each flush is a checkpoint on every disk: the replay's records go in one pass and the settling's in one, whatever the batch's size
	job = create_job(str(tmp_path))
	write_rule(job)
	names = [f'd{number}/f.txt' for number in range(20)]
	seed_monitor(job, {name: name for name in names})
	run_backup(job)
	seed_monitor(job, {'c.txt': 'c'})
	run_backup(job, OrderedDict([event_entry(job, 'c.txt', 'create')]))
	fake_pool.add(job.vault, ['x', 'y'])
	flushes = []
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: flushes.append(1) or [])
	for name in names:
		os.remove(os.path.join(job.monitor, name))
	run_backup(job, OrderedDict(event_entry(job, name, 'delete') for name in names))
	# the prune, the hand-over's three, the replay, the settling, the commit
	assert 0 < len(flushes) <= 7


def test_a_cut_between_a_records_renames_gets_its_link_back(plain_vault, fake_pool):
	job = plain_vault.job
	fake_pool.add(job.vault, ['a', 'b'])
	# dead between the two renames of g's folder: the link gone, the folder not yet in
	def watching(module):
		real = module.TreeWriter.exchange_in
		def exchange_in(self, rel, st, holder):
			if rel == 'g':
				os.rename(self.kept_path(rel), self.staged())
				os._exit(9)
			return real(self, rel, st, holder)
		module.TreeWriter.exchange_in = exchange_in
	kill_run(job, fault=watching, options=plain_vault.options)
	newest = max(rv.list_versions(job.job_vault), key=lambda version: version.number)
	assert not os.path.lexists(os.path.join(newest.path, 'g'))
	assert retry(job, options=plain_vault.options).committed is True
	assert wrong_after_retry(plain_vault) == []


# --- the prune ---

def two_versions(job):
	write_rule(job)
	seed_monitor(job, {'a.txt': 'a', 'D/x.txt': 'x'})
	run_backup(job)
	seed_monitor(job, {'b.txt': 'b'})
	run_backup(job, OrderedDict([event_entry(job, 'b.txt', 'create')]))
	return rv.get_vault_info(job.job_vault).vault_info_dict


def lists_of(job, entry):
	return [name for name in os.listdir(job.job_vault) if rv.change_list_names(name, os.path.basename(entry.path))]


@pytest.fixture
def job(tmp_path):
	return create_job(str(tmp_path))


def test_a_prune_flushes_after_its_rename(job, fake_pool, monkeypatch):
	info = two_versions(job)
	fake_pool.add(job.vault, ['a', 'b'])
	v0 = info[0]
	staged = os.path.join(job.job_vault, rv.STAGING_NAME, os.path.basename(v0.path))
	seen = []
	def flush(job_vault, job_name):
		seen.append((os.path.lexists(v0.path), os.path.isdir(staged), bool(lists_of(job, v0))))
		return []
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	assert rv.prune_oldest(info, 'job', job.monitor, on_tree=True) == (v0.size, v0.inode)
	# gone from the versions, still whole in staging, its list there
	assert seen == [(False, True, True)]
	assert not os.path.lexists(staged) and not lists_of(job, v0)


def test_a_prune_off_a_pool_flushes_nothing(job, monkeypatch):
	info = two_versions(job)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: pytest.fail('a flush off a pool'))
	assert rv.prune_oldest(info, 'job', job.monitor, on_tree=True) != (0, 0)


def test_a_prune_whose_flush_fails_removes_nothing_more(job, fake_pool, monkeypatch):
	info = two_versions(job)
	fake_pool.add(job.vault, ['a', 'b'])
	v0 = info[0]
	staged = os.path.join(job.job_vault, rv.STAGING_NAME, os.path.basename(v0.path))
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: ['/dev/fake'])
	with pytest.raises(rv.JobFailure):
		rv.prune_oldest(info, 'job', job.monitor, on_tree=True)
	assert os.path.isdir(staged) and lists_of(job, v0)
	assert list(info) == [0, 1]


def test_a_disk_mounted_again_during_a_prune_keeps_the_oldest_version(job, fake_pool):
	info = two_versions(job)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	# the batch's guard, as it began: the disk came back since
	guard = rv.PoolGuard([job.job_vault])
	fake_pool.drop(a)
	fake_pool.mount(a)
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.prune_tree_version(info, 'job', guard)
	assert failure.value.reason == f'disk {a} of pool {job.vault} was mounted again during this step'
	assert os.path.isdir(info[0].path) and lists_of(job, info[0]) and list(info) == [0, 1]


def test_a_prune_never_finishes_an_oldest_version_a_missing_disk_hides_on_r(job, fake_pool, tmp_path):
	# V0's folder lived on disk a alone: with it out, the rename would find nothing
	info = two_versions(job)
	v0 = info[0]
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(a)
	hidden = str(tmp_path / 'hidden_v0')
	os.rename(v0.path, hidden)
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.prune_tree_version(info, 'job')
	assert failure.value.reason == f'disk {a} of pool {job.vault} is not mounted'
	assert lists_of(job, v0) and list(info) == [0, 1]
	os.rename(hidden, v0.path)
	fake_pool.mount(a)
	assert rv.prune_tree_version(rv.get_vault_info(job.job_vault).vault_info_dict, 'job') != (0, 0)
	assert not os.path.lexists(v0.path) and not lists_of(job, v0)


def test_a_disk_dropping_during_the_removal_keeps_the_oldest_versions_lists_on_r(job, fake_pool, tmp_path, monkeypatch):
	# the part of V0 on disk a goes out of sight while rm -rf runs, and is back with the disk
	info = two_versions(job)
	v0 = info[0]
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	staged = os.path.join(job.job_vault, rv.STAGING_NAME, os.path.basename(v0.path))
	real = rv.multiCMD.run_command
	hidden = str(tmp_path / 'hidden_part')
	def running(command, *args, **kwargs):
		if command[:2] == ['rm', '-rf']:
			fake_pool.drop(a)
			os.makedirs(hidden)
			os.rename(os.path.join(staged, 'D'), os.path.join(hidden, 'D'))
		return real(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', running)
	with pytest.raises(rv.PoolNotReady):
		rv.prune_tree_version(info, 'job', rv.PoolGuard([job.job_vault]))
	monkeypatch.setattr(rv.multiCMD, 'run_command', real)
	assert lists_of(job, v0) and list(info) == [0, 1]
	# back with the disk, in staging, where the scan removes it with the list of a folder gone
	os.makedirs(staged)
	os.rename(os.path.join(hidden, 'D'), os.path.join(staged, 'D'))
	fake_pool.mount(a)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1]
	assert not lists_of(job, v0) and os.listdir(os.path.join(job.job_vault, rv.STAGING_NAME)) == []


# --- readers in the hand-over's window ---

def stacked(job):
	write_rule(job)
	os.makedirs(rv.state_dir_path(), exist_ok=True)
	seed_monitor(job, {'top.txt': 't0', 'd/x': 'x0'})
	run_backup(job)
	seed_monitor(job, {'d/x': 'x1'})
	run_backup(job, OrderedDict([event_entry(job, 'd/x', 'modify')]))


def in_the_window(job, monkeypatch, at_flush):
	'''A batch on two renames, at_flush {which flush, from 1: what runs there}. The second comes between the two: the version's folder is not there.'''
	monkeypatch.setattr(rv, 'rename_exchange', lambda a, b: no_exchange(rv) or rv.rename_exchange(a, b))
	newest = max(rv.list_versions(job.job_vault), key=lambda version: version.number)
	flushes = []
	def flush(job_vault, job_name):
		flushes.append(1)
		assert os.path.lexists(newest.path) == (len(flushes) != 2)
		assert rv.backup_is_running('job')
		at_flush.get(len(flushes), lambda: None)()
		return []
	monkeypatch.setattr(rv, 'flush_vault_disks', flush)
	seed_monitor(job, {'d/x': 'x2'})
	run_backup(job, OrderedDict([event_entry(job, 'd/x', 'modify')]))
	assert len(flushes) >= 3


def waits_seen(monkeypatch):
	waiting = threading.Event()
	real_wait = rv.wait_for_backup
	def wait(*args, **kwargs):
		waiting.set()
		return real_wait(*args, **kwargs)
	monkeypatch.setattr(rv, 'wait_for_backup', wait)
	return waiting


def test_history_waits_through_the_hand_over_window(job, monkeypatch, capsys):
	stacked(job)
	waiting = waits_seen(monkeypatch)
	result = []
	reader = threading.Thread(target=lambda: result.append(rv.run_command(['history', os.path.join(job.monitor, 'd/x'), '--rule', job.rule_path])))
	def arrive():
		reader.start()
		assert waiting.wait(30)
		assert not result
	in_the_window(job, monkeypatch, {2: arrive})
	reader.join(30)
	assert not reader.is_alive()
	assert result == [0]
	lines = [line.split()[0] for line in capsys.readouterr().out.splitlines() if line.startswith('V') and line[1].isdigit()]
	assert lines == ['V2', 'V1', 'V0']


def restore_thread(job, out, result):
	return threading.Thread(target=lambda: result.append(rv.run_command(['restore', os.path.join(job.monitor, 'd/x'), str(out), '--version', '1', '--rule', job.rule_path])))


def test_a_restore_waits_on_the_lock(job, tmp_path, monkeypatch):
	# come while the batch holds its locks, before the first rename: it reads what it picks, and waits there through the window
	stacked(job)
	at_the_lock = threading.Event()
	real_locks = rv.command_restore_locks
	@contextlib.contextmanager
	def locks(job_name, state_dir=None):
		at_the_lock.set()
		with real_locks(job_name, state_dir):
			yield
	monkeypatch.setattr(rv, 'command_restore_locks', locks)
	out = tmp_path / 'out'
	out.mkdir()
	result = []
	reader = restore_thread(job, out, result)
	def arrive():
		reader.start()
		assert at_the_lock.wait(30)
	in_the_window(job, monkeypatch, {1: arrive, 2: lambda: pytest.fail('the restore ended in the window') if result else None})
	reader.join(30)
	assert not reader.is_alive()
	assert result == [0]
	with open(out / 'x') as f:
		assert f.read() == 'x1'


def test_a_restore_coming_in_the_window_waits_for_the_batch(job, tmp_path, monkeypatch):
	stacked(job)
	waiting = waits_seen(monkeypatch)
	out = tmp_path / 'out'
	out.mkdir()
	result = []
	reader = restore_thread(job, out, result)
	def arrive():
		reader.start()
		assert waiting.wait(30)
		assert not result
	in_the_window(job, monkeypatch, {2: arrive})
	reader.join(30)
	assert not reader.is_alive()
	assert result == [0]
	with open(out / 'x') as f:
		assert f.read() == 'x1'


def test_a_prunes_list_with_no_folder_makes_no_reader_wait(job, monkeypatch):
	# the oldest went at its rename, and its list goes after the removal: no reader waits on that
	info = two_versions(job)
	os.makedirs(rv.state_dir_path(), exist_ok=True)
	os.rename(info[0].path, os.path.join(job.job_vault, rv.STAGING_NAME, 'gone'))
	monkeypatch.setattr(rv, 'backup_is_running', lambda job_name, state_dir=None: True)
	monkeypatch.setattr(rv, 'wait_for_backup', lambda job_name, state_dir=None: pytest.fail('a wait'))
	assert [version.number for version in rv.versions_of_a_batch(job.job_vault, 'job')] == [1]


# --- a real pool ---

@contextlib.contextmanager
def real_pool(size_mib=256):
	"""
	A folder under REVERB_SCRATCH to make a job in, its vault a mergerfs over two new f2fs images, with the options the pool tests run with. The
	monitored tree stays off the pool: a pool moves the mtime of folders above a new entry, and no event says so.
	"""
	root = tempfile.mkdtemp(prefix='pool-writer-', dir=SCRATCH)
	vault = os.path.join(root, 'vault')
	os.mkdir(vault)
	try:
		with LoopImage(os.path.join(root, 'a'), size_mib) as first, LoopImage(os.path.join(root, 'b'), size_mib) as second:
			subprocess.run(['mergerfs', f'{first.mount_point}:{second.mount_point}', vault, '-o', MERGERFS_OPTIONS], check=True)
			try:
				yield root
			finally:
				subprocess.run(['fusermount3', '-u', vault], check=True)
	finally:
		shutil.rmtree(root)


@needs_mergerfs
@pytest.mark.parametrize('only_sync_attributes', [False, True], ids=['attributes_copied', 'only_sync_attributes'])
def test_every_kill_point_on_a_pool(only_sync_attributes):
	with real_pool() as root:
		vault = prepare(root, only_sync_attributes=only_sync_attributes)
		restore(vault)
		wrong = sweep(vault, default=int(os.environ.get('REVERB_POOL_KILL_POINTS', 110)))
		assert not wrong, f'{len(wrong)} kill points wrong: {wrong[:4]}'


@needs_mergerfs
def test_a_conversion_on_a_pool_reads_the_same(v054):
	with real_pool() as root:
		job = create_job(root)
		v054.build(job, SMALL, keep_n_versions=9)
		before = expected(job)
		assert migrate(job) is True
		assert check_vault(job.job_vault, before, set()) == []
		assert view_truth.wrong_lists(job.job_vault) == []
		assert not any(plain_links(job).values())


@needs_mergerfs
def test_hard_links_on_a_pool_read_as_one_inode_and_their_count_as_it_is():
	with real_pool() as root:
		first, second = os.path.join(root, 'vault', 'first'), os.path.join(root, 'vault', 'second')
		with open(first, 'w') as f:
			f.write('x')
		os.link(first, second)
		# what same_landing() goes by
		assert rv.same_inode(os.lstat(first), os.lstat(second))
		assert rv.links_now(first) == rv.links_now(second) == 2
		os.lstat(second)
		os.remove(first)
		# the count an lstat would show for a second is 2: mergerfs keeps each name's attributes that long
		assert rv.links_now(second) == 1
