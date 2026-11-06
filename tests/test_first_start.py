'''
A job's first start on a vault of 0.54 (spec sections 2.8, 3.1, 4.4 and 7, plan S1 and S2): the backuper's scan runs the 0.54 rules,
finishes a pool's cut prune and converts the vault, all under the job's locks, which go before the wait for the monitored
path; and Keep 1 Complete Backup means what it means on design R. The vaults are real: tests/legacy054.py builds them.

Each step is observed from inside the conversion or from an event it sets, never by a sleep: a thread's order is forced, not assumed.
'''
import fcntl
import json
import os
import threading
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.crash_batches import put_text
from tests.harness import create_job, run_backup, seed_monitor, wait_until, write_incomplete_version, write_rule
from tests.test_r_scan import build_base, cut_batch, KEPT, kept_versions_wrong
from tests.test_migration import SMALL, cli_differences, expected, folders_of, plain_links
from tests.test_vault_scan import cut_off_at_the_swap, three_versions
from tests.vault_oracle import check_vault, sizes_by_newest_holder
from tests.version_view_ground_truth import committed_folders

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='the root record is a trusted.* attribute, and a file is chowned')

KEEP_LINE = 'Keep 1 Complete Backup is False for {}: from 0.55 its first version is always a complete copy'
RULE = dict(keep_one_complete_backup=True, only_sync_attributes=False, keep_n_versions=9, backup_size_limit='0')


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	os.makedirs(rv.state_dir_path(), exist_ok=True)


@pytest.fixture
def small(tmp_path, v054):
	'''A 0.54 vault of V0 whole and V1, V2 of chain links.'''
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_n_versions=9)
	return job


def committed_versions(job):
	'''The committed versions' folders, the oldest first, by their lists: a list's name on design R is no du of its folder, which the harness's reads.'''
	return [os.path.join(job.job_vault, name) for name in reversed(committed_folders(job.job_vault))] if os.path.isdir(job.job_vault) else []


def wait_for_committed_count(job, count, timeout=10):
	wait_until(lambda: len(committed_versions(job)) >= count, timeout=timeout, message=f'expected {count} committed versions, got {committed_versions(job)}')
	return committed_versions(job)


def control_of(job):
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	return control


def start(job, control, monitor_flag=None, **rule):
	'''The job's backuper on a thread, with nothing queued: what a start with nothing to resume runs, the batch being a full comparison.'''
	if monitor_flag is None:
		monitor_flag = threading.Event()
		monitor_flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, rv.ChangeEventQueue(job.monitor), threading.Lock(), job.monitor, job.vault, 'N/A', threading.Event(), monitor_flag),
		kwargs=dict(job=control, **{**RULE, **rule}), daemon=True)
	thread.start()
	return thread


def stop(control, *threads):
	control.fail('test done')
	for thread in threads:
		thread.join(timeout=10)
		assert not thread.is_alive()


def ended(control, thread):
	'''Wait for an attempt that ends on its own.'''
	thread.join(timeout=10)
	assert not thread.is_alive()
	return control.failure


def layout_is_r(job):
	wait_until(lambda: rv.recorded_layout(job.job_vault) == 'r', timeout=10, message='the vault was not converted')


def before_the_conversion(monkeypatch, look):
	'''Run look() as the migration is called, with what it gives kept in the list returned, as an assert on the backuper's thread would only fail its job.'''
	seen = []
	real = rv.migrate_job_vault
	def migrate(*args, **kwargs):
		seen.append(look())
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'migrate_job_vault', migrate)
	return seen


def batches(monkeypatch, look=lambda *args, **kwargs: None):
	'''Run look(backup_entries, **do_backup's keywords) as each do_backup begins, with what it gives kept in the list returned.'''
	seen = []
	real = rv.do_backup
	def do_backup(*args, **kwargs):
		seen.append(look(*args, **kwargs))
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'do_backup', do_backup)
	return seen


def lock_held(job, kind):
	fd = os.open(rv.job_lock_path(job.job_name, kind), os.O_RDWR | os.O_CREAT, 0o600)
	try:
		try:
			fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
		except BlockingIOError:
			return True
		return False
	finally:
		os.close(fd)


def locks_held(job):
	return {kind: lock_held(job, kind) for kind in ('backup', 'restore')}


def test_a_054_vault_at_start_is_converted(small):
	# nothing asks for it but the default: a vault 0.54 wrote is on R once its job has started
	assert rv.NEW_VAULT_LAYOUT == 'r'
	before = expected(small)
	assert any(plain_links(small).values())
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert check_vault(small.job_vault, before, set()) == []
	assert not any(plain_links(small).values())


def test_a_054_vault_converts_at_its_first_start_under_the_locks(small, monkeypatch):
	before = expected(small)
	assert any(plain_links(small).values())
	held = before_the_conversion(monkeypatch, lambda: locks_held(small))
	# the monitored path is not ready: the conversion does not wait for it, and the locks do not stay for that wait
	monitor_ready = threading.Event()
	control = control_of(small)
	thread = start(small, control, monitor_ready)
	layout_is_r(small)
	wait_until(lambda: locks_held(small) == {'backup': False, 'restore': False}, timeout=10, message='the locks stayed for the wait for the monitored path')
	assert held == [{'backup': True, 'restore': True}]
	assert check_vault(small.job_vault, before, set()) == []
	assert cli_differences(small.job_vault, before) == []
	assert not any(plain_links(small).values())
	assert os.listdir(rv.staging_path(small.job_vault)) == []
	put_text(small.monitor, 'new.txt', 'new')
	monitor_ready.set()
	wait_for_committed_count(small, 4)
	stop(control, thread)
	assert check_vault(small.job_vault, {**before, 3: expected(small)[3]}, set()) == []


def test_the_conversion_runs_at_the_start_and_only_there(small, monkeypatch):
	calls = before_the_conversion(monkeypatch, lambda: None)
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	# the second start finds it done
	put_text(small.monitor, 'new.txt', 'new')
	control = control_of(small)
	thread = start(small, control)
	wait_for_committed_count(small, 4)
	stop(control, thread)
	assert calls == [None]


@pytest.mark.old_writer
def test_no_conversion_while_new_vaults_are_054(small, monkeypatch):
	calls = before_the_conversion(monkeypatch, lambda: None)
	put_text(small.monitor, 'new.txt', 'new')
	control = control_of(small)
	thread = start(small, control)
	wait_for_committed_count(small, 4)
	stop(control, thread)
	assert calls == [] and rv.recorded_layout(small.job_vault) is None


def test_a_new_vault_is_no_conversion(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	os.makedirs(job.job_vault)
	seed_monitor(job, {'a.txt': 'a'})
	calls = before_the_conversion(monkeypatch, lambda: None)
	control = control_of(job)
	thread = start(job, control)
	wait_for_committed_count(job, 1)
	stop(control, thread)
	assert calls == [] and rv.recorded_layout(job.job_vault) == 'r'


@pytest.mark.parametrize('cut', ['orphan', 'manifest', 'swap'])
def test_the_054_rules_run_first(tmp_path, v054, monkeypatch, cut):
	if cut == 'orphan':
		job = create_job(str(tmp_path))
		v054.build(job, SMALL, keep_n_versions=9)
		left = write_incomplete_version(job, 3, {'a.txt': 'partial'})
	else:
		# 0.54's commit, cut after its manifest named the version: the manifest keeps that name when the 0.54 rules take the version away
		monkeypatch.setattr(rv, 'NEW_VAULT_LAYOUT', '0.54')
		job = three_versions(tmp_path)
		left = cut_off_at_the_swap(job, cut)
		monkeypatch.setattr(rv, 'NEW_VAULT_LAYOUT', 'r')
	seen = before_the_conversion(monkeypatch, lambda: (os.path.lexists(left), rv.recorded_latest_version(job.job_vault).number, os.path.lexists(rv.staging_path(job.job_vault))))
	control = control_of(job)
	thread = start(job, control)
	layout_is_r(job)
	stop(control, thread)
	assert seen == [(False, 2, False)]
	if cut != 'orphan':
		# the name the manifest kept stops no scan, and the cut commit's change makes its version again
		control = control_of(job)
		thread = start(job, control)
		newest = wait_for_committed_count(job, 4)[-1]
		stop(control, thread)
		assert open(os.path.join(newest, 'keep')).read() == 'cut'
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict)[:3] == [0, 1, 2]


def on_a_pool(monkeypatch):
	monkeypatch.setattr(rv.PoolGuard, 'covers', lambda self, path: True)
	monkeypatch.setattr(rv, 'flush_vault_disks', lambda job_vault, job_name: [])


def cut_prune(job, marker):
	'''A pool's prune of V0 cut before its flush: its marker as marker() left it, and V1 lost its link to a.txt on a disk that came back without it.'''
	v0, v1 = committed_versions(job)[:2]
	marker(v0)
	os.remove(os.path.join(v1, 'a.txt'))
	return v0, v1


def test_a_pool_prune_marker_is_finished_before_the_conversion(small, monkeypatch):
	wanted = expected(small)
	del wanted[0]
	on_a_pool(monkeypatch)
	v0, v1 = cut_prune(small, lambda v0: rv.write_prune_marker(small.job_vault, os.path.basename(v0)))
	seen = before_the_conversion(monkeypatch, lambda: (os.path.lexists(v0), os.path.isfile(os.path.join(v1, 'a.txt')), rv.read_prune_marker(small.job_vault)))
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert seen == [(False, True, None)]
	assert check_vault(small.job_vault, wanted, set()) == []
	assert not os.path.lexists(os.path.join(small.job_vault, rv.PRUNE_MARKER_FILE_NAME))


def test_an_unreadable_marker_on_a_pool_removes_no_version(small, monkeypatch):
	# a write of the marker torn by a power loss: it is flushed before the walk and cleared after the flush, so no link is left to repair
	before = expected(small)
	on_a_pool(monkeypatch)
	v0 = committed_versions(small)[0]
	marker = os.path.join(small.job_vault, rv.PRUNE_MARKER_FILE_NAME)
	rv.write_prune_marker(small.job_vault, os.path.basename(v0))
	with open(marker, 'w') as f:
		f.write('{"walk')
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert os.path.lexists(v0)
	assert check_vault(small.job_vault, before, set()) == []
	assert not os.path.lexists(marker)


@pytest.mark.parametrize('names', ['nothing', 'another'])
def test_a_marker_naming_no_cut_prune_of_the_oldest_removes_no_version(small, monkeypatch, names):
	before = expected(small)
	on_a_pool(monkeypatch)
	rv.write_prune_marker(small.job_vault, None if names == 'nothing' else os.path.basename(committed_versions(small)[1]))
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert check_vault(small.job_vault, before, set()) == []


def test_a_marker_off_a_pool_finishes_no_prune(small):
	before = expected(small)
	rv.write_prune_marker(small.job_vault, os.path.basename(committed_versions(small)[0]))
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert check_vault(small.job_vault, before, set()) == []


def test_a_cut_prune_that_cannot_finish_holds_the_conversion_back(small, monkeypatch):
	# history is reading: the prune is postponed, and converting now would lose what its marker says is to be repaired
	wanted = expected(small)
	del wanted[0]
	on_a_pool(monkeypatch)
	v0, v1 = cut_prune(small, lambda v0: rv.write_prune_marker(small.job_vault, os.path.basename(v0)))
	calls = before_the_conversion(monkeypatch, lambda: None)
	fd = os.open(rv.job_lock_path(small.job_name, 'history'), os.O_RDWR | os.O_CREAT, 0o600)
	fcntl.flock(fd, fcntl.LOCK_SH)
	control = control_of(small)
	thread = start(small, control)
	failure = ended(control, thread)
	os.close(fd)
	assert failure is not None and 'prune' in failure.reason
	assert calls == [] and not failure.permanent
	assert not os.path.lexists(rv.staging_path(small.job_vault)) and rv.read_prune_marker(small.job_vault) == os.path.basename(v0)
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert check_vault(small.job_vault, wanted, set()) == []


@pytest.mark.parametrize('cell, line', [('False', True), ('no', True), ('True', False), ('none', False)])
def test_keep_one_is_read_as_true(cell, line, capsys):
	assert rv.read_keep_one_complete_backup(cell, 'job') is True
	out = capsys.readouterr()
	assert (out.out + out.err).count(KEEP_LINE.format('job')) == (1 if line else 0)


@pytest.mark.process
def test_keep_one_false_logs_one_line_and_copies_the_first_version(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello', 'd/b.txt': 'b'})
	write_rule(job, keep_one_complete_backup='False')
	proc = run_reverberator(job.rule_path)
	v0 = wait_for_committed_count(job, 1, timeout=15)[0]
	wait_until(lambda: 'Started job' in ''.join(proc._out_buf + proc._err_buf), timeout=10, message='the daemon did not say it started')
	output = ''.join(proc._out_buf + proc._err_buf)
	assert len([line for line in output.splitlines() if KEEP_LINE.format(job.job_name) in line]) == 1
	for rel in ('a.txt', 'd/b.txt'):
		assert not os.path.islink(os.path.join(v0, rel))
		assert os.path.isfile(os.path.join(v0, rel))


@pytest.mark.process
def test_keep_one_true_says_nothing(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=15)
	assert 'Keep 1 Complete Backup is False' not in ''.join(proc._out_buf + proc._err_buf)


def row_of(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel)
	finally:
		manifest.close()


@pytest.mark.parametrize('sync_attributes', [False, True])
def test_a_referenced_row_counts_as_different(tmp_path, v054, sync_attributes):
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_one_complete_backup=False, keep_n_versions=9, only_sync_attributes=sync_attributes)
	# a comparison reads the rows of the referenced copy, which it wrote unread: no change, so no version
	v054.run(job, OrderedDict(), keep_one_complete_backup=False, keep_n_versions=9, only_sync_attributes=sync_attributes, backup_size_limit='0')
	names = folders_of(job)
	assert len(names) == 3
	assert row_of(job, 'a.txt').kind == 'r' and row_of(job, 'd/e/f.txt').kind == 'r'
	control = control_of(job)
	thread = start(job, control, only_sync_attributes=sync_attributes)
	wait_for_committed_count(job, 4)
	stop(control, thread)
	newest = committed_versions(job)[-1]
	for rel, text in (('a.txt', 'a0'), ('d/e/f.txt', 'f0')):
		path = os.path.join(newest, rel)
		assert not os.path.islink(path) and open(path).read() == text
		assert row_of(job, rel).kind == 'f'
		# restore says what it says today of the versions that only link to the monitored file
		for number in (0, 2):
			version = os.path.join(job.job_vault, names[number])
			resolved = rv.resolve_version_entry(job.job_vault, version, rel, job.monitor)
			assert resolved.kind == 'referenced' and resolved.detail == os.path.join(job.monitor, rel)
			assert rv.restore_failure(resolved, rv.KeptVersion(number, version, names[number], 0.0, 0, 0, '')) == 'not held in the vault (referenced backup)'
	# copied once: the next comparison finds nothing
	run_backup(job, only_sync_attributes=sync_attributes, keep_n_versions=9)
	assert len(committed_versions(job)) == 4


def test_a_referenced_row_stays_the_same_on_054(tmp_path, v054):
	job = create_job(str(tmp_path))
	v054.build(job, SMALL, keep_one_complete_backup=False, keep_n_versions=9)
	run_backup(job, keep_n_versions=9)
	assert len(committed_versions(job)) == 3


@pytest.mark.parametrize('failure', [OSError(5, 'Input/output error'), rv.JobFailure('a step of the conversion failed'), rv.VaultScanError('the vault cannot be read')])
def test_one_job_failing_its_conversion_leaves_the_others_running(tmp_path, v054, monkeypatch, failure):
	bad = create_job(str(tmp_path / 'bad'), 'bad')
	good = create_job(str(tmp_path / 'good'), 'good')
	for job in (bad, good):
		v054.build(job, SMALL, keep_n_versions=9)
	before = expected(bad)
	real = rv.migrate_job_vault
	def migrate(job_vault, manifest, job_name, stop=None):
		if job_name == 'bad':
			raise failure
		return real(job_vault, manifest, job_name, stop)
	monkeypatch.setattr(rv, 'migrate_job_vault', migrate)
	put_text(bad.monitor, 'new.txt', 'new')
	put_text(good.monitor, 'new.txt', 'new')
	bad_control, good_control = control_of(bad), control_of(good)
	bad_thread, good_thread = start(bad, bad_control), start(good, good_control)
	assert ended(bad_control, bad_thread) is not None
	# the error first, as status cuts a reason short; a JobFailure says its own
	assert bad_control.failure.reason.startswith('[Errno 5] Input/output error: the conversion of') if isinstance(failure, OSError) else bad_control.failure.reason == failure.reason
	assert not bad_control.failure.permanent
	wait_for_committed_count(good, 4)
	assert good_control.should_run() and rv.GREEN_LIGHT.is_set()
	assert len(committed_versions(bad)) == 3 and check_vault(bad.job_vault, before, set()) == []
	stop(good_control, good_thread)
	# the job's next attempt
	monkeypatch.setattr(rv, 'migrate_job_vault', real)
	bad_control = control_of(bad)
	bad_thread = start(bad, bad_control)
	wait_for_committed_count(bad, 4)
	stop(bad_control, bad_thread)
	assert rv.recorded_layout(bad.job_vault) == 'r'


def job_record(tmp_path):
	try:
		with open(tmp_path / 'state' / 'job-job.json') as f:
			return json.load(f)
	except (OSError, ValueError):
		return {}


def test_status_shows_a_conversion_in_progress(small, tmp_path, monkeypatch):
	rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), small.rule_path)
	running, go_on = threading.Event(), threading.Event()
	real = rv.migrate_job_vault
	def migrate(*args, **kwargs):
		running.set()
		assert go_on.wait(timeout=10)
		return real(*args, **kwargs)
	monkeypatch.setattr(rv, 'migrate_job_vault', migrate)
	monitor_ready = threading.Event()
	control = control_of(small)
	thread = start(small, control, monitor_ready)
	assert running.wait(timeout=10)
	wait_until(lambda: job_record(tmp_path).get('detail') == 'converting the vault from 0.54', timeout=5, message=f'no conversion in the status: {job_record(tmp_path)}')
	record = job_record(tmp_path)
	assert 'converting the vault from 0.54' in rv.job_state_phrase(record, True, 0)
	go_on.set()
	layout_is_r(small)
	wait_until(lambda: 'converting' not in job_record(tmp_path).get('detail', ''), timeout=5, message='the status kept saying it converts')
	stop(control, thread)


def test_a_stop_during_the_conversion_ends_the_attempt_before_any_batch(small, monkeypatch):
	before = expected(small)
	control = control_of(small)
	real = rv.materialize_version
	def stopped(job_vault, name, stop=None):
		control.fail('stopping')
		return real(job_vault, name, stop)
	monkeypatch.setattr(rv, 'materialize_version', stopped)
	ran = batches(monkeypatch)
	thread = start(small, control)
	failure = ended(control, thread)
	assert failure.reason == 'stopping' and ran == []
	assert rv.recorded_layout(small.job_vault) is None
	assert expected(small) == before
	monkeypatch.setattr(rv, 'materialize_version', real)
	put_text(small.monitor, 'new.txt', 'new')
	control = control_of(small)
	thread = start(small, control)
	wait_for_committed_count(small, 4)
	stop(control, thread)
	assert rv.recorded_layout(small.job_vault) == 'r'


def test_a_conversion_that_failed_goes_on_at_the_next_attempt_after_the_r_scan(small, monkeypatch):
	# what the first attempt did stands: the staging it made gives the vault the R scan, which empties what it left there
	before = expected(small)
	real = rv.materialize_version
	done = []
	def fails_second(job_vault, name, stop=None):
		if done:
			os.mkdir(os.path.join(rv.staging_path(job_vault), 'm'))
			raise OSError(28, 'No space left on device')
		done.append(name)
		return real(job_vault, name, stop)
	monkeypatch.setattr(rv, 'materialize_version', fails_second)
	ran = batches(monkeypatch)
	control = control_of(small)
	failure = ended(control, start(small, control))
	assert 'No space left on device' in failure.reason and ran == []
	monkeypatch.setattr(rv, 'materialize_version', real)
	control = control_of(small)
	thread = start(small, control)
	layout_is_r(small)
	stop(control, thread)
	assert check_vault(small.job_vault, before, set()) == []
	assert not any(plain_links(small).values())


def test_the_first_batch_reads_the_sizes_the_conversion_left(small, monkeypatch):
	put_text(small.monitor, 'new.txt', 'new')
	# as the batch begins, as it goes on to change what it is given
	seen = batches(monkeypatch, lambda entries, vaultInfo, **kwargs: ({number: (entry.size, entry.inode) for number, entry in vaultInfo.vault_info_dict.items()},
		vaultInfo.vault_size, vaultInfo.vault_inodes, sizes_by_newest_holder(small.job_vault)))
	control = control_of(small)
	thread = start(small, control)
	wait_for_committed_count(small, 4)
	stop(control, thread)
	sizes, vault_size, vault_inodes, wanted = seen[0]
	# a list's name rounds a size (format_bytes()): what the name says, not the bytes, is what a scan reads
	assert sizes.keys() == wanted.keys() and all(sizes[number][1] == wanted[number][1] and abs(sizes[number][0] - wanted[number][0]) <= max(wanted[number][0] // 100, 8) for number in wanted)
	assert (vault_size, vault_inodes) == (sum(size for size, _ in sizes.values()), sum(inodes for _, inodes in sizes.values()))


def test_a_lost_manifest_on_r_gets_its_layout_before_any_batch(tmp_path, monkeypatch):
	# the batch reads links by the manifest's layout (record_dirty_entries(), compare_scopes()): a link of the user's with a chain link's text
	# must stay the link, which the rows of VaultMoves would not say on a vault still 'converting'
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job, keep_n_versions=9)
	seed_monitor(job, {'a.txt': 'b'})
	run_backup(job, keep_n_versions=9)
	versions = committed_versions(job)
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	before = expected(job)
	text = f'../{os.path.basename(versions[0])}/user.lnk'
	os.symlink(text, os.path.join(job.monitor, 'user.lnk'))
	layouts = batches(monkeypatch, lambda *args, **kwargs: rv.recorded_layout(job.job_vault))
	control = control_of(job)
	thread = start(job, control)
	wait_for_committed_count(job, 3)
	stop(control, thread)
	assert layouts[0] == 'r'
	assert check_vault(job.job_vault, {**before, 2: expected(job)[2]}, set()) == []
	assert row_of(job, 'user.lnk').kind == 'l' and row_of(job, 'user.lnk').link == text
	assert os.readlink(os.path.join(committed_versions(job)[-1], 'user.lnk')) == text


def test_a_lost_manifest_with_a_cut_tree_rolls_forward_after_the_start(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	wanted = build_base(job, **KEPT)
	tree = cut_batch(job)
	os.remove(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME))
	seen = batches(monkeypatch, lambda entries, vaultInfo, **kwargs: (vaultInfo.tree, rv.recorded_layout(job.job_vault)))
	control = control_of(job)
	thread = start(job, control, **KEPT)
	wait_for_committed_count(job, len(wanted) + 1)
	stop(control, thread)
	assert seen[0] == (tree, 'r')
	assert kept_versions_wrong(job, wanted) == []
