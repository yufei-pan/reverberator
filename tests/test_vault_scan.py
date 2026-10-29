'''
The vault scan (get_vault_info(), which the job runs before any write) deletes nothing unless it is certain (Task 2b):
any error fails the scan as a whole, no partial or empty view reaches a backup, change lists are matched to their
folders by name before any parse, and duplicate version numbers fail the scan. haiku9 p1's inputs.
'''
import errno
import shutil
import subprocess
import sys
import os
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, event_entry, write_committed_version, write_incomplete_version
from tests.test_log_text import alerting_lines

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_folders():
	rv.REAL_VAULT_FOLDERS.clear()


def three_versions(tmp_path):
	'''V0 holding D/secret and keep, then V1 and V2, each modifying keep: V1's D/secret links to V0's, V2's to V1's.'''
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	run_backup(job)
	for i in (1, 2):
		with open(os.path.join(job.monitor, 'keep'), 'w') as f:
			f.write(f'v{i}')
		run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2]
	return job


def version(job, number):
	return [kept for kept in rv.list_versions(job.job_vault) if kept.number == number][0]


def vault_names(job):
	'''What the job vault holds of versions and change lists: each by name, and every entry of each folder, a link by its text.'''
	held = []
	for name in sorted(name for name in os.listdir(job.job_vault) if name.startswith('V')):
		path = os.path.join(job.job_vault, name)
		held.append(name)
		if os.path.isdir(path) and not os.path.islink(path):
			for entry, rel, is_dir in rv.iter_tree_entries(path):
				held.append((name, rel, 'folder' if is_dir else os.readlink(entry) if os.path.islink(entry) else open(entry, 'rb').read()))
	return held


def every_folder_reads_right(job):
	for name in os.listdir(job.job_vault):
		path = os.path.join(job.job_vault, name)
		if name.startswith('V') and os.path.isdir(path):
			assert open(os.path.join(path, 'D/secret')).read() == 'secret', name


class Entry:
	'''A DirEntry of the job vault whose is_dir() and is_file() raise code, as a stat error other than ENOENT does.'''
	def __init__(self, entry, code=None):
		self._entry, self._code = entry, code
		self.name, self.path = entry.name, entry.path

	def _check(self):
		if self._code is not None:
			raise OSError(self._code, os.strerror(self._code), self.path)

	def is_dir(self, *, follow_symlinks=True):
		self._check()
		return self._entry.is_dir(follow_symlinks=follow_symlinks)

	def is_file(self, *, follow_symlinks=True):
		self._check()
		return self._entry.is_file(follow_symlinks=follow_symlinks)

	def is_symlink(self):
		return self._entry.is_symlink()

	def stat(self, *, follow_symlinks=True):
		self._check()
		return self._entry.stat(follow_symlinks=follow_symlinks)


def listing(monkeypatch, job, fail=None, first=None, scandir_code=None):
	'''
	os.scandir() of the job vault with is_dir()/is_file() of the entries named in fail ({name: errno}) raising, the
	entries for which first(name) is true listed first, and with scandir_code, the listing itself failing.
	'''
	real_scandir = os.scandir
	def scandir(path='.'):
		if os.path.abspath(os.fspath(path)) != job.job_vault:
			return real_scandir(path)
		if scandir_code is not None:
			raise OSError(scandir_code, os.strerror(scandir_code), path)
		entries = list(real_scandir(path))
		if first is not None:
			entries.sort(key=lambda entry: 0 if first(entry.name) else 1)
		return iter([Entry(entry, (fail or {}).get(entry.name)) for entry in entries])
	monkeypatch.setattr(rv.os, 'scandir', scandir)


def backup_keeping_two(job):
	'''A backup that would remove V0 (keep 2): what do_backup() gives, or the JobFailure it raises.'''
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('v3')
	try:
		info, manifest, committed = rv.do_backup(OrderedDict([event_entry(job, 'keep', 'modify')]), job_name=job.job_name,
			monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True,
			keep_n_versions=2, backup_size_limit='0')
	except rv.JobFailure as e:
		return e
	manifest.close()
	return info, committed


def assert_nothing_done(job, before, outcome):
	'''The scan failed: no version, change list or entry of a version went or changed, and none was written.'''
	assert isinstance(outcome, rv.JobFailure), outcome
	assert vault_names(job) == before


def change_list_name(job, number):
	return os.path.basename(version(job, number).change_list)


@pytest.mark.parametrize('code', [errno.EIO, errno.EACCES, errno.ENOTCONN], ids=['EIO', 'EACCES', 'ENOTCONN'])
@pytest.mark.parametrize('what', ['change_list', 'folder'])
def test_an_entry_that_cannot_be_looked_at_fails_the_scan(tmp_path, monkeypatch, code, what):
	# haiku9 p1: the stat error came out of DirEntry.is_file() (is_dir()) outside the scan's inner try, so the scan
	# returned what it had: with V2 listed first, V0 and V2, and a backup keeping 2 removed V0 with V2 as the next version
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	before = vault_names(job)
	name = change_list_name(job, 1) if what == 'change_list' else v1.name
	listing(monkeypatch, job, fail={name: code}, first=lambda listed: not listed.startswith('V1--'))
	with pytest.raises(rv.JobFailure) as failure:
		rv.get_vault_info(job.job_vault)
	assert os.strerror(code) in failure.value.reason
	assert vault_names(job) == before
	assert_nothing_done(job, before, backup_keeping_two(job))
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]


@pytest.mark.parametrize('code', [errno.EIO, errno.EACCES], ids=['EIO', 'EACCES'])
def test_an_entry_that_cannot_be_looked_at_first_never_makes_a_new_vault(tmp_path, monkeypatch, code):
	# haiku9 p1: reached first, the error left the scan empty, and the backup wrote a whole V0 beside the old one
	job = three_versions(tmp_path)
	before = vault_names(job)
	name = change_list_name(job, 1)
	listing(monkeypatch, job, fail={name: code}, first=lambda listed: listed == name)
	assert_nothing_done(job, before, backup_keeping_two(job))


@pytest.mark.parametrize('code', [errno.EIO, errno.EACCES, errno.ENOTCONN], ids=['EIO', 'EACCES', 'ENOTCONN'])
def test_a_job_vault_that_cannot_be_listed_never_makes_a_new_vault(tmp_path, monkeypatch, code):
	job = three_versions(tmp_path)
	before = vault_names(job)
	listing(monkeypatch, job, scandir_code=code)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_job_vault_that_cannot_be_looked_at_never_makes_a_new_vault(tmp_path, monkeypatch):
	# only "not there" means there is no vault yet: an EIO looking at it made the scan empty, and a backup a new V0
	job = three_versions(tmp_path)
	before = vault_names(job)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if os.path.abspath(os.fspath(path)) == job.job_vault:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_job_vault_that_is_not_there_is_a_new_vault(tmp_path):
	job = create_job(str(tmp_path))
	info = rv.get_vault_info(job.job_vault)
	assert dict(info.vault_info_dict) == {} and (info.vault_size, info.vault_inodes) == (0, 0)


def renamed(job, number, change):
	'''V<number>'s folder and change list renamed by change(name), each.'''
	kept = version(job, number)
	folder, change_list = os.path.join(job.job_vault, change(kept.name)), os.path.join(job.job_vault, change(os.path.basename(kept.change_list)))
	os.rename(kept.path, folder)
	os.rename(kept.change_list, change_list)
	return folder, change_list


@pytest.mark.chain_ground_truth_allows('refused_chain', reason='V1 is renamed by hand, so the links of V2 name no version')
def test_a_version_number_that_is_not_ascii_digits_fails_the_scan(tmp_path, monkeypatch):
	# haiku9 p1: isdigit() takes V², int() then raised outside the inner try: the scan returned V0 and V2, and a backup
	# keeping 2 removed V0, whose copy V²'s and V2's D/secret named
	job = three_versions(tmp_path)
	folder, change_list = renamed(job, 1, lambda name: name.replace('V1--', 'V²--', 1))
	before = vault_names(job)
	listing(monkeypatch, job, first=lambda listed: not listed.startswith('V²'))
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(folder) and os.path.isfile(change_list)


def test_a_folder_whose_number_is_not_ascii_digits_and_has_no_change_list_is_left_alone(tmp_path):
	job = three_versions(tmp_path)
	odd = os.path.join(job.job_vault, version(job, 1).name.replace('V1--', 'V٣--', 1))
	os.makedirs(odd)
	info = rv.get_vault_info(job.job_vault)
	assert list(info.vault_info_dict) == [0, 1, 2] and os.path.isdir(odd)


@pytest.mark.chain_ground_truth_allows('refused_chain', reason='V1 is renamed by hand, so the links of V2 name no version')
@pytest.mark.parametrize('first', ['change_list', 'folder'])
@pytest.mark.parametrize('bad', ['non_utf8', 'unparsable'])
def test_a_timestamp_that_does_not_parse_fails_the_scan_in_either_order(tmp_path, monkeypatch, first, bad):
	# haiku9 p1: the list's parse error was logged and the folder became an orphan, rm -rf'd when listed after the list
	job = three_versions(tmp_path)
	def change(name):
		folder_part, sep, rest = name.partition('--')[2].partition('--')
		stamp = folder_part[:-5] + ('\udcff' if bad == 'non_utf8' else 'X') + folder_part[-4:]
		return name.partition('--')[0] + '--' + stamp + sep + rest
	folder, change_list = renamed(job, 1, change)
	before = vault_names(job)
	wanted = os.path.basename(change_list if first == 'change_list' else folder)
	listing(monkeypatch, job, first=lambda listed: listed == wanted)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(folder) and os.path.isfile(change_list)


def list_renames(cl):
	'''Hand renamed change list names that name no folder, as haiku9 p1 made them.'''
	body = rv.strip_suffix(cl, rv.CONTENT_FILE_EXTENSION_NAME)
	prefix, _, size_inodes = body.rpartition('--')
	size, _, inodes = size_inodes.rpartition('-')
	zone = prefix[-6:]
	assert zone[0] == '_' and zone[1] in '+-', prefix
	return {
		# a -- in the size: the name's last -- moves into its folder part
		'dashed_size': prefix + '--' + size.replace('.', '--') + '-' + inodes + rv.CONTENT_FILE_EXTENSION_NAME,
		# the timestamp's zone cut: the folder part names no folder there is
		'cut_zone': prefix[:-6] + '--' + size_inodes + rv.CONTENT_FILE_EXTENSION_NAME,
		# the extension cut
		'cut_extension': body,
		'cut_short': cl[:len(prefix) + 6] + rv.CONTENT_FILE_EXTENSION_NAME,
	}


@pytest.mark.parametrize('kind', ['dashed_size', 'cut_zone', 'cut_extension', 'cut_short'])
@pytest.mark.parametrize('first', ['change_list', 'folder'])
def test_a_change_list_whose_name_names_no_folder_keeps_its_version(tmp_path, monkeypatch, kind, first):
	# haiku9 p1: the list was deleted, and its folder removed as an orphan, with every copy V2's links name
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	new_name = list_renames(os.path.basename(v1.change_list))[kind]
	os.rename(v1.change_list, os.path.join(job.job_vault, new_name))
	before = vault_names(job)
	wanted = new_name if first == 'change_list' else v1.name
	listing(monkeypatch, job, first=lambda listed: listed == wanted)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert vault_names(job) == before
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(v1.path) and os.path.isfile(os.path.join(job.job_vault, new_name))


def test_a_change_list_that_names_no_folder_and_can_be_no_versions_is_kept(tmp_path, capsys):
	# with every version folder's own list found, a list whose name does not parse can be none of theirs: it is kept and
	# said, and the scan goes on
	job = three_versions(tmp_path)
	stray = os.path.join(job.job_vault, 'V7--notes' + rv.CONTENT_FILE_EXTENSION_NAME)
	open(stray, 'w').close()
	capsys.readouterr()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert os.path.isfile(stray) and 'V7--notes' in capsys.readouterr().out


@pytest.mark.parametrize('first', ['copy', 'original'])
def test_two_version_folders_with_one_number_fail_the_scan(tmp_path, monkeypatch, first):
	# haiku9 p1: the second folder's entry overwrote the first's, which could then be rm -rf'd as an orphan
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	stamp = v0.name.partition('--')[2]
	other = 'V0--' + ('2020' if not stamp.startswith('2020') else '2019') + stamp[4:]
	os.rename(v0.path, os.path.join(job.job_vault, other))
	os.rename(v0.change_list, os.path.join(job.job_vault, os.path.basename(v0.change_list).replace(v0.name, other, 1)))
	write_committed_version(job, 0, {'D/secret': 'secret'}, timestamp=stamp)
	before = vault_names(job)
	listing(monkeypatch, job, first=lambda listed: listed.startswith(other if first == 'copy' else v0.name))
	with pytest.raises(rv.JobFailure) as failure:
		rv.get_vault_info(job.job_vault)
	assert 'V0' in failure.value.reason
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_two_change_lists_for_one_folder_fail_the_scan(tmp_path):
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	second = rv.change_list_path(v1.path, 1, 1)
	assert second != v1.change_list
	open(second, 'w').close()
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_change_list_whose_folder_is_gone_is_deleted(tmp_path):
	# Task 2b fix round 2: only below the oldest committed version, as a removal cut short leaves it
	job = three_versions(tmp_path)
	gone = prune_keeping_v0_stale_list(job)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2]
	assert not os.path.exists(gone)


@pytest.mark.parametrize('code', [errno.EIO, errno.EACCES], ids=['EIO', 'EACCES'])
def test_a_change_list_whose_folder_cannot_be_looked_at_fails_the_scan(tmp_path, monkeypatch, code):
	job = three_versions(tmp_path)
	gone = prune_keeping_v0_stale_list(job)
	folder = gone.rpartition('--')[0]
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if os.path.abspath(os.fspath(path)) == folder:
			raise OSError(code, os.strerror(code), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	with pytest.raises(rv.JobFailure) as failure:
		rv.get_vault_info(job.job_vault)
	assert os.strerror(code) in failure.value.reason
	assert os.path.isfile(gone)


def test_the_orphan_and_the_leftover_list_go_only_on_a_clean_listing(tmp_path, monkeypatch):
	# an orphan, a list whose folder is gone, and an entry that cannot be looked at: nothing goes until the listing is whole
	job = three_versions(tmp_path)
	gone = prune_keeping_v0_stale_list(job)
	orphan = write_incomplete_version(job, 3, {'x': 'y'})
	listing(monkeypatch, job, fail={change_list_name(job, 2): errno.EIO}, first=lambda listed: not listed.startswith('V2--'))
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isdir(orphan) and os.path.isfile(gone)
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2]
	assert not os.path.exists(orphan) and not os.path.exists(gone)


def test_an_orphan_that_cannot_be_removed_fails_the_scan(tmp_path, monkeypatch):
	# a backup made beside it would take its number, and every scan after that would fail on the two
	job = three_versions(tmp_path)
	orphan = write_incomplete_version(job, 3, {'x': 'y'})
	real_run = rv.multiCMD.run_command
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: real_run(['false'] if command[0] == 'rm' else command, *args, **kwargs))
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isdir(orphan)
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(orphan)


def test_an_orphan_that_rm_cannot_remove_names_rms_message_on_every_attempt(tmp_path, monkeypatch, capsys):
	# a stuck entry (the stand-in fails as rm does on an immutable one): each scan's reason and its log line carry rm's
	# own first line, not only the first attempt's log
	job = three_versions(tmp_path)
	orphan = write_incomplete_version(job, 3, {'x': 'y'})
	real_run = rv.multiCMD.run_command
	script = 'echo "rm: cannot remove \'$1/x\': Operation not permitted" >&2; echo "rm: second line" >&2; exit 1'
	def run(command, *args, **kwargs):
		if command[:2] == ['rm', '-rf']:
			command = ['sh', '-c', script, 'sh', command[-1]]
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	for attempt in range(2):
		capsys.readouterr()
		with pytest.raises(rv.VaultScanError) as failure:
			rv.get_vault_info(job.job_vault)
		assert orphan in failure.value.reason and 'Operation not permitted' in failure.value.reason, attempt
		assert 'second line' not in failure.value.reason
		logged = [line for line in capsys.readouterr().out.splitlines() if f'Failed to remove the orphan {orphan}' in line]
		assert len(logged) == 1 and 'Operation not permitted' in logged[0], attempt
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(orphan)


def test_the_scans_leave_the_pruning_secret_alone(tmp_path):
	job = three_versions(tmp_path)
	salt = rv.vault_prune_salt(job.job_vault, job.job_name)
	path = os.path.join(job.job_vault, rv.PRUNE_SALT_FILE_NAME)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert open(path, 'rb').read() == salt


def test_a_failed_scan_logs_a_failed_marker_and_the_next_attempt_backs_up(tmp_path, monkeypatch, poll_fast, capsys):
	# the job's backup does not run on a scan that failed: its attempt fails with the job's FAILED marker, the daemon
	# goes on, and the next attempt scans again
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	job = three_versions(tmp_path)
	before = vault_names(job)
	failing = [True]
	real_scandir = os.scandir
	def scandir(path='.'):
		if failing[0] and os.path.abspath(os.fspath(path)) == job.job_vault:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_scandir(path)
	monkeypatch.setattr(rv.os, 'scandir', scandir)
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('v3')
	to_process = rv.ChangeEventQueue(job.monitor)
	to_process.append(rv.ChangeEvent(time.monotonic(), False, 'modify', os.path.join(job.monitor, 'keep'), None))
	lock, flag = threading.Lock(), threading.Event()
	attempts = []
	def start_attempt(control, attempt):
		attempts.append(attempt)
		thread = threading.Thread(target=rv.backuper, args=(job.job_name, to_process, lock, job.monitor, job.vault, 'N/A', flag),
			kwargs=dict(keep_n_versions=0, job=control), name=f'{job.job_name} backuper', daemon=True)
		thread.start()
		return [thread]
	control = rv.JobControl(job.job_name)
	result = []
	supervisor = threading.Thread(target=lambda: result.append(rv.run_job(control, start_attempt)), daemon=True)
	supervisor.start()
	try:
		deadline = time.monotonic() + 10
		while not attempts and time.monotonic() < deadline:
			time.sleep(0.01)
		while control.failure is None and time.monotonic() < deadline:
			time.sleep(0.01)
		assert vault_names(job) == before
		while not control.committed.is_set() and time.monotonic() < deadline:
			failing[0] = False
			time.sleep(0.01)
		assert control.committed.is_set()
	finally:
		failing[0] = False
		rv.GREEN_LIGHT.clear()
		supervisor.join(timeout=10)
		rv.GREEN_LIGHT.set()
	out = capsys.readouterr()
	markers = alerting_lines(out.out + out.err)
	assert markers and f'reverberator job {job.job_name} FAILED: ' in markers[0] and os.strerror(errno.EIO) in markers[0]
	assert [version.number for version in rv.list_versions(job.job_vault)] == [0, 1, 2, 3]
	every_folder_reads_right(job)


# --- Task 2b fix round 1 ---

def other_stamp(name):
	'''name (a version folder's) with another year in its timestamp.'''
	number, _, stamp = name.partition('--')
	return f'{number}--' + ('2020' if not stamp.startswith('2020') else '2019') + stamp[4:]


def test_a_list_renamed_for_another_timestamp_keeps_its_version(tmp_path):
	# review10 P1: the renamed list parsed, so it was taken for stale and deleted, and V1, left without a list, was rm -rf'd
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	moved = os.path.join(job.job_vault, os.path.basename(v1.change_list).replace(v1.name, other_stamp(v1.name), 1))
	os.rename(v1.change_list, moved)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(v1.path) and os.path.isfile(moved)


def test_a_listing_that_leaves_out_a_middle_versions_list_removes_nothing(tmp_path, monkeypatch):
	# review10 P3: a listing that skips V1's list without an error made V1 an orphan, rm -rf'd though V0 and V2 are
	# committed around it
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	before = vault_names(job)
	real_scandir = os.scandir
	def scandir(path='.'):
		if os.path.abspath(os.fspath(path)) != job.job_vault:
			return real_scandir(path)
		return iter([entry for entry in real_scandir(path) if entry.name != os.path.basename(v1.change_list)])
	monkeypatch.setattr(rv.os, 'scandir', scandir)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_crash_leftover_above_the_newest_version_is_removed(tmp_path):
	job = three_versions(tmp_path)
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(leftover)


class Killed(BaseException):
	pass


def test_a_removal_cut_short_between_folder_and_list_leaves_a_list_the_scan_deletes(tmp_path, monkeypatch):
	# the prune removes the folder first: killed before its change list goes, it leaves a stale list below the oldest
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real_remove = os.remove
	def remove(path, *args, **kwargs):
		if os.fspath(path).endswith(rv.CONTENT_FILE_EXTENSION_NAME) and os.path.basename(os.fspath(path)).startswith(v0.name + '--'):
			raise Killed()
		return real_remove(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'remove', remove)
	with pytest.raises(Killed):
		rv.decrement_stepper(info, job.job_name, job.monitor)
	monkeypatch.undo()
	assert not os.path.exists(v0.path) and len(lists_of(job, v0)) == 1
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2] and lists_of(job, v0) == []
	every_folder_reads_right(job)


@pytest.mark.parametrize('number, hint', [
	(0, 'a removal cut short by a daemon before 0.44'),
	(2, 'its list may not have been listed, or a commit cut off before its list was placed left it (if it is still refused once every disk of the vault is there, remove it by hand and the job goes on)'),
	(5, 'its list may not have been listed (check that every disk of the vault is there)'),
], ids=['below_the_oldest', 'the_one_the_link_names', 'past_the_one_after'])
def test_an_orphans_refusal_says_what_may_have_left_it(tmp_path, number, hint):
	# current_version names V2: V0, below the oldest committed version, may be a removal cut short; V2, the number the
	# record names, a commit cut off after its link or a list a disk hides; V5, neither it nor the one after, may be out of the listing. Each
	# one line, and nothing is removed
	job = three_versions(tmp_path)
	if number == 5:
		write_incomplete_version(job, 5, {'x': 'y'})
	else:
		os.remove(version(job, number).change_list)
	before = vault_names(job)
	with pytest.raises(rv.VaultScanError) as failure:
		rv.get_vault_info(job.job_vault)
	reason = failure.value.reason
	assert '\n' not in reason and hint in reason
	# and not the other hints
	assert sum(other in reason for other in ('a removal cut short', 'a commit cut off before its list', '(check that every disk of the vault is there)')) == 1
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_an_orphan_between_the_oldest_and_newest_versions_fails_the_scan(tmp_path):
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	os.remove(v1.change_list)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_committed_version_and_an_orphan_of_its_number_fail_the_scan(tmp_path):
	# an attempt that did not commit, then one of the same number that did, with the first one's folder still there
	job = three_versions(tmp_path)
	orphan = os.path.join(job.job_vault, other_stamp(version(job, 2).name))
	os.makedirs(os.path.join(orphan, 'D'))
	before = vault_names(job)
	with pytest.raises(rv.JobFailure) as failure:
		rv.get_vault_info(job.job_vault)
	assert 'numbered 2' in failure.value.reason
	assert_nothing_done(job, before, backup_keeping_two(job))


@pytest.mark.parametrize('stray', ['V7--notes.txt', 'V7--notes' + rv.CONTENT_FILE_EXTENSION_NAME])
def test_a_stray_name_of_another_number_does_not_hold_back_a_crash_leftover(tmp_path, stray):
	# review10 P2: any name that could not be read held back every orphan, so a stray file and any crash wedged the job
	job = three_versions(tmp_path)
	open(os.path.join(job.job_vault, stray), 'w').close()
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert not os.path.exists(leftover) and os.path.isfile(os.path.join(job.job_vault, stray))


@pytest.mark.parametrize('stray', ['V3--notes.txt', 'Vx--notes.txt'], ids=['same_number', 'no_number'])
def test_a_stray_name_that_may_be_the_leftovers_holds_it_back(tmp_path, stray):
	job = three_versions(tmp_path)
	open(os.path.join(job.job_vault, stray), 'w').close()
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isdir(leftover)


@pytest.mark.parametrize('kind', ['folder', 'link_to_a_file', 'link_to_a_folder', 'dangling_link'])
def test_an_entry_with_a_change_lists_name_that_is_no_file_claims_its_version(tmp_path, kind):
	# haiku10 O2, O5: a folder (or a link to one) with V1's list's name was never taken for its list, so V1 was an orphan
	# and rm -rf'd
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	os.remove(v1.change_list)
	if kind == 'folder':
		os.mkdir(v1.change_list)
	else:
		target = {'link_to_a_file': version(job, 0).change_list, 'link_to_a_folder': version(job, 0).path, 'dangling_link': '/nonexistent'}[kind]
		os.symlink(target, v1.change_list)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(v1.path) and os.path.lexists(v1.change_list)


def test_a_version_folder_that_is_a_link_to_another_fails_the_scan(tmp_path):
	# haiku10 O7: V3, a link to V2 with a list of its own, was taken for a version; once V2 was pruned it dangled
	job = three_versions(tmp_path)
	v2 = version(job, 2)
	v3 = v2.path.replace('/V2--', '/V3--')
	os.symlink(os.path.basename(v2.path), v3)
	open(rv.change_list_path(v3, 4096, 1), 'w').close()
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.islink(v3)


def test_an_orphan_that_is_a_link_fails_the_scan(tmp_path):
	# haiku10 extra10b: V5, a link to V2 with no list
	job = three_versions(tmp_path)
	v2 = version(job, 2)
	v5 = v2.path.replace('/V2--', '/V5--')
	os.symlink(v2.path, v5)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.islink(v5) and open(os.path.join(v2.path, 'D/secret')).read() == 'secret'


def lists_of(job, kept):
	'''The change lists of kept's folder there now, by name: its folder's name, --, and a record.'''
	return [name for name in os.listdir(job.job_vault) if name.startswith(kept.name + '--') and name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)]


def strays_beside(job, kept):
	'''Files and folders a user put beside kept's folder, named like it but neither its folder nor its change list.'''
	made = [kept.path + '.stray', kept.path + '-extra', kept.path + '_' + rv.CONTENT_FILE_EXTENSION_NAME]
	open(made[0], 'w').close()
	os.makedirs(os.path.join(made[1], 'inside'))
	open(made[2], 'w').close()
	return made


@pytest.mark.parametrize('how', ['whole', 'cut_short'])
def test_the_prune_removes_only_the_versions_own_folder_and_list(tmp_path, monkeypatch, how):
	# haiku10 O9, O10: the prune's glob of V0's path and * took V0--<ts>.stray and V0--<ts>-extra/ with it
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	made = strays_beside(job, v0)
	if how == 'cut_short':
		real_run = rv.multiCMD.run_command
		def run(command, *args, **kwargs):
			if command[0] == 'rm':
				shutil.rmtree(v0.path)
				return 1
			return real_run(command, *args, **kwargs)
		monkeypatch.setattr(rv.multiCMD, 'run_command', run)
		rv.decrement_stepper(info, job.job_name, job.monitor)
		monkeypatch.undo()
		assert not os.path.exists(v0.path) and len(lists_of(job, v0)) == 1
	rv.decrement_stepper(info, job.job_name, job.monitor)
	assert list(info) == [1, 2] and not os.path.exists(v0.path) and lists_of(job, v0) == []
	assert all(os.path.lexists(path) for path in made), made
	assert os.path.isdir(os.path.join(made[1], 'inside'))
	for kept in rv.list_versions(job.job_vault):
		assert open(os.path.join(kept.path, 'D/secret')).read() == 'secret', kept.name


def test_a_vault_that_vanishes_after_its_versions_were_seen_fails_the_scan(tmp_path, monkeypatch):
	# haiku10 extra10 2: one lstat of the job vault giving ENOENT (a mergerfs branch dropping out) made the backup start
	# a whole V0 beside V0 to V2, and every scan after it fail on the two
	job = three_versions(tmp_path)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	before = vault_names(job)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if os.path.abspath(os.fspath(path)) == job.job_vault:
			raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_new_vault_still_starts_at_v0(tmp_path):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	assert dict(rv.get_vault_info(job.job_vault).vault_info_dict) == {}
	run_backup(job)
	assert [kept.number for kept in rv.list_versions(job.job_vault)] == [0]


# --- Task 2b fix round 1b ---

@pytest.mark.chain_ground_truth_allows('refused_chain', reason='V2 is removed by hand, so the links of V3 name no version')
def test_a_gap_in_the_committed_versions_fails_the_scan(tmp_path):
	# a version deleted by hand, or a listing that left one out without an error: pruning past the gap would take the
	# version after it for the next one, and the missing version's links into the oldest would be broken when it is back
	job = three_versions(tmp_path)
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('v3')
	run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	v0, v2 = version(job, 0), version(job, 2)
	shutil.rmtree(v2.path)
	os.remove(v2.change_list)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure) as failure:
		rv.get_vault_info(job.job_vault)
	assert 'missing' in failure.value.reason
	assert_nothing_done(job, before, backup_keeping_two(job))
	assert os.path.isdir(v0.path) and os.path.isfile(v0.change_list)


def test_versions_made_and_pruned_stay_contiguous(tmp_path, monkeypatch):
	# a failed attempt's number is taken again once its folder goes, and a prune takes only the oldest
	job = three_versions(tmp_path)
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write('v3')
	run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]), keep_n_versions=3)
	assert not os.path.exists(leftover)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2, 3]


@pytest.mark.parametrize('how', ['emptied', 'listed_empty'])
def test_a_vault_that_shows_no_version_after_its_versions_were_seen_fails_the_scan(tmp_path, monkeypatch, how):
	# a mergerfs branch dropping out can show the job vault there but empty: a backup would start a whole V0
	job = three_versions(tmp_path)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	if how == 'emptied':
		aside = os.path.join(str(tmp_path), 'aside')
		os.makedirs(aside)
		for name in os.listdir(job.job_vault):
			if name.startswith('V'):
				os.rename(os.path.join(job.job_vault, name), os.path.join(aside, name))
	else:
		real_scandir = os.scandir
		def scandir(path='.'):
			if os.path.abspath(os.fspath(path)) != job.job_vault:
				return real_scandir(path)
			return iter([entry for entry in real_scandir(path) if not entry.name.startswith('V')])
		monkeypatch.setattr(rv.os, 'scandir', scandir)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_fresh_daemon_starts_an_empty_vault_at_v0(tmp_path):
	job = three_versions(tmp_path)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	for name in os.listdir(job.job_vault):
		path = os.path.join(job.job_vault, name)
		if name.startswith('V'):
			shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
	# a restart: nothing kept in memory
	rv.VAULTS_WITH_VERSIONS.clear()
	assert dict(rv.get_vault_info(job.job_vault).vault_info_dict) == {}
	run_backup(job)
	assert [kept.number for kept in rv.list_versions(job.job_vault)] == [0]


# --- Task 2b fix round 2: an orphan goes only on positive evidence ---

def hide(monkeypatch, job, hidden):
	'''os.scandir() of the job vault leaving out, with no error, the entries for which hidden(name) is true: as a mergerfs
	branch dropping out shows it, each change list on one branch while each version folder spans several.'''
	real_scandir = os.scandir
	def scandir(path='.'):
		if os.path.abspath(os.fspath(path)) != job.job_vault:
			return real_scandir(path)
		return iter([entry for entry in real_scandir(path) if not hidden(entry.name)])
	monkeypatch.setattr(rv.os, 'scandir', scandir)


def assert_refused_everywhere(job, before):
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert_nothing_done(job, before, backup_keeping_two(job))


@pytest.mark.parametrize('memory', ['at_a_start', 'in_process'])
def test_every_list_hidden_removes_nothing(tmp_path, monkeypatch, memory):
	# review11: with no committed version showing, every folder was an orphan, rm -rf'd by the scan of a daemon that had not seen
	# the vault
	job = three_versions(tmp_path)
	if memory == 'in_process':
		rv.get_vault_info(job.job_vault)
	else:
		rv.VAULTS_WITH_VERSIONS.clear()
	before = vault_names(job)
	hide(monkeypatch, job, lambda name: name.endswith(rv.CONTENT_FILE_EXTENSION_NAME))
	assert_refused_everywhere(job, before)


@pytest.mark.parametrize('number', [0, 2], ids=['oldest', 'newest'])
def test_the_oldest_or_newest_list_hidden_removes_nothing(tmp_path, monkeypatch, number):
	# review11: the version whose list was hidden was rm -rf'd as an orphan below the oldest or above the newest
	job = three_versions(tmp_path)
	rv.VAULTS_WITH_VERSIONS.clear()
	hidden = os.path.basename(version(job, number).change_list)
	before = vault_names(job)
	hide(monkeypatch, job, lambda name: name == hidden)
	assert_refused_everywhere(job, before)


@pytest.mark.parametrize('record', ['current_version', 'manifest'])
def test_a_crash_leftover_numbered_after_the_recorded_latest_is_removed(tmp_path, record):
	job = three_versions(tmp_path)
	if record == 'manifest':
		os.remove(os.path.join(job.job_vault, 'current_version'))
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(leftover)


def test_an_orphan_past_a_link_left_behind_fails_the_scan(tmp_path):
	# Task 2b fix round 3: a link one behind (left by a daemon before 0.44, which wrote the change list first) makes V3 two
	# after it: the newest listed is no evidence, as a listing can leave V2's list out as well
	job = three_versions(tmp_path)
	link = os.path.join(job.job_vault, 'current_version')
	os.remove(link)
	os.symlink(version(job, 1).name, link)
	write_incomplete_version(job, 3, {'x': 'y'})
	before = vault_names(job)
	assert_refused_everywhere(job, before)


@pytest.mark.parametrize('number', [4, 5])
def test_a_leftover_past_the_recorded_latest_plus_one_fails_the_scan(tmp_path, number):
	job = three_versions(tmp_path)
	write_incomplete_version(job, number, {'x': 'y'})
	before = vault_names(job)
	assert_refused_everywhere(job, before)


def first_backup_leftover(tmp_path, manifest):
	job = create_job(str(tmp_path))
	timestamp = '2021-01-02_00-00-00_-0800'
	if manifest != 'no_manifest':
		os.makedirs(job.job_vault)
		recorded = rv.VaultManifest(job.job_vault)
		if manifest != 'manifest_without_a_version':
			recorded.begin()
			recorded.commit(os.path.join(job.job_vault, f'V0--{timestamp}' if manifest == 'manifest_naming_it' else 'V0--2021-01-01_00-00-00_-0800'))
		recorded.close()
	return job, timestamp


def test_a_first_backups_crash_is_removed(tmp_path):
	# no current_version, no change list, and the manifest the backup opened before making V0, recording no version
	job, timestamp = first_backup_leftover(tmp_path, 'manifest_without_a_version')
	leftover = write_incomplete_version(job, 0, {'x': 'y'}, timestamp=timestamp)
	assert dict(rv.get_vault_info(job.job_vault).vault_info_dict) == {} and not os.path.exists(leftover)


@pytest.mark.parametrize('manifest', ['no_manifest', 'manifest_naming_it', 'manifest_naming_an_earlier_v0'])
def test_a_lone_v0_without_a_manifest_that_records_nothing_is_kept(tmp_path, manifest):
	# review12: a lone committed V0 whose list and link are out of the listing looks like this, the manifest shown
	# (naming V0) or not; a first backup whose manifest names V0 had its commit under way
	job, timestamp = first_backup_leftover(tmp_path, manifest)
	leftover = write_incomplete_version(job, 0, {'x': 'y'}, timestamp=timestamp)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isdir(leftover)


def test_an_orphan_below_the_oldest_fails_the_scan(tmp_path):
	# a list hidden or moved, or a removal cut short by an older daemon (which removed the list first): no evidence
	job = three_versions(tmp_path)
	os.remove(version(job, 0).change_list)
	before = vault_names(job)
	assert_refused_everywhere(job, before)


@pytest.mark.parametrize('rename', ['renumbered', 'renamed_away'])
def test_a_version_folder_renamed_by_hand_keeps_its_list(tmp_path, rename):
	# haiku11: V2--ts renamed V5--ts or old-V2--ts: V2's list was deleted as stale, and V5 removed as an orphan
	job = three_versions(tmp_path)
	v2 = version(job, 2)
	new = os.path.join(job.job_vault, v2.name.replace('V2--', 'V5--', 1) if rename == 'renumbered' else 'old-' + v2.name)
	os.rename(v2.path, new)
	before = vault_names(job)
	assert_refused_everywhere(job, before)
	assert os.path.isdir(new) and os.path.isfile(v2.change_list)


def test_the_newest_list_renamed_by_hand_keeps_its_version(tmp_path):
	# haiku11: the newest list renamed x-V2--…: V2 was removed as an orphan above the newest
	job = three_versions(tmp_path)
	v2 = version(job, 2)
	os.rename(v2.change_list, os.path.join(job.job_vault, 'x-' + os.path.basename(v2.change_list)))
	before = vault_names(job)
	assert_refused_everywhere(job, before)
	assert os.path.isdir(v2.path)


def prune_keeping_v0_stale_list(job):
	'''V0 removed by a prune, then a change list named for it put back: a stale list below the oldest.'''
	v0 = version(job, 0)
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor)
	assert not os.path.exists(v0.path)
	stale = rv.change_list_path(v0.path, 4096, 1)
	open(stale, 'w').close()
	return stale


def test_a_stale_list_below_the_oldest_is_deleted(tmp_path):
	job = three_versions(tmp_path)
	stale = prune_keeping_v0_stale_list(job)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2] and not os.path.exists(stale)


@pytest.mark.parametrize('number', [3, 9])
def test_a_stale_list_not_below_the_oldest_fails_the_scan(tmp_path, number):
	job = three_versions(tmp_path)
	stale = rv.change_list_path(os.path.join(job.job_vault, f'V{number}--2021-01-09_00-00-00_-0800'), 4096, 1)
	open(stale, 'w').close()
	before = vault_names(job)
	assert_refused_everywhere(job, before)
	assert os.path.isfile(stale)


def test_an_rm_failure_inside_the_oldest_keeps_its_lists_and_the_next_prune_finishes(tmp_path, monkeypatch):
	# the folder goes first, its lists only once it is gone: a removal cut short leaves the version committed
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real_run = rv.multiCMD.run_command
	def run(command, *args, **kwargs):
		if command[0] == 'rm':
			# rm got through the change lists it was given, and part of the folder
			for path in command[2:]:
				if path.endswith(rv.CONTENT_FILE_EXTENSION_NAME):
					os.remove(path)
				elif os.path.isdir(path):
					os.remove(os.path.join(path, 'keep'))
			return 1
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	rv.decrement_stepper(info, job.job_name, job.monitor)
	monkeypatch.undo()
	assert list(info) == [0, 1, 2] and os.path.isdir(v0.path) and len(lists_of(job, v0)) == 1
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	rv.decrement_stepper(info, job.job_name, job.monitor)
	assert list(info) == [1, 2] and not os.path.exists(v0.path) and lists_of(job, v0) == []
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2]
	for kept in rv.list_versions(job.job_vault):
		assert open(os.path.join(kept.path, 'D/secret')).read() == 'secret', kept.name


def test_one_enoent_on_the_oldest_while_it_is_listed_keeps_it(tmp_path, monkeypatch, capsys):
	# review11 p4: the cut-short branch trusted one ENOENT and rm -rf'd what the listing showed of V0, unmaterialised
	job = three_versions(tmp_path)
	v0, v1 = version(job, 0), version(job, 1)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real_lstat = os.lstat
	once = []
	def lstat(path, *args, **kwargs):
		# the prune's own look at V0, once
		if not once and os.path.abspath(os.fspath(path)) == v0.path and sys._getframe(1).f_code.co_name == 'decrement_stepper':
			once.append(path)
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	monkeypatch.undo()
	assert once and list(info) == [0, 1, 2] and os.path.isdir(v0.path) and os.path.isfile(v0.change_list)
	assert len(alerting_lines(capsys.readouterr().out)) == 1
	assert os.readlink(os.path.join(v1.path, 'D/secret')).endswith(f'{v0.name}/D/secret')


@pytest.mark.parametrize('folder', ['Vacation--2020', 'V--notes', 'V7--old'])
def test_a_users_folder_that_claims_nothing_holds_nothing_back(tmp_path, folder):
	# review11 p5: a user's folder named V…--… held back every orphan, so any crash stopped the job
	job = three_versions(tmp_path)
	os.makedirs(os.path.join(job.job_vault, folder, 'inside'))
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert not os.path.exists(leftover) and os.path.isdir(os.path.join(job.job_vault, folder, 'inside'))


def test_the_daemons_own_commits_remember_the_vault(tmp_path, monkeypatch):
	# review11 p1: a vault this process started was never remembered, so a listing that showed it empty got a second V0
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	run_backup(job)
	assert os.path.abspath(job.job_vault) in rv.VAULTS_WITH_VERSIONS
	before = vault_names(job)
	hide(monkeypatch, job, lambda name: name.startswith('V'))
	assert isinstance(backup_keeping_two(job), rv.JobFailure)
	monkeypatch.undo()
	assert vault_names(job) == before


def test_the_prune_keeps_an_entry_named_like_a_list_that_is_no_file(tmp_path):
	# review11 p3: a folder named V0--<ts>--<record>.nsv went with V0
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	odd = os.path.join(job.job_vault, v0.name + '--1_B-1_ino' + rv.CONTENT_FILE_EXTENSION_NAME)
	os.makedirs(os.path.join(odd, 'inside'))
	rv.decrement_stepper(info, job.job_name, job.monitor)
	assert list(info) == [1, 2] and not os.path.exists(v0.path) and os.path.isdir(os.path.join(odd, 'inside'))


# --- Task 2b fix round 3: the records never lag a committed change list ---

def keep_modified(job, text):
	with open(os.path.join(job.monitor, 'keep'), 'w') as f:
		f.write(text)
	return OrderedDict([event_entry(job, 'keep', 'modify')])


def link_number(job):
	return rv.vault_version_number(os.readlink(os.path.join(job.job_vault, 'current_version')))


def committed_folders(job):
	return {kept.number: kept.path for kept in rv.list_versions(job.job_vault)}


@pytest.mark.parametrize('lag', [1, 2])
def test_a_swap_that_fails_leaves_no_committed_version_behind_the_link(tmp_path, monkeypatch, lag):
	# review12: the change list was written before current_version was swapped in, so a swap that failed left the link
	# behind a committed version, which a branch out hiding its list then made an orphan at link + 1, rm -rf'd
	job = three_versions(tmp_path)
	real_replace = os.replace
	def replace(source, dest, *args, **kwargs):
		if os.path.basename(os.fspath(dest)) == 'current_version':
			raise OSError(errno.EIO, os.strerror(errno.EIO), dest)
		return real_replace(source, dest, *args, **kwargs)
	for i in range(lag):
		monkeypatch.setattr(rv.os, 'replace', replace)
		with pytest.raises(OSError):
			run_backup(job, keep_modified(job, f'w{i}'))
		monkeypatch.undo()
	committed = committed_folders(job)
	assert link_number(job) == max(committed)
	# a restart with the newest list's branch out
	rv.VAULTS_WITH_VERSIONS.clear()
	newest = version(job, max(committed))
	hidden = os.path.basename(newest.change_list)
	hide(monkeypatch, job, lambda name: name == hidden)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	monkeypatch.undo()
	assert committed_folders(job) == committed and all(os.path.isdir(path) for path in committed.values())


@pytest.mark.parametrize('manifest', ['shown', 'hidden'])
def test_a_lone_committed_v0_whose_list_and_link_are_hidden_is_kept(tmp_path, monkeypatch, manifest):
	# review12, haiku12 lone_v0: a lone committed V0 was taken for a first backup's leftover
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	run_backup(job)
	v0 = version(job, 0)
	rv.VAULTS_WITH_VERSIONS.clear()
	hidden = {os.path.basename(v0.change_list), 'current_version'} | ({rv.MANIFEST_FILE_NAME} if manifest == 'hidden' else set())
	hide(monkeypatch, job, lambda name: name in hidden)
	real_lstat, real_readlink = os.lstat, os.readlink
	def gone(path):
		path = os.path.abspath(os.fspath(path))
		return os.path.dirname(path) == job.job_vault and os.path.basename(path) in hidden
	def lstat(path, *args, **kwargs):
		if gone(path):
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		return real_lstat(path, *args, **kwargs)
	def readlink(path, *args, **kwargs):
		if gone(path):
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
		return real_readlink(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	monkeypatch.setattr(rv.os, 'readlink', readlink)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	monkeypatch.undo()
	assert os.path.isdir(v0.path) and os.path.isfile(v0.change_list)


def restart_and_scan(job):
	'''A restart: nothing in memory, then the job's scan: (the version folders it removed, the versions or the refusal).'''
	rv.VAULTS_WITH_VERSIONS.clear()
	rv.REAL_VAULT_FOLDERS.clear()
	folders = {os.path.join(job.job_vault, name) for name in os.listdir(job.job_vault) if name.startswith('V')} if os.path.isdir(job.job_vault) else set()
	try:
		scanned = list(rv.get_vault_info(job.job_vault).vault_info_dict)
	except rv.VaultScanError as e:
		scanned = e
	return sorted(path for path in folders if not os.path.lexists(path)), scanned


def commit_hooks(monkeypatch, kill_at=None, fail_place=False):
	'''
	The commit's steps, as the syscalls and calls that make them, recorded in order in the list returned, with a kill
	(Killed) at kill_at: 'writing' (half way through the change list's rows, in its private folder), 'manifest' (just
	after the manifest's commit), 'swap' (just after current_version is swapped in), 'placed' (just after the list's
	rename into place); with fail_place, that rename fails with ENOSPC instead.
	'''
	steps = []
	real_append, real_commit, real_replace = rv.TSVZ.appendLinesTabularFile, rv.VaultManifest.commit, os.replace
	def append(path, rows, *args, **kwargs):
		if rv.CHANGE_LIST_FOLDER_PREFIX not in os.fspath(path):
			return real_append(path, rows, *args, **kwargs)
		if kill_at == 'writing':
			real_append(path, list(rows)[:1], *args, **kwargs)
			raise Killed()
		result = real_append(path, rows, *args, **kwargs)
		steps.append('list written')
		return result
	def commit(self, version_path=None):
		real_commit(self, version_path)
		if version_path is not None:
			steps.append('manifest')
			if kill_at == 'manifest':
				raise Killed()
	def replace(source, dest, *args, **kwargs):
		name = os.path.basename(os.fspath(dest))
		if name.endswith(rv.CONTENT_FILE_EXTENSION_NAME) and fail_place:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), dest)
		result = real_replace(source, dest, *args, **kwargs)
		if name == 'current_version':
			steps.append('link')
			if kill_at == 'swap':
				raise Killed()
		elif name.endswith(rv.CONTENT_FILE_EXTENSION_NAME):
			steps.append('list placed')
			if kill_at == 'placed':
				raise Killed()
		return result
	monkeypatch.setattr(rv.TSVZ, 'appendLinesTabularFile', append)
	monkeypatch.setattr(rv.VaultManifest, 'commit', commit)
	monkeypatch.setattr(rv.os, 'replace', replace)
	return steps


def test_the_commit_writes_the_list_first_and_places_it_last(tmp_path, monkeypatch):
	# Task 2b fix round 4: the slow part, the list's rows written and synced in its private folder, comes before either
	# record names the version; the rename into place, the commit point, comes last
	job = three_versions(tmp_path)
	steps = commit_hooks(monkeypatch)
	run_backup(job, keep_modified(job, 'ordered'))
	monkeypatch.undo()
	assert steps == ['list written', 'manifest', 'link', 'list placed']


def private_folders(job):
	return [name for name in os.listdir(job.job_vault) if name.startswith(rv.CHANGE_LIST_FOLDER_PREFIX)]


@pytest.mark.parametrize('step', ['writing', 'manifest', 'swap', 'placed'])
def test_a_crash_at_each_step_of_the_commit(tmp_path, monkeypatch, step):
	# a kill while the list is written (however long a big one takes) or before the link names the version leaves an
	# orphan at the link + 1, cleaned up; one between the swap and the rename leaves the link on an orphan at the newest
	# version + 1, which nothing can hide a list of on a plain folder: the link goes back and the orphan goes; one after
	# the rename leaves the version committed
	job = three_versions(tmp_path)
	committed = committed_folders(job)
	commit_hooks(monkeypatch, kill_at=step)
	with pytest.raises(Killed):
		run_backup(job, keep_modified(job, 'cut'))
	monkeypatch.undo()
	attempt = [name for name in os.listdir(job.job_vault) if name.startswith('V3--') and os.path.isdir(os.path.join(job.job_vault, name))]
	assert len(attempt) == 1
	removed, scanned = restart_and_scan(job)
	if step in ('writing', 'manifest'):
		assert link_number(job) == 2 and removed == [os.path.join(job.job_vault, attempt[0])] and scanned == [0, 1, 2]
		assert private_folders(job) == []
		run_backup(job, keep_modified(job, 'next'))
		assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3
	elif step == 'swap':
		assert link_number(job) == 2 and removed == [os.path.join(job.job_vault, attempt[0])] and scanned == [0, 1, 2]
		run_backup(job, keep_modified(job, 'next'))
		assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3
	else:
		assert link_number(job) == 3 and removed == [] and scanned == [0, 1, 2, 3]
	assert all(os.path.isdir(path) for path in committed.values())


def test_an_error_reading_the_manifest_in_a_first_backups_clean_up_removes_nothing(tmp_path, monkeypatch):
	# review-t3d p8: the clean-up took an I/O error on the manifest for "no manifest", so it removed V0 and its link but
	# left the manifest naming V0, and a redo that then failed before its commit was refused for good
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	commit_hooks(monkeypatch, kill_at='swap')
	with pytest.raises(Killed):
		run_backup(job)
	monkeypatch.undo()
	manifest = os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if os.fspath(path) == manifest:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_lstat(path, *args, **kwargs)
	with pytest.MonkeyPatch.context() as m:
		m.setattr(rv.os, 'lstat', lstat)
		removed, scanned = restart_and_scan(job)
	assert removed == [] and isinstance(scanned, rv.VaultScanError)
	def copy_failed(*args, **kwargs):
		raise rv.JobFailure('a copy failed')
	with pytest.MonkeyPatch.context() as m:
		m.setattr(rv, 'finish_copies', copy_failed)
		with pytest.raises(rv.JobFailure):
			run_backup(job)
	removed, scanned = restart_and_scan(job)
	assert not isinstance(scanned, rv.VaultScanError) and scanned == []
	run_backup(job)
	assert sorted(committed_folders(job)) == [0]


@pytest.mark.parametrize('step', ['writing', 'manifest', 'swap'])
def test_a_crash_at_each_step_of_a_first_backups_commit(tmp_path, monkeypatch, step):
	# a first backup's manifest names V0 from its commit on, with no link before the swap: on a plain folder, nothing can
	# hide V0's list, so the V0 a kill left without one goes, and its link with it
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	commit_hooks(monkeypatch, kill_at=step)
	with pytest.raises(Killed):
		run_backup(job)
	monkeypatch.undo()
	attempt = [name for name in os.listdir(job.job_vault) if name.startswith('V0--')]
	assert len(attempt) == 1
	removed, scanned = restart_and_scan(job)
	assert removed == [os.path.join(job.job_vault, attempt[0])] and scanned == [] and private_folders(job) == []
	assert not os.path.lexists(os.path.join(job.job_vault, 'current_version'))
	assert rv.recorded_latest_version(job.job_vault).recorded is None
	# a redo that fails before its commit (a copy error, a restart, a disk dropping) leaves a leftover the next scan
	# removes too
	def copy_failed(*args, **kwargs):
		raise rv.JobFailure('a copy failed')
	with pytest.MonkeyPatch.context() as failing:
		failing.setattr(rv, 'finish_copies', copy_failed)
		with pytest.raises(rv.JobFailure):
			run_backup(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and scanned == []
	run_backup(job)
	assert sorted(committed_folders(job)) == [0] and link_number(job) == 0


def test_a_first_backups_change_list_that_cannot_be_placed_leaves_a_leftover_the_next_attempt_removes(tmp_path, monkeypatch):
	# haiku12 chain D: the link was removed, but the manifest still named V0, so the leftover was refused for good. the
	# records now stay on V0, with its list in its private folder, and the scan takes V0 for a commit cut off
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	commit_hooks(monkeypatch, fail_place=True)
	with pytest.raises(OSError):
		run_backup(job)
	monkeypatch.undo()
	assert link_number(job) == 0 and private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and scanned == [] and private_folders(job) == []
	run_backup(job)
	assert sorted(committed_folders(job)) == [0] and link_number(job) == 0


def test_a_change_list_that_cannot_be_placed_is_cleaned_up_by_the_next_scan(tmp_path, monkeypatch):
	# the records stay on V3, with its list in its private folder: the scan puts the link back and removes V3
	job = three_versions(tmp_path)
	commit_hooks(monkeypatch, fail_place=True)
	with pytest.raises(OSError):
		run_backup(job, keep_modified(job, 'full'))
	monkeypatch.undo()
	assert link_number(job) == 3 and private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []


def test_a_prune_that_finds_no_list_for_the_next_version_makes_none(tmp_path, monkeypatch, capsys):
	# haiku12 F5: with V1's list out of the listing, the prune wrote an empty one, and the two wedged the job when the
	# branch came back
	job = three_versions(tmp_path)
	v0, v1 = version(job, 0), version(job, 1)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	aside = os.path.join(job.job_vault, 'x-' + os.path.basename(v1.change_list))
	os.rename(v1.change_list, aside)
	capsys.readouterr()
	assert rv.decrement_stepper(info, job.job_name, job.monitor) == (0, 0)
	assert len(alerting_lines(capsys.readouterr().out)) == 1
	assert list(info) == [0, 1, 2] and os.path.isdir(v0.path) and lists_of(job, v1) == []
	os.rename(aside, v1.change_list)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	every_folder_reads_right(job)


def test_a_first_backups_link_that_cannot_be_made_leaves_a_leftover_the_next_attempt_removes(tmp_path, monkeypatch):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	real_symlink = os.symlink
	def symlink(source, dest, *args, **kwargs):
		if os.path.basename(os.fspath(dest)) == '.current_version.tmp':
			raise OSError(errno.EIO, os.strerror(errno.EIO), dest)
		return real_symlink(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'symlink', symlink)
	with pytest.raises(OSError):
		run_backup(job)
	monkeypatch.undo()
	# the manifest names V0, with no link, and V0's list is in its private folder
	assert rv.recorded_latest_version(job.job_vault).number == 0 and private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and scanned == []
	run_backup(job)
	assert sorted(committed_folders(job)) == [0] and link_number(job) == 0


# --- final fix a: the commit's undo decides only on what it can tell ---

def eio(path):
	return OSError(errno.EIO, os.strerror(errno.EIO), path)


def rename_done_then_eio(monkeypatch, name_is, lstat_fails):
	'''
	os.replace() onto a name name_is(name) takes is made, then reports EIO; and os.lstat() of that name raises EIO from
	then on when lstat_fails: whether it went cannot be told.
	'''
	real_replace, real_lstat = os.replace, os.lstat
	done = []
	def replace(source, dest, *args, **kwargs):
		result = real_replace(source, dest, *args, **kwargs)
		if name_is(os.path.basename(os.fspath(dest))):
			done.append(os.fspath(dest))
			raise eio(dest)
		return result
	def lstat(path, *args, **kwargs):
		if lstat_fails and os.fspath(path) in done:
			raise eio(path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'replace', replace)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	return done


def is_change_list(name):
	return name.endswith(rv.CONTENT_FILE_EXTENSION_NAME)


@pytest.mark.parametrize('first', [False, True])
def test_a_change_list_placed_that_cannot_be_looked_at_keeps_the_records_on_it(tmp_path, monkeypatch, capsys, first):
	# the rename was made and reported EIO, and the lstat after it failed with EIO too: lexists() said not there, so the
	# undo put the link back on V2 while V3 was committed (for a first backup, removed the link and V0's version row).
	# the records now stay as they are after any failure from the manifest's commit on
	if first:
		job = create_job(str(tmp_path))
		seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	else:
		job = three_versions(tmp_path)
	number = 0 if first else 3
	done = rename_done_then_eio(monkeypatch, is_change_list, lstat_fails=True)
	capsys.readouterr()
	with pytest.raises(OSError):
		run_backup(job, None if first else keep_modified(job, 'placed'))
	monkeypatch.undo()
	assert len(done) == 1 and os.path.isfile(done[0])
	assert link_number(job) == number
	assert rv.vault_version_number(rv.recorded_latest_version(job.job_vault).recorded or '') in (None, number)
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert manifest.describes(version(job, number).path)
	finally:
		manifest.close()
	assert restart_and_scan(job)[1] == list(range(number + 1))


@pytest.mark.parametrize('first', [False, True])
def test_a_change_list_rename_that_reports_eio_and_was_not_made_is_cleaned_up_by_the_next_scan(tmp_path, monkeypatch, first):
	# a rename that failed and left nothing there: the records stay on the version, with its list in its private folder,
	# and the next scan puts them back
	if first:
		job = create_job(str(tmp_path))
		seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	else:
		job = three_versions(tmp_path)
	real_replace = os.replace
	def replace(source, dest, *args, **kwargs):
		if is_change_list(os.path.basename(os.fspath(dest))):
			raise eio(dest)
		return real_replace(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'replace', replace)
	with pytest.raises(OSError):
		run_backup(job, None if first else keep_modified(job, 'unplaced'))
	monkeypatch.undo()
	assert link_number(job) == (0 if first else 3) and private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and private_folders(job) == []
	if first:
		assert scanned == [] and not os.path.lexists(os.path.join(job.job_vault, 'current_version'))
		assert rv.recorded_latest_version(job.job_vault).recorded is None
	else:
		assert scanned == [0, 1, 2] and link_number(job) == 2


def test_a_first_backups_link_that_cannot_be_looked_at_keeps_the_manifests_version(tmp_path, monkeypatch, capsys):
	# the swap was made and reported EIO, and the link cannot be looked at: the manifest's version row was dropped on
	# lexists() alone, though the link may be there
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	done = rename_done_then_eio(monkeypatch, lambda name: name == 'current_version', lstat_fails=True)
	capsys.readouterr()
	with pytest.raises(OSError):
		run_backup(job)
	monkeypatch.undo()
	assert len(done) == 1
	assert link_number(job) == 0
	assert rv.vault_version_number(rv.recorded_latest_version(job.job_vault).recorded or 'none') is None
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert rv.vault_version_number(manifest.conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()[0]) == 0
	finally:
		manifest.close()


@pytest.mark.parametrize('first', [False, True])
@pytest.mark.parametrize('kind', ['file', 'folder'])
def test_a_current_version_that_is_no_link_fails_the_scan_and_is_left_as_it_is(tmp_path, monkeypatch, kind, first):
	# something there that is no link, which the swap would have replaced (a file) or failed on (a folder)
	if first:
		job = create_job(str(tmp_path))
		seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
		os.makedirs(job.job_vault)
	else:
		job = three_versions(tmp_path)
	link = os.path.join(job.job_vault, 'current_version')
	if os.path.lexists(link):
		os.remove(link)
	if kind == 'file':
		with open(link, 'w') as f:
			f.write('mine')
	else:
		os.mkdir(link)
		open(os.path.join(link, 'inside'), 'w').close()
	def left_as_it_is():
		if kind == 'file':
			assert open(link).read() == 'mine'
		else:
			assert os.listdir(link) == ['inside']
	# an orphan folder, which the scan can judge only by the record: a current_version that is no link is none, so the
	# attempt fails at the scan, before any copy, naming the entry, and removes nothing
	write_incomplete_version(job, 0 if first else 3, {'a.txt': 'partial'})
	before = vault_names(job)
	with pytest.raises(rv.VaultScanError, match='current_version is no link'):
		rv.get_vault_info(job.job_vault)
	steps = commit_hooks(monkeypatch)
	with pytest.raises(rv.JobFailure, match='current_version is no link'):
		run_backup(job, None if first else keep_modified(job, 'nolink'))
	monkeypatch.undo()
	assert steps == [] and vault_names(job) == before
	left_as_it_is()


# --- final fix h: a clean scan moves a lagging current_version forward ---

def lag_link(job, number):
	'''current_version put back on V<number>, as a daemon before 0.44 left it: the list placed, the swap killed.'''
	link = os.path.join(job.job_vault, 'current_version')
	os.remove(link)
	os.symlink(version(job, number).name, link, target_is_directory=True)


def test_a_clean_scan_moves_a_lagging_link_forward_so_a_later_kill_leaves_an_orphan_it_removes(tmp_path, monkeypatch):
	# the upgrade test's case 2: 0.43 left the link on V1 with V2 committed, then 0.44 was killed mid-copy writing V3, two
	# past the link: the next scan refused V3 for good
	job = three_versions(tmp_path)
	lag_link(job, 1)
	real_backup = rv.do_reverb_backup
	def killed(*args, **kwargs):
		real_backup(*args, **kwargs)
		raise Killed()
	monkeypatch.setattr(rv, 'do_reverb_backup', killed)
	with pytest.raises(Killed):
		run_backup(job, keep_modified(job, 'cut'))
	monkeypatch.undo()
	# the attempt's own scan moved it forward, before its V3 was made
	assert link_number(job) == 2
	attempt = [name for name in os.listdir(job.job_vault) if name.startswith('V3--')]
	assert len(attempt) == 1
	removed, scanned = restart_and_scan(job)
	assert removed == [os.path.join(job.job_vault, attempt[0])] and scanned == [0, 1, 2]
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3


def test_the_link_is_moved_forward_atomically_by_the_commits_own_swap(tmp_path, monkeypatch):
	job = three_versions(tmp_path)
	lag_link(job, 0)
	swaps = []
	real_swap = rv.swap_current_version
	def swap(job_vault, text):
		swaps.append(text)
		return real_swap(job_vault, text)
	monkeypatch.setattr(rv, 'swap_current_version', swap)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert swaps == [version(job, 2).name] and os.readlink(os.path.join(job.job_vault, 'current_version')) == version(job, 2).name


def test_a_scan_never_moves_the_link_back_nor_after_a_failure(tmp_path):
	job = three_versions(tmp_path)
	link = os.path.join(job.job_vault, 'current_version')
	# a link naming a version above the newest listed (its list may be out of the listing) stays
	os.remove(link)
	os.symlink('V7--2021-01-01_00-00-00_-0800', link)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert os.readlink(link) == 'V7--2021-01-01_00-00-00_-0800'
	# nor is one behind moved on a scan that fails (here on an orphan two past it)
	lag_link(job, 1)
	write_incomplete_version(job, 3, {'x': 'y'})
	with pytest.raises(rv.VaultScanError):
		rv.get_vault_info(job.job_vault)
	assert link_number(job) == 1
	# and anything there that is no link is left as it is
	shutil.rmtree(os.path.join(job.job_vault, [name for name in os.listdir(job.job_vault) if name.startswith('V3--')][0]))
	os.remove(link)
	with open(link, 'w') as f:
		f.write('mine')
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and open(link).read() == 'mine'


# --- final fix i: the job's own scan removes the private folders of change lists a crash cut off ---

def hot_journal(job):
	'''A write transaction on the manifest killed in its middle, by a process of its own: a hot journal beside it.'''
	path = os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME)
	code = ('import os, sqlite3, sys\n'
		'conn = sqlite3.connect(sys.argv[1], isolation_level=None)\n'
		'conn.execute("PRAGMA cache_size = 1")\n'
		'conn.execute("BEGIN IMMEDIATE")\n'
		'for i in range(2000):\n'
		'    conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (f"junk{i}", "x" * 500))\n'
		'os._exit(9)\n')
	subprocess.run([sys.executable, '-c', code, path], check=False)
	assert os.path.exists(path + '-journal')


def test_a_first_backup_killed_while_its_list_is_written_with_a_hot_journal_is_cleaned_by_the_jobs_scan(tmp_path, monkeypatch):
	# a manifest with a hot journal cannot be read read-only; the job opens it, which rolls the journal back, and its scan
	# removed the orphan V0 but left the private folder
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	commit_hooks(monkeypatch, kill_at='writing')
	# a SIGKILL runs no clean up
	monkeypatch.setattr(rv, 'discard_change_list', lambda temp_path: None)
	with pytest.raises(Killed):
		run_backup(job)
	monkeypatch.undo()
	assert len(private_folders(job)) == 1
	hot_journal(job)
	rv.VAULTS_WITH_VERSIONS.clear()
	assert len(private_folders(job)) == 1
	manifest = rv.VaultManifest(job.job_vault)
	try:
		assert dict(rv.get_vault_info(job.job_vault).vault_info_dict) == {}
	finally:
		manifest.close()
	assert private_folders(job) == [] and not [name for name in os.listdir(job.job_vault) if name.startswith('V0--')]
	run_backup(job)
	assert sorted(committed_folders(job)) == [0] and link_number(job) == 0 and private_folders(job) == []


def test_a_hot_journal_is_rolled_back_by_a_scan_that_comes_before_any_open_of_the_manifest(tmp_path, monkeypatch):
	# the backuper scans its vault before it opens the manifest (review18): a read only open cannot roll a hot journal
	# back ("attempt to write a readonly database"), which failed every attempt of a new job whose first backup was killed
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	commit_hooks(monkeypatch, kill_at='writing')
	monkeypatch.setattr(rv, 'discard_change_list', lambda temp_path: None)
	with pytest.raises(Killed):
		run_backup(job)
	monkeypatch.undo()
	hot_journal(job)
	rv.VAULTS_WITH_VERSIONS.clear()
	assert dict(rv.get_vault_info(job.job_vault).vault_info_dict) == {}
	assert not os.path.exists(os.path.join(job.job_vault, rv.MANIFEST_FILE_NAME) + '-journal')
	assert private_folders(job) == [] and not [name for name in os.listdir(job.job_vault) if name.startswith('V0--')]
	run_backup(job)
	assert sorted(committed_folders(job)) == [0] and link_number(job) == 0


def test_the_jobs_scan_removes_only_real_folders_of_the_private_prefix(tmp_path):
	job = three_versions(tmp_path)
	private = os.path.join(job.job_vault, rv.CHANGE_LIST_FOLDER_PREFIX + 'cut')
	os.mkdir(private)
	open(os.path.join(private, 'V3--2021-01-01_00-00-00_-0800--1.00_KiB-1.00_ino' + rv.CONTENT_FILE_EXTENSION_NAME), 'w').close()
	elsewhere = os.path.join(str(tmp_path), 'elsewhere')
	os.mkdir(elsewhere)
	open(os.path.join(elsewhere, 'kept'), 'w').close()
	link = os.path.join(job.job_vault, rv.CHANGE_LIST_FOLDER_PREFIX + 'link')
	os.symlink(elsewhere, link)
	near = os.path.join(job.job_vault, 'x' + rv.CHANGE_LIST_FOLDER_PREFIX + 'near')
	os.mkdir(near)
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert not os.path.exists(private) and os.path.islink(link) and os.listdir(elsewhere) == ['kept'] and os.path.isdir(near)


# --- the four rules telling a version's change list agree (final wave) ---

def test_the_four_rules_telling_a_versions_change_list_agree(tmp_path):
	# read_job_vault() (CHANGE_LIST_RECORD), the prune's own_paths(), change_list_of() / parse_change_list_name() and
	# read_version_moves() each tell whether an entry is the change list of a version folder: on every name the daemon
	# writes, and on the odd names of the scan's tests, they say the same
	from tests.harness import write_change_list
	folder = 'V3--2021-01-01_00-00-00_-0800'
	extension = rv.CONTENT_FILE_EXTENSION_NAME
	written = [os.path.basename(rv.change_list_path(folder, size, inodes)) for size in (0, 1, 1023, 1024, 12288, 1610612736, 10 ** 15)
		for inodes in (0, 1, 999, 1000, 1500, 10 ** 7)]
	records = ['1.00_KB-1.00_ino', '1.00_KiB-1.00K_ino', '1.00KiB-1.00_ino', '١_B-1_ino', '1_B-1_ino', '12--00_KiB-4.00_ino',
		'1.00_KiB-1.00_inoX', '1.00_KiB-1.00', 'junk', '1e3_B-1_ino', '1.00_kiB-1.00_ino', '1.00_KiB-1.00_Ki_ino', '+1_B-1_ino',
		'1_B--1_ino', '1.5.0_B-1_ino', ' 1_B-1_ino', '1_B-1_ino ', 'inf_B-1_ino', 'nan_B-1_ino', '1_iB-1_ino', '1_EiB-1_ino',
		'0x1_B-1_ino', '1_B-1_ino.x']
	odd = [f'{folder}--{record}{extension}' for record in records] + [
		f'{folder}--1_B-1_ino', f'{folder}--1_B-1_ino{extension}~', f'{folder}.stray', f'{folder}-extra', f'{folder}_{extension}',
		f'{folder}--1_B-1_ino{extension.upper()}', f'{folder[:-6]}--1_B-1_ino{extension}', f'{folder}--{folder}--1_B-1_ino{extension}',
		f'V3--notes{extension}', f'V3--2021-01-01_00-00-00_-0800x--1_B-1_ino{extension}']
	told = {}
	for at, name in enumerate(written + odd):
		vault = os.path.join(str(tmp_path), f'v{at}')
		version_path = os.path.join(vault, folder)
		os.makedirs(version_path)
		path = os.path.join(vault, name)
		write_change_list(path, '/m', [('x', 'modify', None)])
		try:
			by_scan = rv.read_job_vault(vault).change_lists.get(3) == path
		except rv.VaultScanError:
			by_scan = False
		by_prune = rv.change_list_names(name, folder)
		by_name = (rv.parse_change_list_name(name) or (None, None))[1] == folder
		by_moves = rv.read_version_moves(vault, version_path, '/m')[0] is not None
		told[name] = (by_scan, by_prune, by_name, by_moves)
	assert [name for name, verdicts in told.items() if len(set(verdicts)) != 1] == []
	assert all(told[name][0] for name in written)
	# of the odd ones, only these are change lists: forms format_bytes() writes too
	assert [name for name in odd if told[name][0]] == [f'{folder}--{record}{extension}' for record in ('1.00_KiB-1.00K_ino', '1.00KiB-1.00_ino', '1_B-1_ino')]


# --- round 9, Task 3 fix round 2: a commit cut off between its link swap and its list's placement ---

def vault_on(request, job, where):
	'''The vault on a plain folder, or on a whole fake mergerfs pool of disks a and b: disk a's path, or None.'''
	if where == 'plain':
		return None
	return request.getfixturevalue('fake_pool').add(job.vault, ['a', 'b'])[0]


def cut_off_at_the_swap(job, step='swap', **backup_options):
	'''A backup of three_versions' job killed at step of its commit, run with backup_options: the folder it left.'''
	# a monkeypatch of its own: undoing the test's would undo a fake pool's too
	with pytest.MonkeyPatch.context() as hooks:
		commit_hooks(hooks, kill_at=step)
		with pytest.raises(Killed):
			run_backup(job, keep_modified(job, 'cut'), **backup_options)
	attempt = [name for name in os.listdir(job.job_vault) if name.startswith('V3--') and os.path.isdir(os.path.join(job.job_vault, name))]
	assert len(attempt) == 1
	return os.path.join(job.job_vault, attempt[0])


@pytest.mark.parametrize('step', ['manifest', 'swap'])
def test_a_cut_off_commits_key_goes_once_the_scan_rolls_it_back(tmp_path, step):
	job = three_versions(tmp_path)
	attempt = cut_off_at_the_swap(job, step, matched_since=time.time_ns())
	manifest = rv.VaultManifest(job.job_vault)
	assert manifest.matched[0] == os.path.basename(attempt)
	manifest.close()
	restart_and_scan(job)
	infos = rv.get_vault_info(job.job_vault).vault_info_dict
	manifest = rv.VaultManifest(job.job_vault)
	# a commit later in the same second, carrying a key, would find the rolled back commit's name
	assert manifest.matched is None
	assert rv.full_comparison_since(infos, manifest.matched) == rv.full_comparison_since(infos)
	manifest.close()


def test_forgetting_removed_versions_keeps_a_key_naming_another_version(tmp_path):
	job_vault = str(tmp_path / 'job')
	os.makedirs(job_vault)
	manifest = rv.VaultManifest(job_vault)
	manifest.begin()
	manifest.record_matched(os.path.join(job_vault, 'V2--b'), 5)
	manifest.commit(os.path.join(job_vault, 'V3--c'))
	manifest.close()
	rv.forget_manifest_meta(job_vault, version=False, gone={'V3--c'})
	manifest = rv.VaultManifest(job_vault)
	assert manifest.matched == ('V2--b', 5) and manifest.describes(os.path.join(job_vault, 'V3--c'))
	manifest.close()
	rv.forget_manifest_meta(job_vault, gone={'V2--b', 'V4--d'})
	manifest = rv.VaultManifest(job_vault)
	assert manifest.matched is None and not manifest.describes(os.path.join(job_vault, 'V3--c'))
	manifest.close()


@pytest.mark.parametrize('where', ['plain', 'pool'])
def test_a_kill_between_the_swap_and_the_placement_is_cleaned_up(tmp_path, monkeypatch, request, capsys, where):
	job = three_versions(tmp_path)
	vault_on(request, job, where)
	attempt = cut_off_at_the_swap(job)
	assert link_number(job) == 3
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2] and link_number(job) == 2
	out = capsys.readouterr()
	assert f'{os.path.basename(attempt)} has no change list, though nothing can hide one' in out.out + out.err
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3
	every_folder_reads_right(job)


def test_a_cut_off_commit_is_still_refused_while_a_disk_is_missing(tmp_path, monkeypatch, fake_pool):
	job = three_versions(tmp_path)
	attempt = cut_off_at_the_swap(job)
	_, b = fake_pool.add(job.vault, ['a', 'b'])
	fake_pool.drop(b)
	rv.VAULTS_WITH_VERSIONS.clear()
	with pytest.raises(rv.PoolNotReady) as failure:
		rv.get_vault_info(job.job_vault)
	assert failure.value.reason == f'disk {b} of pool {job.vault} is not mounted'
	assert os.path.isdir(attempt) and link_number(job) == 3


def test_a_drop_that_keeps_the_link_on_the_cut_off_commit_lets_the_next_backup_go_on(tmp_path, monkeypatch, fake_pool):
	# current_version lives on disk a: the drop after the swap hides it, so the undo cannot put it back
	job = three_versions(tmp_path)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	link = os.path.join(job.job_vault, 'current_version')
	hidden = str(tmp_path / 'current_version_on_disk_a')
	real = rv.swap_current_version
	swaps = []
	def swapping(job_vault, text):
		if swaps:
			raise OSError(errno.ENOENT, 'current_version is on a disk that is out', link)
		real(job_vault, text)
		swaps.append(text)
		fake_pool.drop(a)
		os.rename(link, hidden)
	monkeypatch.setattr(rv, 'swap_current_version', swapping)
	with pytest.raises(rv.PoolNotReady):
		run_backup(job, keep_modified(job, 'cut'))
	monkeypatch.setattr(rv, 'swap_current_version', real)
	attempt = os.path.join(job.job_vault, swaps[0])
	fake_pool.mount(a)
	os.rename(hidden, link)
	assert link_number(job) == 3 and os.path.isdir(attempt)
	# the list the commit could not place is still in its private folder, as the undo could not put the link back
	assert private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3
	assert open(os.path.join(committed_folders(job)[3], 'keep')).read() == 'next'


def test_two_kills_in_a_new_jobs_first_two_backups_are_cleaned_up(tmp_path, monkeypatch):
	# V0 committed with no link (a kill between its list and its link, by an older order), then V1 cut off after its
	# manifest's commit: the manifest names V1, and no link names anything
	job = create_job(str(tmp_path))
	seed_monitor(job, {'D/secret': 'secret', 'keep': 'k'})
	run_backup(job)
	os.remove(os.path.join(job.job_vault, 'current_version'))
	commit_hooks(monkeypatch, kill_at='manifest')
	with pytest.raises(Killed):
		run_backup(job, keep_modified(job, 'cut'))
	monkeypatch.undo()
	assert rv.recorded_latest_version(job.job_vault).number == 1
	attempt = [os.path.join(job.job_vault, name) for name in os.listdir(job.job_vault) if name.startswith('V1--')]
	removed, scanned = restart_and_scan(job)
	assert removed == attempt and scanned == [0] and link_number(job) == 0
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1] and link_number(job) == 1


@pytest.mark.parametrize('case', ['link_on_a_committed_version', 'link_two_past_the_newest', 'below_the_oldest',
	'newest_list_removed_by_hand'])
def test_other_orphans_without_a_list_are_still_refused(tmp_path, monkeypatch, case):
	job = three_versions(tmp_path)
	link = os.path.join(job.job_vault, 'current_version')
	if case == 'link_on_a_committed_version':
		# an orphan at the newest + 1 that the link, on V1, does not name
		write_incomplete_version(job, 3, {'keep': 'partial'})
		rv.swap_current_version(job.job_vault, os.path.basename(version(job, 1).path))
	elif case == 'link_two_past_the_newest':
		orphan = write_incomplete_version(job, 4, {'keep': 'partial'}, timestamp='2021-01-05_00-00-00_-0800')
		rv.swap_current_version(job.job_vault, os.path.basename(orphan))
	elif case == 'newest_list_removed_by_hand':
		# the link on V2, the newest + 1 once its list went, but no private folder holds that list
		os.remove(version(job, 2).change_list)
	else:
		# V0's list gone first, and the link on V0
		v0 = os.path.basename(version(job, 0).path)
		for name in os.listdir(job.job_vault):
			if name.startswith(v0 + '--') and name.endswith(rv.CONTENT_FILE_EXTENSION_NAME):
				os.remove(os.path.join(job.job_vault, name))
		rv.swap_current_version(job.job_vault, v0)
	before = vault_names(job)
	removed, scanned = restart_and_scan(job)
	assert removed == [] and isinstance(scanned, rv.VaultScanError) and vault_names(job) == before


# --- round 9, Task 3 fix round 3: a failed commit leaves its records and its unplaced list to the scan ---

def test_a_drop_whose_link_comes_back_with_the_disk_is_cleaned_up(tmp_path, monkeypatch, fake_pool):
	# current_version on disk a, which drops after the commit's swap: a link written now would land on disk b, and
	# disk a's, naming the cut-off V3, would show over it once the disk is back
	job = three_versions(tmp_path)
	a, _ = fake_pool.add(job.vault, ['a', 'b'])
	link = os.path.join(job.job_vault, 'current_version')
	on_a = str(tmp_path / 'current_version_on_disk_a')
	real = rv.swap_current_version
	swaps = []
	def swapping(job_vault, text):
		real(job_vault, text)
		swaps.append(text)
		if len(swaps) == 1:
			fake_pool.drop(a)
			os.rename(link, on_a)
	monkeypatch.setattr(rv, 'swap_current_version', swapping)
	with pytest.raises(rv.PoolNotReady):
		run_backup(job, keep_modified(job, 'cut'))
	monkeypatch.setattr(rv, 'swap_current_version', real)
	# no link was written while the disk was out, and the list stays in its private folder
	assert len(swaps) == 1 and not os.path.lexists(link) and private_folders(job)
	fake_pool.mount(a)
	os.replace(on_a, link)
	attempt = os.path.join(job.job_vault, swaps[0])
	assert link_number(job) == 3
	removed, scanned = restart_and_scan(job)
	assert removed == [attempt] and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3


def test_a_placement_that_cannot_be_told_is_left_to_the_scan(tmp_path, monkeypatch):
	# the list's rename fails, and whether it was made cannot be told (EIO): the records and the list stay as they are
	job = three_versions(tmp_path)
	real_replace, real_lstat = os.replace, os.lstat
	def replace(source, dest, *args, **kwargs):
		if os.fspath(dest).endswith(rv.CONTENT_FILE_EXTENSION_NAME):
			raise OSError(errno.EIO, os.strerror(errno.EIO), dest)
		return real_replace(source, dest, *args, **kwargs)
	def lstat(path, *args, **kwargs):
		if os.fspath(path).endswith(rv.CONTENT_FILE_EXTENSION_NAME) and os.path.dirname(os.fspath(path)) == job.job_vault:
			raise OSError(errno.EIO, os.strerror(errno.EIO), path)
		return real_lstat(path, *args, **kwargs)
	with pytest.MonkeyPatch.context() as failing:
		failing.setattr(rv.os, 'replace', replace)
		failing.setattr(rv.os, 'lstat', lstat)
		with pytest.raises(OSError):
			run_backup(job, keep_modified(job, 'cut'))
	assert link_number(job) == 3 and private_folders(job)
	removed, scanned = restart_and_scan(job)
	assert len(removed) == 1 and scanned == [0, 1, 2] and link_number(job) == 2 and private_folders(job) == []
	run_backup(job, keep_modified(job, 'next'))
	assert sorted(committed_folders(job)) == [0, 1, 2, 3] and link_number(job) == 3
