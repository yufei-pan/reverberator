'''
The vault scan (get_vault_info()) and the startup cleanup (remove_incomplete_vault_versions()) delete nothing unless they
are certain (Task 2b): any error fails the scan as a whole, no partial or empty view reaches a backup, change lists are
matched to their folders by name before any parse, and duplicate version numbers fail the scan. haiku9 p1's inputs.
'''
import errno
import shutil
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == [] and os.path.isdir(odd)


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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	job = three_versions(tmp_path)
	gone = rv.change_list_path(os.path.join(job.job_vault, 'V9--2021-01-09_00-00-00_-0800'), 4096, 1)
	open(gone, 'w').close()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert not os.path.exists(gone)


@pytest.mark.parametrize('code', [errno.EIO, errno.EACCES], ids=['EIO', 'EACCES'])
def test_a_change_list_whose_folder_cannot_be_looked_at_fails_the_scan(tmp_path, monkeypatch, code):
	job = three_versions(tmp_path)
	folder = os.path.join(job.job_vault, 'V9--2021-01-09_00-00-00_-0800')
	gone = rv.change_list_path(folder, 4096, 1)
	open(gone, 'w').close()
	real_lstat = os.lstat
	def lstat(path, *args, **kwargs):
		if os.path.abspath(os.fspath(path)) == folder:
			raise OSError(code, os.strerror(code), path)
		return real_lstat(path, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'lstat', lstat)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isfile(gone)


def test_the_orphan_and_the_leftover_list_go_only_on_a_clean_listing(tmp_path, monkeypatch):
	# an orphan, a list whose folder is gone, and an entry that cannot be looked at: nothing goes until the listing is whole
	job = three_versions(tmp_path)
	orphan = write_incomplete_version(job, 5, {'x': 'y'})
	gone = rv.change_list_path(os.path.join(job.job_vault, 'V9--2021-01-09_00-00-00_-0800'), 4096, 1)
	open(gone, 'w').close()
	listing(monkeypatch, job, fail={change_list_name(job, 2): errno.EIO}, first=lambda listed: not listed.startswith('V2--'))
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
	assert os.path.isdir(orphan) and os.path.isfile(gone)
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2]
	assert not os.path.exists(orphan) and not os.path.exists(gone)


def test_an_orphan_that_cannot_be_removed_fails_the_scan(tmp_path, monkeypatch):
	# a backup made beside it would take its number, and every scan after that would fail on the two
	job = three_versions(tmp_path)
	orphan = write_incomplete_version(job, 3, {'x': 'y'})
	real_run = rv.multiCMD.run_command
	monkeypatch.setattr(rv.multiCMD, 'run_command', lambda command, *args, **kwargs: 1 if command[0] == 'rm' else real_run(command, *args, **kwargs))
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert os.path.isdir(orphan)
	monkeypatch.undo()
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(orphan)


def test_the_scans_leave_the_pruning_secret_alone(tmp_path):
	job = three_versions(tmp_path)
	salt = rv.vault_prune_salt(job.job_vault, job.job_name)
	path = os.path.join(job.job_vault, rv.PRUNE_SALT_FILE_NAME)
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
	assert_nothing_done(job, before, backup_keeping_two(job))


def test_a_crash_leftover_above_the_newest_version_is_removed(tmp_path):
	job = three_versions(tmp_path)
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert rv.remove_incomplete_vault_versions(job.job_vault) == [leftover]
	leftover = write_incomplete_version(job, 3, {'x': 'y'})
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [0, 1, 2] and not os.path.exists(leftover)


def test_a_cut_short_removal_below_the_oldest_version_is_removed(tmp_path, monkeypatch):
	# the prune materialised V1's links, then rm took V0's change list and not its folder
	job = three_versions(tmp_path)
	v0 = version(job, 0)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	real_run = rv.multiCMD.run_command
	def run(command, *args, **kwargs):
		if command[0] == 'rm':
			for path in command[1:]:
				if path.endswith(rv.CONTENT_FILE_EXTENSION_NAME):
					os.remove(path)
			return 1
		return real_run(command, *args, **kwargs)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run)
	rv.decrement_stepper(info, job.job_name, job.monitor)
	monkeypatch.undo()
	assert os.path.isdir(v0.path) and lists_of(job, v0) == []
	assert list(rv.get_vault_info(job.job_vault).vault_info_dict) == [1, 2] and not os.path.exists(v0.path)
	every_folder_reads_right(job)


def test_an_orphan_between_the_oldest_and_newest_versions_fails_the_scan(tmp_path):
	job = three_versions(tmp_path)
	v1 = version(job, 1)
	os.remove(v1.change_list)
	before = vault_names(job)
	with pytest.raises(rv.JobFailure):
		rv.get_vault_info(job.job_vault)
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == [] and os.path.isdir(leftover)


@pytest.mark.parametrize('kind', ['folder', 'link_to_a_file', 'link_to_a_folder', 'dangling_link'])
def test_an_entry_with_a_change_lists_name_that_is_no_file_claims_its_version(tmp_path, kind):
	# haiku10 O2, O5: a folder (or a link to one) with V1's list's name was never taken for its list, so V1 was an orphan
	# and rm -rf'd, by the scan and the startup cleanup
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
	assert '2' in failure.value.reason
	assert rv.remove_incomplete_vault_versions(job.job_vault) == []
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
