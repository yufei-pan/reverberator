'''
0.55.2: a restore syncs the target's filesystem before its marker goes (before the folders are handed over), and again
after, before the command returns; a file target once, once it is in place. A sync that fails is a failure of the
restore that names the disk, with no rerun offered as the fix.
'''
import errno
import os
import stat
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, write_rule

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def restore(tmp_path, capsys, path, *extra):
	# what building the vault logged is not the command's output
	capsys.readouterr()
	code = rv.run_command(['restore', path, *extra, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', str(tmp_path / 'state')])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def destination(tmp_path):
	path = tmp_path / 'out'
	path.mkdir()
	return str(path)


def backed_up(job):
	seed_monitor(job, {'proj/a.txt': 'a' * 5000, 'proj/sub/b.txt': 'b'})
	run_backup(job)
	write_rule(job)


def record(monkeypatch, fail=None):
	'''
	Record each sync (the folder, and whether a restore's marker was in it) and the hand-over's start and end, in
	order, in the list returned. fail(n) gives the OSError the nth sync (from 1) raises, or None.
	'''
	events = []
	hand_over_folders = rv.hand_over_folders

	def syncfs(path):
		events.append(('sync', path, os.path.lexists(os.path.join(path, rv.RESTORE_MARKER_NAME))))
		error = fail(sum(1 for event in events if event[0] == 'sync')) if fail else None
		if error is not None:
			raise error

	def handing(folders, report, check_stop=None):
		events.append('hand over')
		hand_over_folders(folders, report, check_stop)
		events.append('handed over')
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	monkeypatch.setattr(rv, 'hand_over_folders', handing)
	return events


def unfinished(job, tmp_path, capsys, monkeypatch):
	'''A folder restore of proj into out that failed on sub/b.txt, leaving its marker: the target.'''
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	out = destination(tmp_path)
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'FAILED proj/sub/b.txt' in stdout
	monkeypatch.setattr(rv, 'copy_command', copy_command)
	target = os.path.join(out, 'proj')
	assert os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	return target


def test_a_folder_restore_syncs_before_the_hand_over_and_again_after(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = record(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# the first with the marker still there and nothing handed over, the second once the marker is gone
	assert events == [('sync', target, True), 'hand over', 'handed over', ('sync', target, False)]
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_file_restore_syncs_its_folder_once_the_file_is_in_place(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	restored = os.path.join(out, 'a.txt')
	held = os.path.join(rv.list_versions(job.job_vault)[0].path, 'proj', 'a.txt')
	seen = []
	syncfs = lambda path: seen.append((path, os.lstat(restored).st_mtime_ns, os.lstat(restored).st_mode))
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# one sync, of the folder holding the file, once it has its metadata
	copy = os.lstat(held)
	assert seen == [(out, copy.st_mtime_ns, copy.st_mode)]


def test_accept_syncs_before_the_hand_over_and_again_after(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	events = record(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout
	assert events == [('sync', target, True), 'hand over', 'handed over', ('sync', target, False)]


def write_error(n):
	return OSError(errno.EIO, os.strerror(errno.EIO))


def disk_of(path):
	return rv.vault_disks(path)[1][0][0]


@pytest.mark.parametrize('accept', [False, True], ids=['restore', 'accept'])
def test_a_failed_sync_before_the_hand_over_keeps_the_marker_and_offers_no_rerun(job, tmp_path, capsys, monkeypatch, accept):
	backed_up(job)
	if accept:
		target = unfinished(job, tmp_path, capsys, monkeypatch)
		out = os.path.dirname(target)
	else:
		out = destination(tmp_path)
		target = os.path.join(out, 'proj')
	events = record(monkeypatch, fail=lambda n: write_error(n) if n == 1 else None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', *(['--accept'] if accept else []))
	assert code == rv.EXIT_COMMAND_FAILED
	# nothing handed over: the marker stays and the target stays private
	assert events == [('sync', target, True)]
	assert os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith('FAILED proj: ')
	assert 'write error' in failed[0] and disk_of(target) in failed[0] and os.strerror(errno.EIO) in failed[0]
	assert 'run the same restore again' not in stdout + err


def test_a_failed_sync_after_the_hand_over_fails_the_restore(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = record(monkeypatch, fail=lambda n: write_error(n) if n == 2 else None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert events == [('sync', target, True), 'hand over', 'handed over', ('sync', target, False)]
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and 'write error' in failed[0] and disk_of(target) in failed[0]
	assert 'run the same restore again' not in stdout + err


def test_a_failed_sync_of_a_file_target_fails_the_restore(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	monkeypatch.setattr(rv, 'syncfs_folder', lambda path: (_ for _ in ()).throw(write_error(1)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith('FAILED proj/a.txt: ') and 'write error' in failed[0] and disk_of(out) in failed[0]


def test_a_target_on_a_pool_syncs_each_disk_holding_it(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	# two disks: the first holds the target on its second branch only, the second does not hold it at all
	branches = {name: str(tmp_path / 'branches' / name) for name in ('one-a', 'one-b', 'two')}
	for name, branch in branches.items():
		os.makedirs(branch)
	os.mkdir(os.path.join(branches['one-b'], 'proj'))
	vault_disks = rv.vault_disks

	def pooled(path):
		if path != target:
			return vault_disks(path)
		return True, [('one', os.path.join(branches['one-a'], 'proj')), ('one', os.path.join(branches['one-b'], 'proj')), ('two', os.path.join(branches['two'], 'proj'))]
	monkeypatch.setattr(rv, 'vault_disks', pooled)
	synced = []
	syncfs_folder = rv.syncfs_folder
	monkeypatch.setattr(rv, 'syncfs_folder', lambda path: (syncfs_folder(path), synced.append(path)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# never the pool's own path, whose sync does not reach the disks; a disk without the target is passed over
	assert synced == [os.path.join(branches['one-b'], 'proj')] * 2
