'''
0.55.2: a restore syncs the target's filesystem before its marker goes (before the folders are handed over), and again
after, before the command returns; a file target once, once it is in place. Off a pool the sync goes through the target
as this run claimed it (a file target's folder, opened before the copy), so it reports every writeback error since; on
a pool through each disk's branch. A sync that fails is a failure of the restore that names the disk; before the
hand-over it is recorded in the marker, and the run again copies everything again while --accept is refused.
'''
import errno
import json
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


FILES = ('proj/a.txt', 'proj/sub/b.txt')


def backed_up(job):
	seed_monitor(job, {'proj/a.txt': 'a' * 5000, 'proj/sub/b.txt': 'b'})
	run_backup(job)
	write_rule(job)


def record(monkeypatch, fail=None):
	'''
	Record each sync through an fd (the folder it names, whether a restore's marker was in it, and the inode the fd is
	open on) and the hand-over's start and end, in order, in the list returned. fail(n) gives the OSError the nth sync
	(from 1) raises, or None.
	'''
	events = []
	hand_over_folders = rv.hand_over_folders

	def syncfs(fd, path=None):
		events.append(('sync', path, os.path.lexists(os.path.join(path, rv.RESTORE_MARKER_NAME)), os.fstat(fd).st_ino))
		error = fail(sum(1 for event in events if event[0] == 'sync')) if fail else None
		if error is not None:
			raise error

	def handing(folders, report, check_stop=None):
		events.append('hand over')
		hand_over_folders(folders, report, check_stop)
		events.append('handed over')
	monkeypatch.setattr(rv, 'syncfs_fd', syncfs)
	monkeypatch.setattr(rv, 'hand_over_folders', handing)
	return events


def copies(monkeypatch):
	'''The sources of the copies the restore makes, in the list returned.'''
	made = []
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: made.append(source) or copy_command(source, dest))
	return made


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


def claimed(monkeypatch):
	'''The fds claim_restore_target() hands out, in the list returned.'''
	fds = []
	claim = rv.claim_restore_target
	monkeypatch.setattr(rv, 'claim_restore_target', lambda target, check=None: fds.append(claim(target, check)) or fds[-1])
	return fds


def test_a_folder_restore_syncs_before_the_hand_over_and_again_after(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = record(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	ino = os.lstat(target).st_ino
	# the first with the marker still there and nothing handed over, the second once the marker is gone; both through the
	# target as claimed, which no copy came before
	assert events == [('sync', target, True, ino), 'hand over', 'handed over', ('sync', target, False, ino)]
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_both_syncs_go_through_the_fd_the_target_was_claimed_by(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	fds = claimed(monkeypatch)
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(fd))
	# never by opening the target again
	monkeypatch.setattr(rv, 'syncfs_folder', lambda path: pytest.fail(f'{path} opened again for its sync'))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert len(fds) == 1 and synced == fds * 2


def test_a_file_restore_syncs_through_its_folder_opened_before_the_copy(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	restored = os.path.join(out, 'a.txt')
	held = os.path.join(rv.list_versions(job.job_vault)[0].path, 'proj', 'a.txt')
	events = []
	real_open = os.open

	def opening(path, flags, *args, **kwargs):
		fd = real_open(path, flags, *args, **kwargs)
		if os.fspath(path) == out and flags & os.O_DIRECTORY:
			events.append(('opened', fd))
		return fd
	monkeypatch.setattr(os, 'open', opening)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: events.append('copy') or copy_command(source, dest))
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append(('sync', fd, path, os.lstat(restored).st_mtime_ns, os.fstat(fd).st_ino)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# its folder opened before the copy, and synced through that fd once the file has its metadata
	opened = [event for event in events if event[0] == 'opened']
	assert len(opened) == 1
	fd = opened[0][1]
	assert events.index(opened[0]) < events.index('copy')
	assert events[-1] == ('sync', fd, out, os.lstat(held).st_mtime_ns, os.lstat(out).st_ino)
	assert [event for event in events if event[0] == 'sync'] == [events[-1]]


def test_accept_syncs_before_the_hand_over_and_again_after(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	events = record(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout
	ino = os.lstat(target).st_ino
	assert events == [('sync', target, True, ino), 'hand over', 'handed over', ('sync', target, False, ino)]


def write_error(n):
	return OSError(errno.EIO, os.strerror(errno.EIO))


def disk_of(path):
	return rv.vault_disks(path)[1][0][0]


def marker_of(target):
	with open(os.path.join(target, rv.RESTORE_MARKER_NAME), encoding='utf-8') as f:
		return json.load(f)


@pytest.mark.parametrize('accept', [False, True], ids=['restore', 'accept'])
def test_a_failed_sync_before_the_hand_over_keeps_the_marker_and_records_it(job, tmp_path, capsys, monkeypatch, accept):
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
	# nothing handed over: the marker stays, recording the failed sync, and the target stays private
	assert [event[:3] for event in events] == [('sync', target, True)]
	assert marker_of(target).get('sync_failed') is True
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith('FAILED proj: ')
	assert 'write error' in failed[0] and disk_of(target) in failed[0] and os.strerror(errno.EIO) in failed[0]
	# the run again is offered as what it does: it copies everything again
	assert 'run the same restore again, which copies everything again' in stdout
	assert 'retry them' not in stdout and 'as not everything was restored' not in stdout


def test_a_run_again_after_a_failed_sync_copies_everything_again(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	# the kernel reports a writeback error once: the first sync fails, every later one succeeds
	record(monkeypatch, fail=lambda n: write_error(n) if n == 1 else None)
	code, _, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# nothing kept as already there: every file copied again
	assert sorted(os.path.relpath(source, rv.list_versions(job.job_vault)[0].path) for source in made) == sorted(FILES)
	assert 'keeping' not in stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	with open(os.path.join(target, 'a.txt')) as f:
		assert f.read() == 'a' * 5000


def test_accept_over_a_failed_sync_is_refused(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	record(monkeypatch, fail=lambda n: write_error(n) if n == 1 else None)
	code, _, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	handed = []
	monkeypatch.setattr(rv, 'hand_over_folders', lambda *args, **kwargs: handed.append(args))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert 'write error' in err and 'copies everything again' in err
	assert handed == [] and marker_of(target).get('sync_failed') is True


def test_a_marker_without_the_record_reads_as_before(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	assert 'sync_failed' not in marker_of(target)
	assert 'sync_failed' not in rv.read_restore_marker(target)
	# a run again keeps what is there
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert [os.path.basename(source) for source in made] == ['b.txt']


def test_a_failed_sync_after_the_hand_over_fails_the_restore(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = record(monkeypatch, fail=lambda n: write_error(n) if n == 2 else None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert [event if isinstance(event, str) else event[:3] for event in events] == [('sync', target, True), 'hand over', 'handed over', ('sync', target, False)]
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and 'write error' in failed[0] and disk_of(target) in failed[0]
	assert 'run the same restore again' not in stdout + err


def test_a_failed_sync_of_a_file_target_fails_the_restore(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: (_ for _ in ()).throw(write_error(1)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith('FAILED proj/a.txt: ') and 'write error' in failed[0] and disk_of(out) in failed[0]


def pool(tmp_path, monkeypatch, target, branches_of):
	'''The target's disks as a pool's: branches_of {disk: [branch names]}, each a folder made under tmp_path/branches.'''
	listed = []
	for disk, names in branches_of.items():
		for name in names:
			os.makedirs(tmp_path / 'branches' / name)
			listed.append((disk, str(tmp_path / 'branches' / name / 'proj')))
	vault_disks = rv.vault_disks
	monkeypatch.setattr(rv, 'vault_disks', lambda path: (True, listed) if path == target else vault_disks(path))
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: pytest.fail('a pool synced through its own fd'))
	return {name: str(tmp_path / 'branches' / name / 'proj') for names in branches_of.values() for name in names}


def test_a_target_on_a_pool_syncs_each_disk_holding_it(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	# two disks: the first holds the target on its second branch only, the second does not hold it at all
	branch = pool(tmp_path, monkeypatch, target, {'one': ['one-a', 'one-b'], 'two': ['two']})
	os.mkdir(branch['one-b'])
	synced = []
	syncfs_folder = rv.syncfs_folder
	monkeypatch.setattr(rv, 'syncfs_folder', lambda path: (syncfs_folder(path), synced.append(path)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# never the pool's own path, whose sync does not reach the disks; a disk without the target is passed over
	assert synced == [branch['one-b']] * 2


def test_a_branch_the_user_cannot_open_is_a_warning(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	branch = pool(tmp_path, monkeypatch, target, {'one': ['one-a', 'one-b'], 'two': ['two']})
	for name in branch:
		os.mkdir(branch[name])
	synced = []

	def syncfs(path):
		# disk one's first branch denied, its second fine; disk two's only branch denied
		if path in (branch['one-a'], branch['two']):
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		synced.append(path)
	monkeypatch.setattr(rv, 'syncfs_folder', syncfs)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == 0, stdout + err
	warnings = [line for line in stdout.splitlines() if line.startswith('WARNING')]
	# one per sync, for the disk none of whose branches could be opened
	assert len(warnings) == 2 and len(set(warnings)) == 1
	assert warnings[0].startswith(f'WARNING proj: could not sync {branch["two"]}: ') and os.strerror(errno.EACCES) in warnings[0]
	assert warnings[0].endswith('; what was restored there is not known to be on disk')
	assert synced == [branch['one-b']] * 2
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_the_marker_is_on_disk_before_the_first_copy(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = []
	fsync_vault_folder = rv.fsync_vault_folder

	def fsyncing(path):
		events.append(('fsync', path, os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))))
		fsync_vault_folder(path)
	monkeypatch.setattr(rv, 'fsync_vault_folder', fsyncing)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: events.append('copy') or copy_command(source, dest))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# the target, holding the marker, then the folder this restore made it in: both before any copy
	assert events[:3] == [('fsync', target, True), ('fsync', out, True), 'copy']
