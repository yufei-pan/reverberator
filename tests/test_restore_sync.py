'''
0.55.2: a restore syncs the target's filesystem before its marker goes (before the folders are handed over), and again
after, before the command returns; a file target once, once it is in place. Every sync goes through handles opened before
the first copy, so it reports every writeback error since: off a pool the target as this run claimed it (a file target's
folder, opened before the copy), on a pool a branch of each disk. The marker says what the target holds is not known to be
on disk until a sync succeeds; a sync that fails is a failure of the restore that names the disk, the record stays, and
the run again copies everything again while --accept is refused. A run stopped before its sync syncs on its way out, so a
run again keeps what it copied; one killed before it leaves a record that a run again copies everything again over. A
pool disk none of whose branches the user can open is a warning, once per restore.
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
	assert marker_of(target).get('recopy') == 'sync failed' and 'unsynced' not in marker_of(target)
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
	assert 'a sync of what it holds failed' in err and 'copies everything again' in err and 'known to have succeeded' not in err
	assert handed == [] and marker_of(target).get('recopy') == 'sync failed'


def test_a_marker_without_the_record_reads_as_before(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	assert 'unsynced' not in marker_of(target)
	assert 'unsynced' not in rv.read_restore_marker(target)
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


def pooled(tmp_path, fake_pool, disks):
	'''
	The folder to restore into, out, on a mergerfs pool (FakePool) over the branches of disks, {disk: [branch names]}: each
	disk a mount of its own and its branches folders of it, as two branches of one disk are. (out, {branch name: its path}).
	'''
	branches = {}
	for disk, names in disks.items():
		mount = fake_pool.add_mount(str(tmp_path / 'disks' / disk))
		for name in names:
			branches[name] = os.path.join(mount, name)
	fake_pool.add(str(tmp_path / 'pool'), list(branches.values()))
	for branch in branches.values():
		# a folder of its disk, with no mount of its own
		fake_pool.drop(branch)
	out = tmp_path / 'pool' / 'out'
	out.mkdir()
	return str(out), branches


def opened_branches(monkeypatch, branches, events):
	'''Append ('opened', path, fd) to events for each open of one of branches, and 'copy' for each copy the restore starts.'''
	real_open = os.open

	def opening(path, flags, *args, **kwargs):
		fd = real_open(path, flags, *args, **kwargs)
		if os.fspath(path) in branches.values():
			events.append(('opened', os.fspath(path), fd))
		return fd
	monkeypatch.setattr(os, 'open', opening)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: events.append('copy') or copy_command(source, dest))


@pytest.mark.parametrize('kind', ['folder', 'file'])
def test_a_pools_disks_are_opened_before_the_first_copy_and_every_sync_goes_through_them(job, tmp_path, capsys, monkeypatch, fake_pool, kind):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']})
	events = []
	opened_branches(monkeypatch, branches, events)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append(('sync', fd)))
	# never a path opened at the sync, the pool's own included, whose sync does not reach the disks
	monkeypatch.setattr(rv, 'syncfs_folder', lambda path: pytest.fail(f'{path} opened for its sync'))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj' + ('/a.txt' if kind == 'file' else ''), out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	opened = [event for event in events if event[0] == 'opened']
	# each disk's branch itself, once, before the first copy
	assert sorted(path for _, path, _ in opened) == sorted(branches.values())
	assert events.index(opened[-1]) < events.index('copy')
	# a folder target's two syncs, a file target's one: each of every disk, through those fds
	synced = [event[1] for event in events if event[0] == 'sync']
	assert sorted(synced) == sorted([fd for _, _, fd in opened] * (2 if kind == 'folder' else 1))


def test_a_copy_landing_on_a_disk_without_the_target_at_the_claim_is_synced(job, tmp_path, capsys, monkeypatch, fake_pool):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']})
	# at the claim the target's folder is on disk one alone; mergerfs puts the first copy's folder on disk two
	os.makedirs(os.path.join(branches['one'], 'out', 'proj'))
	events = []
	opened_branches(monkeypatch, branches, events)
	copy_command = rv.copy_command

	def landing(source, dest):
		os.makedirs(os.path.join(branches['two'], 'out', 'proj'), exist_ok=True)
		return copy_command(source, dest)
	monkeypatch.setattr(rv, 'copy_command', landing)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append(('sync', fd, os.fstat(fd).st_ino)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# disk two synced too, through its branch as opened before the copy that put the folder there
	opened = {event[2] for event in events if event[0] == 'opened'}
	synced = [event for event in events if event[0] == 'sync']
	assert {fd for _, fd, _ in synced} <= opened
	assert os.lstat(branches['two']).st_ino in {ino for _, _, ino in synced}


def deny(monkeypatch, paths):
	'''An open of a folder of paths (a callable, or a set) as a folder fails with EACCES, as for a user its mode shuts out.'''
	real_open = os.open
	shut = paths if callable(paths) else (lambda path: path in paths)

	def opening(path, flags, *args, **kwargs):
		if flags & os.O_DIRECTORY and shut(os.fspath(path)):
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)


def test_a_disk_none_of_whose_branches_the_user_can_open_is_a_warning_once(job, tmp_path, capsys, monkeypatch, fake_pool):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one-a', 'one-b'], 'two': ['two']})
	target = os.path.join(out, 'proj')
	# disk one's first branch shut out, its second fine; disk two's only branch shut out, as a mode without read for the
	# user shuts a folder it can still go through
	deny(monkeypatch, {branches['one-a'], branches['two']})
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(os.fstat(fd).st_ino))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == 0, stdout + err
	warnings = [line for line in stdout.splitlines() if line.startswith('WARNING')]
	assert len(warnings) == 1 and warnings[0].startswith(f'WARNING proj: could not sync {branches["two"]}: ')
	assert os.strerror(errno.EACCES) in warnings[0] and warnings[0].endswith('; what was restored there is not known to be on disk')
	# disk one synced through its second branch, before the hand-over and after
	assert synced == [os.lstat(branches['one-b']).st_ino] * 2
	assert 'FAILED' not in stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_folder_shut_to_its_owner_by_the_hand_over_is_synced_on_a_pool(job, tmp_path, capsys, monkeypatch, fake_pool):
	# the hand-over gives the target its own mode, here without the owner's read: the second sync goes through the disk's
	# handle of the claim, never through the folder opened again
	if os.geteuid() != 0:
		pytest.skip("only root backs up a folder shut to its owner's reads, and restores out of it")
	seed_monitor(job, {'proj/a.txt': 'a'})
	os.chmod(os.path.join(job.monitor, 'proj'), 0o300)
	run_backup(job)
	write_rule(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	target = os.path.join(out, 'proj')
	# the restored folder as the disk's branch holds it, shut to root as the kernel shuts it to any other user, its owner
	# included, once the target has that mode
	held = os.path.join(branches['one'], 'out', 'proj')
	os.makedirs(held)
	deny(monkeypatch, lambda path: path == held and not os.stat(target).st_mode & stat.S_IRUSR)
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(os.fstat(fd).st_ino))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o300
	assert 'WARNING' not in stdout and synced == [os.lstat(branches['one']).st_ino] * 2


def test_disks_that_cannot_be_listed_are_not_called_a_write_error(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	vault_disks = rv.vault_disks

	def listing(path, roots=False):
		# for the handles the syncs go through, opened at the claim; the marker's fsync lists them too, and can
		if roots:
			raise OSError(errno.EIO, os.strerror(errno.EIO), 'the branch list')
		return vault_disks(path)
	monkeypatch.setattr(rv, 'vault_disks', listing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and 'could not be listed' in failed[0]
	assert 'write error' not in stdout
	assert f'What {target} holds is not known to be on disk: run the same restore again, which copies everything again' in stdout


def test_a_run_stopped_in_the_hand_over_after_a_recopy_is_finished_by_accept(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	record(monkeypatch, fail=lambda n: write_error(n) if n == 1 else None)
	code, _, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and marker_of(target).get('recopy') == 'sync failed'
	# the run again recopies, its sync succeeds, and a signal comes while it hands the folders over
	events = []
	write_restore_marker = rv.write_restore_marker
	monkeypatch.setattr(rv, 'write_restore_marker', lambda *args, **kwargs: events.append(('mark', kwargs.get('recopy'))) or write_restore_marker(*args, **kwargs))
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append('sync'))
	hand_over_folders = rv.hand_over_folders
	monkeypatch.setattr(rv, 'hand_over_folders', lambda *args: events.append('hand over') or hand_over_folders(*args))
	restore_folder_meta = rv.restore_folder_meta

	def stopping(*args, **kwargs):
		rv.RESTORE_STOP.set()
		return restore_folder_meta(*args, **kwargs)
	monkeypatch.setattr(rv, 'restore_folder_meta', stopping)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and '--accept' in err
	# synced, then the marker says so, then the hand-over: never handed over under a marker that refuses --accept
	assert events[:4] == [('mark', 'sync failed'), 'sync', ('mark', None), 'hand over']
	assert 'unsynced' not in marker_of(target) and 'recopy' not in marker_of(target)
	monkeypatch.setattr(rv, 'restore_folder_meta', restore_folder_meta)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_recopy_whose_sync_fails_beside_a_fixable_failure_offers_no_accept(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	# an earlier run whose sync failed: its marker records the recopy
	record(monkeypatch, fail=lambda n: write_error(n) if n == 1 else None)
	code, _, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and marker_of(target).get('recopy') == 'sync failed'
	# the recopy fails a copy, and its sync fails too
	made = copies(monkeypatch)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	record(monkeypatch, fail=lambda n: write_error(n))
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	# a recopy: a.txt, already there, was copied again
	assert [os.path.basename(source) for source in made] == ['a.txt']
	assert 'run the same restore again, which copies everything again' in stdout
	assert '--accept' not in stdout and 'retry them' not in stdout
	assert marker_of(target).get('recopy') == 'sync failed'


def test_a_fixable_failure_with_a_good_sync_is_picked_up_and_can_be_accepted(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	# the sync after the failed copy succeeded: the record is gone, and --accept keeps what is there
	assert 'unsynced' not in marker_of(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout


def stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out):
	'''A restore of proj into out that a signal stops as its second copy starts, once the first is in place: (code, stdout, err).'''
	copy_command = rv.copy_command
	made = []

	def stopping(source, dest):
		made.append(source)
		if len(made) == 2:
			# what the restore's signal handlers do
			rv.RESTORE_STOP.set()
		return copy_command(source, dest)
	with monkeypatch.context() as stopped:
		stopped.setattr(rv, 'RESTORE_COPY_BATCH', 1)
		stopped.setattr(rv, 'copy_command', stopping)
		return restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')


def stopping_line(target):
	return f'Stopping: writing what was restored into {target} out to disk first, which takes as long as the disk needs'


def recopy_line(target):
	return f'Interrupted: what {target} holds is not known to be on disk: run the same restore again, which copies everything again. {rv.unfinished_note(target)}'


def test_a_run_stopped_before_its_sync_syncs_on_its_way_out_and_a_run_again_keeps_it(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	fds = claimed(monkeypatch)
	synced = []
	with monkeypatch.context() as syncing:
		syncing.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append((fd, marker_of(target).get('unsynced'))))
		code, stdout, err = stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out)
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	# it says so, syncs through the target as claimed while the marker still says not known to be on disk, then the
	# record goes
	assert err == f'{stopping_line(target)}\nInterrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {rv.unfinished_note(target)}\n'
	assert synced == [(fds[0], True)]
	assert 'unsynced' not in marker_of(target) and 'recopy' not in marker_of(target)
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# the copy in place before the stop is kept, the other one copied
	assert len(made) == 1 and 'keeping 1 already there' in stdout and whole(target)


def test_a_stopped_run_whose_sync_fails_records_a_recopy(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	with monkeypatch.context() as failing:
		record(failing, fail=write_error)
		code, stdout, err = stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out)
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	lines = err.splitlines()
	assert lines[0] == stopping_line(target) and lines[2:] == [recopy_line(target)]
	assert lines[1].startswith('FAILED proj: the disk ') and 'write error' in lines[1] and os.strerror(errno.EIO) in lines[1]
	assert marker_of(target).get('recopy') == 'sync failed' and 'unsynced' not in marker_of(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'a sync of what it holds failed' in err
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert sorted(os.path.relpath(source, rv.list_versions(job.job_vault)[0].path) for source in made) == sorted(FILES)
	assert 'keeping' not in stdout and whole(target)


def test_a_stop_right_after_its_own_sync_offers_a_run_again_or_accept(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	synced = []

	def syncing(fd, path=None):
		# a signal while the sync waits for the disk: the run stops as its hand-over begins
		synced.append(path)
		rv.RESTORE_STOP.set()
	monkeypatch.setattr(rv, 'syncfs_fd', syncing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	# its record went with that sync: nothing to sync on its way out
	assert err == f'Interrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {rv.unfinished_note(target)}\n'
	assert synced == [target] and 'unsynced' not in marker_of(target)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and whole(target)


def test_a_stop_whose_record_cannot_be_cleared_after_its_sync_says_a_run_again_copies_everything_again(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: None)
	write_restore_marker = rv.write_restore_marker

	def failing(*args, **kwargs):
		# the rewrite without the record, once the sync on the way out succeeded
		if rv.RESTORE_STOP.is_set() and not kwargs.get('unsynced'):
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return write_restore_marker(*args, **kwargs)
	monkeypatch.setattr(rv, 'write_restore_marker', failing)
	code, stdout, err = stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out)
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	assert err.splitlines() == [stopping_line(target), recopy_line(target)]
	assert marker_of(target).get('unsynced') is True
	monkeypatch.setattr(rv, 'write_restore_marker', write_restore_marker)
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert sorted(os.path.basename(source) for source in made) == ['a.txt', 'b.txt']


def test_accept_whose_record_cannot_be_written_does_not_offer_a_run_again(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	record(monkeypatch, fail=lambda n: write_error(n))
	write_restore_marker = rv.write_restore_marker

	def failing(*args, **kwargs):
		if kwargs.get('recopy'):
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return write_restore_marker(*args, **kwargs)
	monkeypatch.setattr(rv, 'write_restore_marker', failing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert code == rv.EXIT_COMMAND_FAILED
	assert any(line.startswith('FAILED proj: the failed sync could not be recorded') and 'out of the way' in line for line in stdout.splitlines())
	assert 'run the same restore again' not in stdout


def test_the_marker_is_on_disk_before_the_first_copy(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = []
	fsync_vault_folder = rv.fsync_vault_folder

	def fsyncing(path, denied=None):
		events.append(('fsync', path, os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))))
		fsync_vault_folder(path, denied)
	monkeypatch.setattr(rv, 'fsync_vault_folder', fsyncing)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: events.append('copy') or copy_command(source, dest))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	# the target, holding the marker, then the folder this restore made it in: both before any copy
	assert events[:3] == [('fsync', target, True), ('fsync', out, True), 'copy']


def nul_out(path):
	'''path holding NULs in place of its bytes, its size and times kept, as a power cut leaves a file on f2fs.'''
	st = os.lstat(path)
	with open(path, 'r+b') as f:
		f.write(b'\0' * st.st_size)
	os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def a_failed_sync_then_a_nul_file(job, tmp_path, capsys, monkeypatch):
	'''A restore of proj into out whose sync failed, and its a.txt NULs since: the target.'''
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	with monkeypatch.context() as failing:
		record(failing, fail=lambda n: write_error(n) if n == 1 else None)
		code, _, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and marker_of(target).get('recopy') == 'sync failed'
	nul_out(os.path.join(target, 'a.txt'))
	return target


def whole(target):
	with open(os.path.join(target, 'a.txt')) as f:
		return f.read() == 'a' * 5000


def test_a_recopy_stopped_at_its_first_copy_keeps_the_record(job, tmp_path, capsys, monkeypatch):
	target = a_failed_sync_then_a_nul_file(job, tmp_path, capsys, monkeypatch)
	copy_command = rv.copy_command
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(path))

	def stopping(source, dest):
		rv.RESTORE_STOP.set()
		return copy_command(source, dest)
	with monkeypatch.context() as stopped:
		stopped.setattr(rv, 'copy_command', stopping)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	# the recopy is not done: no sync on the way out drops its record, and the Interrupted line says what a run again does
	assert code == rv.EXIT_COMMAND_FAILED and synced == []
	assert marker_of(target).get('recopy') == 'sync failed'
	assert err.startswith(f'Interrupted: what {target} holds is not known to be on disk: run the same restore again, which copies everything again')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert whole(target)


def test_a_recopy_with_a_failed_copy_keeps_the_record_past_a_good_sync(job, tmp_path, capsys, monkeypatch):
	target = a_failed_sync_then_a_nul_file(job, tmp_path, capsys, monkeypatch)
	copy_command = rv.copy_command
	with monkeypatch.context() as failing:
		failing.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('a.txt') else copy_command(source, dest))
		code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	# its sync succeeded, but a.txt was not copied again: the recopy is not done
	assert marker_of(target).get('recopy') == 'sync failed'
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert code == rv.EXIT_USAGE and 'a sync of what it holds failed' in err
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert whole(target)


class Killed(BaseException):
	'''A signal the restore cannot catch, SIGKILL: nothing of it runs after.'''


def killed_at_its_sync(job, tmp_path, capsys, monkeypatch):
	'''A restore of proj into out killed after its copies, before its sync: the target, its marker saying its copies are not known to be on disk.'''
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	with monkeypatch.context() as killing:
		killing.setattr(rv, 'sync_restore', lambda *args: (_ for _ in ()).throw(Killed()))
		with pytest.raises(Killed):
			restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	# one value, whatever the boot and the mounts
	assert marker_of(target) == {'job': job.job_name, 'path': 'proj', 'version': rv.list_versions(job.job_vault)[0].name, 'unsynced': True}
	return target


# "unsynced" as this build writes it, and as earlier 0.55.2 builds did: a boot id and the target's mounts, or '' for none
# to tell; and a value no build wrote
@pytest.mark.parametrize('unsynced', [True, '3f2a9c1e-7b4d-4e8a-9c0f-5d6e7f8a9b0c mount 2147484088,2147484101', '', None], ids=['as_written', 'a_boot_and_mounts', 'none_to_tell', 'null'])
def test_a_run_again_after_a_kill_copies_everything_again_and_accept_is_refused(job, tmp_path, capsys, monkeypatch, unsynced):
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	written = {**marker_of(target), 'unsynced': unsynced}
	with open(marker, 'w', encoding='utf-8') as f:
		json.dump(written, f)
	assert rv.read_restore_marker(target)['unsynced'] is True
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert 'no sync of what it holds is known to have succeeded' in err and 'a sync of what it holds failed' not in err
	made = copies(monkeypatch)
	marks = []
	write_restore_marker = rv.write_restore_marker
	monkeypatch.setattr(rv, 'write_restore_marker', lambda *args, **kwargs: marks.append((kwargs.get('unsynced'), kwargs.get('recopy'))) or write_restore_marker(*args, **kwargs))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	# read as a cut: recorded so from the claim on, nothing kept, everything copied again, then synced
	assert marks[0] == (False, 'cut') and marks[-1] == (False, None)
	assert sorted(os.path.relpath(source, rv.list_versions(job.job_vault)[0].path) for source in made) == sorted(FILES)
	assert 'keeping' not in stdout and whole(target) and not os.path.lexists(marker)


def test_a_write_error_copies_everything_again(job, tmp_path, capsys, monkeypatch):
	target = a_failed_sync_then_a_nul_file(job, tmp_path, capsys, monkeypatch)
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert sorted(os.path.basename(source) for source in made) == ['a.txt', 'b.txt'] and whole(target)


def test_a_file_targets_folder_that_cannot_be_opened_is_a_warning(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	real_open = os.open

	def opening(path, flags, *args, **kwargs):
		if os.fspath(path) == out and flags & os.O_DIRECTORY:
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(path))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	# opened once, before the copy: restored, but not known to be on disk
	assert code == 0 and synced == []
	warnings = [line for line in stdout.splitlines() if line.startswith('WARNING')]
	assert len(warnings) == 1 and warnings[0].startswith(f'WARNING proj/a.txt: could not open {out} to sync it: ')
	assert warnings[0].endswith(f'{os.path.join(out, "a.txt")} is not known to be on disk')



def test_a_failed_sync_whose_record_cannot_be_written_leaves_the_claims_record(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	with monkeypatch.context() as failing:
		record(failing, fail=lambda n: write_error(n))
		write_restore_marker = rv.write_restore_marker

		def refusing(*args, **kwargs):
			if kwargs.get('recopy'):
				raise OSError(errno.EROFS, os.strerror(errno.EROFS))
			return write_restore_marker(*args, **kwargs)
		failing.setattr(rv, 'write_restore_marker', refusing)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	# the marker of the claim stays, saying its copies are not known to be on disk, which a run again copies again over
	assert marker_of(target).get('unsynced') is True and 'recopy' not in marker_of(target)
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and 'write error' in failed[0]
	assert f'What {target} holds is not known to be on disk: run the same restore again, which copies everything again' in stdout
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert sorted(os.path.basename(source) for source in made) == ['a.txt', 'b.txt'] and whole(target)
