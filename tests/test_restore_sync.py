'''
0.55.2: a restore syncs the target's filesystem before its marker goes (before the folders are handed over), and again
after, before the command returns; a file target once, once it is in place. Every sync goes through handles opened before
the first copy, so it reports every writeback error since: off a pool the target as this run claimed it (a file target's
folder, opened before the copy), on a pool one per filesystem, at the target's place on each branch or its nearest existing
parent. The marker says what the target holds is not known to be
on disk until a sync succeeds; a sync that fails is a failure of the restore that names the disk, the record stays, and
the run again copies everything again while --accept is refused. A run stopped before its sync syncs on its way out, so a
run again keeps what it copied; one killed before it leaves a record that a run again copies everything again over. A
pool disk none of whose branches the user can open is a warning, once per restore.
'''
import errno
import json
import os
import re
import shutil
import stat
import time
import pytest
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, write_rule

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


def unfinished(job, tmp_path, capsys, monkeypatch, out=None):
	'''A folder restore of proj into out (a new folder by default) that failed on sub/b.txt, leaving its marker: the target.'''
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	out = destination(tmp_path) if out is None else out
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
	monkeypatch.setattr(rv, 'LIBC_SYNCFS', lambda fd: pytest.fail(f'fd {fd} synced past syncfs_fd()'))
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
	assert failed == [f'FAILED proj: the disk {disk_of(target)} reported a write error as the restore was written out to it ({write_error(1)}): what was restored may not be on it']
	if accept:
		# nothing was kept: the head says so
		assert stdout.splitlines()[0] == f'Did not keep {target} as it is, restored from V0: gave no folder its own metadata, copied nothing'
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
	# the copies were synced and the marker is gone: the line says what the sync was for, and the files restored are on disk
	assert failed == [f"FAILED proj: the disk {disk_of(target)} reported a write error as the restore's last changes were written out to it ({write_error(2)}): the files restored are on disk, but their folders' owners, modes and times and the marker's removal may not be"]
	assert 'what was restored may not be on it' not in stdout
	assert 'run the same restore again' not in stdout + err


def test_accept_whose_sync_after_the_hand_over_fails_does_not_say_all_went_well(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	target = unfinished(job, tmp_path, capsys, monkeypatch)
	record(monkeypatch, fail=lambda n: write_error(n) if n == 2 else None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert code == rv.EXIT_COMMAND_FAILED
	lines = stdout.splitlines()
	# the failure is written as it happens too
	assert err == lines[1] + '\n'
	# kept as it is, but not all of it known to be on disk, and the failure line says which part
	assert lines[0] == f'Kept {target} as it is, restored from V0: gave 2 folders their own metadata, copied nothing, but not all of it is known to be on disk'
	assert len(lines) == 2 and lines[1].startswith(f'FAILED proj: the disk {disk_of(target)} reported a write error as the restore\'s last changes were written out to it (')
	assert lines[1].endswith("the files restored are on disk, but their folders' owners, modes and times and the marker's removal may not be")
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_failed_sync_of_a_file_target_fails_the_restore(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: (_ for _ in ()).throw(write_error(1)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj/a.txt', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith('FAILED proj/a.txt: ') and 'write error' in failed[0] and disk_of(out) in failed[0]


def pooled(tmp_path, fake_pool, disks, other=None):
	'''
	The folder to restore into, out, on a mergerfs pool (FakePool) over the branches of disks, {disk: [branch names]}: each
	disk a mount of its own and its branches folders of it, as two branches of one disk are. The fake mounts are folders of
	the basetemp's filesystem, and a restore keeps one handle per filesystem: with other, a folder on another filesystem
	(other_filesystem), the disks after the first are mounts made there, a filesystem other than the first disk's, as a real
	disk is. (out, {branch name: its path}).
	'''
	branches = {}
	for index, (disk, names) in enumerate(disks.items()):
		mount = fake_pool.add_mount(os.path.join(other, disk) if other is not None and index else str(tmp_path / 'disks' / disk))
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
	'''
	Append ('opened', path, fd) to events for each open of one of branches, or of a folder on one, and 'copy' for each copy the
	restore starts.
	'''
	real_open = os.open

	def opening(path, flags, *args, **kwargs):
		fd = real_open(path, flags, *args, **kwargs)
		if any(os.fspath(path) == branch or os.fspath(path).startswith(branch + os.sep) for branch in branches.values()):
			events.append(('opened', os.fspath(path), fd))
		return fd
	monkeypatch.setattr(os, 'open', opening)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: events.append('copy') or copy_command(source, dest))


@pytest.mark.parametrize('kind', ['folder', 'file'])
def test_a_pools_disks_are_opened_before_the_first_copy_and_every_sync_goes_through_them(job, tmp_path, capsys, monkeypatch, fake_pool, kind, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']}, other_filesystem)
	events = []
	opened_branches(monkeypatch, branches, events)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append(('sync', fd)))
	# never a path opened at the sync, the pool's own included, whose sync does not reach the disks
	monkeypatch.setattr(rv, 'LIBC_SYNCFS', lambda fd: pytest.fail(f'fd {fd} synced past syncfs_fd()'))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj' + ('/a.txt' if kind == 'file' else ''), out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	opened = [event for event in events if event[0] == 'opened']
	# each disk's branch, as the nearest existing parent of the target's place on it, once, before the first copy
	assert sorted(path for _, path, _ in opened) == sorted(branches.values())
	assert events.index(opened[-1]) < events.index('copy')
	# a folder target's two syncs, a file target's one: each of every disk, through those fds
	synced = [event[1] for event in events if event[0] == 'sync']
	assert sorted(synced) == sorted([fd for _, _, fd in opened] * (2 if kind == 'folder' else 1))


def test_a_copy_landing_on_a_disk_without_the_target_at_the_claim_is_synced(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']}, other_filesystem)
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
	# disk two synced too, through its branch (the nearest existing parent of the target's place there) as opened before the
	# copy that put the folder there
	opened = {event[2] for event in events if event[0] == 'opened'}
	synced = [event for event in events if event[0] == 'sync']
	assert {fd for _, fd, _ in synced} <= opened
	assert os.lstat(branches['two']).st_ino in {ino for _, _, ino in synced}


def a_disk_joins(fake_pool, tmp_path, other, holds=True):
	'''
	A new disk, a mount made in other (a folder on another filesystem than the pool's disks), joins the pool (a branch added at
	run time), and mergerfs puts the restore's folder on it unless holds is False, as it does once a copy lands there: (the
	disk, its branch).
	'''
	branch = fake_pool.join(str(tmp_path / 'pool'), os.path.join(other, 'new'), 'new')
	if holds:
		os.makedirs(os.path.join(branch, 'out', 'proj'))
	return os.path.realpath(os.path.join(other, 'new')), branch


def joining_at_the_first_copy(monkeypatch, fake_pool, tmp_path, other, holds=True):
	'''The restore's first copy starts as a disk joins the pool (a_disk_joins()): the (disk, branch) once it did, in the list returned.'''
	joined = []
	copy_command = rv.copy_command

	def joining(source, dest):
		if not joined:
			joined.append(a_disk_joins(fake_pool, tmp_path, other, holds))
		return copy_command(source, dest)
	monkeypatch.setattr(rv, 'copy_command', joining)
	return joined


def joined_line(disk):
	return f'FAILED proj: the disk {disk} joined the pool while the restore ran: what was restored onto it is not known to be on disk'


def test_a_disk_that_joined_the_pool_after_the_claim_fails_the_restore_and_a_run_again_finishes(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	target = os.path.join(out, 'proj')
	joined = joining_at_the_first_copy(monkeypatch, fake_pool, tmp_path, other_filesystem)
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(os.fstat(fd).st_ino))
	# an fd opened now would miss a writeback error another sync of that disk met first
	monkeypatch.setattr(rv, 'LIBC_SYNCFS', lambda fd: pytest.fail(f'fd {fd} synced past syncfs_fd()'))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	(disk, branch), = joined
	assert code == rv.EXIT_COMMAND_FAILED
	assert [line for line in stdout.splitlines() if line.startswith('FAILED')] == [joined_line(disk)]
	# the disk it had a handle for was synced, the new one not at all; nothing was handed over, and a run again is offered
	assert synced == [os.lstat(branches['one']).st_ino]
	assert marker_of(target).get('recopy') == 'sync failed' and 'unsynced' not in marker_of(target)
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	assert f'What {target} holds is not known to be on disk: run the same restore again, which copies everything again' in stdout
	# the run again opens that disk at its own claim, at the target's place there, and finishes
	synced.clear()
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert sorted(os.path.relpath(source, rv.list_versions(job.job_vault)[0].path) for source in made) == sorted(FILES)
	assert sorted(synced) == sorted([os.lstat(branches['one']).st_ino, os.lstat(os.path.join(branch, 'out', 'proj')).st_ino] * 2)
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and whole(target)


def test_a_disk_mounted_onto_a_listed_branchs_folder_after_the_claim_fails_the_restore(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	# two branches that are folders of the root filesystem at the claim, which names one disk for both
	fake_pool.add(str(tmp_path / 'pool'), ['one', 'two'])
	fake_pool.drop('one')
	fake_pool.drop('two')
	out = tmp_path / 'pool' / 'out'
	out.mkdir()
	copy_command = rv.copy_command
	two = fake_pool.branch_path('two')
	disk = os.path.join(other_filesystem, 'two')

	def mounting(source, dest):
		if not os.path.islink(two):
			# a disk mounted at the branch's folder, which mergerfs then puts the copy on: a symlink to a folder on another
			# filesystem stands in for it, as os.stat() follows it to another st_dev, and the fake table names its mount
			os.rename(two, two + '.before')
			os.makedirs(os.path.join(disk, 'out', 'proj'))
			os.symlink(disk, two)
			fake_pool.add_mount(disk)
		return copy_command(source, dest)
	monkeypatch.setattr(rv, 'copy_command', mounting)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', str(out), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert [line for line in stdout.splitlines() if line.startswith('FAILED')] == [joined_line(os.path.realpath(disk))]
	assert marker_of(os.path.join(str(out), 'proj')).get('recopy') == 'sync failed'


def test_a_disk_that_joined_the_pool_without_the_restores_folder_is_passed_over(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	joined = joining_at_the_first_copy(monkeypatch, fake_pool, tmp_path, other_filesystem, holds=False)
	synced = []
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(os.fstat(fd).st_ino))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	# nothing can have landed there
	assert joined and (code, err) == (0, ''), stdout
	assert 'FAILED' not in stdout and 'WARNING' not in stdout
	assert synced == [os.lstat(branches['one']).st_ino] * 2


@pytest.mark.parametrize('sync', ['accept', 'stop'])
def test_a_disk_that_joined_the_pool_fails_the_sync_of_accept_and_of_a_stop_too(job, tmp_path, capsys, monkeypatch, fake_pool, sync, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	target = os.path.join(out, 'proj')
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: None)
	if sync == 'accept':
		target = unfinished(job, tmp_path, capsys, monkeypatch, out=out)
		joined = []
		remove_stale_partials = rv.remove_stale_partials

		def joining(folder, held):
			# once accept holds the target: its handles are open
			if not joined:
				joined.append(a_disk_joins(fake_pool, tmp_path, other_filesystem))
			return remove_stale_partials(folder, held)
		monkeypatch.setattr(rv, 'remove_stale_partials', joining)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
		assert code == rv.EXIT_COMMAND_FAILED
		assert stdout.splitlines()[0].startswith('Did not keep ')
		failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
		assert err == failed[0] + '\n'
	else:
		joined = joining_at_the_first_copy(monkeypatch, fake_pool, tmp_path, other_filesystem)
		code, stdout, err = stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out)
		assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
		lines = err.splitlines()
		assert lines[0] == stopping_line(target) and lines[2:] == [recopy_line(target)]
		failed = lines[1:2]
	(disk, _), = joined
	assert failed == [joined_line(disk)]
	# a run again copies everything again, which --accept is refused until it did
	assert marker_of(target).get('recopy') == 'sync failed'
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'a sync of what it holds failed' in err
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert whole(target) and not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_branch_that_failed_to_open_at_the_claim_is_not_called_a_write_error(job, tmp_path, capsys, monkeypatch, fake_pool):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']})
	target = os.path.join(out, 'proj')
	error = OSError(errno.EIO, os.strerror(errno.EIO), branches['two'])
	real_open = os.open

	def opening(path, flags, *args, **kwargs):
		# neither not there nor shut out to the user: any other failure
		if flags & os.O_DIRECTORY and os.fspath(path) == branches['two']:
			raise error
		return real_open(path, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: None)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	disk = rv.vault_disks(branches['two'])[1][0][0]
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert failed == [f'FAILED proj: the disk {disk} could not be opened to write the restore out to it ({error}): what was restored may not be on it']
	assert 'write error' not in stdout
	assert marker_of(target).get('recopy') == 'sync failed'


def test_a_stop_on_a_pool_syncs_through_the_handles_opened_at_the_claim(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']}, other_filesystem)
	target = os.path.join(out, 'proj')
	events = []
	opened_branches(monkeypatch, branches, events)
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: events.append(('sync', fd)))
	# never a path opened at the sync, the pool's own included
	monkeypatch.setattr(rv, 'LIBC_SYNCFS', lambda fd: pytest.fail(f'fd {fd} synced past syncfs_fd()'))
	code, stdout, err = stopped_at_its_second_copy(job, tmp_path, capsys, monkeypatch, out)
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	assert err == f'{stopping_line(target)}\nInterrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {rv.unfinished_note(target)}\n'
	opened = [event for event in events if event[0] == 'opened']
	# each disk's branch once, before the first copy, and no branch opened after it
	assert sorted(path for _, path, _ in opened) == sorted(branches.values())
	assert events.index(opened[-1]) < events.index('copy')
	# the one sync, on the way out, through both of those
	assert sorted(event[1] for event in events if event[0] == 'sync') == sorted(fd for _, _, fd in opened)
	assert 'unsynced' not in marker_of(target) and 'recopy' not in marker_of(target)


def test_a_failed_second_listing_of_the_pool_says_the_look_for_a_joined_disk_failed(job, tmp_path, capsys, monkeypatch, fake_pool):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	target = os.path.join(out, 'proj')
	error = OSError(errno.EIO, os.strerror(errno.EIO), 'the branch list')
	synced, armed = [], []
	# the pool is listed again right after the handles were synced
	monkeypatch.setattr(rv, 'syncfs_fd', lambda fd, path=None: synced.append(os.fstat(fd).st_ino) or armed.append(True))
	vault_disks = rv.vault_disks

	def listing(path, roots=False):
		if armed and not roots:
			armed.clear()
			raise error
		return vault_disks(path, roots)
	monkeypatch.setattr(rv, 'vault_disks', listing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	# the handles were synced: it is not said that the disks could not be listed to write the restore out to them
	assert failed == [f'FAILED proj: the disks holding {target} could not be listed again to check for a disk that joined the pool while the restore ran: {error}']
	assert synced == [os.lstat(branches['one']).st_ino]
	assert marker_of(target).get('recopy') == 'sync failed'


def deny(monkeypatch, paths):
	'''An open of a folder of paths (a callable, or a set) as a folder fails with EACCES, as for a user its mode shuts out.'''
	real_open = os.open
	shut = paths if callable(paths) else (lambda path: path in paths)

	def opening(path, flags, *args, **kwargs):
		if flags & os.O_DIRECTORY and shut(os.fspath(path)):
			raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
		return real_open(path, flags, *args, **kwargs)
	monkeypatch.setattr(os, 'open', opening)


def test_a_disk_none_of_whose_branches_the_user_can_open_is_a_warning_once(job, tmp_path, capsys, monkeypatch, fake_pool, other_filesystem):
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one-a', 'one-b'], 'two': ['two']}, other_filesystem)
	target = os.path.join(out, 'proj')
	# disk one's first branch shut out, its second fine, so its filesystem is synced through the second; disk two's only
	# branch shut out, as a mode without read for the user shuts a folder it can still go through
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
	# handle of the claim, the restore folder's place on its branch (held), never through the folder opened again
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
	assert 'WARNING' not in stdout
	assert synced == [os.lstat(held).st_ino] * 2


# ---- F2: on a pool the restore's handles open at its folder's place on each branch, or its nearest existing parent, one per
# filesystem, and every one is synced; its check for a joined disk goes by filesystem. A symlink to a folder on /dev/shm stands
# in for a mount nested under a branch, as os.open() and os.stat() follow it to another st_dev

def at_the_first_copy(monkeypatch, then):
	'''then() runs once, as the restore's first copy starts: the list returned holds True once it ran.'''
	ran = []
	copy_command = rv.copy_command

	def copying(source, dest):
		if not ran:
			ran.append(True)
			then()
		return copy_command(source, dest)
	monkeypatch.setattr(rv, 'copy_command', copying)
	return ran


def nested_at(fake_pool, branch, other_filesystem):
	'''The restore's folder's place on branch (out/proj), a filesystem of its own: the folder on /dev/shm it leads to, a mount in the fake table; its real path.'''
	nested = fake_pool.add_mount(os.path.join(other_filesystem, os.path.basename(branch)))
	os.makedirs(os.path.join(branch, 'out'), exist_ok=True)
	os.symlink(nested, os.path.join(branch, 'out', 'proj'))
	return nested


def write_error_line(disk):
	return f'FAILED proj: the disk {disk} reported a write error as the restore was written out to it ('


def test_a_restore_onto_a_nested_mount_of_a_branch_reports_its_write_error(job, tmp_path, capsys, monkeypatch, fake_pool, errseq, other_filesystem):
	# fails on main (says done): its one handle is the branch root's, on another filesystem than the folder's place
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	nested = nested_at(fake_pool, branches['one'], other_filesystem)
	ran = at_the_first_copy(monkeypatch, lambda: errseq.fail(nested))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert ran and code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	# it names the disk that failed, the nested mount, not the branch's own (healthy) disk
	assert len(failed) == 1 and failed[0].startswith(write_error_line(nested))
	assert marker_of(os.path.join(out, 'proj')).get('recopy') == 'sync failed'


def test_a_restore_syncs_both_filesystems_of_branches_of_one_disk(job, tmp_path, capsys, monkeypatch, fake_pool, errseq, other_filesystem):
	# fails on main: one handle per disk name, the first branch's that opens, so the second filesystem is never synced
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one-a', 'one-b']})
	nested = nested_at(fake_pool, branches['one-b'], other_filesystem)
	ran = at_the_first_copy(monkeypatch, lambda: errseq.fail(nested))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert ran and code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith(write_error_line(nested))
	# both filesystems of the disk were synced
	assert {event[3] for event in errseq.events if event[0] == 'syncfs'} == {os.stat(branches['one-a']).st_dev, os.stat(nested).st_dev}


def test_a_mount_made_at_the_restore_folders_place_during_the_restore_fails_it(job, tmp_path, capsys, monkeypatch, fake_pool, errseq, other_filesystem):
	# fails on main (says done): its check for a joined disk goes by disk name, which a mount at a listed branch's folder keeps
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one']})
	target = os.path.join(out, 'proj')
	# at the claim the folder's place on the branch is not there; at the first copy a mount is made there, and the copy lands on it
	made = []
	ran = at_the_first_copy(monkeypatch, lambda: made.append(nested_at(fake_pool, branches['one'], other_filesystem)))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert ran and code == rv.EXIT_COMMAND_FAILED
	# it names the disk that was mounted, not the branch's own one, which was in the pool already
	assert [line for line in stdout.splitlines() if line.startswith('FAILED')] == [joined_line(made[0])]
	assert marker_of(target).get('recopy') == 'sync failed'


@pytest.mark.skipif(os.geteuid() == 0, reason='root opens any folder')
def test_a_place_the_user_can_go_through_but_not_read_is_synced_through_its_branch(job, tmp_path, capsys, monkeypatch, fake_pool, errseq, other_filesystem):
	# fails at 15b3108: the open of the place raises EACCES, the restore warns, hears no write error there and says done (0.55.4
	# opened the branch and failed it)
	backed_up(job)
	out, branches = pooled(tmp_path, fake_pool, {'one': ['one'], 'two': ['two']}, other_filesystem)
	# on branch two the restore folder's parent, out, can be gone through and written in by the restoring user, not read
	parent = os.path.join(branches['two'], 'out')
	os.makedirs(parent)
	os.chmod(parent, 0o311)
	landed = os.path.join(parent, 'proj')

	def lands():
		# the copy lands on branch two, whose folder is made there, and the disk meets a write error
		os.mkdir(landed)
		errseq.fail(landed)
	ran = at_the_first_copy(monkeypatch, lands)
	try:
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	finally:
		os.chmod(parent, 0o755)
	assert ran and code == rv.EXIT_COMMAND_FAILED, stdout
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and failed[0].startswith(write_error_line(os.path.realpath(os.path.dirname(branches['two']))))


def test_disks_that_cannot_be_listed_are_not_called_a_write_error(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	vault_disks = rv.vault_disks

	error = OSError(errno.EIO, os.strerror(errno.EIO), 'the branch list')

	def listing(path, roots=False):
		# for the handles the syncs go through, opened at the claim; the marker's fsync lists them too, and can
		if roots:
			raise error
		return vault_disks(path)
	monkeypatch.setattr(rv, 'vault_disks', listing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert failed == [f'FAILED proj: the disks holding {target} could not be listed to write the restore out to them: {error}']
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
	# that folder once: only the first marker of the run that made the target needs it
	assert [event for event in events if event[:2] == ('fsync', out)] == [('fsync', out, True)]


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
	# one value; and that this restore made the target
	assert marker_of(target) == {'job': job.job_name, 'path': 'proj', 'version': rv.list_versions(job.job_vault)[0].name, 'unsynced': True, 'made': True}
	return target


# "unsynced" as the restore writes it, and whatever else a marker holds there: it reads as unsynced all the same
@pytest.mark.parametrize('unsynced', [True, 'any text', None], ids=['as_written', 'a_string', 'null'])
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


# the failures no run again can fix: RESTORE_FINAL_KINDS, and a path the target's filesystem refuses as too long (ENAMETOOLONG)
# at each step of restoring an entry: its copy by cp, its folder, the rename of its copy into place and, as a run again
# picking up an earlier run's output looks at what is there, a look at it
FINAL_KINDS = ['dangling', 'referenced', 'too_long', 'folder', 'rename', 'lstat']
# the look at what is there is made only by a run picking up an earlier run's output
FIRST_RUN_KINDS = [kind for kind in FINAL_KINDS if kind != 'lstat']
# a stop in the hand-over comes between two folders: a folder that cannot be made leaves the target the only one
STOPPED_KINDS = [kind for kind in FINAL_KINDS if kind != 'folder']


def a_final_failure(kind, job, monkeypatch):
	'''
	An entry of V0 that no run again can restore, of kind (one of FINAL_KINDS): (the entry's path as its FAILED line names
	it, the pattern the line's reason matches, the files a run that copies everything makes).
	'''
	refused = OSError(errno.ENAMETOOLONG, os.strerror(errno.ENAMETOOLONG))
	if kind == 'referenced':
		held = os.path.join(rv.list_versions(job.job_vault)[0].path, 'proj/sub/b.txt')
		os.remove(held)
		# a referenced backup links the vault entry to the monitored file itself
		os.symlink(f'{job.monitor}/proj/sub/b.txt', held)
		return 'proj/sub/b.txt', re.escape('not held in the vault (referenced backup)'), ['a.txt']
	if kind == 'dangling':
		resolved_entry = rv.resolved_entry

		def resolving(job_vault, walked, monitor_path):
			found = resolved_entry(job_vault, walked, monitor_path)
			return rv.ResolvedEntry('dangling', found.path, 'V0 is missing') if walked.path.endswith('b.txt') else found
		monkeypatch.setattr(rv, 'resolved_entry', resolving)
		return 'proj/sub/b.txt', re.escape('dangling vault link: V0 is missing'), ['a.txt']
	if kind == 'too_long':
		copy_command = rv.copy_command
		monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['sh', '-c', 'echo "cp: cannot create regular file \'$1\': File name too long" >&2; exit 1', 'sh', dest]
			if source.endswith('b.txt') else copy_command(source, dest))
		return 'proj/sub/b.txt', "cp: cannot create regular file '.*': File name too long", ['a.txt', 'b.txt']
	if kind == 'folder':
		make_restore_folder = rv.make_restore_folder

		def making(dest):
			if dest.endswith('/proj/sub'):
				raise refused
			return make_restore_folder(dest)
		monkeypatch.setattr(rv, 'make_restore_folder', making)
		return 'proj/sub', re.escape(f'{refused}: nothing in it was restored'), ['a.txt']
	if kind == 'rename':
		replace_entry = rv.replace_entry

		def replacing(temp_path, dest_path):
			if dest_path.endswith('/proj/sub/b.txt'):
				raise refused
			return replace_entry(temp_path, dest_path)
		monkeypatch.setattr(rv, 'replace_entry', replacing)
		return 'proj/sub/b.txt', re.escape(str(refused)), ['a.txt', 'b.txt']
	lstat = os.lstat

	def looking(path, *args, **kwargs):
		# at the restored copy, not the vault's
		if os.fspath(path).endswith('/out/proj/sub/b.txt'):
			raise refused
		return lstat(path, *args, **kwargs)
	monkeypatch.setattr(os, 'lstat', looking)
	return 'proj/sub/b.txt', re.escape(str(refused)), ['a.txt']


@pytest.mark.parametrize('kind', FIRST_RUN_KINDS)
def test_a_failure_no_run_again_fixes_does_not_hold_a_restore(job, tmp_path, capsys, monkeypatch, kind):
	backed_up(job)
	rel, reason, _ = a_final_failure(kind, job, monkeypatch)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	events = record(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and re.fullmatch(f'FAILED {rel}: ' + reason, failed[0])
	# finished, naming it: the rest restored, the folders handed over, the marker gone, and no run again offered
	assert 'hand over' in events and 'handed over' in events
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and whole(target)
	assert not os.path.lexists(os.path.join(target, 'sub', 'b.txt'))
	assert not [name for _, _, names in os.walk(target) for name in names if name.endswith(rv.PARTIAL_COPY_SUFFIX)]
	assert 'run the same restore again' not in stdout + err and '--accept' not in stdout + err


@pytest.mark.parametrize('kind', FINAL_KINDS)
def test_a_run_again_after_a_kill_finishes_over_a_failure_no_run_again_fixes(job, tmp_path, capsys, monkeypatch, kind):
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	rel, reason, copied = a_final_failure(kind, job, monkeypatch)
	made = copies(monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = [line for line in stdout.splitlines() if line.startswith('FAILED')]
	assert len(failed) == 1 and re.fullmatch(f'FAILED {rel}: ' + reason, failed[0])
	# everything copied again (all that can be copied: a chain, a link or a folder that cannot be made are not), the one
	# entry named, the record cleared and the restore finished: nothing left to run again
	assert sorted(os.path.basename(source) for source in made) == copied and whole(target)
	assert 'keeping' not in stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	assert 'run the same restore again' not in stdout + err


@pytest.mark.parametrize('kind', STOPPED_KINDS)
def test_a_run_again_after_a_kill_over_such_a_failure_that_stops_in_its_hand_over_is_finished_by_accept(job, tmp_path, capsys, monkeypatch, kind):
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	a_final_failure(kind, job, monkeypatch)
	restore_folder_meta = rv.restore_folder_meta

	def stopping(*args, **kwargs):
		rv.RESTORE_STOP.set()
		return restore_folder_meta(*args, **kwargs)
	with monkeypatch.context() as stopped:
		stopped.setattr(rv, 'restore_folder_meta', stopping)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'finish it by running the same restore again with --accept' in err
	# its sync cleared the record before it handed anything over, so --accept is not refused
	assert 'unsynced' not in marker_of(target) and 'recopy' not in marker_of(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, err) == (0, ''), stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and whole(target)


def test_a_recopy_of_a_vault_missing_a_disk_keeps_its_recopy_and_the_target_private(job, tmp_path, capsys, monkeypatch):
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	# a leftover of the killed run, whose bytes were lost
	nul_out(os.path.join(target, 'a.txt'))
	iter_version_entries = rv.iter_version_entries

	def without_a_txt(*args, **kwargs):
		# a disk of the vault's pool is missing: its entries are not in the walk
		for entry_rel, walked in iter_version_entries(*args, **kwargs):
			if entry_rel != 'proj/a.txt':
				yield entry_rel, walked
	handed = []
	hand_over_folders = rv.hand_over_folders
	with monkeypatch.context() as incomplete:
		incomplete.setattr(rv, 'vault_pool_warning', lambda job_vault: True)
		incomplete.setattr(rv, 'iter_version_entries', without_a_txt)
		incomplete.setattr(rv, 'hand_over_folders', lambda *args, **kwargs: handed.append(args) or hand_over_folders(*args, **kwargs))
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	# not everything was copied again: the recopy stays, nothing is handed over, and the NUL file is not taken as done
	assert code == rv.EXIT_COMMAND_FAILED and handed == []
	assert marker_of(target).get('recopy') == 'cut' and stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	assert not whole(target)
	assert stdout.splitlines()[-1] == f"What {target} holds is not known to be on disk, and a disk of the vault's pool is missing, whose entries this run did not meet: run the same restore again once all the vault's disks are there, which copies everything again. {rv.unfinished_note(target)}"
	assert 'If that keeps failing' not in stdout
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert code == rv.EXIT_USAGE and 'no sync of what it holds is known to have succeeded' in err
	# once the vault's disks are all there, the run again copies everything again and finishes
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert whole(target) and not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def test_a_first_restore_of_a_vault_missing_a_disk_is_not_held_for_it(job, tmp_path, capsys, monkeypatch):
	# nothing was left by an earlier run: what the walk does not meet is not there, and the exit code says why
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	monkeypatch.setattr(rv, 'vault_pool_warning', lambda job_vault: True)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'FAILED' not in stdout
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and whole(target)


def way_out(target, made):
	fresh = f'remove {target} and restore it fresh' if made else 'restore into a new folder instead'
	return f'If that keeps failing, fix the cause and run it again, or {fresh}.'


@pytest.mark.parametrize('reason', ['cut', 'sync failed'])
def test_a_recopy_that_keeps_failing_names_the_way_out_for_a_target_a_restore_made(job, tmp_path, capsys, monkeypatch, reason):
	if reason == 'cut':
		target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	else:
		target = a_failed_sync_then_a_nul_file(job, tmp_path, capsys, monkeypatch)
	assert marker_of(target)['made'] is True
	# --accept is refused, and says what to do about a run again that cannot finish
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert err.endswith(f'run the same restore again without --accept, which copies everything again. {way_out(target, True)}\n')
	# the run again fails a copy, and its summary says so too; the marker still says the restore made the target
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout.splitlines()[-1] == f'What {target} holds is not known to be on disk: run the same restore again, which copies everything again. {way_out(target, True)} {rv.unfinished_note(target)}'
	assert marker_of(target)['made'] is True and marker_of(target).get('recopy') == reason


def a_whole_job_root_killed_at_its_sync(job, tmp_path, capsys, monkeypatch):
	'''A restore in place of the whole job into its empty monitored path, which no restore made, killed before its sync: the root.'''
	backed_up(job)
	# a replaced disk: its root empty
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor, 0o755)
	with monkeypatch.context() as killing:
		killing.setattr(rv, 'sync_restore', lambda *args, **kwargs: (_ for _ in ()).throw(Killed()))
		with pytest.raises(Killed):
			restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert 'made' not in marker_of(job.monitor)
	return job.monitor


def test_a_recopy_that_keeps_failing_never_says_to_remove_a_target_no_restore_made(job, tmp_path, capsys, monkeypatch):
	root = a_whole_job_root_killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	code, stdout, err = restore(tmp_path, capsys, root, '--in-place', '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert err.endswith(f'run the same restore again without --accept, which copies everything again. {way_out(root, False)}\n') and 'remove' not in err
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	code, stdout, err = restore(tmp_path, capsys, root, '--in-place', '--version', '0', '--yes')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout.splitlines()[-1] == f'What {root} holds is not known to be on disk: run the same restore again, which copies everything again. {way_out(root, False)} {rv.unfinished_note(root)}'
	assert 'remove' not in stdout and 'made' not in marker_of(root)


def test_a_marker_without_made_never_says_to_remove_the_target(job, tmp_path, capsys, monkeypatch):
	# a marker of 0.55.1 (or one made by hand) says nothing of who made the target
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	written = {key: value for key, value in marker_of(target).items() if key != 'made'}
	with open(marker, 'w', encoding='utf-8') as f:
		json.dump(written, f)
	assert 'made' not in rv.read_restore_marker(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0', '--accept')
	assert code == rv.EXIT_USAGE and err.endswith(f'{way_out(target, False)}\n')


def test_a_dangling_chain_on_a_vault_missing_a_disk_is_not_final(job, tmp_path, capsys, monkeypatch):
	backed_up(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	with monkeypatch.context() as incomplete:
		# a chain of a 0.54 vault to a file on the missing disk reads as leading nowhere
		a_final_failure('dangling', job, incomplete)
		incomplete.setattr(rv, 'vault_pool_warning', lambda job_vault: True)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	# a run again may find it once the disk is back: the target is held for it
	assert code == rv.EXIT_COMMAND_FAILED
	assert os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	assert f'1 failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {rv.unfinished_note(target)}' in stdout
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, ''), stdout
	assert whole(target) and os.path.isfile(os.path.join(target, 'sub', 'b.txt')) and not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))


def recopy_summary(target, made=True, missing=False):
	line = f'What {target} holds is not known to be on disk: run the same restore again, which copies everything again. {way_out(target, made)}'
	if missing:
		line += " A disk of the vault's pool is missing, whose entries this run did not meet: run it again once all the vault's disks are there."
	return f'{line} {rv.unfinished_note(target)}'


@pytest.mark.parametrize('first', [False, True], ids=['recopy', 'first_run'])
def test_a_failed_sync_on_a_vault_missing_a_disk_keeps_its_own_line_and_the_way_out(job, tmp_path, capsys, monkeypatch, first):
	if first:
		backed_up(job)
		out = destination(tmp_path)
		target = os.path.join(out, 'proj')
	else:
		target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
		out = os.path.dirname(target)
	with monkeypatch.context() as incomplete:
		incomplete.setattr(rv, 'vault_pool_warning', lambda job_vault: True)
		record(incomplete, fail=write_error)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and marker_of(target).get('recopy') == 'sync failed'
	# not the line of a recopy kept for the missing disk: the sync is what failed, and the missing disk stands beside it
	assert stdout.splitlines()[-1] == recopy_summary(target, missing=True)


def test_a_stopped_recopy_on_a_vault_missing_a_disk_keeps_its_own_line(job, tmp_path, capsys, monkeypatch):
	target = killed_at_its_sync(job, tmp_path, capsys, monkeypatch)
	copy_command = rv.copy_command

	def stopping(source, dest):
		rv.RESTORE_STOP.set()
		return copy_command(source, dest)
	with monkeypatch.context() as stopped:
		stopped.setattr(rv, 'vault_pool_warning', lambda job_vault: True)
		stopped.setattr(rv, 'copy_command', stopping)
		code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', os.path.dirname(target), '--version', '0')
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	assert err == recopy_line(target) + '\n'
