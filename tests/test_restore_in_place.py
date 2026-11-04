import errno
import io
import json
import os
import re
import shutil
import stat
import sys
from collections import deque
import pytest
import reverberator as rv
from tests.harness import seed_monitor, run_backup, write_rule, rule_row
from tests.test_restore import Terminal, write, backup, versions, version_path, restore, destination, tree, partial_files
from tests.test_status_command import write_state, daemon_record, job_record

pytestmark = pytest.mark.unit

ROOT = os.geteuid() == 0
# another user's id, for what root can hand to someone else
OTHER = 65534
# trusted.* names, which only root can list, read or write
root_only = pytest.mark.skipif(not ROOT, reason='trusted.* extended attributes need root')


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def asides(folder, name):
	'''What a restore in place moved name aside to, in folder.'''
	return sorted(entry for entry in os.listdir(folder) if entry.startswith(name + '.before-restore-'))


def metadata(path):
	st = os.lstat(path)
	return st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns


def kept_root_metadata(version):
	'''metadata() of the monitored root as version's folder keeps it (trusted.reverberator.root).'''
	if not ROOT:
		pytest.skip('trusted.* extended attributes need root')
	root = rv.read_root_meta(version)
	return stat.S_IFDIR | root.mode, root.uid, root.gid, root.mtime_ns


def inodes(top):
	return {rel: os.lstat(os.path.join(top, rel)).st_ino for rel, text in tree(top).items() if text is not None and rel != rv.RESTORE_MARKER_NAME}


def twenty_files(job, folder='proj'):
	files = {f'{folder}/f{i:02}.txt': str(i) for i in range(20)}
	seed_monitor(job, files)
	run_backup(job)
	write_rule(job)
	return {rel[len(folder) + 1:]: text for rel, text in files.items()}


def interrupted(tmp_path, capsys, monkeypatch, path, *extra):
	'''Run a restore that a Ctrl-C stops once its first RESTORE_COPY_BATCH (here 5) of copies are in place.'''
	monkeypatch.setattr(rv, 'RESTORE_COPY_BATCH', 5)
	finish_restore_copies = rv.finish_restore_copies
	calls = []

	def stopping(pending, report):
		calls.append(len(pending))
		if len(calls) == 2:
			raise KeyboardInterrupt
		return finish_restore_copies(pending, report)
	monkeypatch.setattr(rv, 'finish_restore_copies', stopping)
	try:
		return restore(tmp_path, capsys, path, *extra)
	finally:
		monkeypatch.setattr(rv, 'finish_restore_copies', finish_restore_copies)


def mark(target, job, rel, version_name):
	'''target made by hand as a restore's unfinished output, as an earlier run of it leaves it.'''
	os.mkdir(target)
	os.chmod(target, 0o700)
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	with open(marker, 'w', encoding='utf-8') as f:
		json.dump({'job': job.job_name, 'path': rel, 'version': version_name}, f)
	os.chmod(marker, 0o600)
	return marker


def until_then(target):
	'''What a folder restore that did not complete says it leaves until it is run again.'''
	owner = 'root' if ROOT else f'uid {os.geteuid()}'
	return f'Until then {target} stays private (mode 0700) and its folders stay owned by {owner}, without their own modes and times'


@pytest.fixture
def frozen_disk(job, monkeypatch):
	'''The free space of the monitored path as it is the first time it is asked, so a busy disk cannot move it between the command's reading and the test's.'''
	statvfs = os.statvfs
	held = []
	def frozen(path):
		if os.fspath(path) == job.monitor:
			if not held:
				held.append(statvfs(path))
			return held[0]
		return statvfs(path)
	monkeypatch.setattr(os, 'statvfs', frozen)


def disk_line(root, version):
	'''The line a whole-job restore in place shows about the filesystem it writes to.'''
	mount_point, source = rv.mount_holding(rv.current_mount_table(), root)
	st = os.statvfs(root)
	return (f'Restoring the whole job into {root}, on the filesystem mounted at {mount_point} ({source}): '
		f'{rv.show_size(st.f_bavail * st.f_frsize)} free, V{version.number} took {rv.show_size(version.size)} in the vault')


def target_of(name, tmp_path):
	return str(tmp_path / name / 'proj')


def test_in_place_moves_the_current_file_aside(job, tmp_path, capsys):
	seed_monitor(job, {'a.txt': 'v0', 'b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	write(job, 'a.txt', 'edited')
	path = f'{job.monitor}/a.txt'
	code, stdout, err = restore(tmp_path, capsys, path, '--in-place', '--version', '0')
	assert (code, err) == (0, '')
	with open(path, encoding='utf-8') as f:
		assert f.read() == 'v0'
	[aside] = asides(job.monitor, 'a.txt')
	assert re.fullmatch(r'a\.txt\.before-restore-\d{4}-\d\d-\d\d_\d\d-\d\d-\d\d', aside)
	with open(os.path.join(job.monitor, aside), encoding='utf-8') as f:
		assert f.read() == 'edited'
	assert stdout.split('\n') == [f'Moved {path} aside to {job.monitor}/{aside}', f'Restored 1 entries ({rv.show_size(2)}) from V0 to {path}', '']
	held = os.path.join(version_path(job, 0), 'a.txt')
	assert metadata(path) == metadata(held)
	assert sorted(os.listdir(job.monitor)) == sorted(['a.txt', aside, 'b.txt'])
	# nothing there: nothing to move aside
	os.remove(path)
	code, stdout, _ = restore(tmp_path, capsys, path, '--in-place', '--version', '0')
	assert code == 0 and stdout.startswith('Restored 1 entries')
	assert asides(job.monitor, 'a.txt') == [aside]


def test_move_aside_never_takes_a_name_in_use(tmp_path, monkeypatch):
	monkeypatch.setattr(rv.time, 'strftime', lambda *args: '2026-10-21_10-00-00')
	path = str(tmp_path / 'x')
	os.mkdir(path)
	taken = f'{path}.before-restore-2026-10-21_10-00-00'
	os.mkdir(taken)
	os.symlink('nowhere', taken + '-1')
	assert rv.move_aside(path) == taken + '-2'
	assert not os.path.lexists(path) and os.path.isdir(taken + '-2') and os.listdir(taken) == []
	# a symlink is moved as it is, never followed
	os.symlink(str(tmp_path / 'elsewhere'), path)
	os.mkdir(tmp_path / 'elsewhere')
	assert rv.move_aside(path) == taken + '-3'
	assert os.readlink(taken + '-3') == str(tmp_path / 'elsewhere') and os.listdir(tmp_path / 'elsewhere') == []


def test_in_place_folder_is_restored_exactly(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b', 'other.txt': 'o'})
	os.chmod(f'{job.monitor}/proj', 0o751)
	run_backup(job)
	write_rule(job)
	write(job, 'proj/added.txt', 'new')
	write(job, 'proj/a.txt', 'a2')
	target = f'{job.monitor}/proj'
	code, stdout, err = restore(tmp_path, capsys, target, '--in-place', '--version', '0')
	assert (code, err) == (0, '')
	assert tree(target) == {'a.txt': 'a', 'sub/': None, 'sub/b.txt': 'b'}
	[aside] = asides(job.monitor, 'proj')
	assert tree(os.path.join(job.monitor, aside)) == {'a.txt': 'a2', 'added.txt': 'new', 'sub/': None, 'sub/b.txt': 'b'}
	assert stdout.split('\n')[0] == f'Moved {target} aside to {job.monitor}/{aside}'
	assert metadata(target) == metadata(os.path.join(version_path(job, 0), 'proj'))
	assert sorted(os.listdir(job.monitor)) == sorted(['proj', aside, 'other.txt'])


def test_in_place_folder_taken_right_after_the_move_aside(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write_rule(job)
	write(job, 'proj/a.txt', 'a2')
	target = f'{job.monitor}/proj'
	move_aside = rv.move_aside

	def taken_meanwhile(path):
		aside = move_aside(path)
		# as by another program writing there
		os.mkdir(path)
		write(job, 'proj/new.txt', 'new')
		return aside
	monkeypatch.setattr(rv, 'move_aside', taken_meanwhile)
	code, stdout, err = restore(tmp_path, capsys, target, '--in-place', '--version', '0')
	[aside] = asides(job.monitor, 'proj')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout == f'Moved {target} aside to {job.monitor}/{aside}\n'
	assert err == f'{target} was taken meanwhile, right after what was there was moved aside to {job.monitor}/{aside}: nothing was restored; run the restore again to move that aside too\n'
	assert tree(os.path.join(job.monitor, aside)) == {'a.txt': 'a2'} and tree(target) == {'new.txt': 'new'}


def test_in_place_root_needs_an_empty_root(job, frozen_disk, tmp_path, capsys):
	seed_monitor(job, {'a.txt': 'a', 'd/b.txt': 'b', 'lost+found/': None})
	os.chmod(f'{job.monitor}/lost+found', 0o700)
	run_backup(job)
	write_rule(job)
	before = tree(job.monitor)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert f'{job.monitor} is not empty' in err and 'restore it into a folder instead' in err
	assert tree(job.monitor) == before and asides(tmp_path, 'monitor') == []
	# a replaced disk: nothing on it but lost+found
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor)
	os.mkdir(f'{job.monitor}/lost+found', 0o700)
	write(job, 'lost+found/#1234', 'found')
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'is not empty' in err
	assert tree(job.monitor) == {'lost+found/': None, 'lost+found/#1234': 'found'}
	os.remove(f'{job.monitor}/lost+found/#1234')
	shown_disk = disk_line(job.monitor, versions(job)[0])
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert tree(job.monitor) == {'a.txt': 'a', 'd/': None, 'd/b.txt': 'b', 'lost+found/': None}
	# the root and lost+found, the new disk's own, with the version's metadata: the root's as its version folder keeps it
	assert (err, stdout) == (f'{shown_disk}\n', f'Restored 5 entries ({rv.show_size(2)}) from V0 to {job.monitor}\n')
	assert metadata(job.monitor) == kept_root_metadata(version_path(job, 0))
	assert metadata(f'{job.monitor}/lost+found') == metadata(os.path.join(version_path(job, 0), 'lost+found'))


def test_in_place_never_moves_a_vault_aside(job, tmp_path, capsys):
	seed_monitor(job, {'data/a.txt': 'a', 'b.txt': 'b'})
	run_backup(job)
	# another job keeps its vault in this job's monitored path
	other_vault = f'{job.monitor}/data/vaults'
	os.makedirs(other_vault)
	other = job._replace(job_name='two', monitor=str(tmp_path / 'two'), vault=other_vault)
	os.mkdir(other.monitor)
	write_rule(job, extra_rows=[rule_row(other)])
	before = tree(job.monitor)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/data', '--in-place', '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert f'holds the vault {other_vault}' in err
	assert tree(job.monitor) == before and asides(job.monitor, 'data') == []


def test_interrupted_restore_picks_up(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	code, stdout, err = interrupted(tmp_path, capsys, monkeypatch, f'{job.monitor}/proj', out, '--version', '0', '--threads', '2')
	assert (code, stdout) == (rv.EXIT_COMMAND_FAILED, '')
	assert err == f'Interrupted: run the same restore again to pick it up, or again with --accept to keep what it restored as it is. {until_then(target)}\n'
	# marked as this restore's own, written whole and private, and the output kept private
	with open(marker, encoding='utf-8') as f:
		assert json.load(f) == {'job': job.job_name, 'path': 'proj', 'version': versions(job)[0].name}
	assert rv.read_restore_marker(target) == {'job': job.job_name, 'path': 'proj', 'version': versions(job)[0].name}
	assert stat.S_IMODE(os.lstat(marker).st_mode) == 0o600
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	before = inodes(target)
	assert len(before) == 5 and partial_files(out) == []
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--threads', '2')
	assert (code, err) == (0, '')
	assert tree(target) == files
	# what the first run restored is kept as it is
	assert {rel: ino for rel, ino in inodes(target).items() if rel in before} == before
	size = sum(len(text) for rel, text in files.items() if rel not in before)
	assert stdout == f'Restored 16 entries ({rv.show_size(size)}) from V0 to {target}, keeping 5 already there\n'
	assert metadata(target) == metadata(os.path.join(version_path(job, 0), 'proj'))
	assert partial_files(out) == []


def test_resume_refuses_a_marker_for_another_version(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	v0, v1 = versions(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	mark(target, job, 'proj', v0.name)
	before = tree(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert v0.name in err and job.job_name in err and 'proj' in err
	assert tree(target) == before
	# another path, or another job, is named too
	other = destination(tmp_path, 'other')
	mark(os.path.join(other, 'proj'), job, 'old/proj', v1.name)
	code, _, err = restore(tmp_path, capsys, f'{job.monitor}/proj', other, '--version', '1')
	assert code == rv.EXIT_USAGE and 'old/proj' in err
	# in place too, and nothing is moved aside
	shutil.rmtree(f'{job.monitor}/proj')
	mark(f'{job.monitor}/proj', job, 'proj', v0.name)
	code, _, err = restore(tmp_path, capsys, f'{job.monitor}/proj', '--in-place', '--version', '1')
	assert code == rv.EXIT_USAGE and v0.name in err
	assert asides(job.monitor, 'proj') == []


def test_unmarked_output_is_never_touched(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	os.mkdir(target, 0o700)
	with open(os.path.join(target, 'a.txt'), 'w', encoding='utf-8') as f:
		f.write('mine')
	before = tree(target), metadata(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert 'already exists' in err
	assert (tree(target), metadata(target)) == before


def watch_folder_meta(monkeypatch, marker):
	'''Each folder restore_folder_meta() is given, with whether the marker was there then.'''
	handed = []
	restore_folder_meta = rv.restore_folder_meta

	def watching(source, dest, **kwargs):
		handed.append((dest, os.path.lexists(marker)))
		return restore_folder_meta(source, dest, **kwargs)
	monkeypatch.setattr(rv, 'restore_folder_meta', watching)
	return handed


def test_failures_keep_the_marker_and_a_rerun_retries(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b', 'proj/sub/c.txt': 'c'})
	if ROOT:
		# someone else's folder, theirs only once the restore is complete
		os.chown(f'{job.monitor}/proj/sub', OTHER, OTHER)
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	held = os.path.join(version_path(job, 0), 'proj/b.txt')
	with open(held, encoding='utf-8') as f:
		kept_copy = f.read()
	st = os.lstat(held)
	os.remove(held)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED
	lines = stdout.rstrip('\n').split('\n')
	assert lines[1].startswith('FAILED proj/b.txt: dangling vault link')
	assert lines[-1] == f'1 failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {until_then(target)}'
	assert os.path.isfile(marker)
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700
	# every folder as the restore made it, for a re-run to write into: none handed to its owner yet
	assert os.lstat(os.path.join(target, 'sub')).st_uid == os.geteuid()
	# the copy put back by hand, as from another disk
	with open(held, 'w', encoding='utf-8') as f:
		f.write(kept_copy)
	os.utime(held, ns=(st.st_atime_ns, st.st_mtime_ns))
	before = inodes(target)
	handed = watch_folder_meta(monkeypatch, marker)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert (code, err) == (0, '')
	# the marker stays through the inner folders, so a crash among them leaves a restore to pick up; the target is last
	assert handed == [(os.path.join(target, 'sub'), True), (target, False)]
	# the target and its folder, and b.txt; a.txt and sub/c.txt were there
	assert stdout == f'Restored 3 entries ({rv.show_size(1)}) from V1 to {target}, keeping 2 already there\n'
	assert tree(target) == {'a.txt': 'a1', 'b.txt': 'b', 'sub/': None, 'sub/c.txt': 'c'}
	assert {rel: ino for rel, ino in inodes(target).items() if rel in before} == before
	for rel in ('', 'sub'):
		assert metadata(os.path.join(target, rel)) == metadata(os.path.join(version_path(job, 1), 'proj', rel)), rel


def test_in_place_rerun_does_not_move_aside_again(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	write(job, 'proj/f00.txt', 'edited')
	target = f'{job.monitor}/proj'
	code, stdout, err = interrupted(tmp_path, capsys, monkeypatch, target, '--in-place', '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and err.startswith('Interrupted')
	[aside] = asides(job.monitor, 'proj')
	assert stdout == f'Moved {target} aside to {job.monitor}/{aside}\n'
	code, stdout, err = restore(tmp_path, capsys, target, '--in-place', '--version', '0')
	assert (code, err) == (0, '')
	assert asides(job.monitor, 'proj') == [aside]
	assert stdout.startswith('Restored ') and 'keeping 5 already there' in stdout
	assert tree(target) == files
	assert tree(os.path.join(job.monitor, aside))['f00.txt'] == 'edited'


def test_in_place_root_asks_while_the_daemon_runs_the_job(job, frozen_disk, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	run_backup(job)
	write_rule(job)
	os.remove(f'{job.monitor}/a.txt')
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job))
	shown_disk = disk_line(job.monitor, versions(job)[0])
	running = f'reverberator is running job {job.job_name}, which will back the restore up as one large change'
	monkeypatch.setattr(sys, 'stdin', io.StringIO('y\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert '--yes' in err and running in err
	assert os.listdir(job.monitor) == []
	# asked on a terminal: only yes goes on
	monkeypatch.setattr(sys, 'stdin', Terminal('n\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'Cancelled' in err
	assert err == f'{shown_disk}\n{running}\nContinue? [y/N] Cancelled\n' and stdout == ''
	assert os.listdir(job.monitor) == []
	monkeypatch.setattr(sys, 'stdin', Terminal('y\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert tree(job.monitor) == {'a.txt': 'a'}
	os.remove(f'{job.monitor}/a.txt')
	monkeypatch.setattr(sys, 'stdin', io.StringIO(''))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert err == f'{shown_disk}\n{running}\n' and stdout.startswith('Restored ') and tree(job.monitor) == {'a.txt': 'a'}
	# a stopped job backs nothing up: the disk is still shown and asked about
	os.remove(f'{job.monitor}/a.txt')
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job, state='stopped'))
	monkeypatch.setattr(sys, 'stdin', Terminal('y\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert err == f'{shown_disk}\nContinue? [y/N] ' and stdout.startswith('Restored ')


def refuses_an_untrusted_marker(job, tmp_path, capsys, name, prepare, *found):
	'''A marker of this restore that prepare(target, marker) makes untrustworthy: the run is refused and touches nothing.'''
	v0 = versions(job)[0]
	out = destination(tmp_path, name)
	target = os.path.join(out, 'proj')
	marker = mark(target, job, 'proj', v0.name)
	prepare(target, marker)
	before = tree(target), metadata(target)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, ''), name
	assert all(part in err for part in found), (name, err)
	assert (tree(target), metadata(target)) == before, name


def test_resume_refuses_a_marker_it_cannot_trust_without_root(job, tmp_path, capsys):
	# the cases no other user is needed for
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write_rule(job)

	def open_to_others(target, marker):
		os.chmod(target, 0o777)
	refuses_an_untrusted_marker(job, tmp_path, capsys, 'open', open_to_others, f'{target_of("open", tmp_path)} holds a restore marker', 'other users can write')

	def linked(target, marker):
		os.rename(marker, str(tmp_path / 'real_marker'))
		os.symlink(str(tmp_path / 'real_marker'), marker)
	refuses_an_untrusted_marker(job, tmp_path, capsys, 'linked', linked, rv.RESTORE_MARKER_NAME, 'not a regular file')

	def garbled(target, marker):
		with open(marker, 'w', encoding='utf-8') as f:
			f.write('{not json')
	refuses_an_untrusted_marker(job, tmp_path, capsys, 'garbled', garbled, rv.RESTORE_MARKER_NAME, 'cannot be read')

	def not_json_object(target, marker):
		with open(marker, 'w', encoding='utf-8') as f:
			f.write('[1, 2]')
	refuses_an_untrusted_marker(job, tmp_path, capsys, 'array', not_json_object, rv.RESTORE_MARKER_NAME, 'cannot be read')


@pytest.mark.skipif(not ROOT, reason='needs root to hand folders to another user')
def test_resume_refuses_a_marker_it_cannot_trust(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write_rule(job)
	v0 = versions(job)[0]
	refused = lambda name, prepare, *found: refuses_an_untrusted_marker(job, tmp_path, capsys, name, prepare, *found)
	# planted in a folder another user owns, or can write to: a restore must never write into a folder they control
	refused('theirs', lambda target, marker: os.chown(target, OTHER, OTHER), f'{target_of("theirs", tmp_path)} holds a restore marker', f'uid {OTHER}')
	refused('their_marker', lambda target, marker: os.chown(marker, OTHER, OTHER), rv.RESTORE_MARKER_NAME, f'uid {OTHER}')
	# in place, another user's folder holding a marker is neither picked up nor moved aside
	shutil.rmtree(f'{job.monitor}/proj')
	mark(f'{job.monitor}/proj', job, 'proj', v0.name)
	os.chown(f'{job.monitor}/proj', OTHER, OTHER)
	before = tree(f'{job.monitor}/proj')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', '--in-place', '--version', '0')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'holds a restore marker' in err and f'uid {OTHER}' in err
	assert tree(f'{job.monitor}/proj') == before and asides(job.monitor, 'proj') == []


def test_resume_never_follows_a_symlink_where_a_folder_goes(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b', 'proj/sub/deeper/c.txt': 'c', 'proj/plain/d.txt': 'd', 'proj/theirs/e.txt': 'e'})
	run_backup(job)
	write_rule(job)
	v0 = versions(job)[0]
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = mark(target, job, 'proj', v0.name)
	elsewhere = destination(tmp_path, 'elsewhere')
	os.symlink(elsewhere, os.path.join(target, 'sub'))
	with open(os.path.join(target, 'plain'), 'w', encoding='utf-8') as f:
		f.write('a file where a folder goes')
	if ROOT:
		os.mkdir(os.path.join(target, 'theirs'))
		os.chown(os.path.join(target, 'theirs'), OTHER, OTHER)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'Traceback' not in err
	failed = {line.partition(': ')[0]: line.partition(': ')[2] for line in stdout.split('\n') if line.startswith('FAILED ')}
	assert set(failed) == {'FAILED proj/sub', 'FAILED proj/plain'} | ({'FAILED proj/theirs'} if ROOT else set())
	assert 'symlink' in failed['FAILED proj/sub'] and 'nothing in it' in failed['FAILED proj/sub']
	if ROOT:
		assert f'uid {OTHER}' in failed['FAILED proj/theirs']
		assert os.listdir(os.path.join(target, 'theirs')) == []
	# never followed nor written through, and nothing of what was in the way is replaced
	assert os.listdir(elsewhere) == []
	assert os.readlink(os.path.join(target, 'sub')) == elsewhere
	assert tree(target)['plain'] == 'a file where a folder goes'
	assert tree(target)['a.txt'] == 'a'
	assert os.path.isfile(marker) and stat.S_IMODE(os.lstat(target).st_mode) == 0o700


def test_resume_removes_partial_files_a_killed_run_left(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	mark(target, job, 'proj', versions(job)[0].name)
	os.mkdir(os.path.join(target, 'sub'))
	for folder in (target, os.path.join(target, 'sub')):
		with open(rv.partial_copy_path(os.path.join(folder, 'x')), 'w', encoding='utf-8') as f:
			f.write('half')
	assert len(partial_files(out)) == 2
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, '')
	assert partial_files(out) == []
	assert tree(target) == {'a.txt': 'a', 'sub/': None, 'sub/b.txt': 'b'}


def test_resume_replaces_what_is_not_as_restored(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	assert interrupted(tmp_path, capsys, monkeypatch, f'{job.monitor}/proj', out, '--version', '0')[0] == rv.EXIT_COMMAND_FAILED
	first = inodes(target)
	changed, linked, *same = sorted(first)
	# the same contents and times, but not as the restore left them
	if ROOT:
		os.chown(os.path.join(target, changed), OTHER, OTHER)
	else:
		os.chmod(os.path.join(target, changed), 0o600)
	os.remove(os.path.join(target, linked))
	os.symlink(files[linked], os.path.join(target, linked))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, '')
	assert f'keeping {len(same)} already there' in stdout
	assert tree(target) == files
	after = inodes(target)
	assert after[changed] != first[changed]
	assert {rel: after[rel] for rel in same} == {rel: first[rel] for rel in same}
	for rel in files:
		assert metadata(os.path.join(target, rel)) == metadata(os.path.join(version_path(job, 0), 'proj', rel)), rel


def test_a_backed_up_marker_is_not_restored(job, tmp_path, capsys):
	# an in-place restore under way when the daemon took a version
	planted = '{"job": "job", "path": "proj", "version": "V9"}'
	seed_monitor(job, {'proj/a.txt': 'a', f'proj/{rv.RESTORE_MARKER_NAME}': planted, f'proj/sub/{rv.RESTORE_MARKER_NAME}': planted, 'proj/sub/b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == 0
	# at any depth: an in-place restore of a folder inside it may have been under way too
	warnings = [f'WARNING proj/{rv.RESTORE_MARKER_NAME}: not restored: it is the marker of a restore under way when this version was taken',
		f'WARNING proj/sub/{rv.RESTORE_MARKER_NAME}: not restored: it is the marker of a restore under way when this version was taken']
	assert sorted(stdout.split('\n')[1:3]) == warnings
	# each said as it happened, too
	assert sorted(err.rstrip('\n').split('\n')) == warnings
	assert tree(os.path.join(out, 'proj')) == {'a.txt': 'a', 'sub/': None, 'sub/b.txt': 'b'}


def test_in_place_refuses_a_folder_others_could_change(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	write(job, 'proj/a.txt', 'live')
	proj = f'{job.monitor}/proj'

	def refused(path, folder):
		before = tree(job.monitor)
		code, stdout, err = restore(tmp_path, capsys, path, '--in-place', '--version', '0')
		assert (code, stdout) == (rv.EXIT_USAGE, ''), path
		assert folder in err, err
		assert tree(job.monitor) == before
	os.chmod(proj, 0o777)
	refused(f'{proj}/a.txt', proj)
	os.chmod(proj, 0o755)
	if ROOT:
		os.chown(proj, OTHER, OTHER)
		refused(f'{proj}/a.txt', proj)
		refused(f'{proj}/sub', proj)
		os.chown(proj, 0, 0)
	# a symlink on the way that leads elsewhere now: never written through
	elsewhere = destination(tmp_path, 'elsewhere')
	os.rename(f'{proj}/sub', f'{elsewhere}/sub')
	os.symlink(elsewhere, f'{proj}/sub')
	before = tree(elsewhere)
	refused(f'{proj}/sub/b.txt', f'{proj}/sub')
	assert tree(elsewhere) == before
	# the whole job: the folder holding the monitored path
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor)
	mode = stat.S_IMODE(os.lstat(tmp_path).st_mode)
	os.chmod(tmp_path, 0o777)
	try:
		refused(job.monitor, str(tmp_path))
	finally:
		os.chmod(tmp_path, mode)
	assert os.listdir(job.monitor) == []


def test_in_place_root_is_private_while_restoring(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'd/b.txt': 'b', 'd/c.txt': 'c'})
	os.chmod(job.monitor, 0o751)
	if ROOT:
		os.chown(job.monitor, OTHER, OTHER)
	run_backup(job)
	write_rule(job)
	held = version_path(job, 0)
	# a replaced disk: its root empty, root's own
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor, 0o755)
	marker = os.path.join(job.monitor, rv.RESTORE_MARKER_NAME)
	seen = []
	cp_af_copy_path = rv.cp_af_copy_path

	def watching(*args, **kwargs):
		seen.append((stat.S_IMODE(os.lstat(job.monitor).st_mode), stat.S_IMODE(os.lstat(marker).st_mode)))
		return cp_af_copy_path(*args, **kwargs)
	monkeypatch.setattr(rv, 'cp_af_copy_path', watching)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	# private while it fills, marked before the first copy; the monitored root's of the version once complete
	assert seen and set(seen) == {(0o700, 0o600)}
	assert metadata(job.monitor) == kept_root_metadata(held)
	assert stat.S_IMODE(os.lstat(job.monitor).st_mode) == 0o751 and (not ROOT or os.lstat(job.monitor).st_uid == OTHER)
	assert tree(job.monitor) == {'a.txt': 'a', 'd/': None, 'd/b.txt': 'b', 'd/c.txt': 'c'}
	# when anything fails it stays private, and says so
	monkeypatch.setattr(rv, 'cp_af_copy_path', cp_af_copy_path)
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor, 0o755)
	# held as a link to the live file: not in the vault
	os.remove(os.path.join(held, 'd/c.txt'))
	os.symlink(f'{job.monitor}/d/c.txt', os.path.join(held, 'd/c.txt'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == rv.EXIT_COMMAND_FAILED
	assert stdout.endswith(f'{until_then(job.monitor)}\n')
	assert stat.S_IMODE(os.lstat(job.monitor).st_mode) == 0o700 and os.lstat(job.monitor).st_uid == os.geteuid()
	assert os.path.isfile(marker)
	# no longer empty, but holding this restore's own unfinished output: picked up
	os.remove(os.path.join(held, 'd/c.txt'))
	with open(os.path.join(held, 'd/c.txt'), 'w', encoding='utf-8') as f:
		f.write('c')
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert stdout == f'Restored 3 entries ({rv.show_size(1)}) from V0 to {job.monitor}, keeping 2 already there\n'
	assert tree(job.monitor) == {'a.txt': 'a', 'd/': None, 'd/b.txt': 'b', 'd/c.txt': 'c'}
	assert metadata(job.monitor) == kept_root_metadata(held)


def test_one_run_of_a_restore_at_a_time(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	if ROOT:
		os.chown(f'{job.monitor}/proj', OTHER, OTHER)
	monkeypatch.setattr(rv, 'RESTORE_COPY_BATCH', 5)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	finish_restore_copies = rv.finish_restore_copies
	second = []

	def again(pending, report):
		if not second:
			second.append('started')
			# the same restore started again while this one fills its target: it finds the marker
			second.append(restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0'))
			second.append((os.path.isfile(marker), os.lstat(target).st_uid, stat.S_IMODE(os.lstat(target).st_mode)))
		return finish_restore_copies(pending, report)
	monkeypatch.setattr(rv, 'finish_restore_copies', again)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	_, (second_code, second_out, second_err), left = second
	assert (second_code, second_out) == (rv.EXIT_USAGE, '')
	assert f'{target}: another run of this restore, or another program, holds a lock on it' in second_err
	# it picked nothing up: the first run's marker and private target are as they were
	assert left == (True, os.geteuid(), 0o700)
	assert (code, err) == (0, '')
	assert tree(target) == files and metadata(target) == metadata(os.path.join(version_path(job, 0), 'proj'))
	# in place, a target just made and not marked yet is not moved aside by another run either
	monkeypatch.setattr(rv, 'finish_restore_copies', finish_restore_copies)
	write(job, 'proj/f00.txt', 'edited')
	live = f'{job.monitor}/proj'
	write_restore_marker = rv.write_restore_marker
	during = []

	def racing(*args, **kwargs):
		if not during:
			during.append('started')
			during.append(restore(tmp_path, capsys, live, '--in-place', '--version', '0'))
		return write_restore_marker(*args, **kwargs)
	monkeypatch.setattr(rv, 'write_restore_marker', racing)
	code, stdout, err = restore(tmp_path, capsys, live, '--in-place', '--version', '0')
	_, (racing_code, racing_out, racing_err) = during
	assert (racing_code, racing_out) == (rv.EXIT_USAGE, '') and 'another run of this restore, or another program, holds a lock on it' in racing_err
	assert (code, err) == (0, '')
	[aside] = asides(job.monitor, 'proj')
	assert tree(live) == files and tree(os.path.join(job.monitor, aside))['f00.txt'] == 'edited'


def test_accept_keeps_a_failed_restore_as_it_is(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b', 'proj/sub/c.txt': 'c', 'proj/sub/deeper/d.txt': 'd'})
	os.chmod(f'{job.monitor}/proj/sub', 0o751)
	os.chmod(f'{job.monitor}/proj/sub/deeper', 0o2770)
	if ROOT:
		os.chown(f'{job.monitor}/proj', OTHER, OTHER)
		os.chown(f'{job.monitor}/proj/sub/deeper', OTHER, 0)
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	# gone for good: every re-run fails on it
	os.remove(os.path.join(version_path(job, 0), 'proj/b.txt'))
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	code, stdout, _ = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED
	# the two ways out, and never removing the marker by hand
	assert stdout.rstrip('\n').split('\n')[-1] == f'1 failed: run the same restore again to retry them, or again with --accept to keep the result as it is. {until_then(target)}'
	assert 'remove' not in stdout
	before = inodes(target)
	copies = []
	monkeypatch.setattr(rv, 'copy_command', lambda *args: copies.append(args) or ['false'])
	handed = watch_folder_meta(monkeypatch, marker)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1', '--accept')
	assert (code, err) == (0, '')
	assert stdout == f'Kept {target} as it is, restored from V1: gave 3 folders their own metadata, copied nothing\n'
	# nothing copied; each folder handed over deepest first, the target last and after the marker went
	assert copies == [] and inodes(target) == before
	assert handed == [(os.path.join(target, 'sub/deeper'), True), (os.path.join(target, 'sub'), True), (target, False)]
	assert tree(target) == {'a.txt': 'a1', 'sub/': None, 'sub/c.txt': 'c', 'sub/deeper/': None, 'sub/deeper/d.txt': 'd'}
	for rel in ('', 'sub', 'sub/deeper'):
		assert metadata(os.path.join(target, rel)) == metadata(os.path.join(version_path(job, 1), 'proj', rel)), rel
	# accepted: nothing more to keep
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '1', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'no unfinished restore' in err and '--accept' in err


def test_accept_needs_an_unfinished_restore(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a'})
	run_backup(job)
	write(job, 'proj/a.txt', 'a1')
	backup(job, ('proj/a.txt', 'modify'))
	write_rule(job)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'no unfinished restore' in err
	assert os.listdir(out) == []
	# in place, what is there is neither moved aside nor changed
	before = tree(job.monitor), metadata(f'{job.monitor}/proj')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', '--in-place', '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'no unfinished restore' in err
	assert (tree(job.monitor), metadata(f'{job.monitor}/proj')) == before
	# the marker of another version is refused as a re-run refuses it
	v1 = versions(job)[1]
	mark(os.path.join(out, 'proj'), job, 'proj', v1.name)
	code, _, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert code == rv.EXIT_USAGE and v1.name in err
	assert os.path.isfile(os.path.join(out, 'proj', rv.RESTORE_MARKER_NAME))


def test_in_place_root_shows_the_disk_and_refuses_too_little_space(job, frozen_disk, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'a.txt': 'a' * 5000})
	run_backup(job)
	write_rule(job)
	os.remove(f'{job.monitor}/a.txt')
	version = versions(job)[0]
	# which disk it goes on, as the mount table has it: an empty mount point shows the disk under it
	mount_point, source = rv.mount_holding(rv.current_mount_table(), job.monitor)
	monkeypatch.setattr(sys, 'stdin', Terminal('n\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'Cancelled' in err
	assert err == f'{disk_line(job.monitor, version)}\nContinue? [y/N] Cancelled\n' and stdout == ''
	assert f'mounted at {mount_point} ({source})' in err
	assert os.listdir(job.monitor) == []
	# less free space there than the version took in the vault
	statvfs = os.statvfs
	small = os.statvfs_result((4096, 1024, 100, 10, 1, 100, 50, 50, 0, 255))
	monkeypatch.setattr(os, 'statvfs', lambda path: small if os.fspath(path) == job.monitor else statvfs(path))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert rv.show_size(1024) in err and rv.show_size(version.size) in err and mount_point in err
	assert os.listdir(job.monitor) == []


def test_in_place_root_weighs_free_space_against_the_whole_tree(job, tmp_path, capsys, monkeypatch):
	# V0 holds the whole tree, V1 only what changed after it
	seed_monitor(job, {'big.txt': 'a' * 200000, 'small.txt': 's'})
	run_backup(job)
	write(job, 'small.txt', 's2')
	backup(job, ('small.txt', 'modify'))
	write_rule(job)
	for rel in ('big.txt', 'small.txt'):
		os.remove(f'{job.monitor}/{rel}')
	v0, v1 = versions(job)
	assert v1.size < v0.size
	mount_point, source = rv.mount_holding(rv.current_mount_table(), job.monitor)
	statvfs = os.statvfs
	def free_space(free):
		result = os.statvfs_result((4096, 1, free, free, free, 100, 50, 50, 0, 255))
		monkeypatch.setattr(os, 'statvfs', lambda path: result if os.fspath(path) == job.monitor else statvfs(path))
		return (f'Restoring the whole job into {job.monitor}, on the filesystem mounted at {mount_point} ({source}): '
			f'{rv.show_size(free)} free, V0 to V1 took {rv.show_size(v0.size + v1.size)} in the vault')
	# room for what V1 copied, but not for the tree the oldest version holds
	free_space(v0.size - 1)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '1', '--yes')
	assert (code, stdout) == (rv.EXIT_USAGE, '')
	assert rv.show_size(v0.size - 1) in err and rv.show_size(v0.size) in err and 'V0' in err and mount_point in err
	assert os.listdir(job.monitor) == []
	# room for the oldest version's tree, but not for every version up to V1
	shown_disk = free_space(v0.size)
	monkeypatch.setattr(sys, 'stdin', Terminal('n\n'))
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '1')
	assert code == rv.EXIT_COMMAND_FAILED and 'Cancelled' in err
	assert err == f'{shown_disk}\nV1 may not fit: its files can come from any of V0 to V1, more than the free space\nContinue? [y/N] Cancelled\n' and stdout == ''
	shown_disk = free_space(v0.size + v1.size)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '1', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert err.startswith(shown_disk + '\n') and stdout.startswith('Restored ')
	assert tree(job.monitor) == {'big.txt': 'a' * 200000, 'small.txt': 's2'}


def test_a_picked_up_whole_job_restore_skips_the_free_space_checks(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'a.txt': 'a' * 20000, 'b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	version = versions(job)[0]
	assert version.size > 1024
	shutil.rmtree(job.monitor)
	# less free space than the version took, as part of it is already in place
	statvfs = os.statvfs
	small = os.statvfs_result((4096, 1, 1, 1, 1, 100, 50, 50, 0, 255))
	monkeypatch.setattr(os, 'statvfs', lambda path: small if os.fspath(path) == job.monitor else statvfs(path))
	# nothing in place: refused
	os.mkdir(job.monitor)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'Not restoring the whole job' in err
	# its own unfinished output there: picked up, with neither the refusal nor the warning that it may not fit
	os.rmdir(job.monitor)
	mark(job.monitor, job, '', version.name)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0, err
	assert err.startswith('Restoring the whole job into ') and 'may not fit' not in err and 'Not restoring' not in err
	assert tree(job.monitor) == {'a.txt': 'a' * 20000, 'b.txt': 'b'}


def test_resume_never_replaces_a_folder_where_a_file_goes(job, tmp_path, capsys):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b'})
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = mark(target, job, 'proj', versions(job)[0].name)
	os.makedirs(os.path.join(target, 'a.txt', 'inside'))
	with open(os.path.join(target, 'a.txt', 'inside', 'keep.txt'), 'w', encoding='utf-8') as f:
		f.write('kept')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and 'Traceback' not in err
	assert 'FAILED proj/a.txt: a folder is in its place, which is left as it is' in stdout.split('\n')
	assert tree(os.path.join(target, 'a.txt')) == {'inside/': None, 'inside/keep.txt': 'kept'}
	assert tree(target)['b.txt'] == 'b' and os.path.isfile(marker)


def xattr_support(tmp_path):
	probe = tmp_path / 'xattr-probe'
	probe.write_text('x')
	try:
		os.setxattr(probe, 'user.probe', b'1')
	except OSError:
		pytest.skip('no user xattrs here')


def test_already_restored_compares_extended_attributes(tmp_path):
	xattr_support(tmp_path)
	source, dest = tmp_path / 'source', tmp_path / 'dest'
	for path in (source, dest):
		path.write_text('same')
		os.chmod(path, 0o640)
		os.utime(path, ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
	assert rv.already_restored(str(source), str(dest))
	os.setxattr(source, 'user.note', b'one')
	assert not rv.already_restored(str(source), str(dest))
	os.setxattr(dest, 'user.note', b'two')
	assert not rv.already_restored(str(source), str(dest))
	os.setxattr(dest, 'user.note', b'one')
	assert rv.already_restored(str(source), str(dest))


def test_a_marker_records_entries_whose_metadata_could_not_be_set(tmp_path):
	target = tmp_path / 'target'
	target.mkdir()
	os.chmod(target, 0o700)
	class Version:
		name = 'v0'
	rels = [f'proj/f{number}' for number in range(1500)] + ['proj/\udce9']
	rv.write_restore_marker(str(target), 'job', 'proj', Version, rels)
	marker = rv.read_restore_marker(str(target))
	assert marker['unset'] == rels[:rv.RESTORE_MARKER_UNSET_LIMIT] and len(marker['unset']) == 1000
	rv.write_restore_marker(str(target), 'job', 'proj', Version, ['proj/\udce9'])
	assert rv.read_restore_marker(str(target))['unset'] == ['proj/\udce9']
	# none recorded: the marker is what it was
	rv.write_restore_marker(str(target), 'job', 'proj', Version)
	assert rv.read_restore_marker(str(target)) == {'job': 'job', 'path': 'proj', 'version': 'v0'}


def test_a_resumed_run_reports_kept_entries_whose_metadata_the_earlier_run_could_not_set(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/bad.txt': 'b', 'proj/meta.txt': 'm'})
	run_backup(job)
	write_rule(job)
	copy_command = rv.copy_command

	def failing(source_path, dest_path):
		if source_path.endswith('bad.txt'):
			return ['sh', '-c', f'echo "cp: error reading \'{source_path}\': Input/output error" >&2; exit 1']
		if source_path.endswith('meta.txt'):
			return ['sh', '-c', f'cp -a "{source_path}" "{dest_path}" && echo "cp: failed to preserve ownership for \'{dest_path}\': Operation not permitted" >&2; exit 1']
		return copy_command(source_path, dest_path)
	monkeypatch.setattr(rv, 'copy_command', failing)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	assert 'WARNING proj/meta.txt: copied without all of its metadata' in err
	assert rv.read_restore_marker(target)['unset'] == ['proj/meta.txt']
	# the second run copies what failed; meta.txt is kept, and its warning comes back
	monkeypatch.setattr(rv, 'copy_command', copy_command)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == 0
	assert 'keeping 2 already there' in stdout
	warning = 'WARNING proj/meta.txt: kept as an earlier run restored it, which could not set all of its metadata'
	assert warning in stdout and err == warning + '\n'


def test_resume_recopies_a_kept_file_whose_xattrs_differ(job, tmp_path, capsys, monkeypatch):
	xattr_support(tmp_path)
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/b.txt': 'b'})
	os.setxattr(f'{job.monitor}/proj/a.txt', 'user.note', b'kept')
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('b.txt') else copy_command(source, dest))
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	monkeypatch.setattr(rv, 'copy_command', copy_command)
	os.removexattr(os.path.join(target, 'a.txt'), 'user.note')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert (code, err) == (0, '')
	# a.txt was copied again, not kept
	assert os.getxattr(os.path.join(target, 'a.txt'), 'user.note') == b'kept'
	assert 'keeping' not in stdout


def test_the_claim_looks_at_the_marker_again_under_the_lock(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	marker = mark(target, job, 'proj', versions(job)[0].name)
	lock_restore_target = rv.lock_restore_target

	def finishing(fd, path):
		lock_restore_target(fd, path)
		# the run that held it finished, handing the folder over with its own mode, before this one got the lock
		os.unlink(marker)
		os.fchmod(fd, 0o755)
	monkeypatch.setattr(rv, 'lock_restore_target', finishing)
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	assert code == rv.EXIT_USAGE and 'no longer holds an unfinished restore' in err
	# refused before the claim made it private
	assert stat.S_IMODE(os.lstat(target).st_mode) == 0o755
	assert os.listdir(target) == []


def test_accept_without_a_marker_is_nothing_to_accept_and_moves_nothing(job, tmp_path, capsys, monkeypatch):
	twenty_files(job)
	target = f'{job.monitor}/proj'
	code, stdout, err = restore(tmp_path, capsys, target, '--in-place', '--version', '0', '--accept')
	assert (code, stdout) == (rv.EXIT_USAGE, '') and 'holds no unfinished restore to keep' in err
	assert asides(job.monitor, 'proj') == []
	# the marker goes between two looks at it: nothing is moved aside, whichever look it is
	version = versions(job)[0]
	for vanishing_look in (1, 2, 3, 4):
		shutil.rmtree(target)
		marker = mark(target, job, 'proj', version.name)
		looks = []
		read_restore_marker = rv.read_restore_marker

		def vanishing(path, read_restore_marker=read_restore_marker, marker=marker, looks=looks, vanishing_look=vanishing_look):
			found = read_restore_marker(path)
			looks.append(path)
			if len(looks) == vanishing_look and found is not None:
				os.unlink(marker)
			return found
		monkeypatch.setattr(rv, 'read_restore_marker', vanishing)
		code, stdout, err = restore(tmp_path, capsys, target, '--in-place', '--version', '0', '--accept')
		monkeypatch.setattr(rv, 'read_restore_marker', read_restore_marker)
		assert asides(job.monitor, 'proj') == [], vanishing_look
		assert os.path.isdir(target)


def test_a_stop_while_handing_folders_over_points_at_accept(job, tmp_path, capsys, monkeypatch):
	if not ROOT:
		pytest.skip('needs another uid to own folders')
	seed_monitor(job, {'proj/a.txt': 'a', 'proj/sub/b.txt': 'b', 'proj/sub/deeper/c.txt': 'c'})
	for folder in ('proj/sub', 'proj/sub/deeper'):
		os.chown(f'{job.monitor}/{folder}', OTHER, OTHER)
	run_backup(job)
	write_rule(job)
	restore_folder_meta = rv.restore_folder_meta

	def stopping(source, dest, **kwargs):
		rv.RESTORE_STOP.set()
		return restore_folder_meta(source, dest, **kwargs)
	monkeypatch.setattr(rv, 'restore_folder_meta', stopping)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	monkeypatch.setattr(rv, 'restore_folder_meta', restore_folder_meta)
	assert code == rv.EXIT_COMMAND_FAILED
	assert 'stopped while giving its folders their owners' in err and 'again with --accept' in err and 'run the same restore again' not in err
	assert os.lstat(os.path.join(target, 'sub/deeper')).st_uid == OTHER
	# running it again refuses the folders already handed over; --accept finishes it
	code, stdout, err = restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0', '--accept')
	assert code == 0
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	assert metadata(target) == metadata(os.path.join(version_path(job, 0), 'proj'))


def test_a_marker_that_would_not_go_is_not_rewritten_into_a_folder_being_handed_over(job, tmp_path, capsys, monkeypatch):
	files = twenty_files(job)
	out = destination(tmp_path)
	target = os.path.join(out, 'proj')
	mark(target, job, 'proj', versions(job)[0].name)
	# an earlier run left f00.txt without all of its metadata: this one copies it afresh, so its marker would change
	rv.write_restore_marker(target, job.job_name, 'proj', versions(job)[0], ['proj/f00.txt'])
	marker = os.path.join(target, rv.RESTORE_MARKER_NAME)
	unlink, restore_folder_meta, write_restore_marker = os.unlink, rv.restore_folder_meta, rv.write_restore_marker
	written = []
	def stuck(path, *args, **kwargs):
		if os.fspath(path) == marker:
			raise PermissionError(errno.EPERM, 'Operation not permitted', path)
		return unlink(path, *args, **kwargs)
	def stopped(source, dest, **kwargs):
		if dest == target:
			raise KeyboardInterrupt
		return restore_folder_meta(source, dest, **kwargs)
	monkeypatch.setattr(os, 'unlink', stuck)
	monkeypatch.setattr(rv, 'restore_folder_meta', stopped)
	monkeypatch.setattr(rv, 'write_restore_marker', lambda *args, **kwargs: written.append(args[4:]) or write_restore_marker(*args, **kwargs))
	restore(tmp_path, capsys, f'{job.monitor}/proj', out, '--version', '0')
	# only the claim wrote it, before anything was handed over
	assert len(written) == 1


def xattrs(path):
	return {name: os.getxattr(path, name, follow_symlinks=False) for name in os.listxattr(path, follow_symlinks=False)}


def own_xattrs_in(top):
	'''The trusted.reverberator.* names on top and every entry under it, by rel.'''
	found = {}
	for path, rel in [(top, '')] + [(path, rel) for path, rel, _ in rv.iter_tree_entries(top)]:
		names = [name for name in os.listxattr(path, follow_symlinks=False) if name.startswith('trusted.reverberator.')]
		if names:
			found[rel] = names
	return found


@root_only
def test_a_whole_job_restored_in_place_gets_its_top_folders_own_metadata(job, tmp_path, capsys):
	# each version folder stays root's 0755 folder of its own times, and keeps the monitored root's owner, mode, times
	# and xattrs of its batch (trusted.reverberator.root), so the job's top folder comes back as it was
	seed_monitor(job, {'a.txt': 'a', 'd/b.txt': 'b'})
	os.setxattr(job.monitor, 'user.top', b'v0')
	run_backup(job)
	v0_want = metadata(job.monitor), xattrs(job.monitor)
	write(job, 'n.txt', 'n')
	os.chmod(job.monitor, 0o750)
	if ROOT:
		os.chown(job.monitor, OTHER, OTHER)
	os.setxattr(job.monitor, 'user.top', b'v1')
	old = 1_000_000_000 * 10 ** 9
	os.utime(job.monitor, ns=(old, old))
	run_backup(job, rv.change_events_to_backup_entries(deque([rv.ChangeEvent(1.0, False, 'create', f'{job.monitor}/n.txt', None)]), job.monitor))
	write_rule(job)
	want = metadata(job.monitor), xattrs(job.monitor)
	assert want[1] == {'user.top': b'v1'}
	for number in (0, 1):
		st = os.lstat(version_path(job, number))
		assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o755, os.geteuid(), os.getegid()) and st.st_mtime_ns != old
		assert list(xattrs(version_path(job, number))) == [rv.ROOT_META_XATTR]
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor, 0o755)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '1', '--yes')
	assert code == 0 and err.startswith('Restoring the whole job into ')
	assert tree(job.monitor) == {'a.txt': 'a', 'd/': None, 'd/b.txt': 'b', 'n.txt': 'n'}
	assert (metadata(job.monitor), xattrs(job.monitor)) == want and (not ROOT or os.lstat(job.monitor).st_uid == OTHER)
	assert stat.S_IMODE(os.lstat(job.monitor).st_mode) == 0o750 and os.lstat(job.monitor).st_mtime_ns == old
	assert own_xattrs_in(job.monitor) == {}
	# an older version gives the root's as of that version
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor + '/', out, '--version', '0')
	assert code == 0, err
	top = os.path.join(out, os.path.basename(job.monitor))
	assert (metadata(top), xattrs(top)) == v0_want
	assert own_xattrs_in(top) == {}


@root_only
def test_a_version_without_the_roots_metadata_restores_its_top_folder_as_0_53_did(job, tmp_path, capsys):
	# a version made before the root's metadata was kept on it (or where it could not be written): the job's top folder
	# gets the version folder's own owner, mode and times
	seed_monitor(job, {'a.txt': 'a'})
	os.chmod(job.monitor, 0o750)
	if ROOT:
		os.chown(job.monitor, OTHER, OTHER)
	run_backup(job)
	write_rule(job)
	version = version_path(job, 0)
	os.removexattr(version, rv.ROOT_META_XATTR)
	os.utime(version, ns=(10 ** 18, 10 ** 18))
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor + '/', out, '--version', '0')
	assert code == 0, err
	top = os.path.join(out, os.path.basename(job.monitor))
	assert metadata(top) == metadata(version) and xattrs(top) == {}
	assert stat.S_IMODE(os.lstat(top).st_mode) == 0o755 and os.lstat(top).st_uid == os.geteuid()


@root_only
def test_a_root_metadata_that_cannot_be_kept_is_one_error_and_the_version_falls_back(job, tmp_path, capsys, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	os.chmod(job.monitor, 0o750)
	real = os.setxattr
	def no_room(path, name, *args, **kwargs):
		if name == rv.ROOT_META_XATTR:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return real(path, name, *args, **kwargs)
	monkeypatch.setattr(os, 'setxattr', no_room)
	lines = []
	logger = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda *args, **kwargs: (lines.append((args, kwargs)), logger(*args, **kwargs))[1])
	run_backup(job)
	monkeypatch.setattr(os, 'setxattr', real)
	errors = [kwargs['message'] for args, kwargs in lines if kwargs.get('error') and 'Cannot keep the metadata' in kwargs.get('message', '')]
	assert len(errors) == 1 and 'No space left' in errors[0]
	version = version_path(job, 0)
	assert rv.read_root_meta(version) is None and xattrs(version) == {}
	write_rule(job)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor + '/', out, '--version', '0')
	assert code == 0, err
	assert metadata(os.path.join(out, os.path.basename(job.monitor))) == metadata(version)


@root_only
def test_a_vault_folder_holding_the_daemons_own_names_gives_them_only_as_a_monitored_folders_own(tmp_path):
	# a copy of a vault (rsync -aX) inside a monitored tree keeps trusted.reverberator.root: restored as a monitored folder
	# it is that folder's own, all its names; only a whole job's top folder is given the record and none of those names
	source, dest = tmp_path / 'held', tmp_path / 'made'
	source.mkdir()
	dest.mkdir()
	os.setxattr(source, 'user.k', b'1')
	os.setxattr(source, 'trusted.reverberator.other', b'x')
	record = rv.encode_root_meta(rv.RootMeta(os.geteuid(), os.getegid(), 0o700, 5, 6, {'user.r': b'2', 'trusted.reverberator.root': b'no'}))
	os.setxattr(source, rv.ROOT_META_XATTR, record)
	os.chmod(source, 0o755)
	assert rv.restore_folder_meta(str(source), str(dest)) is None
	assert xattrs(dest) == {'user.k': b'1', 'trusted.reverberator.other': b'x', rv.ROOT_META_XATTR: record}
	assert stat.S_IMODE(os.lstat(dest).st_mode) == 0o755
	# the top folder of a whole job: the record's metadata, the record's names but the daemon's
	dest2 = tmp_path / 'made2'
	dest2.mkdir()
	assert rv.restore_folder_meta(str(source), str(dest2), top=True) is None
	assert xattrs(dest2) == {'user.r': b'2'}
	st = os.lstat(dest2)
	assert (stat.S_IMODE(st.st_mode), st.st_mtime_ns) == (0o700, 6)


@root_only
def test_a_monitored_folder_holding_a_record_gets_it_back_as_its_own_on_restore(job, tmp_path, capsys):
	# job A monitors a tree that holds a copy of another job's vault: its version folder V5 keeps B's record
	seed_monitor(job, {'vaults/B/V5/f': 'x', 'keep': 'k'})
	v5 = os.path.join(job.monitor, 'vaults/B/V5')
	os.chmod(v5, 0o755)
	record = rv.encode_root_meta(rv.RootMeta(OTHER, OTHER, 0o700, 5, 6, {'user.r': b'2'}))
	os.setxattr(v5, rv.ROOT_META_XATTR, record)
	os.utime(v5, ns=(10 ** 18, 10 ** 18))
	own = metadata(v5), xattrs(v5)
	run_backup(job)
	write_rule(job)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, os.path.join(job.monitor, 'vaults'), out, '--version', '0')
	assert code == 0, err
	assert (metadata(os.path.join(out, 'vaults/B/V5')), xattrs(os.path.join(out, 'vaults/B/V5'))) == own
	# and a whole job restored in place
	shutil.rmtree(job.monitor)
	os.mkdir(job.monitor, 0o755)
	code, stdout, err = restore(tmp_path, capsys, job.monitor, '--in-place', '--version', '0', '--yes')
	assert code == 0, err
	assert (metadata(v5), xattrs(v5)) == own


@root_only
@pytest.mark.parametrize('record', [b'{"v":1,"uid":0', b'\xff\xfe', b'{"v":1,"uid":99999999999,"gid":0,"mode":493,"atime_ns":1,"mtime_ns":1,"xattrs":{}}',
	b'{"v":1,"uid":0,"gid":0,"mode":493,"atime_ns":1,"mtime_ns":99999999999999999999,"xattrs":{}}', b'{"v":1,"uid":0,"gid":0,"mode":99999,"atime_ns":1,"mtime_ns":1,"xattrs":{}}'])
def test_a_record_that_cannot_be_decoded_warns_once_and_the_top_folder_gets_the_version_folders_own(job, tmp_path, capsys, record):
	seed_monitor(job, {'a': 'a'})
	os.chmod(job.monitor, 0o750)
	run_backup(job)
	write_rule(job)
	version = version_path(job, 0)
	os.setxattr(version, rv.ROOT_META_XATTR, record)
	out = destination(tmp_path)
	code, stdout, err = restore(tmp_path, capsys, job.monitor + '/', out, '--version', '0')
	top = os.path.join(out, os.path.basename(job.monitor))
	assert code == 0, err
	assert err.count("its version folder's record of the monitored root cannot be read") == 1 and "it gets the version folder's own" in err
	assert metadata(top) == metadata(version) and 'Traceback' not in err


@root_only
def test_a_record_that_cannot_be_read_warns(tmp_path, monkeypatch):
	source, dest = tmp_path / 'held', tmp_path / 'made'
	source.mkdir()
	dest.mkdir()
	os.setxattr(source, rv.ROOT_META_XATTR, rv.encode_root_meta(rv.RootMeta(1, 2, 0o700, 5, 6, {})))
	getxattr = os.getxattr
	def refusing(path, name, *args, **kwargs):
		if name == rv.ROOT_META_XATTR:
			raise OSError(errno.EIO, os.strerror(errno.EIO))
		return getxattr(path, name, *args, **kwargs)
	monkeypatch.setattr(os, 'getxattr', refusing)
	why = []
	assert rv.restore_folder_meta(str(source), str(dest), top=True, warn=why.append) is None
	assert len(why) == 1 and 'cannot be read' in why[0] and 'Input/output error' in why[0]
	assert os.lstat(dest).st_uid == os.lstat(source).st_uid


def test_a_record_of_a_root_dated_before_1970_encodes_and_decodes(tmp_path):
	meta = rv.RootMeta(1, 2, 0o750, -315619200 * 10 ** 9, -315619200 * 10 ** 9 + 7, {'user.a': b'b'})
	assert rv.decode_root_meta(rv.encode_root_meta(meta)) == meta
	root, version = tmp_path / 'root', tmp_path / 'V0'
	root.mkdir()
	version.mkdir()
	os.utime(root, ns=(meta.atime_ns, meta.mtime_ns))
	if ROOT:
		assert rv.record_root_meta(str(root), str(version))
		got = rv.read_root_meta(str(version))
		assert got is not None and got.mtime_ns == meta.mtime_ns
		dest = tmp_path / 'made'
		dest.mkdir()
		assert rv.restore_folder_meta(str(version), str(dest), top=True) is None
		assert os.lstat(dest).st_mtime_ns == meta.mtime_ns


@pytest.mark.parametrize('field,value', [('uid', 2 ** 32), ('gid', -1), ('mode', 0o10000), ('atime_ns', 2 ** 63), ('mtime_ns', -2 ** 63 - 1), ('uid', True), ('mtime_ns', 1.5)])
def test_a_record_with_a_number_out_of_range_is_not_one(field, value):
	record = {'v': 1, 'uid': 0, 'gid': 0, 'mode': 0o755, 'atime_ns': 1, 'mtime_ns': 1, 'xattrs': {}}
	record[field] = value
	with pytest.raises(ValueError):
		rv.decode_root_meta(json.dumps(record).encode())


def logged(monkeypatch):
	lines = []
	logger = rv.backuperTeeLogToTl
	monkeypatch.setattr(rv, 'backuperTeeLogToTl', lambda *args, **kwargs: (lines.append((args, kwargs)), logger(*args, **kwargs))[1])
	return lines


@root_only
def test_a_record_that_cannot_be_written_logs_once_per_job_and_says_when_it_works_again(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	real = os.setxattr
	failing = [True]
	def no_room(path, name, *args, **kwargs):
		if name == rv.ROOT_META_XATTR and failing[0]:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return real(path, name, *args, **kwargs)
	monkeypatch.setattr(os, 'setxattr', no_room)
	lines = logged(monkeypatch)
	text = lambda: [kwargs['message'] for args, kwargs in lines if 'metadata of' in kwargs.get('message', '')]
	version = os.path.join(job.root, 'V')
	os.mkdir(version)
	for _ in range(3):
		assert not rv.record_root_meta(job.monitor, version)
	assert len(text()) == 1 and 'Cannot keep the metadata' in text()[0]
	assert [kwargs.get('error') for args, kwargs in lines][-1] is True
	failing[0] = False
	assert rv.record_root_meta(job.monitor, version) and rv.record_root_meta(job.monitor, version)
	assert len(text()) == 2 and 'again' in text()[1] and not lines[-1][1].get('error')
	# failing again is news again
	failing[0] = True
	assert not rv.record_root_meta(job.monitor, version)
	assert len(text()) == 3 and 'Cannot keep the metadata' in text()[2]
	rv.ROOT_META_TROUBLE.pop(job.monitor, None)


@root_only
def test_a_root_whose_attributes_do_not_fit_gets_a_record_without_them_and_one_line(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	os.chmod(job.monitor, 0o750)
	os.setxattr(job.monitor, 'user.big', b'x' * 3000)
	real = os.setxattr
	def small(path, name, value, *args, **kwargs):
		if name == rv.ROOT_META_XATTR and len(value) > 3500:
			raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
		return real(path, name, value, *args, **kwargs)
	monkeypatch.setattr(os, 'setxattr', small)
	lines = logged(monkeypatch)
	version = os.path.join(job.root, 'V')
	os.mkdir(version)
	assert len(rv.encode_root_meta(rv.RootMeta(0, 0, 0, 0, 0, {'user.big': b'x' * 3000}))) > 3500
	for _ in range(3):
		assert rv.record_root_meta(job.monitor, version)
	got = rv.read_root_meta(version)
	assert got.xattrs == {} and got.mode == 0o750
	said = [kwargs for args, kwargs in lines if 'do not fit' in kwargs.get('message', '')]
	assert len(said) == 1 and not said[0].get('error') and 'without them' in said[0]['message']
	rv.ROOT_META_TROUBLE.pop(job.monitor, None)
