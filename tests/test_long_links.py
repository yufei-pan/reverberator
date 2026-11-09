'''
0.55.2: a source symlink whose text (or path) the vault's filesystem refuses as too long (on XFS, a text of 1,024 bytes
and up: ENAMETOOLONG) is left out of the version with a warning naming it, recorded as absent the way a delete is, so the
job keeps backing up; a restore of such a link to a filesystem that refuses it names it, finishes, and exits 1.

The refusal is cp's own line, made by a fake copy command, wherever the filesystem under the test takes the link. The
tests marked real put the long link on /dev/shm and the other side on the basetemp, and run where the basetemp refuses
it (an XFS basetemp).
'''
import os
import shutil
import stat
import uuid
from collections import OrderedDict

import pytest

import reverberator as rv
from tests.harness import committed_versions, create_job, event_entry, probe_link, run_backup, seed_monitor, write_rule

pytestmark = pytest.mark.unit

# a link text XFS refuses and ext4, f2fs and tmpfs take
LONG = 2000


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


def refuse(monkeypatch, name='l'):
	'''cp refuses to make a symlink named name, as a filesystem that cannot hold its text says it.'''
	copy_command = rv.copy_command

	def refusing(source_path, dest_path):
		if os.path.basename(source_path) == name and os.path.islink(source_path):
			return ['sh', '-c', 'echo "cp: cannot create symbolic link \'$1\': File name too long" >&2; exit 1', 'sh', dest_path]
		return copy_command(source_path, dest_path)
	monkeypatch.setattr(rv, 'copy_command', refusing)


def backup(job, *entries):
	return run_backup(job, OrderedDict(event_entry(job, *entry) for entry in entries))


def warned(text, path):
	return text.count(f'NOT BACKED UP: {path}: ')


def tracked(job, rel):
	manifest = rv.VaultManifest(job.job_vault)
	try:
		return manifest.lookup(rel) is not None
	finally:
		manifest.close()


def write(job, rel, content):
	with open(os.path.join(job.monitor, rel), 'w', encoding='utf-8') as f:
		f.write(content)


def read(path):
	with open(path, encoding='utf-8') as f:
		return f.read()


def test_a_backup_leaves_a_refused_link_out_and_commits_the_rest(job, monkeypatch, capsys):
	seed_monitor(job, {'a': 'a', 'd/b': 'b'})
	run_backup(job)
	refuse(monkeypatch)
	write(job, 'a', 'a2')
	write(job, 'd/c', 'c')
	link = os.path.join(job.monitor, 'd/l')
	os.symlink('t' * 100, link)
	capsys.readouterr()
	versions = backup(job, ('a', 'modify'), ('d/c', 'create'), ('d/l', 'create'))
	assert len(versions) == 2
	v1 = versions[-1]
	assert read(os.path.join(v1, 'a')) == 'a2' and read(os.path.join(v1, 'd/c')) == 'c' and read(os.path.join(v1, 'd/b')) == 'b'
	assert not os.path.lexists(os.path.join(v1, 'd/l'))
	assert not tracked(job, 'd/l') and tracked(job, 'd/c')
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 1
	# the next batch that does not meet it says nothing of it
	write(job, 'a', 'a3')
	versions = backup(job, ('a', 'modify'))
	assert len(versions) == 3 and read(os.path.join(versions[-1], 'a')) == 'a3'
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 0


def test_the_previous_version_keeps_its_own_link_of_that_name(job, monkeypatch, capsys):
	seed_monitor(job, {'a': 'a'})
	os.symlink('short', os.path.join(job.monitor, 'l'))
	versions = run_backup(job)
	assert os.readlink(os.path.join(versions[0], 'l')) == 'short'
	refuse(monkeypatch)
	link = os.path.join(job.monitor, 'l')
	os.remove(link)
	os.symlink('t' * 100, link)
	write(job, 'a', 'a2')
	capsys.readouterr()
	versions = backup(job, ('l', 'create'), ('a', 'modify'))
	assert len(versions) == 2
	v0, v1 = versions
	# gone from the new version as a delete takes it out; the version before keeps its link, browsable as it was
	assert not os.path.lexists(os.path.join(v1, 'l'))
	assert os.readlink(os.path.join(v0, 'l')) == 'short'
	assert read(os.path.join(v0, 'a')) == 'a' and read(os.path.join(v1, 'a')) == 'a2'
	assert not tracked(job, 'l')
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 1


def test_a_full_comparison_meets_the_link_again_and_warns_again(job, monkeypatch, capsys):
	seed_monitor(job, {'a': 'a', 'd/b': 'b'})
	link = os.path.join(job.monitor, 'd/l')
	os.symlink('t' * 100, link)
	refuse(monkeypatch)
	capsys.readouterr()
	# the first backup copies the whole tree, the link left out
	versions = run_backup(job)
	assert len(versions) == 1 and not os.path.lexists(os.path.join(versions[0], 'd/l'))
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 1
	write(job, 'a', 'a2')
	# a full comparison finds it untracked, meets it again, and the batch commits
	versions = run_backup(job)
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2'
	assert not os.path.lexists(os.path.join(versions[-1], 'd/l')) and not tracked(job, 'd/l')
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 1


def test_a_regular_file_the_vault_refuses_still_fails_the_batch(job, monkeypatch):
	seed_monitor(job, {'a': 'a'})
	run_backup(job)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['sh', '-c', 'echo "cp: cannot create regular file \'$1\': File name too long" >&2; exit 1', 'sh', dest]
		if source.endswith('/f') else copy_command(source, dest))
	write(job, 'f', 'f')
	with pytest.raises(rv.JobFailure):
		backup(job, ('f', 'create'))


def restore(job, capsys, path, *extra):
	capsys.readouterr()
	code = rv.run_command(['restore', path, *extra, '--rule', job.rule_path, '--state_dir', os.path.join(job.root, 'state')])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def failed_lines(stdout):
	return [line for line in stdout.splitlines() if line.startswith('FAILED')]


def check_folder_restore(job, capsys, out, link_rel):
	code, stdout, err = restore(job, capsys, f'{job.monitor}/proj', out, '--version', '0')
	target = os.path.join(out, 'proj')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = failed_lines(stdout)
	assert len(failed) == 1 and failed[0].startswith(f'FAILED {link_rel}: ') and "cannot hold a link that long" in failed[0]
	assert 'run the same restore again' not in stdout + err
	# finished: everything else restored, the folders handed over and the marker gone
	assert read(os.path.join(target, 'a')) == 'a' and read(os.path.join(target, 'sub/b')) == 'b'
	assert not os.path.lexists(os.path.join(target, os.path.relpath(link_rel, 'proj')))
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	held = os.lstat(os.path.join(rv.list_versions(job.job_vault)[0].path, 'proj'))
	assert stat.S_IMODE(os.lstat(target).st_mode) == stat.S_IMODE(held.st_mode) != 0o700
	assert [name for name in os.listdir(os.path.join(target, 'sub')) if name.endswith(rv.PARTIAL_COPY_SUFFIX)] == []


def check_file_restore(job, capsys, out, link_rel):
	code, stdout, err = restore(job, capsys, os.path.join(job.monitor, link_rel), out, '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	failed = failed_lines(stdout)
	assert len(failed) == 1 and failed[0].startswith(f'FAILED {link_rel}: ') and "cannot hold a link that long" in failed[0]
	# nothing put there
	assert os.listdir(out) == []


def backed_up_project(job, text):
	seed_monitor(job, {'proj/a': 'a', 'proj/sub/b': 'b'})
	os.chmod(os.path.join(job.monitor, 'proj'), 0o755)
	os.symlink(text, os.path.join(job.monitor, 'proj/sub/l'))
	run_backup(job)
	write_rule(job)


def test_a_folder_restore_of_a_refused_link_finishes_without_it(job, tmp_path, capsys, monkeypatch):
	backed_up_project(job, 't' * 100)
	refuse(monkeypatch)
	out = tmp_path / 'out'
	out.mkdir()
	check_folder_restore(job, capsys, str(out), 'proj/sub/l')


def test_a_file_restore_of_a_refused_link_puts_nothing_there(job, tmp_path, capsys, monkeypatch):
	backed_up_project(job, 't' * 100)
	refuse(monkeypatch)
	out = tmp_path / 'out'
	out.mkdir()
	check_file_restore(job, capsys, str(out), 'proj/sub/l')


def test_a_refused_link_beside_another_failure_holds_the_target_for_a_run_again(job, tmp_path, capsys, monkeypatch):
	backed_up_project(job, 't' * 100)
	refuse(monkeypatch)
	copy_command = rv.copy_command
	monkeypatch.setattr(rv, 'copy_command', lambda source, dest: ['false'] if source.endswith('/a') else copy_command(source, dest))
	out = tmp_path / 'out'
	out.mkdir()
	code, stdout, _ = restore(job, capsys, f'{job.monitor}/proj', str(out), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED
	target = os.path.join(str(out), 'proj')
	assert os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME))
	# the run again is offered for the one it can fix
	assert '1 failed: run the same restore again' in stdout
	monkeypatch.setattr(rv, 'copy_command', copy_command)
	code, stdout, _ = restore(job, capsys, f'{job.monitor}/proj', str(out), '--version', '0')
	assert code == rv.EXIT_COMMAND_FAILED and len(failed_lines(stdout)) == 1
	assert not os.path.lexists(os.path.join(target, rv.RESTORE_MARKER_NAME)) and read(os.path.join(target, 'a')) == 'a'


@pytest.fixture
def shm(tmp_path):
	'''A folder on /dev/shm that takes a LONG link while the basetemp refuses it, removed after; else the test is skipped.'''
	if probe_link(str(tmp_path), LONG) is not None:
		pytest.skip(f'the basetemp takes a link text of {LONG} bytes: the refusal is a fake here')
	if not os.path.isdir('/dev/shm'):
		pytest.skip('no /dev/shm')
	folder = os.path.join('/dev/shm', f'reverb-long-links-{uuid.uuid4().hex}')
	os.mkdir(folder)
	try:
		if probe_link(folder, LONG) is None:
			pytest.skip(f'/dev/shm refuses a link text of {LONG} bytes')
		yield folder
	finally:
		shutil.rmtree(folder)


def test_real_a_backup_to_a_vault_that_refuses_the_link_leaves_it_out(job, shm, capsys):
	job = job._replace(monitor=os.path.join(shm, 'monitor'))
	seed_monitor(job, {'a': 'a', 'd/b': 'b'})
	link = os.path.join(job.monitor, 'd/l')
	os.symlink('t' * LONG, link)
	capsys.readouterr()
	versions = run_backup(job)
	write(job, 'a', 'a2')
	versions = run_backup(job)
	assert len(versions) == 2 and read(os.path.join(versions[-1], 'a')) == 'a2'
	assert not any(os.path.lexists(os.path.join(version, 'd/l')) for version in versions)
	out = capsys.readouterr()
	assert warned(out.out + out.err, link) == 2


def test_real_a_restore_to_a_filesystem_that_refuses_the_link_finishes(shm, tmp_path, capsys):
	job = create_job(shm)
	backed_up_project(job, 't' * LONG)
	out = tmp_path / 'out'
	out.mkdir()
	check_folder_restore(job, capsys, str(out), 'proj/sub/l')
	files = tmp_path / 'files'
	files.mkdir()
	check_file_restore(job, capsys, str(files), 'proj/sub/l')
