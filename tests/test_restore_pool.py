'''
Round 9, Task 6: a restore of a folder never writes out pruning's temporary (a hidden .<hash>.reverberator-partial that is
the same file as a link beside it leads to), and restore and history warn on stderr, and exit 1, while a disk of the
vault's pool is missing.
'''
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import create_job, seed_monitor, run_backup, event_entry, write_rule

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fast(poll_fast):
	return poll_fast


class Killed(BaseException):
	pass


def two_versions(job, tree=None):
	'''V0 holds the tree's copies; V1, a backup of a change to keep, links d/a (and the rest) to V0's.'''
	seed_monitor(job, {'d/a': 'alpha', 'keep': 'k0'} if tree is None else tree)
	run_backup(job)
	write(job, 'keep', 'k1')
	run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]))
	v0, v1 = rv.list_versions(job.job_vault)
	assert os.path.islink(os.path.join(v1.path, 'd/a'))
	return v0, v1


def write(job, rel, content):
	with open(os.path.join(job.monitor, rel), 'w', encoding='utf-8') as f:
		f.write(content)


def add_temp(job, v0, v1, salt):
	'''The temp a prune cut off between its hard link and its rename leaves beside V1's link of d/a.'''
	copy = os.path.join(v0.path, 'd/a')
	temp = rv.prune_link_path(os.path.join(v1.path, 'd/a'), os.lstat(copy), salt)
	os.link(copy, temp)
	return temp


def command(tmp_path, capsys, *argv):
	# what building the vault logged is not the command's output
	capsys.readouterr()
	code = rv.run_command([*argv, '--rule', str(tmp_path / 'rule.tsv'), '--state_dir', str(tmp_path / 'state')])
	out = capsys.readouterr()
	return code, out.out, out.err


def restored_names(dest):
	return sorted(os.path.relpath(os.path.join(top, name), dest) for top, folders, names in os.walk(dest) for name in folders + names)


def test_a_folder_restore_skips_a_prune_temp(tmp_path, capsys):
	job = create_job(str(tmp_path))
	write_rule(job)
	v0, v1 = two_versions(job)
	add_temp(job, v0, v1, rv.vault_prune_salt(job.job_vault, job.job_name))
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'd'), str(dest))
	assert code == 0, (out, err)
	assert restored_names(str(dest)) == ['d', 'd/a']
	assert open(dest / 'd' / 'a').read() == 'alpha'
	assert 'partial' not in out + err


def test_a_prune_temp_without_a_salt_is_skipped_too(tmp_path, capsys):
	job = create_job(str(tmp_path))
	write_rule(job)
	v0, v1 = two_versions(job)
	assert not os.path.lexists(os.path.join(job.job_vault, rv.PRUNE_SALT_FILE_NAME))
	copy = os.path.join(v0.path, 'd/a')
	os.link(copy, rv.prune_link_path(os.path.join(v1.path, 'd/a'), os.lstat(copy), None))
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'd'), str(dest))
	assert code == 0, (out, err)
	assert restored_names(str(dest)) == ['d', 'd/a']
	assert not os.path.lexists(os.path.join(job.job_vault, rv.PRUNE_SALT_FILE_NAME))


def test_a_users_file_of_the_temp_form_is_restored(tmp_path, capsys):
	job = create_job(str(tmp_path))
	write_rule(job)
	name = '.' + 'ab' * 16 + rv.PARTIAL_COPY_SUFFIX
	assert rv.PARTIAL_COPY_NAME.fullmatch(name)
	v0, v1 = two_versions(job, {f'd/a': 'alpha', f'd/{name}': 'mine', 'keep': 'k0'})
	assert os.path.islink(os.path.join(v1.path, 'd', name))
	assert os.lstat(os.path.join(v0.path, 'd', name)).st_ino != os.lstat(os.path.join(v0.path, 'd/a')).st_ino
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'd'), str(dest))
	assert code == 0, (out, err)
	assert restored_names(str(dest)) == sorted(['d', 'd/a', f'd/{name}'])
	assert open(dest / 'd' / name).read() == 'mine'


def test_a_killed_prune_then_the_next_prune_consumes_its_temp(tmp_path, monkeypatch, capsys):
	job = create_job(str(tmp_path))
	write_rule(job)
	v0, v1 = two_versions(job)
	salt = rv.vault_prune_salt(job.job_vault, job.job_name)
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(os.fspath(source))):
			raise Killed()
		return real_rename(source, dest, *args, **kwargs)
	monkeypatch.setattr(rv.os, 'rename', rename)
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	with pytest.raises(Killed):
		rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=salt)
	monkeypatch.undo()
	temps = [n for n in os.listdir(os.path.join(v1.path, 'd')) if rv.PARTIAL_COPY_NAME.fullmatch(n)]
	assert len(temps) == 1
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'd'), str(dest))
	assert code == 0, (out, err)
	assert restored_names(str(dest)) == ['d', 'd/a']
	rv.VERSION_MOVES.clear()
	rv.REAL_VAULT_FOLDERS.clear()
	info = rv.get_vault_info(job.job_vault).vault_info_dict
	rv.decrement_stepper(info, job.job_name, job.monitor, prune_salt=salt)
	assert not os.path.exists(v0.path)
	assert [n for n in os.listdir(os.path.join(v1.path, 'd')) if rv.PARTIAL_COPY_NAME.fullmatch(n)] == []
	assert open(os.path.join(v1.path, 'd/a')).read() == 'alpha' and not os.path.islink(os.path.join(v1.path, 'd/a'))


def test_a_referenced_first_versions_prune_temp_is_skipped(tmp_path, monkeypatch, capsys):
	# Keep 1 Complete Backup False: V0's files are links into the monitored path, and a killed prune's temp beside V1's
	# link is one of them ( kind 'referenced' ), which a folder restore leaves out too
	job = create_job(str(tmp_path))
	write_rule(job, keep_one_complete_backup='False')
	seed_monitor(job, {'d/a': 'alpha', 'keep': 'k0'})
	run_backup(job, keep_one_complete_backup=False)
	write(job, 'keep', 'k1')
	run_backup(job, OrderedDict([event_entry(job, 'keep', 'modify')]), keep_one_complete_backup=False)
	v0, v1 = rv.list_versions(job.job_vault)
	salt = rv.vault_prune_salt(job.job_vault, job.job_name)
	real_rename = os.rename
	def rename(source, dest, *args, **kwargs):
		if rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(os.fspath(source))):
			raise Killed()
		return real_rename(source, dest, *args, **kwargs)
	with monkeypatch.context() as patched:
		patched.setattr(rv.os, 'rename', rename)
		with pytest.raises(Killed):
			rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict, job.job_name, job.monitor, prune_salt=salt)
	assert len([n for n in os.listdir(os.path.join(v1.path, 'd')) if rv.PARTIAL_COPY_NAME.fullmatch(n)]) == 1
	dest = tmp_path / 'out'
	dest.mkdir()
	command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'd'), str(dest))
	# d/a itself is a link into the monitored path, which the restore reports
	assert not [name for name in restored_names(str(dest)) if rv.PARTIAL_COPY_NAME.fullmatch(os.path.basename(name))]


def pooled_job(tmp_path, fake_pool):
	job = create_job(str(tmp_path))
	write_rule(job)
	a, b = fake_pool.add(job.vault, ['a', 'b'])
	two_versions(job)
	return job, a


def test_history_warns_and_exits_1_when_a_vault_disk_is_missing(tmp_path, fake_pool, capsys):
	job, a = pooled_job(tmp_path, fake_pool)
	fake_pool.drop(a)
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'keep'))
	assert 'V1' in out and 'modified' in out
	assert err == f'Warning: disk {a} of pool {job.vault} is not mounted: {job.job_vault} may be incomplete\n'
	assert code == 1


def test_restore_runs_warns_and_exits_1_when_a_vault_disk_is_missing(tmp_path, fake_pool, capsys):
	job, a = pooled_job(tmp_path, fake_pool)
	fake_pool.drop(a)
	dest = tmp_path / 'out'
	dest.mkdir()
	code, out, err = command(tmp_path, capsys, 'restore', '--version', '1', os.path.join(job.monitor, 'keep'), str(dest))
	assert open(dest / 'keep').read() == 'k1'
	warning = f'Warning: disk {a} of pool {job.vault} is not mounted: {job.job_vault} may be incomplete'
	assert err.count(warning) == 1
	assert code == 1


def test_commands_off_any_pool_print_no_warning(tmp_path, capsys):
	job = create_job(str(tmp_path))
	write_rule(job)
	two_versions(job)
	code, out, err = command(tmp_path, capsys, 'history', os.path.join(job.monitor, 'keep'))
	assert (code, err) == (0, '')
	assert 'V1' in out and 'modified' in out
