import errno
import json
import shutil
import os
import subprocess
import sys
import time
import pytest
import reverberator as rv
from tests.harness import create_job, rule_row, write_rule, write_committed_version, reverberator_script

pytestmark = pytest.mark.unit


def state_dir(tmp_path):
	return str(tmp_path / 'state')


def write_state(tmp_path, name, record):
	os.makedirs(state_dir(tmp_path), exist_ok=True)
	with open(os.path.join(state_dir(tmp_path), name), 'w') as f:
		f.write(record if isinstance(record, str) else json.dumps(record))


def daemon_record(job, pid = None, ticks_shift = 0, started_at = None):
	pid = os.getpid() if pid is None else pid
	return {'pid': pid, 'start_ticks': rv.process_start_ticks(pid) + ticks_shift, 'version': 0.38,
		'started_at': time.time() - 100 if started_at is None else started_at, 'rule_path': job.rule_path}


def job_record(job, state = 'running', **fields):
	record = {'job': job.job_name, 'state': state, 'detail': '', 'since': time.time() - 50, 'retry_at': None,
		'failures': 0, 'last_success': None, 'updated': time.time() - 10}
	record.update(fields)
	return record


def two_versions(job, keep = '0'):
	write_rule(job, keep_n_versions=keep)
	write_committed_version(job, 0, {'a': 'x'}, timestamp='2021-01-01_00-00-00_-0800')
	write_committed_version(job, 1, {'a': 'xy'}, timestamp='2021-01-02_00-00-00_-0800')


def status(tmp_path, capsys, *extra):
	code = rv.run_command(['status', '--state_dir', state_dir(tmp_path), *extra])
	captured = capsys.readouterr()
	return code, captured.out, captured.err


def test_main_dispatches_commands_and_keeps_the_daemon_argv(monkeypatch):
	calls = []
	monkeypatch.setattr(rv, 'run_command', lambda argv: calls.append(('cmd', argv)) or 0)
	monkeypatch.setattr(rv, 'run_daemon', lambda: calls.append(('daemon',)))
	with pytest.raises(SystemExit):
		rv.main(['status'])
	rv.main(['-t', '6', 'rule.tsv'])
	assert calls == [('cmd', ['status']), ('daemon',)]


def test_command_args_define_all_three_commands():
	args = rv.get_command_args(['restore', 'p', 'd', '--job', 'j', '--version', '3', '--at', 'x', '--in-place', '--threads', '2', '--yes', '--rule', 'r', '--state_dir', 's'])
	assert (args.command, args.path, args.dest, args.job, args.version, args.at, args.in_place, args.threads, args.yes, args.rule, args.state_dir) == ('restore', 'p', 'd', 'j', 3, 'x', True, 2, True, 'r', 's')
	assert rv.get_command_args(['history', 'p', '--files']).files is True
	assert rv.get_command_args(['status']).rule is None


def test_restore_runs_four_copies_at_once_by_default(capsys):
	# however many processors there are, so a restore does not keep the vault disk busy with more by default
	assert rv.get_command_args(['restore', 'p']).threads == 4
	with pytest.raises(SystemExit):
		rv.get_command_args(['restore', '--help'])
	assert 'Copies to run at once (default 4)' in ' '.join(capsys.readouterr().out.split())


def test_status_with_a_live_daemon(job, tmp_path, capsys):
	two_versions(job, keep='5')
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job))
	code, out, err = status(tmp_path, capsys)
	assert code == 0 and err == ''
	assert 'running since' in out and f'(pid {os.getpid()})' in out and f'rules {job.rule_path}' in out
	assert 'last known' not in out
	assert f'{job.job_name}  ' in out and ' running\n' in out
	assert 'last backup 2021-01-02 00:00 (V1)' in out
	assert '2 versions (limit 5), oldest V0 2021-01-01 00:00' in out
	assert 'no limit' in out and 'inodes' in out


def test_status_after_the_daemon_died(job, tmp_path, capsys):
	two_versions(job)
	proc = subprocess.Popen([sys.executable, '-c', 'pass'])
	proc.wait()
	record = daemon_record(job)
	record['pid'] = proc.pid
	write_state(tmp_path, 'daemon.json', record)
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job))
	code, out, err = status(tmp_path, capsys)
	assert code == 0
	assert 'reverberator is not running (last started ' in out
	assert 'last known: running' in out


def test_status_with_a_reused_pid(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job, ticks_shift=1))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job))
	code, out, err = status(tmp_path, capsys)
	assert code == 0 and 'is not running' in out and 'last known: running' in out


def test_status_marks_a_record_from_an_earlier_run_as_last_known(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job, started_at=time.time() - 10))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job, updated=time.time() - 500))
	code, out, err = status(tmp_path, capsys)
	assert 'running since' in out and 'last known: running' in out


def test_status_state_phrases(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	at = time.mktime((2026, 10, 19, 8, 40, 0, 0, 0, -1))
	cases = [
		(dict(state='retrying', detail='boom', failures=3, retry_at=at), 'retrying at 08:40 after 3 failed attempts: boom'),
		(dict(state='waiting', detail='/mnt/x: not mounted', since=at), 'waiting for disk since 08:40: /mnt/x: not mounted'),
		(dict(state='stopped', detail='skip list lost'), 'stopped: skip list lost'),
		(dict(state='starting'), 'starting'),
	]
	for fields, phrase in cases:
		write_state(tmp_path, f'job-{job.job_name}.json', job_record(job, **fields))
		code, out, err = status(tmp_path, capsys)
		assert code == 0 and phrase in out and 'last known' not in out


def test_status_vault_not_mounted(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job))
	shutil.rmtree(job.vault)
	code, out, err = status(tmp_path, capsys)
	assert code == 0 and f'vault not mounted: {job.vault}' in out and 'no versions yet' in out


def test_status_shows_a_detail_with_control_characters_escaped(job, tmp_path, capsys):
	# a job's detail can quote a monitored path, which anyone writing there names
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	write_state(tmp_path, f'job-{job.job_name}.json', job_record(job, state='stopped', detail='cannot read /m/\x1b[2Jx\nnext \udcff'))
	code, out, err = status(tmp_path, capsys)
	assert (code, err) == (0, '')
	assert 'stopped: cannot read /m/\\x1b[2Jx\\x0anext \\xff\n' in out
	assert '\x1b' not in out


def test_status_numbers_match_the_vault(job, tmp_path):
	two_versions(job, keep='4')
	rules = rv.parse_rules(job.rule_path, read_only=True)
	rules[0] = rules[0]._replace(backup_size_limit='5%,i5%')
	numbers = rv.vault_numbers(rules[0])
	versions = rv.list_versions(job.job_vault)
	assert numbers.present and numbers.versions == 2 and numbers.keep_n == 4
	assert numbers.size == sum(v.size for v in versions) and numbers.inodes == sum(v.inodes for v in versions)
	assert (numbers.size_limit, numbers.inode_limit) == rv.get_backup_limits_from_str('5%,i5%', *rv.get_path_fs_info(job.vault))


def test_status_needs_a_rule_without_a_record(tmp_path, capsys):
	code, out, err = status(tmp_path, capsys)
	assert code == rv.EXIT_USAGE and '--rule' in err and out == ''


def test_status_takes_the_rule_from_a_stale_record(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job, ticks_shift=1))
	assert status(tmp_path, capsys)[0] == 0


def test_status_ignores_malformed_files(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'job-garbage.json', '{not json')
	write_state(tmp_path, f'job-{job.job_name}.json', '{not json')
	code, out, err = status(tmp_path, capsys, '--rule', job.rule_path)
	assert code == 0 and 'unknown' in out and 'reverberator is not running\n' in out
	write_state(tmp_path, 'daemon.json', '[1]')
	write_state(tmp_path, f'job-{job.job_name}.json', {'job': job.job_name, 'state': 'nonsense'})
	code, out, err = status(tmp_path, capsys, '--rule', job.rule_path)
	assert code == 0 and 'unknown' in out


def test_status_names_an_unreadable_rule_file(tmp_path, capsys):
	code, out, err = status(tmp_path, capsys, '--rule', str(tmp_path))
	assert code != 0 and str(tmp_path) in err and 'Traceback' not in err
	empty = tmp_path / 'ignored.tsv'
	empty.write_text('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + 'j\t/m\t/m/vault\n')
	code, out, err = status(tmp_path, capsys, '--rule', str(empty))
	assert code != 0 and 'no jobs' in err


def test_status_keeps_the_header_mismatch_dump_off_the_output(job, tmp_path, capsys):
	two_versions(job)
	with open(job.rule_path) as f:
		lines = f.read().splitlines()
	with open(job.rule_path, 'w') as f:
		f.write('\n'.join('\t'.join(line.split('\t')[:-1]) for line in lines) + '\n')
	code, out, err = status(tmp_path, capsys, '--rule', job.rule_path)
	assert code == 0 and 'mismatch' not in (out + err).lower()


def test_status_writes_nothing(job, tmp_path, capsys):
	two_versions(job)
	write_state(tmp_path, 'daemon.json', daemon_record(job))
	def snapshot():
		found = {}
		for top in (job.root, state_dir(tmp_path)):
			for folder, names, files in os.walk(top):
				for name in names + files:
					path = os.path.join(folder, name)
					found[path] = os.lstat(path)
		return {path: (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode, st.st_uid, st.st_gid) for path, st in found.items()}, open(job.rule_path, 'rb').read()
	before = snapshot()
	assert status(tmp_path, capsys)[0] == 0
	assert snapshot() == before


@pytest.mark.process
def test_status_runs_as_a_subprocess(job, tmp_path, process_env):
	two_versions(job)
	done = subprocess.run([sys.executable, reverberator_script(), 'status', '--rule', job.rule_path, '--state_dir', state_dir(tmp_path)],
		capture_output=True, text=True, env=process_env, timeout=60)
	assert done.returncode == 0 and job.job_name in done.stdout


def test_status_shows_an_unreadable_vault_and_the_other_jobs(job, tmp_path, capsys, monkeypatch):
	two_versions(job)
	other = create_job(str(tmp_path / 'other'), 'second')
	write_committed_version(other, 0, {'a': 'x'})
	write_rule(job, extra_rows=[rule_row(other)])
	real_listdir = os.listdir
	def listdir(path = '.'):
		if os.fspath(path) in (job.vault, job.job_vault):
			raise OSError(errno.ENOTCONN, 'Transport endpoint is not connected')
		return real_listdir(path)
	monkeypatch.setattr(os, 'listdir', listdir)
	code, out, err = status(tmp_path, capsys, '--rule', job.rule_path)
	assert code == 0 and 'Traceback' not in err
	assert f'vault not readable: {job.vault}: ' in out and 'not connected' in out
	assert 'last backup' in out and out.index('second') > out.index('vault not readable')


def test_show_size_and_count_below_a_thousand_are_plain():
	assert [rv.show_size(n) for n in (0, 5, 1023)] == ['0 B', '5 B', '1023 B']
	assert rv.show_size(1536) == '1.50 KiB' and rv.show_size(0, 0) == 'no limit'
	assert [rv.show_count(n) for n in (0, 4, 999)] == ['0', '4', '999']
	assert rv.show_count(1000) == '1.00 K' and rv.show_count(5, 0) == 'no limit'


def test_status_vault_line_formats(job, tmp_path, capsys):
	two_versions(job)
	code, out, err = status(tmp_path, capsys, '--rule', job.rule_path)
	line = next(line for line in out.split('\n') if 'inodes' in line)
	versions = rv.list_versions(job.job_vault)
	assert line.strip() == f'vault {rv.show_size(sum(v.size for v in versions))} / no limit, {sum(v.inodes for v in versions)} inodes / no limit'
	assert 'limit no limit' not in out and ' 4.00 inodes' not in line


def test_status_lists_each_vault_once(job, tmp_path, capsys, monkeypatch):
	two_versions(job)
	listed = []
	real = rv.list_versions
	monkeypatch.setattr(rv, 'list_versions', lambda path: listed.append(path) or real(path))
	assert status(tmp_path, capsys, '--rule', job.rule_path)[0] == 0
	assert listed == [job.job_vault]
