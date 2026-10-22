import os
import signal
import time
import pytest
import reverberator as rv
from tests.test_log_text import alerting_lines
from tests.harness import (
	write_rule, seed_monitor, wait_for_committed_count, committed_versions,
	write_incomplete_version, write_pending, wait_until, create_job, rule_row,
)

pytestmark = pytest.mark.process


def test_drop_sample_writes_file_and_exits(job, run_reverberator):
	rule = write_rule(job)
	os.remove(rule)
	proc = run_reverberator(job.rule_path, extra_args=('--drop_sample_reverb_rule_file',))
	assert proc.wait(timeout=10) == 0
	text = open(job.rule_path, encoding='utf-8').read()
	assert 'Job Name (Unique Key)' in text
	assert 'Incomplete V*' in text


def test_start_creates_v0(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	run_reverberator(job.rule_path)
	versions = wait_for_committed_count(job, 1, timeout=10)
	assert os.path.isfile(os.path.join(versions[0], 'a.txt'))


def test_file_write_creates_second_version(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('new')
	versions = wait_for_committed_count(job, 2, timeout=10)
	assert any(os.path.isfile(os.path.join(v, 'b.txt')) for v in versions)


def test_sigterm_does_not_commit_incomplete(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	open(os.path.join(job.monitor, 'c.txt'), 'w').write('c')
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=5)
	for name in os.listdir(job.job_vault) if os.path.isdir(job.job_vault) else []:
		if not name.startswith('V'):
			continue
		path = os.path.join(job.job_vault, name)
		if os.path.isdir(path) and rv.CONTENT_FILE_EXTENSION_NAME not in name:
			from tests.harness import content_file_path
			if not os.path.isfile(content_file_path(path)):
				link = os.path.join(job.job_vault, 'current_version')
				if os.path.lexists(link):
					assert os.path.basename(os.path.realpath(link)) != name


def test_restart_deletes_incomplete_keeps_committed(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=5)
	orphan = write_incomplete_version(job, 99, {'junk': 'x'}, timestamp='2021-12-31_00-00-00_-0800')
	run_reverberator(job.rule_path)
	wait_until(lambda: not os.path.isdir(orphan), timeout=10, message='incomplete V99 not removed')
	assert len(committed_versions(job)) >= 1


def test_pending_resume_and_discard(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'hello'})
	write_rule(job)
	a = os.path.join(job.monitor, 'a.txt')
	os.makedirs(job.job_vault, exist_ok=True)
	pending = write_pending(job, [rv.ChangeEvent(1.0, False, 'modify', a, None)])
	os.utime(job.monitor, (1000, 1000))
	os.utime(a, (1000, 1000))
	os.utime(pending, (2000, 2000))
	run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	wait_until(lambda: not os.path.exists(pending), timeout=10, message='pending file not consumed')


def test_skip_list_relative_to_rule_file_keeps_matches_out(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a', 'x.tmp': 't'})
	open(os.path.join(job.root, 'skip.txt'), 'w').write('*.tmp\n')
	write_rule(job, skip_list_file='skip.txt')
	run_reverberator(job.rule_path)
	v0 = wait_for_committed_count(job, 1, timeout=10)[0]
	assert os.path.isfile(os.path.join(v0, 'a.txt')) and not os.path.lexists(os.path.join(v0, 'x.tmp'))
	open(os.path.join(job.monitor, 'y.tmp'), 'w').write('y')
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	versions = wait_for_committed_count(job, 2, timeout=10)
	assert os.path.lexists(os.path.join(versions[-1], 'b.txt')) and not os.path.lexists(os.path.join(versions[-1], 'y.tmp'))


def test_job_with_missing_skip_list_does_not_stop_other_jobs(job, tmp_path, run_reverberator):
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	write_rule(job, skip_list_file=os.path.join(job.root, 'missing'), extra_rows=[rule_row(other)])
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(other, 1, timeout=10)
	assert proc.poll() is None and committed_versions(job) == []


def test_failing_job_retries_and_others_keep_running(job, tmp_path, run_reverberator, process_env):
	process_env['REVERB_JOB_RETRY_FIRST_SECONDS'] = '0.5'
	process_env['REVERB_JOB_RETRY_MAX_SECONDS'] = '1'
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	blocker = os.path.join(job.root, 'blocker')
	open(blocker, 'w').write('x')
	broken = rule_row(job)
	broken[2] = os.path.join(blocker, 'vault')   # a vault path under a regular file cannot be created
	write_rule(other, extra_rows=[broken])
	proc = run_reverberator(other.rule_path)
	wait_for_committed_count(other, 1, timeout=10)
	wait_until(lambda: 'reverberator job job FAILED' in ''.join(proc._out_buf + proc._err_buf), timeout=10, message='no FAILED line')
	os.remove(blocker)
	os.makedirs(os.path.join(blocker, 'vault'))
	wait_until(lambda: 'reverberator job job RECOVERED' in ''.join(proc._out_buf + proc._err_buf), timeout=15, message='no RECOVERED line')
	assert proc.poll() is None


def test_every_job_stopped_exits_3(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	open(os.path.join(job.root, 'skip.txt'), 'w').write('[z-a]\n')
	write_rule(job, skip_list_file='skip.txt')
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == 3
	text = ''.join(proc._out_buf + proc._err_buf)
	assert 'reverberator job job STOPPED' in text and 'reverberator EXITING with error' in text


@pytest.mark.parametrize('rule_file', ['missing', 'no_usable_row'])
def test_a_rule_file_with_no_job_exits_3(job, run_reverberator, rule_file):
	# only fixing the rule file helps, so systemd is told not to restart the daemon every 5 s
	if rule_file == 'no_usable_row':
		row = rule_row(job)
		row[1] = ''   # an empty Path Monitoring drops the row
		write_rule(job)
		open(job.rule_path, 'w', encoding='utf-8').write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == rv.EXIT_ALL_STOPPED
	assert 'reverberator EXITING with error: rule file' in ''.join(proc._out_buf + proc._err_buf)


def test_sigterm_exits_0(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	proc.send_signal(signal.SIGTERM)
	assert proc.wait(timeout=10) == 0


def test_job_waits_for_a_monitored_path_that_appears_later(job, run_reverberator):
	missing = os.path.join(job.root, 'late')
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, missing)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	proc = run_reverberator(job.rule_path)
	time.sleep(1)
	assert committed_versions(job) == [] and proc.poll() is None
	os.makedirs(missing)
	open(os.path.join(missing, 'a.txt'), 'w').write('a')
	wait_for_committed_count(job, 1, timeout=15)


def test_colliding_job_names_are_both_stopped(job, tmp_path, run_reverberator):
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	twin = rule_row(other)
	twin[0] = 'JOB'   # cleans up to 'job'
	write_rule(job, extra_rows=[twin])
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == 3
	assert ''.join(proc._out_buf + proc._err_buf).count('reverberator job job STOPPED') == 2
	assert any(line.startswith('JOB\t') for line in open(job.rule_path).read().splitlines())


@pytest.mark.parametrize('verbose', [False, True])
def test_names_that_are_not_text_are_kept_exactly_and_never_alert(job, run_reverberator, process_env, verbose):
	process_env['LANG'] = process_env['LC_ALL'] = 'C.UTF-8'
	seed_monitor(job, {'keep': 'k'})
	write_rule(job)
	proc = run_reverberator(job.rule_path, extra_args=('-v',) if verbose else ())
	wait_for_committed_count(job, 1, timeout=15)
	m = os.fsencode(job.monitor)
	forged = b'reverberator job job FAILED: forged'
	files = {b'bad\xff.txt': b'bad', b'd\xfe/x\xfd': b'nested', b'nl\n' + forged: b'newline', b'esc\x1b[31mred': b'esc'}
	os.makedirs(m + b'/d\xfe')
	for name, content in files.items():
		with open(m + b'/' + name, 'wb') as f:
			f.write(content)
	def kept():
		latest = committed_versions(job)[-1]
		return all(os.path.lexists(os.path.join(os.fsencode(latest), name)) for name in files)
	wait_until(kept, timeout=30, message='the names were not backed up')
	latest = os.fsencode(committed_versions(job)[-1])
	for name, content in files.items():
		assert open(os.path.join(latest, name), 'rb').read() == content
	assert os.path.isdir(os.path.join(latest, b'd\xfe'))
	time.sleep(1)
	assert proc.poll() is None
	proc.send_signal(signal.SIGTERM)
	proc.wait(timeout=15)
	output = ''.join(proc._out_buf + proc._err_buf)
	assert alerting_lines(output) == []
	assert '\x1b[31mred' not in output and not any('\udc80' <= c <= '\udcff' for c in output)
