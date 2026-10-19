import os
import signal
import pytest
import reverberator as rv
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


def test_sigterm_exits_0(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	proc.send_signal(signal.SIGTERM)
	assert proc.wait(timeout=10) == 0
