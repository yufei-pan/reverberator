import os
import signal
import pytest
import reverberator as rv
from tests.harness import (
	write_rule, seed_monitor, wait_for_committed_count, committed_versions,
	write_incomplete_version, write_pending, wait_until,
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
