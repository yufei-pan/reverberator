import os
import pytest
import reverberator as rv

pytestmark = pytest.mark.unit


def test_apply_poll_wait_default_when_env_missing(monkeypatch):
	monkeypatch.delenv('REVERB_POLL_WAIT_SECONDS', raising=False)
	assert rv.apply_poll_wait_from_env() == 3.0
	assert rv.POLL_WAIT_SECONDS == 3.0


def test_apply_poll_wait_reads_env_float(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', '0.05')
	assert rv.apply_poll_wait_from_env() == 0.05
	assert rv.POLL_WAIT_SECONDS == 0.05


def test_apply_poll_wait_invalid_env_uses_default(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', 'nope')
	assert rv.apply_poll_wait_from_env() == 3.0
	assert rv.POLL_WAIT_SECONDS == 3.0


def test_apply_poll_wait_blank_env_uses_default(monkeypatch):
	monkeypatch.setenv('REVERB_POLL_WAIT_SECONDS', '  ')
	assert rv.apply_poll_wait_from_env() == 3.0


from tests.harness import create_job, seed_monitor, write_rule, write_committed_version, write_incomplete_version, committed_versions


def test_harness_write_committed_and_incomplete(tmp_path):
	job = create_job(str(tmp_path))
	seed_monitor(job, {'a.txt': 'hello'})
	v0 = write_committed_version(job, 0, {'a.txt': 'hello'})
	assert os.path.isdir(v0)
	assert os.path.isfile(os.path.join(job.job_vault, 'current_version')) or os.path.islink(os.path.join(job.job_vault, 'current_version'))
	assert committed_versions(job) == [v0]
	orphan = write_incomplete_version(job, 1, {'a.txt': 'x'})
	assert os.path.isdir(orphan)
	assert committed_versions(job) == [v0]


def test_harness_write_rule_explicit_columns(tmp_path):
	job = create_job(str(tmp_path))
	path = write_rule(job)
	assert os.path.isfile(path)
	text = open(path, encoding='utf-8').read()
	assert job.monitor in text
	assert 'N/A' in text
	assert '\tauto\t' not in text

