import os
import sys
import threading
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


def test_slugify_dirty_and_unicode():
	assert rv.slugify('My Job Name!') == 'my-job-name'
	assert rv.slugify('  spaces--and___underscores  ') == 'spaces-and___underscores'
	assert rv.slugify('über') == 'uber'
	assert rv.slugify('café', allow_unicode=True) == 'café'


def test_bidict_overwrite_and_delete():
	d = rv.bidict({1: '/a', 2: '/b'})
	assert d.inverse['/a'] == [1]
	d[1] = '/c'
	assert '/a' not in d.inverse
	assert d.inverse['/c'] == [1]
	del d[2]
	assert '/b' not in d.inverse


def test_get_args_defaults_and_flags():
	args, _ = rv.get_args([])
	assert args.rule_path == 'reverb_rule.tsv'
	assert args.journal is False
	assert rv.get_args(['--journal'])[0].journal is True
	assert rv.get_args(['-t', '0'])[0].threads == 0
	assert rv.get_args(['-t', '-2'])[0].threads == -2
	assert rv.get_args(['-t', '4'])[0].threads == 4
	assert rv.get_args(['--drop_sample_reverb_rule_file', 'out.tsv'])[0].drop_sample_reverb_rule_file is True
	assert rv.get_args(['--verbose'])[0].verbose is True


def test_hash_file_full_vs_partial(tmp_path):
	p = tmp_path / 'blob.bin'
	p.write_bytes(b'x' * (rv.HASH_SIZE + 100) + b'TAIL')
	full = rv.hash_file(str(p), full_hash=True)
	part = rv.hash_file(str(p), full_hash=False)
	assert len(full) == 16
	assert len(part) == 16
	assert full != part


def test_hash_file_refuses_fifo_without_blocking(tmp_path):
	# a file swapped for a FIFO after its lstat would block a plain open forever, with no writer
	fifo = str(tmp_path / 'was_a_file')
	os.mkfifo(fifo)
	outcome = []

	def hash_it():
		try:
			outcome.append(rv.hash_file(fifo, 4096))
		except OSError as e:
			outcome.append(e)
	worker = threading.Thread(target=hash_it, daemon=True)
	worker.start()
	worker.join(timeout=5)
	assert not worker.is_alive(), 'hash_file blocked opening a FIFO'
	assert isinstance(outcome[0], OSError)


def test_check_fs_signature_mismatch(tmp_path):
	assert rv.check_fs_signature(str(tmp_path), 'N/A') is True
	assert rv.check_fs_signature(str(tmp_path), 'this-signature-cannot-match-zzzz') is False


def test_signal_handler_first_clears_green_light_second_exits(monkeypatch):
	rv.GREEN_LIGHT.set()
	exited = []
	monkeypatch.setattr(sys, 'exit', lambda code: exited.append(code))
	monkeypatch.setattr(rv.time, 'sleep', lambda s: None)
	rv.signal_handler(None, None)
	assert rv.GREEN_LIGHT.is_set() is False
	rv.signal_handler(None, None)
	assert exited == [1]

