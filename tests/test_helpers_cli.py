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
