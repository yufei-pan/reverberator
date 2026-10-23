import os
import signal
import subprocess
import sys
import threading
import pytest
import reverberator as rv
from tests.harness import create_job, reverberator_script


@pytest.fixture(autouse=True)
def restore_runtime_globals(tmp_path, monkeypatch):
	old_poll = rv.POLL_WAIT_SECONDS
	rv.GREEN_LIGHT.set()
	# a test may write a version's change list again after its moves were read
	rv.VERSION_MOVES.clear()
	rv.VERSION_MOVES_WARNED.clear()
	# a test's aborted prunes must not hold back another's FAILED marker
	rv.PRUNE_ABORTED.clear()
	# and a test's warning that pruning has no secret must not hold back another's
	rv.PRUNE_SALT_MISSING.clear()
	# and a test's vault seen with versions must not make a later scan of a new vault at that path fail
	rv.VAULTS_WITH_VERSIONS.clear()
	rv.RESTORE_STOP.clear()
	# the daemon publishes status files: keep them out of /run/reverberator
	monkeypatch.setenv('REVERB_STATE_DIR', str(tmp_path / 'state'))
	yield
	rv.STATUS_BOARD = None
	rv.POLL_WAIT_SECONDS = old_poll
	rv.GREEN_LIGHT.set()


@pytest.fixture
def job(tmp_path):
	return create_job(str(tmp_path))


@pytest.fixture
def poll_fast():
	rv.POLL_WAIT_SECONDS = 0.05
	return 0.05


@pytest.fixture
def process_env(tmp_path):
	env = os.environ.copy()
	env['REVERB_STATE_DIR'] = str(tmp_path / 'state')
	env['REVERB_POLL_WAIT_SECONDS'] = '0.05'
	env['PYTHONUNBUFFERED'] = '1'
	return env


@pytest.fixture
def run_reverberator(tmp_path, process_env):
	procs = []
	log_dir = str(tmp_path / 'proc_logs')
	os.makedirs(log_dir, exist_ok=True)

	def _drain(stream, buf):
		try:
			for line in iter(stream.readline, ''):
				buf.append(line)
		except Exception:
			pass

	def _run(rule_path, extra_args=()):
		p = subprocess.Popen(
			[sys.executable, reverberator_script(), '--no_log', '-ld', log_dir, *list(extra_args), str(rule_path)],
			env=process_env,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			# a byte that is not UTF-8 must show in the capture, not end the reading of it
			errors='surrogateescape',
		)
		p._out_buf = []
		p._err_buf = []
		p._drain_threads = (
			threading.Thread(target=_drain, args=(p.stdout, p._out_buf), daemon=True),
			threading.Thread(target=_drain, args=(p.stderr, p._err_buf), daemon=True),
		)
		for t in p._drain_threads:
			t.start()
		procs.append(p)
		return p

	yield _run
	for p in procs:
		if p.poll() is None:
			p.send_signal(signal.SIGTERM)
			try:
				p.wait(timeout=2)
			except subprocess.TimeoutExpired:
				p.kill()
				p.wait()
		for t in getattr(p, '_drain_threads', ()):
			t.join(timeout=1)
		out = ''.join(getattr(p, '_out_buf', []))
		err = ''.join(getattr(p, '_err_buf', []))
		if out:
			print('--- reverberator stdout ---')
			print(out)
		if err:
			print('--- reverberator stderr ---')
			print(err)


def pytest_collection_modifyitems(config, items):
	if sys.platform == 'linux':
		return
	skip = pytest.mark.skip(reason='inotify/process tests require Linux')
	for item in items:
		if item.get_closest_marker('inotify') or item.get_closest_marker('process'):
			item.add_marker(skip)
