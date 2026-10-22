import lzma
import os
import re
import subprocess
import sys
import threading
import time
import pytest
import Tee_Logger
import reverberator as rv
from test_log_text import alerting_lines

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.abspath(rv.__file__))
THREADS = 16
MARKERS = 200

# many threads log markers at the same moment, through the module's own printing logger
SCRIPT = f'''
import threading
import reverberator as rv
barrier = threading.Barrier({THREADS})
def log(t):
	barrier.wait()
	for i in range({MARKERS}):
		rv.job_log(f'job-{{t}}', f'FAILED: marker {{i}}')
threads = [threading.Thread(target=log, args=(t,)) for t in range({THREADS})]
for thread in threads:
	thread.start()
for thread in threads:
	thread.join()
'''


@pytest.mark.process
def test_markers_logged_at_once_from_many_threads_each_start_a_line():
	child = subprocess.run([sys.executable, '-c', SCRIPT], env=dict(os.environ, PYTHONUNBUFFERED='1'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT, timeout=60)
	out = child.stdout.decode('utf-8', 'replace')
	assert child.returncode == 0, child.stderr.decode('utf-8', 'replace')
	lines = alerting_lines(out)
	assert len(lines) == THREADS * MARKERS
	pairs = {tuple(int(n) for n in re.search(r'job job-(\d+) FAILED: marker (\d+)', line).groups()) for line in lines}
	assert pairs == {(t, i) for t in range(THREADS) for i in range(MARKERS)}
	assert [line for line in out.split('\n') if line] == lines


def test_logging_while_holding_the_log_lock_does_not_deadlock(capsys):
	def log_holding_the_lock():
		with rv.LOG_LOCK:
			rv.tl.teeerror('inner')
	# a lock that is not re-entrant would hang here: the thread is joined with a timeout so that the test fails instead
	inner = threading.Thread(target=log_holding_the_lock, daemon=True)
	inner.start()
	inner.join(timeout=5)
	assert not inner.is_alive()
	assert 'inner' in capsys.readouterr().out
	other = threading.Thread(target=rv.tl.teeerror, args=('other',))
	with rv.LOG_LOCK:
		other.start()
		time.sleep(0.2)
		assert 'other' not in capsys.readouterr().out
	other.join(timeout=10)
	assert not other.is_alive()
	assert 'other' in capsys.readouterr().out


def daemon_logger(log_dir, program_name):
	# as run_daemon builds it, writing a log file
	return Tee_Logger.teeLogger(systemLogFileDir=str(log_dir), programName=program_name, compressLogAfterMonths=0, deleteLogAfterYears=2, suppressPrintout=True, noLog=False, callerStackDepth=4, in_place_compression='xz')


def log_probe(logger):
	logger.teeerror('probe')


def log_probe_from_here(logger):
	# depth 4 names this line: log_probe's caller
	log_probe(logger)


def logged_caller(logger, log_dir):
	for handler in list(logger.logger.handlers):
		handler.close()
	texts = []
	for folder, _, names in os.walk(log_dir):
		for name in names:
			path = os.path.join(folder, name)
			if os.path.islink(path):
				continue
			with open(path, 'rb') as f:
				data = f.read()
			if data.startswith(b'\xfd7zXZ'):
				data = lzma.decompress(data)
			texts.append(data.decode('utf-8'))
	lines = [line for text in texts for line in text.split('\n') if line.endswith(' probe')]
	assert len(lines) == 1
	return re.search(r'\] \[([^\]]*)\] probe$', lines[0]).group(1)


def test_the_log_file_names_the_same_caller_through_the_proxy(tmp_path):
	plain = daemon_logger(tmp_path / 'plain', 'reverberator-plain')
	proxied = rv.LockedLogger(daemon_logger(tmp_path / 'proxied', 'reverberator-proxied'))
	log_probe_from_here(plain)
	log_probe_from_here(proxied)
	assert logged_caller(plain, tmp_path / 'plain') == logged_caller(proxied.wrapped, tmp_path / 'proxied')


def test_a_missing_method_still_falls_back():
	class Old:
		def teeprint(self, msg, callerStackDepth=...):
			pass
	assert getattr(rv.LockedLogger(Old()), 'teewarning', 'fallback') == 'fallback'


def test_an_explicit_caller_depth_is_kept_one_deeper():
	class Fake:
		callerStackDepth = 4
		def __init__(self):
			self.calls = []
		def teelog(self, msg, level, callerStackDepth=...):
			self.calls.append(callerStackDepth)
	fake = Fake()
	proxy = rv.LockedLogger(fake)
	proxy.teelog('m', 'info', callerStackDepth=3)
	proxy.teelog('m', 'info')
	proxy.teelog('m', 'info', 3)
	fake.callerStackDepth = -1
	proxy.teelog('m', 'info')
	assert fake.calls == [4, 5, 4, -1]


def test_cut_line_never_splits_a_character():
	assert rv.cut_line('\U0001f600' * 5000) == '\U0001f600' * 4096 + ' \u2026(3616 more bytes)'
	assert rv.cut_line('ab' + '\u65e5' * 6000) == 'ab' + '\u65e5' * 5460 + ' \u2026(1620 more bytes)'


def test_cut_line_keeps_a_line_exactly_at_the_limit():
	assert rv.cut_line('x' * 16384) == 'x' * 16384
	line = 'a' + '\u65e5' * 5461
	assert len(line.encode()) == 16384
	assert rv.cut_line(line) == line


def test_cut_line_counts_a_lone_surrogate_as_three_bytes():
	assert rv.cut_line('\udcff' * 6000) == '\udcff' * 5461 + ' \u2026(1617 more bytes)'


def joined_line_lengths(capsys):
	out = capsys.readouterr().out
	lines = [re.sub(r'\x1b\[[0-9;]*m', '', line) for line in out.split('\n') if line]
	assert lines
	# the cap is on the message; Tee_Logger puts its own level tag before it
	assert all(len(line.encode()) <= len('[ERROR] ') + 16384 + len(' \u2026(99999 more bytes)'.encode()) for line in lines)
	assert lines[0].endswith('more bytes)')


def test_a_joined_watcher_line_is_cut_in_bytes(capsys):
	rv.watcherTeeLogToTl('/m/' + '\u65e5' * 10000, '\u65e5' * 10000, error=True)
	joined_line_lengths(capsys)


def test_a_joined_backuper_line_is_cut_in_bytes(capsys):
	rv.backuperTeeLogToTl('/m/' + '\u65e5' * 10000, '\u65e5' * 10000, error=True)
	joined_line_lengths(capsys)


def test_the_proxy_cuts_each_line_of_a_message():
	class Fake:
		def __init__(self):
			self.seen = []
		def teeprint(self, msg, callerStackDepth=...):
			self.seen.append(msg)
	fake = Fake()
	proxy = rv.LockedLogger(fake)
	proxy.teeprint('x' * 16390 + '\nshort\n' + 'y' * 16385)
	proxy.teeprint(msg='z' * 16386)
	proxy.teeprint(b'x' * 20000)
	assert fake.seen == ['x' * 16384 + ' \u2026(6 more bytes)\nshort\n' + 'y' * 16384 + ' \u2026(1 more bytes)', 'z' * 16384 + ' \u2026(2 more bytes)', b'x' * 20000]
