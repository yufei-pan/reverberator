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
	with rv.LOG_LOCK:
		rv.tl.teeerror('inner')
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
			data = open(path, 'rb').read()
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
	fake.callerStackDepth = -1
	proxy.teelog('m', 'info')
	assert fake.calls == [4, 5, -1]
