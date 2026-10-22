import contextlib
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
	stuck = inner.is_alive()
	if stuck:
		# a plain Lock lets this thread release it, so that the tests after this one do not hang too
		with contextlib.suppress(RuntimeError):
			rv.LOG_LOCK.release()
		inner.join(timeout=5)
	assert not stuck
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


def assert_cut(line, expected):
	# the result, notice included, fits the limit, and cutting it again changes nothing
	result = rv.cut_line(line)
	assert result == expected
	assert len(result.encode('utf-8', 'surrogatepass')) <= rv.LOG_LINE_LIMIT
	assert rv.cut_line(result) == result


def test_cut_line_never_splits_a_character():
	assert_cut('\U0001f600' * 5000, '\U0001f600' * 4090 + ' \u2026(3640 more bytes)')
	assert_cut('ab' + '\u65e5' * 6000, 'ab' + '\u65e5' * 5453 + ' \u2026(1641 more bytes)')


def test_cut_line_steps_back_over_up_to_three_bytes_of_a_character():
	# the notice reserves 22 bytes, so the cut starts at byte 16362, and with 0, 1, 2 or 3 bytes of padding
	# that byte is the third, second or first byte of an emoji, or its fourth (steps back 2, 1, 0 or 3)
	for pad, kept, left in ((0, 4090, 3640), (1, 4090, 3640), (2, 4090, 3640), (3, 4089, 3644)):
		assert_cut('x' * pad + '\U0001f600' * 5000, 'x' * pad + '\U0001f600' * kept + f' \u2026({left} more bytes)')


def test_cut_line_keeps_a_line_exactly_at_the_limit():
	assert_cut('x' * 16384, 'x' * 16384)
	line = 'a' + '\u65e5' * 5461
	assert len(line.encode()) == 16384
	assert_cut(line, line)


def test_cut_line_cuts_a_line_one_byte_over_the_limit():
	assert_cut('x' * 16385, 'x' * 16362 + ' \u2026(23 more bytes)')


def test_cut_line_counts_a_lone_surrogate_as_three_bytes():
	assert_cut('\udcff' * 6000, '\udcff' * 5454 + ' \u2026(1638 more bytes)')


def test_cutting_a_cut_line_again_keeps_its_count_of_bytes_left_out():
	assert rv.cut_line(rv.cut_line('x' * 20000)) == 'x' * 16362 + ' \u2026(3638 more bytes)'


def plain(out):
	return re.sub(r'\x1b\[[0-9;]*m', '', out)


def test_the_line_job_log_prints_is_the_line_it_returns(capsys):
	line = rv.job_log('j', 'UNREADABLE: ' + 'b' * 50000)
	assert line.endswith(' \u2026(33669 more bytes)')
	assert line in plain(capsys.readouterr().out)


def test_the_line_tl_prints_is_the_text_log_text_returns(capsys):
	text = rv.log_text('a' * 30000)
	assert text == 'a' * 16362 + ' \u2026(13638 more bytes)'
	rv.tl.teeerror(text)
	assert text in plain(capsys.readouterr().out)


def test_a_continuation_line_of_log_text_is_printed_as_log_text_returns_it(capsys):
	text = rv.log_text('short\n' + 'a' * 30000)
	second = text.split('\n')[1]
	assert second == '    ' + 'a' * 16358 + ' \u2026(13642 more bytes)'
	assert len(second.encode()) <= rv.LOG_LINE_LIMIT
	rv.tl.teeerror(text)
	assert second in plain(capsys.readouterr().out).split('\n')


def assert_each_line_is_cut(capsys):
	out = capsys.readouterr().out
	lines = [line for line in plain(out).split('\n') if line]
	assert lines
	# the joined line is cut once more, counting its own bytes; Tee_Logger puts its own level tag before it
	assert all(len(line.encode()) <= len('[ERROR] ') + rv.LOG_LINE_LIMIT for line in lines)
	assert lines[0].endswith('more bytes)')


def test_a_joined_watcher_line_is_cut_in_bytes(capsys):
	rv.watcherTeeLogToTl('/m/' + '\u65e5' * 10000, '\u65e5' * 10000, error=True)
	assert_each_line_is_cut(capsys)


def test_a_joined_backuper_line_is_cut_in_bytes(capsys):
	rv.backuperTeeLogToTl('/m/' + '\u65e5' * 10000, '\u65e5' * 10000, error=True)
	assert_each_line_is_cut(capsys)


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
	# no msg parameter: nothing is cut, and the message is found by its position
	class Table:
		def __init__(self):
			self.seen = []
		def printTable(self, data, callerStackDepth=...):
			self.seen.append(data)
		def teelog(self, level, msg, callerStackDepth=...):
			self.seen.append((level, msg))
	table = Table()
	rv.LockedLogger(table).printTable('x' * 20000)
	rv.LockedLogger(table).teelog('q' * 20000, 'w' * 20000)
	assert table.seen == ['x' * 20000, ('q' * 20000, 'w' * 16362 + ' \u2026(3638 more bytes)')]
	assert fake.seen == ['x' * 16362 + ' \u2026(28 more bytes)\nshort\n' + 'y' * 16362 + ' \u2026(23 more bytes)', 'z' * 16362 + ' \u2026(24 more bytes)', b'x' * 20000]
