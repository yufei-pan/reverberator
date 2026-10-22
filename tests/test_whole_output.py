import atexit
import io
import os
import re
import subprocess
import sys
import threading
import pytest
import reverberator as rv
from test_log_text import alerting_lines

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.abspath(rv.__file__))
MARKER_THREADS = 8
LIBRARY_THREADS = 8
LINES = 200
COLOUR = re.compile(r'\x1b\[[0-9;]*m')


class Recorder:
	'''A text stream that keeps each write's argument and counts flushes.'''
	def __init__(self):
		self.writes = []
		self.flushes = 0

	def write(self, text):
		self.writes.append(text)
		return len(text)

	def flush(self):
		self.flushes += 1


def test_a_part_waits_for_its_newline():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	assert w.write('ab') == 2
	assert fake.writes == []
	assert w.write('c\nd') == 3
	assert fake.writes == ['abc\n']
	assert w.write('\n') == 1
	assert fake.writes == ['abc\n', 'd\n']


def test_lines_from_many_threads_reach_the_stream_whole():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	barrier = threading.Barrier(16)
	def write(t):
		barrier.wait()
		for i in range(200):
			w.write(f'T{t} part ')
			w.write(f'{i}')
			w.write('\n')
	threads = [threading.Thread(target=write, args=(t,)) for t in range(16)]
	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join()
	assert all(text.endswith('\n') for text in fake.writes)
	lines = ''.join(fake.writes).split('\n')
	assert lines.pop() == ''
	assert sorted(lines) == sorted(f'T{t} part {i}' for t in range(16) for i in range(200))


def test_parts_left_by_ended_threads_are_written_as_their_own_lines():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	thread = threading.Thread(target=w.write, args=('left',))
	thread.start()
	thread.join()
	w.write('main\n')
	assert fake.writes == ['main\n']
	w.write_held()
	assert fake.writes == ['main\n', 'left\n']
	w.write_held()
	assert fake.writes == ['main\n', 'left\n']


def test_a_part_longer_than_the_limit_is_written_as_its_own_line():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	w.write('x' * (rv.LOG_LINE_LIMIT + 5))
	assert fake.writes == ['x' * (rv.LOG_LINE_LIMIT + 5) + '\n']
	w.write_held()
	assert fake.writes == ['x' * (rv.LOG_LINE_LIMIT + 5) + '\n']


def test_writelines_holds_parts_like_write():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	w.writelines(['a', 'b\n', 'c'])
	assert fake.writes == ['ab\n']
	w.write_held()
	assert fake.writes == ['ab\n', 'c\n']


def test_flush_does_not_write_a_held_part():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	w.write('part')
	before = fake.flushes
	w.flush()
	assert fake.writes == []
	assert fake.flushes > before


def test_attributes_come_from_the_wrapped_stream():
	stream = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
	w = rv.WholeLineStream(stream)
	assert w.encoding == 'utf-8'
	assert w.isatty() is False
	assert w.buffer is stream.buffer
	assert rv.WholeLineStream(sys.__stdout__).fileno() == sys.__stdout__.fileno()


def test_install_daemon_output_wraps_once(monkeypatch):
	stdout, stderr = io.StringIO(), io.StringIO()
	monkeypatch.setattr(sys, 'stdout', stdout)
	monkeypatch.setattr(sys, 'stderr', stderr)
	registered = []
	monkeypatch.setattr(atexit, 'register', lambda *args, **kwargs: registered.append(args))
	monkeypatch.setattr(threading, 'excepthook', threading.excepthook)
	rv.install_daemon_output()
	rv.install_daemon_output()
	assert isinstance(sys.stdout, rv.WholeLineStream) and sys.stdout.stream is stdout
	assert isinstance(sys.stderr, rv.WholeLineStream) and sys.stderr.stream is stderr
	assert len(registered) == 2


# marker threads log through the module's logger while library-style threads write their lines in pieces, as
# multiCMD's failed-start print does; stdout and stderr share one pipe, as in the journal
SCRIPT = f'''
import sys
import threading
import reverberator as rv
rv.install_daemon_output()
barrier = threading.Barrier({MARKER_THREADS + LIBRARY_THREADS})
def markers(t):
	barrier.wait()
	for i in range({LINES}):
		rv.job_log(f'job-{{t}}', f'FAILED: marker {{i}}')
def library(t):
	barrier.wait()
	for i in range({LINES}):
		sys.stderr.write('Error running command: ')
		sys.stderr.write(f'x{{t}}-{{i}}')
		sys.stderr.write('\\n')
		print(f'plain {{t}} {{i}}')
threads = [threading.Thread(target=markers, args=(t,)) for t in range({MARKER_THREADS})]
threads += [threading.Thread(target=library, args=(t,)) for t in range({LIBRARY_THREADS})]
for thread in threads:
	thread.start()
for thread in threads:
	thread.join()
'''


@pytest.mark.process
def test_split_prints_from_threads_never_put_a_marker_mid_line():
	child = subprocess.run([sys.executable, '-c', SCRIPT], env=dict(os.environ, PYTHONUNBUFFERED='1'), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT, timeout=60)
	out = child.stdout.decode('utf-8', 'replace')
	assert child.returncode == 0, out
	alerting = alerting_lines(out)
	assert len(alerting) == MARKER_THREADS * LINES
	alerting = set(alerting)
	errors = plains = 0
	for line in out.split('\n'):
		if not line or line in alerting:
			continue
		text = COLOUR.sub('', line)
		if re.match(r'^Error running command: x\d+-\d+$', text):
			errors += 1
		elif re.match(r'^plain \d+ \d+$', text):
			plains += 1
		else:
			pytest.fail(f'mixed line: {line!r}')
	assert errors == plains == LIBRARY_THREADS * LINES
