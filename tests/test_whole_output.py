import atexit
import io
import os
import re
import subprocess
import sys
import threading
import time
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
	# the next line written puts the ended thread's part ahead of it, each a whole line
	w.write('main\n')
	assert ''.join(fake.writes) == 'left\nmain\n'
	assert all(text.endswith('\n') for text in fake.writes)
	recorded = list(fake.writes)
	w.write_held()
	assert fake.writes == recorded


def test_write_held_writes_the_parts_of_living_threads_too():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	written, done = threading.Event(), threading.Event()
	def hold():
		w.write('waiting')
		written.set()
		done.wait(5)
	thread = threading.Thread(target=hold)
	thread.start()
	written.wait(5)
	# a living thread's part stays held while other lines are written
	w.write('main\n')
	assert fake.writes == ['main\n']
	w.write_held()
	assert fake.writes == ['main\n', 'waiting\n']
	done.set()
	thread.join()


class Strict(Recorder):
	'''A recording stream that cannot encode a lone surrogate, as an ascii or strict utf-8 stream cannot.'''
	def write(self, text):
		text.encode('utf-8')
		return super().write(text)


def test_write_held_skips_only_a_part_the_stream_cannot_write():
	fake = Strict()
	w = rv.WholeLineStream(fake)
	threads = [threading.Thread(target=w.write, args=(text,)) for text in ('one', 'bad \udcff', 'two')]
	for thread in threads:
		thread.start()
		thread.join()
	flushes = fake.flushes
	w.write_held()
	assert fake.writes == ['one\n', 'two\n']
	assert fake.flushes > flushes


def test_a_part_longer_than_the_limit_is_written_as_its_own_line():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	w.write('x' * (rv.LOG_LINE_LIMIT + 5))
	assert fake.writes == ['x' * (rv.LOG_LINE_LIMIT + 5) + '\n']
	w.write_held()
	assert fake.writes == ['x' * (rv.LOG_LINE_LIMIT + 5) + '\n']


def test_a_part_grown_past_the_limit_by_small_writes_is_written_as_its_own_line():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	for _ in range(rv.LOG_LINE_LIMIT + 5):
		w.write('y')
	# cut once it is over the limit; the 4 written after the cut are a new part, held as any part is
	assert fake.writes == ['y' * (rv.LOG_LINE_LIMIT + 1) + '\n']
	w.write_held()
	assert fake.writes == ['y' * (rv.LOG_LINE_LIMIT + 1) + '\n', 'y' * 4 + '\n']


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
	assert registered == [(sys.stdout.write_held,), (sys.stderr.write_held,)]


def test_a_command_run_from_main_keeps_the_plain_streams(monkeypatch):
	stdout, stderr = io.StringIO(), io.StringIO()
	monkeypatch.setattr(sys, 'stdout', stdout)
	monkeypatch.setattr(sys, 'stderr', stderr)
	monkeypatch.setattr(atexit, 'register', lambda *args, **kwargs: None)
	monkeypatch.setattr(threading, 'excepthook', threading.excepthook)
	monkeypatch.setitem(rv.COMMAND_FUNCTIONS, 'status', lambda args: 0)
	with pytest.raises(SystemExit) as exc:
		rv.main(['status'])
	assert exc.value.code == 0
	assert sys.stdout is stdout and sys.stderr is stderr


def test_a_part_written_by_a_reentrant_write_follows_the_part_held_before_it():
	# a signal handler or a finalizer writing on this thread while the stream writes this thread's line
	class Reentrant(Recorder):
		def write(self, text):
			first = not self.writes
			written = super().write(text)
			if first:
				w.write('D\nF')
			return written
	fake = Reentrant()
	w = rv.WholeLineStream(fake)
	w.write('A\nB')
	# the lines keep their order, and 'B', written before 'F', stays ahead of it
	assert fake.writes == ['A\n', 'D\n']
	w.write('E\n')
	assert fake.writes == ['A\n', 'D\n', 'BFE\n']


def test_the_rest_after_the_last_line_break_stays_held_when_the_stream_raises():
	class Failing(Recorder):
		failed = False
		def write(self, text):
			if not self.failed:
				self.failed = True
				raise OSError(28, 'No space left on device')
			return super().write(text)
	fake = Failing()
	w = rv.WholeLineStream(fake)
	with pytest.raises(OSError):
		w.write('lost\nkept')
	w.write_held()
	assert fake.writes == ['kept\n']


def test_a_write_under_a_lock_that_a_log_lock_holder_waits_for_does_not_hang(monkeypatch):
	# the order Tee_Logger can take them in: a log call holds LOG_LOCK and wants a handler lock, while a library
	# thread holds that handler lock and writes to stderr
	monkeypatch.setattr(rv, 'WHOLE_LINE_WAIT_SECONDS', 0.5)
	monkeypatch.setattr(rv, 'WHOLE_LINE_RETRY_SECONDS', 0.05)
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	other = threading.Lock()
	has_other, has_log_lock = threading.Event(), threading.Event()
	got = []
	def log_call():
		has_other.wait(5)
		with rv.LOG_LOCK:
			has_log_lock.set()
			# bounded, so that without the timeout the test fails instead of hanging; the library's 10 writes waiting
			# the full 0.5 s each would take longer than this too, while one wait and 9 retries take about 1 s
			if other.acquire(timeout=2.5):
				got.append(True)
				other.release()
	def library():
		with other:
			has_other.set()
			has_log_lock.wait(5)
			time.sleep(0.05)
			# in pieces, as a traceback is written
			for piece in ('Error running command: ', 'x', '\n') * 3 + ('end\n',):
				w.write(piece)
	threads = [threading.Thread(target=log_call, daemon=True), threading.Thread(target=library, daemon=True)]
	for thread in threads:
		thread.start()
	for thread in threads:
		thread.join(timeout=10)
	assert not any(thread.is_alive() for thread in threads)
	assert got == [True]
	assert fake.writes == ['Error running command: x\n'] * 3 + ['end\n']


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


def test_a_thread_that_gave_up_on_the_log_lock_gets_it_again_when_it_is_held_briefly(monkeypatch):
	monkeypatch.setattr(rv, 'WHOLE_LINE_WAIT_SECONDS', 0.05)
	monkeypatch.setattr(rv, 'WHOLE_LINE_RETRY_SECONDS', 0.1)
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	held, release = threading.Event(), threading.Event()
	def hold():
		with rv.LOG_LOCK:
			held.set()
			release.wait(5)
	holder = threading.Thread(target=hold)
	holder.start()
	held.wait(5)
	w.write('alone\n')
	release.set()
	holder.join()
	assert w._local.gave_up is True
	# another thread logging all the time, holding the lock 0.01 s at a time
	stop, busy = threading.Event(), threading.Event()
	def log_often():
		while not stop.is_set():
			with rv.LOG_LOCK:
				busy.set()
				time.sleep(0.01)
			time.sleep(0.001)
	logger = threading.Thread(target=log_often, daemon=True)
	logger.start()
	busy.wait(5)
	try:
		w.write('again\n')
		gave_up = w._local.gave_up
	finally:
		stop.set()
		logger.join(5)
	assert gave_up is False
	assert fake.writes == ['alone\n', 'again\n']
