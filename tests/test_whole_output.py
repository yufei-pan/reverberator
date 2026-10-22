import atexit
import io
import os
import re
import signal
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


def test_a_part_longer_than_twice_the_limit_is_written_as_its_own_line():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	long = 2 * rv.LOG_LINE_LIMIT
	w.write('x' * long)
	assert fake.writes == []
	w.write('x' * 5)
	assert fake.writes == ['x' * (long + 5) + '\n']
	w.write_held()
	assert fake.writes == ['x' * (long + 5) + '\n']


def test_a_part_grown_past_twice_the_limit_by_small_writes_is_written_as_its_own_line():
	fake = Recorder()
	w = rv.WholeLineStream(fake)
	long = 2 * rv.LOG_LINE_LIMIT
	for _ in range(long + 5):
		w.write('y')
	# cut once it is over the cap; the 4 written after the cut are a new part, held as any part is
	assert fake.writes == ['y' * (long + 1) + '\n']
	w.write_held()
	assert fake.writes == ['y' * (long + 1) + '\n', 'y' * 4 + '\n']


def test_the_longest_line_the_logger_prints_is_written_as_one_record(monkeypatch):
	# a cut line plus the logger's level tag or colour codes is longer than LOG_LINE_LIMIT; print then writes the line
	# break on its own
	fake = Recorder()
	monkeypatch.setattr(sys, 'stdout', rv.WholeLineStream(fake))
	monkeypatch.setattr(sys, 'stderr', rv.WholeLineStream(fake))
	rv.job_log('j', 'FAILED: ' + 'p' * 20000)
	assert len(fake.writes) == 1
	assert fake.writes[0].endswith('\n') and fake.writes[0].count('\n') == 1
	assert fake.writes[0] != '\n'


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
	assert rv.WHOLE_LINE_LOCAL.gave_up is True
	# another thread logging all the time, holding the lock 0.01 s at a time
	stop, busy = threading.Event(), threading.Event()
	def log_often():
		while not stop.is_set():
			with rv.LOG_LOCK:
				busy.set()
				time.sleep(0.01)
			time.sleep(0.005)
	logger = threading.Thread(target=log_often, daemon=True)
	logger.start()
	busy.wait(5)
	try:
		w.write('again\n')
		gave_up = rv.WHOLE_LINE_LOCAL.gave_up
	finally:
		stop.set()
		logger.join(5)
	assert gave_up is False
	assert fake.writes == ['alone\n', 'again\n']


def test_a_thread_that_gave_up_on_one_stream_retries_briefly_on_the_other(monkeypatch):
	monkeypatch.setattr(rv, 'WHOLE_LINE_WAIT_SECONDS', 0.5)
	monkeypatch.setattr(rv, 'WHOLE_LINE_RETRY_SECONDS', 0.02)
	out, err = Recorder(), Recorder()
	stdout, stderr = rv.WholeLineStream(out), rv.WholeLineStream(err)
	held, release = threading.Event(), threading.Event()
	def hold():
		with rv.LOG_LOCK:
			held.set()
			release.wait(5)
	took = []
	def write_both():
		stdout.write('one\n')
		start = time.monotonic()
		stderr.write('two\n')
		took.append(time.monotonic() - start)
	holder = threading.Thread(target=hold)
	holder.start()
	held.wait(5)
	writer = threading.Thread(target=write_both)
	writer.start()
	writer.join(timeout=10)
	release.set()
	holder.join(timeout=10)
	assert not writer.is_alive()
	assert out.writes == ['one\n'] and err.writes == ['two\n']
	# the stderr write waited the retry time, not the full wait
	assert took[0] < 0.3


def run_thread(target, name='worker'):
	thread = threading.Thread(target=target, name=name)
	thread.start()
	thread.join(timeout=10)
	assert not thread.is_alive()


def test_a_thread_traceback_is_logged_escaped(capsys, monkeypatch):
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def fail():
		raise ValueError('bad\nreverberator job x FAILED: forged\x1b[31m')
	run_thread(fail)
	captured = capsys.readouterr()
	out = captured.out + captured.err
	assert any('Uncaught exception in thread worker:' in line for line in out.split('\n'))
	assert alerting_lines(out) == []
	assert '\x1b[31m' not in out
	# Tee_Logger's colour codes are the logger's own, and sit where its version puts them
	stripped = COLOUR.sub('', out)
	assert '\x1b' not in stripped
	forged = [line for line in stripped.split('\n') if line.endswith('reverberator job x FAILED: forged\\x1b[31m')]
	assert len(forged) == 1 and forged[0].startswith('    ')


def test_systemexit_in_a_thread_is_silent(capsys, monkeypatch):
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def leave():
		raise SystemExit(3)
	run_thread(leave)
	captured = capsys.readouterr()
	assert captured.out + captured.err == ''


def test_a_failing_log_falls_back_to_the_log_file_and_stderr_with_escaped_text(monkeypatch):
	class BrokenLogger:
		def __init__(self):
			self.errors = []
		def teeerror(self, text):
			raise OSError('journal gone')
		def error(self, text):
			self.errors.append(text)
	logger = BrokenLogger()
	stderr = io.StringIO()
	seen = []
	monkeypatch.setattr(rv, 'tl', logger)
	monkeypatch.setattr(sys, 'stderr', stderr)
	monkeypatch.setattr(threading, '__excepthook__', lambda args: seen.append(args))
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def fail():
		raise ValueError('bad\nreverberator job x FAILED: forged')
	run_thread(fail)
	assert seen == []
	assert len(logger.errors) == 1
	text = logger.errors[0]
	assert 'Uncaught exception in thread worker:' in text
	assert alerting_lines(text) == []
	assert stderr.getvalue() == text + '\n'


def test_a_failing_log_and_a_failing_log_file_still_write_to_stderr(monkeypatch):
	class BrokenLogger:
		def teeerror(self, text):
			raise OSError('journal gone')
		def error(self, text):
			raise OSError('disk gone')
	stderr = io.StringIO()
	seen = []
	monkeypatch.setattr(rv, 'tl', BrokenLogger())
	monkeypatch.setattr(sys, 'stderr', stderr)
	monkeypatch.setattr(threading, '__excepthook__', lambda args: seen.append(args))
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def fail():
		raise ValueError('lost otherwise')
	run_thread(fail)
	assert seen == []
	assert 'ValueError: lost otherwise' in stderr.getvalue()


def test_pythons_hook_is_used_only_when_the_text_cannot_be_built(monkeypatch):
	class Logger:
		def teeerror(self, text):
			raise AssertionError('nothing may be logged')
		error = teeerror
	def broken(text):
		raise RuntimeError('cannot escape')
	seen = []
	monkeypatch.setattr(rv, 'tl', Logger())
	monkeypatch.setattr(rv, 'log_text', broken)
	monkeypatch.setattr(threading, '__excepthook__', lambda args: seen.append(args))
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def fail():
		raise ValueError('lost otherwise')
	run_thread(fail)
	assert len(seen) == 1
	assert seen[0].exc_type is ValueError and str(seen[0].exc_value) == 'lost otherwise'


def test_a_dying_threads_unfinished_text_is_written_as_its_own_line_before_the_traceback(monkeypatch):
	fake = Recorder()
	monkeypatch.setattr(sys, 'stdout', rv.WholeLineStream(fake))
	monkeypatch.setattr(sys, 'stderr', rv.WholeLineStream(fake))
	monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)
	def fail():
		sys.stdout.write('copying a.txt ... ')
		raise ValueError('boom')
	run_thread(fail)
	assert fake.writes[0] == 'copying a.txt ... \n'
	assert len(fake.writes) > 1
	assert not fake.writes[1].startswith('copying')
	assert 'Uncaught exception in thread worker:' in COLOUR.sub('', fake.writes[1])


def test_install_daemon_output_sets_the_thread_hook(monkeypatch):
	monkeypatch.setattr(sys, 'stdout', io.StringIO())
	monkeypatch.setattr(sys, 'stderr', io.StringIO())
	monkeypatch.setattr(atexit, 'register', lambda *args, **kwargs: None)
	monkeypatch.setattr(threading, 'excepthook', threading.excepthook)
	rv.install_daemon_output()
	assert threading.excepthook is rv.log_thread_exception


class SysctlTask:
	'''What multiCMD.run_command returns with return_object=True: lists of output lines and a return code.'''
	def __init__(self, stdout=(), stderr=(), returncode=0):
		self.stdout = list(stdout)
		self.stderr = list(stderr)
		self.returncode = returncode


def test_sysctl_runs_quiet_in_verbose_mode(monkeypatch):
	quiet = []
	def run_command(*args, **kwargs):
		quiet.append(kwargs.get('quiet'))
		return SysctlTask(['fs.inotify.max_user_watches = 5'])
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	monkeypatch.setattr(rv, 'DEBUG', True)
	manager = rv.inotify_resource_manager()
	assert manager.debug is True
	assert manager.getSysctlValues('fs.inotify.max_user_watches') == 5
	assert len(quiet) >= 5
	assert all(q is True for q in quiet)


class RecordingLogger:
	'''A tl that keeps what each level was given.'''
	def __init__(self):
		self.lines = []
	def __getattr__(self, name):
		return lambda text, *args, **kwargs: self.lines.append((name, text))


def test_set_sysctl_values_runs_quiet_and_uses_the_return_code(monkeypatch):
	calls = []
	def run_command(command, **kwargs):
		calls.append((command, kwargs))
		if command[0] == 'sudo':
			return SysctlTask(returncode=1 if command[-1].endswith('=7') else 0)
		return SysctlTask(['fs.inotify.max_user_watches = 5'])
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	monkeypatch.setattr(rv, 'tl', RecordingLogger())
	manager = rv.inotify_resource_manager()
	assert manager.setSysctlValues('fs.inotify.max_user_watches', 6, 'max_user_watches') is True
	assert manager.max_user_watches == 6
	assert manager.setSysctlValues('fs.inotify.max_user_instances', 7, 'max_user_instances') is False
	assert manager.can_set_max_user_instances is False
	sudo = [kwargs for command, kwargs in calls if command[0] == 'sudo']
	assert len(sudo) == 2 and all(kwargs.get('quiet') is True for kwargs in sudo)


def test_verbose_sysctl_logs_the_error_text_of_sysctl_and_sudo(monkeypatch):
	def run_command(command, **kwargs):
		if command[0] == 'sudo':
			return SysctlTask(stderr=['sudo: a password is required'], returncode=1)
		return SysctlTask(['fs.inotify.max_user_watches = 5'], ['sysctl: permission denied on key'])
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	logger = RecordingLogger()
	monkeypatch.setattr(rv, 'tl', logger)
	monkeypatch.setattr(rv, 'DEBUG', True)
	manager = rv.inotify_resource_manager()
	assert manager.getSysctlValues('fs.inotify.max_user_watches') == 5
	shown = [text for name, text in logger.lines if name == 'teeprint']
	assert any('permission denied on key' in text and 'max_user_watches = 5' in text for text in shown)
	assert manager.setSysctlValues('fs.inotify.max_user_watches', 6, 'max_user_watches') is False
	shown = [text for name, text in logger.lines if name == 'teeprint']
	assert any('a password is required' in text for text in shown)


def test_non_verbose_sysctl_logs_no_error_text(monkeypatch):
	def run_command(command, **kwargs):
		return SysctlTask(['fs.inotify.max_user_watches = 5'], ['sysctl: noise'], 1 if command[0] == 'sudo' else 0)
	monkeypatch.setattr(rv.multiCMD, 'run_command', run_command)
	logger = RecordingLogger()
	monkeypatch.setattr(rv, 'tl', logger)
	monkeypatch.setattr(rv, 'DEBUG', False)
	manager = rv.inotify_resource_manager()
	manager.getSysctlValues('fs.inotify.max_user_watches')
	manager.setSysctlValues('fs.inotify.max_user_watches', 6, 'max_user_watches')
	assert not any('noise' in text for name, text in logger.lines)
	assert not any(name == 'teeprint' for name, text in logger.lines)


def test_the_first_signal_starts_the_shutdown_before_it_logs(monkeypatch):
	seen = []
	class Logger:
		def teeerror(self, text):
			seen.append(rv.GREEN_LIGHT.is_set())
	monkeypatch.setattr(rv, 'tl', Logger())
	was_set = rv.GREEN_LIGHT.is_set()
	rv.GREEN_LIGHT.set()
	try:
		rv.signal_handler(signal.SIGTERM, None)
		assert seen == [False]
		assert not rv.GREEN_LIGHT.is_set()
	finally:
		if was_set:
			rv.GREEN_LIGHT.set()
		else:
			rv.GREEN_LIGHT.clear()
