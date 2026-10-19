import os
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until, committed_versions

pytestmark = pytest.mark.unit


def _run_backuper(paths, job, startup=None, to_process=None):
	to_process = rv.ChangeEventQueue(paths.monitor) if to_process is None else to_process
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(paths.job_name, to_process, threading.Lock(), paths.monitor,
		paths.vault, 'N/A', threading.Event(), flag), kwargs=dict(startup=startup, job=job), daemon=True)
	thread.start()
	return thread, to_process


def test_job_control_first_failure_wins():
	job = rv.JobControl('j')
	job.start_attempt()
	assert job.should_run()
	job.fail('disk gone')
	job.fail('second', permanent=True)
	assert not job.should_run() and job.failure.reason == 'disk gone' and not job.failure.permanent
	job.start_attempt()
	assert job.should_run() and job.failure is None


def test_marker_helpers_exact_text(capsys):
	assert rv.job_log('j', 'STOPPED: bad pattern') == 'reverberator job j STOPPED: bad pattern'
	assert rv.daemon_error_log('every job is stopped') == 'reverberator EXITING with error: every job is stopped'


def test_backuper_failure_stops_only_its_job_and_keeps_events(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	def broken(*args, **kwargs):
		raise OSError(5, 'Input/output error')
	monkeypatch.setattr(rv, 'do_backup', broken)
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	thread, queue = _run_backuper(job, control, to_process=queue)
	thread.join(timeout=5)
	assert not thread.is_alive() and rv.GREEN_LIGHT.is_set()
	assert 'Input/output error' in control.failure.reason and not control.failure.permanent
	assert len(queue) == 1
	assert not os.path.exists(os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME))


def test_watcher_failure_stops_only_its_job(job, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'watchFolder', lambda *a, **k: rv.WATCH_RESULT_INIT_FAILED)
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	assert rv.watcher(flag, job.monitor, rv.ChangeEventQueue(job.monitor), threading.Lock(), threading.Event(),
		rv.inotify_resource_manager(), job=control) is False
	assert rv.GREEN_LIGHT.is_set() and control.failure is not None


def test_startup_failures_classified(job):
	missing = rv.JobStartup(job.job_name, job.monitor, os.path.join(job.root, 'missing'))
	assert missing.load(None) is False and missing.permanent is False
	bad = os.path.join(job.root, 'bad')
	open(bad, 'w').write('[z-a]\n')
	bad_startup = rv.JobStartup(job.job_name, job.monitor, bad)
	assert bad_startup.load(None) is False and bad_startup.permanent is True
	refused = rv.JobStartup(job.job_name, job.monitor)
	assert refused.load('recorded') is False and refused.permanent is True


def test_backuper_reports_permanent_startup_failure(job, poll_fast):
	bad = os.path.join(job.root, 'bad')
	open(bad, 'w').write('[z-a]\n')
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread, _ = _run_backuper(job, control, startup=rv.JobStartup(job.job_name, job.monitor, bad))
	thread.join(timeout=5)
	assert control.failure.permanent and rv.GREEN_LIGHT.is_set()


def test_backuper_marks_committed_and_stops_with_its_job(job, poll_fast):
	seed_monitor(job, {'a.txt': 'a'})
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread, _ = _run_backuper(job, control)
	assert control.committed.wait(10)
	control.fail('watcher failed')
	thread.join(timeout=5)
	assert not thread.is_alive() and rv.GREEN_LIGHT.is_set() and len(committed_versions(job)) == 1


def test_watch_folder_stops_with_its_job(monkeypatch, poll_fast):
	class FakeINotify:
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def read(self, timeout=None):
			time.sleep(timeout / 1000)
			return []
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', lambda *a, **k: 42)
	control = rv.JobControl('j')
	control.start_attempt()
	result = []
	thread = threading.Thread(target=lambda: result.append(rv.watchFolder('/monitor', rv.ChangeEventQueue('/monitor'),
		threading.Lock(), threading.Event(), rv.inotify_resource_manager(), job=control)), daemon=True)
	thread.start()
	control.fail('backuper failed')
	thread.join(timeout=2)
	assert not thread.is_alive() and result == [rv.WATCH_RESULT_OK] and rv.GREEN_LIGHT.is_set()


def _attempts(script):
	'''start_attempt that runs one scripted outcome per attempt: ('fail', reason, permanent) or ('commit_then_fail', reason).'''
	calls = []
	def start_attempt(job, attempt):
		outcome = script[min(attempt - 1, len(script) - 1)]
		calls.append(attempt)
		def body():
			if outcome[0] == 'commit_then_fail':
				job.mark_committed()
			job.fail(outcome[1], permanent=outcome[2] if len(outcome) > 2 else False)
		thread = threading.Thread(target=body, name=f'{job.job_name} backuper', daemon=True)
		thread.start()
		return [thread]
	return start_attempt, calls


def test_run_job_retries_with_backoff_then_stops(monkeypatch, poll_fast, capsys):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	start_attempt, calls = _attempts([('fail', 'disk gone'), ('fail', 'disk gone'), ('fail', 'bad pattern', True)])
	assert rv.run_job(rv.JobControl('j'), start_attempt) == 'stopped'
	assert calls == [1, 2, 3]
	out = capsys.readouterr()
	text = out.out + out.err
	assert text.count('reverberator job j FAILED: disk gone; retrying in') == 2
	assert 'reverberator job j STOPPED: bad pattern' in text


def test_run_job_logs_recovered(monkeypatch, poll_fast, capsys):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	start_attempt, _ = _attempts([('fail', 'disk gone'), ('commit_then_fail', 'x', True)])
	rv.run_job(rv.JobControl('j'), start_attempt)
	out = capsys.readouterr()
	assert 'reverberator job j RECOVERED after 1 failed attempts' in out.out + out.err


def test_run_job_backoff_resets_only_after_a_clean_hour(monkeypatch, poll_fast):
	now = [0.0]
	delays = []
	monkeypatch.setattr(rv, 'job_retry_delay', lambda failures: delays.append(failures) or 0.0)
	durations = iter([10, 10, 3600, 10, 0])
	def start_attempt(job, attempt):
		now[0] += next(durations)
		if attempt == 5:
			job.fail('done', permanent=True)
		else:
			job.fail('flap')
		return []
	rv.run_job(rv.JobControl('j'), start_attempt, clock=lambda: now[0])
	assert delays == [1, 2, 1, 2]


def test_run_job_delay_is_interruptible(monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 3600)
	started = threading.Event()
	def start_attempt(job, attempt):
		job.fail('disk gone')
		started.set()
		return []
	result = []
	thread = threading.Thread(target=lambda: result.append(rv.run_job(rv.JobControl('j'), start_attempt)), daemon=True)
	thread.start()
	assert started.wait(2)
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=2)
	rv.GREEN_LIGHT.set()
	assert result == ['exit']


def test_run_job_counts_a_thread_that_ends_on_its_own_as_a_failure(monkeypatch, poll_fast, capsys):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	def start_attempt(job, attempt):
		if attempt == 2:
			job.fail('done', permanent=True)
			return []
		thread = threading.Thread(target=lambda: None, name='j watcher', daemon=True)
		thread.start()
		return [thread]
	assert rv.run_job(rv.JobControl('j'), start_attempt) == 'stopped'
	out = capsys.readouterr()
	assert 'reverberator job j FAILED: j watcher exited unexpectedly; retrying in' in out.out + out.err


def test_run_job_starts_an_attempt_only_after_the_last_one_ended(monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	threads = []
	alive_at_start = []
	def start_attempt(job, attempt):
		alive_at_start.append([thread.is_alive() for thread in threads])
		if attempt == 3:
			job.fail('done', permanent=True)
			return []
		def lingering():
			# fails the job, then takes a while to wind down, like a backuper finishing its copies
			job.fail('disk gone')
			time.sleep(0.3)
		thread = threading.Thread(target=lingering, name='j backuper', daemon=True)
		threads.append(thread)
		thread.start()
		return [thread]
	assert rv.run_job(rv.JobControl('j'), start_attempt) == 'stopped'
	assert alive_at_start == [[], [False], [False, False]]


def _run_job_in_thread(control, start_attempt, persist_pending):
	result = []
	thread = threading.Thread(target=lambda: result.append(rv.run_job(control, start_attempt, persist_pending=persist_pending)), daemon=True)
	thread.start()
	return thread, result


def test_run_job_saves_the_queue_when_stopped_in_its_retry_delay(job, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 3600)
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	a = os.path.join(job.monitor, 'a.txt')
	queue.append(rv.ChangeEvent(1.0, False, 'modify', a, None))
	failed = threading.Event()
	def start_attempt(control, attempt):
		control.fail('disk gone')
		failed.set()
		return []
	thread, result = _run_job_in_thread(rv.JobControl(job.job_name), start_attempt,
		lambda: rv.persist_failed_job_queue(job.job_name, job.monitor, job.vault, queue, lock))
	assert failed.wait(2)
	pending = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	assert not os.path.exists(pending)
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=5)
	rv.GREEN_LIGHT.set()
	assert result == ['exit']
	text = open(pending).read()
	# the job was not watched while it waited: the next start compares the whole tree, which covers the queued change
	assert '\x00full_scan\x00' in text


def test_run_job_leaves_a_healthy_stop_to_the_backuper(poll_fast):
	saved = []
	control = rv.JobControl('j')
	def start_attempt(job, attempt):
		def idle():
			while job.should_run():
				time.sleep(0.01)
		thread = threading.Thread(target=idle, name='j backuper', daemon=True)
		thread.start()
		return [thread]
	thread, result = _run_job_in_thread(control, start_attempt, lambda: saved.append(True))
	wait_until(control.running.is_set, timeout=2)
	rv.GREEN_LIGHT.clear()
	thread.join(timeout=5)
	rv.GREEN_LIGHT.set()
	# its backuper saved a complete queue, as the job was watched until the stop
	assert result == ['exit'] and saved == []


def test_apply_job_timing_from_env(monkeypatch):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', rv.JOB_RETRY_FIRST_SECONDS)
	monkeypatch.setattr(rv, 'JOB_RETRY_MAX_SECONDS', rv.JOB_RETRY_MAX_SECONDS)
	monkeypatch.setenv('REVERB_JOB_RETRY_FIRST_SECONDS', '0.5')
	monkeypatch.setenv('REVERB_JOB_RETRY_MAX_SECONDS', '2')
	rv.apply_job_timing_from_env()
	assert (rv.JOB_RETRY_FIRST_SECONDS, rv.JOB_RETRY_MAX_SECONDS) == (0.5, 2.0)
	assert [rv.job_retry_delay(n) for n in (1, 2, 3, 4)] == [0.5, 1.0, 2.0, 2.0]
	for invalid in ('soon', '0', '-1', 'inf', 'nan', ''):
		monkeypatch.setenv('REVERB_JOB_RETRY_FIRST_SECONDS', invalid)
		monkeypatch.delenv('REVERB_JOB_RETRY_MAX_SECONDS')
		rv.apply_job_timing_from_env()
		assert (rv.JOB_RETRY_FIRST_SECONDS, rv.JOB_RETRY_MAX_SECONDS) == (60, 3600), invalid
		monkeypatch.setenv('REVERB_JOB_RETRY_MAX_SECONDS', '2')


def test_job_retry_delay_survives_months_of_failures(monkeypatch):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.5)
	assert rv.job_retry_delay(5000) == rv.JOB_RETRY_MAX_SECONDS


@pytest.mark.parametrize('ending', ['job stops', 'root watch fails', 'read raises'])
def test_watch_folder_gives_back_its_inotify_counts(tmp_path, monkeypatch, poll_fast, ending):
	monitor = str(tmp_path / 'monitor')
	for rel in ('d1', 'd2/d3'):
		os.makedirs(os.path.join(monitor, rel))
	control = rv.JobControl('j')
	control.start_attempt()
	irm = rv.inotify_resource_manager()
	# other jobs' share of the counts
	irm.current_user_instances, irm.current_user_watches = 3, 10
	held = []
	class FakeINotify:
		wd = 0
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def add_watch(self, path, mask):
			if ending == 'root watch fails':
				raise OSError(28, 'No space left on device')
			FakeINotify.wd += 1
			return FakeINotify.wd
		def rm_watch(self, wd):
			pass
		def read(self, timeout=None):
			held.append((irm.current_user_instances, irm.current_user_watches))
			if ending == 'read raises':
				raise OSError(5, 'Input/output error')
			control.fail('backuper failed')
			return []
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	try:
		result = rv.watchFolder(monitor, rv.ChangeEventQueue(monitor), threading.Lock(), threading.Event(), irm, job=control)
	except OSError:
		result = 'raised'
	assert result == {'job stops': rv.WATCH_RESULT_OK, 'root watch fails': rv.WATCH_RESULT_INIT_FAILED, 'read raises': 'raised'}[ending]
	if ending != 'root watch fails':
		# the root and its three folders were counted while watched
		assert held[0] == (4, 14)
	assert (irm.current_user_instances, irm.current_user_watches) == (3, 10)


def test_do_backup_closes_a_manifest_it_opened_when_it_raises(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	opened = []
	class RecordedManifest(rv.VaultManifest):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)
			opened.append(self)
	monkeypatch.setattr(rv, 'VaultManifest', RecordedManifest)
	def broken(*args, **kwargs):
		raise OSError(5, 'Input/output error')
	monkeypatch.setattr(rv, 'get_vault_info', broken)
	def backup(manifest=None):
		return rv.do_backup(OrderedDict(), job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault,
			keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0', manifest=manifest)
	with pytest.raises(OSError):
		backup()
	assert len(opened) == 1 and opened[0].conn is None
	# one the caller passed in stays the caller's to close
	given = rv.VaultManifest(job.job_vault)
	with pytest.raises(OSError):
		backup(given)
	assert given.conn is not None
	given.close()


def test_main_exits_1_with_a_marker_when_the_daemon_fails(monkeypatch, capsys):
	def broken():
		raise OSError(5, 'Input/output error')
	monkeypatch.setattr(rv, 'run_daemon', broken)
	with pytest.raises(SystemExit) as exc:
		rv.main()
	assert exc.value.code == 1
	out = capsys.readouterr()
	assert 'reverberator EXITING with error: OSError: [Errno 5] Input/output error' in out.out + out.err


def test_wait_for_path_alerts_after_grace_then_hourly(tmp_path, poll_fast, monkeypatch, capsys):
	now = [0.0]
	flag = threading.Event()
	flag.set()
	path = str(tmp_path / 'later')
	control = rv.JobControl('j')
	control.start_attempt()
	steps = iter([0, 899, 901, 3000, 4502, 4600])
	def clock():
		value = next(steps, None)
		if value is None:
			os.makedirs(path, exist_ok=True)
			return now[0]
		now[0] = value
		return value
	assert rv.wait_for_path(control, flag, path, 'vault filesystem not ready', clock=clock) is True
	out = capsys.readouterr()
	lines = [l for l in (out.out + out.err).splitlines() if 'reverberator job j FAILED: waiting' in l]
	assert len(lines) == 2 and 'waiting 15 min for ' + path in lines[0]


def test_wait_for_path_stops_with_the_job(tmp_path, poll_fast):
	control = rv.JobControl('j')
	control.start_attempt()
	flag = threading.Event()
	threading.Timer(0.2, control.fail, args=('x',)).start()
	assert rv.wait_for_path(control, flag, str(tmp_path), 'x') is False


def test_fs_monitor_rechecks_failed_pairs_without_a_mount_change(tmp_path, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 0.1)
	state = {'ok': False}
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: state['ok'])
	monitor = rv.fs_signature_monitor()
	flag = monitor.register(str(tmp_path), 'UUID-X')
	wait_until(lambda: monitor.states.get((str(tmp_path), 'UUID-X')) is False, timeout=3, message='first check')
	state['ok'] = True
	wait_until(flag.is_set, timeout=3, message='not rechecked')
