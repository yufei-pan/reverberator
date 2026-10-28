import os
import re
import threading
import time
from collections import OrderedDict
import pytest
import reverberator as rv
import signal
from tests.harness import seed_monitor, wait_until, committed_versions, create_job, rule_row, write_rule, wait_for_committed_count
from tests.test_log_text import alerting_lines

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
	order = []
	def broken():
		order.append('daemon')
		raise OSError(5, 'Input/output error')
	monkeypatch.setattr(rv, 'run_daemon', broken)
	# the real one would wrap pytest's capture streams for the rest of the session
	monkeypatch.setattr(rv, 'install_daemon_output', lambda: order.append('install'))
	with pytest.raises(SystemExit) as exc:
		rv.main()
	assert exc.value.code == 1
	assert order == ['install', 'daemon']
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


def _run_watcher_until(control, path, seconds, monkeypatch):
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.watcher, args=(flag, path, rv.ChangeEventQueue(path), threading.Lock(), threading.Event(),
		rv.inotify_resource_manager(), 0, 60), kwargs=dict(job=control), daemon=True)
	thread.start()
	time.sleep(seconds)
	control.fail('test done')
	thread.join(timeout=2)
	assert not thread.is_alive()


def test_the_watcher_and_the_backuper_alert_once_for_the_startup_wait(tmp_path, poll_fast, monkeypatch, capsys):
	# the backuper waits for the same monitored filesystem at startup: only one of the two waits alerts
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)
	control = rv.JobControl('j')
	control.start_attempt()
	path = str(tmp_path / 'missing')
	flag = threading.Event()
	flag.set()
	backuper_wait = threading.Thread(target=rv.wait_for_path, args=(control, flag, path, 'monitored filesystem not ready'),
		daemon=True)
	backuper_wait.start()
	_run_watcher_until(control, path, 0.6, monkeypatch)
	backuper_wait.join(timeout=2)
	assert not backuper_wait.is_alive()
	out = capsys.readouterr()
	assert (out.out + out.err).count('reverberator job j FAILED: waiting') == 1


def test_watcher_alerts_while_waiting_for_a_lost_root(tmp_path, poll_fast, monkeypatch, capsys):
	# a watcher alone waiting for its lost root is the oldest wait for it, so it alerts itself
	monkeypatch.setattr(rv, 'DISK_WAIT_GRACE_SECONDS', 0.1)
	root = tmp_path / 'root'
	root.mkdir()
	def lose_root(**kwargs):
		root.rmdir()
		return rv.WATCH_RESULT_SELF_DESTRUCT
	monkeypatch.setattr(rv, 'watchFolder', lose_root)
	control = rv.JobControl('j')
	control.start_attempt()
	_run_watcher_until(control, str(root), 0.6, monkeypatch)
	out = capsys.readouterr()
	assert f'reverberator job j FAILED: waiting 0 min for {root}: monitored filesystem not ready' in out.out + out.err


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


def test_fs_monitor_rechecks_failed_pairs_through_mount_churn(tmp_path, monkeypatch, poll_fast):
	# docker starting containers changes the mount table every few seconds, which must not keep putting the re-check off
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 0.3)
	calls = []
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: calls.append(path) or False)
	mountinfo = tmp_path / 'mountinfo'
	mountinfo.write_text('22 1 8:1 / / rw - ext4 /dev/sda1 rw\n')
	monitor = rv.fs_signature_monitor(mountinfo_path=str(mountinfo))
	monitor.register(str(tmp_path), 'UUID-X')
	thread = monitor.thread
	stop = threading.Event()
	def churn():
		while not stop.is_set():
			monitor.wake()
			time.sleep(0.02)
	churner = threading.Thread(target=churn, daemon=True)
	churner.start()
	try:
		time.sleep(1.2)
	finally:
		stop.set()
		churner.join(timeout=1)
		rv.GREEN_LIGHT.clear()
		monitor.wake()
		thread.join(timeout=2)
		rv.GREEN_LIGHT.set()
	# the first check, then about every 0.3 s
	assert len(calls) >= 3


def test_fs_monitor_invalidate_clears_the_flag_and_rechecks(tmp_path, monkeypatch, poll_fast):
	state = {'ok': True}
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: state['ok'])
	monitor = rv.fs_signature_monitor()
	key = (str(tmp_path), 'UUID-X')
	flag = monitor.register(*key)
	wait_until(flag.is_set, timeout=3, message='first check')
	state['ok'] = False
	monitor.invalidate(*key)
	assert not flag.is_set() and monitor.states[key] is False
	wait_until(lambda: key in monitor.fingerprints, timeout=3, message='rechecked')
	time.sleep(0.3)
	assert not flag.is_set()


def test_fs_monitor_invalidate_sets_the_flag_again_when_the_check_passes(tmp_path, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'check_fs_signature', lambda path, signature: True)
	monitor = rv.fs_signature_monitor()
	key = (str(tmp_path), 'UUID-X')
	flag = monitor.register(*key)
	wait_until(flag.is_set, timeout=3, message='first check')
	monitor.invalidate(*key)
	assert not flag.is_set()
	wait_until(flag.is_set, timeout=3, message='set again')


@pytest.mark.parametrize('check_result', [False, True])
def test_monitor_gate_registers_the_resolved_signature_before_the_job_starts(tmp_path, monkeypatch, poll_fast, check_result):
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 0.1)
	path = str(tmp_path / 'late')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda p: ['UUID-A'] if os.path.isdir(p) else [])
	monkeypatch.setattr(rv, 'check_fs_signature', lambda p, signature: check_result if signature == 'UUID-A' else True)
	started = []
	monkeypatch.setattr(rv, 'watcher', lambda *a, **k: started.append(('watcher', a)))
	monkeypatch.setattr(rv, 'backuper', lambda *a, **k: started.append(('backuper', a)))
	ungated = rv.FS_SIGNATURE_MONITOR.register(path, 'auto')
	gate = rv.MonitorGate(path, ungated, 'auto')
	starter = rv.job_attempt_starter('j', ('j', path), (ungated, path), ('j', None, None, path, 'v', 'N/A', None, ungated), gate)
	control = rv.JobControl('j')
	control.start_attempt()
	result = []
	thread = threading.Thread(target=lambda: result.append(starter(control, 1)), daemon=True)
	thread.start()
	time.sleep(0.3)
	assert started == [] and thread.is_alive()
	os.makedirs(path)
	thread.join(timeout=5)
	assert not thread.is_alive()
	for t in result[0]:
		t.join(timeout=2)
	assert (path, 'UUID-A') in rv.FS_SIGNATURE_MONITOR.flags
	assert (path, 'auto') not in rv.FS_SIGNATURE_MONITOR.flags or not rv.FS_SIGNATURE_MONITOR.flags[(path, 'auto')]
	flag = dict(started)['backuper'][7]
	assert flag is gate.flag and flag is not ungated
	if check_result:
		wait_until(flag.is_set, timeout=3, message='gated flag set')
	else:
		time.sleep(0.4)
		assert not flag.is_set()
	rv.FS_SIGNATURE_MONITOR.unregister(path, 'UUID-A', flag)


def test_monitor_gate_looks_up_an_unknown_signature_once_per_recheck(tmp_path, monkeypatch, poll_fast):
	# each lookup runs df and lsblk: a gate that cannot tell the signature yet must not spin on them
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 0.4)
	calls = []
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda p: calls.append(p) or [])
	gate = rv.MonitorGate(str(tmp_path), threading.Event(), 'auto')
	control = rv.JobControl('j')
	control.start_attempt()
	result = []
	thread = threading.Thread(target=lambda: result.append(gate.resolve(control)), daemon=True)
	thread.start()
	time.sleep(1.0)
	control.fail('stop')
	thread.join(timeout=1)
	assert not thread.is_alive() and result == [False]
	# at 0, 0.4 and 0.8 s
	assert 2 <= len(calls) <= 4


def test_monitor_gate_looks_up_a_path_as_soon_as_it_appears(tmp_path, monkeypatch, poll_fast):
	monkeypatch.setattr(rv, 'FS_RECHECK_SECONDS', 60)
	path = str(tmp_path / 'late')
	monkeypatch.setattr(rv, 'get_fs_signatures', lambda p: ['UUID-A'] if os.path.isdir(p) else [])
	gate = rv.MonitorGate(path, threading.Event(), 'auto')
	control = rv.JobControl('j')
	control.start_attempt()
	result = []
	thread = threading.Thread(target=lambda: result.append(gate.resolve(control)), daemon=True)
	thread.start()
	time.sleep(0.3)
	os.makedirs(path)
	thread.join(timeout=2)
	try:
		assert result == [True] and gate.signature == 'UUID-A'
	finally:
		control.fail('stop')
		thread.join(timeout=1)
		rv.FS_SIGNATURE_MONITOR.unregister(path, gate.signature, gate.flag)


def test_invalidate_during_a_running_check_keeps_the_flag_clear(tmp_path, monkeypatch):
	monitor = rv.fs_signature_monitor(mountinfo_path=str(tmp_path / 'mountinfo'))
	key = (str(tmp_path), 'UUID-X')
	flag = threading.Event()
	monitor.flags[key] = [flag]
	def stale_check(path, signature):
		monitor.invalidate(path, signature)
		return True
	monkeypatch.setattr(rv, 'check_fs_signature', stale_check)
	monitor.check_changed()
	assert not flag.is_set() and monitor.states.get(key) is not True


def test_watcher_invalidates_its_signature_on_self_destruct_for_an_ordinary_job(tmp_path, monkeypatch, poll_fast):
	path = str(tmp_path)
	calls = []
	monkeypatch.setattr(rv.FS_SIGNATURE_MONITOR, 'invalidate', lambda p, s: calls.append((p, s)))
	results = iter([rv.WATCH_RESULT_SELF_DESTRUCT, rv.WATCH_RESULT_INIT_FAILED])
	monkeypatch.setattr(rv, 'watchFolder', lambda *a, **k: next(results))
	flag = threading.Event()
	flag.set()
	started = []
	monkeypatch.setattr(rv, 'backuper', lambda *a, **k: a[-2].loaded.set())
	real_watcher = rv.watcher
	monkeypatch.setattr(rv, 'watcher', lambda *a, **k: started.append(real_watcher(*a, **k)))
	starter = rv.job_attempt_starter('j', ('j', path), (flag, path, None, None, None, None, 1, 1), ('j', None, None, path, 'v', 'N/A', None, flag), None, 'UUID-RULE')
	control = rv.JobControl('j')
	control.start_attempt()
	for t in starter(control, 1):
		t.join(timeout=5)
	assert calls == [(path, 'UUID-RULE')]


def test_job_attempt_starter_passes_the_backuper_keywords(monkeypatch):
	got = []
	monkeypatch.setattr(rv, 'watcher', lambda *a, **k: None)
	monkeypatch.setattr(rv, 'backuper', lambda *a, **k: got.append(k))
	starter = rv.job_attempt_starter('j', ('j', '/m'), (None, '/m'), ('j', None, None, '/m', 'v', 'N/A', None, None), None, None,
		dict(full_comparison_interval=3600.0, chain_length=20))
	control = rv.JobControl('j')
	control.start_attempt()
	for thread in starter(control, 1):
		thread.join(timeout=5)
	assert got == [dict(full_comparison_interval=3600.0, chain_length=20)]


def test_interrupted_full_comparison_is_requeued(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	def interrupted(*args, **kwargs):
		rv.GREEN_LIGHT.clear()
		return None, None, False
	monkeypatch.setattr(rv, 'do_backup', interrupted)
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, False, 'full_scan', job.monitor, None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	thread, queue = _run_backuper(job, control, to_process=queue)
	thread.join(timeout=5)
	rv.GREEN_LIGHT.set()
	pending = os.path.join(job.job_vault, rv.PENDING_TRANSACTIONS_FILE_NAME)
	assert 'full_scan' in open(pending).read()


def test_untrusted_fingerprint_forces_a_comparison(job):
	startup = rv.JobStartup(job.job_name, job.monitor)
	assert startup.load('', trusted=False) is True and startup.change == 'changed'
	refused = rv.JobStartup(job.job_name, job.monitor)
	assert refused.load('recorded', trusted=False) is False


def test_ignored_and_unknown_watch_events_log_quietly(monkeypatch, poll_fast):
	flags = rv.inotify_simple.flags
	class FakeEvent:
		def __init__(self, wd, mask, name=''):
			self.wd, self.mask, self.cookie, self.name = wd, mask, 0, name
	class FakeINotify:
		reads = 0
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def read(self, timeout=None):
			FakeINotify.reads += 1
			if FakeINotify.reads == 1:
				return [FakeEvent(7, flags.IGNORED), FakeEvent(99, flags.MODIFY, 'x')]
			rv.GREEN_LIGHT.clear()
			return []
		def add_watch(self, path, mask):
			return 42
		def rm_watch(self, wd):
			pass
	logged = []
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', lambda *args, **kwargs: 42)
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda path, message, error=False, ok=False: logged.append(message))
	rv.watchFolder('/monitor', rv.ChangeEventQueue('/monitor'), threading.Lock(), threading.Event(), rv.inotify_resource_manager())
	rv.GREEN_LIGHT.set()
	assert not any('Event name not found' in message for message in logged)
	unknown = [message for message in logged if 'not found' in message]
	assert unknown and '{' not in unknown[0]


def test_removing_many_watches_raises_the_queue_limit_first():
	class FakeIrm:
		max_queued_events = 10
		def __init__(self):
			self.raised = []
		def increaseInotifyMaxQueueEvents(self, max_events):
			self.raised.append(max_events)
			self.max_queued_events = max_events
			return True
		def decreaseUserWatches(self, count=1):
			pass
	class FakeINotify:
		def rm_watch(self, wd):
			pass
	wd_dic = rv.bidict({i: f'/m/d/{i}/' for i in range(30)})
	wd_dic[100] = '/m/d'
	irm = FakeIrm()
	assert rv.remove_watches_under(FakeINotify(), wd_dic, irm, '/m/d') == 31
	assert irm.raised and irm.raised[0] >= 62


def _fake_inotify_with(events_first, monkeypatch):
	flags = rv.inotify_simple.flags
	class FakeINotify:
		reads = 0
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def read(self, timeout=None):
			FakeINotify.reads += 1
			if FakeINotify.reads == 1:
				return events_first
			rv.GREEN_LIGHT.clear()
			return []
		def add_watch(self, path, mask):
			return 42
		def rm_watch(self, wd):
			pass
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', lambda *args, **kwargs: 42)
	return flags


def test_delete_self_for_an_unmapped_watch_does_not_decrement(monkeypatch, poll_fast):
	class FakeEvent:
		def __init__(self, wd, mask):
			self.wd, self.mask, self.cookie, self.name = wd, mask, 0, ''
	flags = rv.inotify_simple.flags
	_fake_inotify_with([FakeEvent(77, flags.DELETE_SELF)], monkeypatch)
	irm = rv.inotify_resource_manager()
	decreased = []
	monkeypatch.setattr(irm, 'decreaseUserWatches', lambda count=1: decreased.append(count))
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda *args, **kwargs: None)
	rv.watchFolder('/monitor', rv.ChangeEventQueue('/monitor'), threading.Lock(), threading.Event(), irm)
	rv.GREEN_LIGHT.set()
	# the watcher releases its own count (0 here) on exit; a DELETE_SELF decrement would be 1
	assert 1 not in decreased


def test_file_bind_mount_is_not_an_inner_mount(tmp_path):
	monitor = tmp_path / 'm'
	monitor.mkdir()
	(monitor / 'file.cfg').write_text('x')
	(monitor / 'dir').mkdir()
	table = [('/', ('1',)), (str(monitor / 'file.cfg'), ('2',)), (str(monitor / 'dir'), ('3',))]
	assert rv.watched_inner_mounts(table, str(monitor)) == {str(monitor / 'dir'): ('3',)}
	inner = {}
	queue = rv.ChangeEventQueue(str(monitor))
	class FakeINotify:
		def rm_watch(self, wd):
			pass
		def add_watch(self, path, mask):
			return 1
	rv.follow_inner_mounts(FakeINotify(), str(monitor), table[:2], inner, rv.bidict(), rv.inotify_resource_manager(), 0, queue, threading.Lock())
	assert inner == {} and len(queue) == 0


def test_run_job_counts_an_exception_from_start_attempt_as_a_failure(monkeypatch, poll_fast, capsys):
	monkeypatch.setattr(rv, 'JOB_RETRY_FIRST_SECONDS', 0.01)
	def permanent(job, attempt):
		raise rv.JobFailure('bad', permanent=True)
	assert rv.run_job(rv.JobControl('j'), permanent) == 'stopped'
	out = capsys.readouterr()
	assert 'reverberator job j STOPPED: bad' in out.out + out.err
	calls = []
	def retryable(job, attempt):
		calls.append(attempt)
		if attempt == 2:
			raise rv.JobFailure('done', permanent=True)
		raise RuntimeError('boom')
	assert rv.run_job(rv.JobControl('j'), retryable) == 'stopped'
	out = capsys.readouterr()
	assert 'reverberator job j FAILED: ' in out.out + out.err and 'boom' in out.out + out.err and calls == [1, 2]


def test_supervise_job_records_a_crash_and_stops_the_others(monkeypatch):
	def crashing(*args, **kwargs):
		raise RuntimeError('supervisor bug')
	monkeypatch.setattr(rv, 'run_job', crashing)
	results = [None]
	try:
		rv.supervise_job(results, 0, rv.JobControl('j'), None, None)
		assert results == ['crashed'] and not rv.GREEN_LIGHT.is_set()
	finally:
		rv.GREEN_LIGHT.set()


def _firewatcher_matches(message, identifier='python[8776]'):
	# as firewatcher reads a .regex file: one pattern a line, searched for in each line journalctl prints
	path = os.path.join(os.path.dirname(rv.__file__), 'firewatcher', 'reverberator.regex')
	patterns = [re.compile(line.strip()) for line in open(path) if line.strip()]
	return any(pattern.search(f'Oct 18 12:00:00 ksxx {identifier}: {message}') for pattern in patterns)


# Tee_Logger colors an error line before 6.42 and on a terminal, and names its level otherwise
@pytest.mark.parametrize('prefix, suffix', [('', ''), ('\x1b[93m', '\x1b[0m'), ('[ERROR] ', '')])
@pytest.mark.parametrize('identifier', ['python[8776]', 'reverberator[3875501]'])
def test_firewatcher_patterns_match_every_alerting_marker_and_not_recovered(prefix, suffix, identifier):
	alerting = [
		rv.job_log('j', 'FAILED: disk gone; retrying in 60s'),
		rv.job_log('my_job-2', 'FAILED: waiting 15 min for /mnt/x: vault filesystem not ready'),
		rv.job_log('j', 'UNREADABLE: /m/a: [Errno 5] Input/output error; keeping its last backed-up copy'),
		rv.job_log('j', 'STOPPED: bad pattern'),
		rv.daemon_error_log('every job is stopped'),
	]
	for line in alerting:
		assert _firewatcher_matches(prefix + line + suffix, identifier), line
	assert not _firewatcher_matches(prefix + rv.job_log('j', 'RECOVERED after 2 failed attempts') + suffix, identifier)


@pytest.mark.parametrize('prefix', ['', '\x1b[0m', '[INFO] ', '\x1b[93m', '[ERROR] '])
def test_firewatcher_patterns_ignore_markers_in_file_names(prefix):
	# a monitored file named like a marker shows up inside other lines, and must not raise an alert
	for message in [
		'📥| /m | Not copying /m/reverberator job x STOPPED: y: it no longer exists; keeping its last backed-up copy',
		'📥| /m | Not tracking a]: reverberator job x FAILED: y: source no longer exists',
		'👀| /m | Failed to add watch for /m/a]: [ERROR] reverberator EXITING with error: z: Permission denied',
		'reverberator job x RECOVERED after 2 failed attempts: reverberator job x FAILED: y',
	]:
		assert not _firewatcher_matches(prefix + message), message


@pytest.mark.parametrize('debug', [False, True])
def test_unmount_of_an_already_removed_watch_logs_only_in_debug(monkeypatch, poll_fast, debug):
	# follow_inner_mounts removed the unmounted disk's watches before their IN_UNMOUNT events were read: one per folder
	flags = rv.inotify_simple.flags
	class FakeEvent:
		def __init__(self, wd, mask, name=''):
			self.wd, self.mask, self.cookie, self.name = wd, mask, 0, name
	class FakeINotify:
		reads = 0
		def __enter__(self):
			return self
		def __exit__(self, *args):
			return False
		def read(self, timeout=None):
			FakeINotify.reads += 1
			if FakeINotify.reads == 1:
				return [FakeEvent(wd, flags.UNMOUNT) for wd in (55, 56, 57)]
			rv.GREEN_LIGHT.clear()
			return []
		def add_watch(self, path, mask):
			return 42
		def rm_watch(self, wd):
			pass
	logged = []
	monkeypatch.setattr(rv, 'DEBUG', debug)
	monkeypatch.setattr(rv.inotify_simple, 'INotify', FakeINotify)
	monkeypatch.setattr(rv, 'initializeFolderWatchers', lambda *args, **kwargs: 42)
	monkeypatch.setattr(rv, 'watcherTeeLogToTl', lambda path, message, error=False, ok=False: logged.append(message))
	rv.watchFolder('/monitor', rv.ChangeEventQueue('/monitor'), threading.Lock(), threading.Event(), rv.inotify_resource_manager())
	rv.GREEN_LIGHT.set()
	assert len([message for message in logged if 'unmount event' in message]) == (3 if debug else 0)


@pytest.mark.process
@pytest.mark.parametrize('raw', ['!!!', '\u65e5\u672c\u8a9e', '...', '???'])
def test_a_job_whose_name_cleans_to_nothing_is_stopped(job, tmp_path, run_reverberator, raw):
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	# the vault root holds a half made version of the nameless job's: it must be left alone
	stray = os.path.join(job.vault, 'V1_stray.incomplete')
	os.makedirs(stray)
	nameless = rule_row(job)
	nameless[0] = raw
	write_rule(other, extra_rows=[nameless])
	before = set(os.listdir(job.vault))
	proc = run_reverberator(other.rule_path)
	wait_for_committed_count(other, 1, timeout=15)
	assert proc.poll() is None
	output = ''.join(proc._out_buf + proc._err_buf)
	# the marker calls the job by its row (the second), which the firewatcher patterns accept, and shows the name as written
	assert any(f"reverberator job row-2 STOPPED: its name '{raw}' has no letters, digits, '-' or '_' left after cleanup; rename it in "
		+ other.rule_path in line for line in output.splitlines())
	assert len([line for line in alerting_lines(output) if 'STOPPED' in line]) == 1
	# nameless jobs share the cleaned name '', so none of them has a status file
	assert not os.path.exists(os.path.join(str(tmp_path / 'state'), 'job-.json'))
	assert set(os.listdir(job.vault)) == before and os.path.isdir(stray)
	assert any(line.startswith(raw + '\t') for line in open(other.rule_path).read().splitlines())
	proc.send_signal(signal.SIGTERM)


@pytest.mark.process
def test_the_only_job_having_no_name_exits_3(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	write_rule(job)
	text = open(job.rule_path).read().replace('job\t', '!!!\t', 1)
	open(job.rule_path, 'w').write(text)
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == 3
	assert os.listdir(job.vault) == []


def test_find_job_ignores_nameless_rules():
	blank = rv.NamelessJobName('!!!')
	rules = [rv.ReverbRule(blank, '/m', *['']*10), rv.ReverbRule('sub', '/m/sub', *['']*10)]
	assert rv.find_job(rules, '/m/sub/x')[0].job_name == 'sub'
	with pytest.raises(rv.CommandError):
		rv.find_job(rules, '/m/other')
	with pytest.raises(rv.CommandError):
		rv.find_job(rules, 'x', job_name='')


def test_each_nameless_row_quotes_its_own_name():
	empty = rv.ReverbRule(*[''] * len(rv.REVERB_RULE_HEADER))
	rules = [empty._replace(job_name=rv.NamelessJobName('!!!')), empty._replace(job_name=rv.NamelessJobName('???'))]
	# both starters are made before either runs, as run_daemon does while the supervisor threads are still starting
	starts = [rv.nameless_start('/rules.tsv', rule) for rule in rules]
	jobs = [rv.JobControl('', 'row-1'), rv.JobControl('', 'row-2')]
	assert [start(job, 1) for start, job in zip(starts, jobs)] == [[], []]
	assert "'!!!'" in jobs[0].failure.reason and "'???'" not in jobs[0].failure.reason
	assert "'???'" in jobs[1].failure.reason and "'!!!'" not in jobs[1].failure.reason
	assert jobs[0].failure.permanent and jobs[1].failure.permanent


def test_status_shows_a_nameless_job_as_stopped(tmp_path):
	rules = [rv.ReverbRule(rv.NamelessJobName('!!!'), '/m', str(tmp_path), *['']*9)]
	status = rv.DaemonStatus(None, False, {})
	text = rv.format_status(status, rules, '/r/rules.tsv')
	assert "!!!  stopped: its name has no letters, digits, '-' or '_' left after cleanup; rename it in /r/rules.tsv" in text
