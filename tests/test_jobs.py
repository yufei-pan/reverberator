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
