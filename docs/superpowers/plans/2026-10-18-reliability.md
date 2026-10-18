# Reliability Round Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep every healthy job backing up whatever one job meets, retry failed jobs with a growing delay, never turn a failed read or an unmounted inner disk into deletions, size versions without walking them, and emit fixed log lines firewatcher can alert on.

**Architecture:** A per-job `JobControl` replaces "clear `GREEN_LIGHT` on failure": the watcher and backuper report a `JobFailure` to it and exit, and a per-job supervisor (`run_job`) restarts the job with backoff, logs the marker lines, and tells `main` whether the job stopped for good. Deep backup code keeps checking only `GREEN_LIGHT`, so a job failure lets an in-progress backup finish. A retry always compares the whole tree (nothing watched during the delay). Inner mounts come from the existing mount-table monitor through a subscription; remounts are compared with a subtree-scoped delta. Read errors are collected by the walker; copies land under a temporary name and are renamed into place only on success.

**Tech Stack:** Python (single module `reverberator.py`), inotify_simple, multiCMD `AsyncExecutor` (tasks expose `returncode` / `stderr`), sqlite manifest, pytest via `uv run --extra test python -m pytest`.

**Spec:** `docs/superpowers/specs/2026-10-18-reliability-design.md`

## Global Constraints

- Log marker lines, exact text, at error level (`tl.teeerror`), produced only through the helpers in Task 1:
  `reverberator job <name> FAILED: <reason>; retrying in <N>s` · `reverberator job <name> FAILED: waiting <N> min for <path>: <reason>` · `reverberator job <name> UNREADABLE: <path>: <error>; keeping its last backed-up copy` · `reverberator job <name> STOPPED: <reason>` · `reverberator job <name> RECOVERED after <N> failed attempts` · `reverberator EXITING with error: <reason>`.
- Retry delay 60 s, doubling, capped at 3600 s; resets after an attempt ran 3600 s before failing.
- Disk-wait alert after 900 s, then every 3600 s while the wait lasts.
- Exit codes: 3 when every job is STOPPED; 1 when the main thread fails; 0 on a signal.
- Config-only failures are permanent (STOPPED, never retried): a skip list that lost its patterns without `none`, a skip pattern that will not parse or decode, two rows whose names clean up to one job name. Everything else is retried.
- A failed read never becomes a deletion; a failed copy into the vault never commits a version.
- No task writes outside the repo. Anything under `/etc` and any `systemctl` command is done by the controller, after the user confirms, in Task 11.
- Keep the crash-safety rules: content file last, manifest commits with the version, pending transactions written when the daemon stops.
- Every wait stays interruptible by `GREEN_LIGHT`.
- Run pytest as `uv run --extra test python -m pytest` (the venv's `pytest` launcher has a stale shebang). Fast loop: `uv run --extra test python -m pytest -m "not inotify and not process and not privileged"`. Privileged tests use the existing `privileged` marker and skip without root.
- `uv.lock` is gitignored: never `git add` it.
- Code style follows `reverberator.py`: tabs, existing naming mix, doctests on small pure helpers. Commit messages: one plain sentence in the repo's style, with a `Co-Authored-By:` trailer naming the committing model.
- Version becomes `0.38` (Task 11).

## Review Focus

- Ctrl-C while a job sits in its retry delay must stop the daemon within a poll interval and exit 0. Test: Task 2, `test_run_job_delay_is_interruptible`.
- A job that fails every few minutes must keep doubling its delay; only an hour of clean running resets it. Test: Task 2, `test_run_job_backoff_resets_only_after_a_clean_hour`.
- An unreadable folder with thousands of entries logs one UNREADABLE line per backup, not one per entry. Test: Task 6, `test_unreadable_folder_keeps_entries_and_logs_once`.
- An inner disk unmounted while reverberator was stopped stays paused at the next start. Test: Task 9, `test_paused_mount_survives_restart`.
- A copy into the vault that fails mid-backup leaves no committed version, and the next attempt cleans up the partial folder. Test: Task 7, `test_failed_vault_copy_commits_nothing_and_next_attempt_cleans_up`.

## File map

| File | Change |
|---|---|
| `reverberator.py` | everything below |
| `reverberator.service` (repo) | `RestartPreventExitStatus=3` |
| `firewatcher/reverberator.txt` (new) | pattern file |
| `README.md` | markers, exit codes, firewatcher, inner mounts |
| `pyproject.toml` | version 0.38 |
| `tests/test_jobs.py` (new) | Tasks 1, 2, 3 (unit) |
| `tests/test_io_errors.py` (new) | Tasks 6, 7 (unit) |
| `tests/test_inner_mounts.py` (new) | Tasks 8, 9 (unit + privileged) |
| `tests/test_version_usage.py` (new) | Task 5 |
| `tests/test_parse_rules.py`, `tests/test_helpers_cli.py`, `tests/test_backup.py`, `tests/test_skip_list_watch.py`, `tests/test_crash_safety.py`, `tests/test_process.py` | additions / one changed test noted in Task 3 |

---

### Task 1: `JobControl`, `JobFailure`, marker helpers; threads report failures instead of stopping everything

**Files:**
- Modify: `reverberator.py` — new code after `JobStartup` (`:478`); `JobStartup.load`; `watcher` (`:1245`); `backuper` (`:2028`)
- Create: `tests/test_jobs.py`

**Interfaces:**
- Produces:
  - `class JobFailure(Exception)`: `__init__(self, reason:str, permanent:bool = False)`; attributes `reason`, `permanent`.
  - `class JobControl`: `__init__(self, job_name:str)`; attributes `job_name`, `running` (`threading.Event`), `failure` (`JobFailure` or `None`), `committed` (`threading.Event`, set after the attempt's first committed backup); methods `start_attempt(self)` (clears `failure` and `committed`, sets `running`), `fail(self, reason:str, permanent:bool = False)` (first failure of an attempt wins; clears `running`; logs nothing), `should_run(self) -> bool` (`GREEN_LIGHT.is_set() and self.running.is_set()`), `mark_committed(self)`.
  - `job_log(job_name:str, text:str) -> str` — logs and returns `f'reverberator job {job_name} {text}'` via `tl.teeerror`; `daemon_error_log(reason:str) -> str` — logs and returns `f'reverberator EXITING with error: {reason}'`.
  - `JobStartup.permanent` (bool): `True` when `load` failed for a config-only reason (`ValueError` from the list, or the `'refuse'` verdict); `False` for `OSError` and unexpected errors.
  - `watcher(..., startup:JobStartup = None, job:JobControl = None)` and `backuper(..., startup:JobStartup = None, job:JobControl = None)`: with `job` given, every place that clears `GREEN_LIGHT` today calls `job.fail(reason)` instead and returns; their own loops and waits use `job.should_run()`; a failed startup calls `job.fail(..., permanent=startup.permanent)`; the backuper catches `JobFailure` (`job.fail(e.reason, e.permanent)`) and any other `Exception` (`job.fail(<exception summary>)`); "Backuper Stopped!" (vault path cannot be created) becomes `job.fail`; an uncommitted backup becomes `job.fail('backup did not commit')`; after each committed backup the backuper calls `job.mark_committed()`; on any failure after it took a batch, the batch goes back to the front of the queue first (`to_process.prepend(backup_entries_to_change_events(backupEntries))`, or a `full_scan` event when the batch was a full comparison); `persist_pending_transactions` runs only when `job is None or not GREEN_LIGHT.is_set()` (on a job failure the queue stays in memory). With `job=None` behaviour is unchanged (existing tests rely on it).

- [ ] **Step 1: Write the failing tests** in `tests/test_jobs.py` (`pytestmark = pytest.mark.unit`)

```python
import os
import threading
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until

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
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_jobs.py -q`
Expected: FAIL with `AttributeError: module 'reverberator' has no attribute 'JobControl'`

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the new and the existing thread tests**

Run: `uv run --extra test python -m pytest tests/test_jobs.py tests/test_crash_safety.py tests/test_job_startup.py -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Report job failures to a per-job control instead of stopping every job."

---

### Task 2: Supervisor, backoff, exit codes, unit file

**Files:**
- Modify: `reverberator.py` — constants beside `MOVE_PAIR_TIMEOUT_SECONDS`; new `job_retry_delay`, `apply_job_timing_from_env`, `run_job`; `main` (`:623-722`); module `__main__` block
- Modify: `reverberator.service` (repo copy only)
- Modify: `tests/test_jobs.py`, `tests/test_process.py`

**Interfaces:**
- Consumes: `JobControl`, `JobFailure`, `job_log`, `daemon_error_log`, `watcher(..., job=)`, `backuper(..., job=)` (Task 1)
- Produces:
  - `JOB_RETRY_FIRST_SECONDS = 60`, `JOB_RETRY_MAX_SECONDS = 3600`, `JOB_RETRY_RESET_SECONDS = 3600`, `EXIT_ALL_STOPPED = 3`.
  - `apply_job_timing_from_env()` — reads `REVERB_JOB_RETRY_FIRST_SECONDS` and `REVERB_JOB_RETRY_MAX_SECONDS` (floats; invalid or missing keep the defaults), called at import and at the start of `main`, like `apply_poll_wait_from_env`.
  - `job_retry_delay(failures:int) -> float` — `min(JOB_RETRY_FIRST_SECONDS * 2 ** (failures - 1), JOB_RETRY_MAX_SECONDS)` for `failures >= 1`; doctest `[job_retry_delay(n) for n in (1, 2, 3, 7, 8)] == [60, 120, 240, 3600, 3600]`.
  - `run_job(job:JobControl, start_attempt, clock = time.monotonic) -> str` — loop: `job.start_attempt()`; `threads = start_attempt(job, attempt)`; wait (in `POLL_WAIT_SECONDS` steps) until a thread ends or `job.failure` is set or `GREEN_LIGHT` clears; a thread that ended with no `job.failure` counts as `job.fail('<thread name> exited unexpectedly')`; then `job.running.clear()` and join every thread. If `GREEN_LIGHT` is clear → return `'exit'`. If the failure is permanent → `job_log(name, f'STOPPED: {reason}')`, return `'stopped'`. Else `failures = 1` if the attempt ran `>= JOB_RETRY_RESET_SECONDS` else `failures + 1`; `delay = job_retry_delay(failures)`; `job_log(name, f'FAILED: {reason}; retrying in {int(delay)}s')`; wait `delay` interruptibly (return `'exit'` if `GREEN_LIGHT` clears). While an attempt runs after `failures > 0`, the first time `job.committed` is set log `job_log(name, f'RECOVERED after {failures} failed attempts')`.
  - `main`: per rule, build the job's fixed parts once (queue, lock, flag, `FS_SIGNATURE_MONITOR.register` of the monitor path) and a `start_attempt(job, attempt)` closure that creates a fresh `JobStartup` and starts `watcher(..., startup, job)` and `backuper(..., startup, job)` named `'<job> watcher'` / `'<job> backuper'`; one supervisor thread per job running `run_job`. After joining the supervisors: if `GREEN_LIGHT` was cleared by a signal → return (exit 0); if every result is `'stopped'` → `daemon_error_log('every job is stopped')`, `sys.exit(EXIT_ALL_STOPPED)`. Any exception escaping `main`'s body → `daemon_error_log(<summary>)`, `sys.exit(1)` (wrap the body; `main` stays the console entry point).
  - Repo `reverberator.service`: add `RestartPreventExitStatus=3` under `[Service]` with a one-line comment.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_jobs.py`)

```python
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
```

(`test_run_job_backoff_resets_only_after_a_clean_hour` drives the clock through `start_attempt`: `run_job` reads `clock()` right before calling `start_attempt` and again after the attempt's threads are joined; the third attempt "runs" an hour, so the fourth failure starts over at 1.)

Append to `tests/test_process.py` (import `create_job`, `rule_row`):

```python
def test_failing_job_retries_and_others_keep_running(job, tmp_path, run_reverberator, process_env):
	process_env['REVERB_JOB_RETRY_FIRST_SECONDS'] = '0.5'
	process_env['REVERB_JOB_RETRY_MAX_SECONDS'] = '1'
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	blocker = os.path.join(job.root, 'blocker')
	open(blocker, 'w').write('x')
	broken = rule_row(job)
	broken[2] = os.path.join(blocker, 'vault')   # a vault path under a regular file cannot be created
	write_rule(other, extra_rows=[broken])
	proc = run_reverberator(other.rule_path)
	wait_for_committed_count(other, 1, timeout=10)
	wait_until(lambda: 'reverberator job job FAILED' in ''.join(proc._out_buf + proc._err_buf), timeout=10, message='no FAILED line')
	os.remove(blocker)
	os.makedirs(os.path.join(blocker, 'vault'))
	wait_until(lambda: 'reverberator job job RECOVERED' in ''.join(proc._out_buf + proc._err_buf), timeout=15, message='no RECOVERED line')
	assert proc.poll() is None


def test_every_job_stopped_exits_3(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	open(os.path.join(job.root, 'skip.txt'), 'w').write('[z-a]\n')
	write_rule(job, skip_list_file='skip.txt')
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == 3
	text = ''.join(proc._out_buf + proc._err_buf)
	assert 'reverberator job job STOPPED' in text and 'reverberator EXITING with error' in text


def test_sigterm_exits_0(job, run_reverberator):
	seed_monitor(job, {'a.txt': 'a'})
	write_rule(job)
	proc = run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1, timeout=10)
	proc.send_signal(signal.SIGTERM)
	assert proc.wait(timeout=10) == 0
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_jobs.py tests/test_process.py -q`
Expected: the new tests FAIL (`AttributeError: ... 'run_job'`; process tests see no FAILED line / exit code 0)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** `reverberator.py reverberator.service tests/test_jobs.py tests/test_process.py` — "Supervise each job, retry failed jobs with a growing delay, and exit 3 when every job is stopped."

---

### Task 3: Disk waits with a grace-period alert; missing monitored paths wait

**Files:**
- Modify: `reverberator.py` — constants; new `wait_for_path`; `fs_signature_monitor.run` (`:~1990`); waits in `watcher` and `backuper`; the self-destruct branch of `watcher`; `parse_rules` monitored-path check (`:~960`)
- Modify: `tests/test_jobs.py`, `tests/test_parse_rules.py` (one existing test changes), `tests/test_process.py`

**Interfaces:**
- Consumes: `JobControl`, `job_log` (Task 1)
- Produces:
  - `DISK_WAIT_GRACE_SECONDS = 900`, `DISK_WAIT_REPEAT_SECONDS = 3600`, `FS_RECHECK_SECONDS = 60`; `apply_job_timing_from_env` also reads `REVERB_DISK_WAIT_GRACE_SECONDS`.
  - `wait_for_path(job:JobControl, flag:threading.Event, path:str, what:str, clock = time.monotonic) -> bool` — returns `True` once `flag.is_set() and os.path.isdir(path)`; `False` when `job` (or, with `job=None`, `GREEN_LIGHT`) says stop. Calls `clock()` once on entry and once per poll iteration (each iteration waits `POLL_WAIT_SECONDS` on `flag`). Logs nothing before `DISK_WAIT_GRACE_SECONDS`; then `job_log(name, f'FAILED: waiting {int(waited // 60)} min for {path}: {what}')` once, and again every `DISK_WAIT_REPEAT_SECONDS`. `what` is e.g. `'monitored filesystem not ready'` / `'vault filesystem not ready'`.
  - Every `while ... not <fs flag>.is_set(): wait` loop in `watcher` and `backuper` becomes `wait_for_path(...)`; the watcher's self-destruct branch no longer clears `monitor_fs_flag` itself (the monitor clears it on an unmount; `wait_for_path` covers a deleted root).
  - `fs_signature_monitor.run`: in addition to mount-table wake-ups, re-check every pair whose last state is `False` at most every `FS_RECHECK_SECONDS` (a deleted and re-created path changes no mount).
  - `parse_rules`: a monitored path that does not exist keeps the rule (warning: "will wait for it"), skips its `realpath` normalisation and its fs-signature auto-fill.

- [ ] **Step 1: Write the failing tests**

`tests/test_jobs.py`:

```python
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
```

`tests/test_parse_rules.py`: replace `test_parse_rules_missing_monitor_ignored` with

```python
def test_parse_rules_missing_monitor_is_kept_to_wait_for(job):
	write_rule(job)
	missing = os.path.join(job.root, 'not-mounted-yet')
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, missing)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	rules = rv.parse_rules(job.rule_path)
	assert [rule.mon_path for rule in rules] == [missing]
```

`tests/test_process.py`:

```python
def test_job_waits_for_a_monitored_path_that_appears_later(job, run_reverberator):
	missing = os.path.join(job.root, 'late')
	write_rule(job)
	text = open(job.rule_path, encoding='utf-8').read().replace(job.monitor, missing)
	open(job.rule_path, 'w', encoding='utf-8').write(text)
	proc = run_reverberator(job.rule_path)
	time.sleep(1)
	assert committed_versions(job) == [] and proc.poll() is None
	os.makedirs(missing)
	open(os.path.join(missing, 'a.txt'), 'w').write('a')
	wait_for_committed_count(job, 1, timeout=15)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_jobs.py tests/test_parse_rules.py tests/test_process.py -q`
Expected: the new tests FAIL (`AttributeError: ... 'wait_for_path'`; the rule is dropped)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Wait for missing disks and paths with an alert after a grace period, and keep rules whose monitored path is not there yet."

---

### Task 4: Rule write-back in place, colliding job names, `get_args` fallback, atomic `current_version`

**Files:**
- Modify: `reverberator.py` — `parse_rules` write-back (`:~1052`); new `rewrite_rule_rows`; `main` (collision check); `get_args` fallback (`:~811`); `do_backup` `current_version` swap (`:~2589`)
- Modify: `tests/test_parse_rules.py`, `tests/test_helpers_cli.py`, `tests/test_backup.py`, `tests/test_process.py`

**Interfaces:**
- Consumes: `JobControl` / `run_job` (Task 2) — a colliding job gets a supervisor that stops at once
- Produces:
  - `rewrite_rule_rows(rule_file:str, rows:dict) -> None` — `rows` maps the job-name cell as written in the file to its new full row (list of cells); for each key, the last line whose first cell (stripped) equals it is replaced by the new row and earlier lines with that key are removed (they were already ignored by TSVZ); every other line is kept byte for byte, line endings kept; written through a temp file + fsync + `os.replace` on the real path, keeping mode and owner (same care as `upgrade_rule_file_header`). `parse_rules` calls it instead of `TSVZ.appendLinesTabularFile`, keyed by the original (pre-`slugify`) name, and never writes back a row whose cleaned name collides with another row's (renaming it would merge the two rows in the file).
  - `colliding_job_names(rules:list) -> dict` — `{job_name: count}` for names used by more than one rule; doctest. `main` gives every rule in a collision a `start_attempt` that fails it at once with `JobFailure(f'{count} rows clean up to the job name {name}', permanent=True)`, so each is STOPPED and counts toward exit 3.
  - `get_args`: the fallback calls `parser.parse_known_args(args)`.
  - `do_backup`: `current_version` is created under a temporary name in the job vault (`'.current_version.tmp'`) and moved over the old link with `os.replace`; nothing removes the old link first.

- [ ] **Step 1: Write the failing tests**

`tests/test_parse_rules.py`:

```python
def test_parse_rules_write_back_rewrites_the_row_in_place(job):
	write_rule(job, min_snapshot='auto')
	before = open(job.rule_path).read().splitlines()
	rv.parse_rules(job.rule_path)
	rv.parse_rules(job.rule_path)
	after = open(job.rule_path).read().splitlines()
	assert len(after) == len(before)
	assert after[1].split('\t')[4] == str(rv.DEFAULT_SNAPSHOT_DELAY)


def test_parse_rules_drops_old_appended_copies(job):
	write_rule(job)
	with open(job.rule_path, 'a') as f:
		f.write('\t'.join(rule_row(job, min_snapshot='auto')) + '\n')
	rv.parse_rules(job.rule_path)
	rows = [line for line in open(job.rule_path).read().splitlines() if line.startswith(job.job_name + '\t')]
	assert len(rows) == 1


def test_parse_rules_slugified_name_does_not_spawn_a_second_job(job):
	row = rule_row(job)
	row[0] = 'My Job'
	open(job.rule_path, 'w').write('\t'.join(rv.REVERB_RULE_TSV_HEADER) + '\n' + '\t'.join(row) + '\n')
	assert [rule.job_name for rule in rv.parse_rules(job.rule_path)] == ['my-job']
	assert [rule.job_name for rule in rv.parse_rules(job.rule_path)] == ['my-job']
	assert 'My Job' not in open(job.rule_path).read()
```

`tests/test_helpers_cli.py`:

```python
def test_get_args_fallback_reports_the_given_arguments(capsys):
	with pytest.raises(SystemExit) as exc:
		rv.get_args(['--no-such-flag', 'rule.tsv'])
	assert exc.value.code == 2
	assert '--no-such-flag' in capsys.readouterr().err
```

`tests/test_backup.py`:

```python
def test_current_version_is_swapped_atomically(job, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	rv.do_backup({}, job_name=job.job_name, monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True,
		only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')[1].close()
	link = os.path.join(job.job_vault, 'current_version')
	first = os.readlink(link)
	removed = []
	monkeypatch.setattr(rv.os, 'remove', lambda path, *a, **k: removed.append(path) if path == link else os.unlink(path))
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	rv.do_backup({os.path.join(job.monitor, 'b.txt'): rv.BackupEntryValues('t', 'create', None)}, job_name=job.job_name,
		monitor_path=job.monitor, vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0')[1].close()
	assert link not in removed and os.readlink(link) != first
	assert not os.path.lexists(os.path.join(job.job_vault, '.current_version.tmp'))
```

`tests/test_process.py`:

```python
def test_colliding_job_names_are_both_stopped(job, tmp_path, run_reverberator):
	other = create_job(str(tmp_path / 'other'), 'other')
	seed_monitor(job, {'a.txt': 'a'})
	seed_monitor(other, {'b.txt': 'b'})
	twin = rule_row(other)
	twin[0] = 'JOB'   # cleans up to 'job'
	write_rule(job, extra_rows=[twin])
	proc = run_reverberator(job.rule_path)
	assert proc.wait(timeout=15) == 3
	assert ''.join(proc._out_buf + proc._err_buf).count('reverberator job job STOPPED') == 2
	assert any(line.startswith('JOB\t') for line in open(job.rule_path).read().splitlines())
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_parse_rules.py tests/test_helpers_cli.py tests/test_backup.py tests/test_process.py -q`
Expected: the new tests FAIL

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Rewrite auto-filled rule rows in place, stop jobs whose names collide, and swap current_version atomically."

---

### Task 5: Size new versions without walking them

**Files:**
- Modify: `reverberator.py` — new `measure_version_usage`; `do_backup` (`:2574-2575`)
- Create: `tests/test_version_usage.py`

**Interfaces:**
- Produces: `measure_version_usage(manifest:VaultManifest, version_path:str) -> tuple` — `(bytes, inodes)`: `os.lstat(...).st_blocks * 512` summed over `version_path` itself and every row of `manifest` (paths joined onto `version_path`), read on a `ThreadPoolExecutor(max_workers=COMPARE_THREADS)` in `MANIFEST_BATCH_SIZE` batches; `inodes` = 1 + the number of rows found; a row whose entry is missing is skipped (debug log). `do_backup` uses it, after `record_dirty_entries`, in place of `get_path_size(backup_folder)` / `get_path_inodes(backup_folder)`. `get_vault_info(recalculate=True)` and `decrement_stepper` keep `du`.

- [ ] **Step 1: Write the failing tests** in `tests/test_version_usage.py` (`pytestmark = pytest.mark.unit`)

```python
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None, keep_one_complete_backup=True):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=keep_one_complete_backup, only_sync_attributes=True,
		keep_n_versions=0, backup_size_limit='0')


def _assert_matches_du(job, manifest, version):
	assert rv.measure_version_usage(manifest, version) == (rv.get_path_size(version), rv.get_path_inodes(version))


@pytest.mark.parametrize('complete', [True, False])
def test_v0_usage_matches_du(job, poll_fast, complete):
	seed_monitor(job, {'a.txt': 'a' * 10000, 'd/e/f.bin': 'x' * 300000, 'empty/': None})
	os.symlink('a.txt', os.path.join(job.monitor, 'short'))
	os.symlink('d/' + 'n' * 200, os.path.join(job.monitor, 'long'))
	_, manifest, _ = _backup(job, keep_one_complete_backup=complete)
	_assert_matches_du(job, manifest, committed_versions(job)[0])
	manifest.close()


def test_replay_version_usage_matches_du(job, poll_fast):
	seed_monitor(job, {'keep.txt': 'k', 'old.txt': 'o' * 5000, 'sub/x.txt': 'x', 'deep/a/b/c.txt': 'c'})
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'old.txt'))
	open(os.path.join(job.monitor, 'new.bin'), 'w').write('n' * 70000)
	os.rename(os.path.join(job.monitor, 'sub'), os.path.join(job.monitor, 'moved'))
	entries = OrderedDict()
	entries[os.path.join(job.monitor, 'old.txt')] = rv.BackupEntryValues('t', 'delete', None)
	entries[os.path.join(job.monitor, 'new.bin')] = rv.BackupEntryValues('t', 'create', None)
	entries[os.path.join(job.monitor, 'moved') + '/'] = rv.BackupEntryValues('t', 'move', os.path.join(job.monitor, 'sub') + '/')
	_, manifest, _ = _backup(job, entries)
	_assert_matches_du(job, manifest, committed_versions(job)[1])
	manifest.close()


def test_backup_no_longer_runs_du_on_the_new_version(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	measured = []
	original = rv.get_path_size
	monkeypatch.setattr(rv, 'get_path_size', lambda *paths: measured.extend(paths) or original(*paths))
	_backup(job)[1].close()
	assert not any(os.path.basename(path).startswith('V0--') for path in measured)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_version_usage.py -q`
Expected: FAIL with `AttributeError: ... 'measure_version_usage'`

- [ ] **Step 3: Implement** `measure_version_usage` and use it in `do_backup`.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Size new versions from the entries the backup tracks instead of walking them twice with du."

---

### Task 6: Read errors in the monitored tree never become deletions

**Files:**
- Modify: `reverberator.py` — `iter_tree_entries` (`:~1690`); `VaultManifest` (new `mark_seen_under`); `delta_generate_backup_entries`; `do_backup` first-backup walks; `do_reverb_backup.copy_path`; `get_all_folders` / `initializeFolderWatchers`; `get_monitor_path_most_recent_change_time`
- Create: `tests/test_io_errors.py`

**Interfaces:**
- Consumes: `JobFailure`, `job_log` (Task 1)
- Produces:
  - `iter_tree_entries(path, rel_prefix='', list_folders_first=False, skip=None, errors:list = None)` — when `os.scandir` of a folder fails, appends `(rel_prefix_of_that_folder, error)` to `errors` (the walk root reports `rel_prefix` as given, `''` for the monitored root) and still logs as today.
  - `VaultManifest.mark_seen_under(self, folder:str)` — marks every tracked row strictly under `folder` (ends with `/`) seen (one `INSERT OR IGNORE ... SELECT` with the `folder_range_end` range).
  - `delta_generate_backup_entries(..., skip_list=None, job_name:str = '')` — collects walk errors; an error at the walk root raises `JobFailure(f'cannot read {monitor_path}: {error}')` before the deleted-entries pass (no deletions, the manifest transaction rolls back via the caller); each unreadable folder is `mark_seen_under` and logged once per call with `job_log(job_name, f'UNREADABLE: {abs_path}: {error}; keeping its last backed-up copy')`. `do_backup` passes `job_name`.
  - `do_backup` first-backup walks (complete copy, referenced rebuild): a root error raises `JobFailure`; a subfolder error logs UNREADABLE (nothing older to keep). `copy_path`'s recursive walk: subfolder errors log UNREADABLE.
  - Watch setup (`get_all_folders`): an unreadable subfolder gets no watch and logs UNREADABLE once (watcher job name from `JobControl.job_name`, or the monitored path without a job).
  - `get_monitor_path_most_recent_change_time`: any read error returns `float('inf')`, so a resume is refused and the tree is compared.

- [ ] **Step 1: Write the failing tests** in `tests/test_io_errors.py` (`pytestmark = pytest.mark.unit`)

```python
import errno
import os
from collections import OrderedDict
import pytest
import reverberator as rv
from tests.harness import seed_monitor, write_tree, committed_versions

pytestmark = pytest.mark.unit


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fail_scandir(monkeypatch, failing_path, err):
	original = os.scandir
	def scandir(path='.'):
		if os.path.abspath(path).rstrip('/') == os.path.abspath(failing_path).rstrip('/'):
			raise OSError(err, os.strerror(err), path)
		return original(path)
	monkeypatch.setattr(os, 'scandir', scandir)


def test_unreadable_folder_keeps_entries_and_logs_once(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', **{f'big/f{i}.txt': str(i) for i in range(500)}})
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'big'), errno.EIO)
	capsys.readouterr()
	_backup(job)[1].close()
	v1 = committed_versions(job)[1]
	assert len(os.listdir(os.path.join(v1, 'big'))) == 500
	out = capsys.readouterr()
	assert (out.out + out.err).count(f'reverberator job {job.job_name} UNREADABLE: {os.path.join(job.monitor, "big")}') == 1


def test_unreadable_root_fails_the_job_without_deletions(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	_fail_scandir(monkeypatch, job.monitor, errno.ENOTCONN)
	with pytest.raises(rv.JobFailure):
		_backup(job)
	assert len(committed_versions(job)) == 1


def test_unreadable_folder_in_first_backup_is_reported(job, poll_fast, monkeypatch, capsys):
	seed_monitor(job, {'a.txt': 'a', 'locked/b.txt': 'b'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'locked'), errno.EACCES)
	_backup(job)[1].close()
	out = capsys.readouterr()
	assert 'UNREADABLE: ' + os.path.join(job.monitor, 'locked') in out.out + out.err


def test_resume_check_refuses_after_a_read_error(job, monkeypatch):
	seed_monitor(job, {'d/a.txt': 'a'})
	_fail_scandir(monkeypatch, os.path.join(job.monitor, 'd'), errno.EIO)
	assert rv.get_monitor_path_most_recent_change_time(job.monitor) == float('inf')
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_io_errors.py -q`
Expected: FAIL (the unreadable folder's entries are deleted; no `JobFailure`)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Keep the last copy of what cannot be read, and fail the job instead of deleting when the monitored root cannot be read."

---

### Task 7: Copy results are checked; failed copies keep the previous entry or fail the job

**Files:**
- Modify: `reverberator.py` — `cp_af_copy_path` (`:~2885`); new `PendingCopy`, `finish_copies`, `source_readable`; call sites in `do_backup` (complete V0) and `do_reverb_backup` (`copy_path`, attrib copy)
- Modify: `tests/test_io_errors.py`

**Interfaces:**
- Consumes: `JobFailure`, `job_log` (Task 1)
- Produces:
  - `PendingCopy = namedtuple('PendingCopy', ['task', 'source_path', 'temp_path', 'dest_path'])`.
  - `cp_af_copy_path(source_path:str, dest_path:str, mcae = ..., pending:list = None)` — copies into `temp_path = os.path.join(os.path.dirname(dest_path), '.' + os.path.basename(dest_path) + '.reverberator-partial')` and leaves `dest_path` untouched until the copy succeeded. Synchronous (`mcae is ...`): renames inline on success and returns the exit code as today. Asynchronous: requires `pending` and appends a `PendingCopy`. The vanished-source early return stays.
  - `source_readable(path:str) -> bool` — `os.lstat` succeeds and, for a regular file, `os.open(path, os.O_RDONLY | os.O_NONBLOCK)` succeeds.
  - `finish_copies(pending:list, manifest:VaultManifest, version_path:str, job_name:str) -> None` — after the executor's commands finished: on success, replace `dest_path` with `temp_path` (`shutil.rmtree` first only when `dest_path` is a real folder, `os.replace` otherwise); on failure, remove `temp_path` and: when `source_readable(source_path)` is `False`, keep `dest_path` as it is and `job_log(job_name, f'UNREADABLE: {source_path}: {stderr or "copy failed"}; keeping its last backed-up copy')`, discarding the manifest row (path relative to `version_path`) when nothing is at `dest_path`; otherwise raise `JobFailure(f'copying {source_path} into the vault failed: {stderr}')`. Callers call it right after their wait for the executor, before `record_dirty_entries`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_io_errors.py`)

```python
class FakeTask:
	def __init__(self, returncode, stderr=()):
		self.returncode = returncode
		self.stderr = list(stderr)


def _tracked(job, version, rel):
	os.makedirs(job.job_vault, exist_ok=True)
	manifest = rv.VaultManifest(job.job_vault)
	manifest.begin()
	manifest.add(rel, dirty=True)
	return manifest


def test_unreadable_source_keeps_the_previous_entry(job, capsys):
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	os.symlink('../V0--x/a.txt', dest)
	temp = os.path.join(version, '.a.txt.reverberator-partial')
	open(temp, 'w').write('partial')
	manifest = _tracked(job, version, 'a.txt')
	rv.finish_copies([rv.PendingCopy(FakeTask(1, ['Input/output error']), os.path.join(job.monitor, 'gone.txt'), temp, dest)],
		manifest, version, job.job_name)
	assert os.readlink(dest) == '../V0--x/a.txt' and not os.path.exists(temp)
	assert 'UNREADABLE: ' in ''.join(capsys.readouterr())
	manifest.rollback(); manifest.close()


def test_new_entry_with_unreadable_source_is_untracked(job):
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	manifest = _tracked(job, version, 'new.txt')
	rv.finish_copies([rv.PendingCopy(FakeTask(1), os.path.join(job.monitor, 'gone.txt'),
		os.path.join(version, '.new.txt.reverberator-partial'), os.path.join(version, 'new.txt'))], manifest, version, job.job_name)
	assert manifest.lookup('new.txt') is None
	manifest.rollback(); manifest.close()


def test_readable_source_with_failed_copy_fails_the_job(job):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('a')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	manifest = _tracked(job, version, 'a.txt')
	with pytest.raises(rv.JobFailure) as exc:
		rv.finish_copies([rv.PendingCopy(FakeTask(1, ['No space left on device']), src,
			os.path.join(version, '.a.txt.reverberator-partial'), os.path.join(version, 'a.txt'))], manifest, version, job.job_name)
	assert 'No space left on device' in exc.value.reason and not exc.value.permanent
	manifest.rollback(); manifest.close()


def test_failed_vault_copy_commits_nothing_and_next_attempt_cleans_up(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a'})
	_backup(job)[1].close()
	v0 = committed_versions(job)[0]
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	def vault_full(*args, **kwargs):
		raise rv.JobFailure('copying b.txt into the vault failed: No space left on device')
	monkeypatch.setattr(rv, 'finish_copies', vault_full)
	with pytest.raises(rv.JobFailure):
		_backup(job, OrderedDict({os.path.join(job.monitor, 'b.txt'): rv.BackupEntryValues('t', 'create', None)}))
	monkeypatch.undo()
	assert committed_versions(job) == [v0]
	_backup(job)[1].close()   # the next attempt compares the whole tree
	versions = committed_versions(job)
	assert len(versions) == 2 and os.path.isfile(os.path.join(versions[1], 'b.txt'))
	assert sorted(name for name in os.listdir(job.job_vault) if name.startswith('V') and rv.CONTENT_FILE_EXTENSION_NAME not in name) == [os.path.basename(v) for v in versions]


def test_successful_async_copy_replaces_the_link(job):
	src = os.path.join(job.monitor, 'a.txt')
	open(src, 'w').write('new')
	version = os.path.join(job.job_vault, 'V1--x')
	os.makedirs(version)
	dest = os.path.join(version, 'a.txt')
	os.symlink('../V0--x/a.txt', dest)
	pending = []
	mcae = rv.multiCMD.AsyncExecutor(semaphore=rv.BACKUP_SEMAPHORE, quiet=True)
	rv.cp_af_copy_path(src, dest, mcae, pending)
	assert os.path.islink(dest)   # untouched until finished
	while mcae.runningThreads:
		mcae.wait(timeout=0.1)
	manifest = _tracked(job, version, 'a.txt')
	rv.finish_copies(pending, manifest, version, job.job_name)
	assert not os.path.islink(dest) and open(dest).read() == 'new'
	manifest.rollback(); manifest.close()
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_io_errors.py -q`
Expected: the new tests FAIL (`AttributeError: ... 'finish_copies'`; the failed copy commits)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Check copy results: keep the previous entry when the source cannot be read, and fail the job when the vault cannot be written."

---

### Task 8: Inner mounts — watcher side

**Files:**
- Modify: `reverberator.py` — new `inner_mount_points`, `current_mount_table`; `fs_signature_monitor` (`subscribe` / `unsubscribe`); `watchFolder` (`IN_UNMOUNT` branch `:~1354`, loop); `ChangeEventQueue` / `change_events_to_backup_entries` (`'scan'` events)
- Create: `tests/test_inner_mounts.py`

**Interfaces:**
- Produces:
  - `inner_mount_points(mount_table:list, monitor_path:str) -> list` — mount points from `parse_mount_table` output strictly under `os.path.realpath(monitor_path)`, sorted, de-duplicated; doctest.
  - `current_mount_table() -> list` — `parse_mount_table` of `MOUNTINFO_PATH`, `[]` on error.
  - `fs_signature_monitor.subscribe(self, callback) -> object` (token) and `unsubscribe(self, token)` — `callback(mount_table)` runs on the monitor thread after every mount-table check, and once right after subscribing.
  - `ChangeEvent(..., event='scan', path=<folder>)` — "compare this folder against the vault"; `ChangeEventQueue` keeps it like any event (compaction never drops it); `change_events_to_backup_entries` skips `'scan'` events.
  - `watchFolder` subscribes on entry and unsubscribes on exit; the callback only stores the latest table (under a lock) for the loop to read. Each loop iteration that sees a new table compares `inner_mount_points` with the previous set: for each mount point that appeared, add watches for it (`initializeFolderWatchers(..., skip_list=skip_list)`, not into `newDirWDs`) and queue `ChangeEvent(now, True, 'scan', mount_point, None)`; for each that disappeared, `remove_watches_under` it, add a watch on the mount point folder itself when it exists, and queue a `'scan'` of it.
  - `IN_UNMOUNT` on a watch other than the root: `del wdDic[wd]` (+ `irm.decreaseUserWatches()`) and nothing else — no `add_watch` (that is the crash).

- [ ] **Step 1: Write the failing tests** in `tests/test_inner_mounts.py`

```python
import os
import subprocess
import threading
import pytest
import reverberator as rv
from tests.harness import seed_monitor, wait_until

def _privileged():
	return os.geteuid() == 0 or os.environ.get('REVERB_PRIVILEGED') == '1'

needs_root = pytest.mark.skipif(not _privileged(), reason='needs root to mount tmpfs')


@pytest.mark.unit
def test_change_events_skip_scan_events():
	entries = rv.change_events_to_backup_entries([rv.ChangeEvent(1.0, True, 'scan', '/tmp/reverb_doctest/m', None)])
	assert entries == {}


@pytest.mark.unit
def test_subscribe_calls_back_with_the_table(tmp_path, monkeypatch):
	table_file = tmp_path / 'mountinfo'
	table_file.write_bytes(b'22 1 8:1 / / rw - ext4 /dev/sda1 rw\n')
	monitor = rv.fs_signature_monitor(mountinfo_path=str(table_file))
	seen = []
	token = monitor.subscribe(seen.append)
	monitor.check_changed()
	monitor.unsubscribe(token)
	assert seen and [mount_point for mount_point, _ in seen[-1]] == ['/']


def _events(queue, lock):
	with lock:
		return list(queue)


def _start(job):
	queue = rv.ChangeEventQueue(job.monitor)
	lock = threading.Lock()
	thread = threading.Thread(target=rv.watchFolder, kwargs=dict(monitor_path=job.monitor, to_process=queue,
		to_process_lock=lock, to_process_flag=threading.Event(), irm=rv.inotify_resource_manager(),
		min_snapshot_delay_seconds=0, max_shapshot_delay_seconds=60), daemon=True)
	thread.start()
	return thread, queue, lock


@pytest.mark.privileged
@needs_root
def test_watcher_survives_inner_unmount_and_rewatches_on_remount(job, poll_fast):
	inner = os.path.join(job.monitor, 'disk')
	os.makedirs(inner)
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
	try:
		os.makedirs(os.path.join(inner, 'a', 'b'))
		thread, queue, lock = _start(job)
		wait_until(lambda: thread.is_alive(), timeout=2)
		subprocess.check_call(['umount', inner])
		wait_until(lambda: any(e.event == 'scan' and e.path.rstrip('/') == inner for e in _events(queue, lock)), timeout=10, message='no scan on unmount')
		assert thread.is_alive()
		subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
		wait_until(lambda: sum(e.event == 'scan' for e in _events(queue, lock)) >= 2, timeout=10, message='no scan on remount')
		target = os.path.join(inner, 'new.txt')
		open(target, 'w').write('x')
		wait_until(lambda: any(e.path == target for e in _events(queue, lock)), timeout=10, message='remounted disk not watched')
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=3)
		rv.GREEN_LIGHT.set()
		subprocess.call(['umount', inner])
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_inner_mounts.py -q`
Expected: FAIL (`AttributeError: ... 'subscribe'`; the watcher thread dies on unmount)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the inotify, privileged and full suites**

Run: `uv run --extra test python -m pytest tests/test_inner_mounts.py tests/test_inotify.py tests/test_skip_list_watch.py tests/test_privileged.py -q`, then `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Watch inner mounts through the mount table and survive their unmount."

---

### Task 9: Inner mounts — pause unmounted subtrees, compare remounts by subtree

**Files:**
- Modify: `reverberator.py` — new `paused_inner_mounts`; `VaultManifest` (`inner_mounts`, `set_inner_mounts`, `unseen_under`); `delta_generate_backup_entries` (`scope_rel`, pause); `do_backup` (pause on every walk, record inner mounts on commit / no-difference delta); `backuper` (handle `'scan'` events)
- Modify: `tests/test_inner_mounts.py`

**Interfaces:**
- Consumes: `inner_mount_points`, `current_mount_table`, `'scan'` events (Task 8); `mark_seen_under` (Task 6)
- Produces:
  - `VaultManifest.inner_mounts` (property, list of rel folders ending in `/`, `[]` when never recorded) and `set_inner_mounts(self, rels:list)` — JSON in the `meta` row `'inner_mounts'`; the caller holds the transaction. `do_backup` records `sorted(currently mounted inner rels | paused rels)` wherever it records the skip fingerprint (same transactions).
  - `paused_inner_mounts(monitor_path:str, remembered:list, mount_table:list) -> set` — rels in `remembered` that are not mounted now (`inner_mount_points`), whose folder exists and is empty; doctest-free (filesystem), unit-tested.
  - Every `do_backup` walk of the monitored tree (first backup, full delta) skips paused rels (compose with the skip list's `skips`), and the delta keeps their rows: `mark_seen` of each paused folder row and `mark_seen_under` it.
  - `VaultManifest.unseen_under(self, folder:str) -> list` — like `unseen()`, restricted to rows at or under `folder`.
  - `delta_generate_backup_entries(..., job_name:str = '', scope_rel:str = '')` — with `scope_rel` (a folder rel ending in `/`), walks only `os.path.join(monitor_path, scope_rel)` with that `rel_prefix`, and the deleted pass uses `unseen_under(scope_rel)`; the scope itself is looked up and compared like any entry.
  - `backuper`: a batch containing `'scan'` events (and no `full_scan`) is handled as: `entries = change_events_to_backup_entries(other events)`; for each scanned folder (deduplicated, outer folders absorbing inner ones), run the scoped delta against the latest version into its own dict, drop the converted entries at or under that folder, and merge the scoped result in; if the merged entries are empty, no backup runs for that batch. A scope that is paused contributes nothing.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_inner_mounts.py`)

```python
from collections import OrderedDict
from tests.harness import committed_versions, wait_for_committed_count


def _backup(job, entries=None):
	return rv.do_backup(OrderedDict() if entries is None else entries, job_name=job.job_name, monitor_path=job.monitor,
		vault_path=job.vault, keep_one_complete_backup=True, only_sync_attributes=True, keep_n_versions=0, backup_size_limit='0')


def _fake_mounts(monkeypatch, job, mounted):
	table = [('/', ('1',))] + [(os.path.join(job.monitor, rel.rstrip('/')), (rel,)) for rel in mounted]
	monkeypatch.setattr(rv, 'current_mount_table', lambda: table)


@pytest.mark.unit
def test_unmounted_inner_disk_is_paused_not_deleted(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f', 'disk/sub/g.txt': 'g'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	for name in ('f.txt', 'sub/g.txt'):
		os.remove(os.path.join(job.monitor, 'disk', name))
	os.rmdir(os.path.join(job.monitor, 'disk', 'sub'))   # the mount point now looks like an empty folder
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
	_, manifest, _ = _backup(job)
	assert manifest.inner_mounts == ['disk/']
	manifest.close()
	v1 = committed_versions(job)[1]
	assert os.path.lexists(os.path.join(v1, 'disk', 'f.txt')) and os.path.lexists(os.path.join(v1, 'disk', 'sub', 'g.txt'))


@pytest.mark.unit
def test_paused_mount_survives_restart(job, poll_fast, monkeypatch):
	seed_monitor(job, {'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	open(os.path.join(job.monitor, 'b.txt'), 'w').write('b')
	_backup(job)[1].close()          # a fresh manifest object, as after a restart
	assert os.path.lexists(os.path.join(committed_versions(job)[-1], 'disk', 'f.txt'))


@pytest.mark.unit
@pytest.mark.parametrize('retire', ['remove', 'repopulate'])
def test_retiring_the_mount_point_ends_the_pause(job, poll_fast, monkeypatch, retire):
	seed_monitor(job, {'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	os.remove(os.path.join(job.monitor, 'disk', 'f.txt'))
	_fake_mounts(monkeypatch, job, [])
	if retire == 'remove':
		os.rmdir(os.path.join(job.monitor, 'disk'))
	else:
		open(os.path.join(job.monitor, 'disk', 'other.txt'), 'w').write('o')
	_backup(job)[1].close()
	latest = committed_versions(job)[-1]
	assert not os.path.lexists(os.path.join(latest, 'disk', 'f.txt'))


@pytest.mark.unit
def test_scoped_delta_compares_only_the_scope(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_, manifest, _ = _backup(job)
	latest = rv.get_vault_info(job.job_vault).vault_info_dict
	latest = latest[next(reversed(latest))]
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('outside change')
	open(os.path.join(job.monitor, 'disk', 'f.txt'), 'w').write('inside change')
	entries = OrderedDict()
	rv.delta_generate_backup_entries(entries, latest, job.monitor, manifest=manifest, scope_rel='disk/')
	manifest.close()
	assert list(entries) == [os.path.join(job.monitor, 'disk', 'f.txt')]
```

@pytest.mark.unit
def test_backuper_handles_scan_events(job, poll_fast, monkeypatch):
	seed_monitor(job, {'a.txt': 'a', 'disk/f.txt': 'f'})
	_fake_mounts(monkeypatch, job, ['disk/'])
	_backup(job)[1].close()
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('outside')
	open(os.path.join(job.monitor, 'disk', 'f.txt'), 'w').write('inside')
	queue = rv.ChangeEventQueue(job.monitor)
	queue.append(rv.ChangeEvent(1.0, True, 'scan', os.path.join(job.monitor, 'disk'), None))
	queue.append(rv.ChangeEvent(2.0, False, 'modify', os.path.join(job.monitor, 'a.txt'), None))
	control = rv.JobControl(job.job_name)
	control.start_attempt()
	flag = threading.Event()
	flag.set()
	thread = threading.Thread(target=rv.backuper, args=(job.job_name, queue, threading.Lock(), job.monitor, job.vault, 'N/A',
		threading.Event(), flag), kwargs=dict(job=control), daemon=True)
	thread.start()
	try:
		v1 = wait_for_committed_count(job, 2)[1]
		assert open(os.path.join(v1, 'a.txt')).read() == 'outside'
		assert open(os.path.join(v1, 'disk', 'f.txt')).read() == 'inside'
	finally:
		rv.GREEN_LIGHT.clear()
		thread.join(timeout=5)
		rv.GREEN_LIGHT.set()


@pytest.mark.privileged
@needs_root
def test_tmpfs_inner_disk_pause_and_remount(job, poll_fast):
	inner = os.path.join(job.monitor, 'disk')
	os.makedirs(inner)
	open(os.path.join(job.monitor, 'a.txt'), 'w').write('a')
	subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
	try:
		open(os.path.join(inner, 'f.txt'), 'w').write('f')
		_backup(job)[1].close()
		subprocess.check_call(['umount', inner])
		open(os.path.join(job.monitor, 'a.txt'), 'w').write('changed')
		_backup(job)[1].close()
		assert os.path.lexists(os.path.join(committed_versions(job)[1], 'disk', 'f.txt'))
		subprocess.check_call(['mount', '-t', 'tmpfs', 'tmpfs', inner])
		open(os.path.join(inner, 'f.txt'), 'w').write('remounted')
		_, manifest, _ = _backup(job)
		manifest.close()
		assert open(os.path.join(committed_versions(job)[2], 'disk', 'f.txt')).read() == 'remounted'
	finally:
		subprocess.call(['umount', inner])

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_inner_mounts.py -q`
Expected: FAIL (the unmounted disk's files are deleted from V1; `scope_rel` unknown)

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Pause unmounted inner disks instead of deleting them, and compare remounted ones by subtree."

---

### Task 10: Follow-ups from the skip-list round

**Files:**
- Modify: `reverberator.py` — `watchFolder` (create / unpaired MOVED_TO, `IN_IGNORED`, the "not found in wdDic" line), `remove_watches_under` / `remove_moved_away_watches` / `rewatch_moved_folder` (queue limit), `backuper` (not-committed branch, startup take), `JobStartup.load`
- Modify: `tests/test_skip_list_watch.py`, `tests/test_jobs.py`

**Interfaces:**
- Produces:
  - *Away and back:* on CREATE or an unpaired MOVED_TO at path P, a pending move-from whose path is P (with or without trailing `/`) is popped with its cookie and its delete event is queued first, then the create.
  - *Interrupted comparison:* when a batch was a full comparison (startup or `full_scan`) and the backup did not commit, the backuper requeues `ChangeEvent(..., 'full_scan', monitor_path, None)` instead of the (empty) entries.
  - *Noise:* events with `IN_IGNORED` and no name are dropped without a log line above debug; the "Watch descriptor {wd} not found" line no longer includes the watch table; before removing more watches than half of `irm.max_queued_events`, call `irm.increaseInotifyMaxQueueEvents(max(irm.max_queued_events * 2, count * 2))`.
  - *Fingerprint trust:* `JobStartup.load(self, recorded_fingerprint, trusted:bool = True)` — when not trusted, an `'unchanged'` verdict becomes `'changed'` (`'refuse'` still uses the recorded value). The backuper passes `trusted=manifest.describes(<latest committed version path>)` (from `get_vault_info`) when it has a manifest.
  - *Stop during startup:* the backuper checks `job.should_run()` (or `GREEN_LIGHT` without a job) right before its startup `to_process.take()` and returns if it should stop, so `finally` keeps the restored events.

- [ ] **Step 1: Write the failing tests**

`tests/test_skip_list_watch.py`:

```python
def test_folder_moved_away_and_back_is_not_deleted_later(job, tmp_path, poll_fast, monkeypatch):
	monkeypatch.setattr(rv, 'MOVE_PAIR_TIMEOUT_SECONDS', 0.5)
	outside = tmp_path / 'outside'
	outside.mkdir()
	seed_monitor(job, {'d/sub/': None})
	thread, to_process, lock = _start(job, [])
	try:
		os.rename(os.path.join(job.monitor, 'd'), str(outside / 'd'))
		os.rename(str(outside / 'd'), os.path.join(job.monitor, 'd'))
		d = os.path.join(job.monitor, 'd')
		wait_until(lambda: any(e.event == 'create' and e.path == d for e in _events(to_process, lock)), message='no create')
		time.sleep(1.0)
		_probe(job, to_process, lock, 'probe_after_expiry.txt')
		events = [(e.event, e.path) for e in _events(to_process, lock) if e.path == d]
		assert events == [('delete', d), ('create', d)]
	finally:
		_stop(thread)
```

`tests/test_jobs.py`:

```python
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
```

`tests/test_jobs.py` (fake inotify, as in `tests/test_crash_safety.py`):

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --extra test python -m pytest tests/test_skip_list_watch.py tests/test_jobs.py -q`
Expected: the new tests FAIL

- [ ] **Step 3: Implement** the interfaces above.

- [ ] **Step 4: Run the full suite** (and `tests/test_skip_list_watch.py` three times for flakes)

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** — "Keep moved-back folders, requeue interrupted comparisons, quiet watch removal, and harden startup."

---

### Task 11: firewatcher pattern, docs, version — and installing on this machine

**Files:**
- Create: `firewatcher/reverberator.txt`
- Modify: `README.md`, `reverberator.py` (`__version__ = 0.38`), `pyproject.toml` (`version = "0.38"`), `tests/test_jobs.py`

**Interfaces:**
- Consumes: the marker helpers (Task 1) and every marker the code now logs.
- Produces: `firewatcher/reverberator.txt` with exactly these lines:

```
reverberator job * FAILED
reverberator job * UNREADABLE
reverberator job * STOPPED
reverberator EXITING with error
```

- [ ] **Step 1: Write the failing test** (`tests/test_jobs.py`)

```python
import fnmatch


def test_firewatcher_patterns_match_every_alerting_marker_and_not_recovered():
	path = os.path.join(os.path.dirname(rv.__file__), 'firewatcher', 'reverberator.txt')
	patterns = ['*' + line.strip() + '*' for line in open(path) if line.strip()]
	alerting = [
		rv.job_log('j', 'FAILED: disk gone; retrying in 60s'),
		rv.job_log('j', 'FAILED: waiting 15 min for /mnt/x: vault filesystem not ready'),
		rv.job_log('j', 'UNREADABLE: /m/a: [Errno 5] Input/output error; keeping its last backed-up copy'),
		rv.job_log('j', 'STOPPED: bad pattern'),
		rv.daemon_error_log('every job is stopped'),
	]
	for line in alerting:
		assert any(fnmatch.fnmatch('Oct 18 12:00:00 host python3[1]: ' + line, p) for p in patterns), line
	assert not any(fnmatch.fnmatch(rv.job_log('j', 'RECOVERED after 2 failed attempts'), p) for p in patterns)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --extra test python -m pytest tests/test_jobs.py -q -k firewatcher`
Expected: FAIL (`FileNotFoundError`)

- [ ] **Step 3: Add the pattern file, the README section** (markers and what each means, exit codes 0/1/3 and `RestartPreventExitStatus=3`, the firewatcher file and where it goes, inner-mount pausing and how to retire a mount point), **and bump the version** to 0.38 (then `uv lock`, unstaged).

- [ ] **Step 4: Run the full suite**

Run: `uv run --extra test python -m pytest -q`
Expected: PASS

- [ ] **Step 5: Commit** `firewatcher/reverberator.txt README.md reverberator.py pyproject.toml tests/test_jobs.py` — "Ship a firewatcher pattern for the failure markers, document them, bump to 0.38."

- [ ] **Step 6 (controller, after asking the user — not an implementer step):** with the user's explicit OK at this point:
  1. Copy `firewatcher/reverberator.txt` to `/etc/firewatcher/patterns.d/reverberator.txt`; check how firewatcher loads patterns (`firewatcher --help`, its source under `/root/.local/bin/firewatcher`) and restart `firewatcher.service` only if it reads patterns only at start; confirm it is active afterwards.
  2. Add `RestartPreventExitStatus=3` under `[Service]` in `/etc/systemd/system/reverberator.service`, run `systemctl daemon-reload`, and confirm with `systemctl show reverberator.service -p RestartPreventExitStatus`.
  3. Do not restart `reverberator.service`: report that the new version takes effect when the user restarts it.
