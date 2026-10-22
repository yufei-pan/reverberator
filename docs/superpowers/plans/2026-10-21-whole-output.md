# Whole Output Lines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In the daemon, every line any in-process code writes to stdout or stderr reaches the journal whole. Thread tracebacks go through the escaping logger.

**Architecture:**
- `WholeLineStream` wraps `sys.stdout` and `sys.stderr`. It holds each thread's text until its newline, then writes whole lines with one write and a flush, holding `LOG_LOCK`.
- `install_daemon_output()` installs both streams and a `threading.excepthook` that logs through `tl`. `main()` calls it on the daemon path.
- The two sysctl calls become quiet.

**Tech Stack:** Python 3 (single module `reverberator.py`, Python ≥ 3.8), Tee_Logger 6.40/6.42, multiCMD 1.51/1.54, TSVZ 3.39/4.9, pytest.

**Spec:** `docs/superpowers/specs/2026-10-21-whole-output-design.md`

**As built (differs from the tasks below):**
- The streams wait at most 5 s for `LOG_LOCK`, then 0.1 s per write until the thread gets it again, and `flush()` takes no lock (see the spec's Anti-goals).
- A held part is written on its own past `2 * LOG_LINE_LIMIT` characters.
- Ended threads' parts come out with the next line.
- `log_thread_exception` escapes first and writes the dying thread's held text first; it falls back to `tl.error` and then stderr.
- sysctl uses `return_object=True`.
- The tests in `tests/test_whole_output.py` hold the shipped behavior.

## Global Constraints

- **Style.** Tab indentation. Match the surrounding code's naming, comment density and docstring style.
- **Library versions.** Must work on the service venv (`/mnt/optane/work/reverberator/.venv`: Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39) and the worktree venv (6.42, 1.54, 4.9).
- **Where to work.** Only in `/mnt/optane/work/reverberator/.worktrees/whole-output`.
  - Never edit the main checkout: the live service runs from it.
  - Never touch `/etc` or systemctl.
  - Never commit `uv.lock`.
- **Test commands.** Run from the worktree root. Baseline: both pass, 784 passed and 1 skipped.
  - `.venv/bin/python -m pytest -q -p no:cacheprovider`
  - `PYTHONDONTWRITEBYTECODE=1 /mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
- **Commit messages.** One plain sentence or two in the repo's style, ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_0179SV9GcZcp5fPuVSWUarb6
  ```
- **Existing pieces to reuse.**
  - `LOG_LOCK` (a module-level `threading.RLock`, next to `class LockedLogger`).
  - `LOG_LINE_LIMIT = 16384`.
  - `log_text(text)`.
  - `tl` (the module logger, a `LockedLogger`).
  - `alerting_lines(output)` and `firewatcher_patterns()` in `tests/test_log_text.py`.

## Review Focus

1. **Part left by a finished thread.** A thread writes part of a line and ends without its newline. The part must not be glued to another thread's text, and must come out by the time the daemon exits. Pinned in Task 1 by `test_parts_left_by_ended_threads_are_written_as_their_own_lines`.
2. **A writer that never ends its line.** Memory stays bounded. Pinned in Task 1 by `test_a_part_longer_than_the_limit_is_written_as_its_own_line`.
3. **`writelines`, `isatty`, `fileno` through the wrapper.** These must not skip the holding or lose the wrapped stream's answers. Pinned in Task 1 by `test_writelines_holds_parts_like_write` and `test_attributes_come_from_the_wrapped_stream`.
4. **A forged marker in an exception message.** A thread raises an exception whose message holds a newline and marker text. No line may alert. Pinned in Task 2 by `test_a_thread_traceback_is_logged_escaped`.
5. **Real stdout and stderr merged into one pipe.** This is how the journal gets them. Markers from some threads and library-style split prints from others must never share a line. Pinned in Task 1 by `test_split_prints_from_threads_never_put_a_marker_mid_line`.

---

### Task 1: Whole-line streams for the daemon

**Files:**
- Modify: `reverberator.py`.
  - Add `class WholeLineStream` and `install_daemon_output()` after `class LockedLogger`.
  - Call `install_daemon_output()` in `main()` on the daemon path, just before `run_daemon()`.
- Create: `tests/test_whole_output.py`.

**Interfaces:**
- Produces `class WholeLineStream`:
  - `__init__(self, stream)` keeps the wrapped text stream as `self.stream`.
  - `write(self, text:str) -> int`, holding `LOG_LOCK`:
    - Join the calling thread's held part with `text`.
    - If the result holds a `'\n'`, write everything up to and including the last `'\n'` with one `self.stream.write(...)`, then `self.stream.flush()`.
    - Hold what is left. If what is left is longer than `LOG_LINE_LIMIT` characters, write it with `'\n'` added, flush, and hold nothing.
    - Returns `len(text)`.
    - If the wrapped stream raises, the exception propagates. The part being written is not held again.
  - `writelines(self, lines)` writes each item through `write()`.
  - `flush(self)` flushes the wrapped stream, holding `LOG_LOCK`, and does not write held parts.
  - `write_held(self)` writes every thread's held part as its own line (`part + '\n'`), then flushes and empties the holding. It holds `LOG_LOCK`.
  - `__getattr__` gives every other attribute from the wrapped stream (`fileno`, `isatty`, `encoding`, `errors`, `buffer`, ...).
  - Held parts are kept per thread, keyed by `threading.current_thread()`. An entry exists only while that thread holds a part.
- Produces `install_daemon_output() -> None`:
  - Wraps `sys.stdout` and `sys.stderr` in `WholeLineStream`, unless one is already a `WholeLineStream`.
  - Registers `atexit` calls of `write_held()` on both.
  - Calling it twice changes nothing.
  - Task 2 adds the excepthook here.

- [ ] **Step 1: Write the failing tests** in `tests/test_whole_output.py`. Use a recording fake stream (it appends each `write` argument to a list and counts `flush` calls) unless a test says otherwise.
  - `test_a_part_waits_for_its_newline`:
    - `w.write('ab')` records nothing.
    - Then `w.write('c\nd')` records exactly `['abc\n']`.
    - Then `w.write('\n')` records `'d\n'` as well.
    - Each `write` returns `len(text)`.
  - `test_lines_from_many_threads_reach_the_stream_whole`:
    - 16 threads wait on one `threading.Barrier(16)`. Each then runs, for `i in range(200)`: `w.write(f'T{t} part ')`, `w.write(f'{i}')`, `w.write('\n')`.
    - Every recorded write ends with `'\n'`.
    - Splitting all recorded text into lines gives exactly the 3200 lines `f'T{t} part {i}'`, each once.
  - `test_parts_left_by_ended_threads_are_written_as_their_own_lines`:
    - A thread writes `'left'` with no newline and ends.
    - The main thread writes `'main\n'`, recorded as exactly `'main\n'` (not glued).
    - `w.write_held()` records `'left\n'`.
    - A second `write_held()` records nothing more.
  - `test_a_part_longer_than_the_limit_is_written_as_its_own_line`: `w.write('x' * (rv.LOG_LINE_LIMIT + 5))` records exactly `['x' * (rv.LOG_LINE_LIMIT + 5) + '\n']` and holds nothing (a later `write_held()` records nothing).
  - `test_writelines_holds_parts_like_write`: `w.writelines(['a', 'b\n', 'c'])` records `['ab\n']`, and `write_held()` then records `'c\n'`.
  - `test_flush_does_not_write_a_held_part`: `w.write('part')`, then `w.flush()`. Nothing is recorded, and the fake's flush count went up.
  - `test_attributes_come_from_the_wrapped_stream`:
    - Wrap a real `io.TextIOWrapper(io.BytesIO(), encoding='utf-8')`.
    - `w.encoding == 'utf-8'`, `w.isatty() is False`, and `w.buffer` is the wrapped stream's buffer.
    - Wrapping `sys.__stdout__` gives `w.fileno() == sys.__stdout__.fileno()`.
  - `test_install_daemon_output_wraps_once`:
    - `monkeypatch.setattr(sys, 'stdout', io.StringIO())` and the same for `sys.stderr`.
    - Monkeypatch `atexit.register` to record its calls.
    - Calling `rv.install_daemon_output()` twice leaves `sys.stdout` and `sys.stderr` as `WholeLineStream` objects whose `.stream` is the original `StringIO` (not wrapped twice), with exactly 2 registered exit calls.
    - Restore the excepthook if Task 2's part is present: monkeypatch `threading.excepthook` to itself before calling.
  - `test_split_prints_from_threads_never_put_a_marker_mid_line`, marked `@pytest.mark.process`:
    - Start a child with `subprocess.run([sys.executable, '-c', SCRIPT], env=dict(os.environ, PYTHONUNBUFFERED='1'), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=<worktree root>, timeout=60)`, so stdout and stderr share one pipe as in the journal.
    - The child imports `reverberator as rv` and calls `rv.install_daemon_output()`.
    - It runs 8 marker threads, each calling `rv.job_log(f'job-{t}', f'FAILED: marker {i}')` for `i in range(200)`.
    - It runs 8 library-style threads, each doing `sys.stderr.write('Error running command: ')`, `sys.stderr.write(f'x{t}-{i}')`, `sys.stderr.write('\n')` for `i in range(200)`, plus `print(f'plain {t} {i}')` to stdout.
    - All 16 threads start together on a `threading.Barrier(16)`.
    - Assert `len(alerting_lines(out)) == 1600`.
    - Assert every non-empty line, colour codes stripped, is an alerting line or matches `^Error running command: x\d+-\d+$` or `^plain \d+ \d+$`.
    - Assert the counts are 1600 of each library kind.

- [ ] **Step 2: Run them and see them fail**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_whole_output.py`
  - Expected: FAIL, because `WholeLineStream` and `install_daemon_output` are not defined.
  - Also run the process test's child script once with `install_daemon_output()` replaced by a no-op, at least 3 times, to show it fails on mixed lines without the fix. Record the counts in the report. If it never fails, raise the counts until it does, and use those in the test.

- [ ] **Step 3: Implement `WholeLineStream` and `install_daemon_output()`, and call it in `main()`.**
  - Put the call before `run_daemon()` and after the command branch, so the commands never get the wrapped streams.
  - The class docstring says why: other code in the process writes a line in pieces, and a marker written between the pieces would sit mid-line where the alerts never see it.

- [ ] **Step 4: Run the new tests and both full suites.**
  - Expected: all pass on both venvs. The existing process tests now run the daemon with the wrapped streams, and they must pass unchanged.

- [ ] **Step 5: Commit** `reverberator.py` and `tests/test_whole_output.py`.

### Task 2: Thread tracebacks through the logger, quiet sysctl, README, 0.42

**Files:**
- Modify: `reverberator.py`.
  - Add `log_thread_exception(args)` next to `install_daemon_output`, and set it as `threading.excepthook` in `install_daemon_output()`.
  - In `getSysctlValues` and `setSysctlValues` (about lines 1873 and 1895), change `quiet=not self.debug` to `quiet=True`.
  - Set `__version__ = 0.42` (line 54).
- Modify: `pyproject.toml`: `version = "0.42"`.
- Modify: `README.md`, line 6. After the sentence ending "cannot start a record inside it.", add: "The daemon also writes every line its libraries print, and every traceback of a thread, whole: a line another thread has not finished waits until it is, so no marker can land inside one."
- Modify: `tests/test_whole_output.py`: add tests.

**Interfaces:**
- Consumes: `install_daemon_output()` from Task 1.
- Produces `log_thread_exception(args) -> None`, with the `threading.excepthook` signature (`args.exc_type`, `args.exc_value`, `args.exc_traceback`, `args.thread`).
  - For `SystemExit` it returns without logging.
  - Otherwise it calls `tl.teeerror(log_text(f'Uncaught exception in thread {name}:\n' + ''.join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)).rstrip('\n')))`, where `name` is `args.thread.name` or `'?'` when `args.thread` is None.
  - If that call raises, it calls `threading.__excepthook__(args)`.

- [ ] **Step 1: Write the failing tests.**
  - `test_a_thread_traceback_is_logged_escaped(capsys, monkeypatch)`:
    - `monkeypatch.setattr(threading, 'excepthook', rv.log_thread_exception)`.
    - Start a thread named `'worker'` that raises `ValueError('bad\nreverberator job x FAILED: forged\x1b[31m')`, then join it.
    - The captured output (out + err) has a line containing `Uncaught exception in thread worker:`.
    - `alerting_lines(...)` is `[]`, and `'\x1b[31m'` is not in the output.
    - A line ending `reverberator job x FAILED: forged\x1b[31m` with the escape shown as `\x1b` starts with four spaces.
  - `test_systemexit_in_a_thread_is_silent`: same hook, a thread raising `SystemExit(3)`. The captured output is empty.
  - `test_a_failing_log_falls_back_to_pythons_hook`:
    - Monkeypatch `rv.tl` to a fake whose `teeerror` raises `OSError`.
    - Monkeypatch `threading.__excepthook__` to a recorder.
    - The thread's exception reaches the recorder once.
  - `test_install_daemon_output_sets_the_thread_hook`: with the stream and atexit monkeypatching from Task 1's install test, plus `monkeypatch.setattr(threading, 'excepthook', threading.excepthook)`, after `rv.install_daemon_output()`, `threading.excepthook is rv.log_thread_exception`.
  - `test_sysctl_runs_quiet_in_verbose_mode`:
    - Monkeypatch `rv.multiCMD.run_command` to record its `quiet` argument and return `['fs.inotify.max_user_watches = 5']`.
    - `monkeypatch.setattr(rv, 'DEBUG', True)` before building `rv.inotify_resource_manager()`. Its constructor copies `DEBUG` into `self.debug` and reads four sysctl values itself.
    - Then call `getSysctlValues('fs.inotify.max_user_watches')`. The result is 5, and every recorded `quiet`, the constructor's included, is True.

- [ ] **Step 2: Run them and see them fail**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_whole_output.py -k "thread or sysctl"`
  - Expected: FAIL, because `log_thread_exception` is not defined and sysctl runs with `quiet=False` in debug mode.

- [ ] **Step 3: Implement.**
  - Add `log_thread_exception`, and set it in `install_daemon_output()`.
  - Make both sysctl calls `quiet=True`. In `getSysctlValues`, when `self.debug`, log `tl.teeprint(log_text(f'sysctl {field}: {rtn}'))` after the call.
  - Bump the version in both places and add the README sentence.

- [ ] **Step 4: Run the new tests and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit** `reverberator.py`, `pyproject.toml`, `README.md` and `tests/test_whole_output.py`.
