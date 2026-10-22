# Whole Log Lines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every line reverberator logs reaches the output whole and at most 16384 bytes long, so firewatcher sees every marker. Round 4's parked small items are fixed alongside.

**Architecture:** A proxy, `LockedLogger`, wraps each Tee_Logger assigned to `tl` and holds one module-level `threading.RLock` across each call. The same proxy cuts each line of a string message to `LOG_LINE_LIMIT` bytes with `cut_line`, which now counts UTF-8 bytes. Small fixes: a `nameless_start` helper, a stricter process test, README wording and the version.

**Tech Stack:** Python 3 (single module `reverberator.py`), Tee_Logger (6.40 in the service venv, 6.42 in the worktree venv), pytest.

**Spec:** `docs/superpowers/specs/2026-10-21-whole-log-lines-design.md`

**As built (differs from the tasks below):**
- The cut notice fits inside `LOG_LINE_LIMIT`, so Task 2's expected strings changed; the tests in `tests/test_log_lines.py` hold the values that shipped.
- `log_text` cuts each line after its indent.
- The watcher and backuper helpers escape and cut their joined line once.
- `_call` finds `msg` by its parameter.
- The README sentences differ from the drafts here: README.md lines 6 and 25 are the shipped text.

## Global Constraints

- **Style.** The code is tab-indented and follows the surrounding code's naming, comment density and docstring-with-doctest style.
- **Library versions.** The code must work on both Tee_Logger 6.40 (`/mnt/optane/work/reverberator/.venv`, no `teewarning` or `teedebug`) and 6.42 (the worktree `.venv`).
- **Where to work.** Work only in the worktree `/mnt/optane/work/reverberator/.worktrees/whole-log-lines`.
  - Never edit the main checkout `/mnt/optane/work/reverberator`; the live service runs from it.
  - Never touch `/etc` or systemctl.
  - Never commit `uv.lock`.
- **Test commands.** Run both from the worktree root:
  - worktree venv: `.venv/bin/python -m pytest -q -p no:cacheprovider`
  - service venv: `/mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
  - Baseline: both pass with 0 failures before Task 1.
- **Commit messages.** One plain sentence or two, in the repo's style (`git log --oneline -5`), ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_0179SV9GcZcp5fPuVSWUarb6
  ```
- **Values.** `LOG_LINE_LIMIT = 16384`, in bytes. The cut notice is `' …({n} more bytes)'`.

## Review Focus

1. **SIGTERM mid-line.** The handler logs from the main thread while that thread is mid-line inside `tl`. It must not deadlock (RLock). Pinned in Task 1 by `test_logging_while_holding_the_log_lock_does_not_deadlock`.
2. **Caller location in the log file.** The wrapper must not show up as the caller. Pinned in Task 1 by `test_the_log_file_names_the_same_caller_through_the_proxy`.
3. **Older Tee_Logger.**
   - Tee_Logger 6.40 lacks `teewarning`. `getattr(tl, 'teewarning', tl.teeprint)` must still fall back.
   - TSVZ passes `callerStackDepth=3` itself, and must still log.
   - Pinned in Task 1 by `test_a_missing_method_still_falls_back` and `test_an_explicit_caller_depth_is_kept_one_deeper`.
4. **Lone surrogates in a message.** A message that skipped `log_text` can hold lone surrogates, and the cut must not raise on it. Pinned in Task 2 by `test_cut_line_counts_a_lone_surrogate_as_three_bytes`.
5. **Characters at the limit.** A character that straddles the limit is dropped whole, and a line exactly at the limit is untouched. Pinned in Task 2 by `test_cut_line_never_splits_a_character` and `test_cut_line_keeps_a_line_exactly_at_the_limit`.

---

### Task 1: One lock around every log call

**Files:**
- Modify: `reverberator.py`:
  - add `LOG_LOCK` and `LockedLogger` just before `def job_log` (about line 750);
  - wrap the three `Tee_Logger.teeLogger(...)` assignments at about lines 989, 1200 and 8834.
- Create: `tests/test_log_lines.py`

**Interfaces:**
- Produces:
  - `LOG_LOCK: threading.RLock`, module level and shared by every proxy.
  - `class LockedLogger`:
    - `__init__(self, wrapped)` keeps the Tee_Logger as `self.wrapped`.
    - `__getattr__(self, name)` returns the wrapped logger's attribute. A missing one raises `AttributeError`, so `getattr(tl, 'teewarning', tl.teeprint)` falls back.
    - A callable is returned wrapped, so the call runs holding `LOG_LOCK`.
    - Caller depth: for a method whose signature has a `callerStackDepth` parameter, take the depth given or, when none is given, `self.wrapped.callerStackDepth`. A depth of 0 or more is passed one deeper; a negative one (Tee_Logger's "find it" default) is passed unchanged.
  - Task 2 adds the line cut to this same wrapper.

- [ ] **Step 1: Write the failing tests** in `tests/test_log_lines.py`, importing `reverberator as rv` and `firewatcher_patterns`/`alerting_lines` the way `tests/test_log_text.py` does.
  - `test_markers_logged_at_once_from_many_threads_each_start_a_line`:
    - Start a child with `subprocess.run([sys.executable, '-c', SCRIPT], env=dict(os.environ, PYTHONUNBUFFERED='1'), stdout=PIPE, stderr=PIPE, cwd=<worktree root>, timeout=60)`.
    - The child imports `reverberator`, whose module-level `tl` prints and is already wrapped. It starts 16 threads that wait on one `threading.Barrier(16)`, then each calls `rv.job_log(f'job-{t}', f'FAILED: marker {i}')` for `i in range(200)`.
    - Assert `child.returncode == 0`.
    - Assert `len(alerting_lines(out)) == 3200`.
    - Assert the set of `(t, i)` parsed from the alerting lines is every pair.
    - Assert every non-empty output line is an alerting line.
  - `test_logging_while_holding_the_log_lock_does_not_deadlock`:
    - Hold `rv.LOG_LOCK` in the test thread (`with rv.LOG_LOCK:`) and call `rv.tl.teeerror('inner')` inside it. It returns; capsys shows `inner`.
    - Also, with the lock held in the test thread, a second thread's `rv.tl.teeerror('other')` has not printed after `0.2` s, and has printed once the lock is released and that thread is joined.
  - `test_the_log_file_names_the_same_caller_through_the_proxy`:
    - Build two Tee_Loggers writing log files under `tmp_path`: `noLog=False`, `suppressPrintout=True`, `callerStackDepth=4`, the other `run_daemon` arguments as there. Wrap one in `rv.LockedLogger`.
    - From the same helper function, log `'probe'` with `teeerror` through each, via a two-deep call chain so that depth 4 lands in test code.
    - The `[file:line]` field of the two log lines is equal.
  - `test_a_missing_method_still_falls_back`:
    - `class Old: def teeprint(self, msg, callerStackDepth=...): ...`
    - `getattr(rv.LockedLogger(Old()), 'teewarning', 'fallback') == 'fallback'`.
  - `test_an_explicit_caller_depth_is_kept_one_deeper`:
    - A fake logger whose `teelog(self, msg, level, callerStackDepth=...)` records its arguments, with `callerStackDepth = 4` set on it.
    - Through the proxy:
      - `teelog('m', 'info', callerStackDepth=3)` records 4;
      - `teelog('m', 'info')` records 5;
      - with the fake's `callerStackDepth = -1`, `teelog('m', 'info')` records -1.

- [ ] **Step 2: Run them and see them fail**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_log_lines.py`
  - Expected: FAIL, because `LockedLogger`/`LOG_LOCK` are not defined. Before adding the proxy, also run the many-threads test with only `LOG_LOCK` defined (no wrapping) at least 3 times. Confirm it fails on merged lines in at least one run, and record the result in the report. If it never fails, raise the thread or line count until it does, and use those numbers in the test.

- [ ] **Step 3: Implement `LOG_LOCK` and `LockedLogger`**, and wrap the three `tl = Tee_Logger.teeLogger(...)` assignments as `tl = LockedLogger(Tee_Logger.teeLogger(...))`. Cache per method name whether it takes `callerStackDepth` (`inspect.signature`), so a call does not inspect each time. The docstring says why the lock exists: Tee_Logger prints the text and its line break as two writes, and a marker another thread logs between them never alerts.

- [ ] **Step 4: Run the new tests and both full suites**
  - Run: the new file, then both test commands from Global Constraints.
  - Expected: all pass on both venvs.

- [ ] **Step 5: Commit** `reverberator.py` and `tests/test_log_lines.py`.

### Task 2: Cut every printed line at 16384 bytes

**Files:**
- Modify: `reverberator.py`:
  - `cut_line` and its doctests, and the `LOG_LINE_LIMIT` comment (about line 7160);
  - `LockedLogger`'s wrapper, to cut the message.
- Modify: `tests/test_log_text.py`: `test_a_very_long_line_is_cut_so_the_journal_cannot_split_it`, for bytes.
- Modify: `tests/test_log_lines.py`: add tests.
- Modify: `README.md`, line 6, the sentence "No log line is longer than 16384 characters; a longer one ends with the number of characters left out."

**Interfaces:**
- Consumes: `LockedLogger` from Task 1.
- Produces: `cut_line(line:str) -> str`.
  - If the line's UTF-8 encoding (with `surrogatepass`, so a lone surrogate counts 3 bytes) is at most `LOG_LINE_LIMIT` bytes, the line is returned unchanged.
  - Otherwise it returns the longest prefix of whole characters that fits in `LOG_LINE_LIMIT` bytes, then `f' …({n} more bytes)'`, where n is the line's bytes minus the kept bytes.
  - It returns early without encoding when `len(line) * 4 <= LOG_LINE_LIMIT`.
- Proxy: for a `str` message, given as the first positional argument or as `msg=`, the wrapper passes on `'\n'.join(cut_line(l) for l in msg.split('\n'))`. Any other argument passes unchanged.

- [ ] **Step 1: Write the failing tests** in `tests/test_log_lines.py`.
  - `test_cut_line_never_splits_a_character`:
    - `rv.cut_line('\U0001f600' * 5000) == '\U0001f600' * 4096 + ' …(3616 more bytes)'`
    - `rv.cut_line('ab' + '日' * 6000) == 'ab' + '日' * 5460 + ' …(1620 more bytes)'`
  - `test_cut_line_keeps_a_line_exactly_at_the_limit`: `rv.cut_line('x' * 16384) == 'x' * 16384`, and `rv.cut_line('a' + '日' * 5461)` is unchanged (16384 bytes).
  - `test_cut_line_counts_a_lone_surrogate_as_three_bytes`: `rv.cut_line('\udcff' * 6000) == '\udcff' * 5461 + ' …(1617 more bytes)'`, with no exception.
  - `test_a_joined_watcher_line_is_cut_in_bytes`:
    - Call `rv.watcherTeeLogToTl('/m/' + '日' * 10000, '日' * 10000, error=True)` with capsys.
    - Strip `\x1b\[[0-9;]*m` from each output line. Each line's UTF-8 length is at most `16384 + len(' …(99999 more bytes)'.encode())`.
    - The first line ends with `more bytes)`.
    - Do the same for `rv.backuperTeeLogToTl`.
  - Update `tests/test_log_text.py::test_a_very_long_line_is_cut_so_the_journal_cannot_split_it` and the `cut_line` doctests to the byte notice, e.g. `cut_line('x' * (LOG_LINE_LIMIT + 3))[-16:] == ' …(3 more bytes)'`.

- [ ] **Step 2: Run them and see them fail**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_log_lines.py tests/test_log_text.py`
  - Expected: the new byte tests FAIL.

- [ ] **Step 3: Implement** `cut_line` in bytes and the proxy's per-line cut. Change the `LOG_LINE_LIMIT` comment to say the limit counts bytes, as journald's LineMax does. To find the cut point, encode once and step back from byte `LOG_LINE_LIMIT` while the byte there is a continuation byte (`b & 0xC0 == 0x80`).

- [ ] **Step 4: README.** Replace the sentence with: "No line reverberator logs holds more than 16384 bytes of text: a longer one is cut there, never inside a character, and ends with the number of bytes left out, so that the journal, which splits a line longer than 48K, cannot start a record inside it."

- [ ] **Step 5: Run the new tests and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 6: Commit** `reverberator.py`, `README.md` and the two test files.

### Task 3: Nameless rows, the surrogate check, README and 0.41

**Files:**
- Modify: `reverberator.py`:
  - add `nameless_start` after `nameless_reason` (about line 776);
  - use it in `run_daemon` in place of the inner `start_nameless` (about line 1241);
  - `__version__ = 0.40` → `0.41` (line 53).
- Modify: `tests/test_jobs.py`: add a unit test next to `test_find_job_ignores_nameless_rules`.
- Modify: `tests/test_process.py`: `test_names_that_are_not_text_are_kept_exactly_and_never_alert`, its last assertion.
- Modify: `README.md`, line 25, "(n is the row's place among the rule rows, ...)".

**Interfaces:**
- Produces: `nameless_start(rule_path:str, rule) -> callable`. It returns `start(job:JobControl, attempt:int) -> list`, which calls `job.fail(nameless_reason(rule_path, raw_job_name(rule)), permanent=True)` and returns `[]`. The rule is bound when `nameless_start` is called.

- [ ] **Step 1: Write the failing tests.**
  - `tests/test_jobs.py::test_each_nameless_row_quotes_its_own_name`:
    - Build two rules with `rv.ReverbRule` whose `job_name`s are `rv.NamelessJobName('!!!')` and `rv.NamelessJobName('???')`. Copy the other fields from an existing test's rule, or from `rv.REVERB_RULE_HEADER` with `''`.
    - Make both starters first, then call each with its own `rv.JobControl('', 'row-1')` / `rv.JobControl('', 'row-2')`.
    - Assert each `job.failure.reason` contains `"'!!!'"` or `"'???'"` respectively, `job.failure.permanent` is true, and each start returned `[]`.
  - `tests/test_process.py`: replace `'\udcff' not in output` with `not any('\udc80' <= c <= '\udcff' for c in output)`. Also assert that the output holds no raw `\x1b[31mred`. That assertion is already there; keep it.

- [ ] **Step 2: Run them and see the unit test fail**
  - Run: `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_jobs.py -k nameless`
  - Expected: FAIL, because `nameless_start` is not defined.

- [ ] **Step 3: Implement `nameless_start`.** Use it in `run_daemon` (`JobControl(job_name, f'row-{index + 1}')`, then `nameless_start(args.rule_path, reverb_rule)`), and bump `__version__` to `0.41`.

- [ ] **Step 4: README line 25.** Change the parenthesis to: "(n counts the rule rows reverberator keeps, leaving out comments, the defaults row and rows it ignores for an empty Job Name, Path Monitoring or Vault Path, so that the marker matches the alert patterns)".

- [ ] **Step 5: Run the touched tests, then both full suites.** Expected: all pass on both venvs, `tests/test_process.py` and `tests/test_jobs.py -k nameless` included.

- [ ] **Step 6: Commit** `reverberator.py`, `README.md`, `tests/test_jobs.py` and `tests/test_process.py`.
