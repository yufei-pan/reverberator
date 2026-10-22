# Whole log lines (0.41)

## Intent

firewatcher raises reverberator's alerts from marker lines (`reverberator job <name> FAILED|UNREADABLE|STOPPED:` and `reverberator EXITING with error:`), and its patterns only match a marker at the start of a journal record. Two threads that log at the same moment can merge their lines today. Tee_Logger's `printWithColor` uses `print()`, which writes the text and the line break as two writes, and under `PYTHONUNBUFFERED=1` (the service) each one is its own `write()`. Another thread's text can land between them, so its marker then sits mid-line and never alerts. Three nameless jobs stopped together merged their markers in 2 of 5 runs (round 4 repro).

This round makes every line reverberator logs reach the output whole and within the journal's line limit. It also clears round 4's parked small items.

## Goals

1. **Whole lines.** No other line from this process's logging lands inside a line being logged. One re-entrant lock, `LOG_LOCK`, is held across each call on `tl`, covering both the print and the log-file write. It is re-entrant because the SIGTERM handler logs from the main thread, which may already hold it.
2. **A byte cap on every printed line.** No line reverberator logs is longer than `LOG_LINE_LIMIT = 16384` bytes of UTF-8, its cut notice included, so a cut line is never cut again (decided during execution: a notice outside the limit made the logger cut lines `log_text` had already cut, and the second notice then miscounted).
   - The cap is checked on each line as it is printed, so the watcher and backuper lines (prefix, path and message joined) are covered too.
   - A cut never splits a character, and the line ends with ` …(<n> more bytes)`.
   - Why bytes: journald's LineMax (48K) counts bytes, and 16384 four-byte characters are 64K.
3. **Nameless jobs quote their own name.** A nameless job's stop reason quotes its own row's name as written. Today `start_nameless` reads the loop variable when its thread runs, which can be the next row under load.
4. **Surrogate test.** The non-UTF-8 process test checks that no lone surrogate reaches the output, covering each of 0xff, 0xfe and 0xfd (today it checks only 0xff).
5. **README.**
   - `row-<n>`: n counts the rule rows that are kept (comments, the defaults row and ignored rows are not counted).
   - The cap sentence says bytes and matches goal 2.
6. **Version.** `__version__ = 0.41`.

## Non-goals

- Changing Tee_Logger. One `write()` per line belongs in the library; the cas side gets that suggestion.
- Writes that bypass `tl`: child processes' own output, and an uncaught thread exception's traceback on stderr. The daemon logs everything through `tl`, and the commands (`status`, `history`, `restore`) are single-threaded.
- Changing the text of any message, apart from the cut notice.

## Anti-goals

- A deadlock. A plain `Lock` would hang the first time the SIGTERM handler logs while the main thread is mid-line.
- Losing the caller's file and line in the log file. The wrapper adds one stack frame, so a caller depth of 0 or more is passed on one deeper.
- Slowing every log call. A short line passes the cap check without being encoded.

## Decisions (builder's calls, made here)

- **Where the lock lives.** It lives in a proxy, `LockedLogger`, that wraps each Tee_Logger the program assigns to `tl`: the module default, `run_daemon`'s and `run_command`'s. Tests that monkeypatch `rv.tl` with a fake keep working, because they bypass the proxy.
- **Where the byte cap applies.** The proxy cuts each line of a string message with `cut_line` just before the call. That one point covers every path, including TSVZ's messages, which reach `tl` through `teeLogger=tl`. `log_text`, `job_log` and `daemon_error_log` keep their own `cut_line` calls: their return values are what callers and tests compare.
- **Lone surrogates.** `cut_line` counts a lone surrogate as 3 bytes (`surrogatepass`), so a message that skipped `log_text` cannot make the cut raise.
- **Nameless start function.** The function a nameless row starts with comes from a helper, `nameless_start(rule_path, rule)`. Binding happens in a call, so it cannot come back, and a test can check it without a process.

## Left to the builder

Names of private helpers; how the proxy finds which methods take `callerStackDepth`; test file layout within `tests/`.
