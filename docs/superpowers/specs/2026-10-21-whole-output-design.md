# Whole output lines (0.42)

## Intent

0.41 made every line reverberator logs through `tl` reach the journal whole, so firewatcher sees every marker. Other code in the daemon process still writes to stdout and stderr itself. Under systemd, both go to one journal stream.

That code includes:
- multiCMD's prints when a command cannot start (EMFILE/EAGAIN under load);
- TSVZ's last-resort print;
- Tee_Logger 6.42's own cleanup and flush threads;
- a thread's uncaught-exception traceback, which `threading.excepthook` writes in several pieces.

Any of these can leave the stream mid-line, and a marker logged at that moment then sits mid-line, where the alert patterns (anchored at the start of a journal record) never see it. A traceback also prints exception text unescaped, so a file name in it could start a forged line.

This round closes those gaps for the daemon, without waiting for library releases. The user chose this approach ("whole-line streams") over targeted fixes only.

## Goals

1. **Whole-line streams.** In the daemon, `sys.stdout` and `sys.stderr` hold each thread's text until its line ends, then write the whole line with one write and a flush, holding `LOG_LOCK` (the same re-entrant lock `LockedLogger` holds).
   - So no line from any in-process writer, library code included, can land inside another, and every marker starts its own line.
   - All the libraries look up `sys.stdout`/`sys.stderr` at call time, so replacing them covers them.
2. **Thread tracebacks go through `tl`.** A thread's uncaught exception is logged through `tl` at error level, as text passed through `log_text`. It is escaped, continuation lines are indented, and it is cut to the byte limit.
   - The first line names the thread.
   - `SystemExit` in a thread stays silent, as Python's default hook keeps it.
   - If logging it raises, Python's own hook reports it instead, so nothing is lost silently.
3. **sysctl stays quiet.** The two sysctl calls (`getSysctlValues`, `setSysctlValues`) always run with `quiet=True`. Today they are `quiet=not self.debug`, so in verbose mode multiCMD echoes the child's output from a watcher thread character by character.
   - In verbose mode, the value read is logged through `tl` instead.
4. **README.** One sentence says that every line the daemon writes, its libraries' included, reaches the journal whole.
5. **Version.** 0.42, in `reverberator.py` and `pyproject.toml`.

## Non-goals

- Child processes writing straight to the inherited stdout/stderr. multiCMD gives its children pipes, and the daemon starts no other children with inherited output.
- The commands (`status`, `history`, `restore`). They are single-threaded and print prompts without a newline, so the streams are not replaced there.
- Changing the libraries. That is the cas side's work; it was sent the notes on 2026-10-21.
- `sys.excepthook` for the main thread. `main()` already catches what `run_daemon` raises, logs it through `tl` and logs the EXITING marker.

## Anti-goals

- **Losing output.**
  - A line part a thread has written without its newline is held, not dropped.
  - Held parts are written, each as its own line, when the daemon exits.
  - A held part longer than `LOG_LINE_LIMIT` characters is written out at once as its own line, so a writer that never ends its line cannot grow memory without bound.
- **Changing what the commands or the tests' in-process calls see.** The streams are replaced only on the daemon's console path in `main()`, not in `run_daemon()`, which tests call in-process.
- **A deadlock.** The streams take the same re-entrant `LOG_LOCK`. `LockedLogger` already holds that lock when Tee_Logger prints through them, and the SIGTERM handler logs from the main thread.
- **Breaking stream attributes.** `fileno()`, `isatty()`, `encoding`, `errors`, `buffer` and the rest come from the wrapped stream. Tee_Logger checks `isatty()`.

## Decisions (builder's calls, made here)

- **Names.**
  - `class WholeLineStream`, wrapping one text stream.
  - `install_daemon_output()` replaces both streams, registers the exit-time write of held parts, and sets `threading.excepthook`. Repeated calls change nothing.
  - `main()` calls it on the daemon path, just before `run_daemon()`.
- **Holding parts.** Held parts are kept per thread, keyed by the `threading.Thread` object, in a dict guarded by `LOG_LOCK`. An entry exists only while that thread has a part held.
- **`flush()`** flushes the wrapped stream and does not write held parts. Writing them would put a part mid-line, which is the problem this round fixes. `print(..., flush=True)` writes its newline before it flushes, so it is unaffected.
- **`writelines()`** goes through `write()`, so it cannot skip the holding.
- **Main thread.** A part the main thread holds when the SIGTERM handler logs from that same thread would join the handler's line. The main thread writes only whole lines through `tl` in the daemon, so this is accepted.

## Left to the builder

Private helper names, test file layout, and how a test child process installs the streams.
