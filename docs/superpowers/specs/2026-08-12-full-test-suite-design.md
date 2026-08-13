# Full test suite for reverberator

Date: 2026-08-12  
Status: approved for planning  
Scope: pytest suite under `tests/`, small hooks in `reverberator.py`, pytest config in `pyproject.toml`, `docTest.sh` as a wrapper

## Goals

- Behavior catalog is the success bar: every user-visible path below has tests.
- Design tests to hit as many branches as those paths reasonably contain. Line/branch coverage is a report, not a CI fail-the-build gate.
- Default `uv run --extra test pytest` runs the full **unprivileged** suite (unit + live inotify + process).
- Fast loop: `uv run --extra test pytest -m unit`.
- Privileged mount/unmount tests exist but skip unless root or `REVERB_PRIVILEGED=1`.
- Keep doctests in `reverberator.py`; pytest collects them.
- Do not split `reverberator.py`. Production changes are thin hooks only.

## Non-goals

- Coverage percentage as a merge gate; no `pytest-cov` requirement.
- Fake-filesystem libraries, injectable `findmnt` / `multiCMD` factories, or an INotify factory.
- `--test-mode` CLI flag (hooks are env + module globals).
- systemd unit tests, CoW reflink space-savings assertions, mid-`cp` byte-level pause/resume.
- Touching the repo `reverb_rule.tsv` from tests.
- Changing pending mtime-gate policy, attrib-through-symlink semantics, or `keep_one_complete_backup=False` referenced-V0 semantics. Tests document current behavior.

## Existing coverage to keep

- `tests/test_crash_safety.py`: incomplete version deletion, watcher init vs self-destruct, uncommitted backup requeue, empty-delta skip, symlink `cp_af` subpath, dir-delete tracking sets, `decrement_stepper` success and abort.
- `tests/test_backup_replay_ordering.py`: parent dirs before `cp`, prune/order/`prepare` replay, file-before-parent create regression.
- Doctests on helpers (`strip_*`, `as_folder_entry`, `slugify`, `bidict`, `get_args`, `check_fs_signature`, `change_events_to_backup_entries` happy paths, `is_subpath`, `format_bytes`, `hash_file`, `get_backup_limits_from_str`, empty `decrement_stepper`).

Migrate the two unittest files to pytest style when touching them; do not drop cases.

---

## 1. Architecture

The daemon stays a single module. Tests are a layered pytest suite.

### Layers (markers)

| Marker | Meaning | Default `pytest` |
|--------|---------|------------------|
| `unit` | In-process, temp dirs, no kernel watch, no subprocess | run |
| `inotify` | Real `inotify_simple` on a temp tree | run |
| `process` | Spawn `reverberator.py` CLI | run |
| `privileged` | Real bind-mount / unmount | collect, **skip** unless `os.geteuid() == 0` or env `REVERB_PRIVILEGED=1` |

`privileged` is test-side only. Production code does not read `REVERB_PRIVILEGED`.

Skip `inotify` and `process` on non-Linux (`sys.platform != "linux"`). This project already declares POSIX Linux.

### File layout

- `tests/conftest.py` — fixtures, autouse `GREEN_LIGHT` / poll restore, skip helpers
- `tests/harness.py` — vault on-disk helpers (`JobPaths`, committed versions, pending NSV, rule TSV, wait-for-version)
- `tests/test_crash_safety.py` — migrated existing cases
- `tests/test_backup_replay_ordering.py` — migrated existing cases
- `tests/test_helpers_cli.py` — string helpers, `get_args`, `bidict`, `hash_file`, `format_bytes`
- `tests/test_parse_rules.py` — rule TSV parsing and rewrite-to-tmp-copy
- `tests/test_events.py` — `change_events_to_backup_entries` branches beyond doctest
- `tests/test_vault.py` — incomplete `V*` cleanup, `get_vault_info`
- `tests/test_pending.py` — persist/load and mtime gate
- `tests/test_backup.py` — V0 complete vs referenced, `do_backup` / `do_reverb_backup` events, journal, abort
- `tests/test_delta.py` — `delta_generate_backup_entries` / `check_duplicate`
- `tests/test_retention.py` — `keep_n_versions`, size/inode limits, `decrement_stepper`
- `tests/test_inotify.py` — live watcher
- `tests/test_process.py` — CLI subprocess
- `tests/test_privileged.py` — mount/unmount

New tests are pytest functions (not `unittest.TestCase`).

### Pytest config

In `pyproject.toml`:

- `[project.optional-dependencies]` `test = ["pytest>=7"]` (pytest 7 still matches `requires-python >= 3.7`; pytest 8 needs 3.8+)
- `[tool.pytest.ini_options]`:
  - `testpaths = ["tests", "reverberator.py"]`
  - `addopts = ["--doctest-modules", "-ra"]`
  - `norecursedirs` includes `.venv`, `dist`, `.git`
  - `markers` for `unit`, `inotify`, `process`, `privileged`

Canonical command: `uv run --extra test pytest`. Fast loop: `uv run --extra test pytest -m unit`.

Each test module sets `pytestmark` to its layer (`unit`, `inotify`, `process`, or `privileged`) so `-m unit` does not collect watcher/CLI tests.

`docTest.sh` becomes a thin wrapper around `uv run --extra test pytest` so there is one runner. Doctests remain in `reverberator.py` and are collected by `--doctest-modules`.

---

## 2. Production hooks

Behavior is unchanged when env is unset. No new CLI flags.

### `POLL_WAIT_SECONDS`

- Module global, default `3`.
- Replace every hardcoded `3` used as a poll/wait/copy-wait timeout in watcher/backuper/backup:
  - `watcher`: `monitor_fs_flag.wait(3)`
  - `watchFolder`: `min(3, min_snapshot_delay_seconds)` cap on inotify `read` delay
  - `backuper`: `vault_fs_flag.wait(3)`, `monitor_fs_flag.wait(3)`, `to_process_flag.wait(3)`
  - `do_backup` / `do_reverb_backup`: `mcae.wait(timeout=3)` and `mcae.cleanup(timeout=3)`
- Do **not** change `signal_handler`’s `time.sleep(0.1)` or `MOVE_PAIR_TIMEOUT_SECONDS`.
- At import (and again at start of `main`, so a subprocess sees the env even if the module was already imported), read `REVERB_POLL_WAIT_SECONDS`. Parse as float. Invalid or missing → default `3`.
- In-process tests may assign `reverberator.POLL_WAIT_SECONDS` directly; the autouse fixture restores the previous value.

### `GREEN_LIGHT`

Protocol unchanged. Autouse pytest fixture: `GREEN_LIGHT.set()` before each in-process test and again after, so a test that clears it cannot poison the next. Process tests use a fresh interpreter and do not rely on this fixture.

### Not added

- INotify factory (live tests use the real class; unit tests monkeypatch `inotify_simple.INotify` / `initializeFolderWatchers` as today).
- Injectable `findmnt` / `multiCMD`.
- Making `tl` fixture-owned (process tests pass `--no_log` and `-ld` under tmp).

---

## 3. Harness and fixtures

`tests/harness.py` is the only place that encodes vault on-disk layout. Tests do not hand-roll content-file names.

### `JobPaths`

Temporary directory containing:

- `monitor/` — source tree
- `vault/` — vault root
- `job_name` — `job`
- `job_vault` — `vault/job_name`
- `rule_path` — tmp copy of a one-job TSV

Helpers:

- `write_rule(...)` — one job; **explicit** columns (not `auto`) so `parse_rules` does not rewrite signatures unexpectedly. Default: min snapshot `1`, max `86400`, FS signatures `N/A`, `keep_one_complete_backup` / `only_sync_attributes` as arguments. Tests that want `auto` or `_defaults_` say so.
- `seed_monitor(files_and_dirs)` — create files/dirs under `monitor/`
- `write_committed_version(n, tree, timestamp=...)` — `V{n}--{timestamp}/` plus matching `CONTENT_FILE_EXTENSION_NAME` sidecar (size/inode strings via existing `format_bytes` + `get_path_size` / `get_path_inodes`, same as production) and optional `current_version` symlink
- `write_incomplete_version(n, ...)` — `V*` directory, **no** content file
- `write_pending(events)` — `.reverberator_pending_transactions.nsv`
- `committed_versions()` — list of version dirs that have a content file
- `wait_for_committed_version(pred, timeout=10)` — poll until `pred` is true or fail with a message; used by process tests

### Fixtures (`conftest.py`)

- **autouse** `restore_runtime_globals`: save/restore `POLL_WAIT_SECONDS`; `GREEN_LIGHT.set()` before and after
- `job` → `JobPaths`
- `poll_fast`: set `POLL_WAIT_SECONDS` to `0.05` for the test
- `process_env`: copy `os.environ`, set `REVERB_POLL_WAIT_SECONDS=0.05`, `PYTHONUNBUFFERED=1`
- `run_reverberator(rule_path, extra_args=())`: `subprocess.Popen([sys.executable, path_to_reverberator.py, "--no_log", "-ld", tmp_log_dir, *extra_args, rule_path], env=process_env)`. Teardown: if the child is still alive, SIGTERM, wait 2s, then SIGKILL. Tests that need post-SIGTERM assertions send SIGTERM themselves and wait for exit; teardown is then a no-op. Capture stdout/stderr for assertion failures.

### Isolation

- One job per test; `TemporaryDirectory` cleaned up after.
- Never read or write repo `reverb_rule.tsv`.
- `parse_rules` may append rewritten rows: only against the tmp rule file.
- Hash (`xxhash`) and `cp -af` stay real.
- In-process tests `import reverberator` and call functions. Process tests must not share `GREEN_LIGHT` / `tl` with the child; the parent only watches the vault directory and the child’s return code.

---

## 4. Behavior catalog

Each area is a required test module (or section). Aim at real branches, not a single happy path. Existing crash-safety and replay-ordering cases count toward the catalog; do not duplicate them blindly.

### Helpers / CLI (`unit`) — `test_helpers_cli.py`

- `strip_suffix` / `strip_prefix` / `as_folder_entry`: doctests are sufficient; do not duplicate in pytest.
- `slugify`: dirty job names, unicode with `allow_unicode` on/off.
- `bidict`: set, overwrite, delete, inverse consistency.
- `is_subpath`: existing symlink false-positive stays in crash-safety file.
- `format_bytes` / `hash_file` (partial vs `full_hash=True`).
- `get_args`: defaults (`rule_path=reverb_rule.tsv`), `--journal`, `--threads` `0` / negative / positive, `--drop_sample_reverb_rule_file` parses True, `--verbose`. Do not call `main()` here; `--drop_sample` end-to-end lives in process tests.
- `check_fs_signature`: `N/A`, `auto`, empty (doctest); add a mismatch case with a fake signature string that cannot match (no mount required).

### Rules (`unit`) — `test_parse_rules.py`

Use tmp TSV only. Cover:

- Missing file → `SystemExit`
- Empty after parse → `SystemExit`
- Empty job name or monitor path → rule ignored
- Monitor path that does not exist → ignored
- Vault path that is a subpath of monitor → ignored
- Dirty job name slugified; dirty monitor path realpathed; rule file appended when updated
- `_defaults_` / `auto` / `none` fills for snapshot times, booleans, keep N, size limit
- `N/A` signatures left as-is (no `get_fs_signatures` requirement)
- `auto` signatures: if `get_fs_signatures` returns a value, rule updated; if empty, stays `auto` for this run (monkeypatch `get_fs_signatures` for the empty branch)

### Events (`unit`) — `test_events.py`

`change_events_to_backup_entries` branches **not** fully covered by doctest:

- Chain moves (A→B then B→C) → one move with original source
- Virgin move (no `moved_from`) → create
- Delete immediately before a move-from → delete ignored
- Attrib then later move from that path → dest escalated off attrib
- Create then later delete on same path → both dropped
- Create then later modify → create
- Directory paths stored with trailing `/`
- `self_destruct` → empty entries, no vault ops
- `backup_entries_to_change_events` round-trip preserves `is_dir`, `event`, `moved_from` for moves
- Keep prune / order / `prepare` tests in the replay-ordering file

### Vault (`unit`) — `test_vault.py`

- Incomplete `V*` deleted; committed + content file kept (`remove_incomplete_vault_versions`, `get_vault_info` orphan path)
- `get_vault_info` indexes only versions with content files; `recalculate=True` refreshes size/inode
- Content-file naming matches production (`format_bytes` + extension)

### Pending (`unit`) — `test_pending.py`

Mtime gate (do **not** sleep 1s+; use `os.utime`):

- Resume: pending file mtime is at least 1 second **newer** than the newest monitor-tree mtime → events loaded, pending file removed
- Discard: monitor mtime is not older than `pending_mtime - 1` → pending removed, deque unchanged, return false
- Persist: `persist_pending_transactions` writes header + rows; empty deque writes nothing
- Corrupt pending file → cleared, file removed, no crash

### Backup (`unit`) — `test_backup.py`

- Empty vault + `keep_one_complete_backup=True` → V0 is a real copy (files are not symlinks into monitor)
- Empty vault + `keep_one_complete_backup=False` → V0 is a referenced copy (symlinks into monitor) — current intentional behavior
- Non-empty vault + empty entries after delta → **no** new `V*`, committed `True` (existing empty-delta test)
- `GREEN_LIGHT` cleared before commit → no content file, no `current_version` update, committed `False` (existing)
- `do_reverb_backup`: create / modify / delete / attrib / move, file and directory; `only_sync_attributes` True vs False on attrib
- Delete barrier: delete then create overlapping path in one batch does not lose the create (replay-ordering + extra if needed)
- Move `os.rename` failure → copy + delete fallback; dest exists
- Directory delete updates tracking sets without mutating a set during iteration (existing)
- `log_journal=True` creates `journal.tsv` under the job vault with start/end rows

### Delta (`unit`) — `test_delta.py`

- Unchanged file vs latest version → not added to entries (`check_duplicate` / hash)
- Changed content → modify (or create if missing in latest)
- New file / new dir / deleted file relative to latest tracking sets
- `delta_generate_backup_entries` mutates the passed `backup_entries` dict (assert resulting keys)

### Retention (`unit`) — `test_retention.py`

- `decrement_stepper`: success materializes symlink into remaining version and removes oldest; abort keeps oldest and restores dict (existing)
- Empty dict / single version → `(0, 0)` (doctest)
- `do_backup` with `keep_n_versions=2` and two committed versions (V0 real file, V1 symlink to that file, as in the existing stepper fixture) → stepper runs before creating V2
- Size limit `'1'` (1 byte via `format_bytes`) against a larger vault → `decrement_stepper` is attempted; if it returns `(0, 0)`, the loop stops and **current code still creates the next version**. Assert that; do not add a new “fail if over limit” policy
- Inode limit `'i1'` the same way
- `get_backup_limits_from_str` stricter (smaller) of multiple limits stays doctest-only; no extra `do_backup` case required

### Inotify (`inotify`) — `test_inotify.py`

Real `watchFolder` (or `watcher` with `monitor_fs_flag` already set) on `job.monitor`, `POLL_WAIT_SECONDS=0.05`, `min_snapshot_delay_seconds=0`:

- File create / modify / delete / attrib appear as `ChangeEvent`s in `to_process`
- File rename → `move` with `moved_from` when the kernel delivers cookies; if the kernel splits into delete+create, assert coalescer still yields a vault-correct entry (create or move), not a lost file
- Directory `mkdir -p` → recursive watches (child file create is seen)
- Queue overflow: try to fill the inotify queue; if this kernel cannot overflow, **skip** that test
- Init failure and fake `UNMOUNT` self-destruct remain **unit** monkeypatches in crash-safety (do not require a real unmount here)

Sync: wait until `to_process` contains the expected event (poll with timeout), not a lone `sleep(1)`.

### Process (`process`) — `test_process.py`

Spawn CLI with `run_reverberator`, tmp rule (`N/A` signatures, min snapshot `1`), `--no_log`, temp `-ld`.

- Start on a seeded monitor → committed V0 appears within 10s
- After V0, write a new file, wait for a second committed version containing that file
- SIGTERM once (first handler path): process exits; if `to_process` had work, pending file may exist — assert no incomplete version is **committed** (no content file / `current_version` not pointing at a tree without content). Incomplete `V*` dirs may remain until next start
- Restart on the same vault: leftover incomplete `V*` directories are deleted; last committed version remains
- Pending resume vs discard: use `os.utime` on monitor vs pending file, then start; resume loads events, discard falls through to delta
- `--drop_sample_reverb_rule_file` writes `SAMPLE_REVERB_RULE_FILE` to `RULE_PATH` and exits 0 without starting watchers

### Privileged (`privileged`) — `test_privileged.py`

Skip unless root or `REVERB_PRIVILEGED=1`.

- Bind-mount a temp dir onto `monitor` (or mount a tmpfs), start watcher or process, unmount, assert watcher returns `self_destruct` / `monitor_fs_flag` cleared and vault history is **not** deleted as if the tree were a normal recursive delete
- Failure inside a privileged test (mount succeeded) is a real failure, not a skip

---

## 5. Error handling, timing, and flakes

- `run_reverberator` teardown: SIGTERM, wait 2s, SIGKILL. Do not leak children.
- `wait_for_committed_version` timeout **10s**. On timeout, fail with child’s stdout/stderr (process) or vault listing (in-process). Do not hang pytest.
- Do not add a pytest-timeout plugin in this work. Timeouts are the 10s wait helper and Popen teardown.
- Process tests send **one** SIGTERM. Double-Ctrl-C / `sys.exit(1)` is a unit test of `signal_handler` only.
- Inotify: poll `to_process` / content files for readiness. Overflow test skips if the queue cannot be filled.
- Privileged: skip (not fail) when the gate is closed.
- Do not assert `Tee_Logger` text formatting unless the assertion is “this error path ran.”
- Pending mtime-gate tests use `os.utime`, not wall-clock sleeps of 1s+.

---

## 6. Data flow (how a test runs)

**Unit backup test:** fixture `job` + `poll_fast` → seed monitor and/or `write_committed_version` → call `do_backup` / `do_reverb_backup` / `change_events_to_backup_entries` → assert vault tree, content file presence, tracking sets, `GREEN_LIGHT`.

**Inotify test:** `job` + `poll_fast` + thread running `watchFolder` → mutate `monitor/` → wait for `ChangeEvent` → stop via `GREEN_LIGHT.clear()`.

**Process test:** `write_rule` + `seed_monitor` → `run_reverberator` with `process_env` → `wait_for_committed_version` → mutate monitor → wait again → SIGTERM on teardown.

**Privileged test:** same as inotify or process, plus bind-mount/unmount around the monitor path.

---

## 7. Implementation notes (for the plan, not extra product scope)

Suggested order: hooks + pytest config + harness/fixtures → migrate existing tests → unit modules (helpers, rules, events, vault, pending, backup, delta, retention) → inotify → process → privileged.

`parse_rules` calling `sys.exit` is tested with `pytest.raises(SystemExit)` or by expecting the ignored-rule continue paths, not by running a full `main()` except drop-sample and process e2e.

`main()` non-root warning stays a warning; tests do not require root except `test_privileged.py`.
