# Status, History and Restore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `status`, `history` and `restore` subcommands to `reverberator.py`, the daemon status files and restore
lock they rely on, and fix vault links broken by moves to another folder depth.

**Architecture:** Everything stays in the single module. One rule (`chain_link_target`) decides where a vault link
points, and the daemon (moves, retention, `read_vault_record`) and the commands share it. The daemon publishes per-job
state as JSON files in a state folder (`/run/reverberator` by default) and postpones pruning while a restore holds a
shared `flock` there. The commands read the rule file read-only, list versions without walking them, stream change
lists, and copy with the existing checked `cp -a` machinery.

**Tech Stack:** Python ≥3.8, stdlib (`argparse`, `fcntl`, `json`), multiCMD `AsyncExecutor`, TSVZ (writing only),
pytest with doctests.

**Spec:** `docs/superpowers/specs/2026-10-19-history-restore-status-design.md`

## Global Constraints

- Single module `reverberator.py`: tabs, the file's naming mix and comment density, doctests on small pure helpers.
- `requires-python >=3.8`; no new dependencies. Code must run on the service venv's libraries (Tee_Logger 6.40,
  multiCMD 1.51, TSVZ 3.39, xxhash 3.8.1, pathspec 1.1.1) and on a fresh resolve.
- Run tests from the worktree root as `.venv/bin/python -m pytest …` (the `pytest` launcher has a stale shebang).
  Task 9 also runs the suite with `/mnt/optane/work/reverberator/.venv/bin/python -m pytest -q` from the worktree root.
- The daemon's command line is unchanged: `reverberator.py [options] RULE_PATH` still starts the daemon.
- The commands never write to a vault, never open a manifest, and never write the rule file.
- Tests never touch `/run`, `/etc` or any vault under `/mnt`: the state folder comes from `REVERB_STATE_DIR` or
  `--state_dir`, set to a tmp folder by the test fixtures.
- Exit codes for the commands: `0` everything shown/restored, `EXIT_COMMAND_FAILED = 1` anything failed,
  `EXIT_USAGE = 2` usage errors (unknown path, no version chosen without a terminal, refused destination).
- In-place moved-aside name: `<name>.before-restore-<YYYY-MM-DD_HH-MM-SS>`. Resume marker file name:
  `.reverberator-restore`. Status files: `daemon.json`, `job-<job name>.json`. Lock file: `job-<job name>.restore.lock`.
- Version 0.39.

## Review Focus

- A folder whose name is a prefix of a sibling (`proj` vs `project`): history counts and job lookup must split on `/`
  boundaries only. Tests: Task 2 `test_find_job_longest_prefix`, Task 6 `test_folder_history_boundary`.
- File names with spaces, non-ASCII, newlines or TSVZ's escape tokens (`<LF>`, `<sep>`): change lists must read back
  exactly and restores must copy them. Tests: Task 2 `test_iter_change_list_round_trips_names`, Task 7
  `test_restore_names_with_spaces_and_unicode`.
- A destination inside the vault (`restore … /mnt/jank/klein/x`) would write into the vault: refused. Test: Task 7
  `test_restore_refuses_destination_inside_vault`.
- The job root, or a path typed with a trailing slash, as the history/restore path. Tests: Task 2
  `test_find_job_longest_prefix`, Task 6 `test_history_root_and_trailing_slash`.
- A version folder removed while a restore reads it (an old daemon without the lock, or by hand): the restore reports
  the missing entries and exits 1, never a traceback. Test: Task 7 `test_restore_reports_a_version_removed_mid_restore`.

---

## File map

- `reverberator.py` — all code. New sections: chain-link rule (near `is_chained_link`), command read layer and
  commands (a new `#%% ---- Commands ----` section before `if __name__`), status board and restore lock (near
  `JobControl`).
- `tests/harness.py` — gains `run_backup(job, entries=None, **kwargs)` and `latest_version(job)`, lifted from
  `tests/test_manifest.py` (which then imports them), plus `move_entry`, `event_entry` helpers below.
- `tests/conftest.py` — state folder fixtures.
- New tests: `tests/test_chain_links.py`, `tests/test_command_reading.py`, `tests/test_status_files.py`,
  `tests/test_status_command.py`, `tests/test_restore_lock.py`, `tests/test_history.py`, `tests/test_restore.py`,
  `tests/test_restore_in_place.py`.
- `README.md`, `pyproject.toml` — Task 9.

---

### Task 1: One chain-link rule; moves keep links resolving; retention follows broken links

**Files:**
- Modify: `reverberator.py` — `is_chained_link`/`read_vault_record` area (~4738-4790), `do_reverb_backup` move branch
  (~5571-5600), `decrement_stepper` (~5301-5425), `VaultManifest.move_tree` docstring (~4631)
- Modify: `tests/harness.py`, `tests/test_manifest.py`
- Create: `tests/test_chain_links.py`

**Interfaces:**
- Produces:
  - `chain_link_target(job_vault:str, link_text:str) -> str | None` — for relative text of the form
    `../`(one or more) + `<version folder>/<rel>` where `vault_version_number(<version folder>)` is not None and
    `<rel>` is non-empty, returns `os.path.join(job_vault, <version folder>, <rel>)`; otherwise None. Location of the
    link does not matter.
  - `next_hop(job_vault:str, link_path:str, link_text:str) -> str` — `chain_link_target(...)`, else
    `os.path.abspath(os.path.join(os.path.dirname(link_path), link_text))`.
  - `retarget_chain_link(job_vault:str, link_path:str) -> bool` — if the link at `link_path` is a chain link (by
    `chain_link_target`), rewrite it to `os.path.relpath(target, os.path.dirname(link_path))` when that differs from
    its text; True if rewritten. Replace via a temp name in the same folder and `os.replace`.
  - `retarget_moved_links(job_vault:str, moved_path:str) -> int` — `retarget_chain_link` on `moved_path` if it is a
    link, or on every link under it if it is a folder (`iter_tree_entries` yields links as files); returns how many
    were rewritten.
  - harness: `run_backup(job, entries=None, **kwargs) -> list` (as `test_manifest.backup`, kwargs override
    `do_backup` keywords such as `keep_n_versions`), `latest_version(job)`,
    `event_entry(job, rel, event, source_rel=None) -> tuple` returning
    `(abs_path, rv.BackupEntryValues(datetime.now().isoformat(), event, abs_source_or_None))` with a trailing `/`
    kept on folder rels.

- [ ] **Step 1: Lift `backup`/`latest_version` from `tests/test_manifest.py` into `tests/harness.py` as `run_backup`/`latest_version`, add `event_entry`, and point `test_manifest.py` at them. Run `.venv/bin/python -m pytest tests/test_manifest.py -q` → all pass.**

- [ ] **Step 2: Write the failing tests in `tests/test_chain_links.py`**

```python
# all build vaults with run_backup; T = a fixed timestamp string 'YYYY-MM-DD_HH-MM-SS_-0800'
def test_file_moved_deeper_keeps_its_link(job):
	seed_monitor(job, {'a/x.txt': 'x', 'deep/er/keep.txt': 'k'})
	v0 = run_backup(job)[0]
	os.rename(f'{job.monitor}/a/x.txt', f'{job.monitor}/deep/er/x.txt')
	v1 = run_backup(job, OrderedDict([event_entry(job, 'deep/er/x.txt', 'move', 'a/x.txt')]))[-1]
	moved = os.path.join(v1, 'deep/er/x.txt')
	assert os.path.islink(moved) and open(moved).read() == 'x'
	assert os.path.realpath(moved) == os.path.realpath(os.path.join(v0, 'a/x.txt'))

def test_file_moved_shallower_keeps_its_link(job): ...       # deep/er/x.txt -> x.txt, same three assertions

def test_folder_moved_to_another_depth_keeps_every_link(job):
	# sub/x.txt and sub/inner/y.txt, moved to deep/er/sub/ (V1), then back to top/ (V2, shallower): each version's
	# copies read back and are links into V0, with no full comparison in between
	...

def test_retarget_moved_links_keeps_user_symlinks(tmp_path):
	# hand-built: V0--T/a/x real; V1--T/deep/er/sub/x -> '../../V0--T/a/x' (broken); V1--T/deep/er/sub/u -> 'x'
	assert rv.retarget_moved_links(job_vault, f'{job_vault}/V1--T/deep/er/sub') == 1
	assert os.readlink(f'{job_vault}/V1--T/deep/er/sub/u') == 'x'
	assert open(f'{job_vault}/V1--T/deep/er/sub/x').read() == 'x'

def test_same_depth_move_leaves_the_link_text_alone(job):
	# a/x.txt -> b/x.txt: the link text in the new version equals the text the old place had before the move
	...

def test_read_vault_record_reads_a_link_broken_by_an_old_move(job):
	# hand-built V0 real a/x, V1 deep/er/x -> '../../V0--T/a/x'; record kind 'f' with V0's size
	assert rv.read_vault_record(v1, 'deep/er/x', job.monitor).kind == 'f'

def test_pruning_materialises_a_link_broken_by_an_old_move(job):
	# write_committed_version V0 {'a/x': 'x'}, V1 {'deep/er/': None} + symlink '../../V0--T/a/x' at V1/deep/er/x
	rv.decrement_stepper(rv.get_vault_info(job.job_vault).vault_info_dict)
	assert not os.path.exists(v0)
	assert not os.path.islink(f'{v1}/deep/er/x') and open(f'{v1}/deep/er/x').read() == 'x'
```

Doctests on `chain_link_target` (job vault `/v/j`, version `V3--2021-01-01_00-00-00_-0800`):
`'../V3--…/a/x'` and `'../../V3--…/a/x'` → `'/v/j/V3--…/a/x'`; `'/abs/V3--…/x'`, `'lib/x'`, `'../V3--…'`,
`'../notaversion/x'` → None.

- [ ] **Step 3: Update `tests/test_manifest.py::test_folder_moved_to_another_depth_is_copied_again`** — rename to
  `test_folder_moved_to_another_depth_needs_no_copy`; after the move backup, delta generation yields no entries
  (`entries == {}`), and the latest version's `deep/er/sub/x.txt` is a link reading `'x'`.

- [ ] **Step 4: Run `.venv/bin/python -m pytest tests/test_chain_links.py tests/test_manifest.py -q`** → new tests FAIL (no `chain_link_target`; moved links dangle).

- [ ] **Step 5: Implement** the four helpers; in the move branch, after a successful `os.rename`, call
  `retarget_moved_links(os.path.dirname(backup_folder), link_target_backup_real_path)` when
  `rel.rstrip('/').count('/')` differs between source and target rel (before the `copy_file_meta` check); in
  `read_vault_record` and `decrement_stepper` compute the hop with `next_hop` instead of `abspath(join(...))`
  (`decrement_stepper`'s job vault is `os.path.dirname(referenceVaultPath)`). Update the `move_tree` docstring: moved
  links are re-targeted; the rows stay unverified so the next comparison reads them once.

- [ ] **Step 6: Run `.venv/bin/python -m pytest -q`** → whole suite passes (doctests included).

- [ ] **Step 7: Commit** — `git commit -m "Keep vault links resolving when a move changes folder depth, and follow links an older daemon broke when reading or pruning."`

---

### Task 2: Read layer for the commands

**Files:**
- Modify: `reverberator.py` — `parse_rules` (~1291), new Commands section
- Create: `tests/test_command_reading.py`

**Interfaces:**
- Consumes: `chain_link_target`, `next_hop`, `is_chained_link` (Task 1).
- Produces:
  - `EXIT_COMMAND_FAILED = 1`, `EXIT_USAGE = 2`; `class CommandError(Exception)` with `.message:str`, `.code:int`
    (default `EXIT_USAGE`); `class RuleFileError(Exception)`.
  - `parse_rules(rule_file:str, read_only:bool = False) -> list` — read-only: no header upgrade, no `makedirs`, no
    signature lookups (cells kept as written), no write-back, and `RuleFileError` instead of `sys.exit` for a missing or
    empty file. Default behaviour unchanged.
  - `job_vault_path(rule:ReverbRule) -> str` = `os.path.join(rule.vault_path, rule.job_name)`.
  - `find_job(rules:list, path:str, job_name:str = None) -> tuple` → `(rule, rel)`; `rel` is `''` for the root, no
    leading or trailing `/`. Path: `os.path.abspath` (relative to cwd); with `job_name`, a relative path is relative to
    that job's monitored path. Longest monitored-path prefix on `/` boundaries wins. No match →
    `CommandError` naming every job's monitored path; unknown `job_name` → `CommandError` naming the jobs.
  - `KeptVersion = namedtuple('KeptVersion', ['number', 'path', 'name', 'timestamp', 'size', 'inodes', 'change_list'])`
  - `parse_change_list_name(name:str)` → `(number, folder_name, timestamp, size, inodes)` or None — same parsing as
    `get_vault_info` (which may be switched to call it).
  - `list_versions(job_vault:str) -> list` of `KeptVersion`, ascending; a folder without a change list, or a change
    list without its folder, is skipped; nothing is deleted or renamed. Missing `job_vault` → `[]`.
  - `ResolvedEntry = namedtuple('ResolvedEntry', ['kind', 'path', 'detail'])`, kind one of `'file'`, `'folder'`,
    `'symlink'` (a user symlink; `path` is that link), `'dangling'`, `'referenced'`, `'missing'`.
  - `resolve_version_entry(job_vault:str, version_path:str, rel:str, monitor_path:str) -> ResolvedEntry` — follows
    chain links hop by hop (`next_hop` + `is_chained_link`) up to `MAX_CHAINED_LINKS`; an absolute link equal to
    `os.path.join(monitor_path, <rel at that hop>)` is `'referenced'`; a missing hop or too many hops is `'dangling'`
    with `detail` saying which.
  - `ChangeRow = namedtuple('ChangeRow', ['path', 'iso_time', 'event', 'source_path'])`;
    `iter_change_list(path:str)` yields `ChangeRow` line by line, never loading the file; `source_path` `'None'` or
    empty → None.
  - `unescape_change_list_field(text:str) -> str` — TSVZ 3.39's inverse escaping, done locally in one regex pass:
    `</sep/>`→`<sep>`, `</LF/>`→`<LF>`, `<sep>`→`'\0'`, `<LF>`→`'\n'`. No trailing-space stripping.

- [ ] **Step 1: Write the failing tests**

```python
def test_read_only_parse_leaves_the_rule_file_unchanged(job):
	# an 11-column rule file (header without Skip List File), signatures 'auto', blank keep_n_versions, vault missing
	before = open(rule, 'rb').read()
	rules = rv.parse_rules(rule, read_only=True)
	assert open(rule, 'rb').read() == before
	assert rules[0].mon_fs_signature == 'auto' and rules[0].skip_list_file == ''
	assert not os.path.exists(missing_vault)

def test_read_only_parse_raises_for_a_missing_file(tmp_path):
	with pytest.raises(rv.RuleFileError): rv.parse_rules(str(tmp_path / 'none.tsv'), read_only=True)

def test_list_versions_is_read_only(job):
	# committed V0, V1; orphan folder V2 without change list; stray change list for V9 without folder
	assert [v.number for v in rv.list_versions(job.job_vault)] == [0, 1]
	assert os.path.isdir(orphan) and os.path.isfile(stray)

def test_resolve_follows_chains(job): ...            # V2 -> V1 -> V0 real: kind 'file', path V0's copy
def test_resolve_dangling_chain(job): ...             # target version folder removed: 'dangling'
def test_resolve_user_symlink(job): ...               # 'lib/x' backed up as a link: 'symlink', path is that link
def test_resolve_referenced_link(job): ...            # absolute link to monitor/rel: 'referenced'
def test_resolve_chain_loop(job): ...                 # V1/a -> ../V2--T/a, V2/a -> ../V1--T/a: 'dangling'
def test_resolve_link_broken_by_an_old_move(job): ... # text from another depth: 'file', V0's copy

def test_iter_change_list_round_trips_names(tmp_path):
	names = ['/m/a b', '/m/café', '/m/new\nline', '/m/x<LF>y', '/m/x<sep>y', '/m/folder/']
	TSVZ.appendLinesTabularFile(path, [[n, 't', 'create', 'None'] for n in names], header=['path'] + rv.BACKUP_ENTRY_VALUES_HEADER, createIfNotExist=True, verifyHeader=True, strict=False)
	assert [row.path for row in rv.iter_change_list(path)] == names
	assert all(row.source_path is None for row in rv.iter_change_list(path))

def test_find_job_longest_prefix(tmp_path, monkeypatch):
	# jobs monitoring /m and /m/sub
	assert find('/m/sub/x') == ('sub', 'x')
	assert find('/m/subway/x') == ('top', 'subway/x')
	assert find('/m/sub/') == ('sub', '') and find('/m/sub') == ('sub', '')
	monkeypatch.chdir('/m/sub'); assert find('x') == ('sub', 'x')
	assert rv.find_job(rules, 'x', job_name='top')[1] == 'x'
	with pytest.raises(rv.CommandError) as e: rv.find_job(rules, '/elsewhere')
	assert e.value.code == rv.EXIT_USAGE and '/m/sub' in e.value.message
```

Use real folders under `tmp_path` for `/m` and `/m/sub`; build rules with `rv.ReverbRule(*rule_row(job))`.

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_command_reading.py -q`** → FAIL (names undefined).
- [ ] **Step 3: Implement the interfaces above.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Read rules, versions, vault links and change lists for the commands without writing anything."`

---

### Task 3: Daemon status files

**Files:**
- Modify: `reverberator.py` — `JobControl` (~563), `wait_for_path` (~721), `run_job` (~786), `MonitorGate.resolve`,
  `run_daemon` (~967)
- Modify: `tests/conftest.py`
- Create: `tests/test_status_files.py`

**Interfaces:**
- Produces:
  - `DEFAULT_STATE_DIR = '/run/reverberator'`; `state_dir_path(override:str = None) -> str` — override, else
    `$REVERB_STATE_DIR`, else the default.
  - `process_start_ticks(pid:int) -> int | None` — field 22 of `/proc/<pid>/stat` (split after the last `)`); None if
    unreadable.
  - `class StatusBoard` — `__init__(self, state_dir:str, rule_path:str)` creates the folder and writes `daemon.json`
    `{"pid", "start_ticks", "version", "started_at", "rule_path"}`; `write_job(self, job_name:str, record:dict)` writes
    `job-<job_name>.json`. Writes are atomic (temp file in the folder + `os.replace`); an `OSError` is logged once per
    board and swallowed.
  - `STATUS_BOARD = None` (module global), set in `run_daemon` right after the `--drop_sample_reverb_rule_file` branch
    to `StatusBoard(state_dir_path(), os.path.abspath(args.rule_path))`, inside a try that logs and leaves None.
  - `JobControl` gains: `set_state(self, state:str, detail:str = '', retry_at:float = None, failures:int = 0)`;
    `begin_wait(self, path:str, what:str) -> object`; `end_wait(self, token)`; `mark_committed()` also records
    `last_success = time.time()`. Each change publishes
    `{"job", "state", "detail", "since", "retry_at", "failures", "last_success", "updated"}` (times are epoch seconds)
    through `STATUS_BOARD.write_job` when it is set. While any wait is active the published state is `'waiting'` with
    the oldest wait's `f'{path}: {what}'` and its start as `since`; otherwise the state last set.
  - States: `'starting'` (`run_job`, each attempt), `'running'` (`run_job`, after `start_attempt` returned with no
    failure), `'retrying'` (before the retry delay: reason, `retry_at = time.time() + delay`, failures in a row),
    `'stopped'` (permanent: reason). `wait_for_path` (when `job` is not None) and `MonitorGate.resolve` call
    `begin_wait` once the path is not ready at the first check and `end_wait` in a `finally`.
- conftest: an autouse fixture sets `REVERB_STATE_DIR` to `tmp_path / 'state'` (monkeypatch.setenv) and restores
  `rv.STATUS_BOARD = None` after each test; `process_env` sets `REVERB_STATE_DIR` to the same folder.

- [ ] **Step 1: Write the failing tests**

```python
def test_status_board_writes_the_daemon_record(tmp_path):
	rv.StatusBoard(str(tmp_path / 's'), '/etc/r.tsv')
	record = json.load(open(tmp_path / 's' / 'daemon.json'))
	assert record['pid'] == os.getpid() and record['start_ticks'] == rv.process_start_ticks(os.getpid())
	assert record['version'] == rv.__version__ and record['rule_path'] == '/etc/r.tsv'

def test_status_board_never_raises(tmp_path):
	(tmp_path / 'file').write_text('x')
	board = rv.StatusBoard(str(tmp_path / 'file'), '/r.tsv'); board.write_job('j', {'state': 'running'})

def test_waits_publish_waiting_until_the_last_ends(tmp_path, board):
	job = rv.JobControl('j'); job.start_attempt(); job.set_state('running')
	a = job.begin_wait('/v', 'vault filesystem not ready'); b = job.begin_wait('/m', 'monitored filesystem not ready')
	job.end_wait(a); assert read_job('j')['state'] == 'waiting' and read_job('j')['detail'].startswith('/m')
	job.end_wait(b); assert read_job('j')['state'] == 'running'

def test_wait_for_path_reports_waiting(tmp_path, board, poll_fast): ...   # missing path: 'waiting' with the path; then created and flag set: 'running'
def test_run_job_publishes_retrying_then_stopped(board, monkeypatch, poll_fast): ...  # use test_jobs._attempts-style script: failure then permanent failure; record 'retrying' (failures 1, retry_at > now) then 'stopped' with the reason
def test_mark_committed_records_last_success(board): ...

@pytest.mark.process
def test_daemon_writes_status_files(job, run_reverberator, tmp_path):
	seed_monitor(job, {'a.txt': 'a'}); write_rule(job); run_reverberator(job.rule_path)
	wait_for_committed_count(job, 1)
	wait_until(lambda: (read_job('job') or {}).get('last_success'))
	assert read_daemon()['rule_path'] == os.path.abspath(job.rule_path) and read_job('job')['state'] == 'running'
```

`board` fixture: `rv.STATUS_BOARD = rv.StatusBoard(str(tmp_path / 'state'), '/r.tsv')`; `read_job`/`read_daemon` read
the JSON (None when missing).

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_status_files.py -q`** → FAIL.
- [ ] **Step 3: Implement the interfaces above.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes, and no file appears under `/run/reverberator` from the tests (`ls /run/reverberator` before and after shows the same).
- [ ] **Step 5: Commit** — `"Publish each job's state and the daemon's identity as status files."`

---

### Task 4: Command dispatch and `status`

**Files:**
- Modify: `reverberator.py` — `main` (~946), Commands section
- Create: `tests/test_status_command.py`

**Interfaces:**
- Consumes: Task 2 read layer, Task 3 status files.
- Produces:
  - `COMMANDS = ('status', 'history', 'restore')`; `main(argv:list = None)` — `argv` defaults to `sys.argv[1:]`; when
    `argv[0]` is a command, `sys.exit(run_command(argv))`; otherwise the daemon exactly as today.
  - `get_command_args(argv:list) -> argparse.Namespace` — subparsers; every command takes `--rule PATH`,
    `--state_dir DIR`; `history` and `restore` take `path`, `--job NAME`; `history --files`; `restore [dest]`,
    `--version N` (int), `--at TIME`, `--in-place`, `--threads N` (default `os.cpu_count()`), `--yes`.
  - `run_command(argv:list) -> int` — sets a quiet `tl` (`noLog=True, suppressPrintout=True`) so library logging
    stays off the output; `CommandError` → message on stderr, its code; `KeyboardInterrupt` → `EXIT_COMMAND_FAILED`.
  - `DaemonStatus = namedtuple('DaemonStatus', ['record', 'alive', 'jobs'])`; `read_status(state_dir:str) -> DaemonStatus`
    — `alive` only when the recorded pid's `process_start_ticks` equals the recorded `start_ticks`; unreadable or
    malformed files read as missing.
  - `command_rule_path(args, status:DaemonStatus) -> str` — `args.rule`, else `status.record['rule_path']` (live or
    stale), else `CommandError` asking for `--rule`.
  - `VaultNumbers = namedtuple('VaultNumbers', ['present', 'versions', 'size', 'inodes', 'size_limit', 'inode_limit', 'keep_n'])`;
    `vault_numbers(rule:ReverbRule) -> VaultNumbers` — sizes summed from `list_versions`; limits from
    `get_backup_limits_from_str(rule.backup_size_limit, *get_path_fs_info(rule.vault_path))`; `keep_n` from the rule
    (0 when not a number). `present` False when the job vault folder is missing.
  - `format_status(status:DaemonStatus, rules:list, rule_path:str) -> str`; `status_command(args) -> int` (always 0
    unless a `CommandError`).
- Output (layout per the spec's "Output shapes"; these phrases are pinned by tests): header `reverberator <version>,
  running since <local time> (pid <pid>), rules <path>` or `reverberator is not running (last started <time>)` or
  `reverberator is not running`; per job a state phrase: `running`, `waiting for disk since <HH:MM>: <detail>`,
  `retrying at <HH:MM> after <n> failed attempts: <reason>`, `stopped: <reason>`, `starting`, or `unknown`; prefixed
  `last known: ` when the daemon is not alive; then `last backup <time> (V<n>)` or `no versions yet`;
  `<n> versions (limit <k>), oldest V<n> <time>` (`no limit` when 0); `vault <size> / limit <limit>, <inodes> inodes
  / limit <limit>`; `vault not mounted: <vault path>` when the vault path is missing or empty.

- [ ] **Step 1: Write the failing tests**

```python
def test_main_dispatches_commands_and_keeps_the_daemon_argv(monkeypatch):
	calls = []
	monkeypatch.setattr(rv, 'run_command', lambda argv: calls.append(('cmd', argv)) or 0)
	monkeypatch.setattr(rv, 'run_daemon', lambda: calls.append(('daemon',)))
	with pytest.raises(SystemExit): rv.main(['status'])
	rv.main(['-t', '6', 'rule.tsv'])
	assert calls == [('cmd', ['status']), ('daemon',)]

def test_status_with_a_live_daemon(job, tmp_path, capsys): ...      # daemon.json with own pid/start_ticks, job 'running', V0+V1: exit 0; 'running since', 'running', 'last backup', '(V1)', '2 versions'
def test_status_after_the_daemon_died(job, tmp_path, capsys): ...    # pid of a finished subprocess: 'is not running' and 'last known: running'
def test_status_with_a_reused_pid(job, tmp_path, capsys): ...        # own pid, start_ticks + 1: 'is not running'
def test_status_state_phrases(job, tmp_path, capsys): ...            # retrying / waiting / stopped records -> the pinned phrases
def test_status_vault_not_mounted(job, tmp_path, capsys): ...        # vault path removed: 'vault not mounted: <vault>'
def test_status_numbers_match_the_vault(job, tmp_path): ...          # vault_numbers sizes == sum of list_versions sizes; limits == get_backup_limits_from_str on statvfs
def test_status_needs_a_rule_without_a_record(tmp_path, capsys): ... # no daemon.json, no --rule: exit 2, '--rule' on stderr
def test_status_ignores_malformed_files(job, tmp_path, capsys): ...  # garbage job file: 'unknown', exit 0
def test_status_writes_nothing(job, tmp_path): ...                   # rule bytes and vault listing (lstat) unchanged

@pytest.mark.process
def test_status_runs_as_a_subprocess(job, tmp_path): ...             # [sys.executable, reverberator_script(), 'status', '--rule', rule, '--state_dir', d] -> 0, job name in stdout
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_status_command.py -q`** → FAIL.
- [ ] **Step 3: Implement the interfaces above.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Add the status command and dispatch commands ahead of the daemon's arguments."`

---

### Task 5: Restore lock and postponed pruning

**Files:**
- Modify: `reverberator.py` — the three retention loops in `do_backup` (~3620-3650), near `decrement_stepper`
- Create: `tests/test_restore_lock.py`

**Interfaces:**
- Consumes: `state_dir_path` (Task 3).
- Produces:
  - `restore_lock_path(job_name:str, state_dir:str = None) -> str` = `os.path.join(state_dir_path(state_dir), f'job-{job_name}.restore.lock')`.
  - `class RestoreLock` — context manager, `__init__(self, job_name:str, state_dir:str = None, stream = sys.stderr)`;
    `__enter__` creates the state folder if needed, opens the lock file, takes `fcntl.LOCK_SH | LOCK_NB`; when that
    would block it writes `Waiting for reverberator to finish removing an old version of <job>` to `stream` once and
    takes `LOCK_SH` blocking. `__exit__` releases and closes.
  - `prune_oldest(vault_info_dict:OrderedDict, job_name:str) -> tuple` — takes `LOCK_EX | LOCK_NB` on the job's lock
    file for the duration of `decrement_stepper(vault_info_dict)` and returns its result; when the lock is held by a
    restore it logs `Postponing removal of the oldest version: a restore is reading the vault` (via
    `backuperTeeLogToTl(job_name, …)`) and returns `(0, 0)`, which ends the retention loops; when the lock file cannot
    be opened (no state folder) it prunes unlocked. The three loops call `prune_oldest` instead of `decrement_stepper`.

- [ ] **Step 1: Write the failing tests**

```python
def test_pruning_waits_while_a_restore_holds_the_lock(job):
	# V0..V2 committed via run_backup; keep_n_versions=3
	with rv.RestoreLock('job'):
		modify(); run_backup(job, entries, keep_n_versions=3)
		assert [v.number for v in rv.list_versions(job.job_vault)] == [0, 1, 2, 3]
	modify(); run_backup(job, entries, keep_n_versions=3)
	assert [v.number for v in rv.list_versions(job.job_vault)][0] >= 2

def test_pruning_resumes_after_the_restoring_process_is_killed(job): ...  # subprocess holding RestoreLock, SIGKILL, then a backup prunes
def test_restore_lock_waits_for_a_running_prune(tmp_path, capsys): ...    # hold LOCK_EX with fcntl in the test; RestoreLock in a thread blocks and prints 'Waiting for reverberator'; release -> entered
def test_pruning_without_a_state_folder_proceeds(job, monkeypatch): ...  # REVERB_STATE_DIR is a file: backup prunes as before
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_restore_lock.py -q`** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Postpone pruning a job's oldest version while a restore reads its vault."`

---

### Task 6: `history`

**Files:**
- Modify: `reverberator.py` — `SkipList`, Commands section
- Create: `tests/test_history.py`

**Interfaces:**
- Consumes: Tasks 2, 4 (`run_command`, `read_status`, `command_rule_path`), 5 (`RestoreLock`, held while reading).
- Produces:
  - `HistoryRow = namedtuple('HistoryRow', ['version', 'event', 'size', 'source', 'counts', 'files'])` — `version`
    a `KeptVersion`; `event` one of `'oldest'`, `'create'`, `'modify'`, `'attrib'`, `'move'` (`source` = the old
    absolute path), `'moved_away'` (`source` = the new absolute path), `'delete'`, `'changed'` (the folder shows a
    change with no change-list row); `size` of the resolved file or None; `counts` a dict
    `{'create', 'modify', 'attrib', 'move', 'delete'}` for folders, else None; `files` a list of `(event, rel)` for
    folders, else None.
  - `path_kind(job_vault:str, versions:list, monitor_path:str, rel:str) -> str | None` — `'folder'`, `'file'`, or None
    when no version holds it; `rel == ''` is `'folder'`.
  - `file_history(job_vault:str, versions:list, monitor_path:str, rel:str) -> list` — newest first. Version N (not the
    oldest) is listed when its entry is not a chain link to the same rel in an older version (a chain link to another
    rel is a `move`), when it lacks the entry the previous version had (`delete`, or `moved_away` when a change-list
    row of N has this path as `source_path`), or when its change list has a row for the path (`attrib` and the like);
    the event label comes from the change-list row when there is one. The oldest kept version holding the entry is
    listed as `'oldest'`.
  - `folder_history(job_vault:str, versions:list, monitor_path:str, rel:str) -> list` — one row per version whose change
    list has rows under the folder (`path` starting with `<abs folder>/`, or every row for the root), counts by event,
    `files` relative to the folder; plus the oldest kept version holding the folder as `'oldest'`.
  - `SkipList.deciding_pattern(self, rel:str, is_dir:bool) -> str | None` — the pattern that makes `rel` (or the
    first skipped folder above it) skipped, None when nothing skips it.
  - `format_history(rule, job_vault:str, rows:list, kind:str, show_files:bool) -> str`; `history_command(args) -> int`.
- Output (pinned by tests): first line `job <name>, vault <job vault>`; file rows
  `V<n>  <YYYY-MM-DD HH:MM>  <label>  <size>` with labels `created`, `modified`, `attributes changed`,
  `moved from <path>`, `moved to <path>`, `deleted`, `changed`, `oldest kept copy`; folder rows
  `V<n>  <time>  <k> created, <k> modified, <k> deleted` (plus `, <k> moved`, `, <k> attributes changed` when non-zero)
  and with `--files` each `    <event> <rel>` below; never backed up: `<path> was never backed up` plus
  `; it matches the skip pattern <pattern>` when the job's skip list (loaded with `SkipList.load(rule.mon_path,
  resolve_skip_list_path(rule.skip_list_file, rule_path))`, ignored if it cannot load) skips it; that case exits 0.

- [ ] **Step 1: Write the failing tests** (vaults built with `run_backup` and `event_entry`)

```python
def test_file_history_create_modify_move_delete(job):
	# V0 seed {'keep.txt'}; V1 create a.txt; V2 modify a.txt; V3 move a.txt -> b/a.txt; V4 delete b/a.txt
	assert [(r.version.number, r.event) for r in hist('a.txt')] == [(3, 'moved_away'), (2, 'modify'), (1, 'create')]
	assert [(r.version.number, r.event) for r in hist('b/a.txt')] == [(4, 'delete'), (3, 'move')]

def test_attribute_change_is_listed(job): ...          # chmod + 'attrib' entry: row with 'attrib' though the version holds a link
def test_oldest_kept_copy(job): ...                    # path present since V0: last row (0, 'oldest')
def test_folder_history_counts_and_files(job): ...     # counts per version; files are rels under the folder
def test_folder_history_boundary(job): ...             # changes in 'project/' never count for 'proj'
def test_history_root_and_trailing_slash(job): ...     # monitor root and 'proj/' give folder history
def test_history_never_backed_up(job, capsys): ...     # 'was never backed up'; with skip list 'build/', path build/x names 'build/'
def test_history_streams_change_lists(job, monkeypatch): ...  # TSVZ.readTabularFile patched to raise: history still works
def test_history_command_output(job, tmp_path, capsys): ...   # run_command(['history', path, '--rule', r, '--state_dir', d]) == 0; header and 'V1' row
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_history.py -q`** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Add the history command for files and folders across the kept versions."`

---

### Task 7: `restore` into a destination

**Files:**
- Modify: `reverberator.py` — Commands section
- Create: `tests/test_restore.py`

**Interfaces:**
- Consumes: Tasks 2, 4, 5, 6; `cp_af_copy_path(source, dest, mcae, pending)`, `PendingCopy`,
  `copy_metadata_failure`, `replace_entry`, `remove_entry`, `copy_file_meta`, `iter_tree_entries`.
- Produces:
  - `parse_at_time(text:str) -> float` — accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, `YYYY-MM-DD HH:MM:SS`, the same with
    `T`, and `VAULT_TIMESTAMP_FORMAT`; local time when no offset; `CommandError` otherwise. Doctest on the vault format.
  - `restore_candidates(job_vault:str, versions:list, monitor_path:str, rel:str, kind:str) -> list` — the history rows
    whose version holds the path (not `delete`/`moved_away`), newest first.
  - `choose_version(candidates:list, versions:list, holds, version:int = None, at:str = None, stdin = sys.stdin, stdout = sys.stdout) -> KeptVersion`
    — `holds(KeptVersion) -> bool` says whether a version holds the path. `--version`: that kept version, which must
    hold it; `--at`: the newest version with `timestamp <= parse_at_time(at)` that holds it; neither: without
    `stdin.isatty()` a `CommandError` asking for `--version` or `--at`; one candidate is used and named on `stdout`;
    else a numbered list (same row format as history) and a prompt reading a number until valid (`q` cancels with
    `EXIT_COMMAND_FAILED`). A version not kept, or not holding the path, is a `CommandError` naming the kept versions.
  - `class RestoreReport` — `restored`, `kept`, `bytes`, `failures` (list of `(rel, reason)`), `warnings`;
    `progress(self, stream)` writes `restored <n> entries, <size>` (rewritten with `\r` once a second on a terminal,
    a line every 60 s otherwise); `summary(self) -> str`.
  - `finish_restore_copies(pending:list, report:RestoreReport) -> None` — like `finish_copies` without manifest or job:
    success (or metadata-only failure, recorded as a warning) → `replace_entry`; failure → `remove_entry(temp)` and a
    failure with cp's message.
  - `restore_entry(job_vault:str, version:KeptVersion, monitor_path:str, rel:str, target:str, threads:int, report:RestoreReport, resume:bool = False) -> None`
    — a file or user symlink: one checked copy of the resolved entry (`cp -a` copies a symlink as a symlink); a folder:
    walk the version's folder, create folders as met, copy files through `resolve_version_entry` on an
    `AsyncExecutor(semaphore=threading.Semaphore(threads))`, finishing pending copies every 1000, then apply each
    folder's metadata with `copy_file_meta` deepest first; `dangling` → failure `dangling vault link: <detail>`;
    `referenced` → failure `not held in the vault (referenced backup)`; an `OSError` on any one entry is a failure for
    that entry, never a traceback. (`resume` is used by Task 8.)
  - `restore_command(args) -> int` — rules → `find_job` → `RestoreLock` for the whole command → `list_versions` →
    `path_kind` → `restore_candidates` → `choose_version` → target. Destination mode: `dest` must be an existing
    folder; target is `os.path.join(dest, basename(rel) or basename(monitor_path))`; a target inside the rule's
    `vault_path` or that already exists is a `CommandError` before anything is written. Then `restore_entry`, the report
    (`Restored <n> entries (<size>) from V<n> to <target>`, then each `FAILED <rel>: <reason>`), and
    `EXIT_COMMAND_FAILED` when anything failed. Exactly one of `dest` and `--in-place` is required (`--in-place` is
    rejected with a `CommandError` until Task 8).

- [ ] **Step 1: Write the failing tests**

```python
def test_restore_file_to_a_destination(job, tmp_path): ...      # content, mode, mtime_ns, uid, gid equal the vault copy's
def test_restore_folder_to_a_destination(job, tmp_path): ...    # whole tree; user symlink restored with its text; folder mtimes equal the vault's
def test_restore_picks_by_number_and_time(job, tmp_path): ...   # --version 1 -> V1 content; --at between V1 and V2 -> V1; --at before V0 -> exit 2
def test_restore_without_a_terminal_needs_a_version(job, tmp_path, monkeypatch): ...  # stdin not a tty -> exit 2
def test_restore_picker_reads_a_choice(job, tmp_path): ...      # choose_version with a fake tty stdin '2\n' -> second listed version
def test_restore_refuses_an_existing_destination_name(job, tmp_path): ...  # exit 2, existing content unchanged
def test_restore_refuses_destination_inside_vault(job, tmp_path): ...       # dest under job.vault -> exit 2, vault unchanged
def test_restore_reports_dangling_and_continues(job, tmp_path, capsys): ... # one dangling link: exit 1, 'FAILED <rel>', other files restored
def test_restore_reports_referenced_links(job, tmp_path, capsys): ...       # absolute link to monitor/rel: 'not held in the vault'
def test_restore_never_writes_the_vault(job, tmp_path): ...     # {path: (st_mode, st_size, st_mtime_ns, readlink)} of the job vault equal before and after
def test_restore_names_with_spaces_and_unicode(job, tmp_path): ...  # 'a b/café.txt' restored with content
def test_restore_reports_a_version_removed_mid_restore(job, tmp_path, monkeypatch, capsys): ...  # choose_version wrapped to remove V0 after choosing V1 (whose files chain to V0): exit 1, failures listed, no traceback
def test_restore_thousands_of_files(job, tmp_path, capsys): ... # 3000 files in 30 folders, --threads 4: all contents match; summary 'Restored 3031 entries'
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_restore.py -q`** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Add the restore command, restoring a file, folder or job into a destination."`

---

### Task 8: In place, picking up interrupted restores, whole-job restores

**Files:**
- Modify: `reverberator.py` — Commands section
- Create: `tests/test_restore_in_place.py`

**Interfaces:**
- Consumes: Task 7, `read_status` (Task 4).
- Produces:
  - `RESTORE_MARKER_NAME = '.reverberator-restore'`; the marker is JSON `{"job", "path" (rel), "version" (folder name)}`
    at the top of a folder restore's target, written before the first copy.
  - `read_restore_marker(target:str) -> dict | None`; `move_aside(path:str) -> str` — renames to
    `f'{path}.before-restore-{YYYY-MM-DD_HH-MM-SS}'`, adding `-1`, `-2` … when taken; returns the new path.
  - `restore_command` gains: `--in-place` (target `os.path.join(monitor_path, rel)`). A target holding a marker for
    the same job, path and version is resumed (`restore_entry(..., resume=True)`): an entry already there with the
    resolved source's type, size and `mtime_ns` is kept (`report.kept`), anything else is copied over it. A marker for
    anything else is a `CommandError` naming its job, path and version. Without a marker: destination mode refuses
    as in Task 7; in place, a non-root target is moved aside (path printed) and the root (`rel == ''`) must be empty
    apart from an empty `lost+found`, else a `CommandError` saying to restore into a folder instead. An in-place
    restore of the root while `read_status` shows the daemon alive and the job not `stopped` prints that the job will
    back the restore up as one large change and asks `Continue? [y/N]`; `--yes` skips it; without a terminal and
    without `--yes` it is a `CommandError`.
  - The marker is removed when a folder restore finishes with no failures; otherwise it stays and the report ends with
    `<n> failed: run the same restore again to retry them, or remove <marker path> to accept the result as it is`.
    File restores write no marker.

- [ ] **Step 1: Write the failing tests**

```python
def test_in_place_moves_the_current_file_aside(job): ...        # live file edited; restore --in-place --version 0: live has V0 content, '<name>.before-restore-*' has the edit
def test_in_place_folder_is_restored_exactly(job): ...          # a file added after V0 exists only in the moved-aside copy
def test_in_place_root_needs_an_empty_root(job): ...            # non-empty root -> 2; emptied root with empty lost+found -> restored; lost+found with a file -> 2
def test_interrupted_restore_picks_up(job, tmp_path, monkeypatch): ...  # finish_restore_copies raises KeyboardInterrupt on its 2nd batch: marker left; re-run completes, inode numbers of files restored before are unchanged, marker gone
def test_resume_refuses_a_marker_for_another_version(job, tmp_path, capsys): ...  # exit 2, message names the marker's version
def test_unmarked_output_is_never_touched(job, tmp_path): ...  # existing unmarked target: exit 2, content unchanged
def test_failures_keep_the_marker_and_a_rerun_retries(job, tmp_path): ...  # dangling link: exit 1, marker stays; link target restored by hand; re-run exit 0, marker gone
def test_in_place_rerun_does_not_move_aside_again(job, monkeypatch): ...  # interrupted in-place, re-run: one '.before-restore-' sibling
def test_in_place_root_asks_while_the_daemon_runs_the_job(job, tmp_path): ...  # live daemon record + running job: no tty, no --yes -> 2; --yes -> restored
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_restore_in_place.py -q`** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `.venv/bin/python -m pytest -q`** → whole suite passes.
- [ ] **Step 5: Commit** — `"Restore in place, pick up an interrupted restore, and restore a whole job onto an empty disk."`

---

### Task 9: Docs, version, both venvs

**Files:**
- Modify: `reverberator.py` (`__version__ = 0.39`; daemon `--help` epilog gains `reverberator status`,
  `reverberator history PATH`, `reverberator restore PATH [DEST | --in-place]`), `pyproject.toml` (`version = "0.39"`),
  `README.md`

- [ ] **Step 1: README** — a "Status, history and restore" section after "Failure handling and log markers", in the
  README's own style: the three commands and their options; where status comes from (`/run/reverberator`,
  `REVERB_STATE_DIR`, `--state_dir`), and that `status` shows last known states when the daemon is not running; how a
  version is chosen; destination vs `--in-place` (moved-aside name), the marker and re-runs, the empty-root rule; that
  with Only Sync Attributes a restored file carries the newest mode, owner and times its shared copy has; that a
  restore postpones pruning and the vault may exceed its limit meanwhile; exit codes 0/1/2; and one line on links that
  moves broke before 0.39 being read and pruned correctly.
- [ ] **Step 2: Bump the version in both places.**
- [ ] **Step 3: Run `.venv/bin/python -m pytest -q` and `/mnt/optane/work/reverberator/.venv/bin/python -m pytest -q`** from the worktree root → both pass with the same counts.
- [ ] **Step 4: Commit** — `"Document status, history and restore, and bump to 0.39."`
