# Verify What Each Batch Touched Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After every batch's replay, compare what the batch's raw events touched with the monitored tree and fix the new, uncommitted version. Each version then matches the tree after renames, saves through backup files, folder swaps and the other sequences in the spec.

**Architecture:**
- The scoped-comparison core is factored out of `delta_generate_backup_entries` into `compare_scopes()`. It runs inside the open transaction against the new version, never reads back this backup's own copies, and can leave attribute-only differences out.
- `do_reverb_backup` runs it over the batch's `TouchedScopes`, replays the fixes with the batch's own replay code, and sweeps the touched folders of the version folder against the manifest. `do_backup` writes the fixes into the change list.
- Small fixes ride along:
  - a full comparison after a batch that lost its raw events;
  - dropping `move X from X`;
  - pending times rebased across a reboot.

**Tech Stack:** Python ≥ 3.8, single module `reverberator.py`, sqlite3 (VaultManifest), pytest.

**Spec:** `docs/superpowers/specs/2026-10-22-batch-replay-design.md`

## Global Constraints

- Code is tab-indented and matches the surrounding code's naming, comment density and docstring style.
- It must work on the service venv (`/mnt/optane/work/reverberator/.venv`: Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39) and the worktree venv (6.42, 1.54, 4.9).
- Work only in `/mnt/optane/work/reverberator/.worktrees/stale-children`.
  - Never edit the main checkout: the live service runs from it.
  - Never touch `/etc`, systemctl or any real vault (`/mnt/jank`, `/mnt/impulse`).
  - Never commit `uv.lock`.
- Run the tests from the worktree root with both commands. The baseline is 815 passed and 1 skipped on both venvs.
  - `.venv/bin/python -m pytest -q -p no:cacheprovider`
  - `PYTHONDONTWRITEBYTECODE=1 /mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
- Commit messages are one or two plain sentences in the repo's style, ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_0179SV9GcZcp5fPuVSWUarb6
  ```
- **Data safety (the spec's anti-goal):** nothing outside the new `backup_folder` and the open manifest transaction may change. Removals never follow links and never act on `backup_folder` itself (rel `''` or `.`).
- **Reference data:** the raw watcher events of each sequence, as the real watcher reports them, are in `/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/r7/investigation.md` (section 1, "events (...)" lines), `out_*.txt` and `check/` in the same folder. Use them verbatim for the event-level tests.

## Review Focus

1. **A crash or SIGTERM during the verification.** Nothing is committed: the manifest rolls back and the incomplete version is removed at the next start, as now. Pinned in Task 2 by `test_interrupted_verification_commits_nothing`.
2. **A skip list and paused inner mounts under a touched folder.** Skipped paths are neither created nor deleted, and a paused mount's rows stay. Pinned in Task 2 by `test_verification_respects_skip_list_and_paused_mounts`.
3. **A name that is not UTF-8 under a re-created folder.** It is compared and stored in its stored form, with no stale or missing rows. Pinned in Task 2 by `test_verification_handles_non_utf8_names`.
4. **An attribute change on a big folder, or on the monitored root.** It compares that folder alone, never its tree. Pinned in Task 2 by `test_folder_attrib_compares_the_folder_only`.
5. **Older versions.** Their listing, link targets, mode, owner and mtime are unchanged by any batch in the spec's table. Pinned in Task 2 by `test_older_versions_are_untouched`.

---

### Task 1: The comparison core, usable inside an open transaction

**Files:**
- Modify: `reverberator.py`.
  - `delta_generate_backup_entries` (about lines 6136-6250).
  - Add `TouchedScopes`, `compare_scopes` next to it.
  - Add `VaultManifest.dirty_rels` near `VaultManifest.lookup` (about line 5302).
- Test: `tests/test_compare_scopes.py` (new).

**Interfaces:**
- Produces `TouchedScopes = namedtuple('TouchedScopes', ['subtrees', 'paths'])`.
  - `subtrees` holds folder rels ending in `/`, each compared with everything under it. The rel `''` means the whole tree.
  - `paths` holds rels compared as single entries: a file rel, or a folder rel ending in `/`, which is compared alone.
- Produces `compare_scopes(backup_entries:dict, manifest:VaultManifest, version_path:str, monitor_path:str, scopes:TouchedScopes, skip=None, paused:set = frozenset(), job_name:str = '', reported:set = None, trusted = frozenset(), attributes:bool = True) -> int`.
  - It adds `BackupEntryValues(now, event, None)` entries keyed by the monitored path, as delta generation does today, and returns the number of tracked entries compared.
  - It never calls `begin`, `commit`, `rollback`, `rebuild` or `prefetch`. It reads the vault only at `version_path`.
  - It stores records it reads with `set_records`, as today.
  - `trusted` rels, which this backup wrote, are compared for presence and kind only: never passed to `compare_entry`, never read from the vault.
  - With `attributes=False`, `attrib` results are left out.
  - It raises `JobFailure` when the monitored root cannot be read.
  - Walk errors, paused mounts and the skip list are handled exactly as delta generation does today.
  - Each subtree's deletions come from `unseen_under`, the whole tree's from `unseen()`. A path is looked up directly.
- Produces `VaultManifest.dirty_rels() -> set`: the rels of rows with `dirty = 1`, in stored-name-decoded form.
- `delta_generate_backup_entries` keeps its signature and behaviour. It does the prefetch, begin, describes/rebuild, commit and rollback, and calls `compare_scopes` with `TouchedScopes([scope_rel], [])`, where the rel is `''` for the whole tree.

- [ ] **Step 1: Write the failing tests in `tests/test_compare_scopes.py`.** Use `tests/harness`: `create_job`, `seed_monitor`, `run_backup`, `latest_version`.
  - `test_a_single_path_reports_its_modify`: the tree's `a.txt` changed after V0, with `TouchedScopes([], ['a.txt'])`, gives exactly `{monitor/a.txt: modify}`.
  - `test_a_subtree_reports_rows_the_tree_lacks`: the manifest has D/old.txt, the tree's D lacks it; `TouchedScopes(['D/'], [])` gives `delete` for D/old.txt and nothing else.
  - `test_trusted_rels_are_not_read_from_the_vault`:
    - Monkeypatch `rv.read_vault_record` to raise if called for a trusted rel.
    - A trusted rel present in the tree gives nothing; a trusted rel absent from the tree gives `delete`.
  - `test_it_leaves_the_transaction_open`:
    - Call `manifest.begin()`, then `compare_scopes(...)`.
    - Then `manifest.conn.in_transaction` is True, `manifest.describes(<V0 path>)` is unchanged, and `manifest.rollback()` restores the rows.
  - `test_it_reads_the_version_it_is_given`:
    - Rows nulled by `manifest.move_tree` are read through `version_path`, a second version folder you build with `do_referenced_copy` plus a rename.
    - Assert no "Cannot read" error line, and no `create` for the moved rows.
  - `test_attributes_false_leaves_attrib_out`: a chmod-only change, with `attributes=False`, gives nothing; with `True` it gives `attrib`.
  - `test_delta_generation_is_unchanged`: run the existing delta tests (`tests/` files that call `delta_generate_backup_entries`); they must pass with no edits.

- [ ] **Step 2: Run them and watch them fail** with `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_compare_scopes.py`. Expected: FAIL, because `TouchedScopes`/`compare_scopes` are not defined.

- [ ] **Step 3: Implement** `TouchedScopes`, `compare_scopes`, `dirty_rels`, and the refactor of `delta_generate_backup_entries` onto them.
  - Keep the walk-order settling (`settle`) and the thread pool as they are, one pool per call.
  - Paths and subtrees share one `clear_seen`.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit** `reverberator.py` and `tests/test_compare_scopes.py`.

### Task 2: Verify the touched scopes after the replay

**Files:**
- Modify: `reverberator.py`.
  - Add `touched_scopes` near `change_events_to_backup_entries`.
  - `do_reverb_backup` (about lines 6751-6985): add the verification and the sweep.
  - `do_backup` (about lines 4006-4250): pass the scopes and paused mounts, write the fixes, adjust the recopy rows.
  - `backuper` (about lines 3596-3640): compute and pass the scopes.
- Test: `tests/test_verify_replay.py` (new).

**Interfaces:**
- Consumes `TouchedScopes`, `compare_scopes` and `VaultManifest.dirty_rels` from Task 1.
- Produces `touched_scopes(events, monitor_path:str) -> TouchedScopes`, taking raw `ChangeEvent`s.
  - A `create`, `delete` or `move` with `is_dir` adds the folder rel with `/` to `subtrees`. A move also adds its `moved_from` as a subtree, when that is inside the tree.
  - Any event that is not `is_dir`, and a folder's `attrib` or `modify`, adds to `paths`: a folder's rel with `/`, plus a move's source.
  - `scan`, `full_scan` and `self_destruct` are skipped, and so are paths outside `monitor_path`.
  - Entries inside a subtree are dropped, and the result is sorted.
- `do_reverb_backup(..., touched:TouchedScopes = None, paused:set = frozenset(), verified:list = None)`. After the batch's own replay and its final `wait_for_async_commands`, inside the same `try` and before the `finally`'s `stop_copies`, when `touched` is not None:
  1. Run `compare_scopes(fixes, manifest, backup_folder, monitor_path, touched, skip, paused, job_name, reported, trusted=manifest.dirty_rels(), attributes=False)`.
  2. Replay `fixes` with the same per-entry code the batch uses. Factor the loop body into a nested `replay(entries)` that both calls use, keeping the delete barrier. Then wait.
  3. Run `sweep_version_folder(manifest, backup_folder, touched) -> tuple`, a new module-level function returning `(removed, missing)` as rel lists.
     - It walks `backup_folder` under each subtree, and lstats each path. It removes, without following links, every entry the manifest does not track, and returns the removed rels.
     - It returns as `missing` the tracked rels that have no entry in the folder.
  4. Replay `missing` as `create` entries, and wait.
  5. Append every fix to `verified`, in this order: the comparison's entries, then `delete` for each removed rel, then `create` for each missing rel. Each is a `(monitored path, BackupEntryValues)` pair, and folder paths end with `/`.
- `do_backup(..., touched:TouchedScopes = None)`. It passes `touched` and the paused mounts it already knows into `do_reverb_backup`.
  - It writes the `verified` rows into the change list after the batch's rows, using `entry_row`.
  - It leaves out `recopy` rows for rels the verification deleted.
  - Full-comparison and scan-only batches pass `touched=None`.
- `backuper` passes `touched=touched_scopes(to_process_temp, monitor_path)` for event batches, including the batch queued at startup, and `None` for full comparisons.

- [ ] **Step 1: Write the failing tests in `tests/test_verify_replay.py`.**
  - **Helper `replay_sequence(tmp_path, before:dict, after:dict, events_spec:list) -> (job, version)`:**
    - Seed the monitored tree with `before` and take V0 with `run_backup`.
    - Make the monitored tree equal `after`; folders are keys ending in `/`.
    - Build raw `ChangeEvent`s from `events_spec`, a list of `(event, rel, source_rel_or_None, is_dir)`.
    - Run `change_events_to_backup_entries`, then `run_backup(job, entries, touched=rv.touched_scopes(events, job.monitor))`.
  - **Helper `assert_version_matches_tree(job, version)`:** the version folder, with links followed only to read bytes, and the manifest's rows both equal the monitored tree, in names, kinds and file bytes.
  - **One test per sequence in the spec's table,** with the events from the reference data: `test_sequence_a`, `_c`, `_d4`, `_d6`, `_d7`, `_f1`, `_e1`, `_e2`, `_e3`, `_e4`, `_d5`, `_f3`, `_f5`, `_git`, `_swap`, `_chain`, `_late_delete`.
    - Each asserts `assert_version_matches_tree`.
    - Each asserts that the change list contains a row for each fix, read with `rv.iter_change_list` or the existing reader.
  - **`test_sequence_loop`** (`mv D D2; mv D2 D`): the backup commits; this needs Task 3's self-move drop. Mark it `xfail(strict=True)` until Task 3, which removes the mark.
  - **`test_a_single_modify_compares_one_path`:** spy on `rv.compare_scopes`. A batch of one file modify passes `TouchedScopes([], ['a.txt'])`.
  - **`test_folder_attrib_compares_the_folder_only`:** a `chmod D` batch, and an `attrib` on the root event path, pass `paths == ['D/']` and no subtree.
  - **`test_verification_respects_skip_list_and_paused_mounts`.**
  - **`test_verification_handles_non_utf8_names`:** case a, with `D/bad\xff.txt` in the old tree.
  - **`test_fresh_copies_keep_unchecked`:** after a case-a batch, rows the replay copied have `unchecked` set.
  - **`test_attribute_only_differences_are_not_replayed`:** chmod a file inside a touched folder. The verification adds no entry, and V0's copy keeps its mode.
  - **`test_older_versions_are_untouched`:** snapshot every older version's `(rel, kind, link target, mode, uid, gid, mtime_ns)` before and after each of the sequence batches. They are equal.
  - **`test_interrupted_verification_commits_nothing`:**
    - Monkeypatch `rv.compare_scopes` to clear `rv.GREEN_LIGHT` and return.
    - The batch does not commit, the manifest equals its pre-batch rows, and the incomplete version is removed by `rv.remove_incomplete_vault_versions`.
    - Restore GREEN_LIGHT afterwards.
  - **`test_recopy_row_dropped_for_a_verified_delete`:** a stale due child (keep_n_versions 0, 33+ versions; reuse the round 4 re-copy test helpers) under a re-created folder. The version has no copy of it, and the change list has no `recopy` row for it.

- [ ] **Step 2: Run them and watch them fail** with `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_verify_replay.py`. Expected: the sequence tests FAIL with stale or missing entries, as in the reference data, and the others fail on the missing `touched` keyword.

- [ ] **Step 3: Implement** `touched_scopes`, the verification and the sweep in `do_reverb_backup`, `sweep_version_folder`, the `do_backup` changes, and the `backuper` wiring.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass on both venvs except the strict xfail.

- [ ] **Step 5: Commit** `reverberator.py` and `tests/test_verify_replay.py`.

### Task 3: Batches without raw events, the self-move, and pending times after a reboot

**Files:**
- Modify: `reverberator.py`.
  - `ChangeEventQueue` (about line 211).
  - `backuper`.
  - `change_events_to_backup_entries`, at its end.
  - `load_pending_transactions_for_resume` (about line 2800).
- Test: `tests/test_verify_replay.py` (append), `tests/test_pending_times.py` (new).

**Interfaces:**
- `ChangeEventQueue.round_tripped: bool`, False by default.
  - `prepend()` sets it to True.
  - `load_pending_transactions_for_resume` sets it to True on the queue when it loads rows.
  - `take()` carries it to the taken queue and clears it on the source.
- `backuper`: after a committed `do_backup` of a taken batch whose `round_tripped` is True, it appends `ChangeEvent(time.monotonic(), False, 'full_scan', monitor_path, None)` to `to_process`, under `to_process_lock`, and logs one line saying why.
- `change_events_to_backup_entries` drops, before returning, every entry whose event is `move` and whose `source_path` equals its path.
- `load_pending_transactions_for_resume`: when the pending file's mtime is earlier than this boot (`time.time() - time.monotonic()`, less 1 second of slack), the rows' times are shifted by one offset. The newest then equals `time.monotonic() - (time.time() - pending_mtime)`. The spacing between rows is kept. Otherwise the times are kept as stored.

- [ ] **Step 1: Write the failing tests.**
  - `test_sequence_loop`: remove its xfail mark.
  - `test_a_resumed_batch_is_followed_by_a_full_comparison`: write a pending file with `tests/harness.write_pending`, then resume it with `load_pending_transactions_for_resume` and `take()`. After the committed backup, the queue holds a `full_scan` event.
  - `test_a_requeued_batch_is_followed_by_a_full_comparison`: the same for a batch put back with `prepend()`.
  - `test_git_pattern_round_tripped_ends_clean`:
    - Run the git sequence's collapsed entries through `backup_entries_to_change_events`, the pending round trip.
    - Back up the result, then run the full comparison the queue now holds.
    - X is gone from the latest version.
  - `test_self_move_is_dropped`: `change_events_to_backup_entries` of `[move D/ from D/]` gives no entry.
  - `tests/test_pending_times.py::test_times_from_an_earlier_boot_are_rebased`:
    - Write a pending file whose rows' times are `time.monotonic() + 345600` and up.
    - Set its mtime with `os.utime` to 60 s ago.
    - Monkeypatch `time.time` / `time.monotonic` if needed, so that the file predates the boot.
    - After the load, the newest event's time is within 2 s of `time.monotonic() - 60`, and the order and spacing are kept.
    - The `iso_time` the collapse computes for it is not in the future.
  - `tests/test_pending_times.py::test_times_from_this_boot_are_kept`: a pending file written in this boot keeps its stored times exactly.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL on the queue flag, the self-move entry, and the future times.

- [ ] **Step 3: Implement** the flag, the follow-up full comparison, the self-move drop and the rebase.

- [ ] **Step 4: Run the touched test files and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit** `reverberator.py`, `tests/test_verify_replay.py` and `tests/test_pending_times.py`.

### Task 4: The sequences through the real watcher, the README, and 0.43

**Files:**
- Create: `tests/test_replay_sequences.py`, with the `inotify` marker plus `process` if it starts a daemon.
- Modify:
  - `README.md`, in the design notes near the other replay sentences;
  - `reverberator.py` line 55 (`__version__`);
  - `pyproject.toml` (`version`).

**Interfaces:**
- Consumes everything above. Port the harness in `/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/r7/repro_lib.py`: the real `watchFolder` thread, `ChangeEventQueue.take()`, the collapse, and `do_backup` with `touched`. Keep its `MOVE_PAIR_TIMEOUT_SECONDS` patch, so move-outs expire quickly.

- [ ] **Step 1: Write the failing tests.** One test per sequence of the spec's table, running the real file operations under the real watcher, each asserting `assert_version_matches_tree`. Import that helper from `tests/test_verify_replay.py` or move it into `tests/harness.py`.

- [ ] **Step 2: Run them against Task 3's head.** They pass, because Tasks 1-3 carry the fix. Run them once with `touched=None` forced, via a monkeypatch of `rv.touched_scopes` that returns None, to show they fail without the verification, and record that in the report. Keep each test under 15 s.

- [ ] **Step 3: README and version.**
  - Add to the README's design notes: "After each batch, every place its events touched is compared with the monitored tree and the new version is fixed before it is committed, so renames, saves through a backup file and folder swaps come out as they are in the tree; a batch resumed after a restart, or put back after a failed backup, is followed by one full comparison."
  - Set `__version__ = 0.43` and `version = "0.43"`.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit** `tests/test_replay_sequences.py`, `README.md`, `reverberator.py` and `pyproject.toml`.
