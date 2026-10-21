# Names, Chains and Leftovers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Back up files whose names are not valid UTF-8, never write a vault link chain longer than 38 hops, stop jobs whose names clean up to nothing, escape names in logs, and clear round 3's deferred items — as reverberator 0.40.

**Architecture:** One reversible name escape (`storable_name` / `stored_name`) maps a surrogate-escaped name to valid Unicode that leaves every UTF-8 name unchanged; the vault database, change lists, pending transactions, journal and remembered inner mounts store names through it. The vault database gains a `copy_version` column (schema '2', upgraded in place from '1') so a referenced copy can re-copy an entry from the vault once its chain would pass its per-name threshold (32..38). Log helpers escape names like `shown()`.

**Tech Stack:** Python ≥3.8, sqlite3, xxhash, TSVZ (writing only), pytest with doctests.

**Spec:** `docs/superpowers/specs/2026-10-21-names-chains-leftovers-design.md`

## Global Constraints

- Single module `reverberator.py`: tabs, the file's naming mix and comment density, doctests on small pure helpers.
- `requires-python >=3.8`; no new dependencies; must run on the service venv's libraries (TSVZ 3.39, multiCMD 1.51, Tee_Logger 6.40, xxhash 3.8.1, pathspec 1.1.1) and on a fresh resolve.
- Run tests from the worktree root as `.venv/bin/python -m pytest …`; before each commit also `/mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider` from the worktree root. Both must pass.
- Never touch the live service checkout (`/mnt/optane/work/reverberator` outside `.worktrees`), `/etc`, `/run`, or any vault under `/mnt`.
- Upgrading a vault must cost no full comparison, no vault re-read of every entry and no re-copy on a job keeping 32 versions or fewer; the skip-list fingerprint and remembered inner mounts survive the upgrade.
- TSVZ 3.39 encodes with `errors='replace'` and sqlite orders every TEXT before every BLOB: names go through `storable_name` before TSVZ or sqlite see them.
- Re-copy thresholds: `RECOPY_MIN_HOPS = 32`, `RECOPY_MAX_HOPS = 38`, inclusive; a re-copy copies the end of the chain as it is in the vault (real file, user symlink or referenced link), never the monitored file.
- The daemon's command line and the status files' format are unchanged. Version 0.40.

## Review Focus

- A non-UTF-8 file inside a non-UTF-8 folder, moved to another depth and then restored: every layer must keep both names' bytes. Test: Task 2 `test_nested_bad_names_survive_a_move_and_restore`.
- A name that itself contains the escape character `NAME_ESCAPE` or the code points it uses: must round-trip, not decode as a surrogate. Test: Task 1 doctests and `test_manifest_round_trips_escape_lookalikes`.
- The oldest kept version pruned between two backups: an entry's recorded copy version may name a removed version; the effective copy version must not make a re-copy late. Test: Task 4 `test_copy_version_follows_retention`.
- A chain ending at a user's symlink or a referenced backup's link reaching its threshold: the re-copy copies that link, not what it points to. Test: Task 5 `test_recopy_keeps_a_user_symlink_and_a_referenced_link`.
- A log message carrying a traceback that mentions a name with a line break: no journal line may start with a marker. Test: Task 3 `test_a_traceback_with_a_bad_name_cannot_start_a_line`.

---

## File map

- `reverberator.py` — all code.
- Tests: `tests/test_names.py` (Tasks 1-2), `tests/test_log_text.py` (Task 3), `tests/test_long_chains.py` (Tasks 4-5), `tests/test_jobs.py` (Task 6), existing test files for Tasks 7-10.
- `README.md`, `pyproject.toml` — Task 10.

---

### Task 1: The name escape and the vault database's schema '2'

**Files:** Modify `reverberator.py` (`VaultManifest` ≈4679-4910, `folder_range_end` ≈4667); Create `tests/test_names.py`.

**Interfaces:**
- Produces:
  - `NAME_ESCAPE = '\U0010fe00'`.
  - `storable_name(text:str) -> str` — per character: `NAME_ESCAPE` → `NAME_ESCAPE + NAME_ESCAPE`; a lone surrogate `\udc80`..`\udcff` (from surrogateescape) → `NAME_ESCAPE + chr(0x10ff00 + (ord(c) - 0xdc00))` (i.e. U+10FF80..U+10FFFF); every other character unchanged. Prefix-preserving (`storable_name(a + b) == storable_name(a) + storable_name(b)`).
  - `stored_name(text:str) -> str` — exact inverse; a `NAME_ESCAPE` followed by anything else is kept as is.
  - `VaultManifest.SCHEMA = '2'`; `entries` gains `copy_version INTEGER` (NULL = unknown). `_open` upgrades schema '1' in place in one transaction (`ALTER TABLE entries ADD COLUMN copy_version INTEGER`; double every `NAME_ESCAPE` already present in `entries.path` and in the inner-mounts meta value with SQL `replace()`, so such rare old names decode exactly; then `meta.schema = '2'`), keeping every row and every other meta key; any other unknown schema is dropped and rebuilt as today.
  - Every `VaultManifest` method that takes or returns a rel (and the `seen` temp table, `inner_mounts` / `set_inner_mounts`) stores through `storable_name` and returns through `stored_name`; range queries use `folder_range_end(storable_name(folder))`. Callers keep passing and receiving surrogate-escaped `str`.

- [ ] **Step 1: Write the failing tests** — doctests on both helpers: `'café'`, `'a/b/'` unchanged; `'bad\udcff.txt'` → `'bad' + NAME_ESCAPE + '\U0010ffff' + '.txt'`; `NAME_ESCAPE` doubled; round trip of `'x' + NAME_ESCAPE + '\U0010ff80'` (a literal look-alike) and of every byte 0x80..0xff after `os.fsdecode`. In `tests/test_names.py`:

```python
def test_manifest_round_trips_bad_names(job):
	# add, lookup, set_records, iter_files, iter_under('d\udcff/'), move_tree('d\udcff/', 'e/f/'), discard, take_dirty,
	# mark_seen/unseen, inner mounts: every rel comes back equal to what went in
def test_manifest_round_trips_escape_lookalikes(job): ...  # names holding NAME_ESCAPE and U+10FF80..
def test_schema_1_upgrades_in_place(job):
	# build a schema '1' database with rows, a skip fingerprint and inner mounts (sqlite3 directly, the old CREATE TABLE)
	m = rv.VaultManifest(job.job_vault)
	assert m.lookup('a.txt') is not None and m.skip_fingerprint == 'abc' and m.inner_mounts == ['mnt/']
	assert schema(job) == '2' and copy_versions(job) == {None}
def test_failed_upgrade_leaves_schema_1(job, monkeypatch): ...  # make the ALTER fail: schema '1' and rows intact
```

- [ ] **Step 2: Run `.venv/bin/python -m pytest tests/test_names.py -q`** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Store names through a reversible escape in the vault database, and upgrade it in place to record copy versions."`

---

### Task 2: Non-UTF-8 names through backups, change lists, pending transactions, journal and the commands

**Files:** Modify `reverberator.py` (change-list writing in `do_backup` ≈3666-3680 and `decrement_stepper`; `pending_transaction_rows` / `persist_pending_transactions` / `load_pending_transactions_for_resume`; journal writers; `iter_change_list`); Test `tests/test_names.py`.

**Interfaces:**
- Consumes: `storable_name`, `stored_name` (Task 1).
- Produces: every TSVZ-written row with a path (`path`, `source_path`, `moved_from`, journal `at_path` / `source_path`) passes through `storable_name`; `iter_change_list` and the pending-transactions loader return `stored_name(...)` of each path field. Files written by 0.39 read as before (identity for them).

- [ ] **Step 1: Write the failing tests** (bad names made with `os.fsencode` paths):

```python
def test_first_full_backup_of_a_bad_name(job): ...           # V0 committed, its copy has the exact bytes
def test_events_on_bad_names(job): ...                      # create, modify, delete, move (also to another depth) via run_backup + event_entry
def test_delta_generation_with_bad_names(job): ...          # full comparison after the upgrade finds no differences
def test_change_list_round_trips_bad_names(job): ...        # iter_change_list yields the exact str names
def test_pending_transactions_round_trip_bad_names(job, tmp_path): ...
def test_retention_with_bad_names(job): ...                 # prune V0, the copy materialises into V1 under its bytes
def test_nested_bad_names_survive_a_move_and_restore(job, tmp_path): ...  # 'd\udcff/x\udcfe' moved to 'a/b/', history lists it, restore recreates both names' bytes
def test_commands_take_bad_paths(job, tmp_path, capsys): ...  # history/restore with a surrogate-escaped argv path; output escaped
def test_status_and_marker_json_keep_bad_names(job, tmp_path): ...  # a status record detail and a restore marker path round-trip through JSON
```

- [ ] **Step 2: Run** → FAIL (the first backup raises UnicodeEncodeError today).
- [ ] **Step 3: Implement.** Find every TSVZ write of a path (`grep -n "TSVZ\." reverberator.py`) and every JSON write holding a path (status files, restore marker: keep `ensure_ascii=True` so surrogates survive).
- [ ] **Step 4: Run the full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Back up files whose names are not UTF-8, keeping their bytes in change lists, pending transactions and the journal."`

---

### Task 3: Escaped names in log lines

**Files:** Modify `reverberator.py` (`job_log` ≈713, `watcherTeeLogToTl` ≈2187, `backuperTeeLogToTl` ≈3372, other `tl.*` calls that format paths); Create `tests/test_log_text.py`.

**Interfaces:**
- Consumes: `shown()` (the commands' display escape; move it above its first use if needed).
- Produces: `log_text(text:str) -> str` — `shown()` for every character except `'\n'`, which stays a line break followed by four spaces, so no continuation line can start with a marker. `job_log` escapes its whole line with `shown()` (marker lines are always one line). The two log helpers pass message and path through `log_text`.

- [ ] **Step 1: Write the failing tests**

```python
def test_marker_with_a_bad_name_is_one_line(capsys): ...   # job_log('j', f'UNREADABLE: /m/a\nreverberator job x FAILED: y; …') -> printed as one line
def test_a_traceback_with_a_bad_name_cannot_start_a_line(capsys): ...  # backuperTeeLogToTl with a message holding '\nreverberator job x FAILED:' -> no output line matches the firewatcher regex in firewatcher/reverberator.regex
def test_logging_a_surrogate_name_does_not_raise(capsys): ...
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Escape names in log lines, so a file name can neither break a log write nor forge a marker line."`

---

### Task 4: Record each entry's copy version

**Files:** Modify `reverberator.py` (`VaultManifest`; the places a backup copies a file: complete V0 in `do_backup`, create/modify/move fallbacks in `do_reverb_backup`); Create `tests/test_long_chains.py`.

**Interfaces:**
- Consumes: Task 1 schema '2'.
- Produces:
  - `VaultManifest.set_copy_version(rels, version:int)`; `VaultManifest.iter_files_with_copy_version()` yielding `(rel, copy_version or None)`.
  - Every file copied into version N (complete backup, create, modify, the copy fallback of a move) gets `copy_version = N` in the same transaction as the version's commit; links leave it unchanged; a move keeps it.
  - `effective_copy_version(recorded, oldest_kept:int)` → `max(recorded, oldest_kept)`, or None when recorded is None (retention never needs to update rows: a pruned version's copies move into the next, which is then the oldest).
  - `learn_copy_version(job_vault:str, version_path:str, rel:str) -> int | None` — walks the entry's chain with `chain_hop` (no 39-link cap; bounded by the version number going down) and returns the number of the version folder holding the chain's end; None when the chain cannot be followed.

- [ ] **Step 1: Write the failing tests**

```python
def test_copies_record_their_version(job): ...      # V0 complete -> 0; a modify in V3 -> 3; an unchanged file keeps 0; a moved file keeps its number
def test_copy_version_follows_retention(job): ...   # keep_n_versions=3, after pruning V0..: effective_copy_version(recorded, oldest) equals learn_copy_version for every file
def test_learn_copy_version_past_39_links(job): ... # hand-built 45-version chain -> 0
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Record which version holds each file's real copy."`

---

### Task 5: Re-copy past the threshold

**Files:** Modify `reverberator.py` (`do_referenced_copy` ≈4266, `get_backup_size_inode`, `do_backup`'s change-list rows, `path_history` / `restore_candidates`); Test `tests/test_long_chains.py`.

**Interfaces:**
- Consumes: Task 4.
- Produces:
  - `RECOPY_MIN_HOPS = 32`, `RECOPY_MAX_HOPS = 38`; `recopy_threshold(rel:str) -> int` = `RECOPY_MIN_HOPS + xxhash.xxh32(storable_name(rel).encode('utf-8')).intdigest() % (RECOPY_MAX_HOPS - RECOPY_MIN_HOPS + 1)` (doctest pins two values).
  - `recopy_rels(manifest, new_version:int, oldest_kept:int, job_vault:str, latest_version_path:str) -> list` — `[]` at once when `new_version - oldest_kept <= RECOPY_MIN_HOPS`; otherwise the file rels whose `new_version - copy_version > recopy_threshold(rel)`, learning (Task 4) and recording unknown copy versions on the way.
  - `do_referenced_copy` copies each of those rels from the chain's end in the latest version (checked copy via `cp_af_copy_path` + `finish_copies`) instead of linking, then `set_copy_version(rels, N)`; their manifest records stay as they are (not dirty, not unchecked).
  - The version's change list gets one `(path, iso_time, 'recopy', None)` row per re-copy.
  - `get_backup_size_inode` (or its caller) adds the re-copies' sizes, so retention prunes first.
  - History and the restore picker skip `recopy` rows; a re-copied entry counts as unchanged.

- [ ] **Step 1: Write the failing tests**

```python
def test_no_chain_passes_38_hops(job): ...          # fast-forward 45 versions with one changing file: every other file's chain <= its threshold, and the kernel opens every entry of the newest version
def test_recopy_at_its_own_threshold(job): ...      # a file whose threshold is 34 re-copies exactly when its chain would be 35
def test_recopy_comes_from_the_vault(job): ...      # the live file changed (no event yet): the re-copy has the vault copy's content, mode, mtime_ns
def test_recopy_keeps_a_user_symlink_and_a_referenced_link(job): ...
def test_short_jobs_never_recopy(job, monkeypatch): ...  # <= 32 kept versions: recopy_rels returns [] without reading the vault (spy on learn_copy_version / os.lstat)
def test_upgraded_long_vault_recopies_only_past_threshold(job): ...  # schema '1' vault of 40 versions with copy_version NULL: only files past their threshold are re-copied
def test_size_estimate_counts_recopies(job): ...
def test_history_and_picker_skip_recopies(job): ...
```

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Copy a file again from the vault before its link chain passes 32 to 38 hops."`

---

### Task 6: Empty job names

**Files:** Modify `reverberator.py` (`run_daemon` ≈1000-1070, beside `colliding_job_names`; `find_job`; `format_status`); Test `tests/test_jobs.py`.

**Interfaces:**
- Produces: a rule whose cleaned name is `''` is stopped before anything touches its vault (no `remove_incomplete_vault_versions`, no watcher), via a permanent failure logged `reverberator job <the raw name, escaped> STOPPED: its name has no letters, digits, '-' or '_' left after cleanup; rename it in <rule file>`; `find_job` ignores such rules; `status` shows them as stopped with that reason. Exit status 3 applies when it was the only job, as for colliding names.

- [ ] **Step 1: Write the failing tests** — `test_a_job_whose_name_cleans_to_nothing_is_stopped` (process test or `run_daemon` in-process with a rule `!!!` and a normal job: the marker line, the other job backs up, nothing new under the vault root), `test_find_job_ignores_nameless_rules`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — `"Stop a job whose name cleans up to nothing, before it can touch the vault root."`

---

### Task 7: Round 3 leftovers in the daemon

**Files:** Modify `reverberator.py`; Tests in the existing files for each area.

Spec appendix items **1, 2, 3, 4, 5, 6, 10, 11, 14, 16, 17** (exact behaviour in the spec's table). Interfaces fixed here: item 17's marker text `reverberator job <name> FAILED: cannot check the restore lock <path>: <error>; pruning postponed`, first after `DISK_WAIT_GRACE_SECONDS`, then every `DISK_WAIT_REPEAT_SECONDS`, tracked per job; item 5's shared parser `parse_chain_text(job_vault:str, link_text:str, link_path:str) -> tuple | None` returning `(version_name, rel_parts)` used by both `chain_link_target` and `chain_form_missing_version`.

- [ ] **Step 1: Write a failing test for each item that changes behaviour** (items 1, 2, 4, 6, 10, 11, 14, 16, 17; items 3 and 5 are docstrings/refactor covered by existing tests).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** (one or more) — e.g. `"Tidy round 3's daemon leftovers: retarget failures, the folder cache, the restore lock's alert and log repetition."`

---

### Task 8: Round 3 leftovers in `status` and `history`

**Files:** Modify `reverberator.py` (commands section); Tests `tests/test_status_command.py`, `tests/test_history.py`, `tests/test_command_reading.py`.

Spec appendix items **7, 8, 9, 12, 13, 18, 19, 20, 21**. Item 12's formats: counts below 1000 as integers (`4 inodes`), `no limit`, `0 B`. Item 18: `history --files` prints each row as it is produced (no full list held). Item 19: a version's change list is read only when that version or the one below holds the path; each version's entry is resolved once.

- [ ] **Step 1: Failing tests per item.** **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — e.g. `"Tidy round 3's status and history leftovers."`

---

### Task 9: Round 3 leftovers in `restore`

**Files:** Modify `reverberator.py` (restore section); Tests `tests/test_restore.py`, `tests/test_restore_in_place.py`, `tests/test_restore_lock.py`.

Spec appendix items **15, 22-32**. Item 22: each `FAILED <rel>: <reason>` line is printed when it happens; the summary gives the counts and repeats at most the first 20. Item 25: the picker and its prompt write to stderr. Item 27's marker may record entries whose metadata could not be set, as a list capped at 1000 rels.

- [ ] **Step 1: Failing tests per item.** **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Full suite on both venvs** → pass.
- [ ] **Step 5: Commit** — e.g. `"Tidy round 3's restore leftovers."`

---

### Task 10: Remaining tests, README, version

**Files:** tests named in spec appendix item 34 not already added by Tasks 7-9; appendix item 33 (the unclosed file in `tests/test_status_files.py`, return annotations that omit None); `README.md`; `reverberator.py` (`__version__ = 0.40`); `pyproject.toml` (`version = "0.40"`).

- [ ] **Step 1: Add the remaining item-34 tests** (each must pass against the current code, or expose a bug that is then fixed in the same commit).
- [ ] **Step 2: README** — in the README's style: non-UTF-8 names are backed up and shown escaped; names in logs are escaped; long-lived files are copied again every 32 to 38 versions on jobs keeping that many (logged as `recopy`, not shown by history); a job whose name cleans to nothing is stopped; the vault database is upgraded in place on the first 0.40 start and an older reverberator would rebuild it from the vault (rollback not supported); plus appendix item 35's omissions.
- [ ] **Step 3: Bump the version in both places; run the full suite on both venvs** → both pass with the same counts.
- [ ] **Step 4: Commit** — `"Document 0.40 and add round 3's remaining tests."`
