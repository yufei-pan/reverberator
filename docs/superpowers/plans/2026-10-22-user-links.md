# Telling Users' Symlinks from the Vault's Own Links Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One classifier decides whether a symlink in a version is the vault's own chain link. It uses the link's depth, the version's move rows, and refuses absolute links and folder targets. Every site that follows links uses it, so a user's symlink is never taken for a chain link.

**Architecture:**
- `VersionMoves` gives a version's move rows. For a committed version they come from its change list, parsed once and cached; for the version being written, from the replay's list of applied moves. It reports whether the rows are usable.
- `vault_chain_hop` implements the design's rule on top of today's text checks, with the unusable-rows fallback to the text alone.
- The sites switch to it. Pruning gets the job name and monitored path, and a FAILED marker when it wedges.
- The manifest stops following the backup's own fresh link copies. For the latest version, `copy_version` is authoritative.

**Tech Stack:** Python ≥ 3.8, single module `reverberator.py`, pytest.

**Spec:** `docs/superpowers/specs/2026-10-22-user-links-design.md`

## Global Constraints

- **Style.** Code is tab-indented and matches the surrounding naming, comment density and docstring-with-doctest style.
- **Library versions.** It must work on the service venv (`/mnt/optane/work/reverberator/.venv`: Tee_Logger 6.40, multiCMD 1.51, TSVZ 3.39) and the worktree venv.
- **Where to work.** Only in `/mnt/optane/work/reverberator/.worktrees/user-links`.
  - Never edit the main checkout: the live service runs from it.
  - Never touch `/etc`, systemctl or real vaults.
  - Never commit `uv.lock`.
- **Tests.** Run from the worktree root on both venvs (baseline below):
  - `.venv/bin/python -m pytest -q -p no:cacheprovider`
  - `PYTHONDONTWRITEBYTECODE=1 /mnt/optane/work/reverberator/.venv/bin/python -m pytest -q -p no:cacheprovider`
- **Commit messages.** One plain sentence or two, in the repo's style, ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_0179SV9GcZcp5fPuVSWUarb6
  ```
- **The anti-goal: never refuse a real chain link.** Pruning by a rule that refuses one loses copies. Every task keeps the investigation's suite-wide ground truth at zero daemon links refused.
- **Data safety from round 7 stays.** No write or removal through a link, and nothing outside the version being written changes.
- **Reference data,** all under `/tmp/claude-0/-mnt-optane-work-reverberator/8ad4e979-212b-4a0b-9477-1847dfee5560/scratchpad/r8/`:
  - `investigation.md` (section 6.1 is the rule)
  - `repro/` (25 repros, each passing while its bug is there)
  - `rules/` (`r8rules.py`, `r8plugin.py`: the ground-truth checker)
  - `check/` (the builder check's `r8check.py`, which also hooks `decrement_stepper`, plus `test_check_away_back.py`)

## Review Focus

1. **Moved chain links in a version whose rows cannot be used** (empty, missing, unreadable, or under an old monitored path) are still followed. Pinned in Task 1 by `test_rows_that_cannot_be_used_fall_back_to_the_text`, and in Task 2 by `test_pruning_keeps_moved_copies_when_rows_cannot_be_used`.
2. **Away and back with a failed retarget** (`mv x d/x; mv d e; mv e/x x`, depth off, R' = R) is accepted, and pruning keeps x. Pinned in Task 1 by `test_away_and_back_with_a_failed_retarget_is_a_chain_link`, and in Task 2 by its prune test.
3. **A user link naming a folder** never wedges pruning, and never has a folder renamed onto it. Pinned in Task 2 by `test_a_user_link_naming_a_folder_never_wedges_pruning`.
4. **The version being written.** Links that a move in this batch renamed are classified with the applied-moves list, including the move whose retarget is running. Pinned in Task 3 by `test_links_moved_in_this_batch_are_chain_links_for_its_readers`.
5. **Escalated create or modify rows carrying a source are not moves** (git's `X.lock` rename). Pinned in Task 1 by `test_escalated_rows_with_a_source_are_not_moves`.

---

### Task 1: The classifier

**Files:**
- Modify: `reverberator.py`:
  - `parse_chain_text` (about line 5921): also return the `../` count;
  - `strict_chain_hop` (about 6005) and `is_chained_link` (about 6103): drop the absolute branch;
  - `chain_form_missing_version` (about 7887);
  - add `VersionMoves` and `vault_chain_hop` near `strict_chain_hop`.
- Test: `tests/test_vault_chain_hop.py` (new).

**Interfaces:**
- Produces `class VersionMoves`. It carries a version's move rows as ordered `(source_rel, dest_rel, is_folder)` triples, where rels have no leading `/` and folders end with `/`, plus `usable: bool`.
  - `VersionMoves.of_committed(job_vault:str, version_path:str, monitor_path:str) -> VersionMoves` finds the change list by listing `job_vault` for the version's `V<n>--<timestamp>` prefix. It reads the rows whose event is `move` and converts the paths relative to `monitor_path`.
    - `usable` is False when the change list is missing, unreadable, or has no rows at all.
    - `usable` is also False when any row's path does not start with `monitor_path`.
    - The result is cached per (version_path, monitor_path), so a version's change list is parsed once.
  - `VersionMoves.applied(moves:list) -> VersionMoves` is for the version being written, from the replay's list. It is always `usable`.
  - `VersionMoves.takes(source_rel:str, dest_rel:str) -> 'bool | None'`. It applies the moves in order, to a file, or to a folder and what is under it, and says whether they take source_rel to dest_rel. It returns None for "cannot tell": a move row without a source lands on dest_rel or a folder above it.
  - `VersionMoves.touches(rel:str) -> bool`: whether any move row applies to rel.
- Produces `vault_chain_hop(job_vault:str, link_path:str, link_text:str, moves:'VersionMoves') -> 'str | None'`. It returns the hop target path when the link at link_path is a chain link, or None when it is not, and raises `UncheckedVaultLink` when it cannot tell. The rule is the spec's Goal 1:
  - The checks `strict_chain_hop` makes today come first (relative text, the exact previous-version name, real folders on the way). Absolute texts give None.
  - With R the link's rel, R' the named rel and u the `../` count:
    - if R' ≠ R or u ≠ depth(R) + 1, the moves are consulted: `takes(R', R)` True gives the hop; False gives None; None raises `UncheckedVaultLink`;
    - otherwise the link is a chain link with no moves read.
  - A target that is a real folder gives None.
  - When `moves.usable` is False, the decision falls back to today's text rule alone (with u ignored), and one warning per version is logged.
- `strict_chain_hop(job_vault, link_path, link_text)` keeps its signature for callers not yet switched over. Its absolute branch goes in this task; the callers switch in Tasks 2-3.

- [ ] **Step 1: Write the failing tests** in `tests/test_vault_chain_hop.py`. Use hand-built job vaults with real change lists, written the way `do_backup` writes them; see `tests/harness.write_committed_version`, extended to take rows.
  - `test_an_unmoved_link_at_its_own_depth_is_a_chain_link`.
  - `test_a_user_link_naming_another_rel_is_not_a_chain_link`: the repro 1.1 text `a/U -> ../<V0>/D/secret` gives None.
  - `test_a_moved_link_is_a_chain_link_when_the_moves_take_it_there`: a file move, a folder move with a file under it, two moves in one batch, and mkdir+mv.
  - `test_away_and_back_with_a_failed_retarget_is_a_chain_link`: the rows `('d/x','move','x'), ('e/','move','d/'), ('x','move','e/x')`, with the link `V1/x -> ../../V0/x`. The result is the hop.
  - `test_a_depth_off_without_a_move_is_not_a_chain_link`: `x -> ../../V0/x` with no move rows gives None.
  - `test_absolute_links_are_never_chain_links`.
  - `test_a_link_naming_a_folder_is_not_a_chain_link`.
  - `test_escalated_rows_with_a_source_are_not_moves`: a `('X','create','X.lock')` row is not a move.
  - `test_rows_that_cannot_be_used_fall_back_to_the_text`: for each of an empty change list, a missing one, an unreadable one (chmod 000) and rows under another monitored path, a moved chain link is followed, and one warning is logged per version.
  - `test_a_move_row_without_a_source_cannot_be_told`: it raises `UncheckedVaultLink`.
  - Update the doctests of `parse_chain_text`, `strict_chain_hop`, `is_chained_link` and `chain_form_missing_version` to the new rule.

- [ ] **Step 2: Run them and watch them fail.** Run `.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_vault_chain_hop.py`. Expected: FAIL, because `VersionMoves` and `vault_chain_hop` are not defined.

- [ ] **Step 3: Implement** `VersionMoves`, `vault_chain_hop`, the `parse_chain_text` count, and the removal of the absolute branch. Update the existing tests that encode absolute chain links, each with a one-line reason; the spec lists them.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass on both venvs.

- [ ] **Step 5: Commit.**

### Task 2: Pruning, history and restore use the classifier

**Files:**
- Modify: `reverberator.py`:
  - `decrement_stepper` (about 7208) and `prune_oldest` (about 7163): add `monitor_path` (and the job name where it is missing), passed from `do_backup` (about 4336-4355);
  - `chain_end` (about 6140);
  - `read_vault_record` (about 6299);
  - `resolve_version_entry` (about 7932) and `history_entry` (about 8467);
  - the restore picker's callers of these.
- Test: `tests/test_user_links.py` (new).

**Interfaces:**
- Consumes `VersionMoves`, `vault_chain_hop` (Task 1).
- `decrement_stepper(vault_info_dict, job_name:str, monitor_path:str) -> tuple`.
  - It classifies each link of the next version with `vault_chain_hop` and `VersionMoves.of_committed` of that version.
  - It never renames a folder onto a link.
  - An "Aborting removal" logs a FAILED marker through `job_log`: once, then every `DISK_WAIT_REPEAT_SECONDS` while it lasts, as prune_oldest's restore-lock marker does.
- `prune_oldest(..., monitor_path:str)` passes `monitor_path` through.
- `chain_end`, `read_vault_record`, `resolve_version_entry` and `history_entry` use `vault_chain_hop` with the moves of each version they step through, all committed versions here.
- For a version whose moves are not usable, `chain_form_missing_version` reports "dangling" only for a text that passes the rule for its place; any other text is a user link.

- [ ] **Step 1: Write the failing tests** in `tests/test_user_links.py`, inverting each repro in `r8/repro/` that covers pruning, history, restore or the re-copy's `chain_end`.
  - The user link stays a link, and no other file's copy moves, changes or disappears, in every kept version: listing, link targets, bytes, mode, owner, mtime.
  - `test_a_user_link_naming_a_folder_never_wedges_pruning`: pruning goes on, and nothing is renamed onto the link.
  - `test_a_wedged_prune_logs_one_failed_marker`: force the abort. One marker matches firewatcher's patterns (see `tests/test_log_text.py`'s `alerting_lines`), and the repeat is on the timer.
  - `test_pruning_keeps_moved_copies_when_rows_cannot_be_used`: an empty change list and one under an old monitored path.
  - `test_away_and_back_with_a_failed_retarget_survives_pruning`: port `r8/check/test_check_away_back.py`.
  - History and restore of a user link in chain form show it as a symlink, never as "moved from" another file, and restore it as the link.

- [ ] **Step 2: Run them and watch them fail.** Expected: FAIL as the repros show.

- [ ] **Step 3: Implement** the signature changes, the switch to the classifier and the FAILED marker. Update the existing tests that rely on header-only change lists for moved links. Under "rows that cannot be used" they still follow by the text, so most should pass unchanged; give a reason for each one you edit.

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass.

- [ ] **Step 5: Commit.**

### Task 3: The version being written uses the replay's applied moves

**Files:**
- Modify: `reverberator.py`:
  - `do_reverb_backup`: the replay's move branch, `retarget_moved_links`, `sync_attributes` and the verification;
  - `read_version_record` and `compare_entry`;
  - `record_dirty_entries` and `read_copied_record` (about 6334);
  - the re-copy, `learn_copy_version` and `recopy_size`.
- Test: `tests/test_user_links.py` (append).

**Interfaces:**
- Consumes Task 1 and Task 2.
- `do_reverb_backup` keeps `applied_moves: list` of `(source_rel, dest_rel, is_folder)`, in replay order.
  - A move is added before its `retarget_moved_links` runs.
  - A move that fell back to delete-and-copy is not added.
  - `VersionMoves.applied(applied_moves)` is passed to every reader of the new version: `sync_attributes`, `retarget_chain_link`, the move branch's metadata check, the verification's `compare_scopes` → `compare_entry` → `read_version_record(fresh=True)`, and `record_dirty_entries` → `read_copied_record`. It goes through the compare and record thread pools as an argument.
- `read_copied_record` lstats a rel whose `copy_version` is this version, instead of following it, so a copied user link is recorded as a link with its text.
- For the latest version, `copy_version` is authoritative. `chain_end`, `read_vault_record`, `sync_attributes` and the re-copy follow down to the version `copy_version` names and stop there, even where the classifier would refuse a hop.

- [ ] **Step 1: Write the failing tests.**
  - `test_links_moved_in_this_batch_are_chain_links_for_its_readers`: a batch that moves a file to another depth, then changes its attributes, then verifies. The attribute sync and the verification follow the moved chain link.
  - Invert the repros for the attribute sync (`r8/repro/test_r8_sync_attributes.py`) and the manifest (`test_r8_manifest.py`). The user link is recorded as `l` with its text, and is not copied again at the next comparison: there is no churn.
  - `test_copy_version_is_authoritative_for_the_latest_version`: a row whose `copy_version` names an older version is followed down to that version even when the classifier would refuse a hop. The re-copy never copies a link that no rule follows later.

- [ ] **Step 2: Run them and watch them fail.**

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run the new file and both full suites.** Expected: all pass.

- [ ] **Step 5: Commit.**

### Task 4: The ground-truth guard, the README and 0.44

**Files:**
- Create: `tests/chain_ground_truth.py`, a pytest plugin or fixture module loaded by `tests/conftest.py`.
- Modify: `README.md`, `reverberator.py` (`__version__`), `pyproject.toml` (`version`).

**Interfaces:**
- Port `r8/rules/r8plugin.py` and `r8/check/r8check.py`.
  - Record every symlink `reverberator.py`'s own frames create.
  - At each test's end, and before each `decrement_stepper` acts, classify every symlink of every kept version with `vault_chain_hop`.
  - Fail the test if a daemon-made link is refused, or a user link is accepted, outside the documented blind spot. The blind spot is a user link whose text is exactly its own path's chain text; the test that makes one marks it.
- Keep the plugin cheap: on by default, with an environment switch to turn it off.

- [ ] **Step 1: Write the plugin.** Run the full suite with it; expected: zero violations. Then break the classifier on purpose (e.g. always None) and confirm it fails tests; restore.
- [ ] **Step 2: README.** Add to the design notes: "A symlink the monitored tree holds is backed up as a symlink and is never taken for the vault's own link to an older version, except one whose text is exactly its own path's link to the previous version, which only that path can be confused by." Set `__version__ = 0.44` and `version = "0.44"`.
- [ ] **Step 3: Run both full suites.** Expected: all pass.
- [ ] **Step 4: Commit.**
