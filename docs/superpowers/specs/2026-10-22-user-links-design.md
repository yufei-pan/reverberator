# Telling users' symlinks from the vault's own links (0.44)

## Intent

Each version stores an unchanged file as a relative symlink back to the previous version's entry, a *chain link*. A symlink that the monitored tree itself holds, a *user link*, is backed up as a symlink too. Today the daemon tells the two apart by the link's text alone (`parse_chain_text` / `strict_chain_hop`, round 3's chain-link rule). It ignores the number of `../` and accepts absolute links. So a user link whose text has the chain form is read as the vault's own.

The round 8 investigation reproduced the damage at every site that follows links. Repros are in the session scratchpad, `r8/repro/`, and the report is `r8/investigation.md`.

| Site | Wrong result, for a user link in the chain form |
|---|---|
| Pruning (`decrement_stepper`) | Moves the named file's copy onto the user link, or deletes the link, so the named file is missing from every kept version. A link naming a folder fails with ENOTDIR at every prune: retention stops for good, with no FAILED marker. |
| Round-4 re-copy | Puts the named file's bytes where the link was. |
| History and restore | Show "moved from" the named file and restore its bytes. A link naming a folder restores as an empty private folder. A link naming a missing version is refused as "dangling". |
| Attribute sync | Round 7's kind check misses chain ends that are symlinks, so owner and times land on another entry of an older version. |
| Manifest, comparisons | Record the link as the named file, so it is copied again: once for a relative link, every time for an absolute one. |
| Retargeting | Low impact: round 7's verification repairs it. |

**The live vaults are not affected today.** A read-only scan of all 8 jobs (32 kept versions, 1,070,353 symlinks) found no user link in the chain form. The new rule accepts every chain link they hold, so no migration is needed.

## Goals

1. **One shared classifier.** It decides whether a link at `V<k>/R` is a chain link, using the investigation's rule (report section 6.1). A link whose text names `V<k-1>/R'`, with `u` leading `../` and passing today's checks (the exact `V<k-1>` name, real folders on the way), is a chain link only if all of these hold:
   - **(a) Moves.** V<k>'s move rows, applied in their order (to a file, or to a folder and everything under it), take R' to R.
   - **(b) No move.** When no move row of V<k> applies to R' (so R' = R), u equals depth(R) + 1: exactly the text the referenced copy writes. When a move applies, any u ≥ 1 is accepted, because a failed retarget, or a daemon before 0.39, keeps the old depth.
   - **When the rows are read.** V<k>'s rows are read whenever R' ≠ R **or** u ≠ depth(R) + 1. For example, `mv x d/x; mv d e; mv e/x x`, with the last retarget failing, leaves `V1/x -> ../../V0/x`: R' = R, but the depth is off, and the moves take x back to x. That link must be accepted.
   - **Which rows are moves.** Move rows are those whose event is `move`. Escalated create and modify rows that carry a source are not moves.
   - **(c) Not a folder.** The target is not a real folder: the daemon links files only.

   Two more rules come with it:
   - **Absolute texts are never chain links.**
   - **Cannot tell.** An unreadable folder on the way, or a move row without a source landing on R or a folder above it, counts as "cannot tell", as today. Pruning and reading treat that as a chain link.
   - **Rows that cannot be used.** A version's change list may be missing, empty (a crash right after the commit: every real version after V0 has at least one row), unreadable, or hold rows that do not start with the job's current monitored path (the path was changed). Such a version is classified by the text alone, as today, and one warning is logged per version. Refusing its moved links would lose copies; following them as today does not.
   - **Finding the change list.** A version's change list is found by listing the job vault for its `V<n>--<timestamp>` prefix, not by rebuilding the name from recorded sizes.

   Where the moves come from:
   - For a committed version, from its change list, parsed once and cached per version. The change list is read only when R' ≠ R.
   - For the version being written, from the replay's own list of the moves it has applied: a new list, in replay order.
     - Each move is added before its own `retarget_moved_links` runs.
     - A move that fell back to delete-and-copy is not added, since it renamed no link.
     - The list reaches the readers of the new version: `sync_attributes`, the verification's `compare_scopes` → `compare_entry` → `read_version_record`, and `record_dirty_entries` → `read_copied_record`.
2. **Every site uses the classifier.** That means `chain_end`, `read_vault_record`, `resolve_version_entry`, `history_entry`, `decrement_stepper`, `sync_attributes`, the re-copy, `retarget_chain_link`, the move branch's metadata check, `learn_copy_version` and `recopy_size`.
   - `chain_form_missing_version` reports "dangling" only for a text that passes (a)/(b) for its place; anything else is a user link.
   - The absolute branch of `strict_chain_hop` and `is_chained_link` goes.
3. **Pruning never wedges silently.**
   - (c) means a folder is never renamed onto a link.
   - An "Aborting removal" in `decrement_stepper` is logged through `job_log` as a FAILED marker, so firewatcher alerts on a wedged prune. It is logged once, then once an hour while the wedge lasts, as the restore lock's marker is.
   - `decrement_stepper` and `prune_oldest` get the job name and the monitored path from `do_backup`.
4. **The manifest doesn't follow the backup's own fresh link copies.** `read_copied_record` lstats the rels this backup copied, instead of following them, so a user link is recorded as a link with its text.
   - For the latest version, `copy_version` overrides the classifier: `chain_end`, `read_vault_record`, `sync_attributes` and the re-copy follow down to the version `copy_version` names, and stop there. The manifest is that version's authority.
   - So a refusal by the classifier, for example on rows that cannot be used, can never make the re-copy copy a link that no rule will follow later.
5. **Version 0.44**, in `reverberator.py` and `pyproject.toml`, and one README sentence: a user's symlink is never taken for the vault's own link, except one whose text is exactly its own path's link to the previous version.

## Non-goals

- **Option B**, a per-version record of user links: a side file, or a new change-list event. That would close the remaining blind spot, but adds a new vault artifact. It is the user's call, and off by default (see Decisions).
- Repairing versions written before 0.44: the scan found nothing to repair.
- Changing the change-list, manifest or pending formats.

## Anti-goals

- **Refusing a real chain link.** Pruning by a rule that refuses one would lose copies, which is worse than the bug. The candidate rule the investigation rejected did exactly that. The new rule must accept every chain link the current rule accepts in real histories:
  - the suite-wide ground-truth check, the investigation's `r8/rules/r8plugin.py`, becomes a permanent test helper;
  - all 1,070,249 chain links of the live scan are accepted.
- Writing or removing anything outside the version being written. Round 7's guards stay.
- Slowing ordinary backups: the change list is read only for moved entries, once per version.

## Decisions (builder's calls, made here)

- **The remaining blind spot is accepted.** That is a user link whose text is exactly its own path's chain text, or its own pre-move path's, e.g. `a/U -> ../../<V<k-1>>/a/U`. Its damage stays on that one path: pruning and restore give a/U's own older copy. It needs the newest version's exact name typed between two backups. The README sentence says so.
- **A legacy switch for absolute chain links:** not added. No live version holds one.

## Tests the change must add

- Each repro in `r8/repro/`, inverted: the user link stays a link, and no other file's copy moves, changes or disappears, in every kept version, after pruning, re-copies, attribute syncs, history and restore.
- A link naming a folder: pruning goes on, and nothing is renamed onto the link.
- A wedged prune logs one FAILED marker that matches firewatcher's patterns.
- The ground-truth helper over the whole suite: no daemon link refused, and no user link accepted except the documented blind spot.
- Sequences that make chain links through moves (mkdir+mv in one batch, two moves in one batch, move away and back, a failed retarget, pre-0.39-style depth): all still accepted.
- **Away and back with a failed retarget:** `mv x d/x; mv d e; mv e/x x` with the last retarget failing. The link is accepted, and pruning keeps x.
- **Rows that cannot be used:** an empty change list, an unreadable one, a missing one, and rows under an old monitored path. Every moved chain link of that version is still followed, pruning keeps every copy, and one warning is logged.
- **The ground-truth helper** also hooks `decrement_stepper`, so it checks the links pruning acts on, not only those left at a test's end. The builder check's `r8/check/r8check.py` shows how.
- **Existing tests that encode the rule being removed** are updated to the new rule, each with a one-line reason:
  - header-only change lists from `write_committed_version`, for example `test_chain_links.py::test_a_two_hop_read_passes_a_link_an_old_move_broke_in_the_middle` and `test_history.py::test_history_of_versions_without_change_rows`;
  - absolute chain links in `test_retention.py`'s `_two_versions_symlink_pair`, `test_command_reading.py`, `test_restore.py`, and the `absolute` parametrisations in `test_chain_links.py`;
  - the doctests of `strict_chain_hop`, `is_chained_link` and `chain_form_missing_version`.
  - A test relying on a header-only change list for a moved link now falls under "rows that cannot be used", so it still follows by the text.
