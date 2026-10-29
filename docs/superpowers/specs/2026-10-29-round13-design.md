# Round 13: no traceback from a rename-heavy batch, a warning for repeated job names

Version 0.49. The two items the user deferred to round 13 on 2026-10-29 (docs/limitations.md), built while the user
slept: "if there are things you can do in round 13 you can start it after you are done with 12".

## The user's words

- The traceback: "Defer to round 13 (Recommended)", on "Find the replay order that loses the move's source, so the rename
  works and no traceback is logged."
- Repeated job names: "Warn in round 13 (Recommended)", on "One warning per repeated job name at start, naming the row
  that wins; your file stays as it is."
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK.

## What the investigation found (round 13 scratch, before this design)

The traceback ("Failed to move", FileNotFoundError, then "Doing delete & copy instead") has more than one cause. All of
them leave the versions right only because the delete-and-copy fallback and the verification after each batch repair
them.

1. **The collapse strands a copy (the probe's case).** In `change_events_to_backup_entries`, a move of a file made or
   saved in the batch is turned into a copy (the escalation). `carried()` takes that copy through a later folder move,
   then stops at the file's own later move, leaving it to the path-exact chain merge, which already ran and missed it
   (it is keyed on the path before the folder move). So `echo new > f; mv f d/g; mv d D; mv D/g h` collapses to
   `D/ <- d/`, `h <- D/g` (a move whose source the version never holds) and a stranded `D/g` create. No replay order can
   make that rename work: the version never held `f`. Minimal reproduction:
   scratchpad r13/investigate/tests/test_r13_rename_traceback.py.
2. **A file moved on before its create was copied (a live race).** A batch's create runs after the file has moved on
   (seen across a vault wait), so the next batch's move has no source in the version.
3. **A chain merge across a folder move** (`mv a/f g; mv a A; mv g h`), and **a move into a folder made in the batch that
   then moves** (`mkdir x; mv old x/f; mv x y`): the move's source or destination is not where the version has it when
   the rename runs. Today the fallback copies the file again (its chain link to the older copy is lost).

## Goal 1: the collapse carries an escalated copy to where the file ends

In `change_events_to_backup_entries`' escalation (the block that turns a move of a file made or saved in the batch into
a copy), every later move of that same entry goes with the copy, whether the path-exact chain merge linked it or a carry
through a moved folder reached it: after `carried()` returns a path, while that path's own later move exists (a `move`
entry whose source is that path), drop that move and carry on from its destination with its time; land the copy where
the entry ends the batch (the existing `stands()` rule), and leave a `delete` at the first move's destination (it
removes what the version held there, as the dropped rename would have). Moves of files the version holds are never
escalated, so they keep their links. No committed version's content changes; the replay is right on its own, with no
rename, no traceback and no "Not tracking … source no longer exists" line. (The investigation's prototype: about 20
lines; 22 of 22 variant checks pass where today's code fails 16; the move-related suites pass. scratchpad
r13/investigate/prototype.diff.)

The user's words said "so the rename works": there is nothing in the version to rename in this case, so the right
result is the copy at the end path (the main session's call; the user's intent, no traceback and a right replay, holds).

## Goal 2: a move whose source the version does not hold is copied, not renamed

In the replay's move step, before `manifest.move_file()` and the rename, a move whose source is not in the version being
written (`os.path.lexists` false, through real folders) is replayed as a copy of its target: one warning line naming the
move and that its source is not in the version, no traceback, and no manifest row moved for a file that is not there
(today `move_file()` runs first and leaves a row the verification must repair). This covers causes 2 and 3 above, at the
cost today's fallback already pays (a copy of the file). Tests keep asserting that the batches the collapse makes in
Goal 1's cases never take this path. (The main session's call, within the user's "no traceback is logged".)

## Goal 3: one warning per repeated job name

At each start, `parse_rules` counts the rule file's job-name cells as TSVZ keys them (first cell right-stripped; comment
lines, the header and the `#_defaults_#` row excluded). For each name that appears more than once it logs one warning
naming the name, the rows (line numbers) that repeat it and the row that wins (the last one, as TSVZ reads it). The file
stays as it is. Cleaned-name collisions (two rows whose names become one job name) keep their existing STOPPED rule.

## Goal 4: version 0.49, docs

- `__version__ = 0.49`, pyproject `version = "0.49"`.
- docs/limitations.md: remove the two deferred entries this round closes ("A rename in a rename-heavy batch can fail and
  log a traceback", "Repeated job names in the rule file") and their README lines; README design lines for Goals 1-3.
- Open for the user in the morning, not written down: causes 3 cost a copy of an unchanged file (its chain link to the
  older copy is lost) — a known limitation, or a later collapse change that keeps the links.

## Non-goals

- Keeping chain links for cause 3 (the collapse change it needs is larger; for the user).
- Any change-list, pending-batch, manifest or rule-file format change.

## Constraints

- Work in `.worktrees/round13`, branch `round13` (from round12 91b490b, not merged); never in the live checkout; never
  write under /etc, /run/reverberator, /mnt/jank, /mnt/impulse or /mnt/klein; never read /etc/firewatcher/firewatcher.conf;
  never touch /mnt/arch-h3render; no sysctl or systemctl; tests at 2 processes at most; both full suites pass.
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

The exact warning texts, the escalation's code shape (the prototype is a starting point, not the spec), and the tests'
names.
