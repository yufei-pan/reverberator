# Round 13: no traceback from a rename-heavy batch, a warning for repeated job names

Version 0.49. The two items the user deferred to round 13 on 2026-10-29 (docs/limitations.md), built while the user
slept: "if there are things you can do in round 13 you can start it after you are done with 12".

## The user's words

- The traceback: "Defer to round 13 (Recommended)", on "Find the replay order that loses the move's source, so the rename
  works and no traceback is logged."
- Repeated job names: "Warn in round 13 (Recommended)", on "One warning per repeated job name at start, naming the row
  that wins; your file stays as it is."
- During the build (2026-10-29), on a move into a new folder made at its own old place (`mv D x; mkdir D; mv x D/D`):
  "One warning, copy (Recommended)", on "A move whose target is under its own source in the version is not tried: one
  warning line, no ERROR, no traceback, then the copy as today"; and for the copy's cost (the moved folder's files written
  again, their chain links lost): "Known limitation (Recommended)".
- After Task 4's review (2026-10-29): the approved entry "Swaps in one batch are repaired by copies" says two folders are
  copied whole and a file swapped with a folder logs one ERROR line: "Correct the entry (Recommended)"; the copy of an
  unchanged entry in `mv a/f g; mv a A; mv g h`, `mkdir x; mv old x/f; mv x y` and `mv D/sub t; rm -r D; mv t D` (one
  warning each in 0.49): "Widen the known limitation (Recommended)", the approved entry "A move into a folder made after
  an earlier move in one batch".
- After the final review (2026-10-29): `Not tracking <path>: source no longer exists` (the copy of an entry gone from the
  live tree, 2,820 in the live journal since 10-15): "Warning level (Recommended)"; the collapse escalating one move twice
  when the watcher sends create + modify (`echo new > f; mv f d/g; mv d D; rm D/g` leaves a stray copy and a Not tracking
  line): "Fix in round 13 (Recommended)"; the older collapse shapes of the Task 1 review (Minors 3 and 4): "Widen the
  known limitation (Recommended)"; the silent one (`mv d e; mkdir d; touch f; mv f d/g; mv d D; rm D/g`, e/g copied
  again by the comparison): "Fold into the widened entry (Recommended)".
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
a copy), the copy goes with every later move of that same entry and lands where the entry ends the batch. The rule (the
spec check's, tested in scratchpad r13/spec-check/fix, ~15 lines over the investigator's prototype; diff
r13/spec-check/fix_vs_proto.diff):

- After `carried(moveDest, entry_when[moveDest], True)` returns `now_at != moveDest`, take the move `carried()` stopped
  at: in `later[now_at]`, the last entry below `escalated_bound`. If that entry ends the path there (None), stop.
- Otherwise its destination is `dest`. If `backup_entries[dest]` is a `move` whose source is `now_at`, that is the
  entry's own move; otherwise it was chain-merged on to its end: use `moveSourceToDestDict[now_at]`, but only when no
  other event touched `now_at` between the bound and the event (`i == len(later[now_at])`). (Taking
  `moveSourceToDestDict[path]` alone is wrong: it holds the earliest move out of the path after the event, which can be
  an older file's move from before the copy got there.)
- Drop that move, carry on with `carried(dest, entry_when[dest], True)`, and repeat. Land the copy with the existing
  rule (it lands when the end path has no entry, has an attrib, or `not stands()`; otherwise the standing entry replays
  and the copy is dropped). Folders made in the batch go the same way.
- Leave a `delete` at the first move's destination only when the loop dropped at least one move, and drop that delete
  again when the reverse walk later meets a move whose source is that path or a folder above it (that move takes what
  the version held there away; deletes replay first, so the delete would remove a file another move still needs).

Moves of files neither made nor saved in the batch are never escalated, so they keep their links. No committed version's
content changes; the replay is right right after the verification (a pre-existing collapse of `mv q a; rm a` with `a` in
the version leaves the old `a` until the verification removes it: outside this round, for the user). In the spec check's
48 cases (with and without verification) the fixed rule logs no traceback, "Not tracking" or "Cannot read" line and
loses no chain link.

The user's words said "so the rename works": in Goal 1's case there is nothing in the version to rename, so the right
result is the copy at the end path (the main session's call; the user's intent, no traceback and a right replay, holds).

**One escalation per move (the user's choice after the final review).** The watcher sends `create` then `modify` for a
written file, and an editor's save sends `modify` alone or several. Every content event of a path before its move is
"made or saved in the batch", so the reverse walk met the move once per event and escalated it each time: the second pass
overwrote the first's result (a delete at the first destination became a create there), leaving a copy of a path the
live tree no longer has (`echo new > f; mv f d/g; mv d D; rm D/g`: `Not tracking d/g`). A move is escalated once, by the
first content event the walk meets (the latest); earlier content events of the same path before that move add nothing,
as the escalated copy takes the file's content at replay time anyway. Goal 1's tests run in both event forms (create
alone, as for an empty file, and create + modify), and none logs a fallback or Not tracking line.

## Goal 1b: a delete that holds a move's source replays after that move (added during the build)

Found by Task 1's review (the plainest form of the user's "the replay order that loses the move's source"): with a
folder `d/` holding `g` in the version, `mv d/g y; rm -r d` collapses to `y <- d/g` and `delete d/`; the replay runs
deletes first (`order_backup_entries_for_replay`, step 1), so `d/` and its `g` are gone before the rename: a traceback,
a delete-and-copy, and `y` loses its chain link. On ecf386a and every round 13 tree.

Rule: a delete whose path is the source of a move in the batch, or a folder above one, is not hoisted with the other
deletes: it replays right after the last move (in the collapse's order, which is time order) whose source lies at or
under it, and before any later move or create whose destination lies at or under it; every other delete keeps today's
place at the front. The replay waits for that delete's `rm` before the next entry that touches its path (as the delete
barrier does today for the front group). Where a later entry must come before it and an earlier move must come after it
(no such order exists), today's order stands and Goal 2's warning covers the rename. That includes a move made after
the delete that lands on, or leaves, a folder above the delete's path and replays at or before its anchor: it changes
what the delete's path names (`rm -r d; mv x d; mv d/s/g y`, the deploy shape `rm -rf site; mv site.new site; mv
site/assets/x elsewhere`), so the delete stays at the front (found by Task 1b's review). Tests: the case above (a file, a
folder moved out, several files moved out, the folder remade and refilled after), each with and without the
verification, asserting no fallback line, the version equals the tree and the moved-out files keep their links; the
existing ordering tests and doctests keep passing; the review's random replay set (scratchpad r13/review-t1) shows no
batch worse with the verification. (The main session's call, within the user's item.)

## Goal 2: a rename that finds nothing logs one warning, not a traceback

In the replay's move step, a `FileNotFoundError` from the rename (`os.rename`) gets its own `except`: one warning line
naming the move and that its source or its destination folder is not in the version, no traceback, then the existing
delete-and-copy as today. This covers cause 2 (a file moved on before its create was copied), cause 3 (a chain merge
across a folder move, and a move into a folder made in the batch that then moves, whose destination folder the version
lacks) and the approved entry "A move into a folder made after an earlier move in one batch" (same mechanism). When the
live target is gone too (moved on again in the batch), that delete-and-copy skips it quietly, as the attribute sync step
already does ("moved on again in the batch"), instead of logging `ERROR Not tracking X: source no longer exists`; the
later entry or the verification takes it. Other errors of the rename keep today's traceback. Tests keep asserting that
Goal 1's batches never reach this branch. (The main session's call, within the user's "no traceback is logged".)

**A move into its own old place (the user's choice during the build).** When a move's target lies under its source
(`link_target_relative_path` starts with the source's relative path plus `/`), the version can never rename it: a folder
would go into itself (`EINVAL`), a file under itself (`NotARealFolder`). Shapes: `mv D x; mkdir D; mv x D/D`, `mv f x;
mkdir f; mv x f/f`, and the swap `mv E/e b; mv d E/e; mv b E/e/E` (the collapse gives `E/e/E <- E/e`). Such a move is not
tried: one warning naming the move and that its new place is inside its old one in the version, no ERROR line and no
traceback, then the same copy as the branch above (delete-and-copy, or the moved-on handling when the live entry is gone).
The moved entry's files are copied whole (known limitation, the user's, 2026-10-29). The version is right as today.

**`Not tracking` is a warning (the user's choice after the final review).** `Not tracking <path>: source no longer exists`
(the replay's copy of an entry the live tree no longer has, in `copy_path` and its folder walk) is logged at warning
level, same text: it is the ordinary race of a file removed before its copy ran, and the vault is right.

## Goal 3: one warning per repeated job name

At each daemon start, `parse_rules` counts the rule file's job-name cells as TSVZ 4.9's `_processLine` keys them: line 1
is the header and is never counted; `\x00` and line ends stripped; a raw line starting with `#` (but not
`#_defaults_#`) is a comment; the key is the first cell right-stripped; an empty key and `#_defaults_#` are skipped;
line numbers are physical, from 1. For each name on more than one line it logs one warning (`tl.teelog`, level
warning: journal and log folder; no alert pattern matches) naming the name, the lines and the line that wins (the last).
A last row with no non-empty cell after the name deletes the key in TSVZ: then no row wins and the job is dropped, and
the warning says so. Commands (`parse_rules(read_only=True)`) do not print it. It repeats at every start until the file
is fixed. Cleaned-name collisions (two rows whose names become one job name) keep their existing STOPPED rule.

The file stays as it is (the user's words): `rewrite_rule_rows()` today removes the earlier lines with the same key
whenever the winning row is written back for filled-in cells; it keeps them now. On the live /etc/reverb_rule.tsv the
first 0.49 start prints five warnings (work 5/10, kes_files 6/11, panruixin_files 7/12, shenshuhong_files 8/13,
passwords 9/14; the later line wins each time), rewrites nothing, and the file stays byte for byte.

## Goal 4: version 0.49, docs

- `__version__ = 0.49`, pyproject `version = "0.49"`.
- docs/limitations.md: remove the two deferred entries this round closes ("A rename in a rename-heavy batch can fail and
  log a traceback", "Repeated job names in the rule file") and their README lines; README design lines for Goals 1-3.
- The approved entry "A move into a folder made after an earlier move in one batch": its wording changes where Goal 2
  removes its traceback (fact correction, in Calls to confirm).
- New known limitation (approved 2026-10-29, "Known limitation (Recommended)"): "A move into its own old place is copied
  whole": an entry moved into a new folder made at its own old place in one batch (`mv D x; mkdir D; mv x D/D`, `mv site
  site.old; mv site.new site; mv site.old site/old`) gets one warning and is copied, so the next version holds full copies
  of its files, not links; a big folder costs its size once; in the swap shape the folder that took its old place is
  copied whole too, unless it was made in that batch (the user, 2026-10-29: "Correct the wording (Recommended)"). Why:
  the version can never rename an entry into itself, and
  keeping the links needs a replay that parks the entry under a temporary name and places it after the entries that make
  its new folder. Revisit when: the warning shows up in the live logs. README Known-limits line.
- Open for the user in the morning, not written down: (1) cause 3 costs a copy of an unchanged file (its chain link to
  the older copy is lost): widen the approved entry "A move into a folder made after an earlier move in one batch" to
  cover `mkdir x; mv old x/f; mv x y` and `mv a/f g; mv a A; mv g h`, or a later collapse change that keeps the links;
  (2) the pre-existing collapse of `mv q a; rm a` (with `a` in the version) leaves the old `a` until the verification
  removes it.

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
