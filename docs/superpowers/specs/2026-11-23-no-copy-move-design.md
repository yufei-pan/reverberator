# The no-copy move into a new folder (P3)

A move into a folder made in the same batch (`mkdir new; mv big new/`) is copied whole today, though the vault already holds
every byte of it. This round makes the copy hard-link each file of the new folder that holds, byte for byte and in its
metadata, a file the batch's own delete took into the version before, and copy everything else as today. The result on disk
is the state a move leaves (one inode, named at the old path in the version before and at the new path in the new one), it
trusts no event and no watch, and its worst case is the copy made today.

Built as its own round after round 0.55.7, on a branch of its own from the merged 0.55.7, as that round rewrites the replay's
looks (its section 7), the change list (section 9) and the length rule (section 1) around the same code. The build starts only
once Q24 is answered, as the answer decides whether it is built now, the candidate rule and the texts of section 10, so no
text is written with a placeholder. "Today" below means 0.55.6, branch `r0556`. Functions are named first; line numbers are of
reverberator.py at e166baa (18,251 lines), the file 0.55.7 builds on, and 0.55.7 moves them.

Why now and why this way: the user gave this move its own design when 0.55.1 dropped it (2026-11-07), and a design study
(2026-11-23, read-only) weighed four families of route. A route in the watcher cannot reach the case: a program's `mkdir`
and `rename`, one right after the other, leave no moment in which the new folder has a watch (a probe saw the move arrive as
an event in 2 of 300 runs), and every fix of 0.55.1 that filled that gap from a walk's view kept wrong bytes in some order of
events. Acting at the copy needs no event at all: it reads the bytes, which is the only proof the manifest can be shown (it
holds a file's size, mtime and last 64 KiB, and a same-size rewrite with its mtime set back keeps all three). It is not
urgent: the study's look at how often such a move happens is in its report (`.superpowers/p3/study-report.md`), kept out of
this public file, and Q24 offers not building it yet. Its harm when it comes is the whole moved size and, under a size limit,
older versions pruned for a copy of what the vault holds.

## The user's words

- 2026-11-03: "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to
  always in run the background. so every little bit will sum up to a lot over days month years."
- 2026-11-03: "simpler and smarter is better"
- 2026-11-04: "one of the core for reverberator is reuse existing linux features and easy browse / restore. we can
  introduce more efficient methods if that reduces usage for users that do not need to manually browse the folders and do
  not need to able to copy out entire versions from the backup store"
- 2026-11-07, round 21 (0.55.1), when another event order kept wrong bytes through the no-copy move: "Drop the feature
  (Recommended)": every move into a folder made in the same batch is copied, as on 0.55, and the no-copy move gets its own
  design later.
- 2026-11-12, offered with "the no-copy move into a new folder gets its own design round after": "continue next phase
  please", then the pick "Fixes + lightness, one round (Recommended)".

The rule the sessions have followed since round 21 (not the user's words): when the watcher cannot be sure, it errs toward a
copy, never toward wrong bytes. A copy costs space and time; a wrong version loses a backup.

The main session's calls this spec builds on (not the user's words): the proof is the full compare alone, with no inode
column in the manifest (no format change, and an inode cannot show a write through a mapped page that a compare sees).
Whether to build it now, and which files it may link, is Q24 (below, and in docs/progress.md): this spec is written on its
option (a); each place its option (b) changes is marked **[Q24]** with what (b) builds there instead; its option (c) builds
nothing yet.

Standing decisions that bind the build (docs/progress.md): a worktree, never the live checkout; the suite in parallel; no
pytest as root on the host; root, loop, mount, mergerfs and power-loss tests in reverberator's own test VM; the headroom rule;
the mergerfs and power-loss tests in the release gate; the scrub before every push.

## Summary

| § | Part | Code it touches | Adds | Removes |
|---|---|---|---|---|
| 2 | What left: the files the batch's deletes took into the previous version | `TreeWriter.record()` (reports what it took), `remove_queued()`, `replay_ops()` (a delete's own op kind), `TreeWriter.pre_record()` (returns what each delete's record took), `do_reverb_backup()`'s `pre_record()`, `verify()` and `delete_path()`, `VaultManifest` (`_open()` and five methods) | a temp table on the manifest's connection, per batch; one feed at each applied delete | nothing |
| 3 | The estimate | `do_backup()` (before `get_backup_size_inode()`, and its `finally`), `get_backup_size_inode()`, `get_unskipped_size_inodes()`, one helper shared with `delete_path()` | a file the batch may link is charged nothing | nothing |
| 4 | The copy step | `do_reverb_backup()`'s `copy_path()` (its two `writer.copy()` calls) and `wait_for_async_commands()`, a new `same_bytes()` beside `hash_file()` (its opener shared) | lookup, checks, a full compare on a compare pool, then the link or the copy | nothing |
| 5 | The writer's verb and the size books | new `TreeWriter.link_kept()`; `BatchSizes` (`shared` by rel, new `linked()`); `finish_copies()` (a link already made) | one verb, one sizes call | nothing |
| 6 | The log line | end of `do_reverb_backup()` | one line per batch that placed a link | nothing |
| 10 | Docs | README lines 15, 19, 22, 42, 43, 45, and 31 on Q25's answer; five docs/limitations.md entries | the narrowed texts, one widened (Q25) | the claim that such a move is always copied |

No change to the watcher, the manifest's stored format, the change list or any command. One number is added, the 1,000 rows a
candidate lookup reads at most (section 4, with the measurement behind it); the compare reuses `hash_file()`'s 1 MiB read, the
compare pool's `COMPARE_THREADS` threads, `compare_scopes()`'s window of four times that, and `BACKUP_SEMAPHORE`. State at
rest: none. Per batch: one temp table, empty unless the batch deletes tracked files; on two renames, what each delete's record
took before the replay; the compares in flight; the links not yet placed. One new question, Q25 (the estimate), besides Q24.

## 1. The rule that keeps a version right

> A file is linked only from a file that a delete of this batch took into the version before (claimed once), recorded
> checked, whose bytes compare equal in full to the monitored file's and whose mode, owner, group, mtime and extended
> attributes are the monitored file's. Everything else is the copy made today.

The first half keeps the vault's shape a move's shape: one path per inode in a version. The second half makes the version's
bytes and metadata the ones a copy would have written. Access times are not compared: `entry_metadata()` leaves them out
everywhere, and a renamed move keeps the old inode's atime too, so a link leaves the atime a move leaves.

**Why no order of events can give a version worse than today's copy.** For each file the replay copies today, the version
now gets either that copy (today's code, unchanged) or a link to a file whose bytes were just compared equal to the bytes a
copy started at that moment would have read, with the metadata a copy would have kept (read right before the compare was
queued; a change after that is a change after the take, which the next batch backs up, as it would after a copy that read
them then). So for every order of events and every state of the tree, the version's contents are those today's copy would
produce. The walk that decides which files are copied is today's, so nothing can be missing that today's copy holds. Which
candidate was tried does not matter to the bytes: any file with the same bytes and metadata is a true stand-in, so the hint
that picks it (its size, mtime, mode, owner and group, and how much of its path it shares with the new one) may be wrong as
often as it likes and costs only a compare. It matters to one thing besides the cost: under Only Sync Attributes a later
change of the new file, synced onto the shared inode, shows on the version before's file at the candidate's path (round 19's
rule below), so the choice prefers the moved entry's own old copy (section 4). No event, no watch, no inode number and no
record of the monitored file is trusted for the bytes. What the rule's first half guards is the vault's shape, not the bytes:
a link to an inode the tree still holds would give one version two paths on one inode, and under Only Sync Attributes a
change synced onto one would reach the other (round 19's spec, `specs/2026-11-04-round19-vault-r-design.md` section 2.4,
lets such a change reach other versions sharing the inode, never a second path of the same version).

**The orders that kept wrong bytes before.** Every fix of 0.55.1 (round 21) inferred, from the watcher's own map or from a
walk's view, that the entry at the new place is the one the vault holds and that no change of it went unseen; round 22's
findings were renames in the vault and lost events from a wrong watch path. Under this route:

| Order (round, commit or review) | What it did | Under this route |
|---|---|---|
| A twin of the same name, size, mtime and tail in the new folder (`mkdir stage; cp -p fw.img stage; mv stage app/v2; mv app/fw.img /archive`) (21, 89bb3bc, then b9c544b) | the guessed file's events were discarded: old bytes for good | the compare differs before the tail: copied |
| A stale found-path key: another folder made or renamed onto the path and moved on (`mkdir n; mv big n/big; mv next big; mv big/sub other/sub`, three more routes) (21, c91ce15, 61abf60, 4debb1c) | a folder left every version and its watch | no pairing state exists; the watcher is 0.55.6's |
| A found folder back in `newDirWDs` by a second walk of its parent (`mkdir a; mkdir a/b; mv big a/b/big`, then a same-size write) (21, 44058e2) | its change discarded: old bytes | the folder is inside the created folder's copy: the changed file differs and is copied, the rest are linked |
| A same-size change between `mkdir n` and `mv app n/app` (`cp -p` or `tar x`) (21, 7d34217; review 3: 4 of 6 wrong on the real daemon) | the vault's old copy put over it | the changed file differs from the version before's: copied |
| A rename between the new folder's `add_watch` and its listing: `poke_between`, `cpp_between`, `in_then_poke_mv` (21, 057ba3c; review 3's F3) | old bytes | the same |
| Renamed again before the walk lists it (`mv app n/app.tmp; mv n/app.tmp n/app`) (21, f5d6031, a5a8efb; review 4: 5 of 8 wrong) | old bytes | the same |
| The stale watch of a folder that left from a new folder (21, 9368fb3; review 5's F1: 3 of 3 wrong) | old bytes | no watch is asked |
| F2, `twice_old_race`; F1 through an ancestor (the count); the take window; the placed watch; `other_pending_remade`, `mv_onto`; `lag_child_out`; `pair_then_new_sub_out` (22) | a rename in the vault, or a lost event, from a wrong watch path | this route adds no rename and reads no event; they stay as 0.55.4 closed them |

**The new orders this route could open, and the rule that closes each.** Each has its own test (section 9).

1. *Two paths of one version on one inode.* A move never leaves that. Rule: a candidate is a file **a delete of this batch
   took into the version before**, by that delete's own record (on two renames, the record `pre_record()` made for that
   delete before the replay, in the replay's order: section 2), and it is **claimed once**, when it is linked. A renamed
   move's source is recorded by `hl_record()`, never by a delete, and its rows move to its target with the rename; a delete
   whose path the version before already holds as its own (recorded earlier in the batch) takes nothing; a delete that runs
   before a rename of something under it takes it, and the rename then finds no source and falls back to a copy. So no inode
   the tree still holds is ever a candidate (section 2 says how the record reports what it took). Two new files with one
   candidate: one link, one copy.
2. *Metadata of another file.* A link shares mode, owner, group, times and extended attributes. Rule: link only when
   `entry_metadata()` of the monitored file and of the candidate are equal; anything else is a copy (docs/lessons.md:
   "never write a change signal onto data it did not come with").
3. *The file changes while it is compared.* The same as a file changing while it is copied: the version holds bytes that
   were read, and the write's event comes after the take and is backed up by the next batch (events in a folder made during
   a batch are recorded again from the take on). A write into a part already compared leaves the old bytes, consistently;
   a copy at that moment would hold a mix.
4. *A link the vault refuses* (`NO_HARD_LINK_ERRNOS`, reverberator.py:12275: EXDEV, EPERM, ENOTSUP, EOPNOTSUPP, EMLINK,
   ENOSYS), or any other error of the link: copy.
5. *The size books.* `BatchSizes` counts an inode in the newest version that holds it. A file a delete renamed or exchanged
   into the version before was counted as that version's alone; a link back into the tree takes it back. A file a delete's
   record hard linked in (on two renames, where every record is a keep) settles by itself, as its link count is back where
   its record left it. Section 5.
6. *A cut batch.* The link is made under the copy's temporary name and placed by `finish_copies()`, as a copy is. A cut
   before the commit leaves it as what the batch made. The next start's repair gives the tree the released file back at its
   old place and, off a pool or over a manifest that describes the version before, removes every name the version before's
   folder does not list (`put_back_recorded()` pass 2, reverberator.py:7239), the new folder with the link in it. On a pool
   over a lost manifest that pass does not run (its caller passes `remove_made` False there, 7506), and what the batch made
   stays: a placed link is copied again by the roll-forward (`new_in_tree()` lists it, and its monitored path is a regular
   file), and an unplaced copy name, which no monitored path has, is a row of the rebuilt manifest that the roll-forward's
   comparison finds gone and removes, while it copies the monitored file as a create. Either way the roll-forward copies the
   moved files: the cut attempt's records stand, so its delete of the old place takes nothing (section 2). Read in the code;
   the crash gates run through it (section 9).
7. *A look that cannot answer.* A look at the version before or at the monitored file that fails (EIO, EACCES) never reads
   as "there" or "equal": it chooses the copy (round 0.55.7, section 7, for why "not there" may not stand for an error).
8. *Bytes the vault never flushed.* The compare reads through the page cache, which can hold right bytes over a disk that
   never got them. Rule: only a row recorded checked is a candidate: its copy was flushed before its commit, through
   handles that heard any write error (0.55.5). A row an older release left unchecked is not.

Items 1, 5, 7 and 8 differ from the study's rule; the Calls to confirm say how.

## 2. What left: the files the batch's deletes took into the version before

**What it does.** A table of the batch's released files: each a regular file a delete of this batch took into the version
before, with its size, mtime, mode, owner and group as its row records them, and its name. It is the only source of
candidates (section 4), and it is filled where the delete is applied, from what that delete's record took, so it holds
positive evidence only.

**Where.**
- `TreeWriter.record(rel, keep, took=None)` (reverberator.py:14074) appends to `took`, when given, the rel of each entry it
  takes into the previous version: a file or link it renames in, or keeps by a hard link and renames in from staging; a
  folder it exchanges in whole, or builds by `hard_link_tree()` and exchanges in. A rel in `took` has no trailing `/`, as
  `record()` walks them (`rel.rstrip('/')`, then `f'{here}/{name}'`), and a folder's stands for everything under it. Where
  the previous version already holds its own entry (not a forward link, and not two real folders), it takes nothing, and
  appends nothing. `TreeWriter.remove_queued(rel, is_dir, mcae, removals, took=None)` (14200) passes it on.
- `replay_ops()` (14569) gives a delete entry its own op kind, `DELETE_OP = 'delete'`, beside `FOLDER_OP` and `ENTRY_OP`;
  nothing else changes (a move's source and target stay `ENTRY_OP`s). Its doctest's delete reads `('delete', 'h')`.
- `TreeWriter.pre_record(ops, poll)` (13887) records a `DELETE_OP` as it records an `ENTRY_OP` (`record(rel, True, took)`, the
  record `hl_record()` makes) and returns `{rel: the rels that record took}` for its `DELETE_OP`s: `{}` off two renames, where
  it records nothing, and what it gathered when a stop ends it early. tests/test_pool_cut.py's `no_pre_record_flush()`
  stand-in returns what the real one returns.
- `do_reverb_backup()`'s `pre_record(make_ops)` (15137) keeps what `writer.pre_record()` returns in one dict for the batch,
  `pre_taken`, extending a rel's list (a file's and a folder's delete at one path give one rel). `verify()` prepares its
  fixes once (`prepare_backup_entries_for_replay()`) and gives the prepared entries to both `replay_ops()` and `replay()`:
  today `replay_ops()` reads them unprepared, in the comparison's order (15170), while `replay()` gets them prepared.
- `do_reverb_backup()`'s `delete_path()` (14811) first takes its rel's list out of `pre_taken`
  (`pre_taken.pop(relative_path, [])`, empty off two renames), passes it as `took` to each of its two
  `writer.remove_queued()` calls (the real folder's, the file's) and, right after the call and before its
  `manifest.remove_tree()` or `manifest.discard()`, feeds the table: `manifest.release_under(took)`. On two renames the list
  holds what the delete's pre-record took, and its own record then takes nothing, as a record only acts where a forward link
  still stands; off them it holds what its own record takes. A delete `delete_path()` does not remove feeds nothing, and its
  list is dropped: one the length rule keeps (`left_out(kept=True)`), one behind a link or a file in the version
  (`real_folders_to()` false), a file whose place holds a folder or a folder whose place holds a file (on two renames its
  pre-record may have taken that other entry, which the tree keeps), the version folder itself.
- **Order.** `pre_record()` records in the replay's order: `do_reverb_backup()` orders the batch's entries with
  `prepare_backup_entries_for_replay()` before `replay_ops()` reads them, the delete that replays behind a move included,
  and the verification's after the change above. So where a move's source lies at or under a delete, whichever replays
  first records it: `mv d/g y; rm -r d` replays the move first, so `g` is the move's, and `d`'s other files are the
  delete's, on two renames as inline.
- **Which deletes feed.** Off two renames, every delete the replay applies, as each comes through `delete_path()`: the
  batch's delete entries (front and behind, `order_backup_entries_for_replay()`), the copy fallbacks' deletes of a move's
  source (`delete_and_copy()`, `copy_instead_of_move()`), the verification's deletes (`verify()` replays its fixes through
  `replay()`), and the location recheck's (`recheck_moved_folder()`, whose records find the moved inodes held by the move's
  own record and take nothing). On two renames, the batch's delete entries and the verification's, through their
  pre-records; a copy fallback's delete of a move's source feeds nothing there, as `pre_record()` recorded that source as
  the move's (an `ENTRY_OP`) before the replay, and its own record finds nothing left: those files are copied, as today.
  Marking a move's source a `DELETE_OP` is no way out: a move that renames keeps those inodes in the tree, at its target.
- **No other removal feeds.** `remove_now()` (the verification's sweep of entries no row tracks, `sweep_version_folder()`;
  `finish_copies()`'s removal of a link too long), a copy's keep record, a rename's records (`record(dst)`,
  `hl_record(src)`) and `make_folder()` take for their own reasons, never for a delete.
- **A roll-forward.** Its writer finds the cut attempt's records standing (`do_backup()` makes it on the tree as it is), so a
  delete of a place the cut attempt recorded takes nothing and feeds nothing; one the attempt had not recorded yet feeds as
  in any batch.
- `VaultManifest._open()` (9564) creates, beside `temp.seen` (9586): `CREATE TEMP TABLE IF NOT EXISTS released(path TEXT
  PRIMARY KEY, name TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER, uid INTEGER, gid INTEGER) WITHOUT ROWID` and an
  index on `(size, mtime_ns, mode, uid, gid, name)`, the key and the name (section 4). Paths and names are stored as
  `entries` stores them (`storable_name()`); `name` is the last part of the stored path.
  **[Q24]** (b): no `name` column and no index beyond the path: its lookups are by path.
- `VaultManifest` gains five methods:
  - `clear_released()`: one statement that empties it.
  - `release_under(rels) -> int`: for each rel (of `took`, or of the estimate's fill, a trailing `/` stripped), one `INSERT OR
    IGNORE INTO temp.released SELECT ... FROM entries` of the rows at it or under it, as `tracks()` matches a rel: `path =
    s OR path > s/ AND path < folder_range_end(s/)`, `s` its `storable_name()`; never `iter_under()`'s range on a bare
    name, which for `d` runs from `d` to `e` and takes `d.bak`, `d2` and `data.txt`. Only files (`kind = 'f'`), not dirty,
    recorded checked (`coalesce(unchecked, 0) = 0`).
    The number added.
  - `may_release(st) -> bool`: one indexed `SELECT`: whether a row with `st`'s size, mtime, mode, owner and group is in it
    (section 3).
  - `released_candidate(rel, st) -> rel or None`: section 4's choice, by at most two indexed `SELECT`s and a choice in
    Python; the path is returned through `stored_name()`. **[Q24]** (b): `released_at(rel, st) -> bool` in its place:
    whether the row at rel is in it with that key.
  - `claim_released(rel) -> bool`: deletes its row; whether one was there (section 4).

**The two fills.** Before the replay the table holds what the batch *may* release: `do_backup()` fills it for the estimate
(section 3), before the prune and the hand-over that begins the transaction. `do_reverb_backup()` empties it at its start,
inside the transaction, and from then on it holds what the replay's deletes *did* take. `do_backup()` empties it again once
the batch ends, in its `finally`, when the manifest is open and holds no transaction: after the commit, or after the rollback
of a batch that stops. It cannot be emptied inside the transaction: a rollback brings back what a statement inside it
removed, the estimate's rows among them (a probe with sqlite 3.46: rows inserted before `BEGIN` and deleted inside it are
back after `ROLLBACK`). A JobFailure leaves the transaction to the job's loop, which closes the manifest, and the temp table
goes with the connection. The idle job's `release_idle_memory()` (`PRAGMA shrink_memory`) then gives its pages back.
`do_reverb_backup()` keeps a count of the rows fed, and the copy step asks the table nothing while it is 0, so a batch that
deletes nothing costs nothing.

**Why from what the record took, not from the rows under the delete.** A row under a delete names what the tree holds
there, and that inode is the version before's only once the delete's own record took it: where that version already holds
its own entry at the path (a rename's `record(dst)`, or a renamed move's `hl_record(src)` earlier in the batch, with
something moved onto the place since), the record takes nothing, and the inode at the old path is another file, possibly one
the tree still holds at a move's target. Reading what the record took (on two renames, the record its pre-record made, in
the same order) leaves no such case to reason about.

**State.** The temp table, in the manifest's connection, per batch; `pre_taken`, per batch, on two renames only; the list
`took`, for one `delete_path()` call. Nothing at rest; no format change: `temp` tables are not in the database file.

**Failure cases.**
- A statement on the temp table that fails raises `sqlite3.Error` and is not caught: it fails the attempt, as an error of
  any other manifest statement of the replay does. They share the replay's transaction, which sqlite may roll back by
  itself on a full disk or an I/O error; going on would write the batch's rows outside it. The next attempt rolls the batch
  forward.
- A record that fails raises JobFailure before anything is fed, as today.
- A rm of a delete that fails: `failed_removal()` fails the attempt at the next wait, which comes before any copy or compare
  (the replay's delete barrier, `delete_and_copy()`'s and `copy_instead_of_move()`'s waits, `recheck_moved_folder()`'s), so
  no candidate is compared or linked while the tree may still hold it.

**Tests** (tests/test_no_copy_move.py, `unit`, through `do_backup()` with raw events as tests/crash_batches.py's
`backup_events()` builds them; every test runs under the suite's ground-truth plugin, which checks each older version and
each change list's sizes). "On two renames" is both ways: the batch's writer made pooled (`hand_over()` wrapped to pass
`pooled=True`, so it is `TreeWriter(pooled=True)` as on a pool), and a filesystem with no exchange (`rename_exchange` patched
to raise EINVAL, as tests/test_moves_into_new_folders.py's `test_on_a_filesystem_with_no_exchange` does: `hand_over()`'s own
exchange then fails, and two renames are on from the version's build).
- `test_a_file_delete_feeds_the_file_its_record_took`: off two renames (renamed in) and on them (from `pre_record()`'s
  report; the inline record's list is empty): the table holds `f` with its row's key.
- `test_a_folder_delete_feeds_every_file_under_it`: by exchange (previous holds a forward link), by the record's walk
  (previous holds the folder real, unfolded by an earlier record in the batch), and on two renames by its pre-record's
  `hard_link_tree()`: every file row under it is fed, no folder and no link row.
- `test_a_delete_feeds_none_of_the_names_its_name_starts`: `rm -r d` beside tracked `d.bak/x`, `d2` and `data.txt`: only
  `d`'s rows are fed.
- `test_a_record_where_the_version_before_holds_its_own_entry_reports_nothing` (tests/test_tree_writer.py, `unit`, on a
  TreeWriter alone, off and on two renames): `hl_record('p')` as a rename's would, another file put at the tree's `p`, then
  `remove_queued('p', False, ..., took=took)`: `took == []`, and the version before's `p` is still the first inode; the same
  for a folder whose entries the previous version holds real.
- `test_pre_record_reports_what_each_delete_took` (tests/test_tree_writer.py, `unit`, `TreeWriter(pooled=True)`): the ops
  `replay_ops()` gives `mv d/g y; rm -r d` (`y`, `d/g`, then `d`'s `DELETE_OP`): `d`'s list holds `d`'s other entries and
  not `g`, and no `ENTRY_OP` is reported; off two renames `{}`.
- `test_a_renamed_moves_source_is_never_fed`: `mv d/g y; rm -r d` (the delete replays right after the move), off and on two
  renames: nothing fed for `g`, `d`'s other files fed.
- `test_on_two_renames_a_fallbacks_delete_feeds_nothing`: `mv D x; mkdir D; mv x D/D` on two renames: nothing fed, `D`'s
  files copied, as today (off two renames they are linked: section 9's pin).
- `test_a_file_delete_whose_place_holds_a_folder_feeds_nothing`, on two renames, where its pre-record took the folder.
- `test_unchecked_dirty_and_non_file_rows_are_not_fed`: an unchecked row, a row this batch copied (dirty), a link row and a
  folder row under a deleted folder.
- `test_a_delete_the_length_rule_keeps_feeds_nothing` (on 0.55.7's rule).
- `test_the_verification_records_its_fixes_in_its_replays_order`: spies on `replay_ops()` and `replay()`: the same entries,
  in the same order.
- `test_the_table_is_empty_when_the_batch_ends`, after a commit and after a stop, with no transaction open.
- `test_a_failing_temp_table_statement_fails_the_attempt`: `release_under()` patched to raise `sqlite3.OperationalError`, at
  the estimate's fill and at the replay's feed (two cases): the attempt fails and nothing is committed; the next attempt
  makes the version right (a batch again after the fill's failure, which came before the hand-over; a roll-forward after
  the feed's).

## 3. The estimate

**What it does.** The estimate made before the replay (`get_backup_size_inode()`, reverberator.py:11801) charges nothing
for a file the batch may link, so the prune makes no room for a copy that is not made: the harm the known limitation names
("after five small versions, one such move left only the newest") goes for a move whose files are unchanged.

**Where.**
- `do_backup()`, right before `attrib_copies` and the estimate (6399-6407), for a batch that is not a roll-forward (`tree is
  None`) and holds a create or a modify and a delete or a move into its own old place: `manifest.clear_released()`, then
  `manifest.release_under()` of the rel of each delete entry and of the source of each move whose target lies under it, each
  left out where `delete_path()` would remove nothing, judged on the tree as it stands (`tree_now`): the version folder
  itself, a path the length rule keeps (`vault_path_too_long(estimate_bytes, rel, False)`, as `replay_ops()` measures a
  delete), one behind a link or a file of the version (`real_folders_to(tree_now, rel, missing_ok=True)` false), and one
  whose place holds the other kind. `delete_path()`'s own tests of these move into one helper both call, so the two cannot
  disagree. `leaving` is then `lambda path, st: manifest.may_release(st)`, or None when nothing was fed. These statements
  run before the transaction begins, each on its own.
- A roll-forward (`tree is not None`) fills nothing, and its `leaving` is None: the cut attempt's records stand, so its
  replay's deletes take nothing that attempt recorded, and those files are copied; the estimate charges every copy, as
  today. It is high only by a file whose delete the cut attempt had not recorded yet, which the roll-forward still links
  (section 2), as today's estimate is for every such move.
- `get_backup_size_inode(..., leaving=None)` passes `leaving` to `get_unskipped_size_inodes()` (11759) for the walks of the
  entries the replay copies through `copy_path()`: a create's or a modify's, the carried moves' subtraction and the written
  entries' add-back that follow from them (`carried_in`, `written`), never an attrib's copy, which the replay makes in its
  attrib branch and never links.
- `get_unskipped_size_inodes(..., leaving=None)`: a regular file (`S_ISREG` of the lstat it makes already) for which
  `leaving(path, st)` is true is charged nothing, no bytes and no inode: the entry itself when it is a file, and each file of
  a folder's walk. A link adds a name, no inode and no block, as the size records already leave out the links a batch makes.
  **[Q24]** (a)'s `leaving` ignores `path`; (b)'s is `leaving(path, st)` of section 4's pairing: true when `path`, a file
  under a folder the batch creates, pairs with a delete entry's path whose row (a file, not dirty, recorded checked) has
  `st`'s size, mtime, mode, owner and group; under (b) `do_backup()` feeds nothing before the estimate.

**Why the batch's deletes and its moves into their own old places.** The estimate errs low, never high: an estimate too low
only passes the limit until the next prune, a copy the estimate charges and the replay never makes prunes versions for good
(the reason the size entry gives). So it must charge nothing the replay can link. The replay links only files a delete took
(section 2). A delete takes only where the version before still holds a forward link, so only version n's entries, never
one moved in during the batch, and the fill leaves out the deletes `delete_path()` removes nothing for. A move counts nothing
in the estimate: the replay renames it, and one that falls back to a copy is left out already (the size entry names it),
except a move into its own old place, whose target the created folder's walk charges, as the replay copies it whole (the
`carried_in` exception). Its source is fed, so its unchanged files are charged nothing, as the fallback's delete takes them
and the copy links them. A move carried into a created folder is charged by that folder's walk and taken back by the
`carried_in` subtraction, both through `leaving`, so the two cancel whatever is fed; feeding any other move's source would
change no charge but a twin's (`cp -p a b; mv a c` would leave `b` uncharged, though the move renames `a` and nothing
releases it). So every file the replay can link among those the estimate charges was a file row under a fed delete, or under
the source of a move into its own old place, when the batch was taken, and the estimate stays at or below what the batch
writes (barring a file changed between the estimate's walk and the replay's, as today, and a roll-forward, charged as today
above). The verification's copies are not
estimated at all. The estimate also charges nothing for some files the replay copies, and is low by each: the vault can
pass its limit by them until the next prune (Q25). They are exactly these:
- a predicted file whose candidate's contents or extended attributes differ (its size, mtime, mode, owner and group
  matched: a same-size rewrite with its mtime set back, an extended attribute set in the move's batch), or whose candidate
  the vault's filesystem keeps with other metadata than the monitored file has (an extended attribute it refuses or sets
  itself, an owner it cannot keep);
- a file whose matching row its delete does not take, as the batch moved that file away first: the twin of a file moved
  out of a place the batch then deletes (`cp -p d/a b; mv d/a c; rm -r d`: `b`);
- a file copied before the delete that takes its row: a delete that replays behind a move, after the batch's creates
  (`mv d/g y; mkdir n; mv d n/d`, section 7);
- the second of two new files that match one released file (one link per released file);
- on a vault that refuses hard links (docs/limitations.md "A copy made where the vault refused a hard link" waits for one
  to show), every predicted file;
- on a mergerfs pool or a filesystem with no exchange, the files of a move into its own old place: the batch recorded its
  source as the move's before the replay, so the copy's delete takes nothing (section 2).

The key is the row's size, mtime, mode, owner and group, which the rows record, so a chmod or chown made with the move (`mkdir
n; mv big n/; chmod -R g+w n`) is charged as the copy it is.

**State.** The table (section 2), filled here and emptied at the replay's start and in `do_backup()`'s `finally`.

**Failure cases.** A statement that fails raises `sqlite3.Error` before anything is written (the estimate comes before the
prune and the hand-over) and fails the attempt. A file gone or changed between the estimate and the copy: as today, the
estimate is what the walk saw.

**Cost.** One indexed lookup per regular file the estimate walks, only in a batch that both deletes tracked files (or moves
one into its own old place) and creates or modifies something; the walk lstats each file already. The fill is one statement
per fed rel, over the rows it covers; the build times the fill and the lookups on a delete of 1,000,000 rows beside
`manifest.remove_tree()` of the same rows.

**Tests** (tests/test_no_copy_move.py, `unit`; tests/test_estimate_charge.py's helpers):
- `test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder`: a delete of `big` and a create of `n/` holding
  it, off and on two renames: the estimate is `n`'s folders' charge alone; under a size limit with five small versions, all
  five stay.
- `test_the_estimate_charges_a_file_changed_in_the_move` (appended, its size moved) and
  `test_the_estimate_charges_a_file_chmodded_in_the_move` (its mode differs from its row's).
- `test_the_estimate_is_never_above_what_the_batch_writes` (a parametrized pin, each shape its own case, off and on two
  renames): a move into a new folder, the same with a file renamed, the same at a start's full comparison, a move into its
  own old place, a move a folder move outran (`mv d e; mkdir e/sub; mv x e/sub/x`), a delete that replays behind a move
  (`mv d/g y; mkdir n; mv d n/d`), two creates twins of one deleted file, and a twin of a renamed file (`cp -p a b; mv a c`):
  estimated bytes and inodes at most the vault's growth in bytes and inodes (`sizes_by_newest_holder()`).
- Q25's pins: `test_a_predicted_link_whose_bytes_differ_is_copied_uncharged`,
  `test_a_twin_of_a_file_moved_out_of_a_deleted_folder_is_copied_uncharged` (`cp -p d/a b; mv d/a c; rm -r d`), and
  `test_on_two_renames_a_move_into_its_own_old_place_is_copied_uncharged`: the estimate leaves the files out, the replay
  copies them.
- `test_a_twin_of_a_renamed_file_is_charged` (`cp -p a b; mv a c`: `b` is charged, and copied).
- `test_a_delete_the_replay_removes_nothing_for_is_not_fed_to_the_estimate`: a delete behind a link of the version, and a
  file's delete whose place holds a folder.
- `test_a_roll_forward_charges_every_copy`: a batch cut after its delete's record and before its commit, then rolled forward:
  the estimate charges `n`'s files, and the replay copies them.
- tests/test_moves_into_new_folders.py's `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`
  and `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one` change: their estimated
  inodes are the names in `n` less the files linked (all of `big`'s but those the row writes or changes), plus the probes;
  `written <= est_size <= grew` stays (the chmod rows keep it because the mode is in the key).
- tests/test_estimate_through_a_take.py's three tests (`test_the_put_back_through_a_take`,
  `test_the_attrib_put_back_through_a_take`, `test_file_rows_through_a_take`) stay as they are: their batch holds `n`'s create
  and a move into it, which renames, and no delete, so nothing is fed.

## 4. The copy step

**What it does.** Before a regular file's copy is queued, the replay looks for a released file with its key, checks it, and
queues a full compare of the two on a compare pool; an equal compare becomes a link in place of the copy, and anything else
is the copy made today.

**Where.** `do_reverb_backup()`'s `copy_path()` (14744) queues a file's copy at two places: the file branch
(`writer.copy(source_real_path, source_relative_path, mcae, pending)`) and the folder walk (`writer.copy(subRealPath,
subRelativePath, mcae, pending)`). Both call a new helper of `do_reverb_backup()`, `copy_or_link(source_path, rel, mcae)`,
in its place. Everything `copy_path()` does before them stays: the source's look, the length rule (`left_out()`: the link
is written under a name of the copy's length, so the rule that measured the copy measures it), the untracked folder above,
the folders made, the row added dirty, so the commit records it as a copy's (`record_dirty_entries()` reads the linked file,
reverberator.py:11116). Every create and modify the replay copies comes through `copy_path()`: the batch's own, a created
folder's walk, `copy_untracked_folder()`, a copy fallback's (`delete_and_copy()`), the verification's missing entries and
`recheck_moved_folder()`'s. The attrib branch's copy and the move branch's copy of a moved file whose metadata changed are
not `copy_path()`'s and stay copies.

`copy_or_link()`, on the replay's thread, each step choosing the copy (`writer.copy()`, as today) when it fails:
1. The table holds no fed row (the count of section 2 is 0): copy, with no look.
2. `st = os.lstat(source_path)`: not a regular file: copy.
3. `candidate = manifest.released_candidate(rel, st)` (the choice below): none: copy.
   **[Q24]** (b): only in the walk of a folder the batch creates (`copy_path()` replaying a create entry; not
   `copy_untracked_folder()`, a fallback or the verification): the candidate pairs `rel` with a delete entry of the batch by
   name. Of the parts of `rel` below the created folder, the deepest whose name is the last part of a delete entry `D` (the
   first by path when several share it) is replaced by `D`, and what is below it kept: `n/big/sub/b` with a delete of `big`
   pairs with `big/sub/b`; `n/f.txt` with a delete of `f.txt` pairs with `f.txt`. Then `manifest.released_at(candidate,
   st)`: false: copy. Steps 4 to 7 are the same; (b) has no choice among rows and no bound.
4. The version before's file: `real_folders_to(writer.previous, candidate, strict=True)` (no folder above it is a forward
   link, through which the path would lead into the tree) and `kind_at()` of it is `'f'` (not a forward link, not gone).
5. `entry_metadata(source_path) == entry_metadata(kept)`, `kept` the version before's file: mode, owner, group, mtime and
   extended attributes, as the move branch's `only_attributes_differ()` compares them (reverberator.py:14877).
6. The compare is queued: `same_bytes(source_path, kept)` submitted to the batch's compare pool, and the file kept in the
   replay's window with its candidate (where it runs, below).
7. When the window settles it, on the replay's thread: equal, and `manifest.claim_released(candidate)` answers that its row
   was there: `writer.link_kept(candidate, source_path, rel, pending)` (section 5); True: the rel is kept with the file's size
   until it is placed (section 6); False: copy. Bytes that differ, a compare that failed, or a candidate an earlier file of
   the window claimed: copy. The daemon stopping (`GREEN_LIGHT` clear): neither a link nor a copy, and the replay ends as
   for any stop.

An OSError at steps 2 to 5, and 0.55.7's `VersionLookError` from a strict look, is caught there and chooses the copy: a look
that cannot answer never links (section 1, item 7). `VersionLookError` is a JobFailure, not an OSError, so the `except`
names both.

**The candidate.** Among the rows with `st`'s key and `rel`'s name, the one whose path shares the most trailing parts with
`rel` (ties: the first by path), so a moved entry pairs with its own old copy: `n/big/b/data.bin` with `big/b/data.bin`, not
`big/a/data.bin` of the same key. With no row of that name, the first row with the key, in the index's order (by name, then
path). One candidate per file, so a file costs at most one compare; one whose candidate differs is copied, though another
row of its key might have matched. The candidate is claimed only once linked: one that fails here may still be another
file's. A lookup reads at most 1,000 rows of one name: in this spec's probe (sqlite 3.46, an in-memory table of 200,000 rows
of one key), a row cost about 0.3 µs to read and 0.2 µs to weigh in Python, so 1,000 rows cost about 0.5 ms, what the `cp`
process a link saves costs (0.5 ms for an empty file, measured beside it). A name shared by more rows of one key (thousands
of empty `__init__.py` unpacked with one mtime) then pairs a file with one of the first 1,000 by path, linked where bytes and
metadata are equal, as empty files' are, and copied where not; with no bound each lookup reads them all, and such a move
costs their number squared. The build measures the lookup on such a folder (section 9).

**`same_bytes(a, b) -> bool`**, beside `hash_file()` (11674). It opens both files as `hash_file()` opens one (no link
followed, never a blocking open of what is not a regular file, a lease waited for as `cp` waits): that opener becomes a
module function both use. It reads both into two buffers of 1 MiB, the size `hash_file()`'s full hash reads in (`1 << 20`),
and answers False at the first block that differs, at a length that differs, at any OSError, and when the daemon is stopping
(`GREEN_LIGHT` clear, looked at between blocks). Not `filecmp.cmp()`: its cache answers from an earlier result when the size
and mtime are the same, which is exactly the case this compare exists for.

**Where it runs.** On a compare pool, in parallel, as `record_dirty_entries()` and `compare_scopes()` run their compares: a
`ThreadPoolExecutor` of `COMPARE_THREADS` threads (`--compare_threads`, 32 by default), made by `do_reverb_backup()` when it
queues its first compare, so a batch that compares nothing makes none. Each compare holds a permit of `BACKUP_SEMAPHORE`
while it reads, as a copy holds one while it runs, so compares and copies together run no more at once than copies alone
do today (twice the cores at the default `--threads -2`; `-t N` gives N, and `-t 0` 200,000). The replay keeps at most
`COMPARE_THREADS * 4` compares
queued, the window `compare_scopes()` keeps (its `settle()`), settling the oldest as it adds one, and
`wait_for_async_commands()` first settles them all: whatever a compare decides is queued before any wait ends, and no move,
delete barrier or verification runs while a compare is open. While it waits for a compare the replay polls the pools
(`poll_pools()`), as it does while it waits for the copies; `same_bytes()` polls nothing itself. The `finally` shuts the
pool down with its queued compares cancelled: one already reading ends at its next block when the daemon is stopping, and
otherwise at its file's end, as it only reads. A compare reads twice what one copy reads and writes nothing; the build
measures it against today's copy (section 9). Not `cmp -s` on the copy executor, which would need no pool: `cmp` opens the
monitored file following a link, and blocks on a FIFO swapped in since the walk, where `cp -a` does neither;
`same_bytes()`'s opener is there for exactly that (it is `hash_file()`'s).

**State.** Per batch: the compare pool, the window, and the rels linked and not yet placed (section 6). Nothing at rest.

**Failure cases.** Each chooses the copy, which then fails or succeeds as today:
- the source gone or replaced since the walk listed it (step 2 or the compare): the copy's own failure keeps the last
  backed-up copy, or, gone, the row goes with today's line;
- no candidate, or a candidate whose version-before file is gone, a link, under a forward link, or cannot be looked at;
- metadata or bytes that differ, an unreadable side;
- a candidate another file of the window claimed first;
- the link refused or failing (section 5).
A stop during the compare chooses nothing: the batch ends as a stop does.

**Tests** (tests/test_no_copy_move.py, `unit` unless said; each through `do_backup()` with raw events, a delete of the old
place and a create of the new, unless said; each ends with the oracle of section 9):
- `test_an_unchanged_file_moved_into_a_new_folder_is_linked`, off and on two renames: the new path in the newest version and
  the old path in the version before are one inode; no two paths of one version share one; one line.
- `test_an_unchanged_folder_moved_into_a_new_folder_is_linked`, off and on two renames, with a subfolder, a link and an empty
  file in it: every regular file linked, the link and folders made as today.
- `test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied`: other bytes before the last 64 KiB (the twin of section 1's
  first order; the tests' `cpp`).
- `test_a_poke_before_the_compare_is_copied`: same size and mtime kept (the tests' `poke`) after the take.
- `test_a_write_during_the_compare`, two cases through a stand-in for `same_bytes()`'s read that writes into the monitored
  file after its first block: into a block not yet compared (copied) and into one already compared (linked to the old bytes;
  the next batch copies the new ones, and its version holds them).
- `test_a_source_gone_before_the_compare_is_copied_as_today` (removed in a stand-in for `released_candidate()`): no link,
  and the lines and rows today's copy gives a source gone between the walk and its copy.
- `test_metadata_that_differs_is_copied`, one case per field: mode (a chmod with the move), mtime (`touch`), an extended
  attribute (`user.x`); owner and group in the VM as root (`needs_root`): each copied, never linked.
- `test_two_new_files_and_one_released_file_link_one`: the first the window settles linked, the other copied.
- `test_a_moved_entry_pairs_with_its_own_old_copy`: `big/a/data.bin` and `big/b/data.bin` of one key and other bytes, `mkdir
  n; mv big n/`: both linked, each to its own.
- `test_one_candidate_is_tried_per_file`: two released files of one key and name, the one sharing more of `rel`'s path
  different in bytes, the other equal: copied, after one compare.
- `test_a_lookup_reads_at_most_1000_rows`: 2,500 empty files of one name, mtime, mode and owner, one in each of 2,500
  folders, moved into a new folder: no lookup reads more than 1,000 rows (a stand-in counting them), and every file is
  linked.
- `test_the_compares_run_in_parallel`: a stand-in for `same_bytes()` that waits for a second call: two files of one moved
  folder are compared at once.
- `test_a_candidate_under_a_forward_link_or_itself_a_link_is_copied`: a row fed by a stand-in for `release_under()` whose
  version-before entry is a forward link, and one under a folder that is one: copied.
- `test_a_stop_during_the_compare_links_nothing`: `GREEN_LIGHT` cleared from the stand-in read: no link and no copy queued
  for the file, the batch ends as a stop does, the next attempt commits it right.
- `test_a_failed_look_at_the_version_before_is_a_copy`: EIO from an `os.lstat` stand-in on the candidate's path.
- `test_the_location_recheck_and_the_verification_link_too`: a create the verification finds missing whose old place its
  own fix deletes: linked.
- `test_a_delete_and_a_create_of_one_path_are_a_copy` (pin): `rm -rf d; tar x` at `d`'s own place, times kept: the batch
  holds no delete, so every file is copied, as today.
- **[Q24]** (b): `test_a_file_renamed_into_a_new_folder_is_copied` (`mkdir n; mv f n/g`), and the fallback and start shapes
  of section 7 copied; the twin and pairing tests above unchanged but for the choice, which (b) does not have.

## 5. The writer's verb and the size books

**What it does.** One `TreeWriter` verb puts the version before's file at the new place the way a copy is put there, and
tells the size books that the file is the tree's again.

**Where.**
- New `TreeWriter.link_kept(kept_rel, source, rel, pending) -> bool`, beside `copy()` (reverberator.py:14170), the one door
  to the tree (tests/test_tree_writes.py reads the module and finds `os.link` there, inside `TreeWriter`). As `copy()` does:
  `record(rel, True)`, `flush_if_needed()`, `_folders_for_copy(source, rel)`. Then a fresh copy name, `partial_copy_path()`
  of `rel`'s path (8222), taken again while one is there as `cp_af_copy_path()` does; `os.link(kept_path(kept_rel), temp,
  follow_symlinks=False)`, as `link_or_copy()` (13556) makes its links; the size books told (below);
  `pending.append(PendingCopy(None, source, temp, path))`, a link already made. True. Any OSError of the link or of the look
  after it (`NO_HARD_LINK_ERRNOS` among them): the copy name removed if made, False, and the caller copies; the record made
  stays, and `copy()` repeats it and finds nothing left to do (a record acts only where a forward link still stands).
- `finish_copies()` (8946): a pending entry whose task is None is a link already made. Its loop branches on that before it
  reads `copy.task.stderr` (8969), which a link has none of: no lines, succeeded, and it is put in place, or left with its
  row dropped where a folder above its place is no longer real, exactly as a finished copy is, and returned among the
  entries put in place (0.55.7's section 9 reads that list as what the replay applied). Its `if copied:
  manifest.copies_unsynced = True` (9026-9027) becomes: set only when it placed an entry with a task, so a link sets no
  flush. `discard_copies()` (8801) removes a link's copy name as a partial copy's (a stop, a JobFailure, a cut's next
  start), which leaves the version before's file whole and its link count where it was.
- `BatchSizes` (13736): `shared` becomes a dict by rel (`pending()` sets `shared[rel] = (size, links)`; a version's entry is
  recorded once, so no rel comes twice); `result()` iterates `self.shared.items()` (`for rel, (bytes_, links) in ...`; today
  it unpacks the list's triples); new `linked(rel, size, links)`.

**The size books.** `BatchSizes` counts what the version before alone holds, each inode in the newest version that holds it
(reverberator.py:13736). `link_kept()` calls `self.sizes.linked(kept_rel, size, links)`, `size` the file's and `links` its
count of names right after the link: an `lstat()` of the new name off two renames (exact there, as `keep_entry()`'s comment
says), `links_now()` on them. Not `st_nlink + 1` of a look before the link, as `keep_entry()` takes it: the compare ran in
between.
- On two renames a delete's record takes every file by a hard link (`record()` makes every record a keep there), so the
  file is in `shared` already, pending at the count its record left. The rm of its delete dropped that count by one, and the
  link brings it back, so `result()` counts it nowhere while the tree holds it, and again here once the tree lets it go.
  `linked()` does nothing for it.
- Off them a delete's record takes a file by a rename (`record()` at 14108 adds its size, its inode taking the forward
  link's place) or with a folder exchanged in whole (`record_dropped()` of `folder_usage()`, its size and an inode), so it is
  not in `shared`. `linked()` takes it back (`self.size -= size`, `self.inodes -= 1`) and sets `shared[rel] = (size,
  links)`, so it counts here again, by size and inode, if the tree lets it go later in the batch (the verification removes
  its new place, a later copy replaces it, the link is discarded).

`linked()` tells the two apart by `shared` itself, not by the writer's `two_renames`, which a roll-forward's first exchange
can still turn on in the middle of a batch. (A file an unfold kept by a hard link, an entry too deep for a forward link,
`unfold()` at 14005, is the version before's own before any delete reaches it, so a delete takes nothing there and it is never
a candidate: such a file is copied, as today.)

A roll-forward's sizes come from `measure_previous()` (7659), which counts in the version before only files the tree does
not share: a linked file is shared, so it needs nothing. The study's "on a pool ... off a pool" is "on two renames (a pool,
or a filesystem with no exchange) ... off them".

**Why the link sets no flush.** The commit flushes the vault's disks before its commit point when the batch placed a copy
(`manifest.copies_unsynced`), when it rolls a cut batch forward, and on two renames always (`do_backup()`, 6511). A
link writes no data: its inode is a file the version before holds, recorded checked, so flushed before the commit that
recorded it (section 1, item 8). It adds a name, which a vault off a pool carries to the disk with the manifest's fsync, as
it carries the batch's renames and exchanges (the power-cut tests at every step on f2fs, ext4 and XFS; docs/limitations.md
"Vaults on btrfs" for the one filesystem not covered). A batch that only links, off a pool, then commits with no flush of
the vault's disks, one `syncfs` less per such batch.

**State.** `BatchSizes.shared` keyed by rel, per batch, as before. Nothing at rest.

**Failure cases.** The link refused or failing: the copy. A cut after the link and before the commit: as section 1, item 6
says, the next start's repair puts the version before's file back in the tree at its old place and removes what the batch
made (on a pool over a lost manifest the roll-forward copies a placed link again, and its comparison removes an unplaced
copy name), and the roll-forward finds the move again and copies it. A stop: `stop_copies()` discards it. A folder above
the new place turned into a link before the placement: left and its row dropped, as a copy.

**Tests:**
- tests/test_tree_writer.py (`unit`, a TreeWriter alone): `test_link_kept_records_its_place_and_queues_a_finished_copy`: an
  entry at `rel` in the tree is recorded in the version before first; the pending entry has no task and its copy name is a
  name of the version before's file; off and on two renames.
- tests/test_no_copy_move.py: `test_the_sizes_after_a_link` (the ground-truth plugin compares each change list with
  `sizes_by_newest_holder()`), one case each: a file renamed in, a folder exchanged in, a folder walked by the record (the
  version before's folder real already), each off and on two renames; and, as a pin, an entry an unfold kept by a hard link
  (a stand-in for `os.symlink` answering ENAMETOOLONG on its path) moved into a new folder: copied, sizes right.
- `test_a_linked_file_the_tree_lets_go_in_its_batch_counts_in_the_version_before`: the monitored new file removed in a stand-in
  for `finish_copies()` after the link was placed, so the verification deletes it.
- `test_a_link_refused_with_each_errno_is_a_copy`, parametrized over `NO_HARD_LINK_ERRNOS` and EIO (an `os.link` stand-in for
  that path): copied, sizes right, no copy name left.
- `test_a_batch_of_links_alone_commits_without_the_flush`: a spy on `flush_copies()`: not called off two renames; called on
  two renames.
- `test_a_stop_before_a_link_is_placed_leaves_no_copy_name`: `GREEN_LIGHT` cleared after `link_kept()`: no
  `.reverberator-partial` name in the tree, the version before's file whole, its link count back.

## 6. The log line

**What it does.** One line at the end of `do_reverb_backup()`, after the verification, when the batch placed a link:
`Linked <n> files, <size>, from <version before> in place of copies: each had the bytes, mode, owner, group, mtime and
extended attributes of a file this batch removed from the version` (`format_bytes()` for the size, as the change list's name
writes it). Today the copy of such a move writes no line at all; a copy still writes none. One line a batch, not one a file:
a moved folder of 100,000 files writes one.

**Where.** `do_reverb_backup()` keeps each rel `link_kept()` linked, with its size, until a wait reports it placed (the rels
`finish_copies()` returns, which 0.55.7 gathers into the batch's `placed` set), and counts it then: a link never placed (left
where a folder above stopped being real, discarded at a stop) is not counted. The line is a plain `backuperTeeLogToTl()`
call (5462) with `monitor_path` and no flag, as the replay's other lines (`Moved … to …`, `Fixing … differences …`): logged
at info level in the daemon's log, and printed too under `--debug`; `log_text()` escapes the whole line, the version's path
with it.

**State.** The rels and the count, per batch.

**Failure cases.** None of its own; a stop or a JobFailure ends the batch before it, as for any line of a batch that did not
commit.

**Tests:** `test_one_line_a_batch_names_the_files_and_bytes_linked` and, as pins, no such line in a batch that linked nothing,
and a link left unplaced (a folder above it replaced by a link) not counted (tests/test_no_copy_move.py). It is an info line:
the repo's alert patterns (firewatcher/reverberator.regex) match only the markers and the exit line, so nothing alerts on it.

## 7. What it does not reach

Each of these stays today's copy, with today's lines; the version is right in each.

1. **A file changed in the move's batch:** its bytes, mode, owner, group, mtime or an extended attribute. That file is
   copied; the rest of a moved folder is linked. Under Only Sync Attributes too: in the move's batch such a file is copied,
   not linked and then given the new metadata (possible, and left for a later round). A change made in a later batch to a
   linked file is an attrib like any other, and under Only Sync Attributes it is synced onto the shared inode, where the
   version before's old path shows it too, as for a renamed file (section 9's test).
2. **An old place whose delete is not applied before the copy:**
   - a batch the maximum delay takes while the move-out still waits for its pair: the check after the batch deletes the old
     place, after the copies ran;
   - a move landing in the instant a batch is taken (the known limitation of that name);
   - a delete that replays behind a move, after the batch's creates: a folder moved into a new folder out of a folder that
     also held the source of an earlier move of the batch (`mv d/g y; mkdir n; mv d n/d`), as
     `order_backup_entries_for_replay()` replays a delete at or above a move's source right after that move.
3. **A delete and a create of one path in one batch** (`rm -rf d; tar xpf d.tar` at `d`'s own place, times kept): they
   collapse into the create (`change_events_to_backup_entries()`), so the batch takes nothing out of the version; each file
   is copied over its old copy, as any modify is. Unpacked at another path, it is linked.
4. **What the version does not hold:** a move into the tree from outside it, from a skipped path or from a paused inner disk;
   a file made in the batch and moved into a new folder (its row is the batch's own, dirty); a file whose copy an older
   release left unchecked (copied once, and recorded checked from then on).
5. **A vault that refuses hard links** (a known limitation already), and a vault whose filesystem cannot hold a monitored file's
   metadata as it is (an extended attribute it refuses or sets itself, an owner it cannot keep): its files are never linked.
6. **The second of two new files that match one released file:** one link per released file.
7. **Copies the replay makes outside `copy_path()`, or with no delete that took their files:** the attrib branch's (a swap
   the collapse could not replay; a chmod with Only Sync Attributes off), the move branch's copy of a moved file whose
   metadata changed, and the copies of a swap made in one batch (docs/limitations.md "Swaps in one batch are repaired by
   copies"): the verification's modifies take nothing out, and in a file swapped with a folder the fallback's delete finds
   the other kind at the move's source and removes nothing (`delete_path()`).
8. **A file deeper than a forward link can name** (about 800 levels on f2fs): an unfold keeps it in the version before by a
   hard link before any delete reaches it, so no delete takes it (section 5).
9. **On a mergerfs pool or a filesystem with no exchange, the copy fallbacks of a move:** a move another change of the batch
   outran, a move into its own old place, a move whose path passes the length limit. The batch records the move's source as
   the move's before the replay, so the fallback's delete takes nothing (section 2).
10. **A batch cut before its commit and finished at the next start:** its roll-forward copies what the cut attempt had
    recorded (section 2).
11. **A folder found ahead of its events** (docs/limitations.md "A folder found ahead of its events can reach the vault a
    version late", README line 44): its copy goes through `copy_path()`, but the batch brings that folder's move as a move,
    renamed in the vault, so no delete takes its files, and it is copied whole once more; a file of it is linked only where
    another delete of the batch took a file of its key and bytes.

**[Q24]** (b) adds: a move that also renames (`mv f n/g`); a move or rename made while reverberator was down; a tree deleted
and unpacked at another path; every copy fallback (a move another change of the batch outran, a move into its own old place);
a move out of a folder that just left the tree; any file not in the walk of a folder the batch creates.

What the operator is told: the narrowed entry "A folder or file moved into a new folder is copied whole" and README line 22
(section 10).

## 8. Interactions with round 0.55.7

This round is built on 0.55.7's merged code. What it takes from it, and where the two meet (0.55.7's spec sections and plan
tasks, `docs/superpowers/plans/2026-11-22-r0557.md`):

- **Section 7, the strict looks (Tasks 5 and 6).** Step 4's looks at the version before are `real_folders_to(strict=True)`
  and `kind_at()`; 0.55.7 makes the strict form raise `VersionLookError` (a JobFailure, not an OSError) for an error other
  than ENOENT and ENOTDIR, and `copy_or_link()`'s `except` names it beside OSError: a failed look here only ever chooses the
  copy, which needs nothing of the version before, so it fails no attempt. The source's look (step 2) is its own lstat: an
  error chooses the copy, and the copy's own failure keeps the last copy with its UNREADABLE line, as 0.55.7's
  `monitored_there()` arranges for `copy_path()`. Task 5 rewrites `delete_path()`'s looks (`os.path.islink()`/`isdir()` to
  `kind_in_version()`): the take from `pre_taken` stays at its start and the feed right after each `writer.remove_queued()`
  call, wherever Task 5 leaves them. Task 5 also makes `finish_copies()`'s three `real_folders_to()` strict and
  `discard_copies()` go on past a failed look: a link's pending entry takes those paths as a copy's does.
- **Section 9, history from what the replay applied (Task 7).** `wait_for_async_commands()` gathers `finish_copies()`'s
  returned rels into the batch's `placed` set, and `copy_path()` records the rel each entry's own `writer.copy()` was given.
  A link is returned by `finish_copies()` among the entries put in place (section 5), so it reads as applied, and its history
  is the events': a delete and a create, as today; section 6 counts the links by the same set. Collision: both rounds change
  the same two lines of `copy_path()`: the rel is recorded in `copy_or_link()`'s caller, whichever way the file goes, and
  `wait_for_async_commands()` settles the compares before it waits.
- **Section 1, the length rule (Tasks 2 to 4).** The link is written under a `partial_copy_path()` name, of the copy's
  length, so `left_out()`'s measure of the copy (its `version_bytes`, counting the next version) holds for it. Task 2 changes
  the estimate's `version_bytes` (`estimate_bytes`, `after`) in the same `get_backup_size_inode()` call that this round gives
  `leaving`, and the estimate's fill measures its deletes with the same `estimate_bytes`: a merge point, no conflict of
  meaning. Tasks 3 and 4 leave entries out by their own sequence (`writer.remove_queued()` straight, not `delete_path()`),
  so they feed nothing; had they gone through `delete_path()`, the feed would be right too (an entry left out for its length
  is still in the monitored tree, and a twin of it may be linked). Task 4 puts its leave-outs at the head of the first
  `pre_record()`'s ops as `ENTRY_OP`s: they are recorded first and reported by nothing, and a delete above one takes the
  rest, as with a move's source.
- **Section 10, the walk's wave (Task 1).** `copy_path()`'s folder walk is `iter_tree_entries()`; `copy_or_link()` is called
  per yielded file and does not touch the walk.
- **Sections 2 to 4, the pool.** They change how a pool's disks are looked at, not how the writer links. Apart from 0.55.7:
  on a pool the link is made through mergerfs from the branch that holds the released file, and mergerfs either makes the
  folders above the new place on that branch, as it does for `hl_record()`'s links today, or answers EXDEV, by its policy
  (reasoned, not run); EXDEV is a copy (section 1, item 4). The approved entry "On a mergerfs pool, a folder cloned to
  another disk can lose setgid" covers folders it makes, as any the batch writes into. The VM's pool gate forces both
  outcomes (section 9).
- **`BatchSizes`, `TreeWriter.record()`, `TreeWriter.pre_record()`, the estimate's walk:** 0.55.7 changes none of them beyond
  the above.

Order: this round's branch is made from the merged 0.55.7; nothing here is built before it.

## 9. The test plan

Every outcome is forced by its own test, through a stand-in at the one call that decides it where the real system cannot be
made to answer so; none is left to a random sweep. The sweeps below (the fuzz, the shapes at their timings) are the
regression gate, not the proof.

**The oracle, at the end of every test.** Each version compared with the tree it backed up, byte for byte in full
(tests/vault_oracle.py `entry_view()` hashes whole files), with mode, owner, mtime and extended attributes, and the version
before compared with the tree before the batch (tests/test_moves_into_new_folders.py `assert_held_as_the_tree()`); the sizes
(the suite's ground-truth plugin, tests/version_view_ground_truth.py, compares each change list's name with
`sizes_by_newest_holder()` after every committed batch, and checks that no older version changed); and the shape: a new
helper in tests/vault_oracle.py, `paths_sharing_an_inode(job_vault, folder_name)`, empty for every version (no two paths of
one version on one inode), with, where a link is expected, the new path in the newest version and the old path in the
version before one inode (`read_view(..., inodes)`).

**tests/test_no_copy_move.py** (new, `unit`; root-only cases `privileged` and run in the VM). Batches through `do_backup()`
with raw events, as tests/crash_batches.py's `backup_events()` builds them, each with its oracle; "on two renames" both ways,
as section 2 says. The tests named in sections 2 to 6, grouped:
- the feed (section 2): what a file's and a folder's delete feeds, by rename, exchange, the record's walk and on two renames
  through the pre-record's report; none of the names a deleted name starts; a renamed move's source never fed; a
  fallback's delete on two renames feeding nothing; a file's delete where the version holds a folder; unchecked, dirty, link
  and folder rows not fed; a delete the length rule keeps; the verification's order; the table empty after a commit and a
  stop; a failing temp-table statement failing the attempt;
- the estimate (section 3): no charge for an unchanged move; a charge for a changed and for a chmodded file; never above
  what the batch writes, over the named shapes; Q25's three pins; a twin of a renamed file charged; the fill's skips; a
  roll-forward charging every copy;
- the copy step (section 4): a file and a folder linked; the twin, the poke before, a write during the compare into a block
  compared and one not yet compared, the source gone; each metadata field (owner and group in the VM); two new files and one
  released; a moved entry paired with its own old copy; one try per file; at most 1,000 rows a lookup; the compares in
  parallel; a candidate under or at a forward link; a stop during the compare; a failed look; the verification and the
  recheck linking; a delete and a create of one path copied;
- the writer and the sizes (section 5): the size cases off and on two renames; a linked file let go in its batch; each
  refused errno; no flush for links alone; a stop before the placement;
- the log line (section 6);
- the fallbacks, each its own test, off and on two renames, asserting what the code gives and pinning it: `mv D x; mkdir D;
  mv x D/D` (linked off two renames, copied on them, the warning kept either way); its swap shape `mv site site.old; mv
  site.new site; mv site.old site/old`; each example of docs/limitations.md "A move that another change of the batch outran
  is copied" (`mv d e; mkdir e/sub; mv x e/sub/x`, `mv a/f g; mv a A; mv g h`, `mkdir x; mv old x/f; mv x y`, `mv D/sub t;
  rm -r D; mv t D`, `mv d D; mv D/k z; rm -r D`, and the new-file one); a move out of a folder that just left the tree (`mv
  X /out/X; mv /out/X/sub sub`, its delete and create as the watcher emits them for an unsettled watch); a rename made while
  the daemon was down (a start's full comparison); a file swapped with a folder (`mv a t; mv b a; mv t b`, one a folder:
  copied); a folder found ahead of its events (the found-folder routes of tests/test_moves_into_new_folders.py: copied whole
  once more). Where a test finds an example linked or copied otherwise than section 10's texts say, the builder stops and
  reports it with the text it would need; the texts are the main session's.
- Only Sync Attributes on and off, each: a link, then a chmod of the new path in the next batch: on, synced onto the shared
  inode, and the version before's old path shows the new mode (round 19's section 2.4, as for a renamed file; the plugin
  allows it); off, copied, and the version before keeps the old mode.
- **[Q24]** (b): the renamed, start, fallback and unsettled-watch tests assert a copy; a pairing test per rule (the deepest
  named part, several delete entries of one name, a moved file, a file in a moved folder's subfolder).

**tests/test_tree_writer.py** (`unit`): the record's report when the version before holds its own entry; `pre_record()`'s
report of what each delete took; `link_kept()`'s record first and its finished pending entry, off and on two renames.

**tests/test_moves_into_new_folders.py** (`inotify`, the real watcher on real inotify; TIMINGS are `apart` and `unread`, and
`at_once` has its stress test):
- `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` becomes
  `test_a_folder_moved_into_an_existing_or_a_new_folder_costs_no_copy`: for `new` and `nested` too, at gaps 0 and 0.2, each
  moved file's inode is its old one (`after[new] == inodes[old]`) and the vault grows by under 200,000 bytes (the test's
  own bound for a move into an existing folder: a copy would be 400 KB).
- New `test_what_a_move_into_a_new_folder_links`, parametrized over shapes of SHAPES at both timings, with the rels each must
  link (the old inode at the new place) and those it must copy: `folder`, `file`, `file_renamed`, `nested` (all linked);
  `changed_before` (`n/big/a` copied, `n/big/sub/b` linked); `changed_between` (the poke: `n/big/a` copied, the rest
  linked); `folder_chmod_in` (`n/big/a` copied for its mode, `n/big/sub/b` linked); `its_own_old_place` (all linked);
  `a_file_made_in_the_batch` (copied: the batch's own file). **[Q24]** (b): `file_renamed` copied.
- `assert_held_as_the_tree()` gains `paths_sharing_an_inode()` empty for the newest version and the version before, so its
  13 callers check the shape too, the MATRIX test of the 32 shapes of SHAPES at their timings among them. The `at_once`
  stress test (`test_moves_into_new_folders_as_fast_as_they_go_end_as_the_tree`), which compares `version_view()` with
  `live_view()` alone, gains the same check after each of its two batches. The file's other tests keep their own asserts:
  they assert the version equals the tree, never that it was copied.
- `test_on_a_filesystem_with_no_exchange` gains: `big`'s files are linked (one inode across the two versions), the reach on
  two renames on the real watcher.
- `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` gains: the new file's inode is not the old one.
- The two estimate tests change as section 3 says.

**tests/test_watcher_fuzz.py** (`inotify`): the random steps already move folders and files into new folders (`mvd_new`,
`mvf_new`); a new step `twin` copies a file with `cp -p` semantics (`shutil.copy2`) to a new name, and one time in two pokes
one of the two (same size and mtime, other bytes). The oracle is the file's own (each version equals the tree, by whole-file
hashes) and the plugin's, plus `paths_sharing_an_inode()` after each round. The suite's sample as now; a longer run is the
main session's gate call.

**Crash** (**main session: VM gate**; builders write these to skip outside the VM). tests/crash_batches.py's batch 3 gains a
released file and a released folder, past f2fs's inline size (`past_inline()`), and their creates in a new folder, so the
batch links both; every kill point of tests/test_crash_harness.py's sweep then cuts through `link_kept()`, the placement and
the commit, and tests/test_crash_power_loss.py's power cuts through the same, each followed by the oracle over every version
(`measure_previous()` and `sizes_by_newest_holder()` among it). On a scratch mergerfs pool in the VM (tests/test_pool_cut.py's
way), the same batch with each disk put back at its own point, over a standing manifest and over a lost one (section 1,
item 6: a placed link copied again, an unplaced copy name removed by the comparison).

**The pool** (**VM gate**, `needs_mergerfs`): a link into a new folder whose released file is on one branch and whose new
folder was made on another, run twice, once with the pool's policies set so mergerfs makes the link and once so it answers
EXDEV (the builder takes the settings from mergerfs's documentation and names them in the test); each run asserts which
happened (one inode across the two versions, or a copy after an EXDEV), never "linked or copied"; the oracle and the sizes
either way; the folders mergerfs makes for the link read with their times as the batch gave them.

**The real daemon** (**main session**, as round 21 measured the limitation: the daemon itself, a scratch job, in the test
container as uid 65534 or in the VM). `mkdir new; mv big new/` for a folder of 100 MB and for a file of 100 MB, at gaps of 0,
1 ms and 1 s between the two, with `mkdir` and `rename` as two system calls of one program and as a shell's two commands;
each again with a poke of one file of the folder before the move, between the two, and after it. **The number it should
show:** for the folder, vault growth of the order of a move into an existing folder (0.04 MB in round 21's measurement;
under 0.1 MB), where today it is 102.44 MB, at every gap; for the file, under 0.01 MB, where today it is 100.11 MB; a poked
file adds its own size; under the entry's size-limit test, all five small versions stay; one line a batch; the time spent in
the replay, against today's copy of the same. A figure off these is a finding, and 10.1's text changes with it.

**Measurements in the build** (the builder's, in the container; the cold-cache ones in the VM, where the page cache may be
dropped): the compare against today's copy for one 1 GiB file and for a folder of 10,000 files of 4 KiB, warm and cold, on the
compare pool as built; the lookups of a folder of 2,500 empty files of one key and name; the estimate's fill and lookups and
the replay's feed on a delete of 1,000,000 rows, beside `manifest.remove_tree()` of the same rows. The figures go in the
handback; what they decide is in the Calls to confirm.

**Gates:** the whole suite in the container and in the VM, the mergerfs and power-loss tests, as the release gate has them.

## 10. Docs

The release is called 0.55.8 below (the round after 0.55.7; the number is the main session's). Each text replaces the one
named, in the commit of the code it describes (section 11). The build starts after Q24's answer, so each narrowed entry's
"Approved" is written with that answer (the user's words or pick and the date, or "chief's decision" and its date), where
`<Q24's answer>` stands below. 10.2 and README line 31 are written once Q25 is answered, with its answer where `<Q25's
answer>` stands; until then that text stays as it is. Under Q24 (b) the three entries of 10.3 to 10.5 and README lines 15, 19,
42, 43 and 45 stay as they are, and 10.1's and line 22's texts take the (b) wording given; under (c) nothing is written.

**No lessons entry is required:** no API, stored format or command changes shape (the change list, the manifest and the
commands are as they were; the log line is new and additive). The main session may add one line to docs/lessons.md:
"prove a moved object where it lands, by its bytes, not by the events that say it moved".

### 10.1 docs/limitations.md: "A folder or file moved into a new folder is copied whole" (narrowed)

```
### A folder or file moved into a new folder is copied where it cannot be linked

- **Kind:** known limitation.
- **What the operator sees:** `mkdir new; mv big new/` inside one quiet time reaches the backup as a delete of `big` and a
  copy of `new`, as nothing watched `new` when `big` arrived. From 0.55.8 each file of that copy that holds, byte for byte,
  the contents of a file the batch's delete took into the version before, with its mode, owner, group, mtime and extended
  attributes, is hard-linked from there in place of a copy, after a read of both, with one line a batch in the log
  (`Linked <n> files, <size>, from <version> in place of copies: ...`): an unchanged move then costs about what a move
  into an existing folder costs (0.04 MB for a 100 MB folder on the real daemon), and with a size limit it prunes nothing.
  Still copied, with no line: a file changed in the move's batch (its contents, mode, owner, group, mtime or an extended
  attribute); every file of the move when its old place leaves the version after the copy (a batch the maximum delay
  takes while the move-out still waits for its pair, a move landing in the instant a batch is taken, or a folder moved
  out of a folder that also held the source of an earlier move of the batch, `mv d/g y; mkdir n; mv d n/d`), or in a
  batch cut before its commit and finished at the next start; the second of two new files that match one removed file;
  and, on a vault that refuses hard links or whose filesystem keeps other metadata than the monitored file has (an
  extended attribute it refuses or sets itself), every such file. Such a copy costs its size (a 100 MB file 100.11 MB),
  and with a size limit it can prune older versions to make room, as on 0.55.7, where every such move is copied.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, and a program's `mkdir` and `rename`, one right after the other, leave no moment in which the
  new folder has a watch. 0.55.1 was built to keep the arrival as a move; four reviews and the fix passes after them each
  found an order of events where the version then kept a file's old bytes for good, so 0.55.1 copied, as 0.55 does. From
  0.55.8 the copy proves each file's bytes by reading them and links only what it proved; what it cannot prove, or what
  changed, it copies. A copy costs space and time; a wrong version loses a backup.
- **Revisit when:** a size-limited job's prunes follow such copies often.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as on
  0.55, and the no-copy move gets its own design later. Narrowed to what the link cannot cover: <Q24's answer>.
```

**[Q24]** (b): the second sentence of "What the operator sees" reads "From 0.55.8 each file of that copy whose place below the
new folder is its old place under the moved entry's own name (`new/big/sub/f` for `big/sub/f`), and which holds, byte for
byte, the contents of the file the batch's delete took into the version before there, with its mode, owner, group, mtime
and extended attributes, is hard-linked from there ..."; and the "Still copied" list starts with "an entry renamed in the
move (`mv big new/other`);".

### 10.2 docs/limitations.md: "Size estimates leave out a version's own small blocks" (widened, on Q25's answer)

In "What the operator sees", after "... and a move that falls back to a copy, so a vault can pass its size and inode limits
by those copies until the next prune.", insert:

```
  From 0.55.8 it also leaves out the copy of a file it took for a link: a file with the size, mtime, mode, owner and
  group of a file that one of the batch's deletes, or a move into its own old place, takes from the version, which the
  replay copies after all: its contents or extended attributes differ (a same-size rewrite with its mtime set back), its
  twin was moved away before that delete (`cp -p d/a b; mv d/a c; rm -r d` copies b), that delete replays after its
  copy, it is the second match of one removed file, or the vault refuses to hard-link it or keeps other metadata; and,
  on a pool or a filesystem with no exchange, every file of a move into its own old place.
```

In "Why", append: "Charging such a file would prune versions for good for every move the replay links instead of copying,
the harm the no-copy move removes; an estimate too low only passes the limit until the next prune." In "Approved", append:
"Widened to a file the estimate takes for a link: <Q25's answer>."

### 10.3 docs/limitations.md: "A move that another change of the batch outran is copied" (narrowed)

In "What the operator sees", the sentence "..., and the entry is copied once more: its files are written to the vault again
in full, a copy instead of a rename." becomes:

```
  ..., and the entry is copied once more instead of renamed: its files are written to the vault again in full, but, from
  0.55.8, those the copy's own delete of the move's old place took into the version before unchanged, which are
  hard-linked from there. All of it is written where the version no longer held the entry at its old place (a copy a
  live move outran, a source another move of the batch took first), and on a pool or a filesystem with no exchange,
  where the batch records the move's old place as the move's before it replays.
```

The examples stay as they are: each names the entry that is copied. "Approved" appends: "Narrowed to the files the copy
links: <Q24's answer>."

### 10.4 docs/limitations.md: "A move into its own old place is copied whole" (narrowed)

```
### A move into its own old place is copied

- **What the operator sees:** an entry moved into a new folder made at its own old place in one batch (`mv D x; mkdir D;
  mv x D/D`, or `mv site site.old; mv site.new site; mv site.old site/old`) logs one warning, `Not renaming … to …: its new
  place is inside its old one in the version; copying it instead`, and is copied. From 0.55.8 the copy's delete of the old
  place takes the entry's files into the version before first, so each one unchanged is hard-linked from there instead of
  written (in `mv D x; mkdir D; mv x D/D`, every unchanged file of D), and the move costs what changed in it. In the swap
  shape the folder that took its old place (site.new) is copied too, as the copy replaces all of the version's site: a file
  of either folder is linked only where the copy's own delete took it into the version before unchanged, which depends on
  the order the batch replays the two moves, and the rest costs its size once. On a pool or a filesystem with no exchange
  the batch records the old place as the move's before it replays, so the delete takes nothing and all of it costs its
  size once, as before 0.55.8. The result is right.
- **Why:** the version can never rename an entry into itself, so the move is replayed as a delete of its old place and a
  copy, which links what that delete took. Keeping every file of it, in the swap shape and on a pool too, needs a replay
  that parks the entry under a temporary name and places it after the entries that make its new folder, a larger change
  for a shape never seen in the live logs.
```

"Kind" and "Revisit when" stay; "Approved" appends: "Narrowed to the files the copy links: <Q24's answer>."

### 10.5 docs/limitations.md: "A move out of a folder that just left the tree is copied" (narrowed)

In "What the operator sees", "is copied whole instead of renamed in the vault" becomes "is copied instead of renamed in the
vault", and the last sentence, "The version is right; the copy costs the moved entry's size once, and with a size limit it
can prune older versions, as the copy of a move into a new folder can.", becomes:

```
  The version is right. From 0.55.8 each file of these copies that the batch's delete of its old place took into the
  version before unchanged is hard-linked from there instead of written, as for a move into a new folder; the rest costs
  its size once, and with a size limit it can prune older versions.
```

"Revisit when" drops "Also when the no-copy move into a new folder gets its own design." (this round is that design).
"Approved" appends: "Narrowed to the files the copy links: <Q24's answer>."

### 10.6 README

- **Line 15**, its last clause "and moves made since the last backup before a stop are copied once instead of renamed."
  becomes "and a move made since the last backup before a stop is a delete and a copy, whose unchanged files are hard-linked
  from the version before in place of copies (read twice, written never)." **[Q24]** (b): unchanged.
- **Line 19**, after "... and is copied the same way.", insert: "Where the version still holds the entry at its old place,
  the copy takes it out first, and each unchanged file is hard-linked from the version before instead of written, as for a
  move into a new folder; on a pool or a filesystem with no exchange it is all written." **[Q24]** (b): unchanged.
- **Line 22**, its last sentence becomes: "A folder or file moved into a folder made in the same batch reaches the backup as
  a delete of its old place and a copy of the new folder, as nothing watched the folder when it arrived: each file of that
  copy that has, byte for byte, the contents of a file the delete took into the version before, with its mode, owner,
  group, mtime and extended attributes, is hard-linked from there in place of a copy, after a read of both (one line a
  batch: Linked <n> files, <size>, from <version> in place of copies), so an unchanged move writes no copy and prunes
  nothing under a size limit; a file changed in the move's batch is copied, and so is all of the move in the orders a known
  limit below names." **[Q24]** (b): "... each file of that copy at its old place below the moved entry's own name ..." and
  "; an entry renamed in the move, a file changed in the move's batch ..."
- **Line 31** (on Q25's answer), "and of moves that fall back to a copy, which the estimate leaves out." becomes "and of moves
  that fall back to a copy, and of a file it took for a link that the replay copies (one with the size, mtime, mode, owner
  and group of a file the batch removes, and other contents or extended attributes, say; on a pool or a filesystem with no
  exchange, every file of a move into its own old place), which the estimate leaves out."
- **Line 42**, "(mv d e; mkdir e/sub; mv x e/sub/x copies x, and mv a/f g; mv a A; mv g h copies h), is copied once more with
  one warning, and its files are written to the vault again in full." becomes "(mv d e; mkdir e/sub; mv x e/sub/x copies x,
  and mv a/f g; mv a A; mv g h copies h), is copied once more with one warning: its files are written to the vault again in
  full, but those unchanged at an old place the version still held, which are hard-linked from the version before (all of
  them are written on a pool or a filesystem with no exchange)."
- **Line 43**, after "The result is right." insert: "Each file of these copies that the batch's delete of its old place took
  into the version before unchanged is hard-linked from there instead of written."
- **Line 45** becomes: "A folder moved into a new folder made at its own old place in one batch (mv D x; mkdir D; mv x D/D)
  is copied once, with one warning, its unchanged files hard-linked from the version before (all written on a pool or a
  filesystem with no exchange); in the swap shape (mv site site.old; mv site.new site; mv site.old site/old) the replacing
  folder is copied too, and either folder's files are linked only where the copy's own delete took them first."

The README's other lines about moves stay, and so do the entries they summarize: 17 (a file made in the batch and moved,
copied once: its row is the batch's own), 39 (swaps: the verification's modifies take nothing out, and a file swapped with a
folder has no delete that removes anything, section 7 item 7), 44 (a folder found ahead of its events, copied whole once
more: its move comes as a move, section 7 item 11). Line 115 stays: it says a file restored under Only Sync Attributes
carries the newest metadata its shared copy has, which covers a linked file's too.

## 11. Order of the build

The build starts once Q24 is answered, on (a) or (b); under (c) nothing below is built. Each step is one commit whose tests
pass, with the docs of the code it adds.
1. Section 2: the table, the record's report, `replay_ops()`'s op kind, `pre_record()`'s report, `verify()`'s order, and the
   feed, with their tests (nothing links yet; the feed is read by nothing).
2. Section 5's `BatchSizes` change and `link_kept()`, and `finish_copies()`'s link entry, with their unit tests.
3. Sections 3, 4 and 6 together: `same_bytes()`, the compare pool and `copy_or_link()` (from here files link), the
   estimate's fill and `leaving`, and the log line. Either half alone breaks tests/test_moves_into_new_folders.py's two
   estimate tests (the copy step alone makes the vault grow less than the estimate, which then passes `grew`; the estimate
   alone charges fewer inodes than the names the replay copies). With them: their tests, those two tests' change, the
   fallback pins, tests/test_moves_into_new_folders.py's other changes, and the texts of 10.1 and 10.3 to 10.6 but line 31;
   10.2 and line 31 too once Q25 is answered, else in their own commit on the answer.
4. The measurements, the fuzz step, then the main session's VM gates (owner and group, crash and power loss, the pool) and
   the real daemon's measurement, which checks 10.1's claim of a cost about that of a move into an existing folder.

## Questions for the user

**Q24. Whether to build the no-copy move now, and which files it may link** (docs/progress.md, as asked there). The route
links a file from the version before, in place of a copy, only when it is a file the batch's own delete took there, compares
equal in full, and has the same mode, owner, group, mtime and extended attributes; open are which files are looked at, and
whether to build it yet.
- (a) Build it, for every file the batch's deletes took, found by size, mtime, mode, owner and group, the one whose path is
  likest the new one first (Recommended, what this spec builds). Besides `mkdir new; mv big new/` it covers, on every vault,
  a move that also renames (`mv big new/other`), a move or rename made while reverberator was down (copied once today), a
  tree deleted and unpacked again at another path with its times kept, and a move out of a folder that just left the tree;
  and, off a mergerfs pool on a filesystem with exchange, where the version still holds the moved entry at its old place,
  the moves that fall back to a copy (a move another change of the batch outran, a move into its own old place). Nowhere:
  a batch cut before its commit and finished at the next start, which copies what the cut attempt recorded. One table per
  batch that deletes tracked files. Beyond the main entry ("A folder or file moved into a new folder is copied whole", and
  README line 22), which (a) and (b) narrow, (a) narrows three approved texts to what is left: "A move that another change
  of the batch outran is copied", "A move into its own old place is copied whole", "A move out of a folder that just left
  the tree is copied"; and README lines 15, 19, 42, 43 and 45. It leaves "Swaps in one batch are repaired by copies" (README
  line 39) and "A folder found ahead of its events can reach the vault a version late" (README line 44) as they are: no
  delete of those batches takes the files they copy.
- (b) Build it, only for an entry moved into a folder made in the batch under its own name (its files at the same places
  below it): the move the user named, nothing more; the other copies stay as approved. It is not less code: it needs a
  pairing by name that (a) does not, and the table, the compare, the link and the size books are the same.
- (c) Not now: keep the entry "A folder or file moved into a new folder is copied whole" and this design on file, and build
  it when a size-limited job prunes for such a move, or a job over a tree of user files is added. What building costs: a temp
  table and five manifest methods, a compare on a thread pool, a writer verb, an estimate change (Q25), five limitations
  texts and seven README lines. The study's look at how often such a move happens is in its report, which the main session
  gives with this question.
- What waits on it: the whole build (section 11), the candidate rule (sections 3 and 4), the tests marked [Q24], and the
  docs of section 10. The user's words: "Drop the feature (Recommended)" (2026-11-07), with "the no-copy move gets its own
  design later", and the pick of 2026-11-12 that gave it "its own design round after". (a) goes beyond the move they named;
  (c) puts off the build their pick gave a round; nothing they said is dropped.

**Q25. The size estimate and a file it takes for a link** (asked with Q24; moot under its option (c)). With a size
limit, the estimate made before each backup decides how many old versions to prune for room. From this round it charges
nothing for a file the batch may link (one with the size, mtime, mode, owner and group of a file the batch deletes, or of a
move into its own old place), so a move into a new folder no longer prunes older versions for a copy that is never made.
Where such a file is copied after all, the vault passes its limit by that copy until the next backup prunes: its contents or
extended attributes differ (a same-size rewrite with its mtime set back), its twin was moved away before the delete (`cp -p
d/a b; mv d/a c; rm -r d`), its delete replays after its copy (`mv d/g y; mkdir n; mv d n/d`), it is the second match of one
removed file, or the vault refuses hard links or keeps other metadata; and, on a pool or a filesystem with no exchange, every
file of a move into its own old place. This widens the approved known limitation "Size estimates leave out a version's own
small blocks", which already leaves out copies of moved files and of moves that fall back.
- (a) Widen the entry (Recommended): the estimate stays at or below what the batch writes, as it is built to (a prune made for
  a copy never made removes a version for good, an overshoot lasts until the next prune). The cases that overshoot are rare
  orders, or need the same size, mtime, mode, owner and group to the nanosecond; the one that comes every time is a move into
  its own old place on a pool or a filesystem with no exchange, itself a rare shape.
- (b) Charge every copy as today: no new overshoot, but with a size limit each move into a new folder still prunes older
  versions for the full moved size although it then costs nothing: "after five small versions, one such move left only the
  newest", the harm the entry names and the reason this round exists.
- (Not offered: comparing the bytes at the estimate too. It would read every moved file's two copies before the prune, and
  again at the copy.)
- What waits on it: section 3, docs 10.2 and README line 31 (built on (a) when not answered by then, with those texts
  written only on the answer, as the agent rules ask). The user's words it would narrow: none; it widens an entry approved
  2026-10-26 ("Known limitation (Recommended)") and widened since, last on 2026-11-13 ("Widen the entry (Recommended)").

## Calls to confirm

Where this spec departs from the study (`.superpowers/p3/study-report.md`, read against reverberator.py at e166baa):
1. **The feed.** The study's index is built once before the estimate from the rows under the batch's delete entries, with
   the rows under every move's source and target taken out, and the verification's deletes added before its fixes. Read
   against the code, that index cannot reach a move that falls back to a copy (`copy_instead_of_move()` and
   `delete_and_copy()` delete the move's source, which the index took out), and `mv D x; mkdir D; mv x D/D` has no delete
   entry at all (its entries are `D/` create and `D/D/` move), though the study's question 2 and docs/progress.md Q24 (a)
   say (a) covers both. This spec fills the table where each delete is applied, from what that delete's record took into
   the version before (`TreeWriter.record()` reports it; on two renames `pre_record()` reports what it recorded for each
   delete before the replay): that needs no move rule (a renamed move's source is recorded by `hl_record()`, never by a
   delete; a delete takes nothing where the version before holds its own entry), covers the verification's and, off two
   renames, the fallbacks' deletes at one site, and holds only positive evidence. Same state (one per-batch table, and on two
   renames one dict of what the pre-records took); one feed site in place of two.
2. **The estimate** asks a prediction, the rows under the batch's deletes and under the sources of its moves into their own
   old places, not the replay's table (which is filled during the replay), and leaves out the deletes `delete_path()` would
   remove nothing for, by the same tests. Every file the replay can link among those the estimate charges is in it, so the
   estimate never charges a copy that is not made, in any batch but a roll-forward; the price is the overshoot of Q25 (the
   study had the same class, smaller, as "the class the size entry already names", which it is not: the entry names copies of
   moved files and moves that fall back, so the widening is a question). Other moves' sources are not fed: they change no
   charge but a twin's, which would be uncharged and copied.
3. **The key** is the row's size, mtime, mode, owner and group (the study: size and mtime), so a chmod or chown made with the
   move is charged and copied without a compare.
4. **Only rows recorded checked** are candidates (the study did not say): the compare reads through the page cache, and a
   copy an older release left unchecked may never have reached the disk.
5. **No tree look.** The study's "not the inode the tree still holds at that path" goes: with the feed from what the record
   took, no candidate is an inode the tree holds, and every rm of a delete is waited for, or fails the attempt, before any
   compare or copy. Inode numbers would prove nothing on a filesystem that numbers names (LESSONS.md).
6. **"A tree deleted and unpacked again with its times kept"** is reached only when unpacked at another path: at its own path
   a delete and a create collapse into the create (`change_events_to_backup_entries()`), so nothing is taken out.
7. **"Deletes replay first"** has `order_backup_entries_for_replay()`'s exception: a delete at or above a move's source replays
   right after that move, after the creates; `mv d/g y; mkdir n; mv d n/d` stays a copy (section 7).
8. **The size books:** "on a pool / off a pool" is "on two renames / off them"; `BatchSizes.shared` is keyed by rel so that
   `linked()` tells a file a hard link took in (pending already) from one a rename or an exchange took in by `shared`
   itself, not by `two_renames`, which a roll-forward's first exchange can still turn on in the middle of a batch.
9. **The test plan:** TIMINGS are two (`apart`, `unread`) plus the `at_once` stress test, not three; the 32 shapes' test asserts
   the version equals the tree, never "copied" (the copy expectation lives in
   `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` and the two estimate tests, which
   change); the watcher fuzz already moves into new folders, so only the twin step is new.
10. **The reach under (a)** is partial where the study says whole: a move that another change outran, and a move into its own
    old place, link only where the version still holds the entry at its old place when the fallback deletes it, and only off
    a pool on a filesystem with exchange; the swap shape depends on the order of its two moves; a roll-forward links nothing
    the cut attempt recorded. Section 10's texts say what holds by construction, and section 9 pins each named example; a pin
    that differs from the text comes back to the main session. Under (a) README lines 15, 19, 42, 43 and 45 change too, and
    Q24 lists them.

Calls made in this spec that change what gets built:
11. One candidate tried per file: among the rows of its key and name, the one sharing the most trailing path parts with the
    new path, else the first row of the key; claimed only once linked; at most 1,000 rows read a lookup (section 4, with
    the measurement). A file whose key matches a released file of other bytes costs up to two reads more than today's copy
    (the compare stops at the first difference): bounded, and rare enough (same size, mtime, mode, owner and group) to be Not
    an issue.
12. The compare runs in parallel on a compare pool of `COMPARE_THREADS` threads, each compare holding a `BACKUP_SEMAPHORE`
    permit as a copy does, with `compare_scopes()`'s window; the link is made on the replay's thread when the window settles
    it, the copy queued there when it differs; the pool is shut down in the `finally` that stops the copies. Not `cmp -s`
    on the copy executor: it follows a link and blocks on a FIFO at the monitored path. If a link is slower in wall time than the copy it replaces on some shape, that is a finding for the
    main session (the light way against the fast way), not something the builder tunes.
13. A link sets no `copies_unsynced`: a batch of links alone, off a pool, commits without the flush of the vault's disks.
14. A failing statement on the temp table fails the attempt, as any manifest statement of the replay does; no error line and
    no fallback to copies (the earlier draft's), as the transaction it runs in may be gone.
15. Metadata that differs is a copy, with no sync onto the shared inode even under Only Sync Attributes (the study's call,
    kept).
16. History keeps showing a delete and a create for such a move (0.55.7's section 9 reads the link as an applied copy).
17. One line per batch that placed a link, counted at placement, a plain info line, its wording in section 6.
18. 0.55.7's growth leave-outs (Tasks 3 and 4) feed nothing; the feed is `delete_path()`'s alone.
19. Two headings change: "A folder or file moved into a new folder is copied whole" becomes "... is copied where it cannot be
    linked", "A move into its own old place is copied whole" becomes "... is copied" (docs/progress.md's P3 names the first
    by its old heading). 10.1 states the cost of an unchanged move as that of a move into an existing folder, which the real
    daemon's measurement checks; it holds no placeholder.
20. The release is called 0.55.8 in the docs texts; the number is the main session's.
21. On two renames the feed comes from `pre_record()`'s report for delete entries only, so there the copy fallbacks' deletes
    of a move's source feed nothing and those files are copied as today (section 7, item 9). Reporting every move's source
    would feed inodes a successful rename keeps in the tree at its target. A move into its own old place never renames, so
    its source alone could be reported as a delete; that is left out, as the create of its new folder, when it replays
    first, records the old folder whole before it (read in the code, not run), and it would be a rule for one rare shape.
22. `verify()` now gives `replay_ops()` its fixes in the order `replay()` replays them, so a pre-record and the replay agree
    on which of two records at one path takes the old entry.
23. A roll-forward's estimate fills nothing and charges every copy, as today, though its replay still links a file whose
    delete the cut attempt had not recorded: the estimate is high by such files in a cut batch, as it is today for every
    such move.
24. The estimate feeds the source of a move into its own old place on every vault, as only the hand-over finds out whether a
    filesystem has exchange; on a pool or a filesystem with no exchange that move is then Q25's overshoot. Leaving it out on a
    pool (known before the estimate) would be one condition more and would still overshoot on a filesystem with no exchange.
25. Under Only Sync Attributes a later chmod of a linked file shows on the version before's file at the candidate's path,
    which may be another file than the moved one when two files share bytes and metadata (the trailing-path choice makes it
    rare). README line 115 already says a restored file under Only Sync Attributes carries the newest metadata its shared copy
    has; this is the same effect, not a widening.
26. Access times are not compared: `entry_metadata()` leaves them out, and a renamed move keeps the old inode's atime too.
27. The table is emptied in `do_backup()`'s `finally`, outside any transaction; after a JobFailure the job's loop closes the
    manifest, which drops it with the connection.
