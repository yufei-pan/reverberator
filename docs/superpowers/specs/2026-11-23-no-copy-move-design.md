# The no-copy move into a new folder (P3)

A move into a folder made in the same batch (`mkdir new; mv big new/`) is copied whole today, though the vault already holds
every byte of it. This round makes the copy hard-link each file of the new folder that holds, byte for byte and in its
metadata, a file the batch's own delete took into the version before (under Only Sync Attributes, only the moved entry's own
old copy, section 4), and copy everything else as today. The result on disk
is the state a move leaves (one inode, named at the old path in the version before and at the new path in the new one), it
trusts no event and no watch, and its worst case is the copy made today.

Built as its own round after round 0.55.7, on a branch of its own from the merged 0.55.7, as that round rewrites the replay's
looks (its section 7), the change list (section 9) and the length rule (section 1) around the same code. The build starts only
once Q24 and Q25 are answered (Q25 is asked with Q24), as the answers decide whether it is built now, the candidate rule, the
estimate and the texts of section 10, so no text is written with a placeholder. "Today" below means 0.55.6, branch
`r0556`. Functions are named first; line numbers are of reverberator.py at e166baa (18,251 lines), the file 0.55.7 builds on,
and 0.55.7 moves them.

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
nothing yet. The estimate is Q25: written on its option (a), each place its option (b) changes marked **[Q25]**.

Standing decisions that bind the build (docs/progress.md): a worktree, never the live checkout; the suite in parallel; no
pytest as root on the host; root, loop, mount, mergerfs and power-loss tests in reverberator's own test VM; the headroom rule;
the mergerfs and power-loss tests in the release gate; the scrub before every push.

## Summary

| § | Part | Code it touches | Adds | Removes |
|---|---|---|---|---|
| 2 | What left: the files the batch's deletes took into the previous version | `TreeWriter.record()` (reports what it took), `remove_queued()`, `replay_ops()` (a delete's own op kind), `TreeWriter.pre_record()` (returns what each delete's record took), `do_reverb_backup()` (`feed_released`), its `pre_record()`, `verify()` and `delete_path()`, `VaultManifest` (`_open()` and five methods) | a temp table on the manifest's connection, per batch; one feed at each applied delete | nothing |
| 3 | The estimate | `do_backup()` (around `get_backup_size_inode()`), `get_backup_size_inode()`, `get_unskipped_size_inodes()`, one helper shared with `delete_path()` | a file the batch may link is charged nothing | nothing |
| 4 | The copy step | `do_reverb_backup()`'s `copy_path()` (its two `writer.copy()` calls), `wait_for_async_commands()` and the replay's `finally`, a new `same_file()` beside `hash_file()` (its opener shared), `entry_metadata()` (of an open handle too) | lookup, a check, a full compare of metadata and bytes on a compare pool, then the link or the copy | nothing |
| 5 | The writer's verb and the size books | new `TreeWriter.link_kept()`; `BatchSizes` (`shared` by rel, new `linked()`); `finish_copies()` (a link already made) | one verb, one sizes call | nothing |
| 6 | The log line | end of `do_reverb_backup()` | one line per batch that placed a link | nothing |
| 10 | Docs | README lines 15, 19, 22, 42, 43, 45, and 31 on Q25's answer; five docs/limitations.md entries | the narrowed texts, one widened (Q25) | the claim that such a move is always copied |

No change to the watcher, the manifest's stored format, the change list or any command. One number is added, the 1,000 rows a
key search reads at most (section 4, with the measurement behind it); the compare reuses `hash_file()`'s 1 MiB read, the
compare pool's `COMPARE_THREADS` threads and `compare_scopes()`'s window of four times that. State at rest: none, on disk or
in memory (section 2: the temp database gives its file's pages back once the table is emptied). Per batch: one temp table,
empty unless the batch deletes tracked files; on two renames, what each delete's record took before the replay; the compares
in flight, with their candidates, and a flag that cancels them; the links not yet placed. One new question, Q25 (the
estimate), besides Q24.

## 1. The rule that keeps a version right

> A file is linked only from a file that a delete of this batch took into the version before (claimed once), recorded
> checked, whose bytes compare equal in full to the monitored file's and whose mode, owner, group, mtime and extended
> attributes are the monitored file's. Everything else is the copy made today.

The first half keeps the vault's shape a move's shape: one path per inode in a version. The second half makes the version's
bytes and metadata the ones a copy would have written. Access times are not compared: `entry_metadata()` leaves them out
everywhere, and a renamed move keeps the old inode's atime too, so a link leaves the atime a move leaves.

**Why no order of events can give a version worse than today's copy.** For each file the replay copies today, the version
now gets either that copy (today's code, unchanged) or a link to a file whose bytes and metadata were just compared equal to
what a copy started at that moment would have read and kept: the compare opens the monitored file once and reads its
metadata (`fstat()`, its extended attributes through the handle) and then its bytes through that one handle, as `cp` reads
one file. A change after the open is a change after the take, which the next batch backs up, as it would after a copy that
read the file then. So for every order of events and every state of the tree, the version's contents are those today's copy
would produce. The walk that decides which files are copied is today's, so nothing can be missing that today's copy holds.
This guarantee is about the version the batch writes; an older version's file can change later only as round 19's rule lets
a shared inode change under Only Sync Attributes (below). Which candidate was tried does not matter to the bytes: off Only
Sync Attributes any file with the same bytes and metadata is a true stand-in, so the hint that picks it (its size, mtime,
mode, owner and group, and how much of its path it shares with the new one) may be wrong as often as it likes and costs only
a compare; the path hint only makes the moved entry's own old copy likelier. Under Only Sync Attributes it matters besides:
a later change of the new file, synced onto the shared inode, shows on the version before's file at the candidate's path
(round 19's rule below), so there the copy links only by the path lookup (section 4), from the released file at the new
path with its leading folders dropped, never from a twin elsewhere. No event, no watch, no inode number and no record of the
monitored file is trusted for the bytes. What the rule's first half guards is the vault's shape, not the bytes:
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
| A found folder back in `newDirWDs` by a second walk of its parent (`mkdir a; mkdir a/b; mv big a/b/big`, then a same-size write) (21, 44058e2) | its change discarded: old bytes | the folder is inside the created folder's copy, and the batch holds `big`'s delete (a move into a new folder keeps its move-out, which is its delete once the tree is quiet): the changed file differs and is copied, the rest are linked |
| A same-size change between `mkdir n` and `mv app n/app` (`cp -p` or `tar x`) (21, 7d34217; review 3: 4 of 6 wrong on the real daemon) | the vault's old copy put over it | the changed file differs from the version before's: copied |
| A rename between the new folder's `add_watch` and its listing: `poke_between`, `cpp_between`, `in_then_poke_mv` (21, 057ba3c; review 3's F3) | old bytes | the same |
| Renamed again before the walk lists it (`mv app n/app.tmp; mv n/app.tmp n/app`) (21, f5d6031, a5a8efb; review 4: 5 of 8 wrong) | old bytes | the same |
| The stale watch of a folder that left from a new folder (21, 9368fb3; review 5's F1: 3 of 3 wrong) | old bytes | no watch is asked |
| F2, `twice_old_race`; F1 through an ancestor (the count); the take window; the placed watch; `other_pending_remade`, `mv_onto`; `lag_child_out`; `pair_then_new_sub_out` (22) | a rename in the vault, or a lost event, from a wrong watch path | this route adds no rename and reads no event; they stay as 0.55.4 closed them |

**The new orders this route could open, and the rule that closes each.** Each has its own test (section 9).

1. *Two paths of one version on one inode.* A move never leaves that. Rule: a candidate is a file **a delete of this batch
   took into the version before**, by that delete's own record (on two renames, the record `pre_record()` made for that
   delete before the replay, in the replay's order: section 2), and it is **claimed once**, right before its link is made (a
   link the vault then refuses spends it, and the file is copied). A renamed move's source is recorded by `hl_record()`, never
   by a delete, and its rows move to its target with the rename; a delete whose path the version before already holds as its
   own (recorded earlier in the batch) takes nothing; a delete that runs before a rename of something under it takes it, and
   `TreeWriter.rename()` then finds no source (`NotRenamed`) and the move falls back to a copy. So no inode the tree still
   holds is ever a candidate (section 2 says how the record reports what it took). Two new files with one candidate: one
   link, one copy.
2. *Metadata of another file.* A link shares mode, owner, group, times and extended attributes. Rule: link only when
   `entry_metadata()` of the monitored file and of the candidate are equal; anything else is a copy (docs/lessons.md:
   "never write a change signal onto data it did not come with").
3. *The file changes while it is compared.* The same as a file changing while it is copied: the version holds bytes that
   were read, through the one handle whose metadata was compared, and the write's event comes after the take and is backed
   up by the next batch (events in a folder made during a batch are recorded again from the take on). A write into a part
   already compared leaves the old bytes, consistently; a copy at that moment would hold a mix. A file replaced at its path
   during the compare is not read: the handle stays on the file it opened.
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
   moved files: a roll-forward feeds nothing (section 2). Read in the code; the crash gates run through it (section 9).
7. *A look that cannot answer.* A look at the version before or at the monitored file that fails (EIO, EACCES) never reads
   as "there" or "equal": it chooses the copy (round 0.55.7, section 7, for why "not there" may not stand for an error). So
   the looks are `kind_at()` and `real_folders_to(strict=True)`, which raise, never `os.path.lexists()`, which answers False
   on EIO and EACCES.
8. *Bytes the vault never flushed.* The compare reads through the page cache, which can hold right bytes over a disk that
   never got them. Rule: only a row recorded checked is a candidate: its copy was flushed before its commit, through
   handles that heard any write error (0.55.5). A row an older release left unchecked is not.

Items 1, 5, 7 and 8 differ from the study's rule; the Calls to confirm say how.

## 2. What left: the files the batch's deletes took into the version before

**What it does.** A table of the batch's released files: each a regular file a delete of this batch took into the version
before, with its size, mtime, mode, owner and group as its row records them, and its name. It is the only source of
candidates (section 4), and it is filled where the delete is applied, from what that delete's record took, so it holds
positive evidence only. What a record takes is the tree's entry, and the tree, the newest version, holds no forward link, so
every file row a feed takes names a real file of the version before from then on, never a forward link.

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
  fixes once (`prepared = prepare_backup_entries_for_replay(fixes)`) and gives `prepared` to both `replay_ops()` and
  `replay()`: today `replay_ops()` reads them unprepared, in the comparison's order (15170), while `replay()` gets them
  prepared. `fixes` itself stays as it is: `applied_fixes(fixes, applied)` reads it for `verified`, the change list's rows,
  and the prepared dict drops the creates a folder create covers (`prune_entries_covered_by_dir_creates()`), which the change
  list keeps.
- `do_reverb_backup()` gains `feed_released=True`; `do_backup()` passes `feed_released=tree is None`, so a roll-forward
  feeds nothing (below).
- `do_reverb_backup()`'s `delete_path()` (14811) first takes its rel's list out of `pre_taken`
  (`pre_taken.pop(relative_path, [])`, empty off two renames), passes it as `took` to each of its two
  `writer.remove_queued()` calls (the real folder's, the file's) and, right after the call and before its
  `manifest.remove_tree()` or `manifest.discard()`, feeds the table when `feed_released`: `manifest.release_under(took)`. On
  two renames the list holds what the delete's pre-record took, and its own record then takes nothing, as a record only acts
  where a forward link still stands; off them it holds what its own record takes. A delete `delete_path()` does not remove
  feeds nothing, and its list is dropped: one the length rule keeps (`left_out(kept=True)`), one behind a link or a file in
  the version (`real_folders_to()` false), one whose place holds a kind its delete does not remove (`removed_by_delete()`,
  the helper section 3 shares: a file's delete removes anything but a real folder, a folder's only a real folder, so a
  folder's delete at a link or a file removes nothing; on two renames its pre-record may have taken that other entry, which
  the tree keeps), the version folder itself.
- **Order.** `pre_record()` records in the replay's order: `do_reverb_backup()` orders the batch's entries with
  `prepare_backup_entries_for_replay()` before `replay_ops()` reads them, the delete that replays behind a move included,
  and the verification's after the change above. So where a move's source lies at or under a delete, whichever replays
  first records it: `mv d/g y; rm -r d` replays the move first, so `g` is the move's, and `d`'s other files are the
  delete's, on two renames as inline.
- **Which deletes feed** (in any batch but a roll-forward, below). Off two renames, every delete the replay applies, as each
  comes through `delete_path()`: the
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
- **A roll-forward feeds nothing.** Its writer finds the cut attempt's records standing (`do_backup()` makes it on the tree
  as it is), so a delete of a place the cut attempt recorded would take nothing anyway, and one the attempt had not recorded
  yet would feed; `feed_released=False` makes it one case: the count of fed rows stays 0, and every copy is made as today
  (section 4, step 1). Its estimate fills nothing either (section 3), so it charges every copy the replay makes, as today.
- `VaultManifest._open()` (9564), before its first temp object (`temp.seen`, 9586), runs `PRAGMA temp.auto_vacuum = FULL`,
  and beside `temp.seen` creates `CREATE TEMP TABLE IF NOT EXISTS released(path TEXT PRIMARY KEY, size INTEGER, mtime_ns
  INTEGER, mode INTEGER, uid INTEGER, gid INTEGER) WITHOUT ROWID` and an index on `(size, mtime_ns, mode, uid, gid)`, the
  key (section 4). Paths are stored as `entries` stores them (`storable_name()`).
  **[Q24]** (b): no index beyond the path: its lookups are by path.
- `VaultManifest` gains five methods:
  - `clear_released()`: one statement that empties it.
  - `release_under(rels) -> int`: for each rel (of `took`, or of the estimate's fill, a trailing `/` stripped), one `INSERT OR
    IGNORE INTO temp.released SELECT ... FROM entries` of the rows at it or under it, as `tracks()` matches a rel: `path =
    s OR path > s/ AND path < folder_range_end(s/)`, `s` its `storable_name()`; never `iter_under()`'s range on a bare
    name, which for `d` runs from `d` to `e` and takes `d.bak`, `d2` and `data.txt`. Only files (`kind = 'f'`), not dirty,
    recorded checked (`coalesce(unchecked, 0) = 0`). It returns the number of rows added, which `do_reverb_backup()` adds to
    its count of fed rows, a local of the call.
  - `may_release(st) -> bool`: one indexed `SELECT ... LIMIT 1`: whether a row with `st`'s size, mtime, mode, owner and
    group is in it (sections 3 and 4).
  - `released_candidate(rel, st, held, by_key) -> rel or None`: section 4's choice: the path lookup, one `SELECT` on the
    primary key, then, with `by_key`, the key search, one indexed `SELECT` of at most 1,000 rows plus those in `held`, and a
    choice in Python; the path is returned through `stored_name()`.
    **[Q24]** (b): no `may_release()`, and `released_candidate(rel, st, held)` is the path lookup alone (four methods).
  - `claim_released(rel)`: deletes its row (section 4).

**The two fills, and the table at rest.** Before the replay the table holds what the batch *may* release: `do_backup()` fills
it for the estimate (section 3), before the prune and the hand-over that begins the transaction, and empties it again right
after `get_backup_size_inode()` returns, still outside the transaction, so the replay starts on an empty table. Inside the
transaction it holds what the replay's deletes *did* take: `do_reverb_backup()` empties it at the end of its `try`, once the
verification's copies are placed, so the commit commits it empty. Every other end of the batch leaves it empty or gone with
nothing more: a rollback (a stop) brings back the empty table it began with, as sqlite's temp tables are in the
transaction (a probe with sqlite 3.46: rows inserted before `BEGIN` and deleted inside it are back after `ROLLBACK`), and on a
batch that does not commit, a stop or any exception, the job's loop breaks and its `finally` closes the manifest
(`backuper()`), which drops the temp tables with the connection. So nothing empties it in `do_backup()`'s `finally`, which
runs after its `except` has closed a manifest it opened. `do_reverb_backup()` keeps a count of the rows fed, and the copy
step asks the table nothing while it is 0, so a batch that deletes nothing costs nothing.

Emptied rows leave no disk or memory behind. A temp table lives in sqlite's temp file (an unlinked file in its temp folder,
`/var/tmp` by default), which keeps its size until the connection closes: a probe here (sqlite 3.46.1, a `released` table
fed 400,000 rows, then emptied and committed) left the file at 85.6 MB without the pragma and at 20 KB, the empty tables'
pages, with `PRAGMA temp.auto_vacuum = FULL` set before the first temp object, which truncates the file at each commit that
freed pages. Its cost in that probe: a claim (`DELETE` by path) 6.9 to 7.7 µs against 6.0 to 6.9, emptying 400,000 rows 43
to 49 ms against 37, the fill and the lookups the same (2.3 to 2.7 s and about 3 µs). The pages the job's connection keeps
in memory go back at `release_idle_memory()` (`PRAGMA shrink_memory`), as the batch's other pages do. `temp.seen` is in the
same temp database and gets the same: its file shrinks when its rows go, at the next comparison's `clear_seen()`; between
comparisons it keeps the last comparison's rows, as today (clearing it at the comparison's end too is not this round's).

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
  itself on a full disk or an I/O error; going on would write the batch's rows outside it. A feed's failure, inside the
  transaction, leaves the next attempt a roll-forward; the estimate's fill fails before the hand-over, so the next attempt
  takes the batch again. A temp folder too full for the table's file fails the attempt so too, as one too full for
  `temp.seen` fails a comparison today, and the job's next attempt goes on once there is room.
- A record that fails raises JobFailure before anything is fed, as today.
- A rm of a delete that fails: while the daemon runs, `failed_removal()` fails the attempt at the next wait, which comes before
  any copy or compare (the replay's delete barrier, `delete_and_copy()`'s and `copy_instead_of_move()`'s waits,
  `recheck_moved_folder()`'s), so no candidate is compared or linked while the tree may still hold it. On a stop that wait
  returns before it, and what keeps a link out is the placement: a compare settled on a stop links nothing (section 4), and a
  link is placed only by `finish_copies()`, which a stop skips (`stop_copies()` discards its name).

**Tests** (tests/test_no_copy_move.py, `unit`, through `do_backup()` with raw events as tests/crash_batches.py's
`backup_events()` builds them; every test runs under the suite's ground-truth plugin, which checks each older version and
each change list's sizes). `backup_events()` asserts the commit (crash_batches.py:49): it is split into `attempt_events()`,
the same call returning `committed`, and the assert, so the tests of a stop or a failing statement call
`attempt_events()`. "On two renames" is both ways: the batch's writer made pooled (`hand_over()` wrapped to pass
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
  in the same order; and `verified` still holds a create the prepared entries drop under a folder create the verification
  makes.
- `test_a_roll_forward_feeds_nothing`: a batch cut after its hand-over and before its delete's record, rolled forward: the
  count of fed rows stays 0, and `n`'s files are copied.
- `test_the_table_holds_nothing_once_the_batch_ends`: after a commit, the table is empty and sqlite's temp file (its handle
  in `/proc/self/fd`, with `SQLITE_TMPDIR` set to the test's folder) is back to its empty tables' size after a batch that fed
  thousands of rows; after a stop (`attempt_events()` returns False), a spy on `manifest.rollback()` reads it empty right
  after the rollback.
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
  None`) and holds a create or a modify and a delete, or a move into its own old place off a pool: `manifest.release_under()`
  of the rel of each delete entry and, off a pool (`on_pool`, asked once as the batch began), of the source of each move
  whose target lies under it. Each is left out where `delete_path()` would remove nothing, judged on the tree as it stands
  (`tree_now`): the version folder itself, a path the length rule keeps (`vault_path_too_long(estimate_bytes, rel, False)`,
  as `replay_ops()` measures a delete), one behind a link or a file of the version (`real_folders_to(tree_now, rel,
  missing_ok=True)` false), and one whose place holds a kind its delete does not remove: `removed_by_delete(path, is_dir)`,
  `delete_path()`'s own two tests (14839, 14847) moved into one helper both call, so the two cannot disagree (a folder's
  delete removes only a real folder, never a link or a file at its place; a file's delete removes anything but a real
  folder; 0.55.7's Task 5 makes these looks strict, and the helper takes them as Task 5 leaves them). `leaving` is then, off
  Only Sync Attributes, `lambda path, st: manifest.may_release(st)`, and under it the copy step's own path lookup, `lambda
  path, st: manifest.released_candidate(os.path.relpath(path, monitor_path), st, (), by_key=False) is not None`, as under it
  the copy links by that lookup alone (section 4); None when nothing was fed. Right after `get_backup_size_inode()` returns,
  `manifest.clear_released()`. These statements run before the transaction begins, each on its own.
  **[Q24]** (b): `leaving` is the path lookup on every job. **[Q25]** (b): no fill, no `leaving` and no clear: the estimate
  charges every copy, as today.
- A roll-forward (`tree is not None`) fills nothing, and its `leaving` is None; its replay feeds nothing (section 2), so it
  copies every file the estimate charges, and the estimate is exact, as today.
- `get_backup_size_inode(..., leaving=None)` passes `leaving` to `get_unskipped_size_inodes()` (11759) only for the walks of
  what `copy_path()` copies: the main walk's call for a create or a modify entry of `taken`, every call of the `carried_in`
  subtraction (it takes back what a created folder's walk charged, through `leaving` too), and the `written` add-back's call
  for a create or a modify entry. Never for an attrib entry, in `taken` or in `written` (`copies()` takes both kinds): the
  replay copies it in its attrib branch, which never links.
- `get_unskipped_size_inodes(..., leaving=None)`: a regular file (`S_ISREG` of the lstat it makes already) for which
  `leaving(path, st)` is true is charged nothing, no bytes and no inode: the entry itself when it is a file, and each file of
  a folder's walk. A hard link adds a name in its folder, no inode and no block of its own.

**Why the batch's deletes and its moves into their own old places.** The estimate errs low, never high: an estimate too low
only passes the limit until the next prune, a copy the estimate charges and the replay never makes prunes versions for good
(the reason the size entry gives). So it must charge nothing the replay can link. The replay links only files a delete took
(section 2). A delete takes only where the version before still holds a forward link, so only version n's entries, never
one moved in during the batch, and the fill leaves out the deletes `delete_path()` removes nothing for. A move counts nothing
in the estimate: the replay renames it, and one that falls back to a copy is left out already (the size entry names it),
except a move into its own old place, whose target the created folder's walk charges, as the replay copies it whole (the
`carried_in` exception). Off a pool its source is fed, so its unchanged files are charged nothing, as the fallback's delete
takes them and the copy links them; on a pool that delete takes nothing (the batch recorded the source as the move's before
the replay, section 2), so the source is not fed and the move is charged, and copied, as today. A move carried into a created
folder is charged by that folder's walk and taken back by the `carried_in` subtraction, both through `leaving`, so the two
cancel whatever is fed; feeding any other move's source would change no charge but a twin's (`cp -p a b; mv a c` would leave
`b` uncharged, though the move renames `a` and nothing releases it). A fallback's delete the fill does not predict (a move
another change outran) feeds rows the estimate never saw, but the fallback's own copy, which the estimate leaves out as it
leaves out every fallback, comes right after that delete's wait and so meets those rows first; a charged file that links
one of them later leaves the fallback's own file of the same bytes copied in full, uncharged, so the total stays at or
below what the batch writes. So every file the replay links is one the estimate leaves
uncharged: it was a file row under a fed delete, or under the source of a move into its own old place off a pool, when the
batch was taken, so the fill put it in the table and `leaving` is true for it (under Only Sync Attributes, by the same path
lookup the copy makes); and the estimate stays at or below what the batch writes (barring a file changed between the
estimate's walk and the replay's, as today). The verification's copies are not estimated at all. The estimate also charges
nothing for some files the replay copies after all, and is low by each: the vault can pass its limit by them until the next
prune (Q25). They are exactly these, by kind of vault:
- on every vault:
  - a predicted file whose candidate's contents or extended attributes differ (its size, mtime, mode, owner and group
    matched: a same-size rewrite with its mtime set back, an extended attribute set in the move's batch);
  - a file whose matching row its delete does not take, as a move of the batch took that row's file away first: the twin of
    a file moved out of a place the batch then deletes (`cp -p d/a b; mv d/a c; rm -r d`: `b`);
  - a file copied before the delete that takes its row: a delete that replays behind a move, after the batch's creates
    (`mv d/g y; mkdir n; mv d n/d`, section 7);
  - a file left without a candidate: the second of two new files that match one released file, and a file whose candidate
    was spent by a link that failed (one link per released file, claimed before its link);
  - a file whose look, compare or link fails with an error: a failed look at the version before or at the monitored file
    (EIO, EACCES), a read error in the compare, a link error outside `NO_HARD_LINK_ERRNOS`;
- on a vault whose filesystem keeps other metadata than the monitored file has (an extended attribute it refuses or sets
  itself, an owner it cannot keep): every predicted file with such metadata;
- on a vault that refuses hard links, or a mergerfs pool that answers EXDEV between its disks (by its policies, section 8),
  every predicted file, every time (docs/limitations.md "A copy made where the vault refused a hard link" waits for such a
  vault to show);
- on a filesystem with no exchange (a vault off a pool on which `hand_over()`'s exchange fails, which only the hand-over finds
  out, after the estimate), every file of a move into its own old place: the batch recorded its source as the move's before
  the replay, so the copy's delete takes nothing (section 2).

The key is the row's size, mtime, mode, owner and group, which the rows record, so a chmod or chown made with the move (`mkdir
n; mv big n/; chmod -R g+w n`) is charged as the copy it is.

**State.** The table (section 2), filled here and emptied once the estimate is made; the replay feeds it again.

**Failure cases.** A statement that fails raises `sqlite3.Error` before anything is written (the estimate comes before the
prune and the hand-over) and fails the attempt; the next attempt takes the batch again. A file gone or changed between the
estimate and the copy: as today, the estimate is what the walk saw.

**Cost.** One indexed lookup per regular file the estimate walks (under Only Sync Attributes, the path lookup too, one
`SELECT` on the primary key), only in a batch that both deletes tracked files (or moves one into its own old place) and
creates or modifies something; the walk lstats each file already. The fill is one statement per fed rel, over the rows it
covers; the build times the fill and the lookups on a delete of 1,000,000 rows beside `manifest.remove_tree()` of the same
rows.

**Tests** (tests/test_no_copy_move.py, `unit`; tests/test_estimate_charge.py's helpers):
- `test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder`: a delete of `big` and a create of `n/` holding
  it, off and on two renames, with Only Sync Attributes on and off: the estimate is `n`'s folders' charge alone; under a size
  limit with five small versions, all five stay.
- `test_the_estimate_charges_a_file_changed_in_the_move` (appended, its size moved) and
  `test_the_estimate_charges_a_file_chmodded_in_the_move` (its mode differs from its row's).
- `test_an_attrib_copy_is_charged_whatever_is_fed`: with Only Sync Attributes off, a chmod of a file whose key a released
  row has: its attrib copy is charged.
- `test_under_only_sync_attributes_a_renamed_move_is_charged`: `mkdir n; mv f n/g` with it on: charged, and copied.
- `test_the_estimate_is_never_above_what_the_batch_writes` (a parametrized pin, each shape its own case, off and on two
  renames, with Only Sync Attributes on and off): a move into a new folder, the same with a file renamed, the same at a
  start's full comparison, a move into its own old place, a move a folder move outran (`mv d e; mkdir e/sub; mv x e/sub/x`),
  a delete that replays behind a move (`mv d/g y; mkdir n; mv d n/d`), two creates twins of one deleted file, a twin of a
  renamed file (`cp -p a b; mv a c`), and a twin of an outran move's source created after it: estimated bytes and inodes at
  most the vault's growth in bytes and inodes (`sizes_by_newest_holder()`).
- Q25's pins, each: the estimate leaves the files out, the replay copies them:
  `test_a_predicted_link_whose_bytes_differ_is_copied_uncharged`,
  `test_a_twin_of_a_file_moved_out_of_a_deleted_folder_is_copied_uncharged` (`cp -p d/a b; mv d/a c; rm -r d`),
  `test_a_predicted_link_the_vault_refuses_is_copied_uncharged` (an `os.link` stand-in answering EPERM), and
  `test_on_a_filesystem_with_no_exchange_a_move_into_its_own_old_place_is_copied_uncharged`.
- `test_on_a_pool_a_move_into_its_own_old_place_is_charged` (pooled: not fed, charged, copied).
- `test_a_twin_of_a_renamed_file_is_charged` (`cp -p a b; mv a c`: `b` is charged, and copied).
- `test_a_delete_the_replay_removes_nothing_for_is_not_fed_to_the_estimate`: a delete behind a link of the version, a file's
  delete whose place holds a folder, and a folder's delete whose place holds a link.
- `test_a_roll_forward_charges_every_copy`: a batch cut after its hand-over and before its commit, then rolled forward: the
  estimate charges `n`'s files, and the replay copies them.
- tests/test_moves_into_new_folders.py's `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`
  and `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one` change: their estimated
  inodes are the names in `n` less the files linked (all of `big`'s but those the row writes or changes), plus the probes;
  `written <= est_size <= grew` stays (the chmod rows keep it because the mode is in the key). **[Q25]** (b): the estimated
  inodes stay the names in `n` plus the probes, and the bound becomes `written <= grew <= est_size`, as the estimate charges
  the files the replay links.
- tests/test_estimate_through_a_take.py's three tests (`test_the_put_back_through_a_take`,
  `test_the_attrib_put_back_through_a_take`, `test_file_rows_through_a_take`) stay as they are: their batch holds `n`'s create
  and a move into it, which renames, and no delete, so nothing is fed.
- **[Q25]** (b): of these only `test_the_estimate_charges_every_file_the_replay_links` (a move into a new folder: the
  estimate charges `big`'s files, the replay links them) and the two changed tests above.

## 4. The copy step

**What it does.** Before a regular file's copy is queued, the replay looks for a released file with its key, checks it, and
queues a full compare of the two, metadata and bytes, on a compare pool; an equal compare becomes a link in place of the
copy, and anything else is the copy made today.

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
3. `manifest.may_release(st)`: no row with its key: copy (one `SELECT`, the usual case for a batch's unrelated creates). Then
   `candidate = manifest.released_candidate(rel, st, held, by_key=not only_sync_attributes)` (the choice below; `held`, the
   candidates of the compares in flight): none: copy.
   **[Q24]** (b): no `may_release()`; `candidate = manifest.released_candidate(rel, st, held)`, the path lookup alone, one
   `SELECT` on a miss, on every job.
4. The version before's file: `real_folders_to(writer.previous, candidate, strict=True)` (no folder above it is a forward
   link, through which the path would lead into the tree) and `kind_at()` of it is `'f'` (not a forward link, not gone).
5. The compare is queued: `same_file(source_path, kept, cancelled)`, `kept` the version before's file, submitted to the
   batch's compare pool, and the file kept in the replay's window with its candidate, which joins `held` (where it runs,
   below).
6. When the window settles it, on the replay's thread, the daemon stopping (`GREEN_LIGHT` clear) comes first: neither a link
   nor a copy, and the replay ends as for any stop. Then, an equal compare: `manifest.claim_released(candidate)` deletes its
   row, and `writer.link_kept(candidate, source_path, rel, pending)` (section 5) makes the link: True, and the rel is kept
   with the file's size until it is placed (section 6); False, a copy, and the candidate stays spent (claimed before the
   link, so no other file tries a link the vault just refused). Metadata or bytes that differ, or a compare that failed: a
   copy, and the candidate leaves `held` unclaimed, for another file.

An OSError at steps 2 to 4, and 0.55.7's `VersionLookError` from a strict look, is caught there and chooses the copy: a look
that cannot answer never links (section 1, item 7). `VersionLookError` is a JobFailure, not an OSError, so the `except`
names both.

**The candidate.** Two lookups, the second only off Only Sync Attributes and only when the first finds none. A candidate a
compare in flight holds (`held`) is never chosen, so no two compares share one, and a claim always finds its row.
- *The path lookup*, on every job: the paths `rel` gives with its first k parts dropped, k = 1 .. depth − 1 (for
  `n/big/sub/b`: `big/sub/b`, `sub/b` and `b`), in one `SELECT ... WHERE path IN (...)` with the key, on the primary key,
  with no bound; the longest found that is not in `held` is the candidate. It finds the moved entry's own old copy wherever
  its old path is its new path with leading folders dropped: an entry moved from the top of the monitored folder into new
  folders (`mkdir new; mv big new/`: `new/big/a` pairs with `big/a`; `mkdir -p a/b; mv big a/b/`), a tree unpacked under its
  own name into new folders (`rm -r big; mkdir r; tar xf big.tar -C r`), and a move into its own old place there (`mv D x;
  mkdir D; mv x D/D`: `D/D/f` with `D/f`). It does not find the old copy of an entry moved below the top of the monitored
  folder (`mkdir P/new; mv P/big P/new/` gives `P/new/big/a`, whose forms `new/big/a`, `big/a` and `a` are not `P/big/a`),
  nor of one renamed in the move.
- *The key search*, off Only Sync Attributes only: one indexed `SELECT` of the rows with the key, in the index's order (by
  path within one key), at most 1,000 plus as many as `held` holds; among those not in `held`, the one whose path shares the
  most trailing parts with `rel` (ties: the first by path), so a moved entry pairs with its own old copy where the path
  lookup cannot find it: `P/new/big/b/data.bin` with `P/big/b/data.bin`, not `P/big/a/data.bin` of the same key.

One candidate per file, so a file costs at most one compare; one whose candidate differs is copied, though another row of
its key might have matched. A key search reads at most 1,000 rows of one key besides those held: in this spec's probe
(sqlite 3.46, an in-memory table of 200,000 rows of one key), a row cost about 0.3 µs to read and 0.2 µs to weigh in Python,
so 1,000 rows cost about 0.5 ms, what the `cp` process a link saves costs (0.5 ms for an empty file, measured beside it);
with no bound each lookup would read every row of the key, and a move of many files of one key would cost their number
squared. The path lookup comes first and has no bound, so a folder of many files of one key moved from the top (2,500 empty
`__init__.py` with one mtime, `mkdir n; mv pkgs n/`) pairs each file with its own copy, wherever the key search's read would
end; moved below the top, such a folder's files pair, by the key search, with rows among the first 1,000 of the key not held,
linked where bytes and metadata are equal, as empty files' are, and copied where not. Under Only Sync Attributes only the
path lookup runs, as a link from a twin elsewhere would let a later attribute change of the new file show at that twin's
path in the version before (section 1): there a file whose own copy the path lookup does not find, a file renamed in the
move among them, is copied, as today.
**[Q24]** (b): the path lookup alone, on every job: no `may_release()`, no key index, no key search and no bound.

**`same_file(source, kept, cancelled) -> bool`**, beside `hash_file()` (11674). It opens the monitored file once, as
`hash_file()` opens one (no link followed, `O_NOFOLLOW`; never a blocking open of what is not a regular file; a lease waited
for as `cp` waits): that opener becomes a module function both use; it opens the kept file so too. It compares
`entry_metadata()`'s tuple of each, read from its handle (`entry_metadata()` takes an open fd as well as a path: `os.fstat()`
and the extended attributes through the fd, with `xattr_names()`'s rule for a filesystem without them), as the move branch's
`only_attributes_differ()` compares them (14877): mode, owner, group, mtime and extended attributes; unequal: False. Then it
reads both through those handles into two buffers of 1 MiB, the size `hash_file()`'s full hash reads in (`1 << 20`), and
answers False at the first block that differs, at a length that differs, at any OSError, and when the daemon is stopping
(`GREEN_LIGHT` clear) or the batch is ending (`cancelled` set), both looked at between blocks. Not `filecmp.cmp()`: its cache
answers from an earlier result when the size and mtime are the same, which is exactly the case this compare exists for. Not
`cmp -s`: it opens the monitored file following a link, and blocks on a FIFO swapped in since the walk, where `cp -a` does
neither.

**Where it runs.** On a compare pool, in parallel, as `record_dirty_entries()` and `compare_scopes()` run their compares: a
`ThreadPoolExecutor` of `COMPARE_THREADS` threads (`--compare_threads`, 32 by default), made by `do_reverb_backup()` when it
queues its first compare, so a batch that compares nothing makes none. The pool is the compares' only bound, as it is for
those two: a compare takes no `BACKUP_SEMAPHORE` permit, so the compares and the copies never wait for each other. (A permit
would not deadlock: multiCMD's dispatcher takes a copy's permit on its own thread, and the copy's thread gives it back when
its command ends, `_HeldPermit.__exit__`, not when a wait reaps it; but a compare waiting for one would hold the `finally`'s
wait behind copies it has not stopped yet.) The replay keeps at most `COMPARE_THREADS * 4` compares in flight, the window
`compare_scopes()` keeps; when it is full, the replay waits for whichever finishes first (`concurrent.futures.wait(...,
return_when=FIRST_COMPLETED)`, in waits of `POLL_WAIT_SECONDS` between which it polls the pools, `poll_pools()`, as it does
while it waits for the copies) and settles every one that has finished: links and copies need no order, where
`compare_scopes()` settles in walk order because its results must be applied in that order. `wait_for_async_commands()`
first settles them all: whatever a compare decides is queued before any wait ends, and no move, delete barrier or
verification runs while a compare is open. `same_file()` polls nothing itself. `do_reverb_backup()`'s `finally` sets
`cancelled`, a `threading.Event` of the batch, then shuts the pool down with its queued compares cancelled
(`shutdown(wait=True, cancel_futures=True)`), then stops the copies as today: a compare already reading ends at its next
block (a JobFailure leaves `GREEN_LIGHT` set, so the batch needs a flag of its own), and one whose open waits for a lease to
break waits out the kernel's lease-break time at most (45 s by default), as `hash_file()`'s opener does while the daemon
runs. A compare reads twice what one copy reads and writes nothing; the build measures it against today's copy (section 9).

**State.** Per batch: the compare pool, the window (each compare with its candidate; `held` is their set), `cancelled`, and
the rels linked and not yet placed (section 6). Nothing at rest.

**Failure cases.** Each chooses the copy, which then fails or succeeds as today:
- the source gone or replaced since the walk listed it (step 2, or the compare's open): the copy's own failure keeps the last
  backed-up copy, or, gone, the row goes with today's line;
- no candidate, or a candidate whose version-before file is gone, a link, under a forward link, or cannot be looked at;
- metadata or bytes that differ, an unreadable side;
- the link refused or failing (section 5).
A stop during the compare chooses nothing: the batch ends as a stop does.

**Tests** (tests/test_no_copy_move.py, `unit` unless said; each through `do_backup()` with raw events, a delete of the old
place and a create of the new, unless said; each ends with the oracle of section 9):
- `test_an_unchanged_file_moved_into_a_new_folder_is_linked`, off and on two renames, with Only Sync Attributes on and off:
  the new path in the newest version and the old path in the version before are one inode; no two paths of one version share
  one; one line.
- `test_an_unchanged_folder_moved_into_a_new_folder_is_linked`, the same ways, with a subfolder, a link and an empty file in
  it: every regular file linked, the link and folders made as today.
- `test_a_folder_moved_below_the_top_is_linked_by_the_key_search` (`mkdir P/n; mv P/big P/n/`): with Only Sync Attributes off
  every file linked, each to its own old copy; with it on, every file copied.
- `test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied`: other bytes before the last 64 KiB (the twin of section 1's
  first order; the tests' `cpp`).
- `test_a_poke_before_the_compare_is_copied`: same size and mtime kept (the tests' `poke`) after the take.
- `test_a_write_during_the_compare`, two cases through a stand-in for `same_file()`'s read that writes into the monitored
  file after its first block: into a block not yet compared (copied) and into one already compared (linked to the old bytes;
  the next batch copies the new ones, and its version holds them).
- `test_a_file_replaced_after_the_compare_opened_it_is_judged_as_opened`: a stand-in for the opener that, once it has opened
  the monitored file, replaces it at its path with a copy of the candidate under other metadata: the compare reads the file
  it opened, and the version never holds the candidate's bytes under the replacement's metadata.
- `test_a_source_gone_before_the_compare_is_copied_as_today` (removed in a stand-in for `released_candidate()`): no link,
  and the lines and rows today's copy gives a source gone between the walk and its copy.
- `test_metadata_that_differs_is_copied`, one case per field: mode (a chmod with the move), mtime (`touch`), an extended
  attribute (`user.x`), owner and group (these two skip unless root, as tests/test_r_readers.py's `needs_root`, and run in
  the VM): each copied, never linked.
- `test_two_new_files_and_one_released_file_link_one`: the first queued holds the candidate and is linked; the second finds
  it held and is copied with no compare.
- `test_a_moved_entry_pairs_with_its_own_old_copy`: `big/a/data.bin` and `big/b/data.bin` of one key and other bytes, `mkdir
  n; mv big n/` (the path lookup, with Only Sync Attributes on and off) and `mkdir P/n; mv P/big P/n/` (the key search, off):
  both linked, each to its own.
- `test_one_candidate_is_tried_per_file`: with Only Sync Attributes off, two released files of one key and name, the one
  sharing more of `rel`'s path different in bytes, the other equal: copied, after one compare.
- `test_a_folder_of_many_files_of_one_key_moved_from_the_top_links_every_file`: 2,500 empty files of one name, mtime, mode
  and owner, one in each of 2,500 folders, `mkdir n; mv pkgs n/`, with Only Sync Attributes on and off: every file linked to
  its own old copy (the path lookup).
- `test_a_key_search_reads_at_most_1000_rows`: the same 2,500 below the top (`mkdir P/n; mv P/pkgs P/n/`), Only Sync
  Attributes off: no key search reads more than 1,000 rows besides those held (a stand-in counting them), no two compares in
  flight hold one candidate, and every file is linked (empty files are equal, so any row is a true stand-in).
- `test_under_only_sync_attributes_a_twin_elsewhere_is_copied`: a released `a` and a new `n/c` with its bytes and metadata:
  copied with it on, linked with it off.
- `test_the_compares_run_in_parallel`: a stand-in for `same_file()` that waits for a second call: two files of one moved
  folder are compared at once.
- `test_the_window_settles_whichever_compare_ends_first`: a stand-in for `same_file()` that holds the first file's compare
  until every other file of the folder is linked: they are, while it is open.
- `test_a_job_failure_ends_the_compares_in_flight`: a stand-in read that waits for `cancelled`, and a JobFailure raised in
  the replay: the attempt fails, and the `finally` returns once the stand-in has seen the flag.
- `test_a_candidate_under_a_forward_link_or_itself_a_link_is_copied`: a row fed by a stand-in for `release_under()` whose
  version-before entry is a forward link, and one under a folder that is one: copied.
- `test_a_stop_during_the_compare_links_nothing`: `GREEN_LIGHT` cleared from the stand-in read: no link and no copy queued
  for the file, the batch ends as a stop does (`attempt_events()` returns False), the next attempt commits it right.
- `test_a_failed_look_at_the_version_before_is_a_copy`: EIO from an `os.lstat` stand-in on the candidate's path.
- `test_the_location_recheck_and_the_verification_link_too`: a create the verification finds missing whose old place its
  own fix deletes: linked.
- `test_a_delete_and_a_create_of_one_path_are_a_copy` (pin): `rm -rf d; tar x` at `d`'s own place, times kept: the batch
  holds no delete, so every file is copied, as today.
- **[Q24]** (b): `test_a_file_renamed_into_a_new_folder_is_copied` (`mkdir n; mv f n/g`), and the key search's tests above
  (below the top, one candidate per file, the bound, the twin elsewhere) assert the copy on every job.

## 5. The writer's verb and the size books

**What it does.** One `TreeWriter` verb puts the version before's file at the new place the way a copy is put there, and
tells the size books that the file is the tree's again.

**Where.**
- New `TreeWriter.link_kept(kept_rel, source, rel, pending) -> bool`, beside `copy()` (reverberator.py:14170), the one door
  to the tree: tests/test_tree_writes.py's `test_the_writer_is_where_the_writes_are` gains `link_kept` among its verbs and
  asserts `os.link` among the writes it holds, as it does for `rename` and `remove_queued`, and `replay_offenders()` keeps
  finding any write of the replay outside the writer (`copy_or_link()` is a closure of `do_reverb_backup()`, and
  `same_file()` a module function it names). As `copy()` does: `record(rel, True)`, `flush_if_needed()`,
  `_folders_for_copy(source, rel)`, here when the window settles the compare: nothing between the compare's queueing and its
  settling changes the folders above `rel` (no move, delete or verification runs while a compare is open), so they stand as
  `copy_path()` made them, and a record or flush that fails raises JobFailure, as in `copy()`. Then a fresh copy name,
  `partial_copy_path()` of `rel`'s path (8222), taken again while one is there as `cp_af_copy_path()` does;
  `os.link(kept_path(kept_rel), temp, follow_symlinks=False)`, as `link_or_copy()` (13553) makes its links, not through
  `link_or_copy()`, which raises outside `NO_HARD_LINK_ERRNOS` and copies within them; the size books told (below);
  `pending.append(PendingCopy(None, source, temp, path))`, a link already made. True. Any OSError of the link or of the look
  after it (`NO_HARD_LINK_ERRNOS` and EIO among them): the copy name removed if made, False, and the caller copies; the
  record made stays, and `copy()` repeats it and finds nothing left to do (a record acts only where a forward link still
  stands). The place `rel` never holds the candidate's inode, so the placement (`os.replace`) is never a rename between two
  names of one inode, which would do nothing and leave the copy name: the tree holds each inode under one name (a hard-linked
  monitored file is copied once per name), and the name the candidate had in the tree went with its delete's rm, which every
  compare waits for (section 2).
- `finish_copies()` (8946): a pending entry whose task is None is a link already made. Its loop branches on that before it
  reads `copy.task.stderr` (8969), which a link has none of: no lines, succeeded, and it is put in place, or left with its
  row dropped where a folder above its place is no longer real, exactly as a finished copy is, and returned among the
  entries put in place (0.55.7's section 9 reads that list as what the replay applied). Its `if copied:
  manifest.copies_unsynced = True` (9026-9027) becomes: set only when it placed an entry with a task, so a link sets no
  flush. `discard_copies()` (8801) removes a link's copy name as a partial copy's, from its two callers: `stop_copies()` (a
  stop, and the replay's `finally` after a JobFailure) and `finish_copies()`'s `finally` (the entries an error left
  unplaced); that leaves the version before's file whole and its link count where it was. A cut leaves the name to the next
  start's repair (section 1, item 6).
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
- tests/test_tree_writer.py (a TreeWriter alone; the module skips unless root, so these run in the VM):
  `test_link_kept_records_its_place_and_queues_a_finished_copy`: an entry at `rel` in the tree is recorded in the version
  before first; the pending entry has no task and its copy name is a name of the version before's file; off and on two
  renames.
- tests/test_tree_writes.py: `link_kept` among the writer's verbs, holding `os.link`.
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
     place, after the copies ran (a batch taken quiet holds the delete: each move-out still held is its delete once the tree
     is quiet);
   - a move landing in the instant a batch is taken (the known limitation of that name);
   - a delete that replays behind a move, after the batch's creates: a folder that held the source of an earlier move of the
     batch, itself moved into a new folder (`mv d/g y; mkdir n; mv d n/d`: `d`'s delete replays right after `y`'s move, as
     `order_backup_entries_for_replay()` replays a delete at or above a move's source, and `n`'s create, with `d` in it,
     before both). A folder moved out of `d` beside that source is taken in time (`mv d/g y; mkdir n; mv d/s n/s`: `d/s`'s
     delete is not at or above `d/g`, so it replays first), and linked where the candidate lookup finds it (item 12: off Only
     Sync Attributes, by the key search).
3. **A delete and a create of one path in one batch** (`rm -rf d; tar xpf d.tar` at `d`'s own place, times kept): they
   collapse into the create (`change_events_to_backup_entries()`), so the batch takes nothing out of the version; each file
   is copied over its old copy, as any modify is. Unpacked at another path, it is linked where the candidate lookup finds the
   old copy (item 12).
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
   the other kind at the move's source and removes nothing (`delete_path()`). The swap shape of a move into its own old place
   (`mv site site.old; mv site.new site; mv site.old site/old`) is the same: the batch collapses it to `site` moved from
   `site.new`, then `site/old` moved from `site`, the first rename's record takes the old `site` into the version before,
   and the fallback's delete of `site` then takes nothing, so nothing of the swap is linked.
8. **A file deeper than a forward link can name** (about 800 levels on f2fs): an unfold keeps it in the version before by a
   hard link before any delete reaches it, so no delete takes it (section 5).
9. **On a mergerfs pool or a filesystem with no exchange, the copy fallbacks of a move:** a move another change of the batch
   outran, a move into its own old place, a move whose path passes the length limit. The batch records the move's source as
   the move's before the replay, so the fallback's delete takes nothing (section 2).
10. **A batch cut before its commit and finished at the next start:** its roll-forward feeds nothing and copies as today
    (section 2).
11. **A folder found ahead of its events** (docs/limitations.md "A folder found ahead of its events can reach the vault a
    version late", README line 44), in the copy the entry names once a batch was taken in between: that copy goes through
    `copy_path()`, but its batch holds no delete of the folder's old place (the folder's move came as a move, renamed in the
    vault), so it is copied whole once more; a file of it is linked only where another delete of that batch took a file of
    its bytes and metadata.
12. **What the candidate lookup does not find** (section 4). Under Only Sync Attributes, on by default
    (`DEFAULT_ONLY_SYNC_ATTRIBUTES`), the path lookup alone runs, so every file whose old path is not its new one with leading
    folders dropped is copied: an entry moved below the top of the monitored folder (`mkdir P/new; mv P/big P/new/`), an entry
    renamed in the move (`mv big new/other`), a move or rename made while reverberator was down but for an entry from the top
    kept under its name, a tree unpacked under another name or below the top, and a move out of a folder that just left the
    tree (`mv X /out/X; mv /out/X/sub sub`: `sub/f` against `X/sub/f`). Off it, the key search finds these, within its
    bound.
13. **The copy fallbacks of a move another change of the batch outran** (docs/limitations.md "A move that another change of
    the batch outran is copied"), by the code, in that entry's examples: in `mv d e; mkdir e/sub; mv x e/sub/x` the fallback's
    delete takes `x` and the fallback's copy of `e/sub` links it, but the batch's own create of `e/sub`, which replays after
    (`copy_instead_of_move()` dropped `e/sub/x` from the moves the walk skips), walks `e/sub` again and copies `x` over the
    link, so `x` is written in full once, where 0.55.6 writes it twice (taking that second walk out would be its own change);
    in `mv a/f g; mv a A; mv g h` the rename of `a` recorded `a/f` first, so the delete takes nothing and `h` is copied; in
    `mkdir x; mv old x/f; mv x y` the create of `y` copies `y/f` before `old`'s delete; in `mv D/sub t; rm -r D; mv t D` the
    rename's record of `D` took the old files, which no delete takes; in the new-file example `q`'s old place leaves only by
    the verification, after the copy. Only `mv d D; mv D/k z; rm -r D` links, off Only Sync Attributes: `z` pairs, by the key
    search, with `d/k`, which `d`'s delete took.

**[Q24]** (b) adds, on every job, what item 12 names under Only Sync Attributes, and `z` of item 13.

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
  is still in the monitored tree, and a twin of it may be linked). Task 3 puts its leave-outs at the head of the first
  `pre_record()`'s ops as `ENTRY_OP`s (the plan's Step 4): they are recorded first and reported by nothing, and a delete
  above one takes the rest, as with a move's source. Task 4's leave-outs, made in the move branch by Task 3's sequence, have
  no `pre_record()` of their own (`replay_ops()` recorded the move's source whole).
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

**The oracle, at the end of every test.** In tests/test_no_copy_move.py, `check_vault()` (tests/vault_oracle.py) over every
version, against the tree each backed up (snapshotted before each batch): each version byte for byte in full (`entry_view()`
hashes whole files), with mode, owner, mtime and extended attributes, but, under Only Sync Attributes, a file of an older
version whose inode another version reads, whose metadata it leaves out (`free_file_meta`, its sharing rule: round 19's
rule lets a synced attribute reach such a file). `assert_held_as_the_tree()` of tests/test_moves_into_new_folders.py, which
the watcher tests use, compares the version before on kind and contents only, as today. Then the sizes (the suite's
ground-truth plugin, tests/version_view_ground_truth.py, compares each change list's name with `sizes_by_newest_holder()`
after every committed batch, and checks that no older version changed); and the shape: a new helper in
tests/vault_oracle.py, `paths_sharing_an_inode(job_vault, folder_name)`, empty for every version (no two paths of one
version on one inode), with, where a link is expected, the new path in the newest version and the old path in the version
before one inode (`read_view(..., inodes)`).

**tests/test_no_copy_move.py** (new, `unit`: a module of one layer, as conftest.py's hook fails a test with two; the owner and
group cases chown, which the `unit` layer allows, and skip unless root, as tests/test_r_readers.py's `needs_root`, so they
run in the VM). Batches through `do_backup()` with raw events, as tests/crash_batches.py's `backup_events()` builds them
(`attempt_events()` where the batch does not commit, section 2), each with its oracle; "on two renames" both ways, as
section 2 says. The tests named in sections 2 to 6, grouped:
- the feed (section 2): what a file's and a folder's delete feeds, by rename, exchange, the record's walk and on two renames
  through the pre-record's report; none of the names a deleted name starts; a renamed move's source never fed; a
  fallback's delete on two renames feeding nothing; a file's delete where the version holds a folder; unchecked, dirty, link
  and folder rows not fed; a delete the length rule keeps; the verification's order and its `verified`; a roll-forward
  feeding nothing; the table holding nothing once the batch ends; a failing temp-table statement failing the attempt;
- the estimate (section 3): no charge for an unchanged move; a charge for a changed and for a chmodded file, for an attrib
  copy, and for a renamed move under Only Sync Attributes; never above what the batch writes, over the named shapes; Q25's
  four pins; a move into its own old place charged on a pool; a twin of a renamed file charged; the fill's skips; a
  roll-forward charging every copy;
- the copy step (section 4): a file and a folder linked, and below the top by the key search; the twin, the poke before, a
  write during the compare into a block compared and one not yet compared, a file replaced after the compare's open, the
  source gone; each metadata field (owner and group in the VM); two new files and one released; a moved entry paired with
  its own old copy; one try per file; many files of one key linked from the top; at most 1,000 rows a key search; a twin
  elsewhere under Only Sync Attributes; the compares in parallel, settled as they end, and ended by a JobFailure; a candidate
  under or at a forward link; a stop during the compare; a failed look; the verification and the recheck linking; a delete
  and a create of one path copied;
- the writer and the sizes (section 5): the size cases off and on two renames; a linked file let go in its batch; each
  refused errno and EIO; no flush for links alone; a stop before the placement;
- the log line (section 6);
- the fallbacks, each its own test, off and on two renames, asserting what the code gives and pinning it: `mv D x; mkdir D;
  mv x D/D` (linked off two renames, copied on them, the warning kept either way); its swap shape `mv site site.old; mv
  site.new site; mv site.old site/old` (copied: section 7, item 7); each example of docs/limitations.md "A move that another
  change of the batch outran is copied", as section 7, item 13 reads them (`mv d e; mkdir e/sub; mv x e/sub/x`: `x` written
  once, the vault holding a copy of it; `mv d D; mv D/k z; rm -r D`: `z` linked off Only Sync Attributes, copied under it;
  the other four copied); a move out of a folder that just left the tree (`mv X /out/X; mv /out/X/sub sub`, its delete and
  create as the watcher emits them for an unsettled watch: linked off Only Sync Attributes, copied under it); a move out of a
  folder beside an earlier move's source (`mv d/g y; mkdir n; mv d/s n/s`: the same) and of that folder itself (`mv d/g y;
  mkdir n; mv d n/d`: copied); a rename made while the daemon was down (a start's full comparison: linked off Only Sync
  Attributes, copied under it), and a move of a top entry into a folder made while down (linked either way); a file swapped
  with a folder (`mv a t; mv b a; mv t b`, one a folder: copied). Where a test finds an example linked or copied otherwise
  than section 10's texts say, the builder stops and reports it with the text it would need; the texts are the main
  session's.
- Only Sync Attributes on and off, each: a link, then a chmod of the new path in the next batch: on, synced onto the shared
  inode, and the version before's old path shows the new mode (round 19's section 2.4, as for a renamed file; the oracle
  allows it); off, copied, and the version before keeps the old mode.
- **[Q24]** (b): the tests that link by the key search (below the top, a renamed move, the start's rename, the move out of a
  folder that left the tree, `z`) assert a copy on every job.

tests/test_job_startup.py's `test_a_stop_saves_nothing_and_the_start_makes_one_version` asserts a copy for a rename made
while down (`moved.txt` to `moved-to.txt`, line 309): its backuper runs with Only Sync Attributes on, the default, where
the path lookup finds no old copy for a rename, so it stays as it is; the start's rename linked off it is the test above.

**tests/test_tree_writer.py** (a TreeWriter alone; the module skips unless root, so its tests run in the VM): the record's
report when the version before holds its own entry; `pre_record()`'s report of what each delete took; `link_kept()`'s record
first and its finished pending entry, off and on two renames.

**tests/test_tree_writes.py** (`unit`): `link_kept` among the writer's verbs, holding `os.link` (section 5).

**tests/test_moves_into_new_folders.py** (`inotify`, the real watcher on real inotify; TIMINGS are `apart` and `unread`, and
`at_once` has its stress test; the session's default is Only Sync Attributes on):
- `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` becomes
  `test_a_folder_moved_into_an_existing_or_a_new_folder_costs_no_copy`: for `new` and `nested` too (each a move of the top
  entry `big`, which the path lookup finds), at gaps 0 and 0.2, each moved file's inode is its old one (`after[new] ==
  inodes[old]`) and the vault grows by under 200,000 bytes (the test's own bound for a move into an existing folder: a copy
  would be 400 KB). Each batch is taken quiet (`take()` waits for the watcher's quiet signal), when every move-out still held
  is its delete in that batch, so the batch holds `big`'s delete at gap 0 too.
- New `test_what_a_move_into_a_new_folder_links`, parametrized over nine shapes of SHAPES at both timings, with the rels each
  must link (the old inode at the new place) and those it must copy: `folder`, `file`, `nested` (all linked);
  `file_renamed` (copied under Only Sync Attributes, linked off it: both settings); `changed_before` (`n/big/a` copied,
  `n/big/sub/b` linked); `changed_between` (the poke: `n/big/a` copied, the rest linked); `folder_chmod_in` (`n/big/a`
  copied for its mode, `n/big/sub/b` linked); `its_own_old_place` (all linked: `big/big/a` pairs with `big/a`);
  `a_file_made_in_the_batch` (copied: no version before holds it, so no other path of the vault shares its inode).
  **[Q24]** (b): `file_renamed` copied off Only Sync Attributes too.
- `assert_held_as_the_tree()` gains `paths_sharing_an_inode()` empty for the newest version and the version before, so its
  13 callers check the shape too, the MATRIX test of the 32 shapes of SHAPES at their timings among them. The `at_once`
  stress test (`test_moves_into_new_folders_as_fast_as_they_go_end_as_the_tree`), which compares `version_view()` with
  `live_view()` alone, gains the same check after each of its two batches.
- The found-folder tests, whose names say the move is copied
  (`test_a_move_in_that_the_walk_saw_and_whose_event_comes_is_a_copy`,
  `test_a_folder_moved_into_a_folder_from_outside_while_it_is_walked_is_copied`,
  `test_a_folder_moved_into_a_new_folder_made_after_its_parents_walk_listed_it_is_copied`,
  `test_a_folder_moved_into_a_folder_from_outside_before_its_subfolder_is_listed_is_copied`, and
  `test_a_folder_the_walk_found_moved_in_and_moved_on_in_a_later_read_ends_as_the_tree`), assert the version equals the tree
  and nothing of how. Under this route each batch, taken quiet, holds `big`'s delete (a move into a new folder keeps its
  source to expire into its delete, as `watchFolder()` says where it discards a new folder's events), so the moved files are
  linked (all from the top: the path lookup), the file written in place with its mtime set back in the second one copied.
  Each gains that assert, inode by inode, and the four `..._is_copied`/`..._is_a_copy` names say linked; a test that shows
  otherwise is a finding the builder reports. Section 7, item 11's copy, made after a batch taken in between, is not theirs.
- `test_on_a_filesystem_with_no_exchange` gains: `big`'s files are linked (one inode across the two versions), the reach on
  two renames on the real watcher.
- `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` gains: the new file's inode is not the old one.
- The two estimate tests change as section 3 says.

**tests/test_watcher_fuzz.py** (`inotify`): the random steps already move folders and files into new folders (`mvd_new`,
`mvf_new`); a new step `twin` copies a file with `cp -p` semantics (`shutil.copy2`) to a new name, and one time in two pokes
one of the two (same size and mtime, other bytes). Its oracle stays the file's own, the newest version equal to the tree by
whole-file hashes, and the plugin's, no older version changed and each change list's sizes; `paths_sharing_an_inode()` joins
it for every version after each round. The suite's sample as now; a longer run is the main session's gate call.

**Crash** (**main session: VM gate**; builders write these to skip outside the VM). tests/crash_batches.py's batch 3 gains a
released file and a released folder, past f2fs's inline size (`past_inline()`), and their creates in a new folder, so the
batch links both; every kill point of tests/test_crash_harness.py's sweep then cuts through `link_kept()`, the placement and
the commit, and tests/test_crash_power_loss.py's power cuts through the same. After each, both run `check_vault()` and
`view_truth.wrong_lists()`, as today, and gain `paths_sharing_an_inode()` empty for every version and
`measure_previous(version before, newest)` equal to `sizes_by_newest_holder()`'s count of the version before (today only
`test_roll_forward_sizes_equal_a_clean_batch` checks those two). `test_the_kill_points_cover_every_kind_of_call` gains `link`
among the kinds it asserts (crash_child.py counts `os.link` as `link`), so the sweep is shown to cut through a link. On a
scratch mergerfs pool in the VM (tests/test_pool_cut.py's way), the same batch with each disk put back at its own point,
over a standing manifest and over a lost one (section 1, item 6: a placed link copied again, an unplaced copy name removed
by the comparison).

**The pool** (**VM gate**, `needs_mergerfs`): a link into a new folder whose released file is on one branch and whose new
folder was made on another, run twice, once with the pool's policies set so mergerfs makes the link and once so it answers
EXDEV (the builder takes the settings from mergerfs's documentation and names them in the test); each run asserts which
happened (one inode across the two versions, or a copy after an EXDEV), never "linked or copied"; the oracle and the sizes
either way; the folders mergerfs makes for the link read with their times as the batch gave them.

**The real daemon** (**main session**, as round 21 measured the limitation: the daemon itself, a scratch job, in the test
container as uid 65534 or in the VM). `mkdir new; mv big new/` for a folder of 100 MB and for a file of 100 MB, `big` at the
top of the monitored folder and, with Only Sync Attributes off, below it, at gaps of 0, 1 ms and 1 s between the two, with
`mkdir` and `rename` as two system calls of one program and as a shell's two commands; each again with a poke of one file of
the folder before the move, between the two, and after it. **The number it should show:** vault growth of the order of a
move into an existing folder, for the folder and for the file: 0.04 MB in round 21's measurement of that move, its folders'
blocks and the change lists, which this move makes too with one folder more, so under 0.1 MB, where today it is 102.44 MB
for the folder and 100.11 MB for the file, at every gap; a poked file adds its own size; the entry's size-limit run (five
small versions, then the move, under a limit that holds them; today it left only the newest) keeps all five; one line a
batch; the time spent in the replay, against today's copy of the same. These figures are what 10.1's text is written with;
one off them is a finding.

**Measurements in the build** (the builder's, in the container; the cold-cache ones in the VM, where the page cache may be
dropped): the compare against today's copy for one 1 GiB file, for a folder of 10,000 files of 4 KiB, and for a mixed folder
(one 1 GiB file early in its walk and 10,000 of 4 KiB), warm and cold, on the compare pool as built; the lookups of a folder of
2,500 empty files of one key and name, from the top and below it; the estimate's fill and lookups and the replay's feed on a
delete of 1,000,000 rows, beside `manifest.remove_tree()` of the same rows. The figures go in the handback; what they decide
is in the Calls to confirm.

**Gates:** the whole suite in the container and in the VM, the mergerfs and power-loss tests, as the release gate has them.

## 10. Docs

The release is called 0.55.8 below (the round after 0.55.7; the number is the main session's). Each text replaces the one
named, in the commit of the code it describes (section 11). The build starts after Q24's and Q25's answers, so each narrowed
or widened entry's "Approved" is written with its answer (the user's words or pick and the date, or "chief's decision" and
its date), where `<Q24's answer>` or `<Q25's answer>` stands below. Under Q24 (b), 10.1 and 10.4 and README lines 15, 19, 22
and 45 take the (b) wording each gives; 10.3 and README lines 42 and 43 stay as they are, and 10.5 loses only its "Revisit
when" clause. Under Q25 (b), 10.2's estimate sentence and line 31's estimate clause are not written (their links sentence
is). Under Q24 (c) nothing is written.

The texts speak of two settings because the copy's lookup does (section 4): with Only Sync Attributes on, the default, a
file is linked only from the moved entry's own old copy at its new path with the leading folders dropped, which reaches an
entry moved from the top of the monitored folder; with it off, from any file the batch's deletes took with its bytes and
metadata.

**No lessons entry is required:** no API, stored format or command changes shape (the change list, the manifest and the
commands are as they were; the log line is new and additive). The main session may add one line to docs/lessons.md:
"prove a moved object where it lands, by its bytes, not by the events that say it moved".

### 10.1 docs/limitations.md: "A folder or file moved into a new folder is copied whole" (narrowed)

```
### A folder or file moved into a new folder is copied where it cannot be linked

- **Kind:** known limitation.
- **What the operator sees:** `mkdir new; mv big new/` inside one quiet time reaches the backup as a delete of `big` and a
  copy of `new`, as nothing watched `new` when `big` arrived. From 0.55.8 a file of that copy is hard-linked from the version
  before in place of a copy, after a read of both, when it holds, byte for byte, the contents of a file the batch's delete
  took there, with its mode, owner, group, mtime and extended attributes: with Only Sync Attributes off, from any such file;
  with it on, the default, only from the moved entry's own old copy, which it finds for an entry moved from the top of the
  monitored folder (`mkdir new; mv big new/`, `mkdir -p a/b; mv big a/b/`), so that a later attribute change of the new file
  reaches no other file's place in the older version. One line a batch says so in the log (`Linked <n> files, <size>, from
  <version> in place of copies: ...`). An unchanged move linked so costs about what a move into an existing folder costs
  (0.04 MB for a 100 MB folder on the real daemon), and with a size limit it prunes nothing. Still copied, with no line: with
  Only Sync Attributes on, an entry moved from below the top of the monitored folder or renamed in the move; a file changed
  in the move's batch (its contents, mode, owner, group, mtime or an extended attribute); every file of the move when its
  old place leaves the version after the copy (a batch the maximum delay takes while the move-out still waits for its pair,
  a move landing in the instant a batch is taken, or a folder moved into a new folder after a move out of it of the same
  batch, `mv d/g y; mkdir n; mv d n/d`), or in a batch cut before its commit and finished at the next start; the second of
  two new files that match one removed file; and, on a vault that refuses hard links or whose filesystem keeps other
  metadata than the monitored file has (an extended attribute it refuses or sets itself), every such file. Such a copy costs
  its size (a 100 MB file 100.11 MB), and with a size limit it can prune older versions to make room, as on 0.55.7, where
  every such move is copied.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, and a program's `mkdir` and `rename`, one right after the other, leave no moment in which the
  new folder has a watch. 0.55.1 was built to keep the arrival as a move; four reviews and the fix passes after them each
  found an order of events where the version then kept a file's old bytes for good, so 0.55.1 copied, as 0.55 does. From
  0.55.8 the copy proves each file's bytes and metadata by reading them and links only what it proved; what it cannot prove,
  or what changed, it copies. A copy costs space and time; a wrong version loses a backup.
- **Revisit when:** a size-limited job's prunes follow such copies often.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as on
  0.55, and the no-copy move gets its own design later. Narrowed to what the link cannot cover: <Q24's answer>.
```

The figure in parentheses is the one section 9's real-daemon run measures, written in with the text; 0.04 MB is what that
run is expected to show (round 21's measurement of a move into an existing folder), and a figure off it is a finding.

**[Q24]** (b): the second sentence of "What the operator sees" reads "From 0.55.8 a file of that copy is hard-linked from
the version before in place of a copy, after a read of both, when it is the moved entry's own old copy, byte for byte, with
its mode, owner, group, mtime and extended attributes, which it finds for an entry moved from the top of the monitored folder
(`mkdir new; mv big new/`, `mkdir -p a/b; mv big a/b/`)."; and the "Still copied" list starts with "an entry moved from
below the top of the monitored folder or renamed in the move;".

### 10.2 docs/limitations.md: "Size estimates leave out a version's own small blocks" (widened, on Q25's answer)

In "What the operator sees", after "... and a move that falls back to a copy, so a vault can pass its size and inode limits
by those copies until the next prune.", insert:

```
  From 0.55.8 it also leaves out a file it expects the no-copy move to link: one with the size, mtime, mode, owner and
  group of a file one of the batch's deletes takes from the version (off a pool, also a move into its own old place; with
  Only Sync Attributes on, only the moved entry's own old copy). The replay copies such a file after all when its contents
  or extended attributes differ (a same-size rewrite with its mtime set back), when its twin was moved away before that
  delete (`cp -p d/a b; mv d/a c; rm -r d` copies b), when that delete replays after its copy, when it is the second match
  of one removed file, or when a look, a compare or a link of it fails; on a vault that refuses hard links (or a pool that
  answers EXDEV between its disks) or that keeps other metadata, every such file; and on a filesystem with no exchange,
  every file of a move into its own old place.
```

And "The links a batch makes are in no size record:" becomes "The forward links (symlinks) a batch makes are in no size
record:", with, after that sentence, "A hard link of the no-copy move adds a name, no inode and no block of its own." In
"Why", append: "Charging a file the no-copy move links would prune versions for good for every move the replay links instead
of copying, the harm the no-copy move removes; an estimate too low only passes the limit until the next prune." In
"Approved", append: "Widened to a file the estimate expects the no-copy move to link: <Q25's answer>." **[Q25]** (b): only
the links sentences, and "Approved" is as it was.

### 10.3 docs/limitations.md: "A move that another change of the batch outran is copied" (narrowed)

In "What the operator sees", the sentence "..., and the entry is copied once more: its files are written to the vault again
in full, a copy instead of a rename." becomes:

```
  ..., and the entry is copied once more instead of renamed: its files are written to the vault again in full, but, from
  0.55.8 and with Only Sync Attributes off, a file with the bytes and metadata of a file a delete of the same batch took out
  of the version, which is hard-linked from there instead.
```

and the example "`mv d D; mv D/k z; rm -r D` (z copied)" becomes "`mv d D; mv D/k z; rm -r D` (z copied; from 0.55.8,
with Only Sync Attributes off, linked from d/k, which the delete of d took)". The other examples stay: each is copied as
written (section 7, item 13). "Approved" appends: "Narrowed to the files the copy links: <Q24's answer>." **[Q24]** (b): the
entry stays as it is.

### 10.4 docs/limitations.md: "A move into its own old place is copied whole" (narrowed)

```
### A move into its own old place is copied

- **What the operator sees:** an entry moved into a new folder made at its own old place in one batch (`mv D x; mkdir D;
  mv x D/D`, or `mv site site.old; mv site.new site; mv site.old site/old`) logs one warning, `Not renaming … to …: its new
  place is inside its old one in the version; copying it instead`, and is copied. From 0.55.8 the copy's delete of the old
  place takes the entry's files into the version before first, so in `mv D x; mkdir D; mv x D/D` each unchanged file is
  hard-linked from there instead of written (with Only Sync Attributes on, the default, for an entry at the top of the
  monitored folder), and the move costs what changed in it. In the swap shape nothing is linked: the replay's first rename
  takes the old site into the version before, so the copy's delete takes nothing, and the folder that took its old place
  (site.new) is copied whole too, as the copy replaces all of the version's site: both folders cost their size once, unless
  the replacing one was made in that batch (then it is copied anyway). On a pool or a filesystem with no exchange the batch
  records the old place as the move's before it replays, so the delete takes nothing and all of it costs its size once, as
  before 0.55.8. The result is right.
- **Why:** the version can never rename an entry into itself, so the move is replayed as a delete of its old place and a
  copy, which links what that delete took. Keeping every file of it, in the swap shape and on a pool too, needs a replay
  that parks the entry under a temporary name and places it after the entries that make its new folder, a larger change
  for a shape never seen in the live logs.
```

"Kind" and "Revisit when" stay; "Approved" appends: "Narrowed to the files the copy links: <Q24's answer>." **[Q24]** (b):
"(with Only Sync Attributes on, the default, for an entry at the top of the monitored folder)" reads "(for an entry at the
top of the monitored folder)".

### 10.5 docs/limitations.md: "A move out of a folder that just left the tree is copied" (narrowed)

In "What the operator sees", "is copied whole instead of renamed in the vault" becomes "is copied instead of renamed in the
vault", "is copied whole once, with the same line" becomes "is copied once, with the same line", and the last sentence, "The
version is right; the copy costs the moved entry's size once, and with a size limit it can prune older versions, as the copy
of a move into a new folder can.", becomes:

```
  The version is right. From 0.55.8, with Only Sync Attributes off, a file of these copies with the bytes and metadata of a
  file a delete of the same batch took out of the version is hard-linked from there instead of written (in `mv X /out/X;
  mv /out/X/sub sub`, X's delete takes every file of sub); the rest costs its size once, and with a size limit it can prune
  older versions.
```

"Revisit when" drops "Also when the no-copy move into a new folder gets its own design." (this round is that design).
"Approved" appends: "Narrowed to the files the copy links: <Q24's answer>." **[Q24]** (b): only the "Revisit when" clause
goes.

### 10.6 README

- **Line 15**, its last clause "and moves made since the last backup before a stop are copied once instead of renamed."
  becomes "and a move made since the last backup before a stop is a delete and a copy: a file of the copy with the bytes and
  metadata of a file the delete took is hard-linked from the version before in place of a copy (read twice, written never),
  with Only Sync Attributes on only for an entry moved from the top of the monitored folder under its own name, and the rest
  is copied once." **[Q24]** (b): "... in place of a copy (read twice, written never) for an entry moved from the top of the
  monitored folder under its own name, and the rest is copied once."
- **Line 19**, after "... and is copied the same way.", insert: "From 0.55.8 that copy takes the entry out of the version
  first, and each unchanged file is hard-linked from the version before instead of written (with Only Sync Attributes on,
  for an entry at the top of the monitored folder); on a pool or a filesystem with no exchange it is all written."
  **[Q24]** (b): "(for an entry at the top of the monitored folder)".
- **Line 22**, its last sentence becomes: "A folder or file moved into a folder made in the same batch reaches the backup as
  a delete of its old place and a copy of the new folder, as nothing watched the folder when it arrived: each file of that
  copy that has, byte for byte, the contents of a file the delete took into the version before, with its mode, owner,
  group, mtime and extended attributes, is hard-linked from there in place of a copy, after a read of both (one line a
  batch: Linked <n> files, <size>, from <version> in place of copies); with Only Sync Attributes on, the default, only from
  the moved entry's own old copy, which is found for an entry moved from the top of the monitored folder. An unchanged move
  linked so writes no copy and prunes nothing under a size limit; the rest is copied whole: a file changed in the move's
  batch, and the moves and orders the known limits below name." **[Q24]** (b): "... is hard-linked from the version before
  in place of a copy, after a read of both, when it is the moved entry's own old copy, which is found for an entry moved from
  the top of the monitored folder (one line a batch: ...)".
- **Line 31.** "The links a backup makes are in no size record:" becomes "The forward links (symlinks) a backup makes are in
  no size record:", and after that sentence comes "A hard link of the no-copy move adds a name, no inode and no block of its
  own." On Q25's (a), "and of moves that fall back to a copy, which the estimate leaves out." becomes "and of moves that fall
  back to a copy, which the estimate leaves out; from 0.55.8 it also leaves out a file it expects the no-copy move to link,
  so a backup passes the limit by such a file when the replay copies it after all (its contents differ under the same size,
  mtime, mode, owner and group, say; on a vault that refuses hard links, every such file; on a filesystem with no exchange,
  every file of a move into its own old place)."
- **Line 42**, "is copied once more with one warning, and its files are written to the vault again in full." becomes "is
  copied once more with one warning, and its files are written to the vault again in full, but, from 0.55.8 and with Only
  Sync Attributes off, a file with the bytes and metadata of a file a delete of the same batch took out of the version, which
  is hard-linked from there (mv d D; mv D/k z; rm -r D links z)." **[Q24]** (b): unchanged.
- **Line 43**, "is copied whole instead of renamed" becomes "is copied instead of renamed", and after "The result is right."
  comes: "From 0.55.8, with Only Sync Attributes off, a file of these copies with the bytes and metadata of a file a delete of
  the same batch took out of the version is hard-linked from there instead of written (in mv X /out/X; mv /out/X/sub sub,
  each unchanged file of sub)." **[Q24]** (b): unchanged.
- **Line 45** becomes: "A folder moved into a new folder made at its own old place in one batch (mv D x; mkdir D; mv x D/D)
  is copied once, with one warning, its unchanged files hard-linked from the version before (with Only Sync Attributes on,
  for a folder at the top of the monitored folder; all written on a pool or a filesystem with no exchange); in the swap shape
  (mv site site.old; mv site.new site; mv site.old site/old) nothing is linked, and the replacing folder is copied whole too."
  **[Q24]** (b): "(for a folder at the top of the monitored folder; ...)".

The README's other lines about moves stay, and so do the entries they summarize: 17 (a file made in the batch and moved,
copied once: its row is the batch's own), 39 (swaps: the verification's modifies take nothing out, and a file swapped with a
folder has no delete that removes anything, section 7 item 7), 44 (a folder found ahead of its events, copied whole once
more: the batch of that copy holds no delete of the folder's old place, as its move came as a move, so a file of it is linked
only where another delete of that batch took a file of its bytes and metadata, section 7 item 11). Line 115 stays: it says a
file restored under Only Sync Attributes carries the newest metadata its shared copy has, which covers a linked file's too.

## 11. Order of the build

The build starts once Q24 and Q25 are answered, on Q24's (a) or (b); under Q24's (c) nothing below is built. Each step is
one commit whose tests pass, with the docs of the code it adds.
1. Section 2: the table (with the temp database's pragma), the record's report, `replay_ops()`'s op kind, `pre_record()`'s
   report, `verify()`'s order, `feed_released`, and the feed, with their tests (nothing links yet; the feed is read by
   nothing).
2. Section 5's `BatchSizes` change and `link_kept()`, and `finish_copies()`'s link entry, with their unit tests.
3. On Q25's (a), sections 3, 4 and 6 together: `same_file()`, the compare pool and `copy_or_link()` (from here files link),
   the estimate's fill and `leaving`, and the log line. Either half alone breaks tests/test_moves_into_new_folders.py's two
   estimate tests (the copy step alone makes the vault grow less than the estimate, which then passes `grew`; the estimate
   alone charges fewer inodes than the names the replay copies). On Q25's (b), sections 4 and 6, with section 3's [Q25] (b)
   change of those two tests (`written <= grew <= est_size`, the inodes as today) and its pin; section 3's code is not
   built. With them: their tests, the fallback pins, tests/test_moves_into_new_folders.py's other changes, and the texts of
   section 10 as Q24's and Q25's answers give them.
4. The measurements, the fuzz step, then the main session's VM gates (owner and group, crash and power loss, the pool) and
   the real daemon's measurement, which gives 10.1 its figure.

## Questions for the user

**Q24. Whether to build the no-copy move now, and which files it may link** (docs/progress.md, as asked there). The route
links a file from the version before, in place of a copy, only when it is a file the batch's own delete took there, compares
equal in full, and has the same mode, owner, group, mtime and extended attributes; open are which files are looked at, and
whether to build it yet. Both build options first look for the moved entry's own old copy at the new path with its leading
folders dropped (the path lookup): it finds the old copy of an entry moved from the top of the monitored folder (`mkdir new;
mv big new/`), and not of one moved from below the top (`mkdir P/new; mv P/big P/new/`) or renamed in the move.
- (a) Build it with the path lookup and, with Only Sync Attributes off, a key search after it (Recommended, what this spec
  builds): where the path lookup finds nothing, the released file of the same size, mtime, mode, owner and group whose path
  is likest the new one, among at most 1,000 of that key. With Only Sync Attributes on, which is the default, the key search
  does not run, so there (a) links what (b) links: a link from a twin elsewhere would let a later attribute change of the
  new file show at the twin's place in the older version. Off it, besides what (b) reaches, (a) links on every vault a move
  from below the top of the monitored folder, a move that also renames (`mv big new/other`), a move or rename made while
  reverberator was down (copied once today), a tree deleted and unpacked again at another path or name with its times kept,
  a move out of a folder that just left the tree (`mv X /out/X; mv /out/X/sub sub`), and `z` of the outran move `mv d D; mv
  D/k z; rm -r D`. What (a) adds to (b)'s code: the key search, its index, its bound and its probe (`may_release()`).
  Beyond (b)'s texts it narrows "A move that another change of the batch outran is copied" (`z`) and "A move out of a folder
  that just left the tree is copied", and README lines 42 and 43, each for Only Sync Attributes off.
- (b) Build it with the path lookup alone, on every job: a file is linked only from the moved entry's own old copy. Besides
  `mkdir new; mv big new/` and `mkdir -p a/b; mv big a/b/` of an entry at the top of the monitored folder, it links, for such
  an entry, a move made while down into a folder under its own name, a tree unpacked under its own name into new folders,
  and, off a mergerfs pool on a filesystem with exchange, a move into its own old place (`mv D x; mkdir D; mv x D/D`). It is
  less code than (a): no key index, no probe, no key search and no bound. It narrows the main entry ("A folder or file moved
  into a new folder is copied whole") and "A move into its own old place is copied whole", and README lines 15, 19, 22 and
  45; "A move out of a folder that just left the tree is copied" loses only its "Revisit when" clause.
- Under (a) and (b) alike: a batch cut before its commit and finished at the next start links nothing (its roll-forward
  copies as today); nothing of a swap is linked, the swap shape of a move into its own old place among them; on a pool or a
  filesystem with no exchange, no copy fallback links. Both leave "Swaps in one batch are repaired by copies" (README line
  39) and "A folder found ahead of its events can reach the vault a version late" (README line 44) as they are: a swap's
  copies are the verification's modifies, which take nothing out, and a file swapped with a folder has no delete that removes
  anything; the batch of the found-ahead copy holds no delete of the folder's old place (its move came as a move), so a file
  of it is linked only where another delete of that batch took a file of its bytes and metadata.
- (c) Not now: keep the entry "A folder or file moved into a new folder is copied whole" and this design on file, and build
  it when a size-limited job prunes for such a move, or a job over a tree of user files is added. What building costs:
  `TreeWriter.record()` and `pre_record()` reporting what each delete took, `replay_ops()`'s delete op, `verify()`'s order,
  `delete_path()`'s feed, a temp table and five manifest methods, the estimate's fill and its walks' charge (Q25),
  `same_file()` with its compare pool and window, `copy_or_link()`, the writer verb `link_kept()`, `BatchSizes` by rel,
  `finish_copies()`'s link entry, the log line, their tests, five limitations texts and seven README lines. The study's look
  at how often such a move happens is in its report, which the main session gives with this question.
- What waits on it: the whole build (section 11), the candidate rule (sections 3 and 4), the tests marked [Q24], and the
  docs of section 10. The user's words: "Drop the feature (Recommended)" (2026-11-07), with "the no-copy move gets its own
  design later", and the pick of 2026-11-12 that gave it "its own design round after". (a) and (b) go beyond the move they
  named where they reach other shapes; their pick gave the move a design round, this spec, and (c) keeps it at that, with
  no build yet; nothing they said is dropped.

**Q25. The size estimate and a file it expects the no-copy move to link** (asked with Q24; moot under its option (c)). With
a size limit, the estimate made before each backup decides how many old versions to prune for room. From this round it
charges nothing for a file the batch may link (one with the size, mtime, mode, owner and group of a file the batch's deletes
take, or, off a pool, of a move into its own old place; with Only Sync Attributes on, only the moved entry's own old copy),
so a move into a new folder no longer prunes older versions for a copy that is never made. Where such a file is copied after
all, the vault passes its limit by that copy until the next backup prunes. Exactly, by kind of vault:
- on every vault: its contents or extended attributes differ (a same-size rewrite with its mtime set back); its twin was
  moved away before the delete (`cp -p d/a b; mv d/a c; rm -r d`); its delete replays after its copy (`mv d/g y; mkdir n;
  mv d n/d`); it is the second match of one removed file, or its match was spent by a link that failed; a look, the compare
  or the link fails with an error (EIO, say);
- on a vault whose filesystem keeps other metadata (an extended attribute it refuses or sets itself, an owner it cannot
  keep): every such file;
- on a vault that refuses hard links, or a mergerfs pool that answers EXDEV between its disks: every predicted file, every
  time;
- on a filesystem with no exchange: every file of a move into its own old place.
This widens the approved known limitation "Size estimates leave out a version's own small blocks", which already leaves out
copies of moved files and of moves that fall back.
- (a) Widen the entry (Recommended): the estimate stays at or below what the batch writes, as it is built to (a prune made for
  a copy never made removes a version for good, an overshoot lasts until the next prune). On a vault that links, the cases
  are rare orders, a same size, mtime, mode, owner and group to the nanosecond over other bytes, an error, or a move into its
  own old place on a filesystem with no exchange, itself a rare shape. On a vault that refuses hard links, or a pool that
  answers EXDEV, every move into a new folder passes the limit by its size until the next prune: no vault has shown a refused
  hard link yet (docs/limitations.md "A copy made where the vault refused a hard link"), and the pool test (section 9) shows
  which way mergerfs answers under the policies it names.
- (b) Charge every copy as today: no new overshoot, but with a size limit each move into a new folder still prunes older
  versions for the full moved size although it then costs nothing: "after five small versions, one such move left only the
  newest", the harm the entry names and the reason this round exists. Built so: section 3's code is not built (no fill, no
  `leaving`); tests/test_moves_into_new_folders.py's two estimate tests bound `written <= grew <= est_size`, their inodes as
  today; section 3's tests give way to its pin `test_the_estimate_charges_every_file_the_replay_links`; 10.2's and line 31's
  estimate sentences are not written (section 11, step 3).
- (Not offered: comparing the bytes at the estimate too. It would read every moved file's two copies before the prune, and
  again at the copy.)
- What waits on it: section 3, docs 10.2 and README line 31, and the build, which starts after both answers. The user's words
  it would narrow: none; it widens an entry approved 2026-10-26 ("Known limitation (Recommended)") and widened since, last on
  2026-11-13 ("Widen the entry (Recommended)").

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
2. **The estimate** asks a prediction, the rows under the batch's deletes and, off a pool, under the sources of its moves
   into their own old places, not the replay's table (which is filled during the replay), and leaves out the deletes
   `delete_path()` would remove nothing for, by the same tests. Every file the replay links is one the estimate leaves
   uncharged, so the estimate never charges a copy that is not made; the price is the overshoot of Q25 (the
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
10. **The reach under (a)** is partial where the study says whole: of the outran moves' examples only `z` links, off Only
    Sync Attributes (section 7, item 13); a move into its own old place links only off a pool on a filesystem with exchange;
    nothing of the swap shape links; a roll-forward links nothing; and under Only Sync Attributes only the path lookup runs
    (calls 28 and 29). Section 10's texts say what holds by the code, and section 9 pins each named example; a pin that
    differs from the text comes back to the main session. Under (a) README lines 15, 19, 42, 43 and 45 change too, and Q24
    lists them.

Calls made in this spec that change what gets built:
11. The candidate (the main session's ruling): first the path lookup, the new path with its first k parts dropped, by the
    primary key with no bound; then, off Only Sync Attributes and only when that finds none, the key search, the row of the
    key sharing the most trailing path parts with the new path among at most 1,000 (section 4, with the measurement); one
    `SELECT` on a miss, the key asked first. One candidate tried per file, claimed right before its link, so a link the vault
    refuses spends it (Q25 lists the file left without one). A file whose key matches a released file of other bytes costs up
    to two reads more than today's copy (the compare stops at the first difference): bounded, and rare enough (same size,
    mtime, mode, owner and group) to be Not an issue.
12. The compare runs in parallel on a compare pool of `COMPARE_THREADS` threads, with `compare_scopes()`'s window, settling
    whichever compare ends first; it opens the monitored file once and compares its metadata and bytes through that handle;
    the link is made on the replay's thread when the window settles it, the copy queued there when it differs; the replay's
    `finally` sets the batch's `cancelled` flag, which a compare looks at between blocks, then shuts the pool down. Not `cmp
    -s` on the copy executor: it follows a link and blocks on a FIFO at the monitored path. If a link is slower in wall time
    than the copy it replaces on some shape, that is a finding for the main session (the light way against the fast way),
    not something the builder tunes.
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
    by its old heading). 10.1 states the cost of an unchanged move with the figure the real daemon's run measures (expected
    about 0.04 MB, what a move into an existing folder costs); it holds no placeholder.
20. The release is called 0.55.8 in the docs texts; the number is the main session's.
21. On two renames the feed comes from `pre_record()`'s report for delete entries only, so there the copy fallbacks' deletes
    of a move's source feed nothing and those files are copied as today (section 7, item 9). Reporting every move's source
    would feed inodes a successful rename keeps in the tree at its target. A move into its own old place never renames, so
    its source alone could be reported as a delete; that is left out, as the create of its new folder, when it replays
    first, records the old folder whole before it (read in the code, not run), and it would be a rule for one rare shape.
22. `verify()` now gives `replay_ops()` and `replay()` one prepared dict of its fixes, so a pre-record and the replay agree on
    which of two records at one path takes the old entry; `applied_fixes()` keeps reading the unprepared fixes for `verified`.
23. A roll-forward feeds nothing (`feed_released`, the main session's ruling): it copies as today, and its estimate, which
    fills nothing, is exact; one condition in place of a replay that linked a file whose delete the cut attempt had not
    recorded, which the estimate charged.
24. The estimate feeds the source of a move into its own old place only off a pool (`on_pool`, known before the estimate; the
    main session's ruling), so a pool charges and copies that shape as today; a filesystem with no exchange, which only the
    hand-over finds out, is Q25's overshoot.
25. Under Only Sync Attributes the copy links by the path lookup alone (the main session's call, in place of accepting a
    twin's reach under README line 115): an older version's file shares an inode only with the file at its own place below a
    moved or unpacked folder, and a twin elsewhere is copied, as today. A later attribute change synced onto a linked file
    then shows at that file's own old path in the version before, as for a renamed file. No new question.
26. Access times are not compared: `entry_metadata()` leaves them out, and a renamed move keeps the old inode's atime too.
27. The table is emptied by its two fillers, the estimate right after its numbers (outside the transaction) and the replay at
    the end of its `try` (inside it, so the commit commits it empty); any other end of the batch has the job's loop close the
    manifest, which drops it. Nothing empties it in `do_backup()`'s `finally`, which runs after its `except` has closed a
    manifest it opened. `PRAGMA temp.auto_vacuum = FULL` gives the temp file's pages back at each commit that frees them
    (section 2's probe: 85.6 MB to 20 KB after 400,000 rows, for about 1 µs more a claim).
28. Only Sync Attributes is on by default (`DEFAULT_ONLY_SYNC_ATTRIBUTES`), so on a job with the default the key search never
    runs, and (a) links what (b) links; Q24 says so.
29. The path lookup drops leading folders only, as the main session's ruling gives it, so it finds the own old copy of an
    entry moved from the top of the monitored folder and not of one moved below it (`mkdir P/new; mv P/big P/new/`): under
    Only Sync Attributes and under (b), such a move is copied, as today. A lookup that found the own old copy wherever the
    entry kept its name would need the place of the entry each delete took kept per row (each row's path from that entry's
    name down, and its index), which this spec does not add.
30. A candidate a compare in flight holds is passed over by both lookups, not only by the key search, so a claim always finds
    its row: `claim_released()` answers nothing, and the "claimed by an earlier file of the window" case is gone under both
    options.
31. A compare takes no `BACKUP_SEMAPHORE` permit: its pool bounds it, as `record_dirty_entries()`'s and `compare_scopes()`'s
    bound theirs, so no wait between compares and copies exists; with `--threads 1` a batch may read with up to
    `COMPARE_THREADS` compares beside its one copy, as a comparison does today.
32. The found-folder tests of tests/test_moves_into_new_folders.py whose names say copied assert the link the code gives
    (their batches are taken quiet and hold the move-out's delete), and their names say linked.
33. A temp folder too full for the table's file fails the attempt, as one too full for `temp.seen` fails a comparison today;
    the job's next attempt goes on once there is room.
34. `entry_metadata()` takes an open fd as well as a path, so the compare reads metadata and bytes through one handle.
35. In `mv d e; mkdir e/sub; mv x e/sub/x` the batch's create of `e/sub` walks it again after the fallback's copy and copies
    `x` over its link, so `x` is written once (0.55.6 writes it twice): taking that second walk out is its own change, not
    this round's.
36. tests/test_job_startup.py's `test_a_stop_saves_nothing_and_the_start_makes_one_version` keeps its assert of a copy (line
    309): it runs with Only Sync Attributes on, where a rename made while down is copied.
37. `temp.seen` keeps the last comparison's rows between comparisons, as today; with the pragma its file shrinks at the next
    `clear_seen()`. Clearing it at a comparison's end too is not this round's.
