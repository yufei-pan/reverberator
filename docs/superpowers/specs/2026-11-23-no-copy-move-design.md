# The no-copy move into a new folder (P3)

A move into a folder made in the same batch (`mkdir new; mv big new/`) is copied whole today, though the vault already holds
every byte of it. This round makes that copy hard-link each file whose old copy the batch's own delete put into the version
before: the file at the same place below the deleted entry of the same name, when the version before alone holds it and it is
the monitored file byte for byte and in its metadata. Everything else is copied as today. The result on disk is the state a
move leaves (one inode, named at the old path in the version before and at the new path in the new one); it trusts no event
and no watch, and its worst case is the copy made today.

Built as its own round after round 0.55.7, on a branch of its own from the merged 0.55.7, as that round rewrites the replay's
looks (its section 7), the change list (section 9) and the length rule (section 1) around the same code. The build starts only
once Q24 and Q25 are answered (Q25 is asked with Q24), so no text is written with a placeholder. "Today" below means 0.55.6,
branch `r0556`. Functions are named first; line numbers are of reverberator.py at e166baa (18,251 lines), the file 0.55.7
builds on, and 0.55.7 moves them.

Why now and why this way: the user gave this move its own design when 0.55.1 dropped it (2026-11-07), and a design study
(2026-11-23, read-only, `.superpowers/p3/study-report.md`) weighed four families of route. A route in the watcher cannot reach
the case: a program's `mkdir` and `rename`, one right after the other, leave no moment in which the new folder has a watch (a
probe saw the move arrive as an event in 2 of 300 runs), and every fix of 0.55.1 that filled that gap from a walk's view kept
wrong bytes in some order of events. Acting at the copy needs no event at all: it reads the bytes, which is the only proof the
manifest can be shown (it holds a file's size, mtime and last 64 KiB, and a same-size rewrite with its mtime set back keeps all
three). It is not urgent: the study's look at how often such a move happens is in its report, kept out of this public file, and
Q24 offers not building it yet. Its harm when it comes is the whole moved size and, under a size limit, older versions pruned
for a copy of what the vault holds.

Why this design: an earlier draft of this spec copied the rows of the files the batch's deletes released into a temporary
table, fed at each applied delete, and searched it by key and by path. Its two check and fix rounds kept finding problems in
that table and in the estimate's prediction of it, and it grew with each, so a fresh agent stepped back on the design. The step
back found the table unneeded: the batch's delete entries name what left, the version before holds it on disk where its delete
put it, and the size books already know whether the tree let it go. This spec is written on that design. From the draft it
keeps the rule, the compare, the link, the writer's verb, the size books' change and the log line.

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

The main session's call this spec builds on (not the user's words): the proof is the full compare alone, with no inode column
in the manifest (no format change, and an inode cannot show a write through a mapped page that a compare sees). Whether to build
it now is Q24 (below, and in docs/progress.md): this spec is written on its option (a); its option (b) builds nothing yet, and
the places that say so are marked **[Q24]**. The estimate is Q25: written on its option (a), each place its option (b) changes
marked **[Q25]**.

Standing decisions that bind the build (docs/progress.md): a worktree, never the live checkout; the suite in parallel; no
pytest as root on the host; root, loop, mount, mergerfs and power-loss tests in reverberator's own test VM; the headroom rule;
the mergerfs and power-loss tests in the release gate; the scrub before every push.

## Summary

| § | Part | Code it touches | Adds | Removes |
|---|---|---|---|---|
| 2 | Which old copy is looked at | new `released_names()` and `old_copy()`, module functions; `do_backup()` builds the names | a dict of names per batch, one lookup on disk per file copied | nothing |
| 3 | The estimate | `do_backup()` (its call of `get_backup_size_inode()`), `get_backup_size_inode()`, `get_unskipped_size_inodes()` | a file the copy step will find is charged nothing | nothing |
| 4 | The copy step | `do_reverb_backup()`'s `copy_path()` (its two `writer.copy()` calls), `wait_for_async_commands()` and the replay's `finally`; a new `same_file()` beside `hash_file()` (its opener shared); `entry_metadata()` (of an open handle too) | a check, a full compare of metadata and bytes on a compare pool, then the link or the copy | nothing |
| 5 | The writer's verb and the size books | new `TreeWriter.link_kept()`; `BatchSizes` (`shared` by rel, new `linked()` and `alone()`); `finish_copies()` (a link already made) | one verb, two methods of the books | nothing |
| 6 | The log line | end of `do_reverb_backup()` | one line per batch that placed a link | nothing |
| 10 | Docs | README lines 15, 22 and 31 (its estimate clause on Q25's answer); two docs/limitations.md entries | the narrowed main entry, the estimate entry widened (Q25) | the claim that such a move is always copied |

No change to the watcher, the manifest (no table, no statement, no stored format), the change list or any command, and none to
`TreeWriter.record()`, `pre_record()`, `replay_ops()`, `delete_path()` or `verify()`. No number is added: the compare reuses
`hash_file()`'s 1 MiB read, the compare pool's `COMPARE_THREADS` threads and `compare_scopes()`'s window of four times that.
State at rest: none, on disk or in memory. Per batch: the names (a few strings), the compares in flight and a flag that cancels
them, the links not yet placed; `BatchSizes.shared`, which exists today. One new question, Q25 (the estimate), besides Q24.

## 1. The rule that keeps a version right

> A file the replay is about to copy is linked only from its old copy: the regular file at its place below a deleted entry of
> the same name in the version before (section 2), which the version before alone holds (section 5), whose bytes compare equal
> in full to the monitored file's, and whose mode, owner, group, mtime and extended attributes are the monitored file's.
> Everything else is the copy made today.

The first half keeps the vault's shape a move's shape: one path per inode in a version. The second half makes the version's
bytes and metadata the ones a copy would have written. Access times are not compared: `entry_metadata()` leaves them out
everywhere, and a renamed move keeps the old inode's atime too, so a link leaves the atime a move leaves.

**Why no order of events can give a version worse than today's copy.** For each file the replay copies today, the version now
gets either that copy (today's code, unchanged) or a link to a file whose bytes and metadata were just compared equal to what a
copy started at that moment would have read and kept: the compare opens the monitored file once and reads its metadata
(`fstat()`, its extended attributes through the handle) and then its bytes through that one handle, as `cp` reads one file. A
change after the open is a change after the take, which the next batch backs up, as it would after a copy that read the file
then. So for every order of events and every state of the tree, the version's contents are those today's copy would produce;
the walk that decides which files are copied is today's, so nothing can be missing that today's copy holds. Which old file was
tried does not matter to the bytes: any file with the same bytes and metadata is a true stand-in, so the name that picks it may
be wrong as often as it likes and costs only a compare. No event, no watch, no inode number and no record of the monitored file
is trusted for the bytes. The guarantee is about the version the batch writes. An older version's file changes later only as
round 19's rule lets a shared inode change: under Only Sync Attributes a later attribute change of the new file, synced onto the
shared inode, shows at the old place in the version before, as after a renamed move (round 19's spec,
`specs/2026-11-04-round19-vault-r-design.md` section 2.4, lets such a change reach other versions sharing the inode, never a
second path of the same version). That is what the first half guards: a link to an inode the tree still holds would give one
version two paths on one inode, and a change synced onto one would reach the other.

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

1. *Two paths of one version on one inode.* A move never leaves that. Rule: the old copy is linked only while
   `BatchSizes.alone()` (section 5) says the version before alone holds it, asked when its compare is queued and again on the
   replay's thread right before the link; the link then tells the books, so a second new file that pairs with the same old file
   finds it held and is copied. A renamed move's source, which the tree keeps at the move's target, gives no name (a delete at
   or above a move's source is left out, section 2), and were it looked at, `alone()` would answer no.
2. *Metadata of another file.* A link shares mode, owner, group, times and extended attributes. Rule: link only when
   `entry_metadata()` of the monitored file and of the old copy are equal; anything else is a copy (docs/lessons.md: "never
   write a change signal onto data it did not come with").
3. *The file changes while it is compared.* The same as a file changing while it is copied: the version holds bytes that were
   read, through the one handle whose metadata was compared, and the write's event comes after the take and is backed up by the
   next batch (events in a folder made during a batch are recorded again from the take on). A write into a part already
   compared leaves the old bytes, consistently; a copy at that moment would hold a mix. A file replaced at its path during the
   compare is not read: the handle stays on the file it opened.
4. *A link the vault refuses* (`NO_HARD_LINK_ERRNOS`, reverberator.py:12275: EXDEV, EPERM, ENOTSUP, EOPNOTSUPP, EMLINK,
   ENOSYS), or any other error of the link: copy.
5. *The size books.* `BatchSizes` counts an inode in the newest version that holds it; a link back into the tree takes the old
   file back from the version before (section 5).
6. *A cut batch.* The link is made under the copy's temporary name and placed by `finish_copies()`, as a copy is. A cut before
   the commit leaves it as what the batch made. The next start's repair gives the tree the old file back at its old place and,
   off a pool or over a manifest that describes the version before, removes every name the version before's folder does not
   list (`put_back_recorded()` pass 2, reverberator.py:7239), the new folder with the link in it. On a pool over a lost manifest
   that pass does not run (its caller passes `remove_made` False there, 7506), and what the batch made stays: a placed link is
   copied again by the roll-forward (`new_in_tree()` lists it, and its monitored path is a regular file), and an unplaced copy
   name, which no monitored path has, is a row of the rebuilt manifest that the roll-forward's comparison finds gone and
   removes, while it copies the monitored file as a create. Either way the roll-forward copies the moved files: a roll-forward
   has no names (section 2). Read in the code; the crash gates run through it (section 9).
7. *A look that cannot answer.* A look at the version before or at the monitored file that fails (EIO, EACCES) never reads as
   "there" or "equal": it chooses the copy (round 0.55.7, section 7, for why "not there" may not stand for an error). So the
   looks are `real_folders_to(strict=True)` and `os.lstat()`, which raise, never `os.path.lexists()`, which answers False on
   EIO and EACCES.
8. *Bytes the vault never flushed.* The compare reads through the page cache, which can hold right bytes over a disk that never
   got them. The old copy is a file the last commit recorded: the deletes that give names replay first (section 3), so the
   version before holds there what the tree held at that commit. A copy of 0.55.5 or later was flushed before its commit; one
   an older release left unchecked is read back by the next comparison that walks it, through the same page cache, before it
   is recorded checked (`compare_entry()`), and the new version's row of a link is read back at its commit as a copy's is
   (`record_dirty_entries()`). The draft's rule "only rows recorded checked" goes (Calls to confirm).

Items 1, 5 and 8 differ from the study's rule; Calls to confirm 3, 7 and 14 say how.

## 2. Which old copy is looked at

**What it does.** For each regular file the replay is about to copy, one lookup on disk in the version before, led by the names
of the entries the batch deleted. Nothing is filled, searched or kept between batches.

**Where.**
- `released_names(backup_entries, monitor_path) -> dict`, a module function beside `order_backup_entries_for_replay()`
  (reverberator.py:8111): the rels of the batch's delete entries (a folder's without its trailing `/`) that lie under no other
  delete entry and at or above no move's source (each move entry's `source_path`), each keyed by its last name; a name two of
  them share maps to a marker that stands for "ambiguous". `prepare_backup_entries_for_replay()` keeps every delete and move
  (`prune_entries_covered_by_dir_creates()` drops only creates, modifies and attribs), so the replay meets every delete the
  names come from.
- `old_copy(names, rel, st, version_path) -> 'str | None'`, a module function beside it: for each part of `rel` that is a name,
  outermost first, the old path is that delete's rel followed by the parts after it (`P/new/big/sub/a`, with `big` the name of
  the deleted `P/big`, gives `P/big/sub/a`; a moved file is the entry itself: `n/top.iso` gives `top.iso`). An ambiguous name,
  and an old path equal to `rel`, is passed over. The first old path whose folders are real in `version_path`
  (`real_folders_to(version_path, old, strict=True)`) and whose `os.lstat()` is a regular file with `st`'s size, mtime (ns),
  mode, owner and group is returned; else None. ENOENT and ENOTDIR are "not there"; any other error of a look is raised
  (OSError; from 0.55.7 the strict look raises `VersionLookError`), and each caller takes it as "none" (sections 3 and 4).
- `do_backup()` builds the names once, right before its estimate (6399-6407), when the batch is not a roll-forward (`tree is
  None`) and holds a delete and a create or a modify; otherwise they are empty. It passes them to the estimate (section 3) and
  to `do_reverb_backup()`, which gains the keyword `names` (empty by default).

**Why the names, and which.** A delete entry names what left the tree, and its record put that into the version before at the
same path: `TreeWriter.record()` renames a file in or exchanges a folder in whole, and on two renames hard-links it in, after
which the rm removes the tree's name. An `lstat()` there finds it; the monitored file gives the key. A delete under another adds
no old place (its old copy lies under the top one), and a full comparison lists a delete for each row it did not see, so only
the top-most count: a moved folder is one name however many rows it had. A delete at or above a move's source can replay behind
that move, after the batch's creates (`order_backup_entries_for_replay()`'s exception), when its old place is not yet in the
version before; it gives no name whichever way it replays, so the estimate and the copy agree. A name two deleted entries share
would point two ways; rather than a rule to choose one, both are copied, as today.

**Reach.** It finds the moved entry's own old copy wherever the move kept the entry's name: `cd P; mkdir new; mv big new/`,
`mkdir -p a/b; mv big a/b/`, a move to another parent (`mkdir Q/n; mv P/big Q/n/`), a moved file as a moved folder; a move made
while reverberator was down that kept its name (the start's full comparison lists the deletes and the creates); and a tree
deleted and unpacked elsewhere under its own name with its times kept. It does not find an entry renamed in the move (`mv big
new/other`), two deleted entries of one name in one batch, a delete at or above a move's source (`mv d/g y; mkdir n; mv d
n/d`), or anything the batch holds no delete entry for (section 7).

**Cost.** In the step back's probe (scratch files, paths 8 deep): a file whose path holds no name costs one dict lookup a part,
0.25 µs, with 100 names as with none; a hit about 4 µs before the compare; the names of 110,100 delete entries (a full
comparison's per-row deletes of 100 folders) were built in 21 ms. No SQL statement, no index and no bound; at most one compare
a file.

**State.** The names, per batch. Nothing at rest.

**Failure cases.** None of its own: a look that cannot answer is "none" to its caller.

**Tests** (tests/test_no_copy_move.py, `unit`):
- `test_released_names_keeps_the_top_most_deletes_by_their_last_name`: a comparison's per-row deletes of `P/big` give `{'big':
  'P/big'}`; a file's and a folder's delete; two deletes of one name give the marker; a delete at a move's source and one above
  it (`mv d/g y; rm -r d`) give no name.
- `test_old_copy_finds_the_file_below_the_deleted_entry_of_its_name`, on scratch trees: the move below the top, to another
  parent, `mkdir -p a/b`, a moved file and an unpack elsewhere each give their own old path; a renamed move, an ambiguous name,
  a key that differs in each of its five fields, an old path through a link or at a link give None; EIO from an `os.lstat`
  stand-in on the old path is raised.

## 3. The estimate

**What it does.** The estimate made before the replay (`get_backup_size_inode()`, reverberator.py:11801) charges nothing for a
file the copy step will find, so the prune makes no room for a copy that is not made: the harm the known limitation names
("after five small versions, one such move left only the newest") goes for a move whose files are unchanged.

**Where.**
- `do_backup()`: `leaving = lambda path, st: old_copy(names, os.path.relpath(path, monitor_path), st, tree_now) is not None`,
  an OSError or a `VersionLookError` answering False; None when the names are empty, a roll-forward's always. Passed as
  `get_backup_size_inode(..., leaving=leaving)`.
- `get_backup_size_inode(..., leaving=None)` passes `leaving` to `get_unskipped_size_inodes()` (11759) only for the walks of
  what `copy_path()` copies: the main walk's call for a create or a modify entry of `taken`, every call of the `carried_in`
  subtraction (it takes back what a created folder's walk charged, through `leaving` too, so the two cancel), and the `written`
  add-back's call for a create or a modify entry. Never for an attrib entry, in `taken` or in `written`: the replay copies it in
  its attrib branch, which never links.
- `get_unskipped_size_inodes(..., leaving=None)`: a regular file (`S_ISREG` of the lstat it makes already) for which
  `leaving(path, st)` is true is charged nothing, no bytes and no inode: the entry itself when it is a file, and each file of a
  folder's walk. A hard link adds a name in its folder, no inode and no block of its own.
- **[Q25]** (b): none of this is built; the estimate charges every copy, as today.

**Why it stays at or below what the batch writes.** The estimate errs low, never high: an estimate too low only passes the
limit until the next prune, while a copy the estimate charges and the replay never makes prunes versions for good (the reason
the size entry gives). It looks at `tree_now`, which is `latest_version_info.path` (6401), before the hand-over; `hand_over()`
leaves the version before at that same path (reverberator.py:14263). The deletes that give names replay first
(`order_backup_entries_for_replay()` puts them first, and on two renames `pre_record()` records `replay_ops()` of the entries in
that order; only 0.55.7's growth leave-outs record before them, and they take the tree's file just the same, section 8), and
each record takes the tree's entry into the version before at its own path, keeping each file's size, mtime, mode, owner and
group. So a file the replay links was found by the same function, with the same names, at the same path, with the same key,
when the estimate asked: every file the replay links is one the estimate left uncharged (reasoned from
`order_backup_entries_for_replay()`, `record()` and `hand_over()`; barring a monitored file changed between the estimate's walk
and the replay's, as today). The verification's copies and the copy fallbacks are left out of the estimate, as today, but for a
move into its own old place, whose target the created folder's walk charges (the `carried_in` exception) through `leaving` like
any file of that walk; so wherever the replay links, the estimate either charged nothing for that copy or asked the same lookup.
A roll-forward has no names: its estimate is exact, as today.

The estimate also leaves uncharged some files the replay copies after all, and is low by each: the vault can pass its limit by
them until the next prune (Q25). They are exactly these four causes, on every kind of vault:
1. the file's contents or extended attributes differ from its old copy's under the same size, mtime, mode, owner and group (a
   same-size rewrite with its mtime set back; an extended attribute set in the move's batch, or one the vault refuses or sets
   itself);
2. its delete removed nothing there: `delete_path()` leaves an entry the length rule keeps (`left_out(kept=True)`), and one
   whose place holds another kind (a folder where a file was deleted, a file where a folder was). Behind a link, or with a link
   at its place, a delete removes nothing either, but there `old_copy()`, which looks through real folders and at regular files
   only, finds no file before the hand-over as after it, so the estimate charges what the replay copies;
3. it is the second of two new files that pair with one old file;
4. its link fails (a vault that refuses hard links, or a mergerfs pool that answers EXDEV between its disks: every such file,
   every time), or a look or the compare meets an error.

A chmod or chown made with the move (`mkdir n; mv big n/; chmod -R g+w n`) changes the key, so the file is charged as the copy
it is. An owner the vault cannot keep shows in the vault's own file, so its key differs there too.

**State.** None beyond the names.

**Failure cases.** A look that cannot answer charges the file, as the copy step will copy it. A file gone or changed between the
estimate and the copy: as today, the estimate is what the walk saw.

**Cost.** Only in a batch that both deletes and creates or modifies: one dict lookup per part of each regular file's path the
walk lstats already, and for a hit the looks of `old_copy()`.

**Tests** (tests/test_no_copy_move.py, `unit`; tests/test_estimate_charge.py's helpers):
- `test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder`: a delete of `big` and a create of `n/` holding
  it, and the same below the top (`P/big` to `P/n/big`), off and on two renames: the estimate is `n`'s folders' charge alone;
  under a size limit with five small versions, all five stay.
- `test_the_estimate_charges_a_file_changed_in_the_move` (appended, its size moved) and
  `test_the_estimate_charges_a_file_chmodded_in_the_move` (its mode differs from the old copy's).
- `test_an_attrib_copy_is_charged_whatever_its_path`: with Only Sync Attributes off, a chmod of a file whose path holds a
  name: its attrib copy is charged.
- `test_a_renamed_move_is_charged` (`mkdir n; mv f n/g`: charged, and copied).
- `test_the_estimate_is_never_above_what_the_batch_writes` (a parametrized pin, each shape its own case, off and on two
  renames): a move into a new folder from the top and from below it, the same with the entry renamed, the same at a start's
  full comparison, a move into its own old place, a move a folder move outran (`mv d e; mkdir e/sub; mv x e/sub/x`), a delete
  that replays behind a move (`mv d/g y; mkdir n; mv d n/d`), two creates that pair with one deleted file, and two deleted
  entries of one name: estimated bytes and inodes at most the vault's growth in bytes and inodes (`sizes_by_newest_holder()`).
- Q25's pins, one per cause, each: the estimate leaves the file out, the replay copies it:
  `test_a_predicted_link_whose_bytes_differ_is_copied_uncharged`,
  `test_a_predicted_link_whose_delete_removes_nothing_is_copied_uncharged` (three cases: the length rule keeps the delete; a
  folder stands where a file was deleted; a file stands where a folder was, its new place named as that file),
  `test_a_second_file_that_pairs_with_one_old_file_is_copied_uncharged`, and
  `test_a_predicted_link_the_vault_refuses_is_copied_uncharged` (an `os.link` stand-in answering EPERM).
- `test_a_roll_forward_charges_every_copy`: a batch cut after its hand-over and before its commit, then rolled forward: the
  estimate charges `n`'s files, and the replay copies them.
- tests/test_moves_into_new_folders.py's `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`
  and `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one` change: their estimated inodes
  are the names in `n` less the files linked (all of `big`'s but those the row writes or changes), plus the probes; `written <=
  est_size <= grew` stays (the touched and chmodded rows keep it, as the mtime and the mode are in the key). **[Q25]** (b): the
  estimated inodes stay the names in `n` plus the probes, and the bound becomes `written <= grew <= est_size`, as the estimate
  charges the files the replay links.
- tests/test_estimate_through_a_take.py's three tests (`test_the_put_back_through_a_take`, `test_the_attrib_put_back_through_a_take`,
  `test_file_rows_through_a_take`) stay as they are: their batch holds `n`'s create and a move into it, and no delete, so it has
  no names.
- **[Q25]** (b): of these only `test_the_estimate_charges_every_file_the_replay_links` (a move into a new folder: the estimate
  charges `big`'s files, the replay links them) and the two changed tests above.

## 4. The copy step

**What it does.** Before a regular file's copy is queued, the replay looks for its old copy, checks that the version before
alone holds it, and queues a full compare of the two, metadata and bytes, on a compare pool; an equal compare becomes a link in
place of the copy, and anything else is the copy made today.

**Where.** `do_reverb_backup()`'s `copy_path()` (14744) queues a file's copy at two places: the file branch
(`writer.copy(source_real_path, source_relative_path, mcae, pending)`) and the folder walk (`writer.copy(subRealPath,
subRelativePath, mcae, pending)`). Both call a new helper of `do_reverb_backup()`, `copy_or_link(source_path, rel, mcae)`, in
its place. Everything `copy_path()` does before them stays: the source's look, the length rule (`left_out()`: the link is
written under a name of the copy's length, so the rule that measured the copy measures it), the untracked folder above, the
folders made, the row added dirty, so the commit records it as a copy's (`record_dirty_entries()` reads the linked file,
reverberator.py:11116). Every create and modify the replay copies comes through `copy_path()`: the batch's own, a created
folder's walk, `copy_untracked_folder()`, a copy fallback's (`delete_and_copy()`), the verification's missing entries and
`recheck_moved_folder()`'s. The attrib branch's copy and the move branch's copy of a moved file whose metadata changed are not
`copy_path()`'s and stay copies.

`copy_or_link()`, on the replay's thread, each step choosing the copy (`writer.copy()`, as today) when it fails:
1. The names are empty: copy, with no look.
2. `st = os.lstat(source_path)`: not a regular file: copy.
3. `old = old_copy(names, rel, st, writer.previous)`: None: copy.
4. `writer.sizes.alone(old, writer.two_renames)`: False: copy.
5. The compare is queued: `same_file(source_path, writer.kept_path(old), cancelled)`, submitted to the batch's compare pool, and
   the file kept in the replay's window with `rel` and `old` (where it runs, below).
6. When the window settles it, on the replay's thread, the daemon stopping (`GREEN_LIGHT` clear) comes first: neither a link
   nor a copy, and the replay ends as for any stop. Then, an equal compare with `alone(old)` still True:
   `writer.link_kept(old, source_path, rel, pending)` (section 5) makes the link; True, and the rel is kept with the file's size
   until it is placed (section 6); False, a copy. Metadata or bytes that differ, a compare that failed, or an old copy another
   file of the window linked first (`alone()` now False): a copy.

An OSError at steps 2 to 4 or of the `alone()` at the settle, and 0.55.7's `VersionLookError` from a strict look, is caught
there and chooses the copy: a look that cannot answer never links (section 1, item 7). `VersionLookError` is a JobFailure, not
an OSError, so the `except` names both.

**`same_file(source, kept, cancelled) -> bool`**, beside `hash_file()` (11674). It opens the monitored file once, as
`hash_file()` opens one (no link followed, `O_NOFOLLOW`; never a blocking open of what is not a regular file; a lease waited for
as `cp` waits): that opener becomes a module function both use; it opens the kept file so too. It compares `entry_metadata()`'s
tuple of each, read from its handle (`entry_metadata()` takes an open fd as well as a path: `os.fstat()` and the extended
attributes through the fd, with `xattr_names()`'s rule for a filesystem without them), as the move branch's
`only_attributes_differ()` compares them (14877): mode, owner, group, mtime and extended attributes; unequal: False. Then it
reads both through those handles into two buffers of 1 MiB, the size `hash_file()`'s full hash reads in (`1 << 20`), and answers
False at the first block that differs, at a length that differs, at any OSError, and when the daemon is stopping (`GREEN_LIGHT`
clear) or the batch is ending (`cancelled` set), both looked at between blocks. Not `filecmp.cmp()`: its cache answers from an
earlier result when the size and mtime are the same, which is exactly the case this compare exists for. Not `cmp -s`: it opens
the monitored file following a link, and blocks on a FIFO swapped in since the walk, where `cp -a` does neither.

**Where it runs.** On a compare pool, in parallel, as `record_dirty_entries()` and `compare_scopes()` run their compares: a
`ThreadPoolExecutor` of `COMPARE_THREADS` threads (`--compare_threads`, 32 by default), made by `do_reverb_backup()` when it
queues its first compare, so a batch that compares nothing makes none. The pool is the compares' only bound, as it is for those
two: a compare takes no `BACKUP_SEMAPHORE` permit, so the compares and the copies never wait for each other. (A permit would not
deadlock: multiCMD's dispatcher takes a copy's permit on its own thread, and the copy's thread gives it back when its command
ends, `_HeldPermit.__exit__`, not when a wait reaps it; but a compare waiting for one would hold the `finally`'s wait behind
copies it has not stopped yet.) The replay keeps at most `COMPARE_THREADS * 4` compares in flight, the window `compare_scopes()`
keeps; when it is full, the replay waits for whichever finishes first (`concurrent.futures.wait(..., return_when=FIRST_COMPLETED)`,
in waits of `POLL_WAIT_SECONDS` between which it polls the pools, `poll_pools()`, as it does while it waits for the copies) and
settles every one that has finished: links and copies need no order, where `compare_scopes()` settles in walk order because its
results must be applied in that order. `wait_for_async_commands()` first settles them all: whatever a compare decides is queued
before any wait ends, and no move, delete barrier or verification runs while a compare is open. `same_file()` polls nothing
itself. `do_reverb_backup()`'s `finally` sets `cancelled`, a `threading.Event` of the batch, then shuts the pool down with its
queued compares cancelled (`shutdown(wait=True, cancel_futures=True)`), then stops the copies as today: a compare already reading
ends at its next block (a JobFailure leaves `GREEN_LIGHT` set, so the batch needs a flag of its own), and one whose open waits
for a lease to break waits out the kernel's lease-break time at most (45 s by default), as `hash_file()`'s opener does while the
daemon runs. A compare reads twice what one copy reads and writes nothing; the build measures it against today's copy
(section 9).

**State.** Per batch: the compare pool, the window (each compare with its file's rel and old path), `cancelled`, and the rels
linked and not yet placed (section 6). No set of claimed or held old copies: `alone()` at the link is the claim. Nothing at rest.

**Failure cases.** Each chooses the copy, which then fails or succeeds as today:
- the source gone or replaced since the walk listed it (step 2, or the compare's open): the copy's own failure keeps the last
  backed-up copy, or, gone, the row goes with today's line;
- no old copy, or one the version before no longer holds alone, or one that cannot be looked at;
- metadata or bytes that differ, an unreadable side;
- the link refused or failing (section 5).
A stop during the compare chooses nothing: the batch ends as a stop does.

**Tests** (tests/test_no_copy_move.py, `unit` unless said; each through `do_backup()` with raw events, a delete of the old place
and a create of the new, unless said; each ends with the oracle of section 9):
- `test_an_unchanged_file_moved_into_a_new_folder_is_linked`, off and on two renames, with Only Sync Attributes on and off: the
  new path in the newest version and the old path in the version before are one inode; no two paths of one version share one;
  one line.
- `test_an_unchanged_folder_moved_into_a_new_folder_is_linked`, the same ways, with a subfolder, a link and an empty file in it:
  every regular file linked, the link and folders made as today.
- `test_a_folder_moved_below_the_top_is_linked`: `cd P; mkdir new; mv big new/`, `mkdir -p P/a/b; mv P/big P/a/b/` and a move to
  another parent (`mkdir Q/n; mv P/big Q/n/`): every file linked to its own old copy.
- `test_a_move_made_while_down_that_kept_its_name_is_linked` (a start's full comparison: the per-row deletes and the creates)
  and `test_a_tree_unpacked_elsewhere_under_its_name_is_linked` (`rm -r big; mkdir r; tar xpf big.tar -C r`).
- `test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied`: other bytes before the last 64 KiB (the twin of section 1's
  first order; the tests' `cpp`).
- `test_a_poke_before_the_compare_is_copied`: same size and mtime kept (the tests' `poke`) after the take.
- `test_a_write_during_the_compare`, two cases through a stand-in for `same_file()`'s read that writes into the monitored file
  after its first block: into a block not yet compared (copied) and into one already compared (linked to the old bytes; the next
  batch copies the new ones, and its version holds them).
- `test_a_file_replaced_after_the_compare_opened_it_is_judged_as_opened`: a stand-in for the opener that, once it has opened the
  monitored file, replaces it at its path with a copy of the old copy under other metadata: the compare reads the file it
  opened, and the version never holds the old copy's bytes under the replacement's metadata.
- `test_a_source_gone_before_the_compare_is_copied_as_today` (removed in a stand-in for `old_copy()`): no link, and the lines
  and rows today's copy gives a source gone between the walk and its copy.
- `test_metadata_that_differs_is_copied`, one case per field: mode (a chmod with the move), mtime (`touch`), an extended
  attribute (`user.x`), owner and group (these two skip unless root, as tests/test_r_readers.py's `needs_root`, and run in the
  VM): each copied, never linked.
- `test_two_new_files_and_one_old_file_link_one` (`rm -r big` with `big/a`; `n1/big/a` and `n2/big/a` created with its bytes and
  metadata): both compared, the first settled linked, the second copied, as `alone()` then answers False.
- `test_what_the_names_do_not_reach_is_copied`, one case each: a renamed move (`mkdir n; mv big n/other`), two deleted entries
  of one name (`x/src` and `y/src`, and `n/src` created with one's bytes), a delete at or above a move's source (`mv d/g y;
  mkdir n; mv d n/d`), a delete and a create of one path (`rm -rf d; tar x` at `d`'s own place, times kept: the batch holds no
  delete).
- `test_the_compares_run_in_parallel`: a stand-in for `same_file()` that waits for a second call: two files of one moved folder
  are compared at once.
- `test_the_window_settles_whichever_compare_ends_first`: a stand-in for `same_file()` that holds the first file's compare until
  every other file of the folder is linked: they are, while it is open.
- `test_a_job_failure_ends_the_compares_in_flight`: a stand-in read that waits for `cancelled`, and a JobFailure raised in the
  replay: the attempt fails, and the `finally` returns once the stand-in has seen the flag.
- `test_an_old_place_with_no_file_is_copied`: a delete the length rule keeps (a forward link stays at the old place in the
  version before), and a user's symlink deleted where the new path's name points: copied.
- `test_a_stop_during_the_compare_links_nothing`: `GREEN_LIGHT` cleared from the stand-in read: no link and no copy queued for
  the file, the batch ends as a stop does (`attempt_events()` returns False), the next attempt commits it right.
- `test_a_failed_look_at_the_version_before_is_a_copy`: EIO from an `os.lstat` stand-in on the old path.
- `test_the_verification_links_too`: a file of the moved folder that the replay's walk missed and the verification finds
  missing: linked.
- `test_a_roll_forward_links_nothing`: a batch cut after its hand-over and before its commit, rolled forward: `n`'s files
  copied.

## 5. The writer's verb and the size books

**What it does.** One `TreeWriter` verb puts the version before's file at the new place the way a copy is put there, and tells
the size books that the file is the tree's again; the books answer whether the version before alone holds a file.

**Where.**
- New `TreeWriter.link_kept(kept_rel, source, rel, pending) -> bool`, beside `copy()` (reverberator.py:14170), the one door to
  the tree: tests/test_tree_writes.py's `test_the_writer_is_where_the_writes_are` gains `link_kept` among its verbs and asserts
  `os.link` among the writes it holds, as it does for `rename` and `remove_queued`, and `replay_offenders()` keeps finding any
  write of the replay outside the writer (`copy_or_link()` is a closure of `do_reverb_backup()`, and `same_file()` a module
  function it names). As `copy()` does: `record(rel, True)`, `flush_if_needed()`, `_folders_for_copy(source, rel)`, here when
  the window settles the compare: nothing between the compare's queueing and its settling changes the folders above `rel` (no
  move, delete or verification runs while a compare is open), so they stand as `copy_path()` made them, and a record or flush
  that fails raises JobFailure, as in `copy()`. Then a fresh copy name, `partial_copy_path()` of `rel`'s path (8222), taken
  again while one is there as `cp_af_copy_path()` does; `os.link(self.kept_path(kept_rel), temp, follow_symlinks=False)`, as
  `link_or_copy()` (13553) makes its links, not through `link_or_copy()`, which raises outside `NO_HARD_LINK_ERRNOS` and copies
  within them; the size books told (below); `pending.append(PendingCopy(None, source, temp, self.path(rel)))`, a link already
  made. True.
  Any OSError of the link or of the look after it (`NO_HARD_LINK_ERRNOS` and EIO among them): the copy name removed if made,
  False, and the caller copies; the record made stays, and `copy()` repeats it and finds nothing left to do (a record acts only
  where a forward link still stands). The place `rel` never holds the old copy's inode, so the placement (`os.replace`) is
  never a rename between two names of one inode, which would do nothing and leave the copy name: `alone()` answered, just
  before, that no path of the tree holds it.
- `finish_copies()` (8946): a pending entry whose task is None is a link already made. Its loop branches on that before it reads
  `copy.task.stderr` (8969), which a link has none of: no lines, succeeded, and it is put in place, or left with its row dropped
  where a folder above its place is no longer real, exactly as a finished copy is, and returned among the entries put in place
  (0.55.7's section 9 reads that list as what the replay applied). Its `if copied: manifest.copies_unsynced = True` (9026-9027)
  becomes: set only when it placed an entry with a task, so a link sets no flush. `discard_copies()` (8801) removes a link's copy
  name as a partial copy's, from its two callers: `stop_copies()` (a stop, and the replay's `finally` after a JobFailure) and
  `finish_copies()`'s `finally` (the entries an error left unplaced); that leaves the version before's file whole and its link
  count where it was. A cut leaves the name to the next start's repair (section 1, item 6).
- `BatchSizes` (13736): `shared` becomes a dict by rel (`pending()` sets `shared[rel] = (size, links)`; a version's entry is
  recorded once, so no rel comes twice); `result()` iterates `self.shared.items()` (`for rel, (bytes_, links) in ...`; today it
  unpacks the list's triples); new `linked(rel, size, links)` and `alone(rel, two_renames)`.

**The size books.** `BatchSizes` counts what the version before alone holds, each inode in the newest version that holds it.
`link_kept()` calls `self.sizes.linked(kept_rel, size, links)`, `size` the file's and `links` its count of names right after the
link: an `lstat()` of the new name off two renames (exact there, as `keep_entry()`'s comment says), `links_now()` on them. Not
`st_nlink + 1` of a look before the link, as `keep_entry()` takes it: the compare ran in between. `linked()` takes the file back
from the version before's count (`self.size -= size`, `self.inodes -= 1`) unless `rel` is in `shared` already, then sets
`shared[rel] = (size, links)`, so the file counts nowhere while the tree holds the link, and counts in the version before again,
by size and inode, if the tree lets it go later in the batch (the verification removes its new place, a later copy replaces it,
the link is discarded).
- Off two renames a delete's record takes a file by a rename (`record()` at 14108 adds its size, its inode taking the forward
  link's place) or with a folder exchanged in whole (`folder_usage()`'s size and inodes), so it is not in `shared`, and
  `linked()` takes it back.
- On two renames a delete's record takes every file by a hard link (`record()` makes every record a keep there), so the file is
  in `shared` already, pending at the count its record left; the rm of its delete dropped that count by one, and the link brings
  it back. `linked()` takes nothing back, as the pending entry was never added.

`linked()` tells the two apart by `shared` itself, not by the writer's `two_renames`, which an exchange that fails can still turn
on in the middle of a batch. A roll-forward's sizes come from `measure_previous()` (7659), which counts in the version before
only files the tree does not share: a linked file is shared, so it needs nothing (and a roll-forward links nothing). The study's
"on a pool ... off a pool" is "on two renames (a pool, or a filesystem with no exchange) ... off them".

**The invariant `alone()` rests on.** `alone(rel, two_renames)`: `rel` is not in `shared`, or the file's count of names now
(`links_now()` on two renames, an `lstat()` elsewhere, as `result()` reads it) is below the count `shared` holds for it. Asked
only of a regular file of the version before reached through real folders (`old_copy()` looked), it is meant to say: no path of
the tree holds this file's inode. It is the one new invariant of this round.
- *Why it holds, in general (reasoned, not run):* a batch's version before starts as forward links alone (`hand_over()`), so
  each regular file in it came by a record of the tree's entry during the batch (`record()`, through `unfold()`,
  `hard_link_tree()` and `exchange_in()`). A record without keep renames the file in, or exchanges its folder in whole, which
  takes the tree's name away. A record with keep (every record on two renames) hard-links it in through `keep_entry()`, the only
  caller of `BatchSizes.pending()`, which puts it in `shared` with the count the link left; however the tree lets it go, that
  count drops by one. A record that copies where hard links are refused makes an inode the tree never held. The tree holds each
  inode under one name (each copy is its own inode, and a hard-linked monitored file is copied once per name), and the only
  other link into the tree is this round's, which `linked()` puts in `shared`. Nothing else changes a count during a batch: the
  prune runs before the hand-over. A roll-forward's books start empty over records the cut attempt made, so `alone()` would read
  wrong there; a roll-forward has no names and never asks it.
- *What was run:* a probe on scratch files with the real `hand_over()` and `TreeWriter`, once off two renames and once with
  `pooled=True`, every flush stubbed. After a folder deleted whole, a top file deleted, a file deleted and then its folder (the
  record walks the folder entry by entry), a copy queued over a file, a renamed move of a file and of a folder, `mv D/g y; rm -r
  D`, and `mv p q; mv other p; rm p` (the version before holds its own `p`), `alone()` was True exactly for the files no path of
  the tree held, on both writers, and False for every file a move carried or a pending copy still held. One link back into the
  tree, told to the books as `linked()` tells them, turned it False, and the tree letting that link go turned it True again:
  that is the claim-once, with no set of claimed files. Not run: an unfold's entry too deep for a forward link, a record copied
  where hard links are refused, the verification's sweep (`remove_now()`), a real mergerfs pool.
- *Its tests:* `test_alone_answers_for_each_kind_of_record` (tests/test_no_copy_move.py, `unit`), a TreeWriter from
  `hand_over()` on a vault in the test's folder, off two renames and with `pooled=True`, one case per record kind: the run ones
  (a copy queued over a file both before and after its placement) and the three not run (an `os.symlink` stand-in answering
  ENAMETOOLONG on one path, an `os.link` stand-in answering EMLINK for the record, `remove_now()`). For each regular file of the
  version before, `alone()` is True exactly when no path of the tree holds its inode (an `os.walk` of the tree's inodes); then
  each file it answers True for is linked into the tree as `link_kept()` links it and told to the books, after which `alone()`
  is False and `paths_sharing_an_inode()` is empty for both versions.
- *If a check finds a hole:* the evidence goes back to what the deletes took, kept as a set of rels beside the names
  (`record()` and `remove_queued()` reporting what they took; on two renames, `pre_record()` what each delete's record took),
  with no table; the lookup, the compare and the rest of this spec stand.

**Why the link sets no flush.** The commit flushes the vault's disks before its commit point when the batch placed a copy
(`manifest.copies_unsynced`), when it rolls a cut batch forward, and on two renames always (`do_backup()`, 6511). A link writes no
data: its inode is a file an earlier commit recorded (section 1, item 8). It adds a name, which a vault off a pool carries to the
disk with the manifest's fsync, as it carries the batch's renames and exchanges (the power-cut tests at every step on f2fs, ext4
and XFS; docs/limitations.md "Vaults on btrfs" for the one filesystem not covered). A batch that only links, off a pool, then
commits with no flush of the vault's disks, one `syncfs` less per such batch.

**State.** `BatchSizes.shared` keyed by rel, per batch, as before. Nothing at rest.

**Failure cases.** The link refused or failing: the copy. A cut after the link and before the commit: as section 1, item 6 says.
A stop: `stop_copies()` discards it. A folder above the new place turned into a link before the placement: left and its row
dropped, as a copy.

**Tests:**
- tests/test_tree_writer.py (a TreeWriter alone; the module skips unless root, so these run in the VM):
  `test_link_kept_records_its_place_and_queues_a_finished_copy`: an entry at `rel` in the tree is recorded in the version before
  first; the pending entry has no task and its copy name is a name of the version before's file; off and on two renames.
- tests/test_tree_writes.py: `link_kept` among the writer's verbs, holding `os.link`.
- tests/test_no_copy_move.py: `test_alone_answers_for_each_kind_of_record` (above); `test_the_sizes_after_a_link` (the
  ground-truth plugin compares each change list with `sizes_by_newest_holder()`), one case each: a file renamed in, a folder
  exchanged in, a folder walked by the record (the version before's folder real already), each off and on two renames, and an
  entry an unfold kept by a hard link (a stand-in for `os.symlink` answering ENAMETOOLONG on its path), its top folder deleted
  and moved into a new folder: linked, as its delete's rm left the version before alone holding it.
- `test_a_linked_file_the_tree_lets_go_in_its_batch_counts_in_the_version_before`: the monitored new file removed in a stand-in
  for `finish_copies()` after the link was placed, so the verification deletes it.
- `test_a_link_refused_with_each_errno_is_a_copy`, parametrized over `NO_HARD_LINK_ERRNOS` and EIO (an `os.link` stand-in for that
  path): copied, sizes right, no copy name left.
- `test_a_batch_of_links_alone_commits_without_the_flush`: a spy on `flush_copies()`: not called off two renames; called on two
  renames.
- `test_a_stop_before_a_link_is_placed_leaves_no_copy_name`: `GREEN_LIGHT` cleared after `link_kept()`: no
  `.reverberator-partial` name in the tree, the version before's file whole, its link count back.

## 6. The log line

**What it does.** One line at the end of `do_reverb_backup()`, after the verification, when the batch placed a link: `Linked <n>
files, <size>, from <version before> in place of copies: each had the bytes, mode, owner, group, mtime and extended attributes of
a file this batch removed from the version` (`format_bytes()` for the size, as the change list's name writes it). Today the copy
of such a move writes no line at all; a copy still writes none. One line a batch, not one a file: a moved folder of 100,000 files
writes one.

**Where.** `do_reverb_backup()` keeps each rel `link_kept()` linked, with its size, until a wait reports it placed (the rels
`finish_copies()` returns, which 0.55.7 gathers into the batch's `placed` set), and counts it then: a link never placed (left
where a folder above stopped being real, discarded at a stop) is not counted. The line is a plain `backuperTeeLogToTl()` call
(5462) with `monitor_path` and no flag, as the replay's other lines (`Moved … to …`, `Fixing … differences …`): logged at info
level in the daemon's log, and printed too under `--debug`; `log_text()` escapes the whole line, the version's path with it.

**State.** The rels and the count, per batch.

**Failure cases.** None of its own; a stop or a JobFailure ends the batch before it, as for any line of a batch that did not
commit.

**Tests:** `test_one_line_a_batch_names_the_files_and_bytes_linked` and, as pins, no such line in a batch that linked nothing,
and a link left unplaced (a folder above it replaced by a link) not counted (tests/test_no_copy_move.py). It is an info line: the
repo's alert patterns (firewatcher/reverberator.regex) match only the markers and the exit line, so nothing alerts on it.

## 7. What it does not reach

Each of these stays today's copy, with today's lines; the version is right in each.

1. **A file changed in the move's batch:** its bytes, mode, owner, group, mtime or an extended attribute. That file is copied;
   the rest of a moved folder is linked. Under Only Sync Attributes too: in the move's batch such a file is copied, not linked
   and then given the new metadata (possible, and left for a later round). A change made in a later batch to a linked file is
   an attrib like any other, and under Only Sync Attributes it is synced onto the shared inode, where the version before's old
   path shows it too, as for a renamed file (section 9's test).
2. **An old place whose delete is not applied before the copy:** a batch the maximum delay takes while the move-out still waits
   for its pair (the check after the batch deletes the old place, after the copies ran; a batch taken quiet holds the delete,
   as each move-out still held is its delete once the tree is quiet); a move landing in the instant a batch is taken (the known
   limitation of that name); and a delete at or above a move's source, which gives no name (section 2): a folder moved into a
   new folder after a move out of it in the same batch (`mv d/g y; mkdir n; mv d n/d`).
3. **An entry renamed in the move** (`mv big new/other`), and so a rename made while reverberator was down (the start's full
   comparison finds a delete and a create of another name): copied once, as today.
4. **Two deleted entries of one name in one batch:** the name is ambiguous, and both moves are copied.
5. **What the batch holds no delete entry for:** a delete and a create of one path (`rm -rf d; tar xpf d.tar` at `d`'s own
   place: they collapse into the create, `change_events_to_backup_entries()`, and each file is copied over its old copy, as any
   modify is); a move into its own old place (`mv D x; mkdir D; mv x D/D`) and its swap shape; swaps in one batch; a folder found
   ahead of its events (its move came as a move); and the copy fallbacks of a move (a move another change of the batch outran, a
   move into its own old place, a move whose path passes the length limit). A fallback's delete gives no name, so its copy links
   only where its path holds the name of one of the batch's own delete entries, which its own shape does not give. The entries
   that say these are copied stay as they are.
6. **What the version does not hold:** a move into the tree from outside it, from a skipped path or from a paused inner disk;
   a file made in the batch and moved into a new folder.
7. **A vault that refuses hard links** (a known limitation already), and a vault whose filesystem cannot hold a monitored file's
   metadata as it is (an extended attribute it refuses or sets itself, an owner it cannot keep): its files are never linked.
8. **The second of two new files that pair with one old file:** one link per old file.
9. **A batch cut before its commit and finished at the next start:** its roll-forward has no names and copies as today.
10. **Copies the replay makes outside `copy_path()`:** the attrib branch's (a swap the collapse could not replay; a chmod with
    Only Sync Attributes off), and the move branch's copy of a moved file whose metadata changed.

What the operator is told: the narrowed entry "A folder or file moved into a new folder is copied whole" and README lines 15 and
22 (section 10).

## 8. Interactions with round 0.55.7

This round is built on 0.55.7's merged code. What it takes from it, and where the two meet (0.55.7's spec sections and plan
tasks, `docs/superpowers/plans/2026-11-22-r0557.md`):

- **Section 7, the strict looks (Tasks 5 and 6).** `old_copy()`'s look at the version before is `real_folders_to(strict=True)`;
  0.55.7 makes the strict form answer False for ENOTDIR and raise `VersionLookError` (a JobFailure, not an OSError) for an error
  other than ENOENT and ENOTDIR, and `copy_or_link()`'s `except` and the estimate's `leaving` name it beside OSError: a failed
  look here only ever chooses the copy (or the charge), which needs nothing of the version before, so it fails no attempt. The
  source's look (step 2) is its own lstat: an error chooses the copy, and the copy's own failure keeps the last copy with its
  UNREADABLE line, as 0.55.7's `monitored_there()` arranges for `copy_path()`. Task 5 also makes `finish_copies()`'s three
  `real_folders_to()` strict and `discard_copies()` go on past a failed look: a link's pending entry takes those paths as a
  copy's does.
- **Section 9, history from what the replay applied (Task 7).** `wait_for_async_commands()` gathers `finish_copies()`'s returned
  rels into the batch's `placed` set, and `copy_path()` records the rel each entry's own `writer.copy()` was given. A link is
  returned by `finish_copies()` among the entries put in place (section 5), so it reads as applied, and its history is the
  events': a delete and a create, as today; section 6 counts the links by the same set. Collision: both rounds change the same
  two lines of `copy_path()`: the rel is recorded in `copy_or_link()`'s caller, whichever way the file goes, and
  `wait_for_async_commands()` settles the compares before it waits.
- **Section 1, the length rule (Tasks 2 to 4).** The link is written under a `partial_copy_path()` name, of the copy's length, so
  `left_out()`'s measure of the copy (its `version_bytes`, counting the next version) holds for it. Task 2 changes the estimate's
  `version_bytes` (`estimate_bytes`, `after`) in the same `get_backup_size_inode()` call that this round gives `leaving`: a merge
  point, no conflict of meaning. Tasks 3 and 4's leave-outs are not delete entries, so they give no names; a file one of them
  takes into the version before at a name's old place is alone there as a delete's take is, and the estimate saw the same file
  at that path before the hand-over.
- **Section 10, the walk's wave (Task 1).** `copy_path()`'s folder walk is `iter_tree_entries()`; `copy_or_link()` is called per
  yielded file and does not touch the walk.
- **Sections 2 to 4, the pool.** They change how a pool's disks are looked at, not how the writer links. Apart from 0.55.7: on a
  pool the link is made through mergerfs from the branch that holds the old copy, and mergerfs either makes the folders above
  the new place on that branch, as it does for `hl_record()`'s links today, or answers EXDEV, by its policy (reasoned, not run);
  EXDEV is a copy (section 1, item 4). The approved entry "On a mergerfs pool, a folder cloned to another disk can lose setgid"
  covers folders it makes, as any the batch writes into. The VM's pool gate forces both outcomes (section 9).
- **`BatchSizes`, `TreeWriter.record()`, `TreeWriter.pre_record()`, the estimate's walk:** 0.55.7 changes none of them beyond the
  above.

Order: this round's branch is made from the merged 0.55.7; nothing here is built before it.

## 9. The test plan

Every outcome is forced by its own test, through a stand-in at the one call that decides it where the real system cannot be made
to answer so; none is left to a random sweep. The sweeps below (the fuzz, the shapes at their timings) are the regression gate,
not the proof.

**The oracle, at the end of every test.** In tests/test_no_copy_move.py, `check_vault()` (tests/vault_oracle.py) over every
version, against the tree each backed up (snapshotted before each batch): each version byte for byte in full (`entry_view()`
hashes whole files), with mode, owner, mtime and extended attributes, but, under Only Sync Attributes, a file of an older version
whose inode another version reads, whose metadata it leaves out (`free_file_meta`, its sharing rule: round 19's rule lets a synced
attribute reach such a file). `assert_held_as_the_tree()` of tests/test_moves_into_new_folders.py, which the watcher tests use,
compares the version before on kind and contents only, as today. Then the sizes (the suite's ground-truth plugin,
tests/version_view_ground_truth.py, compares each change list's name with `sizes_by_newest_holder()` after every committed batch,
and checks that no older version changed); and the shape: a new helper in tests/vault_oracle.py, `paths_sharing_an_inode(job_vault,
folder_name)`, empty for every version (no two paths of one version on one inode), with, where a link is expected, the new path in
the newest version and the old path in the version before one inode (`read_view(..., inodes)`).

**tests/test_no_copy_move.py** (new, `unit`: a module of one layer, as conftest.py's hook fails a test with two; the owner and
group cases chown, which the `unit` layer allows, and skip unless root, as tests/test_r_readers.py's `needs_root`, so they run in
the VM). Batches through `do_backup()` with raw events, as tests/crash_batches.py's `backup_events()` builds them; that helper
asserts the commit (crash_batches.py:49), so it is split into `attempt_events()`, the same call returning `committed`, and the
assert, and the tests of a stop call `attempt_events()`. "On two renames" is both ways: the batch's writer made pooled
(`hand_over()` wrapped to pass `pooled=True`, so it is `TreeWriter(pooled=True)` as on a pool), and a filesystem with no exchange
(`rename_exchange` patched to raise EINVAL, as tests/test_moves_into_new_folders.py's `test_on_a_filesystem_with_no_exchange`
does: `hand_over()`'s own exchange then fails, and two renames are on from the version's build). It holds the tests named in
sections 2 to 6, and one more: with Only Sync Attributes on and off, a link, then a chmod of the new path in the next batch: on,
synced onto the shared inode, and the version before's old path shows the new mode (round 19's section 2.4, as for a renamed
file; the oracle allows it); off, copied, and the version before keeps the old mode.

tests/test_job_startup.py's `test_a_stop_saves_nothing_and_the_start_makes_one_version` keeps its assert of a copy for a rename
made while down (`moved.txt` to `moved-to.txt`, line 309): the name changed, so it gives no old copy, on every job.

**tests/test_tree_writer.py** (a TreeWriter alone; the module skips unless root, so its tests run in the VM): `link_kept()`'s
record first and its finished pending entry, off and on two renames.

**tests/test_tree_writes.py** (`unit`): `link_kept` among the writer's verbs, holding `os.link` (section 5).

**tests/test_moves_into_new_folders.py** (`inotify`, the real watcher on real inotify; TIMINGS are `apart` and `unread`, and
`at_once` has its stress test; the session's default is Only Sync Attributes on):
- `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` becomes
  `test_a_folder_moved_into_an_existing_or_a_new_folder_costs_no_copy`: for `new` and `nested` too, at gaps 0 and 0.2, each
  moved file's inode is its old one (`after[new] == inodes[old]`) and the vault grows by under 200,000 bytes (the test's own
  bound for a move into an existing folder: a copy would be 400 KB). Each batch is taken quiet (`take()` waits for the watcher's
  quiet signal), when every move-out still held is its delete in that batch, so the batch holds `big`'s delete at gap 0 too.
- New `test_what_a_move_into_a_new_folder_links`, parametrized over nine shapes of SHAPES at both timings, with the rels each
  must link (the old inode at the new place) and those it must copy: `folder`, `file`, `nested` (all linked); `file_renamed`
  (copied); `changed_before` (`n/big/a` copied, `n/big/sub/b` linked); `changed_between` (the poke: `n/big/a` copied, the rest
  linked); `folder_chmod_in` (`n/big/a` copied for its mode, `n/big/sub/b` linked); `its_own_old_place` (copied: no delete of the
  batch gives a name in its path); `a_file_made_in_the_batch` (copied: no version before holds it, so no other path of the vault
  shares its inode).
- `assert_held_as_the_tree()` gains `paths_sharing_an_inode()` empty for the newest version and the version before, so its 13
  callers check the shape too, the MATRIX test of the 32 shapes of SHAPES at their timings among them. The `at_once` stress test
  (`test_moves_into_new_folders_as_fast_as_they_go_end_as_the_tree`), which compares `version_view()` with `live_view()` alone,
  gains the same check after each of its two batches.
- The found-folder tests, whose names say the move is copied (`test_a_move_in_that_the_walk_saw_and_whose_event_comes_is_a_copy`,
  `test_a_folder_moved_into_a_folder_from_outside_while_it_is_walked_is_copied`,
  `test_a_folder_moved_into_a_new_folder_made_after_its_parents_walk_listed_it_is_copied`,
  `test_a_folder_moved_into_a_folder_from_outside_before_its_subfolder_is_listed_is_copied`, and
  `test_a_folder_the_walk_found_moved_in_and_moved_on_in_a_later_read_ends_as_the_tree`), assert the version equals the tree and
  nothing of how. Under this route each batch, taken quiet, holds `big`'s delete (a move into a new folder keeps its source to
  expire into its delete, as `watchFolder()` says where it discards a new folder's events), so the moved files are linked by the
  name `big`, the file written in place with its mtime set back in the second one copied. Each gains that assert, inode by
  inode, and the four `..._is_copied`/`..._is_a_copy` names say linked; a test that shows otherwise is a finding the builder
  reports.
- `test_on_a_filesystem_with_no_exchange` gains: `big`'s files and `f.txt` are linked (one inode across the two versions),
  `n/big/z` copied: the reach on two renames on the real watcher.
- `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` gains: the new file's inode is not the old one (the
  name pairs them, the compare tells them apart).
- The two estimate tests change as section 3 says.

**tests/test_watcher_fuzz.py** (`inotify`): the random steps already move folders and files into new folders (`mvd_new`,
`mvf_new`); a new step `twin` copies a file with `cp -p` semantics (`shutil.copy2`) to a new name, and one time in two pokes one of
the two (same size and mtime, other bytes). Its oracle stays the file's own, the newest version equal to the tree by whole-file
hashes, and the plugin's, no older version changed and each change list's sizes; `paths_sharing_an_inode()` joins it for every
version after each round. The suite's sample as now; a longer run is the main session's gate call.

**Crash** (**main session: VM gate**; builders write these to skip outside the VM). tests/crash_batches.py's batch 3 gains a
deleted file and a deleted folder, past f2fs's inline size (`past_inline()`), and their creates under their names in a new
folder, so the batch links both; every kill point of tests/test_crash_harness.py's sweep then cuts through `link_kept()`, the
placement and the commit, and tests/test_crash_power_loss.py's power cuts through the same. After each, both run `check_vault()`
and `view_truth.wrong_lists()`, as today, and gain `paths_sharing_an_inode()` empty for every version and `measure_previous(version
before, newest)` equal to `sizes_by_newest_holder()`'s count of the version before (today only
`test_roll_forward_sizes_equal_a_clean_batch` checks those two). `test_the_kill_points_cover_every_kind_of_call` gains `link` among
the kinds it asserts (crash_child.py counts `os.link` as `link`), so the sweep is shown to cut through a link. On a scratch
mergerfs pool in the VM (tests/test_pool_cut.py's way), the same batch with each disk put back at its own point, over a standing
manifest and over a lost one (section 1, item 6: a placed link copied again, an unplaced copy name removed by the comparison).

**The pool** (**VM gate**, `needs_mergerfs`): a link into a new folder whose old copy is on one branch and whose new folder was
made on another, run twice, once with the pool's policies set so mergerfs makes the link and once so it answers EXDEV (the builder
takes the settings from mergerfs's documentation and names them in the test); each run asserts which happened (one inode across
the two versions, or a copy after an EXDEV), never "linked or copied"; the oracle and the sizes either way; the folders mergerfs
makes for the link read with their times as the batch gave them.

**The real daemon** (**main session**, as round 21 measured the limitation: the daemon itself, a scratch job, in the test container
as uid 65534 or in the VM). `mkdir new; mv big new/` for a folder of 100 MB and for a file of 100 MB, `big` at the top of the
monitored folder and below it (`cd P`), at gaps of 0, 1 ms and 1 s between the two, with `mkdir` and `rename` as two system calls
of one program and as a shell's two commands; each again with a poke of one file of the folder before the move, between the two,
and after it. **The number it should show** (expected, until this run measures it): vault growth of the order of a move into an
existing folder, for the folder and for the file: 0.04 MB in round 21's measurement of that move, its folders' blocks and the
change lists, which this move makes too with one folder more, so under 0.1 MB, where today it is 102.44 MB for the folder and
100.11 MB for the file, at every gap; a poked file adds its own size; the entry's size-limit run (five small versions, then the
move, under a limit that holds them; today it left only the newest) keeps all five; one line a batch; the time spent in the replay,
against today's copy of the same. The measured figures are what 10.1's text is written with; one off them is a finding.

**Measurements in the build** (the builder's, in the container; the cold-cache ones in the VM, where the page cache may be
dropped): the compare against today's copy for one 1 GiB file, for a folder of 10,000 files of 4 KiB, and for a mixed folder (one
1 GiB file early in its walk and 10,000 of 4 KiB), warm and cold, on the compare pool as built; the names of a full comparison's
1,000,000 per-row deletes; the estimate's walk of a moved folder of 100,000 files with `leaving` and without. The figures go in
the handback; what they decide is in the Calls to confirm.

**Gates:** the whole suite in the container and in the VM, the mergerfs and power-loss tests, as the release gate has them.

## 10. Docs

The release is called 0.55.8 below (the round after 0.55.7; the number is the main session's). Each text replaces the one named,
in the commit of the code it describes (section 11). The build starts after Q24's and Q25's answers, so each narrowed or widened
entry's "Approved" is written with its answer (the user's words or pick and the date, or "chief's decision" and its date), where
`<Q24's answer>` or `<Q25's answer>` stands below. **[Q24]** (b): nothing is written. **[Q25]** (b): 10.2's estimate sentence and
line 31's estimate clause are not written (their links sentences are).

Nothing else changes: "A move that another change of the batch outran is copied", "A move into its own old place is copied
whole", "A move out of a folder that just left the tree is copied", "Swaps in one batch are repaired by copies", "A folder found
ahead of its events can reach the vault a version late", and README lines 17, 19, 39, 42, 43, 44 and 45 stay as they are: none
of those shapes gives the copy's path the name of one of the batch's delete entries, or its old copy is not in the version
(section 7 says why each stays a copy). Line 115 stays: it says a file restored under Only Sync Attributes carries the newest
metadata its shared copy has, which covers a linked file's too.

**No lessons entry is required:** no API, stored format or command changes shape (the change list, the manifest and the commands
are as they were; the log line is new and additive). The main session may add one line to docs/lessons.md: "prove a moved object
where it lands, by its bytes, not by the events that say it moved".

### 10.1 docs/limitations.md: "A folder or file moved into a new folder is copied whole" (narrowed)

```
### A folder or file moved into a new folder is copied where it cannot be linked

- **Kind:** known limitation.
- **What the operator sees:** `mkdir new; mv big new/` inside one quiet time reaches the backup as a delete of `big` and a
  copy of `new`, as nothing watched `new` when `big` arrived. From 0.55.8 each file of that copy is hard-linked from the
  version before in place of a copy, after a read of both, when the batch deleted an entry named as one of the file's
  folders, or as the file itself, and the file at the same place below that entry is the same, byte for byte and in its
  mode, owner, group, mtime and extended attributes. That covers a move to the same or another folder anywhere in the tree
  (`mkdir -p a/b; mv big a/b/` too), of a file as of a folder, a move made while reverberator was down that kept the
  entry's name, and a tree deleted and unpacked elsewhere under its own name with its times kept. One line a batch says so
  in the log (`Linked <n> files, <size>, from <version> in place of copies: ...`). An unchanged move linked so costs about
  what a move into an existing folder costs (0.04 MB for a 100 MB folder on the real daemon), and with a size limit it
  prunes nothing. Still copied, with no line: an entry renamed in the move (`mv big new/other`); two entries of one
  name deleted in one batch; a file changed in the move's batch (its contents, mode, owner, group, mtime or an extended
  attribute); every file of the move when its old place leaves the version after the copy (a batch the maximum delay takes
  while the move-out still waits for its pair, a move landing in the instant a batch is taken, or a folder moved into a new
  folder after a move out of it in the same batch, `mv d/g y; mkdir n; mv d n/d`), or in a batch cut before its commit and
  finished at the next start; the second of two new files that match one removed file; and, on a vault that refuses hard
  links or whose filesystem keeps other metadata than the monitored file has (an extended attribute it refuses or sets
  itself, an owner it cannot keep), every such file. Such a copy costs its size (a 100 MB file 100.11 MB), and with a size
  limit it can prune older versions to make room, as on 0.55.7, where every such move is copied.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, and a program's `mkdir` and `rename`, one right after the other, leave no moment in which the
  new folder has a watch. 0.55.1 was built to keep the arrival as a move; four reviews and the fix passes after them each
  found an order of events where the version then kept a file's old bytes for good, so 0.55.1 copied, as 0.55 does. From
  0.55.8 the copy proves each file's bytes and metadata by reading them, and links only what it proved, from a file the
  newest version holds no other name of; what it cannot prove, or what changed, it copies. A copy costs space and time; a
  wrong version loses a backup.
- **Revisit when:** a size-limited job's prunes follow such copies often, or moves that rename the entry show up in a real
  vault.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as on
  0.55, and the no-copy move gets its own design later. Narrowed to what the link cannot cover: <Q24's answer>.
```

The 0.04 MB in parentheses is the figure section 9's real-daemon run is expected to show (round 21's measurement of a move into
an existing folder), labelled so here until that run measures it: step 4 of section 11 writes the measured figure in its place,
and a figure off it is a finding.

### 10.2 docs/limitations.md: "Size estimates leave out a version's own small blocks" (widened, on Q25's answer)

In "What the operator sees", after "... and a move that falls back to a copy, so a vault can pass its size and inode limits by
those copies until the next prune.", insert:

```
  From 0.55.8 it also leaves out a file it expects the no-copy move to link: one whose place below an entry of the same
  name the batch deletes holds a file of its size, mtime, mode, owner and group. The replay copies such a file after all
  when its contents or extended attributes differ (a same-size rewrite with its mtime set back), when that delete removes
  nothing there (one the length rule keeps, or one whose place holds another kind), when it is the second of two new files
  that match one removed file, or when its link, a look or the read of it fails: on a vault that refuses hard links, or a
  pool that answers EXDEV between its disks, every such file.
```

And "The links a batch makes are in no size record:" becomes "The forward links (symlinks) a batch makes are in no size record:",
with, after that sentence, "A hard link of the no-copy move adds a name, no inode and no block of its own." In "Why", append:
"Charging a file the no-copy move links would prune versions for good for every move the replay links instead of copying, the
harm the no-copy move removes; an estimate too low only passes the limit until the next prune." In "Approved", append: "Widened
to a file the estimate expects the no-copy move to link: <Q25's answer>." **[Q25]** (b): only the links sentences, and "Approved"
is as it was.

### 10.3 README

- **Line 15**, its last clause "and moves made since the last backup before a stop are copied once instead of renamed." becomes
  "and a move made since the last backup before a stop is a delete and a copy: each file of the copy that is, byte for byte and
  in its metadata, the file at its place below the deleted entry of the same name is hard-linked from the version before (read
  twice, written never), so a move that kept the entry's name costs no copy, and the rest (a rename, say) is copied once."
- **Line 22**, its last sentence becomes: "A folder or file moved into a folder made in the same batch reaches the backup as a
  delete of its old place and a copy of the new folder, as nothing watched the folder when it arrived: each file of that copy
  that is, byte for byte and in its mode, owner, group, mtime and extended attributes, the file at its place below the deleted
  entry of the same name is hard-linked from the version before in place of a copy, after a read of both (one line a batch:
  Linked <n> files, <size>, from <version> in place of copies). An unchanged move so writes no copy and prunes nothing under a
  size limit; the rest is copied whole: a file changed in the move's batch, an entry renamed in the move, and the moves and
  orders the known limits below name."
- **Line 31.** "The links a backup makes are in no size record:" becomes "The forward links (symlinks) a backup makes are in no
  size record:", and after that sentence comes "A hard link of the no-copy move adds a name, no inode and no block of its own."
  On Q25's (a), "and of moves that fall back to a copy, which the estimate leaves out." becomes "and of moves that fall back to a
  copy, which the estimate leaves out; from 0.55.8 it also leaves out a file it expects the no-copy move to link, so a backup
  passes the limit by such a file when the replay copies it after all (its contents differ under the same size, mtime, mode,
  owner and group, say; on a vault that refuses hard links, every such file)."

## 11. Order of the build

The build starts once Q24 and Q25 are answered, on Q24's (a). **[Q24]** (b): nothing below is built. Each step is one commit whose
tests pass, with the docs of the code it adds.
1. Section 5: `BatchSizes` by rel with `linked()` and `alone()`, `link_kept()`, and `finish_copies()`'s link entry, with their
   tests, `test_alone_answers_for_each_kind_of_record` among them (nothing links yet).
2. Section 2: `released_names()` and `old_copy()`, with their tests (read by nothing yet).
3. On Q25's (a), sections 3, 4 and 6 together: `same_file()`, the compare pool and `copy_or_link()` (from here files link), the
   names built in `do_backup()`, `leaving`, and the log line. Either half alone breaks tests/test_moves_into_new_folders.py's two
   estimate tests (the copy step alone makes the vault grow less than the estimate, which then passes `grew`; the estimate alone
   charges fewer inodes than the names the replay copies). **[Q25]** (b): sections 4 and 6, with section 3's [Q25] (b) change of
   those two tests (`written <= grew <= est_size`, the inodes as today) and its pin; section 3's code is not built. With them:
   their tests, tests/test_moves_into_new_folders.py's other changes, and the texts of section 10 as Q24's and Q25's answers give
   them.
4. The measurements, the fuzz step, then the main session's VM gates (owner and group, crash and power loss, the pool) and the
   real daemon's measurement, whose figure replaces the expected 0.04 MB in 10.1's text in its own commit.

## Questions for the user

**Q24. Whether to build the no-copy move now** (docs/progress.md, as asked there). The route links a file from the version
before, in place of a copy, only when the version before alone holds it, it compares equal in full, and it has the same mode,
owner, group, mtime and extended attributes; open is whether to build it yet.
- (a) Build it (Recommended): on every kind of vault, and with Only Sync Attributes on or off alike, a file under a folder the
  batch copies is hard-linked from the version before when the batch deleted an entry of the same name and the file at the same
  place below it is the same, byte for byte and in its mode, owner, group, mtime and extended attributes. It reaches `mkdir new;
  mv big new/` and `mkdir -p a/b; mv big a/b/` anywhere in the tree, to the same or another parent, a moved file as a moved
  folder, a move made while reverberator was down that kept the entry's name, and a tree deleted and unpacked elsewhere under its
  name with its times kept. Still copied: an entry renamed in the move; two deleted entries of one name in one batch; a file
  changed in the move's batch; an old place deleted after the copy (the three orders the entry names); a cut batch's
  roll-forward; a vault that refuses hard links; and every copy fallback, as its own entry says. It narrows the entry "A folder or
  file moved into a new folder is copied whole" and README lines 15 and 22. What it builds: two small functions that find the old
  copy by the deleted entries' names, one predicate on the size books (`alone()`), the compare on a compare pool, the writer verb
  `link_kept()`, `finish_copies()`'s link entry, the estimate's `leaving` (Q25), the log line, their tests, and those texts; it
  touches neither the watcher, the manifest, nor how the writer records.
- (b) Not now: keep the entry and this design on file, and build it when a size-limited job prunes for such a move, or a job over
  a tree of user files is added. The study's look at how often such a move happens is in its report, which the main session gives
  with this question.
- Not offered: the earlier draft's key search, which looked, where the names find nothing, for a removed file of the same size,
  mtime, mode, owner and group anywhere in the batch. It would add moves that rename the entry and twins elsewhere, and only with
  Only Sync Attributes off (there a twin elsewhere would let a later attribute change of the new file show at the twin's place
  in the older version), so on a job with the default it does nothing; it needs a table of the removed files, an index and a
  bound. It can be a round of its own if moves that rename show up in a real vault.
- What waits on it: the whole build (section 11), and Q25, which (b) makes moot. The user's words: "Drop the feature
  (Recommended)" (2026-11-07), with "the no-copy move gets its own design later", and the pick of 2026-11-12 that gave it "its
  own design round after". (a) reaches beyond the move they named (a move made while down, an unpack elsewhere) by the same rule;
  (b) keeps it at the design round their pick gave, this spec; nothing they said is dropped.

**Q25. The size estimate and a file it expects the no-copy move to link** (asked with Q24; moot under its option (b)). With a size
limit, the estimate made before each backup decides how many old versions to prune for room. From this round it charges nothing
for a file the copy step will find (its place below an entry of the same name the batch deletes holds a file of its size, mtime,
mode, owner and group), so a move into a new folder no longer prunes older versions for a copy that is never made. Where such a
file is copied after all, the vault passes its limit by that copy until the next backup prunes. That happens for exactly these
four causes, on every kind of vault:
1. its contents or extended attributes differ from its old copy's (a same-size rewrite with its mtime set back; an extended
   attribute set in the move's batch, or one the vault refuses or sets itself);
2. its delete removes nothing there (one the length rule keeps, or one whose place holds another kind: a folder where a file was
   deleted, a file where a folder was);
3. it is the second of two new files that match one removed file;
4. its link fails (on a vault that refuses hard links, or a mergerfs pool that answers EXDEV between its disks: every such file,
   every time), or a look at it or its read fails with an error (EIO, say).
This widens the approved known limitation "Size estimates leave out a version's own small blocks", which already leaves out copies
of moved files and of moves that fall back.
- (a) Widen the entry (Recommended): the estimate stays at or below what the batch writes, as it is built to (a prune made for a
  copy never made removes a version for good; an overshoot lasts until the next prune). On a vault that links, the causes are a
  same size, mtime, mode, owner and group to the nanosecond over other bytes or other extended attributes, a delete the length
  rule keeps or that finds another kind at its place, a second copy of one file, or an error. On a vault that refuses hard
  links, or a pool that answers EXDEV, every move into a new folder passes the limit by its size until the next prune: no vault
  has shown a refused hard link yet (docs/limitations.md "A copy made where the vault refused a hard link"), and the pool test
  (section 9) shows which way mergerfs answers under the policies it names.
- (b) Charge every copy as today: no new overshoot, but with a size limit each move into a new folder still prunes older versions
  for the full moved size although it then costs nothing: "after five small versions, one such move left only the newest", the
  harm the entry names and half of the reason this round exists. Built so: section 3's code is not built (no `leaving`);
  tests/test_moves_into_new_folders.py's two estimate tests bound `written <= grew <= est_size`, their inodes as today; section
  3's tests give way to its pin `test_the_estimate_charges_every_file_the_replay_links`; 10.2's and line 31's estimate sentences
  are not written (section 11, step 3).
- (Not offered: comparing the bytes at the estimate too. It would read every moved file's two copies before the prune, and again
  at the copy.)
- What waits on it: section 3, docs 10.2 and README line 31, and the build, which starts after both answers. The user's words it
  would narrow: none; it widens an entry approved 2026-10-26 ("Known limitation (Recommended)") and widened since, last on
  2026-11-13 ("Widen the entry (Recommended)").

## Calls to confirm

Where this design departs from the study (`.superpowers/p3/study-report.md`, read against reverberator.py at e166baa):
1. **No table.** The study's index of what left (a temp table or a dict, filled before the estimate from the rows under the
   batch's delete entries, the rows under every move's source and target taken out) is not built: the old copy is looked up on
   disk in the version before, where its delete put it, and the monitored file gives the key. No SQL statement, no manifest
   method, no change to how the writer records.
2. **The names rule.** The study recommended pairing by size and mtime among every released file, and set aside "by name only"
   (a created path paired with a deleted entry of the same name and the same path below it) as reaching `mv big new/` and missing
   the rest. This design takes the name form, with the deleted entries' last names found in any part of the new path, so it
   reaches the named move anywhere in the tree, to any parent, a move made while down that kept its name, and an unpack
   elsewhere; it gives up what only the key search reached (call 13).
3. **The size books as evidence.** The study's "not the inode the tree still holds at that path", and its rows-under-moves
   exclusion, become `BatchSizes.alone()` (section 5), asked at the queue and again right before the link, which is also the
   claim-once. Its general claim is reasoned and its record kinds run in a probe; a test per record kind forces it (call 10).
4. **The key** is size, mtime, mode, owner and group (the study: size and mtime), read from the version before's file, so a
   chmod or chown made with the move is charged and copied without a compare.
5. **"A tree deleted and unpacked again with its times kept"** is reached only when unpacked at another path: at its own path a
   delete and a create collapse into the create (`change_events_to_backup_entries()`), so the batch holds no delete.
6. **"Deletes replay first"** has `order_backup_entries_for_replay()`'s exception: a delete at or above a move's source can
   replay right after that move, after the creates; such a delete gives no name, and `mv d/g y; mkdir n; mv d n/d` stays a copy.
7. **The size books:** "on a pool / off a pool" is "on two renames / off them"; `BatchSizes.shared` is keyed by rel, so that
   `linked()` and `alone()` tell a file a hard link took in (in `shared` already) from one a rename or an exchange took in by
   `shared` itself, not by `two_renames`, which an exchange that fails can still turn on in the middle of a batch.
8. **The test plan:** TIMINGS are two (`apart`, `unread`) plus the `at_once` stress test, not three; the 32 shapes' test asserts
   the version equals the tree, never "copied" (the copy expectation lives in
   `test_a_folder_moved_into_an_existing_folder_costs_no_copy_and_into_a_new_one_a_copy` and the two estimate tests, which
   change); the watcher fuzz already moves into new folders, so only the twin step is new.
9. **The reach** is narrower than the study's in three places: a move that renames the entry, the moves that fall back to a copy
   today, and a move into its own old place stay copies, and their entries stay as they are (section 7).

The step back's calls, made in this spec:
10. The evidence that the tree let a file go comes from the size books (`alone()`), not from a feed at the deletes; nothing is
    fed, reported or recorded first, and `record()`, `pre_record()`, `replay_ops()`, `delete_path()` and `verify()` are not
    touched. `alone()` was run, with the real `hand_over()` and `TreeWriter` on scratch files, off two renames and with
    `pooled=True`, for the record kinds section 5 lists, and is reasoned in general; the spec check should aim at it. If a hole
    is found, the fallback is what each delete took, kept as a set of rels beside the names, with no table.
11. The old copy is found by the batch's top-most delete entries' names, one rule on every job, with Only Sync Attributes on or
    off; an ambiguous name is a copy. The uniqueness rule is a call for a bounded cost, with no number; a tie rule (the entry
    sharing the most leading folders with the new path) is possible later, once something needs it.
12. The copy fallbacks, the verification's deletes and a roll-forward give no names and are not predicted; their entries and
    README lines stay as they are. A fallback's or the verification's copy can still link where its path holds a name of the
    batch's own delete entries; the estimate leaves those copies out, or (a move into its own old place) charges them through
    the same lookup, so that lowers nothing it charged.
13. The key search of the earlier draft, and with it the wider reach off Only Sync Attributes (moves that rename, twins
    elsewhere, `z` of `mv d D; mv D/k z; rm -r D`), is not built and not offered in Q24 (Q24 says why).
14. The draft's rule "only rows recorded checked" is dropped. The old copy is a file the last commit recorded; a copy an older
    release left unchecked is made "checked" only by a read-back through the same page cache (`compare_entry()` ->
    `read_vault_record()` -> `hash_file()`, 64 KiB of it), and a linked file's row is read back at its commit the same way
    (`record_dirty_entries()`), so "checked" promised no more than the compare, which reads every byte. Keeping it would need a
    manifest lookup per delete entry before the replay.
15. Under Only Sync Attributes a later attribute change synced onto a linked file shows at its old place in the version before:
    for a move, the moved file's own old copy, as for a renamed file; for a file that is only the same at the same place below
    a same-named deleted entry (a `cp -p` and the original removed, a tree unpacked elsewhere), that file's. README line 115
    already says a restored file under Only Sync Attributes carries its shared copy's newest metadata. The draft kept twins
    elsewhere out under Only Sync Attributes by a second rule; the names rule allows only this one, on every job.

Calls of the parts kept from the draft:
16. The compare runs in parallel on a compare pool of `COMPARE_THREADS` threads, with `compare_scopes()`'s window, settling
    whichever compare ends first; it opens the monitored file once and compares its metadata and bytes through that handle; the
    link is made on the replay's thread when the window settles it, the copy queued there when it differs; the replay's `finally`
    sets the batch's `cancelled` flag, which a compare looks at between blocks, then shuts the pool down. Not `cmp -s` on the copy
    executor: it follows a link and blocks on a FIFO at the monitored path. If a link is slower in wall time than the copy it
    replaces on some shape, that is a finding for the main session (the light way against the fast way), not something the
    builder tunes.
17. A compare takes no `BACKUP_SEMAPHORE` permit: its pool bounds it, as `record_dirty_entries()`'s and `compare_scopes()`'s bound
    theirs; with `--threads 1` a batch may read with up to `COMPARE_THREADS` compares beside its one copy, as a comparison does
    today.
18. No set of held or claimed old copies: two new files that pair with one old file are both compared, and the one settled
    second finds `alone()` False and is copied. A file whose key matches an old copy of other bytes costs up to two reads more
    than today's copy (the compare stops at the first difference): bounded, and rare enough (same size, mtime, mode, owner and
    group) to be Not an issue.
19. `entry_metadata()` takes an open fd as well as a path, so the compare reads metadata and bytes through one handle.
20. A link sets no `copies_unsynced`: a batch of links alone, off a pool, commits without the flush of the vault's disks.
21. Metadata that differs is a copy, with no sync onto the shared inode even under Only Sync Attributes (the study's call, kept).
22. Access times are not compared: `entry_metadata()` leaves them out, and a renamed move keeps the old inode's atime too.
23. History keeps showing a delete and a create for such a move (0.55.7's section 9 reads the link as an applied copy).
24. One line per batch that placed a link, counted at placement, a plain info line, its wording in section 6.
25. 0.55.7's growth leave-outs (Tasks 3 and 4) give no names; a file one of them takes into the version before at a name's old
    place is alone there as a delete's take is, and the estimate saw the same file.
26. One heading changes: "A folder or file moved into a new folder is copied whole" becomes "... is copied where it cannot be
    linked" (docs/progress.md's P3 names it by its old heading). 10.1 states the cost of an unchanged move with the figure the
    real daemon's run measures; until that run, the text carries the expected 0.04 MB (what a move into an existing folder
    costs), labelled as expected in this spec, never a placeholder.
27. The release is called 0.55.8 in the docs texts; the number is the main session's.
28. The found-folder tests of tests/test_moves_into_new_folders.py whose names say copied assert the link the code gives (their
    batches are taken quiet and hold the move-out's delete), and their names say linked.
29. tests/test_job_startup.py's `test_a_stop_saves_nothing_and_the_start_makes_one_version` keeps its assert of a copy (line 309):
    a rename made while down gives no old copy, on every job.
