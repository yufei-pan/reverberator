# The no-copy move into a new folder (P3)

A move into a folder made in the same batch (`mkdir new; mv big new/`) is copied whole today when the watcher does not see it as
a move (a move it pairs is renamed), though the vault already holds every byte of it. This round makes that copy hard-link each
file whose old copy the batch's own delete put into the version before: the file at the same place below the deleted entry of
the same name, when the version before alone holds it and it is the monitored file byte for byte and in its metadata. Everything
else is copied as today. The result on disk is the state a move leaves (one inode, named at the old path in the version before
and at the new path in the new one); it trusts no event and no watch, and its worst case is the copy made today.

Built as its own round after round 0.55.7, on a branch of its own from the merged 0.55.7, as that round rewrites the replay's
looks (its section 7), the change list (section 9) and the length rule (section 1) around the same code. The build starts only
once Q24 and Q25 are answered (Q25 is asked with Q24), so no text is written with a placeholder. "Today" below means 0.55.6,
branch `r0556`. Functions are named first; line numbers are of reverberator.py at e166baa (18,251 lines), the file 0.55.7
builds on, and 0.55.7 moves them.

Why this way: a design study (2026-11-23, read-only, `.superpowers/p3/study-report.md`, which also holds how often such a move
happens) found that no route in the watcher can reach the case (a program's `mkdir` and `rename` leave no moment in which the
new folder has a watch, and every fix of 0.55.1 that filled that gap kept wrong bytes in some order of events), while a route
at the copy needs no event: it reads the bytes, the only proof (the manifest's size, mtime and tail hash survive a same-size
rewrite with the mtime set back). A step back then found an earlier draft's table of released rows unneeded, as the batch's
delete entries name what left, the version before holds it where its delete put it, and the size books know whether the tree
let it go: this spec is written on that design.

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
pytest as root on the host, and root, loop and mount tests in reverberator's own test VM (2026-11-09); the headroom rule; the
mergerfs and power-loss tests in the release gate (2026-11-08); the scrub before every push; a cold measurement from the live
backups after a deploy, not from flushing a page cache ("Use the live backups (Recommended)", 2026-11-03).

## Summary

| § | Part | Code it touches | Adds | Removes |
|---|---|---|---|---|
| 2 | Which old copy is looked at | new `released_names()` and `old_copy()`, module functions; `do_backup()` builds the names | a dict of names per batch; a dict lookup per part of each copied file's path, and looks on disk only where a part is a name | nothing |
| 3 | The estimate | `do_backup()` (its call of `get_backup_size_inode()`), `get_backup_size_inode()`, `get_unskipped_size_inodes()` | a file the copy step will find is charged nothing | nothing |
| 4 | The copy step | `do_reverb_backup()`'s `copy_path()` (its two `writer.copy()` calls); a new `same_file()` beside `hash_file()`, with `hash_file()`'s opener moved out as `no_follow_opener()` and a new `read_block()`; `entry_metadata()` and `xattr_names()` (of an open handle too) | a check, a full compare of metadata and bytes on the replay's thread holding a `--threads` permit, then the link or the copy | nothing |
| 5 | The writer's verb and the size books | new `TreeWriter.link_kept()` and `links_refused`; `BatchSizes` (`shared` by rel, new `linked()` and `alone()`, its docstring); `finish_copies()` (a link already made) | one verb, two methods of the books | nothing |
| 6 | The log line | end of `do_reverb_backup()` | one line per attempt of a batch whose version holds a link | nothing |
| 10 | Docs | README lines 4, 15, 22, 31 (its estimate clause on Q25's answer), 43 and 115; three docs/limitations.md entries | the narrowed main entry, the estimate entry widened (Q25), one sentence of the name rule's reach | the claim that such a move is always copied |

No change to the watcher, the manifest (no table, no statement, no stored format), the change list or any command, and none to
`TreeWriter.record()`, `pre_record()`, `replay_ops()`, `delete_path()` or `verify()`. One number is added, the compare's block
of 256 KiB, with its reason (section 4). State at rest: none, on disk or in memory. Per batch: the names (a few strings), the
compare's two block buffers, a flag for a vault that refuses links, whether a compare has raised, and the links made;
`BatchSizes.shared`, which exists today. One new question, Q25 (the estimate), besides Q24.

## 1. The rule that keeps a version right

> A file the replay is about to copy is linked only from its old copy: the regular file at its place below a deleted entry of
> the same name in the version before (section 2), which the version before alone holds (section 5), whose bytes compare equal
> in full to the monitored file's, and whose mode, owner, group, mtime and extended attributes are the monitored file's.
> Everything else is the copy made today.

The first half keeps the vault's shape a move's shape: one path per inode in a version. The second half makes the version's
bytes and metadata the ones a copy would have written, its access time aside. Access times are not compared: `entry_metadata()`
leaves them out everywhere, and a renamed move keeps the old inode's atime too, so a link leaves the atime a move leaves.

**Why no order of events can give a version worse than today's copy.** For each file the replay copies today, the version now
gets either that copy (today's code, unchanged) or a link to a file whose bytes and metadata were just compared equal to what a
copy started at that moment would have read and kept: the compare opens the monitored file once and reads its metadata
(`fstat()`, its extended attributes through the handle) and then its bytes through that one handle, as `cp` reads one file. A
change after the open is a change after the take, which the next batch backs up, as it would after a copy that read the file
then. So for every order of events and every state of the tree, the version's contents are those today's copy would produce, and
the walk that decides which files are copied is today's. Which old file was tried does not matter to the bytes: any file with
the same bytes and metadata is a true stand-in, so the name that picks it may be wrong as often as it likes and costs only a
compare. No event, watch, inode number or record of the monitored file is trusted for the bytes. An older version's file
changes later only as round 19's rule lets a shared inode change (`specs/2026-11-04-round19-vault-r-design.md` section 2.4: a
change may reach other versions sharing the inode, never a second path of the same version): under Only Sync Attributes a later
attribute change of the new file, synced onto the shared inode, shows at the old place in the version before, as after a
renamed move. That is what the first half guards: a link to an inode the tree still holds would give one version two paths on
one inode, and a change synced onto one would reach the other.

Every order that kept wrong bytes in rounds 21 and 22 (tabulated in this spec at 221a531, section 1) came from inferring, from
the watcher's map or a walk's view, that the entry at the new place is the one the vault holds; this route infers nothing from
events and adds no rename, and its tests replay the twin, the poke and a write during the compare (section 4).

**The new orders this route could open, and the rule that closes each.** Each has its own test (section 9).

1. *Two paths of one version on one inode.* A move never leaves that. Rule: the old copy is linked only while
   `BatchSizes.alone()` (section 5) says the version before alone holds it, asked before the compare and again by `link_kept()`
   itself right before the link; the link then tells the books, so a second new file that pairs with the same old file finds
   it held and is copied. A renamed move's source, which the tree keeps at the move's target, gives no name (a delete at or
   above a move's source is left out, section 2), and were it looked at, `alone()` would answer no.
2. *Metadata of another file.* A link shares mode, owner, group, times and extended attributes. Rule: link only when
   `entry_metadata()` of the monitored file and of the old copy are equal; anything else is a copy (docs/lessons.md: "never
   write a change signal (an mtime, a hash, a version stamp) onto data it did not come with; when in doubt, copy").
3. *The file changes while it is compared.* The same as a file changing while it is copied: the version holds bytes that were
   read, through the one handle whose metadata was compared, and the write's event comes after the take and is backed up by the
   next batch (events in a folder made during a batch are recorded again from the take on). A write into a part already
   compared leaves the old bytes, consistently; a copy at that moment would hold a mix. A file replaced at its path during the
   compare is not read: the handle stays on the file it opened; and `link_kept()` links only the inode the compare read of
   the old copy (section 5).
4. *A link the vault refuses* (`NO_HARD_LINK_ERRNOS`, reverberator.py:12275: EXDEV, EPERM, ENOTSUP, EOPNOTSUPP, EMLINK,
   ENOSYS), or any other error of the link: copy. `link_kept()` takes its own errors, every OSError a copy; it does not go
   through `link_or_copy()`, which raises outside that set and copies within it. After the first link refused with EPERM,
   ENOTSUP, EOPNOTSUPP or ENOSYS (a filesystem that has no hard links), the rest of the batch copies with no compare; EXDEV (a
   pool's branches) and EMLINK (one file's link limit) stay per file (section 5).
5. *The size books.* `BatchSizes` counts an inode in the newest version that holds it; a link back into the tree takes the old
   file back from the version before (section 5).
6. *A cut batch.* The link is made under the copy's temporary name and placed by `finish_copies()`, as a copy is, so a cut
   before the commit leaves it as what the batch made. The next start's repair gives the tree the old file back at its old place
   and, off a pool or over a manifest that describes the version before, removes every name the version before's folder does
   not list (`put_back_recorded()` pass 2, reverberator.py:7239), the link among them. On a pool over a lost manifest that pass
   does not run (`remove_made` False, 7506): a placed link is copied again by the roll-forward (`new_in_tree()` lists it), and an
   unplaced copy name is a row of the rebuilt manifest that the roll-forward's comparison finds gone and removes. Either way the
   roll-forward copies the moved files, as it has no names (section 2). Read in the code; the crash gates run through it.
7. *A look that cannot answer.* A look at the version before or at the monitored file that fails (EIO, EACCES) never reads as
   "there" or "equal": it chooses the copy (round 0.55.7, section 7, for why "not there" may not stand for an error). So the
   looks are `real_folders_to(strict=True)` and `os.lstat()`, which raise, never `os.path.lexists()`, which answers False on
   EIO and EACCES.
8. *Bytes the vault never flushed.* The compare reads through the page cache, which can hold right bytes over a disk that never
   got them: an old copy an older release left unchecked, or a copy a record of this batch made where hard links were refused
   (`keep_entry()`). A placed link sets `manifest.copies_unsynced` as a placed copy does (`finish_copies()` unchanged), so the
   commit flushes the vault's disks before its commit point whatever the old copy is, as for the copy the link replaces, and
   the new version's row of the link is recorded checked from the commit's read-back of its tail (`record_dirty_entries()`), as
   a copy's is; that function's docstring, whose reason is that the commit flushed every copy, names a placed link beside them.
   A link saves the copy's bytes and writes, not the flush. The draft's rule "only rows recorded checked" goes.

## 2. Which old copy is looked at

**What it does.** For each regular file `copy_path()` is about to copy, a lookup led by the names of the entries the batch
deleted, made on disk in the version before only where a part of the file's path is such a name. `copy_path()`'s two
`writer.copy()` calls (14798, 14804) are the only places it is made: the attrib branch's copy (15025) and the move branch's
(15107) are not looked up (section 4). Nothing is filled, searched or kept between batches.

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
  mode, owner and group is returned; else None. ENOENT and ENOTDIR are "not there": the old path's `os.lstat()` so takes
  both, and the strict folder look answers ENOTDIR so from 0.55.7 (today it raises it). Any other error of a look is
  raised: OSError from the old path's `os.lstat()`, 0.55.7's `VersionLookError` from the folder look (section 8); each caller
  takes either as "none" (sections 3 and 4).
- `do_backup()` builds the names once, right before its estimate (6399-6407), when the batch is not a roll-forward (`tree is
  None`) and holds a delete and a create or a modify; otherwise they are empty. It passes them to the estimate (section 3) and
  to `do_reverb_backup()`, which gains the keyword `names` (empty by default). **[Q25]** (b): they are built and passed to
  `do_reverb_backup()` the same way, and not to the estimate.

**Why the names, and which.** A delete entry names what left the tree, and its record put that into the version before at the
same path (`TreeWriter.record()` renames a file in or exchanges a folder in whole, and on two renames hard-links it in before the
rm), where an `lstat()` finds it. A delete under another adds no old place, and a full comparison lists a delete for each row
it did not see, so only the top-most count: a moved folder is one name however many rows it had. A delete at or above a move's
source can replay behind that move, after the creates (`order_backup_entries_for_replay()`'s exception); it gives no name
whichever way it replays, so the estimate and the copy agree. A name two deleted entries share would point two ways: both are
copied, as today.

**Reach.** It finds the moved entry's own old copy wherever the move kept the entry's name: `cd P; mkdir new; mv big new/`,
`mkdir -p a/b; mv big a/b/`, a move to another parent (`mkdir Q/n; mv P/big Q/n/`), a moved file as a moved folder; a move made
while reverberator was down that kept its name (the start's full comparison lists the deletes and the creates); and a tree
deleted and unpacked elsewhere under its own name with its times kept. By the same rule it links any file whose path holds a
deleted entry's name and that is the same as the file at its place below that entry, whatever brought it there: a part of a
folder that left the tree, moved back in the same batch to its own place below a folder of that folder's name (`mv P/X /out/X;
mkdir -p Q/X; mv /out/X/sub Q/X/`), or a saved copy put back under the name of a file the batch removed (`rm other; mkdir n;
cp -a <saved copy of other> n/other`). Each is a true stand-in (section 1). What it does not find is section 7's list.

**Cost.** In the step back's probe (paths 8 deep): a file whose path holds no name costs one dict lookup a part, 0.25 µs, with
100 names as with none, and no look on disk; a part that is a name costs `old_copy()`'s looks, a hit about 4 µs before the
compare; the names of 110,100 delete entries (a full comparison's per-row deletes of 100 folders) took 21 ms. No SQL, no index,
no bound; at most one compare a file.

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
- `do_backup()`, when the names are not empty (a roll-forward's are always empty), defines

  ```python
  def leaving(rel, st):
      try:
          return old_copy(names, rel, st, tree_now) is not None
      except (OSError, VersionLookError):
          # a look that cannot answer: charged, as the copy step copies it
          return False
  ```

  and passes it as `get_backup_size_inode(..., leaving=leaving)`; else `leaving` is None.
- `get_backup_size_inode(..., leaving=None)` passes `leaving` to `get_unskipped_size_inodes()` (11759) only for the walks of
  what `copy_path()` copies: the main walk's call for a create or a modify entry of `taken`, every call of the `carried_in`
  subtraction (it takes back what a created folder's walk charged, through `leaving` too, so the two cancel), and the `written`
  add-back's call for a create or a modify entry. Never for an attrib entry, in `taken` or in `written`: the replay copies it in
  its attrib branch, which never links.
- `get_unskipped_size_inodes(..., leaving=None)`: a regular file (`S_ISREG` of the lstat it makes already) for which
  `leaving(rel, st)` is true is charged nothing, no bytes and no inode: the entry itself when it is a file, and each file of a
  folder's walk. `rel` is the one the function already forms, so no `os.path.relpath()` runs per file: the entry's own
  `os.path.relpath(path, monitor_path)`, which its length rule's call computes (kept in a local), and for each walked file
  `base + rel` of the walk's yield, as its `skip` forms it. A hard link adds a name in its folder, no inode or data block.
- **[Q25]** (b): none of this is built; the estimate charges every copy, as today.

**Why it stays at or below what the batch writes.** The estimate errs low, never high: an estimate too low only exceeds the
limit until the next prune, while a copy the estimate charges and the replay never makes prunes versions for good (the reason
the size entry gives). It looks at `tree_now` (6401: `latest_version_info.path if tree is None else tree`), which in every batch
with names is `latest_version_info.path`, before the hand-over, and `hand_over()` leaves the version before at that same path
(14263). The deletes that give names replay first (`order_backup_entries_for_replay()`; on two renames `pre_record()` records in
that order; only 0.55.7's growth leave-outs record before them, taking the tree's file just the same, section 8), and each
record takes the tree's entry into the version before at its own path with its size, mtime, mode, owner and group. So every
file the replay links was found by the same function, names, path and key when the estimate asked, and left uncharged
(reasoned from `order_backup_entries_for_replay()`, `record()` and `hand_over()`; barring a file changed between the two
walks, as today). The
verification's copies and the copy fallbacks are left out of the estimate, as today, but for a move into its own old place,
whose target the created folder's walk charges (the `carried_in` exception) through `leaving` like any file of that walk. A
roll-forward has no names: its estimate is exact, as today.

The estimate also leaves uncharged some files the replay copies after all, and is low by each: the vault can exceed its limit
by them until the next prune (Q25). Beside the copies it leaves out today (a moved file's, a fallback's, which stay as they
are), these are four new causes, on every kind of vault (a hand edit of the vault during a batch is outside this claim, as it
is outside the size books'):
1. the file's contents or extended attributes differ from its old copy's under the same size, mtime, mode, owner and group (a
   same-size rewrite with its mtime set back; an extended attribute set in the move's batch, or one the vault refuses or sets
   itself), or the file changed after the estimate's walk: then the estimate misses its whole size, where today it misses
   only its growth;
2. its delete removed nothing there: `delete_path()` leaves an entry the length rule keeps (`left_out(kept=True)`), and one
   whose place holds another kind (a folder where a file was deleted, a file where a folder was). Behind a link, or with a link
   at its place (which its record takes into the version before), `old_copy()`, looking through real folders at regular files
   only, finds no file before the hand-over or after it, so the estimate charges what the replay copies;
3. it is the second of two new files that pair with one old file;
4. its link fails (a vault that refuses hard links, or a mergerfs pool that answers EXDEV between its disks: every such file,
   every time), or a look or the compare meets an error.

A chmod or chown made with the move (`mkdir n; mv big n/; chmod -R g+w n`) changes the key, so the file is charged as the copy
it is. An owner the vault cannot keep shows in the vault's own file, so its key differs there too.

**State.** None beyond the names.

**Failure cases.** A look that cannot answer charges the file, as the copy step will copy it. A file gone or changed between the
estimate and the copy: the estimate is what the walk saw, as today (cause 1 for a file it left uncharged).

**Cost.** Only in a batch that both deletes and creates or modifies: one dict lookup per part of each regular file's path the
walk lstats already, and for each part that is a name the looks of `old_copy()`, found or not.

**Tests** (tests/test_no_copy_move.py, `unit`; tests/test_estimate_charge.py's helpers):
- `test_the_estimate_charges_no_file_of_an_unchanged_move_into_a_new_folder`: a delete of `big` and a create of `n/` holding
  it, and the same below the top (`P/big` to `P/n/big`), off and on two renames: the estimate is `n`'s folders' charge alone;
  under a size limit with five small versions, all five stay.
- `test_the_estimate_charges_a_file_changed_in_the_move` (appended, its size moved) and
  `test_the_estimate_charges_a_file_chmodded_in_the_move` (its mode differs from the old copy's).
- `test_an_attrib_copy_is_charged_whatever_its_path`: with Only Sync Attributes off, a chmod of a file whose path holds a
  name: its attrib copy is charged.
- `test_a_renamed_move_is_charged` (`mkdir n; mv f n/g`: charged, and copied).
- `test_the_estimate_is_never_above_what_the_batch_writes` (a parametrized pin, off and on two renames): a move into a new
  folder from the top and from below it, the same with the entry renamed, at a start's full comparison, a move into its own old
  place, a move a folder move outran (`mv d e; mkdir e/sub; mv x e/sub/x`), a delete behind a move (`mv d/g y; mkdir n; mv d
  n/d`), two creates pairing with one deleted file, and two deleted entries of one name: estimated bytes and inodes at most the
  vault's growth (`sizes_by_newest_holder()`).
- Q25's pins, one per cause (the estimate leaves the file out, the replay copies it):
  `test_a_predicted_link_whose_bytes_differ_is_copied_uncharged`,
  `test_a_predicted_link_whose_delete_removes_nothing_is_copied_uncharged` (the length rule keeps the delete; a folder where a
  file was deleted; a file where a folder was), `test_a_second_file_that_pairs_with_one_old_file_is_copied_uncharged`, and
  `test_a_predicted_link_the_vault_refuses_is_copied_uncharged` (an `os.link` stand-in answering EPERM).
- `test_a_roll_forward_charges_every_copy`: a batch cut after its hand-over and before its commit, then rolled forward: the
  estimate charges `n`'s files, and the replay copies them.
- tests/test_moves_into_new_folders.py's `test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one`
  and `test_the_size_estimate_counts_the_attribute_copies_under_a_folder_moved_into_a_new_one` change: their estimated inodes
  are the names in `n` less the files linked (all of `big`'s but those the row writes or changes), plus the probes. Their
  bounds stay: the first's `written <= est_size <= grew`, the second's `15 << 20 <= est_size <= grew` (the touched and
  chmodded rows keep it, as the mtime and the mode are in the key). **[Q25]** (b): the estimated inodes stay the names in `n`
  plus the probes, and the bounds become `written <= grew <= est_size` and `15 << 20 <= grew <= est_size`, as the estimate
  charges the files the replay links.
- tests/test_folder_times.py's stand-in for `get_unskipped_size_inodes()` (`lambda path, *args`, line 468) takes the
  `leaving` keyword too (`lambda path, *args, **kwargs`, passed on). **[Q25]** (b): unchanged.
- tests/test_estimate_through_a_take.py's three tests stay: their batch holds no delete, so it has no names.
- **[Q25]** (b): of these only `test_the_estimate_charges_every_file_the_replay_links` (a move into a new folder: the estimate
  charges `big`'s files, the replay links them) and the two changed tests above.

## 4. The copy step

**What it does.** Before a regular file's copy is queued, the replay looks for its old copy, checks that the version before
alone holds it, and compares the two in full, metadata and bytes, on its own thread; an equal compare becomes a link in place of
the copy, and anything else is the copy made today.

**Where.** `do_reverb_backup()`'s `copy_path()` (14744) queues a file's copy at two places: the file branch
(`writer.copy(source_real_path, source_relative_path, mcae, pending)`) and the folder walk (`writer.copy(subRealPath,
subRelativePath, mcae, pending)`). Both call a new helper of `do_reverb_backup()`, `copy_or_link(source_path, rel, mcae)`, in
its place. Everything `copy_path()` does before them stays: the source's look, the length rule (the link is written under a
name of the copy's length), the untracked folder above, the folders made, the row added dirty, so the commit records it as a
copy's (`record_dirty_entries()`, 11116). Every create and modify the replay copies comes through `copy_path()`: the batch's
own, a created folder's walk, `copy_untracked_folder()`, a copy fallback's, the verification's and `recheck_moved_folder()`'s.
The attrib branch's copy and the move branch's copy of a moved file whose metadata changed stay copies.

`copy_or_link()`, on the replay's thread, each step choosing the copy (`writer.copy()`, as today) when it fails:
1. The names are empty, or `writer.links_refused` (section 5): copy, with no look.
2. No part of `rel` is a name (one dict lookup a part, no look on disk): copy. So a file that is no move's costs no look more
   than today: `copy_path()`'s own `os.path.lexists()` stays its one look, also in a batch that deleted a temporary file.
3. `st = os.lstat(source_path)`: not a regular file: copy.
4. `old = old_copy(names, rel, st, writer.previous)`: None: copy.
5. `writer.sizes.alone(old, writer.two_renames)`: False: copy.
6. `kept = same_file(source_path, writer.kept_path(old), blocks)`, the batch's two block buffers made at its first compare. It
   sits in a `try` of its own: a JobFailure is raised on, and any other exception (a ValueError, say; `same_file()` answers an
   OSError itself) is None, the batch's first such logging an error line with its traceback, as the move branch's `except
   Exception` does (15123-15128), so a fault that turns every link into a copy shows.
7. `poll_pools()`, once: a pool disk that dropped during a long compare is found before the link or the copy writes, as the
   walk's poll before each copy finds it today.
8. `GREEN_LIGHT` clear (the daemon stopping, which `same_file()` saw between blocks): neither a link nor a copy for the file;
   the replay goes on as after any stop, its waits returning at once and placing nothing, and `do_backup()` leaves the batch to
   the next attempt.
9. `kept` is not None and `writer.link_kept(old, source_path, rel, pending, kept)` (section 5) answers True: the link, kept with
   its old path and size for the log line (section 6). Else a copy.

An OSError at steps 3 to 5, and 0.55.7's `VersionLookError` from the strict folder look, is caught there and chooses the copy
(section 1, item 7). `link_kept()` is outside every `try`: its JobFailure (a record or a flush that failed) fails the attempt as
`copy()`'s does, as the move branch raises its own (15114). The compare and the link are one step of the replay's thread, where
the copy would be queued: the folders above `rel` stand as `copy_path()` made them, no compare is open at a delete, a move or
the verification, and a link waits for its placement as a copy does (section 5).

**`same_file(source, kept, blocks) -> 'tuple | None'`**, beside `hash_file()` (11674): the kept file's `(st_dev, st_ino)`,
from its handle's `fstat()`, when the two are equal; else None.
- *The permit.* It takes one `BACKUP_SEMAPHORE` permit for its opens and reads, as a copy's `cp` holds one, waiting as
  multiCMD's dispatcher waits (`acquire(timeout=0.1)` in a loop) and giving up, None, when `GREEN_LIGHT` is clear. A
  `try`/`finally` gives it back whatever ends the opens and reads, before `same_file()` returns, so the link or the copy that
  follows holds none (one lost would stop every copy under `--threads 1`). So `--threads` bounds the compares' whole-file reads
  as it bounds the copies, across the daemon's jobs. No wait closes a circle (read in multiCMD 1.51): multiCMD takes a copy's
  permit on its dispatcher's thread and gives it back when the copy's command ends (`_HeldPermit.__exit__`), not when a wait
  reaps it, and the replay's thread holds one only inside `same_file()`, which waits for nothing but its two files;
  `do_backup()`'s note on `BACKUP_SEMAPHORE` (~6184) gains that.
- *The opens.* Each file is opened once, unbuffered (`open(path, 'rb', buffering=0, opener=no_follow_opener)`, a `FileIO`, so
  no buffered state lies between a seek and a read), through `no_follow_opener(file, flags)`, `hash_file()`'s inner `opener()`
  moved out to a module function both use: no link followed, never a blocking open of what is not a regular file, and a write
  lease waited for as `cp` waits (the kernel's lease-break time, 45 s by default, or a network filesystem's own period), holding
  the permit as a `cp` on the same lease holds its own. After each open, `hash_file()`'s next two steps: a handle that is not a
  regular file is None, and `O_NONBLOCK` is cleared, as a filesystem may pass it on to reads.
- *The metadata.* It compares `entry_metadata()`'s tuple of each, read from its handle, as the move branch's
  `only_attributes_differ()` compares them (14877): mode, owner, group, mtime and extended attributes, and the two handles'
  sizes; unequal: None. `entry_metadata()` and `xattr_names()` take a path only today; they take an open fd too, and on an fd
  call `os.fstat()`, `os.listxattr(fd)` and `os.getxattr(fd, name)` with no `follow_symlinks` (an fd names its file, and Python
  raises ValueError for an fd with `follow_symlinks=False`), keeping `xattr_names()`'s rule for a filesystem without them.
- *The bytes.* Then it reads both through those handles, a block at a time, by `read_block(f, buffer) -> int`, a module
  function that calls `f.readinto()` until the block is full or the file ends (an unbuffered read may return short; 0 at the
  end), into `blocks`, two `bytearray`s of 256 KiB, and compares them with `==` (a memcmp; a memoryview's `==` goes item by
  item, about 70 times slower in a probe), a short last block by its slices. 256 KiB is coreutils' own read size (its
  IO_BUFSIZE: coreutils 9.7's `cat` reads 262,144 bytes at a time), so the compare reads as `cp`'s family does; section 9
  measures it against 1 MiB.
- *Holes.* Where both files are sparse (each fstat's `st_blocks * 512` below its `st_size`), after each block both handles seek
  to their next data (`f.seek(pos, os.SEEK_DATA)`; ENXIO is no data to the end) and both go on from the nearer: the range
  between is a hole in both, zeros in both, so skipping it compares what reading it would; both at their ends are equal, as
  their sizes are; a filesystem that cannot tell holes answers every range as data. So a sparse image is compared by its data,
  as `cp --sparse=always` copies it; a dense file costs no seek, and one that reads as sparse with no hole (a compressed or an
  inline file) a seek pair a block.
- It answers None at the first block that differs, at a length that differs, at any OSError, and when `GREEN_LIGHT` is clear,
  looked at between blocks. The opener and `read_block()` are the seams the tests stand in for.

A compare reads both files' data where a copy reads one and writes it; one large file holds the replay's queueing behind it
while it reads, as the copies queued before it run on; the build measures it against today's copy (section 9).

**State.** Per batch: the two block buffers, whether a compare has raised (the one error line), and the links made (section 6);
`links_refused` is the writer's (section 5). No set of claimed or held old copies: `alone()` at the link is the claim. Nothing
at rest.

**Failure cases.** Each chooses the copy, which then fails or succeeds as today:
- the source gone or replaced since the walk listed it (step 3, or the compare's open): the copy's own failure keeps the last
  backed-up copy, or, gone, the row goes with today's line;
- no old copy, or one the version before no longer holds alone, or one that cannot be looked at;
- metadata or bytes that differ, an unreadable side;
- a compare that raised: one error line with its traceback a batch;
- the link refused or failing, or the kept path no longer the inode the compare read (section 5); after a refusal that holds
  for the whole filesystem, every later file of the batch, with no compare.
A stop during the compare chooses nothing: the batch ends as a stop does. A pool disk gone, or a record or a flush of the link
that fails: JobFailure, as for a copy.

**Tests** (tests/test_no_copy_move.py, `unit` unless said; each through `do_backup()` with raw events, a delete of the old place
and a create of the new, unless said; each ends with the oracle of section 9):
- `test_an_unchanged_file_moved_into_a_new_folder_is_linked`, off and on two renames, with Only Sync Attributes on and off: the
  new path in the newest version and the old path in the version before are one inode; no two paths of one version share one;
  one line.
- `test_an_unchanged_folder_moved_into_a_new_folder_is_linked`, the same ways, with a subfolder, a link, an empty file and a
  file with a `user.x` attribute: every regular file linked, the link and folders made as today.
- `test_a_folder_moved_below_the_top_is_linked`: `cd P; mkdir new; mv big new/`, `mkdir -p P/a/b; mv P/big P/a/b/` and a move to
  another parent (`mkdir Q/n; mv P/big Q/n/`): every file linked to its own old copy.
- `test_a_move_made_while_down_that_kept_its_name_is_linked` (a start's full comparison: the per-row deletes and the creates)
  and `test_a_tree_unpacked_elsewhere_under_its_name_is_linked` (`rm -r big; mkdir r; tar xpf big.tar -C r`).
- `test_a_twin_of_the_same_name_size_mtime_and_tail_is_copied`: other bytes before the last 64 KiB (the tests' `cpp`).
- `test_a_poke_before_the_compare_is_copied`: same size and mtime kept (the tests' `poke`) after the take.
- `test_a_write_during_the_compare`, two cases through a `read_block()` stand-in that writes into the monitored file after its
  first block: into a block not yet compared (copied) and into one already compared (linked to the old bytes; the next batch
  copies the new ones, and its version holds them).
- `test_a_file_replaced_after_the_compare_opened_it_is_judged_as_opened`: a `no_follow_opener()` stand-in that, after opening
  the monitored file, replaces it with a copy of the old copy under other metadata: the version never holds the old copy's
  bytes under the replacement's metadata.
- With `BACKUP_SEMAPHORE` a `Semaphore(1)`: `test_a_compare_that_raises_is_a_copy` (a `read_block()` stand-in raising ValueError
  for two files: both copied, one error line with its traceback, the batch's later copies finish, the permit is back, the batch
  commits) and `test_a_compare_holds_a_threads_permit` (a `read_block()` stand-in finds no permit left while it reads, and the
  permit is back after; `same_file()` called while the test holds the permit, `GREEN_LIGHT` cleared, returns None).
- `test_a_sparse_file_is_compared_by_its_data`: a file of 64 MiB with data in its first and last 4 KiB and a hole between, moved
  into a new folder, linked, with a `read_block()` stand-in counting the bytes read (its data, not 64 MiB); one whose hole in
  the old copy is written zeros in the monitored file, linked; one with other bytes inside the old copy's hole, copied; and two
  files sparse alike (256 KiB of equal data at 0, a hole to 2 MiB, 256 KiB at 2 MiB that differs, a hole to 4 MiB), copied.
- `test_a_source_gone_before_the_compare_is_copied_as_today` (removed in an `old_copy()` stand-in): today's lines and rows.
- `test_metadata_that_differs_is_copied`, one case per field: mode (a chmod with the move), mtime (`touch`), an extended
  attribute (`user.x`), owner and group (these two skip unless root, as tests/test_r_readers.py's `needs_root`, and run in the
  VM): each copied, never linked.
- `test_two_new_files_and_one_old_file_link_one` (`rm -r big` with `big/a`; `n1/big/a` and `n2/big/a` created with its bytes and
  metadata): the first linked, the second copied with no compare, as `alone()` then answers False.
- `test_what_the_names_do_not_reach_is_copied`, one case each of section 7's items 2 to 6: a renamed move, two deleted entries
  of one name (`x/src`, `y/src`, `n/src` with one's bytes), `mkdir n; mv a/b/big n/; rm -r a`, `mv d/g y; mkdir n; mv d n/d`,
  and `rm -rf d; tar x` at `d`'s own place.
- `test_a_true_stand_in_below_a_deleted_entry_of_its_name_is_linked`: section 2's saved copy put back and part of a left
  folder moved back, each linked.
- `test_a_vault_that_refuses_links_copies_the_rest_without_a_compare`, over EPERM, ENOTSUP, EOPNOTSUPP and ENOSYS and, as pins,
  EXDEV and EMLINK (an `os.link` stand-in on the copy names, a spy on `same_file()`, three files of a moved folder): the first
  four, one compare and three copies; EXDEV and EMLINK, three compares and three copies.
- `test_a_pool_disk_gone_during_a_compare_fails_before_the_link` (a `same_file()` stand-in makes the `PoolGuard` find a disk
  gone at its next poll) and `test_a_failed_record_at_the_link_fails_the_attempt` (a `TreeWriter.record` stand-in raising
  JobFailure for the link's rel): the attempt fails, with no link and no copy for the file.
- `test_an_old_place_with_no_file_is_copied`: a delete the length rule keeps (a forward link stays at the old place in the
  version before), and a user's symlink deleted where the new path's name points: copied.
- `test_a_stop_during_the_compare_links_nothing`: `GREEN_LIGHT` cleared from a `read_block()` stand-in: no link and no copy
  queued for the file, the batch ends as a stop does (`attempt_events()` returns False), the next attempt commits it right.
- `test_a_failed_look_at_the_version_before_is_a_copy`: EIO from an `os.lstat` stand-in on the old path.
- `test_the_verification_links_too`: a file of the moved folder that the replay's walk missed and the verification finds
  missing: linked.
- `test_a_roll_forward_links_nothing`: a batch cut after its hand-over and before its commit, rolled forward: `n`'s files
  copied.

## 5. The writer's verb and the size books

**What it does.** One `TreeWriter` verb puts the version before's file at the new place the way a copy is put there, and tells
the size books that the file is the tree's again; the books answer whether the version before alone holds a file.

**Where.**
- New `TreeWriter.link_kept(kept_rel, source, rel, pending, kept) -> bool`, beside `copy()` (reverberator.py:14170), the one
  door to the tree (tests/test_tree_writes.py's `replay_offenders()` keeps finding any write of the replay outside the writer;
  `copy_or_link()` is a closure of `do_reverb_backup()`, and `same_file()` a module function that only reads):
  1. `self.sizes.alone(kept_rel, self.two_renames)`: False returns False with nothing done, so the rule's first half is kept at
     this one door (`copy_or_link()`'s step 5 only spares a compare).
  2. As `copy()` does: `record(rel, True)`, `flush_if_needed()`, `_folders_for_copy(source, rel)`; a record or flush that fails
     raises JobFailure, as in `copy()`.
  3. A fresh copy name, `partial_copy_path()` of `rel`'s path (8222), taken again while one is there as `cp_af_copy_path()` does;
     `os.link(self.kept_path(kept_rel), temp, follow_symlinks=False)`, as `link_or_copy()` (13553) makes its links.
  4. One `lstat()` of the copy name, whose `(st_dev, st_ino)` must be `kept`, the inode the compare read through its handle;
     else the copy name is removed and False. The case it catches: mergerfs's `link-exdev` symlink modes (`rel-symlink`,
     `abs-base-symlink`, `abs-pool-symlink`) answer a link across the pool's disks with a symlink at the copy name, and
     `os.link()` succeeds; unchecked, the version would hold a symlink to the version before's file, the books would count it
     as that file, and a prune of the version before would break it. On a pool it also rests on mergerfs's default `inodecalc`
     giving both names one number (a branch's device and inode); one that numbers paths answers two, a copy (reasoned; the pool
     gate shows it, section 9). The link follows the compare on the replay's thread, so no delete of the daemon's can free the
     kept inode for reuse in between; a hand edit is outside the claim.
  5. The size books told from that same lstat (below); `pending.append(PendingCopy(None, source, temp, self.path(rel)))`, a link
     already made. True.

  Any OSError of `alone()`, the link or the look after it (`NO_HARD_LINK_ERRNOS` and EIO among them): the copy name removed if
  made, False, and the caller copies; an `os.link()` refused with EPERM, ENOTSUP, EOPNOTSUPP or ENOSYS also sets
  `self.links_refused`, a flag of the writer (so of the batch, False at its making), which `copy_or_link()`'s step 1 reads. A
  removal of the copy name that fails raises JobFailure: that name of the kept inode, which the books were never told of, would
  let `alone()` answer True and a second file link it again; the next attempt's repair of the cut removes what the batch made
  (section 1, item 6). The record made stays, and `copy()` repeats it and finds nothing left to do (a record acts only where a
  forward link still stands). The place `rel` never holds the old copy's inode (`alone()` just said no path of the tree holds
  it), so the placement (`os.replace`) is never a rename between two names of one inode, which would leave the copy name.
- `finish_copies()` (8946): a pending entry whose task is None is a link already made. Its loop branches on that before it reads
  `copy.task.stderr` (8969), which a link has none of: no lines, succeeded; it is put in place and returned among the entries put
  in place, as a finished copy is (0.55.7's section 9 reads that list as what the replay applied), or, where a folder above its
  place is no longer real, left with its row dropped, as a copy is, and not returned. Its `if copied: manifest.copies_unsynced =
  True` (9026-9027) stays as it is (section 1, item 8). `discard_copies()` (8801) removes a link's copy name as a partial copy's,
  from the two of its six call sites a backup reaches (restore's `finish_restore_copies()` holds the other four):
  `stop_copies()` (a stop, and the replay's `finally` after a JobFailure) and `finish_copies()`'s `finally` (the entries an error
  left unplaced), leaving the version before's file whole and its link count where it was.
- `BatchSizes` (13736): `shared` becomes a dict by rel (`pending()` sets `shared[rel] = (size, links)`; a version's entry is
  recorded once, so no rel comes twice); `result()` iterates `self.shared.items()` (`for rel, (bytes_, links) in ...`; today it
  unpacks the list's triples); new `linked(rel, size, links)` and `alone(rel, two_renames)`. Its docstring's "Nothing but the
  record's own link and the tree's copy changes that count during a batch" names the no-copy move's link (`link_kept()`) too.

**The size books.** `BatchSizes` counts what the version before alone holds, each inode in the newest version that holds it.
`link_kept()` calls `self.sizes.linked(kept_rel, size, links)` from one `lstat()` of the copy name right after the link: `size`
is the linked inode's `st_size` (section 6 counts the same), and `links` its count of names, that lstat's `st_nlink` off two
renames and `links_now()` on them, as `BatchSizes.result()` reads a count (on two renames a name's attribute can be a second
old). Not `st_nlink + 1` of a look before the link, as `keep_entry()` takes it: the compare ran in between. `linked()` takes
the file back from the version before's count (`self.size -= size`, `self.inodes -= 1`) only when `rel` is not in `shared` yet,
and in either case sets `shared[rel] = (size, links)`, so the file counts nowhere while the tree holds the link, and counts in
the version before again if the tree lets it go later in the batch (the verification removes its new place, a later copy
replaces it, the link is discarded).
- Off two renames a delete's record takes a file by a rename (`record()` at 14108 adds its size, its inode taking the forward
  link's place) or with a folder exchanged in whole (`folder_usage()`'s size and inodes), so it is not in `shared`, and
  `linked()` takes it back.
- On two renames a delete's record takes every file by a hard link (`record()` makes every record a keep there), so the file is
  in `shared` already, pending at the count its record left; the rm of its delete dropped that count by one, and the link brings
  it back. `linked()` takes nothing back: `keep_entry()` put the file in `shared` and never added its size or inode to the
  counts.

`linked()` tells the two apart by `shared` itself, not by the writer's `two_renames`, which an exchange that fails can still turn
on in the middle of a batch. A roll-forward's sizes come from `measure_previous()` (7659), which counts in the version before
only files the tree does not share: a linked file is shared, so it needs nothing (and a roll-forward links nothing).

**The invariant `alone()` rests on.** `alone(rel, two_renames)`: `rel` is not in `shared`, or the file's count of names now
(`links_now()` on two renames, an `lstat()` elsewhere, as `result()` reads it) is below the count `shared` holds for it. Asked
only of a regular file of the version before reached through real folders (`old_copy()` looked), it is meant to say: no path of
the tree holds this file's inode. It is the one new invariant of this round, run in the step back's probe for the record kinds
its test lists and reasoned in general:
- A batch's version before starts as forward links alone (`hand_over()`), so each regular file in it came by a record of the
  tree's entry during the batch (`record()`, through `unfold()`, `hard_link_tree()` and `exchange_in()`). A record without keep
  renames the file in, or exchanges its folder in whole, which takes the tree's name away. A record with keep (every record on
  two renames) hard-links it in through `keep_entry()`, the only caller of `BatchSizes.pending()`, which puts it in `shared` with
  the count the link left; however the tree lets it go, that count drops by one. A record that copies where hard links are
  refused makes an inode the tree never held. The tree holds each inode under one name (each copy is its own inode, and a
  hard-linked monitored file is copied once per name), and the only other link into the tree is this round's, which `linked()`
  puts in `shared`. Nothing else changes a count during a batch: the prune runs before the hand-over. A roll-forward's books
  start empty over records the cut attempt made, so `alone()` would read wrong there; a roll-forward has no names and never
  asks it.
- *Its test:* `test_alone_answers_for_each_kind_of_record` (tests/test_no_copy_move.py, `unit`), a TreeWriter from `hand_over()`
  on a vault in the test's folder, off two renames and with `pooled=True`, one case per record kind: a folder deleted whole, a
  top file deleted, a file deleted and then its folder, a copy queued over a file both before and after its placement, a renamed
  move of a file and of a folder, `mv D/g y; rm -r D`, `mv p q; mv other p; rm p`, an unfold's entry kept by a hard link (an
  `os.symlink` stand-in answering ENAMETOOLONG on one path), a record copied (an `os.link` stand-in answering EMLINK for the
  record), and `remove_now()`. For each regular file of the version before, `alone()` is True exactly when no path of the tree
  holds its inode (an `os.walk` of the tree's inodes); then each file it answers True for is linked into the tree as
  `link_kept()` links it and told to the books, after which `alone()` is False and the oracle's new `paths_sharing_an_inode()`
  (section 9) is empty for both versions.

**State.** `BatchSizes.shared` keyed by rel, per batch, as before; `links_refused`, per batch. Nothing at rest.

**Failure cases.** The link refused or failing, or the kept path no longer the compared inode: the copy. Its copy name not
removable: JobFailure. A cut after the link and before the commit: as section 1, item 6 says. A stop: `stop_copies()` discards
it. A folder above the new place no longer real at the placement: the link is left and its row dropped, as a copy is, and no
name of the kept inode is left behind (read in the code). Whatever stops that folder being real before the placement removes
the copy name with it: a placement's `replace_entry()` (8498) removes the real folder it replaces whole (`shutil.rmtree`), and
a delete that replays after the link (one behind a move, after `recheck_moved_folder()`'s links) removes the tree's folder with
everything in it. No record can take the copy name into the version before instead: `link_kept()`'s own record left every
folder above `rel` real there (or none, below a folder this batch made), a record takes a folder whole only at a forward link,
and the copy name, made after that record, has no entry of the version before to record. The books then count the file back in
the version before, its count having dropped.

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
- `test_a_kept_file_swapped_after_its_compare_is_a_copy`, two cases: an `os.link` stand-in that first puts another inode with
  the same bytes and metadata at the kept path, and one that makes a symlink to the kept file at the copy name and returns, as
  a mergerfs `link-exdev` symlink mode does: copied, no copy name left, the kept file's count as it was.
- `test_a_copy_name_that_cannot_be_removed_fails_the_attempt`: an `os.lstat` stand-in answering another inode for the copy name
  and an `os.unlink` stand-in failing on it: JobFailure; the next attempt commits right, and no two paths of a version share an
  inode.
- `test_a_batch_of_links_alone_flushes_as_a_batch_of_copies`: a spy on `flush_copies()`: called off and on two renames.
- `test_a_stop_before_a_link_is_placed_leaves_no_copy_name`: `GREEN_LIGHT` cleared after `link_kept()`: no
  `.reverberator-partial` name in the tree, the version before's file whole, its link count back.

## 6. The log line

**What it does.** One line at the end of `do_reverb_backup()`, after the verification, when the version holds a link the batch
made: `Reused <n> files, <size>, from <version before> by hard links in place of copies: each had the bytes, mode, owner, group,
mtime and extended attributes of a file this batch removed from the version` (`format_bytes()` for the size, as the change
list's name writes it). Its lead word is one no other line has: "Linked" leads two of the prune's lines (13058, and the error at
13066). Today the copy of such a move writes no line at all; a copy still writes none. One line an attempt, not one a file: a
moved folder of 100,000 files writes one.

**Where.** `do_reverb_backup()` keeps the old path and size of each link `link_kept()` made, and at the end counts those the tree
still holds by the books: `not writer.sizes.alone(old, writer.two_renames)`, one look each, as the commit's `result()` reads
them (an error of that look: not counted). A link never placed (discarded at a stop, left where a folder above stopped being
real) or let go later in the batch (the verification removes its new place, a later copy replaces it) has dropped its count and
is not counted. The line is a plain `backuperTeeLogToTl()` call (5462) with `monitor_path` and no flag, as the replay's other
lines (`Moved … to …`, `Fixing … differences …`): logged at info level in the daemon's log, and printed too under `--debug`;
`log_text()` escapes the whole line, the version's path with it.

**State.** The links made, per batch.

**Failure cases.** None of its own. A stop or a JobFailure in the replay ends the batch before it. The line is written before
the commit, as the replay's other lines are: a batch that fails after the replay, in `do_backup()` (a pool disk that drops, a
flush that fails), has logged it for links its version never commits, and its next attempt logs its own.

**Tests:** `test_one_line_a_batch_names_the_files_and_bytes_linked` and, as pins, no such line in a batch that linked nothing; a
link left unplaced not counted (a `finish_copies()` stand-in first removes a folder above the link's place, its copy name with
it, and puts a symlink there); and a link the verification removes not counted (section 5's test of a linked file the tree lets
go, its line asserted) (tests/test_no_copy_move.py). It is an info line: the repo's alert patterns
(firewatcher/reverberator.regex) match only the markers and the exit line, so nothing alerts on it.

## 7. What it does not reach

Each of these is copied as today, with today's lines, unless the file's path also holds a name a top-most delete of the batch
gives (section 2) and the file at its place below that delete's entry is the same: then it is linked, a true stand-in (section
1, and section 2's reach). The version is right in each.

1. **A file changed in the move's batch:** its bytes, mode, owner, group, mtime or an extended attribute. That file is copied;
   the rest of a moved folder is linked. Under Only Sync Attributes too: in the move's batch such a file is copied, not linked
   and then given the new metadata (possible, and left for a later round). A change made in a later batch to a linked file is
   an attrib like any other, and under Only Sync Attributes it is synced onto the shared inode, where the version before's old
   path shows it too, as for a renamed file (section 9's test).
2. **An old place whose delete is not applied before the copy:** a batch the maximum delay takes while the move-out still waits
   for its pair (the check after the batch deletes the old place; a batch taken quiet holds the delete); a move landing in the
   instant a batch is taken (the known limitation of that name); and a delete at or above a move's source, which gives no name:
   a folder moved into a new folder after a move out of it in the same batch (`mv d/g y; mkdir n; mv d n/d`).
3. **An entry renamed in the move** (`mv big new/other`), and so a rename made while reverberator was down (the start's full
   comparison finds a delete and a create of another name): copied once, as today.
4. **Two deleted entries of one name in one batch:** the name is ambiguous, and both moves are copied.
5. **An entry whose own delete lies under another delete of the batch:** a move out of a folder the batch also deletes
   (`mkdir n; mv a/b/big n/; rm -r a`), or a copy of a file under a folder it deletes (`mkdir n; cp -p P/big/x n/x; rm -r P`):
   only the top-most delete gives a name (`a`, `P`), and the new path does not hold it.
6. **What the batch holds no delete entry for:** a delete and a create of one path (`rm -rf d; tar xpf d.tar` at `d`'s own
   place: they collapse into the create, `change_events_to_backup_entries()`, and each file is copied over its old copy); a move
   into its own old place (`mv D x; mkdir D; mv x D/D`) and its swap shape; swaps in one batch; a folder found ahead of its events
   (its move came as a move); and the copy fallbacks of a move (a move another change of the batch outran, a move into its own
   old place, a path past the length limit), whose deletes give no name. Their entries stay as they are.
7. **What the version does not hold:** a move into the tree from outside it, from a skipped path or from a paused inner disk;
   a file made in the batch and moved into a new folder (README line 17). (A part of a folder that left the tree in the batch,
   moved back below a folder of that folder's name, is not of these: the version before holds it, and it links, section 2.)
8. **A vault that refuses hard links** (a known limitation already), and a vault whose filesystem cannot hold a monitored file's
   metadata as it is (an extended attribute it refuses or sets itself, an owner it cannot keep): its files are never linked.
9. **The second of two new files that pair with one old file:** one link per old file.
10. **A batch cut before its commit and finished at the next start:** its roll-forward has no names and copies as today.
11. **Copies the replay makes outside `copy_path()`:** the attrib branch's (a swap the collapse could not replay; a chmod with
    Only Sync Attributes off), and the move branch's copy of a moved file whose metadata changed.

What the operator is told: the narrowed entry "A folder or file moved into a new folder is copied whole", README lines 4, 15
and 22, and the name rule's reach in "A move out of a folder that just left the tree is copied" and README line 43 (section 10).

## 8. Interactions with round 0.55.7

This round is built on 0.55.7's merged code. What it takes from it, and where the two meet (0.55.7's spec sections and plan
tasks, `docs/superpowers/plans/2026-11-22-r0557.md`):

- **Section 7, the strict looks (Tasks 5 and 6).** `old_copy()`'s look at the version before is `real_folders_to(strict=True)`,
  on `r0556` already; 0.55.7 makes it answer False for ENOTDIR and raise a JobFailure for an error other than ENOENT and ENOTDIR
  (its section 7), `VersionLookError` (its plan's name, Task 5). It is a JobFailure, not an OSError, so `copy_or_link()`'s
  `except` and the estimate's `leaving` name it beside OSError; a failed look here chooses the copy (or the charge) and fails no
  attempt, where 0.55.7's section 7 fails the attempt on a look at the version that errs: it decides only between a link and
  today's copy, which needs nothing of the version before. The source's look (step 3) is its own lstat: an error chooses the
  copy, whose own failure keeps the last copy with its UNREADABLE line (0.55.7's `monitored_there()`). Task 5's strict looks in
  `finish_copies()` and `discard_copies()` take a link's pending entry as a copy's.
- **Section 9, history from what the replay applied (Task 7).** `wait_for_async_commands()` gathers `finish_copies()`'s returned
  rels into the batch's `placed` set, and `copy_path()` records the rel each entry's own `writer.copy()` was given. A link is
  returned by `finish_copies()` among the entries put in place (section 5), so it reads as applied, and its history is the
  events': a delete and a create, as today. Collision: both rounds change the same two lines of `copy_path()`: the rel is
  recorded in `copy_or_link()`'s caller, whichever way the file goes.
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
  the new place on that branch, as it does for `hl_record()`'s links today, or answers EXDEV, or under a `link-exdev` symlink
  mode makes a symlink, by its settings (reasoned, not run); EXDEV and a symlink are a copy (section 5). The approved entry "On a
  mergerfs pool, a folder cloned to another disk can lose setgid" covers folders it makes, as any the batch writes into. The VM's
  pool gate forces each outcome (section 9).
- **`BatchSizes`, `TreeWriter.record()`, `TreeWriter.pre_record()`, the estimate's walk:** 0.55.7 changes none of them beyond the
  above.

Order: this round's branch is made from the merged 0.55.7; nothing here is built before it.

## 9. The test plan

Every outcome is forced by its own test, through a stand-in at the one call that decides it where the real system cannot be made
to answer so; none is left to a random sweep. The sweeps below (the fuzz, the shapes at their timings) are the regression gate,
not the proof.

**The oracle, at the end of every test.** In tests/test_no_copy_move.py, `check_vault()` (tests/vault_oracle.py) over every
version, against the tree each backed up (snapshotted before each batch): each version byte for byte in full, with mode, owner,
mtime and extended attributes, but, under Only Sync Attributes, the metadata of an older version's file whose inode another
version reads (`free_file_meta`, as round 19's rule lets a synced attribute reach it). `assert_held_as_the_tree()`, which the
watcher tests use, compares the version before on kind and contents only, as today. Then the sizes (the ground-truth plugin,
tests/version_view_ground_truth.py, compares each change list's name with `sizes_by_newest_holder()` after every committed batch,
and checks that no older version changed); and the shape: a new helper the build writes in tests/vault_oracle.py,
`paths_sharing_an_inode(job_vault, folder_name)`, empty for every version, with, where a link is expected, the new path in the
newest version and the old path in the version before one inode (`read_view(..., inodes)`).

**tests/test_no_copy_move.py** (new, `unit`: a module of one layer, as conftest.py's hook fails a test with two; the owner and
group cases chown, which the `unit` layer allows, and skip unless root, as tests/test_r_readers.py's `needs_root`, so they run
in the VM). Batches through `do_backup()` with raw events, as tests/crash_batches.py's `backup_events()` builds them; that
helper asserts the commit (crash_batches.py:49), so it is split into `attempt_events()`, the same call returning `committed`,
and the assert, and the tests of a stop call `attempt_events()`. "On two renames" is both ways: the writer made pooled
(`hand_over()` wrapped to call the real one with its fifth argument, `pooled`, replaced by True: `do_backup()` passes it by
position, 6445, so a keyword would raise TypeError), and a filesystem with no exchange (`rename_exchange` patched to raise
EINVAL, as `test_on_a_filesystem_with_no_exchange` does). It holds the tests named in sections 2 to 6, and one more: with Only
Sync Attributes on and off, a link, then a chmod of the new path in the next batch: on, synced onto the shared inode, and the
version before's old path shows the new mode (as for a renamed file; the oracle allows it); off, copied, the old mode kept.

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
- The found-folder tests assert the version equals the tree and nothing of how. Each batch, taken quiet, holds `big`'s delete
  (a move into a new folder keeps its source to expire into its delete, as `watchFolder()` says), so the moved files are linked
  by the name `big`. Those named "copied" are renamed and assert, inode by inode, what they link and copy (SEED's `big/a` and
  `big/sub/b`): `..._whose_event_comes_is_a_copy` (373) becomes `..._is_linked` (both linked); `..._while_it_is_walked_is_copied`
  (699) becomes `..._links_its_unchanged_files` (`<into>/a`, written with its mtime set back, copied; `<into>/sub/b` linked;
  `m/x`, from outside, copied); `..._after_its_parents_walk_listed_it_is_copied` (739) becomes `..._is_linked` (`p/q/big/f0` to
  `f3`); `..._before_its_subfolder_is_listed_is_copied` (784) becomes `..._is_linked` (both); and
  `..._moved_on_in_a_later_read_ends_as_the_tree` gains the assert. Every comment that says such a move is copied, or held by
  the new folder's copy, "as on 0.55", says what its test now asserts: the module docstring (1-7) and the comments at 268, 283,
  374-375, 597, 642, 673-674, 700-702, 740-742, 764, 785-786, 808 and 888; those at 399 and 419 stay (their files are copied).
  A test that shows otherwise is a finding the builder reports.
- `test_on_a_filesystem_with_no_exchange` gains: `big`'s files and `f.txt` are linked (one inode across the two versions),
  `n/big/z` copied: the reach on two renames on the real watcher.
- `test_a_file_moved_out_is_not_taken_for_a_new_folders_file_of_its_name` gains: the new file's inode is not the old one (the
  name pairs them, the compare tells them apart).
- The two estimate tests change as section 3 says.

**tests/test_watcher_fuzz.py** (`inotify`): the random steps already move folders and files into new folders (`mvd_new`,
`mvf_new`); a new step `twin` makes a new folder `n<k>`, copies a file into it under its own name with `cp -p` semantics
(`shutil.copy2`) and removes the original, so the batch deletes the name the twin's path holds, and one time in two pokes the
twin first (same size and mtime, other bytes). Its oracle stays the file's own, the newest version equal to the tree by whole-file
hashes, and the plugin's, no older version changed and each change list's sizes; `paths_sharing_an_inode()` joins it for every
version after each round. The suite's sample as now; a longer run is the main session's gate call.

**Crash** (**main session: VM gate**; builders write these to skip outside the VM). tests/crash_batches.py's batch 3 gains a
deleted file and a deleted folder, past f2fs's inline size (`past_inline()`), and their creates under their names in a new
folder, so the batch links both; the kill points of tests/test_crash_harness.py's sweep then cut through `link_kept()`, the
placement and the commit, and tests/test_crash_power_loss.py's power cuts through the same. After each, both run `check_vault()`
and `view_truth.wrong_lists()`, as today, and gain `paths_sharing_an_inode()` empty for every version and
`measure_previous(version before, newest)` equal to `sizes_by_newest_holder()`'s count of the version before (today only
`test_roll_forward_sizes_equal_a_clean_batch` checks those two). The VM gate runs them with `REVERB_CRASH_FULL=1`, so
`kill_points()` cuts every step, the link steps among them; the default stride (tests/test_crash_harness.py:401-407, the power
cuts too) may miss them all and proves nothing of the links. The recording run (uncut, counting each kind of call) shows they
exist: `test_the_kill_points_cover_every_kind_of_call` gains `link` among its kinds (crash_child.py counts `os.link` as `link`,
`KillPoints.step()` at 53-63); a killed child reports nothing, so no cut is asked what it killed. On a scratch mergerfs pool
in the VM (tests/test_pool_cut.py's way), the same batch with each disk put back at its own point, over a standing manifest and
over a lost one (section 1, item 6: a placed link copied again, an unplaced copy name removed by the comparison).

**The pool** (**VM gate**, `needs_mergerfs`): a link into a new folder whose old copy is on one branch and whose new folder was
made on another, run three times: with the pool's policies set so mergerfs makes the link, so it answers EXDEV (the builder takes
the settings from mergerfs's documentation and names them in the test), and with `link-exdev=rel-symlink`, so it makes a symlink
at the copy name; each run asserts which happened (one inode across the two versions, or a copy after the EXDEV or the symlink),
never "linked or copied"; the oracle and the sizes each way; the folders mergerfs makes for the link read with their times as
the batch gave them.

**The real daemon** (**main session**, as round 21 measured the limitation: the daemon itself, a scratch job, in the test
container as uid 65534 or in the VM). `mkdir new; mv big new/` for a folder of 100 MB (1,000 files of 100,000 bytes, as the
limitation's measurement) and for a file of 100 MB, `big` at the top and below it (`cd P`), at gaps of 0, 1 ms and 1 s, with
`mkdir` and `rename` as two system calls of one program and as a shell's two commands; each again with a poke of one file
before the move, between the two, and after it. **The number it should show** (expected, until this run measures it): vault
growth under 0.1 MB for the folder and for the file, where today it is 102.44 MB and 100.11 MB, at every gap (a move into an
existing folder grew it 0.04 MB in round 21's measurement, its folders' blocks and the change lists, which this move makes too,
with one folder more and its 1,000 names); a poked file adds its own size; the entry's size-limit run (five small versions,
then the move; today it left only the newest) keeps all five; one line a batch; the replay's time against today's copy of the
same. A run in the VM is a VM figure, not a cold one: the VM's disks bypass the host's page cache, so after the guest drops its
own the reads come from another disk than the live vaults'. The measured figure replaces 10.1's expected one (section 11, step
4); one off it is a finding, and so is a linked move much slower than its copy. The cold figure comes from the live backups
after the deploy, as the standing decision says: the main session reads in the daemon's log the replay's time of the first real
move into a new folder that links (its batch's first `Processing` line to its `Reused` line) against the same job's latest
batch before the deploy that copied a like size, and records both in P3's row of docs/progress.md.

**Measurements in the build** (the builder's, in the container, warm): the compare against today's copy for one 1 GiB file and
for a folder of 10,000 files of 4 KiB, with blocks of 256 KiB and of 1 MiB, and the process's peak memory (`VmHWM`) after each;
the names of a full comparison's 1,000,000 per-row deletes; the estimate's walk of a moved folder of 100,000 files with
`leaving` and without. The figures go in the handback; a block size the measurement changes gets its reason beside it.

**Gates:** the whole suite in the container and in the VM, the mergerfs and power-loss tests, as the release gate has them.

## 10. Docs

The release is called 0.55.8 below (the round after 0.55.7; the number is the main session's). Each text replaces the one named,
in the commit of the code it describes (section 11). The build starts after Q24's and Q25's answers, so each narrowed or widened
entry's "Approved" is written with its answer (the user's words or pick and the date, or "chief's decision" and its date), where
`<Q24's answer>` or `<Q25's answer>` stands below. **[Q24]** (b): nothing is written. **[Q25]** (b): 10.2's estimate sentence and
line 31's estimate clause are not written (their links sentences are).

Nothing else changes: "A move that another change of the batch outran is copied", "A move into its own old place is copied
whole", "Swaps in one batch are repaired by copies", "A folder found ahead of its events can reach the vault a version late",
and README lines 17, 19, 39, 42, 44 and 45 stay: their own shapes give no name, or their old copy is not in the version (section
7); a copy of theirs that links anyway, by another deleted entry's name, is a true stand-in and costs less than they say.

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
  mode, owner, group, mtime and extended attributes. That covers a move to the same or another parent folder anywhere in
  the tree (`mkdir -p a/b; mv big a/b/` too), of a file as of a folder, a move made while reverberator was down that kept
  the entry's name, and a tree deleted and unpacked elsewhere under its own name with its times kept. One line says so in
  the log at each attempt of the batch, before its commit (`Reused <n> files, <size>, from <version> by hard links in
  place of copies: ...`). An unchanged move linked so is expected to cost about what a move into an existing folder costs
  (under 0.1 MB for a 100 MB folder of 1,000 files), and with a size limit the estimate charges nothing for its files, so
  it prunes nothing for them. Still copied, with no line: an entry renamed in the move (`mv big new/other`); two entries of
  one name deleted in one batch; an entry moved out of a folder the same batch deletes (`mkdir n; mv a/big n/; rm -r a`);
  a file changed in the move's batch (its contents, mode, owner, group, mtime or an extended attribute); a file made in
  the batch and then moved; a tree deleted and unpacked again at its own place (each file copied over its old copy, as
  any change); every file of the move when its old place leaves the version after the copy (a batch the maximum delay
  takes while the move-out still waits for its pair, a move landing in the instant a batch is taken, or a folder moved
  into a new folder after a move out of it in the same batch, `mv d/g y; mkdir n; mv d n/d`), or in a batch cut before
  its commit and finished at the next start; the second of two new files that match one removed file; and, on a vault
  that refuses hard links or whose filesystem keeps other metadata than the monitored file has (an extended attribute it
  refuses or sets itself, an owner it cannot keep), every such file. Such a copy costs its size (a 100 MB file 100.11
  MB), and with a size limit it can prune older versions to make room, as on 0.55.7, where every such move is copied.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, and a program's `mkdir` and `rename`, one right after the other, leave no moment in which the
  new folder has a watch. 0.55.1 was built to keep the arrival as a move; four reviews and the fix passes after them each
  found an order of events where the version then kept a file's old bytes for good, so 0.55.1 copied, as 0.55 does. From
  0.55.8 the copy proves each file's bytes and metadata by reading them, and links only what it proved, from a file the
  version before alone holds; what it cannot prove, or what changed, it copies. A copy costs space and time; a wrong
  version loses a backup.
- **Revisit when:** a size-limited job's prunes follow such copies often, or moves that rename the entry show up in a real
  vault.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as on
  0.55, and the no-copy move gets its own design later. Narrowed to what the link cannot cover: <Q24's answer>.
```

The "under 0.1 MB" in parentheses is what section 9's real-daemon run is expected to show; the text says "is expected to cost"
until that run measures it. Step 4 of section 11 then writes "costs about ... (<the measured figure> for a 100 MB folder of
1,000 files on the real daemon)" in its place, and a figure off it is a finding. **[Q25]** (b): "and with a size limit the
estimate charges nothing for its files, so it prunes nothing for them" becomes "but with a size limit the estimate still
charges its files, so it can prune older versions for them first".

### 10.2 docs/limitations.md: "Size estimates leave out a version's own small blocks" (widened, on Q25's answer)

In "What the operator sees", after "... and a move that falls back to a copy, so a vault can pass its size and inode limits by
those copies until the next prune.", insert:

```
  From 0.55.8 it also leaves out a file it expects the no-copy move to link: one whose place below an entry of the same
  name the batch deletes holds a file of its size, mtime, mode, owner and group. The replay copies such a file after all
  when its contents or extended attributes differ (a same-size rewrite with its mtime set back), or the file changed after
  the estimate looked (then the estimate misses its whole size, where for a file it charged it misses only the growth),
  when that delete removes nothing there (one the length rule keeps, or one whose place holds another kind), when it is
  the second of two new files that match one removed file, or when its link, a look or the read of it fails: on a vault
  that refuses hard links, or a pool that answers EXDEV between its disks, every such file.
```

Then, in the same field, "The links a batch makes are in no size record, so neither `status` nor the limit sees their bytes:"
becomes "The forward links (symlinks) a batch makes are in no size record, so neither `status` nor the limit sees their
bytes:", and after the sentence it opens, which ends "until that version is pruned.", insert "A hard link of the no-copy move
adds a name, no inode or data block." In "Why", append: "Charging a file the no-copy move links would prune versions for good
for a copy never made, the harm that move removes; an estimate too low only exceeds the limit until the next prune." In "Revisit
when", append: "Also when such files are copied after all often: a vault that refuses hard links, or a pool that answers EXDEV."
In "Approved", append: "Widened to a file the estimate expects the no-copy move to link: <Q25's answer>." **[Q25]** (b): only
the links sentences, and "Revisit when" and "Approved" are as they were.

### 10.3 README

- **Line 4**, "A copy is recorded checked at its commit, which flushed it first;" becomes "A copy, or a hard link the no-copy
  move made in its place, is recorded checked at its commit, which flushed it first;", and "a commit flushes the batch's copies
  first" becomes "a commit flushes the batch's copies and placed links first".
- **Line 15**, its last clause "and moves made since the last backup before a stop are copied once instead of renamed." becomes
  "and a move made since the last backup before a stop is a delete and a copy: each file of the copy that is, byte for byte and
  in its metadata, the file at its place below the deleted entry of the same name is hard-linked from the version before (both
  read once, and only a name written), so a move that kept the entry's name costs no copy, and the rest (a rename, say) is
  copied once."
- **Line 22**, its last sentence becomes: "A folder or file moved into a folder made in the same batch reaches the backup as a
  delete of its old place and a copy of the new folder, as nothing watched the folder when it arrived: each file of that copy
  that is, byte for byte and in its mode, owner, group, mtime and extended attributes, the file at its place below the deleted
  entry of the same name is hard-linked from the version before in place of a copy, after a read of both (one line a batch:
  Reused <n> files, <size>, from <version> by hard links in place of copies). An unchanged move linked so writes no copy, and
  under a size limit the estimate charges nothing for its files; each file not linked is copied whole: a file changed in the
  move's batch, an entry renamed in the move, a file made in the batch (line 17), and the rest docs/limitations.md lists under
  "A folder or file moved into a new folder is copied where it cannot be linked"." **[Q25]** (b): "and under a size limit the
  estimate charges nothing for its files" is left out.
- **Line 43**, before its last sentence ("The result is right."), comes, as 10.4 says: "From 0.55.8, a part of the left folder
  moved back in the same batch to its own place below a folder of that name (mv X /out/X; mkdir -p Q/X; mv /out/X/sub Q/X/) can
  instead be hard-linked from the version before, as the no-copy move links a move into a new folder."
- **Line 31.** "The links a backup makes are in no size record:" becomes "The forward links (symlinks) a backup makes are in no
  size record:", and after that sentence comes "A hard link of the no-copy move adds a name, no inode or data block." On Q25's
  (a), "and of moves that fall back to a copy, which the estimate leaves out." becomes "and of moves that fall back to a copy,
  which the estimate leaves out; from 0.55.8 it also leaves out a file it expects the no-copy move to link, so a backup exceeds
  the limit by such a file when the replay copies it after all (its contents differ under the same size, mtime, mode, owner and
  group, say; on a vault that refuses hard links, every such file)."
- **Line 115**, "a restored file carries the newest mode, owner and times its shared copy has" becomes "a restored file carries
  the newest mode, owner, times and extended attributes its shared copy has": a synced extended attribute reaches a shared
  inode too (`writer.file_meta()`, as after a renamed move today), and a linked file is one more such inode.

### 10.4 docs/limitations.md: "A move out of a folder that just left the tree is copied" (one sentence)

At the end of "What the operator sees", after "... as the copy of a move into a new folder can.", insert:

```
  From 0.55.8, a part of the left folder moved back in the same batch to its own place below a folder of that name
  (`mv X /out/X; mkdir -p Q/X; mv /out/X/sub Q/X/`) can instead be hard-linked from the version before, as the no-copy
  move links a move into a new folder ("A folder or file moved into a new folder is copied where it cannot be linked").
```

In "Revisit when", "Also when the no-copy move into a new folder gets its own design." goes: that design is this one, and its
name rule does not reach the entry's own shapes; "the log shows big copies from this route often" stays. In "Approved", append:
"Narrowed by the no-copy move's reach: <Q24's answer>." The rest of the entry stays.

## 11. Order of the build

The build starts once Q24 and Q25 are answered, on Q24's (a). **[Q24]** (b): nothing below is built. Its branch is made from the
merged 0.55.7, a precondition: this round uses code that is 0.55.7's and not on `r0556`, `VersionLookError` (its plan's Task
5), the strict look's answer for ENOTDIR (its spec's section 7; `real_folders_to(strict=True)` itself is on `r0556`, 8396), and
`finish_copies()`'s returned rels read as what the replay applied (its section 9), and meets its other changes as section 8
says. Each step is one commit whose tests pass, with the docs of the code it adds.
1. Section 5's code: `BatchSizes` by rel with `linked()`, `alone()` and its docstring, `link_kept()` with `links_refused`, and
   `finish_copies()`'s link entry, with the tests that need no replay (tests/test_tree_writer.py's, the writer-verb test, and
   `test_alone_answers_for_each_kind_of_record`, with the oracle's new `paths_sharing_an_inode()` in tests/vault_oracle.py,
   which that test is the first to use; nothing links yet). The main session runs tests/test_tree_writer.py in the VM after it.
2. Section 2: `released_names()` and `old_copy()`, with their tests (read by nothing yet).
3. On Q25's (a), sections 3, 4 and 6 together, in one commit: `no_follow_opener()`, `read_block()`, `same_file()`,
   `entry_metadata()` and `xattr_names()` on an fd, `copy_or_link()` (from here files link), the names built in `do_backup()`
   and passed on, `leaving` with tests/test_folder_times.py's stand-in taking `**kwargs`, and the log line; with them their
   tests, section 5's tests through `do_backup()` (all but step 1's), tests/test_moves_into_new_folders.py's other changes, and
   the texts of section 10 as Q24's and Q25's answers give them. Either half alone breaks that module's two estimate tests (the
   copy step alone makes the vault grow less than the estimate; the estimate alone charges fewer inodes than the replay copies).
   The main session runs the owner and group cases in the VM after it. **[Q25]** (b): the same without section 3 (`leaving`, the
   estimate's code and the stand-in's change are not built; `copy_or_link()` reads the names), with section 3's [Q25] (b) change
   of those two tests and its pin.
4. The builder's measurements and the fuzz step; then the main session's VM gates (tests/test_tree_writer.py, owner and group,
   crash and power loss with `REVERB_CRASH_FULL=1`, the pool's three runs) and the real daemon's measurement, whose figure
   replaces the expected "under 0.1 MB" in 10.1's text in its own commit; after the deploy, the cold figure from the live backups
   in P3's row (section 9).

## Questions for the user

docs/progress.md holds each question's full text for the user, kept in step with this spec; here are the question, what each
option builds, and the marks.

**Q24. Whether to build the no-copy move now.** The route links a file from the version before, in place of a copy, only when
the version before alone holds it, it compares equal in full, and it has the same mode, owner, group, mtime and extended
attributes; open is whether to build it yet.
- (a) Build it (Recommended): this spec, on a vault that links, with Only Sync Attributes on or off: section 2's reach linked,
  every copy the names do not reach copied (section 7), and section 10's texts (narrowing the main entry and README lines 15 and
  22; adding to README lines 4, 43 and 115 and to the entry on a folder that just left the tree). As after a move, under Only
  Sync Attributes (the default) a later change of a linked file's mode, owner, times or extended attributes also shows at its
  old place in the version before (for an unpack, or a `cp -p` then `rm`, the old file's place).
- (b) Not now **[Q24]**: nothing is built or written; the entry and this design stay on file, to be built when a size-limited
  job prunes for such a move, or a job over a tree of user files is added. The study's look at how often such a move happens
  goes with the question.
- Not offered: the earlier draft's key search (Calls to confirm).
- What waits on it: the whole build (section 11), and Q25, which (b) makes moot. The user's words: the pick "Drop the feature
  (Recommended)" (2026-11-07), whose option said the no-copy move gets its own design later; and on 2026-11-12, "continue next
  phase please" and the pick "Fixes + lightness, one round (Recommended)", offered with "the no-copy move into a new folder gets
  its own design round after" (the offered text, not theirs). (a) reaches beyond the move they named (a move made while down,
  an unpack elsewhere) by the same rule; (b) keeps it at this design; nothing they said is dropped.

**Q25. The size estimate and a file it expects the no-copy move to link** (asked with Q24; moot under its (b)). With a size
limit, the estimate made before each backup decides how many old versions to prune; from this round it charges nothing for a
file the copy step will find, so a move into a new folder no longer prunes for a copy never made, and where such a file is
copied after all (section 3's four new causes, among them a file changed after the estimate looked) the vault exceeds its
limit by that copy until the next prune. This widens the approved known limitation "Size estimates leave out a version's own
small blocks".
- (a) Widen the entry (Recommended): sections 3 and 10.2; a prune made for a copy never made removes a version for good, an
  overshoot lasts until the next prune; no vault has shown a refused hard link yet, and the pool test shows how mergerfs answers.
- (b) Charge every copy as today **[Q25]**: no new overshoot, but with a size limit each move into a new folder still prunes
  older versions for the full moved size ("after five small versions, one such move left only the newest"). Built so: no
  `leaving`; the two estimate tests of tests/test_moves_into_new_folders.py bound `written <= grew <= est_size` and `15 << 20 <=
  grew <= est_size`, their inodes as today; section 3's tests give way to its pin
  `test_the_estimate_charges_every_file_the_replay_links`; 10.2's and line 31's estimate sentences are not written.
- Not offered: comparing the bytes at the estimate too (every moved file read twice before the prune, and again at the copy).
- What waits on it: section 3, docs 10.2 and README line 31, and the build. The user's words it would narrow: none; it widens
  an entry approved 2026-10-26 ("Known limitation (Recommended)"), last widened 2026-11-13 ("Widen the entry (Recommended)").

## Calls to confirm

Departures from the study (`.superpowers/p3/study-report.md`, read against e166baa):
1. No table of what left: the old copy is looked up on disk where its delete put it, keyed by the monitored file (section 2).
2. The name form the study set aside, a deleted entry's last name found in any part of the new path (section 2).
3. The study's "not the inode the tree still holds" and its rows-under-moves exclusion become `alone()`, asked before the
   compare and at the link, which is also the claim-once (sections 1, 5).
4. The key is size, mtime, mode, owner and group from two lstats, so a chmod or chown with the move is charged and copied
   with no compare (sections 2, 3).
5. A tree deleted and unpacked again is reached only at another path: at its own the delete collapses into the create
   (sections 2, 7).
6. A delete at or above a move's source, which can replay after the creates, gives no name (sections 2, 3).
7. "On a pool / off a pool" is "on two renames / off them"; `shared` by rel tells a record's hard link from a rename by itself,
   not by `two_renames` (section 5).
8. The test plan: two TIMINGS plus the `at_once` stress test; the 32 shapes assert the version equals the tree; only the fuzz's
   twin step is new (section 9).
9. A renamed move, the copy fallbacks and a move into its own old place stay copies with their texts (README 19 and 42 too); a
   copy of theirs or of the verification links only by another delete's name, a true stand-in (the main session's ruling),
   left out of the estimate or charged through the same lookup (sections 3, 7, 10).

The step back's calls:
10. The tree's letting go is read in the size books, not fed from the deletes (run for its test's record kinds, reasoned in
    general); if a hole is found, the fallback is what each delete took, as a set of rels beside the names (section 5).
11. One rule on every job, Only Sync Attributes on or off; an ambiguous name is a copy (a bounded cost, no number); a tie rule
    can come once something needs it (section 2).
12. The draft's key search (renamed moves, twins elsewhere, off Only Sync Attributes only) is not built or offered: it does
    nothing on a default job and needs a table, an index and a bound (section 2, Q24).
13. The draft's "only rows recorded checked" goes: a placed link sets the commit's flush as a copy does and is recorded checked
    from the commit's read-back; no batch of links alone skips the flush (the main session's ruling) (section 1, item 8).
14. Under Only Sync Attributes a later synced attribute change of a linked file shows at its old place in the version before,
    as after a renamed move, on every job; README line 115 gains extended attributes (sections 7, 10.3).

The compare and the link:
15. The compare runs inline on the replay's thread (the main session's ruling: the pool drew findings every round, and nothing
    measured showed it needed), with no pool, window, cancel flag, settle, shutdown, pool tests, pool-or-inline run or
    `--compare_threads` help change; a linked move much slower than its copy is a finding at measurement (sections 4, 9).
16. A compare holds one `BACKUP_SEMAPHORE` permit while it opens and reads, given back by `try`/`finally` before the link or
    copy; no wait closes a circle, read in multiCMD 1.51 (section 4).
17. `poll_pools()` once after each compare, before the link or the copy (section 4).
18. A compare raising anything but an OSError or a JobFailure is a copy, one error line with its traceback a batch; a
    JobFailure, and `link_kept()`'s, fails the attempt (section 4).
19. Unbuffered handles; `hash_file()`'s post-open steps; `entry_metadata()` and `xattr_names()` on an fd; the seams
    `no_follow_opener()` and `read_block()`. Not `filecmp.cmp()` (its cache answers by size and mtime, the very case) nor
    `cmp -s` (it follows a link and blocks on a FIFO) (section 4).
20. The holes of both of two sparse files are skipped by `SEEK_DATA`, as `cp --sparse=always` copies by data; a compressed or
    inline file costs a seek pair a block (section 4).
21. 256 KiB blocks, coreutils' read size, two buffers a batch; `hash_file()`'s 1 MiB full-hash read, cited earlier, runs only in
    tests/test_helpers_cli.py and its doctest; section 9 measures 1 MiB (section 4).
22. The names are tested before any look: a file whose path holds no name costs a dict lookup a part and no lstat (section 4).
23. After a link refused with EPERM, ENOTSUP, EOPNOTSUPP or ENOSYS the batch copies with no compare (a flag of the writer);
    EXDEV and EMLINK stay per file (sections 4, 5).
24. No held set: the second of two new files of one old file is copied; a key matching other bytes costs up to two reads more
    than the copy: rare, Not an issue (sections 4, 5).
25. No wait at the end of `recheck_moved_folder()`: no compare is open at a delete, and no record can take a link's copy name
    into the version before (sections 4, 5).
26. `link_kept()` asks `alone()` itself and links only the compared inode: the check exists for mergerfs's `link-exdev` symlink
    modes, which the pool gate's third run forces; on a pool it rests on the default `inodecalc` (reasoned) (sections 5, 9).
27. A copy name `link_kept()` cannot remove fails the attempt, as a name of the kept inode the books do not know would let a
    second file link it (section 5).
28. `finish_copies()`'s branch for a folder above no longer real removes nothing more for a link: the copy name went with the
    folder; the ruling to remove one there is not built (section 5).
29. Metadata that differs is a copy, with no sync onto the shared inode under Only Sync Attributes (the study's call); access
    times are not compared (sections 1, 7).
30. A look that errs at the version before chooses the copy or the charge and fails no attempt, where 0.55.7's section 7 fails
    it: OSError from the old path's lstat, `VersionLookError` from the folder look (section 8).

The rest:
31. History shows a delete and a create for such a move (section 8). 0.55.7's growth leave-outs give no names (section 8).
32. The log line: one an attempt, led by "Reused" ("Linked" leads two prune lines), written before the commit, counting by the
    books at the end the links the version still holds, with no set of placed rels (section 6).
33. A hand edit of the vault during a batch is outside the estimate's claim, as it is outside the size books' (section 3).
34. The name rule's reach is documented as it is, a saved copy put back and a part of a left folder moved back among it; 10.4's
    entry drops its clause about this design and keeps its own trigger; the reach is revisited with 10.1's, renamed moves
    showing up in a real vault (the main session's call) (sections 2, 10.4).
35. The main entry's heading becomes "... copied where it cannot be linked" (progress.md's P3 names the old one); its cost is
    "expected" (under 0.1 MB for 100 MB of 1,000 files) until the real daemon measures it (section 10.1).
36. README line 4 names a link beside a copy, recorded checked and flushed by the commit (section 10.3).
37. VM figures are labelled so (another disk than the vaults'); the cold figure is the live backups' first linked move after
    the deploy against a like copy before, in P3's row (section 9).
38. Crash: `REVERB_CRASH_FULL=1` at the VM gate cuts every link step; the default stride may miss them; the recording run shows
    they exist; no killed child reports its kind (section 9).
39. Root-only tests run in the VM after steps 1 and 3 (section 11).
40. The found-folder tests named "copied" are renamed to what they assert, their comments and the docstring say linked;
    test_job_startup.py keeps its copy assert for a rename made while down (section 9).
41. The release is called 0.55.8 in the texts (the main session's number); the build starts from the merged 0.55.7 (sections 10,
    11).
