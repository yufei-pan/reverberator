# Round 22, step back: the events move the watches, and the tree's view waits for an empty queue

This is the design pass the user chose on 2026-11-09, "Step back on the design (Recommended)": look for a smaller design
than round 22's watch tree (v16, `2026-11-08-round22-watcher-design.md`), where a wrong watch map costs an extra copy or
a rescan of one folder, never wrong bytes or a lost change. v16 stays the fallback.

**The recommendation.** Keep 0.55.1's watcher and change four things in it:
1. **A walk never moves a watch the events hold.** One it finds at another path stays where the events put it, and the
   watcher notes where the walk saw it.
2. **What needs the tree's view waits until the kernel holds no unread event** (`FIONREAD` on the inotify descriptor is
   0 after a read is handled). Then the tree is where the events left it, so a probe sees what the events would say:
   a noted watch is put where the walk saw it (and that folder is copied, as its events since came at the old path),
   the watches of a folder that left the tree are removed, and a folder move that took two watches from one path is
   settled.
3. **A move reported by a watch whose path is not settled** (noted by a walk, of a folder that left, or taken in an
   ambiguous move) **is recorded as a delete and a create, never as a rename in the vault.**
4. **An overflow restarts the watch**, as v16 does.

It is +153/-74 lines in reverberator.py (+121/-65 without comments and blank lines) against v16's +815/-170, keeps no
state per watch, and costs nothing per file event. It closes the three deferred entries and passes the routes v16 fixes
(gates in section 8). The price is a copy where 0.55.1 kept a rename in a few rare orders: 25 more copies over the 5,150
orders of the 99 shapes that 0.55.1 gets right (section 7), and a limitation the user is asked about (section 6).

## The user's words

- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in
  run the background. so every little bit will sum up to a lot over days month years."
- "simpler and smarter is better"
- "one of the core for reverberator is reuse existing linux features and easy browse / restore."
- 2026-11-08: "Keep inotify (Recommended)".
- 2026-11-07: "Drop the feature (Recommended)": a move into a folder made in the same batch is copied, as on 0.55.
- 2026-11-09: "Step back on the design (Recommended)", whose text was: "A fresh design pass looks for a smaller design,
  where a wrong watch map costs an extra copy or a rescan of one folder, never wrong bytes or a lost change. One
  example: check a rename against the tree by inode before the vault applies it. v16 stays as the fallback, and its
  gates rerun when memory allows."

## 1. Where harm comes from

`wdDic` maps each watch to a path, and every event's path is `wdDic[wd]` plus the event's name (`watchFolder()`). Three
things write the map in 0.55.1, each at its own time against the events still queued:
- a walk (`initializeFolderWatchers()`, its `watch()`) sets each watch it meets to where the folder is now;
- a paired folder move rewrites every path under the old one (the loop in `watchFolder()`'s `MOVED_TO` branch);
- the expiry of a move-out (`expire_move_out()`, `forget_moved_away()`, `remove_moved_away_watches()`), the move into a
  new folder (`remove_watches_under()` in the discard branch) and the move into a skipped folder remove watches.

What the batch does with an event, and what can then go wrong:
- **A change** (`modify`, `attrib`, `create`) is copied or compared at its path. The collapse,
  `change_events_to_backup_entries()`, places a change made before a move where the later moves carry it (`carried()`),
  and drops one at a path that a later move lands on, as "of what that move replaced". So a path that lags behind the
  tree (the events have not moved it yet) is safe, and a path ahead of the events is not.
- **A move** is a rename in the vault (`do_reverb_backup()`'s `replay()`, with `VaultManifest.move_file()` or
  `move_tree()`). Nothing checks that the file now at the destination is the one the vault holds at the source.
- **The check after the batch**, `compare_scopes()` through `compare_entry()` and `compare_monitor_entry()`, looks only
  at the batch's touched scopes (`touched_scopes()`), and compares size, mtime and the last 64 KiB (`hash_file()`,
  `HASH_SIZE`). A change that keeps those three, as `cp -p` of a same-size file does and as the shapes' `poke` does,
  shows only by its event.

So harm needs two things: an event at the wrong path (or no event), and a change the check after the batch cannot see.
The harm map:

| What goes wrong in the map | How 0.55.1 gets there | The action that turns it into harm | Harm |
|---|---|---|---|
| A watch of a folder that left the tree stays mapped in it (stale) | its move-out read in a folder made in the batch is discarded, with no cookie, so nothing removes it; or an ancestor's rename re-pointed it before the expiry, which looks only under the old path (the deferred F3 entry) | a rename inside the folder outside is a move in the tree: `replay()` renames the vault's file of the folder now at that path, and `compare_monitor_entry()` passes it when the two files match in size, mtime and the last 64 KiB | wrong bytes (review 5's F1: 3 of 6 on 0.55.1) |
| The same | the same | a folder renamed inside the folder outside: the rewrite loop moves the watches of the live folder at that path too | lost change |
| A watch ahead of its events | a walk puts a watch where its folder is now while the folder's renames are still queued (`watch()`'s `wdDic[wd] = folder`) | a change read before the renames gets a path the renames never had; the collapse drops it (F2, `twice_old_race`) | lost change |
| The same, inside a folder made in the batch | the create's walk also puts that watch in `newDirWDs` | its events are discarded while its own move stays a move, so no copy holds them (`over_empty`) | lost change |
| The same, then taken by another move | the folder that was at that path moves away next, and the rewrite loop takes the watch with it (`root_put_*`) | the folder's later events go under another folder's path | lost change |
| Two watches under one path | `RENAME_EXCHANGE` (one rename swaps two folders); a stale watch and a live one; a watch a walk put ahead and the folder that is leaving | the rewrite loop moves both, so one folder's events go to the other's path | lost change; wrong renames |
| A live folder's watch removed | the expiry probes a watch at its mapped path while a rename of it is still unread (R5's order); the discard branch removes what is under the old path after a walk that did not reach the folder | no event for the folder; a full comparison cannot see the invisible change | lost change |
| A folder never watched | an overflow loses its create (`Q_OVERFLOW` only requests a full comparison); a walk at a path the folder no longer has | no event for the folder | lost change |

Every path to harm goes through one of three actions: a rename in the vault from events of a watch whose path is
wrong; a change recorded at a path ahead of the events (or discarded) where no copy covers it; and a folder with no
working watch. The step back makes each of the three safe at its source.

## 2. Candidates

**Identity before a rename, by inode.** The vault would check, before renaming a to b, that the tree's b is the file it
holds for a.
- The manifest records `kind, size, mtime_ns, mode, uid, gid, hash, link, unchecked` (`MANIFEST_RECORD_HEADER`): no
  inode and no ctime. The check needs a new column, recorded at every copy and kept through every rename: a format
  change of the manifest.
- On mergerfs it holds for files only. A pool's options are on the mergerfs process's command line and in the
  `user.mergerfs.*` xattrs of its control file (`/proc/mounts` shows only FUSE's own); the pools checked run 2.42.0 with
  the default `inodecalc=hybrid-hash` and `cache.attr=60`. On a scratch pool in a test VM with the same options, five
  files kept `st_ino` through a rename in their folder and a move to another folder; a folder did not: `fstat` through a
  descriptor opened before the rename gave a new number, while `stat` by path still gave the old one from the attribute
  cache.
- It would close F1 and nothing else: in F2 every rename is right and the change is lost, and a folder with no watch
  loses changes no rename touches.
- Not taken. The step back closes F1 by never renaming from a watch whose path is not settled (rule 3).

**A rescan instead of trust.** A comparison of a folder cannot see a change that keeps size, mtime and the last 64 KiB,
so it cannot stand in for a lost event. Where the watcher cannot be sure, only a copy is safe. Taken in that form: the
settle copies a folder whose events came at another path (rule 2), and a doubtful move is a copy (rule 3).

**The kernel's identity of a watch.** `/proc/self/fdinfo/<inotify fd>` lists each watch's file handle, and
`open_by_handle_at()` would give its folder's path now. It needs `CAP_DAC_READ_SEARCH` (the daemon has it; the test
containers as uid 65534 do not, so no gate could run it), FUSE decodes a handle only for an inode it holds, and the path
it gives is the tree now, ahead of the events, as a walk's is. Not taken.

**ctime in the manifest.** A rename moves a file's ctime as a write does, so a renamed file cannot be told from a
renamed and rewritten one without reading it whole. Not taken.

**v16's watch tree.** Exact bookkeeping of each watch's place, moved only by the events in order. It works, and it took
twenty rules to get there; section 9 compares the two.

**The step back (recommended).** Section 3.

## 3. The design

**The facts it rests on.**
- **A.** The kernel queues a change's events inside the system call that makes it, in one queue per inotify instance.
  `ioctl(FIONREAD)` on the descriptor gives the bytes queued (inotify(7)). So when a read's events are all handled and
  `FIONREAD` is 0, the map holds all the events said about every change made so far, and any change from now on comes
  as an event.
- **B.** The collapse carries a change through the moves after it (section 1). A path that lags behind the tree is
  safe; a path ahead of it is not. 0.55.1's walk makes paths lead; the step back lets them lag until the events, or
  the settle, move them.
- **C.** `add_watch` of a folder already watched gives back its watch (round 22's fact 6), so `add_watch(path) == wd` is
  a probe of whether a folder is at its path.

**The rules, against 0.55.1.**

| Where | 0.55.1 | Step back |
|---|---|---|
| A walk meets a watch held at another path | puts it there (`wdDic[wd] = folder`), and in `newDirWDs` for a create's walk | leaves it where the events put it, and notes the path the walk saw (`found`) |
| Folder `MOVED_FROM` | cookie with the watches under the path | the same; the watches are also `outgoing` until a move-in pairs |
| `MOVED_TO`, cookie known | `move` recorded, watches under the old path rewritten, walk | the same (`move_watches()`, 0.55.1's loop), unless a watch of either folder of the move is not settled (`found`, `outgoing`, `leaving`, `doubtful`): then the move-out expires into its delete, and the move-in is a create, as one with an unknown cookie |
| The rewrite takes more than one watch from exactly the old path | moves them all | moves them all, and each watch it moved is `doubtful`, with its path before |
| A move-out expires (quiet read, pair timeout, a create at its path, eviction) | delete recorded; `remove_moved_away_watches()` probes the watches still under the old path and removes them now | delete recorded; the move-out's watches are `leaving` |
| Folder `MOVED_TO` into a new folder, cookie known (discard branch) | walk, then `remove_watches_under()` of the old path | the watches move with it as the events say (unless not settled), then the walk |
| Folder `MOVED_FROM` in a new folder (discard branch) | nothing: the watches stay for good | the watches under the path are `leaving` |
| Folder `MOVED_TO` into a skipped folder, cookie known | `remove_watches_under()` now | the move-out's watches are `leaving` |
| End of a read, and every read with no event | nothing | `settle()`, when anything is noted and `FIONREAD` is 0 |
| `Q_OVERFLOW` | full comparison requested; the watch goes on | the same, then the watch ends and `watcher()` starts a new one, which walks the tree and requests a full comparison again (v16's 2.7) |

**`settle()`**, once the kernel holds no unread event:
1. Each `found` watch still at another path than the walk saw, and which the probe finds there, is put there. Its folder
   is walked (watching what was made in it while its events came at the old path) and copied (a `create` event). A
   watch is left there with no event of the move only when the move was not taken as one (a move-in with no pair, one
   in a folder made in the batch, or one rule 3 turned into a copy), so the batch copies that folder already and the
   collapse drops the second copy as covered; section 7 counts what it adds.
2. Each `doubtful` watch not at its path, but at its path before, goes back there, and that folder is copied.
3. Each `leaving` watch not at its path is removed, if `FIONREAD` is still 0 after the probes (nothing moved while they
   ran). Otherwise they wait for the next settle.

Each correction is per watch, by probe, so two watches at one path never confuse it, and none moves a watch ahead of
the events: when the queue is empty there is nothing ahead.

**Why each harm is closed.**
- *A rename in the vault from a wrong path.* A watch's path can be wrong only while it is `found`, `outgoing`,
  `leaving` or `doubtful`, or a new watch a walk added ahead of its folder's arrival. A move through one of the first
  four is a delete and a create. A watch added ahead has no event of its own before its arrival (its folder's events
  come after its arrival in the one queue, fact A), and the arrival's walk finds it held elsewhere if a move-out took it
  meanwhile (`found`). The check after the batch then compares, and a copy is made from the tree.
- *A change at a path ahead of the events.* No watch moves ahead: walks note, the settle runs on an empty queue. A watch
  of a folder that reached its place where no event saw it lags at the old path until the settle, and the settle copies
  the folder (rule 1).
- *A folder with no working watch.* A watch is removed only at an empty queue, after a probe, and after the found
  watches were put where they are (so a folder that came back keeps its watch). Folders made inside a lagging folder are
  walked at the settle. An overflow walks the whole tree again.

## 4. The three deferred entries, v16's routes and item 23

- **"A folder renamed twice into a folder whose move is being walked can keep old bytes" (F2):** closed. The walk notes
  the folder and moves nothing; the change is recorded at its own path and the collapse carries it through both renames.
  No copy: the found watch is where the events put it by the settle. Gates: `twice_old_race`, `twice_old_race_sub`,
  `root_ahead` (section 8).
- **"A folder moved out of the tree from a new folder keeps its watch" (F3):** closed. A move-out discarded in a new
  folder makes its watches `leaving`, and an expiry makes them `leaving` by watch, not by path, so an ancestor's rename
  in between does not hide them. A rename they report meanwhile is a delete and a create. Review 5's F1 probe: 6 of 6
  right (0.55.1: 3 of 6 wrong).
- **"An event queue overflow can leave a new folder unwatched":** closed, by v16's restart. The overflow probe: 9 of 9
  right with the watch map checked both ways (0.55.1: 9 of 9 wrong).
- **v16's routes** (`exchange`, `exchange_twice`, `over_empty`, the `root_put_*` shapes, `back_home_*`,
  `land_ahead_taken`, `back_home_under_new`) and the seeds that found them: all in the gates of section 8.
- **v16's item 23** (an expiry before the folder's `MOVE_SELF`, with a create elsewhere at the same path) does not
  arise: the step back takes no meaning from a subfolder's `MOVE_SELF` (0.55.1 skips it, as before) and removes no watch
  by its place in the event order, only by a probe on an empty queue.

What the step back leaves, reasoned, not run:
- **A rename caught between its two halves in the kernel.** `vfs_rename()` moves the name, then queues its events; a
  probe in between sees the new tree with an empty queue. If a `leaving` watch's folder came back into the tree and is
  renamed in exactly that instant, the settle removes its watch; its move-in then pairs and walks, so the folder gets a
  new watch at once, and a change in the microseconds between could be lost. It needs a folder that left, came back,
  and is renamed during the settle's probe of it. v16 rests on the same kernel ordering (its facts 1 to 16); 0.55.1's
  expiry probes with a whole read unhandled.
- **A tree with no instant of an empty queue.** The settle waits for one. Until then a found folder's changes come at
  its old path, and a move through an unsettled watch is a copy. The settle runs after the read that ends each burst of
  events, so a batch taken after a quiet period always follows it; only a batch the maximum delay takes while events
  keep coming can be taken before it, and that version can miss a change in the found folder, which the settle's copy
  brings into the next version.

## 5. What changes for the operator

- The three deferred entries go (section 4).
- **A move out of a folder that has just left the tree is copied**, where 0.55.1 renamed it in the vault: `mv X /out/X;
  mv /out/X/sub sub` within the pair timeout (60 s by default) copies `sub` whole. So is a rename reported by a folder a
  walk found ahead of its events, or by one of the two folders of a `RENAME_EXCHANGE`, until the next empty queue. The
  version is right; the copy costs the moved entry's size once. This is new, and needs the user's OK as a known
  limitation (section 6).
- An overflow restarts the watch: one more INFO line, "Watching the tree again after the overflow", and a second full
  comparison after the walk (v16's 2.7).
- Two INFO lines: `Copying <path>: its watch got there with no event of the move, so its events since came at its old
  path` (the settle's copy) and `Copying <path>, moved from <path>: a watch of the move is not settled` (rule 3).
- The watches of a folder moved out of the tree go at the first empty queue after the move-out expires, where 0.55.1
  removed them at the expiry itself.

## 6. Limitations to propose

Each needs the user's OK before it is written down; none is decided here.

1. **"A move out of a folder that just left the tree is copied"** (known limitation). What the operator sees: a file or
   folder moved back into the tree out of a folder moved out of it less than the pair timeout before is copied, not
   renamed; also a rename in a folder a walk saw ahead of its events, or swapped by `RENAME_EXCHANGE`, until the watcher
   next finds its queue empty (normally the end of that read). Why: such a watch can report its folder's moves at a path
   another folder now has; trusting it is the route to F1's wrong bytes, and telling the two apart needs v16's watch
   tree. Revisit when: the copy shows in the live logs (the INFO line above), or the no-copy move into a new folder gets
   its design.
2. **The settle needs an instant with no unread event** (known limitation, or a sentence in the entry above). A tree
   whose kernel queue never empties keeps a found folder's events at its old path until it does. Revisit when: a live
   job's watcher log shows found watches waiting long.

## 7. The cost

Measured through the real `watchFolder()` on real inotify on tmpfs in containers (uid 65534), `probes/bench_watcher.py`
(round 22's, with a workload added for `mkdir n; mv d n/`), 0.55.1 and the step back alternating, three runs each, the
watcher's CPU only. The host ran at a load of 200 to 270 on 32 cores, so the CPU numbers carry about ±10%; the ranges
of the two overlap in every workload but the overflow.

| Workload (a tree of 20,251 folders unless said) | 0.55.1 | Step back |
|---|---|---|
| The watcher's memory after watching 102,061 folders (tracemalloc) | 17.73 MiB | 17.74 MiB |
| The first walk of 102,061 folders | 0.724 to 0.777 s | 0.713 to 0.803 s |
| 20,000 file writes in 50 folders (24,000 to 26,000 events) | 0.125 to 0.160 s | 0.148 to 0.160 s |
| 200 renames of folders of 50 subfolders, and back | 1.331 to 1.499 s | 1.344 to 1.387 s |
| 300 folders of 10 subfolders moved out of the tree and back | 0.528 to 0.541 s | 0.538 to 0.562 s |
| 2,000 renames in a folder of 10,000 subfolders | 8.747 to 8.972 s | 8.594 to 8.707 s |
| 300 times `mkdir n; mv d n/` | 0.453 to 0.487 s | 0.483 to 0.488 s |
| 10,000 folders made one by one, as `tar x` | 0.078 to 0.094 s | 0.081 to 0.083 s |
| One overflow | none (no walk) | 0.153 to 0.165 s: the restart walks the tree, about 8 µs a folder |

- **Memory:** no state per watch. `found`, `leaving`, `doubtful` and `outgoing` hold only the watches of a race or of a
  move-out, until the next empty queue or expiry.
- **Per event:** nothing for a file event (5 to 6.5 µs an event on both codes in the file writes above). One `settle()`
  call per read, which returns at once when nothing is noted; with something noted, one `FIONREAD` ioctl. A move-in
  whose move-out was read looks its two folders' watches up in four sets, almost always empty: eight hash lookups.
- **Per folder walked:** for a watch the walk finds held (not a new one), one comparison of its path, as before.
- **Per folder move:** 0.55.1's pass over every watch stays (v16 removed it; section 9).
- **Extra reads:** the settle's probes (an `add_watch` per noted watch, a path lookup in the dentry cache) and its walk
  of each found folder; the copies of rule 3 read the moved entry whole.
- **Extra copies, counted:** the 99 schedule shapes at small bounds (every order to 6 visits for 3 and 4 steps, to 5 for
  5 steps, 50 sampled for 6 and 7; 5,334 orders), each order's batches logged on both codes and each create carried
  through the batch's later moves and deletes as the collapse carries it, a create under another one counted as
  covered (`tools/copycount.py` in the scratch folder). 0.55.1 ended wrong in 184 orders (`exchange_twice` 56,
  `root_put_*` 89, `exchange` 21, `over_empty` 18), the step back in none. Over the 5,150 orders 0.55.1 gets right the
  step back made 6,526 copies to 0.55.1's 6,501: 21 are `out_back_sub` (`mv big /out/big; mv /out/big/sub sub2`, the
  take-back of limitation 1, a copy of `sub` where 0.55.1 renamed it), and 4 are an empty folder of
  `root_put_into_itself` (`mkdir n; mv n big/n; mv big n`) copied by the settle. Where 0.55.1 is wrong the step back's
  extra copies are the repair (`exchange_twice` turns 2 renames an order into 2 copies).

## 8. Gates

All in containers as uid 65534 on the host's XFS, but the root suite, which ran in a test VM. The
variant is 0.55.1 (6726e75) with the step back, in a scratch clone; 0.55.1's and v16's numbers are round 22's
(section 9 of its spec) and v16's rerun of today, where it got to. The gates ran the prototype's commit 50e391d of that
clone (0.55.1's ran its 6726e75); the root suite copied the clone's files, and its tree was clean at that commit, with
no change and no untracked file, so the copy was the commit.

| Gate | Step back | 0.55.1 | v16 |
|---|---|---|---|
| The 99 schedule shapes at review 5's bounds, the watch map checked both ways (91,049 orders) | 91,049 orders, none wrong | 5,439 wrong: `back_home_via_outside` 1,238, `back_home_via_new` 870, `back_home_via_new_sub` 870, `exchange_twice` 816, `over_empty` 273, `root_put_*` 268, `found_out` 259, `land_ahead_taken` 225, `back_home_under_new` 179, `root_ahead` 147, `exchange` 136, `twice_old_race` 120, `twice_old_race_sub` 30, `back_then_sub_out` 8 | today's rerun: 91,049 orders, none wrong |
| `tests/test_watcher_schedules.py` with v16's 56 shapes, as the suite samples them (100 orders a shape) | 5,514 passed | its own 10 shapes: 40,801 passed at every order (round 21) | at every order: today's rerun, so far 118,887 orders (73%), none failed |
| The seed 4284 agent's 10 shapes at review 5's bounds, the watch map checked both ways | 11,949 orders, none wrong | not in round 22's record | not run |
| Review 5's F1 order (`probes/test_r5_f3_wrong.py`) | 6 of 6 right | 3 of 6 wrong | not run |
| Overflows in process, the watch map checked both ways (`probes/test_overflow.py`) | 9 of 9 right | 9 of 9 wrong | not run |
| The fuzz, lists checked | seeds 0 to 5,999: 6,000 passed, 3 teardown errors (254, 5723, 5811), all the size-record class; 5723 alone errors 1 of 3 here and 2 of 3 on 0.55.1 | seeds 0 to 5,999: 6,000 passed, 11 teardown errors, the size-record class | before the stop, 2,616 seeds, no failure; today's rerun, seeds 0 to 29,999 in 15 runs, so far 29,233 seeds, no failure, 41 errors (their reasons print at each run's end; 254 and 372 error on 0.55.1 too) |
| Fuzz seeds alone, 3 tries each | 2195, 2509, 4284, 12812, 12831, 14124, 16462 and 19006: 24 of 24 pass | round 22: 2509 2 of 2 and 12812, 19006 3 of 3 pass, 12831 and 16462 3 of 3 fail; today 12831 and 16462 pass 3 of 3 | 2509, 12812, 12831, 14124, 19006: 15 of 15 pass |
| The suite in containers as uid 65534 | 268 failed, 3,059 passed, 601 skipped, 1 error: the same 269 that fail on 0.55.1 in the run beside it (in containers the tests that need root fail or skip) | the same counts today (round 22: 287 failed, 3,321 passed, 320 skipped, 1 error) | not run |
| The suite as root in the test VM (`gate.sh`, with tag v0.54.1 so the 0.54 vault tests run), but `test_pool_cut.py` | 3,881 passed, 1 skipped (a queue-fill test this kernel would not fill) | 3,908 passed and the same skip, with `test_pool_cut.py` in the run: 27 of its 46 pass under xdist, which it refuses, and 19 fail | not run |
| `test_pool_cut.py` alone in the test VM | 46 passed | not run (under xdist above) | not run |
| The copy count of section 7 (5,334 orders) | none wrong | 184 wrong | not run |
| Prototype a, without `outgoing` (rule 3 not yet guarding a pending move-out's watches): `twice_old_race`, `over_empty`, `exchange`, `found_out`, `root_put_wrong_mover`, `c2_unwatched_old` | 4,949 orders, none wrong; then about 5% of the 99 and 275 fuzz seeds, none wrong | | |

## 9. Against v16

| | Step back | v16 |
|---|---|---|
| reverberator.py | +153/-74 | +815/-170 |
| Rules | four (section 3) | about twenty (its 2.1) |
| Memory | none per watch | 94 B a watch, 1.6 MB at the live 17,200 |
| First walk | as 0.55.1 | about 1.4 µs a folder more (idle), 24 to 85 ms at 17,200 |
| A folder made | as 0.55.1 | 3.7 to 5.5 µs more |
| A folder renamed | as 0.55.1: two passes over every watch | O(its subtree): 0.13 µs a watch a rename saved |
| Copies 0.55.1 does not make | a move out of a folder that just left the tree; renames through unsettled watches before the next empty queue; counted, 25 more copies in the 5,150 orders 0.55.1 gets right of 5,334 (section 7) | the root put's copy (14 of 5,624 orders) |
| Walk | 0.55.1's by path | through open folders, iterative, `/proc` needed |
| Known wrong order left | none run; two reasoned (section 4) | item 23, reasoned |

v16 is faster where one folder of a large tree is renamed often (its O(subtree) moves); the step back is lighter in
memory and in walks, and a fifth of the code. The passes over every watch at a folder move could go on their own later,
by an index of paths, without the rest of the watch tree.

## 10. Calls to confirm

1. **The recommendation:** the step back in place of v16, with v16 as the fallback until the step back's build passes
   its gates.
2. **New copies** (section 5): a move out of a folder that just left the tree, and a rename through an unsettled watch,
   are copied where 0.55.1 renamed. Known limitation 1 of section 6, for the user's OK.
3. **The settle waits for an empty queue** (limitation 2 of section 6), for the user's OK.
4. **The watches of a folder that left are removed at the first empty queue after its move-out expires**, not at the
   expiry; a probe with a read unhandled was R5's failure.
5. **The overflow restart is v16's**, with its log line and its second full comparison.
6. **Tests changed for the prototype:** the session restarts the watch after an overflow, as `watcher()` does; the
   session knows `exchange`; `tests/harness.py` gains `watch_map_errors()`; v16's 56-shape schedule file runs on
   0.55.1's walk hooks (`iter_tree_entries`), without its two `WatchTree` guard asserts.
7. **Not run:** the real daemon, and the schedule shapes on a scratch mergerfs pool (round 22's walk check, a mount test
   for the test VM). Nobody has reviewed this design yet; it goes to a review before a build, as round 22's did.
8. **The prototype is outside the branch,** in the session's scratch folder (`<scratchpad>/stepback/sv`, its frozen copy
   `stepback/vb` for the gates), with its diff in `stepback/out/stepback_reverberator.diff`. The schedule file ran on
   `sv`, which is `vb` with a docstring and the test changes of item 6.
