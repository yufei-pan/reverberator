# Round 22, step back: the events move the watches, and the tree's view waits for an empty queue (build spec)

Version 0.55.4, on main's 0.55.3 (the flush round, which shipped first). This is the design pass the user chose on
2026-11-09, "Step back on the design (Recommended)": a design smaller than round 22's watch tree (v16,
`2026-11-08-round22-watcher-design.md`), where a wrong watch map costs an extra copy or a rescan of one folder, never
wrong bytes or a lost change. A design review the same day found it sound with changes, a spec check followed, the main
session ruled on both, and the user approved its limitations. This revision is the spec a builder builds from, brought
up to date with the cost pass that followed the build. v16 stays the fallback until the build passes its gates.

**The design.** Keep 0.55.1's watcher and change four things in it:
1. **A walk never moves a watch the events hold.** One it finds at another path stays where the events put it, and the
   watcher notes where the walk saw it.
2. **What needs the tree's view waits until the kernel holds no unread event** (`FIONREAD` on the inotify descriptor is
   0 after a read is handled). Then a probe sees what the events would say: a noted watch is put where the walk saw it,
   the watches of a folder that left the tree are removed, and a folder move that took two watches from one path is
   settled; a folder whose events came at another path is copied where the batch does not copy it already.
3. **A move reported by a watch whose path is not settled** (noted by a walk, of a folder that left or is leaving, or
   taken in an ambiguous move) **is recorded as a delete and a create, never as a rename in the vault.**
4. **An overflow restarts the watch**, as v16 does.

It closes the three deferred entries and passes the routes v16 fixes, keeps no state per watch at rest and costs
nothing per file event. The price is a copy where 0.55.1 kept a rename in a few rare orders, and two known limitations
plus one sentence in a third (section 6).

**What the review changed** (each a main session ruling; sections 7 and 8 hold the numbers):
- **`outgoing` is a count per watch, and each move-out lets its watches go once** (3.2). As a set, an ancestor's
  pairing cleared the watch of a nested move-out still pending, and a rename it reported put wrong bytes in the version
  that a whole-tree comparison keeps (3 of 3 in process, on 0.55.1 too).
- **`settle()` acts per probe, with no retry** (3.4). The retry probed every `leaving` watch again at each read of a
  busy tree: 6.21 s of watcher CPU after a big move-out, where 0.55.1 spends 0.335 s.
- **The discard branch's folder move-out looks only at `newDirWDs` and `found`**, not at every watch (3.2): 2.94 to
  3.05 s against 0.046 to 0.053 s for 2,000 folder renames inside a new folder. (The cost pass replaced this look; see
  below.)
- **`follow_inner_mounts()` passes `found`** (3.5).

**What the spec check changed** (the main session's rulings on it, and the user's corrected picks):
- **The discard branch skips its scan when the same read holds the move-in** onto a watched folder that is not skipped
  (3.3); the move-in runs the scan only if its walk does not meet the moved folder's watch. (Replaced by the cost pass's
  MOVE_SELF rule; see below.)
- **A walk puts each watch it adds below a new folder into `newDirWDs`** (rule 3 of 3.2): a normal pairing's walk can
  reach new folders nested in the moved one.
- **`doubtful` keeps the first path before, and the settle probes every path the doubtful watches hold or held** (3.4).
- **A probe counts only for a path with no symlink in it** (fact C), and **a probe that cannot look leaves the watch
  flagged** for the next settle (3.4).
- **A found folder is copied by the settle only when a batch was taken since the walk noted it** (3.4).
- **`raise_queue_limit_for_removals()` goes**, and the settle removes at most half the instance's queue limit at a time
  (3.4). **The max-delay clock carries across an overflow's restart** (3.6). **One full comparison follows an overflow.**
- **A watch that leaves `wdDic` leaves every set** (3.2). The answers to a builder's questions are in 3.2 to 3.6, 8.2,
  10 and 11.
- **Limitations 1 and 2 as corrected; the overflow's window as one sentence** in "A rewrite made while down that keeps
  size and mtime" (section 6). The fact-E races and the first walk's race are not an issue (section 4).

**What the cost pass changed** (the main session's rulings on the build's report; 3.3, 3.4, 4 and 7 hold the details):
- **A folder move-out read in a new folder is marked by the moved folder's own `IN_MOVE_SELF`** (the MOVE_SELF rule,
  3.3). This replaces the same-read skip and its look by path. Under the skip, the look ran at nearly every rename:
  20,000 renames inside a new folder cost 14.9 to 15.6 s of watcher CPU, against 0.50 to 0.56 s on 0.55.1. They now
  cost what 0.55.1's do (section 7). The rule covers found watches too. It opened one window that the skip did not
  have; the main session ruled it Fix now, and the old `newDirWDs` serves the rule until the next take (section 4).
- **`settle()`'s walked and copied places are sets,** and each place looks up its parents (3.4, step 5). As a list,
  the cost grew with the square of the folders placed in one settle.
- **Rules 2 and 3 of 3.2 each have a shape that needs them,** at 28 visits, beyond review 5's bounds (3.2).
- **Version 0.55.4,** on main's 0.55.3.

**What the final review changed** (fix round 4, the main session's rulings; 3.2, 3.3, 4 and 7 hold the details):
- **The MOVE_SELF rule probes every subfolder's `IN_MOVE_SELF`,** but one whose own path holds a pending move-out
  (route B, 3.3). The cost pass's rule acted only for a watch in `newDirWDs` or `found`, inferring that the events
  followed every other move, and four reviews in a row found a watch where that was false. `new_before_take`, re-review
  2's cookie change and `WatchNotes.new_dirs` went with the inference.
- **Its cost:** one probe for each folder rename the pairing settled, with one `realpath` for each parent in a read
  (`renamesold`, section 7).
- **The settle's pass over the paths that left takes only the outermost ones** (finding 4, 3.4).
- **Parts that went:** `through_link()`'s form with no shared real paths, and a test pinning the absence of a call that
  no longer exists.
- **The schedule harness writes each step that failed** (an `OSError`, which counts as done) for the gate run to count
  by shape (section 8.2).

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
- 2026-11-09: "Yes, release them first (Recommended)": the restore sync, the estimate on XFS, long links and the XFS test
  fixes ship as 0.55.2 ahead of the watcher (so this build is 0.55.3).
- 2026-11-09, on the three limitations, each its own question:
  - "Accept: copy (Recommended)": a move out of the tree, then back within the pair timeout, a rename through a folder
    whose events the watcher hasn't reached, or through either folder of a swap, is copied whole until the queue next
    runs empty.
  - "Accept: next version (Recommended)": the tree's view waits for an empty queue, so under nonstop events a found
    folder's change can land one version late.
  - "Accept: one sentence (Recommended)": the overflow restart's blind window, about 0.15 s at 17,200 folders, for
    changes that keep size, mtime and the last 64 KiB, as one sentence in the existing overflow entry.
- 2026-11-09, after the main session said its first question had the window wrong:
  - Limitation 1, "Approve as corrected (Recommended)": the window is the job's minimum snapshot delay or 30 s,
    whichever is longer (60 s by default); anything moved from a folder that left the tree back into the tree is copied
    whole in that window; the same copy covers a folder moved onto the place of one that just left, then moved again,
    and renames through a two-folder swap until the queue next runs empty. "Revisit if the log shows big copies from
    this route often, as you said."
  - Limitation 2, "Approve as corrected (Recommended)": it also names that a folder swapped with another in one rename
    has its changes seen at the other folder's path until the next empty queue, then copied by the settle, and that
    after a batch taken in between, that copy copies the folder whole once more (vault space). "Revisit if a live tree
    shows long stretches with no empty queue, as you said."

Not the user's words: the rounds' ruling that when the watcher cannot be sure it errs toward a copy, never toward wrong
bytes (round 21).

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

- **Identity before a rename, by inode.** The manifest records no inode (`MANIFEST_RECORD_HEADER`), so it needs a new
  column kept through every rename, a format change; on mergerfs a folder's `fstat` gives a new number after a rename,
  so it holds for files only; and it closes F1 alone (in F2 every rename is right and the change is lost). Not taken:
  rule 3 closes F1 at its source.
- **A rescan instead of trust.** A comparison cannot see a change that keeps size, mtime and the last 64 KiB, so it
  cannot stand in for a lost event; where the watcher cannot be sure only a copy is safe. Taken in that form: the
  settle's copy (rule 2) and the copy of a move through an unsettled watch (rule 3).
- **The kernel's identity of a watch** (`/proc/self/fdinfo` handles and `open_by_handle_at()`): needs
  `CAP_DAC_READ_SEARCH`, which the test containers lack, FUSE decodes a handle only for an inode it holds, and the path
  it gives is the tree now, ahead of the events. Not taken.
- **ctime in the manifest:** a rename moves a file's ctime as a write does. Not taken.
- **v16's watch tree:** exact bookkeeping of each watch's place; it works, and took twenty rules (section 9).

## 3. The design

### 3.1 The facts it rests on

- **A. An empty queue is a complete map.** The kernel queues a change's events inside the system call that makes it,
  in one queue per inotify instance, and `ioctl(FIONREAD)` gives the bytes queued (inotify(7)). `inotify_simple`'s
  `read()` reads exactly `FIONREAD` bytes and keeps no buffer (the review read its `_readall`). So when a read's events
  are all handled and `FIONREAD` is 0, the map holds all the events said about every change made so far, and any later
  change comes as an event.
- **B. A path that lags is safe; one that leads is not** (section 1). 0.55.1's walk makes paths lead; the step back
  lets them lag until the events, or the settle, move them.
- **C. `add_watch` is a probe.** inotify keeps one mark per inode per instance, so `add_watch` of a watched folder
  returns its watch by whatever path (round 22's fact 6), with or without `IN_MASK_ADD`, which changes only how masks
  combine. `IN_ONLYDIR` and `IN_DONT_FOLLOW` steer only the lookup, and `IN_DONT_FOLLOW` covers only the last
  component: a symlink earlier in the path is followed (the spec check). So a probe of a path answers one of three:
  - **here:** it returns the watch, and the path has no symlink in it below the tree's root;
  - **not here:** `ENOENT` or `ENOTDIR`; another watch; a watch not in the map (a folder with no watch: the probe's own,
    removed again); or a symlink in the path below the root (the tree's walk never follows one, so the folder is not at
    that path in the tree);
  - **could not look:** any other error (`EIO`, `ENOTCONN` from a dead mergerfs, `ENOMEM`, `ENOSPC` at the user's watch
    limit). It is never counted as an absence (the rules' absence rule): the watch keeps its flag for the next settle.

  The symlink check is the builder's choice of two: compare `os.path.realpath(path)` with the root's real path (taken
  once per watch, so a monitored path that itself goes through a link still works) joined with the part of `path`
  below the root; or `lstat` each component below the root. It runs only when the probe returned the watch, as every
  other answer is "not here" already, so a big `leaving` set of folders gone pays nothing for it. Built (review 1): the
  realpath of the path's parent, once for each parent in one settle, as the probe found a folder at the last name and
  only the folders above it can be links.
- **D. C holds on mergerfs.** In the test VM, on a scratch mergerfs 2.42.0 pool over two tmpfs branches, with the live
  pools' options, then with `cache.entry=1`, then with every cache off: `add_watch` by a renamed folder's new path
  returned its old watch on every line, after a rename in place, a move out of the tree and back under a new name, a
  folder made after the mount renamed into another parent, and an ancestor's rename; `fstat` through an fd opened
  before the rename showed the new `st_ino` (FUSE finds an inode by node id, not by `st_ino`). So the rewrite of paths
  at a pairing and the settle's probes hold on the two live jobs that watch mergerfs trees. This answers a second
  reviewer's worry that a folder renamed there gets a new kernel inode.
- **E. A rename's window.** `vfs_rename()` moves the name, then queues its events under both parents' locks; a probe
  in between sees the new name with `FIONREAD` 0, for nanoseconds. Only a change inside the moved folder can land in
  that window, as it needs no parent lock (section 4).
- **F. Busy trees empty their queue often.** In a container, with writers at 57,000, 89,000 and 108,000 events a
  second and 6 µs of handling an event, the queue was empty after 69%, 59% and 42% of reads, the longest non-empty
  streak under 10 ms (the review's `fionread_burst.py`).
- **G. One full comparison at a time.** `ChangeEventQueue.append()` drops every event while a `full_scan` is queued, a
  second `full_scan` included.
- **H. A renamed folder's own watch is told after its rename's pair.** The cost pass checked this with real inotify as
  uid 65534 in a container; `tests/test_watch_settle.py` pins the first three cases:
  - a watched folder renamed in the tree gets `MOVED_FROM`, `MOVED_TO`, then `IN_MOVE_SELF` on its own watch;
  - one moved out of the tree gets `MOVED_FROM`, then `IN_MOVE_SELF`;
  - a folder with no watch gets no `IN_MOVE_SELF`, and neither does a watched subfolder of the moved one;
  - a `RENAME_EXCHANGE` gives one to each folder, after its own pair;
  - a watch removed before the rename gets its `IN_IGNORED` and no `IN_MOVE_SELF`.

  The two can still fall in different reads. Of 20,000 renames of watched folders under a concurrent reader, every
  `IN_MOVE_SELF` came after its `MOVED_TO` and none was missing, but 886 of 18,087 reads ended between the two. So the
  watcher acts on the event when it comes, and never on its absence.

### 3.2 The structures, and what each keeps true

All live in `watchFolder()` for one watch's life; an overflow's restart starts them empty.

| Structure | What it holds | What it keeps true |
|---|---|---|
| `wdDic` (wd → path) | as 0.55.1 | each path is where the events read so far put the folder, except while the watch is guarded. Only `move_watches()` at an unguarded pairing, the settle (on an empty queue) and removals change a held watch's path; a walk writes only the path of a watch it adds |
| `cookieDic` (cookie → `COOKIE_VALUE(wd, path, isDir, wds)`) | as 0.55.1: a move-out waiting for its pair; `wds`, the watches mapped at or under its path when its `MOVED_FROM` was read | a cookie holds its `wds` in `outgoing` from its `MOVED_FROM` until it lets them go, once |
| `newDirWDs` (set) | as 0.55.1: the watches of folders made since the last take, whose events are discarded (the batch's copy holds them) | its watches' events are discarded, and nothing else reads it: no rule decides where a watch is by it (fix round 4, below). Cleared at each take |
| `found` (wd → path) | a held watch a walk met at another path than its own, with the path the walk saw, and the take count the watcher knew at that read (3.4) | the watch is guarded until the next settle, which clears it |
| `outgoing` (wd → count) | for each watch, how many cookies hold it | the count is the number of cookies still holding the watch; the entry goes at zero |
| `leaving` (set) | the watches of a folder that left the tree or its place: an expired or evicted move-out's `wds`; a move into a skipped folder's; the watches under a folder moved out of a new folder whose own watch failed (it is in `unwatched`); and the watches at or under the path of a found or doubtful watch whose folder moved on (3.4) | each is probed at the next settle, and removed if its folder is not at its path |
| `doubtful` (wd → path before) | every watch a folder move took when the old path held more than one watch (`RENAME_EXCHANGE`, or a folder moved onto the place of one whose move-out is pending), descendants included, with its path before the first such move (a later one keeps it); and a watch whose `IN_MOVE_SELF` says it moved, but for one whose own path holds a pending move-out, unless a probe finds it at its path, with that path (3.3) | settled at the next settle |

**Guarded.** A watch is guarded while it is in `found`, `leaving` or `doubtful`, or its `outgoing` count is above
zero (`guarded()`). A move whose source folder's watch or destination folder's watch is guarded (the cookie's `wd` and
the `MOVED_TO`'s `wd`) is a delete and a create, never a rename in the vault, for a file as for a folder.

**A watch that leaves `wdDic` leaves every set** (`found`, `leaving`, `doubtful` and its `outgoing` entry; `newDirWDs`
keeps it until the next take clears it, as on 0.55.1, which harms nothing: only an event on a mapped watch is looked up
in it), wherever it goes: `DELETE_SELF`,
`UNMOUNT`, `follow_inner_mounts()`'s and `remove_newly_skipped_watches()`'s removals, a walk's unreadable folder, the
settle. Removing, letting go of, or flagging a wd that is no longer in
`wdDic` does nothing (`remove_watches()` skips it, as 0.55.1's `remove_moved_away_watches()` did; today it raises
`KeyError`). Watch numbers are not given again soon (round 22's fact 11), so a late let-go never touches another
folder's watch.

**The count** (review finding 1). In `mv keep/s/n2 /out/n2; mv keep c/keep2; mv live c/keep2/s/n2; mv /out/n2/g
/out/n2/h`, n2's watch is held by its own move-out and by keep's. As a set, keep's pairing cleared it while n2's
move-out was pending; the pairing had re-pointed it to `c/keep2/s/n2`, where `live` then landed, so the rename outside
was recorded as `c/keep2/s/n2/g → h` and the vault renamed live's g onto h. With the count, the watch stays guarded
until n2's own move-out lets it go, so that rename is a delete and a create.

**Each move-out lets its watches go once:**
- the normal branch's pairing pops the cookie and lets go (its watches moved with the folder, as the events say);
- an expiry (quiet read, pair timeout, a create at its path) or an eviction pops it, lets go, and makes its `wds`
  `leaving`;
- a move into a skipped folder pops it, lets go, and makes its `wds` and the watches under its path `leaving`;
- the discard branch's unguarded pairing moves the watches into the new folder and lets go, and keeps the cookie for
  its delete, as 0.55.1 does, stored again with no watches (`cookie_value._replace(wds=())`, which keeps its place in
  `cookieDic`). Its expiry then lets nothing go a second time, which would take the count of another pending move-out
  of the same watch, and makes none of them `leaving`: the walk after the move met them at their paths, and those it
  did not meet are in `newDirWDs` (rule 1 below), where a later move-out of them finds them. The review's patch let go
  at both the pairing and the expiry; that double release must not be copied;
- the discard branch's guarded pairing moves and lets go of nothing; its expiry does both, once.

**What `newDirWDs` is for** (fix round 4). Only which events are discarded, as on 0.55.1: those of a folder whose copy
the batch holds. Until fix round 4 it was also the MOVE_SELF rule's domain (3.3): the rule acted only on the
`IN_MOVE_SELF` of a watch in `newDirWDs` or `found` (or, after review 1, in `new_before_take`, the set before the
latest take). So every watch whose folder could leave a new folder by a move read on the new folder's watch had to be
in one of them, and three rules (below) put it there. Four reviews in a row found a watch outside them:
- review 1's take window (section 4);
- re-review 2's `lag_child_out`;
- the final review's three routes: a late create, an ancestor's move-out that pairs, and the settle's placement (all
  in section 4).

The rule now probes every subfolder's `IN_MOVE_SELF` but one whose own path holds a pending move-out (3.3), so no
membership is inferred, and `new_before_take` went. This removes the state the failures needed, where a fifth rule
would only have added more.

**Three rules put watches into `newDirWDs`.** They stay, now for the discard alone: each puts a watch there whose folder
the batch's copy holds.
1. **The discard branch's unguarded pairing puts every watch `move_watches()` moved into `newDirWDs`**, as 0.55.1's
   removal and the walk's re-adding did. Shape: `moved_sub_out_before_walk` (`mkdir n; mv big n/big; mv n/big/sub
   /out/sub`).
2. **The settle's walk of a folder it puts in place passes `newDirWDs`**, as every create's walk does. The batch
   holds a create that copies the folder (the settle's, or the one that noted it, 3.4). The settle also puts each watch
   it places there at the placement (review 1). Shape: `into_renamed_new_then_out` (`mkdir n/m; mv n/m n/m2; mv next
   n/m2/nx; mv n/m2/nx /out/nx`, to 28 visits).
3. **Any walk puts a watch it adds into `newDirWDs` when the folder it is in has its watch there** (the spec check's
   4a). The walk knows that folder's watch from its own record of what it watched (`watched`). A walk's root joins only
   when its caller passes `newDirWds`, as today, so an inner mount's walk, whose root's parent is not looked at, keeps
   its events (section 4). Shape: `new_sub_walked_by_pair_then_out` (`mkdir next/n; mkdir next/n/s; mv next nx; mv
   nx/n/s /out/s`, to 28 visits).

Under the old rule each shape kept a stale watch without its rule: 495 orders at review 5's bounds, 36 and 280 of
4,060 to 28 visits. They stay in the schedule file. Without a rule now, its folder's events are recorded rather than
discarded: more work, still right.

### 3.3 Event by event, against 0.55.1

| Where | 0.55.1 | Step back |
|---|---|---|
| A walk meets a watch held at another path | puts it there (`wdDic[wd] = folder`), and in `newDirWDs` for a create's walk | leaves it where the events put it, notes the path the walk saw in `found`, and does not add it to `newDirWDs` (3.5) |
| A walk adds a watch below a folder of `newDirWDs` | in `newDirWDs` only for a create's walk | in `newDirWDs` for any walk (rule 3) |
| Folder `MOVED_FROM` | cookie with the watches under the path | the same; each of them gains one in `outgoing` |
| Folder `MOVED_FROM` in a new folder (discard branch) | nothing: the watches stay for good | no cookie, as on 0.55.1. The moved folder's `IN_MOVE_SELF` marks its watch (the next row). For a moved folder whose own watch failed (it is in `unwatched`), the watches at or under the path, by one pass over the map, are `leaving` |
| A subfolder's `IN_MOVE_SELF` | skipped | a probe of the watch's path, but when that path holds a pending move-out (its own, which deals with it). Unless the watch is there, it is `doubtful` with that path (the MOVE_SELF rule, below) |
| `MOVED_TO`, cookie known, neither folder's watch guarded | `move` recorded, every path under the old one rewritten, walk | the same (`move_watches()`, 0.55.1's loop; walk with `found`); the cookie lets go |
| `MOVED_TO`, cookie known, a folder's watch guarded | as above | rule 3's INFO line, for a file as for a folder; the move-out expires into its delete, and the move-in is a create (walk with `newDirWDs` and `found`), as one with an unknown cookie |
| The rewrite takes more than one watch from exactly the old path | moves them all | moves them all, and every watch it moved is `doubtful` (descendants too), keeping the path before the first such move |
| A move-out expires or is evicted | delete recorded; `remove_moved_away_watches()` probes the watches still under the old path and removes them now | delete recorded; it lets go, and its `wds` are `leaving` |
| Folder `MOVED_TO` into a new folder, cookie known (discard branch) | walk, then `remove_watches_under()` of the old path | unguarded: `move_watches()`, every watch it moved into `newDirWDs`, the cookie lets go and stays with no watches; guarded: nothing moves. Then the walk, with `newDirWDs` and `found` |
| Folder `MOVED_TO` into a skipped folder, cookie known | delete; `remove_watches_under()` now | delete; the cookie lets go; its `wds` and the watches under its path are `leaving` |
| End of a read, and every read with no event | nothing | `settle()` (3.4) |
| `Q_OVERFLOW` | full comparison requested; the watch goes on | the same, then the watch ends and `watcher()` starts a new one (3.6) |

**The MOVE_SELF rule** (the cost pass's ruling 1, in place of the spec check's same-read skip; fix round 4's form). A
folder move-out read in a new folder keeps no cookie, so nothing pairs it or expires it. The moved folder's own watch
tells the move (`IN_MOVE_SELF`, fact H).
- **The rule.** On a subfolder's `IN_MOVE_SELF` of a mapped watch, the watcher probes the watch's path (fact C) unless
  that path holds a pending move-out. Unless the watch is there, it is `doubtful`, with that path.
- **The skip.** A pending move-out at the watch's own path is the folder's own: the kernel queues the rename's
  `MOVED_FROM` and `MOVED_TO` before its `IN_MOVE_SELF` (fact H). If the `MOVED_TO` came, the pair has already put the
  watch where it went, and no move-out is pending there. If not, the folder left the tree or went where the events
  keep no pair, and the move-out's expiry makes its watches `leaving`.
- **The settle.** Step 2 (3.4) probes the watch again. If its folder is at neither its path nor its path before, it
  leaves with every watch its path holds, but for those at their paths.
- **Why every other one is probed** (fix round 4). The cost pass's rule probed only a watch in `newDirWDs` or `found`
  that no pending move-out held (`outgoing`), so it inferred from those sets that every other move was in the events'
  view. Four reviews in a row found a watch where it was not:
  - review 1's take window, closed then by `new_before_take`;
  - re-review 2's `lag_child_out`, closed then by a cookie that also took the found place's watches;
  - the final review's late create, its ancestor's move-out that pairs, and the settle's placement window (section 4).

  The probe needs no such inference. `new_before_take` and re-review 2's cookie change went with the set condition.
  Their shapes and tests pass without them: `lag_child_out` and `lag_child_out_back` (1,640 orders), and the take
  window's test.
- **Its cost** is one probe for each folder rename in the tree that paired: an `add_watch` and one `realpath` of the
  parent. `renamesold` measures it (section 7).
- **The watches it leaves alone.**
  - A watch with no `IN_MOVE_SELF`: a folder under a moved one, which a pair moves with it, and the settle's pass over
    the paths that left covers.
  - A watch a walk found is probed like any other. If it is not at its path, it is `doubtful` too, and step 1 settles
    both when it puts the watch in place.
- **The look by path** (one pass over the map, at the `MOVED_FROM`) stays for one case: a moved folder whose own watch
  failed (it is in `unwatched`). Its subfolders may hold watches that get no `IN_MOVE_SELF` of their own (fact H).
- **Why the skip went** (the cost pass). In `renamesinnew`, each folder's create and rename come in one read, so the
  move-in's walk adds a new watch at the moved folder's place, which the fallback could not tell from another folder
  there. The look over `newDirWDs` ran at nearly every rename, and its cost grew with the square of the renames
  (section 7).
- **Absence and overflow.** The rule acts on the event when it comes, and never on its absence. An overflow restarts
  the watch, and a lost `IN_MOVE_SELF` goes with it.
- **Tests.** `tests/test_watch_settle.py` pins fact H. It also runs:
  - a folder made in a new folder, renamed in it and then out of the tree in one read, with another made at its first
    name, both watched before and never watched (without the rule, the watched case keeps a stale watch, 3 of 3);
  - the take window (section 4);
  - the final review's first walk and ancestor routes (section 4).

File moves follow the same rows (guarded or not); a file's move-out holds no watch.

### 3.4 `settle()`

**Where it runs:** at the end of every read's events, and at every read with no event after the quiet read's expiries,
in both cases before the read's `read_wall_ns` and `pending_move_outs` stamp, and, with no event, before the quiet
signal and the branch's `continue`: the stamp claims every change before the read began has its event queued, so the
settle's creates must be queued under it. It returns at once unless `found`, `leaving` or `doubtful` holds something
and `FIONREAD` is 0. Then, each step by probe (fact C: `add_watch` with the watcher's mask, `IN_ONLYDIR` and
`IN_DONT_FOLLOW`):
1. **`found`:** each watch still at another path than the walk saw, which the probe finds here, is put there, and
   joins `newDirWDs` at once (rule 2 of 3.2). A doubt on it (the MOVE_SELF rule's, 3.3) is settled with it. A watch the
   probe finds not here moved on before the queue emptied, by a move whose events reached it at its path: that path
   joins the paths that left (below). One the probe could not look for stays in `found`. The rest of `found` is
   cleared.
2. **`doubtful`:** every path a doubtful watch holds now or held before (its first path before) is probed once, and
   each doubtful watch a probe finds here goes to that path, its folder to be copied if it moved, and joins `newDirWDs`
   at once (rule 2 of 3.2).
   - One a probe could not look for stays in `doubtful`.
   - So does one still in `found`: its walk's place could not be probed, and step 1 settles it later.
   - Any other doubtful watch is at neither of its paths. Its folder left the tree or its place, and its path joins the
     paths that left.

   The spec check's two orders show why every path is probed:
   - in `mv --exchange site.new site; mv site.new site.old`, the second move takes both watches again, and only the
     first path before (`site`) finds the watch of the folder now at `site`;
   - in `exchange A B; exchange A C`, one watch is at neither of its own paths, only at a path another doubtful watch
     held.

   **The paths that left:** every watch at or under one of them becomes `leaving`, for step 3 to probe at its own path.
   What the map held there may have gone with the folder: the walk that found a watch could not list what moved on
   before it got there, and the MOVE_SELF rule marks only the moved folder's own watch. A watch still at its path stays.
   This pass is the build's fix for the hole it reported as finding A, for found watches; the cost pass runs it after
   step 2, for doubtful watches too.
   - **Where it looks:** one pass over `wdDic`, a prefix test for each path against the outermost paths that left (with
     or without the trailing slash; a path under another adds nothing, and cost a comparison per watch: the final
     review's finding 4, section 4). No set holds every watch under a path (3.2), and an inner mount's watches are in
     none of them (section 4).
   - **Why not a view by parent.** The map keeps no parent-to-children view, which would be state for each watch at
     rest, and the watch tree of round 22's first design.
   - **The cost** (review 1). The cost pass's code walked up each path's parents: 300 times `mkdir -p new/d/s; mv new/d
     /out/` (`outofnew`) cost 3.3 to 3.4 s, against 0.04 s on 0.55.1 (section 7). The prefix test brings it to 0.34 to
     0.40 s, about 1 ms for each such move-out on a map of 20,000 watches, in proportion to the map (fix round 2's
     runs; fix round 1 measured 0.19 to 0.22 s for the same pass, whose tree now runs as 898961f does). Fix round 1
     narrowed the pass to `newDirWDs` and the found watches when every folder that moved on was in `newDirWDs` (0.04
     to 0.07 s), on the line that what a path of `newDirWDs` holds is there. Review 1's probe of it found that line
     false (12 of 558 settles, 3.2) and the inner-mount route open again, so the fix round 2 ruling took the plain pass
     and its cost.
3. **`leaving`:** each watch the probe finds not here is removed (`remove_watches()`); one it could not look for stays
   for the next settle; one still in `found` or `doubtful` waits for its walk's place, or a path it holds or held, to be
   probed (review 1: step 3 had probed a kept doubtful watch at its own path, found nothing and removed a live folder's
   watch); the rest leave `leaving`. At most
   half the queue limit the instance was made with is removed in one settle; the rest stays for the next one (ruling on
   `raise_queue_limit_for_removals()`, below).
4. The probes' own watches (a folder at a probed path that had none) are removed.
5. Each folder put in place is walked, outermost first and once (one under another is in its walk), with `newDirWDs`
   and `found` (rule 2 of 3.2), so what was made in it while its events came at another path gets watched. The walked
   and copied places are sets, and each place looks up its parents in them, so the cost is the place's depth, not the
   number of places (the cost pass's ruling 2; a list grew with the square of the separate folders placed in one
   settle). It also gets
   a `create` event, with one INFO line, `Copying <path>: its changes came at another path until the event queue ran
   empty`, when the batch does not copy it already:
   - a doubtful folder, always: the batch recorded the swap as moves, and its repair copies come from a comparison of
     size, mtime and the last 64 KiB, which does not see a change that keeps them;
   - a found folder, only when a batch was taken since the walk noted it (the spec check's Q2 (a)): with no take
     since, the batch still holds the create whose walk noted it (a move-in with no pair, a guarded move-in, or the
     create of the new folder it is in), so the settle's create would be a second copy that the collapse drops as
     covered. The watcher stores with each `found` entry the take count it knew at that read, and the settle compares
     it with the queue's own count under the queue's lock, as the discard branch's "a take since this read" check
     does: a take between the read and the settle then counts as a take, so a copy is never skipped wrongly (one taken
     just before the note costs a covered copy).

   Each walk comes before its create, so a change made after the copy passed it raises its event.

`found` comes before `doubtful` and `leaving`, so a folder that came back keeps its watch; the walks come last. Each
correction is per watch, by probe, so two watches at one path never confuse it, and none moves a watch ahead of the
events: on an empty queue nothing is ahead. New `found` entries from step 5's walks wait for the next settle: the
watcher reads again within its poll wait (3 s by default), with those watches guarded meanwhile, and a loop of settles
in one read would need another bound.

**Why no retry** (the review's argument, ruling 2). A probe that finds a leaving watch not here, on a queue that was
empty when the settle began, means its folder is not there. A folder that comes back into the tree while the probes
run comes back by a rename whose events are read next: from outside its cookie was never seen, so the move-in is a
create, whose walk gives it a new watch and whose copy holds what it holds, a change made before that walk included;
within the tree its move-out and move-in come too, with the same walk. So no removal needs undoing, and none needs the
queue to stay empty while the probes run. The design pass's re-check (`if not queued_events()` before the removals)
made every probe of a big `leaving` set run again at each read of a busy tree, removing nothing.

**Removals and the queue.** Each removed watch queues an `IN_IGNORED`, which counts against the queue limit, and the
kernel reads that limit only when an instance is made (round 22's fact 15), so `raise_queue_limit_for_removals()`'s
sysctl write never enlarged the queue of the instance removing the watches. It goes. The settle caps its removals at
half the limit the instance was made with (`irm.max_queued_events` read just before `inotify_simple.INotify()`; the
kernel's default 16,384 if it could not be read), so their `IN_IGNORED` events fit with the other half free for the
tree's own events until the next read takes them; a `leaving` set of 10,001 under the default limit takes two settles.
The other removals (an inner mount's, a skip list's after a move, a walk's unreadable folder) are as 0.55.1 left them
in effect, as the raise never reached them either; an overflow there now restarts the watch.

### 3.5 The walks

`initializeFolderWatchers()` gains `found` (a dict) and rule 3. With `found`, a held watch met at another path than its
own stays where the events put it, `found` gets the path the walk saw, and the walk returns the watch without adding it
to `newDirWds`: it is guarded until the settle. The walk still lists the folder by path (`iter_tree_entries()`), so what
is under it is met too. Callers:
- the first walk of a watch: without `found`, as 0.55.1 (its race with a rename is not an issue, section 4);
- a create's walk and a move-in's with no pair: `newDirWDs` and `found`;
- the normal pairing's walk: `found` (rule 3 still puts what it adds below a new folder into `newDirWDs`);
- the discard branch's walks: `newDirWDs` and `found`;
- the settle's walk: `newDirWDs` and `found`;
- `follow_inner_mounts()`'s walk of a mount point: `found` (review finding 4), passed down from `watchFolder()`; not
  `newDirWDs`, as its scan only compares, so it must keep the mount's events.

### 3.6 The overflow restart

At `Q_OVERFLOW` the watcher logs as 0.55.1 does (`Queue overflow, event maybe lost` at ERROR, `Attempting to increase
inotify max_queued_events`), doubles the queue limit, queues a full comparison, logs `Watching the tree again after the
overflow` (INFO) and returns `WATCH_RESULT_OVERFLOW`, leaving the rest of the read unhandled. `watcher()` takes it as a
lost root (`root_lost`, so the next `watchFolder()` gets `root_returned`), without the lost root's ERROR line and
signature reset:
- closing the old instance frees its watches at once, with no flood of `IGNORED`;
- the new instance takes the raised limit, which the kernel reads only when an instance is made (round 22's fact 15);
- its first walk watches the tree as it is, a folder whose create was lost included;
- **one full comparison follows:** the one queued at the overflow makes the batch in progress a full comparison, and
  the restart's own request after its walk is dropped while that one is queued (fact G). Only if a batch is taken
  during the walk does the restart's request make the next batch a full comparison too, which then covers the walk.
- **the max-delay clock carries across the restart:** the new watch counts from the old watch's last take, not from its
  own start (0.55.1 never restarted at an overflow, and while events never pause only the maximum delay takes a batch,
  so repeated overflows, as when the sysctl cannot be raised, must not keep putting it off). How the time reaches the
  new watch is the builder's choice (for example, `watcher()` keeps it and hands it to each `watchFolder()`).

What the old watch held goes: its pending move-outs (the comparison finds what is gone), `newDirWDs` (the new watch
keeps those folders' events: more events, no loss) and the four sets. From the old instance's close until the new walk
reaches a folder, nothing watches it: about 8 µs a folder, 0.15 s at 17,200 folders (the sentence of section 6).

### 3.7 What goes, what stays, what comes

- **Goes:** `remove_moved_away_watches()` (its probe moves to the settle); `raise_queue_limit_for_removals()` and its
  sysctl write (3.4); the rewrite loop written inline in the `MOVED_TO` branch (it becomes `move_watches()`); the
  discard branch's `remove_watches_under()` at a folder move-in with a known cookie; the skipped move-in's
  `remove_watches_under()`; the walk's `wdDic[wd] = folder` for a held watch when `found` is given; `Q_OVERFLOW`'s
  `continue`; and, at the cost pass, the spec check's same-read skip (its index, its recorded paths and the move-in's
  fallback).
- **Stays:** the walk by path; `cookieDic` and its `wds` (one pass over every watch at each folder move-out, one at each
  pairing; v16 removed them); `newDirWDs` and its discard, cleared at each take; the expiry triggers; `remove_watches()`
  (skipping gone wds); `remove_newly_skipped_watches()`; `follow_inner_mounts()`'s `remove_watches_under()`; the
  `DELETE_SELF` and `UNMOUNT` handling.
- **Comes:** `found`, `outgoing` (a count), `leaving`, `doubtful` and `guarded()`; `move_watches()`, which also returns
  the watches it moved (for rule 1); `settle()` with its three-way probe; `queued_events()` (`FIONREAD`, with `import
  termios`); the MOVE_SELF rule (3.3); `WATCH_RESULT_OVERFLOW` and the carried
  max-delay time; `found` and rule 3 in `initializeFolderWatchers()`, and `found` in `follow_inner_mounts()`; the INFO
  lines of section 5.

### 3.8 Why each harm is closed

- *A rename in the vault from a wrong path.* A watch's path can be wrong only while it is guarded, or while it is a new
  watch a walk added ahead of its folder's arrival. A move through a guarded watch is a delete and a create, and the
  count keeps a watch guarded while any pending move-out holds it, so an ancestor's pairing in between does not clear
  a nested one's. A watch added ahead has no event of its own before its arrival (its folder's events come after the
  arrival in the one queue, fact A), and the arrival's walk finds it held elsewhere if a move-out took it meanwhile
  (`found`). The check after the batch then compares, and a copy is made from the tree.
- *A change at a path ahead of the events.* No watch moves ahead: walks note, the settle runs on an empty queue. A
  watch of a folder that reached its place where no event saw it lags at the old path until the settle, and the folder
  is copied, by the batch's create or the settle's.
- *A folder with no working watch.* A watch is removed only by a probe on an empty queue that found it not here (never
  one that could not look, nor through a symlink), after the found watches were put where they are (so a folder that
  came back keeps its watch). Folders made inside a lagging folder are walked at the settle. An overflow walks the whole
  tree again.

## 4. The three deferred entries, v16's routes and item 23

- **"A folder renamed twice into a folder whose move is being walked can keep old bytes" (F2):** closed. The walk notes
  the folder and moves nothing; the change is recorded at its own path and the collapse carries it through both renames.
  No copy: the found watch is where the events put it by the settle. Gates: `twice_old_race`, `twice_old_race_sub`,
  `root_ahead`.
- **"A folder moved out of the tree from a new folder keeps its watch" (F3):** closed, with the count. A move-out
  discarded in a new folder makes its watches `leaving`: by its folder's `IN_MOVE_SELF` (the MOVE_SELF rule, 3.3), or
  by path, one pass over the map, when its folder had no watch. An expiry makes them `leaving` by watch, not by
  path, so an ancestor's rename in between does not hide them; and while a move-out holds a watch it is guarded, so a
  rename it reports is a delete and a create. F1 is 6 of 6 right with the count: review 5's order through a new folder
  already on the design pass (0.55.1: 3 of 6 wrong), and its ancestor route (the review's `test_nested_outgoing.py`) on
  the review's patched copy (0.55.1 and the design pass: 3 of 6 wrong, the three with alike tails).
- **"An event queue overflow can leave a new folder unwatched":** closed, by the restart. The overflow probe: 9 of 9
  right with the watch map checked both ways (0.55.1: 9 of 9 wrong). The entry goes; the restart's window is one
  sentence in another entry (section 6).
- **v16's routes** (`exchange`, `exchange_twice`, `over_empty`, the `root_put_*` shapes, `back_home_*`,
  `land_ahead_taken`, `back_home_under_new`) and the seeds that found them: all in the gates of section 8.
- **v16's item 23** (an expiry before the folder's `MOVE_SELF`, with a create elsewhere at the same path) does not
  arise. Since the cost pass, the step back does take meaning from a subfolder's `IN_MOVE_SELF`, so the reason is
  narrower than before:
  - The rule removes nothing. It probes the watch at its own path and, unless it is there, flags it doubtful. Only the
    settle removes, by a probe on an empty queue, and it keeps every watch it finds at its path. A folder made at the
    same path has a watch of its own, which therefore stays.
  - An expiry cannot come first in the order v16 feared. The rename queues its `IN_MOVE_SELF` right after its pair
    (fact H), and all three expiries come later. A quiet read and the pair timeout each need the minimum snapshot delay
    or the pair timeout to pass after the move-out, and a create at the path is queued after the rename. While the
    move-out holds the watch, the rule skips it.
  - A watch the expiry's settle has already removed is no longer in `wdDic`, and the rule skips it too.

What the step back leaves, reasoned, not run, each with its bucket:
- **A rename caught in its window (fact E), at any probe: not an issue** (the main session's ruling on the spec check's
  1e). A probe between a rename's move of the name and the queueing of its events sees the new tree with an empty
  queue: a `found` or `doubtful` watch put there is ahead of the events, so a change made in its folder before they are
  queued is recorded where the move then lands and dropped as what the move replaced; a `leaving` watch removed there
  loses a change made before its folder's move-in walk adds a new watch. It needs a rename of the very folder probed,
  inside that window, and a change in the same microseconds that keeps size, mtime and the last 64 KiB. v16 rests on
  the same kernel ordering.
- **The first walk's race with a rename: not an issue** (the same ruling). The first walk puts a watch where it finds
  it, as on 0.55.1 (3.5), so a change made during it can be dropped as what a queued rename replaced; it is the blind
  spot of "A rewrite made while down that keeps size and mtime", as the start's full comparison follows the first walk.
- **A queue that never empties:** limitation 2 (section 6). The settle runs after the read that ends each burst, so a
  batch taken after a quiet period always follows it; only a batch taken while events keep coming (the maximum
  delay's) can come first. Fact F says the queue empties within milliseconds even at 108,000 events a second.
- **An inner mount followed inside a folder made since the last take: closed** since the cost pass (d99ef70; review
  1 read it at 3e87c9c), and kept closed by the settle's full pass over the map. Its walk keeps the mount's events, so
  its watches are not in `newDirWDs`. The route: a move out of the tree, read on the new folder's watch, of a folder
  holding the mount point. It needs a disk mounted below a folder made in the same batch, and a folder inside the new
  one and above the mount point moved out of the tree in that batch (the mount point itself cannot be renamed:
  `rename()` gives `EBUSY`). The moved folder's watch is in `newDirWDs`, so the
  MOVE_SELF rule makes it doubtful; the settle does not find it at its path, so that path left, and the pass over the
  map sends the mount's watches under it to `leaving`, where each is probed at its own path and removed. Fix round 1's
  narrowed pass, among `newDirWDs` and the found watches only, missed them, and the route was open again until fix
  round 2. Shown by argument: a mount needs root, which this round's gates do not run.
- **A folder the settle puts in place, which leaves the new folder before the settle's walk of it: closed** (review
  1). The settle's own run was a window.
  - Step 1 or 2 put the watch at its place, and only step 5's walk put it into `newDirWDs` (rule 2).
  - If the folder moved out of the new folder in between, that walk failed and the watch was in no set.
  - Its `IN_MOVE_SELF` was then skipped, and the watch stayed at its place in the tree: review 5's F1 route.

  The settle now puts each watch it places into `newDirWDs` at the placement. The test
  `tests/test_watch_settle.py::test_a_placed_watch_whose_folder_leaves_before_the_settles_walk` moves the folder inside
  the settle, before its walk. Without the change it keeps the stale watch and wrong bytes (3 of 3); with it, the
  result is right. Its control moves the folder once the walk is done.
- **A move-out of a new folder whose `IN_MOVE_SELF` is read after a take: closed** (the main session's ruling: Fix
  now), but for one case left, of fact E's class.
  - **The window,** as the cost pass found it. The rule needs the watch in `newDirWDs` (or `found`) when its
    `IN_MOVE_SELF` is read, and a take cleared `newDirWDs` right after the read that saw it. A read can end between the
    move-out's `MOVED_FROM`, read on the new folder's watch (so no cookie), and its `IN_MOVE_SELF`: fact H counted 886 of
    18,087 reads doing so under a stream of renames. If a batch was also taken before the `IN_MOVE_SELF` was read, that
    read cleared `newDirWDs` first and then skipped the `IN_MOVE_SELF`.
  - **What it did.** The watch stayed mapped at its old path in the tree while its folder was outside, until that folder
    was deleted or the watch restarted. Its later events came at that path. A create there named a path that does not
    exist. A rename inside it was a rename in the vault at that path: review 5's F1 route, which gives wrong bytes once
    another folder holds that path with two files that end alike (size, mtime and the last 64 KiB). The same-read skip
    had no such window, as it looked at the `MOVED_FROM` in that read.
  - **The fix, first form** (the cost pass's ruling). At a take, the watcher started a new `newDirWDs` and kept the old
    one (`new_before_take`) for the MOVE_SELF rule until the next take. One read was not enough: the kernel queues the
    `IN_MOVE_SELF` before `rename()` returns (fact H), but a renaming thread can be preempted between its rename's
    events while other threads' events fill whole reads. A probe of 20,000 to 200,000 renames by 1 to 64 threads found
    it two or more reads later for 35 of the 1,675 reads that ended between them with 4 to 64 threads, and for none of
    91 with one.
  - **The fix as built** (fix round 4). The rule no longer reads `newDirWDs`, so a take changes nothing for it, and
    `new_before_take` went (3.3). This also closes what the first form left: an `IN_MOVE_SELF` read after two takes.
  - **The tests.** `tests/test_watch_settle.py` runs the window in process on real inotify.
    - The read ends right after the move-out's `MOVED_FROM`, and a batch is taken before the next read.
    - The `IN_MOVE_SELF` comes in that read, or in the read after it.
    - Then a folder is made at the old path with two files alike in size, mtime and last 64 KiB, and a rename is made in
      the folder outside.

    With no fix, all four cases (two each) keep the stale watch, and the version keeps the wrong bytes of `n/x/h` (3 of
    3 runs). They pass under fix round 4's rule, with no `new_before_take`.
- **A folder made under a found folder's place, then moved out of the tree on that folder's watch: closed**
  (re-review 2's finding 1; the main session's ruling: Fix now).
  - **The route:** `mv big /out/big; mv other o2; mv /out/big o2/big; mkdir o2/big/dd; mv o2/big/dd /out/dd`. o2's
    pairing walk meets big's watch at `o2/big`, while the events still map it at `big` (big's move-out is pending), so
    the watch is `found`. The walk then adds dd's watch at `o2/big/dd`.
  - **What went wrong.** dd's move-out comes on big's watch, at the lagging path `big/dd`. The cookie's
    `watches_under()` of that path missed dd's watch, and dd's `IN_MOVE_SELF` was skipped, as the watch is in no set
    (it was added below a found folder, not below one of `newDirWDs`). The watch stayed mapped at `o2/big/dd` for
    good: review 5's F1 route once another folder holds that path. 0.55.1 has the route too (re-review 2: 28 of 103
    orders).
  - **The fix.** Fix round 3 had the cookie also hold the watches under the folder's place below the found place.
    Fix round 4's rule closes the route without it: dd's `IN_MOVE_SELF` comes at `o2/big/dd`, where no move-out is
    pending, so the probe finds dd gone and the settle removes its watch (3.3). The cookie change went.
  - **Shapes:** `lag_child_out` (then a write in `/out/dd`) and `lag_child_out_back` (a folder made again at
    `o2/big/dd`). Their first four steps run at the first visit and the last two at every pair of visits up to 40
    (the schedule file's `AT_ONCE`): 820 orders each. On 898961f, 57 of the 1,640 fail (28 and 29). Each failure keeps
    dd's watch at `o2/big/dd`, with the folder gone or a new folder's watch beside it. None shows wrong bytes in
    these shapes. They pass on 3ff5027 (the cookie change) and on fix round 4's rule without it, all 1,640.
- **The final review's findings 1 to 3: an `IN_MOVE_SELF` the old rule skipped: closed** (the main session's ruling:
  route B, 3.3). Each is a watch outside the sets the old rule looked at, so its folder's move went unseen and the
  watch stayed mapped in the tree.
  - **Finding 1, a late create.** `mv other o2; mkdir o2/n; mkdir o2/n/w; mv o2/n/w /out/w`.
    - o2's pairing walk watches n and w, not as new. n's create, read later, makes n new, but its walk no longer meets
      w, which has left.
    - w's move-out is read on n's watch and discarded (no cookie). w's watch is in no set, so its `IN_MOVE_SELF` was
      skipped.
    - Shape: `pair_then_new_sub_out`, 105 of 816 orders stale at `o2/n/w` on 3ff5027.
    - The same route runs through the first walk and through the overflow restart's walk (3 of 3 each).
    - The test `test_a_folder_made_during_the_first_walk_whose_subfolder_leaves` fails 3 of 3 on 3ff5027.
    - 0.55.1 has the route too.
  - **Finding 2, an ancestor's move-out that pairs.** w (in a new folder) leaves the tree, while x above it is renamed
    to y by another thread. The kernel can queue w's `MOVED_FROM` and `IN_MOVE_SELF` between x's `MOVED_FROM` and
    `MOVED_TO`.
    - x's move-out held w's watch when its `IN_MOVE_SELF` was read, so the rule skipped it.
    - x's pair then took the watch to `y/n/w`.
    - The test `test_a_move_self_between_an_ancestors_move_out_and_its_pair` forces that order on the read: 3 of 3
      stale on 3ff5027.
    - Now the watch's own path holds no pending move-out (x's path does), so the probe marks it `doubtful`. The pair
      takes it along, and step 2 finds it at neither path.
  - **Finding 3, the settle's placement** (reasoned). Between a placement and step 5's walk, a subfolder of the
    placed folder could leave the same way as in finding 1. The probe covers it too.
  - With the rule's new form, all three pass: the shape's 816 orders, and both tests 3 of 3, with their controls.
- **The settle's pass over nested paths that left** (the final review's finding 4: Fix now). `moved_on` could hold a
  path and paths under it, and the prefix pass compared each watch with every one of them. On a map of 30,001 watches,
  10,001 nested paths cost 0.50 s, against 0.9 ms with the outermost path only. The settle now keeps only the outermost
  paths (3.4).

## 5. What changes for the operator

- The three deferred entries go (section 4).
- **A move out of a folder that has just left the tree is copied**, where 0.55.1 renamed it in the vault, for the pair
  timeout after the folder left (the larger of the job's minimum snapshot delay and 30 s; 60 s by default): `mv X
  /out/X; mv /out/X/sub sub` copies `sub` whole. So is a rename in a folder a walk found ahead of its events, in either
  folder of a `RENAME_EXCHANGE`, or in a folder moved onto the place of one that had just left and then moved on, until
  the next empty queue (limitation 1). One INFO line each (rule 3's): `Copying <path>, moved from <path>: a watch of the
  move is not settled`.
- **The settle's copy** logs one INFO line, `Copying <path>: its changes came at another path until the event queue ran
  empty`: after a swap by one rename, and for a found folder when a batch was taken since the walk noted it
  (limitation 2). A folder renamed inside a folder made in the same batch is still walked a second time by the settle
  (two more INFO lines, the walk's own), with no copy and no copy line.
- **A change in a found or swapped folder can reach the vault one version late** under events that never pause, and its
  copy then copies the folder whole once more (limitation 2).
- **An overflow restarts the watch:** one more INFO line, `Watching the tree again after the overflow`; one full
  comparison follows, as on 0.55.1, and a batch taken during the restart's walk is followed by another; the maximum
  delay counts on from before the overflow. A change during the walk that keeps size, mtime and the last 64 KiB is
  missed (section 6).
- The watches of a folder moved out of the tree go at the first empty queue after its move-out expires, where 0.55.1
  removed them at the expiry itself.

## 6. docs/limitations.md and the README

**docs/limitations.md** (round 22's build):
- **Goes, as closed:** "A folder renamed twice into a folder whose move is being walked can keep old bytes", "A folder
  moved out of the tree from a new folder keeps its watch" and "An event queue overflow can leave a new folder
  unwatched".
- **Changed:**
  - "A folder or file moved into a new folder is copied whole": its revisit no longer waits for the two entries that
    go: "Revisit when: the no-copy move gets its own design; sooner if size limits start pruning because of it."
  - "A rewrite made while down that keeps size and mtime" gains one sentence at the end of "What the operator sees":
    "So is one made while the watcher watches the tree afresh after an event queue overflow (about 8 µs a folder, some
    0.15 s at 17,200 folders): the full comparison that follows has the same blind spot." Its "Approved" gains:
    "2026-11-09, on the window of the watch's restart after an overflow: "Accept: one sentence (Recommended)"."
  - "Swaps in one batch are repaired by copies" gains, after its first sentence: "An exchange of two entries by one
    rename (`mv --exchange a b`, `RENAME_EXCHANGE`) in one batch is repaired the same way."
- **New:** limitations 1 and 2 below, after "A move that another change of the batch outran is copied".

```markdown
### A move out of a folder that just left the tree is copied

- **Kind:** known limitation.
- **What the operator sees:** for the pair timeout after a folder is moved out of the tree (the larger of the job's
  minimum snapshot delay and 30 s: 60 s by default, an hour on a job whose minimum delay is an hour), anything moved
  from that folder back into the tree, as in `mv X /out/X; mv /out/X/sub sub`, is copied whole instead of renamed in
  the vault, with one INFO line, `Copying <path>, moved from <path>: a watch of the move is not settled`. Until the
  watcher next finds its event queue empty, normally at the end of that read, the same copy covers a rename in a folder
  moved onto the place of one that had just left the tree and then moved on, in either folder of a swap by one rename
  (`RENAME_EXCHANGE`), and in a folder the watcher found at a place its events had not brought it to yet (a rename
  racing the walk of a folder just moved or made). 0.55.1 renamed these. The version is right; the copy costs the moved
  entry's size once, and with a size limit it can prune older versions, as the copy of a move into a new folder can.
- **Why:** such a folder's watch can report its moves at a path another folder now has; trusting it is how a version
  kept a file's old bytes for good, and telling the two folders apart needs the watch tree of round 22's first design
  (about 815 more lines and 94 bytes a watch).
- **Revisit when:** the log shows big copies from this route often. Also when the no-copy move into a new folder gets
  its own design.
- **Approved:** 2026-11-09, the user's choice "Accept: copy (Recommended)"; then, with the window corrected to the pair
  timeout and the routes named, "Approve as corrected (Recommended)".

### A folder found ahead of its events can reach the vault a version late

- **Kind:** known limitation.
- **What the operator sees:** when a walk of the watcher finds a folder at a place its events have not brought it to
  yet (a rename racing the walk of a folder just moved or made), or one rename swaps two folders (`RENAME_EXCHANGE`),
  that folder's changes come at another path (its old one, or the other folder's) until the watcher finds its event
  queue empty. Then it puts the folder's watch in place and watches what was made in it; a swapped folder, and a found
  one after a batch taken in between, is also copied, with one INFO line, `Copying <path>: its changes came at another
  path until the event queue ran empty`. A batch taken before that moment, while events keep coming (the maximum
  delay's), can lack a change made in that folder meanwhile; the next version has it, and the copy that brings it
  copies the folder whole once more (vault space). The queue empties often even in a busy tree: with writers at
  108,000, 89,000 and 57,000 events a second it was empty after 42%, 59% and 69% of reads, the longest non-empty streak
  under 10 ms.
- **Why:** only an empty queue tells the watcher that what it sees in the tree is what its events say; deciding with
  events unread is how 0.55.1 could remove a live folder's watch or keep a file's old bytes.
- **Revisit when:** a live tree shows long stretches with no empty queue.
- **Approved:** 2026-11-09, the user's choice "Accept: next version (Recommended)"; then, with the swap and the second
  copy named, "Approve as corrected (Recommended)".
```

**README:**
- one line each in its list of limitations, after the line on a move another change of the batch outran:
  - "For the pair timeout after a folder leaves the tree (the larger of the minimum snapshot delay and 30 s), anything
    moved from it back into the tree (mv X /out/X; mv /out/X/sub sub) is copied whole instead of renamed, with one INFO
    line (Copying …: a watch of the move is not settled); so is a rename in a folder the watcher found ahead of its
    events or swapped by one rename (mv --exchange), until its event queue next runs empty. The result is right."
  - "Under events that never pause, a change in a folder the watcher found ahead of its events, or swapped by one
    rename, can reach the vault one version late, and that folder is then copied whole once more."
- line 36 ("A file rewritten in place while reverberator is down…") gains one clause: "…, or during the watcher's
  restart after an event queue overflow (about 0.15 s at 17,200 folders)".
- line 46 ("A swap in one batch (mv a t; mv b a; mv t b)…") names the exchange: "(mv a t; mv b a; mv t b, or mv
  --exchange a b)".

docs/lessons.md: nothing; no API changes (the log lines are not an API, and no flag, config key or format changes).

## 7. The cost

Measured through the real `watchFolder()` on real inotify on tmpfs in containers (uid 65534), `probes/bench_watcher.py`
(round 22's, with workloads added), 0.55.1 and the step back alternating, three runs each unless said, the watcher's
CPU only. The host ran at a load of 200 to 270 on 32 cores, so the CPU numbers carry about ±10%.

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
| `outbusy2` (the review's): a folder of 10,001 subfolders moved out of the tree while a writer keeps it busy (about 200 writes a second for 36 s), so its move-out expires at the pair timeout during the writes; one run each | 0.335 s | design pass 6.21 s; per probe (the review's patched copy) 0.284 s |
| `renamesinnew` (the review's): 2,000 `mkdir n/d; mv n/d n/e` inside a folder made in the batch | 0.046 to 0.053 s | design pass 2.94 to 3.05 s; the build (ruling 3 and the same-read skip), at 20,000 renames: 14.9 to 15.6 s against 0.50 to 0.56 s; the cost pass's MOVE_SELF rule: below |

**Ruling 3's scan, timed alone** (this spec; a Python loop of the two scans with no inotify, in a container as uid
65534 at a load of about 22): for 2,000 such move-outs in a tree of 20,251 watches, scanning every watch took 1.53 s and
scanning `newDirWDs` and `found` 0.086 s, `newDirWDs` growing to 2,001. That scan grows with the folders made since the
last take, so a run of move-outs that all pay it grows with their square (20,000 would cost some 8.6 s, reasoned, not
run). The same-read skip was meant to leave it to move-outs of the tree and pairs split across reads. The build
measured otherwise: at 20,000 renames the look ran at nearly every rename (90 of 103 s of a profiled run), for
14.9 to 15.6 s. The cost pass replaced it with the MOVE_SELF rule (3.3), which costs up to three set lookups for each
subfolder's `IN_MOVE_SELF`, plus one probe for a watch of `newDirWDs` or `found` that no move-out holds. Each rename
inside a new folder also costs the settle's probe and a second walk of the moved folder, where 0.55.1 walks it once.

**The cost pass** (the cost brief's gates: 0.55.1 against the rebased branch 60baf6a, whose watcher is the cost pass's,
alternating, three runs each, at a lower host load than the table above, so the two tables do not compare):

| Workload | 0.55.1 | Branch |
|---|---|---|
| The watcher's memory after watching 102,061 folders | 17.54 MiB | 17.54 MiB |
| The first walk of 102,061 folders | 0.426 to 0.470 s | 0.436 to 0.469 s |
| 20,000 file writes in 50 folders | 0.217 to 0.245 s | 0.215 to 0.235 s |
| 200 renames of folders of 50 subfolders, and back | 0.794 to 0.810 s | 0.834 to 0.862 s |
| 300 folders of 10 subfolders moved out of the tree and back | 0.331 to 0.382 s | 0.367 to 0.392 s |
| 2,000 renames in a folder of 10,000 subfolders | 5.450 to 10.277 s | 5.469 to 10.608 s |
| 300 times `mkdir n; mv d n/` | 0.476 to 0.497 s | 0.502 to 0.554 s |
| 10,000 folders made one by one | 0.073 to 0.082 s | 0.071 to 0.074 s |
| One overflow | 0.000 s | 0.123 to 0.130 s |
| `outbusy2` | 0.347 to 0.370 s | 0.335 to 0.521 s |
| `renamesinnew`, 2,000 renames | 0.044 to 0.050 s | 0.051 to 0.076 s |
| the same, six more runs | 0.034 to 0.049 s | 0.036 to 0.041 s |
| `renamesinnew`, 20,000 renames | 0.499 to 0.529 s | 0.509 to 0.538 s |
| the same, six more runs | 0.385 to 0.418 s | 0.382 to 0.489 s |
| `outpeak`: peak / watcher CPU | 0.89 MiB / 0.136 to 0.146 s | 11.77 MiB / 0.139 to 0.154 s |

- **renamesinnew** no longer grows with the renames. At 2,000 renames, the first set of three missed an overlap by
  1 ms while the gates loaded the host; the six runs after it overlap.
- **Six quiet runs** of two workloads, against 0.55.1:
  - the moves into new folders: 0.290 to 0.303 s against 0.273 to 0.292 s, about +5% (the build measured +10 to 20%);
  - the move-outs: 0.371 to 0.393 s against 0.341 to 0.353 s, +7 to 8%.
- **Six runs side by side** of 0.55.1, the build's head (5a6e5a5) and the branch show those costs already on the build's
  head, so the cost pass added none:
  - move-outs: means 0.346, 0.373 and 0.375 s;
  - moves into new folders: 0.334, 0.390 and 0.382 s;
  - renames: 1.505, 1.654 and 1.509 s.
- **The move-outs' cost.** A profile puts it, I think, in the settle's probes of the leaving watches: 2,700 probes in 14
  settles, each with the symlink check's `realpath` (21,125 `lstat` calls), about 0.05 s under the profiler. Not cut:
  the cost pass's ruling 5 asked for numbers, not code. Review 1 cut it (below).

**Review 1** (fix round 1: the pass over the paths that left narrowed to `newDirWDs` and the found watches when it can
be, and one realpath for each parent in a settle; 0.55.1 against 396580b, alternating; fix round 2 put the plain
pass over the map back, below). `outofnew` is review 1's
workload: 300 times `mkdir -p new_i/d/s; mv new_i/d /out/`, each in its own reads, a take every 30.

| Workload | Runs | 0.55.1 | Branch |
|---|---|---|---|
| `outofnew` on the cost pass's code (3e87c9c), a pass over the map with a walk up each path's parents | 3 | 0.038 to 0.044 s | 3.26 to 3.42 s |
| `outofnew`, the map pass as a prefix test alone (fix round 1's tree) | 3 | 0.037 to 0.047 s | 0.191 to 0.220 s |
| `outofnew`, the narrowed pass (396580b, gone in fix round 2) | 3 / 6 | 0.039 to 0.043 / 0.032 to 0.049 s | 0.055 to 0.057 / 0.044 to 0.068 s |
| `outofnew` at 3,000 times, the narrowed pass | 3 | 0.385 to 0.426 s | 0.365 to 0.513 s |
| move-outs (300 folders of 10 subfolders out and back) | 3 / 6 | 0.621 to 0.659 / 0.586 to 0.633 s | 0.633 to 0.646 / 0.580 to 0.644 s |
| moves into new folders | 3 / 6 | 0.511 to 0.524 / 0.504 to 0.548 s | 0.546 to 0.567 / 0.536 to 0.563 s |
| `renamesinnew`, 2,000 | 3 / 6 | 0.044 to 0.050 / 0.041 to 0.058 s | 0.047 to 0.058 / 0.034 to 0.053 s |
| `renamesinnew`, 20,000 | 3 / 6 | 0.483 to 0.503 / 0.500 to 0.586 s | 0.512 to 0.608 / 0.494 to 0.596 s |
| `outbusy2` | 3 | 0.284 to 0.316 s | 0.301 to 0.322 s |

The host ran busier than in the cost pass's table (other sessions at loads of 75 to 275), hence the higher numbers.
The move-outs now overlap 0.55.1 in both sets. The rest of section 7's workloads overlap too, as before: memory 17.44
against 17.45 MiB, `outpeak` 0.89 against 11.77 MiB, and the overflow's restart 0.136 to 0.140 s.

**Fix round 2** (the plain prefix pass over the map; 0.55.1 against 898961f, alternating, three runs each and six more
for `outofnew` and `renamesinnew`; the host's load rose from about 8 to 110 while they ran).

| Workload | Runs | 0.55.1 | Branch |
|---|---|---|---|
| `outofnew` | 3 / 6 | 0.035 to 0.040 / 0.033 to 0.044 s | 0.338 to 0.361 / 0.342 to 0.395 s |
| `outofnew` at 3,000 times | 3 | 0.335 to 0.399 s | 3.64 to 3.82 s |
| the pass alone: a map of 20,200 paths, one path that left, 2,000 passes | 3 | | 0.99 to 1.10 ms a pass |
| move-outs (300 folders of 10 subfolders out and back) | 3 | 0.621 to 0.660 s | 0.627 to 0.649 s |
| moves into new folders | 3 | 0.513 to 0.520 s | 0.539 to 0.545 s |
| `renamesinnew`, 2,000 | 3 / 6 | 0.036 to 0.052 / 0.040 to 0.057 s | 0.041 to 0.050 / 0.040 to 0.046 s |
| `renamesinnew`, 20,000 | 3 / 6 | 0.476 to 0.495 / 0.488 to 0.539 s | 0.498 to 0.511 / 0.496 to 0.575 s |
| `outbusy2` | 3 | 0.262 to 0.333 s | 0.282 to 0.316 s |
| the watcher's memory after watching 101,051 folders | 3 | 17.61 MiB | 17.61 MiB |
| the first walk of 101,051 folders | 3 | 0.655 to 0.665 s | 0.658 to 0.687 s |
| 20,000 file writes in 50 folders | 3 | 0.115 to 0.144 s | 0.133 to 0.161 s |
| 200 renames of folders of 50 subfolders, and back | 3 | 1.508 to 1.521 s | 1.508 to 1.574 s |
| 2,000 renames in a folder of 10,000 subfolders | 3 | 9.814 to 10.021 s | 9.818 to 10.069 s |
| 10,000 folders made one by one | 3 | 0.062 to 0.069 s | 0.063 to 0.066 s |
| one overflow | 3 | 0.000 s | 0.138 to 0.140 s |
| `outpeak`: peak / watcher CPU | 3 | 0.89 MiB / 0.133 to 0.149 s | 11.77 MiB / 0.143 to 0.152 s |

- **`outofnew`** costs about 1 ms for each move-out of a folder from a new folder: one pass over the map's 20,000
  watches, which alone takes 1.0 to 1.1 ms. Fix round 1 measured the same pass at 0.191 to 0.220 s. Its tree, run
  again beside 898961f (three runs each, alternating), gave 0.355 to 0.370 s against 0.323 to 0.350 s, so the difference
  is the host's, not the code's.
- **`renamesinnew` does not reach the map pass of `leave_moved_out()`** (gone in fix round 3: its one caller takes
  `watches_under()`, the same pass). That pass runs only for a folder in `unwatched`, and a profile of 20,000 renames
  shows no call to it. Over nine runs each, the median is 0.505 s on the
  branch against 0.490 s on 0.55.1, and each code's runs overlap the other's.
- **The rest** overlap 0.55.1, but for the moves into new folders, still about +5% (the cost pass's figure), and the
  overflow's restart walk.

**Fix round 4** (route B: every subfolder's `IN_MOVE_SELF` probed but one whose own path holds a pending move-out;
0.55.1 against the branch, alternating, three runs each). `renamesold` is the fix round's workload: `<count>` renames
of folders watched since the watch began (not new), each within its parent and back on the next pass. Each one pairs,
and the rule now probes it where the old rule skipped it.

| Workload | 0.55.1 | Route B, a realpath each probe | Route B, a realpath per parent per read |
|---|---|---|---|
| `renamesold`, 2,000 (a quiet host) | 3.405 to 3.473 s | 3.490 to 3.535 s | |
| `renamesold`, 2,000 (a busier host) | 4.251 to 4.799 s | 4.407 to 4.756 s | 4.250 to 5.113 s |
| `renamesold`, 20,000 (quiet, then busier) | 34.97 to 44.32 / 49.80 to 57.89 s | 35.38 to 50.24 / 46.57 to 64.28 s | 41.24 to 112.67 s |
| the probe alone: 2,000 probes of watched folders (`probe_micro.py`) | | 7.5 to 8.6 µs a probe | 1.1 to 1.5 µs a probe |
| `renamesinnew`, 2,000 | 0.032 to 0.045 s | 0.034 to 0.046 s | |
| `renamesinnew`, 20,000 | 0.325 to 0.456 s | 0.332 to 0.469 s | |
| move-outs | 0.317 to 0.352 s | 0.335 to 0.341 s | |
| moves into new folders | 0.263 to 0.269 s | 0.265 to 0.283 s | |
| `outofnew` | 0.030 to 0.055 s | 0.193 to 0.335 s | |

- **`renamesold` with a realpath each probe** missed 0.55.1's range at 2,000 on the quiet host: +2.5%, about 40 µs
  for each rename. The ruling's step for a miss is to share the parents' real paths across one read's probes, as one
  settle's probes share them. That brings the probe from 7.5 to 8.6 µs down to 1.1 to 1.5 µs, and the code takes it.
- **The busier host's runs overlap,** but are too noisy to show a 2% difference: 0.55.1's own 20,000 ran from 35 to
  58 s. Each rename costs 0.55.1 about 1.7 ms, its two passes over every watch at a folder move (section 9), so the
  probe is a small part of it either way.

- **Memory:** no state per watch at rest. The four structures hold only the watches of a race or of a pending
  move-out, until the next settle, pairing or expiry. `outgoing` holds one entry per watch of a pending move-out for up
  to the pair timeout, where 0.55.1 holds the cookie's tuple alone: for a move-out of 100,000 folders, a dict of
  100,000 entries, a few MB (reasoned). Measured by the build (`outpeak`: tracemalloc's peak from the move-out of a
  folder of 100,000 subfolders until its expiry has removed their watches, three runs each): 11.77 MiB on the branch,
  0.89 MiB on 0.55.1, the same in each run.
- **Per event:** nothing for a file event (5 to 6.5 µs an event on both codes in the file writes above). One `settle()`
  call per read, which returns at once when nothing is noted; with something noted, one `FIONREAD` ioctl. A move-in
  whose move-out was read looks its two folders' watches up in four structures, almost always empty. A subfolder's
  `IN_MOVE_SELF` looks its watch up in three sets, and probes it when it is in `newDirWDs` or `found` and no move-out
  holds it.
- **Per folder walked:** for a watch the walk finds held (not a new one), one comparison of its path, as before; for a
  watch it adds below the root, one lookup of its parent in the walk's own record and one in `newDirWDs`.
- **Per folder move:** 0.55.1's two passes over every watch stay (v16 removed them; section 9).
- **Extra reads:** the settle's probes (an `add_watch` per noted watch, a lookup in the dentry cache, and the symlink
  check for a probe that found its watch) and its walk of each folder it puts in place; the copies of rule 3 read the
  moved entry whole.
- **Extra copies, counted on the design pass** (`tools/copycount.py` in the scratch folder): the 99 schedule shapes at
  small bounds (every order to 6 visits for 3 and 4 steps, to 5 for 5 steps, 50 sampled for 6 and 7; 5,334 orders),
  each order's batches logged on both codes and each create carried through the batch's later moves and deletes as the
  collapse carries it, a create under another one counted as covered. 0.55.1 ended wrong in 184 orders
  (`exchange_twice` 56, `root_put_*` 89, `exchange` 21, `over_empty` 18), the step back in none. Over the 5,150 orders
  0.55.1 gets right the step back made 6,526 copies to 0.55.1's 6,501: 21 are `out_back_sub` (`mv big /out/big; mv
  /out/big/sub sub2`, limitation 1), and 4 are an empty folder of `root_put_into_itself` (`mkdir n; mv n big/n; mv big
  n`) copied by the settle. Where 0.55.1 is wrong, the step back's extra copies are the repair.

## 8. Gates

### 8.1 What ran

All in containers as uid 65534 on XFS, but the root suite, which ran in the test VM. The design pass's prototype is
0.55.1 (6726e75) with the step back, in a scratch clone; its gates ran the clone's commit 50e391d, and the root suite
copied that commit's files.

| Gate | Design pass (50e391d) | 0.55.1 | v16 (its rerun of 2026-11-09, finished) |
|---|---|---|---|
| The 99 schedule shapes at review 5's bounds, the watch map checked both ways (91,049 orders) | none wrong | 5,439 wrong: `back_home_via_outside` 1,238, `back_home_via_new` 870, `back_home_via_new_sub` 870, `exchange_twice` 816, `over_empty` 273, `root_put_*` 268, `found_out` 259, `land_ahead_taken` 225, `back_home_under_new` 179, `root_ahead` 147, `exchange` 136, `twice_old_race` 120, `twice_old_race_sub` 30, `back_then_sub_out` 8 | none wrong |
| `tests/test_watcher_schedules.py` with v16's 56 shapes | as the suite samples them (100 orders a shape): 5,514 passed | its own 10 shapes at every order: 40,801 passed (round 21) | at every order: 161,889 passed |
| The seed 4284 agent's 10 shapes at review 5's bounds | 11,949 orders, none wrong | not in round 22's record | 5,733 passed |
| Review 5's F1 order (`test_r5_f3_wrong.py`) | 6 of 6 right | 3 of 6 wrong | 6 of 6 |
| Overflows in process, the watch map checked both ways (`test_overflow.py`) | 9 of 9 right | 9 of 9 wrong | 9 of 9 |
| The fuzz, lists checked | seeds 0 to 5,999: no failure, 3 teardown errors (254, 5723, 5811), all the size-record class | seeds 0 to 5,999: no failure, 11 teardown errors, the size-record class | seeds 0 to 29,999: no failure, 41 teardown errors, the size-record class |
| Fuzz seeds alone, 3 tries each: 2195, 2509, 4284, 12812, 12831, 14124, 16462, 19006 | 24 of 24 pass | round 22: 12831 and 16462 failed 3 of 3; on 2026-11-09 they pass 3 of 3 | 2509, 12812, 12831, 14124, 19006: 15 of 15 |
| The suite in containers as uid 65534 | 268 failed, 3,059 passed, 601 skipped, 1 error: the same 269 that fail on 0.55.1 beside it (tests that need root) | the same counts | 278 failed, a subset of 0.55.1's |
| The suite as root in the test VM (`gate.sh`, tag v0.54.1), but `test_pool_cut.py` | 3,881 passed, 1 skipped (a queue-fill test this kernel would not fill) | 3,908 passed and the same skip, with `test_pool_cut.py` in the run (19 of its 46 fail under xdist, which it refuses) | not run |
| `test_pool_cut.py` alone in the test VM | 46 passed | not run alone | not run |
| The copy count of section 7 (5,334 orders) | none wrong | 184 wrong | not run |

**On the review's patched copy** (the design pass with the count and the per-probe settle; `found` through the
inner-mount walk was in the review's runs but is not in the patch it saved): the ancestor route's probe 6 of 6, review
5's F1 probe 6 of 6, the overflow probe 9 of 9; 2,882 orders of 27 move-out and found-watch shapes at 3:8, 4:8 and
5:6 visits and 100 sampled for 6 and 7, the watch map checked both ways, none wrong; `outbusy2` 0.284 s. The 99 shapes
at review 5's bounds and the fuzz were not run on it. Ruling 3 and the spec check's rules have not run anywhere.

### 8.2 The gates on the built branch

Every gate below runs on the branch before release; each has a bar. **The base** for the watcher gates (shapes, probes,
fuzz, benchmarks) is 0.55.1 (6726e75); for the suite gates it is 0.55.1 until main is merged in, then main as merged,
run beside the branch in the same container or VM. 0.55.2 changes nothing in the watcher, so its merge changes no
watcher bar. Test code never runs as root on the host: the container gates as uid 65534 (the scratch `dk.sh`: `docker
run --rm --init --memory=<cap>` with no `--memory-swap`, `--pids-limit`, `--user 65534:65534`, the code and the test
venv read-only), the root suite in the test VM. Read `/proc/pressure/memory` before a fan-out, cap each container, and
remove each run's temp tree at its end.

| Gate | Bar |
|---|---|
| The 99 shapes plus the new ones of task 1 at review 5's bounds (3 and 4 steps every vector to 16 visits, 5 to 12, 6 and 7 steps 1,000 sampled), the watch map checked both ways (`all99.sh`, `SCHED_WATCHES=1`) | none wrong |
| The seed 4284 agent's 10 shapes at review 5's bounds | none wrong |
| `tests/test_watcher_schedules.py` at every order (`REVERB_WATCH_SCHED_SAMPLE=0`), in capped shards by shape, with each step that failed (`OSError`, counted as done) written by shape (`REVERB_WATCH_SCHED_FAILED_STEPS`) | none failed; no shape whose point is a step that mostly fails |
| The final review's four open shapes (`open_in_poke`, `open_in_out`, `open_file_in_poke`, `open_lag_in_poke`; 4,545 orders) | none failed |
| The in-process tests of task 1: review 5's F1 order and its ancestor route, each with its control; the overflow cases; the chunked removal; the clock across an overflow; gone wds; a probe that could not look | 6 of 6, 6 of 6, 9 of 9, the rest all pass |
| The fuzz, seeds 0 to 29,999, lists checked, 15 containers of 2,000 seeds (`fz.sh`), each under its `--memory` cap with no `--memory-swap`, and inside it each process's address space capped at 12 GB: a normal worker's is 4.8 to 7 GB, so a runaway seed (as 2509 was on v8) fails alone with a `MemoryError` instead of the cap killing the whole container's 2,000 seeds | no failure; teardown errors only of the size-record class ("A size record too low after a rename falls back to a copy") |
| Fuzz seeds 2195, 2509, 4284, 12812, 12831, 14124, 16462 and 19006 alone, 3 tries each | all pass |
| The copy count of section 7 | none wrong; the extra copies over 0.55.1's right orders are limitation 1's and the settle's, each named |
| The suite in containers as uid 65534 | fails only what the base fails in the same container |
| The suite as root in the test VM (`gate.sh`, tag v0.54.1 in its `.git`): `--deselect tests/test_pool_cut.py`, then `tests/test_pool_cut.py` alone (`--alone`); this holds the suite's mergerfs and power-loss tests, which the user brought back for this round, and the chunked-removal test with the sysctl really set low | all pass, but the queue-fill skip |
| `probes/bench_watcher.py` (`bench.sh`): every workload of section 7, `renamesinnew` at 2,000 and 20,000 renames, `outofnew` (review 1), `renamesold` at 2,000 and 20,000 (fix round 4), the base and the branch alternating, three runs each; and tracemalloc's peak during a pending move-out of 100,000 folders | each within the base's noise (the ranges overlap), the overflow and `outofnew` excepted (about 1 ms each, accepted, item 20); `outbusy2`, `renamesinnew` and `renamesold` at the base's numbers. The peak is measured and written into section 7, with no bar. A miss goes to the main session with the numbers, not into more code |

**When the schedule harness checks the watch map:** after the shape's last batch, as the prototype's harness does. That
batch follows a quiet read, whose expiries and settle have run, so no watch is still flagged for a reason the next
settle would fix; a watch still flagged then and wrong counts as stale. `watch_map_errors()` also counts as stale a
held watch whose path has a symlink below the root (fact C), which `add_watch` by path alone would pass.

## 9. Against v16

| | Step back | v16 |
|---|---|---|
| reverberator.py | the design pass's +153/-74, plus the review's and the spec check's changes (estimated at 60 to 90 lines) | +815/-170 |
| Rules | four, with the structures of 3.2 and their rules | about twenty (its 2.1) |
| Memory | none per watch at rest; a count per watch of a pending move-out | 94 B a watch, 1.6 MB at the live 17,200 |
| First walk | as 0.55.1 | about 1.4 µs a folder more (idle), 24 to 85 ms at 17,200 |
| A folder made | as 0.55.1 | 3.7 to 5.5 µs more |
| A folder renamed | as 0.55.1: two passes over every watch | O(its subtree): 0.13 µs a watch a rename saved |
| Copies 0.55.1 does not make | limitation 1's; counted, 25 more copies in the 5,150 orders 0.55.1 gets right | the root put's copy (14 of 5,624 orders) |
| Walk | 0.55.1's, by path | through open folders, iterative, `/proc` needed |
| Known wrong order left | none run; section 4's, each bucketed | item 23, reasoned |

v16 is faster where one folder of a large tree is renamed often; the step back is lighter in memory and in walks, and a
fraction of the code. The passes over every watch at a folder move could go on their own later, by an index of paths
(the lightness round), without the rest of the watch tree.

## 10. The build's tasks, in order

**Base:** build on round22 now (0.55.1 and this spec); merge main in once 0.55.2 is on main, and run the suite gates
again after the merge. **Inputs:** the design pass's reverberator.py diff against 6726e75 is in the worktree,
untracked: `.superpowers/sdd/2026-11-08-round22/stepback.diff` (the scratch clone's commit 50e391d plus an uncommitted
docstring). The main session hands over the rest in the build brief: the scratch clone (its test commits 100ef5c and
5e62c74, and v16's 56-shape schedule file in them); the probes (the design pass's `test_r5_f3_wrong.py`,
`test_overflow.py`, `watchmap.py`, `test_sched.py` with the 99 shapes' list and the seed 4284 agent's 10 shapes; the
review's `test_nested_outgoing.py`, and `bench_watcher.py` with `outbusy2` and `renamesinnew`); the scratch helpers
(`dk.sh`, `suite_dk.sh`, `all99.sh`, `sched.sh`, `fz.sh`, `bench.sh`, `probe.sh`); and the test VM with its `gate.sh`.
Each task ends with its command passing; `<tree>` is the worktree, run in a container as uid 65534 (`dk.sh <cap> <tree>
python3 -m pytest -q -n auto -p no:cacheprovider -o tmp_path_retention_policy=failed --basetemp=<bt> <files>`).

1. **The version, and the tests first.**
   - `__version__ = "0.55.3"`.
   - Bring in the clone's test changes against 6726e75: `watch_map_errors()` in `tests/harness.py`, which also counts a
     held watch whose path has a symlink below the root as stale; `Session.watch()` in
     `tests/test_moves_into_new_folders.py`, which runs `watchFolder()` again with `root_returned=True` after
     `WATCH_RESULT_OVERFLOW`, as `watcher()` does, the `exchange` verb (`renameat2()` with `RENAME_EXCHANGE`), and new
     verbs `symlink` and `take`; `tests/test_watcher_schedules.py` with v16's 56 shapes on 0.55.1's walk hooks
     (`iter_tree_entries()`), without v16's two `WatchTree` asserts, and the watch map checked at the end of every
     shape. They name `rv.WATCH_RESULT_OVERFLOW`, which task 2 adds: for the red run on the base, add that one constant.
   - Add these shapes, to the schedule file and to the 99's list (`probes/test_sched.py`), in the file's tree; the
     builder fits the steps to the harness if they need it:

     | Shape | Steps | What it holds |
     |---|---|---|
     | `nested_out_ancestor` | `mv big/sub {outside}/sub; mv big other/b2; mv next2/sub other/b2/sub; mv {outside}/sub/b {outside}/sub/z`, a `poke` in `other/b2/sub` | the count (the review's route) |
     | `moved_sub_out_before_walk` | `mkdir n; mv big n/big; mv n/big/sub {outside}/sub; mv next2/sub n/big/sub`, a write in `{outside}/sub` | rule 1 |
     | `back_into_new_then_out` | `mv big {outside}/big; mkdir n; mv {outside}/big n/big; mkdir big; mv n/big {outside}/b2; mv next2/sub n/big`, a write in `{outside}/b2` | rule 2 (0.55.1 leaves the stale watch too) |
     | `pairing_walk_under_new` | `mkdir big/n`, then `mkdir big/n/s; mv big b2` before that read is handled, `mv b2/n/s {outside}/s; mv next2/sub b2/n/s`, a write in `{outside}/s` | rule 3 (the spec check's 4a) |
     | `renamed_in_new_then_out` | `mkdir n; mkdir n/d; mv n/d n/e; mv n/e {outside}/e; mkdir n/d`, a write in `{outside}/e` | the same-read skip's fallback; since the cost pass, the MOVE_SELF rule |
     | `exchange_then_rename` | `exchange big other; mv big b3`, a `poke` in `other/a`, a write in `b3` | `doubtful`'s first path before (4b) |
     | `exchange_chain` | `exchange big other; exchange big next`, a `poke` in `other/a`, a write in `next` | the probe of every doubtful path (4b) |
     | `out_then_link` | `mv next2/sub {outside}/sub; rmtree next2; symlink next2 → {outside}`, a write in `{outside}/sub` | the symlink check (4c) |
     | `back_as_new_name` and `back_as_new_name_take` | `mv big {outside}/big; mv {outside}/big big2`, a `poke` in `big2/a`; the second with a `take` between the move-in and the poke | the settle's covered copy (Q2 (a)): no lost change with a take between the note and the settle or without |
   - A new test file (its name the builder's) with the in-process tests:
     - review 5's F1 order and its control (`test_r5_f3_wrong.py`), its ancestor route and control
       (`test_nested_outgoing.py`), the overflow cases with `watch_map_errors()` (`test_overflow.py`, whose
       `watchmap.py` is the same check);
     - **the chunked removal:** the queue limit the watch reads at its start patched to 64, a folder of 300 subfolders
       moved out of the tree, then quiet: no overflow restart, and every one of its watches gone within a few settles,
       the map checked both ways; in the test VM as root, the same with `fs.inotify.max_queued_events` really set to 64
       for the test and restored after;
     - **the clock across an overflow:** events queued, the maximum delay short, an overflow in between: the batch is
       still signalled when the maximum delay since the last take has passed;
     - **gone wds:** `remove_watches()` with a wd already gone does nothing; a `DELETE_SELF` of a watch in `found`,
       `leaving` or `doubtful` takes it out of every set;
     - **could not look:** a fake `add_watch` that raises `EIO` for a leaving watch's path: the watch stays, still
       `leaving`, and goes at the first settle whose probe answers.
   - Run them on the base and record what fails. Expected red: the F1 order 3 of 6, the ancestor route 3 of 6, the
     overflow cases 9 of 9, some orders of the shapes 8.1 names for 0.55.1, of `back_into_new_then_out`,
     `pairing_walk_under_new`, `renamed_in_new_then_out` and `out_then_link`, and the tests of parts 0.55.1 lacks.
     Command: the suite command with `tests/test_watcher_schedules.py`, the new file,
     `tests/test_moves_into_new_folders.py`.
2. **The design pass's code.** Port `stepback.diff`: `found` in the walk, `guarded()`, the four structures,
   `move_watches()`, the event rows of 3.3, `settle()` and `queued_events()`, the overflow restart and `watcher()`'s
   `root_lost`, and `remove_moved_away_watches()` gone. Proof: the task 1 tests from the design pass's gates pass
   (F1, overflow, the 56 shapes), the ancestor route's probe still fails 3 of 6 (the count is needed), and the suite in
   a container fails only what the base fails.
3. **The review's changes, rulings 1, 2 and 4.**
   - `outgoing` as a count (3.2): hold at a `MOVED_FROM`; let go once, at the pops 3.2 lists, and at the discard
     branch's unguarded pairing with the cookie stored again with no `wds`.
   - `settle()` per probe: the re-check before the removals goes (3.4), with the argument for no retry in a comment.
   - `follow_inner_mounts()` takes `found` and passes it to its walk; `watchFolder()` passes its own; the walk's
     docstring then names the first walk alone as the one without `found`.

   Proof: the ancestor route 6 of 6, F1 6 of 6, overflow 9 of 9; `nested_out_ancestor` passes; `bench.sh` with
   `outbusy2` at the base's number.
4. **The settle and its housekeeping (the spec check's rulings).** The three-way probe with the symlink check (fact C);
   `doubtful`'s first path before and the probe of every doubtful path (3.4 step 2); a doubtful watch no probe finds into
   `leaving`; a found folder copied only after a take since its note (3.4 step 5); the removals capped at half the
   instance's queue limit and `raise_queue_limit_for_removals()` gone; a watch leaving `wdDic` leaving every set, and
   `remove_watches()` skipping gone wds (3.2); the max-delay clock carried across the restart (3.6). Proof:
   `exchange_then_rename`, `exchange_chain`, `out_then_link`, `back_as_new_name` and `back_as_new_name_take` pass; the
   in-process tests of the chunked removal, the clock, gone wds and could-not-look pass; the 56 shapes still pass.
5. **Ruling 3, its three rules and the same-read skip** (3.2, 3.3; the cost pass replaced the skip, task 8). Proof:
   `moved_sub_out_before_walk`, `back_into_new_then_out`, `pairing_walk_under_new` and `renamed_in_new_then_out` pass,
   and each fails in some order
   without its rule or the fallback (run each at review 5's bounds with that one part taken out, to show it is needed,
   then put it back; task 3's release-once rule stays in, as the design pass's expiry would make rule 1's stale watches
   `leaving` at the quiet read and hide the need); every shape of the schedule file passes; `bench.sh` with
   `renamesinnew` at 2,000 and 20,000. If `renamesinnew` misses the base's numbers, stop this task, report the numbers
   to the main session, and go on with tasks 6 and 7: the docs do not depend on it, and the correctness gates run on the
   branch as it is (again, if the answer changes ruling 3's code).
6. **The docs** (section 6), word for word: docs/limitations.md and the README lines. The user approved the entries;
   the main session writes them, or tells the builder to.
7. **The gates of 8.2**, on the branch.
8. **The cost pass** (the main session's rulings on the build's report). Its gates are those of 8.2, run after the
   change and again after the rebase:
   - **Ruling 1, the MOVE_SELF rule (3.3), in place of the same-read skip.** Proofs:
     - fact H, checked first, and pinned by `tests/test_watch_settle.py`;
     - the folder renamed twice out of a new folder in one read keeps a stale watch without the rule (3 of 3);
     - `found_out` fails in 56 orders without found watches in the rule;
     - `renamesinnew` is at 0.55.1's numbers (section 7).
   - **Ruling 2, settle step 5's sets (3.4).**
   - **Ruling 4: rules 2 and 3 each shown needed, at 28 visits (3.2).** Their shapes, `into_renamed_new_then_out` and
     `new_sub_walked_by_pair_then_out`, join the schedule file at 28 visits, with `renamed_outside_onto_taken_place`
     (limitation 1's copy by its plain route).
   - **The version.** After `git rebase main` onto 0.55.3, the version is 0.55.4. The suite is compared with main's set.

## 11. Left to the builder

- Names, comments and DEBUG lines; how `move_watches()` hands back what it moved; how `found` keeps the take count with
  each entry; how the carried max-delay time reaches the new watch; the symlink check's form (fact C); how the probes
  fold into the suite; the order of the commits (the task 1 tests may land with the code they need, so that no commit
  of the branch is red).
- Log levels, but for the lines of sections 3.6 and 5, which the limitations quote and their revisits read. Count them
  right: a walk logs two INFO lines of its own ("Adding watch for", "Watching N sub folders"), so a folder renamed
  inside a folder made in the batch goes from 0.55.1's one walk and two lines to two walks and four lines, with no copy
  line (Q2 (a)).
- If a shape of task 1 does not fail without its part, say so and keep it as a regression shape; the part then rests on
  its argument in 3.2 to 3.4, and the main session decides whether it stays.

## 12. Calls to confirm

Each ruling that was the main session's, each call this spec made on its own, and each change of behaviour against
0.55.1. **Settled** marks those the 2026-11-09 rulings or picks decided.
1. **`outgoing` as a count** (ruling 1). Open: this spec's release-once rule (the discard branch's unguarded pairing
   stores its cookie again with no `wds`, so its expiry neither lets go again nor makes those watches `leaving`; the
   review's patch let go at both). Reasoned, not run.
2. **`settle()` per probe, no retry** (ruling 2), with the review's argument (3.4).
3. **Ruling 3's scan over `newDirWDs` and `found`.** Settled: its cost question, by the same-read skip (Q1 (a)), with
   `renamesinnew` at 2,000 and 20,000 as the gate; rule 3 (4a). Open: rules 1 and 2 (this spec's), and the skip's
   fallback at the move-in (this spec's: the walk that does not meet the moved folder's watch runs the scan). The cost
   pass replaced the skip and its fallback with the MOVE_SELF rule (item 19), and showed rules 1, 2 and 3 each needed
   by a shape (3.2).
4. **`found` through the inner-mount walk** (ruling 4). It is not in the review's saved patch.
5. **The note's edits** (the main session's): limitation 2 cut to the measured statement; the residual races cover
   every kind of probe; the mergerfs probe as fact D.
6. **The gates:** the ancestor route's shape and probe, `outbusy2` and `renamesinnew` with the base's numbers, and the
   memory peak are the main session's. Open, this spec's: the fuzz at seeds 0 to 29,999 (the design pass ran 0 to 5,999)
   and the copy count again; keeping the fuzz's 12 GB address-space cap inside the `--memory` cap, for its reason in 8.2
   (the ruling said to drop it unless the spec gave one).
7. **The overflow's window:** settled, one sentence in "A rewrite made while down that keeps size and mtime" and one
   clause in its README line; the deferred overflow entry goes. Settled: one full comparison follows an overflow.
8. **README lines:** this spec's: the two lines of limitations 1 and 2, and "or mv --exchange a b" in the swap line.
9. **Version and base:** settled: 0.55.3, built on round22 now, main merged in once 0.55.2 is on main, the watcher gates
   against 0.55.1. Then, the main session's call: the flush round shipped first as 0.55.3, round22 was rebased onto it,
   and this round is 0.55.4.
10. **More INFO lines than 0.55.1:** rule 3's copy line, the settle's copy line (fewer, by Q2 (a)), the overflow's
    restart line, and the settle's second walk of a folder renamed inside a new folder (its two lines).
11. **Limitations 1 and 2:** settled, "Approve as corrected (Recommended)". Open: limitation 1 keeps the found route
    ("a rename through a folder whose events the watcher hasn't reached", from the first pick), which the corrected
    question, as relayed to this spec, does not name again.
12. **The watches of a folder that left are removed at the first empty queue after its move-out expires**, not at the
    expiry; a probe with a read unhandled was R5's failure.
13. **Settled:** the first walk keeps no `found` (not an issue); `raise_queue_limit_for_removals()` goes. Open: the
    settle's removal cap of half the instance's queue limit (this spec's number, 3.4); the two passes over every watch
    at a folder move stay.
14. **Settled:** the fact-E races are not an issue. An inner mount in a folder made since the last take (section 4)
    is closed by the settle's pass over the map (since the cost pass; fix round 2 keeps it), shown by argument only.
15. **Tests changed for the prototype** (the design pass's call): the session restarts the watch after an overflow, as
    `watcher()` does; the session knows `exchange`; `tests/harness.py` gains `watch_map_errors()`; v16's 56-shape
    schedule file runs on 0.55.1's walk hooks, without its two `WatchTree` asserts. This spec adds the `symlink` and
    `take` verbs and the symlink check in `watch_map_errors()`.
16. **Settled by the rulings, with this spec's choices in them:** `doubtful` keeps the first path before and every
    doubtful path is probed (4b), and a doubtful watch no probe finds goes to `leaving` (this spec's); a probe counts
    only with no symlink in the path, checked only when it found its watch (4c; the check's form left to the builder);
    a probe that could not look leaves the watch flagged (`ENOSPC` among those errors, though the kernel answers it
    only for a folder with no watch); a found folder is copied only after a take since its note, compared with the
    queue's own count under its lock (Q2 (a), the comparison this spec's); doubtful folders are always copied (this
    spec's: their repair is a comparison that a size-, mtime- and tail-keeping change escapes); the max-delay clock
    carries across a restart; a watch leaving `wdDic` leaves every set.
17. **Answers to a builder's questions that this spec decided:** the settle's place in the read loop (3.4); new
    `found` entries from step 5's walks wait for the next settle; ruling 3 matches a found watch by its `wdDic` path;
    the guarded pairing's line is rule 3's, for files too; the map is checked after the shape's last batch.
18. **Not run on any code yet:** ruling 3 with its rules and the same-read skip, the release-once rule, the spec check's
    settle rules, and the 99 shapes at review 5's bounds and the fuzz with the review's changes; `found` through the
    inner-mount walk ran only in the review's runs. The real daemon ran only through the VM suite's tests that start
    it, on the design pass. (Written before the build. The build and the cost pass have since run all of these but the
    same-read skip, which went.)
19. **The cost pass** (the main session's rulings on the build's report):
    - **The MOVE_SELF rule (3.3)** replaces the same-read skip and its fallback. It covers found watches, the build's
      call after `found_out`. The look by path stays only for a moved folder with no watch of its own.
    - **Its window at a take** (section 4): ruled Fix now. The old `newDirWDs` serves the rule until the next take,
      where the ruling said one read: this pass's call, as a probe found the `IN_MOVE_SELF` two or more reads late
      under concurrent renames. What is left is a stall across two takes, which is fact E's class.
    - **Settled:** settle step 5's sets (ruling 2); version 0.55.4 on 0.55.3.
    - **Open, the reviewer's:** rules 2 and 3 show only at 28 visits.
    - **Open, the user's:** finding C, limitation 1's copy by its plain route (`mv X /out/X; mv Y X; mv /out/X/a
      /out/X/b`). The approved text may not name this route, and the main session puts the wording to the user.
    - **Open, measured, not cut:** the build's costs that remain (section 7).
      - The move-outs are +7 to 8%; the settle's symlink check for each probe looks like the cause.
      - The moves into new folders are about +5%.
      - `outpeak`'s peak is 11.77 MiB.
20. **Review 1** (the main session's rulings, all Fix now):
    - Step 3 leaves a doubtful watch that step 2 kept.
    - The settle puts each watch it places into `newDirWDs` at the placement.
    - One realpath for each parent in a settle.
    - The pass over the paths that left is one prefix pass over the map (fix round 2's ruling, the reviewer's option
      a). Fix round 1 had narrowed it to `newDirWDs` and the found watches; review 1's probe found that premise false
      and the inner-mount route open again (sections 3.2, 3.4 and 4). `outofnew` costs 0.34 to 0.40 s on the branch
      against 0.03 to 0.04 s on 0.55.1, about 1 ms for each move-out of a folder from a new folder on a map of 20,000
      watches (section 7, fix round 2). The ruling accepted fix round 1's figure for the same pass, 0.19 to 0.22 s
      (about 0.7 ms each); fix round 2's runs put it at about 1 ms.
    - The look for a moved folder with no watch of its own (`leave_moved_out()`, a folder in `unwatched`) is one pass
      over the map too, as it had leaned on the same premise (fix round 2's call; the case is rare). Fix round 3
      removed `leave_moved_out()`: its one caller makes `watches_under()` of the path `leaving`, as the moves into a
      skipped folder do.
21. **Re-review 2** (fix round 3; the main session's rulings, all Fix now):
    - A folder move-out read on a `found` watch: the cookie also holds the watches under the folder's place below the
      found place (section 4, `lag_child_out` and `lag_child_out_back`).
    - `leave_moved_out()` goes: its one caller makes `watches_under()` of the path `leaving`.
    - The schedule file gains `AT_ONCE`, for a shape whose first steps all run at the first visit (the fix round's
      call, for the reviewer's vectors `(0, 0, 0, 0, i, j)`). The suite samples 100 orders of each of the two shapes, as
      for any shape over the sample size; the gates run all 1,640.
    - Fix round 4 took the cookie change out again: the MOVE_SELF rule's new form closes the route alone (section 4).
22. **The final review** (fix round 4; the main session's rulings):
    - **Route B** (3.3): every subfolder's `IN_MOVE_SELF` is probed, but one whose own path holds a pending move-out.
      `new_before_take` and `WatchNotes.new_dirs` go, and so does re-review 2's cookie change (the fix round's call:
      the probe closes `lag_child_out` without it, 1,640 of 1,640). Rules 1 to 3 of 3.2 stay, for the discard alone (the
      fix round's call: without them, more events are recorded, still right).
    - **The probe's realpath is shared by one read's probes** (the ruling's step for a miss on `renamesold`): 1.1 to
      1.5 µs a probe, against 7.5 to 8.6 µs with a realpath each. A parent replaced by a symlink within one read could
      pass a probe through it until the next read; the events of that replacement follow in the queue (the fix round's
      call, as for one settle's probes).
    - **The settle keeps only the outermost paths that left** (finding 4).
    - **Parts that went:** `through_link()`'s form with no shared real paths;
      `tests/test_jobs.py::test_removing_many_watches_writes_no_queue_limit`. `move_watches()` still returns its list,
      which the discard branch uses and which it builds anyway for the doubtful marking, so no one-line change drops it
      at the normal pairing.
    - **The first design's spec** (2026-11-08-round22-watcher-design.md) stays as the record, with a line at its top
      saying that it was not built.
    - **The schedule harness** writes each failed step by shape (`REVERB_WATCH_SCHED_FAILED_STEPS`; the scratch shape
      probes' `SCHED_FAILED_STEPS`), and the gate run counts them (section 8.2).
    - **New tests:** the shape `pair_then_new_sub_out`, plus `test_a_folder_made_during_the_first_walk_whose_subfolder_leaves`
      and `test_a_move_self_between_an_ancestors_move_out_and_its_pair` in tests/test_watch_settle.py. Each fails on
      3ff5027 (105 of 816; 3 of 3; 3 of 3) and passes with route B.
