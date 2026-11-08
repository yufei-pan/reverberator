# Round 22 design: the watcher keeps each watch where the events put it (the watch tree)

Version 0.55.2. It fixes the watcher's three older deferred entries in docs/limitations.md, all on 0.55 and 0.55.1:
- "A folder renamed twice into a folder whose move is being walked can keep old bytes" (round 21 review 4's F2);
- "A folder moved out of the tree from a new folder keeps its watch" (review 4's F3, round 21's R5 phantom, review 5's F1);
- "An event queue overflow can leave a new folder unwatched".

A variant built from this design passes every gate in section 9. Section 12 records the user's decision on the one
new copy, the only question.

## The user's words

- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in
  run the background. so every little bit will sum up to a lot over days month years." "simpler and smarter is better".
  "one of the core for reverberator is reuse existing linux features and easy browse / restore."
- 2026-11-07, on these three entries: "Next round, right after 0.55.1 (Recommended)".
- 2026-11-07, round 21, when another order kept wrong bytes through the move into a new folder: "Drop the feature
  (Recommended)", so every such move is copied, as on 0.55.
- 2026-11-08, on section 12's question: "Known limitation (Recommended)", widening the approved entry "A move that
  another change of the batch outran is copied".

Not the user's words, but the rule this design follows from round 21's rulings: when the watcher cannot be sure, it
errs toward a copy, never toward wrong bytes.

## 0. In short

**The cause.** `wdDic` (watch → path) is the watcher's only record of where each watched folder is. Three things change
it, each at its own time against the events still in the queue:
- a walk sets a watch to where its folder is now;
- a paired move rewrites every path under the old one;
- an expiry probes each path with `add_watch`.

The three issues are three ways these disagree with the events:
- F2: a walk moves a watch ahead of the folder's own rename events, so its earlier changes come at a path it only
  passed through;
- F3: a move-out discarded in a new folder leaves no record at all, and an expiry judges a watch by a path that a later
  rename of its old parent changed;
- the overflow: lost events never add the watches they would have added.

Round 21 added conditions about where a watch is mapped, and each condition had an order that fooled it.

**The design: one idea, in place of those conditions.** The watcher keeps each watch's *place*: its parent folder's
watch and its name.
- Only the kernel's events, read in order, move a watch from one place to another. Paths become a cache derived from
  the places.
- A walk sees the tree as it is now, ahead of the events still queued, so it moves no watch the events have not moved:
  it notes where it found it. The folder's own `IN_MOVE_SELF` then settles the matter, and the kernel queues that event
  after the move-in whenever there is one (verified).
- A walk opens each folder from the folder it is in, adds its watch through that open folder, and lists it through
  it. A rename in between can no longer put a folder's watch under a parent it is not in (2.3).
- The few places where the watcher must take the walk's view are named in 2.3 and 2.5. Each is at a place the batch
  copies (a folder made in the batch, or one that came in from outside), or ends in a copy or a full comparison.

What the same structure gives:
- An expiry removes a moved-out folder's watches only if the folder is still at the place it left, and keeps each one a
  walk found back in the tree. It judges no watch by its path, so it neither removes a live folder's watch (R5's
  failure) nor misses one re-pointed by a rename of its old parent (F3).
- A folder's move-out read in a new folder gets a cookie that records nothing but settles its watches (F3).
- An overflow puts every watch where a walk finds it, and watches what the lost events would have watched.
- Two older routes to wrong bytes go too, found while backing the design: a swap by one rename (`RENAME_EXCHANGE`), and
  a folder renamed over an empty folder made in the same batch.

**What goes:**
- `remove_moved_away_watches()` and its `add_watch` probe;
- the `wds` tuple of each folder move-out, and the pass of `watches_under()` over every watch that fills it;
- the pass over every watch at each paired folder move;
- the watcher's use of `iter_tree_entries()`, whose `except Exception` also swallowed a test's `NameError` (section 7).

**What comes:**
- `class WatchTree`: 281 lines in the variant, 58 of them docstrings and a doctest;
- the walk through open folders, with the tree's rules: `initializeFolderWatchers()` goes from 79 lines to 150, plus
  `subfolders_of()`, 17; `watchFolder()`, with the event rules, from 326 to 433;
- a `moving` map: own watch → cookie, or landed;
- the cookie that records nothing;
- `leave_tree()`: a subtree that left the tree goes, but for the watches in it that a walk found back in the tree (2.5);
- a walk's check for a folder back at the place it left, whose move-out then keeps its watches (2.5);
- a forgotten watch's children set adrift, so a deleted parent does not hide a pending move-out (2.5);
- a walk at an overflow.

**Numbers:** the gates are in section 9, the costs in section 8.

## 1. The kernel facts it relies on

Each fact was run with inotify on ext4 and on tmpfs, with the same results; the probe is kept with the design report.

| # | Fact | What the kernel gave |
|---|---|---|
| 1 | A folder renamed in one watched folder | `MOVED_FROM`, `MOVED_TO` (on the parent's watch, one cookie), then `MOVE_SELF` on the folder's own watch |
| 2 | Renamed across two watched folders | the same order |
| 3 | Renamed out to an unwatched folder | `MOVED_FROM`, `MOVE_SELF` |
| 4 | Renamed in from an unwatched folder | `MOVED_TO` (a cookie never seen), `MOVE_SELF` |
| 5 | An ancestor renamed | `MOVE_SELF` on the ancestor's watch only; nothing on the watches below it |
| 6 | `add_watch` of a folder already watched, by its new path | the same watch number |
| 7 | `IN_MASK_CREATE` | `EEXIST` on a watched folder, a new watch on an unwatched one (not used by the design) |
| 8 | `rmdir`, `rm -r` | `DELETE_SELF` and `IGNORED` of each folder before its parent's `DELETE`, deepest first |
| 9 | A folder renamed over an empty watched folder | `MOVED_FROM v`, `MOVED_TO t`, `ATTRIB` on `t`'s own watch (its link count), `MOVE_SELF v`, `DELETE_SELF t`, `IGNORED t` |
| 10 | `RENAME_EXCHANGE` of two watched folders | `FROM p`, `TO q`, `MOVE_SELF p`, `FROM q`, `TO p`, `MOVE_SELF q`, two cookies, no `ATTRIB` |
| 11 | Watch numbers | rising, not given again soon: six add/remove cycles gave 1 to 6, the next 7, 8 |
| 12 | `rm_watch` with events queued on the watch | they stay queued, and its `IGNORED` comes after them |
| 13 | Two processes renaming folders in two folders, 20,000 renames each | ext4: 6,828 of 40,000 renames had another event between their `MOVED_FROM` and `MOVE_SELF`; tmpfs: 10,846. Each rename's own order held in every one |
| 14 | `add_watch('/proc/self/fd/<fd>')` of an open folder | the watch of that folder, wherever it is renamed to (the walk's 2.3; run in the variant's suite and gates) |

An overflow was not run on the kernel. Making one needs a lower `max_queued_events`, which needs `sysctl -w`, and the
default on the test machine is 8,388,608. It is made in-process instead: the read that holds the chosen events loses
them and ends with an `IN_Q_OVERFLOW`, as a full kernel queue does.

**Reasoned from the kernel source, not run.** One rename queues its three events inside `vfs_rename()`, while it holds
the locks that a second rename of the same folder needs. So a folder's renames are queued in the order they happened,
whatever other processes do in between. Fact 13 shows the in-between part.

## 2. The design

### 2.1 Places

`WatchTree` holds, for each watch:
- `paths[wd]`: its path. This is the watcher's `wdDic`, kept as the cache every event reads, so a file event costs what
  it costs today.
- `up[wd]`: its parent's watch.
- `kids[parent]`: its children. One child is held as the int itself. More are held as a dict keyed by the child's path:
  the same string object as in `paths`, so it costs no string of its own. Its value is the watch, or a list of watches,
  oldest first.

Every operation the watcher needs is O(1), or O(the folder's subtree) for a move:
- `at(parent, name)`: the watch the events put at that name;
- `put()` and `move()`: a watch with its subtree to a new place, every path below it with it;
- `subtree()`;
- `forget()`.

**Two watches at one place.** Two watches can share one place for a while: a walk lists a folder made where another
one left, before that move-out is read. The older one is the one the events name (`at()`) until it leaves. A watch the
events have just named a place for, displacing the one held there, sets that one aside (a *shadow*). When the one named
leaves, the oldest shadow is named again.

**No cycles.** The kernel moves no folder into its own subtree. So when `put()` is asked to put a watch under one held
below it, the folder in between left by a way the events have not shown (2.5). It leaves the moved watch's subtree and
is held nowhere (`adrift`) until a walk finds it. Without this, `put()`'s pass over the subtree never ends: fuzz seed
340 ran the variant out of memory before the walk rule of 2.3 that removes its cause.

### 2.2 Event by event

| Event | 0.55.1 | Round 22 |
|---|---|---|
| Folder `MOVED_FROM` | cookie with `watches_under(path)`: a pass over every watch | cookie with `own = at(parent, name)` |
| Folder `MOVED_TO`, cookie known | `move` recorded; every path under the old one rewritten (a pass over every watch); walk of the new place | `move` recorded; `own` with its subtree moved to the new place (`move()`), `moving[own] = landed`; walk of the new place, which knows `own` landed there |
| `MOVED_TO`, cookie unknown | create, walk | the same; a folder whose walk root is its own watch, at the place its pending move-out left, came back and keeps its watches (2.5) |
| Folder `CREATE` | create, walk | the same |
| `MOVE_SELF` on a folder's own watch | skipped | landed: nothing. Otherwise the folder went where no watch was: to the place a walk found it since (`found`), or, with none, it is `adrift` until a walk finds it. A cookie that records nothing (2.5) is settled now; the cookie of a move-out still to expire stays in `moving` (2.5) |
| Unpaired move-out expires (the quiet read, the 30 s pair timeout, a create at its path) | delete recorded; each watch of `wds` still mapped under the old path is probed with `add_watch` and removed unless handed back | delete recorded; if `own` is still at the place it left, or adrift, its subtree leaves the tree (`leave_tree()`, 2.5): removed, but for each watch in it that a walk found back in the tree, put there |
| Folder `MOVED_TO` into a skipped folder, cookie known | delete recorded; the watches mapped under the old path removed | delete recorded as on 0.55.1; `own`'s subtree leaves the tree (`leave_tree()`), here and in a folder made in the batch |
| `ATTRIB` with no name on a folder's own watch | nothing | a folder a move-in landed on is replaced: set aside (2.6) |
| `DELETE_SELF`, `UNMOUNT` | the watch dropped | the same, from the tree; a watch still held below it is held nowhere (`adrift`), as its folder left by a move-out still to settle (2.5) |
| `Q_OVERFLOW` | full comparison requested | the same, then a walk that puts every watch where it finds it, and removes the watches it did not find (2.7) |
| A read with nothing pending (the quiet read) | pending move-outs expire | the same; cookies that record nothing and are still held settle (2.5); then `moving`, `found`, `ahead`, `adrift`, `replaced` are cleared: every event that could settle them has been read |

Takes, the discard of events in a folder made in the batch (`newDirWDs`), the scan after a take, skip lists and inner
mounts are 0.55.1's, with the tree passed along.

### 2.3 Walks

**How a walk reads the tree.** A walk adds each folder's watch before reading the folder, as today, so a folder made in
it afterwards raises its create. What changes is how it reaches each folder:
1. It opens the folder relative to the folder it is in (`openat()`, as a folder and not a link to one).
2. It adds the watch through that open folder (`/proc/self/fd/<fd>`).
3. It lists the folder through it.

The watch and the listing are then of the one folder the walk holds, and each subfolder is opened from it, so each
watch goes under the watch of the folder it is in. One open folder is held a level, as today.

**Why it reads through open folders.** By path, a walk adds `p`'s watch, then lists `p`. A folder renamed away from
`p` and replaced by another in between gives the newcomer's subfolders the old folder's watch as their parent. No
event ever says otherwise, as those watches never move.
- 0.55.1 is put right by the next walk that passes there, as each walk re-points watches to where it finds them, which
  is F2's cause.
- The tree is not: the round 22 shape `c1_collision` failed 15 of 1,000 orders on a by-path variant (0.55.1 fails none).

**Without `/proc`** the walk falls back to `add_watch(path)`, with that race.

**What a walk does with each watch it gets.** Its root is the place the event at hand names.
- **A new watch:** added at the place the walk found it, under its parent's watch. A folder whose parent could not be
  watched is not watched either: no event would carry its watch along when that parent moves.
- **A watch the events already hold there:** nothing.
- **A held watch found anywhere else, below the root:** left where the events have it, with the place noted in `found`.
  Its move here is still queued: a move-in moves it, or its `MOVE_SELF` with no move-in puts it at the found place.
- **At the root, when the events already name a watch at the place** (`landed`): the place belongs to that watch, the
  folder the event at hand is about. For a paired move-in, it is the watch that landed there. For a create or a move-in
  with an unknown cookie, it is the watch an earlier walk added there, having listed the folder before this event was
  read (`at()` when the walk starts). Another watch found at the root came by a later move whose events are still
  queued, so it is treated as below the root: noted in `found`, or, new, added beside the one named, which stays named
  until it leaves. Treating it as the root named it at the place, and the next move-out from there moved the wrong
  folder:
  - fuzz seed 340, at a paired move-in: a folder put under itself;
  - `c2_unwatched_old`, at a create: on a variant without this rule, 6 of 150 orders failed, as the move-out of the
    first `u` moved the second `u`'s watch.
- **A held watch found at the root of a create's walk, or of a move-in with an unknown cookie, where the events name
  none:** put there at once. The event at hand names this place for a folder that arrived there, and `add_watch` says
  this folder is there now. If the events had it at another place, that place goes in `ahead`. Its move-out from there,
  when read, is recorded as a delete and a create (a copy), not a move: the events from before it can have come at the
  new place ahead of their time, and only a copy reads what is there.
- **A held watch whose `MOVE_SELF` came with no move-in and no found place (`adrift`):** put where this walk finds it.
  The events have nothing more to say about it.
- **At the root, the watch of a folder whose move-out from this very place is still to expire:** the folder came back
  (2.5), and its move-out leaves its watches alone.
- **After an overflow:** every watch is put where the walk finds it.

**A put from a walk's view displaces nothing.** The `MOVE_SELF` that puts a watch at its found place, the walk that
puts an adrift one, and `leave_tree()` (2.5) all take a place from a walk, which saw the tree ahead of the events. A
watch the events name at that place keeps it until its own move-out or delete is read; the newcomer is added beside it.
Only the events' own puts (a move-in, the root rules above) set the one named there aside, or note it in `replaced`
(2.6).

### 2.4 `MOVE_SELF`

The kernel queues it on the moved folder's own watch after the rename's `MOVED_TO` (facts 1 to 4). So when it is read:
- If the move-in was read, the folder has landed, and nothing is left to do.
- If no move-in was read, the folder went to a place with no watch: out of the tree, into a skipped folder, or into a
  folder not watched yet. A walk that found it since says where it is; otherwise the next walk that finds it does.
- A folder's renames are queued in order (section 1), so a `MOVE_SELF` is never read before the move-in of its own
  rename.

One case has no `MOVE_SELF`: a folder renamed between the walk's open of it and its watch. The watch is added through
the open folder after the rename, so the kernel has nothing to report. Its `MOVED_FROM`, on its parent's watch, does
come. 2.5 settles it.

### 2.5 Move-outs that never pair, and those in a folder made in the batch

- **A regular move-out** keeps 0.55's window: its delete waits for the quiet read, the pair timeout or a create at its
  path, and the moved folder's watches stay meanwhile. That is what keeps a take-back a move: in `mv X /out/X;
  mv /out/X/sub sub`, X's watch still reports `sub`'s move-out, which pairs. At the expiry:
  - `own`'s subtree is removed if `own` is still at the place it left, or is adrift. A take-back, a move-in or a walk
    that put it elsewhere is what moved it, and its watch is live there.
  - If a walk found it elsewhere and no `MOVE_SELF` came (2.4), it is put where the walk found it. All events are read
    by then, so the walk's place is the one no event will correct. `chain_through_a_new_folder` failed 1 of 1 at one
    order of the suite's sample (deterministic) before this rule: the expiry removed a live folder's watches.
- **Every subtree that leaves the tree goes through `leave_tree()`:** an expiry, a move-in to a skipped folder (paired,
  or in a folder made in the batch), and a cookie that records nothing settled at its `MOVE_SELF` or at the quiet read.
  Each watch in the subtree that a walk found back in the tree is put there, with what is below it, and the rest is
  removed. A walk sees the tree after every event of the read it runs in, so a watch it found at a place in the tree is
  there: the folder left with its parent's, or before it, and came back where no watch saw it come. If that watch is
  `own`, nothing is removed. The puts repeat until none is left, as one can take another's found place out of the
  leaving subtree.
  - Fuzz seed 647 found the case on the variant before this rule, through a skipped folder: `c` moved into a skipped
    folder, then `c`'s subfolder from there into a folder made in the batch, both before the walk of that folder ran.
    The move-in to the skipped folder removed `c`'s subtree at once, the subfolder's watch with it, and the folder
    stayed unwatched.
  - The schedule shape `out_made_sub_into_new` is the same route through an expiry (`mkdir n; mv big /out/big;
    mkdir big; mv /out/big/sub n/sub`, then a change in `n/sub`, the create of `big` expiring the move-out before the
    subfolder's `MOVE_SELF` is read): 210 of 2,730 orders failed on the variant before this rule, none on 0.55.1, none
    after it. 0.55.1 is right there because it removes by path, and the walk re-pointed the subfolder's watch.
- **A folder back where it left, before its move-out expires.** A create or a move-in at the old *path* expires the
  move-out first (as on 0.55.1), so the subtree goes and the walk adds fresh watches. When the folder's parent was
  renamed in between, the old place has a new path, and nothing expires it: the move-in's walk gets the folder's own
  watch at its root, still held at that place. Then the folder came back, and the move-out leaves its watches alone:
  the walk takes the cookie out of `moving`, and the cookie keeps only its delete (of the old path, at the expiry, as
  0.55.1 records it) or, recording nothing, goes. For this, a `MOVE_SELF` leaves the cookie of a move-out still to
  expire in `moving`, which then holds each folder's pending move-out until it settles.
  - Fuzz seed 929 found it on the variant before this rule (2 of 2; 0.55.1 passes it): a folder moved out, its parent
    moved into a folder made in the batch, and the folder moved back in under it. The expiry removed the watches of a
    folder that was there. Seed 1911 also failed 2 of 2 there and passes 2 of 2 after the rule (and on 0.55.1); its
    route was not traced.
  - The schedule shapes `sub_back_parent_renamed` (`mv big/sub /out/sub; mv big b2; mv /out/sub b2/sub`, then a
    change in `b2/sub`) and `sub_back_parent_into_new` (the same with `mkdir n; mv big n/big`) failed 542 of 816 and
    1,216 of 1,365 orders on the variant before this rule, none on 0.55.1 and none after it.
- **A folder's move-out read in a folder made in the batch** is discarded as on 0.55.1: the batch's copy of the new
  folder holds it, so nothing is recorded. It now gets a cookie that records nothing (`record=False`), for its watches
  only:
  - a move-in pairs with it: the watches go with the folder, and the move-in is a create, as 0.55.1 records it today;
  - its `MOVE_SELF` comes with no move-in: it left for a place with no watch, so the subtree goes at once, unless a walk
    found it since;
  - neither came by the quiet read (2.4's case): it settles there, as at an expiry.
- **The old parent deleted before the move-out settles.** `rm -r` deletes what is in a folder first (fact 8), so a
  watch still held below a folder at that folder's `DELETE_SELF` is one whose own move-out from it is still to settle.
  `forget()` of the parent sets it adrift (held nowhere), so the expiry, which takes an adrift watch held nowhere as
  still at the place it left, sends its subtree through `leave_tree()`.
  - Fuzz seed 5837 found it on the variant before this rule (3 of 4 alone; 0.55.1 passes 4 of 4): a folder moved into a
    skipped folder, its old parent deleted, and the expiry, finding no watch at a place whose parent was gone, kept the
    folder's watch at its old path. A later batch brought the folder back with its parent's move, which gives no
    `MOVE_SELF` of its own (fact 5), so the walk's `found` place was never taken up, and its events kept the dead path.
  - The schedule shape `out_parent_deleted_back` (`mv big/sub /out/d/sub; rm -r big; mkdir n; mv /out/d n/d`, then a
    change in `n/d/sub`) failed 7 of 1,365 orders before this rule, none on 0.55.1 and none after it.

### 2.6 One rename onto another folder: replaced or swapped

A move-in that lands on a place still held by another folder does not set that folder aside: `move()` notes it in
`replaced`. The kernel then says which case it was:
- an `ATTRIB` on that folder's own watch means it was replaced (fact 9), and it is set aside;
- its own `MOVED_FROM` next means it was the other half of a `RENAME_EXCHANGE` (fact 10), and it moves.

0.55.1 rewrites both folders' paths under one name in an exchange.

### 2.7 Overflow

`clear_places()`, then a walk of the whole tree with `resync`. Every watch it finds is put where it is, a folder whose
create was lost is watched, and each watch it did not see is removed. Removing them is safe: their folders left the
tree with their events lost. Then `moving`, `found`, `ahead`, `adrift` and `replaced` are cleared.

The batch is already a full comparison, and the queue drops every later event until the take, so what the walk does is
for the batches after it. Events read after the overflow can come from before the walk: a rename, or a folder made
where another left. Each folder's own events come after the create or move-in that put it at its place (FIFO). So such
a folder is re-placed at the root of that event's walk before its own events are read (2.3), as in `c2_unwatched_old`
below.

## 3. Issue 1: a folder renamed twice into a folder whose move is being walked (F2)

**What goes wrong today.** In `mv other o2; cp -p new big/a; mv big o2/x; mv o2/x o2/big`:
1. The paired move of `other` walks `o2`.
2. If the two renames land before that walk lists `o2`, the walk finds `big`'s watch at `o2/x` and re-points it there.
3. The modify of `big/a`, read next, is recorded at `o2/x/a`, a path that exists only between the two renames.
4. The collapse drops it, and the moves carry the old bytes.

With one rename, the modify lands at the final path and the collapse keeps it. That is why `renamed_walk_race` passes
on 0.55.1.

**Mechanism.** 2.3: the walk leaves `big`'s watch at `big` and notes `found`. The modify is recorded at `big/a`, where
it happened. Each move-in moves the watch, and the `MOVE_SELF` after each is a landed no-op. The batch reads: modify
`big/a`, move `big → o2/x`, move `o2/x → o2/big`, and the collapse replays it right.

**Across the orders:**
- **The walk before the renames:** it finds nothing held elsewhere; as 0.55.1.
- **The walk between the two renames:** `found` holds `o2/x`, and the first move-in lands it there.
- **The walk after both:** `found` holds `o2/big`, the two move-ins land it, and the second pops `found`.
- **Another process renaming elsewhere between the events:** places are by watch, not by path, so an ancestor renamed in
  between changes no place below it (fact 5). The cache's paths follow when that rename's move-in is read.
- **A take between:** takes do not touch places.
- **An expiry between:** a move-out of `big` that pairs never expires.
- **F2 at the root of a walk** (`root_ahead`: `mkdir o2/x; rmdir o2/x; mv big o2/x; mv o2/x o2/big`, the create of
  `o2/x` read after the renames): the walk of that create finds `big`'s watch at its root, which is put at once, with
  `big`'s place in `ahead`. `big`'s move-out, read next, is a delete and a create: the copy holds the new bytes.
- **The same root rule fixes a rename over an empty folder made in the batch** (`over_empty`, section 6).

**What it records against 0.55.1:**
- Events are recorded at the place the events give them, not where a walk saw their folder later. In the orders where
  0.55.1 kept old bytes, the variant records the change at its own path.
- At a create's walk root, the move-out becomes a delete and a create (section 12).
- No test of the suite changes what it records (section 7).

**Cost:** see section 8. `found` is one dict entry per held watch a walk finds elsewhere, a race, cleared by its
`MOVE_SELF`.

## 4. Issue 2: a folder moved out of the tree from a new folder keeps its watch (F3)

**What goes wrong today.** Two routes:
- `mkdir n; mkdir n/x; mv n/x /elsewhere/x` in one batch: the move-out comes on `n`'s watch, a new folder, and is
  discarded. No cookie, no expiry: `/elsewhere/x`'s watch stays mapped at `n/x` for good. With two files alike in size,
  mtime and last 64 KiB in a folder later at `n/x`, a rename in `/elsewhere/x` from one name to the other keeps wrong
  bytes (review 5's F1: 3 of 3).
- `mv keep/s/n2 /out/x; mv keep c/keep2`, both read before the move-out expires: the expiry removes only the watches
  still mapped under `keep/s/n2`. `n2`'s watch was re-pointed to `c/keep2/s/n2`, so it stays.

R5 judged every watch at the expiry by `add_watch` of its path, and removed a live folder's watch (`mv X /out/X;
mv /out/X/sub sub; mv sub sub2`, the path `sub` empty at the expiry). A path cannot tell a live folder's watch from a
phantom.

**Mechanism:**
- The first route gets a cookie that records nothing (2.5). With no move-in, its `MOVE_SELF` removes `x`'s watches at
  once; a move-in moves them.
- The second route's expiry is by place: `n2`'s watch is still at its place in `s`'s folder, whatever `keep` is called
  now, so it goes.
- R5's case stays right: `sub`'s move-in from X's stale watch paired and moved `sub`'s watch to the root, so at X's
  expiry `sub` is no longer in X's subtree, and its watch is kept.

**Across the orders:**
- **The move-out's `MOVE_SELF` before or after other processes' events:** its move-in, if any, comes before it (2.4).
- **A walk that lists the folder at a new place in the tree before its `MOVE_SELF` is read** (it went into a folder
  not watched yet): `found` keeps it, and the `MOVE_SELF` puts it there instead of removing it.
- **A walk after the `MOVE_SELF`:** `adrift`; the walk puts it.
- **A folder below it taken back into the tree, into a folder not watched yet, before the subtree is removed** (fuzz
  seed 647, `out_made_sub_into_new`): the walk of that folder found its watch, so `leave_tree()` puts it there with what
  is below it, and the rest goes (2.5).
- **No `MOVE_SELF` at all** (its watch came after the rename, 2.4): the expiry, or the quiet read for a cookie that
  records nothing, puts it where a walk found it, or removes it.
- **A take between:** the cookie records nothing, so takes do not change it.
- **A create or move-in at the old path before the expiry:** it expires the move-out before its own walk runs, so the
  subtree goes, and the walk watches what is there now. That is right for a new folder and for the one that left, back
  again; for the latter it costs a remove and an add per folder (section 8).
- **A move-in at the old place under a new path** (the old parent renamed in between): its walk gets the folder's own
  watch at its root, so the folder came back, and the move-out keeps its watches (2.5).
- **The old parent renamed or moved out itself before the expiry:** the place is by watch, so the expiry finds it.
- **The old parent deleted before the expiry:** the folder that moved out of it gets no `DELETE_SELF` (it is not in it
  any more), and the place goes with the parent. The parent's `forget()` sets each watch still held below it adrift,
  so the expiry still finds it and it leaves the tree (2.5).
- **Watch numbers given again:** fact 11, they are not given again soon, so a removed watch's queued events cannot
  meet a new folder's watch of the same number. Those events are dropped as "Watch descriptor not found", as on 0.55.1.

**What it records against 0.55.1:**
- Changes made outside the tree in a folder that left it are no longer recorded inside it.
- No test of the suite changes what it records. Review 5's F1 probe goes from wrong 3 of 3 to right 6 of 6 (both tail
  cases).

## 5. Issue 3: an event queue overflow can leave a new folder unwatched

**Mechanism:** 2.7.

**Across the orders:**
- **Events of the same read before the overflow** are handled first, as today.
- **Events after it** were queued after the queue had room again. Most describe changes after the walk; those from
  before it (a rename the walk already put) land the folder where it already is.
- **A folder misnamed as the mover** (a folder made where another left, which the walk put at the old place) is
  re-placed at its own create or move-in, which is read before its own events (2.7).
- **A take between:** the full comparison is the batch.
- **A second overflow:** the same again.

**What it records against 0.55.1:**
- After an overflow, later writes in a folder whose create was lost reach a version; on 0.55.1 they raise no event
  until a restart.
- A folder renamed with its events lost has its later changes recorded at its new path, where 0.55.1 kept wrong bytes
  in the probe: `lost_rename` left `b2/a` wrong, with stale watches.
- Watches of folders that left the tree are removed.
- The overflow probe: 9 of 9 fail on 0.55.1, 9 of 9 pass on the variant.

**Cost:** one walk of the tree per overflow: 0.65-0.68 s of the watcher's CPU for 102,061 folders, about the first
walk's (section 8; 0.55.1 spends nothing there, as it only asks for the full comparison). An overflow raises the queue
limit (it doubles), so it does not repeat soon.

## 6. Two older routes the same design fixes

Both are older than 0.55.1, and both are on 0.55. Neither has an entry in docs/limitations.md.

- **`RENAME_EXCHANGE` of two watched folders, then changes in them** (`exchange`, `exchange_twice`):
  - On 0.55.1, the first move-in rewrites `big`'s paths to `other`, and the second rewrites everything at `other`, both
    folders, to `big`. Every later event of either folder is recorded under `big`.
  - 0.55.1 fails `exchange` in 136 of 136 orders and `exchange_twice` in 816 of 816; the variant fails none.
  - `renameat2()` with `RENAME_EXCHANGE` does this, and recent coreutils' `mv --exchange` calls it.
- **A folder renamed over an empty folder made in the same batch, then renamed on and changed** (`over_empty`: `mkdir e;
  mv -T big e; mv e f`, then a same-size change in `f/a`):
  - On 0.55.1, the walk of `e`'s create finds `big`'s watch at `e`, re-points it and puts it in `newDirWDs`, so its
    later events are discarded until a take. The batch records `big`'s move, not a copy, so a change caught in that
    window is lost: 273 of 816 orders.
  - The variant's root rule (2.3) records a copy; it fails none.

## 7. What is recorded differently from 0.55.1, and what changes in the tests

**In the suite, no test changes what it asserts.** The walk's new way of reaching folders changes how some tests inject
their races, and those tests change with it:
- **`tests/harness.py`:**
  - `scripted_watch()`'s stand-in for `initializeFolderWatchers()` takes the tree, the parent and the name, and puts its
    watch in the tree;
  - a new helper, `fs_path()`, turns what a watcher's call names into the folder's path: a path, an open folder's fd
    (`os.scandir(fd)`), or `/proc/self/fd/<fd>` (`add_watch` of an open folder).
- **Fakes of `add_watch` and `os.scandir` that match a path** read it through `fs_path()`: `tests/test_inotify.py`,
  `tests/test_matched_time.py`, `tests/test_inner_mounts.py`, `tests/test_skip_list_watch.py`,
  `tests/test_moves_into_new_folders.py`.
- **Hooks that stepped in at a point of the watcher's walk** wrap `subfolders_of()` in place of `iter_tree_entries()`,
  each at the same point:
  - six tests of `tests/test_moves_into_new_folders.py`;
  - the walk visits of `tests/test_watcher_schedules.py` (one visit a subfolder, where it was one an entry), so its
    sampled vectors reach other orders than before.
- **`tests/test_inner_mounts.py`** imports `errno`. Its EIO fake raised a `NameError` that `iter_tree_entries()`'s
  `except Exception` swallowed as an unreadable folder, so the test passed by accident; the new walk catches `OSError`
  only.

**Over the schedule shapes:** the comparison (`probes/compare.py`) runs every shape on both codes and counts what each
records. At 8 visits, with 150 orders sampled for 5 to 7 steps, 7,350 orders of 61 shapes:
- **Wrong:** 0.55.1 241 (`exchange_twice` 120, `over_empty` 45, `exchange` 36, `root_ahead` 25, `twice_old_race` 15);
  the variant none.
- **Moves:** 4,173 against 4,131. 42 orders record fewer moves (a copy), all in `over_empty` (section 12), and none
  records more. Of `over_empty`'s 120 orders, 0.55.1 was wrong in 45: the variant copies in 30 of them and moves right
  in 15. In the other 75, 0.55.1 moved right: the variant copies in 12 and moves in 63.
- **Creates** differ in three shapes, each toward the tree:
  - `q3_deep_out` (300 against 431): 0.55.1 also records the writes that a watch of a folder outside the tree reported,
    under the tree's path (F3's phantoms);
  - `twice_in_new_newfile` (190 against 220): 0.55.1 also records the write in `big/sub` made before `big` moved into
    the new folder, then `big`'s delete; the variant discards it with the moved folder's events, which the new
    folder's copy holds;
  - `c2_unwatched_old` (328 against 322): in 6 orders the variant records a write in `o2/u2` at its own path, from
    `u2`'s watch, where 0.55.1 records nothing for it. Both are right in all 150.
- The seven shapes added late (`out_sub_into_new`, `out_deep_into_new`, `out_made_sub_into_new`,
  `out_made_deep_into_new`, `sub_back_parent_renamed`, `sub_back_parent_into_new`, `out_parent_deleted_back`) record
  the same on both codes at these bounds: 960 orders, none wrong, 120 moves and 1,260 creates each.

**The changes, all toward the tree as it is:**
1. A walk no longer puts a watch ahead of its folder's events (F2).
2. At a create's walk root, a held watch taken from another place makes that place's move-out a copy (section 12).
3. No phantom events from a watch whose folder left the tree (F3).
4. After an overflow, watches follow the tree.
5. An exchange's two folders keep their own paths.

## 8. What it costs (measured)

Through the real `watchFolder()` on real inotify, tmpfs, 0.55.1 against the variant, three runs each, alternating; the
watcher's CPU only. The machine ran the gates meanwhile, so CPU numbers carry about ±10%. The tree: project folders of
50 module folders, each with one `src` folder (1,010 projects for 102,061 folders, 200 for 20,251), plus the
workload's own folders.

| Workload (`probes/bench_watcher.py`) | 0.55.1 | Variant |
|---|---|---|
| Memory after the first walk, 102,061 folders (tracemalloc) | 17.98 MiB | 27.08-27.09 MiB (+94 B a watch) |
| The first walk, 102,061 folders | 0.49-0.51 s | 0.56-0.62 s |
| 20,000 file writes in 50 folders (23,000-26,000 events) | 0.09-0.11 s | 0.09-0.10 s |
| 200 folders of 101 folders renamed and back (400 renames), 20,251 folders | 0.95-1.20 s | 0.14-0.15 s |
| 300 folders of 10 subfolders moved out and back in, 20,251 folders | 0.40-0.47 s (3,202 events) | 0.086-0.095 s (6,802 events) |
| 2,000 renames in one folder of 10,000 subfolders | 7.52-7.95 s | 0.052-0.062 s |
| `rm -r` of one folder of 10,000 subfolders | 0.080-0.087 s | 0.083-0.093 s |
| One `IN_Q_OVERFLOW` read, 102,061 folders (injected, no sysctl written) | 0.000 s | 0.65-0.68 s |

The variant's extra events in the move-out row are the `IGNORED` of the watches a folder back at its own path gets
fresh (see the notes). The load on the machine was 125 to 145 on 32 cores during these runs (the gates). Two earlier
runs of the same bench, on the variant before its last rules and at loads of about 120 and 150 to 250, gave the same
picture (first walk 0.60-0.62 against 0.50-0.54 s, and 0.67-0.68 against 0.54-0.56 s).

**The walk alone,** by `probes/walk_fd_cost.py` on an idle machine, 101,000 folders, 3 runs:

| Walk | µs a folder |
|---|---|
| By path, as 0.55.1 (`add_watch(path)`, `scandir(path)`) | 2.33-2.46 |
| Through open folders (this design) | 2.91-2.99 |
| Through open folders, checked to be still at its name after the watch | 3.74-3.78 |

The last, dropped, would close 2.4's no-`MOVE_SELF` case at the walk. 2.5 settles that case at the expiry for nothing
per folder.

**Notes:**
- **Memory** is most of the cost: `up` and `kids` beside the path cache. A layout of an int or a list for the children
  costs 11 to 19 B a watch less (`probes/mem_layouts.py`), but makes renames and deletes in a wide folder O(its size) in
  Python: 2,000 renames in a 10,000-wide folder took 10.7-13.6 s and the `rm -r` 0.55 s. The design takes the
  path-keyed dict.
- **The CPU saving** is the pass over every watch that 0.55.1 makes twice per folder move. It grows with the tree:
  0.55.1 paid 0.12 to 0.13 µs per watch per rename in the wide-folder run (30,252 watches), so about 0.13 s per folder
  rename at 1,000,000 watched folders (extrapolated, not run).
- **A file event** costs the same: one dict lookup of the path cache.
- **A walk** costs more per folder: the tree's links and the open of each folder. That is about 0.1 s more per 100,000
  folders at the start (0.56-0.62 s against 0.49-0.51 s above), and the same per folder made by `mkdir -p` or `tar x`.
- **A folder that left the tree and came back to its own path before the expiry** gets fresh watches: one `rm_watch`
  and one `add_watch` per folder, plus their `IGNORED` events. 0.55.1 makes one `add_watch` probe per folder. One back
  at its place under a renamed parent keeps its watches (2.5).
- **An ordinary batch** pays nothing more. Moves are still moves, except at a create's walk root (section 12).

## 9. Tests and gates

Counts on 0.55.1 and on the variant (the reverberator.py of this design, outside the branch). Schedule runs use the
round 21 harness: each step at a chosen hook visit of the watcher's own thread, and every vector of non-decreasing
visits up to the bound, or a seeded sample. Review 5's bounds: 3 and 4 steps every vector to 16 visits, 5 steps to 12,
6 and 7 steps 1,000 sampled. `SCHED_WATCHES=1` also checks at the end that every watch in `wdDic` is the one
`add_watch` hands back for its path.

| Gate | 0.55.1 | Variant |
|---|---|---|
| The suite (no path argument) | 3,888 passed, 40 skipped | 3,990 passed, 40 skipped (the same tests, plus 100 sampled orders of `out_made_sub_into_new` and two doctests) |
| Every schedule shape, review 5's bounds, `SCHED_WATCHES=1`: round 21's 53, round 22's 8 and the 7 added late (62,790 orders) | 1,882 fail: `exchange_twice` 816, the watch map of five F3 shapes 306 (`found_out` 259, `back_then_sub_out` 25, `sub_of_found_out` 17, `q3_deep_out` 4, `q3_sub_out` 1), `over_empty` 273, `root_ahead` 141, `exchange` 136, `twice_old_race` 135, `twice_old_race_sub` 75; the 7 late shapes none of 7,908 | all 62,790 pass |
| Review 5's F1 order (`probes/test_r5_f3_wrong.py`) | 3 of 6 fail (the tails alike) | 6 pass |
| Overflows, in process (`probes/test_overflow.py`) | 9 of 9 fail | 9 pass |
| `tests/test_watcher_schedules.py` at every order | 40,801 passed (round 21's record of this code) | 44,677 passed (its one shape more has 3,876 orders) |
| The take points (`probes/test_takes.py`) | 4,320 passed; 9 with a version taken mid-swap that lacks the swapped files, which a later version holds | 4,320 passed; 10 such points, of the same two swap shapes |
| The fuzz, seeds 0 to 5,999, lists checked | 6,001 passed, 7 errors | 6,001 passed, 8 errors |
| The real daemon (`probes/measure.py` rows 1:0, 2:0, 2:0.2, 4:0.2, two tries each) | +0.04, +102.44, +102.44, +100.11 MB | the same |
| `probes/real_twice.py` (twice, oldtwice, landfirsttwice, once, 3 tries each, with a restart) | 0 of 12 wrong | 0 of 12 wrong |

- **The fuzz's errors** are all one teardown check of both codes: the size a change list's name records (round 21's
  "L1 errors"), in other seeds on each run. No seed failed on the variant. Seeds 6,000 to 8,999 on the variant before
  `forget()`'s rule: 3,001 passed, 3 errors of the same check.
- **The fuzz found four routes on the way** that 0.55.1 gets right and earlier variants did not; each is a rule of 2.5
  and a schedule shape above: seed 647 (`leave_tree()`), seeds 929 and 1911 (a folder back at its place), seed 5837
  (`forget()`). Seed 4284 failed once on the variant before `forget()`'s rule and passed 27 of 27 alone there; it
  passed in this run.
- **The take points' mid-swap losses** are 0.55.1's: run alone three times each, `swap` and `folder_swap` give the same
  10 points on both codes. In a full run under load, the set moves by a point or two on either code.
- **The machine:** the gates ran side by side at full width, each in a memory-capped scope with as much swap as its cap,
  the fuzz with `OOMPolicy=continue`; the load stood at 100 to 250 on 32 cores.

**What the build adds to the suite:**
1. The schedule shapes to `tests/test_watcher_schedules.py`, sampled as its others are: `twice_old_race`, `root_ahead`,
   `twice_old_race_sub`, `c1_collision`, `c2_unwatched_old`, `out_back_sub`, `exchange`, `over_empty`, `exchange_twice`,
   `out_made_sub_into_new` (in the variant's suite already: 3 of its 100 sampled orders fail without `leave_tree()`'s
   puts), `sub_back_parent_renamed`, `sub_back_parent_into_new` and `out_parent_deleted_back` (2.5).
   `out_made_deep_into_new`, `out_sub_into_new` and `out_deep_into_new` ran in the gates too, and may join.
   Every shape of the file also gets the watch-map check at its end: each watch in `wdDic` is the one `add_watch` of
   its path hands back.
2. The overflow cases, in process, with the watch-map check.
3. Review 5's F1 order as an in-process test, and its control.
4. The `WatchTree` and `subfolders_of()` doctests.
5. Fuzz seed 340's order as its own test, if the builder can pin it; the seed alone reached it 2 of 2.

**The gates before release:**
- the suite;
- the schedule file at every order;
- the take points;
- the 6,000-seed fuzz, in a memory-capped scope with `OOMPolicy=continue`, so a runaway kills its own worker and fails
  its seed, not the run. An address-space cap per worker (`ulimit -v`, 4 GB) was tried and dropped: threads failed to
  start under it on both codes (11 of 600 seeds on 0.55.1);
- the real daemon on a plain f2fs scratch image (`tests/scratch_images.py`), for the rows above;
- no mergerfs and no `f2fs_io shutdown` tests.

## 10. The build's tasks, in order

1. `WatchTree`, with its doctest, beside `initializeFolderWatchers()`.
2. The walk through open folders (`subfolders_of()`, `WALK_OPEN_FLAGS`, `PROC_FD`) and its rules (2.3): `tree`,
   `parent`, `name`, `resync` and `landed`. `follow_inner_mounts()` and `remove_newly_skipped_watches()` take the tree.
   The test changes of section 7 go with it.
3. The event handling (2.2):
   - `COOKIE_VALUE` (`cookie`, `wd`, `name`, `path`, `isDir`, `own`, `record`, `ahead`), `LANDED` and `moving`;
   - `add_move_out()` (the cookie and its eviction), `land()`, and `forget_moved_away()` by place;
   - `leave_tree()` and `WatchTree.within()`, used by the expiry and by both move-ins to a skipped folder (2.5);
   - the walk's check for a folder back where it left (`walk()` in the variant), with `MOVE_SELF` leaving a pending
     move-out's cookie in `moving` (2.5);
   - `WatchTree.forget()` setting the watches still held below a forgotten one adrift (2.5);
   - the `MOVE_SELF` and nameless `ATTRIB` branches.

   `remove_moved_away_watches()` and the pass over every watch at a paired move go.
4. The discard branch: the cookie that records nothing, the move-in with a known cookie.
5. The overflow walk (2.7).
6. The quiet read: leftover cookies that record nothing settle, and the five maps clear.
7. Tests (section 9), then the gates.
8. Docs, written by the main session:
   - docs/limitations.md:
     - the three deferred entries go;
     - "A folder or file moved into a new folder is copied whole" loses the clause that names them as the condition
       to revisit;
     - "A move that another change of the batch outran is copied" gains the root-rule copy (section 12).
   - README: the watcher's paragraph (line 24) gains one sentence on what the watcher does at an overflow, and one on
     the root-rule copy.
   - docs/lessons.md: nothing; no API changes.

## 11. Left to the builder

- Names, log levels and messages. The DEBUG lines of the variant say which branch ran. At INFO or above, the overflow
  walk gets one line with its count of watches put and removed.
- Whether `WatchTree` keeps `name_of()` (used by `place_of()` only) or slices the path.
- `watch_at()` stays the one O(n) path lookup, for `follow_inner_mounts()` only (a mount change).
- Whether the walk checks for `/proc/self/fd` once at import (the variant) or at each walk.
- The variant clears `moving`, `found`, `ahead`, `adrift` and `replaced` at the quiet read only. In a tree that is never
  quiet, only entries whose event can no longer come stay: their watch was removed. That is a few dozen bytes each, and
  no aging is proposed.

## 12. Questions for the user

One question, now decided; no other is open. The rules added after it (2.5: `leave_tree()`, a folder back at its
place, `forget()`) change nothing recorded against 0.55.1 over the comparison of section 7, so they raise none.

### The one new copy (decided)

**A folder whose move a create's walk saw before its move-out was read, at the place of the create, is copied** (the
root rule of 2.3, where the events name no watch at that place yet).

- **What the operator sees:** in a race, a folder that another command moves into the place a create or a move-in from
  outside names is recorded as a delete and a create. The commands: `mkdir e; mv -T big e`, a rename over an empty folder
  made just before; or `mkdir o2/x; rmdir o2/x; mv big o2/x`. All of them land before the watcher reads the first one.
  - The batch copies the folder's files again, though the vault holds them, with no line in the log.
  - With a size limit, that copy can prune older versions, as the copy of "A folder or file moved into a new folder is
    copied whole" can.
  - The result is right. Over the two shapes, 0.55.1 kept wrong bytes in 141 of 1,000 orders (`root_ahead`) and lost a
    change in 273 of 816 (`over_empty`); the variant is right in all of them, with a copy in some and a move in the
    rest (the counts below).
- **Why not fix it:** the folder's events from before its move-out are still in the queue, and may already have come
  at the new place. Only reading ahead in the queue could tell whether any change is among them, and that adds parts
  for a race between the commands and the watcher's read of the first of them.
- **Revisit when:** a copy shows up for such a move in the live logs or in the vault's size, or the no-copy move into a
  new folder gets its design. That design meets the same question.
- **Decision (2026-11-08):** "Known limitation (Recommended)". The approved entry "A move that another change of the
  batch outran is copied" is widened to this case; the main session writes it.
- **The verified design still needs it:** yes. At review 5's bounds, with the batches logged on both codes
  (`probes/test_sched_log.py`, `probes/compare.py`):
  - `over_empty`, 816 orders: the variant copies in 210. 0.55.1 was wrong in 182 of them and recorded a right move in
    28. In the other 606 the variant records the move, right in each, 91 of them orders 0.55.1 got wrong.
  - `root_ahead`, 1,000 sampled orders: the variant copies in 218. 0.55.1 was wrong in 1 of them and recorded a right
    move in 217. In the other 782 the variant records the move, right in each, 140 of them orders 0.55.1 got wrong.
  - So 245 of the 1,816 orders are new copies where 0.55.1 moved right, and none is wrong. At the comparison's smaller
    bounds (section 7) only `over_empty` reaches the copy, 42 of 120 orders.
