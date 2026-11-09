# Round 22 design: the watcher keeps each watch where the events put it (the watch tree)

Version 0.55.2. It fixes the watcher's three older deferred entries in docs/limitations.md, all on 0.55 and 0.55.1:
- "A folder renamed twice into a folder whose move is being walked can keep old bytes" (round 21 review 4's F2);
- "A folder moved out of the tree from a new folder keeps its watch" (review 4's F3, round 21's R5 phantom, review 5's F1);
- "An event queue overflow can leave a new folder unwatched".

A variant built from this design (v16, outside the branch) passes every gate that ran on it, and the shapes and seeds
of each route the gates found on the way; its gates were stopped at 5 to 72% by the host's low memory and are to run
again in full (section 9). Revision 1 (2026-11-08)
follows the spec check and the main session's rulings on it. What it changed in the design:
- **The rules are checked against stated invariants (2.1).** That check found one more order, where a move-out named
  the watch of a folder that had left already (`leaving()`, 2.5), and narrowed the one rule that takes a walk's view:
  the root put copies a folder only when an event of it came at its new place before its move-out was read (2.3). A
  script's `mkdir e; mv -T big e`, a copy every time on revision 0, is a move again (section 12); over the root put's
  schedule shapes, 14 of 5,624 orders copy, each with a change in the folder between the create and the move. Removing
  the root put was tried and fails an order (2.1).
- **An overflow restarts the watcher** (2.7), as a lost root does: a fresh instance takes the raised queue limit, its
  first walk watches the tree, and the full comparison covers the rest.
- **The walk is iterative** (2.3), so a tree deeper than Python's recursion limit is watched to its bottom, and it needs
  `/proc` (no fallback).
- **A new watch goes only where its folder is once the watch exists** (2.3): the walk checks it through the open parent
  after `add_watch`, and opens its root from the parent's folder. This is the seed 4284 agent's rule: on v8, a folder
  renamed between the walk's open and its watch kept a watch at the place it had left, and a change in it was lost
  (fuzz seed 4284, and v8's one failing shape on mergerfs).
- **A move-out takes no watch that a walk's root put at its place ahead of the folder's own move** (`leaving()`, 2.5).
  Fuzz seed 2509: a create's walk found there a folder whose move in was still queued, behind the created folder's own
  move-out, and that move-out took the found folder's watch. When the created folder had gone into the found one, the
  found watch was put under itself, and the watcher's pass over its subtree never ended: the watcher grew without bound
  on v7 to v9. 0.55.1 loses a change on the same route (section 6).
- **On mergerfs, a folder removed after the walk opened it is a folder gone**: mergerfs refuses its fd with `EBADF`,
  where a local filesystem lists it as empty. On v9 the check's `fstat` raised it and the job's watcher stopped
  (section 1).
- **An expiry takes a folder's watches only if its move-out is the last move of the folder read and the folder's
  `MOVE_SELF` came after it** (2.1, 2.5). The fuzz on v10, the variant first given the gates, failed two seeds:
  14124, a folder moved into a new folder and back to the very place it left, its parent renamed in between (an older
  route: the shapes cut from it lose a change in 870 of 1,365 orders on 0.55.1, 505 on v10); and 12812, a regression
  from 0.55.1, where a walk watched a folder made where another had just left, and that one's move-out, read after,
  took the new watch and its expiry removed it (756 of 1,000 orders on v10, none on 0.55.1). v14 is v10 with the two
  conditions; it passes both seeds and the shapes.
- **Every folder a walk meets at the place its pending move-out left came back** (2.5), not only the walk's root. The
  fuzz on v14 failed seed 12831 (0.55.1 fails it too, 3 of 3): a folder came back to its place from outside while its
  parent was in a folder made in the batch and a higher one had moved into another; its move-in's walk ran at a stale
  path, and only the walk of the other new folder met it there. The shape cut from it loses a change in 661 of 1,000
  orders on v14 and 179 on 0.55.1. v15 is v14 with the check at every folder; it passes the seed and the shape.
- **A move-in moves the watch its move-out named only once that watch's `MOVE_SELF` confirms it** (2.4, 2.5): a later
  event in either folder of the move with no `MOVE_SELF` read sends the watch back (`unland()`). This fixes revision
  1's one open finding, `c2_then_into_old`, a regression from 0.55.1, and fuzz seed 19006 on v15 (3 of 3; 0.55.1 passes
  it, but loses the shape cut from it, `land_ahead_taken`, in 225 of 1,000 orders). v16 is v15 with it.
- **Every move-out settles at the latest at the pair timeout** (2.5), those that record nothing too;
  `remove_newly_skipped_watches()` looks at the moved folder's subtree only; `raise_queue_limit_for_removals()` goes;
  "Event name not found" is a DEBUG line; the root put's copy logs one WARNING.

## The user's words

- "I want this to be as light and as fast as possible... cause it is an backup solution, so it is designed to always in
  run the background. so every little bit will sum up to a lot over days month years." "simpler and smarter is better".
  "one of the core for reverberator is reuse existing linux features and easy browse / restore."
- 2026-11-07, on the entry of a folder renamed twice into a folder whose move is being walked (F2): "Next round, right
  after 0.55.1 (Recommended)".
- 2026-11-07, round 21, when another order kept wrong bytes through the move into a new folder: "Drop the feature
  (Recommended)": every such move is copied, as on 0.55, and the no-copy move gets its own design later.
- For 0.55.1, on the mergerfs and `f2fs_io shutdown` tests: "Skip them for 0.55.1 (Recommended)"; they come back in the
  round that touches the pool or the crash-safety code.
- 2026-11-08, on revision 0's question (section 12): "Known limitation (Recommended)", widening the approved entry "A
  move that another change of the batch outran is copied". Revision 1 removes the copy it was about.
- 2026-11-08, after the host's reboot: "Resume at full width (Recommended)".
- 2026-11-08, on the gates 0.55.1 skipped: "Bring both back (Recommended)": the mergerfs and power-loss tests run
  again, on scratch images and scratch mergerfs mounts only.
- 2026-11-08, on the fanotify research (section 1): "Keep inotify (Recommended)".

Not the user's words:
- The entries of a folder moved out of the tree from a new folder (F3) and of an overflow came to this round as the
  sessions' deferrals: F3's with the renamed-twice entry (round 21), the overflow's by its revisit, "the next round that
  changes the watcher".
- The rule this design follows from round 21's rulings: when the watcher cannot be sure, it errs toward a copy, never
  toward wrong bytes.

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
- Section 2.1 states what each structure holds and what every event, walk, expiry and quiet read keeps true; each
  rule of 2.3 to 2.6 is checked against it there. One rule takes the walk's view, at the root of a create's walk, and
  it ends in a copy when the folder changed in between (2.3, section 12).

What the same structure gives:
- An expiry removes a moved-out folder's watches only if the folder is still at the place it left, no later move of
  it was read, and its `MOVE_SELF` came after the move-out; it keeps each one a walk found back in the tree. It judges
  no watch by its path, so it neither removes a live folder's watch (R5's failure) nor misses one re-pointed by a
  rename of its old parent (F3).
- A folder's move-out read in a new folder gets a cookie that records nothing but settles its watches (F3).
- An overflow ends the watch and starts a new one (2.7), as a lost root does: its first walk watches the tree as it is.
- Two older routes to wrong bytes go too, found while backing the design: a swap by one rename (`RENAME_EXCHANGE`), and
  a folder renamed over an empty folder made in the same batch.

**What goes:**
- `remove_moved_away_watches()` and its `add_watch` probe;
- the `wds` tuple of each folder move-out, and the pass of `watches_under()` over every watch that fills it;
- the pass over every watch at each paired folder move (and, for a skip list that depends on location, the second
  pass of `remove_newly_skipped_watches()`, which looks at the moved folder's subtree only);
- `raise_queue_limit_for_removals()` and its sysctl write at each large removal (2.7);
- the watcher's use of `iter_tree_entries()`, whose `except Exception` also swallowed a test's `NameError` (section 7).

**What comes:**
- `class WatchTree`, with its doctest, beside `initializeFolderWatchers()`;
- the walk through open folders, iterative, with the tree's rules (2.3), plus `subfolders_of()`;
- a `moving` map: own watch → the cookie of its last move-out, or landed;
- the cookie that records nothing, and each cookie's `moved` (its folder's `MOVE_SELF` came after it);
- `landing` and `unland()`: a move-in's landing stands once the watch's `MOVE_SELF` comes, and goes back when a later
  event in either folder of the move comes first (2.5; revision 1's open finding, fuzz seed 19006);
- `leave_tree()`: a subtree that left the tree goes, but for the watches in it that a walk found back in the tree (2.5);
- a walk's check, at every folder it meets, for one back at the place it left, whose move-out then keeps its watches
  (2.5);
- a forgotten watch's children set adrift, so a deleted parent does not hide a pending move-out (2.5);
- `leaving()`: the watch a move-out takes is the one at the place whose own move-out from there was not read, and not
  one a walk's root put there ahead of its own move (2.5; fuzz seed 2509);
- `folder_still_at()`: a new watch goes into the tree only at a place its folder is at once the watch exists, and a
  walk's root is opened from its parent's folder (2.3; fuzz seed 4284);
- `WALK_GONE`: what a walk's open, listing or check gets for a folder gone, `EBADF` on mergerfs among them (2.3);
- `WATCH_RESULT_OVERFLOW`: an overflow restarts the watch (2.7).

**Numbers:** the gates are in section 9, the costs in section 8.

## 1. The kernel facts it relies on

Facts 1 to 14 were run with inotify on ext4 and on tmpfs, with the same results; the probe is kept with the design
report.

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
| 15 | An instance's queue limit | set when the instance is made: inotify(7) says `max_queued_events` "is used when an application calls inotify_init(2) to set an upper limit on the number of events that can be queued to the corresponding inotify instance"; in the kernel, `do_inotify_init()` passes it to `inotify_new_group()`, which keeps it in `group->max_events` (read in the man page on this host; the kernel source is reasoned, as the host has none) |
| 16 | Another process changing the same folder while a folder in it is renamed back and forth, 20,000 renames (in a container, on XFS; `probes/fact16.py`) | none of B's events came between a rename's `MOVED_FROM` and its `MOVE_SELF`; with B in another folder, 144 of 20,000 did (fact 13). `vfs_rename()` queues the three under both parents' locks (reasoned from the kernel source), so any later event in either folder comes after the `MOVE_SELF` |

**On FUSE.** Two live jobs watch trees on a mergerfs (FUSE) mount. The main session checked there, read-only, that
`add_watch` through `/proc/self/fd/<fd>` of an open folder gives the same watch as `add_watch` of its path, for both
folders it tried (`<scratchpad>/r22/verify/fuse_wd.py`): fact 14 holds there. Facts 1 to 10 come from the VFS, not the
filesystem: `vfs_rename()` queues a rename's events through `fsnotify_move()`, and `vfs_unlink()`/`vfs_rmdir()` the
deletes, for every filesystem. That is reasoned from the kernel source.

Renames on mergerfs ran on a scratch pool instead (never a live mount): mergerfs 2.42.0 over two `/dev/shm` branches
(bind mounts, as the daemon wants each disk of a pool mounted), with the live pools' options (`func.readdir=cor`,
`passthrough.io=rw`, `category.create=pfrd`, `cache.entry=60`, `cache.attr=60`, `cache.negative-entry=60`,
`cache.readdir=true`, `cache.symlinks=true`), the schedule shapes' watched folder and outside folder on the pool
(`probes/test_sched_mfs.py`, section 9). The pool and its bind mounts were mounted on the host as setup; the tests ran
in containers as uid 65534. At 8 visits for 3 and 4 steps and 50 orders sampled for 5 to 7, over 89 shapes (6,634
orders), 0.55.1 is wrong in 164 (`over_empty` 45, `twice_old_race` 15, `root_ahead` 7, `found_out`'s stale watch 3,
and the `root_put_*` shapes' lost change 94), and v10 passed all 6,634. With the ten shapes added since (99 shapes,
section 9), v15 passed 7,053 of 7,054 orders (the one, a folder's mtime off, passed 4 of 4 again), and v16 ran
5,282 before its gates were stopped, 2 of them the same mtime flake; 0.55.1 did not run the ten. On the way: v8 (74 shapes and 10 more, run as
root in capped scopes before the host's rule) was wrong in 5 orders of `c2_unwatched_old` and in 4 of
`stale_root_path`, the seed 4284 route; v9 stopped its watcher in 12 orders (below); v11, a check by the kernel's
identity, made the pool list folders that were not there in 6 (below). A failure with only a folder's mtime off came
now and then on every code but v10 (0.55.1 7 in one run of 5,310 orders, v8 3, v11 3; all 4 that were run again
passed), which I take for mergerfs's attribute cache; not run down.

Two facts of mergerfs 2.42.0 the walk meets there, both run on that scratch pool:
- **An fd of a folder removed after its open is refused:** `fstat`, `listdir` and `scandir` through it give `EBADF`,
  for an `rmdir` and for a rename over the empty folder alike, where tmpfs, ext4 and XFS give its stat and an empty
  listing. `add_watch` through `/proc/self/fd/<fd>` still works, and the watch gets `DELETE_SELF` and `IGNORED` when
  the fd closes. The walk takes `EBADF` as a folder gone (`WALK_GONE`, 2.3). On v9, the walk's check called `fstat`
  outside its `try`, and the error stopped the job's watcher thread: 12 orders of `cycle_guard_root` and `over_empty`,
  both of which rename a folder over an empty one a walk holds open, 18 of 18 when run again.
- **A folder's `st_ino` is made from its path** (`inodecalc=hybrid-hash`, the default, read from the scratch pool's
  `.mergerfs` control file): a folder made at the name of one renamed away gets the number the old one had. The walk's
  check (2.3) compares the stat of the name through the open parent with the `fstat` of the open folder; in five
  probes of that (a rename by `os.rename` and by `mv`, then a folder made at the old name) the open folder's number had
  moved with its new path every time, so the two differed. A by-path `stat` of the renamed folder from another
  process showed its old number once (the attribute cache, `cache.attr=60`), so the check rests on `fstat` reading the
  folder's own attributes. A check by the kernel's identity instead (`add_watch` of the name through the open parent,
  v11) made the scratch pool list folders that were not there, in 6 of the 446 `root_put_*` orders (`ls` of the
  created folder showed its new parent's entries; every later scan and marker failed on them), and 5 of 6 when those
  orders ran again; v10 (the stat) and 0.55.1 did not in the same 446 orders. That was not run down, and the design
  keeps the stat.

An overflow was not run on the kernel. Making one needs a lower `max_queued_events`, which needs `sysctl -w`, and the
value on the test machine is 8,388,608. It is made in-process instead: the read that holds the chosen events loses
them and ends with an `IN_Q_OVERFLOW`, as a full kernel queue does.

**Reasoned from the kernel source, not run.** One rename queues its three events inside `vfs_rename()`, while it holds
the locks that a second rename of the same folder needs. So a folder's renames are queued in the order they happened,
whatever other processes do in between. Fact 13 shows the in-between part. Each removed watch queues an `IGNORED`,
which counts against the queue limit like any event.

**Why not fanotify.** fanotify can report each event with a handle of the folder it happened in
(`FAN_REPORT_DFID_NAME`, Linux 5.9) and a rename as one event with both places (`FAN_RENAME`, 5.17), and one mark on a
filesystem needs no watch per folder; the daemon runs as root. That would remove the walks at a create or a move-in,
the per-watch memory, the unwatched folder after an overflow, and every race between a walk and the events. A research
agent ran it on this host (`.superpowers/sdd/2026-11-08-round22/fanotify-report.md`, beside this round's ledger): a
filesystem mark works on XFS, but mergerfs (FUSE, zero `fsid`) refuses filesystem and mount marks with `ENODEV`, so the
two mergerfs jobs would need a mark per folder or marks on each branch, and a filesystem mark sees the whole busy
filesystem, filtered down to the tree in the daemon. It recommends keeping inotify, and the user chose so ("Keep
inotify (Recommended)", 2026-11-08): this round fixes the inotify watcher the daemon has.

## 2. The design

### 2.1 Places, and what each structure keeps true

`WatchTree` holds, for each watch:
- `paths[wd]`: its path. This is the watcher's `wdDic`, kept as the cache every event reads, so a file event costs what
  it costs today.
- `up[wd]`: its parent's watch.
- `kids[parent]`: its children. One child is held as the int itself. More are held as a dict keyed by the child's path:
  the same string object as in `paths`, so it costs no string of its own. Its value is the watch, or a list of watches,
  oldest first.

Every operation the watcher needs is O(1), or O(the folder's subtree) for a move: `at(parent, name)` (the watch the
events name at that place: the oldest held there, not set aside), `held()` (all held there), `put()` and `move()` (a
watch with its subtree to a new place, every path below it with it), `subtree()`, `forget()`.

**Words used below.** *K* is the tree as the kernel had it right after the change of the last event read: the events
are queued in the order their changes happened, a folder's own events in order (section 1). A walk sees the tree as it
is now, which can be ahead of K. *A watch's place* is `(up[wd], its name)`; *held nowhere* means `up[wd]` is `None`
for a watch other than the job's root.

**The invariants.** For each structure: what it holds, which watch can be in it, and what keeps it true.

| Structure | Holds | Kept true by |
|---|---|---|
| `paths` | every watch of the instance not yet removed (`rm_watch`), deleted (`DELETE_SELF`) or unmounted (`UNMOUNT`). A placed watch's path is its parent's path and its name; one held nowhere keeps the path of its last place | only `add()`, `put()`, `move()` (which rebuild the paths of the subtree they move) and `forget()` write it |
| `up`, `kids` | each watch's place; `kids[p]` is exactly the watches whose `up` is `p`. No cycle | the same; `put()` cuts a cycle loose (below) |
| **I1, the places** | a watch's place is its folder's place in K, but for these, each recorded: a pending move-out (the place is kept until it settles), `found`, `adrift`, `ahead`, `replaced`, and a new watch a walk placed where its folder is now, ahead of K | every event moves the watch it names, in order; a walk moves no held watch (it notes it in `found`), with one exception, the root put (`ahead`) |
| `found` | held watch → the place a walk listed its folder at, where the events do not have it. Only held watches | set by a walk; popped by the watch's move-in to that place, by its `MOVE_SELF` (which puts it there), by `leave_tree()`, by `forget()`; cleared at the quiet read, after the move-outs settle |
| `adrift` | the watches whose place no event can give any more: a `MOVE_SELF` with no move-in and no found place; one still held below a folder at its `DELETE_SELF`/`UNMOUNT` (held nowhere: it left that folder by a move-out still to settle, as `rm -r` deletes what is in a folder first, fact 8); one cut loose by `put()`'s cycle guard | a walk that finds it puts it there; any `put()` takes it out; cleared at the quiet read |
| `ahead` | place → [the watch a walk's root put elsewhere, whether an event of its subtree was read since]. While it is there, the watch's folder is at that place in K: its move-out from there, and its move to where it was put, are still queued | set by the root put (2.3), but for a watch whose move-out from that place was read already (`walk()` drops it); popped by that place's next move-out; cleared at the quiet read |
| `replaced` | watch → its place, where a move-in landed another folder while this one is still named there | `move()`; then an `ATTRIB` with no name on its own watch (it was replaced: set aside) or its own move-out (an exchange); popped by any `put()` or `forget()`; cleared at the quiet read |
| `shadows` | watches set aside at their place: replaced (on their way to `DELETE_SELF`), or displaced by an event's own put | `put()`; the oldest set aside is named again when the one named leaves |
| `moving` | own watch → the cookie of its last move-out read, from its `MOVED_FROM` until that settles; or `LANDED`, from its move-in until its `MOVE_SELF`. A later move of the watch, out or in, overwrites it, so a move-out whose cookie is no longer there is not the folder's last move read | the move-out, `land()`, `MOVE_SELF` (pops `LANDED` only), the settling of the move-out, the walk's check for a folder back where it left; cleared at the quiet read |
| `landing` | own watch → the move-out's place and the move-in's, from a folder's move-in until its `MOVE_SELF`: the move is the watch's only once that comes | `land()`; popped by the watch's `MOVE_SELF` (the move was its folder's), or by `unland()` at the first later event in either folder of the move, or at the quiet read, with none read (it was not: the watch goes back to the move-out's place); by `DELETE_SELF` |
| the cookies | each move-out read and not settled, oldest first: the place it left, `own` (the watch `leaving()` names there, `None` for a file or a folder with none), `record`, `ahead`, the time it was read, `moved` (`own`'s `MOVE_SELF` was read after it, while it was `own`'s last move-out). Every one that records has its delete pending | settled exactly once: by its move-in (a pair), at the pair timeout, at a create or move-in at its path, at the 16,384th later one (eviction), at the quiet read |
| `newDirWDs` | watches of folders inside a folder the batch copies (made, or moved in as a copy, since the last take): their events are discarded, as the copy holds them | a create's walk, a copied move-in's walk; cleared at each take |

**What each step keeps true:**
- *An event* moves only the watch it names, to the place it names (I1): a move-in moves `own` with its subtree, and
  `own`'s `MOVE_SELF` confirms it, or a later event in either folder with none sends it back; a `MOVE_SELF` with no
  move-in puts the watch at its found place or sets it adrift; a delete forgets it. A move-out
  moves nothing yet: the place is kept until the move-out settles, so a take-back still pairs (0.55's window).
- *A walk* adds each new watch at the place its folder is at once the watch exists, under the watch of the folder it was
  listed in, and moves no held watch; it notes one found elsewhere. It puts an adrift watch where it finds it. The root put (2.3) is the one
  exception, recorded in `ahead`.
- *A settling move-out with no pair* takes `own`'s subtree out of the tree if it is still `own`'s last move read, `own`'s
  `MOVE_SELF` came after it, and `own` is still where it left, or held nowhere; the watches in it a walk found back in
  the tree stay, there.
- *The quiet read* settles every move-out, then clears `moving`, `found`, `ahead`, `adrift` and `replaced`: every event
  that could settle them has been read, and the settling read them (2.2).

**Each rule of 2.3 to 2.6 against them:**

| Rule | Follows from the invariants, or a condition for an order |
|---|---|
| The walk through open folders (2.3) | follows: a watch goes under the watch of the folder it was listed in (I1) |
| A new watch where the walk found it; none under a folder that could not be watched | follows (I1: a place needs a parent watch) |
| A held watch at its place: nothing. Elsewhere: `found` | follows: a walk moves no held watch (I1) |
| At a walk's root, with a watch the events already name there (`landed`): another watch found there is treated as below the root | follows: the walk's root is a place the event at hand names; putting another watch there would move it on the walk's view (I1). Seed 340 and `c2_unwatched_old` are the orders it was found by |
| At the root of a create's walk, or of a move-in with an unknown cookie, a held watch where the events name none: put there, its old place in `ahead` | a condition for orders. The one place the design takes the walk's view. The event at hand names this place for a folder, and its own later events come after this event (FIFO), so the watch of the folder there must be at this place from now on. But the walk cannot tell that folder from one that came there after it by a rename still queued (`root_ahead`, `over_empty`), so the move-out from the old place is copied if an event of the folder was read in between (2.3). Without it, `c2_unwatched_old` fails: the first `u`'s move-out, read after a walk placed the second `u`'s watch at `u`, moves that watch away, and nothing else puts it back. A variant that noted the root watch in `found` instead failed 5 of its orders before the run was stopped (the second `u` unwatched) |
| The root put's copy: only when an event of the put watch's subtree is read between the put and the old place's move-out; none when that move-out was read before the put; the put watch and those below it kept out of `newDirWDs` | follows from FIFO: the folder's events from before its move are queued before its move-out, so only those read after the put can have come at the new place, and none can once the move-out was read. A move that may stay a move needs its folder's events, which no copy then holds (0.55.1 lost a change in `over_empty` by discarding them) |
| A copied move-in's walk adds to `newDirWDs`, as a create's does | follows (`newDirWDs`: the copy holds what changes in it) |
| A held watch adrift: put where the walk finds it | follows (`adrift`) |
| A folder a walk meets at the place its pending move-out left, at the walk's root or below it: the move-out keeps its watches (2.5) | follows from what a cookie's `own` is, the folder that left the place and has not come back, and from the walk seeing the tree after that move-out was read: the folder is back. The path-based expiry at a create or move-in does the same when the path is the same; this check covers the place under a new path. Found at the root by seeds 929 and 1911; below the root by seed 12831 on v14, where the move-in's own walk ran at a stale path and only another new folder's walk met the folder |
| `MOVE_SELF`: landed, nothing; otherwise the found place, or adrift (2.4) | follows (`moving`, `found`, `adrift`) |
| A cookie that records nothing settles at its `MOVE_SELF` | follows: it records nothing, and the `MOVE_SELF` says the folder went where no watch was |
| The expiry by place, through `leave_tree()` (2.5) | follows (I1 and `found`): a walk's found place is the one no event will correct once every event is read |
| The expiry takes `own`'s watches only while the move-out is the last move of `own` read (`moving[own]` is its cookie) | follows from I1 and the kernel's order (a folder's renames are queued in order, facts 1 to 4 and 13): a later move-out or move-in of `own` says its folder was in the tree after this move-out, and that later move's events place it. The place alone cannot tell, as a folder can come back to the very place it left through a new folder (`mv sub/d n/d; mv n/d sub/d`, `n` made in the batch), and with its parent renamed in between the path-based expiry at the move-in does not catch it either. Found by fuzz seed 14124 on v10: `back_home_via_new` and `back_home_via_new_sub` lose the write in 505 of their 1,365 orders each on v10, in 870 on 0.55.1 (an older route, section 6) |
| A move-in's landing of `own` stands only if `own`'s `MOVE_SELF` comes before any later event in either folder of the move; otherwise `own` goes back to the move-out's place (`unland()`, v16) | follows from fact 16, as the expiry's second condition does: a watch the move-out named that gets no `MOVE_SELF` was added after the rename, for a folder a walk found at that place after the mover left, so the move was another folder's. Revision 1 found the route at its end (`c2_then_into_old`: a folder the walk watched at a place another had just left, then moved into that folder; the move-in carried the second folder's watch to the first one's new place, and the second folder's own `MOVE_SELF` was then taken as that landing's) and left it open; fuzz seed 19006 on v15 found it in the fuzz (`land_ahead_taken`; reasoned from the code, as its failing orders passed when run alone with the log on: the root put of the second folder's create took the watch back from the wrong place, and its `ahead` entry then kept the second folder's own move-out from it). `c2_then_into_old` fails 5 of 5 orders on v9, v10 and v12, `land_ahead_taken` 204 of 1,000 on v15 and 225 on 0.55.1; v16 passes both and `c2_then_moved` |
| ... and only if `own`'s `MOVE_SELF` was read after the move-out (`moved`) | follows from fact 16: the kernel queues a rename's `MOVE_SELF` on each watch the folder has before any later event in either folder of the rename, and every expiry comes after such an event or later (a create or move-in at the path is one in the same folder; the quiet read has read everything; the pair timeout is 30 s on; eviction 16,384 move-outs on). So a watch with no `MOVE_SELF` since the move-out was added after the rename, by a walk that found its folder at that place after the mover left: another folder, made or moved there since, which the walk placed ahead of K. Found by fuzz seed 12812 on v10: in `walk_ahead_taken` (`mkdir big/n m; mv big/n m/n; mkdir big/n; mv big m/n/big`), the first create's walk watches the second `n`, the first `n`'s move-out, read next, names that watch, and the second create expires it, removing the watch of a folder still in the tree; the create's walk runs at `big`'s old path and finds nothing. It and `walk_ahead_taken_sub` lose the write in 756 and 772 of 1,000 sampled orders on v10, none on 0.55.1 or with the condition |
| `leaving()`: a move-out takes the watch at the place whose own move-out from there was not read | follows from the cookies: a watch with a pending move-out from a place has left it, and is kept there only until that settles. Found by checking the cookies against I1 (`made_at_pending_out_*`: 11 of 600 orders left a watch of a folder outside the tree, where 0.55.1 left none) |
| `leaving()`: nor a watch the root put at the place while its `ahead` entry stands | follows from I1 and `ahead`: in K that watch's folder is still at its old place, and the kernel queues its move to the new place, and any move from there, after its move-out from the old one; so a move-out from the new place read before that is another folder's, the one the create named. The revision 1 check judged the root put against the old place only; fuzz seed 2509 found the new one (2.5). Without it, 422 of the 3,949 orders of the five `root_put_*` shapes put a watch under itself on v9 (run with the endless pass made an error; v9 itself grows without bound) |
| `forget()` sets the watches still held below adrift | follows from fact 8 and the cookies: such a watch left by a move-out still to settle. Found by seed 5837 |
| A new watch goes into the tree only at a place its folder is at once the watch exists: checked through the open parent right after `add_watch`; a walk's root opened from its parent's folder | follows from I1: only the kernel's events move a watch, and the kernel reports a folder's moves only from the moment its watch exists, so a watch's first place has to be read after that moment. Found by fuzz seed 4284 (the seed 4284 agent's report): without it, v8 loses a change in 13, 7, 13, 5 and 3 orders of five shapes at review 5's bounds, and in 16 of 75 deeper orders of the seed's own round |
| `put()`'s cycle guard | follows: K has no cycle, so a parent held below the moved watch left it by a move-out still to settle. Reached: `cycle_guard_root`, 18 of its 1,365 orders (a create's root put read while the tree still holds the parent under the put folder, and another folder at the put folder's old path holds the parent at the same path, so the parent's path checks out). `cycle_guard`, which reached it 165 times on v8 through a watch placed before its folder's rename was seen, no longer does. Seed 2509's cycle was not this one: its move-in named the moved folder's own watch as the parent (a wrong mover, not a parent left behind), which the guard's climb, from the parent's parent up, does not look at; the fix is `leaving()`'s, at the rule that named the mover |
| Cookies that record nothing expire at the pair timeout | follows: every move-out settles once, at the latest at the pair timeout |
| Replaced or swapped (2.6) | follows from facts 9 and 10 (`replaced`) |

What the check changed: it added `leaving()`, and narrowed the root put's copy to the case FIFO cannot rule out. It
removed no rule: none turned out to follow from another, and the one tried for removal, the root put, is a condition
an order needs. It missed one consequence of the root put, which fuzz seed 2509 then showed: the put watch's new place
is ahead of K, so no move-out read from there before its `ahead` entry goes is its own (`leaving()`'s second clause).
It missed two of the expiry, which the fuzz on v10 showed (seeds 14124 and 12812): judged by its place alone, an expiry
cannot tell a folder that never moved since its move-out from one that came back to that place, nor the mover's watch
from one a walk placed there after the mover left. Both follow from what the kernel queues for a watch (the expiry's
two conditions above); the place stays as the third. And the fuzz on v14 (seed 12831) showed that the check for a
folder back where it left held at a walk's root only, where what it rests on, a walk seeing the tree after the
move-out, holds for every folder the walk meets. The open finding of revision 1 and fuzz seed 19006 on v15 were the
move-in's side of the expiry's second condition: a move-in carried a watch that got no `MOVE_SELF` (`unland()`).

**Two watches at one place.** Two watches can share one place for a while: a walk lists a folder made where another
one left, before that move-out is read. The older one is the one the events name (`at()`) until it leaves; the newer
one is held beside it. A move-in onto a place another folder holds notes that one in `replaced` (2.6).

**No cycles.** The kernel moves no folder into its own subtree. So when `put()` is asked to put a watch under one held
below it, the folder in between left by a move the events have not shown yet (the root put ahead of it,
`cycle_guard_root`). It leaves the moved watch's subtree and is held nowhere (`adrift`) until a walk finds it or its
move-out settles. Without this, `put()`'s pass over the subtree never ends. A move-in that names the moved watch as its
own parent is no such case: the rule that named the mover is wrong, and `leaving()` is where that is kept true.

### 2.2 Event by event

| Event | 0.55.1 | Round 22 |
|---|---|---|
| Folder `MOVED_FROM` | cookie with `watches_under(path)`: a pass over every watch | cookie with `own = leaving(parent, name)`: the watch at that place, but for one whose own move-out from there was read already, or that a walk's root put there ahead of its own move (2.5) |
| Any event in either folder of a move whose landing waits for its `MOVE_SELF` | — | first, the landing is undone: the watch goes back to the move-out's place, as its folder did not make the move (`unland()`, 2.5) |
| Folder `MOVED_TO`, cookie known | `move` recorded; every path under the old one rewritten (a pass over every watch); walk of the new place | `move` recorded; `own` with its subtree moved to the new place (`move()`), `moving[own] = landed`, and the landing noted until `own`'s `MOVE_SELF` (`landing`); walk of the new place, which knows `own` landed there |
| `MOVED_TO`, cookie unknown | create, walk | the same; a folder a walk meets at the place its pending move-out left (its root, or any folder below it, while a move-out is pending) came back and keeps its watches (2.5) |
| Folder `CREATE` | create, walk | the same |
| `MOVE_SELF` on a folder's own watch | skipped | landed: the landing is the watch's (`landing` popped). Otherwise the folder went where no watch was: to the place a walk found it since (`found`), or, with none, it is `adrift` until a walk finds it. A cookie that records nothing (2.5) is settled now; the cookie of a move-out still to settle stays in `moving` (2.5) |
| An unpaired move-out settles: at the quiet read, at the pair timeout (`max(min_snapshot_delay, 30 s)`, 60 s at the default delay), at a create or move-in at its path, or when the 16,384th later move-out evicts it | delete recorded; each watch of `wds` still mapped under the old path is probed with `add_watch` and removed unless handed back | delete recorded; if `own` is still at the place it left, or held nowhere, its subtree leaves the tree (`leave_tree()`, 2.5): removed, but for each watch in it that a walk found back in the tree, put there |
| Folder `MOVED_TO` into a skipped folder, cookie known | delete recorded; the watches mapped under the old path removed | delete recorded as on 0.55.1; `own`'s subtree leaves the tree (`leave_tree()`), here and in a folder made in the batch |
| `ATTRIB` with no name on a folder's own watch | one INFO line, "Event name not found, ignoring event" (one a folder for a `chmod -R`) | a folder a move-in landed on is replaced: set aside (2.6). The line is DEBUG only |
| `DELETE_SELF`, `UNMOUNT` | the watch dropped | the same, from the tree; a watch still held below it is held nowhere (`adrift`), as its folder left by a move-out still to settle (2.5) |
| `Q_OVERFLOW` | full comparison requested, queue limit raised | the same, then the watch ends, and `watcher()` starts a new one (2.7) |
| The quiet read: a read with no event, more than `min_snapshot_delay` (60 s by default) after the last read that had one, or the last mount change | every pending move-out expires | each landing still waiting for its `MOVE_SELF` is undone first; then the same, for every cookie, oldest first, the ones that record nothing too (2.5); then `moving`, `found`, `ahead`, `adrift` and `replaced` are cleared. Only after the cookies settle: settling reads `moving` (the check for a folder back where it left), `found` (`leave_tree()`'s puts) and `adrift` (held nowhere). A read with no event before the delay is not the quiet read, and clears nothing |

Takes, the discard of events in a folder made in the batch (`newDirWDs`), the scan after a take, skip lists and inner
mounts are 0.55.1's, with the tree passed along.

### 2.3 Walks

**How a walk reads the tree.** A walk adds each folder's watch before reading the folder, as today, so a folder made in
it afterwards raises its create. What changes is how it reaches each folder:
1. It opens the folder relative to the folder it is in (`openat()`, as a folder and not a link to one: `O_DIRECTORY`,
   `O_NOFOLLOW`).
2. It adds the watch through that open folder (`/proc/self/fd/<fd>`).
3. It checks a new watch: the name in the open parent must still be the folder it holds (`folder_still_at()`: `st_ino`
   and `st_dev` of the name's stat through the open parent, against the `fstat` of the open folder). If the folder was
   renamed away between its open and its watch, the kernel will report no move of it (it had no watch then), so the
   watch is removed again and the folder is treated as gone before its watch: the walk of where it went watches it
   (its move-in's walk, or the create walk of the folder not watched yet that it went into; out of the tree, nothing
   needs one). An open folder whose `fstat` fails is gone (mergerfs gives `EBADF` for a folder removed after its open;
   on v9 that error stopped the watcher). On mergerfs `st_ino` is made from the path; section 1 says why the check
   still tells the two folders apart there, and why the kernel's identity (`add_watch` of the name) is not used.
4. It lists the folder through it. A folder gone by then, or a link now (`ENOENT`, `ENOTDIR`, `ELOOP`, and `EBADF` on
   mergerfs, which refuses an fd of a folder removed after its open), is left to its own events, with no log line.

The watch and the listing are then of the one folder the walk holds, and each subfolder is opened from it, so each
watch goes under the watch of the folder it is in, at a place the folder is at once its watch exists.

**The root is opened from its parent's folder** too, when the walk has a parent: the parent's folder by its cached
path, which is the parent's only if `add_watch` through it hands back the parent's own watch (facts 6 and 14). Then
the root is opened by name from it and checked as above. A parent path that now holds another folder, or none (the
parent's rename is still queued), gives no walk: the walk of where the parent went lists the root. Opened by the
event's path instead, a create read after its parent's rename and a folder made again at the old path watched the new
folder under the old parent's watch (`stale_root_path`, 3 of 136 orders on v8).

**Iterative.** The walk keeps a stack of the open folders, one a level, each with what is left of its listing: depth
first, a folder's subfolders right after it, as before. It makes no call a level, so a tree deeper than Python's
recursion limit (1,000) is watched to its bottom: one `mkdir -p` of about 1,000 levels no longer stops the job with a
`RecursionError` (the spec check's probe; 0.55.1 leaves the deepest levels unwatched). The daemon raises
`RLIMIT_NOFILE` to its hard limit; past it, a folder the walk cannot open is unreadable, logged and left unwatched as
0.55.1 logs one ("Not watching unreadable folder"), and the walk goes on.

**Why it reads through open folders.** By path, a walk adds `p`'s watch, then lists `p`. A folder renamed away from
`p` and replaced by another in between gives the newcomer's subfolders the old folder's watch as their parent. No
event ever says otherwise, as those watches never move.
- 0.55.1 is put right by the next walk that passes there, as each walk re-points watches to where it finds them, which
  is F2's cause.
- The tree is not: the round 22 shape `c1_collision` failed 15 of 1,000 orders on a by-path variant (0.55.1 fails none).

The walk needs `/proc`, as the daemon does already (`/proc/self/mountinfo`, `/proc/<pid>/stat`,
`/proc/sys/kernel/random/boot_id`); there is no by-path fallback.

**What a walk does with each watch it gets.** Its root is the place the event at hand names.
- **A new watch:** added at the place the walk found it, under its parent's watch. A folder whose parent could not be
  watched is not watched either: no event would carry its watch along when that parent moves.
- **A watch the events already hold there:** nothing.
- **A held watch found anywhere else, below the root:** left where the events have it, with the place noted in `found`.
  Its move here is still queued: a move-in moves it, or its `MOVE_SELF` with no move-in puts it at the found place.
- **At the root, when the events already name a watch at the place** (`landed`): the place belongs to that watch. For
  a paired move-in, it is the watch that landed there. For a create or a move-in with an unknown cookie, it is the
  watch an earlier walk added there (`at()` when the walk starts). Another watch found at the root is treated as below
  the root: noted in `found`, or, new, added beside the one named, which stays named until it leaves. Treating it as
  the root named it at the place, and the next move-out from there moved the wrong folder:
  - fuzz seed 340, at a paired move-in: a folder put under itself;
  - `c2_unwatched_old`, at a create: on a variant without this rule, 6 of 150 orders failed, as the move-out of the
    first `u` moved the second `u`'s watch.
- **The root put: a held watch found at the root of a create's walk, or of a move-in with an unknown cookie, where the
  events name none:** put there at once, and its old place goes in `ahead`. The event at hand names this place for a
  folder that arrived there, and every later event of that folder comes after this one, so the watch of the folder the
  walk finds there is put there now. That is what puts right a watch an earlier event moved by mistake
  (`c2_unwatched_old`: the first `u`'s move-out, read after a walk placed the second `u`'s watch at `u`, carried that
  watch to `u2`; the second `u`'s create puts it back). The walk cannot tell that folder from one that came there
  after it, by a rename whose events are still queued (`mkdir e; mv -T big e`, `mkdir o2/x; rmdir o2/x; mv big o2/x`):
  the folder's events from before its move-out then come at the new place. So:
  - the watcher marks the `ahead` entry when it reads any event of a watch in the put watch's subtree, from the put
    until that place's move-out (a climb of the event's folder's parents per event while `ahead` holds an entry,
    nothing otherwise);
  - that move-out, when read, is recorded as a delete and a create (a copy) if the mark is set, with one WARNING line
    (section 12); otherwise it is a move, as on 0.55.1, since no event of the folder came at the new place before it;
  - the put watch and the watches below it stay out of `newDirWDs`: their events are kept, as the move may stay a
    move, and no copy then holds them;
  - when the folder's move-out from its old place was read before the put (its cookie is pending), every event of it
    from before the move was read before that, at the old place: no mark is kept (`walk()` drops it), and the move-in
    pairs as a move.

  A move-out whose own events were all read before the put is the common case: `mkdir e; mv -T big e` from one script
  is a move, not a copy.
- **A held watch whose `MOVE_SELF` came with no move-in and no found place (`adrift`):** put where this walk finds it.
  The events have nothing more to say about it.
- **At the root, the watch of a folder whose move-out from this very place is still to settle:** the folder came back
  (2.5), and its move-out leaves its watches alone.

**A put from a walk's view displaces nothing.** The `MOVE_SELF` that puts a watch at its found place, the walk that
puts an adrift one, and `leave_tree()` (2.5) all take a place from a walk, which saw the tree ahead of the events. A
watch the events name at that place keeps it until its own move-out or delete is read; the newcomer is added beside it.
Only the events' own puts (a move-in, the root put) set the one named there aside, or note it in `replaced` (2.6).

**A copied move-in's walk** (a move-out from a folder made in the batch, which records nothing, or one marked
`ahead`): the folder is recorded as a create, so its walk adds the watches it finds to `newDirWDs`, as a create's walk
does: the batch's copy of the folder holds what changes in it until the next take, and those events need not be kept.

### 2.4 `MOVE_SELF`

The kernel queues it on the moved folder's own watch after the rename's `MOVED_TO` (facts 1 to 4). So when it is read:
- If the move-in was read, the folder has landed: the `MOVE_SELF` confirms that the watch the move-out named made the
  move (`landing`). One that has not come by a later event in either folder of the move will not: that watch was not
  the mover's, and it goes back (`unland()`, 2.5).
- If no move-in was read, the folder went to a place with no watch: out of the tree, into a skipped folder, or into a
  folder not watched yet. A walk that found it since says where it is; otherwise the next walk that finds it does.
- A folder's renames are queued in order (section 1), so a `MOVE_SELF` is never read before the move-in of its own
  rename.

Every rename of a folder while it has a watch queues a `MOVE_SELF` on that watch, before any later event in either
folder of the rename (fact 16). The walk's check (2.3) gives no folder a watch at a place it left before the watch
existed, so a move-out from a place whose watch gets no `MOVE_SELF` after it was not that watch's folder's: the watch
came after the mover left, for another folder a walk found there, and the move-out's expiry leaves it alone (2.5).
Before the check (v8), a folder renamed between the walk's open of it and its watch got a watch at the place it had
left, and every event read on it until the move-out settled got the old path: a folder made in it was walked where
nothing was, and stayed unwatched (fuzz seed 4284).

### 2.5 Move-outs that never pair, and those in a folder made in the batch

- **A regular move-out** keeps 0.55's window: its delete waits for the quiet read, the pair timeout or a create at its
  path, and the moved folder's watches stay meanwhile. That is what keeps a take-back a move: in `mv X /out/X;
  mv /out/X/sub sub`, X's watch still reports `sub`'s move-out, which pairs. When it settles:
  - `own`'s subtree is removed if `own` is still at the place it left (held there, named or not), or is held nowhere.
    A take-back, a move-in or a walk that put it elsewhere is what moved it, and its watch is live there.
  - And only if this move-out is still `own`'s last move read (`moving[own]` is its cookie) and `own`'s `MOVE_SELF` was
    read after it (`moved`), the two conditions of 2.1. A later move of `own` says its folder was back in the tree, at
    whatever place: fuzz seed 14124 on v10 moved a folder into a new folder and back to the very place it left, its
    parent renamed in between (`back_home_via_new`: `mkdir big/n0; mv big/sub/deep big/n0/deep; mv big other/t;
    mv other/t/n0/deep other/t/sub/deep`, then a write in it). The walk of `n0` found `deep` there, its `MOVE_SELF` put
    it there, its move-out from `n0` and move-in back home moved it, and the first move-out, expiring, found it at the
    place it had left and removed its watch. And a watch with no `MOVE_SELF` after the move-out came after the rename,
    for another folder: fuzz seed 12812 on v10, in `walk_ahead_taken` (2.1's row). Both seeds pass on v14 to v16 (3 of 3
    alone), as do the five shapes cut from them at review 5's bounds (section 9).
  - If a walk found it elsewhere and no `MOVE_SELF` came (2.4), it is put where the walk found it. All events are read
    by then, so the walk's place is the one no event will correct. `chain_through_a_new_folder` failed 1 of 1 at one
    order of the suite's sample (deterministic) before this rule: the expiry removed a live folder's watches.
- **Every move-out settles once, at the latest at the pair timeout,** oldest first: those that record nothing too, so
  a tree that is never quiet cannot keep one, and the watch it holds, for good (the spec check's 3.2). The cookies
  are in the order they were read, so the check at each read stops at the first one younger than the timeout.
- **The watch a move-out takes (`leaving()`)** is the one at the place, oldest first, whose own move-out from that place
  has not been read. One that has a pending move-out from there left it already and is kept there only until that
  settles; a walk can have found a folder made where it left (held beside it), and that folder's move-out is the one
  read now. Before this rule the second move-out named the first watch again, and the second folder's watch stayed in
  the tree when its parent was deleted, reporting a folder outside the tree under the tree's path
  (`made_at_pending_out_parent_deleted`: `mv big/sub /out/sub; mv big b2; mkdir b2/sub; mv b2/sub /out/sub2; rm -r b2`,
  then a write in `/out/sub2`; with `made_at_pending_out_moved`, 11 of 600 orders on the variant before the rule, none
  on 0.55.1 and none after it).
  - **Nor a watch a walk's root put at the place ahead of its folder's move** (`ahead` names it). In K that folder is
    still at its old place; the kernel queues its move here after its move-out from there, and any move of it from
    here after that, so a move-out read from here first is of the folder that was here before it came: the one the
    create named. Fuzz seed 2509 (traced on v9 with every read and tree operation logged):
    `keep/n0/b` was watched (watch 5), then, from the fuzz's script, `mkdir a/t; mv a/t keep/n0/b/s; mv keep/n0/b a/t`.
    All of it was queued when the watcher read the create of `a/t`; its walk found `keep/n0/b`'s folder at `a/t`, so the
    root put moved watch 5 there and noted `keep/n0/b` in `ahead`. The next event, the move-out of `a/t` (the created
    folder leaving for `keep/n0/b/s`), took watch 5, and its move-in, on watch 5 itself, put watch 5 under itself:
    `put(5, 5, 's')`. The pass over the subtree's paths then never ended, each turn a longer path, until memory ran out
    (v7, the seed 4284 agent's D2, v8 and v9 alike, 4 of 4 and 2 of 2 alone; 0.55.1 passes). With the clause, that
    move-out takes no watch, its move-in walks `a/t/s` and finds the created folder's own watch there, and the found
    folder's move-out from `keep/n0/b`, read next, settles its `ahead` entry (a copy, as an event of it came at the new
    place first: the create and the move-in in it).
  - The same route with a change in the found folder after it, `root_put_*` (`mkdir n; mv n big/n; mv big n`, a
    same-size write in `n/a`; with `big/x` made first; the created folder sent into `big/sub` or into `other`): every
    order passes with the clause (3,949 at review 5's bounds). 0.55.1 loses the change in 268 of them, as its walk
    re-pointed `big`'s watch to `n` and the created folder's move-out then carried it away (section 6).
  - **A landing stands only once the watch's `MOVE_SELF` comes** (v16). A walk can give a folder a watch at a place
    before the move-out of the folder that was there is read (`mkdir o2/u; mv o2/u o2/u2; mkdir o2/u`, the second `u`
    watched by a walk that ran after all three): no rule can tell the two folders apart there, and `leaving()` names
    the second `u`'s watch. When the move-out pairs, `land()` moves that watch where the first `u` went, and notes the
    landing (`landing`). The kernel queues the mover's `MOVE_SELF` before any later event in either folder of the move
    (fact 16), so the first such event with no `MOVE_SELF` of the watch read, or the quiet read, says it did not move:
    `unland()` puts it back at the move-out's place, and its folder's own arrival and moves, read after, place it from
    there. Before this (v9 to v15), the watch stayed where the first `u` went, and the second `u`'s own `MOVE_SELF`,
    when it moved on, was taken as that landing's: in `c2_then_into_old` (the second `u` then moved into the first),
    the second `u` was left unwatched, where 0.55.1 is right; in `land_ahead_taken` (fuzz seed 19006 on v15: the second
    folder moved into a new folder), it was lost in 204 of 1,000 orders, 225 on 0.55.1. v16 passes both, and
    `c2_then_moved`.
- **Every subtree that leaves the tree goes through `leave_tree()`:** a settled move-out, a move-in to a skipped folder
  (paired, or in a folder made in the batch), and a cookie that records nothing settled at its `MOVE_SELF`, at its
  timeout or at the quiet read. Each watch in the subtree that a walk found back in the tree is put there, with what
  is below it, and the rest is removed. A walk sees the tree after every event of the read it runs in, so a watch it
  found at a place in the tree is there: the folder left with its parent's, or before it, and came back where no watch
  saw it come. If that watch is `own`, nothing is removed. The puts repeat until none is left, as one can take
  another's found place out of the leaving subtree.
  - Fuzz seed 647 found the case on the variant before this rule, through a skipped folder: `c` moved into a skipped
    folder, then `c`'s subfolder from there into a folder made in the batch, both before the walk of that folder ran.
    The move-in to the skipped folder removed `c`'s subtree at once, the subfolder's watch with it, and the folder
    stayed unwatched.
  - The schedule shape `out_made_sub_into_new` is the same route through an expiry: 210 of 2,730 orders failed on the
    variant before this rule, none on 0.55.1, none after it.
- **A folder back where it left, before its move-out settles.** A create or a move-in at the old *path* expires the
  move-out first (as on 0.55.1), so the subtree goes and the walk adds fresh watches. When the folder's parent was
  renamed in between, the old place has a new path, and nothing expires it: the move-in's walk gets the folder's own
  watch at its root, still held at that place. Then the folder came back, and the move-out leaves its watches alone:
  the walk takes the cookie out of `moving`, and the cookie keeps only its delete (of the old path, as 0.55.1 records
  it) or, recording nothing, goes. For this, a `MOVE_SELF` leaves the cookie of a move-out still to settle in
  `moving`, which then holds each folder's pending move-out until it settles.
  - Fuzz seeds 929 and 1911 found it on the variant before this rule (2 of 2 each; 0.55.1 passes both). Seed 1911's
    route, traced on that variant (round 3 of the seed): `keep/s` moved out of the tree (its move-out pending, its
    `MOVE_SELF` setting it adrift); `mkdir n0; mv keep n0/keep`, read with the walk of `n0` finding `keep`'s watch
    there (put there by `keep`'s `MOVE_SELF`); then the folder moved out came back as `n0/keep/s`, a move-in with an
    unknown cookie on `keep`'s watch: the same place, `keep`'s watch and `s`, under the new path. Nothing expired the
    move-out at that path, the walk got `s`'s own watch at its root, and at the quiet read the move-out removed the 12
    watches of `s`'s subtree, so every folder of the round's tree under `n0/keep/s` stayed unwatched (its markers
    missing from the version). With the rule, the walk takes the cookie's `own` out, and the watches stay.
  - The schedule shapes `sub_back_parent_renamed` (`mv big/sub /out/sub; mv big b2; mv /out/sub b2/sub`, then a
    change in `b2/sub`) and `sub_back_parent_into_new` (the same with `mkdir n; mv big n/big`) failed 542 of 816 and
    1,216 of 1,365 orders on the variant before this rule, none on 0.55.1 and none after it.
  - **Below a walk's root too** (v15). The move-in's walk can miss the folder: it opens the place by its path, which is
    stale while a higher folder's move is still queued. Another walk can then meet the folder at its place, below that
    walk's root, after the move-out was read; it came back there as well. Fuzz seed 12831 on v14 (0.55.1 fails it too,
    3 of 3): `a/s/t/b/s` moved out; `a/s` moved into a new `a/n2`; the folder came back as `a/n2/s/t/b/s`; `a` moved
    into a new `b/n2`, all before the read. The walk of `b/n2` met `s`'s own watch at its place; the move-in's walk,
    read next, looked for `a/n2/s/t/b/s` while `a`'s move was still queued and found nothing, and the move-out's expiry
    removed the watch. `back_home_under_new` (`mv big/sub/deep /out/deep; mkdir m big/n; mv big/sub big/n/sub;
    mv /out/deep big/n/sub/deep; mv big m/big`) loses the folder in 661 of 1,000 sampled orders on v14 and 179 on
    0.55.1, none on v15. The walk collects the watched folders it meets where the tree has them only while a move-out
    is pending, and checks each as it checks its root.
- **A folder's move-out read in a folder made in the batch** is discarded as on 0.55.1: the batch's copy of the new
  folder holds it, so nothing is recorded. It now gets a cookie that records nothing (`record=False`), for its watches
  only:
  - a move-in pairs with it: the watches go with the folder, and the move-in is a create, as 0.55.1 records it today;
  - its `MOVE_SELF` comes with no move-in: it left for a place with no watch, so the subtree goes at once, unless a walk
    found it since;
  - neither came (2.4's case): it settles at its timeout or at the quiet read, as any move-out.
- **The old parent deleted before the move-out settles.** `rm -r` deletes what is in a folder first (fact 8), so a
  watch still held below a folder at that folder's `DELETE_SELF` is one whose own move-out from it is still to settle.
  `forget()` of the parent sets it adrift (held nowhere), so its settling, which takes a watch held nowhere as still
  at the place it left, sends its subtree through `leave_tree()`.
  - Fuzz seed 5837 found it on the variant before this rule (3 of 4 alone; 0.55.1 passes 4 of 4). The schedule shape
    `out_parent_deleted_back` failed 7 of 1,365 orders before this rule, none on 0.55.1 and none after it.

### 2.6 One rename onto another folder: replaced or swapped

A move-in that lands on a place still held by another folder does not set that folder aside: `move()` notes it in
`replaced`. The kernel then says which case it was:
- an `ATTRIB` on that folder's own watch means it was replaced (fact 9), and it is set aside;
- its own `MOVED_FROM` next means it was the other half of a `RENAME_EXCHANGE` (fact 10), and it moves.

0.55.1 rewrites both folders' paths under one name in an exchange.

### 2.7 Overflow

At `Q_OVERFLOW` the watcher logs it, raises the queue limit (it doubles, as 0.55.1 does), queues the full comparison,
and returns from `watchFolder()` with `WATCH_RESULT_OVERFLOW`. `watcher()` then starts a new `watchFolder()` with
`root_returned`, as after a lost root:
- closing the old instance frees all of its watches in one call, with no flood of `IGNORED` events;
- the new instance takes the raised limit, which the kernel reads only when an instance is made (fact 15), so the
  raise reaches the watch it is for;
- its first walk watches the tree as it is now, the folder whose create was lost included;
- once that walk is done, it queues a full comparison again (as after a lost root), so the batch after it compares the
  whole tree with the vault now that its changes are watched; the one queued at the overflow makes the batch in
  progress a full comparison too, even if it is taken before the walk ends. The queue keeps one full comparison.

What the old watch held goes with it, and the full comparison covers each:
- the batch in progress: already a full comparison, and the queue drops every later event until the take;
- pending move-outs: not recorded as deletes; the comparison finds what is gone;
- `newDirWDs`: the new watch starts with none, so the events of folders made in the batch are kept rather than
  discarded: more events, no loss;
- `moving`, `found`, `ahead`, `adrift`, `replaced` and the cookies: a new tree, from the walk.

The pending move-out paths and the read time the old watch published to the queue stay until the new one publishes
its own; a full comparison uses neither. Each restart starts the max-delay clock again, as a lost root's does (the
default max delay is 86,400 s, and the limit doubles at each overflow, so restarts end after a few).

`raise_queue_limit_for_removals()` goes, with its sysctl write: it raised the limit before a removal of many watches
(their `IGNORED` events), but that raise reaches only instances made later (fact 15), so it never helped the watch
that removes them. A removal of more watches than the queue holds now overflows that watch, which restarts with the
raised limit; at this host's limit (8,388,608) no removal comes near it.

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
  `o2/x` read after the first rename): the walk of that create finds `big`'s watch at its root, which is put at once,
  with `big`'s place in `ahead`. The change to `big/a` was made before `mkdir o2/x`, so its event is read before the
  create, at `big/a`: no event of `big` is read between the put and `big`'s move-out, which stays a move. Had the
  change come between the create and the rename, its event would be read after the put, at `o2/x/a`, and the move-out
  is a delete and a create: the copy holds the new bytes.
- **The same root rule fixes a rename over an empty folder made in the batch** (`over_empty`, section 6).

**What it records against 0.55.1:**
- Events are recorded at the place the events give them, not where a walk saw their folder later. In the orders where
  0.55.1 kept old bytes, the variant records the change at its own path.
- At a create's walk root, a move-out is a delete and a create only when an event of the folder came at the new place
  first (section 12).
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
- **No `MOVE_SELF` at all** (its watch came after the rename, 2.4): the settling of its move-out, at its timeout or at
  the quiet read, puts it where a walk found it, or removes it.
- **A take between:** the cookie records nothing, so takes do not change it.
- **A create or move-in at the old path before the expiry:** it expires the move-out before its own walk runs, so the
  subtree goes, and the walk watches what is there now. That is right for a new folder and for the one that left, back
  again; for the latter it costs a remove and an add per folder (section 8).
- **A move-in at the old place under a new path** (the old parent renamed in between): its walk gets the folder's own
  watch at its root, so the folder came back, and the move-out keeps its watches (2.5).
- **A second folder made at the old place under a new path, and moved out too** (`made_at_pending_out_*`): its
  move-out takes its own watch (`leaving()`, 2.5), and each settles on its own.
- **The old parent renamed or moved out itself before the expiry:** the place is by watch, so the expiry finds it.
- **The old parent deleted before the expiry:** the folder that moved out of it gets no `DELETE_SELF` (it is not in it
  any more), and the place goes with the parent. The parent's `forget()` sets each watch still held below it adrift,
  so the expiry still finds it and it leaves the tree (2.5).
- **Watch numbers given again:** fact 11, they are not given again soon, so a removed watch's queued events cannot
  meet a new folder's watch of the same number. Those events are dropped as "Watch descriptor not found", as on 0.55.1.

**What it records against 0.55.1:**
- Changes made outside the tree in a folder that left it are no longer recorded inside it.
- No test of the suite changes what it records. Review 5's F1 probe goes from wrong 3 of 6 to right 6 of 6 (both tail
  cases).

## 5. Issue 3: an event queue overflow can leave a new folder unwatched

**Mechanism:** 2.7. The new watch's first walk watches every folder there is, and the full comparison after it covers
every change the lost events would have recorded.

**Across the orders:**
- **Events of the same read before the overflow** are handled first, as today; those after it in the read go with the
  old watch, and the full comparison covers them.
- **Events queued after the overflow** stay in the old instance, which closes: the new watch's walk and the full
  comparison cover them.
- **A take between:** the full comparison is the batch, and the second one, queued after the walk, the next.
- **A second overflow:** the same again, with the limit doubled once more.

**What it records against 0.55.1:**
- After an overflow, later writes in a folder whose create was lost reach a version; on 0.55.1 they raise no event
  until a restart.
- A folder renamed with its events lost has its later changes recorded at its new path, where 0.55.1 kept wrong bytes
  in the probe: `lost_rename` left `b2/a` wrong, with stale watches.
- Watches of folders that left the tree go with the old instance.
- The overflow probe: 9 of 9 fail on 0.55.1 (each with a stale watch, or a folder with none: `n` and `n/s` in
  `lost_create`), 9 of 9 pass on the variant, with the watch map checked both ways.

**Cost:** one walk of the tree per overflow, about the first walk's (section 8), and a second full comparison, which
for the batch after the overflow reads what the first one wrote. 0.55.1 spends no walk, and leaves what the lost
events would have watched unwatched.

## 6. Five older routes the same design fixes

All five are on 0.55.1, the first two on 0.55 too (the last three were not run there). None has an entry in
docs/limitations.md.

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
  - The variant's root put (2.3) keeps the watch's events, and records the move as a move unless an event of `big`
    came at `e` before it.
- **A folder made, sent elsewhere, and replaced at its name by a folder renamed there, then a change in that folder**
  (`root_put_wrong_mover`: `mkdir n; mv n other/n; mv big n`, then a same-size change in `n/a`; `root_put_into_itself*`
  and `root_put_into_sub` send `n` into `big` or `big/sub` instead):
  - On 0.55.1, the walk of `n`'s create finds `big` at `n` and re-points `big`'s watch there; the move-out of `n` that
    comes next then rewrites every path at `n`, `big`'s with them, to where `n` went. `big`'s later events are recorded
    under that path (reasoned from 0.55.1's code; its batch at visits 0, 0, 0, 0 holds `create n`, `move n → other/n`,
    `move big → n` and no change at `n/a`), and the change in `n/a` is lost: 268 of the five shapes' 3,949 orders at
    review 5's bounds, and 94 of 446 at the mergerfs check's bounds on the scratch pool.
  - The variant passes every one: the root put notes `big`'s old place in `ahead`, and `n`'s move-out takes no watch it
    put there (`leaving()`, 2.5). Fuzz seed 2509 found the route on the variant (v7 to v9), where it put a watch under
    itself.
- **A folder that left its place and came back to it before its move-out settled, its parent renamed in between**
  (`back_home_via_new`: `mkdir big/n0; mv big/sub/deep big/n0/deep; mv big other/t; mv other/t/n0/deep other/t/sub/deep`,
  then a write in it; `back_home_via_new_sub` moves `big/sub`; `back_home_via_outside` goes out of the tree and back
  through `next`):
  - On 0.55.1 the folder is left unwatched in 870 of the first two shapes' 1,365 orders each, and in 1,238 of the
    third's 1,365: the marker written in it after the batches is missing from the version (0.55.1's route was not
    traced; on v10 it was the first move-out's expiry removing the folder's watch).
  - v10 failed the first two in 505 orders each and passed the third; v14 to v16 pass all three, as the first move-out is no
    longer the folder's last move read when it settles (2.5). Fuzz seed 14124 found it on v10.
  - The same return where only another new folder's walk meets the folder (`back_home_under_new`, fuzz seed 12831):
    0.55.1 loses it in 179 of 1,000 sampled orders, v14 in 661, v15 and v16 in none (2.5).
- **A folder made where another had just left, then moved into a folder made in the batch** (`land_ahead_taken`:
  `mkdir big/n; mv big/n other/n; mkdir big/n; mkdir m; mv big/n m/n`, then a write in `m/n`):
  - On 0.55.1 the second `n` is left unwatched in 225 of 1,000 sampled orders (its marker missing; 0.55.1's route was
    not traced).
  - v15 lost it in 204; v16 passes every one, as the first `n`'s move-in no longer carries the second `n`'s watch
    away (2.5). Fuzz seed 19006 found it on v15.

## 7. What is recorded differently from 0.55.1, and what changes in the tests

**In the suite, no test changes what it asserts**, but one that tested a removed part. The walk's new way of reaching
folders changes how some tests inject their races, and those tests change with it:
- **`tests/harness.py`:**
  - `scripted_watch()`'s stand-in for `initializeFolderWatchers()` takes the tree, the parent and the name, and puts its
    watch in the tree;
  - `fs_path()` turns what a watcher's call names into the folder's path: a path, an open folder's fd
    (`os.scandir(fd)`), or `/proc/self/fd/<fd>` (`add_watch` of an open folder);
  - `watch_map_errors()`: the watch map checked both ways (section 9).
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
- **`tests/test_moves_into_new_folders.py`'s `Session`** runs `watchFolder()` as `watcher()` does, starting a new watch
  after an overflow, and its steps gain `exchange` (`renameat2()` with `RENAME_EXCHANGE`).
- **`tests/test_jobs.py`** loses `test_removing_many_watches_raises_the_queue_limit_first`, with the part it tested.
- **`tests/test_inotify.py`** gains a tree 1,200 levels deep, watched to its bottom, and a walk past the limit of open
  files, which leaves the rest unreadable and goes on.
- **`tests/test_watcher_schedules.py`** gains the shapes of section 9, the second `next2/sub` and `g.txt` in its tree
  (for `exchange_twice`), the watch-map check at the end of every shape, and two pinned orders that must reach
  `put()`'s cycle guard.

**Over the schedule shapes:** the comparison (`probes/compare.py`) runs every shape on both codes and counts what each
records. At 8 visits, with 150 orders sampled for 5 to 7 steps, 9,210 orders of 74 shapes: 0.55.1 is wrong in 201.
No variant of revision 1 ran it in full: v16's gates were stopped before it (section 9), and v8's run was cut short at
112 schedules. Section 12 has the root put's counts, from v8's runs of those shapes.

**The changes, all toward the tree as it is:**
1. A walk no longer puts a watch ahead of its folder's events (F2).
2. At a create's walk root, a held watch taken from another place makes that place's move-out a copy only when an
   event of the folder came at the new place first (section 12), with one WARNING line; otherwise a move, as 0.55.1
   records it.
3. No phantom events from a watch whose folder left the tree (F3).
4. After an overflow, the watch starts again: the tree is watched as it is, and compared in full a second time once
   its watches are in place.
5. An exchange's two folders keep their own paths.
6. **Fewer creates in `twice_in_new_newfile`** (the spec check's 2.4): a write made in `big/sub` before `big` moved
   into a folder made in the batch is discarded with the moved folder's events, which the new folder's copy holds.
   0.55.1 recorded it, then `big`'s delete. Both versions are the tree.
7. **The walk follows no link that replaced a folder while it ran** (2.5): it opens each folder with `O_NOFOLLOW` and
   takes `ELOOP` as gone. 0.55.1 lists with `is_dir(follow_symlinks=False)`, then calls `scandir(entry.path)` and
   `add_watch(path)`, which both follow a link put there in between, so it could watch and list a folder outside the
   tree.
8. **No ERROR lines for a folder gone while it is walked** (2.6): 0.55.1 logs "Error scanning <path>" at error level,
   and can add "Not watching unreadable folder"; the new walk logs nothing for `ENOENT`, `ENOTDIR` and `ELOOP`, nor for
   `EBADF` (mergerfs's answer for a folder removed after the walk opened it, 2.3), as the folder's own events say what
   became of it.
9. **"Event name not found, ignoring event" is a DEBUG line:** the watcher reads a nameless `ATTRIB` on a folder's own
   watch now (2.6), and 0.55.1 logged that line at INFO once per folder of a `chmod -R`.
10. **A tree deeper than about 1,000 levels is watched to its bottom;** 0.55.1 left the deepest levels unwatched (994
    of 1,101 folders at 1,100 levels, each logged), and the variant before revision 1 stopped the job.
11. **No sysctl write before a large removal of watches** (`raise_queue_limit_for_removals()`, 2.7).

## 8. What it costs (measured)

Through the real `watchFolder()` on real inotify, tmpfs, 0.55.1 against the variant, three runs each, alternating; the
watcher's CPU only. Other jobs ran on the machine meanwhile (a load of about 215 on 32 cores), so CPU numbers carry
about ±10%. The tree: project folders of 50 module folders, each with one `src` folder (1,010 projects for 102,061
folders, 200 for 20,251), plus the workload's own folders.

| Workload (`probes/bench_watcher.py`) | 0.55.1 | v8 |
|---|---|---|
| Memory after the first walk, 102,061 folders (tracemalloc) | 17.97 MiB | 27.08 MiB (+94 B a watch) |
| The first walk, 102,061 folders | 0.52-0.54 s | 0.67-0.69 s |
| 20,000 file writes in 50 folders (about 26,000 events) | 0.107-0.116 s | 0.104-0.119 s |
| 200 folders of 101 folders renamed and back (400 renames), 20,251 folders | 1.24-1.36 s | 0.157-0.165 s |
| 300 folders of 10 subfolders moved out and back in, 20,251 folders | 0.50-0.53 s (3,202 events) | 0.088-0.096 s (6,800-6,802 events) |
| 2,000 renames in one folder of 10,000 subfolders | 8.48-8.92 s | 0.057-0.064 s |
| `rm -r` of one folder of 10,000 subfolders | 0.077-0.084 s | 0.084-0.097 s |
| One `IN_Q_OVERFLOW` read, 102,061 folders (injected, no sysctl written) | 0.000 s | 0.71-0.72 s (the new watch's walk) |
| One folder of 5,000 subfolders renamed away and back 200 times (400 paired moves, each walked), 20,251 folders | 7.01-7.05 s | 7.30-7.51 s |

The variant's extra events in the move-out row are the `IGNORED` of the watches a folder back at its own path gets
fresh (see the notes). The first walk costs 1.3 to 1.6 µs a folder more at this load; `probes/walk_fd_cost.py`, on an
idle machine, gives 0.5 to 0.6 µs (below).

**v9** adds to v8's walk the check of each new watch (two stats) and, at each walk's root, one open, `add_watch` and
close of the parent's folder (2.3). It holds no new state, so the memory row stands. The same bench, the three codes
alternating, at a load of about 300 (`out/bench_v9_init.txt`):

| Workload | 0.55.1 | v8 | v9 |
|---|---|---|---|
| The first walk, 102,061 folders | 0.52-0.53 s | 0.67-0.71 s | 0.81-0.82 s |
| 200 folders of 101 folders renamed and back, 20,251 folders | 1.13-1.20 s | 0.142-0.157 s | 0.159-0.163 s |
| 10,100 folders made one by one (100 of 100), 20,251 folders | 0.051-0.057 s | 0.074-0.077 s | 0.090-0.094 s |

**v10** walks as v9 does: `leaving()`'s new clause costs a look at `ahead` when it holds an entry, and the `try`
around the check's `fstat` nothing. **v14** walks as v10 does: its two expiry conditions cost one
dictionary look and one tuple copy at a folder's `MOVE_SELF` while its move-out is pending, and a comparison at each
expiry. **v15** adds to a walk, only while a move-out is pending, one list and, for each watched
folder it meets where the tree has it, one append and one dictionary look; nothing while none is pending, which is
the daemon's state almost always. **v16**, the final variant, adds one look at a small dictionary for each event
read while a folder's move-in waits for its `MOVE_SELF`, which the kernel queues right behind it. None of the three
was measured again. Two runs in containers (uid 65534, as every test since the host's
rule of 2026-11-08 23:04), the codes alternating, at a load of about 260 to 300. v11 (a check by `add_watch` of the
name, not taken, section 1) ran in the first, and v12 (v10 with one more branch in `walk()`, not taken either) in the
second (`out/bench_v11.txt`, `out/bench_v12.txt`):

| Workload | 0.55.1 | v9 | v11 | v12 (v10's walk) |
|---|---|---|---|---|
| The first walk, 102,061 folders | 0.72-0.74 s; 0.66-0.70 s | 1.28-1.42 s; 1.10-1.23 s | 1.13-1.15 s | 1.12-1.26 s |
| 10,100 folders made one by one (100 of 100), 20,251 folders | 0.067-0.071 s; 0.075-0.078 s | 0.126-0.139 s; 0.136-0.140 s | 0.114-0.117 s | 0.130-0.134 s |

**The walk alone,** by `probes/walk_fd_cost.py` on an idle machine, 101,000 folders, 3 runs (revision 0):

| Walk | µs a folder |
|---|---|
| By path, as 0.55.1 (`add_watch(path)`, `scandir(path)`) | 2.33-2.46 |
| Through open folders (this design) | 2.91-2.99 |
| Through open folders, checked to be still at its name after the watch | 3.74-3.78 |

The last is what v9 does (2.3): revision 0 dropped it, as 2.5 settled 2.4's no-`MOVE_SELF` case at the expiry for
nothing per folder; fuzz seed 4284 showed the expiry comes too late for the events read in between.

**At the live daemon's size.** The main session counted the live daemon's watches: about 17,200 (15,020, 2,180 and a
few), with a resident size of 22 MB.
- Memory: 94 B a watch more, about 1.6 MB in all (7% of its 22 MB), for as long as the daemon runs.
- The first walk, at each start (and at each overflow or lost root): on v9, about 24 ms more on an idle machine (1.3
  to 1.4 µs a folder, `probes/walk_fd_cost.py`), about 49 ms at the load the bench ran under (2.8 µs a folder). In
  the container runs, at a load of 260 to 300, v10's walk (v12's row) costs 4.5 to 5.4 µs a folder more than 0.55.1,
  about 85 ms at 17,200 watches; no idle machine was there to measure v10 on, and its walk is v9's.
- A `mkdir -p` or a `tar x`: 10,100 folders made one by one in the watched tree (100 folders of 100, the bench's
  `mkdirs`, at a load of about 300) cost the watcher 0.051-0.057 s on 0.55.1, 0.074-0.077 s on v8 and 0.090-0.094 s
  on v9 (`out/bench_v9_mkdirs.txt`): about 3.7 µs more a folder made than 0.55.1, 37 ms for such a `tar x`. In the
  container runs, v10's walk costs about 5.5 µs more a folder made than 0.55.1, 56 ms for such a `tar x` at that load.
- What it saves: the passes over every watch at each folder move, 0.13 µs a watch a rename in the wide-folder run
  (30,252 watches); at 17,200 watches about 2 ms a folder rename, twice (0.55.1's two passes).

**Notes:**
- **Memory** is most of the cost: `up` and `kids` beside the path cache. A layout of an int or a list for the children
  costs 11 to 19 B a watch less (`probes/mem_layouts.py`), but makes renames and deletes in a wide folder O(its size) in
  Python: 2,000 renames in a 10,000-wide folder took 10.7-13.6 s and the `rm -r` 0.55 s. The design takes the
  path-keyed dict.
- **The CPU saving** is the pass over every watch that 0.55.1 makes twice per folder move. It grows with the tree:
  0.55.1 paid 0.12 to 0.13 µs per watch per rename in the wide-folder run, so about 0.13 s per folder rename at
  1,000,000 watched folders (extrapolated, not run).
- **A file event** costs the same: one dict lookup of the path cache. While `ahead` holds an entry (a race at a
  create's walk root, until the next quiet read), each event also climbs its folder's chain of parents once.
- **A folder that left the tree and came back to its own path before the expiry** gets fresh watches: one `rm_watch`
  and one `add_watch` per folder, plus their `IGNORED` events. 0.55.1 makes one `add_watch` probe per folder. One back
  at its place under a renamed parent keeps its watches (2.5).
- **An overflow** costs a walk of the tree, about the first walk's, and a second full comparison.
- **An ordinary batch** pays nothing more. Moves are still moves, except at a create's walk root when the folder
  changed in between (section 12).

**One folder renamed back and forth thousands of times in one batch** (the entry of that name, which quotes the
watcher's walk): it still holds. The last row of the table is
that entry's case: each paired move walks the moved folder, which is almost all of its cost, 18.3 to 18.8 ms a move on
the variant and 17.5 to 17.6 ms on 0.55.1 (a round trip 36.5 to 37.6 ms, and 35.1 to 35.3). For 12,500 round trips that
is 456 to 469 s of watcher time on the variant and 438 to 441 s on 0.55.1, where the entry says about 460 s: the walk's
extra cost a folder about cancels the passes over every watch that go. The batch's collapse (49 s) is not the
watcher's, and this round does not change it.

## 9. Tests and gates

Counts on 0.55.1 and on the variant (v16, the reverberator.py of this design, outside the branch). Schedule runs use the
round 21 harness: each step at a chosen hook visit of the watcher's own thread, and every vector of non-decreasing
visits up to the bound, or a seeded sample. Review 5's bounds: 3 and 4 steps every vector to 16 visits, 5 steps to 12,
6 and 7 steps 1,000 sampled.

**The watch-map check, both ways.** At the end of every shape, in the probes and in the suite (`watch_map_errors()` in
`tests/harness.py`, and `probes/watchmap.py`, the same code for 0.55.1):
- every watch held is the one `add_watch` of its path gives (a watch whose folder is gone or elsewhere is stale);
- every folder of the tree that the job watches (not skipped, on the root's filesystem, so not under an inner mount)
  has a watch.

A watch the check adds is removed again. It runs only once the version equals the tree, which the shape checks first.

**The gates did not finish on v16.** Each variant's gates ran in containers as uid 65534 (the mergerfs pool mounted
on the host as setup). The fuzz on v10, v14 and v15 found a failing seed each, so each of those runs was stopped for
the next variant. Then, at 05:13 on 2026-11-09, the agent harness stopped v16's run because the host was critically
low on memory, most of it held by other work on the host; the run's containers were capped at 16 GB each. The harness
says not to start the run again unless the main session asks. So the v16
column below is what ran before the stop. The v14 and v15 columns are those variants' runs before each was replaced;
v15 differs from v16 only in the landing (2.5), and v14 differs from v15 only in the walk's check at every folder.
The suite's phase (the suite, the take points, the seed 4284 shapes, the comparison logs, F1 and the overflow probes)
did not run on any variant after v9.

| Gate | 0.55.1 | v16 (final), before the stop | v15 / v14, before each was replaced |
|---|---|---|---|
| The suite, in containers as uid 65534 | 287 failed, 3,321 passed, 320 skipped, 1 error | not run (v9's run: 278 failed, every one also failing on 0.55.1, root-only or XFS, 6,536 passed) | not run |
| Every schedule shape at review 5's bounds, the watch map checked both ways (99 shapes, 91,049 orders: revision 0's 68, revision 1's 16, the five `root_put_*`, and the ten cut from fuzz seeds 14124, 12812, 12831 and 19006 with `c2_then_*`) | 5,439 wrong: `back_home_via_outside` 1,238, `back_home_via_new` 870, `back_home_via_new_sub` 870, `exchange_twice` 816, `over_empty` 273, `root_put_*` 268, `found_out` 259 (a stale watch), `land_ahead_taken` 225, `back_home_under_new` 179, `root_ahead` 147, `exchange` 136, `twice_old_race` 120, `twice_old_race_sub` 30, `back_then_sub_out` 8 (a stale watch) | 9,023 orders run (9%), none wrong; run alone before the gates: `c2_then_moved` and `c2_then_into_old` 2,000 orders, `land_ahead_taken` 1,000, none wrong | v15: 48,200 orders of 96 shapes (54%), none wrong; v14: 54,508 of 95 (62%), none wrong. v10 ran 44,096 orders (54%) of 89 shapes with no failure |
| `tests/test_watcher_schedules.py` at every order (56 shapes) | its 10 shapes: 40,801 passed (round 21's record) | 8,552 orders run (5%), none failed | v15: 46,505 of 53 shapes' (32%), none failed; v14: 52,895 of 52 (38%), none failed |
| The walk's shapes on a scratch mergerfs pool (8 visits, 50 sampled for 5 to 7 steps) | 89 shapes: 164 wrong (`root_put_*` 94, `over_empty` 45, `twice_old_race` 15, `root_ahead` 7, `found_out` 3) | 5,282 orders run (72%), 2 wrong: a folder's mtime off by 3 ms, contents right (mergerfs's attribute cache, as on every code; section 1) | v15: 96 shapes, 7,054 orders, 1 such mtime flake, which passed 4 of 4 again; v14: 95 shapes, 7,004 of 7,004; v10: 89 shapes, 6,634 of 6,634 |
| The fuzz, lists checked, seeds 0 to 29,999 (15 containers of 2,000 seeds, 3 workers each) | seeds 0 to 5,999: 6,000 passed, 11 teardown errors, all the deferred "A size record too low after a rename falls back to a copy" | 2,616 seeds run (the first 390 or so of each 2,000), no failure, 1 teardown error (seed 372, which errors on 0.55.1 too) | v15: 11,779 seeds, one failure, 19006 (fixed in v16), 7 teardown errors; v14: 12,954 seeds, failures 12831 (fixed in v15) and 12862 (a thread the harness's 12 GB address-space cap would not start; 1 of 3 alone on v14, 0 of 3 on v15 and 0.55.1), 14 teardown errors. The teardown errors whose seeds 0.55.1 also errors on (254, 372, 4444, 4492) are the size-record class; 14224, run alone, is too; 24028 and 26251 passed alone |
| Fuzz seeds alone, 3 tries each in containers | 2509 2 of 2 pass; 12812 and 19006 3 of 3 pass; 12831 3 of 3 fail; 16462 3 of 3 fail | 2509, 12812, 12831, 14124 and 19006: 15 of 15 pass | v8, v9: 2509 runs out of memory; v10: 12812 fails 3 of 3, 14124 1 of 2; v14: 12831 2 of 3; v15: 19006 3 of 3 |
| The root put's shapes with the batches logged; the records over 74 shapes; the seed 4284 agent's shapes; review 5's F1; overflows in process; the take points | as before (section 12; F1 3 of 6; overflows 9 of 9 fail; takes 4,320 passed) | not run | not run |
| The real daemon; the suite's mergerfs and power-loss tests; the root-only suite tests | as section 12 | pending the user's decision on where root tests run | (the real daemon ran on v9, as root, before the host's rule of 23:04) |

**Notes on the runs.**
- On XFS (the host's filesystem for test runs since 2026-11-08), 17 suite tests fail on every code, 0.55.1 too: links
  of 1,024 bytes and more (`ENAMETOOLONG`, section 10's task 4), the size estimate counting XFS's speculative
  preallocation (task 3), and `st_blocks` of 0 for small links. Fuzz seed 254's teardown error comes 6 of 6 there,
  and the fuzz's timing changed. Nothing else ran differently on XFS than on ext4.
- In containers the suite also fails or skips the tests that need root (loop images, mounts, `trusted.*` xattrs):
  0.55.1's 287 failures are those and the 17. v9's 278 are all among 0.55.1's; no suite run failed anything else.
- The fuzz's teardown errors are the version-view check of the deferred "A size record too low after a rename falls
  back to a copy" (docs/limitations.md), which `tests/test_watcher_fuzz.py` still leaves to that entry's round.
- The mergerfs folder-mtime flake (a folder's mtime off by a few ms, its contents right) came on every code
  (section 1) and passed each time it was run again.

**What the build adds to the suite** (all in v16 already):
1. The schedule shapes to `tests/test_watcher_schedules.py`, sampled as its others are (100 orders each, review 5's
   bound of 12 visits for 5 steps or more):
   - section 9 of revision 0: `twice_old_race`, `root_ahead`, `twice_old_race_sub`, `c1_collision`,
     `c2_unwatched_old`, `out_back_sub`, `exchange`, `over_empty`, `exchange_twice`, `out_made_sub_into_new` (there
     already), `sub_back_parent_renamed`, `sub_back_parent_into_new`, `out_parent_deleted_back`;
   - the five F3 shapes whose watch map 0.55.1 gets wrong: `found_out`, `back_then_sub_out`, `sub_of_found_out`,
     `q3_deep_out`, `q3_sub_out`;
   - the three that "may join": `out_made_deep_into_new`, `out_sub_into_new`, `out_deep_into_new`;
   - `new_into_new_then_sub` and `new_into_new_then_sub2`: revision 0 ran them in probes only (2,000 orders on each
     code, all right), not in its gates; they pass on both codes in the gates above;
   - `made_at_pending_out_parent_deleted` and `made_at_pending_out_moved` (2.5);
   - `cycle_guard`, and `cycle_guard_root` with two of its orders pinned: they run whatever the sample, and must reach
     `put()`'s cycle guard (v8's pinned orders of `cycle_guard` no longer reach it on v9 or v10);
   - `over_empty_poke_between` and `gone_place_poke_between` (section 12): they hold the root put's copy to its
     reason, as v8 without the copy fails 3 and 4 of their orders, and 0.55.1 6 and 5;
   - `open_renamed_into_new`, `open_renamed_child_into_new` and `stale_root_path` (the seed 4284 agent's shapes, 2.3):
     the file's 100 sampled orders of each fail 5 times on v8, and 0 on v9;
   - the five `root_put_*` shapes (2.5, section 6): seed 2509's route, which 0.55.1 gets wrong in 268 of 3,949 orders
     and v9 puts a watch under itself in 422;
   - `back_home_via_new`, `back_home_via_new_sub` and `back_home_via_outside` (seed 14124's route, section 6), and
     `walk_ahead_taken` and `walk_ahead_taken_sub` (seed 12812's, 2.1): 0.55.1 is wrong in 2,978 of the first three's
     4,095 orders, v10 in 1,010 of them and in 1,528 of the last two's 2,000 sampled, v14 in none;
   - `back_home_under_new` (seed 12831's route, 2.5): 0.55.1 is wrong in 179 of 1,000 sampled orders, v14 in 661, v15
     in none;
   - `c2_then_moved`, `c2_then_into_old` and `land_ahead_taken` (the landing, 2.5): 0.55.1 is wrong in 225 of the
     last one's 1,000 sampled orders and in none of the first two's, v15 in 204 of the last one's, v16 in none.

   Every shape of the file gets the watch-map check, both ways, at its end.
2. The overflow cases, in process, with the watch-map check both ways (`probes/test_overflow.py`).
3. Review 5's F1 order as an in-process test, and its control.
4. The `WatchTree` and `subfolders_of()` doctests.
5. The deep tree and the walk past the open files limit (`tests/test_inotify.py`).

**The gates before release.** No test runs as root on the host (the host's rule of 2026-11-08 23:04): the gates
that need root, mounts, loop images, `trusted.*` xattrs or `f2fs_io shutdown` (the scratch-image tests, the real
daemon, the mergerfs and power-loss tests) run where the user decides, which the main session asks; the others run
in containers as uid 65534.
- the suite (in a container it skips or fails the tests that need root; those run with the gates above);
- the schedule file at every order;
- the take points;
- the fuzz, seeds 0 to 29,999, lists checked, in containers with each process's address space capped at 12 GB (the
  seed 4284 agent's `FZ_VMEM`; a normal worker's is 4.8 to 7 GB), so a runaway fails its own seed with a `MemoryError`,
  not the run;
- the real daemon on a plain f2fs scratch image (`tests/scratch_images.py`), for the rows above;
- the suite's mergerfs and power-loss tests (`REVERB_SCRATCH` set, as root, with `mergerfs` and `mkfs.f2fs`), on
  scratch images and scratch mergerfs mounts only, never a live mount: the user brought both back for this round
  ("Bring both back (Recommended)", 2026-11-08);
- the walk's rename shapes on a scratch mergerfs over `/dev/shm` branches (`probes/test_sched_mfs.py`: the 96 shapes
  with the watched folder and the outside folder on the pool, the vault off it, the live pools' mergerfs options; the
  branches bind mounts, as the daemon wants each disk of a pool mounted). It is the one place the walk through
  `/proc/self/fd/<fd>` had no rename run, and two live jobs watch mergerfs trees. Its counts are in the table above:
  the pool and its bind mounts were mounted on the host as setup, and the tests ran in containers as uid 65534 (the
  0.55.1 and v8 runs of 74 shapes, before the host's rule, ran as root in capped scopes).

## 10. The build's tasks, in order

The builder ports v16's diff (reverberator.py and the tests), then applies what this spec says beyond it:
1. The version: `__version__ = "0.55.2"` (v16 still says 0.55.1).
2. **A restore syncs before it ends** (the main session's call): at the end of each restore, one `syncfs` of the
   target's filesystem (`syncfs_folder()`), before a folder target's restore marker is removed in
   `hand_over_folders()`, and for a file target before the command returns. A restore puts new files in place and
   syncs nothing, so a hard reset within the writeback window can leave restored files empty with no marker to say the
   restore did not finish; this is older than this round, and ext4 and XFS have the same window. On a mergerfs target,
   whose own sync does not reach the disks, it is each branch holding the target, as `sync_vault_filesystems()` does
   for a vault. A `syncfs` error is a failure of the restore: the marker stays, as for any failure. A test records
   the calls and checks that the sync comes before the marker's unlink (and, for a file target, before the command
   returns). It needs nothing from v16.
3. **The size estimate counts what the vault grows by, on XFS too** (the main session's ruling, "Fix now", in this
   round's build). Both of its routes count blocks: the walk (`get_unskipped_size_inodes()`, `lstat().st_blocks`) and
   `get_path_size()` (`du --block-size=1`). XFS's speculative preallocation can show a file just appended to at about
   2.6 times its size in blocks for minutes, so under a Backup Size Limit the prune before a batch would remove versions
   the limit did not need gone. Two live jobs on XFS (work, docker_volumes) have limits, far from them today. What the
   build must keep:
   - the estimate is at or above what the vault grows by, for sparse files and small files too;
   - the inode count is exact;
   - it costs no more than today (no read of file contents, no call a file beyond today's).
   The fixer's proposal is one way: a regular file charged the smaller of its blocks and its size rounded up to the
   block on the walk route, and `du --apparent-size` or the walk in place of `du` on the other. The red tests, on XFS,
   some red only some of the time (the preallocation comes and goes with timing):
   `tests/test_estimate_through_a_take.py::test_file_rows_through_a_take[folder carried, file moved over-du]` and its
   `-walk` twin;
   `tests/test_moves_into_new_folders.py::test_the_size_estimate_counts_what_is_written_under_a_folder_moved_into_a_new_one[one file rewritten-walk]`
   (a reviewer's run: 13,574,144 against a bound of 5,255,168);
   `tests/test_moves_then_changes.py::test_the_estimate_puts_back_what_is_written_under_a_folder_it_took_out[du]`
   (499,712 against 495,616). Acceptance is every estimate test of the suite holding on XFS every time, not only these:
   the build runs them repeatedly on XFS (say 20 runs each, in containers) and on ext4, with no failure. It needs
   nothing from v16.
4. **A link the vault's filesystem refuses does not stop the job** (the main session's ruling, "Fix now", in this
   round's build). Today a source link whose text the vault's filesystem refuses (XFS: 1,024 bytes and up,
   `ENAMETOOLONG`) fails every batch: the copy's failure is counted as the vault's, the batch raises a job failure, and
   the job retries with waits doubling to 3,600 s, so no version commits while the link exists (the main session's
   probe of the real 0.55.1 daemon in a container; the job recovers once the link goes). What the build must keep:
   - **Backup:** a source link whose copy into the version is refused with `ENAMETOOLONG` is left out of the version,
     with one warning that names it and says why ("its text or its path is longer than the vault's filesystem
     takes"), and the batch goes on. The warning comes whenever a batch meets it, as for an unreadable file. If an
     earlier version held that name, the new version does not show the old link: the entry is absent from the new
     version, as the vault cannot hold what the tree holds.
   - **Restore:** the same refusal while a restore copies is a warning in its report, as for metadata it cannot keep,
     and the restore finishes and exits 0 (today it reports `FAILED <rel>`, exits 1, and leaves the target at mode
     0700 until a rerun with `--accept`).
   - Tests for both, with a stale entry in the previous version among them.
   Leaving the link out is a known limitation pending the user's OK, which the main session asks; no limitations entry
   is written until then, and a way to keep such a link would be its own change. The live vaults are f2fs, which takes
   link texts up to 4,095 bytes, so no live backup meets it today. It needs nothing from v16.
5. The docs, written by the main session:
   - docs/limitations.md:
     - the three deferred entries go;
     - "A folder or file moved into a new folder is copied whole" loses the clause that names them as the condition
       to revisit;
     - "A move that another change of the batch outran is copied" gains the root put's copy (section 12), with its
       warning line;
     - "One folder renamed back and forth thousands of times in one batch" gets the numbers of section 8.
   - README: the watcher's paragraph (line 24) gains one sentence on what the watcher does at an overflow, and one on
     the root put's copy.
   - docs/lessons.md: nothing; no API changes.
6. **A test of a folder gone under the walk on mergerfs** (not in v16): a fake that makes the walk's listing and its
   check of a new watch fail with `EBADF`, as mergerfs does for a folder removed after its open; the walk logs
   nothing, leaves `unwatched` empty and goes on, and the watcher keeps running. The suite has no mergerfs, so only the
   scratch-pool gate ran it for real.
7. The gates of section 9, on the branch.

What v16 holds, in the order a builder reading it meets it:
1. `WatchTree`, with its doctest, beside `initializeFolderWatchers()`.
2. The walk through open folders (`subfolders_of()`, `folder_still_at()`, `WALK_OPEN_FLAGS`, `PROC_FD`, `WALK_GONE`), iterative,
   with the root opened from its parent's folder, and its rules (2.3): `tree`, `parent`, `name` and `landed`. `follow_inner_mounts()` and `remove_newly_skipped_watches()` take the tree;
   the latter looks at the moved folder's subtree only.
3. The event handling (2.2):
   - `COOKIE_VALUE` (`cookie`, `wd`, `name`, `path`, `isDir`, `own`, `record`, `ahead`, `at`, `moved`), `LANDED` and
     `moving`;
   - `add_move_out()` (the cookie and its eviction), `land()` with `landing` and `unland()` (the check at each event while
     a landing waits, and at the quiet read), `leaving()` (with its `ahead` clause), and
     `forget_moved_away()` by place, with the expiry's two conditions (the move-out still `own`'s last one read, and
     `moved`, which the `MOVE_SELF` branch sets);
   - `settle_move_out()`: every cookie settles oldest first at the pair timeout, and all of them at the quiet read;
   - `leave_tree()` and `WatchTree.within()`, used by the settling and by both move-ins to a skipped folder (2.5);
   - the walk's check for a folder back where it left (`came_back()`, at the walk's root and at each held watch it meets
     where the tree has it, collected through `initializeFolderWatchers()`'s `met`), with `MOVE_SELF` leaving a pending
     move-out's cookie in `moving` (2.5);
   - `WatchTree.forget()` setting the watches still held below a forgotten one adrift (2.5);
   - the `MOVE_SELF` and nameless `ATTRIB` branches;
   - the `ahead` mark at each event while `ahead` holds an entry, and the root put's WARNING.

   `remove_moved_away_watches()`, the pass over every watch at a paired move and `raise_queue_limit_for_removals()` go.
4. The discard branch: the cookie that records nothing, the move-in with a known cookie.
5. The overflow's restart (`WATCH_RESULT_OVERFLOW`, 2.7).
6. The quiet read: every cookie settles, then the five maps clear.
7. Tests (section 9).

## 11. Left to the builder

- Names, log levels and messages. The DEBUG lines of the variant say which branch ran.
- `watch_at()` stays the one O(n) path lookup, for `follow_inner_mounts()` only (a mount change).
- The variant clears `moving`, `found`, `ahead`, `adrift` and `replaced` at the quiet read only. In a tree that is
  never quiet, only entries whose event can no longer come stay: their watch was removed, or the place's move-out was
  read before the walk. That is a few dozen bytes each, and no aging is proposed: every cookie settles by the pair
  timeout, so none holds a watch.

## 12. Questions for the user

No question is open. Revision 0's one question was decided, and revision 1 narrows what it was about.

### Fixed in v16: a folder a walk watched at a place another folder had just left, then moved into that folder

Found at the end of revision 1's first pass by a shape made to test `leaving()`'s new clause against
`c2_unwatched_old`'s route, and left open in the draft; a regression from 0.55.1, which gets it right. v16 fixes it
by the landing rule (2.5), and fuzz seed 19006 on v15 was the same route.

- **The shape:** `c2_then_into_old`: `mv other o2; mkdir o2/u; mv o2/u o2/u2; mkdir o2/u; mv o2/u o2/u2/u`, then a
  write in `o2/u2/u/f`. It failed 5 of 5 orders on v9, v10 and v12; v16 passes every one of its 1,000 sampled
  orders at review 5's bounds, and of `c2_then_moved`'s (section 9).
- **The route, traced on v12 (v10 with one more branch, which made no difference here) with every read and tree
  operation logged:**
  - `o2`'s move-in walk lists `o2` (one entry, `u`: the first `u`); before it opens `u`, the first `u` is renamed to
    `u2` and a second `u` is made. The walk opens `u` and adds the second `u`'s watch at `(o2, u)`, where in K no
    folder is yet: the first `u`'s create is still queued.
  - The next read holds both creates at `u`, both move-outs from `u`, and the first `u`'s move-in at `u2`. The first
    create's walk finds nothing (the second `u` has moved on); the first `u`'s move-out takes the second `u`'s watch,
    as the one named at `u` (this is `c2_unwatched_old`'s mistake); its move-in lands it at `u2`, and that move-in's
    walk adds the first `u`'s watch and finds the second `u`'s below it (`found`).
  - The second create's walk finds nothing either, so the root put that puts right `c2_unwatched_old` never runs. The
    second `u`'s move-out takes no watch, its `MOVE_SELF` is taken as the landing's (`LANDED`), so its found place is
    never applied, and its move into the first `u` gives no move-in (that watch came after it). The watch stays at
    `u2`: the write is recorded as `o2/u2/f`, the move as a delete, and `o2/u2/u` is unwatched (its marker missing).
  - 0.55.1 is right: its walks re-point the watch to where they find it.
- **The fix, at the rule that moved the watch:** the landing waits for the watch's `MOVE_SELF`. The second `u`'s watch
  gets none for the first `u`'s move, so at the next event in `o2` (the second create) it goes back to `(o2, u)`;
  the second `u`'s own move-out then names it, its move-in lands it in the first `u`, and its own `MOVE_SELF` confirms
  (reasoned from v16's code; the orders were not traced on it).

### The root put's copy (decided, then narrowed)

**A folder whose move a create's walk saw before its move-out was read, at the place of the create, is copied when an
event of the folder came at that place first** (the root put of 2.3, where the events name no watch at that place
yet).

- **What the operator sees:** a folder that another command moves into the place a create or a move-in from outside
  names, before the watcher reads the first of them, and that is changed between that create and its move, is
  recorded as a delete and a create, with one WARNING line:
  `Not renaming <old path> to <new path>: the watcher found it there before it read the move; copying it instead`.
  The commands: `mkdir e; echo x >> big/f; mv -T big e` (a rename over an empty folder made just before), or
  `mkdir o2/x; rmdir o2/x; echo x >> big/f; mv big o2/x`.
  - The batch copies the folder's files again, though the vault holds them. With a size limit, that copy can prune
    older versions, as the copy of "A folder or file moved into a new folder is copied whole" can.
  - The result is right.
- **How often, on the real daemon** (`probes/measure.py`, a plain f2fs image, a 100 MB folder of 1,000 files, the
  commands back to back from one script; 5 tries a run: two runs on 0.55.1 and on v8, one on v7 and on v9):

  | Commands | 0.55.1 | Revision 0 (v7) | v8 | Revision 1 (v9) |
  |---|---|---|---|---|
  | `mkdir e; mv -T big e` | 0 of 10 copied (+0.03 MB each) | 5 of 5 copied (+102.43 MB each) | 0 of 10 | 0 of 5 |
  | `mkdir o2/x; rmdir o2/x; mv big o2/x` | 0 of 10 | 5 of 5 | 0 of 10 | 0 of 5 |
  | `mv big o2/x`, the control | 0 of 10 | 0 of 5 | 0 of 10 | 0 of 5 |
  | `mkdir e; echo x >> big/f7; mv -T big e` | 0 of 10 (+0.13 MB: the move and the changed file) | 3 of 5 | 8 of 10 | 5 of 5, each with the warning |
  | `mkdir o2/x; rmdir o2/x; echo x >> big/f7; mv big o2/x` | 0 of 10 | 5 of 5 | 7 of 10 | 5 of 5, each with the warning |

  In the second run on 0.55.1 and v8, and in v9's, the newest version was the tree (`diff -rq` of the version's
  folder and the watched folder) after every try. The tries that did not copy are those where the watcher walked the new folder before the
  rename landed: then the root put does not happen. The real daemon's log shows the warning once per copy, with no
  traceback.

  v16 (the final variant) differs from v9 in `leaving()`'s `ahead` clause, `EBADF` taken as a folder gone (v10), the
  expiry's two conditions (v14), the walk's check at every folder it meets (v15) and the landing held until its
  `MOVE_SELF` (v16); these rows were not run on it,
  as the real daemon needs loop mounts as root, which the host's rule of 23:04 keeps off the host until the user
  decides where such tests run. The clause changes what a move-out from the put place takes, which none of these commands has; the conditions and the check change what
  an expiry removes, and none of these commands moves a folder out of the tree; the landing changes nothing where the
  moved folder's watch is its own, as each of these is.

  Revision 0's rule copied the folder whenever the walk put it, which a script's back-to-back commands make the usual
  case (5 of 5 tries of the first two commands). Revision 1 copies only when an event of the folder came at the new
  place before its move-out was read.
- **Why the copy is needed:** that event (a change made before the move) was recorded at the new path, before the
  move; a move would carry the vault's old bytes over it. 0.55.1 copies nothing in the tries above and is right there,
  as the appended byte changes the file's size, which the batch's comparison sees. A change that keeps the file's size
  and mtime shows only by its event. The same commands as schedule shapes (`probes/test_sched_x.py`, every order to 16
  visits, the watch map checked both ways):

  | Shape | Orders | 0.55.1 wrong | v8 wrong | v8 without the copy wrong |
  |---|---|---|---|---|
  | `over_empty_poke_between`: `mkdir e`, a write in `big/a` with its size and mtime kept, `mv -T big e` | 136 | 6 | 0 | 3 |
  | `over_empty_append_between`: the same with an append | 136 | 0 | 0 | 0 |
  | `gone_place_poke_between`: `mkdir other/x; rmdir other/x`, the write, `mv big other/x` | 816 | 5 | 0 | 4 |
  | `gone_place_append_between`: the same with an append | 816 | 0 | 0 | 0 |

  0.55.1 loses the change where its walk of the create found `big`'s watch at the new place and put it in
  `newDirWDs`: the change's event is discarded and the batch records the move (`over_empty_poke_between` at visits
  0, 0, 1: `create e`, `move big → e`, no modify). v8 without the copy records the modify at the new path before the
  move, which carries the old bytes over it.
- **Why not fix it further:** the change's event is recorded at the new path before the move is read; only reading
  ahead in the queue, at the create, could tell that the folder at the place is not the one the create made.
- **Revisit when:** the warning shows up often in the live logs, or the no-copy move into a new folder gets its
  design, which meets the same question.
- **Decision (2026-11-08):** "Known limitation (Recommended)", widening the approved entry "A move that another change
  of the batch outran is copied"; the main session writes it. Revision 1's copy is a narrower case of the one decided,
  with the warning the entry's revisit reads, so the decision covers it and no new question is raised. The user decided
  on revision 0's wording, "in a race", before the real daemon showed revision 0 copying in 5 of 5 tries; revision 1
  removes that common case.
- **The verified design still needs it:** yes, in few orders (counted on v8; not run again on v16, section 9). At review 5's bounds, with the batches logged on both
  codes (`probes/test_sched_log.py` and its copy with the four shapes above, `probes/test_sched_log_x.py`;
  `probes/compare.py`, `probes/copies.py`):
  - `over_empty` (816 orders) and `root_ahead` (1,000 sampled): v8 copies in none, and records the move right in
    each, 273 and 141 of them orders 0.55.1 got wrong. Revision 0's rule copied in 210 and 218 of them, 245 where
    0.55.1 moved right.
  - The four shapes of the real daemon's last two rows (1,904 orders): v8 copies in 14, the same orders in each pair
    (3 of 136, 4 of 816), and is right in all. With the change that keeps size and mtime, 0.55.1 was wrong in all 7
    of those orders, and in 4 others where v8 moves right; with an append, 0.55.1 moved right in all 7.
  - So 14 of these 5,624 orders copy, 7 of them where 0.55.1 recorded a right move.

## 13. Calls to confirm

Each call this design made on its own, and each change of behaviour against 0.55.1:
1. **Memory for speed:** the path-keyed `kids` dict, 94 B a watch more than 0.55.1 (about 1.6 MB
   at the live daemon's 17,200 watches), for O(subtree) moves where 0.55.1 passes over every watch twice.
2. **The walk catches `OSError` only** (0.55.1's `iter_tree_entries()` caught every exception as an unreadable
   folder); another exception now ends the walk, and the job's watcher with it, as a bug should.
3. **The walk needs `/proc`** (the main session's ruling on 2.2): no by-path fallback.
4. **The overflow restarts the watch** (the ruling on 1.3): a second full comparison after the walk; each restart
   starts the max-delay clock again; the pending move-outs and read time the old watch published stay until the new
   one publishes its own (a full comparison reads neither).
5. **`raise_queue_limit_for_removals()` goes** (W1): a removal of more watches than the queue holds overflows the watch
   that removes them, which restarts with the raised limit. At this host's 8,388,608 none comes near; on a fresh host
   (16,384) it takes a removal of over 16,384 watches in one batch.
6. **Five older routes fixed, with no entry:** `RENAME_EXCHANGE`, a rename over an empty folder made in the batch,
   a folder made, sent elsewhere and replaced at its name by a renamed folder (section 6, 0.55.1 wrong in 268 of
   3,949 orders), and a folder back at the place it left before its move-out settled, its parent renamed in between
   (0.55.1 wrong in 2,978 of 4,095 orders of three shapes, and in 179 of 1,000 of a fourth), and a folder made where
   another had just left, then moved into a new folder (0.55.1 wrong in 225 of 1,000).
7. **The root put** takes the walk's view at the root of a create's walk (the one such rule), and copies only when an
   event of the folder came at the new place first; its watch and those below it stay out of `newDirWDs`, so their
   events are recorded while the move may stay a move. One WARNING line at each such copy (the ruling on 1.2).
8. **`leaving()`**, a rule the invariants found: a move-out takes the watch at the place whose own move-out from there
   was not read. Without it, v7 and v8 before it left a watch of a folder outside the tree in 11 of 600 orders where
   0.55.1 left none.
9. **Every move-out settles once, oldest first, at the latest at the pair timeout** (the ruling on 3.2): the cookies
   that record nothing too; at the quiet read, all of them in the one oldest-first pass (0.55.1 and v7 expired those
   that record before those that do not).
10. **`remove_newly_skipped_watches()` looks at the moved folder's subtree only** (the ruling on 3.10).
11. **Fewer creates in `twice_in_new_newfile`** (section 7, 6), **no link followed mid-walk** (7), **no ERROR line for a
    folder gone mid-walk** (8), **"Event name not found" at DEBUG** (9), **a deep tree watched to its bottom** (10).
12. **The cycle guard stays**: on v9, `cycle_guard_root` reaches it in 18 of its 1,365 orders, and two of them are
    pinned in the suite (both reach it and pass on v16, 3 runs of 2). `cycle_guard`, whose 165 orders reached it on v8, no longer does, as the walk's
    new check removes the stale place it came through. Seed 2509's trace shows a cycle the guard does not see (a
    move-in naming the moved watch as its own parent, from a wrong mover); it is fixed at `leaving()`, the rule that
    named the mover, and the guard is unchanged.
13. **One INFO line at each overflow's restart**, "Watching the tree again after the overflow", after 0.55.1's two
    overflow lines, which keep their text.
14. **The suite's schedule file** grows from 0.55.1's 10 shapes to 56 and its tree gains `next2/sub/z` and `g.txt`, so
    its sampled orders of the old shapes are other orders than round 21's record; at every order it holds 161,889
    orders, of which v16's stopped run passed the first 8,552.
15. **The seed 4284 agent's rule is in the design** (2.3, from its report): a new watch is checked through the open
    parent after `add_watch`, and a walk's root is opened from its parent's folder. A folder renamed between its walk's
    open and its watch gets no watch from that walk; the walk of where it went adds one. Its check compares `st_ino` and
    `st_dev`, as the report has it, with an `fstat` that fails counted as gone (mergerfs's `EBADF`). On mergerfs
    `st_ino` is made from the path; the probes of section 1 found the check still tells the folders apart there, and the
    kernel's identity (`add_watch` of the name), tried as v11, made mergerfs list folders that were not there. It costs
    about 1.4 µs a folder on the first walk (idle) and 3.7 to 5.5 µs a folder made (at load, section 8).
16. **A restore syncs before it ends** (the main session's call, section 10): one `syncfs` before a folder target's
    marker goes, or before a file target's restore returns; a `syncfs` error keeps the marker.
17. **The gates ran on XFS** (the host's `/mnt/fast` since 2026-11-08 20:07). Since the host's rule of 23:04 (test
    code never runs as root on the host), every gate run on v10 to v16 ran in containers as uid 65534; the suite there
    skips and fails the tests that need root, so those wait for the user's decision on where they run (section 9). The
    real daemon's rows (section 12) ran on v9, as root, before that rule; the changes of v10 and v14 to v16 since have not run
    on the real daemon.
18. **The mergerfs and power-loss tests are gates again** (the user's "Bring both back (Recommended)"): the walk's
    rename shapes ran on a scratch mergerfs pool (section 1; mounted on the host as setup, the tests in containers);
    the suite's mergerfs and power-loss tests need root, and wait for the user's decision on where they run.
19. **`leaving()` takes no watch the root put at the place while its `ahead` entry stands** (2.5): a rule from the
    invariants that the revision 1 check missed and fuzz seed 2509 found; without it the watcher could grow without
    bound.
20. **`EBADF` is a folder gone for the walk** (`WALK_GONE`, 2.3): mergerfs's answer for a folder removed after its open.
    On a local filesystem the walk never gets it for an fd it just opened.
21. **The size estimate's fix for XFS is in this build** (the main session's ruling, section 10): the estimate stays at
    or above what the vault grows by, with the inodes exact and its cost as today's; it changes what a Backup Size
    Limit prunes on XFS, never toward pruning more.
22. **A link the vault's filesystem refuses is left out of the version, with a warning** (the main session's ruling,
    section 10), and a restore that meets one warns and exits 0. Leaving it out is a known limitation **pending the
    user's OK**; no entry is written until then.
23. **An expiry takes a folder's watches only if its move-out is the folder's last move read and the folder's
    `MOVE_SELF` came after it** (2.1, 2.5): two conditions the fuzz on v10 found (seeds 14124 and 12812), which v14
    added. Both follow from what the kernel queues for a watch (facts 1 to 4, 13 and 16); the place stays the third
    condition. One order is left that the second condition gets wrong, reasoned and not run: an expiry before the
    folder's `MOVE_SELF` is read, which needs a create in *another* folder whose tree path is the moved-out path (two
    watches holding one path, as while a parent's rename is unread), queued by another process between the rename's
    `MOVED_FROM` and its `MOVE_SELF` (fact 13). The folder's watch then stays, adrift, where it left (the stale watch
    of F3's class) where v10 removed it. I left it with no code: it needs two such coincidences at once, and catching
    it means keeping each expired cookie for a `MOVE_SELF` still to come.
24. **A walk checks every watched folder it meets for one back at the place its pending move-out left** (2.5, v15),
    where v9 to v14 checked its root only: fuzz seed 12831 on v14, which 0.55.1 fails too. It runs only while a
    move-out is pending, and keeps a list of what the walk met for that time.
25. **A move-in's landing stands only once the moved watch's `MOVE_SELF` comes** (2.5, v16): the first later event in
    either folder of the move with none read, or the quiet read, puts the watch back at the move-out's place. It fixes
    the finding revision 1's draft left open (`c2_then_into_old`, a regression from 0.55.1) and fuzz seed 19006 on
    v15, from fact 16 as the expiry's second condition is. It changes nothing for a watch that made its move, as the
    kernel always queues that `MOVE_SELF`.
26. **v16's gates did not finish** (section 9): the fuzz found a seed on v10, v14 and v15 in turn, each fixed in the
    next variant, and the agent harness stopped v16's run at 5 to 72% when the host ran short of memory, with the
    instruction to start it again only when asked. What ran passed. The build's task 7 runs the gates on the branch;
    running them on v16 first takes about 3.5 hours at full width.
