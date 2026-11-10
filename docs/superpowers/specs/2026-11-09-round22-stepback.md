# Round 22, step back: the events move the watches, and the tree's view waits for an empty queue (build spec)

Version 0.55.3. This is the design pass the user chose on 2026-11-09, "Step back on the design (Recommended)": a design
smaller than round 22's watch tree (v16, `2026-11-08-round22-watcher-design.md`), where a wrong watch map costs an extra
copy or a rescan of one folder, never wrong bytes or a lost change. A design review the same day found it sound with
changes; the main session ruled on its findings, and the user approved its three limitations. This revision is the spec
a builder builds from. v16 stays the fallback until the build passes its gates.

**The design.** Keep 0.55.1's watcher and change four things in it:
1. **A walk never moves a watch the events hold.** One it finds at another path stays where the events put it, and the
   watcher notes where the walk saw it.
2. **What needs the tree's view waits until the kernel holds no unread event** (`FIONREAD` on the inotify descriptor is
   0 after a read is handled). Then a probe sees what the events would say: a noted watch is put where the walk saw it
   (and that folder is copied, as its events since came at the old path), the watches of a folder that left the tree
   are removed, and a folder move that took two watches from one path is settled.
3. **A move reported by a watch whose path is not settled** (noted by a walk, of a folder that left or is leaving, or
   taken in an ambiguous move) **is recorded as a delete and a create, never as a rename in the vault.**
4. **An overflow restarts the watch**, as v16 does.

It closes the three deferred entries and passes the routes v16 fixes, keeps no state per watch and costs nothing per
file event. The price is a copy where 0.55.1 kept a rename in a few rare orders, and three known limitations (section 6).

**What the review changed** (each a main session ruling; sections 7 and 8 hold the numbers):
- **`outgoing` is a count per watch, and each move-out lets its watches go once** (3.2). As a set, an ancestor's
  pairing cleared the watch of a nested move-out still pending, and a rename it reported put wrong bytes in the version
  that a whole-tree comparison keeps (3 of 3 in process, on 0.55.1 too).
- **`settle()` acts per probe, with no retry** (3.4). The retry probed every `leaving` watch again at each read of a
  busy tree: 6.21 s of watcher CPU after a big move-out, where 0.55.1 spends 0.335 s.
- **The discard branch's folder move-out looks only at `newDirWDs` and `found`**, not at every watch (3.2): 2.94 to
  3.05 s against 0.046 to 0.053 s for 2,000 folder renames inside a new folder. Two rules keep what that rests on.
- **`follow_inner_mounts()` passes `found`** (3.5).
- Fact D on mergerfs and fact F on busy trees (3.1); the residual races for every kind of probe (section 4).

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
  combine; `IN_ONLYDIR` and `IN_DONT_FOLLOW` steer only the lookup. So `add_watch(path) == wd` says the folder of `wd`
  is at `path`. A wd not in the map is a folder with no watch (the probe's own, removed again); a failed `add_watch`
  is "not there" (`ENOENT`, `ENOTDIR`; `EACCES` cannot hit the daemon, which runs as root; `ENOSPC` only for a folder
  with no watch).
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

### 3.2 The structures, and what each keeps true

All live in `watchFolder()` for one watch's life; an overflow's restart starts them empty.

| Structure | What it holds | What it keeps true |
|---|---|---|
| `wdDic` (wd → path) | as 0.55.1 | each path is where the events read so far put the folder, except while the watch is guarded. Only `move_watches()` at an unguarded pairing, the settle (on an empty queue) and removals change a held watch's path; a walk writes only the path of a watch it adds |
| `cookieDic` (cookie → `COOKIE_VALUE(wd, path, isDir, wds)`) | as 0.55.1: a move-out waiting for its pair; `wds`, the watches mapped at or under its path when its `MOVED_FROM` was read | a cookie holds its `wds` in `outgoing` from its `MOVED_FROM` until it lets them go, once |
| `newDirWDs` (set) | as 0.55.1: the watches of folders made since the last take, whose events are discarded (the batch's copy holds them) | every watch mapped at or under a folder of `newDirWDs` is in `newDirWDs` or in `found` (one exception, section 4) |
| `found` (wd → path) | a held watch a walk met at another path than its own, with the path the walk saw | the watch is guarded until the next settle, which clears `found` |
| `outgoing` (wd → count) | for each watch, how many cookies hold it | the count is the number of cookies still holding the watch; the entry goes at zero |
| `leaving` (set) | the watches of a folder that left the tree or its place: an expired or evicted move-out's `wds`, the watches under a folder's move-out read in a new folder, a move into a skipped folder's | each is probed at the next settle, and removed if its folder is not at its path |
| `doubtful` (wd → path before) | each watch a folder move took from a path that held more than one watch (`RENAME_EXCHANGE`, or a folder moved onto the place of one whose move-out is pending) | settled at the next settle |

**Guarded.** A watch is guarded while it is in `found`, `leaving` or `doubtful`, or its `outgoing` count is above
zero (`guarded()`). A move whose source folder's watch or destination folder's watch is guarded (the cookie's `wd` and
the `MOVED_TO`'s `wd`) is a delete and a create, never a rename in the vault.

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

**What `newDirWDs` must keep true** (ruling 3). The discard branch's folder `MOVED_FROM` makes `leaving` the watches
mapped at or under its path, as the design pass had it, but looks for them only among `newDirWDs` and `found`. That
rests on `newDirWDs`'s line in the table, which two rules keep; the design pass had neither, as its scan looked at
every watch:
1. **The discard branch's unguarded pairing puts every watch `move_watches()` moved into `newDirWDs`**, as 0.55.1's
   removal and the walk's re-adding did. Without it, a subfolder of the moved folder that leaves before the walk
   reaches it (`mkdir n; mv big n/big; mv n/big/sub /out/sub`) keeps a watch mapped in the new folder that no scan of
   `newDirWDs` finds, whose events are not discarded either.
2. **The settle's walk of a folder it copies passes `newDirWDs`**, as every create's walk does: the settle's copy is a
   `create`, which holds what the folder's events would say until the take. Without it, a watch from outside the new
   folder that the settle put in it, and what its walk adds, are in neither set once the settle has cleared `found`:
   in `mv big /out/big; mkdir n; mv /out/big n/big`, big's watch, still held by its pending move-out, is `found` at
   `n/big` and put there; once that move-out expires (`mkdir big`) nothing guards it, and a later `mv n/big /out/b2`
   leaves it stale. (A folder made inside the new folder needs no rule: its create's walk put it in `newDirWDs`.)

Every other walk under a new folder passes `newDirWDs` already: a create's, the discard branch's, a move-in with no
pair, and a guarded move-in, which becomes a create. A normal pairing cannot land under a new folder, as its
`MOVED_TO` came on a watch not in `newDirWDs`; a watch mapped in a new folder and not in `newDirWDs` is in `found`,
hence guarded, so a move into it is a create too.

### 3.3 Event by event, against 0.55.1

| Where | 0.55.1 | Step back |
|---|---|---|
| A walk meets a watch held at another path | puts it there (`wdDic[wd] = folder`), and in `newDirWDs` for a create's walk | leaves it where the events put it, notes the path the walk saw in `found`, and does not add it to `newDirWDs` (3.5) |
| Folder `MOVED_FROM` | cookie with the watches under the path | the same; each of them gains one in `outgoing` |
| Folder `MOVED_FROM` in a new folder (discard branch) | nothing: the watches stay for good | the watches at or under the path, among `newDirWDs` and `found`, are `leaving` |
| `MOVED_TO`, cookie known, neither folder's watch guarded | `move` recorded, every path under the old one rewritten, walk | the same (`move_watches()`, 0.55.1's loop; walk with `found`); the cookie lets go |
| `MOVED_TO`, cookie known, a folder's watch guarded | as above | one INFO line; the move-out expires into its delete, and the move-in is a create (walk with `newDirWDs` and `found`), as one with an unknown cookie |
| The rewrite takes more than one watch from exactly the old path | moves them all | moves them all, and each watch it moved is `doubtful`, with its path before |
| A move-out expires or is evicted | delete recorded; `remove_moved_away_watches()` probes the watches still under the old path and removes them now | delete recorded; it lets go, and its `wds` are `leaving` |
| Folder `MOVED_TO` into a new folder, cookie known (discard branch) | walk, then `remove_watches_under()` of the old path | unguarded: `move_watches()`, every watch it moved into `newDirWDs`, the cookie lets go and stays with no watches; guarded: nothing moves. Then the walk, with `newDirWDs` and `found` |
| Folder `MOVED_TO` into a skipped folder, cookie known | delete; `remove_watches_under()` now | delete; the cookie lets go; its `wds` and the watches under its path are `leaving` |
| End of a read, and every read with no event | nothing | `settle()` |
| `Q_OVERFLOW` | full comparison requested; the watch goes on | the same, then the watch ends and `watcher()` starts a new one (3.6) |

A subfolder's `MOVE_SELF` is skipped, as on 0.55.1. File moves follow the same rows (guarded or not); a file's
move-out holds no watch.

### 3.4 `settle()`

It runs at the end of every read, and at every read with no event, after the quiet read's expiries. It returns at once
unless `found`, `leaving` or `doubtful` holds something and `FIONREAD` is 0. Then, each step by probe (`add_watch` of
the path with the watcher's mask, `IN_ONLYDIR` and `IN_DONT_FOLLOW`):
1. **`found`:** each watch still at another path than the walk saw, which the probe finds there, is put there, and its
   folder is to be copied. A watch is left there with no event of the move only when the move was not taken as one (a
   move-in with no pair, one in a folder made in the batch, or one rule 3 turned into a copy), so the batch copies that
   folder already, and the collapse drops the settle's copy as covered. `found` is cleared.
2. **`doubtful`:** each watch not at its path but at its path before goes back there, and its folder is to be copied.
   `doubtful` is cleared.
3. **`leaving`:** each watch the probe does not find at its path is removed (`remove_watches()`), and `leaving` is
   cleared, whatever the queue holds by then (ruling 2).
4. The probes' own watches (a folder at a probed path that had none) are removed.
5. Each folder to be copied, outermost first and once (one under another is covered), is walked with `newDirWDs` and
   `found` (rule 2 of 3.2), then gets a `create` event, with one INFO line. It is walked first, so a change made after
   the copy passed it raises its event.

`found` comes before `leaving`, so a folder that came back keeps its watch; the walks come last, so what was made in a
found folder while its events came at the old path gets watched, and its copy holds it. Each correction is per watch,
by probe, so two watches at one path never confuse it, and none moves a watch ahead of the events: on an empty queue
nothing is ahead.

**Why no retry** (the review's argument, ruling 2). A probe that does not find a leaving watch at its path, on a queue
that was empty when the settle began, means its folder is not there. A folder that comes back into the tree while the
probes run comes back by a rename whose events are read next: from outside its cookie was never seen, so the move-in
is a create, whose walk gives it a new watch and whose copy holds what it holds, a change made before that walk
included; within the tree its move-out and move-in come too, with the same walk. So no removal needs undoing, and none
needs the queue to stay empty while the probes run. The design pass's re-check (`if not queued_events()` before the
removals) made every probe of a big `leaving` set run again at each read of a busy tree, removing nothing.

### 3.5 The walks

`initializeFolderWatchers()` gains `found` (a dict). With it, a held watch met at another path than its own stays
where the events put it, `found` gets the path the walk saw, and the walk returns the watch without adding it to
`newDirWds`: it is guarded until the settle. The walk still lists the folder by path (`iter_tree_entries()`), so what
is under it is met too. Callers:
- the first walk of a watch: without `found`, as 0.55.1 (the review left its race with a rename out of this round: the
  start's full comparison follows it);
- a create's walk and a move-in's with no pair: `newDirWDs` and `found`;
- the normal pairing's walk: `found`;
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
- once that walk is done it queues a full comparison again; the one queued at the overflow makes the batch in progress
  a full comparison too, and the queue keeps one full comparison.

What the old watch held goes: its pending move-outs (the comparison finds what is gone), `newDirWDs` (the new watch
keeps those folders' events: more events, no loss) and the four sets. Each restart starts the max-delay clock again.
From the old instance's close until the new walk reaches a folder, nothing watches it: about 8 µs a folder, 0.15 s at
17,200 folders (limitation 3).

### 3.7 What goes, what stays, what comes

- **Goes:** `remove_moved_away_watches()` (its probe moves to the settle); the rewrite loop written inline in the
  `MOVED_TO` branch (it becomes `move_watches()`); the discard branch's `remove_watches_under()` at a folder move-in
  with a known cookie; the skipped move-in's `remove_watches_under()`; the walk's `wdDic[wd] = folder` for a held watch
  when `found` is given; `Q_OVERFLOW`'s `continue`.
- **Stays:** the walk by path; `cookieDic` and its `wds` (one pass over every watch at each folder move-out, one at each
  pairing; v16 removed them); `newDirWDs` and its discard, cleared at each take; the expiry triggers; `remove_watches()`
  with `raise_queue_limit_for_removals()`; `remove_newly_skipped_watches()`; `follow_inner_mounts()`'s
  `remove_watches_under()`; the `DELETE_SELF` and `UNMOUNT` handling; a subfolder's `MOVE_SELF` skipped.
- **Comes:** `found`, `outgoing` (a count), `leaving`, `doubtful` and `guarded()`; `move_watches()`, which also returns
  the watches it moved (for rule 1); `settle()`; `queued_events()` (`FIONREAD`, with `import termios`);
  `WATCH_RESULT_OVERFLOW`; the `found` parameter of `initializeFolderWatchers()` and of `follow_inner_mounts()`; the
  INFO lines of section 5.

### 3.8 Why each harm is closed

- *A rename in the vault from a wrong path.* A watch's path can be wrong only while it is guarded, or while it is a new
  watch a walk added ahead of its folder's arrival. A move through a guarded watch is a delete and a create, and the
  count keeps a watch guarded while any pending move-out holds it, so an ancestor's pairing in between does not clear
  a nested one's. A watch added ahead has no event of its own before its arrival (its folder's events come after the
  arrival in the one queue, fact A), and the arrival's walk finds it held elsewhere if a move-out took it meanwhile
  (`found`). The check after the batch then compares, and a copy is made from the tree.
- *A change at a path ahead of the events.* No watch moves ahead: walks note, the settle runs on an empty queue. A
  watch of a folder that reached its place where no event saw it lags at the old path until the settle, and the settle
  copies the folder.
- *A folder with no working watch.* A watch is removed only by a probe on an empty queue, after the found watches were
  put where they are (so a folder that came back keeps its watch). Folders made inside a lagging folder are walked at
  the settle. An overflow walks the whole tree again.

## 4. The three deferred entries, v16's routes and item 23

- **"A folder renamed twice into a folder whose move is being walked can keep old bytes" (F2):** closed. The walk notes
  the folder and moves nothing; the change is recorded at its own path and the collapse carries it through both renames.
  No copy: the found watch is where the events put it by the settle. Gates: `twice_old_race`, `twice_old_race_sub`,
  `root_ahead`.
- **"A folder moved out of the tree from a new folder keeps its watch" (F3):** closed, with the count. A move-out
  discarded in a new folder makes its watches `leaving` (found among `newDirWDs` and `found`, 3.2); an expiry makes
  them `leaving` by watch, not by path, so an ancestor's rename in between does not hide them; and while a move-out
  holds a watch it is guarded, so a rename it reports is a delete and a create. F1 is 6 of 6 right with the count:
  review 5's order through a new folder already on the design pass (0.55.1: 3 of 6 wrong), and its ancestor route (the
  review's `test_nested_outgoing.py`) on the review's patched copy (0.55.1 and the design pass: 3 of 6 wrong, the three
  with alike tails).
- **"An event queue overflow can leave a new folder unwatched":** closed, by the restart. The overflow probe: 9 of 9
  right with the watch map checked both ways (0.55.1: 9 of 9 wrong); the entry becomes limitation 3.
- **v16's routes** (`exchange`, `exchange_twice`, `over_empty`, the `root_put_*` shapes, `back_home_*`,
  `land_ahead_taken`, `back_home_under_new`) and the seeds that found them: all in the gates of section 8.
- **v16's item 23** (an expiry before the folder's `MOVE_SELF`, with a create elsewhere at the same path) does not
  arise: the step back takes no meaning from a subfolder's `MOVE_SELF` and removes no watch by its place in the event
  order, only by a probe on an empty queue.

What the step back leaves, reasoned, not run:
- **A rename caught in its window (fact E), at any probe.** A probe between a rename's move of the name and the queueing
  of its events sees the new tree with an empty queue. A `found` or `doubtful` watch put there is ahead of the events:
  a change made in its folder before they are queued is recorded at the place the move then lands on, and the collapse
  drops it as what the move replaced. A `leaving` watch removed there loses a change made before its folder's move-in
  walk adds a new watch. Each needs a rename of that very folder during the settle's probe of it, and a change in the
  same microseconds that keeps size, mtime and the last 64 KiB. v16 rests on the same kernel ordering; 0.55.1's expiry
  probes with a whole read unhandled.
- **A queue that never empties** (limitation 2). Until the settle, a found folder's changes come at its old path, and a
  move through a guarded watch is a copy. The settle runs after the read that ends each burst, so a batch taken after
  a quiet period always follows it; only a batch taken while events keep coming (the maximum delay's) can come first,
  and that version can lack a change in the found folder, which the settle's copy brings into the next one. Fact F says
  the queue empties within milliseconds even at 108,000 events a second.
- **An inner mount followed inside a folder made since the last take** is the exception to `newDirWDs`'s line: its walk
  keeps the mount's events, so its watches are not in `newDirWDs`, and a move out of the tree, read on the new folder's
  watch, of a folder holding the mount point leaves the mount's watches mapped in the tree. It needs a disk mounted below
  a folder made in the same batch, and a folder inside the new one and above the mount point moved out of the tree in
  that batch; 0.55.1 is the same. Proposed: not an issue.
- **The first walk** puts a watch where it finds it, as on 0.55.1 (3.5).

## 5. What changes for the operator

- The three deferred entries go (section 4).
- **A move out of a folder that has just left the tree is copied**, where 0.55.1 renamed it in the vault: `mv X /out/X;
  mv /out/X/sub sub` within the pair timeout (60 s by default) copies `sub` whole. So is a rename reported by a folder
  a walk found ahead of its events, or by either folder of a `RENAME_EXCHANGE`, until the next empty queue. The version
  is right; the copy costs the moved entry's size once (limitation 1). One INFO line each: `Copying <path>, moved from
  <path>: a watch of the move is not settled`.
- **The settle's copy** logs one INFO line: `Copying <path>: its watch got there with no event of the move, so its
  events since came at its old path`. It comes once per found watch put in place, which includes every folder renamed
  inside a folder made in the same batch (the discard branch keeps no cookie, so the move-in's walk finds the watch at
  the old path); those copies cost no bytes, as the new folder's copy covers them. 0.55.1 logged nothing there.
- **A change in a found folder can reach the vault one version late** under events that never pause (limitation 2).
- **An overflow restarts the watch:** one more INFO line, `Watching the tree again after the overflow`, and a second
  full comparison after the walk (limitation 3).
- The watches of a folder moved out of the tree go at the first empty queue after its move-out expires, where 0.55.1
  removed them at the expiry itself.

## 6. docs/limitations.md and the README

**docs/limitations.md** (round 22's build):
- **Goes:** "A folder renamed twice into a folder whose move is being walked can keep old bytes" and "A folder moved out
  of the tree from a new folder keeps its watch".
- **Replaced in place:** "An event queue overflow can leave a new folder unwatched" becomes "An event queue overflow
  restarts the watch" (limitation 3 below); the user's pick puts its window as one sentence in the overflow entry.
- **Changed:** "A folder or file moved into a new folder is copied whole": its revisit no longer waits for the two
  entries that go: "Revisit when: the no-copy move gets its own design; sooner if size limits start pruning because of
  it."
- **New:** limitations 1 and 2 below, after "A move that another change of the batch outran is copied".

The three entries, as they go into the file:

```markdown
### A move out of a folder that just left the tree is copied

- **Kind:** known limitation.
- **What the operator sees:** a file or folder moved back into the tree out of a folder that was moved out of it less
  than the pair timeout before (60 s by default), as in `mv X /out/X; mv /out/X/sub sub`, is copied whole instead of
  renamed in the vault, with one INFO line, `Copying <path>, moved from <path>: a watch of the move is not settled`. So
  is a rename in a folder the watcher found at a place its events had not brought it to yet (a rename racing the walk
  of a folder just moved or made), or in either folder of a swap by one rename (`RENAME_EXCHANGE`), until the watcher
  next finds its event queue empty, normally at the end of that read. 0.55.1 renamed these. The version is right; the
  copy costs the moved entry's size once, and with a size limit it can prune older versions, as the copy of a move into
  a new folder can.
- **Why:** such a folder's watch can report its moves at a path another folder now has; trusting it is how a version
  kept a file's old bytes for good, and telling the two folders apart needs the watch tree of round 22's first design
  (about 815 more lines and 94 bytes a watch).
- **Revisit when:** the INFO line shows up often in the live logs, or the no-copy move into a new folder gets its own
  design.
- **Approved:** 2026-11-09, the user's choice "Accept: copy (Recommended)".

### A folder found ahead of its events can reach the vault a version late

- **Kind:** known limitation.
- **What the operator sees:** when a walk of the watcher finds a folder at a place its events have not brought it to
  yet (it was renamed while the walk of a folder just moved or made ran), the folder's changes keep coming at its old
  path until the watcher finds its event queue empty; then it puts the folder's watch in place, watches what was made
  in it and copies it, with one INFO line, `Copying <path>: its watch got there with no event of the move, so its events
  since came at its old path`. A batch taken before that moment, while events keep coming (the maximum delay's), can
  lack a change made in that folder meanwhile; the next version has it. The queue empties often even in a busy tree:
  with writers at 108,000, 89,000 and 57,000 events a second it was empty after 42%, 59% and 69% of reads, the longest
  non-empty streak under 10 ms.
- **Why:** only an empty queue tells the watcher that what it sees in the tree is what its events say; deciding with
  events unread is how 0.55.1 could remove a live folder's watch or keep a file's old bytes.
- **Revisit when:** a version is found to lack a change that the next version holds, on a job whose events never pause.
- **Approved:** 2026-11-09, the user's choice "Accept: next version (Recommended)".

### An event queue overflow restarts the watch

- **Kind:** known limitation.
- **What the operator sees:** when the kernel's event queue overflows, the watcher logs `Queue overflow, event maybe
  lost` (ERROR), doubles the queue limit, logs `Watching the tree again after the overflow` and watches the tree afresh
  with a new inotify instance: the batch in progress becomes a full comparison, and another follows the new watch's
  walk, so a folder whose create was lost is watched and backed up. A change made during that walk (about 8 µs a
  folder, some 0.15 s for 17,000 folders) that keeps a file's size, mtime and last 64 KiB is seen by neither comparison,
  and the vault keeps that file's old bytes until it next changes.
- **Why:** after lost events the watch map cannot be trusted, and only a new instance takes the raised queue limit (the
  kernel reads it when an instance is made); keeping the old instance's watches through the walk would hold two watches
  a folder for the walk's length, for an event the live logs have not shown.
- **Revisit when:** an overflow shows in the live logs.
- **Approved:** 2026-11-09, the user's choice "Accept: one sentence (Recommended)": the walk's window as one sentence in
  the overflow entry, rewritten here as the restart closes "An event queue overflow can leave a new folder unwatched".
```

**README**, one line each in its list of limitations, after the line on a move another change of the batch outran:
- "A file or folder moved back into the tree out of a folder that left it within the pair timeout (mv X /out/X; mv
  /out/X/sub sub), or renamed in a folder the watcher found ahead of its events or swapped by one rename
  (RENAME_EXCHANGE), is copied whole once instead of renamed, with one INFO line (Copying …: a watch of the move is not
  settled). The result is right."
- "Under events that never pause, a change in a folder the watcher found ahead of its events can reach the vault one
  version late."
- "An event queue overflow makes the watcher watch the tree afresh and compare it in full twice; a change made during
  that walk (about 0.15 s for 17,000 folders) that keeps a file's size, mtime and last 64 KiB is missed until the file
  next changes."

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
| `renamesinnew` (the review's): 2,000 `mkdir n/d; mv n/d n/e` inside a folder made in the batch | 0.046 to 0.053 s | design pass 2.94 to 3.05 s; with ruling 3 not run |

**Ruling 3's scan, timed alone** (this revision; a Python loop of the two scans with no inotify, in a container as uid
65534 at a load of about 22): for 2,000 such move-outs in a tree of 20,251 watches, scanning every watch took 1.53 s and
scanning `newDirWDs` and `found` 0.086 s, `newDirWDs` growing to 2,001. That scan grows with the folders made since the
last take, so its total grows with their square: 20,000 renames inside one new folder would cost about 100 times as
much, some 8.6 s (reasoned from the square, not run), where 0.55.1's discard branch does nothing at a move-out. The
build measures `renamesinnew` at 2,000 and at 20,000 (section 8).

- **Memory:** no state per watch. The four structures hold only the watches of a race or of a pending move-out, until
  the next settle, pairing or expiry.
- **Per event:** nothing for a file event (5 to 6.5 µs an event on both codes in the file writes above). One `settle()`
  call per read, which returns at once when nothing is noted; with something noted, one `FIONREAD` ioctl. A move-in
  whose move-out was read looks its two folders' watches up in four structures, almost always empty.
- **Per folder walked:** for a watch the walk finds held (not a new one), one comparison of its path, as before.
- **Per folder move:** 0.55.1's two passes over every watch stay (v16 removed them; section 9).
- **Extra reads:** the settle's probes (an `add_watch` per noted watch, a lookup in the dentry cache) and its walk of
  each found folder; the copies of rule 3 read the moved entry whole.
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
at review 5's bounds and the fuzz were not run on it. Ruling 3 has not run anywhere.

### 8.2 The gates on the built branch

Every gate below runs on the branch before release; each has a bar. Test code never runs as root on the host: the
container gates as uid 65534 (the scratch `dk.sh`: `docker run --rm --init --memory=<cap>` with no `--memory-swap`,
`--pids-limit`, `--user 65534:65534`, the code and the test venv read-only), the root suite in the test VM. Read
`/proc/pressure/memory` before a fan-out, cap each container, and remove each run's temp tree at its end.

| Gate | Bar |
|---|---|
| The 99 shapes plus the new `nested_out_ancestor` and ruling 3's two shapes (section 10, task 1) at review 5's bounds (3 and 4 steps every vector to 16 visits, 5 to 12, 6 and 7 steps 1,000 sampled), the watch map checked both ways (`all99.sh`, `SCHED_WATCHES=1`) | none wrong |
| The seed 4284 agent's 10 shapes at review 5's bounds | none wrong |
| `tests/test_watcher_schedules.py` at every order (`REVERB_WATCH_SCHED_SAMPLE=0`) | none failed |
| The in-process probes in the suite: review 5's F1 order and its ancestor route, each with its control; the overflow cases | 6 of 6, 6 of 6, 9 of 9 |
| The fuzz, seeds 0 to 29,999, lists checked, 15 containers of 2,000 seeds, each process's address space capped at 12 GB (`fz.sh`) | no failure; teardown errors only of the size-record class ("A size record too low after a rename falls back to a copy") |
| Fuzz seeds 2195, 2509, 4284, 12812, 12831, 14124, 16462 and 19006 alone, 3 tries each | all pass |
| The copy count of section 7 | none wrong; the extra copies over 0.55.1's right orders are limitation 1's and the settle's, each named |
| The suite in containers as uid 65534 | fails only what the base (main with 0.55.2) fails in the same container |
| The suite as root in the test VM (`gate.sh`, tag v0.54.1 in its `.git`): `--deselect tests/test_pool_cut.py`, then `tests/test_pool_cut.py` alone (`--alone`); this holds the suite's mergerfs and power-loss tests, which the user brought back for this round | all pass, but the queue-fill skip |
| `probes/bench_watcher.py` (`bench.sh`): every workload of section 7, `renamesinnew` also at 20,000 renames, the base and the branch alternating, three runs each | each within the base's noise (the ranges overlap), the overflow excepted; `outbusy2` and `renamesinnew` at the base's numbers. A miss goes to the main session with the numbers, not into more code |

## 9. Against v16

| | Step back | v16 |
|---|---|---|
| reverberator.py | the design pass's +153/-74, plus about 30 lines for the review's changes (estimated) | +815/-170 |
| Rules | four, with the structures of 3.2 | about twenty (its 2.1) |
| Memory | none per watch | 94 B a watch, 1.6 MB at the live 17,200 |
| First walk | as 0.55.1 | about 1.4 µs a folder more (idle), 24 to 85 ms at 17,200 |
| A folder made | as 0.55.1 | 3.7 to 5.5 µs more |
| A folder renamed | as 0.55.1: two passes over every watch | O(its subtree): 0.13 µs a watch a rename saved |
| Copies 0.55.1 does not make | limitation 1's; counted, 25 more copies in the 5,150 orders 0.55.1 gets right | the root put's copy (14 of 5,624 orders) |
| Walk | 0.55.1's, by path | through open folders, iterative, `/proc` needed |
| Known wrong order left | none run; the reasoned ones of section 4 | item 23, reasoned |

v16 is faster where one folder of a large tree is renamed often; the step back is lighter in memory and in walks, and a
fifth of the code. The passes over every watch at a folder move could go on their own later, by an index of paths
(the lightness round), without the rest of the watch tree.

## 10. The build's tasks, in order

The design pass's reverberator.py diff against 6726e75 is in the worktree, untracked:
`.superpowers/sdd/2026-11-08-round22/stepback.diff` (the scratch clone's commit 50e391d plus an uncommitted docstring).
The main session hands the builder the rest: the scratch clone's test changes (its commits 100ef5c and 5e62c74), the
probes (the design pass's `test_r5_f3_wrong.py`, `test_overflow.py`, `watchmap.py`, `test_sched.py` with the 99 shapes'
list; the review's `test_nested_outgoing.py`, and `bench_watcher.py` with `outbusy2` and `renamesinnew`) and the
scratch helpers (`dk.sh`, `suite_dk.sh`, `all99.sh`, `sched.sh`, `fz.sh`, `bench.sh`, `probe.sh`). Each task ends with
its command passing; `<tree>` is the worktree, run in a container as uid 65534 (`dk.sh <cap> <tree> python3 -m pytest
-q -n auto -p no:cacheprovider -o tmp_path_retention_policy=failed --basetemp=<bt> <files>`).

1. **The base, and the tests first.**
   - Merge main into round22 once 0.55.2 is there; `__version__ = "0.55.3"`.
   - Bring in the clone's test changes against 6726e75: `watch_map_errors()` in `tests/harness.py`; `Session.watch()`
     in `tests/test_moves_into_new_folders.py`, which runs `watchFolder()` again with `root_returned=True` after
     `WATCH_RESULT_OVERFLOW`, as `watcher()` does, and the `exchange` verb (`renameat2()` with `RENAME_EXCHANGE`);
     `tests/test_watcher_schedules.py` with v16's 56 shapes on 0.55.1's walk hooks (`iter_tree_entries()`), without
     v16's two `WatchTree` asserts, and the watch map checked at the end of every shape. They name
     `rv.WATCH_RESULT_OVERFLOW`, which task 2 adds: for the red run on the base, add that one constant alone.
   - Add the shapes, to the schedule file and to the 99's list (`probes/test_sched.py`): `nested_out_ancestor`, the
     review's route in the file's tree (`mv big/sub {outside}/sub; mv big other/b2; mv next2/sub other/b2/sub; mv
     {outside}/sub/b {outside}/sub/z`, then a `poke` in `other/b2/sub`); for ruling 3's rule 1,
     `moved_sub_out_before_walk` (`mkdir n; mv big n/big; mv n/big/sub {outside}/sub; mv next2/sub n/big/sub`, then a
     write in `{outside}/sub`); for rule 2, `back_into_new_then_out` (`mv big {outside}/big; mkdir n; mv {outside}/big
     n/big; mkdir big; mv n/big {outside}/b2; mv next2/sub n/big`, then a write in `{outside}/b2`; 0.55.1 leaves the
     stale watch here too). The builder fits the steps to the harness if they need it.
   - A new test file (its name the builder's) with the in-process probes: review 5's F1 order and its control
     (`test_r5_f3_wrong.py`), its ancestor route and control (`test_nested_outgoing.py`), the overflow cases with
     `watch_map_errors()` (`test_overflow.py`, whose `watchmap.py` is the same check).
   - Run them on the base and record what fails. Expected red: the F1 order 3 of 6, the ancestor route 3 of 6, the
     overflow cases 9 of 9, and in the schedule file some orders of the shapes 8.1 names for 0.55.1. Command: the suite
     command with `tests/test_watcher_schedules.py`, the new file, `tests/test_moves_into_new_folders.py`.
2. **The design pass's code.** Port `stepback.diff`: `found` in the walk, `guarded()`, the four structures,
   `move_watches()`, the event rows of 3.3, `settle()` and `queued_events()`, the overflow restart and `watcher()`'s
   `root_lost`, and `remove_moved_away_watches()` gone. Proof: the task 1 tests pass but the ancestor route's probe
   (still 3 of 6 wrong, which shows the count is needed), and the suite in a container fails only what the base fails.
3. **The review's changes, rulings 1, 2 and 4.**
   - `outgoing` as a count (3.2): hold at a `MOVED_FROM`; let go once, at the pops 3.2 lists, and at the discard
     branch's unguarded pairing with the cookie stored again with no `wds`.
   - `settle()` per probe: the re-check before the removals goes (3.4), with the argument for no retry in a comment.
   - `follow_inner_mounts()` takes `found` and passes it to its walk; `watchFolder()` passes its own; the walk's
     docstring then names the first walk alone as the one without `found`.
   Proof: the ancestor route 6 of 6, F1 6 of 6, overflow 9 of 9; `bench.sh` with `outbusy2` at the base's number.
4. **Ruling 3 and its two rules** (3.2): the discard branch's folder `MOVED_FROM` looks among `newDirWDs` and `found`;
   the discard branch's unguarded pairing puts the watches `move_watches()` moved into `newDirWDs`; the settle's walk
   passes `newDirWDs`. Proof: `moved_sub_out_before_walk` and `back_into_new_then_out` pass with the rules, and each
   fails in some order without its rule (run each shape at review 5's bounds on the branch with that rule taken out,
   to show it is needed, then put it back; task 3's release-once rule stays in, as the design pass's expiry would make
   rule 1's stale watches `leaving` at the quiet read and hide the need); every shape of the schedule file passes;
   `bench.sh` with `renamesinnew` at 2,000 and 20,000. If `renamesinnew` misses the base's numbers, stop and report
   them to the main session (section 12, item 3).
5. **The docs** (section 6), word for word: docs/limitations.md and the three README lines. The user approved the
   entries; the main session writes them, or tells the builder to.
6. **The gates of 8.2**, on the branch.

## 11. Left to the builder

- Names, comments and DEBUG lines; how `move_watches()` hands back what it moved; how the probes fold into the suite;
  the order of the commits (the task 1 tests may land with the code they need, so that no commit of the branch is red).
- Log levels, but for the lines of sections 3.6 and 5, which the limitations quote and their revisits read. The
  settle's copy line comes once per folder renamed inside a folder made in the batch, so it stays one line, like the
  walk's own.
- If a shape of task 1 does not fail without its rule, say so and keep it as a regression shape; the rule then rests
  on its argument in 3.2, and the main session decides whether it stays.

## 12. Calls to confirm

Each ruling that was the main session's, each call this spec made on its own, and each change of behaviour against
0.55.1:
1. **`outgoing` as a count** (ruling 1, review finding 1). This spec adds that each move-out lets its watches go once:
   the discard branch's unguarded pairing stores its cookie again with no `wds`, so its expiry neither lets go a second
   time nor makes those watches `leaving` (the review's patch let go at both). Reasoned, not run.
2. **`settle()` per probe, no retry** (ruling 2, finding 2), with the review's argument (3.4).
3. **The discard branch's scan over `newDirWDs` and `found`** (ruling 3, finding 3, for the user's "as light and as fast
   as possible"). This spec adds the two rules it needs (3.2): the discard pairing's moved watches go into `newDirWDs`,
   and the settle's walk passes `newDirWDs`. Not run. Timed alone, the scan costs 0.086 s against 1.53 s for 2,000
   renames, but grows with the square of the folders made since the last take, where 0.55.1 pays nothing. If
   `renamesinnew` misses the base, the choice is the main session's: accept it; skip the scan when the same read holds
   the move-in of the same cookie into a watched folder (that move-in's walk finds the watch); or the index of paths
   of the lightness round.
4. **`found` through the inner-mount walk** (ruling 4, finding 4). It is not in the review's saved patch.
5. **The note's edits** (the main session's): limitation 2 cut to the measured statement; the residual races cover
   `found`, `doubtful` and `leaving` probes alike; the mergerfs probe as fact D.
6. **The gates:** the ancestor route's shape and probe, and `outbusy2` and `renamesinnew` with the base's numbers as
   the bar, are the main session's; this spec adds ruling 3's two shapes, `renamesinnew` at 20,000, the fuzz at seeds
   0 to 29,999 (v16's gate; the design pass ran 0 to 5,999) and the copy count again.
7. **The overflow entry:** "one sentence in the existing overflow entry" read as the deferred entry rewritten in place,
   with a new heading and kind, the window as its one sentence.
8. **Three README lines**, one for each new limitation (section 6).
9. **Version and base:** 0.55.3, from round22 with main merged in once 0.55.2 is there.
10. **More INFO lines than 0.55.1:** rule 3's copy line, the settle's copy line (once per folder renamed inside a
    folder made in the batch, among others; those copies cost no bytes) and the overflow's restart line.
11. **New copies** (limitation 1) and **a change one version late** (limitation 2): approved by the user.
12. **The watches of a folder that left are removed at the first empty queue after its move-out expires**, not at the
    expiry; a probe with a read unhandled was R5's failure.
13. **Kept from 0.55.1 on purpose:** the first walk without `found` (the review left it out of this round);
    `raise_queue_limit_for_removals()`; the two passes over every watch at a folder move.
14. **An inner mount in a folder made since the last take** (section 4): proposed not an issue; 0.55.1 is the same.
15. **Tests changed for the prototype** (the design pass's call): the session restarts the watch after an overflow, as
    `watcher()` does; the session knows `exchange`; `tests/harness.py` gains `watch_map_errors()`; v16's 56-shape
    schedule file runs on 0.55.1's walk hooks, without its two `WatchTree` asserts.
16. **Not run on any code yet:** ruling 3 and its two rules, the release-once rule, and the 99 shapes at review 5's
    bounds and the fuzz with the review's changes; `found` through the inner-mount walk ran only in the review's runs.
    The real daemon ran only through the VM suite's tests that start it, on the design pass.
