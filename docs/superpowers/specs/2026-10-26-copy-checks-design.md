# Round 10: copies trusted only once on disk, a matching time for full comparisons, no phantom after a move-out

Version 0.46. Three of the four items the user deferred to round 10 on 2026-10-26 (docs/limitations.md). The fourth,
files written through mmap, is researched in this round and decided with the user; it is not built here.

## The user's words

- On copies that may not be on disk yet (asked whether to flush every copy): "I am thinking this is less of a big deal
  because we are a backup tool? compare to cossting every single write, (fine on our setup but maybe very costly on
  network vaults?) maybe a full compare is less costly? considering this will only happen on power loss?" Then, offered
  "Round 10 adds a power-loss test (a newest copy left short, then a restart re-copies it) and flushes a copy just before
  it is marked checked": "Defer to round 10 (Recommended)".
- On full comparisons reading every changed entry's xattrs (offered "the database records when each batch or comparison
  last found the vault matching, and that becomes the bound (one meta key)"): "Defer to round 10 (Recommended)".
- On the phantom (offered "round 10 makes the check after a batch also look at paths whose move-out is still waiting for
  its pair"): "Defer to round 10 (Recommended)".
- On tonight's work: "Build the 3 agreed, research mmap (Recommended)", then "I am going to sleep so please work on your
  own until I check back in."
- On mmap: "I think qbit torrent and related stuff may use mmap? for my use case of reverberator it probably does not
  matter as I am not versioning qbit downloaded stuff ( lol ) but maybe for some user? so let's put some effort into it
  but I do not expect it to be common use case. if unable to do this cleanly I think it also make sense to put as
  limitations."
- Standing: nothing is merged, pushed or restarted without the user; known limitations and deferrals need the user's OK
  before they are written down.

## Goal 1: a copy is recorded as checked only once it can be on disk

Today every file a backup copies stays unchecked in the vault database until delta generation reads it back from the
vault (size, mtime, hash of its last 64 KiB) and records it checked; a copy that does not match is copied again. A full
comparison runs at every restart, so after a power loss the restart reads back every unchecked copy. The gap: a later
batch's check, or a restart within seconds, can read a copy back from the page cache and record it checked before its
bytes reach the disk; a power loss then leaves a short copy that nothing reads back again.

**Rule (revised 2026-10-27 night, after Task 1's review; see the call below):** a comparison stores a regular file's
read-back as checked only after a successful sync of the vault's filesystems made in that comparison. Before storing its
first such record, the comparison syncs once: `syncfs` (through ctypes; Python has no `os.syncfs`) on each mergerfs
branch that holds the job vault, found as round 9's per-branch flush finds them, or on the vault's own filesystem when it
is on no pool. If any sync fails or cannot be made, every file record that comparison stores is kept unchecked (the record
read is still stored, so the row is no longer unverified), and a later comparison tries again; the failure is logged once
per comparison as a warning. A comparison that stores no checked file record makes no sync: most batches' checks, whose
fresh copies stay unchecked (`read_copied_record()`, `read_version_record(fresh=True)`). Nothing is flushed on the write
path.

- Why it is enough for a power loss: `syncfs` returns only once every dirty page of that filesystem is written, so every
  copy read back in the comparison (all made before it) is on disk once it succeeds.
- What it does not cover (an open question for the user, not written down until they rule): a data-writeback I/O error
  is reported once (errseq), to the first `syncfs` after it, so that comparison keeps its copies unchecked and warns; a
  later comparison's sync, or another job's or process's on the same disk, gets 0, and its read-back from the page cache,
  which still holds the good bytes, records the copy checked; after a reboot the copy reads back zeroed or short, and no
  comparison reads it again. XFS does not shut down on a data-write error (probed on a dm error target). The warning is a
  log line only (firewatcher alerts on FAILED, UNREADABLE and STOPPED). A fix, if the user wants one: a failed sync is
  remembered per branch until the next reboot (a marker under /run), and while it is there every comparison keeps that
  pool's file records unchecked, so the restart after the reboot reads them from disk.
- The sync sits where the records are stored (`compare_scopes`' settling, the caller's thread), not in
  `read_vault_record()`, which runs on the compare pool; the read-backs themselves are unchanged.
- Mismatch handling is unchanged: a copy whose read-back does not match its record is copied again.

**My call, back to the agreed words:** the user agreed to "flush a copy just before it is marked checked", weighing the
cost of "every single write". Task 1 first built an age rule instead (a copy younger than 600 s by its ctime stays
unchecked, nothing flushed). Its review showed that route relies on the kernel's writeback timing and the clock, misses
an isolated data-writeback I/O error (which does not shut XFS down; only log and metadata errors do), and re-reads young
copies at every comparison inside the window. One `syncfs` per comparison that marks copies checked is the agreed flush,
at one flush per comparison instead of one per copy (an fsync of a clean XFS file still issues a device cache flush, so a
per-copy flush would pay tens of thousands after a week of backups), and it needs no age, no clock and no window. Its
cost: a comparison that checks copies waits until the vault disks' dirty data, other writers' included, is written: about
1-2 s with the disks idle, up to ~15-50 s during a download burst on the same disks (dirty limit ~2-2.8 GB on HDDs), more
if the writes are seek-bound; other jobs and readers go on meanwhile. On the live jobs that is a restart's or a failed
attempt's full comparison (about 6 of the 8 jobs read something back from the vault at a restart), and a batch check that
meets an older unchecked copy or a moved or renamed file (its rows are read back through a link): about one a day in the
Oct 23-26 logs. Listed in Calls to confirm.

**Tests:**
- The power-loss test the user agreed to: a backup copies a file; a later batch's check reads that copy back while the
  vault sync fails (patched), so it stays unchecked (0.45 recorded it checked from the page cache); the copy is then lost
  as a failed writeback leaves it, (a) truncated to a shorter or empty file, and (b) its bytes replaced with zeros of the
  same length and its mtime set back; a restart's full comparison logs that the copy does not match its record and copies
  it again, and the new version restores the right bytes. On 0.45, both cases after the later batch's read-back are not
  caught.
- A comparison that reads back an unchecked copy syncs exactly once before storing it, and stores it checked when the
  sync succeeds; a comparison with many such copies still syncs once.
- When the sync fails, every file record of that comparison stays unchecked, one warning is logged, and the next
  comparison syncs again and records them checked.
- A batch check that stores no checked file record makes no sync.
- The real helper on the test's filesystem succeeds (no patch), and on a fake pool it syncs each branch that holds the
  job vault.

## Goal 2: a full comparison's xattr bound is the time the vault last matched the tree

Today a full comparison compares the xattrs of every entry whose ctime is at or after the time the version before the
newest was made (`full_comparison_since()`, minus `VERIFY_CTIME_MARGIN_SECONDS`). After a version that changed every
entry that is every entry: panruixin_files' restart comparison took 252 s instead of 15-21 s, and stays that slow until
that job's next version.

**Rule:** a meta key, `matched`, JSON `[version folder name, wall clock ns]`, says from when the vault is known to match
the whole tree. It is written only in the final commit of a backup attempt (the backup's commit, or its "No differences"
commit), in the same transaction, never in the commit `delta_generate_backup_entries()` makes of what it read:

- It **advances** only when that attempt saw the whole tree: a full comparison of the whole tree (a restart's, a failed
  attempt's, an overflow's, a follow-up's, or V0), or a fresh batch (not round-tripped: not resumed from the pending file
  nor handed back after a failure), in both cases with no inner mount paused. The time is, for a batch, the wall clock
  time at which the watcher began the latest inotify read whose events were all queued before the batch was taken (the
  queue carries it, set under its lock, as `first_wall_ns` is); for a full comparison, that same time as of when it began.
  Every change made before that read began has its event (or the overflow marker) in this batch or an earlier one.
- Otherwise it is **carried forward**: when the key named the version this attempt builds on, the new commit writes the
  key's old time with the new version's name; else it writes nothing.
- `full_comparison_since()` uses the key's time when it names the newest committed version; otherwise (0.45 vaults, a
  version the scan rolled back, no key) it falls back to today's rule. The margin is still taken off. The scans of
  folders that came back (`compare_scanned_folders()`) keep today's rule: a batch taken after a paused mount returned
  but before its scan event was queued must not move their bound past that mount's changes.
- A scans-only batch that never reaches `do_backup()` writes nothing.
- Why the version name: a commit the scan later rolls back (a cut-off commit) must not leave a time that claims more than
  the vault holds; naming the version makes such a key fall back.
- Written in the same transaction as the commit it describes; a failed attempt writes nothing, so the older, earlier
  time stays.
- The first full comparison after the 0.46 restart still falls back (no key yet), so panruixin_files pays once more;
  every later one is cheap.

**Tests:** after a fresh batch commits, `matched` names the new version and that batch's read time; after a "No
differences" commit it names the newest version and the later time; a full comparison then compares xattrs only of
entries whose ctime is after it (count os.listxattr calls); a resumed batch, a handed-back batch and a batch with a paused
inner mount carry the old time forward (an xattr set while the daemon was down still reaches the follow-up comparison's
version); a key naming another version, or no key, gives today's bound; a cut-off commit's key is not used once the scan
has rolled the version back; the delta generation's own commit writes no key.

## Goal 3: a move-out whose pair cannot come any more goes into the batch it belongs to

`mkdir d; mv a.txt d/a.txt` in one batch: the move into the brand-new folder is not seen (its watch is added after), so
the move-out waits for a pair (`max(min_snapshot_delay_seconds, MOVE_PAIR_TIMEOUT_SECONDS)`, 1 to 12 h on the live
jobs) before it becomes a delete, and the versions made meanwhile show a.txt at its old place as well as d/a.txt; a
move-out that is a batch's last event can miss that batch altogether.

**Rule:** when the watcher hands a batch over at the quiet hand-over (no events for `min_snapshot_delay_seconds`), it
first queues every pending move-out as its delete, exactly as the timeout does today (the cookie dropped, so a late
move-in is a create; the moved-away watches removed). A rename queues its move-in right after its move-out, so a read
that returns nothing means no pair is still coming: no grace is needed. The max-delay hand-over (while events flow,
before the current read's events are handled) keeps today's behaviour, so a split pair is never broken; the timeout
stays as it is.

- Left over: a move-out pending at a max-delay hand-over still shows its phantom in that version. That is a would-be
  known limitation for the user, not written down until they agree.
- A create at the move-out's source already queues the move-out first (`queue_pending_move_from_at()`), so the order is
  kept.
- The batch then holds the delete of a.txt and the create of d/a.txt (the new folder's walk), and the check after the
  batch compares a.txt as a touched path, as the user's words asked.

**My call against the agreed words:** the user agreed to "the check after a batch also compares paths whose move-out is
still waiting for its pair". Handing the expired move-out over as its delete does that (its path is touched) and also
keeps the phantom out of the replay, with no new event kind and no pending-batch format change. Listed in Calls to
confirm.

**Tests:** `mkdir d; mv a.txt d/a.txt` in one batch gives a version with only d/a.txt; a move-out that is a batch's last
event lands in that batch; a move-out pending at a max-delay hand-over still pairs with a move-in read after it (inject
the events); a create at a move-out's source after the move keeps both in the right order; a folder moved out of the
tree just before a quiet hand-over is gone from that version and its watches are removed.

## Goal 5: a restart whose pending batch holds only scans still compares the whole tree (verify, then fix)

The spec check reports: at startup, a pending file holding only scan events is resumed with `round_tripped` False and no
follow-up full comparison, so changes made while the daemon was down outside those folders (contents too, not only
xattrs) are not compared until the next full comparison. A missed change is a wrong result. The builder first writes the
failing test (stop with scan events pending, change a file elsewhere while it is down, restart: the next version must hold
the change); if it passes on 0.45, this goal is dropped as not an issue, with the reason in the report. Otherwise any
resumed pending batch counts as round-tripped, so the follow-up full comparison runs.

## Goal 6: a folder made while the watcher walks its parent is watched (pre-existing, found by Task 2's review)

`initializeFolderWatchers()` lists the whole subtree (`get_all_folders()`) and only then adds the watches. A folder made
inside an already-listed folder before that folder's watch is added raises no event (no watch yet) and is not in the
list, so it is never watched, nor is anything made under it later: `cp -r`, `tar x` or rsync of a tree into a watched
folder race the walk, and so does the root's startup walk. Its recursive copy backs up what is there at copy time, and
every later change in it is missing from the versions until the next full comparison (in practice the next restart). A
silent wrong result, so worth fixing (the user's rules); added to this round by the main session while the user slept,
listed in Calls to confirm.

**Rule:** `initializeFolderWatchers()` adds each folder's watch as the walk yields it, before the walk reads that folder
(`iter_tree_entries()` yields a folder before its contents and reads nothing up front): a folder made in it after its
watch is added raises its event, and one made before is in the walk. A folder that then turns out unreadable has its
watch removed again and is logged as today. The counts given to the resource manager stay right (one watch each, the
ones removed given back). Nothing else changes: the same folders end up watched when nothing races the walk.

**Tests:** a folder made inside a listed folder between the listing and the watch (simulate the race by making it from
the walk, the way the review's probe does: scratchpad r10/review-t2/copy/tests/test_probe_walk_race.py) is watched, and a
change in it is queued; the unreadable-folder and skip-list behaviour of today's tests is unchanged; the watch count
given to `irm` matches the watches held.

## Goal 7: a batch taken without the watcher's signal does not leave new folders' events discarded (pre-existing)

Events in a folder created during a batch are discarded until that batch is taken, as its recursive copy holds the
folder. The watcher learns of the take only through `processPending` and the flag it set: a take it did not signal (the
backuper's startup take at every attempt, which follows the resume check's whole-tree walk when a pending file exists;
a restarted watcher, or a retry's new one, finding its predecessor's flag still set) leaves `newDirWDs` uncleared, and
every later event in those folders is discarded; if all activity is there, nothing is ever queued. A silent wrong result
(review probe: scratchpad r10/review-t2/copy/tests/test_probe_newdirs.py); added to this round as Goal 6 was.

**Rule:** `ChangeEventQueue.take()` counts takes (`takes`, an int on the queue, under the same lock as every queue use).
Right after each read returns, the watcher compares the count with the one it saw last; when it moved, it clears
`newDirWDs` and resets `lastProcessTime`, as the signalled take does today. `processPending` goes. A new watcher starts
from the queue's current count. Why right after the read: an event read before the take happened before it, so the
recursive copy (made after the take) holds it; an event read after the take may come after the copy passed that entry,
and must be kept (a kept duplicate costs nothing). The same placement also closes today's window in which a copy finished
before the watcher's next loop could still have its folder's events discarded.

**Tests:** after an unsignalled take (take the queue directly, no flag), a change in a folder created before the take is
queued; after a signalled take, the same as today; a new watcher started while the queue's flag is still set discards a
new folder's events only until the next take; the order: an event read before the take is discarded, one read after it
is kept (scripted reads with `scripted_watch`).

## Goal 8: a folder renamed before the watcher handles its create is watched at its new path (pre-existing)

`mkdir d; mv d e` (or a tool that makes a folder under a temporary name and renames it) can rename the folder before the
watcher handles d's CREATE: `initializeFolderWatchers()` then finds d gone and returns -1 silently, and the cookie-matched
move d -> e only renames the watches d already had, which are none, so e is never watched and every later change made
in it never reaches a batch. Found by Task 2's second-opinion stress run (327 changes and 45 renames lost in two 60 s
runs, almost all under folders renamed within a millisecond of their mkdir; repro
scratchpad r10/haiku-t2/repro_05e1d07.py). A silent wrong result; added to this round as Goals 6 and 7 were.

**Rule:** when a folder moves in from a known source (the cookie-matched move) and no watch maps to its old path, the
watcher adds the destination's watches as for a new folder (`initializeFolderWatchers()` with `newDirWDs`, so its
events are discarded until the batch is taken, the batch's recursive copy holding its contents). A folder that had
watches is handled as today. A chain of renames before the watcher catches up ends watched at its last name.

**Tests:** scripted reads (`scripted_watch`): CREATE|ISDIR d, then MOVED_FROM d / MOVED_TO e with the same cookie, with d
gone when its create is handled; e gets a watch, and an event under e's new wd is recorded after the next take; a chain
d -> e -> f ends watched at f; a folder that had watches moves its watches as today (no new add_watch). A real watcher:
`mkdir d; mv d e` in quick succession, then a file in e reaches a batch.

## Goal 4: version 0.46, docs

- `__version__ = 0.46` and pyproject.toml `version = "0.46"`.
- docs/limitations.md: remove the three entries this round closes ("Copies marked checked before they reach the disk",
  "Full comparisons read every changed entry's xattrs since the previous version", "A file moved into a folder made in
  the same batch shows at its old place too"); the mmap entry stays until the user decides. README: remove the phantom's
  known-limits line; rewrite line 12's statement of today's bound ("since the version before the latest was made") to the
  matched time; one line says a copy is recorded checked only after the comparison that reads it back has synced
  the vault's disks (syncfs, once per comparison), and that a failed sync keeps it unchecked.

## Non-goals

- mmap writes (researched separately; the user decides).
- Any change to the change-list, pending-batch or history formats. The new meta key is an addition the older daemon
  ignores.
- Flushing copies, folders or the vault on the write path, or once per copy.

## Constraints

- Work in a worktree (`.worktrees/copy-checks`, branch `copy-checks`); never in the live checkout; never under /mnt/jank,
  /mnt/impulse or /mnt/klein; never `sudo sysctl`; tests at 2 processes at most.
- Code must run on the live venv's older libraries and the worktree's; both full suites pass.
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

Exact names beyond those above, and how the read time reaches the final commit.
