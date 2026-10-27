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

**Rule:** a record read back from the vault for a regular file is stored as checked only when the copy it read (the
chain end) last changed at least `CHECKED_COPY_AGE_SECONDS` = 600 ago, by its `st_ctime`. A younger copy is stored
unchecked (the record read is still stored, so the row is no longer unverified), and a later read-back records it
checked once it is old enough. Nothing is flushed: no fsync on the write path or the read path.

- Why 600 s: this host writes dirty pages back after 30 s (`vm.dirty_expire_centisecs` 3000) at 15 s intervals
  (`vm.dirty_writeback_centisecs` 1500); ten times that covers a congested writeback. Copies older than that are trusted
  to be on disk, as they are today.
- A copy whose ctime moves later (a prune's hard link changes its link count) only waits again: never less safe.
- The rule applies wherever a read-back is stored as checked: compare_entry's unchecked and unverified branches and any
  other caller that stores `read_vault_record()`'s file record with `unchecked = 0`. Records of copies the backup just
  made already stay unchecked (`read_copied_record()`, `read_version_record(fresh=True)`).
- Mismatch handling is unchanged: a copy whose read-back does not match its record is copied again, young or old.

**My call against the agreed words:** the user agreed to "flush a copy just before it is marked checked". Leaving a young
copy unchecked instead gives the same safety with no fsync at all: copies older than the window rely on writeback in both
routes, and a young copy is simply not trusted yet. It is simpler, has no failure path, and costs nothing, which is what
the user's words weigh ("compare to cossting every single write"). An fsync of a clean XFS file still issues a device
cache flush, so a restart soon after a large batch would otherwise pay one flush per copy. Listed in Calls to confirm.

**Tests:**
- The power-loss test the user agreed to: a backup copies a file; its vault copy's bytes are then replaced with zeros of
  the same length and its mtime set back (what a lost writeback leaves); a restart's full comparison logs that the copy
  does not match its record and copies it again; the new version restores the right bytes. (No test covers this today.)
- A copy read back by a later batch's check while younger than the window stays unchecked; the same read-back after the
  window (ctime set back, or the constant patched) records it checked.
- A restart's full comparison right after a backup leaves that backup's copies unchecked; one after the window records
  them checked.

## Goal 2: a full comparison's xattr bound is the time the vault last matched the tree

Today a full comparison compares the xattrs of every entry whose ctime is at or after the time the version before the
newest was made (`full_comparison_since()`, minus `VERIFY_CTIME_MARGIN_SECONDS`). After a version that changed every
entry that is every entry: panruixin_files' restart comparison took 252 s instead of 15-21 s, and stays that slow until
that job's next version.

**Rule:** every commit of the vault database that records what the vault holds (a backup's commit, and the "No
differences" commit of a batch or a full comparison) also writes a meta key, `matched`, holding the folder name of the
newest committed version it describes and a wall clock time in ns: for a batch, the time the backuper took the batch;
for a full comparison, the time it began. `full_comparison_since()` uses that time when the key's version is the newest
committed version; otherwise (0.45 vaults, or a version the scan rolled back) it falls back to today's rule. The margin
is still taken off by the bound.

- Why the take time: every event read before the take is in the batch, so after its commit the vault matches the tree as
  of the take; a change lost later (daemon down, overflow) happened after it, apart from read lag, which the 10 s margin
  covers. A full comparison's own start is the same for its result.
- Why the version name: a commit the scan later rolls back (a cut-off commit) must not leave a time that claims more than
  the vault holds; naming the version makes such a key fall back.
- Written in the same transaction as the commit it describes; a failed attempt writes nothing, so the older, earlier
  time stays.
- The first full comparison after the 0.46 restart still falls back (no key yet), so panruixin_files pays once more;
  every later one is cheap.

**Tests:** after a batch commits, `matched` names the new version and the take time; after a "No differences" commit it
names the newest version and the later time; a full comparison then compares xattrs only of entries whose ctime is after
that time (count os.listxattr calls); a key naming another version, or no key, gives today's bound; a cut-off commit's
key is not used once the scan has rolled the version back.

## Goal 3: a move-out whose pair cannot come any more goes into the batch it belongs to

`mkdir d; mv a.txt d/a.txt` in one batch: the move into the brand-new folder is not seen (its watch is added after), so
the move-out waits up to 30 s (`MOVE_PAIR_TIMEOUT_SECONDS`) for a pair before it becomes a delete, and the versions made
meanwhile show a.txt at its old place as well as d/a.txt.

**Rule:** when the watcher hands a batch to the backuper (both places that set `to_process_flag`), it first queues every
move-out that has waited longer than a short grace, `MOVE_PAIR_GRACE_SECONDS` = 2, as its delete, exactly as the timeout
does today (the cookie dropped, so a late move-in is a create; the moved-away watches removed). A move-in from the same
rename is read within milliseconds of its move-out, so after the grace no pair can still come. The 30 s timeout stays for
move-outs while no batch is handed over.

- The quiet hand-over comes after `min_snapshot_delay_seconds` without events, so every pending move-out is past the
  grace; the max-delay hand-over happens while events flow, so a move-out read in the last 2 s keeps waiting for its pair
  in the same read stream.
- A create at the move-out's source already queues the move-out first (`queue_pending_move_from_at()`), so the order is
  kept.
- The batch then holds the delete of a.txt and the create of d/a.txt (the new folder's walk), and the check after the
  batch compares a.txt as a touched path, as the user's words asked.

**My call against the agreed words:** the user agreed to "the check after a batch also compares paths whose move-out is
still waiting for its pair". Handing the expired move-out over as its delete does that (its path is touched) and also
keeps the phantom out of the replay, with no new event kind and no pending-batch format change. Listed in Calls to
confirm.

**Tests:** `mkdir d; mv a.txt d/a.txt` in one batch gives a version with only d/a.txt; a move-out read in the last 2 s
before a max-delay hand-over still pairs with its move-in; a create at a move-out's source after the move keeps both in
the right order; a folder moved out of the tree just before a hand-over is gone from that version and its watches are
removed.

## Goal 4: version 0.46, docs

- `__version__ = 0.46` and pyproject.toml `version = "0.46"`.
- docs/limitations.md: remove the three entries this round closes ("Copies marked checked before they reach the disk",
  "Full comparisons read every changed entry's xattrs since the previous version", "A file moved into a folder made in
  the same batch shows at its old place too"); the mmap entry stays until the user decides. README: remove the phantom's
  known-limits line; add a design note for each goal in the style of the existing ones.

## Non-goals

- mmap writes (researched separately; the user decides).
- Any change to the change-list, pending-batch or history formats. The new meta key is an addition the older daemon
  ignores.
- Flushing copies, folders or the vault on the write path.

## Constraints

- Work in a worktree (`.worktrees/copy-checks`, branch `copy-checks`); never in the live checkout; never under /mnt/jank,
  /mnt/impulse or /mnt/klein; never `sudo sysctl`; tests at 2 processes at most.
- Code must run on the live venv's older libraries and the worktree's; both full suites pass.
- The user's rules: /mnt/optane/work/agent-rules/RULES.md.

## Left to the builder

Exact names beyond those above, where the age check sits, and how the take time reaches the commit.
