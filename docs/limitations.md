# Known limitations and deferred work

Each entry here has the user's OK. Reviewers read this file first and don't raise these entries again.

### The conversion from 0.54 judges links by their text

- **Kind:** known limitation.
- **What the operator sees:** until a job's one-time conversion ends, and during it, a symlink of the user's whose
  text has the shape of a 0.54 chain link (for example `a/U -> ../../V<n-1>--<timestamp>/a/U`) is taken for the
  vault's own link. It reads, restores and converts as the file it names, not as a link. A vault whose manifest was
  lost with a hot journal is read the same way and logs a Note; that case is by reading the code, not tested. Once a
  job is converted, its versions are plain trees and no link is judged by its text.
- **Why:** a 0.54 vault holds nothing that tells such a link from the daemon's own. Telling it would need a new
  per-version record for a format that is going away.
- **Revisit when:** the 0.54 reader goes, a release after 0.55; this entry goes with it.
- **Approved:** 2026-10-22, "Leave it (Recommended)"; 2026-11-04, "Accept for the conversion"; 2026-11-06, "Accept
  (Recommended)" for reading a vault before its conversion.

### World-readable vault database and change lists

- **Kind:** known limitation.
- **What the operator sees:** any local user can read `.reverberator_manifest.sqlite` and the `V<n>--…modified_contents.nsv`
  change lists in a job vault. Together they list every backed-up file name and its size, the names in a job that holds secrets included.
- **Why:** making them root-only (0600) would leave only root able to run status, history and restore. The user chose to
  keep them readable.
- **Revisit when:** a vault is shared with users who must not see other jobs' file names.
- **Approved:** 2026-10-23, the user's choice "Known limitation".

### Size records rounded to 2 decimals

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** each version's size is stored rounded to 2 decimals in its change list's name (for example
  `11.54_MiB`). After a restart, the vault's total can be off by up to 0.5% per version, so a prune can remove the oldest
  version slightly early.
- **Why:** it is small, it errs toward removing early and never toward growing past the limit, and exact sizes would
  change the change-list name format.
- **Revisit when:** a vault's size limit needs to be met exactly.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### Versions more than 40 back cannot be browsed by hand

- **Kind:** known limitation.
- **What the operator sees:** a path k versions older than the newest passes through up to k forward links, and every
  symlink in the vault's own path counts as well. Past the kernel's 40 (about 20 while Docker changes mounts),
  browsing by hand gives "too many levels of symbolic links". restore and history work. The live maximum keep-N is 14.
- **Why:** re-pointing links would cost writes on every cycle.
- **Revisit when:** a job keeps more than 20 versions and is browsed by hand.
- **Approved:** 2026-11-04, "Known limitation".

### A SnapRAID fix while reverberator runs

- **Kind:** known limitation.
- **What the operator sees:** a replaced disk is mounted, so jobs resume while `snapraid fix` restores its files.
- **Why:** nothing tells a disk being rebuilt from one that is whole.
- **Revisit when:** it bites.
- **Approved:** 2026-10-23, the user's choice "Known limitation, README says stop it (Recommended)".

### Kernels before 6.8 and the pool check

- **Kind:** known limitation.
- **What the operator sees:** on a kernel before 6.8, a disk of a pool swapped very quickly for another may not pause its
  jobs. This host runs 7.0.
- **Why:** statx gives no unique mount id before 6.8, so the check falls back to mountinfo ids, which the kernel reuses.
- **Revisit when:** reverberator runs on an older kernel.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Kernels without f2fs's checkpoint status

- **Kind:** known limitation.
- **What the operator sees:** on a kernel whose f2fs has no `stat/cp_status` in sysfs (before about 6.1), a failed f2fs
  disk (a vault on one SSD, or a pool's disk) is warned of once and taken for whole, so its jobs do not pause; they fail
  on their writes and retry instead. A removed device or a missing f2fs sysfs folder still pauses them. This host runs
  7.0, which has the file.
- **Why:** that file is the only place f2fs reports a checkpoint error; without it a failed f2fs reads like a healthy
  one, and taking a disk that cannot be told for failed would stop its jobs for good.
- **Revisit when:** reverberator runs on such a kernel.
- **Approved:** 2026-11-04, the user's choice "Both (Recommended)".

### A disk that is dying but not yet failed

- **Kind:** known limitation.
- **What the operator sees:** jobs keep writing to a dying disk until its filesystem shuts down (XFS) or flags a
  checkpoint error (f2fs); only then do they pause, as for a missing disk.
- **Why:** catching it earlier needs SMART or I/O-error watching, which is a separate tool.
- **Revisit when:** a disk fails without its filesystem noticing.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Two pools out at once are reported one after the other

- **Kind:** known limitation.
- **What the operator sees:** when a vault disk and a monitored disk are both missing, an idle or batching job's waiting
  marker names one pool; once that pool is back, a second marker names the other. Nothing is lost.
- **Why:** each wait is for one path, and a combined wait would add a part for a rare case.
- **Revisit when:** the two-step report confuses.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Files written through mmap

- **Kind:** known limitation.
- **What the operator sees:** a write through mmap raises no inotify event, so 0.47 relies on the mtime it moves: an
  attribute-only change whose mtime moved copies the file, and a full comparison (a restart, or the job's Full
  Comparison Interval when set) copies a file whose mtime moved. Every comparison also hashes a file's last 64 KiB, so
  what is left concerns stores before that tail (none, for a file of 64 KiB or less): (1) a second store into a page
  still dirty from an earlier one moves no mtime, so a copy taken between them misses the later store until the mtime
  next moves; (2) an mmap write followed by setting the mtime back is not seen; (3) a copy that a 0.46 or older daemon
  synced after an mmap write (old bytes under the new mtime) stays wrong until the file is written again. And (4) a file
  written only through mmap (a chat app's MMKV files) is backed up only at its next normal write, a restart, or the job's
  Full Comparison Interval if one is set.
- **Why:** no inotify or fanotify flag reports mmap stores (round 10's research: scratchpad r10/mmap/report.md); the
  kernel moves the mtime only on the first store into a clean page.
- **Revisit when:** a kernel interface reports mmap stores, or a job's files are seen stale this way.
- **Approved:** 2026-10-26, "let's defer. let's see if we can catch something, or if we can know if a file is mmaped";
  2026-10-27: "should we trust mtime change as indication of file is changed to just do the copy? this way we only do
  one read and one write not three reads and one write in most cases", then "Keep it, round 11 (Recommended)", and for
  the scheduled comparison "Configurable per job and default off"; 2026-10-28, on what is left after 0.47: "Known
  limitation, as listed (Recommended)". The entry "A file moved and then touched in one batch is copied again" was
  removed the same day ("Remove it (Recommended)"): every touch that moves the mtime now copies the file.

### Swaps in one batch are repaired by copies

- **Kind:** known limitation.
- **What the operator sees:** a swap collapsed in one batch (`mv a t; mv b a; mv t b`) copies both files again instead of
  renaming them, and two folders whole: the replay renames each onto the other's old place, the comparison after the
  batch finds both different and copies them, and nothing is logged at warning or error level. An exchange of two entries
  by one rename (`mv --exchange a b`, `RENAME_EXCHANGE`) in one batch is repaired the same way. A file swapped with a
  folder keeps one renamed and copies the other, logging `Not renaming … to …: … is a folder in the version, as an earlier
  move of the batch left it; doing delete & copy instead` (or `is not a folder`) at ERROR level, with no traceback
  (firewatcher does not alert on it). The result is right.
- **Why:** renaming them in one step would need a change-list format change.
- **Revisit when:** the change list's format changes for another reason.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)"; corrected 2026-10-29, "Correct the entry
  (Recommended)".

### A move that another change of the batch outran is copied

- **Kind:** known limitation.
- **What the operator sees:** a move whose source, or the folder it goes into, is not in its place in the version when
  the move replays, because another change of the same batch (a move, a delete, or a folder made after it) replays in
  another order, logs one warning, `Not renaming … to …: its source or the folder it goes into is not in the version;
  copying it instead`, with no traceback (firewatcher does not alert on it), and the entry is copied once more: its files
  are written to the vault again in full, a copy instead of a rename. Some of these shapes also log a warning `Not tracking
  <path>: source no longer exists` for a copy the batch left behind. Examples: `mv d e; mkdir e/sub; mv x e/sub/x` (x
  copied), `mv a/f g; mv a A; mv g h` (h copied), `mkdir x; mv old x/f; mv x y` (y/f copied), `mv D/sub t; rm -r D; mv t
  D` (D's files copied), `mv d D; mv D/k z; rm -r D` (z copied), and, with a new file f, `echo new > f; mv f d/g; mv d D;
  mv D/g h; mkdir d; mv q d/g` (q copied). The result is right.
- **Why:** replaying such moves so the version follows them is a larger change to the batch's collapse and replay, for
  one extra copy in a rare order.
- **Revisit when:** the warning shows up often in the live logs.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)"; widened 2026-10-29, "Widen the known
  limitation (Recommended)", then for the older collapse shapes "Widen the known limitation (Recommended)".

### A move out of a folder that just left the tree is copied

- **Kind:** known limitation.
- **What the operator sees:** for the pair timeout after a folder is moved out of the tree (the larger of the job's
  minimum snapshot delay and 30 s: 60 s by default, an hour on a job whose minimum delay is an hour), anything moved
  from that folder back into the tree, as in `mv X /out/X; mv /out/X/sub sub`, is copied whole instead of renamed in the
  vault, with one INFO line, `Copying <path>, moved from <path>: a watch of the move is not settled`. Until the watcher
  next finds its event queue empty, normally at the end of that read, the same copy covers a rename in a folder moved
  onto the place of one that had just left the tree and then moved on, in either folder of a swap by one rename
  (`RENAME_EXCHANGE`), in a folder the watcher found at a place its events had not brought it to yet (a rename racing
  the walk of a folder just moved or made), and in a folder that was renamed and then renamed again, itself or a folder
  above it, before the watcher read the first rename. For the pair timeout too, a rename inside a folder that left the
  tree, made after another folder was moved to its old place (`mv X /out/X; mv Y X; mv /out/X/a /out/X/b`, or the same
  with X's parent renamed in between), is reported at X's old path: the entry named b in the folder now at X, if it has
  one, is copied whole once, with the same line. 0.55.1 renamed these. The version is right; the copy costs the moved
  entry's size once, and with a size limit it can prune older versions, as the copy of a move into a new folder can.
- **Why:** such a folder's watch can report its moves at a path another folder now has; trusting it is how a version
  kept a file's old bytes for good, and telling the two folders apart needs the watch tree of round 22's first design
  (about 815 more lines and 94 bytes a watch).
- **Revisit when:** the log shows big copies from this route often. Also when the no-copy move into a new folder gets
  its own design.
- **Approved:** 2026-11-09, the user's choice "Accept: copy (Recommended)"; then, with the window corrected to the pair
  timeout and the routes named, "Approve as corrected (Recommended)"; 2026-11-10, the rename inside a folder that left
  the tree after another took its place, "Add the sentence (Recommended)"; 2026-11-11, a folder renamed again (itself
  or a folder above it) before the watcher read the first rename, "Widen the entry (Recommended)".

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

### One folder renamed back and forth thousands of times in one batch

- **Kind:** known limitation.
- **What the operator sees:** the batch's collapse slows: 12,500 round trips of one folder take 49 s, as every event
  inside it is carried through each rename. The watcher slows too, as each of those moves also walks the folder again:
  for a folder of 5,000 subfolders (37 ms a walk) they add about 460 s of watcher time. Normal use, even 50k moves of
  different paths, stays under a second.
- **Why:** a memo that fixes it does not fit in a small, clean change.
- **Revisit when:** a real workload does this.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### Size estimates leave out a version's own small blocks

- **Kind:** known limitation.
- **What the operator sees:** with a size limit, the estimate made before a backup leaves out the real folders the
  batch makes in the previous version, about 4 KiB for each folder it touches and each folder above them (a chmod of
  3,030 folders passed a limit by 11.64 MiB on the real daemon) and the version's xattr blocks (a few KB), so a vault can
  go over its limit by that much until the next prune. It also leaves out, as 0.55.4 did, a moved file that the replay
  copies (with Only Sync Attributes off, one whose mode, owner or mtime changed, or only an extended attribute) and a move
  that falls back to a copy, so a vault can pass its size and inode limits by those copies until the next prune. The links a batch makes are in no size record, so neither `status` nor the limit sees their bytes:
  about 4 KiB each on f2fs, so one file changed in a folder of 5,000 entries took 20.6 MB of disk while the records
  rose 4 KiB, until that version is pruned. With an
  inode limit, the estimate leaves out the links the hand-over and unfolds make, so a batch can pass the limit by that
  many until the next prune: a folder of 100K entries that changes makes 100K links in that version. The sizes
  recorded after each backup are counted, each file by its size plus 4 KiB per folder, and each inode in the newest
  version that holds it, so later prunes are right.
- **Why:** counting folders means working out before each batch which folders and parents become real, on every job,
  for an overshoot that lasts until the next prune. A link's bytes differ by filesystem, so counting them needs a
  figure for each one. Counting a moved file's copy needs each move's source followed through the batch's earlier moves
  to the row it had before the batch; read at the move's own path, the row can be another file's, which counted copies
  the replay never made and pruned versions for good (12 of 13 in a review's probe), where an estimate too low only
  passes the limit until the next prune.
- **Revisit when:** a job sits at its limit and its batches touch thousands of folders, or a vault's disk fills ahead of
  its limit.
- **Approved:** 2026-10-26, "Known limitation (Recommended)"; 2026-11-05, "Extend the entry (Recommended)"; 2026-11-06,
  "Change the text (Recommended)", for the measured overshoot of the folders; 2026-11-06, "Correct the text
  (Recommended)", for the links' bytes; 2026-11-13, "Widen the entry (Recommended)", for the moved files the replay
  copies and the moves that fall back to a copy.

### A vault down to its only version can pass its size limit

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** a vault that pruning has brought down to its only version (a new vault, or a size limit
  near the tree's own size) can pass its Backup Size Limit by the size of the next change, as its only version is never
  removed: the backup adds a second version, and the next backup's prune removes the older one.
- **Why:** removing the only version would leave no backup.
- **Revisit when:** a job's size limit is close to its tree's size.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### Changes made outside the watched folder

- **Kind:** known limitation.
- **What the operator sees:** an xattr-only change made outside the watched folder (straight onto a disk of a mergerfs
  pool, such as /mnt/pool_disks/<disk>/..., or a remote write on a network filesystem) raises no event, and once a
  later batch moves the vault's matched time past it, no full comparison reads it: that xattr is missing from the
  versions until the file changes again. Content changes are still caught, by size and mtime.
- **Why:** round 10's matched time bounds a full comparison's xattr reads to what changed since the vault last matched
  the whole tree, and that bound assumes every change goes through the watched folder.
- **Revisit when:** a job monitors a network filesystem, or files are changed on a pool's disks directly.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A copy made where the vault refused a hard link

- **Kind:** known limitation.
- **What the operator sees:** on a vault whose filesystem refuses a hard link, a record is a copy, and that copy holds
  the only copy of an older version's file (a cut batch's record, or a 0.54 conversion's tree). That file can then read
  wrong in two ways: it can hold lost bytes with no alert, when another program's sync of the disk saw the copy's write
  error before the next attempt opened its handles; or it can be lost after a VAULT WRITE ERROR on that disk, when the
  batch's own flush of the record copy fails and the retry does not make the record again and replaces the tree's file.
  After a batch cut on such a vault, the next start makes the newest version the one before again by copying back each
  name the batch had recorded, where another vault would link it. A folder the batch deleted is copied back whole and
  then removed again by the replay. A disk too full for those copies fails every attempt at its scan, before any prune
  can free space. And where the batch was cut before it changed a name, the newest version's own file, flushed at the
  commit of the version before, is replaced by a copy of the record copy, which no flush is known to cover; at a name the
  retry does not copy again (under an inner mount unmounted at the start, say) the newest version keeps that copy under a
  checked row. A mergerfs pool that answers EXDEV between its disks does the same.
- **Why:** no other copy of those bytes exists.
- **Revisit when:** a vault ever shows refused hard links.
- **Approved:** 2026-11-09, the user's choice "Known limitation (Recommended)", then "Widen the entry (Recommended)"
  for the second way; 2026-11-13, "Widen the entry (Recommended)".

### A clock set back after a read was stamped

- **Kind:** known limitation.
- **What the operator sees:** if the wall clock is set back by more than 10 s after the watcher stamped a read (a fast
  hardware clock corrected after start), xattr-only changes made while nothing watched (the daemon down, an overflow, a
  failed attempt) are not compared until the next batch moves the matched time on. The installed unit waits up to
  ~5 min for chrony to sync before starting (ExecStartPre=-/usr/bin/chronyc waitsync 30 0.1), which closes the usual
  boot case; the repo's unit template documents the same.
- **Why:** the matched time is a wall clock time, compared with ctimes; a boot-clock guard would add a part for a narrow
  case.
- **Revisit when:** the clock is seen stepping back after start.
- **Approved:** 2026-10-27, the user's choices "Known limitation + unit fix (Recommended)" and "Wait in reverberator's unit
  only (Recommended)".

### A paused inner mount or an unwatched folder holds the matched time

- **Kind:** known limitation.
- **What the operator sees:** while an inner mount stays paused, or a folder stays unwatched (unreadable, or a failed
  watch), every batch keeps the vault's matched time where it was, so full comparisons read the xattrs of everything
  changed since then (slow, as before round 10) until the mount is back or the folder is watched again. Nothing is lost.
- **Why:** the matched time claims the whole tree; a time per subtree would add parts for a cost-only case.
- **Revisit when:** a mount stays away for long.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### An xattr change lost while an inner mount was paused

- **Kind:** known limitation, already in 0.45.
- **What the operator sees:** an xattr-only change on an inner mount whose event was lost while the mount was paused (the
  disk away, then back) falls outside the mount-back scan's bound and the next matched time, so it is missing from the
  versions until the file changes again. No live job has an inner mount.
- **Why:** the mount-back scan compares xattrs by the version-based bound, which does not reach back to the pause.
- **Revisit when:** a job gets an inner mount.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A move landing in the same instant a batch is taken

- **Kind:** known limitation.
- **What the operator sees:** when a batch is taken within one inotify read of a move into a new folder or out of the tree
  (mkdir d; mv f d/f), that batch's version, rarely the next one too, still shows f at its old place; later versions are
  right. A batch holding a change inside a folder that is renamed before the watcher handles the rename gives a version
  without the changed file, or without the whole folder when the change was to the folder itself; reproduced with the
  batch taken in that gap, and by reading a rename at any point while the batch runs does the same. The next version is
  right, and nothing is lost for good.
- **Why:** a move's two events can straddle one read, so a move-out is carried into a batch only once a whole read has
  passed; carrying it sooner would break a rename split by the take into a delete and a copy. A batch's comparison reads
  the live tree, so a path renamed away looks deleted; holding such a path back until a later read confirms it would
  change how every version is checked.
- **Revisit when:** it is seen on the live jobs, or a version missing a folder matters in practice.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)"; widened 2026-11-05, the user's choice
  "Known limitation (Recommended)".

### A disk that hangs while a renamed folder gets its watches

- **Kind:** known limitation.
- **What the operator sees:** a batch waits while the watcher adds the watches of a folder renamed inside the tree. If the
  disk hangs at that moment, the backuper hangs with it: status shows no wait, and after a forced kill the next start
  compares the whole tree. No wrong result and nothing lost.
- **Why:** the wait is what keeps a rename and its folder's changes in one batch, and a stop already hangs in this state;
  showing it would add parts for a state that already stalls the daemon.
- **Revisit when:** a hung disk during a rename is seen on the live jobs.
- **Approved:** 2026-11-05, the user's choice "Known limitation (Recommended)".

### A rewrite made while down that keeps size and mtime

- **Kind:** known limitation, already in 0.45.
- **What the operator sees:** a file rewritten in place while the daemon is down, at the same size and with its mtime set
  back, changed only before its last 64 KiB, is missed at the restart and kept wrong until it changes again. So is such
  a rewrite made while the daemon ran whose event a stop dropped before it was backed up, as every stop drops the queued
  changes: the start's full comparison has the same blind spot. A kill drops it the same way, and so does a failed
  backup, whose next attempt compares the whole tree with that blind spot (both as in 0.55.4). On the upgrade, the first
  0.55.5 start removes the pending-transactions file a 0.55.4 stop left in the job vault
  (`.reverberator_pending_transactions.nsv`, with one INFO line) without replaying it, so the changes it held get that
  full comparison, once. So is such a rewrite of a file under an inner mount, made while a batch that copied it was cut
  (a kill or a power loss), with that mount unmounted at the next start: the newest version keeps the bytes of the
  version before until the file changes again, with no line. So is one made while the watcher watches the tree afresh
  after an event queue overflow (about 8 µs a folder, some 0.15 s at 17,200 folders): the full comparison that follows
  has the same blind spot.
- **Why:** a full comparison checks size, mtime and the tail hash; utime cannot set ctime back, but ctime is not checked.
  Reading the whole file when its ctime is after the matched time would catch it, but making that check affordable
  needed three more parts, for a rare case.
- **Revisit when:** such rewrites are seen in practice.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)"; then 2026-10-27, on that whole-file
  check: "why do we bother?", then "Drop it, known limitation (Recommended)"; 2026-10-28, on widening it to a rewrite
  made while running whose event a stop dropped: "Widen it (Recommended)"; 2026-11-09, on the window of the watch's
  restart after an overflow: "Accept: one sentence (Recommended)"; 2026-11-13, on dropping the resume at a start: "Drop
  resume (Recommended)"; on the cut batch under a paused mount: "Add it to the rewrite entry (Recommended)".

### A rewritten rule row keeps the defaults it was given

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** when reverberator fills a rule row's auto cells, it writes that row's resolved columns 1-12
  back: a blank cell takes its #_defaults_# row value and an auto cell reverberator's own default (a cleaned-up Job Name
  or monitored path rewrites the row too), so a later edit of the defaults row no longer reaches that job: edit the job's own row, or clear its cells, to follow
  a changed default. Columns 13 to 15 are never written.
- **Why:** filling in defaults and auto fields is how the rule file records what each job runs with.
- **Revisit when:** a host relies on editing the defaults row for jobs already started.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### A file edited during a full comparison is copied twice

- **Kind:** known limitation, already before 0.47.
- **What the operator sees:** an edit made while a full comparison runs lands in the comparison's version, and the next
  batch (from the edit's event) copies the file again into one more version: an extra copy and version, no wrong
  result. Jobs with a Full Comparison Interval meet it a little more often.
- **Why:** the fix sits in the replay's core path, a risk not worth an extra version.
- **Revisit when:** it costs noticeable space.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### A vouched chmod keeps a checked copy checked

- **Kind:** known limitation.
- **What the operator sees:** under Only Sync Attributes, after a chmod or chown whose record vouches for the vault copy,
  the copy stays recorded checked, and no comparison syncs or reads it back. If a power loss or a metadata write error
  loses the copy's new mode or owner in the seconds after the commit, the vault keeps the old mode or owner while its
  record says the new one, until the file next changes, and restores give the old mode or owner. The data is
  unaffected; folders and symlinks already worked this way.
- **Why:** marking such copies unchecked would make the next full comparison read each one back, the vault reads this round
  removed for a chmod or chown over a large tree, for a loss confined to a few seconds after a commit.
- **Revisit when:** a restore is seen giving an old mode or owner after a power loss or a write error.
- **Approved:** 2026-10-28, the user's choice "Keep checked, known limitation (Recommended)".

### Vault disks mounted outside fstab

- **Kind:** known limitation.
- **What the operator sees:** the disk check reads /etc/fstab and mergerfs pools. So a vault on a disk mounted outside
  fstab (by hand, by a systemd .mount unit, by autofs) that is unmounted when reverberator starts gets its Vault Path made
  there, which is hidden once the disk mounts; nothing is lost. But a start that made the folder there then waits with
  "vault filesystem not ready" until a restart, when the disk mounts without that folder. With an N/A or auto Vault File System Signature and such a disk
  unmounted at start, the job backs up into the bare folder on the disk below until the disk mounts: those versions are
  hidden then and use that disk's space, and an auto signature filled from such a folder is the disk below's. This is
  the same as in 0.47; once the disk mounts, such a job waits on the wrong signature, with repeated FAILED alerts, until
  the cell is set back to auto.
- **Why:** such mounts are not known to reverberator without reading systemd units or autofs maps.
- **Revisit when:** a host keeps a vault on such a disk.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)"; then "Fold into that entry
  (Recommended)" for the start; 2026-10-29, on the signature case: "Widen it (Recommended)".

### A disk mounted by hand under an unmounted fstab mount point waits

- **Kind:** known limitation.
- **What the operator sees:** while an fstab mount point is not mounted, a disk mounted some other way below it (by hand,
  by a systemd .mount unit, by autofs) does not count as there. A vault or monitored path on it waits with the FAILED: waiting
  marker naming the fstab point. Put the disk in /etc/fstab, or mount the fstab point first.
- **Why:** a bind mount of a root-disk folder or a tmpfs mounted there must not count (a vault could land on the root
  disk or in RAM), and telling them apart from a disk needs rules on a mount's type, source and root: extra parts for a
  layout this host does not use.
- **Revisit when:** a host mounts a vault or monitored disk that way.
- **Approved:** 2026-10-29, the user's choice "Revert it, known limitation (Recommended)".

### A move into its own old place is copied whole

- **Kind:** known limitation.
- **What the operator sees:** an entry moved into a new folder made at its own old place in one batch (`mv D x; mkdir D;
  mv x D/D`, or `mv site site.old; mv site.new site; mv site.old site/old`) logs one warning, `Not renaming … to …: its new
  place is inside its old one in the version; copying it instead`, and is copied: the next version holds full copies of
  its files in full, so a big folder costs its full size in the vault once. In the swap shape the
  folder that took its old place (site.new) is copied whole too, as the copy replaces all of the version's `site`: both
  folders cost their size once, unless the replacing one was made in that batch (then it is copied anyway). The result is
  right.
- **Why:** the version can never rename an entry into itself; keeping the links needs a replay that parks the entry under
  a temporary name and places it after the entries that make its new folder, a larger change for a shape never seen in
  the live logs.
- **Revisit when:** the warning shows up in the live logs.
- **Approved:** 2026-10-29, the user's choice "Known limitation (Recommended)" (with "One warning, copy (Recommended)"
  for the warning); the swap shape's cost: "Correct the wording (Recommended)".

### A live database's files are copied one at a time

- **Kind:** known limitation.
- **What the operator sees:** a database an application keeps writing (a SQLite file with its `-wal` and `-shm`, a
  PostgreSQL or MySQL data folder) is copied file by file, each when its turn comes, while the application goes on
  writing. A version can then hold the database and its write-ahead log from different moments, or a file copied
  in the middle of a write. Restored, such a copy may lack the newest changes or not open at all. On 2026-11-02
  two hourly versions of snowluma's `messages.db` (93 MiB) were checked: in each of them the database and its
  `-wal` were copied up to 20 minutes apart, and both opened and passed SQLite's integrity check, so the risk is
  real but small in practice.
- **Why:** a consistent copy of files that change together needs one instant for all of them: a filesystem snapshot
  (the sources here are ext4 and mergerfs, which have none) or the database's own copy. A copy made through the
  database (SQLite's backup function) is not byte for byte the source, so the comparison after each batch would
  see a difference and copy it again every time, and it would cover one database kind only. Every file-level
  backup (restic, rsync, borg) has the same limit; the usual answer is to back up a dump.
- **Revisit when:** a monitored folder lives on a filesystem with snapshots, or someone needs a live database backed
  up that cannot be dumped.
- **Approved:** 2026-11-02, "Known limitation + README line (Recommended)", after the user asked "for general user's
  use case, should we accept as limitation? or should we plan / rig something up?". The same day the user chose
  "Skip messages.db" for docker_volumes (in /etc/reverb_skip_docker_volumes.txt, with its -wal and -shm; restic's own
  copies still hold it) and "Leave restic as it is (Recommended)".

### A folder whose extended attributes alone fail to copy keeps the wrong ones

- **Kind:** known limitation.
- **What the operator sees:** when copying a folder's metadata into a version fails, the copy is tried again at the end
  of the batch, and a folder that still fails has its record marked so the next comparison copies its owner and mode
  again. A failure that only ever hits its extended attributes (ACLs among them) is logged with a traceback each time,
  and the version keeps the folder's xattrs as they were, so a restore gives them back that way.
- **Why:** records hold no xattrs, so no comparison can see that they differ; recording them would cost every entry.
- **Revisit when:** such failures are seen in the log.
- **Approved:** 2026-11-04, the user's choice "All three (Recommended)".

### On a mergerfs pool, a folder cloned to another disk can lose setgid

- **Kind:** known limitation.
- **What the operator sees:** on a vault kept on a mergerfs pool, a folder that mergerfs clones onto another disk
  while a batch records into it or writes into it can lose its setgid bit on that disk (a mergerfs bug: upstream
  https://github.com/trapexit/mergerfs/issues/1689); a batch gives such folders back their times only, so the pool may
  show the folder without setgid, and a restore gives it back so.
- **Why:** copying the whole metadata of every folder a batch writes into would cost requests on every vault, for a
  bug of mergerfs that a vault on one disk never meets.
- **Revisit when:** a mergerfs release carries the fix (the issue was closed as completed on 2026-11-05), or a vault
  on a pool relies on setgid folders.
- **Approved:** 2026-11-04, "All three (Recommended)"; narrowed 2026-11-05, "Apply as drafted (Recommended)".

### After a crash, a folder whose row holds no record can keep the backup's time

- **Kind:** known limitation.
- **What the operator sees:** a crash in the one call between a change inside a folder of the previous version and
  giving that folder its times back leaves the backup's time on it. The roll-forward restores it from the folder's
  database row, except when that row holds no record (its vault entry could not be read when it was recorded, or the
  manifest was lost). A restore of that version then gives that one folder that time. Files and other folders are not
  affected.
- **Why:** keeping the time elsewhere would need a durable write per folder.
- **Revisit when:** it is seen.
- **Approved:** 2026-11-04, "Known limitation".

### Vaults on btrfs

- **Kind:** known limitation.
- **What the operator sees:** design R relies on the manifest's fsync also carrying earlier folder changes to the
  disk. Power-cut tests confirm that on f2fs, ext4 and XFS (0.55.5's sweeps cut at every step of a batch on each). btrfs
  should not hold (reasoned, not run): on a btrfs vault, a power cut at the wrong moment could make the next start refuse
  the vault, or finish a commit with a part-applied tree.
- **Why:** a stronger flush before each commit, with its own tests on btrfs, for a filesystem no vault here uses.
- **Revisit when:** a vault goes on btrfs.
- **Approved:** 2026-11-05, "Known limitation (Recommended)".

### A copy lost before the upgrade restores as a broken link

- **Kind:** known limitation.
- **What the operator sees:** a file whose copy was already lost before the conversion to 0.55 restores from the older
  versions that held it as a broken link, with no FAILED line, where 0.54 printed FAILED. The conversion logs one
  error line for each, `<path> of <version> is a chain that leads nowhere (...): its copy was lost before the
  conversion, so it stays the link`. That line raises no alert: firewatcher's patterns do not match it.
- **Why:** keeping the FAILED would mean carrying the 0.54 rule on design R for ever.
- **Revisit when:** such files are found on a real vault.
- **Approved:** 2026-11-06, "Accept, log line only (Recommended)".

### The conversion runs on one thread

- **Kind:** known limitation.
- **What the operator sees:** at a job's first start on 0.55 its backups wait for a one-time conversion that does not
  fill the machine: 2 min 23 s for five versions of about 93,000 entries on a real SSD with nothing cached, where a loop
  image with its data cached took half a minute; 3.5 to 5 minutes for four versions of 183,000 files on a loop image on a
  busier machine; and under 3 s for small jobs.
- **Why:** it runs once, it is the riskiest step, and its code goes with the 0.54 reader a release later.
- **Revisit when:** a job with far more entries is converted.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### history can name a place a file only passed through

- **Kind:** known limitation.
- **What the operator sees:** when one batch moves a folder and also moves a file in or out of it through a name that
  same batch overwrote or removed, `history` can name a place the file passed through, not where it was. A name
  created again between moves, and a target moved and removed in one batch, do the same. In a fuzz of hard batches
  about 108 of 102,855 names read wrong. Restores are right.
- **Why:** the change list keeps one row per chain and no true order, so a fix needs a change list format change.
- **Revisit when:** someone meets it on a real tree, or the format changes for another reason.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### status can show one version fewer during a hand-over

- **Kind:** known limitation.
- **What the operator sees:** on a pool or a filesystem with no exchange, while a batch swaps in the new tree, `status`
  can show one version fewer. history and restore wait through it and read right.
- **Why:** a status that waits could hang behind a backup, and status is what is run when things look stuck.
- **Revisit when:** something reads that count to make a decision.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A kill can leave a version folder's own time moved

- **Kind:** known limitation.
- **What the operator sees:** on a pool or a filesystem with no exchange, the rename from staging can move the version
  folder's mtime, so the hand-over sets it back. A kill between the skeleton's rename and that call leaves the version
  folder's own mtime moved. No view of the version shows it, and its contents and restores are right.
- **Why:** mending it at the scan is more code for a value nothing reads.
- **Revisit when:** something reads that time.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A manifest lost in the same cut as a split on a pool

- **Kind:** known limitation.
- **What the operator sees:** on a pool, if the manifest is lost in the same power cut that left a folder record or a
  conversion's rename on one disk and not on another, the repair cannot tell a removed entry from a new one. An older
  version can lose an entry, or part of a version being converted can go with staging, with no error. Two faults at
  once. Reasoned by reading the code, not run.
- **Why:** a fix would need staged links that carry their path, a new format for a layout no vault here uses.
- **Revisit when:** a vault goes back on a pool.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A monitored tree on a pool: a clone's folder time comes with no event

- **Kind:** known limitation.
- **What the operator sees:** if a monitored tree sits on a mergerfs pool, mergerfs moves the mtime of folders above a
  new entry when it clones the path, and sends no event. A batch can miss that folder time until the next full
  comparison. Only a folder's time is affected.
- **Why:** mergerfs sends no event, so nothing can react sooner.
- **Revisit when:** mergerfs sends one.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A first version of folders alone on a pool gets no commit flush

- **Kind:** known limitation.
- **What the operator sees:** on a pool, a job's V0 that holds only folders and no files has no copies, so its commit
  does not flush; the job vault's own fsync on each branch follows it. A cut there could lose some of those empty
  folders from V0, and the next comparison would make them again. That outcome is by reading the code, not run.
- **Why:** there are no copies to protect.
- **Revisit when:** a vault goes back on a pool and a first version loses a folder.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A mergerfs with no forget command

- **Kind:** known limitation.
- **What the operator sees:** after a power cut, on a mergerfs that lacks `invalidate-all-nodes`, a folder in the last
  two versions can show a wrong mtime, and it stays wrong; an attempt may also fail once and go on at the next. With
  the command stubbed out on 2.42, 1 to 10 of 274 cut runs were wrong, and each wrong line looked at closely was a
  folder's time alone. No file data was wrong.
- **Why:** repairing it means reading each folder's time on every disk, for a version of mergerfs not in use here.
- **Revisit when:** someone runs such a mergerfs.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A FUSE vault with exchange and cached attributes

- **Kind:** known limitation.
- **What the operator sees:** on a vault on a FUSE filesystem that gives RENAME_EXCHANGE and keeps a name's attributes
  for a second, link counts can read stale, so version sizes can read low and Backup Size Limit undercounts, with no
  error. Reasoned, not run. Pools and filesystems with no exchange are covered.
- **Why:** covering it means reading fresh link counts on every batch of every job.
- **Revisit when:** a vault goes on such a filesystem.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### f2fs can keep a symlink with no text

- **Kind:** deferred.
- **What the operator sees:** nothing, today: `is_skeleton()` passes over a link `readlink` cannot read. A checkpoint
  inside symlink(2) followed by a power cut keeps a link that lstat lists and readlink answers ENOENT for, and
  fsck.f2fs does not see it. A later checkpoint heals it.
- **Why:** the proper fix is in the kernel; a report is drafted for the f2fs list.
- **Revisit when:** a kernel carries the fix: then that tolerance in `is_skeleton()` can go.

### A symlink the vault's filesystem can't hold is left out

- **Kind:** known limitation.
- **What the operator sees:** a symlink in the monitored tree whose text or path is longer than the vault's filesystem
  takes is in no version: on an XFS vault, a link text of 1,024 bytes and up (ext4 and f2fs take up to 4,095). Each
  backup that meets it logs `reverberator job <name> NOT BACKED UP: <path>: a symlink whose text or path is longer than
  the vault's filesystem takes; left out of this version`, which alerts, and the rest of the batch is backed up. A path
  too long is left out this way when the temporary name the copy is first written under passes the limit (in a folder
  whose path in the vault reaches 4,041 bytes); a link whose own path in the vault passes 4,095 bytes is not left out
  but fails every backup (deferred: "An entry whose path in the vault passes 4,095 bytes fails every backup"). A
  version that held a link of that name before keeps it; the new version shows none. A restore that meets such a link
  (from a vault on another filesystem to a target on XFS) restores everything else, names the link
  (`FAILED <rel>: not restored: the target's filesystem cannot hold a link that long (its text or its path)`), finishes,
  and exits 1.
- **Why:** a version holds a link as itself, so a vault that cannot hold its text cannot keep it browsable. Before 0.55.2
  the failed copy stopped every backup of the job until the link was gone. Keeping it another way (its text in a file
  with a marker) would add code, and browsing would show a file where the link was.
- **Revisit when:** someone needs such links kept on an XFS vault.
- **Approved:** 2026-11-09, "Accept: leave it out, warn (Recommended)".

### A killed restore copies everything again

- **Kind:** known limitation.
- **What the operator sees:** a folder restore killed (SIGKILL), crashed or cut by a power loss before its sync copies
  everything again when it is run again, rather than keeping what it had copied, and `--accept` is refused (exit 2) until
  that run has finished and synced. A stopped one (Ctrl-C, SIGTERM, SIGHUP) first writes what it restored out to disk,
  saying so, and waits for the disk, which nothing cuts short; the same restore run again keeps that, unless it was itself
  copying everything again, or its write-out failed. A run again that keeps failing for a cause it may fix can never
  finish while the cause stays: the summary and `--accept`'s refusal say to fix the cause and run again, or to remove the
  target and restore it fresh (only for a target a restore made; otherwise to restore into a new folder instead). The
  README's restore paragraph says so.
- **Why:** no run can tell afterwards whether the copies reached the disk. A writeback error is reported to a sync through
  a newly opened handle only if no other sync of that disk met it first, and the daemon's own vault flush is one. Keeping
  the copies could end in a restore that says it is done over files that lost their bytes. The cost is time, never wrong
  data.
- **Revisit when:** big restores get killed often.
- **Approved:** 2026-11-09, "Recopy after a kill (Recommended)", with the Ctrl-C wait "Wait for the disk (Recommended)";
  2026-11-09, "Say the way out (Recommended)" for a rerun that keeps failing.

### mergerfs answers EBADF to a lstat during an rm

- **Kind:** deferred.
- **What the operator sees:** nothing, today: `TreeWriter.removing` keeps the writer's walks out of a folder whose
  removal is queued. lstat of that folder or of a path below it can answer EBADF while `rm -rf` runs through mergerfs
  2.42.
- **Why:** the proper fix is in mergerfs: upstream https://github.com/trapexit/mergerfs/issues/1693.
- **Revisit when:** a mergerfs release carries the fix: then check whether `removing` is still worth keeping.

### A folder or file moved into a new folder is copied whole

- **Kind:** known limitation.
- **What the operator sees:** `mkdir new; mv big new/` inside one quiet time copies what moved, with no line in the log,
  though the vault already holds it: 102.44 MB for a 100 MB folder on the real daemon, at every gap between the two
  commands, against 0.04 MB for a move into an existing folder; a 100 MB file costs 100.11 MB. With a size limit, the copy
  can prune older versions to make room: after five small versions, such a move left only the newest of them. 0.55 and
  0.54.2 do the same. A move into a folder made before the last backup was taken is a move and costs no copy.
- **Why:** the watcher drops the events in a folder made during the batch until the batch's copy of that folder runs, the
  move's arrival with them, so the move becomes a delete of its old place and the copy. 0.55.1 was built to keep the
  arrival as a move; four reviews and the fix passes after them each found an order of events where the version then
  kept a file's old bytes for good where 0.55 is right (the last needs the stale watch of a folder that left the tree, at
  the moved folder's old path), so 0.55.1 copies, as 0.55 does. A copy costs space and time; a wrong version loses a backup.
- **Revisit when:** the no-copy move gets its own design; sooner if size limits start pruning because of it.
- **Approved:** 2026-11-07, "Drop the feature (Recommended)": 0.55.1 ships with every move into a new folder copied, as
  on 0.55, and the no-copy move gets its own design later.

### A batch whose only changes are left out can still commit a version

- **Kind:** known limitation.
- **What the operator sees:** a batch, or a full comparison such as the one at each start, whose only differences are
  entries it leaves out (an unreadable file, a symlink the vault's filesystem can't hold) commits no version, but for
  three cases, each of which commits one version that changes nothing; with Keep N Versions, that version pushes the
  oldest one out:
  - a symlink in a folder whose full path in the vault reaches 4,041 bytes, in a folder that holds no regular file (one
    would fail every backup), with the link's NOT BACKED UP line. Its copy is written under a temporary name (a dot, 32
    hex digits and `.reverberator-partial`, 54 bytes, after its slash), and that path passes Linux's 4,096-byte path
    limit there, whatever the link's own name. A link whose own path there passes 4,095 bytes fails every backup instead
    (deferred: "An entry whose path in the vault passes 4,095 bytes fails every backup");
  - a file readable when the batch is checked and unreadable or gone when it is copied a moment later;
  - on a mergerfs pool, a symlink the vault's filesystem can't hold, with its NOT BACKED UP line: there the check counts
    every symlink as a change, as 0.55.4 did.
- **Why:** the check that keeps such batches from committing runs before the copy, and probes a link's text, not the
  path its copy is written under. Telling that path apart needs the new version's name and a length rule, for a rare
  link; closing the race would need the check and the copy to be one step. On a pool the probe, made in staging, can
  land on another disk than the link's copy, and on a pool of disks with different filesystems it would then leave out
  a link the vault can hold, which is worse than an empty version.
- **Revisit when:** such a link is seen in a monitored tree, or such empty versions are seen.
- **Approved:** 2026-11-12, "Leave that case out (Recommended)"; 2026-11-13, on the race: "Accept the race
  (Recommended)"; 2026-11-13, on the pool case: "Widen the entry (Recommended)".

### A power cut right after a backup hides its version until the next start

- **Kind:** known limitation.
- **What the operator sees:** on a vault off a mergerfs pool, after a power cut within the filesystem's checkpoint
  interval of a backup (on f2fs, whose default is 60 s, about 62 s from the commit, and 87 s once in 67 measured
  batches), that backup's version is missing from status, history and restore until the job's next start scans the
  vault. A restore run by hand until then offers the version before as the newest, and it reads right, through its
  forward links; status reads the vault's size low. A write error on that backup's last sync is reported at a later sync
  instead of failing that backup. A job that never starts again (removed from the rules, its disk read on another
  system) never lists it. At most one version is hidden, and nothing is lost.
- **Why:** the two folder fsyncs after the commit that would close it cost two f2fs checkpoints and 37 KiB of the 455 KiB
  each backup writes; the commit itself is on the disk, and the start's scan finishes what follows it.
- **Revisit when:** a restore is run from another system right after a power cut, or the version must show before the
  job starts again.
- **Approved:** 2026-11-13, "Accept it (Recommended)".

### A lost manifest stops an unmounted inner disk being paused

- **Kind:** deferred.
- **What the operator sees:** when a job's vault database is lost or unreadable (removed or damaged from outside; the
  daemon's own messages suggest removing it in some cases), three things go wrong. First, it forgets which inner mounts
  it had seen. An inner disk unmounted at that moment then looks like an empty folder: the next comparison commits a
  version with that folder empty, with no "Inner mounts not mounted" line, and when the disk is mounted again every file
  is copied back. Under Keep N Versions or a size limit, the versions holding the disk's files can be pruned meanwhile,
  so a disk that never comes back can lose its backup. Second, when a batch was cut (a kill or a power loss) before the
  database was lost, a file the cut batch had just copied in new, whose source cannot be read at the retry, keeps the
  cut copy as its backed-up copy: if the cut damaged that copy, the newest version holds wrong bytes for it, with no
  line but the file's UNREADABLE one, until the file changes again. With the database standing, the start removes such
  a copy and the file is left out with its line. Third, on a vault filesystem with no RENAME_EXCHANGE (off a pool too), a
  batch cut between the two renames that put a folder into the version before it (a folder it records, or makes real
  there to change something in it: a batch that only deletes `p/d` makes `p` real) leaves that version with nothing at
  that folder once the database is lost, and what the batch deleted or replaced under it is then in no version: the
  start empties staging, where the cut left the folder's forward link, and no row gives it back. 0.55.4 does the same
  (run on both).
- **Why:** the inner mounts are recorded in the database only, so a rebuilt database has none to pause. And without the
  database the start cannot tell a file the cut batch made from one of the version before whose forward link a cut
  between two renames left in staging (on a pool, or a filesystem with no exchange): removing the first would remove the
  second, which is data loss (the design re-check's run N5), so the start keeps both, as 0.55.4 does. The fix belongs at
  the source: the version's own state kept outside the database, with the version: its inner mounts, and the forward
  links a cut staged, which already name their places.
- **Revisit when:** the round after 0.55.5. For the third case, and off a pool the second: a forward link the cut left
  in staging names its own place in its text (`forward_text()`), so the scan could give it back to the version before
  ahead of `empty_staging()`, with no database (reasoned, not run).

### An entry whose path in the vault passes 4,095 bytes fails every backup

- **Kind:** deferred.
- **What the operator sees:** a symlink whose own path in the vault passes 4,095 bytes (Linux's path limit is 4,096
  bytes with its terminating NUL), or a regular file in a folder whose path in the vault reaches 4,041 bytes (where the
  temporary name its copy is written under passes the limit), fails every attempt of its job for as long as it is in
  the monitored tree, and no version is made: the link with `FAILED: recording <rel> in <version> failed: [Errno 36] File
  name too long`, before any copy, and the file with `FAILED: copying <path> into the vault failed: cp: ... File name too
  long`, each retried with the growing delay. A path in the vault is the Vault Path, the job name, the version folder's
  name (about 30 bytes) and the path below the monitored root, so only a monitored tree some 4,000 bytes deep can meet
  it. 0.55.4 does the same (run on it).
- **Why:** older than 0.55.5. Neither the copy's temporary name nor the record made at the entry's own path in the
  version before has a rule for a path the vault refuses, as a link whose text it refuses has (left out with NOT BACKED
  UP).
- **Revisit when:** the round after 0.55.5, with the fix at source: a shorter temporary name, and an entry whose path the
  vault refuses left out at the record step with its NOT BACKED UP line.

### A disk taken out of a pool through its control file goes unseen

- **Kind:** deferred.
- **What the operator sees:** on a vault on a mergerfs pool, when a disk is taken out of the pool through mergerfs's
  control file while a batch runs, the batch's flush syncs only the disks the pool lists by then: what the batch wrote to
  that disk is not synced, and the batch is not failed but commits, with no alert. The same removal while the start
  after a cut puts the cut batch's tree back is seen by no guard either: the version before's listing misses the names
  on that disk, and the scan's removals of what the cut batch made (the put-back's, and those of a name left a folder on
  one disk and something else on another) can remove an entry that version's forward link names, so once the disk is
  back that version has lost it. A disk unmounted at that moment is caught: the start's repair checks the pool before
  every act that trusts a listing (its removals, the judgement of a leftover version folder, and its end, before a
  backup uses the scan), and stops with nothing removed (the user's pick of 2026-11-13, "Finish the check rule
  (Recommended)"; a test on a real mergerfs pool shows it). The control-file case is reasoned from the code, not run.
- **Why:** older than 0.55.5. A flush picks its handles by the disks the pool lists at that moment, and the pool check
  looks for a listed disk that is missing or was mounted again, not for one the pool stopped listing; the scan's guard
  asks the same.
- **Revisit when:** the round after 0.55.5: check it by a run, and fail the batch, or stop the scan, when a disk it began
  with has left the pool.

### A restore does not notice its filesystem change under it

- **Kind:** deferred.
- **What the operator sees:** a restore onto a mergerfs pool checks at each of its syncs for a disk that joined the
  pool, or a filesystem mounted at its folder's place on a disk, while it ran, but not for the pool itself unmounted (a
  lazy unmount) or another filesystem mounted over it; off a pool a restore checks for no such change. Its later copies then
  land on a filesystem none of its handles is on, its syncs do not cover them, and it can say it is done for files no
  sync of its own wrote out: a write error there is not heard, and a power cut soon after can lose them.
- **Why:** older than 0.55.5. The end check runs only while the folder is still on a pool, and off a pool there is
  none.
- **Revisit when:** the round after 0.55.5: every restore, on a pool or off one, checks its folder's filesystem
  (`st_dev`) at each sync against the handles it opened, as the daemon's units check theirs.

### A batch whose monitored disk goes while it waits for its locks

- **Kind:** deferred.
- **What the operator sees:** a full comparison, or another batch, that has walked the tree and then waits for the job's
  locks (while a restore of the job copies, say) commits, when the monitored disk is unmounted during that wait, a
  version without the copies of the files that vanished with it: a file it found changed keeps its older copy in that
  version, and a new file is missing from it, with no alert (at most a warning, `Not tracking <path>: source no longer
  exists`), until a comparison with the disk back finds them (every start makes one). Reasoned from the code, not run.
- **Why:** older than 0.55.5. The batch looks for an unmounted monitored disk after its walk, before that wait, and not
  again after it; 0.55.5 moved the look after the locks for a job's first version only.
- **Revisit when:** the round after 0.55.5: look again once the locks are held, as a first version does.

### An /etc/fstab that cannot be read names no disk

- **Kind:** deferred.
- **What the operator sees:** while /etc/fstab cannot be read for another reason than its absence (a read error; the
  daemon reads it as root, so in practice a failing root filesystem), the disk check takes it as naming no mount point,
  as it takes a missing one, and says nothing: a path under an unmounted fstab mount point counts as there, so a start
  makes the Vault Path and the job's own folder on the bare mount point and, with an N/A or auto Vault File System
  Signature, backs up there, as for a disk mounted outside fstab (see "Vault disks mounted outside fstab").
- **Why:** older than 0.55.5 for the Vault Path; 0.55.5's wait on the job's own folder takes the same rule. A missing file
  is an answer; a read error is none, and an absence counts as evidence only when the source answered.
- **Revisit when:** the round after 0.55.5: a read error other than "no such file" is a problem that the wait names and
  waits on.

### An xattr change made while down, in a folder renamed during the start's walk

- **Kind:** deferred.
- **What the operator sees:** an extended-attribute-only change made while the daemon is down, to an entry in a folder
  that is then renamed while the start's full comparison walks the tree (between its parent's listing and its own), is
  never compared: the walk finds the folder gone, and the rename's batch compares extended attributes only from its own
  time, then records its matched time past the change. The change is missing from the versions until the entry changes
  again, with no line. Run on this round's code, before and after its L10 change.
- **Why:** older than 0.55.5, and a narrow window: a folder renamed in the moment the walk passes it, after an xattr-only
  change made while nothing watched.
- **Revisit when:** the round after 0.55.5.

### A name its parent lists but the kernel cannot look up drops out of a batch's comparison

- **Kind:** deferred.
- **What the operator sees:** on a monitored filesystem that can list a name it cannot look up (name trouble on a CIFS
  or sshfs mount, say, whose lstat of the name answers ENOENT every time), a batch whose comparison walks such a name as
  a scope it touched (a folder or a path of the batch's events) takes it as gone: its rows are deleted, so the
  new version lacks it and everything under it, with no line; older versions keep it. The whole-tree walk tells it apart:
  a folder its parent still lists is not gone, and keeps its ERROR and UNREADABLE lines at every walk.
- **Why:** older than 0.55.5. The scope walks (`iter_scope_entries()`, `scope_path_entry()`) take an lstat's ENOENT as
  gone, which is the normal answer for every folder and file a batch deleted or moved away; asking the parent's listing
  each time, as the whole-tree walk does on its error path, would list a parent once per deleted entry, about 8 ms for
  a parent of 100,000 names.
- **Revisit when:** the round after 0.55.5: the same parent-listing rule in the scope walks, with one listing per parent
  kept for the comparison.

### A walk lists a parent once per folder gone under it

- **Kind:** deferred.
- **What the operator sees:** nothing but cost: a walk tells a folder that vanished as it reached it by listing its
  parent once (on the error path only), so a mass deletion of many sibling folders while a walk passes lists that
  parent once per folder: about 8 ms a listing for a parent of 100,000 names, so the time grows with the square of the
  folders deleted. A rare case: a mass deletion during a full comparison.
- **Why:** each listing answers for one folder, which keeps the rule to one call on the error path.
- **Revisit when:** the round after 0.55.5: one listing per parent per walk, listed again only when the kept listing
  still names the folder.

### The footprint gate does not catch a missing trim after a commit

- **Kind:** deferred.
- **What the operator sees:** nothing, today: the daemon trims its heap after each commit. The test that holds its idle
  memory down (`tests/test_footprint.py`) measures after a restart and one backup, so it fails when the trim after the
  start goes, not when the trim after each commit does: that one could be lost without a test failing, and the memory
  a busy job keeps between backups would go unchecked.
- **Why:** a growth gate needs a burst of changes and a bound for what memory may keep after it, and that bound is not
  measured yet.
- **Revisit when:** the round after 0.55.5: a gate after a burst of changes, once its bound is measured.
