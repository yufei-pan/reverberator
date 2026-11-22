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
- **Why:** no inotify or fanotify flag reports mmap stores (round 10's research); the
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
  backup, whose next attempt compares the whole tree with that blind spot (both as in 0.55.4). On the upgrade, a
  pending-transactions file a 0.55.4 stop left in the job vault (`.reverberator_pending_transactions.nsv`) is not
  replayed (0.55.5 removed it at its first start; from 0.55.6 it stays, unread), so the changes it held get that full
  comparison, once. So is such a rewrite of a file under an inner mount, made while a batch that copied it was cut
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
  two hourly versions of an application's `messages.db` (93 MiB) were checked: in each of them the database and its
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
  "Skip messages.db" for docker_volumes (in that job's skip list, with its -wal and -shm; restic's own
  copies still hold it) and "Leave restic as it is (Recommended)".

### A folder whose extended attributes alone fail to copy keeps the wrong ones

- **Kind:** known limitation.
- **What the operator sees:** when copying a folder's metadata into a version fails (an ERROR line with a traceback),
  the commit marks the folder's row, so the next comparison that meets the folder (a full comparison, or a batch that
  compares it) copies all of its metadata again, its extended attributes (ACLs among them) included, once. A failure
  that hits every time is tried that once more, which makes one version that changes nothing, and is then left: where
  only the folder's extended attributes fail (an inherited default ACL not removed, or the source's own attributes not
  copied), the versions keep its xattrs as they were, so a restore gives them back that way, and the traceback is
  logged at each copy. A failed copy that also leaves the folder's mode, owner or mtime unlike the monitored folder's
  (an attribute write failing with a full disk or an I/O error before the mode is set, or a change of owner the vault's
  filesystem refuses) is copied again at every comparison that meets the folder (when only its mtime differs, at every
  full comparison), each time making a version that changes nothing, with its ERROR line, as 0.55.5 does; under Keep N
  Versions each such version pushes the oldest one out.
- **Why:** records hold no xattrs, so no comparison can see that they differ; recording them would cost every entry. The
  mark gives a failure that would work if tried its one more try for the price of one value in the row; a give-up mark
  for a failure that leaves the mode, owner or mtime different would be a second mark with rules of its own.
- **Revisit when:** such failures are seen in the log.
- **Approved:** 2026-11-04, the user's choice "All three (Recommended)"; 2026-11-17, the mark and its one retry built,
  the user's answer (through chief) "Build the retry (Recommended)".

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

### A manifest lost after a cut, on a pool

- **Kind:** known limitation.
- **What the operator sees:** on a pool, if the manifest is lost in the same power cut that left a folder record or a
  conversion's rename on one disk and not on another, the repair cannot tell a removed entry from a new one. An older
  version can lose an entry, or part of a version being converted can go with staging, with no error. Two faults at
  once. Reasoned by reading the code, not run. And when the database is lost after a backup was cut (a kill or a power
  loss), a file that backup had just copied in new, whose source cannot be read at the retry, keeps the cut copy as its
  backed-up copy, wrong bytes if the cut damaged it, until the file changes again; its UNREADABLE line ends "keeping the
  copy a cut backup made of it, which may be damaged". Run on a stand-in pool. Off a pool the start removes such a copy
  whatever the database, and the file is left out of the version with its line.
- **Why:** a fix would need staged links that carry their path, a new format for a layout no vault here uses. Over a lost
  database on a pool the start cannot tell what the cut backup made from an entry of a version whose record is on
  another disk (the split above), so it removes neither, and a copy it keeps is copied again only when its source reads.
- **Revisit when:** a vault goes back on a pool.
- **Approved:** 2026-11-06, "Accept (Recommended)"; widened to the cut copy kept over a lost database on a pool:
  chief's decision, 2026-11-15, on the user's words "Support pools with a limitation" (2026-11-04).

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

### A symlink or a path the vault can't hold is left out

- **Kind:** known limitation.
- **What the operator sees:** two kinds of entry in the monitored tree are in no version. Each backup that meets one logs
  its NOT BACKED UP line once, which alerts, and the rest of the batch is backed up; a batch or full comparison that
  meets only such entries makes no version.
  - A symlink whose text is longer than the vault's filesystem takes: on an XFS vault, a link text of 1,024 bytes and up
    (ext4 and f2fs take up to 4,095), with `reverberator job <name> NOT BACKED UP: <path>: a symlink whose text or path
    is longer than the vault's filesystem takes; left out of this version`. A version that held a link of that name
    before keeps it; the new version shows none. A restore that meets such a link (from a vault on another filesystem to
    a target on XFS) restores everything else, names the link (`FAILED <rel>: not restored: the target's filesystem
    cannot hold a link that long (its text or its path)`), finishes, and exits 1.
  - Any entry whose path in the vault would pass Linux's 4,095 bytes (4,096 with its terminating NUL), whatever the
    filesystem: a file, a link or an entry of another kind, or a folder with everything under it, with `reverberator job
    <name> NOT BACKED UP: <path>: its path in the vault would be longer than Linux takes (4,095 bytes); left out of this
    version`. A path in the vault is the Vault Path, the job name, the version folder's name (about 30 bytes) and the
    path below the monitored root, so only a monitored tree some 4,000 bytes deep meets it. An entry that is copied
    (anything but a folder) is first written under a temporary name 54 bytes long in its folder, so every such entry in
    a folder whose path in the vault reaches 4,041 bytes is left out, whatever its own name. On a mergerfs pool the path
    is counted as mergerfs writes it: the longest disk's path in place of the pool's mount point, and the vault's path as
    the pool has it, not as a link into the pool spells it (reasoned from how mergerfs writes a path, not run on a real
    pool). An entry a version already holds past the limit (a version number's growth, V99 to V100, or a folder renamed
    to a longer name can put one there) stays as it is; its delete leaves it in the newest version, with its line ending
    `this version keeps it`, and makes no version of its own; but a change in its folder, or a rename of a folder above
    it, fails every backup of the job until it is gone (deferred: "An entry past the path limit inside a version fails the
    job's backups when its folder changes").
- **Why:** a version holds a link as itself, so a vault that cannot hold its text cannot keep it browsable; keeping it
  another way (its text in a file with a marker) would add code, and browsing would show a file where the link was.
  Linux refuses a path past 4,095 bytes on every filesystem, so no version can hold such an entry by its path. A shorter
  temporary name (about 20 bytes) would let entries into folders of 4,041 to about 4,075 bytes, at the price of a second
  name form that the restore's clean-up of its leftovers and the 0.54 prune reader would read from then on. Before 0.55.2
  such a link stopped every backup of the job until it was gone, and before 0.55.6 such a path did.
- **Revisit when:** someone needs such links kept on an XFS vault, or a NOT BACKED UP alert names a path too long for the
  vault.
- **Approved:** 2026-11-09, "Accept: leave it out, warn (Recommended)", for a symlink; widened to every entry whose path
  in the vault passes 4,095 bytes, the copy's temporary name kept as it is (which drops the shorter name the deferred fix
  had planned, which "Fixes round (Recommended)", 2026-11-14, had put in this round): chief's decision, 2026-11-15, on the
  user's pick of 2026-11-09 for the same case in a symlink.

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
  entries it leaves out (an unreadable file, an entry whose path the vault refuses, a symlink whose text the vault's
  filesystem can't hold) commits no version, but for two cases, each of which commits one version that changes nothing;
  with Keep N Versions, that version pushes the oldest one out:
  - a file readable when the batch is checked and unreadable or gone when it is copied a moment later;
  - on a mergerfs pool, a symlink whose text the vault's filesystem can't hold, with its NOT BACKED UP line: there the
    check counts every symlink as a change, as 0.55.4 did.

  A file whose read fails only before its last 64 KiB makes such a version too, at every comparison that meets it: a
  known limitation, in its own entry ("A file whose read fails only before its last 64 KiB makes a version at every
  comparison").
- **Why:** the check that keeps such batches from committing runs before the copy; closing the race would need the check
  and the copy to be one step. On a pool the probe, made in staging, can land on another disk than the link's copy, and
  on a pool of disks with different filesystems it would then leave out a link the vault can hold, which is worse than
  an empty version.
- **Revisit when:** such empty versions are seen.
- **Approved:** 2026-11-12, "Leave that case out (Recommended)", for a link in a folder whose path in the vault reaches
  4,041 bytes, a case 0.55.6's length rule takes out of this entry; 2026-11-13, on the race: "Accept the race
  (Recommended)"; 2026-11-13, on the pool case: "Widen the entry (Recommended)".

### A file whose read fails only before its last 64 KiB makes a version at every comparison

- **Kind:** known limitation.
- **What the operator sees:** a regular file larger than 64 KiB that opens, whose last 64 KiB read, and whose read
  fails earlier (a bad sector under its first part, say, or a read error of a FUSE or network filesystem there), when
  it is the only difference a full comparison finds or the only entry of a batch, makes one version that changes nothing
  each time, with its UNREADABLE line (the file keeping its last backed-up copy, or, when it is new, left out): at every
  full comparison (every start, each Full Comparison Interval, when events were lost) and at every batch of its events.
  With Keep N Versions each such version pushes the oldest one out: in a probe on 0.55.5 with Keep 3 (a stand-in for cp
  that fails as GNU cp does on a read error; not run on a failing device), three full comparisons left the three kept
  versions holding one content of the file where they had held three. This is not the race the entry above accepts: the
  read fails every time, so it comes back at every comparison. A file that does not open, or whose last 64 KiB cannot be
  read, makes no version, with its UNREADABLE line (0.55.5 made one for every file that opens and cannot be read).
- **Why:** the check before the hand-over (`entries_all_drop_out()`) reads a file's last 64 KiB, the tail every
  comparison reads, which the copy then reads from the cache. Catching the rest needs the whole file read at the check,
  a second read of the first file of every batch, uncached for a large one; or the hand-over taken back when every copy
  of the batch failed, about 40 lines on the commit path where a mistake makes a wrong version, which is the rollback
  path declined on 2026-11-13 for the race ("Accept the race (Recommended)").
- **Revisit when:** one file's UNREADABLE alert repeats at full comparisons and `history` shows a new version each time.
- **Approved:** 2026-11-15, "Known limitation (Recommended)", the user's pick (through chief), shown that it leaves a
  wrong result the rules call always worth fixing and that "Fixes round (Recommended)" (2026-11-14) had put its fix in
  this round.

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

### An xattr change made while down, in a folder renamed during the start's walk

- **Kind:** known limitation.
- **What the operator sees:** an extended-attribute-only change made while the daemon is down, to an entry in a folder
  that is then renamed while the start's full comparison walks the tree (between its parent's listing and its own), is
  never compared: the walk finds the folder gone, and the rename's batch compares extended attributes only from its own
  time, then records its matched time past the change. The change is missing from the versions until the entry changes
  again, with no line. Run on 0.55.5's code, before and after its L10 change.
- **Why:** older than 0.55.5, and three things must meet: an xattr-only change made while nothing watched, a rename of
  its folder, and that rename in the moment the walk passes it. Each fix costs more than the case: a second whole-tree
  walk whenever a folder vanishes during a full comparison (three such lines in a week of a live journal, from all
  walks), or a part with its own state carrying the gone folders and the comparison's bound to the rename's batch.
- **Revisit when:** a restore is found missing such a change.
- **Approved:** chief's decision, 2026-11-15, on the user's words on a rare case, "if unable to do this cleanly I think
  it also make sense to put as limitations" (2026-10-26).

### A name its parent lists but the kernel cannot look up drops out of a batch's comparison

- **Kind:** known limitation.
- **What the operator sees:** on a monitored filesystem that can list a name it cannot look up (name trouble on a CIFS
  or sshfs mount, say, whose lstat of the name answers ENOENT every time), a batch whose comparison walks such a name as
  a scope it touched (a folder or a path of the batch's events) takes it as gone: its rows are deleted, so the
  new version lacks it and everything under it, with no line; older versions keep it (0.55.4 does the same). The
  whole-tree walk tells it apart: a folder its parent still lists is not gone, and keeps its ERROR and UNREADABLE lines
  at every walk; the watcher counts such a folder unwatched, so it holds the matched time ("A paused inner mount or an
  unwatched folder holds the matched time").
- **Why:** older than 0.55.5. The scope walks (`iter_scope_entries()`, `scope_path_entry()`) take an lstat's ENOENT as
  gone, which is the normal answer for every folder and file a batch deleted or moved away; asking the parent's listing,
  as the whole-tree walk does on its error path, would list the parent of every path a batch finds gone, on the path
  every delete takes: about 8 ms a batch with a deletion in a folder of 100,000 names, about 0.1 ms in one of 1,000
  (scaled from that measure). And the case needs an event naming the very name the server lists and refuses: an event's
  path is the name a local program used, which on such mounts differs from the one the server lists (a charset it maps,
  a name it mangles), so it is reasoned rare, not seen.
- **Revisit when:** a job monitors a CIFS or sshfs mount.
- **Approved:** 2026-11-15, "Known limitation (Recommended)", the user's pick (through chief), with the watcher's half
  and the whole-tree walk built, shown that "Fixes round (Recommended)" (2026-11-14) had it in this round.

### A change to the monitored folder's own metadata alone makes no version

- **Kind:** deferred.
- **What the operator sees:** a chmod, chown, touch or extended-attribute change of the monitored folder itself (the
  job's top folder), with nothing else in the tree changing, reaches no version and writes no line. The next version
  that something else in the tree causes records the top folder's metadata as of then; until it, a whole-job restore of
  the newest version gives the top folder its owner, mode, times and extended attributes from before the change. The
  top folder of a disk mounted inside the tree waits the same way, for the next full comparison (each start; the Full
  Comparison Interval). Found by round 0.55.6's review, from the code and an inotify probe; the inner disk's case is
  reasoned, not run.
- **Why:** older than 0.55.6. The change raises only a nameless event on the folder's own watch (its parent is not
  watched, or for an inner disk's top folder is not told), which the watcher drops; a full comparison compares the top
  folder only as the whole tree, so with no other difference it makes no version; and the top folder's metadata is
  recorded on a version's folder only when a version is written.
- **Revisit when:** the round after 0.55.6: queue that nameless attribute event as a change of the folder, and commit a
  batch holding only it when the top folder's metadata differs from its record (or record it at a full comparison that
  finds no other difference).

### Two restores into one folder on NFS are not kept apart

- **Kind:** known limitation.
- **What the operator sees:** a restore locks the folder it writes into, so a second run into the same folder is
  refused while the first runs. On a filesystem that cannot lock a folder (NFS), both runs go ahead: two runs of one
  restore copy the same bytes, each under a temporary name renamed into place, and end right, but two different
  versions restored there leave the folder holding files of both, each run saying it is done. Reasoned from the code,
  not run on NFS.
- **Why:** the lock is `flock()` on the folder, which such a filesystem refuses. Keeping the runs apart there needs a
  lock of another kind where flock fails (a POSIX lock on a lock file of the restore's own in the target, a name kept
  out of the restore's listing), for two runs into one folder at once on NFS.
- **Revisit when:** restores into an NFS folder are run side by side.
- **Approved:** 2026-11-15, "Known limitation (Recommended)", the user's pick (through chief).

### A disk out of the pool at the flush's one listing and back before the commit's check leaves its copies unsynced

- **Kind:** deferred.
- **What the operator sees:** on a vault on a mergerfs pool, a disk taken out of the pool's list (through mergerfs's
  control file) just as a backup flushes the vault's disks before its commit, and listed again before the commit checks
  the pool, is flushed by nothing: the backup commits, with no line, while its copies on that disk are not known to be
  on it. A power cut soon after can then leave them wrong in the committed version (a filesystem's journal can keep a
  new file's size without its bytes), and a write error on that disk is not heard by that backup. A disk still out at
  the commit's check fails the backup, as any disk that leaves the pool during a step does. Reasoned from the code, not
  run.
- **Why:** the flush lists the pool's disks once and syncs the job vault on each disk listed then; the part that
  flushes keeps neither the backup's check of the pool nor the disks the backup began with, and a failure raised there
  today would carry no disk that left, so the next attempt would not wait for that disk.
- **Revisit when:** the round after 0.55.6: the disk that left raised through the flush, and the prune's flush, as the
  pool check raises it, so the backup fails and the next attempt waits for the disk.

### A daemon restarted while a disk that left its pool is still out forgets to wait for it

- **Kind:** deferred.
- **What the operator sees:** a backup that fails because a disk was taken out of its mergerfs pool's list (`disk <disk>
  left pool <pool> during this step`) makes the job wait, before its next attempt touches the vault, for the pool to
  list that disk again. The job keeps that disk in memory only: when reverberator restarts while the disk is still out,
  the job starts with the pool as it is. On the vault's pool, the start's repair of the failed backup then reads the
  version before through a pool that hides what that disk holds, and can write a link to the new version over a file of
  the version before whose own copy is on that disk: once the disk is listed again, that version shows the new
  version's bytes for the file, or its own, by the pool's order of disks, with no line (shown on a stand-in pool, without
  the wait). On the monitored path's pool, the start's comparison takes the files on that disk for deleted: the new
  version lacks them, older versions keep them, and they are copied again, at the latest by the first full comparison
  after the disk is back (each start; the Full Comparison Interval), as the pool raises no event when it lists a disk
  again (reasoned).
- **Why:** the disks a failed attempt saw leave its pool are kept in the daemon's memory, which a restart clears; a
  restart is also how an operator lets a disk taken out for good go.
- **Revisit when:** the round after 0.55.6: keep those disks in the job's state across a restart, with another way to
  let a disk taken out for good go.

### An entry past the path limit inside a version fails the job's backups when its folder changes

- **Kind:** deferred.
- **What the operator sees:** an entry a version already holds past Linux's 4,095-byte path limit (it fit when it was
  written and passed the limit later: the version number gained a digit, V9's 4,095 bytes being V10's 4,096, or a folder
  above it was renamed to a longer name) makes every backup of the job fail, retried with the growing delay, once a
  change reaches its folder (a file beside it made, changed or removed while the version before still shares the folder
  with the newest) or a folder above it is renamed: each attempt fails with `recording ... failed: [Errno 36] File name
  too long`, until the entry is removed from the monitored tree or a folder above it is renamed shorter. Its own delete
  is handled (the newest version keeps it, with its NOT BACKED UP line). Only a monitored tree some 4,000 bytes deep can
  reach it. Found by round 0.55.6's final review and run in a test container; older than 0.55.6, which failed at such an
  entry's own create.
- **Why:** the writer of a version reaches its entries by their full paths, which Linux refuses past 4,095 bytes; the
  length rule refuses an entry before anything is written for it, not one that grows past the limit afterwards.
- **Revisit when:** the round after 0.55.6: the writer works on a version's entries through a handle of the folder that
  holds them (dir_fd), so no path it passes is longer than one name.

### An inner disk under one disk of a pool is not paused when another disk shows its folder

- **Kind:** deferred.
- **What the operator sees:** on a monitored path on a mergerfs pool, a disk mounted inside the tree under one of the
  pool's disks (an inner disk) is paused while it is unmounted, keeping its files in each new version, only while its
  folder reads empty through the pool. When another disk of the pool holds an entry in a folder of the same name (any
  create policy can put one there), the folder is not empty through the pool: the inner disk is not paused, with no
  `Inner mounts not mounted` line, its files leave each new version (older versions keep them), the job forgets the
  mount, and once it stays away past Keep N Versions the versions that held its files are pruned, and the vault loses
  them. No live job has such a disk. Found by round 0.55.6's final review, reasoned from the code, not run.
- **Why:** the pause looks at the folder through the pool, the union of every disk's folder of that name, as it looks
  at a disk inside the tree off a pool.
- **Revisit when:** the round after 0.55.6: record the disk of the pool each inner mount sits under, and look at that
  disk's folder.

### A disk taken out of a pool's list while the job is idle is not waited for

- **Kind:** deferred.
- **What the operator sees:** a disk taken out of a mergerfs pool's list (through mergerfs's control file) between a
  job's backups, still mounted, is never seen leaving: no wait and no line. The next backup works on the pool as it is:
  a full comparison (each start, an inotify overflow, the Full Comparison Interval) records that disk's files of the
  monitored path deleted in the version it commits (older versions keep them), a prune removes only what the pool still
  shows of the oldest version and leaves its part on that disk behind, and a forward link to an entry on that disk fails
  the backup. A disk taken out during a backup fails it and is waited for. Found by round 0.55.6's final review,
  reasoned from the code, not run.
- **Why:** a disk that left is found by comparing the pool's list with the one a backup took when it began; between
  backups no list is kept.
- **Revisit when:** the round after 0.55.6: keep each pool's last list per job between backups (with the state of
  "A daemon restarted while a disk that left its pool is still out forgets to wait for it"), so a disk gone from it is
  waited for.

### A disk that joins a pool and leaves it within one restore is not seen

- **Kind:** deferred.
- **What the operator sees:** a restore into a folder on a mergerfs pool fails, when it syncs, for a disk that joined
  the pool since it began and for one that left; a disk that joins and leaves again between the restore's start and its
  last sync is seen by neither: copies that landed on it are not synced and are no longer in the pool's view, and the
  restore says done. Found by round 0.55.6's final review, reasoned from the code, not run.
- **Why:** the look for a disk that joined reads the pool's list at the sync, and the look for one that left compares
  it with the list at the restore's start; nothing reads it between.
- **Revisit when:** the round after 0.55.6: read the pool's list once per batch of copies (one extended-attribute read),
  keeping every disk seen.

### A folder restore keeps copying after its target moved to another filesystem

- **Kind:** deferred.
- **What the operator sees:** when the target folder of a restore moves to another filesystem while the restore runs
  (its disk unmounted lazily, or another filesystem mounted over it), the restore goes on copying by path into what is
  there now (after a lazy unmount, the folder under the mount point, on the disk below it) until its walk ends, which
  can fill that filesystem; it fails, naming the change of filesystem, only at its sync after the walk. `--accept`'s
  walk does the same. Found by round 0.55.6's final review, reasoned from the code, not run.
- **Why:** the restore looks at its target's filesystem once per sync, as round 0.55.6 chose (one stat a sync).
- **Revisit when:** the round after 0.55.6: look at it once per batch of copies, and stop there.

### A disk mounted and unmounted inside the tree within one backup is taken for emptied

- **Kind:** deferred.
- **What the operator sees:** a disk mounted inside the monitored tree after a backup began and unmounted again before
  that backup commits is in neither mount table the backup reads (after its locks, and at its commit), so the job does
  not remember it: the version may hold its files (a walk or copy met them while it was mounted), and the next backup
  takes its empty folder for emptied: the next version lacks those files (older versions keep them), with no `Inner
  mounts not mounted` line. Found by round 0.55.6's review, reasoned from the code, not run.
- **Why:** the inner mounts a backup remembers come from the mount tables it reads; none is read between them.
- **Revisit when:** the round after 0.55.6: remember a mount the backup's walks or copies met too.

### A link given back after a cut can lose its text to a power cut on f2fs

- **Kind:** deferred.
- **What the operator sees:** after a backup cut between the two renames that record a folder (on a mergerfs pool, or
  a vault whose filesystem has no exchange), the next start gives the version before its link back. A power cut between
  that link's write and the flush right after it can leave, on f2fs, a link with no text (see "f2fs can keep a symlink
  with no text"), which the start after reads as given back and never writes again: that version then holds a broken
  link where its entry was. Found by round 0.55.6's review, reasoned from the code, not run.
- **Why:** the flush after the put-back narrows the window to the write itself; the start's judgement takes a link that
  is there as given back, whatever its text.
- **Revisit when:** the round after 0.55.6: the judgement reads the link's text, and writes it again when it cannot.

### A top folder with many inner disks loses its own extended attributes from its record

- **Kind:** deferred.
- **What the operator sees:** the record of the monitored folder's own metadata that each version's folder keeps (for a
  whole-job restore of the top folder) holds the inner disks' mount points too; when both do not fit in one extended
  attribute of the version's folder (about 100 inner mounts, or about 4 KiB of the top folder's own extended
  attributes), the record keeps the mount points and drops the top folder's own extended attributes, with one line
  saying so: a whole-job restore of that version gives the top folder none of its extended attributes. At about 100
  inner mounts the mount points alone do not fit: the record drops them too, with a line saying so, and keeps the owner,
  mode and times, so over a lost database no inner disk is paused then. When the write
  of that record fails (an I/O error, or no room even for the owner, mode and times), with its ERROR line, the version
  keeps the record of the version before, whose mount points may be older: if the vault's database is then lost before
  a later version's record is written, an inner disk mounted since that older record and unmounted at that moment reads
  as a folder emptied, and the next version lacks its files until the disk is back (the versions before keep them).
  Removing the old record on a failed write would protect no inner disk at all.
- **Why:** the record is one attribute, so 0.55.5 reads it as it always did and it is one write; the mount points and
  the top folder's attributes share its room.
- **Revisit when:** the round after 0.55.6: the mount points in an attribute of their own, written so a failed write
  keeps the newest set.

### An I/O or permission error reads as "not there" in parts of a backup's replay

- **Kind:** deferred.
- **What the operator sees:** where a backup's replay cannot look at a folder above an entry in the version, or at the
  monitored entry (an lstat that fails with EIO or EACCES), some of its steps take it for missing: a delete drops the
  entry's row and leaves the entry in the version, with no line; a finished copy's row is dropped and its partial file
  left in the version, with a false `a folder above it in the version is not a real folder` line; a copy whose source
  cannot be looked at is passed over with `source no longer exists`; a folder may be left unmade the same way. A later
  comparison, once the error is gone, puts each right. Found by round 0.55.6's review, reasoned from the code, not run;
  older than 0.55.6, whose new places read such an error as the error it is.
- **Why:** those steps ask a look that answers "no" for any error (real_folders_to() without strict, os.path.lexists()).
- **Revisit when:** the round after 0.55.6: the strict look, which raises an error rather than answering "no", at each
  step that acts on "not there".

### History names a change a version left out

- **Kind:** deferred.
- **What the operator sees:** a version's change list, which `history` reads, is written from every entry of its
  backup, those the replay left out too (an entry whose path the vault cannot hold, a source gone by its copy): history
  can say an entry was modified, or moved to a place, in a version that kept its old copy or never got the target.
  Found by round 0.55.6's review, reasoned from the code, not run.
- **Why:** the list is written from the backup's entries, not from what the replay applied.
- **Revisit when:** the round after 0.55.6: write the list from what the replay applied.

### A deletion running in a folder a walk is inside slows the walk

- **Kind:** deferred.
- **What the operator sees:** when a walk of the tree (the watcher's, a comparison's or a folder copy's) is inside a
  folder while another program deletes the folders in it, the walk lists that folder again for each folder it finds
  gone, where it should once for each such wave: about the square of their number in names read (tens of seconds for
  10,000 folders), during which the watcher reads no events (they wait in the kernel's queue, which can overflow into a
  full comparison). Found by round 0.55.6's final review, reasoned from the code, not run.
- **Why:** the walk asks the folder's listing again for each name it kept that fails to open (child_gone()).
- **Revisit when:** the round after 0.55.6: list the folder again once for each wave of names that fail to open.
