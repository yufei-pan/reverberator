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
  change lists in a job vault. Together they list every backed-up file name and its size, the passwords job's included.
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
  batch finds both different and copies them, and nothing is logged at warning or error level. A file swapped with a
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
- **What the operator sees:** with a size limit, the estimate made before a backup leaves out the new version's own
  folders, links and xattr blocks (a few KB, at most ~77 KB in testing) and a change kept under a folder moved into a
  new folder (up to that file's size), so a vault can go over its limit by that much until the next prune. With an
  inode limit, the estimate leaves out the links the hand-over and unfolds make, so a batch can pass the limit by that
  many until the next prune: a folder of 100K entries that changes makes 100K links in that version. The sizes
  recorded after each backup are measured, each file by its size plus 4 KiB per folder, and each inode in the newest
  version that holds it, so later prunes are right.
- **Why:** counting them would add estimates for a small, one-batch overshoot.
- **Revisit when:** a vault's limit is tight enough for it to matter.
- **Approved:** 2026-10-26, "Known limitation (Recommended)"; 2026-11-05, "Extend the entry (Recommended)".

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

### A copy whose start was lost after a power loss

- **Kind:** known limitation.
- **What the operator sees:** a cut after a checkpoint of the disk (another job's commit, the kernel's periodic one, a
  sync) and before the batch's flush ends can leave a copy all NUL in the tree. The roll-forward copies again every
  file whose row differs. A copy whose row did not change, an attribute change with Only Sync Attributes off, is
  compared by size, mtime and last 64 KiB, so one that ends in 64 KiB of NUL passes and stays all NUL in the newest
  version. Older versions keep the right copy.
- **Why:** the read-back hashes the tail only; a whole-file read would cost every check a full read.
- **Revisit when:** such a loss is seen, or a job turns Only Sync Attributes off and holds files that end in zeros.
- **Approved:** 2026-10-27, "Known limitation (Recommended)"; 2026-11-06, the text above, "Approve the text
  (Recommended)".

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
  disk hangs at that moment, the backuper hangs with it: status shows no wait, and after a forced kill no pending
  transactions are left, so the next start compares the whole tree. No wrong result and nothing lost.
- **Why:** the wait is what keeps a rename and its folder's changes in one batch, and a stop already hangs in this state;
  showing it would add parts for a state that already stalls the daemon.
- **Revisit when:** a hung disk during a rename is seen on the live jobs.
- **Approved:** 2026-11-05, the user's choice "Known limitation (Recommended)".

### A failed batch of scans handed back as a whole-tree comparison

- **Kind:** known limitation.
- **What the operator sees:** a batch made only of folder scans that fails while a move-out is still waiting for its pair
  is handed back as a whole-tree comparison instead of its scans: one extra full walk, no wrong result.
- **Why:** telling such a batch apart in the hand-back would add a part for a rare, cost-only case.
- **Revisit when:** it is seen.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A rewrite made while down that keeps size and mtime

- **Kind:** known limitation, already in 0.45.
- **What the operator sees:** a file rewritten in place while the daemon is down, at the same size and with its mtime set
  back, changed only before its last 64 KiB, is missed at the restart and kept wrong until it changes again. So is such
  a rewrite made while the daemon ran, when a stop with the vault not there dropped its event: the start's full
  comparison has the same blind spot.
- **Why:** a full comparison checks size, mtime and the tail hash; utime cannot set ctime back, but ctime is not checked.
  Reading the whole file when its ctime is after the matched time would catch it, but making that check affordable
  needed three more parts, for a rare case.
- **Revisit when:** such rewrites are seen in practice.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)"; then 2026-10-27, on that whole-file
  check: "why do we bother?", then "Drop it, known limitation (Recommended)"; 2026-10-28, on widening it to a rewrite
  made while running whose event a stop dropped: "Widen it (Recommended)".

### A write error in the middle of a copy after the reboot

- **Kind:** known limitation.
- **What the operator sees:** after the reboot that ends a vault disk's failed-sync marker, the restart's full comparison
  reads each unchecked copy back by its size, mtime and last 64 KiB. A page lost in the middle of a file to the write
  error passes, and the copy stays wrong until the file changes again.
- **Why:** reading every unchecked copy whole at a restart costs a full read of everything copied since the last check.
- **Revisit when:** a vault disk keeps working after write errors, so this is met.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A failed sync that cannot be recorded, after a restart

- **Kind:** known limitation.
- **What the operator sees:** when a vault disk's failed sync cannot be recorded (a broken or full state folder, an
  unreadable boot id, or a disk path too long for a marker's name), the alert still goes out and the disk is remembered
  in memory; if reverberator restarts before the next reboot, that
  memory is gone, and copies on that disk read back from the page cache can be recorded checked, though after the reboot
  they may be bad.
- **Why:** it needs a disk write error while its marker cannot be written, and the alert has told the operator.
- **Revisit when:** it is met.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### Bind mounts and btrfs subvolumes get separate failed-sync markers

- **Kind:** known limitation.
- **What the operator sees:** markers are kept per mount point, so a vault reached through a bind mount of another
  vault's disk, or btrfs subvolumes of one filesystem mounted at separate mount points, get separate markers, and a
  write error one job's sync sees can be missed by the other job.
- **Why:** the kernel keeps the error per filesystem; keying markers by mountinfo's device number would probably group
  both layouts, an extra part for layouts not used on this host.
- **Revisit when:** such a layout is used.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

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

### A resumed batch of only untracked deletes walks the tree twice

- **Kind:** known limitation.
- **What the operator sees:** after a restart that resumes a pending file holding only a carried move-out's late
  delete, the delete is dropped and the whole tree is compared twice (the empty batch's comparison, then the resumed
  batch's follow-up), with no version; 0.46 made an empty version there instead.
- **Why:** one extra full walk at a rare restart, and no wrong result.
- **Revisit when:** such restarts are frequent.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

### An older pending file replayed after a stop dropped changes

- **Kind:** known limitation.
- **What the operator sees:** a stop while the job's vault path is not a folder, or its disk is not there, writes no
  pending file: the queued changes are dropped with one warning line, as the next start compares the whole tree. A
  pending file already in the job vault, saved by an earlier stop while the vault was there and not loaded since because
  no start got past the vault wait, stays. A later start replays it only when its resume check passes: the newest mtime
  in the monitored tree is at least 1 s older than the file, so a dropped content change, create or delete (each moves
  an mtime, unless a tool such as rsync -a or tar x sets the mtimes back) fails the check and the tree is compared in
  full. What can be missed is an attribute-only change (chmod, chown, an xattr) or one whose mtimes were kept or set
  back, and only in the replayed batch's version: the whole-tree comparison that follows every replayed batch, in the
  same start and from a matched time the replay did not move, puts them in the next version, as any full comparison
  would; a same-size rewrite that kept its mtime and changed only before its last 64 KiB is missed by it too (see "A
  rewrite made while down that keeps size and mtime").
- **Why:** the stop cannot remove the old file from a vault that is not there, and the start that finds it cannot tell it
  from a current one; the case needs a stop with changes queued while the vault was there, a start that never got past
  the vault wait, and a second stop with changes queued.
- **Revisit when:** missed changes are seen after such stops.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)"; 2026-10-28, on the smaller impact: "Keep
  it, reworded (Recommended)".

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
- **What the operator sees:** the disk check reads /etc/fstab and mergerfs pools, and the stop checks the disk, not the
  vault's signature. So a vault on a disk mounted outside fstab (by hand, by a systemd .mount unit, by autofs) that is
  unmounted when reverberator stops gets the job's pending file on the bare mount point, and one that is unmounted when
  it starts gets its Vault Path made there. Both are hidden once the disk mounts, and nothing is lost: the next start
  compares the whole tree. But a start that made the folder there then waits with "vault filesystem not ready" until a
  restart, when the disk mounts without that folder. With an N/A or auto Vault File System Signature and such a disk
  unmounted at start, the job backs up into the bare folder on the disk below until the disk mounts: those versions are
  hidden then and use that disk's space, and an auto signature filled from such a folder is the disk below's. This is
  the same as in 0.47; once the disk mounts, such a job waits on the wrong signature, with repeated FAILED alerts, until
  the cell is set back to auto.
- **Why:** such mounts are not known to reverberator without reading systemd units or autofs maps, and checking the
  signature at a stop runs df and lsblk, which can block on a hung disk.
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
  disk. Power-cut tests confirm that on f2fs, and ext4 and xfs should hold by reasoning. btrfs should not (reasoned,
  not run): on a btrfs vault, a power cut at the wrong moment could make the next start refuse the vault, or finish a
  commit with a part-applied tree.
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
  fill the machine: about 6 s per version and half a minute in all for 100,000 entries per version, measured on a loop
  image on an SSD, and under 3 s for small jobs.
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

### A comparison's failed sync does not fail the attempt

- **Kind:** known limitation.
- **What the operator sees:** when a comparison's sync of the vault disk fails, the attempt goes on. The disk is
  marked and an alert goes out, the copies stay unchecked, and the next read-back copies them again. A batch's own
  flush before its commit does fail the attempt.
- **Why:** the kernel reports a write error once, so failing here would need the code to tell "failed now" from
  "already marked", and a comparison with no copies should not fail.
- **Revisit when:** an alert is ever missed.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### status can show one version fewer during a hand-over

- **Kind:** known limitation.
- **What the operator sees:** while a batch swaps in the new tree, `status` can show one version fewer. history and
  restore wait through it and read right.
- **Why:** a status that waits could hang behind a backup, and status is what is run when things look stuck.
- **Revisit when:** something reads that count to make a decision.
- **Approved:** 2026-11-06, "Accept (Recommended)".

### A kill can leave a version folder's own time moved

- **Kind:** known limitation.
- **What the operator sees:** f2fs moves a folder's mtime on a cross-folder exchange, so the hand-over sets it back. A
  kill between the skeleton's rename and that call leaves the version folder's own mtime moved. No view of the version
  shows it, and its contents and restores are right.
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

### mergerfs answers EBADF to a lstat during an rm

- **Kind:** deferred.
- **What the operator sees:** nothing, today: `TreeWriter.removing` keeps the writer's walks out of a folder whose
  removal is queued. lstat of that folder or of a path below it can answer EBADF while `rm -rf` runs through mergerfs
  2.42.
- **Why:** the proper fix is in mergerfs: upstream https://github.com/trapexit/mergerfs/issues/1693.
- **Revisit when:** a mergerfs release carries the fix: then check whether `removing` is still worth keeping.
