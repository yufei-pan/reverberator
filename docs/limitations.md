# Known limitations and deferred work

Each entry here has the user's OK. Reviewers read this file first and don't raise these entries again.

### A user's link written as its own path's chain link

- **Kind:** known limitation.
- **What the operator sees:** a symlink in the monitored tree whose text is exactly its own path's link to the previous
  version (for example `a/U -> ../../V<n-1>--<timestamp>/a/U`) is taken for the vault's own link. Pruning and restore then
  give a/U's own older copy in place of the link. Nothing beyond that one path is affected.
- **Why:** the vault holds nothing that tells such a link from the daemon's own. Telling it would need a new per-version
  record of user links, a new vault artifact.
- **Revisit when:** someone needs to back up symlinks of that exact form, which requires typing the newest version's
  folder name between two backups.
- **Approved:** 2026-10-22, the user's choice "Leave it (Recommended)" on the round 8 design's blind spot.

### World-readable vault database and change lists

- **Kind:** known limitation.
- **What the operator sees:** any local user can read `.reverberator_manifest.sqlite` and the `V<n>--…modified_contents.nsv`
  change lists in a job vault. Together they list every backed-up file name and its size, the passwords job's included.
- **Why:** making them root-only (0600) would leave only root able to run status, history and restore. The user chose to
  keep them readable.
- **Revisit when:** a vault is shared with users who must not see other jobs' file names.
- **Approved:** 2026-10-23, the user's choice "Known limitation".

### No flush before a prune's removal

- **Kind:** known limitation.
- **What the operator sees:** after a power loss in the middle of a prune on mergerfs, a link that was being replaced may
  come back in either form, old or new. No copy is lost, but a restore can show a dangling link for that file until the
  next full comparison.
- **Why:** flushing the whole pool before every prune would cost time on each backup, for a rare event that loses no copy.
- **Revisit when:** power losses during prunes are seen in practice.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### Size records rounded to 2 decimals

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** each version's size is stored rounded to 2 decimals in its change list's name (for example
  `11.54_MiB`). After a restart, the vault's total can be off by up to 0.5% per version, so a prune can remove the oldest
  version slightly early.
- **Why:** it is small, it errs toward removing early and never toward growing past the limit, and exact sizes would
  change the change-list name format.
- **Revisit when:** a vault's size limit needs to be met exactly.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

### User symlinks past 40 hops when keep-N is 40 or more

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** with keep-N at 40 or more, an unchanged user symlink is chained through more than 40 links
  by way of `current_version/` (at 41 or more, through its own version folder too), so browsing the vault by hand through
  the kernel gives "too many levels of symbolic links" for it. Restore gives it back correctly. The live jobs keep 3 to
  5 versions.
- **Why:** the re-copies every 32-38 hops at the default Chain Length of 40 that keep files under the kernel's limit apply
  to files only.
- **Revisit when:** a job keeps 40 or more versions and its vault is browsed by hand.
- **Approved:** 2026-10-23, the user's choice "Known limitation (Recommended)".

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
  written only through mmap (mein's QQ MMKV files) is backed up only at its next normal write, a restart, or the job's
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
  renaming them, and logs `Failed to move … delete & copy instead` at ERROR level (firewatcher does not alert on it). The
  result is right.
- **Why:** renaming them in one step would need a change-list format change.
- **Revisit when:** the change list's format changes for another reason.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

### A move into a folder made after an earlier move in one batch

- **Kind:** known limitation.
- **What the operator sees:** `mv d e; mkdir e/sub; mv x e/sub/x` in one batch falls back to delete & copy for x, logging
  `Failed to move … delete & copy instead` at ERROR level (firewatcher does not alert on it), and x is copied once more.
  The result is right.
- **Why:** replaying such moves in batch order is a larger change to the replay for one extra copy in a rare order.
- **Revisit when:** it is seen often.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

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
  folders, links and xattr blocks (a few KB, at most ~77 KB in testing) and a change kept under a folder moved into a new
  folder (up to that file's size), so a vault can go over its limit by that much until the next prune. The sizes recorded
  after each backup are measured, so later prunes are right.
- **Why:** counting them would add estimates for a small, one-batch overshoot.
- **Revisit when:** a vault's limit is tight enough for it to matter.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

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
  pool, such as /mnt/impulse_data/<disk>/..., or a remote write on a network filesystem) raises no event, and once a
  later batch moves the vault's matched time past it, no full comparison reads it: that xattr is missing from the
  versions until the file changes again. Content changes are still caught, by size and mtime.
- **Why:** round 10's matched time bounds a full comparison's xattr reads to what changed since the vault last matched
  the whole tree, and that bound assumes every change goes through the watched folder.
- **Revisit when:** a job monitors a network filesystem, or files are changed on a pool's disks directly.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### A copy whose start was lost after a power loss

- **Kind:** known limitation.
- **What the operator sees:** after a power loss, a vault copy whose first blocks were lost but whose last 64 KiB reached
  the disk reads back with the right size, mtime and tail hash, so it is recorded checked and keeps the lost bytes.
  Writeback usually loses a file's end, which is caught.
- **Why:** the read-back hashes the tail only; a whole-file read would cost every check a full read.
- **Revisit when:** such a loss is seen.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

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
  right.
- **Why:** a move's two events can straddle one read, so a move-out is carried into a batch only once a whole read has
  passed; carrying it sooner would break a rename split by the take into a delete and a copy.
- **Revisit when:** it is seen on the live jobs.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

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
  back, changed only before its last 64 KiB, is missed at the restart and kept wrong until it changes again.
- **Why:** a full comparison checks size, mtime and the tail hash; utime cannot set ctime back, but ctime is not checked.
  Reading the whole file when its ctime is after the matched time would catch it, but making that check affordable
  needed three more parts, for a rare case.
- **Revisit when:** such rewrites are seen in practice.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)"; then 2026-10-27, on that whole-file
  check: "why do we bother?", then "Drop it, known limitation (Recommended)".

### A write error in the middle of a copy after the reboot

- **Kind:** known limitation.
- **What the operator sees:** after the reboot that ends a vault disk's failed-sync marker, the restart's full comparison
  reads each unchecked copy back by its size, mtime and last 64 KiB. A page lost in the middle of a file to the write
  error passes, and the copy stays wrong until the file changes again.
- **Why:** reading every unchecked copy whole at a restart costs a full read of everything copied since the last check.
- **Revisit when:** a vault disk keeps working after write errors, so this is met.
- **Approved:** 2026-10-27, the user's choice "Known limitation (Recommended)".

### One lock for every comparison's vault sync

- **Kind:** known limitation.
- **What the operator sees:** all comparisons' vault syncs take one lock, so a write error is marked before another job
  syncs that disk; a vault disk that hangs in a sync (SCSI timeouts, a link-reset loop) stalls every job's checked
  records, on any pool, not only the jobs on that disk.
- **Why:** a lock per disk needs a lock table; on this host every vault is on /mnt/jank.
- **Revisit when:** a host keeps vaults on several pools.
- **Approved:** 2026-10-28, the user's choice "Known limitation (Recommended)".

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
  back, values taken from the #_defaults_# row included (a cleaned-up Job Name or monitored path rewrites the row too),
  so a later edit of the defaults row no longer reaches that job: edit the job's own row, or clear its cells, to follow
  a changed default. Columns 13 and 14 are never written.
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
  no start got past the vault wait, stays. A later start may replay it (its resume check passes when nothing in the
  monitored tree has an mtime newer than the file), and the dropped changes are then missed until the next full
  comparison, as changes made while the daemon is down would be. A replayed batch is followed by a whole-tree
  comparison, which caught them in testing.
- **Why:** the stop cannot remove the old file from a vault that is not there, and the start that finds it cannot tell it
  from a current one; the case needs a stop with changes queued while the vault was there, a start that never got past
  the vault wait, and a second stop with changes queued.
- **Revisit when:** missed changes are seen after such stops.
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
