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

### User symlinks past 40 hops when keep-N is 41 or more

- **Kind:** known limitation, already in 0.43.
- **What the operator sees:** with keep-N at 41 or more, an unchanged user symlink is chained through more than 40 links,
  so browsing the vault by hand through the kernel gives "too many levels of symbolic links" for it. Restore gives it back
  correctly. The live jobs keep 3 to 5 versions.
- **Why:** the re-copies every 32-38 hops that keep files under the kernel's limit apply to files only.
- **Revisit when:** a job keeps 41 or more versions and its vault is browsed by hand.
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

- **Kind:** deferred (round 11).
- **What the operator sees:** a file written through mmap raises no inotify event. If its mode, owner or xattrs then
  change in the same batch, the version keeps its old bytes under the new metadata, and a full comparison does not see
  it either (the metadata sync put the new mtime on the old copy), until the file is written normally again. A file
  written only through mmap (mein's QQ MMKV files, for example) is backed up only at a restart's full comparison.
- **Why:** no inotify or fanotify flag reports mmap stores (round 10's research: scratchpad r10/mmap/report.md); an mmap
  store does move the file's mtime.
- **Revisit when:** round 11: (1) an attribute-only change whose live mtime moved is copied rather than synced, so the
  mtime stays a true signal for later comparisons (a touch of a big unchanged file then costs one copy); (2) a scheduled
  full comparison per job, configurable in the rule file and off by default, for files that get no event at all.
- **Approved:** 2026-10-26, "let's defer. let's see if we can catch something, or if we can know if a file is mmaped";
  2026-10-27: "should we trust mtime change as indication of file is changed to just do the copy? this way we only do
  one read and one write not three reads and one write in most cases", then "Keep it, round 11 (Recommended)", and for
  the scheduled comparison "Configurable per job and default off".

### A file moved and then touched in one batch is copied again

- **Kind:** known limitation.
- **What the operator sees:** a file moved and then given a new mtime (`touch -m`, `rsync -t`) in the same batch is
  copied again whole by the check after the batch, and the size estimate does not count that copy.
- **Why:** letting a moved row vouch for its copy would weaken the guard that keeps a swap from putting one file's
  metadata on another's copy.
- **Revisit when:** it costs noticeable space.
- **Approved:** 2026-10-26, the user's choice "Known limitation (Recommended)".

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

### A vault disk's data-write error caught by one comparison only

- **Kind:** deferred (round 11).
- **What the operator sees:** a vault disk that fails a data write but keeps working (XFS does not shut down on a data
  write error) reports the error once, to the next comparison's sync, which keeps its copies unchecked and logs a
  warning; a later comparison's sync gets no error, and its read-back from the page cache, which still holds the good
  bytes, records the copy checked. After a reboot the copy reads back short or zeroed, and no comparison reads it again.
- **Why:** syncfs reports a writeback error once; the read-back cannot tell the page cache from the disk.
- **Revisit when:** round 11: remember a failed sync per disk until the next reboot (a marker under /run), and while it is
  there keep that pool's copies unchecked, so the restart after the reboot reads them from disk.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)".

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

### A configurable chain length

- **Kind:** deferred (round 11).
- **What the operator sees:** a version's unchanged file is reached through a chain of links into older versions, re-copied
  every 32-38 hops. Anything reading the vault through the kernel (hand browsing, cp, other tools) can get "too many
  levels of symbolic links" for chains over about 20 links while mounts change on the host (Docker does this), as the
  kernel then counts links twice. reverberator follows chains itself and is unaffected; the live jobs keep 3-5 versions.
- **Why:** the re-copy distance is fixed.
- **Revisit when:** round 11: make the re-copy distance configurable, default the current one, with a README note on
  lowering it to about 20 where tools read the vault through the kernel; no limit can suit users who never browse by
  hand (reverberator's own chain follower then needs no limit either).
- **Approved:** 2026-10-27, the user: "make this max chain length configurable? let's default to our current one and keep
  some notes about your case so user knows to change it on systems that may only want 20 linkx. and for users that do
  not intend to manually copy them, then maybe no link limit is acceptable."

### A rewrite made while down that keeps size and mtime

- **Kind:** deferred (round 11), already in 0.45.
- **What the operator sees:** a file rewritten in place while the daemon is down, at the same size and with its mtime set
  back, changed only before its last 64 KiB, is missed at the restart and kept wrong until it changes again.
- **Why:** a full comparison checks size, mtime and the tail hash; utime cannot set ctime back, but ctime is not checked.
- **Revisit when:** round 11: a full comparison reads the whole file when its ctime is after the matched time while its
  size and mtime are unchanged.
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)".

### A version with no change after a carried move-out

- **Kind:** deferred (round 11).
- **What the operator sees:** when a batch carries a pending move-out and removes its phantom, the move-out's own delete
  arrives at the pair timeout (1-12 h on the live jobs) and, if nothing else changed, makes a version identical to the
  one before; 0.45 made the same extra version, so the count is unchanged.
- **Why:** a delete of a path the vault no longer tracks still counts as work for a batch.
- **Revisit when:** round 11: drop such deletes before deciding a batch has work, so it ends in "No differences".
- **Approved:** 2026-10-27, the user's choice "Defer to round 11 (Recommended)".
